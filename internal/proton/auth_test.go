package proton

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/go-srp"
	"proton-calendar-mcp/internal/vault"
)

// Public signed SRP modulus from ProtonMail/go-srp's test fixtures. It contains
// no account data or private key and is verified by the library's pinned key.
const signedModulus = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n" +
	"o4ycZ14/7LfHkuSKWNlpQEh6bwLMVKvo0MFqVq9wHXwkZ/zMcqYaVhqNvLyDB0WY5Uv/Bo23JQsox52lM+4jPydw9/A9saAj" +
	"8erLCc3ZaZHxOl/a8tlYTq7FeDrbhSSgivwTKJ5Y9otla/U8FATZBxqi7nqDihS5/7x/yK3VRnEsBG1i5DcY1UQK3KD9i9v7" +
	"N2QTuGFYnRCv0MFsHzrQZWvUa1NsUhozU5PSV5s7hZkb/p6J3B9ybD6+LzuLS9fyLMcVdxzn2WUXG7JLeBbqsoECUfq9KP2w" +
	"aTzVLELOenWUV1wbioceJsaiP97ViwNJdnKx1ICoYu2c+z8ctVcqlw==\n" +
	"-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\n" +
	"wl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAB02wD5AOhMNS/K6/nvaeRhTr5n\niDGMalQccYlb58XzUEhqf3sBAOcTsz0fP3PVdMQYBbqcBl9Y6LGIG9DF4B4H\nZeLCoyYN\n=cAxM\n" +
	"-----END PGP SIGNATURE-----\n"

func TestSRPServerProofAndTOTP(t *testing.T) {
	for _, test := range []struct {
		name      string
		forge     bool
		twoFA     int
		wantError string
	}{
		{"successful TOTP", false, 1, ""},
		{"forged server", true, 0, "server proof"},
		{"hardware only", false, 2, "hardware-key-only"},
	} {
		t.Run(test.name, func(t *testing.T) {
			password := []byte("synthetic-account-password")
			salt := []byte("0123456789")
			auth, err := srp.NewAuthForVerifier(password, signedModulus, salt)
			if err != nil {
				t.Fatal(err)
			}
			verifier, err := auth.GenerateVerifier(2048)
			if err != nil {
				t.Fatal(err)
			}
			server, err := srp.NewServerFromSigned(signedModulus, verifier, 2048)
			if err != nil {
				t.Fatal(err)
			}
			challenge, err := server.GenerateChallenge()
			if err != nil {
				t.Fatal(err)
			}
			askedTOTP := false
			receivedTOTP := false
			persisted := false
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				json.NewDecoder(r.Body).Decode(&body)
				if _, ok := body["Password"]; ok {
					t.Error("plaintext password transmitted")
				}
				var response any
				switch r.URL.Path {
				case "/auth/v4/sessions":
					if r.Header.Get("x-enforce-unauthsession") != "true" {
						t.Error("unauthenticated session not enforced")
					}
					response = map[string]any{"Code": 1000, "UID": "unauth", "AccessToken": "a", "RefreshToken": "r"}
				case "/core/v4/auth/info":
					response = map[string]any{"Code": 1000, "Version": 4, "Username": "test", "Salt": base64.StdEncoding.EncodeToString(salt), "Modulus": signedModulus, "ServerEphemeral": base64.StdEncoding.EncodeToString(challenge), "SRPSession": "srp-session"}
				case "/core/v4/auth":
					a, _ := base64.StdEncoding.DecodeString(body["ClientEphemeral"])
					b, _ := base64.StdEncoding.DecodeString(body["ClientProof"])
					proof, err := server.VerifyProofs(a, b)
					if err != nil {
						t.Error(err)
					}
					if test.forge {
						proof[0] ^= 1
					}
					response = map[string]any{"Code": 1000, "UID": "signed-in", "AccessToken": "access", "RefreshToken": "refresh", "ServerProof": base64.StdEncoding.EncodeToString(proof), "2FA": map[string]int{"Enabled": test.twoFA}}
				case "/core/v4/auth/2fa":
					receivedTOTP = body["TwoFactorCode"] == "123456"
					response = map[string]int{"Code": 1000}
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
				}
				json.NewEncoder(w).Encode(response)
			}))
			defer ts.Close()
			c := New(vault.State{}, func(vault.State) error { persisted = true; return nil })
			c.base = ts.URL
			err = c.Login(context.Background(), "test", password, func() (string, error) { askedTOTP = true; return "123456", nil })
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatal(err)
				}
			} else if err != nil || !askedTOTP || !receivedTOTP {
				t.Fatal(err, askedTOTP, receivedTOTP)
			}
			if persisted {
				t.Fatal("unvalidated key hierarchy persisted")
			}
			if test.forge && c.state.Session.UID == "signed-in" {
				t.Fatal("forged session accepted")
			}
		})
	}
}

func TestUnsignedSRPModulusRefused(t *testing.T) {
	writes := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/v4/sessions" {
			w.Write([]byte(`{"Code":1000,"UID":"unauth","AccessToken":"a","RefreshToken":"r"}`))
			return
		}
		if r.URL.Path == "/core/v4/auth/info" {
			w.Write([]byte(`{"Code":1000,"Version":4,"Modulus":"untrusted","Salt":"c2FsdA=="}`))
			return
		}
		writes++
	}))
	defer ts.Close()
	c := New(vault.State{}, nil)
	c.base = ts.URL
	if err := c.Login(context.Background(), "test", []byte("password"), nil); err == nil || !strings.Contains(err.Error(), "untrusted") {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatal("proof sent against unsigned modulus")
	}
}
