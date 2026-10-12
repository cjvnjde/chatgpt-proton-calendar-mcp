package proton

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"

	"github.com/ProtonMail/go-srp"
	"proton-calendar-mcp/internal/vault"
)

// Login uses go-srp's signed-modulus verification and verifies the server proof.
// Only an operator CLI invokes this; no MCP tool accepts credentials.
func (c *Client) Login(ctx context.Context, username string, password []byte, totp func() (string, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initializing = true
	var session struct{ UID, AccessToken, RefreshToken string }
	if err := c.call(ctx, "POST", "/auth/v4/sessions", nil, struct{}{}, &session, false); err != nil {
		return err
	}
	c.state.Session = vault.Session{UID: session.UID, AccessToken: session.AccessToken, RefreshToken: session.RefreshToken}
	var info struct {
		Version                                              int
		Username, Salt, Modulus, ServerEphemeral, SRPSession string
	}
	if err := c.call(ctx, "POST", "/core/v4/auth/info", nil, map[string]string{"Username": username, "Intent": "Proton"}, &info, true); err != nil {
		return err
	}
	auth, err := srp.NewAuth(info.Version, info.Username, password, info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return errors.New("invalid or untrusted Proton SRP parameters")
	}
	proof, err := auth.GenerateProofs(2048)
	if err != nil {
		return errors.New("cannot generate SRP proof")
	}
	var result struct {
		UID, AccessToken, RefreshToken, ServerProof string
		TwoFA                                       struct{ Enabled int } `json:"2FA"`
	}
	err = c.call(ctx, "POST", "/core/v4/auth", nil, map[string]string{
		"Username": username, "ClientProof": base64.StdEncoding.EncodeToString(proof.ClientProof),
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proof.ClientEphemeral), "SRPSession": info.SRPSession,
	}, &result, true)
	if err != nil {
		return err
	}
	serverProof, err := base64.StdEncoding.DecodeString(result.ServerProof)
	if err != nil || subtle.ConstantTimeCompare(serverProof, proof.ExpectedServerProof) != 1 {
		return errors.New("Proton SRP server proof verification failed")
	}
	if result.UID == "" || result.AccessToken == "" || result.RefreshToken == "" {
		return errors.New("Proton returned incomplete login credentials")
	}
	c.state.Session = vault.Session{UID: result.UID, AccessToken: result.AccessToken, RefreshToken: result.RefreshToken}
	if result.TwoFA.Enabled != 0 {
		if result.TwoFA.Enabled&1 == 0 || totp == nil {
			return errors.New("this login command supports TOTP; hardware-key-only login is not implemented")
		}
		code, err := totp()
		if err != nil {
			return err
		}
		if err := c.call(ctx, "POST", "/core/v4/auth/2fa", nil, map[string]string{"TwoFactorCode": code}, nil, true); err != nil {
			return err
		}
	}
	return nil // Save only after the key hierarchy has also unlocked successfully.
}
