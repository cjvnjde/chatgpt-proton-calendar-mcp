package proton

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proton-calendar-mcp/internal/vault"
)

func TestRefreshIsPersistedBeforeRetryAndErrorsAreSanitized(t *testing.T) {
	persisted := false
	refreshes := 0
	gets := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/auth/v4/refresh" {
			refreshes++
			if r.Header.Get("Authorization") != "" {
				t.Error("bearer on refresh")
			}
			json.NewEncoder(w).Encode(map[string]any{"Code": 1000, "AccessToken": "new", "RefreshToken": "next"})
			return
		}
		gets++
		if r.Header.Get("Authorization") == "Bearer old" {
			w.WriteHeader(401)
			w.Write([]byte(`{"Code":401,"Error":"SECRET"}`))
			return
		}
		if !persisted {
			t.Error("retry before persistence")
		}
		w.Write([]byte(`{"Code":1000}`))
	}))
	defer ts.Close()
	c := New(vault.State{Session: vault.Session{UID: "uid", AccessToken: "old", RefreshToken: "refresh"}}, func(s vault.State) error {
		persisted = true
		if s.Session.RefreshToken != "next" {
			t.Error("wrong persisted token")
		}
		return nil
	})
	c.base = ts.URL
	if err := c.Do(context.Background(), "GET", "/test", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if refreshes != 1 || gets != 2 {
		t.Fatal(refreshes, gets)
	}
}

func TestFailedCredentialSaveBlocksFurtherRequests(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/v4/refresh" {
			w.Write([]byte(`{"Code":1000,"AccessToken":"new","RefreshToken":"next"}`))
			return
		}
		w.WriteHeader(401)
		w.Write([]byte(`{"Code":401,"Error":"SECRET_PASSWORD"}`))
	}))
	defer ts.Close()
	c := New(vault.State{Session: vault.Session{AccessToken: "old", RefreshToken: "refresh"}}, func(vault.State) error { return errors.New("disk SECRET") })
	c.base = ts.URL
	for i := 0; i < 2; i++ {
		err := c.Do(context.Background(), "GET", "/test", nil, nil, nil)
		if err == nil || strings.Contains(err.Error(), "SECRET") {
			t.Fatal(err)
		}
	}
}

func TestRedirectCannotLeakCredentials(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer other.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, 302) }))
	defer first.Close()
	c := New(vault.State{Session: vault.Session{AccessToken: "secret"}}, nil)
	c.base = first.URL
	if c.Do(context.Background(), "GET", "/test", nil, nil, nil) == nil || hit {
		t.Fatal("redirect followed")
	}
}

func TestUnsaltedPasswordIsNeverPersisted(t *testing.T) {
	saved := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/core/v4/users" {
			w.Write([]byte(`{"Code":1000,"User":{"ID":"u","Keys":[{"ID":"key"}]}}`))
			return
		}
		w.Write([]byte(`{"Code":1000,"KeySalts":[]}`))
	}))
	defer ts.Close()
	c := New(vault.State{}, func(vault.State) error { saved = true; return nil })
	c.base = ts.URL
	if err := c.DeriveKeyPassword(context.Background(), []byte("original-password")); err == nil || !strings.Contains(err.Error(), "unsalted") {
		t.Fatal(err)
	}
	if saved || c.state.Session.KeyPassword != "" {
		t.Fatal("original password persisted")
	}
}
