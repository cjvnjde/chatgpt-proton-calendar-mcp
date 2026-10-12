package vault

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVaultEncryptionIntegrityAndExclusiveOwner(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	path := filepath.Join(dir, "vault.enc")
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := Open(path, key); err == nil {
		t.Fatal("two vault owners accepted")
	}
	state := State{AccountID: "account", Session: Session{AccessToken: "SECRET_ACCESS_TOKEN", KeyPassword: "SECRET_KEY_PASSWORD"}, Operations: map[string]Operation{"one": {UID: "event"}}}
	if err := s.Save(state); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("SECRET")) {
		t.Fatal("plaintext credential on disk")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
	got, err := s.Load()
	if err != nil || got.Session.AccessToken != state.Session.AccessToken {
		t.Fatal(got, err)
	}
	b[len(b)-1] ^= 1
	os.WriteFile(path, b, 0600)
	if _, err := s.Load(); err == nil {
		t.Fatal("tampered vault accepted")
	}
}

func TestWorldReadableSecretRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	os.WriteFile(path, []byte(strings.Repeat("aa", 32)), 0644)
	if _, err := ReadSecret(path); err == nil {
		t.Fatal("world-readable secret accepted")
	}
}
