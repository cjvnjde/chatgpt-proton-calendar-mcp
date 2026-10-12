// Package vault stores session credentials encrypted at rest. One process owns
// a vault at a time so single-use refresh tokens cannot race on this filesystem.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

type Session struct {
	UID          string
	AccessToken  string
	RefreshToken string
	KeyPassword  string
}

type Operation struct {
	Fingerprint string
	UID         string
	EventID     string
	CalendarID  string
}

type State struct {
	AccountID  string
	Session    Session
	Operations map[string]Operation
}

type Store struct {
	path string
	aead cipher.AEAD
	lock *os.File
}

func ReadSecret(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open secret file")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("secret must be a regular file accessible only to its owner (chmod 600)")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil || len(b) > 4096 {
		return nil, errors.New("cannot read secret file")
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

func Open(path, keyFile string) (*Store, error) {
	encoded, err := ReadSecret(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(string(encoded))
	clear(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("vault key must contain 64 hexadecimal characters")
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("vault is already in use; stop the server before login")
	}
	return &Store{path: path, aead: aead, lock: lock}, nil
}

func (s *Store) Close() error { return s.lock.Close() }

func (s *Store) Load() (State, error) {
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return State{Operations: map[string]Operation{}}, nil
	}
	if err != nil {
		return State{}, errors.New("cannot read vault")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16<<20 {
		return State{}, errors.New("vault must be an owner-only regular file of at most 16 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(f, (16<<20)+1))
	if err != nil || len(b) > 16<<20 {
		return State{}, errors.New("cannot read vault")
	}
	const header = "PCAL1"
	if len(b) < len(header)+s.aead.NonceSize() || string(b[:len(header)]) != header {
		return State{}, errors.New("invalid encrypted vault")
	}
	n := b[len(header) : len(header)+s.aead.NonceSize()]
	plain, err := s.aead.Open(nil, n, b[len(header)+len(n):], []byte(header))
	if err != nil {
		return State{}, errors.New("vault authentication failed; check its key")
	}
	defer clear(plain)
	var state State
	if err := json.Unmarshal(plain, &state); err != nil {
		return State{}, errors.New("invalid vault state")
	}
	if state.Operations == nil {
		state.Operations = map[string]Operation{}
	}
	return state, nil
}

func (s *Store) Save(state State) error {
	plain, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(plain)
	n := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(n); err != nil {
		return err
	}
	b := append([]byte("PCAL1"), n...)
	b = s.aead.Seal(b, n, plain, []byte("PCAL1"))
	f, err := os.CreateTemp(filepath.Dir(s.path), ".vault-*")
	if err != nil {
		return errors.New("cannot create vault file")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(f.Name(), s.path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return fmt.Errorf("vault directory: %w", err)
	}
	defer dir.Close()
	return dir.Sync()
}
