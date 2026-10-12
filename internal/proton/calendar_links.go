package proton

import (
	"encoding/base64"
	"errors"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
)

func SealCalendarText(ck *CalendarKeys, text string) (string, error) {
	e, err := PGP.Encryption().Recipients(ck.Encrypt).Utf8().New()
	if err != nil {
		return "", err
	}
	m, err := e.Encrypt([]byte(text))
	if err != nil {
		return "", err
	}
	return m.Armor()
}
func OpenCalendarText(ck *CalendarKeys, text string) (string, error) {
	b, err := decrypt(ck.Calendar, []byte(text), pgp.Armor, true)
	if err != nil {
		return "", errors.New("cannot decrypt calendar link metadata")
	}
	defer clear(b)
	return string(b), nil
}

// XOR here is the official public-link format, not encryption of account data.
// The URL deliberately discloses the key needed to reconstruct the passphrase.
func MaskCalendarPassphrase(ck *CalendarKeys, key []byte) ([]byte, error) {
	pass, err := decrypt(ck.Address.Read, []byte(ck.PassphraseMessage), pgp.Armor, false)
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	raw, err := base64.StdEncoding.DecodeString(string(pass))
	if err != nil {
		return nil, errors.New("unsupported calendar passphrase format")
	}
	defer clear(raw)
	if len(key) != 32 || len(raw) != 32 {
		return nil, errors.New("unsupported calendar passphrase length")
	}
	out := make([]byte, 32)
	for i := range out {
		out[i] = key[i] ^ raw[i]
	}
	return out, nil
}
