package proton

import (
	"crypto/rand"
	"encoding/base64"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
)

// CalendarSetup prepares all cryptography before a remote calendar is created.
// The only exported private key is locked by a randomly generated passphrase.
func CalendarSetup(address *pgp.KeyRing, addressID string) (map[string]any, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer clear(raw)
	pass := []byte(base64.StdEncoding.EncodeToString(raw))
	defer clear(pass)
	key, err := PGP.KeyGeneration().AddUserId("Calendar key", "").New().GenerateKey()
	if err != nil {
		return nil, err
	}
	defer key.ClearPrivateParams()
	locked, err := PGP.LockKey(key, pass)
	if err != nil {
		return nil, err
	}
	armor, err := locked.Armor()
	if err != nil {
		return nil, err
	}
	e, err := PGP.Encryption().Recipients(address).Utf8().New()
	if err != nil {
		return nil, err
	}
	msg, err := e.Encrypt(pass)
	if err != nil {
		return nil, err
	}
	sig, err := sign(address, string(pass))
	if err != nil {
		return nil, err
	}
	return map[string]any{"AddressID": addressID, "PrivateKey": armor, "Passphrase": map[string]string{"DataPacket": base64.StdEncoding.EncodeToString(msg.BinaryDataPacket()), "KeyPacket": base64.StdEncoding.EncodeToString(msg.BinaryKeyPacket())}, "Signature": sig}, nil
}
