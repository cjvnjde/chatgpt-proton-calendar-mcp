package proton

import (
	"encoding/base64"
	"errors"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
)

// AttendeeCard seals the private guest list under the event's existing session
// key and wraps that same key for each Proton recipient. No mail is sent here.
func AttendeeCard(text, packet string, ck *CalendarKeys, recipients map[string]*pgp.KeyRing) (Card, []map[string]any, error) {
	kp, err := base64.StdEncoding.DecodeString(packet)
	if err != nil {
		return Card{}, nil, errors.New("invalid event key packet")
	}
	dec, err := PGP.Decryption().DecryptionKeys(ck.Calendar).New()
	if err != nil {
		return Card{}, nil, err
	}
	sk, err := dec.DecryptSessionKey(kp)
	if err != nil {
		return Card{}, nil, err
	}
	defer sk.Clear()
	enc, err := PGP.Encryption().SessionKey(sk).Utf8().New()
	if err != nil {
		return Card{}, nil, err
	}
	msg, err := enc.Encrypt([]byte(text))
	if err != nil {
		return Card{}, nil, err
	}
	signature, err := sign(ck.Address.Write, text)
	if err != nil {
		return Card{}, nil, err
	}
	added := []map[string]any{}
	for email, key := range recipients {
		e, err := PGP.Encryption().Recipients(key).New()
		if err != nil {
			return Card{}, nil, err
		}
		p, err := e.EncryptSessionKey(sk)
		if err != nil {
			return Card{}, nil, err
		}
		added = append(added, map[string]any{"Email": email, "AddressKeyPacket": base64.StdEncoding.EncodeToString(p)})
	}
	return Card{Type: 3, Data: base64.StdEncoding.EncodeToString(msg.BinaryDataPacket()), Signature: signature}, added, nil
}
