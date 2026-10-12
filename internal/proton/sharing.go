package proton

import (
	"context"
	"encoding/base64"
	"errors"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"net/url"
)

// PublishedEncryptionKey uses only active primary encryption keys. Missing or
// unusable keys are errors, never a reason to fall back to cleartext delivery.
func (c *Client) PublishedEncryptionKey(ctx context.Context, email string) (*pgp.KeyRing, error) {
	var r struct {
		Address struct {
			Keys []struct {
				PublicKey      string
				Primary, Flags int
			}
		}
	}
	if err := c.Do(ctx, "GET", "/core/v4/keys/all", url.Values{"Email": {email}, "InternalOnly": {"1"}}, nil, &r); err != nil {
		return nil, err
	}
	ring, err := pgp.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}
	for _, record := range r.Address.Keys {
		if record.Primary != 1 || record.Flags&3 != 3 {
			continue
		}
		key, err := pgp.NewKeyFromArmored(record.PublicKey)
		if err != nil {
			return nil, errors.New("recipient public key is unreadable")
		}
		if err := ring.AddKey(key); err != nil {
			return nil, err
		}
	}
	if ring.CountEntities() == 0 {
		return nil, errors.New("recipient has no usable primary Proton encryption key")
	}
	return ring, nil
}

func (c *Client) ShareCalendar(ctx context.Context, id, email string, permissions int, ck *CalendarKeys) error {
	recipient, err := c.PublishedEncryptionKey(ctx, email)
	if err != nil {
		return err
	}
	msg, err := pgp.NewPGPMessageFromArmored(ck.PassphraseMessage)
	if err != nil {
		return errors.New("invalid calendar passphrase packet")
	}
	d, err := PGP.Decryption().DecryptionKeys(ck.Address.Read).New()
	if err != nil {
		return err
	}
	sk, err := d.DecryptSessionKey(msg.BinaryKeyPacket())
	if err != nil {
		return errors.New("cannot open calendar sharing key")
	}
	defer sk.Clear()
	enc, err := PGP.Encryption().Recipients(recipient).New()
	if err != nil {
		return err
	}
	packet, err := enc.EncryptSessionKey(sk)
	if err != nil {
		return err
	}
	signer, err := PGP.Sign().SigningKeys(ck.Address.Write).Detached().SigningContext(pgp.NewSigningContext("calendar.sharing.invite", true)).New()
	if err != nil {
		return err
	}
	signature, err := signer.Sign(sk.Key, pgp.Armor)
	if err != nil {
		return err
	}
	body := map[string]any{"AddressID": ck.Member.AddressID, "Signature": string(signature), "Members": []any{map[string]any{"Email": email, "PassphraseKeyPacket": base64.StdEncoding.EncodeToString(packet), "Permissions": permissions}}}
	return c.Do(ctx, "POST", "/calendar/v1/"+id+"/members", nil, body, nil)
}
