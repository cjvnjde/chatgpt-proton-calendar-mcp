package proton

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"

	"github.com/ProtonMail/go-srp"
	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"proton-calendar-mcp/internal/vault"
)

// ProtonV1 selects Proton's algorithms and packet profile. This is an official
// crypto library; no cryptographic primitives are implemented here.
var PGP = pgp.PGPWithProfile(profile.ProtonV1())

type KeyRecord struct {
	ID, PrivateKey, Token, Signature string
	Primary, Active, Flags           int
}
type Address struct {
	ID, Email string
	Keys      []KeyRecord
}
type Rings struct{ Read, Write, Verify *pgp.KeyRing }
type Identity struct {
	User      *pgp.KeyRing
	Addresses map[string]Rings
}

func (i *Identity) Close() {
	if i.User != nil {
		i.User.ClearPrivateParams()
	}
	for _, r := range i.Addresses {
		r.Read.ClearPrivateParams()
	}
}

func decrypt(kr *pgp.KeyRing, data []byte, encoding int8, text bool) ([]byte, error) {
	b := PGP.Decryption().DecryptionKeys(kr)
	if text {
		b = b.Utf8()
	}
	d, err := b.New()
	if err != nil {
		return nil, err
	}
	r, err := d.Decrypt(data, encoding)
	if err != nil {
		return nil, err
	}
	return r.Bytes(), nil
}

func verify(kr *pgp.KeyRing, data []byte, sig string, text bool) error {
	b := PGP.Verify().VerificationKeys(kr)
	if text {
		b = b.Utf8()
	}
	v, err := b.New()
	if err != nil {
		return err
	}
	r, err := v.VerifyDetached(data, []byte(sig), pgp.Armor)
	if err != nil {
		return err
	}
	return r.SignatureError()
}

func sign(kr *pgp.KeyRing, data string) (string, error) {
	s, err := PGP.Sign().SigningKeys(kr).Detached().Utf8().New()
	if err != nil {
		return "", err
	}
	b, err := s.Sign([]byte(data), pgp.Armor)
	return string(b), err
}

func openRing(records []KeyRecord, pass []byte, user *pgp.KeyRing) (Rings, error) {
	r, _ := pgp.NewKeyRing(nil)
	w, _ := pgp.NewKeyRing(nil)
	trusted, _ := pgp.NewKeyRing(nil)
	for _, record := range records {
		if record.Active == 0 {
			continue
		}
		secret := pass
		var token []byte
		if user != nil && (record.Token != "" || record.Signature != "") {
			if record.Token == "" || record.Signature == "" {
				continue
			}
			var err error
			token, err = decrypt(user, []byte(record.Token), pgp.Armor, false)
			if err != nil || verify(user, token, record.Signature, false) != nil {
				clear(token)
				continue
			}
			secret = token
		}
		key, err := pgp.NewKeyFromArmored(record.PrivateKey)
		if err != nil {
			clear(token)
			continue
		}
		unlocked, err := key.Unlock(secret)
		clear(token)
		if err != nil {
			continue
		}
		if err := r.AddKey(unlocked); err != nil {
			r.ClearPrivateParams()
			return Rings{}, err
		}
		if user == nil || record.Flags&1 != 0 {
			if err := trusted.AddKey(unlocked); err != nil {
				r.ClearPrivateParams()
				return Rings{}, err
			}
		}
		if record.Primary == 1 && (user == nil || record.Flags&3 == 3) {
			if err := w.AddKey(unlocked); err != nil {
				r.ClearPrivateParams()
				return Rings{}, err
			}
		}
	}
	if r.CountEntities() == 0 {
		return Rings{}, errors.New("no active keys could be unlocked")
	}
	return Rings{r, w, trusted}, nil
}

func (c *Client) UnlockIdentity(ctx context.Context) (*Identity, error) {
	var result struct{ User struct{ Keys []KeyRecord } }
	if err := c.Do(ctx, "GET", "/core/v4/users", nil, nil, &result); err != nil {
		return nil, err
	}
	pass := []byte(c.KeyPassword())
	defer clear(pass)
	if len(pass) == 0 {
		return nil, errors.New("run the local login command to unlock account keys")
	}
	user, err := openRing(result.User.Keys, pass, nil)
	if err != nil {
		return nil, errors.New("account keys did not unlock; log in again")
	}
	i := &Identity{User: user.Read, Addresses: map[string]Rings{}}
	var addresses struct{ Addresses []Address }
	if err := c.Do(ctx, "GET", "/core/v4/addresses", nil, nil, &addresses); err != nil {
		i.Close()
		return nil, err
	}
	for _, a := range addresses.Addresses {
		if ring, err := openRing(a.Keys, pass, i.User); err == nil {
			i.Addresses[a.ID] = ring
		}
	}
	if len(i.Addresses) == 0 {
		i.Close()
		return nil, errors.New("no address keys could be unlocked")
	}
	return i, nil
}

// DeriveKeyPassword derives the mailbox key passphrase after SRP login. The
// actual account/mailbox password is never saved.
func (c *Client) DeriveKeyPassword(ctx context.Context, password []byte) error {
	var u struct {
		User struct {
			ID   string
			Keys []KeyRecord
		}
	}
	var salts struct {
		KeySalts []struct{ ID, KeySalt string }
	}
	if err := c.Do(ctx, "GET", "/core/v4/users", nil, nil, &u); err != nil {
		return err
	}
	if len(u.User.Keys) == 0 {
		return errors.New("account has no keys")
	}
	if err := c.Do(ctx, "GET", "/core/v4/keys/salts", nil, nil, &salts); err != nil {
		return err
	}
	var pass []byte
	for _, s := range salts.KeySalts {
		if s.ID != u.User.Keys[0].ID || s.KeySalt == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(s.KeySalt)
		if err != nil {
			return errors.New("invalid key salt")
		}
		derived, err := srp.MailboxPassword(password, raw)
		if err != nil || len(derived) < 31 {
			return errors.New("cannot derive mailbox key password")
		}
		defer clear(derived)
		pass = derived[len(derived)-31:]
		break
	}
	if len(pass) == 0 {
		return errors.New("legacy unsalted account keys are not supported; refusing to persist the original password")
	}
	// Confirm the keys open before writing a new session over a working one.
	c.mu.Lock()
	c.state.Session.KeyPassword = string(pass)
	c.mu.Unlock()
	i, err := c.UnlockIdentity(ctx)
	if err != nil {
		return err
	}
	i.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	if u.User.ID == "" {
		return errors.New("Proton returned no account identity")
	}
	if c.state.AccountID != "" && c.state.AccountID != u.User.ID {
		c.state.Operations = map[string]vault.Operation{}
	}
	c.state.AccountID = u.User.ID
	c.initializing = false
	return c.persist()
}

type Member struct {
	ID, AddressID, Email, Name, Color, Description string
	Permissions, Flags, Display                    int
}
type CalendarKeys struct {
	Settings          json.RawMessage
	PassphraseMessage string
	PassphraseID      string
	Calendar          *pgp.KeyRing
	Encrypt           *pgp.KeyRing
	Address           Rings
	Member            Member
	Identity          *Identity
}

func (k *CalendarKeys) Close() { k.Calendar.ClearPrivateParams(); k.Identity.Close() }

func (c *Client) UnlockCalendar(ctx context.Context, id string) (*CalendarKeys, error) {
	i, err := c.UnlockIdentity(ctx)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			i.Close()
		}
	}()
	var b struct {
		CalendarSettings json.RawMessage
		Members          []Member
		Keys             []KeyRecord
		Passphrase       struct {
			ID                string
			MemberPassphrases []struct{ MemberID, Passphrase, Signature string }
		}
	}
	if err := c.Do(ctx, "GET", "/calendar/v2/"+id+"/bootstrap", nil, nil, &b); err != nil {
		return nil, err
	}
	var member Member
	var addr Rings
	for _, m := range b.Members {
		if r, found := i.Addresses[m.AddressID]; found {
			member = m
			addr = r
			break
		}
	}
	if member.ID == "" {
		return nil, errors.New("no matching calendar membership")
	}
	var pass []byte
	var passMessage string
	for _, p := range b.Passphrase.MemberPassphrases {
		if p.MemberID != member.ID {
			continue
		}
		passMessage = p.Passphrase
		pass, err = decrypt(addr.Read, []byte(p.Passphrase), pgp.Armor, false)
		if err != nil || verify(addr.Verify, pass, p.Signature, false) != nil {
			clear(pass)
			return nil, errors.New("calendar passphrase signature verification failed")
		}
		break
	}
	defer clear(pass)
	if len(pass) == 0 {
		return nil, errors.New("calendar passphrase unavailable")
	}
	r, _ := pgp.NewKeyRing(nil)
	w, _ := pgp.NewKeyRing(nil)
	for _, record := range b.Keys {
		key, err := pgp.NewKeyFromArmored(record.PrivateKey)
		if err != nil {
			continue
		}
		key, err = key.Unlock(pass)
		if err != nil {
			continue
		}
		if err := r.AddKey(key); err != nil {
			r.ClearPrivateParams()
			return nil, errors.New("cannot load calendar key")
		}
		if record.Flags&3 == 3 {
			if err := w.AddKey(key); err != nil {
				r.ClearPrivateParams()
				return nil, errors.New("cannot load primary calendar key")
			}
		}
	}
	if r.CountEntities() == 0 {
		return nil, errors.New("calendar keys could not be unlocked")
	}
	ok = true
	return &CalendarKeys{Calendar: r, Encrypt: w, Address: addr, Member: member, Identity: i, PassphraseMessage: passMessage, PassphraseID: b.Passphrase.ID, Settings: b.CalendarSettings}, nil
}

type Card struct {
	Type      int    `json:"Type"`
	Data      string `json:"Data"`
	Signature string `json:"Signature,omitempty"`
}

// OpenCards is strict about card types and decoding. Signature validity is
// reported separately for reads; writes require every signature to verify.
func OpenCards(cards []Card, packet string, decKR, verifyKR *pgp.KeyRing) ([]string, bool, error) {
	if len(cards) == 0 || len(cards) > 16 {
		return nil, false, errors.New("missing or oversized event card set")
	}
	kp, err := base64.StdEncoding.DecodeString(packet)
	if err != nil {
		return nil, false, errors.New("invalid key packet")
	}
	var result []string
	verified := true
	for _, card := range cards {
		text := card.Data
		switch card.Type {
		case 2:
		case 3:
			dp, err := base64.StdEncoding.DecodeString(card.Data)
			if err != nil {
				return nil, false, errors.New("invalid encrypted event card")
			}
			plain, err := decrypt(decKR, pgp.NewPGPSplitMessage(kp, dp).Bytes(), pgp.Bytes, true)
			if err != nil {
				return nil, false, errors.New("event content could not be decrypted")
			}
			text = string(plain)
			clear(plain)
		default:
			return nil, false, errors.New("unsupported unsigned or unknown event card")
		}
		if len(text) > 256<<10 {
			return nil, false, errors.New("event content exceeds limit")
		}
		if verify(verifyKR, []byte(text), card.Signature, true) != nil {
			verified = false
		}
		result = append(result, text)
	}
	return result, verified, nil
}

func MakeCards(signedText, encryptedText string, encryptKR, signKR, decryptKR *pgp.KeyRing, existing string) ([]Card, string, error) {
	sig, err := sign(signKR, signedText)
	if err != nil {
		return nil, "", err
	}
	var sk *pgp.SessionKey
	var packet string
	if existing != "" {
		kp, err := base64.StdEncoding.DecodeString(existing)
		if err != nil {
			return nil, "", err
		}
		d, err := PGP.Decryption().DecryptionKeys(decryptKR).New()
		if err != nil {
			return nil, "", err
		}
		sk, err = d.DecryptSessionKey(kp)
		if err != nil {
			return nil, "", err
		}
	} else {
		sk, err = PGP.GenerateSessionKey()
		if err != nil {
			return nil, "", err
		}
		e, err := PGP.Encryption().Recipients(encryptKR).New()
		if err != nil {
			return nil, "", err
		}
		kp, err := e.EncryptSessionKey(sk)
		if err != nil {
			return nil, "", err
		}
		packet = base64.StdEncoding.EncodeToString(kp)
	}
	defer sk.Clear()
	e, err := PGP.Encryption().SessionKey(sk).Utf8().New()
	if err != nil {
		return nil, "", err
	}
	msg, err := e.Encrypt([]byte(encryptedText))
	if err != nil {
		return nil, "", err
	}
	encSig, err := sign(signKR, encryptedText)
	if err != nil {
		return nil, "", err
	}
	return []Card{{2, signedText, sig}, {3, base64.StdEncoding.EncodeToString(msg.BinaryDataPacket()), encSig}}, packet, nil
}

func SignCard(text string, kr *pgp.KeyRing) (Card, error) {
	sig, err := sign(kr, text)
	return Card{2, text, sig}, err
}
