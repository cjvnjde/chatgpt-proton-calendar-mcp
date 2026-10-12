package calendar

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"net/mail"
	"net/url"
	"strings"
	"time"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	ical "github.com/emersion/go-ical"
	"proton-calendar-mcp/internal/proton"
)

type GuestInput struct {
	Email    string `json:"email"`
	Name     string `json:"name,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

func validateGuests(guests []GuestInput) error {
	if len(guests) > 100 {
		return errors.New("at most 100 guests")
	}
	for _, g := range guests {
		a, err := mail.ParseAddress(g.Email)
		if err != nil || a.Address != g.Email || len(g.Email) > 254 || strings.ContainsAny(g.Email, "\r\n") {
			return errors.New("guest email must be a bare address")
		}
		if validateString(g.Name, 256) != nil || strings.ContainsAny(g.Name, "\r\n") {
			return errors.New("invalid guest name")
		}
	}
	return nil
}
func (s *Service) guestData(ctx context.Context, uid, packet string, stamp time.Time, guests []GuestInput, ck *proton.CalendarKeys) (map[string]any, error) {
	emails := url.Values{}
	for _, g := range guests {
		emails.Add("Emails[]", g.Email)
	}
	emails.Add("Emails[]", ck.Member.Email)
	var result struct {
		Responses []struct {
			Email    string
			Response struct {
				CanonicalEmail string
				Code           int
			}
		}
	}
	if err := s.Client.Do(ctx, "GET", "/core/v4/addresses/canonical", emails, nil, &result); err != nil {
		return nil, err
	}
	canonical := map[string]string{}
	for _, r := range result.Responses {
		if r.Response.CanonicalEmail != "" && len(r.Response.CanonicalEmail) <= 512 && (r.Response.Code == 0 || r.Response.Code == 1000) {
			canonical[r.Email] = r.Response.CanonicalEmail
		}
	}
	if canonical[ck.Member.Email] == "" {
		return nil, errors.New("organizer address could not be canonicalized")
	}
	attendees := component()
	attendees.Props.SetText("UID", uid)
	attendees.Props.SetDateTime("DTSTAMP", stamp)
	cleartext := []map[string]any{}
	keys := map[string]*pgp.KeyRing{}
	seen := map[string]bool{}
	for _, g := range guests {
		address := canonical[g.Email]
		if address == "" {
			return nil, errors.New("guest address could not be canonicalized")
		}
		if address == canonical[ck.Member.Email] {
			return nil, errors.New("organizer cannot also be a guest")
		}
		if seen[address] {
			return nil, errors.New("guest list contains duplicate canonical addresses")
		}
		seen[address] = true
		// No external-email fallback: an unsupported recipient stops the complete
		// operation before any event is written or invitation is delivered.
		key, err := s.Client.PublishedEncryptionKey(ctx, g.Email)
		if err != nil {
			return nil, err
		}
		keys[g.Email] = key
		sum := sha1.Sum([]byte(uid + address))
		token := hex.EncodeToString(sum[:])
		p := ical.NewProp("ATTENDEE")
		p.Value = "mailto:" + g.Email
		p.Params.Set("X-PM-TOKEN", token)
		p.Params.Set("PARTSTAT", "NEEDS-ACTION")
		p.Params.Set("RSVP", "TRUE")
		role := "REQ-PARTICIPANT"
		if g.Optional {
			role = "OPT-PARTICIPANT"
		}
		p.Params.Set("ROLE", role)
		if g.Name != "" {
			p.Params.Set("CN", g.Name)
		}
		attendees.Props.Add(p)
		cleartext = append(cleartext, map[string]any{"Token": token, "Status": 0})
	}
	text, err := renderCard(attendees)
	if err != nil {
		return nil, err
	}
	card, added, err := proton.AttendeeCard(text, packet, ck, keys)
	if err != nil {
		return nil, errors.New("cannot prepare encrypted guest list")
	}
	return map[string]any{"AttendeesEventContent": []proton.Card{card}, "Attendees": cleartext, "AddedProtonAttendees": added}, nil
}
