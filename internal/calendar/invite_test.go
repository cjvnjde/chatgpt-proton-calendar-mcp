package calendar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"proton-calendar-mcp/internal/proton"
)

func TestProtonGuestCreateDeliversSameEncryptedEvent(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	key, err := proton.PGP.KeyGeneration().AddUserId("Guest", "guest@example.test").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.ClearPrivateParams()
	public, _ := key.ToPublic()
	armor, _ := public.Armor()
	ring, _ := pgp.NewKeyRing(key)
	interceptAPI(t, f, func(req *http.Request) (any, bool) {
		switch req.URL.Path {
		case "/api/core/v4/keys/all":
			return map[string]any{"Address": map[string]any{"Keys": []any{map[string]any{"Primary": 1, "Flags": 3, "PublicKey": armor}}}}, true
		case "/api/core/v4/addresses/canonical":
			rows := []any{}
			for _, email := range req.URL.Query()["Emails[]"] {
				rows = append(rows, map[string]any{"Email": email, "Response": map[string]any{"CanonicalEmail": strings.ToLower(email), "Code": 1000}})
			}
			return map[string]any{"Responses": rows}, true
		}
		return nil, false
	})
	in := createInput()
	in.Guests = []GuestInput{{Email: "guest@example.test", Name: "Guest", Optional: true}}
	if _, err := f.service.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.raw.SharedEvents[0].Data, "ORGANIZER:mailto:addr@example.test") {
		t.Fatal("organizer missing from official signed card")
	}
	if strings.Contains(f.raw.SharedEvents[0].Data, "guest@example.test") {
		t.Fatal("guest email exposed in clear card")
	}
	e, err := f.service.Get(ctx, "calendar1", "event1")
	if err != nil {
		t.Fatal(err)
	}
	if !e.Verified || len(e.Attendees) != 1 || e.Attendees[0].Email != "guest@example.test" || e.Attendees[0].Role != "OPT-PARTICIPANT" || e.Attendees[0].Status != "NEEDS-ACTION" || e.Organizer != "addr@example.test" {
		t.Fatal(e)
	}
	var added []struct{ Email, AddressKeyPacket string }
	json.Unmarshal(f.lastMutation["AddedProtonAttendees"], &added)
	if len(added) != 1 || added[0].Email != "guest@example.test" {
		t.Fatal("missing recipient key", added)
	}
	ck, err := f.service.Client.UnlockCalendar(ctx, "calendar1")
	if err != nil {
		t.Fatal(err)
	}
	defer ck.Close()
	texts, verified, err := proton.OpenCards(f.raw.SharedEvents, added[0].AddressKeyPacket, ring, ck.Address.Verify)
	if err != nil || !verified || len(texts) != 2 || !strings.Contains(texts[1], in.Title) {
		t.Fatal("guest cannot read same signed event", err)
	}
	guests, verified, err := proton.OpenCards(f.raw.AttendeesEvents, added[0].AddressKeyPacket, ring, ck.Address.Verify)
	if err != nil || !verified || !strings.Contains(guests[0], "guest@example.test") {
		t.Fatal("guest card unreadable", err)
	}
	// The signed guest list and responses survive silent text edits.
	before, _ := json.Marshal(f.raw.AttendeesEvents)
	title := "Updated"
	silent := false
	if _, err := f.service.Update(ctx, UpdateInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: e.Revision, Title: &title, SendUpdateNotice: &silent}); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(f.raw.AttendeesEvents)
	if string(before) != string(after) {
		t.Fatal("guest card replaced")
	}
	if _, ok := f.lastMutation["AddedProtonAttendees"]; ok {
		t.Fatal("existing guests re-invited")
	}
	if _, err := base64.StdEncoding.DecodeString(added[0].AddressKeyPacket); err != nil {
		t.Fatal(err)
	}
}

func TestGuestValidationHasNoRemoteSideEffects(t *testing.T) {
	f := setup(t)
	in := createInput()
	in.Guests = []GuestInput{{Email: "guest@example.test\r\nBcc: other@example.test"}}
	if _, err := f.service.Create(context.Background(), in); err == nil {
		t.Fatal("accepted header injection")
	}
	if f.writes != 0 {
		t.Fatal("created event after invalid guest")
	}
}
