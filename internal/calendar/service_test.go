package calendar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"proton-calendar-mcp/internal/proton"
	"proton-calendar-mcp/internal/vault"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type fixture struct {
	t                           *testing.T
	service                     *Service
	users, addresses, bootstrap any
	raw                         RawEvent
	writes                      int
	ambiguous                   bool
	changes                     any
}

func setup(t *testing.T) *fixture {
	t.Helper()
	key := func(name string) (*pgp.Key, *pgp.KeyRing, string) {
		k, err := proton.PGP.KeyGeneration().AddUserId(name, name+"@example.test").New().GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		r, err := pgp.NewKeyRing(k)
		if err != nil {
			t.Fatal(err)
		}
		locked, err := proton.PGP.LockKey(k, []byte("mailbox-secret"))
		if err != nil {
			t.Fatal(err)
		}
		armor, err := locked.Armor()
		if err != nil {
			t.Fatal(err)
		}
		return k, r, armor
	}
	_, user, userArmor := key("user")
	_, addr, addrArmor := key("addr")
	_, _, calArmor := key("calendar")
	enc, err := proton.PGP.Encryption().Recipients(addr).New()
	if err != nil {
		t.Fatal(err)
	}
	message, err := enc.Encrypt([]byte("mailbox-secret"))
	if err != nil {
		t.Fatal(err)
	}
	arm, err := message.Armor()
	if err != nil {
		t.Fatal(err)
	}
	sign, err := proton.PGP.Sign().SigningKeys(addr).Detached().New()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign.Sign([]byte("mailbox-secret"), pgp.Armor)
	if err != nil {
		t.Fatal(err)
	}
	// Address key uses the migrated token hierarchy, including its binary signature.
	userEnc, err := proton.PGP.Encryption().Recipients(user).New()
	if err != nil {
		t.Fatal(err)
	}
	token, err := userEnc.Encrypt([]byte("mailbox-secret"))
	if err != nil {
		t.Fatal(err)
	}
	tokenArm, _ := token.Armor()
	userSign, err := proton.PGP.Sign().SigningKeys(user).Detached().New()
	if err != nil {
		t.Fatal(err)
	}
	tokenSig, err := userSign.Sign([]byte("mailbox-secret"), pgp.Armor)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t}
	f.users = map[string]any{"User": map[string]any{"ID": "account1", "Keys": []proton.KeyRecord{{ID: "uk", PrivateKey: userArmor, Primary: 1, Active: 1, Flags: 3}}}}
	f.addresses = map[string]any{"Addresses": []proton.Address{{ID: "address1", Email: "addr@example.test", Keys: []proton.KeyRecord{{ID: "ak", PrivateKey: addrArmor, Token: tokenArm, Signature: string(tokenSig), Primary: 1, Active: 1, Flags: 3}}}}}
	f.bootstrap = map[string]any{"Members": []proton.Member{{ID: "member1", AddressID: "address1", Email: "addr@example.test", Permissions: 31, Flags: 1}}, "Keys": []proton.KeyRecord{{PrivateKey: calArmor, Flags: 3}}, "Passphrase": map[string]any{"MemberPassphrases": []map[string]any{{"MemberID": "member1", "Passphrase": arm, "Signature": string(sig)}}}}
	old := http.DefaultTransport
	http.DefaultTransport = transportFunc(f.respond)
	t.Cleanup(func() { http.DefaultTransport = old; user.ClearPrivateParams(); addr.ClearPrivateParams() })
	client := proton.New(vault.State{Session: vault.Session{UID: "session1", AccessToken: "token", RefreshToken: "refresh", KeyPassword: "mailbox-secret"}, Operations: map[string]vault.Operation{}}, func(vault.State) error { return nil })
	loc, _ := time.LoadLocation("Europe/Kyiv")
	f.service = &Service{Client: client, Allowed: map[string]bool{"calendar1": true}, Location: loc}
	return f
}

func (f *fixture) respond(req *http.Request) (*http.Response, error) {
	if !strings.HasPrefix(req.URL.String(), proton.BaseURL) {
		f.t.Fatal("unexpected outbound host")
	}
	if req.Header.Get("Authorization") != "Bearer token" {
		f.t.Fatal("missing bearer")
	}
	var value any
	path := strings.TrimPrefix(req.URL.Path, "/api")
	switch path {
	case "/core/v4/users":
		value = f.users
	case "/core/v4/addresses":
		value = f.addresses
	case "/calendar/v2/calendar1/bootstrap":
		value = f.bootstrap
	case "/calendar/v1":
		value = map[string]any{"Calendars": []any{map[string]any{"ID": "calendar1", "Type": 0, "Members": []proton.Member{{Name: "Personal", Permissions: 31}}}}}
	case "/calendar/v1/calendar1/events/sync":
		f.writes++
		var body struct {
			MemberID string
			Events   []struct {
				ID        string
				Overwrite int
				Event     map[string]json.RawMessage
			}
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			f.t.Fatal(err)
		}
		if body.MemberID != "member1" || len(body.Events) != 1 {
			f.t.Fatal("invalid sync")
		}
		op := body.Events[0]
		if op.Event == nil {
			f.raw = RawEvent{}
		} else {
			if op.ID == "" {
				f.raw.ID = "event1"
				f.raw.CalendarID = "calendar1"
			}
			json.Unmarshal(op.Event["SharedEventContent"], &f.raw.SharedEvents)
			if p := op.Event["SharedKeyPacket"]; len(p) > 0 {
				json.Unmarshal(p, &f.raw.SharedKeyPacket)
			}
			if p := op.Event["CalendarEventContent"]; len(p) > 0 {
				json.Unmarshal(p, &f.raw.CalendarEvents)
			}
			json.Unmarshal(op.Event["IsOrganizer"], &f.raw.IsOrganizer)
			f.raw.Notifications = op.Event["Notifications"]
			f.raw.Color = op.Event["Color"]
		}
		if f.ambiguous {
			return nil, errors.New("lost reply with secret internal details")
		}
		value = map[string]any{"Responses": []any{map[string]any{"Index": 0, "Response": map[string]any{"Code": 1000, "Event": map[string]string{"ID": "event1"}}}}}
	case "/calendar/v1/calendar1/events/event1":
		value = map[string]any{"Event": f.raw}
	case "/calendar/v1/calendar1/events":
		events := []RawEvent{}
		if f.raw.ID != "" {
			events = append(events, f.raw)
		}
		value = map[string]any{"Events": events, "More": 0}
	case "/calendar/v1/calendar1/modelevents/latest":
		value = map[string]any{"CalendarModelEventID": "cursor1"}
	case "/calendar/v1/calendar1/modelevents/cursor1":
		value = f.changes
	default:
		f.t.Fatalf("unexpected endpoint %s", path)
	}
	b, _ := json.Marshal(value)
	var object map[string]any
	json.Unmarshal(b, &object)
	object["Code"] = 1000
	b, _ = json.Marshal(object)
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func createInput() CreateInput {
	return CreateInput{CalendarID: "calendar1", RequestID: "request1", Title: "Private dentist", Description: "Keep this private", Start: "2026-10-12T10:00:00+03:00", End: "2026-10-12T11:00:00+03:00", Timezone: "Europe/Kyiv", ReminderMinutes: []int{15}}
}

func TestNativeCreateReadEditDeleteAndReplay(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := createInput()
	w, err := f.service.Create(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if w.ID != "event1" || f.writes != 1 {
		t.Fatal(w, f.writes)
	}
	if strings.Contains(f.raw.SharedEvents[0].Data, in.Title) {
		t.Fatal("title exposed in signed clear card")
	}
	if len(f.raw.CalendarEvents) != 1 || !strings.Contains(f.raw.CalendarEvents[0].Data, "STATUS:CONFIRMED") {
		t.Fatal("status not in calendar signed card")
	}
	w, err = f.service.Create(ctx, in)
	if err != nil || !w.Replayed || f.writes != 1 {
		t.Fatal("create retry was not idempotent", err)
	}
	changed := in
	changed.Title = "other"
	if _, err := f.service.Create(ctx, changed); err == nil {
		t.Fatal("accepted changed request ID")
	}
	e, err := f.service.Get(ctx, "calendar1", "event1")
	if err != nil {
		t.Fatal(err)
	}
	if !e.Verified || e.Title != in.Title || e.Description != in.Description || e.Status != "CONFIRMED" {
		t.Fatal(e)
	}
	stale := e.Revision
	title := "Follow-up"
	_, err = f.service.Update(ctx, UpdateInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: e.Revision, Title: &title})
	if err != nil {
		t.Fatal(err)
	}
	e, err = f.service.Get(ctx, "calendar1", "event1")
	if err != nil {
		t.Fatal(err)
	}
	if e.Title != title || e.Description != in.Description || e.Start != in.Start || !e.Verified {
		t.Fatal("edit lost fields", e)
	}
	if _, err := f.service.Delete(ctx, DeleteInput{"calendar1", "event1", stale}); err == nil {
		t.Fatal("stale delete accepted")
	}
	if _, err := f.service.Delete(ctx, DeleteInput{"calendar1", "event1", e.Revision}); err != nil {
		t.Fatal(err)
	}
}

func TestUncertainCreateCannotBeDuplicated(t *testing.T) {
	f := setup(t)
	f.ambiguous = true
	ctx := context.Background()
	if _, err := f.service.Create(ctx, createInput()); err == nil || strings.Contains(err.Error(), "secret internal") {
		t.Fatal("unsanitized or missing error", err)
	}
	if _, err := f.service.Create(ctx, createInput()); err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatal("pending create replayed", err)
	}
	if f.writes != 1 {
		t.Fatal("duplicate write")
	}
}

func TestInactivePrimaryCalendarKeyCannotWrite(t *testing.T) {
	f := setup(t)
	b := f.bootstrap.(map[string]any)
	keys := b["Keys"].([]proton.KeyRecord)
	keys[0].Flags = 2
	b["Keys"] = keys
	if _, err := f.service.Create(context.Background(), createInput()); err == nil {
		t.Fatal("inactive primary key used for encryption")
	}
	if f.writes != 0 {
		t.Fatal("unsafe write submitted")
	}
}

func TestChangedSignaturesBlockWritesAndAllowlist(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.service.Create(ctx, createInput()); err != nil {
		t.Fatal(err)
	}
	f.raw.SharedEvents[0].Signature = "tampered"
	e, err := f.service.Get(ctx, "calendar1", "event1")
	if err != nil {
		t.Fatal(err)
	}
	if e.Verified {
		t.Fatal("tampering verified")
	}
	title := "bad"
	if _, err := f.service.Update(ctx, UpdateInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: e.Revision, Title: &title}); err == nil {
		t.Fatal("tampered write accepted")
	}
	if _, err := f.service.Get(ctx, "other", "event1"); err == nil {
		t.Fatal("allowlist bypass")
	}
	if _, err := f.service.Get(ctx, "calendar1", "../event1"); err == nil {
		t.Fatal("path injection")
	}
	if f.writes != 1 {
		t.Fatal("unsafe write submitted")
	}
}

func TestListingAndChangeFeed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.service.Create(ctx, createInput()); err != nil {
		t.Fatal(err)
	}
	listed, err := f.service.List(ctx, ListInput{CalendarID: "calendar1", Start: "2026-10-12T10:00:00+03:00", End: "2026-10-12T11:00:00+03:00"})
	if err != nil {
		t.Fatal(err)
	}
	if listed.Total != 1 || len(listed.Events) != 1 {
		t.Fatal("boundary event missing or duplicated", listed)
	}
	byUID, err := f.service.List(ctx, ListInput{CalendarID: "calendar1", Start: "2026-10-12T00:00:00+03:00", End: "2026-10-13T00:00:00+03:00", Query: listed.Events[0].UID})
	if err != nil || byUID.Total != 1 {
		t.Fatal("UID reconciliation search failed", byUID, err)
	}
	base, err := f.service.Changes(ctx, ChangesInput{CalendarID: "calendar1"})
	if err != nil || !base.Baseline || base.Cursor != "cursor1" {
		t.Fatal(base, err)
	}
	f.changes = map[string]any{"CalendarModelEventID": "cursor2", "CalendarEvents": []any{map[string]any{"ID": "event1", "Action": 1}, map[string]any{"ID": "deleted1", "Action": 0}}, "More": 1}
	changes, err := f.service.Changes(ctx, ChangesInput{"calendar1", "cursor1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes.Changes) != 2 || changes.Changes[1].Action != "deleted" || !changes.HasMore {
		t.Fatal(changes)
	}
	f.changes = map[string]any{"CalendarModelEventID": "cursor3", "Refresh": 1}
	changes, err = f.service.Changes(ctx, ChangesInput{"calendar1", "cursor1"})
	if err != nil || !changes.RefreshRequired {
		t.Fatal(changes, err)
	}
}
