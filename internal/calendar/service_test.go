package calendar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	ical "github.com/emersion/go-ical"
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
	series                      []RawEvent
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
	case "/calendar/v1/events", "/calendar/v1/calendar1/events":
		events := []RawEvent{}
		if f.raw.ID != "" {
			events = append(events, f.raw)
		}
		if path == "/calendar/v1/events" && f.series != nil {
			events = f.series
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
	if _, err := f.service.Delete(ctx, DeleteInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: stale}); err == nil {
		t.Fatal("stale delete accepted")
	}
	if _, err := f.service.Delete(ctx, DeleteInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: e.Revision}); err != nil {
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

func TestAllCalendarsWhenUnrestricted(t *testing.T) {
	f := setup(t)
	f.service.Allowed = nil
	ctx := context.Background()
	calendars, err := f.service.Calendars(ctx)
	if err != nil || len(calendars) != 1 || calendars[0].ID != "calendar1" {
		t.Fatal("unrestricted discovery failed", calendars, err)
	}
	if _, err := f.service.Create(ctx, createInput()); err != nil {
		t.Fatal("unrestricted create failed", err)
	}
	if _, err := f.service.Get(ctx, "calendar1", "event1"); err != nil {
		t.Fatal("unrestricted read failed", err)
	}
	if err := f.service.allowed("../calendar1"); err == nil {
		t.Fatal("unrestricted mode allowed path injection")
	}
	f.service.Allowed = map[string]bool{"other": true}
	calendars, err = f.service.Calendars(ctx)
	if err != nil || len(calendars) != 0 {
		t.Fatal("restricted discovery leaked a calendar", calendars, err)
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

func TestPaddedProtonIDs(t *testing.T) {
	f := setup(t)
	f.service.Allowed = nil
	calendarID := strings.Repeat("a", 86) + "=="
	eventID := strings.Repeat("b", 86) + "=="
	cursorID := strings.Repeat("c", 86) + "=="
	encode := strings.NewReplacer("calendar1", calendarID, "event1", eventID, "cursor1", cursorID)
	decode := strings.NewReplacer(calendarID, "calendar1", eventID, "event1", cursorID, "cursor1")
	http.DefaultTransport = transportFunc(func(r *http.Request) (*http.Response, error) {
		copy := r.Clone(r.Context())
		copy.URL.Path = decode.Replace(copy.URL.Path)
		copy.URL.RawPath = ""
		resp, err := f.respond(copy)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		body := encode.Replace(string(data))
		resp.Body = io.NopCloser(strings.NewReader(body))
		resp.ContentLength = int64(len(body))
		return resp, nil
	})
	ctx := context.Background()
	calendars, err := f.service.Calendars(ctx)
	if err != nil || len(calendars) != 1 || calendars[0].ID != calendarID {
		t.Fatal("padded calendar disappeared", calendars, err)
	}
	in := createInput()
	in.CalendarID = calendarID
	if _, err := f.service.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	event, err := f.service.Get(ctx, calendarID, eventID)
	if err != nil || event.ID != eventID {
		t.Fatal("padded event failed", event, err)
	}
	baseline, err := f.service.Changes(ctx, ChangesInput{CalendarID: calendarID})
	if err != nil || baseline.Cursor != cursorID {
		t.Fatal(baseline, err)
	}
	f.changes = map[string]any{"CalendarModelEventID": "cursor2", "CalendarEvents": []any{}}
	if _, err := f.service.Changes(ctx, ChangesInput{CalendarID: calendarID, Cursor: cursorID}); err != nil {
		t.Fatal(err)
	}
	f.service.Allowed = map[string]bool{calendarID: true}
	if calendars, err := f.service.Calendars(ctx); err != nil || len(calendars) != 1 {
		t.Fatal("padded allowlist failed", calendars, err)
	}
	f.service.Allowed = map[string]bool{"other": true}
	if calendars, err := f.service.Calendars(ctx); err != nil || len(calendars) != 0 {
		t.Fatal("allowlist leaked", calendars, err)
	}
}

func TestIDValidation(t *testing.T) {
	for _, id := range []string{"calendar1", "abc=", "abc==", "ab-_=="} {
		if !ValidID(id) {
			t.Errorf("valid ID rejected: %q", id)
		}
	}
	for _, id := range []string{"", "=", "abc===", "a=b", "../abc", "a/b", "a?b", "a#b", "a%2fb", "a\nb", strings.Repeat("a", 513)} {
		if ValidID(id) {
			t.Errorf("unsafe ID accepted: %q", id)
		}
	}
}

func TestDeleteWeekdayOccurrencesPreservesFriday(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := createInput()
	in.Title = "Daily"
	in.Start, in.End = "2026-10-12T19:00:00+03:00", "2026-10-12T19:15:00+03:00"
	in.RecurrenceRule = "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR"
	if _, err := f.service.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	original, err := f.service.Get(ctx, "calendar1", "event1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Delete(ctx, DeleteInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: original.Revision}); err == nil {
		t.Fatal("series deleted without occurrence")
	}
	for _, day := range []string{"12", "13", "14", "15"} {
		current, err := f.service.Get(ctx, "calendar1", "event1")
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.service.Delete(ctx, DeleteInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: current.Revision, Occurrence: "2026-10-" + day + "T19:00:00+03:00"})
		if err != nil {
			t.Fatal(day, err)
		}
	}
	result, err := f.service.List(ctx, ListInput{CalendarID: "calendar1", Start: "2026-10-12T00:00:00+03:00", End: "2026-10-19T00:00:00+03:00"})
	if err != nil || len(result.Events) != 1 || result.Events[0].Start != "2026-10-16T19:00:00+03:00" {
		t.Fatal(result, err)
	}
	next, err := f.service.List(ctx, ListInput{CalendarID: "calendar1", Start: "2026-10-19T00:00:00+03:00", End: "2026-10-26T00:00:00+02:00"})
	if err != nil || len(next.Events) != 5 {
		t.Fatal("future week changed", next, err)
	}
	current, err := f.service.Get(ctx, "calendar1", "event1")
	if err != nil {
		t.Fatal(err)
	}
	if current.RecurrenceRule != original.RecurrenceRule || current.Title != original.Title || current.Description != original.Description || !current.Verified {
		t.Fatal("series metadata or signatures lost", current)
	}
	before := f.writes
	for _, bad := range []DeleteInput{
		{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: original.Revision, Occurrence: "2026-10-16T19:00:00+03:00"},
		{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: current.Revision, Occurrence: "2026-10-17T19:00:00+03:00"},
		{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: current.Revision, Occurrence: "2026-10-16T19:05:00+03:00"},
		{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: current.Revision, Occurrence: "2026-10-12T19:00:00+03:00"},
	} {
		if _, err := f.service.Delete(ctx, bad); err == nil {
			t.Fatal("invalid occurrence/revision accepted")
		}
	}
	if f.writes != before {
		t.Fatal("unsafe mutation")
	}
}

func TestDeleteOccurrenceAcrossDSTAndAllDay(t *testing.T) {
	for _, allDay := range []bool{false, true} {
		t.Run(strconv.FormatBool(allDay), func(t *testing.T) {
			f := setup(t)
			ctx := context.Background()
			in := createInput()
			in.Start, in.End = "2026-10-24T19:00:00+03:00", "2026-10-24T19:15:00+03:00"
			in.AllDay = allDay
			if allDay {
				in.Start, in.End = "2026-10-24", "2026-10-25"
			}
			in.RecurrenceRule = "FREQ=DAILY;COUNT=3"
			if _, err := f.service.Create(ctx, in); err != nil {
				t.Fatal(err)
			}
			query := ListInput{CalendarID: "calendar1", Start: "2026-10-24T00:00:00+03:00", End: "2026-10-27T00:00:00+02:00"}
			before, err := f.service.List(ctx, query)
			if err != nil || len(before.Events) != 3 {
				t.Fatal(before, err)
			}
			e, err := f.service.Get(ctx, "calendar1", "event1")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.service.Delete(ctx, DeleteInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: e.Revision, Occurrence: before.Events[1].Occurrence}); err != nil {
				t.Fatal(err)
			}
			after, err := f.service.List(ctx, query)
			if err != nil || len(after.Events) != 2 || after.Events[0].Start != before.Events[0].Start || after.Events[1].Start != before.Events[2].Start {
				t.Fatal(after, err)
			}
		})
	}
}

func TestDeleteEditedOccurrenceRefused(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := createInput()
	in.RecurrenceRule = "FREQ=DAILY;COUNT=3"
	if _, err := f.service.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	ck, err := f.service.Client.UnlockCalendar(ctx, "calendar1")
	if err != nil {
		t.Fatal(err)
	}
	defer ck.Close()
	e, err := f.service.open(f.raw, ck)
	if err != nil {
		t.Fatal(err)
	}
	e.shared[0].Props.Del("RRULE")
	at, err := time.Parse(time.RFC3339, in.Start)
	if err != nil {
		t.Fatal(err)
	}
	e.shared[0].Props.SetDateTime("RECURRENCE-ID", at.UTC())
	a, err := renderCard(e.shared[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderCard(e.shared[1])
	if err != nil {
		t.Fatal(err)
	}
	cards, _, err := proton.MakeCards(a, b, ck.Encrypt, ck.Address.Write, ck.Calendar, f.raw.SharedKeyPacket)
	if err != nil {
		t.Fatal(err)
	}
	override := f.raw
	override.ID = "override1"
	override.SharedEvents = cards
	f.series = []RawEvent{f.raw, override}
	before := f.writes
	_, err = f.service.Delete(ctx, DeleteInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: e.event.Revision, Occurrence: in.Start})
	if err == nil || !strings.Contains(err.Error(), "edited separately") {
		t.Fatal(err)
	}
	if f.writes != before {
		t.Fatal("override deletion submitted a partial write")
	}
}

func TestPersonalOrganizerMetadataAllowsOccurrenceDeletion(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	in := createInput()
	in.RecurrenceRule = "FREQ=DAILY;COUNT=3"
	if _, err := f.service.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	ck, err := f.service.Client.UnlockCalendar(ctx, "calendar1")
	if err != nil {
		t.Fatal(err)
	}
	defer ck.Close()
	e, err := f.service.open(f.raw, ck)
	if err != nil {
		t.Fatal(err)
	}
	organizer := ical.NewProp("ORGANIZER")
	organizer.Value = "mailto:addr@example.test"
	e.shared[0].Props.Set(organizer)
	a, err := renderCard(e.shared[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := renderCard(e.shared[1])
	if err != nil {
		t.Fatal(err)
	}
	cards, _, err := proton.MakeCards(a, b, ck.Encrypt, ck.Address.Write, ck.Calendar, f.raw.SharedKeyPacket)
	if err != nil {
		t.Fatal(err)
	}
	f.raw.SharedEvents = cards
	current, err := f.service.Get(ctx, "calendar1", "event1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Delete(ctx, DeleteInput{CalendarID: "calendar1", EventID: "event1", ExpectedRevision: current.Revision, Occurrence: in.Start}); err != nil {
		t.Fatal(err)
	}
	updated, err := f.service.open(f.raw, ck)
	if err != nil {
		t.Fatal(err)
	}
	if prop(updated.model, "ORGANIZER") != organizer.Value {
		t.Fatal("organizer metadata lost")
	}
	events, err := f.service.List(ctx, ListInput{CalendarID: "calendar1", Start: "2026-10-12T00:00:00+03:00", End: "2026-10-15T00:00:00+03:00"})
	if err != nil || len(events.Events) != 2 || events.Events[0].Start != "2026-10-13T10:00:00+03:00" {
		t.Fatal(events, err)
	}
}

func TestParticipantMutationGuard(t *testing.T) {
	for _, kind := range []string{"not-owner", "invite", "attendee-card", "attendee-info", "more-attendees", "signed-attendee", "unverified"} {
		t.Run(kind, func(t *testing.T) {
			e := opened{event: Event{Verified: true}, raw: RawEvent{IsOrganizer: 1}, model: component()}
			switch kind {
			case "not-owner":
				e.raw.IsOrganizer = 0
			case "invite":
				e.raw.IsProtonProtonInvite = 1
			case "attendee-card":
				e.raw.AttendeesEvents = []proton.Card{{Type: 2}}
			case "attendee-info":
				e.raw.AttendeesInfo.Attendees = []json.RawMessage{json.RawMessage(`{}`)}
			case "more-attendees":
				e.raw.AttendeesInfo.MoreAttendees = 1
			case "signed-attendee":
				p := ical.NewProp("ATTENDEE")
				p.Value = "mailto:guest@example.test"
				e.model.Props.Add(p)
			case "unverified":
				e.event.Verified = false
			}
			if err := safeEdit(e); err == nil {
				t.Fatal("participant or unverified event accepted")
			}
		})
	}
}
