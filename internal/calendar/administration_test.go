package calendar

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	pgp "github.com/ProtonMail/gopenpgp/v3/crypto"
	"proton-calendar-mcp/internal/proton"
)

func interceptAPI(t *testing.T, f *fixture, handler func(*http.Request) (any, bool)) {
	t.Helper()
	http.DefaultTransport = transportFunc(func(req *http.Request) (*http.Response, error) {
		if !strings.HasPrefix(req.URL.String(), proton.BaseURL) || req.Header.Get("Authorization") != "Bearer token" {
			t.Fatal("unexpected outbound request")
		}
		value, ok := handler(req)
		if !ok {
			return f.respond(req)
		}
		b, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]any
		if err := json.Unmarshal(b, &fields); err != nil {
			t.Fatal(err)
		}
		fields["Code"] = 1000
		b, _ = json.Marshal(fields)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(b)))}, nil
	})
}
func requestBody(t *testing.T, r *http.Request) map[string]json.RawMessage {
	t.Helper()
	var b map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCalendarSettingsPartialUpdateAndGuards(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	settings := CalendarSettings{DefaultEventDuration: 30, MakesUserBusy: 1, DefaultPartDayNotifications: []Notification{{Type: 1, Trigger: "-PT15M"}}}
	writes := 0
	interceptAPI(t, f, func(req *http.Request) (any, bool) {
		if req.URL.Path == "/api/calendar/v2/calendar1/bootstrap" {
			f.bootstrap.(map[string]any)["CalendarSettings"] = settings
			return nil, false
		}
		if req.URL.Path != "/api/calendar/v1/calendar1/settings" {
			return nil, false
		}
		if req.Method == "PUT" {
			writes++
			body := requestBody(t, req)
			if len(body) != 1 {
				t.Fatal("unexpected changes", body)
			}
			if err := json.Unmarshal(body["DefaultEventDuration"], &settings.DefaultEventDuration); err != nil {
				t.Fatal(err)
			}
		}
		return map[string]any{"CalendarSettings": settings}, true
	})
	d, err := f.service.CalendarGet(ctx, CalendarInput{"calendar1"})
	if err != nil {
		t.Fatal(err)
	}
	duration := 45
	updated, err := f.service.CalendarSettingsUpdate(ctx, CalendarSettingsInput{CalendarID: "calendar1", ExpectedRevision: d.Revision, Duration: &duration})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Settings.DefaultEventDuration != 45 || updated.Settings.MakesUserBusy != 1 || len(updated.Settings.DefaultPartDayNotifications) != 1 || updated.Revision == d.Revision {
		t.Fatal(updated)
	}
	if _, err := f.service.CalendarSettingsUpdate(ctx, CalendarSettingsInput{CalendarID: "calendar1", ExpectedRevision: d.Revision, Duration: &duration}); err == nil {
		t.Fatal("stale revision accepted")
	}
	if _, err := f.service.CalendarGet(ctx, CalendarInput{"other"}); err == nil {
		t.Fatal("allowlist bypass")
	}
	if writes != 1 {
		t.Fatal("unexpected mutation", writes)
	}
	for _, n := range []Notification{{Type: 2, Trigger: "-PT15M"}, {Type: 1, Trigger: "-PT"}, {Type: 1, Trigger: "PT1H"}} {
		if validateNotifications([]Notification{n}) == nil {
			t.Fatal("invalid reminder", n)
		}
	}
	if validateNotifications([]Notification{{Type: 0, Trigger: "-PT15M"}}) != nil {
		t.Fatal("email reminder rejected")
	}
}

func TestCalendarCreateEncryptsKeysAndReplays(t *testing.T) {
	f := setup(t)
	f.service.Allowed = nil
	ctx := context.Background()
	posts := 0
	var keyBody map[string]json.RawMessage
	interceptAPI(t, f, func(req *http.Request) (any, bool) {
		switch {
		case req.URL.Path == "/api/calendar/v1" && req.Method == "POST":
			posts++
			body := requestBody(t, req)
			if string(body["Name"]) != `"New calendar"` {
				t.Fatal(body)
			}
			return map[string]any{"Calendar": map[string]any{"ID": "calendar2"}}, true
		case req.URL.Path == "/api/calendar/v1/calendar2/keys":
			posts++
			keyBody = requestBody(t, req)
			return map[string]any{}, true
		}
		return nil, false
	})
	in := CalendarCreateInput{Name: "New calendar", Color: "#112233", AddressID: "address1", RequestID: "new-cal"}
	result, err := f.service.CalendarCreate(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if result.CalendarID != "calendar2" || posts != 2 {
		t.Fatal(result, posts)
	}
	replay, err := f.service.CalendarCreate(ctx, in)
	if err != nil || !replay.Replayed || posts != 2 {
		t.Fatal("calendar duplicated", replay, err, posts)
	}
	in.Name = "Other"
	if _, err := f.service.CalendarCreate(ctx, in); err == nil {
		t.Fatal("request ID reused")
	}
	identity, err := f.service.Client.UnlockIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	var packet map[string]string
	json.Unmarshal(keyBody["Passphrase"], &packet)
	kp, _ := base64.StdEncoding.DecodeString(packet["KeyPacket"])
	dp, _ := base64.StdEncoding.DecodeString(packet["DataPacket"])
	d, err := proton.PGP.Decryption().DecryptionKeys(identity.Addresses["address1"].Read).New()
	if err != nil {
		t.Fatal(err)
	}
	pass, err := d.Decrypt(pgp.NewPGPSplitMessage(kp, dp).Bytes(), pgp.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	var private, sig string
	json.Unmarshal(keyBody["PrivateKey"], &private)
	json.Unmarshal(keyBody["Signature"], &sig)
	key, err := pgp.NewKeyFromArmored(private)
	if err != nil {
		t.Fatal(err)
	}
	unlocked, err := key.Unlock(pass.Bytes())
	if err != nil {
		t.Fatal("generated calendar key did not unlock", err)
	}
	defer unlocked.ClearPrivateParams()
	v, err := proton.PGP.Verify().VerificationKeys(identity.Addresses["address1"].Verify).Utf8().New()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := v.VerifyDetached(pass.Bytes(), []byte(sig), pgp.Armor)
	if err != nil || verified.SignatureError() != nil {
		t.Fatal("passphrase signature invalid", err)
	}
}

func TestSharingWrapsPassphraseKeyAndProtectsOwners(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	key, err := proton.PGP.KeyGeneration().AddUserId("Guest", "guest@example.test").New().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.ClearPrivateParams()
	public, err := key.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	armor, err := public.Armor()
	if err != nil {
		t.Fatal(err)
	}
	var shared map[string]json.RawMessage
	writes := 0
	interceptAPI(t, f, func(req *http.Request) (any, bool) {
		switch req.URL.Path {
		case "/api/core/v4/keys/all":
			return map[string]any{"Address": map[string]any{"Keys": []any{map[string]any{"PublicKey": armor, "Primary": 1, "Flags": 3}}}}, true
		case "/api/calendar/v1/calendar1/members/all":
			return map[string]any{"Members": []any{map[string]any{"ID": "member1", "Email": "addr@example.test", "Permissions": 31}}}, true
		case "/api/calendar/v1/calendar1/invitations":
			return map[string]any{"Invitations": []any{}}, true
		case "/api/calendar/v1/calendar1/members":
			writes++
			shared = requestBody(t, req)
			return map[string]any{}, true
		}
		return nil, false
	})
	if _, err := f.service.CalendarShare(ctx, CalendarShareInput{CalendarID: "calendar1", Email: "guest@example.test", Access: "editor"}); err != nil {
		t.Fatal(err)
	}
	var members []struct {
		Email, PassphraseKeyPacket string
		Permissions                int
	}
	json.Unmarshal(shared["Members"], &members)
	if len(members) != 1 || members[0].Permissions != 112 || writes != 1 {
		t.Fatal("wrong permission bundle", members)
	}
	ring, _ := pgp.NewKeyRing(key)
	d, _ := proton.PGP.Decryption().DecryptionKeys(ring).New()
	packet, _ := base64.StdEncoding.DecodeString(members[0].PassphraseKeyPacket)
	sk, err := d.DecryptSessionKey(packet)
	if err != nil {
		t.Fatal("recipient cannot decrypt sharing key", err)
	}
	defer sk.Clear()
	identity, err := f.service.Client.UnlockIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	v, err := proton.PGP.Verify().VerificationKeys(identity.Addresses["address1"].Verify).VerificationContext(pgp.NewVerificationContext("calendar.sharing.invite", true, 0)).New()
	if err != nil {
		t.Fatal(err)
	}
	var sig string
	json.Unmarshal(shared["Signature"], &sig)
	result, err := v.VerifyDetached(sk.Key, []byte(sig), pgp.Armor)
	if err != nil || result.SignatureError() != nil {
		t.Fatal("sharing context signature invalid", err)
	}
	list, err := f.service.CalendarMembers(ctx, CalendarInput{"calendar1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.CalendarAccessUpdate(ctx, CalendarAccessInput{CalendarID: "calendar1", MemberID: "member1", ExpectedRevision: list.Revision, Access: "remove"}); err == nil {
		t.Fatal("owner access removed")
	}
	if writes != 1 {
		t.Fatal("guard issued a write")
	}
}

func TestLimitedLinkRoundTripAndListingDoesNotRevealURL(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var stored rawLink
	deleted := false
	interceptAPI(t, f, func(req *http.Request) (any, bool) {
		if req.URL.Path == "/api/calendar/v1/calendar1/urls/link1" && req.Method == "DELETE" {
			deleted = true
			return map[string]any{}, true
		}
		if req.URL.Path != "/api/calendar/v1/calendar1/urls" {
			return nil, false
		}
		if req.Method == "POST" {
			body := requestBody(t, req)
			stored = rawLink{CalendarUrlID: "link1", CalendarID: "calendar1"}
			json.Unmarshal(body["EncryptedCacheKey"], &stored.EncryptedCacheKey)
			json.Unmarshal(body["EncryptedPurpose"], &stored.EncryptedPurpose)
			return map[string]any{"CalendarUrl": stored}, true
		}
		return map[string]any{"CalendarUrls": []rawLink{stored}}, true
	})
	made, err := f.service.PublicLinkCreate(ctx, LinkCreateInput{CalendarID: "calendar1", Name: "Availability", Access: "limited"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(made.URL, "CacheKey=") || strings.Contains(made.URL, "PassphraseKey=") {
		t.Fatal("wrong limited link", made)
	}
	listed, err := f.service.PublicLinks(ctx, CalendarInput{"calendar1"})
	if err != nil || len(listed.Links) != 1 || listed.Links[0].URL != "" || listed.Links[0].Name != "Availability" {
		t.Fatal(listed, err)
	}
	opened, err := f.service.PublicLinkGet(ctx, LinkInput{"calendar1", "link1"})
	if err != nil || opened.URL != made.URL {
		t.Fatal("link round trip", opened, err)
	}
	if _, err := f.service.PublicLinkDelete(ctx, LinkInput{"calendar1", "link1"}); err != nil || !deleted {
		t.Fatal("link not revoked", err)
	}
}

func TestSyncBatchRejectsIncompleteOrMixedAcknowledgements(t *testing.T) {
	for _, tc := range []struct {
		name      string
		responses []any
	}{
		{"missing", []any{map[string]any{"Index": 0, "Response": map[string]any{"Code": 1000}}}},
		{"duplicate", []any{map[string]any{"Index": 0, "Response": map[string]any{"Code": 1000}}, map[string]any{"Index": 0, "Response": map[string]any{"Code": 1000}}}},
		{"partially refused", []any{map[string]any{"Index": 0, "Response": map[string]any{"Code": 1000}}, map[string]any{"Index": 1, "Response": map[string]any{"Code": 2001}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			calls := 0
			interceptAPI(t, f, func(req *http.Request) (any, bool) {
				if req.URL.Path == "/api/calendar/v1/calendar1/events/sync" {
					calls++
					return map[string]any{"Responses": tc.responses}, true
				}
				return nil, false
			})
			if _, err := f.service.syncBatch(context.Background(), "calendar1", "member1", []map[string]any{{"ID": "event1"}, {"ID": "override1"}}); err == nil {
				t.Fatal("accepted bad acknowledgement")
			}
			if calls != 1 {
				t.Fatal("batch was retried")
			}
		})
	}
}
