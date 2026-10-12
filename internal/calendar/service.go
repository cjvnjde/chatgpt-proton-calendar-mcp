package calendar

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	ical "github.com/emersion/go-ical"
	"proton-calendar-mcp/internal/proton"
	"proton-calendar-mcp/internal/vault"
)

type Calendar struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Writable bool   `json:"writable"`
	Type     int    `json:"type"`
}
type Service struct {
	Client   *proton.Client
	Allowed  map[string]bool
	Location *time.Location
	mu       sync.Mutex
}

// Proton IDs are URL-safe base64 and may retain trailing padding.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+={0,2}$`)
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func ValidID(id string) bool { return len(id) <= 512 && idPattern.MatchString(id) }
func (s *Service) allowed(id string) error {
	if !ValidID(id) {
		return errors.New("invalid calendar ID")
	}
	if len(s.Allowed) > 0 && !s.Allowed[id] {
		return errors.New("calendar is not in the configured allowlist")
	}
	return nil
}

func Discover(ctx context.Context, c *proton.Client) ([]Calendar, error) {
	var r struct {
		Calendars []struct {
			ID      string
			Type    int
			Members []proton.Member
		}
	}
	if err := c.Do(ctx, "GET", "/calendar/v1", nil, nil, &r); err != nil {
		return nil, err
	}
	out := []Calendar{}
	for _, cal := range r.Calendars {
		if !ValidID(cal.ID) {
			return nil, errors.New("Proton returned an invalid calendar ID")
		}
		if len(cal.Members) == 0 {
			continue
		}
		m := cal.Members[0]
		out = append(out, Calendar{cal.ID, m.Name, cal.Type == 0 && m.Permissions&16 != 0, cal.Type})
	}
	return out, nil
}

func (s *Service) Calendars(ctx context.Context) ([]Calendar, error) {
	all, err := Discover(ctx, s.Client)
	if err != nil {
		return nil, err
	}
	out := []Calendar{}
	for _, c := range all {
		if s.allowed(c.ID) == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

type RawEvent struct {
	ID, CalendarID, UID                                             string
	IsOrganizer, Permissions                                        int
	SharedKeyPacket, CalendarKeyPacket, AddressKeyPacket, AddressID string
	SharedEvents, CalendarEvents, AttendeesEvents                   []proton.Card
	Notifications                                                   json.RawMessage
	Color                                                           json.RawMessage
	AttendeesInfo                                                   struct {
		Attendees     []json.RawMessage
		MoreAttendees int
	}
}

type opened struct {
	raw    RawEvent
	model  *ical.Component
	shared []*ical.Component
	event  Event
}

func revision(raw RawEvent) string {
	b, _ := json.Marshal(raw)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Service) open(raw RawEvent, ck *proton.CalendarKeys) (opened, error) {
	if !ValidID(raw.ID) {
		return opened{}, errors.New("Proton returned an invalid event ID")
	}
	decKR := ck.Calendar
	packet := raw.SharedKeyPacket
	if raw.AddressKeyPacket != "" {
		if r, ok := ck.Identity.Addresses[raw.AddressID]; ok {
			decKR = r.Read
			packet = raw.AddressKeyPacket
		} else {
			return opened{}, errors.New("invitation address key unavailable")
		}
	}
	texts, verified, err := proton.OpenCards(raw.SharedEvents, packet, decKR, ck.Address.Verify)
	if err != nil {
		return opened{}, err
	}
	shared := []*ical.Component{}
	for _, t := range texts {
		c, err := parseCard(t)
		if err != nil {
			return opened{}, err
		}
		shared = append(shared, c)
	}
	parts := append([]*ical.Component{}, shared...)
	if len(raw.CalendarEvents) > 0 {
		ts, v, err := proton.OpenCards(raw.CalendarEvents, raw.CalendarKeyPacket, ck.Calendar, ck.Address.Verify)
		if err != nil {
			return opened{}, err
		}
		verified = verified && v
		for _, t := range ts {
			c, err := parseCard(t)
			if err != nil {
				return opened{}, err
			}
			parts = append(parts, c)
		}
	}
	model, err := merge(parts)
	if err != nil {
		return opened{}, err
	}
	ev, err := view(model, raw.ID, raw.CalendarID, revision(raw), verified, s.Location)
	if err != nil {
		return opened{}, err
	}
	if raw.UID != "" && ev.UID != raw.UID {
		return opened{}, errors.New("event metadata disagrees with signed UID")
	}
	return opened{raw, model, shared, ev}, nil
}

func (s *Service) getRaw(ctx context.Context, cal, id string) (RawEvent, error) {
	if err := s.allowed(cal); err != nil {
		return RawEvent{}, err
	}
	if !ValidID(id) {
		return RawEvent{}, errors.New("invalid event ID")
	}
	var r struct{ Event RawEvent }
	err := s.Client.Do(ctx, "GET", "/calendar/v1/"+cal+"/events/"+id, nil, nil, &r)
	if err != nil {
		return RawEvent{}, err
	}
	if r.Event.ID != id || (r.Event.CalendarID != "" && r.Event.CalendarID != cal) {
		return RawEvent{}, errors.New("unexpected event identity")
	}
	r.Event.CalendarID = cal
	return r.Event, nil
}

func (s *Service) Get(ctx context.Context, cal, id string) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(cal); err != nil {
		return Event{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, cal)
	if err != nil {
		return Event{}, err
	}
	defer ck.Close()
	raw, err := s.getRaw(ctx, cal, id)
	if err != nil {
		return Event{}, err
	}
	e, err := s.open(raw, ck)
	return e.event, err
}

type ListInput struct {
	CalendarID string `json:"calendar_id" jsonschema:"Calendar ID from calendars_list"`
	Start      string `json:"start" jsonschema:"Inclusive RFC3339 start with UTC offset"`
	End        string `json:"end" jsonschema:"Exclusive RFC3339 end with UTC offset; at most 90 days after start"`
	Query      string `json:"query,omitempty" jsonschema:"Case-insensitive search in title description location UID and event ID"`
	Limit      int    `json:"limit,omitempty" jsonschema:"Page size 1-500; default 100"`
	Offset     int    `json:"offset,omitempty" jsonschema:"Offset into sorted matches; default 0"`
}
type ListResult struct {
	Events     []Event `json:"events"`
	Total      int     `json:"total"`
	HasMore    bool    `json:"has_more"`
	NextOffset int     `json:"next_offset"`
}

func (s *Service) List(ctx context.Context, in ListInput) (ListResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return ListResult{}, err
	}
	from, err := time.Parse(time.RFC3339, in.Start)
	if err != nil {
		return ListResult{}, errors.New("start must be RFC3339 with an offset")
	}
	to, err := time.Parse(time.RFC3339, in.End)
	if err != nil || !to.After(from) || to.Sub(from) > 90*24*time.Hour || from.Unix() < 86400 || to.Year() > 2200 {
		return ListResult{}, errors.New("invalid query range; use 1970-2200 and at most 90 days")
	}
	if in.Limit == 0 {
		in.Limit = 100
	}
	if in.Limit < 1 || in.Limit > 500 || in.Offset < 0 || in.Offset > 10000 {
		return ListResult{}, errors.New("invalid pagination")
	}
	if err := validateString(in.Query, 256); err != nil {
		return ListResult{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return ListResult{}, err
	}
	defer ck.Close()
	var events []opened
	seen := map[string]bool{}
	// Proton's endpoint answers four types (timed/all-day, starts/overlaps),
	// with month-sized windows. Padding covers all-day UTC metadata boundaries.
	for begin := from.Add(-24 * time.Hour); begin.Before(to.Add(24 * time.Hour)); {
		end := begin.Add(28 * 24 * time.Hour)
		if end.After(to.Add(24 * time.Hour)) {
			end = to.Add(24 * time.Hour)
		}
		for typ := 0; typ < 4; typ++ {
			for page := 0; ; page++ {
				if page >= 100 {
					return ListResult{}, errors.New("upstream pagination limit exceeded")
				}
				q := url.Values{"Start": {strconv.FormatInt(begin.Unix(), 10)}, "End": {strconv.FormatInt(end.Unix(), 10)}, "Timezone": {"UTC"}, "Type": {strconv.Itoa(typ)}, "Page": {strconv.Itoa(page)}, "PageSize": {"100"}}
				var r struct {
					Events []RawEvent
					More   int
				}
				if err := s.Client.Do(ctx, "GET", "/calendar/v1/"+in.CalendarID+"/events", q, nil, &r); err != nil {
					return ListResult{}, err
				}
				for _, raw := range r.Events {
					if seen[raw.ID] {
						continue
					}
					seen[raw.ID] = true
					if raw.CalendarID != "" && raw.CalendarID != in.CalendarID {
						return ListResult{}, errors.New("unexpected calendar identity")
					}
					raw.CalendarID = in.CalendarID
					e, err := s.open(raw, ck)
					if err != nil {
						return ListResult{}, err
					}
					events = append(events, e)
					if len(events) > 10000 {
						return ListResult{}, errors.New("upstream event limit exceeded")
					}
				}
				if len(r.Events) < 100 && r.More == 0 {
					break
				}
				if len(r.Events) == 0 {
					return ListResult{}, errors.New("upstream pagination did not advance")
				}
			}
		}
		begin = end
	}
	all, err := expand(ctx, events, from, to, s.Location)
	if err != nil {
		return ListResult{}, err
	}
	filtered := []Event{}
	q := strings.ToLower(in.Query)
	for _, e := range all {
		if q == "" || strings.Contains(strings.ToLower(e.Title+"\n"+e.Description+"\n"+e.Location+"\n"+e.UID+"\n"+e.ID), q) {
			filtered = append(filtered, e)
		}
	}
	total := len(filtered)
	offset := min(in.Offset, total)
	end := min(offset+in.Limit, total)
	return ListResult{filtered[offset:end], total, end < total, end}, nil
}

type CreateInput struct {
	CalendarID      string `json:"calendar_id"`
	RequestID       string `json:"request_id" jsonschema:"Unique stable request ID; reuse exactly the same ID and arguments on retries"`
	Title           string `json:"title"`
	Start           string `json:"start" jsonschema:"RFC3339 with offset, or YYYY-MM-DD for all-day"`
	End             string `json:"end" jsonschema:"Exclusive end, same date/time format as start"`
	Timezone        string `json:"timezone,omitempty" jsonschema:"IANA timezone for recurring local times; default configured timezone"`
	AllDay          bool   `json:"all_day,omitempty"`
	Description     string `json:"description,omitempty"`
	Location        string `json:"location,omitempty"`
	RecurrenceRule  string `json:"recurrence_rule,omitempty" jsonschema:"Optional RRULE, daily or less frequent"`
	ReminderMinutes []int  `json:"reminder_minutes,omitempty" jsonschema:"Optional display reminders before start, 0-40320 minutes; omitted uses calendar defaults"`
}
type WriteResult struct {
	ID         string `json:"id"`
	CalendarID string `json:"calendar_id"`
	UID        string `json:"uid,omitempty"`
	Replayed   bool   `json:"replayed"`
}

func times(start, end, zone string, all bool, fallback *time.Location) (time.Time, time.Time, error) {
	loc := fallback
	var err error
	if zone != "" {
		loc, err = time.LoadLocation(zone)
		if err != nil {
			return time.Time{}, time.Time{}, errors.New("invalid IANA timezone")
		}
	}
	var a, b time.Time
	if all {
		a, err = time.ParseInLocation("2006-01-02", start, loc)
		if err == nil {
			b, err = time.ParseInLocation("2006-01-02", end, loc)
		}
	} else {
		a, err = time.Parse(time.RFC3339, start)
		if err == nil {
			b, err = time.Parse(time.RFC3339, end)
		}
		a = a.In(loc)
		b = b.In(loc)
	}
	if err != nil || !b.After(a) || b.Sub(a) > 366*24*time.Hour || a.Year() < 1970 || b.Year() > 2200 {
		return time.Time{}, time.Time{}, errors.New("invalid start/end; end is exclusive and must be after start (duration at most 366 days)")
	}
	return a, b, nil
}

func setTimes(c *ical.Component, a, b time.Time, all bool) {
	if all {
		c.Props.SetDate("DTSTART", a)
		c.Props.SetDate("DTEND", b)
	} else {
		c.Props.SetDateTime("DTSTART", a)
		c.Props.SetDateTime("DTEND", b)
	}
	c.Props.Del("DURATION")
}

func reminders(in []int) (json.RawMessage, error) {
	if in == nil {
		return json.RawMessage("null"), nil
	}
	if len(in) > 5 {
		return nil, errors.New("at most five reminders are allowed")
	}
	out := []map[string]any{}
	for _, m := range in {
		if m < 0 || m > 40320 {
			return nil, errors.New("reminder must be 0-40320 minutes")
		}
		out = append(out, map[string]any{"Type": 1, "Trigger": "-PT" + strconv.Itoa(m) + "M"})
	}
	return json.Marshal(out)
}

func (s *Service) writable(ctx context.Context, id string, ck *proton.CalendarKeys) error {
	all, err := s.Calendars(ctx)
	if err != nil {
		return err
	}
	for _, cal := range all {
		if cal.ID == id {
			if cal.Type != 0 || ck.Member.Permissions&16 == 0 || ck.Member.Flags&1 == 0 || ck.Member.Flags&(32|64) != 0 {
				return errors.New("calendar is read-only or disabled")
			}
			if ck.Address.Write.CountEntities() == 0 || ck.Encrypt.CountEntities() == 0 {
				return errors.New("primary signing/encryption key unavailable")
			}
			return nil
		}
	}
	return errors.New("calendar no longer exists")
}

func (s *Service) sync(ctx context.Context, cal, member string, op map[string]any) (string, error) {
	var result struct {
		Responses []struct {
			Index    int
			Response struct {
				Code  int
				Event struct{ ID string }
			}
		}
	}
	err := s.Client.Do(ctx, "PUT", "/calendar/v1/"+cal+"/events/sync", nil, map[string]any{"MemberID": member, "Events": []any{op}}, &result)
	if err != nil {
		return "", err
	}
	if len(result.Responses) != 1 || result.Responses[0].Index != 0 {
		return "", errors.New("incomplete sync acknowledgement; inspect current state")
	}
	r := result.Responses[0].Response
	if r.Code != 1000 && r.Code != 1001 {
		return "", errors.New("Proton refused the event mutation")
	}
	id := r.Event.ID
	if _, deleting := op["Event"]; !deleting {
		return "", nil
	}
	if !ValidID(id) {
		return "", errors.New("missing event ID in sync acknowledgement; inspect current state")
	}
	return id, nil
}

func (s *Service) Create(ctx context.Context, in CreateInput) (WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return WriteResult{}, err
	}
	if !requestIDPattern.MatchString(in.RequestID) {
		return WriteResult{}, errors.New("request_id must be a unique 1-128 character identifier")
	}
	if strings.TrimSpace(in.Title) == "" {
		return WriteResult{}, errors.New("title is required")
	}
	for _, field := range []string{in.Title, in.Location, in.Description} {
		if err := validateString(field, 32768); err != nil {
			return WriteResult{}, err
		}
	}
	a, b, err := times(in.Start, in.End, in.Timezone, in.AllDay, s.Location)
	if err != nil {
		return WriteResult{}, err
	}
	signed := component()
	encrypted := component()
	personal := component()
	setTimes(signed, a, b, in.AllDay)
	if len(in.RecurrenceRule) > 1024 {
		return WriteResult{}, errors.New("recurrence rule too long")
	}
	if in.RecurrenceRule != "" {
		p := ical.NewProp("RRULE")
		p.Value = in.RecurrenceRule
		signed.Props.Set(p)
		if _, err := recurrence(signed, a, a.AddDate(1, 0, 0), s.Location); err != nil {
			return WriteResult{}, err
		}
	}
	notifications, err := reminders(in.ReminderMinutes)
	if err != nil {
		return WriteResult{}, err
	}
	fingerprintBytes, _ := json.Marshal(in)
	digest := sha256.Sum256(fingerprintBytes)
	fp := hex.EncodeToString(digest[:])
	opID := in.CalendarID + "/" + in.RequestID
	if old, ok := s.Client.Operation(opID); ok {
		if old.Fingerprint != fp {
			return WriteResult{}, errors.New("request_id was already used with different arguments")
		}
		if old.EventID != "" {
			return WriteResult{old.EventID, in.CalendarID, old.UID, true}, nil
		}
		// A pending write is never replayed automatically. The signed UID can
		// be searched through event_list to reconcile it without duplication.
		return WriteResult{}, errors.New("previous create outcome is unknown; find UID " + old.UID + " before attempting another create")
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return WriteResult{}, err
	}
	defer ck.Close()
	if err := s.writable(ctx, in.CalendarID, ck); err != nil {
		return WriteResult{}, err
	}
	uid := rand.Text() + "@proton-calendar-mcp"
	stamp := time.Now().UTC()
	for _, c := range []*ical.Component{signed, encrypted, personal} {
		c.Props.SetText("UID", uid)
		c.Props.SetDateTime("DTSTAMP", stamp)
	}
	sequence := ical.NewProp("SEQUENCE")
	sequence.Value = "0"
	signed.Props.Set(sequence)
	encrypted.Props.SetText("SUMMARY", in.Title)
	encrypted.Props.SetText("DESCRIPTION", in.Description)
	encrypted.Props.SetText("LOCATION", in.Location)
	personal.Props.SetText("STATUS", "CONFIRMED")
	signedText, err := renderCard(signed)
	if err != nil {
		return WriteResult{}, err
	}
	encryptedText, err := renderCard(encrypted)
	if err != nil {
		return WriteResult{}, err
	}
	cards, packet, err := proton.MakeCards(signedText, encryptedText, ck.Encrypt, ck.Address.Write, ck.Calendar, "")
	if err != nil {
		return WriteResult{}, errors.New("cannot encrypt/sign event")
	}
	personalText, err := renderCard(personal)
	if err != nil {
		return WriteResult{}, err
	}
	card, err := proton.SignCard(personalText, ck.Address.Write)
	if err != nil {
		return WriteResult{}, errors.New("cannot sign calendar part")
	}
	op := vault.Operation{Fingerprint: fp, UID: uid, CalendarID: in.CalendarID}
	if err := s.Client.SaveOperation(opID, op); err != nil {
		return WriteResult{}, err
	}
	object := map[string]any{"Permissions": 1, "IsOrganizer": 1, "SharedEventContent": cards, "SharedKeyPacket": packet, "CalendarEventContent": []proton.Card{card}, "Notifications": notifications, "Color": nil}
	id, err := s.sync(ctx, in.CalendarID, ck.Member.ID, map[string]any{"Overwrite": 0, "Event": object})
	if err != nil {
		return WriteResult{}, err
	}
	op.EventID = id
	if err := s.Client.SaveOperation(opID, op); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{id, in.CalendarID, uid, false}, nil
}

type UpdateInput struct {
	CalendarID       string  `json:"calendar_id"`
	EventID          string  `json:"event_id"`
	ExpectedRevision string  `json:"expected_revision" jsonschema:"Exact revision from event_get; refuses if event changed"`
	Title            *string `json:"title,omitempty"`
	Description      *string `json:"description,omitempty"`
	Location         *string `json:"location,omitempty"`
	Start            *string `json:"start,omitempty"`
	End              *string `json:"end,omitempty"`
	Timezone         string  `json:"timezone,omitempty"`
	ReminderMinutes  *[]int  `json:"reminder_minutes,omitempty"`
}

func safeEdit(e opened) error {
	if !e.event.Verified {
		return errors.New("event signature could not be verified; refusing mutation")
	}
	if e.raw.IsOrganizer != 1 || len(e.raw.AttendeesEvents) > 0 || len(e.raw.AttendeesInfo.Attendees) > 0 || e.raw.AttendeesInfo.MoreAttendees != 0 || prop(e.model, "ORGANIZER") != "" {
		return errors.New("invitation/participant event mutations are not supported; use Proton's UI")
	}
	return nil
}

func (s *Service) Update(ctx context.Context, in UpdateInput) (WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return WriteResult{}, err
	}
	if in.Title == nil && in.Description == nil && in.Location == nil && in.Start == nil && in.End == nil && in.ReminderMinutes == nil {
		return WriteResult{}, errors.New("no changes supplied")
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return WriteResult{}, err
	}
	defer ck.Close()
	if err := s.writable(ctx, in.CalendarID, ck); err != nil {
		return WriteResult{}, err
	}
	raw, err := s.getRaw(ctx, in.CalendarID, in.EventID)
	if err != nil {
		return WriteResult{}, err
	}
	e, err := s.open(raw, ck)
	if err != nil {
		return WriteResult{}, err
	}
	if in.ExpectedRevision == "" || e.event.Revision != in.ExpectedRevision {
		return WriteResult{}, errors.New("event changed; read it again before editing")
	}
	if err := safeEdit(e); err != nil {
		return WriteResult{}, err
	}
	if len(e.shared) != 2 || raw.SharedEvents[0].Type != 2 || raw.SharedEvents[1].Type != 3 {
		return WriteResult{}, errors.New("unsupported event card layout; refusing to rewrite it")
	}
	if in.Title != nil && strings.TrimSpace(*in.Title) == "" {
		return WriteResult{}, errors.New("title cannot be empty")
	}
	for name, p := range map[string]*string{"SUMMARY": in.Title, "DESCRIPTION": in.Description, "LOCATION": in.Location} {
		if p != nil {
			if err := validateString(*p, 32768); err != nil {
				return WriteResult{}, err
			}
			e.shared[1].Props.SetText(name, *p)
		}
	}
	if in.Start != nil || in.End != nil {
		// Rescheduling a series or an override requires Proton's occurrence
		// transaction machinery; never accidentally move all future meetings.
		if prop(e.model, "RRULE") != "" || prop(e.model, "RECURRENCE-ID") != "" {
			return WriteResult{}, errors.New("rescheduling recurring events is not yet supported")
		}
		start, end := e.event.Start, e.event.End
		if in.Start != nil {
			start = *in.Start
		}
		if in.End != nil {
			end = *in.End
		}
		zone := in.Timezone
		if zone == "" {
			zone = e.event.Timezone
		}
		a, b, err := times(start, end, zone, e.event.AllDay, s.Location)
		if err != nil {
			return WriteResult{}, err
		}
		setTimes(e.shared[0], a, b, e.event.AllDay)
	}
	return s.writeEdited(ctx, e, ck, in.ReminderMinutes)
}

// writeEdited preserves existing encrypted card layout and unrelated metadata.
func (s *Service) writeEdited(ctx context.Context, e opened, ck *proton.CalendarKeys, reminderMinutes *[]int) (WriteResult, error) {
	raw := e.raw
	if len(e.shared) != 2 || len(raw.SharedEvents) != 2 || raw.SharedEvents[0].Type != 2 || raw.SharedEvents[1].Type != 3 {
		return WriteResult{}, errors.New("unsupported event card layout; refusing to rewrite it")
	}
	seq, _ := strconv.Atoi(prop(e.shared[0], "SEQUENCE"))
	p := ical.NewProp("SEQUENCE")
	p.Value = strconv.Itoa(seq + 1)
	e.shared[0].Props.Set(p)
	now := time.Now().UTC()
	for _, part := range e.shared {
		part.Props.SetDateTime("DTSTAMP", now)
	}
	a, err := renderCard(e.shared[0])
	if err != nil {
		return WriteResult{}, err
	}
	b, err := renderCard(e.shared[1])
	if err != nil {
		return WriteResult{}, err
	}
	cards, _, err := proton.MakeCards(a, b, ck.Encrypt, ck.Address.Write, ck.Calendar, raw.SharedKeyPacket)
	if err != nil {
		return WriteResult{}, errors.New("cannot encrypt/sign update")
	}
	notifications := raw.Notifications
	if len(notifications) == 0 {
		notifications = json.RawMessage("null")
	}
	if reminderMinutes != nil {
		notifications, err = reminders(*reminderMinutes)
		if err != nil {
			return WriteResult{}, err
		}
	}
	color := raw.Color
	if len(color) == 0 {
		color = json.RawMessage("null")
	}
	object := map[string]any{"SharedEventContent": cards, "Notifications": notifications, "Color": color, "IsOrganizer": raw.IsOrganizer}
	id, err := s.sync(ctx, raw.CalendarID, ck.Member.ID, map[string]any{"ID": raw.ID, "Event": object})
	if err != nil {
		return WriteResult{}, err
	}
	if id != raw.ID {
		return WriteResult{}, errors.New("update acknowledged a different event; inspect current state")
	}
	return WriteResult{id, raw.CalendarID, e.event.UID, false}, nil
}

type DeleteInput struct {
	Occurrence       string `json:"occurrence,omitempty" jsonschema:"Exact occurrence value from event_list. Required for recurring series; deletes only that occurrence. Use the series event_id and its latest revision."`
	CalendarID       string `json:"calendar_id"`
	EventID          string `json:"event_id"`
	ExpectedRevision string `json:"expected_revision"`
}

func (s *Service) Delete(ctx context.Context, in DeleteInput) (WriteResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return WriteResult{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return WriteResult{}, err
	}
	defer ck.Close()
	if err := s.writable(ctx, in.CalendarID, ck); err != nil {
		return WriteResult{}, err
	}
	raw, err := s.getRaw(ctx, in.CalendarID, in.EventID)
	if err != nil {
		return WriteResult{}, err
	}
	e, err := s.open(raw, ck)
	if err != nil {
		return WriteResult{}, err
	}
	if in.ExpectedRevision == "" || e.event.Revision != in.ExpectedRevision {
		return WriteResult{}, errors.New("event changed; read it again before deleting")
	}
	if err := safeEdit(e); err != nil {
		return WriteResult{}, err
	}
	if in.Occurrence != "" {
		return s.deleteOccurrence(ctx, in, e, ck)
	}
	if prop(e.model, "RRULE") != "" || len(e.model.Props.Values("RDATE")) > 0 || prop(e.model, "RECURRENCE-ID") != "" {
		return WriteResult{}, errors.New("recurring-event deletion requires occurrence from event_list; whole-series deletion is not supported")
	}
	if _, err := s.sync(ctx, in.CalendarID, ck.Member.ID, map[string]any{"ID": in.EventID}); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{in.EventID, in.CalendarID, e.event.UID, false}, nil
}
