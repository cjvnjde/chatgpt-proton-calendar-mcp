package calendar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"proton-calendar-mcp/internal/vault"
	"regexp"
	"strings"

	"proton-calendar-mcp/internal/proton"
)

type CalendarInput struct {
	CalendarID string `json:"calendar_id"`
}

type Notification struct {
	Type    int    `json:"Type" jsonschema:"1 for a display reminder, 0 for email"`
	Trigger string `json:"Trigger" jsonschema:"Negative ISO 8601 duration before the event, such as -PT15M"`
}

type CalendarSettings struct {
	DefaultEventDuration        int            `json:"DefaultEventDuration"`
	DefaultPartDayNotifications []Notification `json:"DefaultPartDayNotifications"`
	DefaultFullDayNotifications []Notification `json:"DefaultFullDayNotifications"`
	MakesUserBusy               int            `json:"MakesUserBusy"`
}

type CalendarDetails struct {
	CalendarID string           `json:"calendar_id"`
	Member     proton.Member    `json:"membership"`
	Settings   CalendarSettings `json:"settings"`
	Revision   string           `json:"revision"`
}

func (s *Service) calendarDetails(ctx context.Context, id string) (CalendarDetails, error) {
	if err := s.allowed(id); err != nil {
		return CalendarDetails{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, id)
	if err != nil {
		return CalendarDetails{}, err
	}
	defer ck.Close()
	var settings CalendarSettings
	if len(ck.Settings) == 0 || string(ck.Settings) == "null" || json.Unmarshal(ck.Settings, &settings) != nil {
		return CalendarDetails{}, errors.New("calendar bootstrap omitted valid settings")
	}
	d := CalendarDetails{CalendarID: id, Member: ck.Member, Settings: settings}
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	d.Revision = hex.EncodeToString(sum[:])
	return d, nil
}

func (s *Service) CalendarGet(ctx context.Context, in CalendarInput) (CalendarDetails, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calendarDetails(ctx, in.CalendarID)
}

type CalendarUpdateInput struct {
	CalendarID       string  `json:"calendar_id"`
	ExpectedRevision string  `json:"expected_revision"`
	Name             *string `json:"name,omitempty"`
	Description      *string `json:"description,omitempty"`
	Color            *string `json:"color,omitempty"`
	Display          *bool   `json:"display,omitempty"`
}

var colorPattern = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

func (s *Service) CalendarUpdate(ctx context.Context, in CalendarUpdateInput) (CalendarDetails, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body := map[string]any{}
	for name, value := range map[string]*string{"Name": in.Name, "Description": in.Description, "Color": in.Color} {
		if value == nil {
			continue
		}
		if err := validateString(*value, 1024); err != nil {
			return CalendarDetails{}, err
		}
		if name == "Name" && (strings.TrimSpace(*value) == "" || len(*value) > 100) {
			return CalendarDetails{}, errors.New("calendar name must contain 1-100 bytes")
		}
		if name == "Color" && !colorPattern.MatchString(*value) {
			return CalendarDetails{}, errors.New("color must be #RRGGBB")
		}
		body[name] = *value
	}
	if in.Display != nil {
		body["Display"] = bit(*in.Display)
	}
	if len(body) == 0 {
		return CalendarDetails{}, errors.New("no changes supplied")
	}
	d, err := s.calendarDetails(ctx, in.CalendarID)
	if err != nil {
		return CalendarDetails{}, err
	}
	if in.ExpectedRevision == "" || in.ExpectedRevision != d.Revision {
		return CalendarDetails{}, errors.New("calendar changed; read calendar_get again")
	}
	if !ValidID(d.Member.ID) {
		return CalendarDetails{}, errors.New("invalid membership identity")
	}
	if err := s.Client.Do(ctx, "PUT", "/calendar/v1/"+in.CalendarID+"/members/"+d.Member.ID, nil, body, nil); err != nil {
		return CalendarDetails{}, err
	}
	updated, err := s.calendarDetails(ctx, in.CalendarID)
	if err != nil {
		return CalendarDetails{}, fmt.Errorf("calendar update was acknowledged but rereading failed; inspect the calendar before retrying: %w", err)
	}
	return updated, nil
}

type CalendarSettingsInput struct {
	CalendarID       string          `json:"calendar_id"`
	ExpectedRevision string          `json:"expected_revision"`
	Duration         *int            `json:"default_duration_minutes,omitempty"`
	TimedReminders   *[]Notification `json:"timed_reminders,omitempty"`
	AllDayReminders  *[]Notification `json:"all_day_reminders,omitempty"`
	Busy             *bool           `json:"shows_as_busy,omitempty"`
}

// Bound trigger syntax before interpreting it; no user data becomes an endpoint.
var triggerPattern = regexp.MustCompile(`^-P(?:(?:[0-9]{1,3})D)?(?:T(?:(?:[0-9]{1,3})H)?(?:(?:[0-9]{1,5})M)?)?$`)

func validateNotifications(ns []Notification) error {
	if len(ns) > 5 {
		return errors.New("at most five reminders are allowed")
	}
	for _, n := range ns {
		if (n.Type != 1 && n.Type != 0) || !triggerPattern.MatchString(n.Trigger) || n.Trigger == "-P" || n.Trigger == "-PT" || strings.HasSuffix(n.Trigger, "T") {
			return errors.New("invalid reminder type or trigger")
		}
	}
	return nil
}

func (s *Service) CalendarSettingsUpdate(ctx context.Context, in CalendarSettingsInput) (CalendarDetails, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body := map[string]any{}
	if in.Duration != nil {
		if *in.Duration < 1 || *in.Duration > 1440 {
			return CalendarDetails{}, errors.New("duration must be 1-1440 minutes")
		}
		body["DefaultEventDuration"] = *in.Duration
	}
	if in.Busy != nil {
		body["MakesUserBusy"] = bit(*in.Busy)
	}
	for name, ns := range map[string]*[]Notification{"DefaultPartDayNotifications": in.TimedReminders, "DefaultFullDayNotifications": in.AllDayReminders} {
		if ns == nil {
			continue
		}
		if err := validateNotifications(*ns); err != nil {
			return CalendarDetails{}, err
		}
		values := *ns
		if values == nil {
			values = []Notification{}
		}
		body[name] = values
	}
	if len(body) == 0 {
		return CalendarDetails{}, errors.New("no changes supplied")
	}
	d, err := s.calendarDetails(ctx, in.CalendarID)
	if err != nil {
		return CalendarDetails{}, err
	}
	if in.ExpectedRevision == "" || in.ExpectedRevision != d.Revision {
		return CalendarDetails{}, errors.New("calendar changed; read calendar_get again")
	}
	if err := s.Client.Do(ctx, "PUT", "/calendar/v1/"+in.CalendarID+"/settings", nil, body, nil); err != nil {
		return CalendarDetails{}, err
	}
	updated, err := s.calendarDetails(ctx, in.CalendarID)
	if err != nil {
		return CalendarDetails{}, fmt.Errorf("calendar update was acknowledged but rereading failed; inspect the calendar before retrying: %w", err)
	}
	return updated, nil
}

func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}

type CalendarCreateInput struct {
	Name            string `json:"name"`
	Color           string `json:"color"`
	AddressID       string `json:"address_id" jsonschema:"Your sending address ID, from addresses_list"`
	RequestID       string `json:"request_id"`
	SubscriptionURL string `json:"subscription_url,omitempty" jsonschema:"Optional public HTTPS ICS feed that Proton will fetch"`
}

type CalendarCreateResult struct {
	CalendarID string `json:"calendar_id"`
	Replayed   bool   `json:"replayed"`
}

func (s *Service) CalendarCreate(ctx context.Context, in CalendarCreateInput) (CalendarCreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// A fixed allowlist cannot authorize a calendar which does not yet exist.
	if len(s.Allowed) > 0 {
		return CalendarCreateResult{}, errors.New("calendar creation requires unrestricted PROTON_CALENDAR_IDS; a fixed allowlist cannot authorize a new calendar")
	}
	if !requestIDPattern.MatchString(in.RequestID) || !ValidID(in.AddressID) {
		return CalendarCreateResult{}, errors.New("invalid request or address ID")
	}
	if strings.TrimSpace(in.Name) == "" || validateString(in.Name, 100) != nil || !colorPattern.MatchString(in.Color) {
		return CalendarCreateResult{}, errors.New("provide a name of 1-100 bytes and a #RRGGBB color")
	}
	if in.SubscriptionURL != "" {
		u, err := url.Parse(in.SubscriptionURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || len(in.SubscriptionURL) > 4096 {
			return CalendarCreateResult{}, errors.New("subscription URL must be an absolute HTTPS feed URL without credentials or fragment")
		}
	}
	b, _ := json.Marshal(in)
	sum := sha256.Sum256(b)
	fp := hex.EncodeToString(sum[:])
	opID := "calendar-create/" + in.RequestID
	if old, ok := s.Client.Operation(opID); ok {
		if old.Fingerprint != fp {
			return CalendarCreateResult{}, errors.New("request_id already used with different arguments")
		}
		if old.EventID != "" {
			return CalendarCreateResult{old.EventID, true}, nil
		}
		return CalendarCreateResult{}, fmt.Errorf("previous calendar creation is incomplete or uncertain; inspect Proton Calendar before retrying (known calendar ID: %s)", old.CalendarID)
	}
	identity, err := s.Client.UnlockIdentity(ctx)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	defer identity.Close()
	address, ok := identity.Addresses[in.AddressID]
	if !ok || address.Write.CountEntities() == 0 {
		return CalendarCreateResult{}, errors.New("sending address unavailable")
	}
	setup, err := proton.CalendarSetup(address.Write, in.AddressID)
	if err != nil {
		return CalendarCreateResult{}, errors.New("cannot prepare calendar keys")
	}
	if in.SubscriptionURL != "" {
		var r struct{ ValidationResult struct{ Result *int } }
		if err := s.Client.Do(ctx, "POST", "/calendar/v1/subscription/validate", nil, map[string]any{"URL": in.SubscriptionURL, "Mode": 0}, &r); err != nil {
			return CalendarCreateResult{}, err
		}
		if r.ValidationResult.Result == nil || *r.ValidationResult.Result != 0 {
			return CalendarCreateResult{}, errors.New("Proton could not validate the subscription feed")
		}
	}
	op := vault.Operation{Fingerprint: fp}
	if err := s.Client.SaveOperation(opID, op); err != nil {
		return CalendarCreateResult{}, err
	}
	body := map[string]any{"Name": in.Name, "Color": in.Color, "Display": 1, "AddressID": in.AddressID}
	if in.SubscriptionURL != "" {
		body["URL"] = in.SubscriptionURL
	}
	var r struct{ Calendar struct{ ID string } }
	if err := s.Client.Do(ctx, "POST", "/calendar/v1", nil, body, &r); err != nil {
		return CalendarCreateResult{}, err
	}
	if !ValidID(r.Calendar.ID) {
		return CalendarCreateResult{}, errors.New("calendar creation returned no valid ID; inspect Proton Calendar")
	}
	op.CalendarID = r.Calendar.ID
	if err := s.Client.SaveOperation(opID, op); err != nil {
		return CalendarCreateResult{}, err
	}
	if err := s.Client.Do(ctx, "POST", "/calendar/v1/"+r.Calendar.ID+"/keys", nil, setup, nil); err != nil {
		return CalendarCreateResult{}, fmt.Errorf("calendar %s was created but key setup was not acknowledged; inspect it in Proton Calendar: %w", r.Calendar.ID, err)
	}
	op.EventID = r.Calendar.ID
	if err := s.Client.SaveOperation(opID, op); err != nil {
		return CalendarCreateResult{}, err
	}
	return CalendarCreateResult{r.Calendar.ID, false}, nil
}

type AddressInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

func (s *Service) Addresses(ctx context.Context) ([]AddressInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r struct{ Addresses []proton.Address }
	if err := s.Client.Do(ctx, "GET", "/core/v4/addresses", nil, nil, &r); err != nil {
		return nil, err
	}
	out := []AddressInfo{}
	for _, a := range r.Addresses {
		if !ValidID(a.ID) {
			return nil, errors.New("invalid address ID")
		}
		out = append(out, AddressInfo{a.ID, a.Email})
	}
	return out, nil
}

type CalendarDeleteInput struct {
	CalendarID       string `json:"calendar_id"`
	ExpectedRevision string `json:"expected_revision"`
	ConfirmName      string `json:"confirm_name" jsonschema:"Exact calendar name from calendar_get, to confirm deletion of the calendar and every event"`
}

func (s *Service) CalendarDelete(ctx context.Context, in CalendarDeleteInput) (CalendarCreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, err := s.calendarDetails(ctx, in.CalendarID)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	if in.ExpectedRevision == "" || d.Revision != in.ExpectedRevision || d.Member.Name != in.ConfirmName {
		return CalendarCreateResult{}, errors.New("calendar name or revision changed; reread calendar_get")
	}
	if d.Member.Permissions&1 == 0 {
		return CalendarCreateResult{}, errors.New("only the calendar owner may delete it")
	}
	if err := s.Client.Do(ctx, "DELETE", "/calendar/v1/"+in.CalendarID, nil, nil, nil); err != nil {
		return CalendarCreateResult{}, err
	}
	return CalendarCreateResult{CalendarID: in.CalendarID}, nil
}
