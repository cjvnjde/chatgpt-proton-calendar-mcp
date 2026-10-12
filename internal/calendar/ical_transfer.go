package calendar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"proton-calendar-mcp/internal/vault"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
)

type ExportInput struct {
	CalendarID string `json:"calendar_id"`
	EventID    string `json:"event_id"`
}
type ExportResult struct {
	ICS      string `json:"ics"`
	Verified bool   `json:"verified"`
}

func (s *Service) Export(ctx context.Context, in ExportInput) (ExportResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return ExportResult{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return ExportResult{}, err
	}
	defer ck.Close()
	raw, err := s.getRaw(ctx, in.CalendarID, in.EventID)
	if err != nil {
		return ExportResult{}, err
	}
	e, err := s.open(raw, ck)
	if err != nil {
		return ExportResult{}, err
	}
	records := []opened{e}
	if prop(e.model, "RRULE") != "" || len(e.model.Props.Values("RDATE")) > 0 {
		records, err = s.loadSeries(ctx, e, ck)
		if err != nil {
			return ExportResult{}, err
		}
	}
	cal := ical.NewCalendar()
	cal.Props.SetText("VERSION", "2.0")
	cal.Props.SetText("PRODID", "-//proton-calendar-mcp//EN")
	verified := true
	for _, r := range records {
		verified = verified && r.event.Verified
		cal.Children = append(cal.Children, r.model)
	}
	var b strings.Builder
	if err := ical.NewEncoder(&b).Encode(cal); err != nil {
		return ExportResult{}, errors.New("cannot encode exported event")
	}
	return ExportResult{b.String(), verified}, nil
}

type ImportInput struct {
	CalendarID string `json:"calendar_id"`
	RequestID  string `json:"request_id" jsonschema:"Stable import request ID; reuse it with exactly the same ICS after a partial result"`
	ICS        string `json:"ics" jsonschema:"VCALENDAR document, at most 256 KiB and 100 personal VEVENTs. Guest invitations and recurrence exceptions are refused rather than discarded."`
}
type ImportResult struct {
	Events      []WriteResult `json:"events"`
	Complete    bool          `json:"complete"`
	FailedIndex *int          `json:"failed_index,omitempty"`
	Error       string        `json:"error,omitempty"`
}

// Parse and validate the entire document before any remote mutation. Individual
// creates use the existing persistent idempotency ledger, including uncertain writes.
func (s *Service) Import(ctx context.Context, in ImportInput) (ImportResult, error) {
	if err := s.allowed(in.CalendarID); err != nil {
		return ImportResult{}, err
	}
	if !requestIDPattern.MatchString(in.RequestID) {
		return ImportResult{}, errors.New("invalid request_id")
	}
	if err := validateString(in.ICS, 256<<10); err != nil {
		return ImportResult{}, err
	}
	if strings.Count(strings.ToUpper(in.ICS), "BEGIN:") > 201 {
		return ImportResult{}, errors.New("too many calendar components")
	}
	decoder := ical.NewDecoder(strings.NewReader(in.ICS))
	cal, err := decoder.Decode()
	if err != nil {
		return ImportResult{}, errors.New("invalid ICS document")
	}
	if _, err := decoder.Decode(); err != io.EOF {
		return ImportResult{}, errors.New("expected exactly one VCALENDAR")
	}
	if cal.Props.Get("METHOD") != nil {
		return ImportResult{}, errors.New("invitation messages cannot be imported as personal events")
	}
	if len(cal.Children) == 0 || len(cal.Children) > 100 {
		return ImportResult{}, errors.New("import requires 1-100 events")
	}
	inputs := []CreateInput{}
	for i, c := range cal.Children {
		if c.Name != "VEVENT" || len(c.Children) > 0 {
			return ImportResult{}, errors.New("only VEVENT records without nested components are supported by this import")
		}
		for name, properties := range c.Props {
			if len(properties) != 1 {
				return ImportResult{}, errors.New("duplicate ICS property: " + name)
			}
			switch name {
			case "UID", "DTSTAMP", "CREATED", "LAST-MODIFIED", "SEQUENCE", "DTSTART", "DTEND", "DURATION", "SUMMARY", "DESCRIPTION", "LOCATION", "RRULE", "STATUS":
			default:
				return ImportResult{}, errors.New("unsupported ICS property: " + name)
			}
		}
		if status := prop(c, "STATUS"); status != "" && status != "CONFIRMED" {
			return ImportResult{}, errors.New("only confirmed personal events can be imported")
		}
		a, b, all, err := span(c, s.Location)
		if err != nil {
			return ImportResult{}, err
		}
		title, err := text(c, "SUMMARY")
		if err != nil || strings.TrimSpace(title) == "" {
			return ImportResult{}, errors.New("imported event must have a title")
		}
		desc, err := text(c, "DESCRIPTION")
		if err != nil {
			return ImportResult{}, err
		}
		place, err := text(c, "LOCATION")
		if err != nil {
			return ImportResult{}, err
		}
		for _, v := range []string{title, desc, place} {
			if err := validateString(v, 32768); err != nil {
				return ImportResult{}, err
			}
		}
		format := time.RFC3339
		if all {
			format = "2006-01-02"
		}
		hash := sha256.Sum256([]byte(in.RequestID + "/" + strconv.Itoa(i)))
		input := CreateInput{CalendarID: in.CalendarID, RequestID: "import-" + hex.EncodeToString(hash[:]), Title: title, Description: desc, Location: place, Start: a.Format(format), End: b.Format(format), Timezone: a.Location().String(), AllDay: all, RecurrenceRule: prop(c, "RRULE")}
		if _, _, err := times(input.Start, input.End, input.Timezone, input.AllDay, s.Location); err != nil {
			return ImportResult{}, err
		}
		if len(input.RecurrenceRule) > 1024 {
			return ImportResult{}, errors.New("recurrence rule too long")
		}
		if _, err := recurrence(c, a, a.AddDate(1, 0, 0), s.Location); err != nil {
			return ImportResult{}, err
		}
		inputs = append(inputs, input)
	}
	// Bind the whole document, including event order and omitted properties, to
	// the import identity before any creates can be submitted.
	payload, _ := json.Marshal(in)
	digest := sha256.Sum256(payload)
	fingerprint := hex.EncodeToString(digest[:])
	s.mu.Lock()
	old, exists := s.Client.Operation("import-document/" + in.RequestID)
	if exists && old.Fingerprint != fingerprint {
		s.mu.Unlock()
		return ImportResult{}, errors.New("import request_id already used with a different document")
	}
	if !exists {
		if err := s.Client.SaveOperation("import-document/"+in.RequestID, vault.Operation{Fingerprint: fingerprint}); err != nil {
			s.mu.Unlock()
			return ImportResult{}, err
		}
	}
	s.mu.Unlock()
	out := ImportResult{Events: []WriteResult{}}
	for i, input := range inputs {
		result, err := s.Create(ctx, input)
		if err != nil {
			out.FailedIndex = &i
			out.Error = err.Error()
			return out, nil
		}
		out.Events = append(out.Events, result)
	}
	out.Complete = true
	return out, nil
}
