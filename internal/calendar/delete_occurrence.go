package calendar

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
	"proton-calendar-mcp/internal/proton"
)

func (s *Service) deleteOccurrence(ctx context.Context, in DeleteInput, e opened, ck *proton.CalendarKeys) (WriteResult, error) {
	if prop(e.model, "RECURRENCE-ID") != "" || (prop(e.model, "RRULE") == "" && len(e.model.Props.Values("RDATE")) == 0) {
		return WriteResult{}, errors.New("occurrence deletion requires the recurring series event_id")
	}
	start, _, allDay, err := span(e.model, s.Location)
	if err != nil {
		return WriteResult{}, err
	}
	at, err := time.Parse(time.RFC3339, in.Occurrence)
	if err != nil || at.Year() < 1970 || at.Year() > 2200 || at.Nanosecond() != 0 {
		return WriteResult{}, errors.New("occurrence must be the exact RFC3339 occurrence returned by event_list")
	}
	at = at.In(start.Location())
	// Check membership, including existing exclusions, using the same bounded
	// expansion as event_list. Do not reinterpret a date as another start time.
	instances, err := expand(ctx, []opened{e}, at, at.Add(time.Nanosecond), s.Location)
	if err != nil {
		return WriteResult{}, err
	}
	found := false
	for _, instance := range instances {
		original, parseErr := time.Parse(time.RFC3339, instance.Occurrence)
		if parseErr == nil && original.Equal(at) {
			found = true
		}
	}
	if !found {
		return WriteResult{}, errors.New("occurrence is not present in this series; relist events")
	}
	// Separately edited instances need a multi-record operation. Detect them
	// across the complete UID chain rather than silently leaving one visible.
	if err := s.checkOccurrenceOverrides(ctx, e, ck, at); err != nil {
		return WriteResult{}, err
	}
	if len(e.shared) != 2 {
		return WriteResult{}, errors.New("unsupported event card layout")
	}
	exdate := ical.NewProp("EXDATE")
	if allDay {
		exdate.SetDate(at)
	} else if strings.HasSuffix(e.model.Props.Get("DTSTART").Value, "Z") {
		exdate.SetDateTime(at.UTC())
	} else {
		exdate.Value = at.Format("20060102T150405")
		if zone := e.model.Props.Get("DTSTART").Params.Get("TZID"); zone != "" {
			exdate.Params.Set("TZID", zone)
		}
	}
	e.shared[0].Props.Add(exdate)
	return s.writeEdited(ctx, e, ck, nil)
}

func (s *Service) checkOccurrenceOverrides(ctx context.Context, master opened, ck *proton.CalendarKeys, at time.Time) error {
	seen := map[string]bool{}
	masterFound := false
	for page := 0; page < 100; page++ {
		var r struct {
			Events []RawEvent
			More   int
		}
		query := url.Values{"UID": {master.event.UID}, "Page": {strconv.Itoa(page)}, "PageSize": {"100"}}
		if err := s.Client.Do(ctx, "GET", "/calendar/v1/events", query, nil, &r); err != nil {
			return err
		}
		for _, raw := range r.Events {
			if seen[raw.ID] {
				return errors.New("series lookup did not advance")
			}
			seen[raw.ID] = true
			if raw.CalendarID == "" {
				return errors.New("series lookup omitted calendar identity")
			}
			if raw.CalendarID != master.raw.CalendarID {
				continue
			}
			if raw.ID == master.raw.ID {
				masterFound = true
				if revision(raw) != master.event.Revision {
					return errors.New("series changed; read it again before deleting")
				}
				continue
			}
			e, err := s.open(raw, ck)
			if err != nil {
				return err
			}
			if e.event.UID != master.event.UID {
				return errors.New("unexpected UID in series lookup")
			}
			p := e.model.Props.Get("RECURRENCE-ID")
			if p == nil {
				return errors.New("ambiguous series records; refusing occurrence deletion")
			}
			if !e.event.Verified || p.Params.Get("RANGE") != "" {
				return errors.New("unverified or range override prevents occurrence deletion")
			}
			original, err := eventDateTime(p, s.Location)
			if err != nil {
				return err
			}
			if original.Equal(at) {
				return errors.New("this occurrence was edited separately; deleting stored overrides is not yet supported")
			}
		}
		if len(r.Events) < 100 && r.More == 0 {
			if !masterFound {
				return errors.New("series lookup omitted the master event")
			}
			return nil
		}
		if len(r.Events) == 0 {
			return errors.New("series lookup did not advance")
		}
	}
	return errors.New("series lookup exceeded pagination limit")
}
