package calendar

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	ical "github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
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
	records, err := s.loadSeries(ctx, e, ck)
	if err != nil {
		return WriteResult{}, err
	}
	overrides := []opened{}
	for _, record := range records {
		if p := record.model.Props.Get("RECURRENCE-ID"); p != nil {
			original, _ := eventDateTime(p, s.Location)
			if original.Equal(at) {
				if record.raw.IsOrganizer != 1 {
					return WriteResult{}, errors.New("override is not owned by this organizer")
				}
				if hasParticipants(record) {
					if in.SendCancellationNotice == nil || *in.SendCancellationNotice {
						return WriteResult{}, errors.New("override has guests; explicitly set send_cancellation_notice=false")
					}
					if _, err := preservedParticipants(record, ck); err != nil {
						return WriteResult{}, err
					}
				}
				overrides = append(overrides, record)
			}
		}
	}
	// Check membership, including existing exclusions, using the same bounded
	// expansion as event_list. Do not reinterpret a date as another start time.
	instances, err := expand(ctx, []opened{e}, at, at.Add(time.Nanosecond), s.Location)
	if err != nil {
		return WriteResult{}, err
	}
	found := len(overrides) > 0
	for _, instance := range instances {
		original, parseErr := time.Parse(time.RFC3339, instance.Occurrence)
		if parseErr == nil && original.Equal(at) {
			found = true
		}
	}
	if !found {
		return WriteResult{}, errors.New("occurrence is not present in this series; relist events")
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
	object, err := s.editedObject(e, ck, nil)
	if err != nil {
		return WriteResult{}, err
	}
	ops := []map[string]any{{"ID": e.raw.ID, "Event": object}}
	for _, override := range overrides {
		ops = append(ops, map[string]any{"ID": override.raw.ID})
	}
	if _, err := s.syncBatch(ctx, in.CalendarID, ck.Member.ID, ops); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{e.raw.ID, in.CalendarID, e.event.UID, false}, nil
}

func (s *Service) loadSeries(ctx context.Context, master opened, ck *proton.CalendarKeys) ([]opened, error) {
	seen := map[string]bool{}
	found := false
	out := []opened{}
	for page := 0; page < 100; page++ {
		var r struct {
			Events []RawEvent
			More   int
		}
		q := url.Values{"UID": {master.event.UID}, "Page": {strconv.Itoa(page)}, "PageSize": {"100"}}
		if err := s.Client.Do(ctx, "GET", "/calendar/v1/events", q, nil, &r); err != nil {
			return nil, err
		}
		for _, raw := range r.Events {
			if !ValidID(raw.ID) || seen[raw.ID] {
				return nil, errors.New("series lookup did not advance")
			}
			seen[raw.ID] = true
			if raw.CalendarID == "" {
				return nil, errors.New("series lookup omitted calendar identity")
			}
			if raw.CalendarID != master.raw.CalendarID {
				continue
			}
			e, err := s.open(raw, ck)
			if err != nil {
				return nil, err
			}
			if !e.event.Verified || e.event.UID != master.event.UID {
				return nil, errors.New("unverified or mismatched series record")
			}
			if raw.ID == master.raw.ID {
				found = true
				if revision(raw) != master.event.Revision {
					return nil, errors.New("series changed; read it again before mutation")
				}
			} else {
				p := e.model.Props.Get("RECURRENCE-ID")
				if p == nil || p.Params.Get("RANGE") != "" {
					return nil, errors.New("ambiguous series or range override")
				}
				if _, err := eventDateTime(p, s.Location); err != nil {
					return nil, err
				}
			}
			out = append(out, e)
			if len(out) > 100 {
				return nil, errors.New("series exceeds 100-record transaction limit")
			}
		}
		if len(r.Events) < 100 && r.More == 0 {
			if !found {
				return nil, errors.New("series lookup omitted the master event")
			}
			return out, nil
		}
		if len(r.Events) == 0 {
			return nil, errors.New("series lookup did not advance")
		}
	}
	return nil, errors.New("series lookup exceeded pagination limit")
}

func (s *Service) deleteSeriesScope(ctx context.Context, in DeleteInput, e opened, ck *proton.CalendarKeys) (WriteResult, error) {
	if prop(e.model, "RECURRENCE-ID") != "" {
		return WriteResult{}, errors.New("use the master series event_id for all/future scope")
	}
	if in.Scope == "all" && in.Occurrence != "" {
		return WriteResult{}, errors.New("omit occurrence when deleting all events")
	}
	records, err := s.loadSeries(ctx, e, ck)
	if err != nil {
		return WriteResult{}, err
	}
	var cutoff time.Time
	if in.Scope == "future" {
		cutoff, err = time.Parse(time.RFC3339, in.Occurrence)
		if err != nil {
			return WriteResult{}, errors.New("future scope requires occurrence from event_list")
		}
		instances, err := expand(ctx, records, cutoff, cutoff.AddDate(0, 0, 1), s.Location)
		if err != nil {
			return WriteResult{}, err
		}
		found := false
		for _, x := range instances {
			at, _ := time.Parse(time.RFC3339, x.Occurrence)
			if at.Equal(cutoff) {
				found = true
			}
		}
		// A moved exception may no longer overlap its original time.
		for _, x := range records {
			if p := x.model.Props.Get("RECURRENCE-ID"); p != nil {
				at, _ := eventDateTime(p, s.Location)
				if at.Equal(cutoff) {
					found = true
				}
			}
		}
		if !found {
			return WriteResult{}, errors.New("occurrence not found; relist the series")
		}
	}
	ops := []map[string]any{}
	for _, record := range records {
		if record.raw.IsOrganizer != 1 {
			return WriteResult{}, errors.New("series includes an event you do not organize")
		}
		if hasParticipants(record) {
			if in.SendCancellationNotice == nil || *in.SendCancellationNotice {
				return WriteResult{}, errors.New("guest series requires explicit send_cancellation_notice=false")
			}
			if _, err := preservedParticipants(record, ck); err != nil {
				return WriteResult{}, err
			}
		}
		if in.Scope == "all" {
			ops = append(ops, map[string]any{"ID": record.raw.ID})
			continue
		}
		start, _, _, err := span(record.model, s.Location)
		if err != nil {
			return WriteResult{}, err
		}
		if p := record.model.Props.Get("RECURRENCE-ID"); p != nil {
			original, _ := eventDateTime(p, s.Location)
			if !original.Before(cutoff) {
				ops = append(ops, map[string]any{"ID": record.raw.ID})
			}
		} else if !start.Before(cutoff) {
			ops = append(ops, map[string]any{"ID": record.raw.ID})
		} else {
			if err := truncateRecurrence(record.shared[0], cutoff, s.Location); err != nil {
				return WriteResult{}, err
			}
			object, err := s.editedObject(record, ck, nil)
			if err != nil {
				return WriteResult{}, err
			}
			ops = append(ops, map[string]any{"ID": record.raw.ID, "Event": object})
		}
	}
	if _, err := s.syncBatch(ctx, in.CalendarID, ck.Member.ID, ops); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{in.EventID, in.CalendarID, e.event.UID, false}, nil
}

func truncateRecurrence(c *ical.Component, cutoff time.Time, loc *time.Location) error {
	start, _, all, err := span(c, loc)
	if err != nil {
		return err
	}
	if p := c.Props.Get("RRULE"); p != nil {
		opt, err := rrule.StrToROptionInLocation(p.Value, start.Location())
		if err != nil {
			return errors.New("invalid recurrence rule")
		}
		// Do not extend an already-ended COUNT/UNTIL rule when the selected future
		// date came from RDATE rather than the rule.
		if opt.Count > 0 {
			opt.Dtstart = start
			r, err := rrule.NewRRule(*opt)
			if err != nil {
				return err
			}
			next := r.Iterator()
			count := 0
			for i := 0; ; i++ {
				if i >= 100000 {
					return errors.New("recurrence truncation limit exceeded")
				}
				at, ok := next()
				if !ok || !at.Before(cutoff) {
					break
				}
				count++
			}
			if count == 0 {
				c.Props.Del("RRULE")
			} else {
				opt.Count = count
				p.Value = opt.RRuleString()
			}
		} else if opt.Until.IsZero() || !opt.Until.Before(cutoff) {
			fields := []string{}
			for _, f := range strings.Split(p.Value, ";") {
				if !strings.HasPrefix(strings.ToUpper(f), "UNTIL=") {
					fields = append(fields, f)
				}
			}
			until := cutoff.Add(-time.Second).UTC().Format("20060102T150405Z")
			if all {
				until = cutoff.In(start.Location()).AddDate(0, 0, -1).Format("20060102")
			}
			p.Value = strings.Join(append(fields, "UNTIL="+until), ";")
		}
	}
	for _, name := range []string{"EXDATE", "RDATE"} {
		kept := []ical.Prop{}
		for _, p := range c.Props.Values(name) {
			for _, v := range strings.Split(p.Value, ",") {
				q := p
				q.Value = v
				d, err := eventDateTime(&q, loc)
				if err != nil {
					return err
				}
				if d.Before(cutoff) {
					kept = append(kept, q)
				}
			}
		}
		c.Props.Del(name)
		for _, p := range kept {
			c.Props.Add(&p)
		}
	}
	return nil
}
