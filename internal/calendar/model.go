package calendar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	ical "github.com/emersion/go-ical"
	"github.com/teambition/rrule-go"
)

type Event struct {
	ID             string `json:"id"`
	CalendarID     string `json:"calendar_id"`
	UID            string `json:"uid"`
	Title          string `json:"title"`
	Description    string `json:"description,omitempty"`
	Location       string `json:"location,omitempty"`
	Start          string `json:"start"`
	End            string `json:"end"`
	AllDay         bool   `json:"all_day"`
	Timezone       string `json:"timezone"`
	RecurrenceRule string `json:"recurrence_rule,omitempty"`
	Occurrence     string `json:"occurrence,omitempty"`
	Status         string `json:"status,omitempty"`
	Verified       bool   `json:"verified"`
	Revision       string `json:"revision"`
}

func parseCard(text string) (*ical.Component, error) {
	if !utf8.ValidString(text) || len(text) > 256<<10 || strings.Count(strings.ToUpper(text), "BEGIN:") > 16 {
		return nil, errors.New("invalid event content")
	}
	d := ical.NewDecoder(strings.NewReader(text))
	cal, err := d.Decode()
	if err != nil {
		return nil, errors.New("cannot parse event content")
	}
	if _, err := d.Decode(); err != io.EOF {
		return nil, errors.New("event card must contain one calendar")
	}
	if len(cal.Children) != 1 || cal.Children[0].Name != "VEVENT" || len(cal.Children[0].Children) != 0 {
		return nil, errors.New("unexpected event card structure")
	}
	c := cal.Children[0]
	for name, props := range c.Props {
		if len(props) > 1 && name != "EXDATE" && name != "RDATE" && name != "ATTENDEE" {
			return nil, errors.New("duplicate event property")
		}
	}
	if prop(c, "UID") == "" {
		return nil, errors.New("event card has no UID")
	}
	return c, nil
}

func renderCard(c *ical.Component) (string, error) {
	cal := ical.NewCalendar()
	cal.Props.SetText("VERSION", "2.0")
	cal.Props.SetText("PRODID", "-//proton-calendar-mcp//EN")
	cal.Children = []*ical.Component{c}
	var b strings.Builder
	if err := ical.NewEncoder(&b).Encode(cal); err != nil {
		return "", errors.New("cannot render event content")
	}
	return b.String(), nil
}

func component() *ical.Component { return &ical.Component{Name: "VEVENT", Props: ical.Props{}} }
func prop(c *ical.Component, name string) string {
	p := c.Props.Get(name)
	if p == nil {
		return ""
	}
	return p.Value
}
func text(c *ical.Component, name string) (string, error) { return c.Props.Text(name) }

func merge(parts []*ical.Component) (*ical.Component, error) {
	out := component()
	uid := ""
	for _, c := range parts {
		if uid == "" {
			uid = prop(c, "UID")
		} else if uid != prop(c, "UID") {
			return nil, errors.New("event cards disagree about UID")
		}
		for name, ps := range c.Props {
			if old := out.Props.Get(name); old != nil && name != "EXDATE" && name != "ATTENDEE" {
				if name == "DTSTAMP" {
					if ps[0].Value > old.Value {
						out.Props[name] = ps
					}
					continue
				}
				if old.Value != ps[0].Value {
					return nil, errors.New("event cards contain conflicting properties")
				}
				continue
			}
			out.Props[name] = ps
		}
	}
	return out, nil
}

// Report the timezone or property without exposing event dates or content.
func eventDateTime(p *ical.Prop, loc *time.Location) (time.Time, error) {
	value, err := p.DateTime(loc)
	if err == nil {
		return value, nil
	}
	zone := p.Params.Get(ical.PropTimezoneID)
	if zone != "" && p.ValueType() != ical.ValueDate && !strings.HasSuffix(p.Value, "Z") {
		if _, zoneErr := time.LoadLocation(zone); zoneErr != nil {
			if len(zone) > 128 {
				return time.Time{}, errors.New("unsupported event timezone (identifier too long)")
			}
			return time.Time{}, fmt.Errorf("unsupported event timezone %q in %s", zone, p.Name)
		}
	}
	return time.Time{}, fmt.Errorf("invalid event date/time in %s", p.Name)
}

func span(c *ical.Component, loc *time.Location) (time.Time, time.Time, bool, error) {
	p := c.Props.Get("DTSTART")
	if p == nil {
		return time.Time{}, time.Time{}, false, errors.New("event has no start")
	}
	start, err := eventDateTime(p, loc)
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	allDay := p.ValueType() == ical.ValueDate
	var end time.Time
	if e := c.Props.Get("DTEND"); e != nil {
		if (e.ValueType() == ical.ValueDate) != allDay {
			return time.Time{}, time.Time{}, false, errors.New("event mixes dates and times")
		}
		end, err = eventDateTime(e, loc)
	} else if d := c.Props.Get("DURATION"); d != nil {
		var dur time.Duration
		dur, err = d.Duration()
		end = start.Add(dur)
	} else if allDay {
		end = start.AddDate(0, 0, 1)
	} else {
		end = start
	}
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	if end.Before(start) {
		return time.Time{}, time.Time{}, false, errors.New("invalid event duration")
	}
	return start, end, allDay, nil
}

func view(c *ical.Component, id, calendarID, revision string, verified bool, loc *time.Location) (Event, error) {
	s, e, all, err := span(c, loc)
	if err != nil {
		return Event{}, err
	}
	title, err := text(c, "SUMMARY")
	if err != nil {
		return Event{}, errors.New("invalid event title")
	}
	desc, err := text(c, "DESCRIPTION")
	if err != nil {
		return Event{}, errors.New("invalid event description")
	}
	place, err := text(c, "LOCATION")
	if err != nil {
		return Event{}, errors.New("invalid event location")
	}
	format := time.RFC3339
	if all {
		format = "2006-01-02"
	}
	return Event{ID: id, CalendarID: calendarID, UID: prop(c, "UID"), Title: title, Description: desc, Location: place,
		Start: s.Format(format), End: e.Format(format), AllDay: all, Timezone: s.Location().String(), RecurrenceRule: prop(c, "RRULE"),
		Status: prop(c, "STATUS"), Verified: verified, Revision: revision}, nil
}

func overlaps(s, e, from, to time.Time) bool {
	if s.Equal(e) {
		return !s.Before(from) && s.Before(to)
	}
	return s.Before(to) && e.After(from)
}

func dates(p ical.Prop, loc *time.Location) ([]time.Time, error) {
	if p.ValueType() == ical.ValuePeriod {
		return nil, errors.New("RDATE periods are not supported")
	}
	var out []time.Time
	for _, v := range strings.Split(p.Value, ",") {
		p.Value = v
		t, err := p.DateTime(loc)
		if err != nil {
			return nil, errors.New("invalid recurrence date")
		}
		out = append(out, t)
	}
	return out, nil
}

func recurrence(c *ical.Component, s, to time.Time, loc *time.Location) (*rrule.Set, error) {
	set := &rrule.Set{}
	set.RDate(s)
	if p := c.Props.Get("RRULE"); p != nil {
		opt, err := rrule.StrToROptionInLocation(p.Value, s.Location())
		if err != nil {
			return nil, errors.New("invalid recurrence rule")
		}
		// Avoid unbounded, dense or impossible searches inside the upstream
		// iterator. Complex rules fail explicitly instead of returning free time.
		if opt.Freq > rrule.DAILY || opt.Interval < 0 || opt.Interval > 1000 || opt.Count < 0 || opt.Count > 100000 {
			return nil, errors.New("recurrence exceeds supported bounds")
		}
		for _, x := range []string{"BYSECOND=", "BYMINUTE=", "BYHOUR="} {
			if strings.Contains(strings.ToUpper(p.Value), x) {
				return nil, errors.New("subdaily recurrence selectors are not supported")
			}
		}
		opt.Dtstart = s
		if opt.Until.IsZero() || opt.Until.After(to) {
			opt.Until = to
		}
		r, err := rrule.NewRRule(*opt)
		if err != nil {
			return nil, errors.New("invalid recurrence rule")
		}
		set.RRule(r)
	}
	for _, name := range []string{"EXDATE", "RDATE"} {
		for _, p := range c.Props.Values(name) {
			ds, err := dates(p, loc)
			if err != nil {
				return nil, err
			}
			for _, d := range ds {
				if name == "EXDATE" {
					set.ExDate(d)
				} else {
					set.RDate(d)
				}
			}
		}
	}
	return set, nil
}

// expand preserves recurrence exceptions and overlays separately stored edits.
// A query that exceeds a bound fails rather than silently losing occurrences.
func expand(ctx context.Context, stored []opened, from, to time.Time, loc *time.Location) ([]Event, error) {
	var result []Event
	overrides := map[string]bool{}
	for _, e := range stored {
		if p := e.model.Props.Get("RECURRENCE-ID"); p != nil {
			if p.Params.Get("RANGE") != "" {
				return nil, errors.New("RANGE recurrence overrides are not supported")
			}
			d, err := p.DateTime(loc)
			if err != nil {
				return nil, errors.New("invalid recurrence override")
			}
			overrides[prop(e.model, "UID")+"/"+d.UTC().Format(time.RFC3339)] = true
		}
	}
	for _, e := range stored {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s, end, all, err := span(e.model, loc)
		if err != nil {
			return nil, err
		}
		if prop(e.model, "RRULE") == "" && len(e.model.Props.Values("RDATE")) == 0 {
			if overlaps(s, end, from, to) {
				v := e.event
				if p := e.model.Props.Get("RECURRENCE-ID"); p != nil {
					d, _ := p.DateTime(loc)
					v.Occurrence = d.Format(time.RFC3339)
				}
				result = append(result, v)
			}
			continue
		}
		if s.Year() < 1900 {
			return nil, errors.New("recurrence starts before supported epoch")
		}
		set, err := recurrence(e.model, s, to, loc)
		if err != nil {
			return nil, err
		}
		next := set.Iterator()
		for n := 0; ; n++ {
			if n >= 100000 {
				return nil, errors.New("recurrence expansion limit exceeded")
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			d, ok := next()
			if !ok || !d.Before(to) {
				break
			}
			if overrides[prop(e.model, "UID")+"/"+d.UTC().Format(time.RFC3339)] {
				continue
			}
			finish := d.Add(end.Sub(s))
			if all {
				date := func(t time.Time) time.Time { y, m, d := t.Date(); return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }
				days := int(date(end).Sub(date(s)).Hours() / 24)
				finish = d.AddDate(0, 0, days)
			}
			if !overlaps(d, finish, from, to) {
				continue
			}
			v := e.event
			format := time.RFC3339
			if all {
				format = "2006-01-02"
			}
			v.Start, v.End = d.Format(format), finish.Format(format)
			v.Occurrence = d.Format(time.RFC3339)
			result = append(result, v)
		}
		if len(result) > 10000 {
			return nil, errors.New("event result limit exceeded; use a narrower range")
		}
	}
	sort.Slice(result, func(i, j int) bool {
		instant := func(e Event) time.Time {
			if e.AllDay {
				v, _ := time.ParseInLocation("2006-01-02", e.Start, loc)
				return v
			}
			v, _ := time.Parse(time.RFC3339, e.Start)
			return v
		}
		a, b := instant(result[i]), instant(result[j])
		if a.Equal(b) {
			return result[i].ID+result[i].Occurrence < result[j].ID+result[j].Occurrence
		}
		return a.Before(b)
	})
	return result, nil
}

func validateString(value string, max int) error {
	if !utf8.ValidString(value) || len(value) > max || strings.ContainsRune(value, 0) {
		return fmt.Errorf("text must be valid UTF-8 and at most %d bytes", max)
	}
	return nil
}
