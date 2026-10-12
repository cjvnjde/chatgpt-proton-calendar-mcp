package calendar

import (
	"context"
	"errors"
)

type ChangesInput struct {
	CalendarID string `json:"calendar_id"`
	Cursor     string `json:"cursor,omitempty" jsonschema:"Cursor returned by a previous event_changes call; omit to start monitoring from now"`
}
type Change struct {
	EventID string `json:"event_id"`
	Action  string `json:"action"`
	Event   *Event `json:"event,omitempty"`
}
type ChangesResult struct {
	Cursor          string   `json:"cursor"`
	Changes         []Change `json:"changes"`
	HasMore         bool     `json:"has_more"`
	RefreshRequired bool     `json:"refresh_required"`
	Baseline        bool     `json:"baseline"`
}

// Changes uses Proton's model-event feed, not a time-window diff. A removed
// event is reported by ID, so leaving a date window never looks like deletion.
// Cursors are owned by the caller; reading one does not consume other clients'
// monitoring state. A reset is explicit and requires a fresh listing.
func (s *Service) Changes(ctx context.Context, in ChangesInput) (ChangesResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return ChangesResult{}, err
	}
	if in.Cursor == "" {
		var r struct{ CalendarModelEventID string }
		if err := s.Client.Do(ctx, "GET", "/calendar/v1/"+in.CalendarID+"/modelevents/latest", nil, nil, &r); err != nil {
			return ChangesResult{}, err
		}
		if !ValidID(r.CalendarModelEventID) {
			return ChangesResult{}, errors.New("invalid change-feed cursor")
		}
		return ChangesResult{Cursor: r.CalendarModelEventID, Changes: []Change{}, Baseline: true}, nil
	}
	if !ValidID(in.Cursor) {
		return ChangesResult{}, errors.New("invalid change-feed cursor")
	}
	var r struct {
		CalendarModelEventID string
		More, Refresh        int
		CalendarEvents       []struct {
			ID     string
			Action int
			Event  *RawEvent
		}
	}
	if err := s.Client.Do(ctx, "GET", "/calendar/v1/"+in.CalendarID+"/modelevents/"+in.Cursor, nil, nil, &r); err != nil {
		return ChangesResult{}, err
	}
	if !ValidID(r.CalendarModelEventID) {
		return ChangesResult{}, errors.New("invalid change-feed response cursor")
	}
	if r.More != 0 && r.CalendarModelEventID == in.Cursor {
		return ChangesResult{}, errors.New("change feed did not advance")
	}
	out := ChangesResult{Cursor: r.CalendarModelEventID, Changes: []Change{}, HasMore: r.More != 0, RefreshRequired: r.Refresh != 0}
	if out.RefreshRequired {
		return out, nil
	}
	if len(r.CalendarEvents) > 1000 {
		return ChangesResult{}, errors.New("change-feed page exceeds limit")
	}
	var hasContent bool
	for _, e := range r.CalendarEvents {
		if e.Action != 0 {
			hasContent = true
		}
	}
	var ckErr error
	if hasContent {
		ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
		ckErr = err
		if ckErr != nil {
			return ChangesResult{}, ckErr
		}
		defer ck.Close()
		for _, e := range r.CalendarEvents {
			if !ValidID(e.ID) {
				return ChangesResult{}, errors.New("invalid changed event ID")
			}
			if e.Action == 0 {
				out.Changes = append(out.Changes, Change{EventID: e.ID, Action: "deleted"})
				continue
			}
			if e.Action != 1 && e.Action != 2 && e.Action != 3 {
				return ChangesResult{}, errors.New("unknown change-feed action")
			}
			// Prefer the signed content as it was at the feed entry: fetching
			// current state could fail for an event deleted by a later entry.
			var raw RawEvent
			if e.Event != nil && len(e.Event.SharedEvents) > 0 {
				raw = *e.Event
				if raw.ID != e.ID || (raw.CalendarID != "" && raw.CalendarID != in.CalendarID) {
					return ChangesResult{}, errors.New("change feed event identity mismatch")
				}
				raw.CalendarID = in.CalendarID
			} else {
				var err error
				raw, err = s.getRaw(ctx, in.CalendarID, e.ID)
				if err != nil {
					return ChangesResult{}, err
				}
			}
			opened, err := s.open(raw, ck)
			if err != nil {
				return ChangesResult{}, err
			}
			action := "updated"
			if e.Action == 1 {
				action = "created"
			}
			out.Changes = append(out.Changes, Change{e.ID, action, &opened.event})
		}
	} else {
		for _, e := range r.CalendarEvents {
			if !ValidID(e.ID) {
				return ChangesResult{}, errors.New("invalid deleted event ID")
			}
			out.Changes = append(out.Changes, Change{EventID: e.ID, Action: "deleted"})
		}
	}
	return out, nil
}
