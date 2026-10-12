package calendar

import (
	"encoding/json"
	"errors"

	"proton-calendar-mcp/internal/proton"
)

// Silent occurrence edits retain existing guest cards, tokens and responses.
// This function never creates mail, cancellation content or attendee removals.
func preservedParticipants(e opened, ck *proton.CalendarKeys) (map[string]any, error) {
	if e.raw.AttendeesInfo.MoreAttendees != 0 {
		return nil, errors.New("incomplete guest list; silent occurrence deletion is not supported for this event")
	}
	if len(e.raw.AttendeesEvents) == 0 || len(e.raw.AttendeesInfo.Attendees) == 0 {
		return nil, errors.New("missing guest cards or metadata; refusing to rewrite participant event")
	}
	key, packet := ck.Calendar, e.raw.SharedKeyPacket
	if e.raw.AddressKeyPacket != "" {
		rings, ok := ck.Identity.Addresses[e.raw.AddressID]
		if !ok {
			return nil, errors.New("participant address key unavailable")
		}
		key, packet = rings.Read, e.raw.AddressKeyPacket
	}
	texts, verified, err := proton.OpenCards(e.raw.AttendeesEvents, packet, key, ck.Address.Verify)
	if err != nil || !verified {
		return nil, errors.New("guest cards could not be verified; refusing participant mutation")
	}
	tokens := map[string]bool{}
	for _, text := range texts {
		card, err := parseCard(text)
		if err != nil || prop(card, "UID") != e.event.UID {
			return nil, errors.New("guest card identity could not be verified")
		}
		for _, attendee := range card.Props.Values("ATTENDEE") {
			token := attendee.Params.Get("X-PM-TOKEN")
			if token == "" || tokens[token] {
				return nil, errors.New("missing or duplicate signed guest token")
			}
			tokens[token] = true
		}
	}
	if len(tokens) == 0 || len(tokens) != len(e.raw.AttendeesInfo.Attendees) {
		return nil, errors.New("guest cards contain no participants; refusing ambiguous mutation")
	}
	attendees := make([]map[string]any, 0, len(e.raw.AttendeesInfo.Attendees))
	seen := map[string]bool{}
	for _, raw := range e.raw.AttendeesInfo.Attendees {
		var a struct {
			Token   string
			Status  *int
			Comment json.RawMessage
		}
		if json.Unmarshal(raw, &a) != nil || a.Token == "" || len(a.Token) > 4096 || a.Status == nil || seen[a.Token] || !tokens[a.Token] {
			return nil, errors.New("invalid guest metadata; refusing participant mutation")
		}
		seen[a.Token] = true
		entry := map[string]any{"Token": a.Token, "Status": *a.Status}
		if len(a.Comment) > 0 {
			entry["Comment"] = a.Comment
		}
		attendees = append(attendees, entry)
	}
	return map[string]any{"AttendeesEventContent": e.raw.AttendeesEvents, "Attendees": attendees}, nil
}
