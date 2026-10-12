package calendar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/mail"
	"strings"
)

type CalendarMember struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	Permissions int    `json:"permissions"`
	Pending     bool   `json:"pending"`
}
type MembersResult struct {
	Members  []CalendarMember `json:"members"`
	Revision string           `json:"revision"`
}

func (s *Service) members(ctx context.Context, id string) (MembersResult, error) {
	if err := s.allowed(id); err != nil {
		return MembersResult{}, err
	}
	var members struct {
		Members []struct {
			ID, Email   string
			Permissions int
		}
	}
	var invites struct {
		Invitations []struct {
			CalendarInvitationID, Email string
			Permissions, Status         int
		}
	}
	if err := s.Client.Do(ctx, "GET", "/calendar/v1/"+id+"/members/all", nil, nil, &members); err != nil {
		return MembersResult{}, err
	}
	if err := s.Client.Do(ctx, "GET", "/calendar/v1/"+id+"/invitations", nil, nil, &invites); err != nil {
		return MembersResult{}, err
	}
	out := MembersResult{Members: []CalendarMember{}}
	for _, m := range members.Members {
		if !ValidID(m.ID) {
			return MembersResult{}, errors.New("invalid member identity")
		}
		out.Members = append(out.Members, CalendarMember{m.ID, m.Email, m.Permissions, false})
	}
	for _, i := range invites.Invitations {
		if !ValidID(i.CalendarInvitationID) {
			return MembersResult{}, errors.New("invalid invitation identity")
		}
		out.Members = append(out.Members, CalendarMember{i.CalendarInvitationID, i.Email, i.Permissions, true})
	}
	b, _ := json.Marshal(out.Members)
	sum := sha256.Sum256(b)
	out.Revision = hex.EncodeToString(sum[:])
	return out, nil
}
func (s *Service) CalendarMembers(ctx context.Context, in CalendarInput) (MembersResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.members(ctx, in.CalendarID)
}

type CalendarShareInput struct {
	CalendarID string `json:"calendar_id"`
	Email      string `json:"email"`
	Access     string `json:"access" jsonschema:"viewer or editor"`
}

func (s *Service) CalendarShare(ctx context.Context, in CalendarShareInput) (CalendarCreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return CalendarCreateResult{}, err
	}
	email, err := mail.ParseAddress(in.Email)
	if err != nil || email.Address != in.Email || strings.ContainsAny(in.Email, "\r\n") || len(in.Email) > 254 {
		return CalendarCreateResult{}, errors.New("provide one bare email address")
	}
	permissions, err := sharingPermissions(in.Access)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	defer ck.Close()
	if ck.Member.Permissions&3 == 0 {
		return CalendarCreateResult{}, errors.New("only calendar owners may grant access")
	}
	current, err := s.members(ctx, in.CalendarID)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	for _, m := range current.Members {
		if strings.EqualFold(m.Email, in.Email) {
			return CalendarCreateResult{}, errors.New("recipient is already a member or has an invitation; use calendar_access_update")
		}
	}
	if err := s.Client.ShareCalendar(ctx, in.CalendarID, in.Email, permissions, ck); err != nil {
		return CalendarCreateResult{}, err
	}
	return CalendarCreateResult{CalendarID: in.CalendarID}, nil
}
func sharingPermissions(access string) (int, error) {
	switch access {
	case "viewer":
		return 32 | 64, nil
	case "editor":
		return 32 | 16 | 64, nil
	}
	return 0, errors.New("access must be viewer or editor")
}

type CalendarAccessInput struct {
	CalendarID       string `json:"calendar_id"`
	MemberID         string `json:"member_id" jsonschema:"Member or pending invitation ID from calendar_members"`
	ExpectedRevision string `json:"expected_revision" jsonschema:"Revision from calendar_members"`
	Access           string `json:"access" jsonschema:"viewer, editor, or remove"`
}

func (s *Service) CalendarAccessUpdate(ctx context.Context, in CalendarAccessInput) (CalendarCreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidID(in.MemberID) {
		return CalendarCreateResult{}, errors.New("invalid member ID")
	}
	permissions, err := sharingPermissions(in.Access)
	if err != nil && in.Access != "remove" {
		return CalendarCreateResult{}, err
	}
	list, err := s.members(ctx, in.CalendarID)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	if in.ExpectedRevision == "" || in.ExpectedRevision != list.Revision {
		return CalendarCreateResult{}, errors.New("members changed; reread calendar_members")
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	defer ck.Close()
	if ck.Member.Permissions&3 == 0 {
		return CalendarCreateResult{}, errors.New("only calendar owners may change access")
	}
	for _, m := range list.Members {
		if m.ID != in.MemberID {
			continue
		}
		if m.Permissions&3 != 0 || m.ID == ck.Member.ID {
			return CalendarCreateResult{}, errors.New("owner/self access cannot be changed through this tool")
		}
		path := "/calendar/v1/" + in.CalendarID + "/members/" + m.ID
		if m.Pending {
			path = "/calendar/v1/" + in.CalendarID + "/invitations/" + m.ID
		}
		method := "PUT"
		var body any = map[string]any{"Permissions": permissions}
		if in.Access == "remove" {
			method = "DELETE"
			body = nil
		} else if !m.Pending {
			path += "/permission"
		}
		if err := s.Client.Do(ctx, method, path, nil, body, nil); err != nil {
			return CalendarCreateResult{}, err
		}
		return CalendarCreateResult{CalendarID: in.CalendarID}, nil
	}
	return CalendarCreateResult{}, errors.New("member not found")
}
