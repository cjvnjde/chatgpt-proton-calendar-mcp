package calendar

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"proton-calendar-mcp/internal/proton"
)

type rawLink struct {
	CalendarUrlID, CalendarID, EncryptedCacheKey, EncryptedPurpose, EncryptedPassphrase string
	AccessLevel                                                                         int
	CreateTime                                                                          int64
}
type PublicLink struct {
	ID      string `json:"id"`
	Access  string `json:"access"`
	Name    string `json:"name"`
	Created int64  `json:"created"`
	URL     string `json:"url,omitempty"`
}
type PublicLinksResult struct {
	Links []PublicLink `json:"links"`
}

func (s *Service) rawLinks(ctx context.Context, id string) ([]rawLink, error) {
	if err := s.allowed(id); err != nil {
		return nil, err
	}
	var r struct{ CalendarUrls []rawLink }
	if err := s.Client.Do(ctx, "GET", "/calendar/v1/"+id+"/urls", nil, nil, &r); err != nil {
		return nil, err
	}
	for _, l := range r.CalendarUrls {
		if !ValidID(l.CalendarUrlID) || (l.CalendarID != "" && l.CalendarID != id) {
			return nil, errors.New("invalid public link identity")
		}
	}
	return r.CalendarUrls, nil
}
func linkView(raw rawLink, ck *proton.CalendarKeys) (PublicLink, error) {
	access := "limited"
	if raw.AccessLevel == 1 {
		access = "full"
	} else if raw.AccessLevel != 0 {
		return PublicLink{}, errors.New("unknown public link access level")
	}
	name := ""
	var err error
	if raw.EncryptedPurpose != "" {
		name, err = proton.OpenCalendarText(ck, raw.EncryptedPurpose)
		if err != nil {
			return PublicLink{}, err
		}
	}
	return PublicLink{ID: raw.CalendarUrlID, Access: access, Name: name, Created: raw.CreateTime}, nil
}
func (s *Service) PublicLinks(ctx context.Context, in CalendarInput) (PublicLinksResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	raws, err := s.rawLinks(ctx, in.CalendarID)
	if err != nil {
		return PublicLinksResult{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return PublicLinksResult{}, err
	}
	defer ck.Close()
	out := PublicLinksResult{Links: []PublicLink{}}
	for _, raw := range raws {
		l, err := linkView(raw, ck)
		if err != nil {
			return PublicLinksResult{}, err
		}
		out.Links = append(out.Links, l)
	}
	return out, nil
}

type LinkCreateInput struct {
	CalendarID string `json:"calendar_id"`
	Name       string `json:"name"`
	Access     string `json:"access" jsonschema:"limited exposes free/busy; full exposes all event details to anyone holding the returned URL"`
}

func (s *Service) PublicLinkCreate(ctx context.Context, in LinkCreateInput) (PublicLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.allowed(in.CalendarID); err != nil {
		return PublicLink{}, err
	}
	if err := validateString(in.Name, 500); err != nil {
		return PublicLink{}, err
	}
	if in.Access != "limited" && in.Access != "full" {
		return PublicLink{}, errors.New("access must be limited or full")
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return PublicLink{}, err
	}
	defer ck.Close()
	if ck.Member.Permissions&3 == 0 {
		return PublicLink{}, errors.New("only calendar owners may publish links")
	}
	cache := make([]byte, 16)
	salt := make([]byte, 8)
	if _, err := rand.Read(cache); err != nil {
		return PublicLink{}, err
	}
	if _, err := rand.Read(salt); err != nil {
		return PublicLink{}, err
	}
	cacheKey := base64.URLEncoding.EncodeToString(cache)
	saltText := base64.StdEncoding.EncodeToString(salt)
	hash := sha256.Sum256([]byte(saltText + cacheKey))
	sealed, err := proton.SealCalendarText(ck, cacheKey)
	if err != nil {
		return PublicLink{}, err
	}
	body := map[string]any{"AccessLevel": 0, "CacheKeySalt": saltText, "CacheKeyHash": base64.StdEncoding.EncodeToString(hash[:]), "EncryptedCacheKey": sealed, "EncryptedPassphrase": nil, "PassphraseID": nil, "EncryptedPurpose": nil}
	if in.Name != "" {
		purpose, err := proton.SealCalendarText(ck, in.Name)
		if err != nil {
			return PublicLink{}, err
		}
		body["EncryptedPurpose"] = purpose
	}
	var passKey []byte
	if in.Access == "full" {
		if !ValidID(ck.PassphraseID) {
			return PublicLink{}, errors.New("calendar passphrase identity unavailable")
		}
		passKey = make([]byte, 32)
		defer clear(passKey)
		if _, err := rand.Read(passKey); err != nil {
			return PublicLink{}, err
		}
		masked, err := proton.MaskCalendarPassphrase(ck, passKey)
		if err != nil {
			return PublicLink{}, err
		}
		body["AccessLevel"] = 1
		body["PassphraseID"] = ck.PassphraseID
		body["EncryptedPassphrase"] = base64.StdEncoding.EncodeToString(masked)
	}
	var r struct{ CalendarUrl rawLink }
	if err := s.Client.Do(ctx, "POST", "/calendar/v1/"+in.CalendarID+"/urls", nil, body, &r); err != nil {
		return PublicLink{}, err
	}
	if !ValidID(r.CalendarUrl.CalendarUrlID) || (r.CalendarUrl.CalendarID != "" && r.CalendarUrl.CalendarID != in.CalendarID) {
		return PublicLink{}, errors.New("missing link ID; inspect public links before retrying")
	}
	return PublicLink{ID: r.CalendarUrl.CalendarUrlID, Access: in.Access, Name: in.Name, Created: r.CalendarUrl.CreateTime, URL: publicLinkURL(r.CalendarUrl.CalendarUrlID, cacheKey, passKey)}, nil
}
func publicLinkURL(id, cache string, pass []byte) string {
	q := url.Values{"CacheKey": {cache}}
	if len(pass) > 0 {
		q.Set("PassphraseKey", base64.URLEncoding.EncodeToString(pass))
	}
	return "https://calendar.proton.me/api/calendar/v1/url/" + id + "/calendar.ics?" + q.Encode()
}

type LinkInput struct {
	CalendarID string `json:"calendar_id"`
	LinkID     string `json:"link_id"`
}

func (s *Service) PublicLinkGet(ctx context.Context, in LinkInput) (PublicLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidID(in.LinkID) {
		return PublicLink{}, errors.New("invalid link ID")
	}
	links, err := s.rawLinks(ctx, in.CalendarID)
	if err != nil {
		return PublicLink{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return PublicLink{}, err
	}
	defer ck.Close()
	for _, raw := range links {
		if raw.CalendarUrlID == in.LinkID {
			l, err := linkView(raw, ck)
			if err != nil {
				return PublicLink{}, err
			}
			cache, err := proton.OpenCalendarText(ck, raw.EncryptedCacheKey)
			if err != nil {
				return PublicLink{}, err
			}
			var pass []byte
			if raw.AccessLevel == 1 {
				masked, err := base64.StdEncoding.DecodeString(raw.EncryptedPassphrase)
				if err != nil {
					return PublicLink{}, errors.New("invalid public link passphrase")
				}
				pass, err = proton.MaskCalendarPassphrase(ck, masked)
				if err != nil {
					return PublicLink{}, err
				}
				defer clear(pass)
			}
			l.URL = publicLinkURL(l.ID, cache, pass)
			return l, nil
		}
	}
	return PublicLink{}, errors.New("public link not found")
}
func (s *Service) PublicLinkDelete(ctx context.Context, in LinkInput) (CalendarCreateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ValidID(in.LinkID) {
		return CalendarCreateResult{}, errors.New("invalid link ID")
	}
	links, err := s.rawLinks(ctx, in.CalendarID)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	ck, err := s.Client.UnlockCalendar(ctx, in.CalendarID)
	if err != nil {
		return CalendarCreateResult{}, err
	}
	defer ck.Close()
	if ck.Member.Permissions&3 == 0 {
		return CalendarCreateResult{}, errors.New("only calendar owners may revoke public links")
	}
	for _, l := range links {
		if l.CalendarUrlID == in.LinkID {
			if err := s.Client.Do(ctx, "DELETE", "/calendar/v1/"+in.CalendarID+"/urls/"+in.LinkID, nil, nil, nil); err != nil {
				return CalendarCreateResult{}, err
			}
			return CalendarCreateResult{CalendarID: in.CalendarID}, nil
		}
	}
	return CalendarCreateResult{}, errors.New("public link not found")
}
