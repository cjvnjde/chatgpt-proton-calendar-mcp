// Package proton implements only the account and Calendar endpoints needed by
// this server. It deliberately has no arbitrary API or remote URL tool.
package proton

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"proton-calendar-mcp/internal/vault"
)

const BaseURL = "https://mail.proton.me/api"

type APIError struct{ Status, Code int }

func (e *APIError) Error() string {
	if e.Code == 9001 {
		return "Proton requires human verification; complete account verification outside MCP"
	}
	if e.Status == 401 {
		return "Proton session expired; run the local login command"
	}
	if e.Status == 429 {
		return "Proton rate limited this request; wait before trying again"
	}
	return fmt.Sprintf("Proton rejected the request (HTTP %d, code %d)", e.Status, e.Code)
}

type Client struct {
	mu           sync.Mutex
	http         *http.Client
	base         string
	state        vault.State
	save         func(vault.State) error
	broken       bool
	initializing bool
}

func New(state vault.State, save func(vault.State) error) *Client {
	return &Client{base: BaseURL, state: state, save: save, http: &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Every HTTP call and refresh is serialized within the single vault owner.
// An ambiguous write is never resent. Authentication rejection is the one
// safe exception: Proton refused it before application, so refresh then retry.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken {
		return errors.New("credential persistence failed; stop the server and repair the vault")
	}
	err := c.call(ctx, method, path, query, body, out, true)
	var api *APIError
	if errors.As(err, &api) && api.Status == 401 && c.state.Session.RefreshToken != "" {
		if err := c.refresh(ctx); err != nil {
			return err
		}
		return c.call(ctx, method, path, query, body, out, true)
	}
	return err
}

func (c *Client) call(ctx context.Context, method, path string, query url.Values, body, out any, bearer bool) error {
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			return errors.New("cannot encode Proton request")
		}
	}
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(data))
	if err != nil {
		return errors.New("cannot construct Proton request")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	r.Header.Set("x-pm-appversion", "Other")
	r.Header.Set("User-Agent", "proton-calendar-mcp/0.1.0")
	if path == "/auth/v4/sessions" {
		r.Header.Set("x-enforce-unauthsession", "true")
	}
	if c.state.Session.UID != "" {
		r.Header.Set("x-pm-uid", c.state.Session.UID)
	}
	if bearer && c.state.Session.AccessToken != "" {
		r.Header.Set("Authorization", "Bearer "+c.state.Session.AccessToken)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return errors.New("Proton request failed; a write may have succeeded—inspect current state before retrying")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (8<<20)+1))
	if err != nil || len(b) > 8<<20 {
		return errors.New("invalid or oversized Proton response; write outcome may be unknown")
	}
	var envelope struct{ Code int }
	if err := json.Unmarshal(b, &envelope); err != nil {
		return errors.New("invalid Proton response; write outcome may be unknown")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || (envelope.Code != 1000 && envelope.Code != 1001) {
		return &APIError{resp.StatusCode, envelope.Code}
	}
	if out != nil && json.Unmarshal(b, out) != nil {
		return errors.New("unexpected Proton response schema; write outcome may be unknown")
	}
	return nil
}

func (c *Client) persist() error {
	if c.initializing {
		return nil
	}
	if c.save != nil {
		if err := c.save(c.state); err != nil {
			c.broken = true
			return errors.New("cannot persist encrypted credentials; further requests are blocked")
		}
	}
	return nil
}

func (c *Client) refresh(ctx context.Context) error {
	s := c.state.Session
	var r struct{ AccessToken, RefreshToken string }
	err := c.call(ctx, "POST", "/auth/v4/refresh", nil, map[string]string{
		"GrantType": "refresh_token", "RedirectURI": "https://protonmail.ch", "ResponseType": "token",
		"RefreshToken": s.RefreshToken, "UID": s.UID, "State": strconv.FormatInt(time.Now().UnixNano(), 10),
	}, &r, false)
	if err != nil {
		return err
	}
	if r.AccessToken == "" || r.RefreshToken == "" {
		return errors.New("Proton returned incomplete session credentials")
	}
	c.state.Session.AccessToken, c.state.Session.RefreshToken = r.AccessToken, r.RefreshToken
	return c.persist()
}

func (c *Client) KeyPassword() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state.Session.KeyPassword
}
func (c *Client) SetKeyPassword(pass string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Session.KeyPassword = pass
	return c.persist()
}

func (c *Client) Operation(id string) (vault.Operation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	op, ok := c.state.Operations[id]
	return op, ok
}

func (c *Client) SaveOperation(id string, op vault.Operation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken {
		return errors.New("vault needs repair")
	}
	if c.state.Operations == nil {
		c.state.Operations = map[string]vault.Operation{}
	}
	if len(c.state.Operations) >= 10000 {
		if _, ok := c.state.Operations[id]; !ok {
			return errors.New("create operation ledger full; archive the vault before continuing")
		}
	}
	c.state.Operations[id] = op
	return c.persist()
}
