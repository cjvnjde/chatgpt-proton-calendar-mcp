package mcpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"proton-calendar-mcp/internal/calendar"
)

func TestMCPDiscoveryOverAuthenticatedHTTP(t *testing.T) {
	token := strings.Repeat("a", 64)
	server := New(&calendar.Service{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var handler http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	handler = Handler(server, token, []string{host})
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp", HTTPClient: &http.Client{Transport: authTransport{http.DefaultTransport, token}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 7 {
		t.Fatal(len(tools.Tools))
	}
	if tools.Tools[0].InputSchema == nil {
		t.Fatal("missing schemas")
	}
	foundDelete := false
	for _, tool := range tools.Tools {
		if tool.Name != "event_delete" {
			continue
		}
		foundDelete = true
		data, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]struct{ Type string }
			Required   []string
		}
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatal(err)
		}
		if schema.Properties["occurrence"].Type != "string" {
			t.Fatalf("event_delete missing occurrence: %s", data)
		}
		for _, field := range schema.Required {
			if field == "occurrence" {
				t.Fatal("occurrence must remain optional for non-recurring events")
			}
		}
		t.Logf("advertised event_delete schema: %s", data)
	}
	if !foundDelete {
		t.Fatal("event_delete is not advertised")
	}
}

type authTransport struct {
	base  http.RoundTripper
	token string
}

func (a authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+a.token)
	return a.base.RoundTrip(r)
}

func TestHTTPAuthHostOriginAndBodyLimits(t *testing.T) {
	token := strings.Repeat("a", 64)
	h := Handler(mcp.NewServer(&mcp.Implementation{Name: "test", Version: "1"}, nil), token, []string{"localhost:8080"})
	for _, test := range []struct {
		path, host, auth, origin string
		status                   int
	}{
		{"/mcp", "localhost:8080", "", "", 401},
		{"/mcp", "localhost:8080", "Bearer wrong", "", 401},
		{"/mcp", "attacker.test", "Bearer " + token, "", 421},
		{"/mcp", "localhost:8080", "Bearer " + token, "https://attacker.test", 403},
		{"/other", "localhost:8080", "Bearer " + token, "", 404},
	} {
		r := httptest.NewRequest("POST", "http://localhost:8080"+test.path, strings.NewReader(`{}`))
		r.Host = test.host
		r.Header.Set("Authorization", test.auth)
		r.Header.Set("Origin", test.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.status {
			t.Errorf("%+v: %d", test, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "http://localhost:8080/mcp", strings.NewReader(strings.Repeat("x", 300<<10)))
	r.Host = "localhost:8080"
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatal("body not bounded", w.Code)
	}
	r = httptest.NewRequest("POST", "http://localhost:8080/mcp", strings.NewReader("{\"x\":\"\xff\"}"))
	r.Host = "localhost:8080"
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatal("invalid UTF-8 accepted", w.Code)
	}
}
