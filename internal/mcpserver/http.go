package mcpserver

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Both public and tunnel listeners authenticate. The tunnel uses a distinct
// key and is bound to loopback unless explicitly configured otherwise.
func Handler(server *mcp.Server, token string, hosts []string) http.Handler {
	stream := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	protected := http.NewCrossOriginProtection().Handler(stream)
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		validHost := false
		for _, h := range hosts {
			if strings.EqualFold(r.Host, h) {
				validHost = true
				break
			}
		}
		if !validHost {
			http.Error(w, "Invalid Host", http.StatusMisdirectedRequest)
			return
		}
		if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
			w.Write([]byte("ok\n"))
			return
		}
		if r.URL.Path != "/mcp" {
			http.NotFound(w, r)
			return
		}
		scheme, supplied, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		actual := sha256.Sum256([]byte(supplied))
		if token == "" || !ok || !strings.EqualFold(scheme, "Bearer") || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		if r.Method == http.MethodPost {
			b, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Request body too large or unreadable", http.StatusRequestEntityTooLarge)
				return
			}
			if !utf8.Valid(b) {
				http.Error(w, "Invalid UTF-8", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		protected.ServeHTTP(w, r)
	})
}
