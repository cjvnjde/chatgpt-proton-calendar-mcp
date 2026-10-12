package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"proton-calendar-mcp/internal/vault"
)

func TestCLIStdioDiscovery(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	path := filepath.Join(dir, "vault.enc")
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := vault.Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Save(vault.State{Session: vault.Session{AccessToken: "synthetic", KeyPassword: "synthetic"}}); err != nil {
		t.Fatal(err)
	}
	v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestServeHelper")
	command.Env = []string{"PROTON_MCP_TEST_HELPER=1", "MCP_TRANSPORT=stdio", "PROTON_VAULT_KEY_FILE=" + key, "PROTON_VAULT_PATH=" + path, "PROTON_CALENDAR_IDS=calendar1", "PROTON_TIMEZONE=Europe/Kyiv"}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.ListTools(ctx, nil)
	if err != nil || len(result.Tools) != 7 {
		t.Fatal(result, err)
	}
}

func TestServeHelper(t *testing.T) {
	if os.Getenv("PROTON_MCP_TEST_HELPER") != "1" {
		return
	}
	if err := run([]string{"serve"}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestHTTPWaitsForTerminalLogin(t *testing.T) {
	dir := t.TempDir()
	key, path := filepath.Join(dir, "key"), filepath.Join(dir, "vault.enc")
	if err := os.WriteFile(key, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestServeHelper")
	token := strings.Repeat("a", 64)
	command.Env = []string{"PROTON_MCP_TEST_HELPER=1", "MCP_TRANSPORT=http", "MCP_HTTP_ADDR=" + addr, "MCP_ALLOWED_HOSTS=" + addr, "MCP_BEARER_TOKEN=" + token, "PROTON_VAULT_KEY_FILE=" + key, "PROTON_VAULT_PATH=" + path}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	client := &http.Client{Timeout: time.Second}
	status := func(path, bearer string) int {
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+addr+path, nil)
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	deadline := time.Now().Add(5 * time.Second)
	for status("/healthz", "") != 200 {
		if time.Now().After(deadline) {
			t.Fatal("server did not become healthy before login")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := status("/mcp", ""); got != 401 {
		t.Fatal("unauthenticated setup request", got)
	}
	if got := status("/mcp", token); got != 503 {
		t.Fatal("setup request should need login", got)
	}
	// Simulate the separate terminal login process, including its exclusive lock.
	var v *vault.Store
	for {
		v, err = vault.Open(path, key)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := v.Save(vault.State{Session: vault.Session{AccessToken: "synthetic", KeyPassword: "synthetic"}}); err != nil {
		v.Close()
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	if got := status("/mcp", token); got != 503 {
		v.Close()
		t.Fatal("server read session before login released lock", got)
	}
	v.Close()
	for status("/mcp", token) == 503 {
		if ctx.Err() != nil {
			t.Fatal("server did not activate")
		}
		time.Sleep(20 * time.Millisecond)
	}
	mcpClient := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	authClient := &http.Client{Transport: bearerTransport{token: token}}
	session, err := mcpClient.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: "http://" + addr + "/mcp", HTTPClient: authClient}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.ListTools(ctx, nil)
	if err != nil || len(result.Tools) != 7 {
		t.Fatal(result, err)
	}
	if v, err := vault.Open(path, key); err == nil {
		v.Close()
		t.Fatal("active server did not retain vault lock")
	}
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
