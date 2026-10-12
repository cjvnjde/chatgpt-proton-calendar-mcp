package config

import (
	"strings"
	"testing"
)

func TestSecureConfigDefaultsAndTunnelIsolation(t *testing.T) {
	for _, key := range []string{"MCP_TRANSPORT", "MCP_HTTP_ADDR", "MCP_TUNNEL_ADDR", "MCP_BEARER_TOKEN", "MCP_TUNNEL_TOKEN", "MCP_BEARER_TOKEN_FILE", "MCP_TUNNEL_TOKEN_FILE", "PROTON_VAULT_KEY", "PROTON_VAULT_KEY_FILE", "PROTON_CALENDAR_IDS", "MCP_ALLOWED_HOSTS", "PROTON_TIMEZONE"} {
		t.Setenv(key, "")
	}
	if c, err := Load(true); err != nil || len(c.Allowed) != 0 {
		t.Fatal("empty calendar IDs should allow all calendars", c, err)
	}
	t.Setenv("PROTON_CALENDAR_IDS", "calendar1")
	c, err := Load(true)
	if err != nil || c.Transport != "stdio" {
		t.Fatal(c, err)
	}
	t.Setenv("MCP_TRANSPORT", "http")
	if _, err := Load(true); err == nil {
		t.Fatal("unauthenticated HTTP accepted")
	}
	t.Setenv("MCP_BEARER_TOKEN", strings.Repeat("a", 64))
	t.Setenv("MCP_TUNNEL_ADDR", "127.0.0.1:8081")
	t.Setenv("MCP_TUNNEL_TOKEN", strings.Repeat("a", 64))
	if _, err := Load(true); err == nil {
		t.Fatal("shared bearer accepted")
	}
	t.Setenv("MCP_TUNNEL_TOKEN", strings.Repeat("b", 64))
	c, err = Load(true)
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPAddr != "127.0.0.1:8080" {
		t.Fatal("non-local default", c.HTTPAddr)
	}
	t.Setenv("MCP_ALLOWED_HOSTS", "localhost:8080,127.0.0.1:8080,proton-calendar-mcp:8080,proton-calendar-mcp:8081,calendar.example.com")
	t.Setenv("MCP_BEARER_TOKEN", strings.Repeat("trn", 22))
	c, err = Load(true)
	if err != nil || len(c.Hosts) != 5 {
		t.Fatal("normal Docker/domain hosts or printable tokens refused", c.Hosts, err)
	}
	for _, host := range []string{"host\rname", "host\nname", "host\tname"} {
		t.Setenv("MCP_ALLOWED_HOSTS", host)
		if _, err := Load(true); err == nil {
			t.Fatalf("control character accepted in host %q", host)
		}
	}
	t.Setenv("MCP_ALLOWED_HOSTS", "*.example.com")
	if _, err := Load(true); err == nil {
		t.Fatal("wildcard host accepted")
	}
}
