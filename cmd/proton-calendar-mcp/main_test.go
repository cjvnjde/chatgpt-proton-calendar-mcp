package main

import (
	"context"
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
