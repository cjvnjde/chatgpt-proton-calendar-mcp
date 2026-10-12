package config

import (
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"proton-calendar-mcp/internal/calendar"
	"proton-calendar-mcp/internal/vault"
)

type Config struct {
	Transport, VaultPath, KeyFile, KeyValue, HTTPAddr, TunnelAddr, Token, TunnelToken string
	Hosts                                                                             []string
	Allowed                                                                           map[string]bool
	Location                                                                          *time.Location
}

func value(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
func secret(env, fileEnv string) (string, error) {
	v := os.Getenv(env)
	f := os.Getenv(fileEnv)
	if v != "" && f != "" {
		return "", errors.New("configure only one of " + env + " and " + fileEnv)
	}
	if f != "" {
		b, err := vault.ReadSecret(f)
		if err != nil {
			return "", err
		}
		v = string(b)
		clear(b)
	}
	return v, nil
}

func Load(requireServer bool) (Config, error) {
	c := Config{Transport: value("MCP_TRANSPORT", "stdio"), VaultPath: value("PROTON_VAULT_PATH", "data/vault.enc"), HTTPAddr: value("MCP_HTTP_ADDR", "127.0.0.1:8080"), TunnelAddr: os.Getenv("MCP_TUNNEL_ADDR"), Allowed: map[string]bool{}}
	c.KeyValue = os.Getenv("PROTON_VAULT_KEY")
	c.KeyFile = os.Getenv("PROTON_VAULT_KEY_FILE")
	if c.KeyValue != "" && c.KeyFile != "" {
		return c, errors.New("choose PROTON_VAULT_KEY or PROTON_VAULT_KEY_FILE")
	}
	if c.KeyValue == "" && c.KeyFile == "" {
		c.KeyFile = "secrets/vault.key"
	}
	loc, err := time.LoadLocation(value("PROTON_TIMEZONE", "UTC"))
	if err != nil {
		return c, errors.New("invalid PROTON_TIMEZONE")
	}
	c.Location = loc
	for _, id := range strings.Split(os.Getenv("PROTON_CALENDAR_IDS"), ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if !calendar.ValidID(id) {
			return c, errors.New("invalid calendar allowlist ID")
		}
		c.Allowed[id] = true
	}
	if !requireServer {
		return c, nil
	}
	if len(c.Allowed) == 0 {
		return c, errors.New("PROTON_CALENDAR_IDS must explicitly allow at least one calendar")
	}
	if c.Transport != "stdio" && c.Transport != "http" {
		return c, errors.New("MCP_TRANSPORT must be stdio or http")
	}
	if c.Transport == "stdio" {
		if c.TunnelAddr != "" {
			return c, errors.New("tunnel listener requires HTTP transport")
		}
		return c, nil
	}
	if _, _, err := net.SplitHostPort(c.HTTPAddr); err != nil {
		return c, errors.New("invalid MCP_HTTP_ADDR")
	}
	c.Token, err = secret("MCP_BEARER_TOKEN", "MCP_BEARER_TOKEN_FILE")
	if err != nil {
		return c, err
	}
	if err := validateToken(c.Token); err != nil {
		return c, err
	}
	if c.TunnelAddr != "" {
		if _, _, err := net.SplitHostPort(c.TunnelAddr); err != nil {
			return c, errors.New("invalid MCP_TUNNEL_ADDR")
		}
		if c.TunnelAddr == c.HTTPAddr {
			return c, errors.New("HTTP and tunnel addresses must differ")
		}
		c.TunnelToken, err = secret("MCP_TUNNEL_TOKEN", "MCP_TUNNEL_TOKEN_FILE")
		if err != nil {
			return c, err
		}
		if err := validateToken(c.TunnelToken); err != nil {
			return c, err
		}
		if c.Token == c.TunnelToken {
			return c, errors.New("use separate direct and tunnel bearer tokens")
		}
	}
	for _, host := range strings.Split(os.Getenv("MCP_ALLOWED_HOSTS"), ",") {
		host = strings.TrimSpace(host)
		if host != "" {
			if strings.ContainsAny(host, "/* \r\n\t") {
				return c, errors.New("MCP_ALLOWED_HOSTS requires exact Host values, including ports")
			}
			c.Hosts = append(c.Hosts, host)
		}
	}
	if len(c.Hosts) == 0 {
		c.Hosts = []string{"localhost:8080", "127.0.0.1:8080"}
	}
	return c, nil
}

func validateToken(token string) error {
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, " \t\r\n") {
		return errors.New("HTTP bearer token must be 32-256 characters with no whitespace; generate with openssl rand -hex 32")
	}
	for _, b := range []byte(token) {
		if b < 33 || b > 126 {
			return errors.New("HTTP bearer token must contain printable ASCII only")
		}
	}
	return nil
}

func (c Config) OpenVault() (*vault.Store, error) {
	if c.KeyValue == "" {
		return vault.Open(c.VaultPath, c.KeyFile)
	}
	// Environment secrets support Dokploy without mounting host secret files.
	// The temporary file is removed immediately after opening the vault.
	f, err := os.CreateTemp("", "proton-vault-key-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.WriteString(c.KeyValue); err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	return vault.Open(c.VaultPath, f.Name())
}
