package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/term"
	"proton-calendar-mcp/internal/calendar"
	"proton-calendar-mcp/internal/config"
	"proton-calendar-mcp/internal/mcpserver"
	"proton-calendar-mcp/internal/proton"
	"proton-calendar-mcp/internal/vault"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	command := "serve"
	if len(args) > 0 {
		command = args[0]
	}
	if command == "version" {
		fmt.Println(mcpserver.Version)
		return nil
	}
	if command == "health" {
		url := "http://127.0.0.1:8080/healthz"
		if len(args) > 1 {
			url = args[1]
		}
		client := http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(url)
		if err != nil {
			return errors.New("server is not healthy")
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return errors.New("server is not healthy")
		}
		return nil
	}
	if command == "init" {
		path := os.Getenv("PROTON_VAULT_KEY_FILE")
		if path == "" {
			path = "secrets/vault.key"
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return errors.New("cannot create vault key; existing keys are never overwritten")
		}
		defer f.Close()
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
			return err
		}
		clear(key)
		fmt.Fprintln(os.Stderr, "Created vault key at", path)
		return f.Sync()
	}
	if command != "serve" && command != "login" && command != "calendars" {
		return errors.New("usage: proton-calendar-mcp [init|login --username ADDRESS|calendars|serve|health|version]")
	}
	cfg, err := config.Load(command == "serve")
	if err != nil {
		return err
	}
	if command == "serve" && cfg.Transport == "http" {
		return serveHTTP(cfg)
	}
	v, err := cfg.OpenVault()
	if err != nil {
		return err
	}
	defer v.Close()
	state, err := v.Load()
	if err != nil {
		return err
	}
	client := proton.New(state, v.Save)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if command == "login" {
		fs := flag.NewFlagSet("login", flag.ContinueOnError)
		username := fs.String("username", os.Getenv("PROTON_USERNAME"), "Proton username")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *username == "" {
			return errors.New("login requires --username ADDRESS")
		}
		password, err := prompt("Account password: ")
		if err != nil {
			return err
		}
		defer clear(password)
		client.SetHumanVerification(func(page string) error {
			fmt.Fprintln(os.Stderr, "Open this Proton page in your browser and complete the human verification:")
			fmt.Fprintln(os.Stderr, page)
			fmt.Fprintln(os.Stderr, "Return here and press Enter after the page confirms verification.")
			_, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if err != nil {
				return errors.New("human verification cancelled")
			}
			return nil
		})
		loginCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		err = client.Login(loginCtx, *username, password, func() (string, error) {
			b, err := prompt("TOTP code: ")
			defer clear(b)
			return strings.TrimSpace(string(b)), err
		})
		if err != nil {
			return err
		}
		var settings struct {
			UserSettings struct{ Password struct{ Mode int } }
		}
		if err := client.Do(loginCtx, "GET", "/core/v4/settings", nil, nil, &settings); err != nil {
			return err
		}
		mailbox := password
		if settings.UserSettings.Password.Mode == 2 {
			mailbox, err = prompt("Mailbox password: ")
			if err != nil {
				return err
			}
			defer clear(mailbox)
		}
		if err := client.DeriveKeyPassword(loginCtx, mailbox); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "Session saved in the encrypted vault. A waiting HTTP server will activate automatically.")
		return nil
	}
	if state.Session.AccessToken == "" || state.Session.KeyPassword == "" {
		return errors.New("no unlocked session; run login before starting the server")
	}
	if command == "calendars" {
		c, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		all, err := calendar.Discover(c, client)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(all)
	}
	service := &calendar.Service{Client: client, Allowed: cfg.Allowed, Location: cfg.Location}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	server := mcpserver.New(service, logger)
	if cfg.Transport == "stdio" {
		return server.Run(ctx, &mcp.StdioTransport{})
	}
	return nil
}

func serveHTTP(cfg config.Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var active atomic.Pointer[mcp.Server]
	var owned *vault.Store
	defer func() {
		if owned != nil {
			owned.Close()
		}
	}()
	activate := func() error {
		v, err := cfg.OpenVault()
		if errors.Is(err, vault.ErrLocked) {
			return nil
		}
		if err != nil {
			return err
		}
		state, err := v.Load()
		if err != nil {
			v.Close()
			return err
		}
		if state.Session.AccessToken == "" || state.Session.KeyPassword == "" {
			v.Close()
			return nil
		}
		client := proton.New(state, v.Save)
		service := &calendar.Service{Client: client, Allowed: cfg.Allowed, Location: cfg.Location}
		logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
		owned = v
		active.Store(mcpserver.New(service, logger))
		fmt.Fprintln(os.Stderr, "Proton session loaded; MCP ready.")
		return nil
	}
	if err := activate(); err != nil {
		return err
	}
	if active.Load() == nil {
		fmt.Fprintln(os.Stderr, "Waiting for Proton login. In the container terminal run: proton-calendar-mcp login --username YOUR_EMAIL")
	}
	listeners := []struct{ addr, token string }{{cfg.HTTPAddr, cfg.Token}}
	if cfg.TunnelAddr != "" {
		listeners = append(listeners, struct{ addr, token string }{cfg.TunnelAddr, cfg.TunnelToken})
	}
	var servers []*http.Server
	var sockets []net.Listener
	defer func() {
		for _, socket := range sockets {
			socket.Close()
		}
	}()
	for _, l := range listeners {
		socket, err := net.Listen("tcp", l.addr)
		if err != nil {
			return errors.New("cannot bind MCP listener")
		}
		sockets = append(sockets, socket)
		servers = append(servers, &http.Server{Handler: mcpserver.DynamicHandler(active.Load, l.token, cfg.Hosts), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 3 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10})
	}
	errCh := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { errCh <- srv.Serve(sockets[i]) }()
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var serveErr error
	running := true
	for running {
		select {
		case <-ctx.Done():
			running = false
		case err := <-errCh:
			if !errors.Is(err, http.ErrServerClosed) {
				serveErr = errors.New("MCP HTTP listener stopped unexpectedly")
			}
			running = false
		case <-ticker.C:
			if active.Load() == nil {
				if err := activate(); err != nil {
					serveErr = err
					running = false
				}
			}
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(shutdown); err != nil {
			srv.Close()
		}
	}
	return serveErr
}

func prompt(label string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("login requires an interactive terminal; never pass account passwords in arguments or MCP")
	}
	fmt.Fprint(os.Stderr, label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil || len(b) == 0 {
		return nil, errors.New("secret input failed")
	}
	return b, nil
}
