// Command ipgate is an IP allowlist gate for Caddy forward_auth with OIDC login.
//
// Usage:
//
//	ipgate              run the server (configured via environment variables)
//	ipgate healthcheck  GET /healthz on the local listener; exit 0 if healthy
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Olsenius/ipgate/internal/auth"
	"github.com/Olsenius/ipgate/internal/config"
	"github.com/Olsenius/ipgate/internal/server"
	"github.com/Olsenius/ipgate/internal/store"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "healthcheck":
			if err := healthcheck(os.Getenv("LISTEN_ADDR"), 3*time.Second); err != nil {
				fmt.Fprintln(os.Stderr, "unhealthy:", err)
				os.Exit(1)
			}
			return
		case "-h", "--help", "help":
			fmt.Println("usage: ipgate [healthcheck]\n\nConfiguration is read from environment variables; see README.md.")
			return
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q (usage: ipgate [healthcheck])\n", os.Args[1])
			os.Exit(2)
		}
	}
	if err := run(); err != nil {
		slog.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return errors.New("configuration error")
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	slog.SetDefault(log)

	path := filepath.Join(cfg.DataDir, "allowlist.json")
	st, err := store.Open(path, nil)
	if err != nil {
		return fmt.Errorf("refusing to start: %w", err)
	}
	log.Info("allowlist loaded", "path", path, "entries", len(st.List(nil)))
	if cfg.PublicURL.Scheme != "https" {
		log.Warn("PUBLIC_URL is not https; cookies are Secure and browsers will only send them over https (or to localhost)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	oidc := auth.NewOIDC(auth.OIDCConfig{
		Issuer:       cfg.OIDCIssuer,
		ClientID:     cfg.OIDCClientID,
		ClientSecret: cfg.OIDCClientSecret,
		RedirectURL:  cfg.RedirectURL(),
	})
	go oidc.DiscoverLoop(ctx, log)
	go st.RunPruner(ctx, 10*time.Minute, func(n int, err error) {
		if err != nil {
			log.Error("prune failed", "err", err)
		} else if n > 0 {
			log.Info("pruned expired entries", "count", n)
		}
	})

	srv, err := server.New(cfg, st, oidc, log, nil)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.ListenAddr, "public_url", cfg.PublicURL.String())
		errc <- hs.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}

// healthURL maps LISTEN_ADDR to a loopback URL for /healthz.
func healthURL(listenAddr string) (string, error) {
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "", fmt.Errorf("LISTEN_ADDR %q: %w", listenAddr, err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}

func healthcheck(listenAddr string, timeout time.Duration) error {
	u, err := healthURL(listenAddr)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: timeout}
	resp, err := c.Get(u)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		return fmt.Errorf("%s returned %d", u, resp.StatusCode)
	}
	return nil
}
