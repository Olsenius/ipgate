package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Scopes requested from the provider.
var Scopes = []string{oidc.ScopeOpenID, "profile", "email", "groups"}

// ErrNotReady is returned while OIDC discovery has not yet succeeded.
var ErrNotReady = errors.New("oidc provider not discovered yet")

// Claims are the identity claims ipgate uses.
type Claims struct {
	Sub               string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Groups            []string `json:"groups"`
}

// DisplayName picks the friendliest available name.
func (c *Claims) DisplayName() string {
	for _, s := range []string{c.Name, c.PreferredUsername, c.Email} {
		if s != "" {
			return s
		}
	}
	return c.Sub
}

// OIDCConfig configures the OIDC client.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client // optional; defaults to a client with a 10s timeout
}

type discovered struct {
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// OIDC wraps provider discovery, the authorization URL and code exchange.
// It is safe for concurrent use; discovery may complete after construction.
type OIDC struct {
	cfg    OIDCConfig
	client *http.Client
	ready  atomic.Pointer[discovered]
}

// NewOIDC returns an OIDC client. Call Discover or DiscoverLoop before use.
func NewOIDC(cfg OIDCConfig) *OIDC {
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 10 * time.Second}
	}
	return &OIDC{cfg: cfg, client: c}
}

// ctx attaches the HTTP client. The provider keeps this context for later JWKS
// fetches, so it must not be cancelled; request timeouts come from the client.
func (o *OIDC) ctx(parent context.Context) context.Context {
	return oidc.ClientContext(parent, o.client)
}

// Discover performs one discovery attempt.
func (o *OIDC) Discover() error {
	p, err := oidc.NewProvider(o.ctx(context.Background()), o.cfg.Issuer)
	if err != nil {
		return err
	}
	o.ready.Store(&discovered{
		oauth: oauth2.Config{
			ClientID:     o.cfg.ClientID,
			ClientSecret: o.cfg.ClientSecret,
			RedirectURL:  o.cfg.RedirectURL,
			Endpoint:     p.Endpoint(),
			Scopes:       Scopes,
		},
		verifier: p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}),
	})
	return nil
}

// DiscoverLoop retries discovery with exponential backoff (1s to 30s) until it
// succeeds or ctx is done.
func (o *OIDC) DiscoverLoop(ctx context.Context, log *slog.Logger) {
	delay := time.Second
	for attempt := 1; ; attempt++ {
		err := o.Discover()
		if err == nil {
			log.Info("oidc discovery succeeded", "issuer", o.cfg.Issuer, "attempt", attempt)
			return
		}
		log.Warn("oidc discovery failed; retrying", "issuer", o.cfg.Issuer, "attempt", attempt, "retry_in", delay.String(), "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, 30*time.Second)
	}
}

// Ready reports whether discovery has succeeded.
func (o *OIDC) Ready() bool { return o.ready.Load() != nil }

// AuthCodeURL builds the authorization URL with state, nonce and a PKCE S256 challenge.
func (o *OIDC) AuthCodeURL(ls LoginState) (string, error) {
	d := o.ready.Load()
	if d == nil {
		return "", ErrNotReady
	}
	return d.oauth.AuthCodeURL(ls.State, oidc.Nonce(ls.Nonce), oauth2.S256ChallengeOption(ls.Verifier)), nil
}

// Exchange redeems the code (with the PKCE verifier), verifies the ID token
// (signature, issuer, audience, expiry) and its nonce, and returns its claims.
func (o *OIDC) Exchange(ctx context.Context, code string, ls LoginState) (*Claims, error) {
	d := o.ready.Load()
	if d == nil {
		return nil, ErrNotReady
	}
	ctx = o.ctx(ctx)
	tok, err := d.oauth.Exchange(ctx, code, oauth2.VerifierOption(ls.Verifier))
	if err != nil {
		return nil, fmt.Errorf("code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return nil, errors.New("token response has no id_token")
	}
	idt, err := d.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(ls.Nonce)) != 1 {
		return nil, errors.New("id token: nonce mismatch")
	}
	var c Claims
	if err := idt.Claims(&c); err != nil {
		return nil, fmt.Errorf("id token claims: %w", err)
	}
	if c.Sub == "" {
		return nil, errors.New("id token: empty sub")
	}
	return &c, nil
}

// NewLoginState returns fresh state, nonce and PKCE verifier values.
func NewLoginState() LoginState {
	return LoginState{State: RandomString(), Nonce: RandomString(), Verifier: oauth2.GenerateVerifier()}
}
