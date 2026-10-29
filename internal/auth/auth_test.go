package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Olsenius/ipgate/internal/oidctest"
)

var secret = []byte(strings.Repeat("k", 32))

func TestSignVerify(t *testing.T) {
	s := NewSigner(secret, nil)
	tok, err := s.Sign("p", map[string]string{"a": "b"}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := s.Verify("p", tok, &got); err != nil || got["a"] != "b" {
		t.Fatalf("Verify = %v, %v", got, err)
	}
	if err := s.Verify("other-purpose", tok, &got); err != ErrSignature {
		t.Errorf("cross-purpose verify err = %v, want ErrSignature", err)
	}
	if err := NewSigner([]byte(strings.Repeat("z", 32)), nil).Verify("p", tok, &got); err != ErrSignature {
		t.Errorf("other key verify err = %v, want ErrSignature", err)
	}
}

func TestSessionRoundTripTamperExpiry(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	s := NewSigner(secret, func() time.Time { return now })
	sess := s.NewSession("sub-1", "Kari", true, time.Hour)
	v, err := s.EncodeSession(sess)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.DecodeSession(v)
	if err != nil || got != sess {
		t.Fatalf("round trip: %+v, %v", got, err)
	}

	// Tampering with the payload (e.g. flipping admin) breaks the signature.
	payload, sig, _ := strings.Cut(v, ".")
	raw, _ := b64.DecodeString(payload)
	forged := strings.Replace(string(raw), `"sub-1"`, `"sub-2"`, 1)
	if _, err := s.DecodeSession(b64.EncodeToString([]byte(forged)) + "." + sig); err != ErrSignature {
		t.Errorf("tampered payload err = %v", err)
	}
	// Tampering with the signature.
	last := sig[len(sig)-1]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	if _, err := s.DecodeSession(payload + "." + sig[:len(sig)-1] + string(repl)); err != ErrSignature {
		t.Errorf("tampered signature err = %v", err)
	}
	for _, bad := range []string{"", "abc", ".", "abc.", ".abc", "!!!.!!!"} {
		if _, err := s.DecodeSession(bad); err == nil {
			t.Errorf("DecodeSession(%q) succeeded", bad)
		}
	}

	// Expiry.
	now = now.Add(time.Hour)
	if _, err := s.DecodeSession(v); err != ErrExpired {
		t.Errorf("expired session err = %v", err)
	}
}

func TestLoginStateNotUsableAsSession(t *testing.T) {
	s := NewSigner(secret, nil)
	v, _ := s.EncodeLogin(NewLoginState(), time.Minute)
	if _, err := s.DecodeSession(v); err == nil {
		t.Fatal("login cookie accepted as session")
	}
	ls, err := s.DecodeLogin(v)
	if err != nil || ls.State == "" || ls.Verifier == "" || ls.Nonce == "" {
		t.Fatalf("DecodeLogin = %+v, %v", ls, err)
	}
}

func TestCSRF(t *testing.T) {
	s := NewSigner(secret, nil)
	a := s.NewSession("a", "A", false, time.Hour)
	b := s.NewSession("a", "A", false, time.Hour)
	tok := s.CSRFToken(a)
	if !s.CheckCSRF(a, tok) {
		t.Error("valid token rejected")
	}
	if s.CheckCSRF(b, tok) {
		t.Error("token accepted for another session")
	}
	if s.CheckCSRF(a, "") || s.CheckCSRF(a, tok+"x") {
		t.Error("bad token accepted")
	}
}

// --- OIDC ---

func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// login runs the browser leg against the fake provider and returns code and state.
func login(t *testing.T, o *OIDC, ls LoginState) (string, string) {
	t.Helper()
	u, err := o.AuthCodeURL(ls)
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	q := pu.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") != ls.Nonce || q.Get("state") != ls.State {
		t.Fatalf("auth URL missing PKCE/state/nonce: %s", u)
	}
	if got := q.Get("scope"); got != "openid profile email groups" {
		t.Errorf("scope = %q", got)
	}
	resp, err := noRedirect().Get(u)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	loc, _ := url.Parse(resp.Header.Get("Location"))
	return loc.Query().Get("code"), loc.Query().Get("state")
}

func newOIDC(t *testing.T) (*oidctest.Server, *OIDC) {
	t.Helper()
	p := oidctest.NewServer("ipgate", "s3cret")
	t.Cleanup(p.Close)
	o := NewOIDC(OIDCConfig{Issuer: p.Issuer, ClientID: "ipgate", ClientSecret: "s3cret", RedirectURL: "https://enable.example/auth/callback"})
	if err := o.Discover(); err != nil {
		t.Fatal(err)
	}
	return p, o
}

func TestOIDCExchange(t *testing.T) {
	p, o := newOIDC(t)
	p.Set(func(s *oidctest.Settings) {
		s.User = oidctest.User{Sub: "abc", Name: "Kari Nordmann", PreferredUsername: "kari", Email: "kari@example.com", Groups: []string{"media", "admins"}}
	})
	ls := NewLoginState()
	code, state := login(t, o, ls)
	if state != ls.State {
		t.Fatalf("state = %q", state)
	}
	c, err := o.Exchange(context.Background(), code, ls)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "abc" || c.DisplayName() != "Kari Nordmann" || c.PreferredUsername != "kari" || c.Email != "kari@example.com" || len(c.Groups) != 2 {
		t.Errorf("claims = %+v", c)
	}
	// Codes are single use.
	if _, err := o.Exchange(context.Background(), code, ls); err == nil {
		t.Error("code reused successfully")
	}
}

func TestOIDCExchangeFailures(t *testing.T) {
	wrong := "wrong-nonce"
	cases := map[string]struct {
		set    func(*oidctest.Settings)
		mutate func(*LoginState)
		want   string
	}{
		"wrong nonce":    {set: func(s *oidctest.Settings) { s.Nonce = &wrong }, want: "id token: nonce mismatch"},
		"wrong audience": {set: func(s *oidctest.Settings) { s.Audience = "someone-else" }, want: "id token: wrong audience"},
		"wrong issuer":   {set: func(s *oidctest.Settings) { s.Issuer = "https://evil.example" }, want: "id token: wrong issuer"},
		"expired token":  {set: func(s *oidctest.Settings) { s.TTL = -time.Minute }, want: "id token: expired"},
		"bad signature":  {set: func(s *oidctest.Settings) { s.BadSignature = true }, want: "id token: bad signature"},
		"pkce mismatch":  {mutate: func(ls *LoginState) { ls.Verifier = "x" + ls.Verifier[1:] }, want: "token endpoint: provider error invalid_grant (HTTP 400)"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, o := newOIDC(t)
			if tc.set != nil {
				p.Set(tc.set)
			}
			ls := NewLoginState()
			code, _ := login(t, o, ls)
			if tc.mutate != nil {
				tc.mutate(&ls)
			}
			_, err := o.Exchange(context.Background(), code, ls)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestOIDCNotReadyAndDiscoverLoop(t *testing.T) {
	// The provider answers 503 until "up" is set, like Pocket ID still starting.
	var up atomic.Bool
	p := oidctest.NewServerWrapped("ipgate", "s3cret", func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !up.Load() {
				http.Error(w, "starting", http.StatusServiceUnavailable)
				return
			}
			h.ServeHTTP(w, r)
		})
	})
	defer p.Close()
	issuer := p.Issuer

	o := NewOIDC(OIDCConfig{Issuer: issuer, ClientID: "ipgate", ClientSecret: "s3cret"})
	if o.Ready() {
		t.Fatal("ready before discovery")
	}
	if _, err := o.AuthCodeURL(NewLoginState()); err != ErrNotReady {
		t.Errorf("AuthCodeURL err = %v", err)
	}
	if _, err := o.Exchange(context.Background(), "c", NewLoginState()); err != ErrNotReady {
		t.Errorf("Exchange err = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		o.DiscoverLoop(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
		close(done)
	}()
	time.Sleep(200 * time.Millisecond)
	if o.Ready() {
		t.Fatal("ready while provider is failing")
	}
	up.Store(true)
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("DiscoverLoop did not succeed")
	}
	if !o.Ready() {
		t.Fatal("not ready after DiscoverLoop")
	}
}

// secretBody looks like a token response that arrived with an error status, the
// scenario from the security review (F1).
const secretBody = `{"access_token":"SECRET-ACCESS-MARKER","refresh_token":"SECRET-REFRESH-MARKER","id_token":"SECRET-ID-MARKER"}`

func assertNoMarker(t *testing.T, where, s string) {
	t.Helper()
	if strings.Contains(s, "MARKER") {
		t.Errorf("%s leaks upstream content: %s", where, s)
	}
}

func TestExchangeErrorsDoNotLeakUpstreamContent(t *testing.T) {
	cases := map[string]struct {
		set  func(*oidctest.Settings)
		want string
	}{
		"token 502 with token body": {
			set:  func(s *oidctest.Settings) { s.Token = &oidctest.Response{Status: 502, Body: secretBody} },
			want: "token endpoint: unsuccessful response (HTTP 502)",
		},
		"token error with description and uri": {
			set: func(s *oidctest.Settings) {
				s.Token = &oidctest.Response{Status: 400, Body: `{"error":"invalid_grant","error_description":"DESC-MARKER","error_uri":"https://x/URI-MARKER"}`}
			},
			want: "token endpoint: provider error invalid_grant (HTTP 400)",
		},
		"token nonstandard error code": {
			set:  func(s *oidctest.Settings) { s.Token = &oidctest.Response{Status: 400, Body: `{"error":"CODE-MARKER"}`} },
			want: "token endpoint: provider error other (HTTP 400)",
		},
		"token 200 without id_token": {
			set: func(s *oidctest.Settings) {
				s.Token = &oidctest.Response{Status: 200, Body: `{"access_token":"SECRET-MARKER","token_type":"Bearer"}`}
			},
			want: "token endpoint: response has no id_token",
		},
		"jwks 500 with body": {
			set:  func(s *oidctest.Settings) { s.JWKS = &oidctest.Response{Status: 500, Body: secretBody} },
			want: "id token: jwks fetch failed",
		},
		"jwks garbage": {
			set:  func(s *oidctest.Settings) { s.JWKS = &oidctest.Response{Status: 200, Body: "not json MARKER"} },
			want: "id token: jwks fetch failed",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p, o := newOIDC(t)
			ls := NewLoginState()
			code, _ := login(t, o, ls)
			p.Set(tc.set)
			_, err := o.Exchange(context.Background(), code, ls)
			if err == nil || err.Error() != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			assertNoMarker(t, "error", err.Error())
			assertNoMarker(t, "error %+v", fmt.Sprintf("%+v %#v", err, err))
			if errors.Unwrap(err) != nil {
				t.Error("error exposes its upstream cause via Unwrap")
			}
		})
	}
}

func TestDiscoveryErrorsDoNotLeakUpstreamContent(t *testing.T) {
	cases := map[string]struct {
		resp oidctest.Response
		want string
	}{
		"500 with body":  {oidctest.Response{Status: 500, Body: secretBody}, "discovery: unsuccessful response (HTTP 500)"},
		"invalid json":   {oidctest.Response{Status: 200, Body: "<html>MARKER</html>"}, "discovery: invalid discovery document"},
		"issuer differs": {oidctest.Response{Status: 200, Body: `{"issuer":"https://MARKER.example","jwks_uri":"x"}`}, "discovery: issuer mismatch"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := oidctest.NewServer("ipgate", "s3cret")
			defer p.Close()
			resp := tc.resp
			p.Set(func(s *oidctest.Settings) { s.Discovery = &resp })
			o := NewOIDC(OIDCConfig{Issuer: p.Issuer, ClientID: "ipgate"})
			err := o.Discover()
			if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("err = %v, want prefix %q", err, tc.want)
			}
			assertNoMarker(t, "error", err.Error())

			// DiscoverLoop logs the same safe error.
			var buf strings.Builder
			var mu sync.Mutex
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				o.DiscoverLoop(ctx, slog.New(slog.NewJSONHandler(lockedWriter{&mu, &buf}, nil)))
				close(done)
			}()
			time.Sleep(100 * time.Millisecond)
			cancel()
			<-done
			mu.Lock()
			logs := buf.String()
			mu.Unlock()
			if !strings.Contains(logs, "oidc discovery failed") {
				t.Fatalf("no discovery failure logged: %s", logs)
			}
			assertNoMarker(t, "discovery log", logs)
		})
	}
}

func TestDiscoveryUnreachable(t *testing.T) {
	o := NewOIDC(OIDCConfig{Issuer: "http://127.0.0.1:1", ClientID: "ipgate"})
	if err := o.Discover(); err == nil || err.Error() != "discovery: unreachable" {
		t.Fatalf("err = %v", err)
	}
}

func TestSafeOAuthCode(t *testing.T) {
	if SafeOAuthCode("access_denied") != "access_denied" || SafeOAuthCode("<script>") != "other" || SafeOAuthCode("") != "other" {
		t.Error("SafeOAuthCode allowlist broken")
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
