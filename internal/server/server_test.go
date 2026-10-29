package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Olsenius/ipgate/internal/auth"
	"github.com/Olsenius/ipgate/internal/config"
	"github.com/Olsenius/ipgate/internal/oidctest"
	"github.com/Olsenius/ipgate/internal/store"
)

const publicURL = "https://enable.example"

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	t     *testing.T
	cfg   *config.Config
	store *store.Store
	op    *oidctest.Server
	h     http.Handler
	logs  *syncBuffer
}

func newEnv(t *testing.T, mutate func(*config.Config)) *env {
	t.Helper()
	op := oidctest.NewServer("ipgate", "client-secret")
	t.Cleanup(op.Close)
	pu, _ := url.Parse(publicURL)
	cfg := &config.Config{
		PublicURL:        pu,
		OIDCIssuer:       op.Issuer,
		OIDCClientID:     "ipgate",
		OIDCClientSecret: "client-secret",
		SessionSecret:    []byte(strings.Repeat("x", 32)),
		ClientIPHeader:   "X-Client-IP",
		DefaultTTL:       168 * time.Hour,
		MaxTTL:           720 * time.Hour,
		SessionTTL:       12 * time.Hour,
		DataDir:          t.TempDir(),
	}
	if mutate != nil {
		mutate(cfg)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "allowlist.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	o := auth.NewOIDC(auth.OIDCConfig{Issuer: cfg.OIDCIssuer, ClientID: cfg.OIDCClientID, ClientSecret: cfg.OIDCClientSecret, RedirectURL: cfg.RedirectURL()})
	if err := o.Discover(); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s, err := New(cfg, st, o, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{t: t, cfg: cfg, store: st, op: op, h: s.Handler(), logs: logs}
}

// browser keeps cookies by hand: they are Secure, which net/http/cookiejar would
// not send over the plain-HTTP test transport.
type browser struct {
	e       *env
	ip      string
	cookies map[string]*http.Cookie
	headers map[string]string
}

func (e *env) browser(ip string) *browser {
	return &browser{e: e, ip: ip, cookies: map[string]*http.Cookie{}, headers: map[string]string{}}
}

func (b *browser) do(method, target string, form url.Values) *http.Response {
	b.e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, publicURL+target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if b.ip != "" {
		req.Header.Set("X-Client-IP", b.ip)
	}
	req.Header.Set("User-Agent", "TestBrowser/1.0")
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}
	for _, c := range b.cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	rec := httptest.NewRecorder()
	b.e.h.ServeHTTP(rec, req)
	resp := rec.Result()
	for _, c := range resp.Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
	return resp
}

func bodyOf(t *testing.T, r *http.Response) string {
	t.Helper()
	b, _ := io.ReadAll(r.Body)
	return string(b)
}

// startLogin runs /login and the provider's authorize step, returning the callback
// path+query the provider redirected to.
func (b *browser) startLogin() string {
	t := b.e.t
	t.Helper()
	resp := b.do("GET", "/login", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("/login status %d: %s", resp.StatusCode, bodyOf(t, resp))
	}
	authURL := resp.Header.Get("Location")
	if !strings.HasPrefix(authURL, b.e.op.Issuer+"/authorize?") {
		t.Fatalf("/login redirected to %q", authURL)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pr, err := client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	cb, _ := url.Parse(pr.Header.Get("Location"))
	if cb.Scheme+"://"+cb.Host != publicURL || cb.Path != "/auth/callback" {
		t.Fatalf("provider redirected to %q", cb)
	}
	return cb.RequestURI()
}

func (b *browser) login(user oidctest.User) {
	t := b.e.t
	t.Helper()
	b.e.op.Set(func(s *oidctest.Settings) { *s = oidctest.Settings{User: user} })
	resp := b.do("GET", b.startLogin(), nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback status %d location %q: %s", resp.StatusCode, resp.Header.Get("Location"), bodyOf(t, resp))
	}
	if b.cookies[sessionCookie] == nil {
		t.Fatal("no session cookie after login")
	}
	if b.cookies[loginCookie] != nil {
		t.Fatal("login cookie not cleared after callback")
	}
}

func (b *browser) csrf() string {
	t := b.e.t
	t.Helper()
	page := bodyOf(t, b.do("GET", "/", nil))
	const marker = `name="csrf" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		t.Fatalf("no csrf token on page:\n%s", page)
	}
	rest := page[i+len(marker):]
	return rest[:strings.IndexByte(rest, '"')]
}

func (b *browser) post(path string, form url.Values) *http.Response {
	b.e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if !form.Has("csrf") {
		form.Set("csrf", b.csrf())
	}
	return b.do("POST", path, form)
}

func (e *env) check(ip string, extra map[string]string) int {
	e.t.Helper()
	req := httptest.NewRequest("GET", "http://ipgate:8080/check", nil)
	if ip != "" {
		req.Header.Set("X-Client-IP", ip)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code
}

func (e *env) put(ip, sub string, ttl time.Duration) {
	e.t.Helper()
	now := time.Now()
	created := now.Add(min(ttl, 0) - time.Hour) // also allows already-expired entries
	if err := e.store.Put(store.Entry{IP: netip.MustParseAddr(ip), Sub: sub, User: sub, CreatedAt: created, ExpiresAt: now.Add(ttl)}); err != nil {
		e.t.Fatal(err)
	}
}

var (
	alice = oidctest.User{Sub: "alice-sub", Name: "Alice", Groups: []string{"media"}}
	bob   = oidctest.User{Sub: "bob-sub", Name: "Bob", Groups: []string{"media"}}
	admin = oidctest.User{Sub: "admin-sub", Name: "Admin", Groups: []string{"media", "admins"}}
)

// --- /check ---

func TestCheck(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.AlwaysAllow = []netip.Prefix{netip.MustParsePrefix("10.116.0.0/24"), netip.MustParsePrefix("fd7a:115c::/32")}
	})
	e.put("203.0.113.10", "alice", time.Hour)
	e.put("2001:db8:aa:bb:1:2:3:4", "alice", time.Hour)
	e.put("203.0.113.20", "alice", -time.Minute) // already expired

	cases := []struct {
		name  string
		ip    string
		extra map[string]string
		want  int
	}{
		{"allowed", "203.0.113.10", nil, 204},
		{"allowed with whitespace", " 203.0.113.10 ", nil, 204},
		{"allowed ipv4-mapped", "::ffff:203.0.113.10", nil, 204},
		{"other ip", "203.0.113.11", nil, 403},
		{"expired", "203.0.113.20", nil, 403},
		{"missing header", "", nil, 403},
		{"garbage header", "not-an-ip", nil, 403},
		{"ip with port", "203.0.113.10:443", nil, 403},
		{"spoofed x-forwarded-for ignored", "198.51.100.1", map[string]string{"X-Forwarded-For": "203.0.113.10", "X-Real-IP": "203.0.113.10"}, 403},
		{"x-forwarded-for alone ignored", "", map[string]string{"X-Forwarded-For": "203.0.113.10"}, 403},
		{"always allow lan", "10.116.0.1", nil, 204},
		{"always allow tailnet v6", "fd7a:115c:a1e0::1", nil, 204},
		{"outside always allow", "10.116.1.1", nil, 403},
		{"ipv6 same /64", "2001:db8:aa:bb:ffff:ffff:ffff:ffff", nil, 204},
		{"ipv6 other /64", "2001:db8:aa:bc::1", nil, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.check(tc.ip, tc.extra); got != tc.want {
				t.Errorf("check(%q) = %d, want %d", tc.ip, got, tc.want)
			}
		})
	}
}

func TestCheckRemoteAddrIgnored(t *testing.T) {
	e := newEnv(t, nil)
	e.put("203.0.113.10", "alice", time.Hour)
	req := httptest.NewRequest("GET", "/check", nil)
	req.RemoteAddr = "203.0.113.10:5555"
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Errorf("RemoteAddr was trusted: %d", rec.Code)
	}
}

func TestCheckDenyResponse(t *testing.T) {
	e := newEnv(t, nil)
	for _, method := range []string{"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"} {
		req := httptest.NewRequest(method, "/check", nil)
		req.Header.Set("X-Client-IP", "203.0.113.99")
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != 403 {
			t.Errorf("%s /check = %d", method, rec.Code)
		}
		if method == "GET" {
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
				t.Errorf("content-type = %q", ct)
			}
			want := "Access denied from this IP address. Go to https://enable.example to log in."
			if !strings.Contains(rec.Body.String(), want) {
				t.Errorf("body = %q", rec.Body.String())
			}
		}
	}
	e.put("203.0.113.99", "x", time.Hour)
	req := httptest.NewRequest("POST", "/check", nil)
	req.Header.Set("X-Client-IP", "203.0.113.99")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	if rec.Code != 204 || rec.Body.Len() != 0 {
		t.Errorf("allowed POST /check = %d %q", rec.Code, rec.Body.String())
	}
}

func TestCheckCustomHeader(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.ClientIPHeader = "X-Real-Client" })
	e.put("203.0.113.10", "alice", time.Hour)
	if got := e.check("203.0.113.10", nil); got != 403 {
		t.Errorf("default header honoured with custom CLIENT_IP_HEADER: %d", got)
	}
	if got := e.check("", map[string]string{"X-Real-Client": "203.0.113.10"}); got != 204 {
		t.Errorf("custom header not honoured: %d", got)
	}
}

func TestCheckNotLoggedAtInfo(t *testing.T) {
	e := newEnv(t, nil)
	var buf syncBuffer
	o := auth.NewOIDC(auth.OIDCConfig{Issuer: e.cfg.OIDCIssuer})
	s, _ := New(e.cfg, e.store, o, slog.New(slog.NewJSONHandler(&buf, nil)), nil)
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Client-IP", "203.0.113.1")
	s.Handler().ServeHTTP(httptest.NewRecorder(), req)
	if buf.String() != "" {
		t.Errorf("check logged at info: %s", buf.String())
	}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, nil)
	resp := e.browser("").do("GET", "/healthz", nil)
	if resp.StatusCode != 200 || strings.TrimSpace(bodyOf(t, resp)) != "ok" {
		t.Errorf("healthz = %d", resp.StatusCode)
	}
}

// --- UI ---

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, nil)
	for _, path := range []string{"/", "/static/style.css", "/nope"} {
		resp := e.browser("203.0.113.5").do("GET", path, nil)
		h := resp.Header
		if !strings.Contains(h.Get("Content-Security-Policy"), "default-src 'self'") ||
			h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Referrer-Policy") != "same-origin" ||
			h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: missing security headers: %v", path, h)
		}
	}
}

func TestIndexAnonymous(t *testing.T) {
	e := newEnv(t, nil)
	resp := e.browser("203.0.113.5").do("GET", "/", nil)
	page := bodyOf(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(page, "203.0.113.5") || !strings.Contains(page, `href="/login"`) || !strings.Contains(page, "Log in") {
		t.Errorf("anonymous index: %d\n%s", resp.StatusCode, page)
	}
	if strings.Contains(page, `action="/allow"`) {
		t.Error("allow form shown to anonymous user")
	}
	if !strings.Contains(page, `lang="en"`) {
		t.Error("page not marked as English")
	}
}

func TestFullFlow(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)

	page := bodyOf(t, b.do("GET", "/", nil))
	for _, want := range []string{"Alice", "Not allowed", "1 day", "7 days", "30 days", `value="168h0m0s" checked`, "mobile data", "Log out", "Allow this IP address"} {
		if !strings.Contains(page, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Fatal("allowed before /allow")
	}

	resp := b.post("/allow", url.Values{"duration": {"24h0m0s"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?m=allowed" {
		t.Fatalf("allow: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.check("203.0.113.5", nil) != 204 {
		t.Fatal("not allowed after /allow")
	}
	if e.check("203.0.113.6", nil) != 403 {
		t.Fatal("other IP allowed")
	}
	entries := e.store.List(nil)
	if len(entries) != 1 || entries[0].Sub != "alice-sub" || entries[0].User != "Alice" || entries[0].UserAgent != "TestBrowser/1.0" {
		t.Fatalf("entries = %+v", entries)
	}
	if d := time.Until(entries[0].ExpiresAt); d < 23*time.Hour || d > 25*time.Hour {
		t.Errorf("expiry %v from now, want ~24h", d)
	}

	page = bodyOf(t, b.do("GET", "/?m=allowed", nil))
	for _, want := range []string{"Your IP address is now allowed.", "Allowed until", "Your entries", "TestBrowser/1.0", "Extend", "Remove"} {
		if !strings.Contains(page, want) {
			t.Errorf("index after allow missing %q", want)
		}
	}
	if strings.Contains(page, "All entries") {
		t.Error("non-admin sees admin list")
	}

	resp = b.post("/revoke", url.Values{"ip": {"203.0.113.5"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?m=revoked" {
		t.Fatalf("revoke: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Fatal("still allowed after revoke")
	}

	resp = b.post("/logout", nil)
	if resp.StatusCode != http.StatusSeeOther || b.cookies[sessionCookie] != nil {
		t.Fatalf("logout: %d, cookie still set: %v", resp.StatusCode, b.cookies[sessionCookie] != nil)
	}
	if strings.Contains(bodyOf(t, b.do("GET", "/", nil)), "Log out") {
		t.Error("still logged in after logout")
	}

	logs := e.logs.String()
	for _, want := range []string{`"msg":"login succeeded"`, `"msg":"ip allowed"`, `"msg":"ip revoked"`, `"msg":"logout"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %s", want)
		}
	}
}

func TestLogsContainNoSecrets(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	session := b.cookies[sessionCookie].Value
	b.post("/allow", url.Values{"duration": {"24h0m0s"}})
	logs := e.logs.String()
	for _, secret := range []string{session, "client-secret", string(e.cfg.SessionSecret)} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain secret %q", secret[:min(len(secret), 12)])
		}
	}
}

func TestAllowUsesHeaderIPNotForm(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	b.post("/allow", url.Values{"duration": {"24h0m0s"}, "ip": {"198.51.100.77"}})
	if e.check("198.51.100.77", nil) != 403 {
		t.Error("IP from form was allowed")
	}
	if e.check("203.0.113.5", nil) != 204 {
		t.Error("IP from header was not allowed")
	}
	// X-Forwarded-For on the UI is ignored too.
	b.ip = ""
	b.headers["X-Forwarded-For"] = "198.51.100.88"
	resp := b.post("/allow", url.Values{"duration": {"24h0m0s"}})
	if resp.Header.Get("Location") != "/?m=noip" || e.check("198.51.100.88", nil) != 403 {
		t.Errorf("allow without client IP header: %q", resp.Header.Get("Location"))
	}
}

func TestAllowRefusesPrivate(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	for _, ip := range []string{"10.116.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.10", "127.0.0.1", "100.64.0.1", "100.127.255.254", "::1", "fd00::1", "fc00::1", "fe80::1", "169.254.1.1", "0.0.0.0", "::ffff:192.168.1.1"} {
		b.ip = ip
		resp := b.post("/allow", url.Values{"duration": {"24h0m0s"}})
		if resp.Header.Get("Location") != "/?m=private" {
			t.Errorf("allow from %s: %d %q", ip, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if n := len(e.store.List(nil)); n != 0 {
		t.Errorf("private IPs stored: %d", n)
	}
	b.ip = "192.168.1.10"
	page := bodyOf(t, b.do("GET", "/?m=private", nil))
	if !strings.Contains(page, "private or local address") || strings.Contains(page, `action="/allow"`) {
		t.Error("private IP page should explain and hide the allow form")
	}
	// Edges just outside the refused ranges are accepted.
	for _, ip := range []string{"172.32.0.1", "100.128.0.1", "11.0.0.1"} {
		b.ip = ip
		if loc := b.post("/allow", url.Values{"duration": {"24h0m0s"}}).Header.Get("Location"); loc != "/?m=allowed" {
			t.Errorf("allow from %s: %q", ip, loc)
		}
	}
}

func TestAllowDurationValidation(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.MaxTTL = 168 * time.Hour })
	b := e.browser("203.0.113.5")
	b.login(alice)
	page := bodyOf(t, b.do("GET", "/", nil))
	if strings.Contains(page, "30 days") || !strings.Contains(page, "7 days") {
		t.Error("durations above MAX_TTL shown")
	}
	for _, d := range []string{"720h0m0s", "1000h", "", "abc", "-24h0m0s", "24h"} {
		if loc := b.post("/allow", url.Values{"duration": {d}}).Header.Get("Location"); loc != "/?m=duration" {
			t.Errorf("duration %q accepted: %q", d, loc)
		}
	}
	if loc := b.post("/allow", url.Values{"duration": {"168h0m0s"}}).Header.Get("Location"); loc != "/?m=allowed" {
		t.Errorf("valid duration rejected: %q", loc)
	}
}

func TestReallowRefreshesAndTakesOwnership(t *testing.T) {
	e := newEnv(t, nil)
	a := e.browser("203.0.113.5")
	a.login(alice)
	a.post("/allow", url.Values{"duration": {"24h0m0s"}})
	b := e.browser("203.0.113.5")
	b.login(bob)
	b.post("/allow", url.Values{"duration": {"720h0m0s"}})
	es := e.store.List(nil)
	if len(es) != 1 || es[0].Sub != "bob-sub" || time.Until(es[0].ExpiresAt) < 700*time.Hour {
		t.Fatalf("entries = %+v", es)
	}
}

func TestCSRFRequired(t *testing.T) {
	e := newEnv(t, nil)
	a := e.browser("203.0.113.5")
	a.login(alice)
	other := e.browser("203.0.113.5")
	other.login(alice) // same user, different session
	otherToken := other.csrf()

	for _, path := range []string{"/allow", "/revoke", "/logout"} {
		for name, tok := range map[string]string{"missing": "", "wrong": "abc", "other session": otherToken} {
			form := url.Values{"duration": {"24h0m0s"}, "ip": {"203.0.113.5"}, "csrf": {tok}}
			resp := a.do("POST", path, form)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s with %s token: %d", path, name, resp.StatusCode)
			}
		}
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Error("allow succeeded without CSRF token")
	}
	if a.cookies[sessionCookie] == nil {
		t.Error("logout succeeded without CSRF token")
	}
}

func TestOriginCheck(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	for _, origin := range []string{"https://evil.example", "null", "http://enable.example", "https://enable.example:8443"} {
		b.headers["Origin"] = origin
		if resp := b.post("/allow", url.Values{"duration": {"24h0m0s"}}); resp.StatusCode != http.StatusForbidden {
			t.Errorf("Origin %q: %d", origin, resp.StatusCode)
		}
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Fatal("cross-origin allow succeeded")
	}
	b.headers["Origin"] = publicURL
	if loc := b.post("/allow", url.Values{"duration": {"24h0m0s"}}).Header.Get("Location"); loc != "/?m=allowed" {
		t.Errorf("same-origin allow: %q", loc)
	}
	delete(b.headers, "Origin")
	if loc := b.post("/revoke", url.Values{"ip": {"203.0.113.5"}}).Header.Get("Location"); loc != "/?m=revoked" {
		t.Errorf("allow without Origin: %q", loc)
	}
}

func TestPostWithoutSession(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	resp := b.do("POST", "/allow", url.Values{"duration": {"24h0m0s"}, "csrf": {"x"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?m=expired" {
		t.Errorf("unauthenticated allow: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Error("unauthenticated allow succeeded")
	}
	// A forged session cookie is rejected.
	b.cookies[sessionCookie] = &http.Cookie{Name: sessionCookie, Value: "eyJleHAiOjk5OTk5OTk5OTl9.AAAA"}
	if resp := b.do("POST", "/allow", url.Values{"duration": {"24h0m0s"}, "csrf": {"x"}}); resp.Header.Get("Location") != "/?m=expired" {
		t.Errorf("forged session: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestRevokeOwnershipAndAdmin(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.AdminGroups = []string{"admins"} })
	a := e.browser("203.0.113.5")
	a.login(alice)
	a.post("/allow", url.Values{"duration": {"24h0m0s"}})

	b := e.browser("198.51.100.9")
	b.login(bob)
	if strings.Contains(bodyOf(t, b.do("GET", "/", nil)), "203.0.113.5") {
		t.Error("bob sees alice's entry")
	}
	if resp := b.post("/revoke", url.Values{"ip": {"203.0.113.5"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob revoking alice's entry: %d", resp.StatusCode)
	}
	if e.check("203.0.113.5", nil) != 204 {
		t.Fatal("entry removed by non-owner")
	}
	if loc := b.post("/revoke", url.Values{"ip": {"192.0.2.200"}}).Header.Get("Location"); loc != "/?m=notfound" {
		t.Errorf("revoke unknown: %q", loc)
	}
	if loc := b.post("/revoke", url.Values{"ip": {"garbage"}}).Header.Get("Location"); loc != "/?m=notfound" {
		t.Errorf("revoke garbage: %q", loc)
	}

	ad := e.browser("198.51.100.10")
	ad.login(admin)
	page := bodyOf(t, ad.do("GET", "/", nil))
	if !strings.Contains(page, "All entries") || !strings.Contains(page, "203.0.113.5") || !strings.Contains(page, "Alice") {
		t.Errorf("admin list missing alice's entry:\n%s", page)
	}
	if loc := ad.post("/revoke", url.Values{"ip": {"203.0.113.5"}}).Header.Get("Location"); loc != "/?m=revoked" {
		t.Errorf("admin revoke: %q", loc)
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Fatal("admin revoke did not take effect")
	}
}

func TestRevokeIPv6AnyAddressInPrefix(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("2001:db8:1:2::abcd")
	b.login(alice)
	b.post("/allow", url.Values{"duration": {"24h0m0s"}})
	if e.check("2001:db8:1:2:9::9", nil) != 204 {
		t.Fatal("IPv6 /64 not allowed")
	}
	if loc := b.post("/revoke", url.Values{"ip": {"2001:db8:1:2::abcd"}}).Header.Get("Location"); loc != "/?m=revoked" {
		t.Fatalf("revoke: %q", loc)
	}
	if e.check("2001:db8:1:2:9::9", nil) != 403 {
		t.Fatal("IPv6 /64 still allowed")
	}
}

// --- login ---

func TestLoginCookies(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	resp := b.do("GET", "/login", nil)
	var lc *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == loginCookie {
			lc = c
		}
	}
	if lc == nil {
		t.Fatal("no login cookie")
	}
	if !strings.HasPrefix(lc.Name, "__Host-") || !strings.HasPrefix(sessionCookie, "__Host-") {
		t.Error("cookies must use the __Host- prefix")
	}
	if !lc.HttpOnly || !lc.Secure || lc.SameSite != http.SameSiteLaxMode || lc.Path != "/" || lc.Domain != "" || lc.MaxAge != 600 {
		t.Errorf("login cookie attributes: %+v", lc)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("state") == "" || q.Get("nonce") == "" {
		t.Errorf("auth URL lacks PKCE/state/nonce: %s", loc)
	}
	if q.Get("redirect_uri") != publicURL+"/auth/callback" || q.Get("scope") != "openid profile email groups" {
		t.Errorf("auth URL redirect/scope: %s", loc)
	}

	b2 := e.browser("203.0.113.5")
	b2.login(alice)
	sc := b2.cookies[sessionCookie]
	if !sc.HttpOnly || !sc.Secure || sc.SameSite != http.SameSiteLaxMode || sc.Path != "/" || sc.Domain != "" || sc.MaxAge != 12*3600 {
		t.Errorf("session cookie attributes: %+v", sc)
	}
	// Already logged in: /login goes straight home.
	if resp := b2.do("GET", "/login", nil); resp.Header.Get("Location") != "/" {
		t.Errorf("/login when logged in: %q", resp.Header.Get("Location"))
	}
}

func TestCallbackFailures(t *testing.T) {
	wrongNonce := "not-the-nonce"
	cases := []struct {
		name       string
		cfg        func(*config.Config)
		set        func(*oidctest.Settings)
		tamper     func(b *browser, cb string) string
		wantStatus int
		wantText   string
		wantLog    string
	}{
		{name: "wrong nonce", set: func(s *oidctest.Settings) { s.Nonce = &wrongNonce }, wantStatus: 502, wantText: "Login failed", wantLog: "nonce mismatch"},
		{name: "wrong audience", set: func(s *oidctest.Settings) { s.Audience = "other-client" }, wantStatus: 502, wantText: "Login failed", wantLog: "audience"},
		{name: "bad signature", set: func(s *oidctest.Settings) { s.BadSignature = true }, wantStatus: 502, wantText: "Login failed", wantLog: "signature"},
		{
			name:       "group not allowed",
			cfg:        func(c *config.Config) { c.AllowedGroups = []string{"media"} },
			set:        func(s *oidctest.Settings) { s.User.Groups = []string{"other"} },
			wantStatus: 403, wantText: "You do not have access", wantLog: "not in allowed groups",
		},
		{
			name:       "no groups claim",
			cfg:        func(c *config.Config) { c.AllowedGroups = []string{"media"} },
			set:        func(s *oidctest.Settings) { s.User.Groups = nil },
			wantStatus: 403, wantText: "You do not have access", wantLog: "not in allowed groups",
		},
		{
			name: "state mismatch",
			tamper: func(b *browser, cb string) string {
				u, _ := url.Parse(cb)
				q := u.Query()
				q.Set("state", "forged")
				u.RawQuery = q.Encode()
				return u.RequestURI()
			},
			wantStatus: 400, wantText: "Login failed", wantLog: "state mismatch",
		},
		{
			name:       "missing login cookie",
			tamper:     func(b *browser, cb string) string { delete(b.cookies, loginCookie); return cb },
			wantStatus: 400, wantText: "Login failed", wantLog: "missing login state",
		},
		{
			name: "login cookie from another attempt",
			tamper: func(b *browser, cb string) string {
				b.do("GET", "/login", nil) // overwrites cookie with fresh state/verifier
				return cb
			},
			wantStatus: 400, wantText: "Login failed", wantLog: "state mismatch",
		},
		{
			name:       "provider error",
			tamper:     func(b *browser, cb string) string { return "/auth/callback?error=access_denied&state=x" },
			wantStatus: 400, wantText: "Login failed", wantLog: "access_denied",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.cfg)
			e.op.Set(func(s *oidctest.Settings) {
				*s = oidctest.Settings{User: alice}
				s.User.Groups = append([]string(nil), alice.Groups...)
				if tc.set != nil {
					tc.set(s)
				}
			})
			b := e.browser("203.0.113.5")
			cb := b.startLogin()
			if tc.tamper != nil {
				cb = tc.tamper(b, cb)
			}
			resp := b.do("GET", cb, nil)
			page := bodyOf(t, resp)
			if resp.StatusCode != tc.wantStatus || !strings.Contains(page, tc.wantText) {
				t.Errorf("status %d (want %d), page:\n%s", resp.StatusCode, tc.wantStatus, page)
			}
			if b.cookies[sessionCookie] != nil {
				t.Error("session cookie set despite failure")
			}
			if logs := e.logs.String(); !strings.Contains(logs, `"msg":"login failed"`) || !strings.Contains(logs, tc.wantLog) {
				t.Errorf("logs missing failure reason %q:\n%s", tc.wantLog, logs)
			}
		})
	}
}

func TestAllowedGroupsAndAdminFlag(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.AllowedGroups = []string{"media", "family"}
		c.AdminGroups = []string{"admins"}
	})
	b := e.browser("203.0.113.5")
	b.login(oidctest.User{Sub: "fam", Name: "Fam", Groups: []string{"family"}})
	if strings.Contains(bodyOf(t, b.do("GET", "/", nil)), "All entries") {
		t.Error("non-admin flagged as admin")
	}
	ad := e.browser("203.0.113.6")
	ad.login(admin)
	if !strings.Contains(bodyOf(t, ad.do("GET", "/", nil)), "All entries") {
		t.Error("admin not flagged as admin")
	}
}

func TestLoginWhileOIDCUnavailable(t *testing.T) {
	e := newEnv(t, nil)
	e.put("203.0.113.10", "alice", time.Hour)
	// A server whose OIDC client never discovered anything.
	o := auth.NewOIDC(auth.OIDCConfig{Issuer: "http://127.0.0.1:1"})
	s, err := New(e.cfg, e.store, o, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	e.h = s.Handler()
	resp := e.browser("203.0.113.5").do("GET", "/login", nil)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(bodyOf(t, resp), "Login unavailable") {
		t.Errorf("/login without OIDC: %d", resp.StatusCode)
	}
	if e.check("203.0.113.10", nil) != 204 || e.check("203.0.113.11", nil) != 403 {
		t.Error("/check does not work without OIDC")
	}
}

func TestExpiredSessionIgnored(t *testing.T) {
	e := newEnv(t, nil)
	signer := auth.NewSigner(e.cfg.SessionSecret, func() time.Time { return time.Now().Add(-24 * time.Hour) })
	sess := signer.NewSession("alice-sub", "Alice", false, time.Hour)
	v, _ := signer.EncodeSession(sess)
	b := e.browser("203.0.113.5")
	b.cookies[sessionCookie] = &http.Cookie{Name: sessionCookie, Value: v}
	if strings.Contains(bodyOf(t, b.do("GET", "/", nil)), "Log out") {
		t.Error("expired session accepted")
	}
}

func TestDurationChoices(t *testing.T) {
	label := func(cs []durationChoice) string {
		var s []string
		for _, c := range cs {
			s = append(s, c.Label)
		}
		return strings.Join(s, ",")
	}
	for _, tc := range []struct {
		def, max time.Duration
		want     string
	}{
		{168 * time.Hour, 720 * time.Hour, "1 day,7 days,30 days"},
		{168 * time.Hour, 168 * time.Hour, "1 day,7 days"},
		{48 * time.Hour, 720 * time.Hour, "1 day,2 days,7 days,30 days"},
		{12 * time.Hour, 12 * time.Hour, "12 hours"},
	} {
		if got := label(durationChoices(tc.def, tc.max)); got != tc.want {
			t.Errorf("choices(%v, %v) = %q, want %q", tc.def, tc.max, got, tc.want)
		}
	}
}

func BenchmarkCheck(b *testing.B) {
	st, _ := store.Open(filepath.Join(b.TempDir(), "allowlist.json"), nil)
	st.Put(store.Entry{IP: netip.MustParseAddr("203.0.113.10"), Sub: "x", User: "x", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	pu, _ := url.Parse(publicURL)
	cfg := &config.Config{PublicURL: pu, SessionSecret: make([]byte, 32), ClientIPHeader: "X-Client-IP", DefaultTTL: time.Hour, MaxTTL: time.Hour}
	s, _ := New(cfg, st, auth.NewOIDC(auth.OIDCConfig{}), slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	h := s.Handler()
	req := httptest.NewRequest("GET", "/check", nil)
	req.Header.Set("X-Client-IP", "203.0.113.10")
	w := &discardWriter{h: http.Header{}}
	b.ReportAllocs()
	for b.Loop() {
		h.ServeHTTP(w, req)
	}
}

type discardWriter struct{ h http.Header }

func (d *discardWriter) Header() http.Header         { return d.h }
func (d *discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (d *discardWriter) WriteHeader(int)             {}

func TestCallbackFailureLogsContainNoUpstreamContent(t *testing.T) {
	secretBody := `{"access_token":"SECRET-ACCESS-MARKER","refresh_token":"SECRET-REFRESH-MARKER","id_token":"SECRET-ID-MARKER"}`
	cases := map[string]struct {
		set     func(*oidctest.Settings)
		tamper  func(cb string) string
		wantLog string
	}{
		"token endpoint 502 with token body": {
			set:     func(s *oidctest.Settings) { s.Token = &oidctest.Response{Status: 502, Body: secretBody} },
			wantLog: "token endpoint: unsuccessful response (HTTP 502)",
		},
		"token endpoint error description": {
			set: func(s *oidctest.Settings) {
				s.Token = &oidctest.Response{Status: 400, Body: `{"error":"invalid_grant","error_description":"DESC-MARKER"}`}
			},
			wantLog: "provider error invalid_grant (HTTP 400)",
		},
		"jwks failure with body": {
			set:     func(s *oidctest.Settings) { s.JWKS = &oidctest.Response{Status: 500, Body: secretBody} },
			wantLog: "id token: jwks fetch failed",
		},
		"callback error_description": {
			tamper: func(cb string) string {
				return "/auth/callback?error=CODE-MARKER&error_description=SECRET-DESC-MARKER&state=x"
			},
			wantLog: `"error":"other"`,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.op.Set(func(s *oidctest.Settings) { *s = oidctest.Settings{User: alice} })
			b := e.browser("203.0.113.5")
			cb := b.startLogin()
			if tc.set != nil {
				e.op.Set(tc.set)
			}
			if tc.tamper != nil {
				cb = tc.tamper(cb)
			}
			resp := b.do("GET", cb, nil)
			if resp.StatusCode < 400 || b.cookies[sessionCookie] != nil {
				t.Fatalf("login did not fail: %d", resp.StatusCode)
			}
			logs := e.logs.String()
			if !strings.Contains(logs, `"msg":"login failed"`) || !strings.Contains(logs, tc.wantLog) {
				t.Errorf("logs missing %q:\n%s", tc.wantLog, logs)
			}
			if strings.Contains(logs, "MARKER") {
				t.Errorf("logs leak upstream content:\n%s", logs)
			}
			if page := bodyOf(t, resp); strings.Contains(page, "MARKER") {
				t.Errorf("page leaks upstream content:\n%s", page)
			}
		})
	}
}

func TestStorageNotDurableIsReported(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	e.store.SetDirSyncForTest(func(string) error { return errors.New("injected EIO") })

	if loc := b.post("/allow", url.Values{"duration": {"24h0m0s"}}).Header.Get("Location"); loc != "/?m=unsynced" {
		t.Fatalf("allow: %q", loc)
	}
	if e.check("203.0.113.5", nil) != 204 {
		t.Error("entry on disk but not active")
	}
	page := bodyOf(t, b.do("GET", "/?m=unsynced", nil))
	if !strings.Contains(page, "could not confirm it was saved to disk") {
		t.Error("durability warning not shown")
	}
	if loc := b.post("/revoke", url.Values{"ip": {"203.0.113.5"}}).Header.Get("Location"); loc != "/?m=unsynced" {
		t.Fatalf("revoke: %q", loc)
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Error("revoke not in effect after directory sync failure (must fail closed)")
	}
	// Both warning events carry the same audit fields as the normal events.
	for _, msg := range []string{"ip allowed but not confirmed durable", "ip revoked but not confirmed durable"} {
		ev := logEvent(t, e.logs.String(), msg)
		if ev == nil {
			t.Errorf("logs missing %q", msg)
			continue
		}
		for _, k := range []string{"user", "sub", "ip", "expires_at", "err"} {
			if v, _ := ev[k].(string); v == "" {
				t.Errorf("%q event missing %s: %v", msg, k, ev)
			}
		}
		if exp, _ := ev["expires_at"].(string); exp != "" {
			ts, err := time.Parse(time.RFC3339, exp)
			if err != nil || !strings.HasSuffix(exp, "Z") || time.Until(ts) < 23*time.Hour {
				t.Errorf("%q expires_at = %q, want UTC RFC 3339 about 24h ahead", msg, exp)
			}
		}
	}
}

func TestStorageWriteFailureIsReported(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	if err := os.Chmod(e.cfg.DataDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(e.cfg.DataDir, 0o700)
	if f, err := os.CreateTemp(e.cfg.DataDir, "probe"); err == nil {
		f.Close()
		t.Skip("directory still writable (running as root?)")
	}
	if loc := b.post("/allow", url.Values{"duration": {"24h0m0s"}}).Header.Get("Location"); loc != "/?m=error" {
		t.Fatalf("allow: %q", loc)
	}
	if e.check("203.0.113.5", nil) != 403 {
		t.Error("failed write is active")
	}
}

func TestPlainCookieNamesIgnored(t *testing.T) {
	// A valid session value under the old unprefixed name (as a sibling subdomain
	// could plant it) is not accepted.
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	v := b.cookies[sessionCookie].Value
	delete(b.cookies, sessionCookie)
	b.cookies["ipgate_session"] = &http.Cookie{Name: "ipgate_session", Value: v}
	if strings.Contains(bodyOf(t, b.do("GET", "/", nil)), "Log out") {
		t.Error("unprefixed session cookie accepted")
	}
}

// logEvent returns the first JSON log event with the given msg.
func logEvent(t *testing.T, logs, msg string) map[string]any {
	t.Helper()
	for line := range strings.SplitSeq(logs, "\n") {
		var ev map[string]any
		if json.Unmarshal([]byte(line), &ev) == nil && ev["msg"] == msg {
			return ev
		}
	}
	return nil
}

// TestReferrerPolicyKeepsOriginOnForms pins Referrer-Policy to "same-origin".
// With "no-referrer", real browsers send "Origin: null" on same-origin form
// POSTs, so every /allow was rejected in production. Do not change it to
// no-referrer, and keep rejecting Origin: null.
func TestReferrerPolicyKeepsOriginOnForms(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser("203.0.113.5")
	b.login(alice)
	for _, path := range []string{"/", "/login", "/nope"} {
		if got := e.browser("203.0.113.5").do("GET", path, nil).Header.Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf("%s: Referrer-Policy = %q, want same-origin", path, got)
		}
	}
	if got := b.do("GET", "/", nil).Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("logged-in page: Referrer-Policy = %q", got)
	}
	// What a browser sends under same-origin policy: the real origin. Accepted.
	b.headers["Origin"] = publicURL
	if loc := b.post("/allow", url.Values{"duration": {"24h0m0s"}}).Header.Get("Location"); loc != "/?m=allowed" {
		t.Errorf("same-origin POST rejected: %q", loc)
	}
	// What a browser sends under no-referrer (or from a sandboxed/opaque context). Still rejected.
	b.headers["Origin"] = "null"
	if resp := b.post("/revoke", url.Values{"ip": {"203.0.113.5"}}); resp.StatusCode != http.StatusForbidden {
		t.Errorf("Origin: null accepted: %d", resp.StatusCode)
	}
}
