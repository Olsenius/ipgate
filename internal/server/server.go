// Package server implements ipgate's HTTP handlers: the Caddy forward_auth check
// endpoint and the web UI.
package server

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // distroless has no zoneinfo; embed it for Europe/Oslo
	"unicode/utf8"

	"github.com/Olsenius/ipgate/internal/auth"
	"github.com/Olsenius/ipgate/internal/config"
	"github.com/Olsenius/ipgate/internal/store"
)

//go:embed web
var webFS embed.FS

const (
	sessionCookie = "ipgate_session"
	loginCookie   = "ipgate_login"
	loginTTL      = 10 * time.Minute
	maxUserAgent  = 200
	maxFormBytes  = 8 << 10
)

// refusedPrefixes are never added to the allowlist: private, loopback, CGNAT,
// unique-local and link-local ranges.
var refusedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// Refused reports whether a may not be allowlisted. Besides the ranges above it
// rejects anything that is not global unicast (unspecified, multicast, IPv4
// link-local, ...).
func Refused(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range refusedPrefixes {
		if p.Contains(a) {
			return true
		}
	}
	return !a.IsGlobalUnicast()
}

// OIDCClient is the part of auth.OIDC the server uses.
type OIDCClient interface {
	AuthCodeURL(auth.LoginState) (string, error)
	Exchange(ctx context.Context, code string, ls auth.LoginState) (*auth.Claims, error)
}

type durationChoice struct {
	d     time.Duration
	Value string
	Label string
}

// Server holds the handler dependencies.
type Server struct {
	cfg    *config.Config
	store  *store.Store
	oidc   OIDCClient
	signer *auth.Signer
	log    *slog.Logger
	now    func() time.Time
	loc    *time.Location
	tmpl   *template.Template
	css    []byte

	durations []durationChoice
	denyBody  []byte
	csp       string
}

// New creates a Server. now may be nil (time.Now).
func New(cfg *config.Config, st *store.Store, oidc OIDCClient, log *slog.Logger, now func() time.Time) (*Server, error) {
	if now == nil {
		now = time.Now
	}
	loc, err := time.LoadLocation("Europe/Oslo")
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"entries": func(es []entryView, csrf string) any {
			return struct {
				Entries []entryView
				CSRF    string
			}{es, csrf}
		},
	}).ParseFS(webFS, "web/*.html")
	if err != nil {
		return nil, err
	}
	css, err := webFS.ReadFile("web/style.css")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, store: st, oidc: oidc, log: log, now: now, loc: loc, tmpl: tmpl, css: css,
		signer:    auth.NewSigner(cfg.SessionSecret, now),
		durations: durationChoices(cfg.DefaultTTL, cfg.MaxTTL),
		denyBody:  fmt.Appendf(nil, "Access denied from this IP address. Go to %s to log in.\n", cfg.PublicURL),
		csp:       "default-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
	}
	return s, nil
}

// durationChoices returns 1, 7 and 30 days (those <= max), plus the default if it
// is not one of them.
func durationChoices(def, max time.Duration) []durationChoice {
	var out []durationChoice
	add := func(d time.Duration) {
		if d > max || slices.ContainsFunc(out, func(c durationChoice) bool { return c.d == d }) {
			return
		}
		out = append(out, durationChoice{d: d, Value: d.String(), Label: durationLabel(d)})
	}
	for _, days := range []int{1, 7, 30} {
		add(time.Duration(days) * 24 * time.Hour)
	}
	add(def)
	slices.SortFunc(out, func(a, b durationChoice) int { return int(a.d - b.d) })
	return out
}

func durationLabel(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		if n := int(d / (24 * time.Hour)); n == 1 {
			return "1 day"
		} else {
			return fmt.Sprintf("%d days", n)
		}
	}
	if d%time.Hour == 0 {
		if n := int(d / time.Hour); n == 1 {
			return "1 hour"
		} else {
			return fmt.Sprintf("%d hours", n)
		}
	}
	return d.String()
}

// Handler returns the HTTP handler with all routes.
func (s *Server) Handler() http.Handler {
	ui := http.NewServeMux()
	ui.HandleFunc("GET /{$}", s.index)
	ui.HandleFunc("GET /static/style.css", s.style)
	ui.HandleFunc("GET /login", s.login)
	ui.HandleFunc("GET /auth/callback", s.callback)
	ui.Handle("POST /allow", s.protect(s.allow))
	ui.Handle("POST /revoke", s.protect(s.revoke))
	ui.Handle("POST /logout", s.protect(s.logout))

	mux := http.NewServeMux()
	mux.HandleFunc("/check", s.check) // any method: forward_auth copies the original one
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("/", s.securityHeaders(ui))
	return mux
}

// clientIP reads the client address from the configured header only.
func (s *Server) clientIP(r *http.Request) (netip.Addr, bool) {
	v := r.Header.Get(s.cfg.ClientIPHeader)
	if v == "" {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func (s *Server) alwaysAllowed(a netip.Addr) bool {
	for _, p := range s.cfg.AlwaysAllow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

var (
	plainText = []string{"text/plain; charset=utf-8"}
	noStore   = []string{"no-store"}
)

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	ip, ok := s.clientIP(r)
	allowed := false
	if ok {
		if s.alwaysAllowed(ip) {
			allowed = true
		} else {
			_, allowed = s.store.Lookup(ip)
		}
	}
	if s.log.Enabled(r.Context(), slog.LevelDebug) {
		s.log.Debug("check", "ip", ip.String(), "valid", ok, "allowed", allowed)
	}
	if allowed {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	h := w.Header()
	h["Content-Type"] = plainText
	h["Cache-Control"] = noStore
	w.WriteHeader(http.StatusForbidden)
	w.Write(s.denyBody)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte("ok\n"))
}

func (s *Server) style(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(s.css)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", s.csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// --- cookies and sessions ---

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) { s.setCookie(w, name, "", -1) }

func (s *Server) session(r *http.Request) (auth.Session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return auth.Session{}, false
	}
	sess, err := s.signer.DecodeSession(c.Value)
	if err != nil {
		return auth.Session{}, false
	}
	return sess, true
}

// protect guards state-changing POSTs: Origin check, form size limit, valid
// session and CSRF token.
func (s *Server) protect(next func(http.ResponseWriter, *http.Request, auth.Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.checkPost(w, r)
		if !ok {
			return
		}
		next(w, r, sess)
	})
}

// checkPost validates a POST and writes an error response if it fails.
func (s *Server) checkPost(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	if o := r.Header.Get("Origin"); o != "" && o != s.cfg.PublicOrigin() {
		s.log.Warn("rejected cross-origin post", "path", r.URL.Path, "origin", truncate(o, 100))
		s.message(w, http.StatusForbidden, "Invalid request", "The request came from another site and was rejected.")
		return auth.Session{}, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.message(w, http.StatusBadRequest, "Invalid request", "The form could not be read.")
		return auth.Session{}, false
	}
	sess, ok := s.session(r)
	if !ok {
		http.Redirect(w, r, "/?m=expired", http.StatusSeeOther)
		return auth.Session{}, false
	}
	if !s.signer.CheckCSRF(sess, r.PostForm.Get("csrf")) {
		s.log.Warn("rejected post with invalid csrf token", "path", r.URL.Path, "user", sess.Name, "sub", sess.Sub)
		s.message(w, http.StatusForbidden, "Invalid form", "The form has expired or is invalid. Reload the page and try again.")
		return auth.Session{}, false
	}
	return sess, true
}

// --- rendering ---

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.log.Error("template render failed", "template", name, "err", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

type messagePage struct {
	Title, Message, LinkURL, LinkText string
}

func (s *Server) message(w http.ResponseWriter, status int, title, msg string) {
	s.render(w, status, "message", messagePage{Title: title, Message: msg, LinkURL: "/", LinkText: "Back to start"})
}

func (s *Server) formatTime(t time.Time) string {
	return t.In(s.loc).Format("2006-01-02 15:04 MST")
}

func truncate(v string, n int) string {
	v = strings.ToValidUTF8(v, "")
	if utf8.RuneCountInString(v) <= n {
		return v
	}
	return string([]rune(v)[:n]) + "…"
}
