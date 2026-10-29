package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/Olsenius/ipgate/internal/auth"
	"github.com/Olsenius/ipgate/internal/store"
)

type flash struct{ Kind, Text string }

// Flash messages are selected by a fixed code in the query string, so nothing
// user-controlled is ever reflected.
var flashes = map[string]flash{
	"allowed":  {"ok", "Your IP address is now allowed."},
	"revoked":  {"ok", "The entry has been removed."},
	"private":  {"bad", "This is a private or local address (home network, CGNAT or similar). Such addresses either already have access or cannot meaningfully be allowed."},
	"noip":     {"bad", "Could not determine your IP address."},
	"duration": {"bad", "Invalid duration. Choose one of the options."},
	"notfound": {"bad", "No active entry found for that address."},
	"expired":  {"bad", "Your session has expired. Please log in again."},
	"error":    {"bad", "Something went wrong. Please try again."},
	"unsynced": {"bad", "The change is in effect, but the server could not confirm it was saved to disk, so it might be lost if the server crashes. Please tell an administrator."},
}

type durationOption struct {
	Value, Label string
	Selected     bool
}

type entryView struct {
	IP, User, Created, Expires, UserAgent string
}

type indexPage struct {
	Title    string
	Return   string // validated "https://<host>/" or ""
	LoginURL string
	Continue bool // show the Continue link to Return
	Flash    *flash
	IP       string
	LoggedIn bool
	Name     string
	Admin    bool
	CSRF     string

	AlwaysAllowed bool
	Allowed       bool
	AllowedUntil  string
	Private       bool
	CanAllow      bool
	Durations     []durationOption

	Mine []entryView
	All  []entryView
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	p := indexPage{Title: "Access", LoginURL: "/login"}
	if p.Return = s.returnURL(r.URL.Query().Get("return")); p.Return != "" {
		p.LoginURL = "/login?" + url.Values{"return": {p.Return}}.Encode()
	}
	if f, ok := flashes[r.URL.Query().Get("m")]; ok {
		p.Flash = &f
	}
	ip, ipOK := s.clientIP(r)
	if ipOK {
		p.IP = ip.String()
	}
	sess, ok := s.session(r)
	if !ok {
		s.render(w, http.StatusOK, "index", p)
		return
	}
	p.LoggedIn, p.Name, p.Admin, p.CSRF = true, sess.Name, sess.Admin, s.signer.CSRFToken(sess)

	if ipOK {
		p.AlwaysAllowed = s.alwaysAllowed(ip)
		p.Private = Refused(ip)
		if e, ok := s.store.Lookup(ip); ok {
			p.Allowed, p.AllowedUntil = true, s.formatTime(e.ExpiresAt)
		}
		p.CanAllow = !p.Private
		p.Continue = p.Return != "" && (p.Allowed || p.AlwaysAllowed)
	}
	for _, c := range s.durations {
		p.Durations = append(p.Durations, durationOption{Value: c.Value, Label: c.Label, Selected: c.d == s.cfg.DefaultTTL})
	}

	view := func(es []store.Entry) []entryView {
		out := make([]entryView, len(es))
		for i, e := range es {
			out[i] = entryView{IP: e.IP.String(), User: e.User, Created: s.formatTime(e.CreatedAt), Expires: s.formatTime(e.ExpiresAt), UserAgent: e.UserAgent}
		}
		return out
	}
	p.Mine = view(s.store.List(func(e store.Entry) bool { return e.Sub == sess.Sub }))
	if sess.Admin {
		p.All = view(s.store.List(nil))
	}
	s.render(w, http.StatusOK, "index", p)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ret := s.returnURL(r.URL.Query().Get("return"))
	if _, ok := s.session(r); ok {
		http.Redirect(w, r, home("", ret), http.StatusFound)
		return
	}
	ls := auth.NewLoginState()
	ls.Return = ret
	u, err := s.oidc.AuthCodeURL(ls)
	if err != nil {
		s.log.Warn("login unavailable", "err", err)
		s.message(w, http.StatusServiceUnavailable, "Login unavailable", "The login service is not responding right now. Please try again shortly.")
		return
	}
	v, err := s.signer.EncodeLogin(ls, loginTTL)
	if err != nil {
		s.log.Error("encode login state", "err", err)
		s.message(w, http.StatusInternalServerError, "Error", "Something went wrong. Please try again.")
		return
	}
	s.setCookie(w, loginCookie, v, int(loginTTL/time.Second))
	http.Redirect(w, r, u, http.StatusFound)
}

func (s *Server) loginFailed(w http.ResponseWriter, status int, reason string, attrs ...any) {
	s.log.Warn("login failed", append([]any{"reason", reason}, attrs...)...)
	s.render(w, status, "message", messagePage{
		Title:    "Login failed",
		Message:  "The login could not be completed. Please try again.",
		LinkURL:  "/login",
		LinkText: "Try again",
	})
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, err := r.Cookie(loginCookie)
	s.clearCookie(w, loginCookie) // single use, whatever happens next
	if err != nil {
		s.loginFailed(w, http.StatusBadRequest, "missing login state cookie")
		return
	}
	ls, err := s.signer.DecodeLogin(c.Value)
	if err != nil {
		s.loginFailed(w, http.StatusBadRequest, "invalid login state cookie", "err", err)
		return
	}
	if e := q.Get("error"); e != "" {
		// error_description is attacker-controllable free text; log only a known code.
		s.loginFailed(w, http.StatusBadRequest, "provider returned error", "error", auth.SafeOAuthCode(e))
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(ls.State)) != 1 {
		s.loginFailed(w, http.StatusBadRequest, "state mismatch")
		return
	}
	code := q.Get("code")
	if code == "" {
		s.loginFailed(w, http.StatusBadRequest, "missing code")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	claims, err := s.oidc.Exchange(ctx, code, ls)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, auth.ErrNotReady) {
			status = http.StatusServiceUnavailable
		}
		s.loginFailed(w, status, "token exchange or verification failed", "err", err)
		return
	}
	user := claims.DisplayName()
	if len(s.cfg.AllowedGroups) > 0 && !intersects(claims.Groups, s.cfg.AllowedGroups) {
		s.log.Warn("login failed", "reason", "not in allowed groups", "user", user, "sub", claims.Sub, "groups", claims.Groups)
		s.render(w, http.StatusForbidden, "message", messagePage{
			Title:    "You do not have access",
			Message:  "Your account is not a member of a group that has access to this service.",
			LinkURL:  "/",
			LinkText: "Back to start",
		})
		return
	}
	admin := intersects(claims.Groups, s.cfg.AdminGroups)
	sess := s.signer.NewSession(claims.Sub, user, admin, s.cfg.SessionTTL)
	v, err := s.signer.EncodeSession(sess)
	if err != nil {
		s.loginFailed(w, http.StatusInternalServerError, "encode session", "err", err)
		return
	}
	s.setCookie(w, sessionCookie, v, int(s.cfg.SessionTTL/time.Second))
	s.log.Info("login succeeded", "user", user, "sub", claims.Sub, "admin", admin)
	// The return URL comes only from the signed login cookie, and is re-validated
	// against the current configuration.
	http.Redirect(w, r, home("", s.returnURL(ls.Return)), http.StatusFound)
}

func intersects(have, want []string) bool {
	for _, g := range have {
		if slices.Contains(want, g) {
			return true
		}
	}
	return false
}

func (s *Server) allow(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ret := s.returnURL(r.PostForm.Get("return"))
	ip, ok := s.clientIP(r)
	if !ok {
		http.Redirect(w, r, home("noip", ret), http.StatusSeeOther)
		return
	}
	if Refused(ip) {
		s.log.Info("allow refused for private address", "user", sess.Name, "sub", sess.Sub, "ip", ip.String())
		http.Redirect(w, r, home("private", ret), http.StatusSeeOther)
		return
	}
	var ttl time.Duration
	for _, c := range s.durations {
		if c.Value == r.PostForm.Get("duration") {
			ttl = c.d
		}
	}
	if ttl <= 0 || ttl > s.cfg.MaxTTL {
		http.Redirect(w, r, home("duration", ret), http.StatusSeeOther)
		return
	}
	now := s.now()
	e := store.Entry{
		IP:        ip,
		Sub:       sess.Sub,
		User:      sess.Name,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		UserAgent: truncate(r.UserAgent(), maxUserAgent),
	}
	err := s.store.Put(e)
	switch {
	case errors.Is(err, store.ErrNotDurable):
		// The entry is in effect (on disk and in memory) but may not survive a crash.
		s.log.Error("ip allowed but not confirmed durable", "user", sess.Name, "sub", sess.Sub, "ip", ip.String(), "expires_at", e.ExpiresAt.UTC().Format(time.RFC3339), "err", err)
		http.Redirect(w, r, home("unsynced", ret), http.StatusSeeOther) // warning first; Continue is shown
	case err != nil:
		s.log.Error("allow failed", "user", sess.Name, "sub", sess.Sub, "ip", ip.String(), "err", err)
		http.Redirect(w, r, home("error", ret), http.StatusSeeOther)
	default:
		s.log.Info("ip allowed", "user", sess.Name, "sub", sess.Sub, "ip", ip.String(), "expires_at", e.ExpiresAt.UTC().Format(time.RFC3339))
		if ret != "" {
			http.Redirect(w, r, ret, http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/?m=allowed", http.StatusSeeOther)
	}
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	ip, err := netip.ParseAddr(r.PostForm.Get("ip"))
	if err != nil {
		http.Redirect(w, r, "/?m=notfound", http.StatusSeeOther)
		return
	}
	e, found, removed, err := s.store.RemoveIf(ip, func(e store.Entry) bool { return sess.Admin || e.Sub == sess.Sub })
	switch {
	case removed && errors.Is(err, store.ErrNotDurable):
		// Access is already revoked in memory (fail closed); a crash before the
		// directory update is durable could bring the old file back.
		s.log.Error("ip revoked but not confirmed durable", "user", sess.Name, "sub", sess.Sub, "admin", sess.Admin, "ip", e.IP.String(), "owner", e.User, "owner_sub", e.Sub, "expires_at", e.ExpiresAt.UTC().Format(time.RFC3339), "err", err)
		http.Redirect(w, r, "/?m=unsynced", http.StatusSeeOther)
	case err != nil:
		s.log.Error("revoke failed", "user", sess.Name, "sub", sess.Sub, "ip", ip.String(), "err", err)
		http.Redirect(w, r, "/?m=error", http.StatusSeeOther)
	case !found:
		http.Redirect(w, r, "/?m=notfound", http.StatusSeeOther)
	case !removed:
		s.log.Warn("revoke denied: not owner", "user", sess.Name, "sub", sess.Sub, "ip", e.IP.String(), "owner_sub", e.Sub)
		s.message(w, http.StatusForbidden, "Access denied", "You can only remove your own entries.")
	default:
		s.log.Info("ip revoked", "user", sess.Name, "sub", sess.Sub, "admin", sess.Admin, "ip", e.IP.String(), "owner", e.User, "owner_sub", e.Sub, "expires_at", e.ExpiresAt.UTC().Format(time.RFC3339))
		http.Redirect(w, r, "/?m=revoked", http.StatusSeeOther)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, sess auth.Session) {
	s.clearCookie(w, sessionCookie)
	s.log.Info("logout", "user", sess.Name, "sub", sess.Sub)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
