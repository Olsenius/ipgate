package server

import (
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Olsenius/ipgate/internal/config"
	"github.com/Olsenius/ipgate/internal/oidctest"
)

// newReturnEnv enables return links for *.gullane.no and jf.example.org. It also
// lists the PUBLIC_URL host (enable.example), which config.Load would refuse,
// to prove the runtime guard rejects it too.
func newReturnEnv(t *testing.T) *env {
	t.Helper()
	rh, err := config.ParseReturnHosts("*.gullane.no, jf.example.org, enable.example")
	if err != nil {
		t.Fatal(err)
	}
	return newEnv(t, func(c *config.Config) { c.ReturnHosts = rh })
}

func TestReturnURLValidation(t *testing.T) {
	e := newReturnEnv(t)
	s, _ := New(e.cfg, e.store, nil, nil, nil)
	valid := map[string]string{
		"https://app.gullane.no/":            "https://app.gullane.no/",
		"https://app.gullane.no":             "https://app.gullane.no/",
		"https://APP.Gullane.NO/":            "https://app.gullane.no/",
		"https://app.gullane.no:443/":        "https://app.gullane.no/",
		"https://a.b.gullane.no/":            "https://a.b.gullane.no/",
		"https://jf.example.org/":            "https://jf.example.org/",
		"https://app.gullane.no/x/y?q=1#f":   "https://app.gullane.no/",
		"https://app.gullane.no?next=evil":   "https://app.gullane.no/",
		"https://app.gullane.no#@evil.com":   "https://app.gullane.no/",
		"https://xn--4ca.gullane.no/":        "https://xn--4ca.gullane.no/", // punycode IDN
		"https://app.gullane.no/%2F%2Fevil/": "https://app.gullane.no/",
	}
	for in, want := range valid {
		if got := s.returnURL(in); got != want {
			t.Errorf("returnURL(%q) = %q, want %q", in, got, want)
		}
	}
	invalid := []string{
		"",
		// wildcard edges
		"https://gullane.no/", "https://evilgullane.no/", "https://a.gullane.no.evil.com/",
		"https://app.gullane.no./", "https://x.jf.example.org/", "https://example.org/",
		// IDN / Unicode, IPs
		"https://ä.gullane.no/", "https://аpp.gullane.no/", "https://203.0.113.5/", "https://[2001:db8::1]/",
		"https://127.1/", "https://0x7f000001/",
		// schemes and relative forms
		"javascript:alert(1)", "javascript://app.gullane.no/%0aalert(1)", "data:text/html,<script>alert(1)</script>",
		"http://app.gullane.no/", "//app.gullane.no/", "///app.gullane.no/", "/\\app.gullane.no", "app.gullane.no",
		"https:app.gullane.no", "https:/app.gullane.no", "https:///app.gullane.no", "HTTPS://app.gullane.no/",
		"https:\\\\app.gullane.no", " https://app.gullane.no/", "https://app.gullane.no/ ", "\thttps://app.gullane.no/",
		// encoded tricks
		"https://app.gullane.no%2eevil.com/", "https://app%2egullane.no/", "https%3A%2F%2Fapp.gullane.no%2F",
		"https://app.gullane.no%2F@evil.com/", "https://evil.com\\@app.gullane.no/", "https://evil.com\\.gullane.no/",
		"https://app.gullane.no\x00.evil.com/", "https://app.gullane.no\r\n/", "https://app.gullane.no%00/",
		// ports
		"https://app.gullane.no:8443/", "https://app.gullane.no:80/", "https://app.gullane.no:/", "https://app.gullane.no:0443/",
		"https://app.gullane.no:443:443/",
		// userinfo
		"https://user@app.gullane.no/", "https://user:pw@app.gullane.no/", "https://app.gullane.no@evil.com/",
		"https://evil.com@app.gullane.no/", "https://@app.gullane.no/",
		// the PUBLIC_URL host itself, even though listed and matched
		"https://enable.example/", "https://ENABLE.example:443/",
		// too long
		"https://app.gullane.no/" + strings.Repeat("a", maxReturnLen),
	}
	for _, in := range invalid {
		if got := s.returnURL(in); got != "" {
			t.Errorf("returnURL(%q) = %q, want rejected", in, got)
		}
	}

	// Feature off: nothing is accepted.
	off := newEnv(t, nil)
	s2, _ := New(off.cfg, off.store, nil, nil, nil)
	if got := s2.returnURL("https://app.gullane.no/"); got != "" {
		t.Errorf("RETURN_HOSTS empty but %q accepted", got)
	}
}

var continueLink = regexp.MustCompile(`<a class="button" href="([^"]*)">Continue</a>`)

// visibleText strips tags, so attribute values (hrefs, hidden inputs) are excluded.
func visibleText(page string) string {
	return regexp.MustCompile(`<[^>]*>`).ReplaceAllString(page, " ")
}

func TestReturnCarriedThroughLoginAndAllow(t *testing.T) {
	e := newReturnEnv(t)
	b := e.browser("203.0.113.5")
	ret := url.QueryEscape("https://app.gullane.no/some/path?x=1")

	// Anonymous index: Log in link carries the canonical return URL.
	page := bodyOf(t, b.do("GET", "/?return="+ret, nil))
	if !strings.Contains(page, `href="/login?return=https%3A%2F%2Fapp.gullane.no%2F"`) {
		t.Fatalf("login link does not carry return URL:\n%s", page)
	}

	// /login stores it in the signed login cookie; the callback URL from the
	// provider does not contain it.
	e.op.Set(func(s *oidctest.Settings) { *s = oidctest.Settings{User: alice} })
	resp := b.do("GET", "/login?return="+ret, nil)
	if strings.Contains(resp.Header.Get("Location"), "gullane") {
		t.Errorf("return URL leaked into the authorization request: %s", resp.Header.Get("Location"))
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	pr, err := client.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	pr.Body.Close()
	cb, _ := url.Parse(pr.Header.Get("Location"))

	// A return parameter injected into the callback is ignored; the cookie wins.
	q := cb.Query()
	q.Set("return", "https://jf.example.org/")
	cb.RawQuery = q.Encode()
	resp = b.do("GET", cb.RequestURI(), nil)
	if loc := resp.Header.Get("Location"); loc != "/?return=https%3A%2F%2Fapp.gullane.no%2F" {
		t.Fatalf("callback redirect = %q", loc)
	}

	// Logged in, not yet allowed: no Continue, but the allow form carries return.
	page = bodyOf(t, b.do("GET", "/?return=https%3A%2F%2Fapp.gullane.no%2F", nil))
	if continueLink.MatchString(page) {
		t.Error("Continue shown before the IP is allowed")
	}
	if !strings.Contains(page, `name="return" value="https://app.gullane.no/"`) {
		t.Fatalf("allow form lacks return field:\n%s", page)
	}

	// After allow: straight to the return URL.
	resp = b.post("/allow", url.Values{"duration": {"24h0m0s"}, "return": {"https://app.gullane.no/"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "https://app.gullane.no/" {
		t.Fatalf("allow redirect: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if e.check("203.0.113.5", nil) != 204 {
		t.Fatal("not allowed")
	}

	// Already allowed: Continue links to the return URL, host name not printed.
	page = bodyOf(t, b.do("GET", "/?return=https%3A%2F%2Fapp.gullane.no%2F", nil))
	m := continueLink.FindStringSubmatch(page)
	if m == nil || m[1] != "https://app.gullane.no/" {
		t.Fatalf("Continue link missing or wrong: %v\n%s", m, page)
	}
	if strings.Contains(strings.ToLower(visibleText(page)), "gullane") {
		t.Errorf("return host printed on the page:\n%s", visibleText(page))
	}

	// Without a return parameter: no Continue.
	if continueLink.MatchString(bodyOf(t, b.do("GET", "/", nil))) {
		t.Error("Continue shown without a return URL")
	}
	// Logged in and visiting /login with return: back to the index with it.
	if loc := b.do("GET", "/login?return="+ret, nil).Header.Get("Location"); loc != "/?return=https%3A%2F%2Fapp.gullane.no%2F" {
		t.Errorf("/login when logged in: %q", loc)
	}
}

func TestInvalidReturnIgnoredSilently(t *testing.T) {
	e := newReturnEnv(t)
	b := e.browser("203.0.113.5")
	b.login(alice)
	for _, bad := range []string{"https://evil.com/", "javascript:alert(1)", "//app.gullane.no/", "https://enable.example/"} {
		q := "/?return=" + url.QueryEscape(bad)
		resp := b.do("GET", q, nil)
		page := bodyOf(t, resp)
		if resp.StatusCode != 200 || strings.Contains(page, `name="return"`) || strings.Contains(page, "evil") || strings.Contains(page, "javascript") {
			t.Errorf("%s: invalid return not ignored (%d)", bad, resp.StatusCode)
		}
		resp = b.post("/allow", url.Values{"duration": {"24h0m0s"}, "return": {bad}})
		if loc := resp.Header.Get("Location"); loc != "/?m=allowed" {
			t.Errorf("allow with return %q redirected to %q", bad, loc)
		}
		if loc := b.do("GET", "/login?return="+url.QueryEscape(bad), nil).Header.Get("Location"); loc != "/" {
			t.Errorf("/login with return %q redirected to %q", bad, loc)
		}
	}
	// Continue never appears for an invalid return, even when allowed.
	if continueLink.MatchString(bodyOf(t, b.do("GET", "/?return="+url.QueryEscape("https://evil.com/"), nil))) {
		t.Error("Continue shown for invalid return")
	}
}

func TestReturnKeptOnAllowErrors(t *testing.T) {
	e := newReturnEnv(t)
	b := e.browser("192.168.1.10")
	b.login(alice)
	resp := b.post("/allow", url.Values{"duration": {"24h0m0s"}, "return": {"https://app.gullane.no/"}})
	if loc := resp.Header.Get("Location"); loc != "/?m=private&return=https%3A%2F%2Fapp.gullane.no%2F" {
		t.Errorf("private: %q", loc)
	}
	b.ip = "203.0.113.5"
	resp = b.post("/allow", url.Values{"duration": {"bogus"}, "return": {"https://app.gullane.no/"}})
	if loc := resp.Header.Get("Location"); loc != "/?m=duration&return=https%3A%2F%2Fapp.gullane.no%2F" {
		t.Errorf("duration: %q", loc)
	}
}

func TestContinueForAlwaysAllowed(t *testing.T) {
	rh, _ := config.ParseReturnHosts("*.gullane.no")
	e := newEnv(t, func(c *config.Config) {
		c.ReturnHosts = rh
		c.AlwaysAllow = []netip.Prefix{netip.MustParsePrefix("10.116.0.0/24")}
	})
	b := e.browser("10.116.0.1") // hairpin LAN address: always allowed, never stored
	b.login(alice)
	m := continueLink.FindStringSubmatch(bodyOf(t, b.do("GET", "/?return=https%3A%2F%2Fapp.gullane.no%2F", nil)))
	if m == nil || m[1] != "https://app.gullane.no/" {
		t.Errorf("Continue not shown for an always-allowed address: %v", m)
	}
}

func TestCSPAllowsRedirectToReturnHosts(t *testing.T) {
	e := newReturnEnv(t)
	csp := e.browser("203.0.113.5").do("GET", "/", nil).Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self' https://*.gullane.no https://jf.example.org") {
		t.Errorf("CSP form-action does not allow return hosts: %s", csp)
	}
	off := newEnv(t, nil)
	csp = off.browser("203.0.113.5").do("GET", "/", nil).Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "form-action 'self';") {
		t.Errorf("CSP form-action with feature off: %s", csp)
	}
}

// Caddy builds the link without percent-encoding: /?return=https://<host>/
func TestReturnUnencodedFromCaddy(t *testing.T) {
	e := newReturnEnv(t)
	page := bodyOf(t, e.browser("203.0.113.5").do("GET", "/?return=https://app.gullane.no/", nil))
	if !strings.Contains(page, `href="/login?return=https%3A%2F%2Fapp.gullane.no%2F"`) {
		t.Errorf("unencoded return not accepted:\n%s", page)
	}
}
