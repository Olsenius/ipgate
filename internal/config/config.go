// Package config loads ipgate's configuration from environment variables.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MinSecretLen is the minimum length of SESSION_SECRET in bytes.
const MinSecretLen = 32

// Config is the validated runtime configuration.
type Config struct {
	ListenAddr       string
	PublicURL        *url.URL // scheme://host, no path
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	SessionSecret    []byte
	AllowedGroups    []string
	AdminGroups      []string
	AlwaysAllow      []netip.Prefix
	ClientIPHeader   string
	DefaultTTL       time.Duration
	MaxTTL           time.Duration
	SessionTTL       time.Duration
	DataDir          string
	LogLevel         slog.Level
}

// RedirectURL is the OIDC redirect URI.
func (c *Config) RedirectURL() string { return c.PublicURL.String() + "/auth/callback" }

// PublicOrigin is the origin (scheme://host) of PUBLIC_URL, used for the Origin check.
func (c *Config) PublicOrigin() string { return c.PublicURL.Scheme + "://" + c.PublicURL.Host }

// Load reads the configuration using getenv (normally os.Getenv). All problems are
// collected and returned together so the operator can fix them in one go.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	get := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}
	dur := func(key, def string) time.Duration {
		v := get(key, def)
		d, err := time.ParseDuration(v)
		if err != nil {
			fail("%s: invalid duration %q", key, v)
			return 0
		}
		if d <= 0 {
			fail("%s: must be positive", key)
		}
		return d
	}
	secret := func(key string) string {
		v := getenv(key)
		file := strings.TrimSpace(getenv(key + "_FILE"))
		switch {
		case v != "" && file != "":
			fail("%s and %s_FILE are both set; use one", key, key)
		case file != "":
			b, err := os.ReadFile(file)
			if err != nil {
				fail("%s_FILE: %v", key, err)
				return ""
			}
			v = string(b)
		}
		v = strings.TrimRight(v, "\r\n")
		if v == "" {
			fail("%s (or %s_FILE) is required", key, key)
		}
		return v
	}

	c := &Config{
		ListenAddr:       get("LISTEN_ADDR", ":8080"),
		OIDCIssuer:       strings.TrimRight(get("OIDC_ISSUER", ""), "/"),
		OIDCClientID:     get("OIDC_CLIENT_ID", ""),
		OIDCClientSecret: secret("OIDC_CLIENT_SECRET"),
		SessionSecret:    []byte(secret("SESSION_SECRET")),
		AllowedGroups:    splitList(getenv("ALLOWED_GROUPS")),
		AdminGroups:      splitList(getenv("ADMIN_GROUPS")),
		ClientIPHeader:   get("CLIENT_IP_HEADER", "X-Client-IP"),
		DefaultTTL:       dur("DEFAULT_TTL", "168h"),
		MaxTTL:           dur("MAX_TTL", "720h"),
		SessionTTL:       dur("SESSION_TTL", "12h"),
		DataDir:          get("DATA_DIR", "/data"),
	}

	if raw := get("PUBLIC_URL", ""); raw == "" {
		fail("PUBLIC_URL is required")
	} else if u, err := parsePublicURL(raw); err != nil {
		fail("PUBLIC_URL: %v", err)
	} else {
		c.PublicURL = u
	}

	if c.OIDCIssuer == "" {
		fail("OIDC_ISSUER is required")
	} else if err := checkIssuer(c.OIDCIssuer); err != nil {
		fail("OIDC_ISSUER: %v", err)
	}
	if !validHeaderName(c.ClientIPHeader) {
		fail("CLIENT_IP_HEADER: %q is not a valid HTTP header name", c.ClientIPHeader)
	}
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		fail("LISTEN_ADDR: %v", err)
	}
	if !filepath.IsAbs(c.DataDir) {
		fail("DATA_DIR: must be an absolute path")
	}
	if c.OIDCClientID == "" {
		fail("OIDC_CLIENT_ID is required")
	}
	if len(c.SessionSecret) > 0 && len(c.SessionSecret) < MinSecretLen {
		fail("SESSION_SECRET must be at least %d bytes (got %d)", MinSecretLen, len(c.SessionSecret))
	}

	for _, s := range splitList(getenv("ALWAYS_ALLOW")) {
		p, err := parsePrefix(s)
		if err != nil {
			fail("ALWAYS_ALLOW: %v", err)
			continue
		}
		c.AlwaysAllow = append(c.AlwaysAllow, p)
	}

	if c.DefaultTTL > 0 && c.MaxTTL > 0 && c.DefaultTTL > c.MaxTTL {
		fail("DEFAULT_TTL (%s) must not exceed MAX_TTL (%s)", c.DefaultTTL, c.MaxTTL)
	}

	switch lvl := strings.ToLower(get("LOG_LEVEL", "info")); lvl {
	case "debug":
		c.LogLevel = slog.LevelDebug
	case "info":
		c.LogLevel = slog.LevelInfo
	case "warn", "warning":
		c.LogLevel = slog.LevelWarn
	case "error":
		c.LogLevel = slog.LevelError
	default:
		fail("LOG_LEVEL: unknown level %q (use debug, info, warn or error)", lvl)
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration:\n  %w", joinIndented(errs))
	}
	return c, nil
}

func parsePublicURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("must start with https://")
	}
	if u.Host == "" {
		return nil, errors.New("missing host")
	}
	if u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || u.Opaque != "" {
		return nil, errors.New("must be scheme and host only, for example https://enable.gullane.no")
	}
	// Canonical form, so the Origin header comparison is exact: lower-case host,
	// no default port.
	host := strings.ToLower(u.Host)
	if (u.Scheme == "https" && strings.HasSuffix(host, ":443")) || (u.Scheme == "http" && strings.HasSuffix(host, ":80")) {
		host = host[:strings.LastIndexByte(host, ':')]
	}
	return &url.URL{Scheme: u.Scheme, Host: host}, nil
}

// checkIssuer validates the issuer's shape. A path is allowed (some providers use
// one); query, fragment and userinfo are not valid in an OIDC issuer.
func checkIssuer(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return errors.New("must be an absolute https URL")
	case u.Host == "" || u.Opaque != "":
		return errors.New("missing host")
	case u.User != nil:
		return errors.New("must not contain user info")
	case u.RawQuery != "" || u.ForceQuery:
		return errors.New("must not contain a query")
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return errors.New("must not contain a fragment")
	}
	return nil
}

// validHeaderName reports whether s is an RFC 9110 field-name token.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}

// parsePrefix accepts a CIDR or a bare IP address (treated as a single-host prefix).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func splitList(s string) []string {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinIndented(errs []error) error {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Error()
	}
	return errors.New(strings.Join(msgs, "\n  "))
}
