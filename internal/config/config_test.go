package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func base() map[string]string {
	return map[string]string{
		"PUBLIC_URL":         "https://enable.gullane.no",
		"OIDC_ISSUER":        "https://id.gullane.no",
		"OIDC_CLIENT_ID":     "ipgate",
		"OIDC_CLIENT_SECRET": "client-secret",
		"SESSION_SECRET":     strings.Repeat("s", 32),
	}
}

func TestLoadDefaults(t *testing.T) {
	c, err := Load(env(base()))
	if err != nil {
		t.Fatal(err)
	}
	if c.ListenAddr != ":8080" || c.ClientIPHeader != "X-Client-IP" || c.DataDir != "/data" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.DefaultTTL != 168*time.Hour || c.MaxTTL != 720*time.Hour || c.SessionTTL != 12*time.Hour {
		t.Errorf("unexpected durations: %v %v %v", c.DefaultTTL, c.MaxTTL, c.SessionTTL)
	}
	if c.LogLevel != slog.LevelInfo {
		t.Errorf("log level = %v", c.LogLevel)
	}
	if got := c.RedirectURL(); got != "https://enable.gullane.no/auth/callback" {
		t.Errorf("redirect = %q", got)
	}
	if got := c.PublicOrigin(); got != "https://enable.gullane.no" {
		t.Errorf("origin = %q", got)
	}
}

func TestLoadLists(t *testing.T) {
	m := base()
	m["ALLOWED_GROUPS"] = "media, family ,"
	m["ADMIN_GROUPS"] = "admins"
	m["ALWAYS_ALLOW"] = "10.116.0.0/24, 100.64.0.0/10,192.0.2.7,fd00::/8,::ffff:198.51.100.0/120"
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.AllowedGroups, "|") != "media|family" || strings.Join(c.AdminGroups, "|") != "admins" {
		t.Errorf("groups: %v %v", c.AllowedGroups, c.AdminGroups)
	}
	want := []string{"10.116.0.0/24", "100.64.0.0/10", "192.0.2.7/32", "fd00::/8", "198.51.100.0/24"}
	if len(c.AlwaysAllow) != len(want) {
		t.Fatalf("always allow: %v", c.AlwaysAllow)
	}
	for i, p := range c.AlwaysAllow {
		if p.String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, p, want[i])
		}
	}
}

func TestLoadSecretFiles(t *testing.T) {
	dir := t.TempDir()
	cs := filepath.Join(dir, "cs")
	ss := filepath.Join(dir, "ss")
	os.WriteFile(cs, []byte("from-file\n"), 0o600)
	os.WriteFile(ss, []byte(strings.Repeat("x", 40)+"\n"), 0o600)
	m := base()
	delete(m, "OIDC_CLIENT_SECRET")
	delete(m, "SESSION_SECRET")
	m["OIDC_CLIENT_SECRET_FILE"] = cs
	m["SESSION_SECRET_FILE"] = ss
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDCClientSecret != "from-file" || len(c.SessionSecret) != 40 {
		t.Errorf("secrets not read correctly: %q %d", c.OIDCClientSecret, len(c.SessionSecret))
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]func(m map[string]string){
		"PUBLIC_URL is required":        func(m map[string]string) { delete(m, "PUBLIC_URL") },
		"PUBLIC_URL: must be scheme":    func(m map[string]string) { m["PUBLIC_URL"] = "https://x.no/sub" },
		"PUBLIC_URL: must start":        func(m map[string]string) { m["PUBLIC_URL"] = "ftp://x.no" },
		"OIDC_ISSUER is required":       func(m map[string]string) { delete(m, "OIDC_ISSUER") },
		"OIDC_CLIENT_ID is required":    func(m map[string]string) { delete(m, "OIDC_CLIENT_ID") },
		"OIDC_CLIENT_SECRET (or":        func(m map[string]string) { delete(m, "OIDC_CLIENT_SECRET") },
		"at least 32 bytes":             func(m map[string]string) { m["SESSION_SECRET"] = "short" },
		"both set":                      func(m map[string]string) { m["SESSION_SECRET_FILE"] = "/nonexistent" },
		"ALWAYS_ALLOW":                  func(m map[string]string) { m["ALWAYS_ALLOW"] = "not-an-ip" },
		"DEFAULT_TTL (":                 func(m map[string]string) { m["DEFAULT_TTL"] = "1000h" },
		"MAX_TTL: invalid duration":     func(m map[string]string) { m["MAX_TTL"] = "forever" },
		"SESSION_TTL: must be positive": func(m map[string]string) { m["SESSION_TTL"] = "-1h" },
		"LOG_LEVEL: unknown level":      func(m map[string]string) { m["LOG_LEVEL"] = "chatty" },
	}
	for want, mutate := range cases {
		t.Run(want, func(t *testing.T) {
			m := base()
			mutate(m)
			_, err := Load(env(m))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, want containing %q", err, want)
			}
		})
	}
}
