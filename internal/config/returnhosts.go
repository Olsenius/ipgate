package config

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ReturnHosts is the parsed RETURN_HOSTS allowlist: exact host names and
// "*.suffix" wildcards. A wildcard matches any name ending in ".suffix" (one or
// more extra labels), never the suffix itself. Empty means the return-link
// feature is off.
type ReturnHosts struct {
	exact    []string
	suffixes []string // stored with the leading dot, e.g. ".gullane.no"
	patterns []string // normalized patterns, in order, for CSP form-action
}

// Patterns returns the normalized patterns (e.g. "app.gullane.no", "*.gullane.no").
func (r ReturnHosts) Patterns() []string { return r.patterns }

// Empty reports whether the feature is off.
func (r ReturnHosts) Empty() bool { return len(r.patterns) == 0 }

// Match reports whether host (already validated with ValidHostname and lower-case)
// is allowed.
func (r ReturnHosts) Match(host string) bool {
	for _, e := range r.exact {
		if host == e {
			return true
		}
	}
	for _, s := range r.suffixes {
		if len(host) > len(s) && strings.HasSuffix(host, s) {
			return true
		}
	}
	return false
}

// ParseReturnHosts parses a comma list of exact hosts and "*.suffix" wildcards.
func ParseReturnHosts(raw string) (ReturnHosts, error) {
	var r ReturnHosts
	for _, p := range splitList(raw) {
		p = strings.ToLower(p)
		name, wildcard := strings.CutPrefix(p, "*.")
		if err := ValidHostname(name); err != nil {
			return ReturnHosts{}, fmt.Errorf("%q: %v", p, err)
		}
		if wildcard {
			if !strings.Contains(name, ".") {
				return ReturnHosts{}, fmt.Errorf("%q: wildcard suffix must have at least two labels (e.g. *.example.com)", p)
			}
			r.suffixes = append(r.suffixes, "."+name)
		} else {
			r.exact = append(r.exact, name)
		}
		r.patterns = append(r.patterns, p)
	}
	return r, nil
}

// ValidHostname accepts a lower-case ASCII DNS name: labels of 1-63 characters
// [a-z0-9-], not starting or ending with '-', at most 253 characters, no
// trailing dot, and not an IP address (including all-numeric last labels, which
// browsers would treat as IPv4). Punycode (xn--) labels are ordinary ASCII
// labels and are accepted; raw Unicode is not.
func ValidHostname(h string) error {
	if h == "" {
		return errors.New("empty host name")
	}
	if len(h) > 253 {
		return errors.New("host name too long")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return errors.New("IP addresses are not allowed")
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return errors.New("empty label (leading, trailing or double dot)")
		}
		if len(l) > 63 {
			return errors.New("label longer than 63 characters")
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return errors.New("label starts or ends with '-'")
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("invalid character %q (use lower-case ASCII; punycode for IDN)", c)
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return errors.New("numeric top-level label (looks like an IP address)")
	}
	return nil
}
