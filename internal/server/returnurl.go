package server

import (
	"strings"

	"github.com/Olsenius/ipgate/internal/config"
)

const maxReturnLen = 2048

// returnURL validates a "return" parameter and returns the canonical
// "https://<host>/" for it, or "" if it is not acceptable. Invalid values are
// ignored silently by callers, so a bad link simply has no return target and can
// never become an open redirect.
//
// Rules: the raw value must start with the literal "https://"; the authority must
// be a plain lower-/upper-case ASCII host name with no userinfo, no percent or
// backslash tricks and no port other than 443; the host must match RETURN_HOSTS
// and must not be the PUBLIC_URL host. Path, query and fragment are dropped.
func (s *Server) returnURL(raw string) string {
	rh := s.cfg.ReturnHosts
	if raw == "" || rh.Empty() || len(raw) > maxReturnLen {
		return ""
	}
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok {
		return "" // javascript:, data:, http:, //host, https:/host, HTTPS://...
	}
	// The authority ends at the first '/', '?' or '#'. Anything that a browser
	// might parse differently from us ('\\', '%', '@', whitespace, control
	// characters, brackets) makes the whole value invalid.
	authority := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		authority = rest[:i]
	}
	for i := 0; i < len(raw); i++ {
		if c := raw[i]; c <= ' ' || c == 0x7f || c == '\\' {
			return ""
		}
	}
	if strings.ContainsAny(authority, "@%[]") {
		return ""
	}
	host, port, hasPort := strings.Cut(authority, ":")
	if hasPort && port != "443" {
		return ""
	}
	host = strings.ToLower(host)
	if config.ValidHostname(host) != nil {
		return "" // empty, IP address, trailing dot, Unicode, bad labels
	}
	if host == s.cfg.PublicHost() || !rh.Match(host) {
		return ""
	}
	return "https://" + host + "/"
}
