package auth

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Error is an OIDC failure whose message is a fixed, log-safe category such as
// "token endpoint: provider error invalid_grant (HTTP 400)".
//
// Upstream errors can embed response bodies (oauth2 includes the token response
// body when no error code is present; go-oidc includes discovery and JWKS bodies),
// and those may contain tokens. Error never carries the original error, so it
// cannot leak through logging, %v or errors.Unwrap.
type Error struct {
	Stage    string // "discovery", "token endpoint", "id token"
	Category string
}

func (e *Error) Error() string { return e.Stage + ": " + e.Category }

func newError(stage, category string) *Error { return &Error{Stage: stage, Category: category} }

// oauthErrorCodes are the error codes from RFC 6749 §4.1.2.1 / §5.2 and OIDC Core
// §3.1.2.6. Anything else is reported as "other".
var oauthErrorCodes = []string{
	"invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type",
	"invalid_scope", "server_error", "temporarily_unavailable", "invalid_client", "invalid_grant",
	"unsupported_grant_type", "interaction_required", "login_required", "account_selection_required",
	"consent_required", "invalid_request_uri", "invalid_request_object", "request_not_supported",
	"request_uri_not_supported", "registration_not_supported",
}

// SafeOAuthCode returns code if it is a standard OAuth/OIDC error code, else "other".
func SafeOAuthCode(code string) string {
	if slices.Contains(oauthErrorCodes, code) {
		return code
	}
	return "other"
}

// transportCategory classifies network-level failures.
func transportCategory(err error) (string, bool) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", true
	}
	if errors.Is(err, context.Canceled) {
		return "canceled", true
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return "timeout", true
		}
		return "unreachable", true
	}
	return "", false
}

func classifyToken(err error) *Error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		status := "HTTP ?"
		if re.Response != nil {
			status = "HTTP " + strconv.Itoa(re.Response.StatusCode)
		}
		if re.ErrorCode != "" {
			return newError("token endpoint", "provider error "+SafeOAuthCode(re.ErrorCode)+" ("+status+")")
		}
		return newError("token endpoint", "unsuccessful response ("+status+")")
	}
	if c, ok := transportCategory(err); ok {
		return newError("token endpoint", c)
	}
	return newError("token endpoint", "request failed")
}

// classifyVerify maps go-oidc verification errors to categories. Only the
// category is kept; the matched text is never logged.
func classifyVerify(err error) *Error {
	var te *oidc.TokenExpiredError
	if errors.As(err, &te) {
		return newError("id token", "expired")
	}
	msg := err.Error()
	for _, m := range []struct{ substr, category string }{
		{"fetching keys", "jwks fetch failed"},
		{"get keys failed", "jwks fetch failed"},
		{"failed to decode keys", "jwks fetch failed"},
		{"different provider", "wrong issuer"},
		{"expected audience", "wrong audience"},
		{"before the nbf", "not yet valid"},
		{"unsupported signing algorithm", "unsupported algorithm"},
		{"verify id token signature", "bad signature"},
		{"failed to verify signature", "bad signature"},
		{"malformed jwt", "malformed token"},
		{"not signed", "malformed token"},
	} {
		if strings.Contains(msg, m.substr) {
			return newError("id token", m.category)
		}
	}
	return newError("id token", "verification failed")
}

var statusPrefix = regexp.MustCompile(`^([1-5][0-9]{2}) `)

func classifyDiscovery(err error) *Error {
	var ie *oidc.IssuerMismatchError
	if errors.As(err, &ie) {
		return newError("discovery", "issuer mismatch (OIDC_ISSUER must equal the provider's issuer exactly)")
	}
	if c, ok := transportCategory(err); ok {
		return newError("discovery", c)
	}
	msg := err.Error()
	if m := statusPrefix.FindStringSubmatch(msg); m != nil {
		return newError("discovery", "unsuccessful response (HTTP "+m[1]+")")
	}
	if strings.Contains(msg, "failed to decode provider discovery") {
		return newError("discovery", "invalid discovery document")
	}
	return newError("discovery", "failed")
}
