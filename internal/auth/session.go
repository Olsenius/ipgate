package auth

import (
	"crypto/rand"
	"time"
)

// Session is the content of the signed session cookie.
type Session struct {
	ID        string `json:"sid"`
	Sub       string `json:"sub"`
	Name      string `json:"name"`
	Admin     bool   `json:"admin,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// LoginState is the content of the short-lived cookie that carries PKCE and
// anti-replay values across the OIDC redirect.
type LoginState struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	// Return is the already-validated return URL ("https://<host>/") or "".
	// It travels only inside this signed cookie, never via the callback URL.
	Return string `json:"return,omitempty"`
}

const (
	purposeSession = "session"
	purposeLogin   = "login"
	purposeCSRF    = "csrf"
)

// NewSession creates a session for the given identity, valid for ttl.
func (s *Signer) NewSession(sub, name string, admin bool, ttl time.Duration) Session {
	now := s.now()
	return Session{
		ID:        RandomString(),
		Sub:       sub,
		Name:      name,
		Admin:     admin,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}
}

// EncodeSession signs a session for use as a cookie value.
func (s *Signer) EncodeSession(sess Session) (string, error) {
	return s.Sign(purposeSession, sess, time.Unix(sess.ExpiresAt, 0))
}

// DecodeSession verifies a session cookie value.
func (s *Signer) DecodeSession(v string) (Session, error) {
	var sess Session
	if err := s.Verify(purposeSession, v, &sess); err != nil {
		return Session{}, err
	}
	if sess.ID == "" || sess.Sub == "" {
		return Session{}, ErrMalformed
	}
	return sess, nil
}

// EncodeLogin signs login state valid for ttl.
func (s *Signer) EncodeLogin(ls LoginState, ttl time.Duration) (string, error) {
	return s.Sign(purposeLogin, ls, s.now().Add(ttl))
}

// DecodeLogin verifies a login-state cookie value.
func (s *Signer) DecodeLogin(v string) (LoginState, error) {
	var ls LoginState
	if err := s.Verify(purposeLogin, v, &ls); err != nil {
		return LoginState{}, err
	}
	if ls.State == "" || ls.Nonce == "" || ls.Verifier == "" {
		return LoginState{}, ErrMalformed
	}
	return ls, nil
}

// CSRFToken is the per-session CSRF token: an HMAC of the session id.
func (s *Signer) CSRFToken(sess Session) string { return s.MAC(purposeCSRF, sess.ID) }

// CheckCSRF reports whether token is valid for sess.
func (s *Signer) CheckCSRF(sess Session, token string) bool {
	return token != "" && sess.ID != "" && s.EqualMAC(purposeCSRF, sess.ID, token)
}

// RandomString returns 32 random bytes, base64url-encoded.
func RandomString() string {
	b := make([]byte, 32)
	rand.Read(b) // never fails (crypto/rand panics on failure)
	return b64.EncodeToString(b)
}
