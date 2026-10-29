// Package auth implements signed cookies, sessions, CSRF tokens and the OIDC login flow.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var (
	ErrMalformed = errors.New("malformed token")
	ErrSignature = errors.New("bad signature")
	ErrExpired   = errors.New("token expired")
)

// Strict: reject non-zero padding bits, so each token has exactly one accepted
// encoding (the last character of an unpadded value otherwise has variants that
// decode to the same bytes).
var b64 = base64.RawURLEncoding.Strict()

// Signer creates and verifies HMAC-SHA256 signed, expiring tokens. Each purpose
// ("session", "login", "csrf") uses its own derived key so a token minted for one
// purpose is never accepted for another.
type Signer struct {
	secret []byte
	now    func() time.Time
}

// NewSigner returns a Signer for secret. now may be nil (time.Now).
func NewSigner(secret []byte, now func() time.Time) *Signer {
	if now == nil {
		now = time.Now
	}
	return &Signer{secret: append([]byte(nil), secret...), now: now}
}

func (s *Signer) key(purpose string) []byte {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte("ipgate/" + purpose))
	return m.Sum(nil)
}

func (s *Signer) mac(purpose string, msg []byte) []byte {
	m := hmac.New(sha256.New, s.key(purpose))
	m.Write(msg)
	return m.Sum(nil)
}

type envelope struct {
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"d"`
}

// Sign encodes v with an expiry as "<payload>.<mac>".
func (s *Signer) Sign(purpose string, v any, exp time.Time) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(envelope{Exp: exp.Unix(), Data: data})
	if err != nil {
		return "", err
	}
	p := b64.EncodeToString(payload)
	return p + "." + b64.EncodeToString(s.mac(purpose, []byte(p))), nil
}

// Verify checks the signature (constant time) and expiry, then decodes into v.
func (s *Signer) Verify(purpose, token string, v any) error {
	p, sig, ok := strings.Cut(token, ".")
	if !ok || p == "" || sig == "" {
		return ErrMalformed
	}
	got, err := b64.DecodeString(sig)
	if err != nil {
		return ErrMalformed
	}
	if !hmac.Equal(got, s.mac(purpose, []byte(p))) {
		return ErrSignature
	}
	payload, err := b64.DecodeString(p)
	if err != nil {
		return ErrMalformed
	}
	var env envelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return ErrMalformed
	}
	if s.now().Unix() >= env.Exp {
		return ErrExpired
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		return ErrMalformed
	}
	return nil
}

// MAC returns an unexpiring HMAC of msg for purpose, base64url-encoded.
func (s *Signer) MAC(purpose, msg string) string {
	return b64.EncodeToString(s.mac(purpose, []byte(msg)))
}

// EqualMAC compares a presented MAC against the expected one in constant time.
func (s *Signer) EqualMAC(purpose, msg, presented string) bool {
	return hmac.Equal([]byte(presented), []byte(s.MAC(purpose, msg)))
}
