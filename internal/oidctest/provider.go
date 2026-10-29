// Package oidctest is a minimal fake OpenID Connect provider for tests and local
// development: discovery, JWKS, an auto-approving authorize endpoint and a token
// endpoint that enforces client authentication, redirect URI and PKCE (S256).
// It must never be used in production.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"
)

var b64 = base64.RawURLEncoding

// User is the identity the provider logs in as.
type User struct {
	Sub               string
	Name              string
	PreferredUsername string
	Email             string
	Groups            []string
}

// Settings control what the provider puts in ID tokens. Zero values mean "correct".
type Settings struct {
	User         User
	Audience     string        // override aud (default: client id)
	Issuer       string        // override iss (default: issuer)
	Nonce        *string       // override nonce (default: nonce from the authorize request)
	TTL          time.Duration // ID token lifetime (default 5m); negative = already expired
	BadSignature bool          // sign with a key not in the JWKS

	// Raw overrides: when set, the endpoint returns this instead of its normal
	// response (used to test that upstream error bodies never reach logs).
	Discovery *Response
	JWKS      *Response
	Token     *Response
}

// Response is a canned HTTP response.
type Response struct {
	Status int
	Body   string
}

func (r *Response) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.Status)
	w.Write([]byte(r.Body))
}

type authReq struct {
	clientID, redirectURI, challenge, nonce string
}

// Provider is a fake OIDC provider.
type Provider struct {
	Issuer       string
	ClientID     string
	ClientSecret string

	key, otherKey *rsa.PrivateKey
	kid           string

	mu       sync.Mutex
	settings Settings
	codes    map[string]authReq
}

// NewProvider creates a provider for issuer (which must be the URL it is served at).
func NewProvider(issuer, clientID, clientSecret string) *Provider {
	k1, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	k2, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &Provider{
		Issuer: issuer, ClientID: clientID, ClientSecret: clientSecret,
		key: k1, otherKey: k2, kid: "test-key",
		settings: Settings{User: User{Sub: "user-1", Name: "Test Bruker", PreferredUsername: "test", Email: "test@example.com"}},
		codes:    map[string]authReq{},
	}
}

// Server wraps a Provider in an httptest.Server.
type Server struct {
	*Provider
	Server *httptest.Server
}

// NewServer starts a fake provider on a random local port.
func NewServer(clientID, clientSecret string) *Server {
	return NewServerWrapped(clientID, clientSecret, nil)
}

// NewServerWrapped is NewServer with optional middleware around the provider handler.
func NewServerWrapped(clientID, clientSecret string, wrap func(http.Handler) http.Handler) *Server {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	p := NewProvider("http://"+l.Addr().String(), clientID, clientSecret)
	h := p.Handler()
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener.Close()
	srv.Listener = l
	srv.Start()
	return &Server{Provider: p, Server: srv}
}

// Close stops the server.
func (s *Server) Close() { s.Server.Close() }

// Set changes the provider settings.
func (p *Provider) Set(f func(*Settings)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	f(&p.settings)
}

func (p *Provider) get() Settings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.settings
}

// Handler returns the provider's HTTP handler.
func (p *Provider) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	if o := p.get().Discovery; o != nil {
		o.write(w)
		return
	}
	writeJSON(w, 200, map[string]any{
		"issuer":                                p.Issuer,
		"authorization_endpoint":                p.Issuer + "/authorize",
		"token_endpoint":                        p.Issuer + "/token",
		"jwks_uri":                              p.Issuer + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
	})
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	if o := p.get().JWKS; o != nil {
		o.write(w)
		return
	}
	pub := p.key.PublicKey
	writeJSON(w, 200, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": p.kid,
		"n": b64.EncodeToString(pub.N.Bytes()),
		"e": b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") != p.ClientID ||
		q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("state") == "" || q.Get("redirect_uri") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	code := randomString()
	p.mu.Lock()
	p.codes[code] = authReq{clientID: q.Get("client_id"), redirectURI: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	p.mu.Unlock()
	rq := redirect.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	redirect.RawQuery = rq.Encode()
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != p.ClientID || subtle.ConstantTimeCompare([]byte(secret), []byte(p.ClientSecret)) != 1 {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	if o := p.get().Token; o != nil {
		o.write(w)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	code := r.PostForm.Get("code")
	p.mu.Lock()
	req, ok := p.codes[code]
	delete(p.codes, code) // codes are single use
	p.mu.Unlock()
	if !ok || req.redirectURI != r.PostForm.Get("redirect_uri") || req.clientID != id {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if b64.EncodeToString(sum[:]) != req.challenge {
		writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
		return
	}

	s := p.get()
	now := time.Now()
	ttl := s.TTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}
	claims := map[string]any{
		"iss":   p.Issuer,
		"aud":   p.ClientID,
		"sub":   s.User.Sub,
		"iat":   now.Unix(),
		"exp":   now.Add(ttl).Unix(),
		"nonce": req.nonce,
	}
	if s.Issuer != "" {
		claims["iss"] = s.Issuer
	}
	if s.Audience != "" {
		claims["aud"] = s.Audience
	}
	if s.Nonce != nil {
		claims["nonce"] = *s.Nonce
	}
	if s.User.Name != "" {
		claims["name"] = s.User.Name
	}
	if s.User.PreferredUsername != "" {
		claims["preferred_username"] = s.User.PreferredUsername
	}
	if s.User.Email != "" {
		claims["email"] = s.User.Email
	}
	if s.User.Groups != nil {
		claims["groups"] = s.User.Groups
	}
	key := p.key
	if s.BadSignature {
		key = p.otherKey
	}
	idToken, err := signJWT(key, p.kid, claims)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"access_token": randomString(),
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     idToken,
	})
}

func signJWT(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": kid})
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signing := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64.EncodeToString(sig), nil
}

func randomString() string {
	b := make([]byte, 24)
	rand.Read(b)
	return b64.EncodeToString(b)
}
