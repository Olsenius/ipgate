# ipgate

IP allowlist gate for Caddy `forward_auth`, with Pocket ID (OIDC, passkeys) login.

Jellyfin and Seerr are exposed on the internet behind Caddy, but every IP is denied by default.
Someone who visits `https://enable.gullane.no` and logs in with Pocket ID gets their current public IP
added to an allowlist for a limited time. After that, every device behind that IP (TVs, phones,
Jellyfin apps that cannot do SSO) can reach Jellyfin and Seerr.

ipgate is one small Go service with two jobs:

1. **`/check`** for Caddy `forward_auth`: `204` if the client IP is allowed right now, otherwise `403`
   with a short plain-text hint pointing at `PUBLIC_URL`.
2. **Web UI** (`PUBLIC_URL`): OIDC login, shows your IP, allow it for 1/7/30 days, list and revoke
   entries (admins see and revoke everyone's).

[SPEC.md](SPEC.md) is the source of truth for behaviour; this README summarises it.

## Configuration

All configuration is via environment variables. Missing or invalid values make ipgate exit at start
with a message listing every problem.

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Listen address |
| `PUBLIC_URL` | (required) | e.g. `https://enable.gullane.no` (scheme and host only). Redirect URI is `PUBLIC_URL/auth/callback` |
| `OIDC_ISSUER` | (required) | e.g. `https://id.gullane.no` (no user info, query or fragment) |
| `OIDC_CLIENT_ID` | (required) | |
| `OIDC_CLIENT_SECRET` | (required, or `OIDC_CLIENT_SECRET_FILE`) | |
| `SESSION_SECRET` | (required, or `SESSION_SECRET_FILE`; at least 32 bytes) | HMAC key for cookies and CSRF tokens |
| `ALLOWED_GROUPS` | empty (= any authenticated user) | Comma list of Pocket ID group names allowed to log in |
| `ADMIN_GROUPS` | empty | Comma list; members see and revoke all entries |
| `ALWAYS_ALLOW` | empty | Comma list of CIDRs (or bare IPs) always allowed by `/check`, e.g. LAN and tailnet |
| `CLIENT_IP_HEADER` | `X-Client-IP` | Header carrying the client IP (set by Caddy); must be a valid header name |
| `DEFAULT_TTL` | `168h` | Pre-selected duration (must be `<= MAX_TTL`) |
| `MAX_TTL` | `720h` | Upper bound; longer choices are hidden and rejected |
| `SESSION_TTL` | `12h` | Login session lifetime |
| `DATA_DIR` | `/data` | Absolute path to an existing, writable directory holding `allowlist.json` (checked at start) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |

`*_FILE` variants read the secret from a file (trailing newline stripped); setting both is an error.
Generate a session secret with `openssl rand -base64 48`.

Pocket ID client: redirect URI `https://enable.gullane.no/auth/callback`, confidential client (secret),
PKCE enabled. ipgate requests scopes `openid profile email groups` and reads the `groups` claim from the
ID token.

## Caddy

```caddyfile
	@media host jellyfin.gullane.no seerr.gullane.no
	handle @media {
		forward_auth ipgate:8080 {
			uri /check
			header_up X-Client-IP {client_ip}
		}
		@jellyfin host jellyfin.gullane.no
		reverse_proxy @jellyfin <jellyfin-ip>:8096
		@seerr host seerr.gullane.no
		reverse_proxy @seerr <seerr-ip>:5055
	}

	@enable host enable.gullane.no
	handle @enable {
		reverse_proxy ipgate:8080 {
			header_up X-Client-IP {client_ip}
		}
	}
```

`header_up X-Client-IP {client_ip}` **overwrites** any `X-Client-IP` the client sent, which is what makes
the header trustworthy. Hairpin traffic from the home LAN arrives as `10.116.0.1`; put the LAN in
`ALWAYS_ALLOW` (e.g. `ALWAYS_ALLOW=10.116.0.0/24`).

## Docker

```sh
docker build -t ipgate .
```

The image is `gcr.io/distroless/static-debian12:nonroot` (about 21 MB) and runs as `nonroot`. Distroless has
no shell, so Docker's `HEALTHCHECK` with a shell command does not work; use the built-in subcommand from
compose instead. Example compose service (no published port):

```yaml
  ipgate:
    build: ./ipgate
    restart: unless-stopped
    environment:
      PUBLIC_URL: https://enable.gullane.no
      OIDC_ISSUER: https://id.gullane.no
      OIDC_CLIENT_ID: ipgate
      OIDC_CLIENT_SECRET_FILE: /run/secrets/ipgate_oidc_secret
      SESSION_SECRET_FILE: /run/secrets/ipgate_session_secret
      ALLOWED_GROUPS: media
      ADMIN_GROUPS: admins
      ALWAYS_ALLOW: 10.116.0.0/24
    volumes:
      - ipgate-data:/data
    healthcheck:
      test: ["CMD", "/usr/local/bin/ipgate", "healthcheck"]
      interval: 30s
      timeout: 5s
```

`ipgate healthcheck` GETs `http://127.0.0.1:<port from LISTEN_ADDR>/healthz` and exits non-zero on failure.
`/data` in the image is owned by `nonroot`, so a fresh named volume is writable. With a bind mount, create
the directory first and make it writable by UID 65532; ipgate refuses to start if `DATA_DIR` is missing or
not writable.

## Development

Requires Go 1.27.

```sh
go vet ./...
go test -race ./...
gofmt -l .
```

The test suite includes a fake OIDC provider (`internal/oidctest`: discovery, JWKS, authorize, token
endpoint with PKCE checking) and covers the full login flow, wrong nonce/audience/issuer/signature,
group denial, CSRF, Origin checks, private-IP refusal and the store.

To try the whole flow by hand, run the fake provider and point ipgate at it:

```sh
go run ./cmd/fakeoidc -addr 127.0.0.1:9999 -issuer http://127.0.0.1:9999 &
PUBLIC_URL=http://localhost:8080 OIDC_ISSUER=http://127.0.0.1:9999 OIDC_CLIENT_ID=ipgate \
OIDC_CLIENT_SECRET=dev-secret SESSION_SECRET=0123456789abcdef0123456789abcdef \
DATA_DIR=$(mktemp -d) ADMIN_GROUPS=admins go run ./cmd/ipgate
```

Cookies are `Secure` with the `__Host-` prefix, so use `http://localhost` (which browsers and curl treat as a
secure context) or https; other plain-HTTP hostnames will not keep the login. Browsers do not add
`X-Client-IP`, so locally use a header-injecting extension, or curl:
`curl -H 'X-Client-IP: 203.0.113.7' localhost:8080/check`. `cmd/fakeoidc` auto-approves every login and is
development-only; it is not in the Docker image.

## Security model

- **Trust boundary is Caddy.** The client IP comes only from `CLIENT_IP_HEADER`, which Caddy overwrites
  with the real client IP. `X-Forwarded-For`, `X-Real-IP` and the TCP peer address are ignored.
  **Never expose port 8080 directly** (no host port in compose): anyone who can reach ipgate directly can
  set the header to any IP and both pass `/check` and allowlist arbitrary addresses.
- `/check` denies by default: missing or unparsable header means `403`. Lookups are in memory with no I/O.
- IPv4 matches the exact address. IPv6 matches on the /64 of the stored address, since privacy addresses
  rotate inside a /64. IPv4-mapped IPv6 addresses are treated as IPv4.
- `/allow` always uses the request's client IP, never a form value, and refuses private, loopback,
  CGNAT, unique-local and link-local addresses.
- Login: Authorization Code flow with PKCE (S256), `state` and `nonce`, kept in a 10-minute signed cookie.
  The ID token's signature (JWKS), issuer, audience, expiry and nonce are verified.
- Sessions are stateless HMAC-SHA256 signed cookies (`HttpOnly`, `Secure`, `SameSite=Lax`, host-only, named
  with the `__Host-` prefix so a sibling subdomain cannot plant or shadow them), compared in constant time. Separate derived keys are used for session, login-state and CSRF tokens.
  Rotating `SESSION_SECRET` logs everyone out. Group membership and the admin flag are fixed at login
  and stay until the session expires (`SESSION_TTL`).
- Every POST requires a per-session CSRF token, and POSTs with an `Origin` other than `PUBLIC_URL` are
  rejected.
- UI responses carry a strict CSP (`default-src 'self'`, no inline scripts or styles), `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer` and `X-Content-Type-Options: nosniff`.
- Logs (JSON on stdout) record logins, allows and revokes with user and IP; `/check` is logged only at
  `debug`. ipgate never logs its cookies, secrets or the provider's tokens. OIDC failures are logged as fixed
  categories (e.g. `token endpoint: unsuccessful response (HTTP 502)`), never as upstream response bodies, raw
  library errors or the provider's `error_description`, because those can contain tokens. Tests inject secret
  markers into failing token, discovery and JWKS responses and check that none reach the logs.
- A corrupt or malformed `allowlist.json` (including records with missing fields or inconsistent times)
  stops ipgate from starting and is left untouched, rather than being pruned or overwritten.
- Writes are atomic (temp file, fsync, rename, directory fsync) and never block `/check`: readers use the
  last committed state while a write is in progress. If only the final directory fsync fails, the change is
  in effect but may not survive a crash; this is logged at error level and the user sees a warning. Revokes
  take effect immediately either way.
- No application-level rate limits: allowlist writes only happen on authenticated user actions and the
  10-minute pruner. Put rate limits for `/login` and `/auth/callback` in Caddy if needed.

## Deviations from the spec

Changes made after review round 1 (log-safe OIDC errors, non-blocking store writes, durability handling,
strict allowlist validation, stricter configuration checks, `__Host-` cookies) are written into SPEC.md and
are not deviations. The following are interpretations of, or small additions to, the spec. Some of them change
behaviour in edge cases:

- **IPv6 entries are keyed by /64.** "One entry per IP" is applied per match key: re-allowing from another
  address in the same /64 refreshes that entry (and records the new address) instead of creating a second
  entry. Revoking any address in the /64 removes it. Two entries for the same /64 in the file count as corrupt.
- **Refused addresses for `/allow`** are the spec's list plus anything that is not global unicast
  (unspecified, multicast, IPv4 link-local `169.254/16`).
- **`ALWAYS_ALLOW`** also accepts bare IPs (treated as /32 or /128).
- **`DEFAULT_TTL` not in 1/7/30 days** is added as an extra choice (e.g. `48h` shows "2 days"), so the
  default can always be pre-selected.
- **Allowlist files with unknown fields** are rejected as corrupt (strict schema).
- **`PUBLIC_URL`** is canonicalised (lower-case host, default port removed) before the Origin comparison.
  `LISTEN_ADDR` must be `host:port`.
- **Times in the UI** are shown in `Europe/Oslo` (zone data is embedded, since distroless has none).
- **Logout** requires a valid session and CSRF token like every other POST; without a session it redirects
  to `/` with a "session expired" notice.
- **`/healthz`** reports process health only, not OIDC readiness, so the container stays healthy while
  Pocket ID is starting (`/check` works without OIDC). Storage is checked once at startup.
- **`cmd/fakeoidc`** and `internal/oidctest` are a dev/test-only fake provider, not part of the image.
- **Dependencies:** only `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` (plus
  `github.com/go-jose/go-jose/v4`, pulled in indirectly by go-oidc).
