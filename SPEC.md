# ipgate: spec

Status: approved for implementation (Andreas, 2026-10-29). Written by claude-code@homelab-admin.
Background and homelab context: vault notes `34.16 caddy-migration` and `34.11 future-work`
("Jellyfin and Seerr through Caddy with an IP allowlist") in `~/agent/30 Platform/34 Homelab/`.

## 1. Goal

Expose Jellyfin (`jellyfin.gullane.no`) and Seerr (`seerr.gullane.no`) on the internet through Caddy, but
**deny every IP by default**. A person who visits `https://enable.gullane.no` and logs in with Pocket ID
(passkeys, OIDC) gets their current public IP added to an allowlist for a limited time. After that, every device
behind that IP (TVs, phones, Jellyfin apps that cannot do SSO) can reach Jellyfin and Seerr.

The services named here are background only. ipgate's UI and responses must stay neutral and never name a
protected service (see §3.2). (Added after production testing, 2026-10-29.)

ipgate is one small Go service that does two jobs:

1. **Check endpoint** for Caddy `forward_auth`: "is this client IP allowed right now?"
2. **Web UI** on `enable.gullane.no`: OIDC login, show your IP, allow it, list and revoke entries.

## 2. Context (how it is deployed, not part of this repo's work)

- Runs as a container on VM 300 (`docker`, `10.116.0.117`) in the Docker Compose project
  `~/docker-compose/caddy/`, next to `caddy`, `crowdsec` and `pocket-id`. **No host port**: only Caddy reaches it,
  over the compose network, as `ipgate:8080`.
- Caddy (2.11) terminates TLS for `*.gullane.no`, runs CrowdSec first, then routes by host. Caddy sees the real
  client IP (the router port-forwards 443). Hairpin traffic from the home LAN arrives as `10.116.0.1`.
- Pocket ID (v2.19.1) is the OIDC provider at `https://id.gullane.no`. Open signups are off; users get one-time
  login links. Groups exist in Pocket ID and can be sent as a `groups` claim (request scope `groups`).
- Planned Caddyfile wiring (for reference; the homelab admin agent applies it):

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

## 3. Requirements

### 3.1 Check endpoint

- `GET /check` (Caddy may also send other methods; accept any method).
- Client IP comes **only** from the header named by `CLIENT_IP_HEADER` (default `X-Client-IP`). Ignore
  `X-Forwarded-For`, `RemoteAddr` and everything else. Missing or unparsable header → deny.
- Allowed if the IP is in `ALWAYS_ALLOW` (CIDR list) or has an unexpired allowlist entry.
- Allowed → `204 No Content`. Denied → `403` with a short plain-text body in English, for example:
  `Access denied from this IP address. Go to https://enable.gullane.no to log in.` (use `PUBLIC_URL`).
- Must be fast and allocation-light: in-memory lookup, no disk or network I/O per request.
- Normalise IPs with `net/netip` (`Unmap()` IPv4-mapped IPv6). Exact-IP match for IPv4. For IPv6, match on the
  /64 prefix of the stored address (residential IPv6 privacy addresses rotate inside a /64).

### 3.2 Web UI (`enable.gullane.no`)

All UI text in **English** (changed from Norwegian 2026-10-29), simple and mobile-friendly; one embedded HTML template set and a small
inline stylesheet, no JavaScript frameworks, no external assets (CSP: `default-src 'self'`, inline style allowed
via hash or a tiny embedded CSS file).

- The UI must not name Jellyfin, Seerr or any other protected service anywhere: page titles, headings, texts,
  error pages and the `/check` 403 body use neutral wording (heading "Access"; "Log in to give this IP address
  access. Every device on the same network (TV, phone, tablet) then gets access."). (Added after production
  testing, 2026-10-29.)
- `GET /`: not logged in → page with the visitor's IP and a "Log in" button (→ `/login`). Logged in →
  - the visitor's current IP and whether it is already allowed (and until when),
  - a form to allow this IP with a duration choice: 1 day, 7 days (default), 30 days (only durations
    `<= MAX_TTL` are shown),
  - a hint: if you are on mobile data, choose 1 day (mobile IPs are shared, CGNAT),
  - a list of the user's own entries (IP, created, expires, user agent at creation) with "Remove" buttons,
  - for admins (member of a group in `ADMIN_GROUPS`): all entries from all users, with "Remove",
  - "Log out".
- `GET /login`: start OIDC Authorization Code flow with **PKCE (S256)**, `state` and `nonce`. Store
  verifier/state/nonce in a short-lived (10 min), signed, `HttpOnly`, `Secure`, `SameSite=Lax` cookie.
  Scopes: `openid profile email groups`.
- `GET /auth/callback`: verify state, exchange code, verify the ID token (issuer, audience, expiry, signature via
  JWKS, nonce). Read `sub`, `preferred_username`, `name`, `email`, `groups`.
  - If `ALLOWED_GROUPS` is non-empty and the user is in none of them → 403 page ("You do not have access").
  - Otherwise set the session cookie and redirect to `/`.
- `POST /allow`: logged in + valid CSRF token. Adds/refreshes the entry for the **request's client IP** (from
  `CLIENT_IP_HEADER`, same rules as `/check`), never an IP from the form. Duration from the form, validated
  against the allowed choices and `MAX_TTL`. Refusing IPs that are private/loopback/CGNAT
  (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `100.64/10`, `::1`, `fc00::/7`, `fe80::/10`) with a friendly
  message (these are already allowed or meaningless). Redirect to `/`.
- `POST /revoke`: logged in + CSRF. Form field `ip`. Users may revoke only their own entries; admins any.
- `POST /logout`: clear session, redirect to `/`.
- `GET /healthz`: `200 ok` (no auth), for the Docker healthcheck.

### 3.3 Sessions and CSRF

- Session = signed cookie (HMAC-SHA256 with `SESSION_SECRET`), containing `sub`, display name, admin flag,
  issued/expiry (`SESSION_TTL`, default 12h). Cookie: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, host-only.
  Constant-time signature comparison. No server-side session store needed.
- Cookie names use the `__Host-` prefix (`__Host-ipgate_session`, `__Host-ipgate_login`) so a sibling subdomain
  cannot plant or shadow them. (Added after review round 1, 2026-10-29.)
- CSRF: per-session token (for example HMAC of session id) as a hidden field on every form; check on every POST.
  Also reject POSTs whose `Origin` header is present and not equal to `PUBLIC_URL`'s origin.
- Security headers on UI responses: `Content-Security-Policy`, `X-Frame-Options: DENY`,
  `Referrer-Policy: same-origin`, `X-Content-Type-Options: nosniff`. (Changed from `no-referrer` after
  production testing, 2026-10-29: with `no-referrer`, browsers send `Origin: null` on same-origin form POSTs,
  so the Origin check rejected every form. `same-origin` still sends no referrer to other sites. `Origin: null`
  stays rejected.)

### 3.4 Storage

- JSON file `DATA_DIR/allowlist.json`: list of entries
  `{ip, sub, user, created_at, expires_at, user_agent}`. One entry per IP (re-allowing refreshes it and takes
  ownership).
- Loaded at start; held in memory behind a `sync.RWMutex`; written atomically (temp file + `fsync` + rename +
  directory `fsync`) on every change. Expired entries are pruned at load and by a background ticker (every
  10 min), and ignored by `/check` even before pruning.
- Readers (`/check`, the UI) never wait for disk I/O: mutations are serialized by a separate writer lock, the
  file is written without holding the reader lock, and the new state is published only after the file is
  committed. (Added after review round 1.)
- A write that fails before the rename changes nothing (memory and file keep the old state). If only the
  directory `fsync` after the rename fails, the change is in effect on disk and in memory; it is logged at error
  level and the user is told it may not survive a crash. A revoke therefore takes effect as soon as
  its file is renamed into place, before the response is sent. (Added after review round 1.)
- Corrupt file at start → log an error and refuse to start (do not silently drop the allowlist). "Corrupt"
  includes malformed records: the file must be a JSON array of complete entries (valid `ip`, non-empty `sub` and
  `user`, non-zero `created_at` and `expires_at` with `expires_at` after `created_at`), with no unknown fields,
  no trailing data and no two entries covering the same IP (IPv6: /64). The whole file is validated before
  anything is pruned or rewritten, and a rejected file is left untouched. (Clarified after review round 1.)

### 3.5 Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `LISTEN_ADDR` | `:8080` | Listen address |
| `PUBLIC_URL` | (required) | `https://enable.gullane.no`; redirect URI is `PUBLIC_URL + /auth/callback` |
| `OIDC_ISSUER` | (required) | `https://id.gullane.no`; no user info, query or fragment |
| `OIDC_CLIENT_ID` | (required) | |
| `OIDC_CLIENT_SECRET` | (required, or `OIDC_CLIENT_SECRET_FILE`) | |
| `SESSION_SECRET` | (required, or `SESSION_SECRET_FILE`; at least 32 bytes) | HMAC key |
| `ALLOWED_GROUPS` | empty (= any authenticated user) | Comma list of Pocket ID group names |
| `ADMIN_GROUPS` | empty | Comma list; members see and revoke all entries |
| `ALWAYS_ALLOW` | empty | Comma list of CIDRs always allowed by `/check` (LAN, tailnet) |
| `CLIENT_IP_HEADER` | `X-Client-IP` | Must be a valid HTTP header name |
| `DEFAULT_TTL` | `168h` | Pre-selected duration |
| `MAX_TTL` | `720h` | Upper bound |
| `SESSION_TTL` | `12h` | |
| `DATA_DIR` | `/data` | Absolute path to an existing, writable directory (checked at start) |
| `LOG_LEVEL` | `info` | |

Fail fast with a clear message on missing/invalid config, including a missing or unwritable `DATA_DIR`
(added after review round 1). OIDC discovery runs at start with retries
(Pocket ID may start after ipgate); `/check` must work even if OIDC discovery has not succeeded yet.

### 3.6 Logging and metrics

- Structured logs with `log/slog` (JSON) to stdout. Log every allow/revoke (user, IP, expiry) and every login
  (user, success/failure reason). Do **not** log every `/check` at info (debug only); never log tokens, cookies or
  secrets.
- OIDC failures (discovery, token endpoint, JWKS, ID token verification) are logged as fixed categories only, for
  example `token endpoint: unsuccessful response (HTTP 502)`. Upstream response bodies, raw library error
  strings and the provider's `error_description` are never logged, because they can contain tokens; only
  standard OAuth error codes are recorded. (Added after review round 1.)
- Optional: `GET /metrics` is out of scope for v1.

## 4. Non-functional

- Go (latest stable, 1.27), standard library first. Allowed dependencies: `github.com/coreos/go-oidc/v3` and
  `golang.org/x/oauth2`. Nothing else without a good reason written in the README.
- Layout suggestion: `cmd/ipgate/main.go`, `internal/{config,store,server,auth}`, templates embedded with
  `embed`.
- `Dockerfile`: multi-stage, `golang:1.27-alpine` builder, `CGO_ENABLED=0`, `-trimpath -ldflags="-s -w"`,
  final image `gcr.io/distroless/static-debian12:nonroot`, `USER nonroot`, `EXPOSE 8080`, `HEALTHCHECK` is not
  available in distroless, so add a `ipgate healthcheck` subcommand that GETs `/healthz` (compose uses it).
- Tests (`go test ./...`, run with `-race`):
  - store: add/refresh/revoke/expiry/prune/persist/reload, atomic write, corrupt file → error,
  - check handler: allowed, expired, missing header, spoofed `X-Forwarded-For` ignored, `ALWAYS_ALLOW`, IPv6 /64,
  - session sign/verify, tampering, expiry; CSRF required on POSTs; Origin check,
  - `/allow` refuses private IPs and takes the IP from the header, not the form,
  - OIDC callback with a fake OIDC provider (`httptest` server with discovery + JWKS + token endpoint), including
    wrong nonce, wrong audience and group not allowed.
- `go vet` and `gofmt` clean. A GitHub Actions workflow (`.github/workflows/ci.yml`) running vet, tests with
  `-race`, and `docker build` on push and PR.
- CI publishes a private image to `ghcr.io/olsenius/ipgate` (linux/amd64) with `docker/build-push-action`,
  only for pushes to `main` and `v*` tags and only after the test and docker jobs pass; pull requests never
  publish. It uses `GITHUB_TOKEN` with job-level `packages: write` (workflow default `contents: read`). Tags:
  `sha-<7-char sha>` and `main` on main; `v1.2.3`, `1.2`, `1` for tag `v1.2.3`; no `latest`. OCI labels
  source, revision and created. Deployments pin `sha-` tags. (Added 2026-10-29; replaces building on VM 300.)
- README (English): what it is, config table, Caddy snippet, how to run tests, how to build the image, and the
  security model (trust boundary = Caddy; never expose port 8080 directly).

## 5. Out of scope (handled by homelab-admin)

- Creating the OIDC client and groups in Pocket ID, secrets in 1Password, the compose service, Caddy routes,
  deploying to VM 300, and opening Jellyfin/Seerr. Do not touch the homelab.
- ~~Publishing images to a registry. VM 300 will build from a clone of this repo.~~ Now in scope: CI publishes
  the image (see §4); pulling and deploying it on VM 300 remains homelab-admin's job.

## 6. Acceptance

- `go test -race ./...` green, `go vet` clean, `docker build .` succeeds, CI green on GitHub.
- Running the container locally with a fake OIDC provider (or the test suite's) shows the full flow works:
  login → allow IP → `/check` returns 204 for that `X-Client-IP` and 403 for others → revoke → 403.
- README and this SPEC agree; deviations from the spec are listed in the README under "Deviations".
