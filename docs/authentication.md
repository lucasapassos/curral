# Authentication

How clients prove who they are, and how curral protects itself when exposed to a network.

## Methods

Three methods, chosen by the `Authorization` header:

| Header | Method | Where roles come from |
|---|---|---|
| `Basic base64(user:password)` | local user (bcrypt, cached) | `users[].roles` in the users file |
| `Bearer curral_...` | service API key | `api_keys[].roles` in the users file |
| `Bearer <JWT>` | OIDC token (Keycloak, Auth0, Entra, Google...) | the `--oidc-roles-claim` claim |

- **Local users**: `curral hash-password` produces the bcrypt hash for the users file. See `examples/users.yaml`.
- **API keys**: `curral gen-api-key etl-job etl` prints the key **once**, along with
  the entry for the users file. The file stores only the key's SHA-256.
  `expires` is optional. Like users, API keys reload on `SIGHUP`.
- **JWT**:
  - **Startup:** curral runs OIDC discovery and downloads the JWKS. If the provider is unreachable, startup fails.
  - **Keys:** the JWKS is refreshed in the background.
  - **Validation:** signature, `iss`, `aud`, `exp` and `nbf`. Unsigned tokens (`alg: none`) or tokens signed by another key are rejected.
  - **Roles:** the claim may be a list or a space-separated string (e.g. `scope`).
- **Tracking:** the audit log records `auth_method` (`basic`, `api_key`, `jwt`). `curral_auth_failures_total{method}` splits failures by method, and the operational log carries the reason. The client always just gets 401.

```sh
curral serve ... --oidc-issuer https://sso.example.com/realms/main --oidc-audience curral \
  --oidc-user-claim preferred_username --oidc-roles-claim realm_access.roles
```

### Roles by identity (`identities:`)

Some providers send no roles in the token (Google, for instance). The
`identities` section of the users file assigns roles per user or per e-mail
domain, and reloads on `SIGHUP`:

```yaml
identities:
  - match: ana@example.com    # exact, case-insensitive
    roles: [analyst]
  - match: "*@example.com"    # any address in the domain (not subdomains)
    roles: [analyst]
```

Mapped roles are added to any roles the token already carries. An
authenticated user who matches no entry (and has no roles in the token) gets
access to nothing under the example policy.

### Google

```sh
curral serve ... \
  --oidc-issuer https://accounts.google.com \
  --oidc-audience <CLIENT_ID>.apps.googleusercontent.com \
  --oidc-user-claim email
  # optional, Google Workspace accounts: --oidc-hosted-domain example.com
```

- **Client ID:** create an OAuth Client in Google Cloud Console → APIs &
  Services → Credentials.
- **Token:** the client sends the **ID token** (JWT) in
  `Authorization: Bearer ...`. Google access tokens are not JWTs and do not work.
- **Who can log in:** with an "External" consent screen, any Google account
  can obtain a valid token for your client ID (e.g. `ana@gmail.com`). Access
  comes only from `identities`, and `email_verified` is required so that an
  account with an unverified e-mail cannot pose as a mapped address.
- **Local testing:** `gcloud auth print-identity-token` produces an ID token
  whose audience is gcloud's own client ID. Do not use that audience in
  production: every gcloud user would have their tokens accepted.

## Network exposure: TLS and brute force

### TLS

Without TLS, passwords, API keys and tokens travel in clear text, and curral
warns about it at startup. There are two options:

- **Native TLS:** `--tls-cert`/`--tls-key`. `SIGHUP` reloads the certificate
  without dropping connections, and an invalid file keeps the current
  certificate.
- **Proxy with automatic certificates:** `docker compose --profile tls up`
  starts Caddy in front, with Let's Encrypt for `CURRAL_DOMAIN` or a local CA
  for `localhost`, plus HSTS. See [deploy/README.md](../deploy/README.md).

### Brute force

- **Counting:** authentication failures are counted per IP and per user name.
  The per-user limit catches distributed attacks.
- **Lockout:** past the limit, requests get **429** with `Retry-After`,
  **even with the right credential**. The lockout is checked before bcrypt, so
  it costs no CPU.
- **CPU:** bcrypt runs with concurrency capped at the number of CPUs, so a
  flood of wrong passwords cannot exhaust the machine.
- **Tracking:** `auth_blocked` audit events and the metrics
  `curral_auth_lockouts_total{scope}` and `curral_auth_blocked_total{scope}`.
- **Trade-off:** the per-user lockout lets someone temporarily lock another
  person's account by getting their password wrong. Tune
  `--auth-user-max-failures`, or set it to 0 to turn it off.

### Real client IP behind a proxy

curral only uses `X-Forwarded-For` when the connection comes from a
`--trusted-proxy`, and reads it right to left, stopping at the first untrusted
IP. So an IP the client writes into the header itself is never accepted. Trust
**only the proxy's IP**, never the whole Docker subnet: it includes the
gateway, through which any access to ports published on the host arrives, and
those could then forge the header. The compose file pins Caddy's IP
(`CURRAL_PROXY_IP`) for this reason.

See also: [Configuration](configuration.md) · [API](api.md) · [Authorization](authorization.md) · [Security](security.md) · [Operations](operations.md)
