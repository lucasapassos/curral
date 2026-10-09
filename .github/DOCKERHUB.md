# curral

**A secure SQL gateway for DuckDB.** curral puts your DuckDB databases and
Iceberg lakes behind an HTTP API, with authentication, a policy that decides
what each user may read or write, row-level security and column masking.

- Source, issues and full documentation: **https://github.com/lucasapassos/curral**
- License: Apache 2.0

## Quick start

The example configuration lives in the GitHub repository (two local DuckDB
databases and three users: `admin`, `analyst` and `etl`):

```sh
git clone https://github.com/lucasapassos/curral && cd curral

docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/examples:/etc/curral:ro" -e CURRAL_DATA=/var/lib/curral \
  lucasapassos/curral serve \
    --catalog /etc/curral/catalog.yaml \
    --users   /etc/curral/users.yaml \
    --policy  /etc/curral/policy.rego --policy /etc/curral/roles.json
```

```sh
curl -u admin:admin-pw localhost:8080/v1/query \
  -d '{"sql": "CREATE TABLE orders AS SELECT range AS id, range * 10 AS amount FROM range(5)"}'

curl -u analyst:analyst-pw 'localhost:8080/v1/query?format=csv' \
  -d '{"sql": "SELECT * FROM orders"}'
```

The example passwords are public: never use `examples/users.yaml` outside
local tests.

## Tags

| Tag | |
|---|---|
| `latest` | the most recent release |
| `vX.Y.Z` | a specific release ([changelog](https://github.com/lucasapassos/curral/blob/main/CHANGELOG.md)) |

Images are multi-arch: `linux/amd64` and `linux/arm64`.

## About the image

- **Base:** `gcr.io/distroless/cc` (Debian 13), running as the non-root user
  `nonroot` (UID 65532), with no shell.
- **Entrypoint:** `curral`; the default command is `serve`. Other
  subcommands: `version`, `check`, `hash-password`, `gen-api-key`,
  `healthcheck`, `query`.
- **Ports:** `8080` (API) and `9090` (Prometheus `/metrics`, only when
  `CURRAL_METRICS_LISTEN=:9090` is set; it has no authentication, so keep it
  internal).
- **Extensions:** `httpfs`, `avro` and `iceberg` are installed at build time
  in `/opt/curral/extensions`, so the container starts without internet
  access and with pinned extension builds.
- **Healthcheck:** built in (`curral healthcheck`), since there is no curl in
  the image.

| Path | Purpose |
|---|---|
| `/var/lib/curral` | working directory; mount a volume here for DuckDB files |
| `/var/lib/curral/tmp` | DuckDB spill directory (`CURRAL_TEMP_DIR`); a tmpfs works well |
| `/var/log/curral` | a place for the audit log (`CURRAL_AUDIT_LOG=/var/log/curral/audit.jsonl`) |

## Configuration

Every flag of `curral serve` can also be set as an environment variable
`CURRAL_<FLAG>`, e.g. `CURRAL_MAX_CONCURRENCY=16`. Repeatable flags take a
comma-separated list: `CURRAL_POLICY=/etc/curral/policy.rego,/etc/curral/roles.json`.

```yaml
services:
  curral:
    image: lucasapassos/curral:latest
    ports: ["127.0.0.1:8080:8080"]
    environment:
      CURRAL_CATALOG: /etc/curral/catalog.yaml
      CURRAL_USERS: /etc/curral/users.yaml
      CURRAL_POLICY: /etc/curral/policy.rego,/etc/curral/roles.json
      CURRAL_AUDIT_LOG: /var/log/curral/audit.jsonl
    volumes:
      - ./config:/etc/curral:ro
      - audit:/var/log/curral
    read_only: true
    tmpfs: ["/var/lib/curral/tmp:uid=65532,gid=65532,mode=0700"]
    cap_drop: [ALL]
volumes:
  audit:
```

Send `SIGHUP` (`docker compose kill -s HUP curral`) to reload users, policy,
row filters and the TLS certificate, and to reopen the audit log.

Need more extensions? Build the image yourself:

```sh
docker build --build-arg EXTENSIONS="httpfs avro iceberg postgres" -t curral .
```

## Documentation

- [Configuration](https://github.com/lucasapassos/curral/blob/main/docs/configuration.md): flags, catalog file, Iceberg / Cloudflare R2
- [API](https://github.com/lucasapassos/curral/blob/main/docs/api.md): `/v1/query`, `/v1/schema`, formats, dry-run
- [Authentication](https://github.com/lucasapassos/curral/blob/main/docs/authentication.md): users, API keys, OIDC, TLS
- [Authorization](https://github.com/lucasapassos/curral/blob/main/docs/authorization.md): Rego policies, limits, row-level security, masking
- [Security](https://github.com/lucasapassos/curral/blob/main/docs/security.md) and [operations](https://github.com/lucasapassos/curral/blob/main/docs/operations.md)
- [Production deployment behind Caddy](https://github.com/lucasapassos/curral/blob/main/deploy/README.md)

Report vulnerabilities privately: see the
[security policy](https://github.com/lucasapassos/curral/blob/main/SECURITY.md).
