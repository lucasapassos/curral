# Configuration

How to run `curral serve`: command-line flags, the catalog file, reloading, Docker and building from source.

## Running the server

```sh
curral hash-password                       # generates the bcrypt hash for users.yaml

CURRAL_DATA=./data curral serve \
  --catalog examples/catalog.yaml \
  --users   examples/users.yaml \
  --policy  examples/policy.rego \
  --policy  examples/roles.json \
  --max-concurrency 8 --queue-timeout 5s --query-timeout 60s \
  --memory-limit 8GB --threads 8

curral check ...                           # validates the files and mounts the catalog without starting HTTP
curral serve -h                            # every flag
```

Every flag can also be set from the environment as `CURRAL_<FLAG>`, for
example `CURRAL_MAX_CONCURRENCY=16`. Repeatable flags accept a comma-separated
list: `CURRAL_POLICY=policy.rego,roles.json`.

## Flags

| Flag | Default | |
|---|---|---|
| `--catalog` | — | extensions, secrets and databases (`ATTACH`) |
| `--users` | — | users, bcrypt hashes and roles |
| `--policy` | — | `.rego` or JSON/YAML data (`data.*`), repeatable |
| `--policy-query` | `data.curral.allow` | decision that must be `true` |
| `--policy-limits-query` | (off) | optional rule with per-request limits, e.g. `data.curral.limits` |
| `--policy-masks-query` | (off) | optional rule with column masks, e.g. `data.curral.masks` |
| `--row-filters` | (off) | RLS file: which rows each user sees, per table; reloaded on `SIGHUP` |
| `--max-concurrency` | 8 | queries executing at the same time |
| `--queue-timeout` | 5s | wait for a free slot; after that the response is 503 |
| `--max-concurrency-per-user` | 0 (no limit) | concurrent queries per user when the policy sets no `max_concurrency` |
| `--query-timeout` | 60s | maximum duration; after that the response is 504 |
| `--max-rows` | 0 | row limit per response (0 = no limit) |
| `--threads`, `--memory-limit`, `--temp-dir`, `--max-temp-size` | | DuckDB resources |
| `--extension-dir` | | pre-installed extensions (offline) |
| `--external-access` | false | keeps `enable_external_access` on |
| `--allowed-path` | | prefix (directory or `s3://bucket/`) allowed while external access is off, repeatable |
| `--auth-cache-ttl` | 5m | cache of already-verified passwords |
| `--schema-cache-ttl` | 10m | reuse of the `/v1/schema` listing; afterwards it reloads in the background (0 = load on every request) |
| `--oidc-issuer` / `--oidc-audience` | (off) | accept JWTs from this OIDC provider; the audience is mandatory |
| `--oidc-user-claim` / `--oidc-roles-claim` | `sub` / `roles` | user and roles claims (dotted paths work: `realm_access.roles`) |
| `--oidc-skew` | 30s | clock tolerance for `exp`/`nbf` |
| `--oidc-require-email-verified` | true | with `--oidc-user-claim email`, requires `email_verified=true` |
| `--oidc-hosted-domain` | (any) | accept only tokens with this `hd` claim (Google Workspace domain), repeatable |
| `--audit-log` | (off) | JSONL audit file; `-` = stdout; `SIGHUP` reopens it |
| `--audit-sql` | `redacted` | SQL text in the audit log: `redacted`, `full` or `hash` |
| `--audit-queue` | 4096 | in-memory events waiting to be written |
| `--metrics-listen` | (off) | separate address for the Prometheus `/metrics`, e.g. `127.0.0.1:9090` |
| `--tls-cert` / `--tls-key` | (plain HTTP) | native HTTPS, TLS 1.2+; the certificate reloads on `SIGHUP` |
| `--trusted-proxy` | (none) | IP/CIDR of a proxy allowed to set `X-Forwarded-For`, repeatable |
| `--auth-ip-max-failures` | 10 | login failures per IP within the window before lockout (0 = off) |
| `--auth-user-max-failures` | 30 | failures per user name within the window before lockout (0 = off) |
| `--auth-failure-window` / `--auth-lockout` | 5m / 15m | counting window / lockout duration |

## Catalog

See `examples/catalog.yaml`. Values accept `${VAR}` and `${VAR:-default}`. A
missing variable without a default aborts startup, so credentials are never
empty by accident. `ATTACH` and secret options are passed through as-is, so
Iceberg, Postgres, S3 and so on all work the same way:

```yaml
extensions: [httpfs, iceberg]
secrets:
  - name: lake_catalog
    type: iceberg
    params: { CLIENT_ID: "${ICEBERG_CLIENT_ID}", CLIENT_SECRET: "${ICEBERG_CLIENT_SECRET}" }
databases:
  - name: lake
    path: ${ICEBERG_WAREHOUSE}
    options: { TYPE: iceberg, SECRET: lake_catalog, ENDPOINT: "${ICEBERG_ENDPOINT}" }
```

Secret values and paths are redacted in the log.

The `schema` field (default `main`) sets the schema used for unqualified
names. Iceberg catalogs have no `main`, so set the namespace (e.g.
`schema: analytics`).

`READ_ONLY: true` in a database's `options` requires the file to already
exist: DuckDB cannot create a database in read-only mode. That is why the
example catalog ships with it commented out for `logs`; the example policy
grants no writes there anyway.

### Cloudflare R2 Data Catalog

The example is in `examples/catalog.r2.yaml` and `examples/r2.env.example`. No
S3 secret is needed, because R2 vends storage credentials through the catalog.
With external access off, allow just the bucket:

```sh
curral serve --catalog examples/catalog.r2.yaml ... --allowed-path s3://<bucket>/
```

#### Catalog metadata cache (`cache_ttl`)

On every request DuckDB asks the REST catalog for the table metadata
(`loadTable`), and that is not cached across transactions. On R2 this round
trip costs 250–900 ms, nearly all of the query time. The files themselves
(avro, parquet) are already kept in DuckDB's own external file cache.

`cache_ttl` puts a local caching proxy (`127.0.0.1`) between DuckDB and the
catalog:

```yaml
databases:
  - name: lake
    path: ${R2_WAREHOUSE}
    schema: analytics
    cache_ttl: 30s
    options: { TYPE: iceberg, SECRET: r2_catalog, ENDPOINT: "${R2_CATALOG_URI}" }
```

- **Caching rules:**
  - Only 200 responses to GET are cached.
  - The key includes a hash of the `Authorization` header.
  - Identical concurrent requests collapse into a single upstream call.
- **Writes:** any POST/PUT/DELETE (commit) passes straight through and empties the cache.
- **Temporary credentials:** if the response carries `*expires-at-ms`, the entry expires 1 minute before the credentials do. R2 does not report expiry, so keep the TTL short.
- **Trade-off:** commits by **other** writers can take up to `cache_ttl` to show up.

Measured against R2 (simple aggregation, over HTTP with auth and policy):

| | no cache | `cache_ttl: 30s` |
|---|---|---|
| p50, 1 client | 273 ms | 8 ms |
| throughput, 8 clients | 3 req/s | 338 req/s |

Integration test (skipped when the variables are not set):

```sh
source .env.r2 && go test ./internal/engine -run R2 -v
```

## Reload without restart

`SIGHUP` (or `docker compose kill -s HUP curral`) reloads the **users file**
and the **policy** (`.rego` and data) and reopens the audit log.

- **Invalid new file:** the previous version stays in effect and the error goes to the log.
- **Atomic swap:** in-flight requests finish with the version they started with.
- **Password cache:** it is dropped, so removed users or changed passwords lose access immediately.
- **Tracking:** each attempt produces a `config_reload` audit event, with the new `policy_sha256` or the error, and counts in `curral_config_reloads_total`. `curral_policy_info` shows the hash in effect.
- **Catalog:** it is mounted and locked at startup, so changes to it require a restart.

The `--row-filters` file and the TLS certificate also reload on `SIGHUP`.

## Docker

```sh
docker compose up --build        # uses .env (R2 credentials) and examples/
```

- **`distroless/cc` image** (~190 MB), non-root user, no shell.
- **The `httpfs`, `avro` and `iceberg` extensions** are installed at build time with the binary's own DuckDB, so the container boots **without internet access** and with pinned versions. Other extensions: `--build-arg EXTENSIONS="httpfs avro iceberg postgres"`.
- **`docker-compose.yml`** runs with a read-only filesystem, `cap_drop: ALL` and a tmpfs for DuckDB's spill, and publishes the port only on `127.0.0.1`. It requires `R2_SCHEMA` and `R2_ALLOWED_PATH`, along with the `R2_CATALOG_URI`, `R2_WAREHOUSE` and `R2_TOKEN` credentials.
- **Helper subcommands:** `curral version`, `curral healthcheck [url]` (used by `HEALTHCHECK`, since the image has no curl) and `curral install-extensions --extension-dir DIR names...`.

For a production deployment behind Caddy with automatic TLS, see
[deploy/README.md](../deploy/README.md).

## Build

Requires Go 1.27+ and a C compiler (cgo, because of DuckDB).

```sh
go build -tags duckdb_arrow -ldflags "-s -w" -o bin/curral ./cmd/curral
go test -tags duckdb_arrow ./...
```

The `duckdb_arrow` tag enables Arrow IPC output and is used by the Docker image
and CI. Without it the build works the same, but `format: arrow` responds 400.

See also: [API](api.md) · [Authentication](authentication.md) · [Authorization](authorization.md) · [Security](security.md) · [Operations](operations.md)
