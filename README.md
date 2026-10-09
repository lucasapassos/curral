# curral

[![ci](https://github.com/lucasapassos/curral/actions/workflows/ci.yml/badge.svg)](https://github.com/lucasapassos/curral/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/lucasapassos/curral)](https://github.com/lucasapassos/curral/releases)
[![docker](https://img.shields.io/docker/pulls/lucasapassos/curral)](https://hub.docker.com/r/lucasapassos/curral)
[![license](https://img.shields.io/github/license/lucasapassos/curral)](LICENSE)

**A secure SQL gateway for DuckDB.** curral puts your DuckDB databases and
Iceberg lakes behind an HTTP API, with authentication, a policy that decides
what each user may read or write, row-level security and column masking.

*Curral* is Portuguese for "corral": the place where you keep the herd in and
decide who gets through the gate.

```
client ──HTTP──▶ curral
                  ├─ authenticate      Basic (bcrypt) · API keys · OIDC/JWT
                  ├─ queue             global and per-user concurrency limits
                  ├─ inspect           DuckDB's own planner: statement type, tables read and written
                  ├─ authorize         embedded OPA policy (Rego) → allow / deny
                  ├─ protect           rewrite the query with row filters and column masks
                  └─ execute & stream  JSON · CSV · NDJSON · Arrow IPC
```

## Why curral?

DuckDB is a great engine, but it has no users, no permissions and no network
protocol. Sharing a DuckDB file or an Iceberg lake usually means either
handing out raw storage credentials or building a custom API per use case.
curral is the missing layer in between:

- **One binary, no moving parts.** DuckDB is embedded; databases and
  catalogs declared in a config file are attached at startup.
- **Policy as code.** Access rules are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
  and evaluated by an embedded OPA. The policy sees the base tables each
  statement *really* reads (views, CTEs and joins included), taken from
  DuckDB's own planner rather than a regex.
- **Row-level security and column masking.** Each user sees only their rows,
  and sensitive columns arrive masked, enforced by rewriting the query before
  it runs, so filters and joins cannot be used to guess hidden values.
- **Works with your lake.** Anything DuckDB can `ATTACH`: DuckDB files,
  Iceberg REST catalogs (including Cloudflare R2 Data Catalog, with a
  built-in metadata cache), Postgres, S3…
- **Built for production.** TLS, brute-force lockout, per-user and per-role
  limits, a fail-closed JSONL audit log, Prometheus metrics and hot reload
  with `SIGHUP`.
- **Friendly to tools and AI agents.** `GET /v1/schema` lists only what the
  caller may query, `dry_run` explains a policy decision without executing
  anything, and Arrow output streams straight into pandas, polars or DuckDB.

## Quickstart

Run curral with the example configuration (two local DuckDB databases and
three users: `admin`, `analyst` and `etl`):

```sh
git clone https://github.com/lucasapassos/curral && cd curral

docker run --rm -p 127.0.0.1:8080:8080 \
  -v "$PWD/examples:/etc/curral:ro" -e CURRAL_DATA=/var/lib/curral \
  lucasapassos/curral serve \
    --catalog /etc/curral/catalog.yaml \
    --users   /etc/curral/users.yaml \
    --policy  /etc/curral/policy.rego --policy /etc/curral/roles.json
```

In another terminal, create a table as `admin` and read it as `analyst`:

```sh
curl -u admin:admin-pw localhost:8080/v1/query \
  -d '{"sql": "CREATE TABLE orders AS SELECT range AS id, range * 10 AS amount FROM range(5)"}'

curl -u analyst:analyst-pw 'localhost:8080/v1/query?format=csv' \
  -d '{"sql": "SELECT * FROM orders"}'
```

The analyst can read but not write. Ask the policy why, without running
anything:

```sh
curl -u analyst:analyst-pw localhost:8080/v1/query \
  -d '{"sql": "DELETE FROM orders", "dry_run": true}'
# {"dry_run":true,"decision":"deny","decided_by":"policy","statement_type":"DELETE",
#  "tables":["sales.main.orders"],"targets":["sales.main.orders"], ...}
```

The example passwords and API key are public: never use `examples/users.yaml`
outside local tests.

## Installation

| Option | |
|---|---|
| **Docker** | `docker pull lucasapassos/curral` (linux/amd64 and linux/arm64, distroless, non-root, ~190 MB) |
| **Binary** | Linux amd64/arm64 tarballs (glibc 2.35+) on the [releases page](https://github.com/lucasapassos/curral/releases), with the `httpfs`, `avro` and `iceberg` extensions bundled so it runs offline |
| **From source** | Go 1.27+ and a C compiler: `go install -tags duckdb_arrow github.com/lucasapassos/curral/cmd/curral@latest` |

With the release tarball, point curral at the bundled extensions:

```sh
tar xzf curral_vX.Y.Z_linux_amd64.tar.gz && cd curral_vX.Y.Z_linux_amd64
./curral serve --extension-dir ./extensions --catalog ... --users ... --policy ...
```

## Querying

**HTTP.** One statement per `POST /v1/query`; parameters are bound
server-side:

```sh
curl -u analyst:analyst-pw localhost:8080/v1/query \
  -d '{"sql": "SELECT * FROM orders WHERE id = $1", "params": [3], "format": "json"}'
```

**CLI.** The same binary is also a client:

```sh
export CURRAL_URL=http://localhost:8080 CURRAL_USER=analyst CURRAL_PASSWORD=analyst-pw
curral query "SELECT count(*) FROM orders"                  # CSV on stdout
curral query -f arrow -o orders.arrow "SELECT * FROM orders"
```

**Python.** A single-file client in [`clients/python`](clients/python):

```python
from curral import Client
c = Client("http://localhost:8080", user="analyst", password="analyst-pw")
df = c.query("SELECT * FROM orders").to_pandas()   # Arrow under the hood
```

**AI agents.** [`skills/curral`](skills/curral) is an agent skill that
teaches an assistant to discover the schema, validate with `dry_run` and
query within its permissions.

## Writing a policy

The policy receives what the statement does and returns `allow`:

```rego
package curral
import rego.v1

default allow := false

allow if "admin" in input.roles

allow if {
	"analyst" in input.roles
	input.resolved
	input.statement_type == "SELECT"
	every t in input.tables { startswith(t, "sales.") }
}
```

Optional rules add per-role limits (timeout, max rows, concurrency) and
column masks; a separate file defines row filters. See
[`examples/policy.rego`](examples/policy.rego) for a complete role-based
model and [docs/authorization.md](docs/authorization.md) for every input
field.

## Connecting a lake

The catalog file declares extensions, secrets and databases. Values can come
from the environment, and a missing variable aborts startup:

```yaml
extensions: [httpfs, iceberg]
secrets:
  - name: lake_catalog
    type: iceberg
    params: { TOKEN: "${LAKE_TOKEN}" }
databases:
  - name: lake
    path: ${LAKE_WAREHOUSE}
    schema: analytics
    cache_ttl: 30s          # cache catalog metadata: ~8 ms instead of 250–900 ms per query on R2
    options: { TYPE: iceberg, SECRET: lake_catalog, ENDPOINT: "${LAKE_CATALOG_URI}" }
```

[`docker-compose.yml`](docker-compose.yml) runs curral against a Cloudflare
R2 Data Catalog, and [`deploy/`](deploy) shows a production setup with Caddy
and automatic HTTPS.

## Documentation

| | |
|---|---|
| [Configuration](docs/configuration.md) | flags, environment variables, catalog file, R2/Iceberg, Docker, reload |
| [API](docs/api.md) | `/v1/query`, `/v1/schema`, formats, errors, dry-run, CLI |
| [Authentication](docs/authentication.md) | users, API keys, OIDC (Keycloak, Auth0, Entra, Google), TLS, brute-force protection |
| [Authorization](docs/authorization.md) | policy input, per-role limits, fairness, row-level security and masking |
| [Security](docs/security.md) | built-in guarantees, audit log, how inspection is verified, known limitations |
| [Operations](docs/operations.md) | metrics, alerts, performance, releasing |
| [Deployment](deploy/README.md) | Docker Compose behind Caddy on a single server |

## Status

curral is pre-1.0: the API and configuration may still change between minor
versions, and every change is listed in the [CHANGELOG](CHANGELOG.md).
Security fixes are released as soon as they are ready.

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE).
