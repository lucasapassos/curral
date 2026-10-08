# Changelog

Versions follow [Semantic Versioning](https://semver.org). Each release's
notes are taken from its section here.

## [v0.2.0] - 2026-10-08

### Data protection
- Row-level security from a file (`--row-filters`): per table, rules by role
  or user (exact or `*@domain`) with a SQL predicate; matching rules are OR-ed;
  users matching no rule are not filtered. `getvariable('curral_user')` and
  `getvariable('curral_roles')` allow ACL tables. Validated against the real
  tables at boot, `check` and reload (SIGHUP).
- Column masking decided by the policy (`--policy-masks-query`): presets
  `null`, `redact`, `last:N`, or custom SQL.
- Applied by rewriting DuckDB's own parse tree: each protected table becomes a
  filtered, masked subquery, so user predicates never see real values.
  Fail-closed: non-SELECT statements on protected tables, indirect reads
  (views/macros), unstable round trips, TABLESAMPLE/AT and PIVOT are refused.
- Dry runs and audit events show `row_filters` and `masked_columns`;
  `curral_queries_rewritten_total` counts rewritten queries.
- Differential test and weekly fuzz against a pre-filtered, pre-masked copy.

## [v0.1.0] - 2026-10-07

First release. A single Go binary that embeds DuckDB and serves SQL over REST
with authentication, Rego-based authorization and auditing.

### Engine
- Databases mounted from a catalog file via `ATTACH`: DuckDB files and any
  ATTACH-capable source (Iceberg REST catalogs such as Cloudflare R2, Postgres,
  S3...). Credentials come from `${ENV}` references and are removed from the
  environment after boot.
- Hardened instance: external access off (allowlisted prefixes), locked
  configuration, no extension loading; ATTACH, DETACH, LOAD, INSTALL and UPDATE
  EXTENSIONS are always denied.
- A fresh connection and a single transaction per request; concurrency limit
  with a queue; per-request and per-role timeouts.
- Catalog metadata cache for Iceberg REST (`cache_ttl`): ~8 ms instead of
  250–900 ms per query on R2.

### Security
- Authentication: local users (bcrypt), API keys (`curral gen-api-key`) and
  OIDC JWTs (Keycloak, Auth0, Entra, Google...), with `identities` mapping users
  or e-mail domains to roles.
- Authorization by an embedded OPA policy over the inspected statement:
  tables read (from DuckDB's plan, or its parser for Iceberg), write targets,
  table functions, statement type. Inspection fails closed on anything it
  cannot read exactly like DuckDB, and is checked by differential fuzzing.
- Per-request limits from the policy: timeout, max rows, max concurrency per
  user or group.
- TLS (with reload), brute-force lockouts per IP and user, trusted proxies.

### Operations
- Audit log (JSONL) with fail-closed execution, redacted SQL, policy hash and
  per-stage timings; Prometheus metrics; reload of users, policy and
  certificate on SIGHUP; dry runs.
- Output as CSV, JSON, NDJSON or Arrow IPC (~7x faster than CSV for large
  results).
- `curral query` command-line client and a Python client (`clients/python`).
- Docker image `lucasapassos/curral` (distroless, extensions included, works
  offline; linux/amd64 and linux/arm64), compose file with an optional Caddy
  TLS front.
