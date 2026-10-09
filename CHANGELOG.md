# Changelog

Versions follow [Semantic Versioning](https://semver.org). Each release's
notes are taken from its section here.

## [v0.3.2] - 2026-10-09

### Security
- Fixed: errors raised while binding, before the policy ran, mapped tables
  the caller cannot read: an unknown column gave 400 "column not found"
  where an existing one gave 403, and type errors named column types. Read
  file functions leaked whether a path existed the same way. When binding
  fails, the policy is now asked about the tables and table functions named
  in the parse tree; if it denies, the caller gets exactly the response of a
  valid denied statement (also in dry runs). Syntax errors, and errors on
  objects the caller may read, are reported as before.

## [v0.3.1] - 2026-10-09

### Security
- Fixed: a write reading DESCRIBE output (`INSERT ... SELECT ... FROM
  (DESCRIBE t)`, `CREATE TABLE/VIEW ... AS ... (DESCRIBE t)`) still copied
  the columns of a denied table, since only SELECT was checked. Writes that
  contain DESCRIBE, SHOW or SUMMARIZE (or DESC starting a query) are now
  unresolved, so the policy fails closed; `ORDER BY ... DESC` is unaffected.
- Fixed: catalog listings were only refused when the plan named them, so
  statements without a plan (`COPY (SELECT ... duckdb_tables()) ...`,
  `SET VARIABLE x = (... duckdb_views())`) could still run them and crash
  the server. Any mention of a listing function, pragma or catalog schema
  in such a statement is refused, and so are `query()`, `query_table()`
  and `json_execute_serialized_sql()`, whose SQL is a string.
- Fixed: a view or table macro wrapping DESCRIBE revealed the columns of the
  table it describes. A plan with more bind-time results (CHUNK_GET) than
  the statement's own DESCRIBEs is now unresolved.
- Fixed: error suggestions were only removed from SQL errors and when they
  started a line; they are now removed from every error message.

## [v0.3.0] - 2026-10-09

### Security
- Fixed: `DESCRIBE`/`SHOW` (also as a subquery, or `DESCRIBE SELECT ...`)
  revealed the columns and types of tables the policy denies: DuckDB answers
  them while binding, so the plan read no table. The inner query of each
  DESCRIBE is now inspected like a real read; `SHOW TABLES`-style catalog
  listings are unresolved (fail closed). `SUMMARIZE` was already covered.
- Fixed: DuckDB error suggestions ("Did you mean ...?", "Candidate
  bindings: ...") named tables and columns the caller cannot read, before
  the policy ran. They are removed from responses (logs and audit keep the
  full message), which point to `GET /v1/schema` instead.
- Fixed: `/v1/schema` listed tables and views in a single `UNION ALL` of
  `duckdb_tables()` and `duckdb_views()`, which crashed the process (SIGSEGV
  in DuckDB) when run concurrently with queries on an Iceberg catalog. The
  same statement sent to `/v1/query` crashed v0.2.2 as well (DuckDB issue),
  so catalog listings are now refused for every role, before the policy:
  `duckdb_tables()`, `duckdb_views()`, `duckdb_columns()` and the other
  catalog-wide functions, `information_schema`/`pg_catalog` views,
  `SHOW TABLES`, `PRAGMA show_tables` and `CALL duckdb_*()`. Use
  `GET /v1/schema` instead.

### Added
- `max_rows` in `/v1/query` requests: lowers the row limit for that request
  (never raises the server's or the role's). Also `curral query -max-rows`
  and `max_rows=` in the Python client; a cut at the limit the caller asked
  for is a sample there, not an error. The dry run reports the effective
  limit.
- `GET /v1/schema`: tables and views with their columns (type, nullability,
  comments), filtered per caller through the same inspection, policy and
  protections as `SELECT * FROM object`; masked columns and row-filtered
  tables are flagged. Narrow with `?database=`, `?schema=`, `?table=`.
  Audited as `schema` events.
- Schema snapshot cache (`--schema-cache-ttl`, default 10m), loaded at boot,
  refreshed in the background when stale and at once after DDL through
  curral. Against R2 (4 tables): ~4 s cold, ~0.5 ms cached; per-caller
  filtering runs in memory, so policy changes apply immediately.

## [v0.2.2] - 2026-10-08

### Performance
- Row filters/masks: rewrites are cached (LRU, 4096 entries) by statement,
  database and protections; the indirect-read check still runs on every
  request against that request's plan, so a view redefined later is caught
  (tested). Session variables are only set when a filter or mask calls
  getvariable() or a user macro (detected on DuckDB's parse tree).
- Fixed overhead per protected query: ~1.6 ms -> ~0.2 ms (engine benchmark).
  Local point lookups at 8 clients lose ~20% throughput vs unprotected
  (was ~58%); on R2 the p50 overhead is ~1.5-2.5 ms (was ~3.5 ms).

## [v0.2.1] - 2026-10-08

### Security
- Fixed: a local view over a lake (Iceberg) table bypassed row filters, masks
  and table-level policy, because DuckDB's plan does not name the Iceberg table
  behind the view. Inspection now counts lake scans against direct references;
  extra scans (`hidden_remote_scans`) make the statement unresolved, and users
  with any filter or mask on a lake table are refused such statements even
  under a policy that accepts unresolved ones. Found by validating against
  the real R2 catalog; covered by R2 integration tests.

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
