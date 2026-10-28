# Changelog

Versions follow [Semantic Versioning](https://semver.org). Each release's
notes are taken from its section here.

## [Unreleased]

### Added
- `GET /v1/schema` reports `docs` on each table: how many semantic
  documents are about it, matched as the document filters match names;
  omitted when none. Under `--docs-scope schema` only documents the caller
  may read count. A client can skip listing documents for tables without
  any.
- Documents listed by `GET /v1/docs` or returned by `POST /v1/docs/search`
  carry `accessible_tables` and `inaccessible_tables`: which of their
  `tables` the caller may query, by the caller's `/v1/schema` listing, in
  both `--docs-scope` modes.

### Changed
- `GET /v1/docs` and `POST /v1/docs/search` list the caller's schema (one
  `docs_scope` audit event per request) under `--docs-scope all` too, to
  annotate the documents; like queries, they are refused while the audit
  log cannot record it. `GET /v1/docs/{id}` under `all` still needs no
  listing.
- `--docs-scope schema`: a semantic document that names tables or schemas
  is served only to callers who may query at least one of them, as listed
  by `/v1/schema` and audited as `docs_scope`. Reads and writes alike
  answer 404 for an out-of-scope id, a short name shared across databases
  counts only when every table it fits is readable, and documents naming
  no table or schema reach everyone. The default `all` keeps serving every
  document to every authenticated user.
- `GET /v1/capabilities` reports `docs` (`enabled`, `scope`,
  `delegated_writes`), so a client knows whether `/v1/docs` is served
  without probing it.
- Delegated document writes: a delegating key with `docs_write: true`
  creates, updates and deletes semantic documents on behalf of the identity
  it names. The docs decision then sees `input.identity` and `input.actor`
  and the document's author is the identity. Without the flag, delegated
  requests keep refusing writes; the flag on a key without `delegation` is
  refused when the users file loads.

## [v0.7.0] - 2026-10-25

### Added
- Execution delegation: API keys with `delegation: true` query on behalf of
  the identity they name in `X-Curral-Execution-Context`, over HTTP and
  Flight SQL. The policy sees it as `input.identity` and the key as
  `input.actor` (with the key's `attributes`); its own roles are never
  used, requests are read-only and responses confirm the identity in
  `X-Curral-Effective-Subject`. See `docs/delegation.md`.
- `GET /v1/capabilities` describes the credential and the delegation
  contract.
- Policy row predicates (`--policy-row-filters-query`, default
  `data.curral.row_filters`), ANDed with the `--row-filters` file, and the
  `curral_identity` session variable for filters and masks.

### Changed
- DuckDB 2.0.0 (was 1.5.6). Database files DuckDB 2.0 creates (a catalog
  path that does not exist yet, files seeded with DuckDB 2.0) use storage
  format v2.0.0+, which older curral releases (DuckDB 1.x) cannot open, so
  there is no going back to an older release with them; back them up
  first. Existing 1.x files keep their storage version when written.
- `SHOW <table>` goes through the policy as a read of that table under
  DuckDB 2.0's parser too. `SHOW` of a name that DuckDB would read as a
  setting, or that it parses again (dots or quotes inside one quoted
  identifier), is unresolved; qualify the table or use `DESCRIBE`. So are
  `SHOW`/`DESCRIBE` inside a `WITH` clause, and a bare `SHOW` next to a
  direct `pragma_show(...)` call.
- Row filters (file and policy) and `{"sql": ...}` masks must each be a
  single SQL expression; a filter that could escape its parentheses, or
  holds `;`, comments or dollar quotes, is refused.
- Shared keys may send an audit-only `X-Curral-Caller-Context`; audit events
  gain `actor`, `identity` and `caller`, and refused identities are recorded
  as `delegation_denied`.
- The agent skill keeps curral credentials out of the conversation:
  `scripts/curral.sh login`, run by the user in a terminal, asks for the
  URL and the password (not echoed) and saves them to
  `~/.config/curral/credentials` (mode 600, or `$CURRAL_CONFIG`), which the
  script reads when the environment has no credentials. `curral.sh status`
  checks the connection without showing the secret and exits 5 when none
  is configured; the skill starts with it and asks the user to run `login`
  instead of asking for the password in the chat.
- `skills/curral/scripts/curral.ps1`: the skill's client for PowerShell on
  Windows (5.1 or later, with the `curl.exe` that ships with Windows), with
  the same commands, output and exit codes as `curral.sh`. Its `login`
  stores the secret in `%APPDATA%\curral\credentials` encrypted with DPAPI.

### Fixed
- Nested `SHOW`/`DESCRIBE` results cannot hide metadata reads of unauthorized
  tables through views or macros when matching the statement to its plan.
- `scripts/curral.sh` broke Basic auth when the user or password contained
  `"`.

## [v0.6.0] - 2026-10-12

### Added
- Arrow Flight SQL on a second port with `--flight-listen` (off by default),
  so DBeaver, DataGrip (Arrow Flight SQL JDBC driver) and ADBC clients
  connect to curral. Calls go through the same authentication, lockouts,
  policy, row filters, masks, limits, audit log and metrics as the HTTP API,
  over the same TLS certificate. A password login gets a 12-hour session
  token; database trees list only what the user may query; preparing a
  statement authorizes it (`prepare` audit event) and returns its parameter
  and result types; the `database` header or JDBC's `setCatalog` picks the
  database for unqualified names.

## [v0.5.0] - 2026-10-10

### Added
- Semantic documents: with `--docs-dir`, `/v1/docs` stores JSON notes on
  schemas, tables and example SQL (one file each) for AI agents to read.
  Any authenticated user reads them; writes (`POST`, `PUT`, `PATCH` merge
  patch, `DELETE`, with `If-Match`) follow the policy decision
  `--policy-docs-query` (default `data.curral.docs_allow`) and are audited.
  The example policy grants them to the new `poet` role.
- `POST /v1/docs/search` returns the semantic documents that best fit a
  question: `table`/`schema` filters, then BM25 over the documents (title
  weighted most; accents, identifiers and plurals folded). With `--jev-key`,
  TypeSafe's Jev model judges the best `--search-shortlist` candidates and
  only those at or above `--jev-threshold` (0.7) are returned, ranked by
  it; when none is, those at or above `--jev-floor` (0.2) come back as weak
  matches.
- The Python client reads, searches and writes semantic documents
  (`docs()`, `doc()`, `search_docs()`, `create_doc()`, `update_doc()`,
  `patch_doc()`, `delete_doc()`), and the agent skill searches them before
  writing SQL; `scripts/curral.sh` gains `docs`, `doc`, `search` and
  `doc-create`/`doc-update`/`doc-patch`/`doc-delete`.

### Fixed
- `scripts/curral.sh schema` split filter values on spaces, so a value such
  as `table=x -x http://host` became curl options (e.g. sending the
  credentials through a proxy). Filters are now always passed as single
  URL-encoded values.

## [v0.4.1] - 2026-10-09

### Changed
- The Go module path is now `github.com/lucasapassos/curral`, so
  `go install -tags duckdb_arrow github.com/lucasapassos/curral/cmd/curral@latest`
  works.
- Dependencies: arrow-go 18.8.0 and golang.org/x/sync 0.24.0.
- The deployment guide and the agent skill under `skills/curral` are now in
  English.
- The Docker Hub page carries an overview of the image, kept in sync from
  `.github/DOCKERHUB.md`.

## [v0.4.0] - 2026-10-09

### Changed
- Licensed under Apache 2.0; release tarballs include the `LICENSE`.
- Documentation rewritten in English: a shorter README and reference pages
  under `docs/`.
- `examples/catalog.yaml` no longer attaches `logs` as `READ_ONLY`, which
  failed on a fresh data directory; the example policy grants no writes
  there anyway.
- `docker-compose.yml` reads the R2 credentials only as `R2_CATALOG_URI`,
  `R2_WAREHOUSE` and `R2_TOKEN`; the older alias names are gone.

## [v0.3.3] - 2026-10-09

### Security
- Fixed: on a bind failure the policy saw the names in the statement, so a
  view over a denied table passed as readable and its errors (unknown
  column, types) mapped that table. Each name is now resolved as
  `SELECT * FROM name` would be, views to their base tables.

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
