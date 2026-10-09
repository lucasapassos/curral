# HTTP API and clients

The endpoints curral exposes, their request and response formats, and the bundled clients.

## Endpoints

| Endpoint | Auth | |
|---|---|---|
| `POST /v1/query` | yes | run a statement (or a dry run) |
| `GET /v1/schema` | yes | tables, views and columns the caller may query |
| `GET /v1/databases` | yes | attached databases |
| `GET /healthz` | no | liveness |

The Prometheus `/metrics` endpoint lives on a separate port; see
[Operations](operations.md).

## `POST /v1/query`

With `Authorization: Basic ...` (or a bearer token, see
[Authentication](authentication.md)):

```json
{"sql": "SELECT * FROM orders WHERE id = $1", "params": [42], "database": "sales", "format": "csv"}
```

- **`format`**: `csv`, `json` (default), `ndjson` or `arrow` (Arrow IPC stream,
  `application/vnd.apache.arrow.stream`). It can also come from `?format=` or the `Accept` header.
- **`database`**: catalog used for unqualified names. The default comes from the catalog's `default` field.
- **`max_rows`**: row limit for this response. It can only **lower** the limit in effect: the smallest of `--max-rows`, the role's `max_rows` in the policy and the request wins. No `LIMIT` is added to the SQL: the server stops reading the result when the limit is reached and signals the cut (`X-Curral-Max-Rows`, trailer `X-Curral-Error: row limit reached`, `error` field in JSON). Queries with `ORDER BY`, aggregation or window functions compute everything before the first row; for cheap samples, put a `LIMIT` in the SQL itself.
- **Blocked catalog functions**: `duckdb_tables()`, `duckdb_views()`, `duckdb_columns()`, `duckdb_schemas()` and similar, the `information_schema.*`, `pg_catalog.*` and `sqlite_master` views, plus `SHOW TABLES` and `PRAGMA show_tables`, respond 403 for every role. They walk every attached catalog, and two of them running at once over an Iceberg catalog crash the process (a DuckDB bug). To list the catalog, use `/v1/schema`.
- **JSON response**: `{"columns":[{"name","type"}],"data":[{...}],"row_count":N}`.
- **Types converted to strings**: DECIMAL, HUGEINT and UUID, so no precision is lost.
- **Error mid-stream**: once the 200 status has been sent, the error goes in the `X-Curral-Error` trailer. In JSON it also appears as an `"error"` field. The `X-Curral-Row-Count` trailer carries the total row count.
- **Errors before the stream**: `{"error": "..."}` with 400 (invalid SQL), 401, 403, 499 (client disconnected), 503 (queue full) or 504 (timeout).
- **No metadata leaks**: DuckDB's hints in errors ("Did you mean...?", "Candidate bindings: ...") can name tables and columns the user cannot read, because the binder runs before the policy. They are therefore stripped from the response but kept in the log and the audit trail. The way to discover names is `/v1/schema`. `DESCRIBE`/`SHOW` of a table goes through the policy as a read of that table.

## `GET /v1/schema`

Lists tables and views with their columns, so clients and AI agents can
discover the structure before writing SQL. Each user sees **only what they
could query**: every object goes through the same inspection, policy and
protections as a `SELECT * FROM object`. A table in `deny_tables` does not
appear.

```sh
curl -u admin https://curral.example.com/v1/schema
curl -u admin 'https://curral.example.com/v1/schema?database=lake&schema=analytics&table=monthly_revenue'
```

```json
{"default_database":"lake",
 "databases":[{"name":"lake","type":"iceberg","schema":"analytics","read_only":false}],
 "tables":[{"database":"lake","schema":"analytics","name":"monthly_revenue","kind":"table",
            "columns":[{"name":"customer","type":"VARCHAR","nullable":true},
                       {"name":"ssn","type":"VARCHAR","nullable":true,"masked":true}],
            "row_filtered":true}]}
```

- **Filters:** `database`, `schema` and `table`, case-insensitive.
- **`masked`:** the column reaches this user masked.
- **`row_filtered`:** the table is read with a row filter (RLS). For a view,
  the flags come from its base tables: the view is flagged when any base table
  is filtered, and columns are flagged when they share a name with a masked
  column.
- **`comment`:** table and column comments (`COMMENT ON`), when present.
- **`schema` in `databases`:** the schema used for unqualified names.
- **Audit:** each call produces a `schema` event listing the tables returned.

### Cache

Loading the schema of a remote catalog is slow: with Iceberg, each table costs
a round trip to the catalog, about 1 s cold on R2. So curral keeps a snapshot
of every object and filters it per user in memory on each call:

- **Performance:** with the cache, the response uses no DuckDB slot. Measured
  against R2 with 4 tables: ~4 s cold, ~0.5 ms cached.
- **Startup:** the snapshot is loaded in the background right at startup.
- **Expiry:** after `--schema-cache-ttl`, the next call still gets the
  previous snapshot while a new one loads in the background.
- **DDL through curral** (`CREATE`, `DROP`, `ALTER`, `COMMENT`) reloads the
  snapshot immediately.
- **External writers:** tables created or changed by other writers of the
  catalog show up within `--schema-cache-ttl`.
- **Policy and RLS:** changes apply immediately, without waiting for the
  cache, because the filtering runs on every call.

## Dry run

`"dry_run": true` on `/v1/query` runs the inspection and evaluates the policy
**without executing**. It is handy for writing and debugging `.rego`:

```sh
curl -u analyst:analyst-pw -d '{"sql":"DELETE FROM orders WHERE id = 1","dry_run":true}' localhost:8080/v1/query
```
```json
{"dry_run":true,"decision":"deny","decided_by":"policy","statement_type":"DELETE",
 "database":"sales","tables":["sales.main.orders"],"targets":["sales.main.orders"],
 "functions":[],"databases":["sales"],"resolved":true,"policy_sha256":"..."}
```

- **Engine denials** (ATTACH, `UPDATE EXTENSIONS`...) show up as `"decided_by":"engine"`.
- **Invalid SQL** still responds 400.
- **Scope:** the dry run evaluates the policy for the authenticated user themselves. It is audited as a `dry_run` event but kept out of the query metrics.

## Command-line client

The `curral` binary doubles as a client:

```sh
export CURRAL_URL=https://curral.example.com CURRAL_TOKEN=curral_...   # or CURRAL_USER/CURRAL_PASSWORD
curral query "SELECT * FROM orders LIMIT 10"                          # CSV on stdout
curral query -f arrow -o orders.arrow "SELECT * FROM orders"
curral query -p 42 "SELECT * FROM orders WHERE id = \$1"
echo "DELETE FROM orders" | curral query --dry-run -f json
```

`curral query` exits with an error code on error responses and when the
result arrives incomplete.

## Python client

A single-file client lives in [`clients/python`](../clients/python/README.md).

See also: [Configuration](configuration.md) · [Authentication](authentication.md) · [Authorization](authorization.md) · [Security](security.md) · [Operations](operations.md)
