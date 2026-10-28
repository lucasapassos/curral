# HTTP API and clients

The endpoints curral exposes, their request and response formats, and the bundled clients.

## Endpoints

| Endpoint | Auth | |
|---|---|---|
| `GET /v1/capabilities` | yes | the credential and its [delegation](delegation.md) contract |
| `POST /v1/query` | yes | run a statement (or a dry run) |
| `GET /v1/schema` | yes | tables, views and columns the caller may query |
| `GET /v1/databases` | yes | attached databases |
| `GET /v1/docs`, `GET /v1/docs/{id}` | yes | semantic documents (with `--docs-dir`) |
| `POST /v1/docs`, `PUT`/`PATCH`/`DELETE /v1/docs/{id}` | yes | write semantic documents, as the policy allows |
| `GET /healthz` | no | liveness |

The Prometheus `/metrics` endpoint lives on a separate port; see
[Operations](operations.md). With `--flight-listen`, the same data is also
served over [Arrow Flight SQL](#flight-sql-dbeaver-datagrip-jdbc-adbc), for
database IDEs and JDBC/ADBC clients.

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
            "row_filtered":true,"docs":2}]}
```

- **Filters:** `database`, `schema` and `table`, case-insensitive.
- **`masked`:** the column reaches this user masked.
- **`row_filtered`:** the table is read with a row filter (RLS). For a view,
  the flags come from its base tables: the view is flagged when any base table
  is filtered, and columns are flagged when they share a name with a masked
  column.
- **`comment`:** table and column comments (`COMMENT ON`), when present.
- **`docs`:** with `--docs-dir`, how many [semantic documents](#semantic-documents-v1docs)
  are about the table (naming it exactly or by its last parts, as the
  document filters match); omitted when none. With `--docs-scope schema`
  only the documents the caller may read count, so a count never reveals a
  document the listing would hide. Clients can skip `GET /v1/docs` for
  tables without a count.
- **`schema` in `databases`:** the schema used for unqualified names.
- **Audit:** each call produces a `schema` event listing the tables returned
  (and, when counting documents under `--docs-scope schema`, a `docs_scope`
  event for the caller's scope).

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

## Semantic documents: `/v1/docs`

With `--docs-dir`, curral keeps **semantic documents**: notes on what schemas
and tables mean and which SQL answers which question, for AI agents (and
people) to read before writing queries. Each one is a JSON file,
`<docs-dir>/<id>.json`.

```json
{"id": "019a2f1c3a4b9f2e18c4d7a6b05",
 "header": {"author": "poet", "created_at": "2026-10-10T12:00:00Z",
            "updated_at": "2026-10-10T12:30:00Z", "updated_by": "admin",
            "title": "Monthly revenue",
            "description": "Gross revenue per customer and month",
            "used_for": ["finance reports", "churn analysis"]},
 "context": {"schemas": ["lake.analytics"],
             "tables": ["lake.analytics.monthly_revenue"],
             "body": "Free text, as long as needed: meaning of columns, caveats, joins...",
             "sqls": [{"sql": "SELECT customer, sum(revenue) FROM lake.analytics.monthly_revenue GROUP BY 1",
                       "description": "revenue per customer"}]}}
```

- **Required:** `header.title` (up to 200 characters) and `context.body`; each
  `sqls[]` item needs `sql`. Everything else is optional. `tables` and
  `schemas` are free text, not checked against the catalog unless
  `--docs-validate-names` says so (below).
- **Server-set:** `id`, `author` (who created it), `created_at`, `updated_at`
  and `updated_by` (who changed it last). Values sent for them are ignored, so
  a document from a `GET` can be sent back as is. Unknown fields are a 400.
- **Reading:** every authenticated user. `GET /v1/docs` lists full documents,
  most recently updated first; `?table=`, `?schema=` (exact name or its last
  parts, so `orders` finds `sales.main.orders`) and `?q=` (text in title,
  description or `used_for`) narrow it, all case-insensitive. `?tables=`
  and `?schemas=` take several names (repeated or comma-separated, up to
  100 each) and keep a document about any of them; `table` with `tables`,
  or `schema` with `schemas`, is a 400. `?fields=header` leaves out `body`
  and `sqls`.
- **Access:** each document listed or searched carries `accessible_tables`
  and `inaccessible_tables`: the entries of its `tables` the caller may
  query and the rest (a name counts as accessible when every object it
  fits is readable; one fitting nothing in the catalog is not). A document
  naming no table has two empty lists. The split uses the caller's
  `/v1/schema` listing, made once per request in both scopes and audited
  as a `docs_scope` event, so listing and search are refused (503, 429 or
  500) when that listing is; `GET /v1/docs/{id}` under `--docs-scope all`
  needs none.
- **Scope:** with `--docs-scope schema`, a document that names `tables` is
  served (listed, fetched, searched) only to a caller who may query at least
  one of them; one that names only `schemas`, to a caller who may query a
  table in one of them. Names match as in the filters (a qualified name
  exactly, a shorter one by its last parts); a short name that fits several
  objects counts only when the caller may query all of them, and one that
  fits nothing in the catalog never counts. The decision is the one of
  `/v1/schema`, audited as a `docs_scope` event. An out-of-scope id answers
  404 on `GET`, `PUT`, `PATCH` and `DELETE` alike, so a write never reads
  the document back. Documents naming no table or schema reach everyone.
  The default, `all`, serves every document to every authenticated user.
  `GET /v1/capabilities` reports the mode in `docs.scope`.
- **Searching:** `POST /v1/docs/search` returns the documents that best fit a
  question; see [below](#searching-documents).
- **Writing:** `POST /v1/docs` creates (201, `Location` and `ETag`), `PUT
  /v1/docs/{id}` replaces the content, `PATCH /v1/docs/{id}` applies a [JSON
  merge patch](https://www.rfc-editor.org/rfc/rfc7396) (`null` removes a
  field) and `DELETE /v1/docs/{id}` removes it (204). Who may write is decided
  by the policy; see [Authorization](authorization.md#semantic-documents).
  A delegating key writes only when marked `docs_write`, and then as the
  identity it names; see [delegation](delegation.md#semantic-documents).
- **Names:** with `--docs-validate-names strict`, a write resolves each
  entry of `context.tables` and `context.schemas` to one catalog object
  (by its qualified name, or by its last parts when only one object fits)
  and saves the qualified name, so scopes, filters and clients match it
  exactly; a name fitting nothing or several objects is a 400 naming it.
  `warn` qualifies what resolves and keeps the rest as written, logging it;
  `off`, the default, saves names as written. The policy sees the resolved
  names. The catalog is read whole for this, not through the writer's
  policy: a writer learns whether a name exists, never what the object
  holds. While the catalog cannot be read the write is refused (503,
  `Retry-After`).
- **Concurrent edits:** `GET` returns an `ETag`; send it back in `If-Match` on
  `PUT`, `PATCH` or `DELETE` and the write fails with 412 if someone else
  changed the document in between.
- **Size:** request bodies are capped by `--max-body`.
- **Audit:** writes produce `doc_create`, `doc_update` and `doc_delete` events
  with the document id in `doc`; like queries, they are refused (503) while
  the audit log is unavailable.
- **Files:** written atomically and pretty-printed, so they can be versioned or
  edited by hand; `SIGHUP` reloads the directory.

```sh
curl -u poet:poet-pw -H 'Content-Type: application/json' -d @doc.json localhost:8080/v1/docs
curl -u analyst:analyst-pw 'localhost:8080/v1/docs?table=orders&fields=header'
curl -u poet:poet-pw -X PATCH -H 'If-Match: "<etag>"' \
  -d '{"header":{"used_for":["finance reports"]}}' localhost:8080/v1/docs/<id>
```

### Searching documents

`POST /v1/docs/search` takes a question in plain words and returns the
documents most likely to help answer it, best first. Any authenticated user
may search.

```sh
curl -u analyst:analyst-pw -d '{"q":"monthly revenue per customer","limit":3}' localhost:8080/v1/docs/search
```
```json
{"ranker": "jev",
 "results": [{"score": 0.93, "judged": true,
              "doc": {"id": "...", "header": {...}, "context": {...},
                      "accessible_tables": ["lake.analytics.monthly_revenue"], "inaccessible_tables": []}}]}
```

- **Request:** `q` (required), optional `table` and `schema` filters (as in
  the listing) or their list forms `tables` and `schemas` (any of up to 100
  names; not together with the single form), `limit` (default 5, at most
  50) and `fields` (`full`, the default, or `header`). The filters apply
  before ranking, so documents outside them take no place in the Jev
  shortlist or the limit. Each `doc` carries `accessible_tables` and
  `inaccessible_tables`, as in the listing.
- **Ranking:** words are matched without case or accents, identifiers split
  on `_` and `.`, and a plural `s` is ignored. Matches in the title count
  most, then `used_for`, `tables`/`schemas`, the description, and the body and
  SQL ([BM25](https://en.wikipedia.org/wiki/Okapi_BM25)). Documents with
  no word of the question are left out.
- **With Jev** (`--jev-key`): the best BM25 candidates (`--search-shortlist`,
  at least `limit`) are each sent to [TypeSafe](https://typesafe.ai)'s Jev
  model, which judges whether the document is needed to write the SQL. Only
  documents at or above `--jev-threshold` (0.7) are returned, ranked by that
  probability (`score`, with `"judged": true`). If none reaches it, the best
  judged ones at or above `--jev-floor` (0.2) come back with
  `"below_threshold": true`; treat them as weak matches. Below the floor
  they are left out, so a question no document fits gets an empty list. A
  document Jev could not rate in time keeps its BM25 place after
  the judged ones, with `"judged": false`.
- **Without Jev:** `"ranker": "bm25"` and `score` is the BM25 score, useful only
  for ordering.

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

## Flight SQL (DBeaver, DataGrip, JDBC, ADBC)

`--flight-listen` (or `CURRAL_FLIGHT_LISTEN`) serves
[Arrow Flight SQL](https://arrow.apache.org/docs/format/FlightSql.html) over
gRPC on a second port, for clients that speak a database protocol rather
than HTTP: DBeaver and DataGrip through the Arrow Flight SQL JDBC driver,
ADBC (Python, Go, R), and BI tools with a Flight SQL driver. Without the
flag nothing listens; it needs a build with `-tags duckdb_arrow`, as are
the release binaries and the Docker image.

```sh
curral serve ... --flight-listen :31337
```

Every call goes through the same pipeline as `/v1/query`: users, API keys
and JWTs, lockouts, the policy, row filters and masks, limits, the audit
log and the metrics. The TLS certificate (`--tls-cert`) also covers the
Flight port.

- **Logging in:** with user and password, the client's handshake gets a
  session token for its later calls (12 h, signed with a key that lives in
  memory: a restart, a password change or the user's removal ends it). API
  keys and JWTs go as a bearer token on every call (JDBC: `token=`).
- **Listing:** catalogs are the attached databases. Schemas, tables and
  columns come from the same listing as `GET /v1/schema`: only what the
  user could query, audited as `schema` events. Primary and foreign keys and
  type information come back empty.
- **Database for unqualified names:** a `database` header (JDBC: a
  `database=` URL property; ADBC: the `adbc.flight.sql.rpc.call_header.database`
  option) or the `catalog` session option, which JDBC's `setCatalog` (picking
  a database in the IDE) sends. Otherwise the catalog's `default`.
- **Prepared statements:** preparing inspects and authorizes the statement
  without running it (a `prepare` audit event, kept out of the query
  metrics), so a refused statement fails right away, and returns its
  parameter and result types. Running it is authorized again (a `query`
  event). Each statement read through a prepared statement, as JDBC does for
  all of them, is thus inspected twice; with lake catalogs, set `cache_ttl`.
  `DECIMAL` parameters are sent as text.
- **No transactions:** each statement runs in its own transaction, as over
  HTTP; clients see autocommit.
- **Row limit:** a cut result ends cleanly with the trailer
  `x-curral-error: row limit reached`.

### JDBC: DBeaver and DataGrip

Download `flight-sql-jdbc-driver-<version>.jar` from
[Maven Central](https://repo1.maven.org/maven2/org/apache/arrow/flight-sql-jdbc-driver/)
and add it as a custom driver:

- **Class:** `org.apache.arrow.driver.jdbc.ArrowFlightJdbcDriver`
- **URL:** `jdbc:arrow-flight-sql://curral.example.com:31337`, with
  `?useEncryption=false` when the port has no TLS. Add `&database=logs` to
  pick the database for unqualified names.
- **Credentials:** the curral user and password, or `token=curral_...` as a
  driver property for an API key.
- **Java options:** `--add-opens=java.base/java.nio=ALL-UNNAMED`, plus
  `--sun-misc-unsafe-memory-access=allow` on Java 24 and later (only there:
  older JVMs refuse to start with it). Without them the driver fails to
  start with `ExceptionInInitializerError`.

**DataGrip:** *Database Explorer → ⚙ Drivers → +*. Under *Driver Files*, add
the jar with *+ → Custom JARs…* (the file, not its folder); then pick the
class above from the *Class* list. A class left at `java.sql.Driver` fails
with `java.sql.Driver.<init>()`. In the data source, put the URL and the
credentials, and the Java options in *Advanced → VM options*: DataGrip runs
each driver in its own JVM, and its bundled runtime is Java 25, so both
options are needed.

**DBeaver:** *Database → Driver Manager → New*: add the jar under
*Libraries*, the class under *Class Name* and
`jdbc:arrow-flight-sql://{host}:{port}` as *URL Template*; set
`useEncryption=false` in the connection's *Driver properties* when the port
has no TLS. The Java options go after `-vmargs` in `dbeaver.ini`.

**Why the Java options:** the driver keeps results in off-heap Arrow
buffers, allocated through the netty it bundles. That needs the address
fields of `java.nio` buffers, closed to other modules since Java 16
(`--add-opens`), and `sun.misc.Unsafe` memory access, which Java 24
restricts (`--sun-misc-unsafe-memory-access=allow`). Any Flight SQL server
needs them with this driver; curral does not.

The IDE's SQL dialect is generic: write DuckDB SQL. Catalog views
(`information_schema`, `duckdb_tables()`...) stay blocked; the IDE's
database tree uses the Flight SQL listing instead.

### ADBC (Python)

```python
import adbc_driver_flightsql.dbapi as flightsql

conn = flightsql.connect("grpc://localhost:31337",
                         db_kwargs={"username": "analyst", "password": "analyst-pw"})
cur = conn.cursor()
cur.execute("SELECT * FROM orders WHERE id = ?", (3,))
table = cur.fetch_arrow_table()
```

Use `grpc+tls://` when the port has TLS.

See also: [Configuration](configuration.md) · [Authentication](authentication.md) · [Authorization](authorization.md) · [Security](security.md) · [Operations](operations.md)
