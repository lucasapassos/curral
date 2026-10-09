---
name: curral
description: Query data through a curral server (a REST API that runs DuckDB SQL over DuckDB databases and Iceberg catalogs, such as the Cloudflare R2 Data Catalog, with authentication and per-user permissions). Use this skill whenever you read data through curral, for example when CURRAL_URL/CURRAL_TOKEN are set in the environment, when the user mentions curral, the "lake" or tables it serves, or asks for numbers, reports, exports or the structure of the tables that live there, even without naming curral. Covers schema discovery (/v1/schema), writing the SQL, validating with dry_run, row limits and interpreting 400/401/403/429/503/504 errors.
---

# Querying data through curral

curral is an HTTP server in front of DuckDB. You send **one** SQL statement
per request to `POST /v1/query` and get the result back as JSON, CSV,
NDJSON or Arrow. Every request goes through an access policy that decides,
per user:
- which tables they can read;
- which rows they see (row filter);
- which columns arrive masked;
- how many rows and how much time each query may use.

You act as a regular user of this server. The restrictions are
intentional: the goal is to answer well **within** them and to tell the user
what they prevented.

## Connection

Credentials live in the environment, never in the response text or in files:

| Variable | Use |
|---|---|
| `CURRAL_URL` | e.g. `https://curral.example.com` |
| `CURRAL_TOKEN` | API key (`curral_...`) or JWT, sent as `Authorization: Bearer ...` |
| `CURRAL_USER` + `CURRAL_PASSWORD` | Basic auth, used when there is no token |

If the user gives a URL and credentials in the conversation, use them, but do
not repeat them in your answer. In commands, prefer environment variables to
writing the password on the command line.

**With a shell:** use `scripts/curral.sh`, which builds the JSON with correct
escaping, authenticates and warns on stderr when the result is truncated:

```sh
scripts/curral.sh schema                         # everything you can read
scripts/curral.sh schema table=monthly_revenue     # filters: database= schema= table=
scripts/curral.sh query "SELECT count(*) AS n FROM monthly_revenue"
scripts/curral.sh query -f csv -o out.csv "SELECT ..."
scripts/curral.sh query -m 20 "SELECT * FROM monthly_revenue"   # sample: at most 20 rows
scripts/curral.sh query -p 2025-01-01 "SELECT ... WHERE ref_date >= \$1::DATE"
scripts/curral.sh dry-run "SELECT ..."           # decides without executing
```

Pass options before the SQL, and the SQL as a single argument. The exit
codes are:

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | HTTP or network error; details on stderr |
| 2 | incorrect usage |
| 3 | **result truncated** by the row limit (the body is incomplete) |
| 4 | error in the middle of the result |

**Without a shell:** with only an HTTP tool, see `references/api.md`, which
describes requests, responses, headers and errors.

## Workflow

### 1. Discover the structure before writing SQL

Call `GET /v1/schema` once at the start. The response lists **only** the
tables and views you can query, with columns and types. It is served from a
cache and answers in milliseconds, so use it freely. Do not guess table or
column names: a wrong name costs a round trip and a binder error.

What to look for in the response:
- **`default_database`** and the `schema` of each database in `databases`:
  unqualified names (`FROM monthly_revenue`) resolve to that database and
  schema. Tables in other schemas need the full name:
  `database.schema.table`.
- **`"masked": true` on a column:** the value arrives masked for you
  (null, `***`, partial). Filtering, grouping or joining on it does not
  work as expected, because the mask is applied before your query.
- **`"row_filtered": true` on a table:** you see only part of the rows.
  Totals and counts reflect only that subset. Tell the user when you
  report numbers from that table.
- **Missing table:** you have no access. Do not try to reach it another
  way.

**Fallback:** if `/v1/schema` answers 404, the server predates that
endpoint. Run `DESCRIBE table` for the tables you know. If you need a
listing, use
`SELECT table_catalog, table_schema, table_name FROM information_schema.tables`.
In Iceberg catalogs, `information_schema.columns` shows a fake
`__ UNKNOWN` column for tables not loaded yet. Use `DESCRIBE`.

### 2. Write the SQL (DuckDB dialect)

- **One statement per request.** No `;` separating statements, no
  `BEGIN`/`COMMIT`: each request already runs in its own transaction.
- **Read only:** use `SELECT`, CTEs (`WITH`), `DESCRIBE`, `SUMMARIZE` and
  `EXPLAIN`. Do not use `CREATE TEMP TABLE`, `SET` or `PRAGMA`: the policy
  usually denies them (403). For intermediate results, use CTEs.
- **Catalog:** `SHOW TABLES`, `information_schema`, `pg_catalog` and
  `duckdb_tables()`/`duckdb_columns()` are always denied, for every role,
  because they can bring the server down. To discover tables and columns,
  use `/v1/schema`. `DESCRIBE table` works for the tables you can read.
- **External files:** functions such as `read_parquet`, `read_csv` and
  `iceberg_scan` on arbitrary paths are usually blocked. Read through the
  catalog tables.
- **Parameters:** values coming from the user go as `$1`, `$2`... in
  `params`, not concatenated into the SQL. Dates go as a string with a cast:
  `$1::DATE`.
- **Aggregate on the server.** `GROUP BY`, `count`, `sum` and
  `approx_quantile` in DuckDB cost far less than fetching rows to aggregate
  them yourself. To get to know the data, start with `SUMMARIZE table` or
  `SELECT ... LIMIT 20`.
- **Iceberg** (tables of a `type: iceberg` database in `databases`): every
  query calls the remote catalog and reads files from object storage. Filter
  on the date/partition columns (e.g. `ref_date`), select only the columns
  you need and avoid `SELECT *` without `LIMIT` on large tables.

### 3. When unsure about permissions, use `dry_run`

`{"sql": "...", "dry_run": true}` runs the inspection and applies the policy
**without executing**. The response includes:
- `decision` (`allow`/`deny`);
- the tables the statement reads;
- the `limits` that would apply (`max_rows`, `timeout`);
- the `row_filters` and `masked_columns` that would be applied.

Use it before an expensive query or when a 403 does not make the reason
clear. A denial is just `{"error":"forbidden"}`, without saying which table
failed. `dry_run` shows which tables were considered.

### 4. Execute and check that the result is complete

The default format is JSON:
`{"columns":[{"name","type"}],"data":[{...}],"row_count":N}`. DECIMAL,
HUGEINT and UUID arrive as **strings**, so no precision is lost. Convert
them before doing arithmetic. For large results or to save to a file, use
`format: "csv"`.

**Samples:** to see only a few rows, ask for `max_rows` in the request
(`-m N` in the script). It can only lower your account's limit. The script
does not treat a cut you asked for as an error. For cheap samples of large
tables, also put `LIMIT N` in the SQL. Without `LIMIT`, queries with
`ORDER BY` or aggregation compute everything before returning the first row.

**Row limit.** The result can be cut silently in the middle, with status
**200**. The signs are:
- the `X-Curral-Max-Rows` header (the limit in force);
- the `X-Curral-Error: row limit reached` trailer and the
  `X-Curral-Row-Count` trailer;
- in JSON, the field `"error": "row limit reached"` at the end of the body.

A `row_count` equal to the limit is also a sign. If the result was
truncated, you do **not** have all the rows: do not present totals computed
over it as complete. Prefer aggregating in SQL. If the user needs the rows,
split by period or key (e.g. one month per request) or explain that the
account's limit prevents a full export.

An error once the stream is under way drops the connection or comes in the
`X-Curral-Error` trailer. An incomplete response is never a valid result.

### 5. Handle errors by status

| Status | Meaning | What to do |
|---|---|---|
| 400 | invalid SQL (parser/binder) or malformed request; DuckDB's message comes in `error`, without name suggestions ("did you mean") | fix the SQL; check names in `/v1/schema` |
| 401 | missing or wrong credential | do not guess; ask the user for the credential |
| 403 | the policy denied it (table without access, statement not allowed, indirect read of a protected table) | do not work around it; use `dry_run` to understand and explain the restriction to the user |
| 429 | too many of your queries at once, or a lockout after failed logins (`Retry-After`) | run queries one after another; wait `Retry-After` seconds |
| 499 | the client disconnected | — |
| 503 | queue full or audit unavailable (`Retry-After`) | wait and retry, a few times at most |
| 504 | exceeded the timeout (global or your role's) | reduce the work: filter by period, aggregate, select fewer columns |

Every response carries `X-Request-Id`. Include it when reporting an
unexpected error, because it ties the case to the server's audit log.

## Respect the protections

Masks, row filters and denied tables exist for reasons such as personal data
and contracts. Do not try to infer masked values or to work around a denial
by rewriting the query: do not use views, file-reading functions or
cross-references to re-identify people. The server blocks most of these
attempts and records all of them in the audit log. If the task needs data
you cannot see, say so clearly and suggest the right path: ask the curral
owner for access, or answer with aggregated data you can see.

## When answering the user

- Show the SQL you ran when the number matters, so they can check and
  reuse it.
- Say when the result was **truncated**, when the table has a **row
  filter** (totals are partial) and when columns arrived **masked**.
- Convert DECIMAL strings before adding or comparing, and state the units
  and the period considered.
