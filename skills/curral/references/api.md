# curral HTTP API

Reference for agents that only have an HTTP tool. For the workflow, see
`SKILL.md`.

## Contents
- Authentication
- `GET /v1/schema`
- `POST /v1/query`
- Dry run
- Headers and trailers
- Errors
- Other endpoints

## Authentication

Every call (except `/healthz`) needs the `Authorization` header:

| Header | Credential |
|---|---|
| `Authorization: Basic base64(user:password)` | user name and password |
| `Authorization: Bearer curral_...` | service API key |
| `Authorization: Bearer eyJ...` | JWT from an OIDC provider configured on the server |

Repeated login failures lock out the IP and the user for a few minutes.
The response is then 429 with `Retry-After`, even with the right password.

## `GET /v1/schema`

Tables and views that **you** can query, with their columns. Optional query
string: `database`, `schema` and `table` (case-insensitive match).

```
GET /v1/schema?schema=analytics
```

```json
{
  "default_database": "lake",
  "databases": [
    {"name": "lake", "type": "iceberg", "schema": "analytics", "read_only": false}
  ],
  "tables": [
    {
      "database": "lake", "schema": "analytics", "name": "monthly_revenue", "kind": "table",
      "comment": "optional",
      "row_filtered": true,
      "columns": [
        {"name": "region", "type": "VARCHAR", "nullable": true},
        {"name": "revenue", "type": "DOUBLE", "nullable": true, "masked": true}
      ]
    }
  ]
}
```

- **`databases[].schema`:** the schema used for unqualified names in that
  database.
- **`kind`:** `table` or `view`.
- **`masked` and `row_filtered`:** present only when `true`.
- **Freshness:** the listing comes from a cache. A table created by another
  system may take a few minutes to show up.
- **404:** an older server without the endpoint. Use `DESCRIBE` through
  `/v1/query`.

## `POST /v1/query`

JSON body. Unknown fields are rejected with 400.

```json
{
  "sql": "SELECT region, sum(revenue) AS total FROM monthly_revenue WHERE ref_date >= $1::DATE GROUP BY 1 ORDER BY 2 DESC",
  "params": ["2025-01-01"],
  "database": "lake",
  "format": "json",
  "max_rows": 100,
  "dry_run": false
}
```

| Field | | |
|---|---|---|
| `sql` | required | a single statement |
| `params` | optional | scalar values (string, number, bool, null) for `$1`, `$2`... |
| `database` | optional | database used for unqualified names; defaults to `default_database` |
| `format` | optional | `json` (default), `csv`, `ndjson`, `arrow`; also via `?format=` or `Accept` |
| `max_rows` | optional | at most N rows in this response; only lowers the server/role limit, never raises it |
| `dry_run` | optional | `true` = inspect and decide without executing; the response includes the effective `max_rows` |

### Responses by format

**`json`:**

```json
{"columns":[{"name":"region","type":"VARCHAR"},{"name":"total","type":"DOUBLE"}],
 "data":[{"region":"A","total":123.4}],
 "row_count":1}
```

- **Types as strings:** DECIMAL, HUGEINT and UUID come as strings.
- **Error midway:** if the query failed or was cut midway, the object ends
  with `"error": "..."`. When cut by the limit, it is
  `"error": "row limit reached"`.

**`csv`:** header on the first line, then the data. The completion status
comes only in the trailers (below).

**`ndjson`:** one JSON object per line.

**`arrow`:** Arrow IPC stream (`application/vnd.apache.arrow.stream`), for
consumption by code.

## Dry run

```json
{"sql": "SELECT * FROM monthly_revenue", "dry_run": true}
```

```json
{"dry_run":true,"decision":"allow","decided_by":"policy","statement_type":"SELECT",
 "database":"lake","tables":["lake.analytics.monthly_revenue"],"targets":[],"functions":[],
 "databases":["lake"],"resolved":true,
 "limits":{"max_rows":10000,"timeout":"30s","max_concurrency":2},
 "row_filters":["lake.analytics.monthly_revenue"],
 "masked_columns":{"lake.analytics.monthly_revenue":["revenue"]},
 "policy_sha256":"..."}
```

- **`decision`:** `allow` or `deny`.
- **`decided_by`:** who decided. `policy` is the access policy. `engine` is
  a fixed server rule, such as ATTACH, multiple statements or invalid SQL;
  in that case `reason` explains.
- **`resolved: false`:** the server could not determine everything the
  statement reads. The policy usually denies this case.
- **Invalid SQL:** answers 400, like a normal query.

## Headers and trailers

| Name | Where | |
|---|---|---|
| `X-Request-Id` | header, every response | identifies the request in the audit log |
| `X-Curral-Statement-Type` | header | `SELECT`, `EXPLAIN`, ... |
| `X-Curral-Max-Rows` | header | row limit in force for this request |
| `X-Curral-Row-Count` | trailer | rows sent |
| `X-Curral-Error` | trailer | error after the stream started, including `row limit reached` |

Trailers arrive **after** the body. Many HTTP clients do not expose them.
In that case:
- in JSON, use the `error` field;
- in CSV/NDJSON, compare the number of rows with `X-Curral-Max-Rows`.

A connection closed before the end of the body is an incomplete result.

## Errors

Before the stream starts, an error comes as `{"error": "message"}` with the status:

| Status | Cause |
|---|---|
| 400 | invalid body, SQL with a parser/binder/execution error, multiple statements, transaction statement |
| 401 | missing or invalid credential (`WWW-Authenticate` lists the accepted schemes) |
| 403 | the policy denied it, or a filter/mask could not be guaranteed (e.g. indirect read through a view) |
| 429 | the user's concurrent query limit, or a lockout after failed logins; honor `Retry-After` |
| 499 | client disconnected |
| 500 | failed to evaluate the policy |
| 503 | execution queue full or audit unavailable; honor `Retry-After` |
| 504 | query timeout |

## Other endpoints

- `GET /v1/databases`: attached databases (name, type, default schema,
  read-only).
- `GET /healthz`: no authentication; `{"status":"ok"}`.
