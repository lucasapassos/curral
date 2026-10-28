---
name: curral
description: Query data through a curral server (a REST API that runs DuckDB SQL over DuckDB databases and Iceberg catalogs, such as the Cloudflare R2 Data Catalog, with authentication and per-user permissions). Use this skill whenever you read or change data through curral, for example when CURRAL_URL/CURRAL_TOKEN are set in the environment or ~/.config/curral/credentials exists, when the user gives you the URL of a curral server, mentions curral, the "lake" or tables it serves, or asks for numbers, reports, exports or the structure of the tables that live there, even without naming curral. Covers checking the connection and asking the user to set it up without exposing the password, schema discovery (/v1/schema), semantic documents with notes and sample SQL (/v1/docs), writing the SQL, validating with dry_run, row limits and interpreting 400/401/403/429/503/504 errors.
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

## Getting the skill from the server

Every curral server hands out this skill's documentation itself, so an
agent with nothing but the URL can get going: `GET /` lists the endpoints
and where everything is, and `GET /skill/SKILL.md` is this file. The
scripts are code, so by default the server does **not** serve them: it
points at the repository, pinned to its own version, and `GET /` carries
the exact install command, which looks like:

```sh
curl -fsSL https://raw.githubusercontent.com/lucasapassos/curral/v0.8.0/skills/curral/scripts/install.sh -o install.sh
CURRAL_SKILL_REF=v0.8.0 sh install.sh ./curral
```

That downloads `SKILL.md`, `references/api.md` and `scripts/` into
`./curral`; then go on with `./curral/scripts/curral.sh status` below. A
server run with `--serve-skill all` (networks without access to GitHub)
serves the scripts too, at `/skill/scripts/...`, over TLS or to the local
machine only; its `GET /` says so. Run only scripts you got from the
repository or from a server you reached over TLS: a script replaced on the
way could read the credentials file. A skill already installed in your
agent's skills directory works just as well.

## Connection

**Secrets never go through you.** Do not ask for a password or token in the
chat, and never write one in a command (`export CURRAL_PASSWORD=...`,
`curl -u ...`), a file you create or your answer: every command you run is
shown on screen and kept in the conversation log. The script reads the
connection itself:

| Source | Content |
|---|---|
| environment | `CURRAL_URL`; `CURRAL_TOKEN` (API key `curral_...` or JWT, sent as Bearer) or `CURRAL_USER` + `CURRAL_PASSWORD` (Basic) |
| `~/.config/curral/credentials` (or `$CURRAL_CONFIG`) | the same variables as `KEY=value` lines, written by `curral.sh login` (mode 600) |
| `%APPDATA%\curral\credentials` (or `$env:CURRAL_CONFIG`), Windows | written by `curral.ps1 login`; the secret is encrypted with DPAPI, readable only by that Windows user |

Credentials in the environment take precedence over the file. Two more
settings, in either place: `CURRAL_CA=/path/ca.pem` for a server whose
certificate the system does not trust (private CA), and `CURRAL_CONFIG` to
pick the file, which is how you work with **several servers**: one
credentials file each, `CURRAL_CONFIG=~/.config/curral/prod` for one
command and `.../staging` for another. The user runs `login` once per file
(`CURRAL_CONFIG=... curral.sh login`).

**Which script:** `scripts/curral.sh` where there is `sh` (Linux, macOS,
Git Bash, WSL). In PowerShell on Windows, use `scripts\curral.ps1` with the
same commands, output and exit codes, run as:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\curral.ps1 query -m 20 'SELECT * FROM monthly_revenue WHERE region = ''South'''
```

There, quote the SQL with single quotes (doubling the quotes inside), so
PowerShell does not expand `$1`. The `curral.sh` examples below apply to
both.

**Start every session with** `scripts/curral.sh status`. It prints the URL
and the user (never the secret) on stderr and the databases on stdout. The
user you run as decides everything that follows (tables, rows, masks,
limits), so say which one it is when it matters.
- **Exit 0:** connected; go on.
- **Exit 5 (no connection configured) or 1 with HTTP 401:** stop and ask the
  user to configure it. Give them the absolute path that the script
  printed and ask them to run it **in their own terminal**, outside the
  chat:

  ```sh
  /path/to/skills/curral/scripts/curral.sh login
  ```

  On Windows, the script prints the `powershell ... curral.ps1 login`
  line instead. It asks for the URL, the user (empty for an API key) and
  the password without echoing it, saves the file readable only by the
  user and checks the connection. Wait for the user to confirm, then run
  `status` again. Do not run `login` yourself: it needs a terminal and
  fails without one.
- **If the user pastes a password or token in the chat anyway:** do not use
  it and do not repeat it. Tell them it is now in the conversation log, that
  they should change it, and ask them to run `login` with the new one.

**With a shell:** use `scripts/curral.sh`, which builds the JSON with correct
escaping, authenticates and warns on stderr when the result is truncated:

```sh
scripts/curral.sh status                         # connection check; first command of the session
scripts/curral.sh capabilities                   # the account as the server sees it, server version, formats
scripts/curral.sh schema                         # everything you can read
scripts/curral.sh schema table=monthly_revenue     # filters: database= schema= table=
scripts/curral.sh query "SELECT count(*) AS n FROM monthly_revenue"
scripts/curral.sh query -f csv -o out.csv "SELECT ..."   # also -f ndjson, -f arrow (with -o)
scripts/curral.sh query -m 20 "SELECT * FROM monthly_revenue"   # sample: at most 20 rows
scripts/curral.sh query -p 2025-01-01 "SELECT ... WHERE ref_date >= \$1::DATE"
scripts/curral.sh dry-run "SELECT ..."           # decides without executing
scripts/curral.sh search "revenue per customer last month"   # semantic documents that fit the question, best first
scripts/curral.sh search table=monthly_revenue limit=3 "..."   # options before the question: table= schema= limit= fields=header
scripts/curral.sh docs table=monthly_revenue     # list semantic documents; filters: table= schema= q= fields=header
scripts/curral.sh doc ID                         # one document (its ETag on stderr)
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
| 5 | no connection configured; ask the user to run `login` (see above) |

**Without a shell:** with only an HTTP tool, see `references/api.md`, which
describes requests, responses, headers and errors. You cannot read the
credentials file there, so the secret would have to come through the chat
and sit in the `Authorization` header of every call: tell the user, and
suggest an API key with narrow permissions or an agent with a shell.

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
- **`comment` on a table or column:** documentation left by whoever owns
  the data (`COMMENT ON`), such as units, grain ("one row per order") or
  what a code means. Read it before guessing from names, and quote it when
  it settles a question.
- **`"masked": true` on a column:** the value arrives masked for you
  (null, `***`, partial). Filtering, grouping or joining on it does not
  work as expected, because the mask is applied before your query.
- **`"row_filtered": true` on a table:** you see only part of the rows.
  Totals and counts reflect only that subset. Tell the user when you
  report numbers from that table.
- **Missing table:** you have no access, or it does not exist; the
  listing (and `schema table=name`, which then returns `"tables": []`)
  does not tell which. `dry-run "SELECT 1 FROM name"` does: `deny` with
  `resolved: true` and the table in `tables` means it exists and you may
  not read it; a 400 means no such table. Do not try to reach a denied
  table another way.

`DESCRIBE table` (and `SHOW table`) through `/v1/query` gives the same
columns, also for tables with row filters or masks; `SUMMARIZE table`
reads the data (as you see it: filtered and masked). `information_schema`,
`SHOW TABLES` and the `duckdb_*()` functions are refused for everyone
(see step 2): `/v1/schema` is the listing.

### 1b. Read the semantic documents for those tables

If the server keeps semantic documents (`GET /v1/docs` answers 200; 404
means the feature is off, and the script says so: go on with the schema
alone), search them with the user's question before writing SQL: `POST /v1/docs/search` with `{"q": "<the question>"}` (add
`"table"` or `"schema"` when you already know them). Results come best
first, whole. With `"ranker": "jev"`, check each result's `judged` flag:
`true` means Jev evaluated it; `false` means evaluation failed or timed out
and the result uses BM25. `"below_threshold": true` means no evaluated
document reached the relevance threshold, so treat evaluated results as
weak matches. For every `"judged": false` result, including all results
with `"ranker": "bm25"`, the score reflects shared words only: check that
the document is really about your question before using it to write SQL.
To browse instead, `GET
/v1/docs?table=monthly_revenue&fields=header`, then `GET /v1/docs/{id}`.

Each document has `header` (title, description, `used_for`: the questions
it helps answer) and `context` (`tables`, `schemas`, a free-text `body`
and `sqls`: sample queries with a description). They are written by people
who know the data: the meaning of columns, units, caveats, the right joins
and filters. Prefer what they say over guesses from column names, and start
from their `sqls` when one fits the question (adapting it, and still going
through `dry_run` when unsure). If a document contradicts `/v1/schema`, the
schema wins: the document may be outdated; mention it to the user.

### 2. Write the SQL (DuckDB dialect)

- **One statement per request.** No `;` separating statements, no
  `BEGIN`/`COMMIT`: each request already runs in its own transaction.
- **Reading:** use `SELECT`, CTEs (`WITH`), `DESCRIBE` and `SUMMARIZE`.
  Do not use `CREATE TEMP TABLE`, `SET` or `PRAGMA`: the policy usually
  denies them (403). For intermediate results, use CTEs. `EXPLAIN` is
  refused on tables with row filters or masks (the plan would show the
  filter); `dry_run` answers the questions `EXPLAIN` would.
- **Writing** (`INSERT`, `UPDATE`, `DELETE`, `CREATE`, `COMMENT ON`...):
  the policy decides, per account, what you may change; most agent
  accounts are read-only and get 403. When the user asks for a change and
  the account allows it, run `dry_run` first and show it, then one
  statement per request. There are no multi-statement transactions, so a
  change in several steps is not atomic: order the steps so a failure
  halfway leaves something consistent, and check the result afterwards.
  Never write to work around a read restriction (no copying a protected
  table into another).
- **Catalog:** `SHOW TABLES`, `information_schema`, `pg_catalog` and
  `duckdb_tables()`/`duckdb_columns()` are always denied, for every role,
  because they can bring the server down. To discover tables and columns,
  use `/v1/schema`. `DESCRIBE table` works for the tables you can read.
- **External files:** functions such as `read_parquet`, `read_csv` and
  `iceberg_scan` on arbitrary paths are usually blocked. Read through the
  catalog tables.
- **Parameters:** values coming from the user go as `$1`, `$2`... in
  `params`, not concatenated into the SQL. Dates go as a string with a cast:
  `$1::DATE`. With the script, one `-p` per value, in order:
  `query -p 2025-01-01 -p 2025-02-01 "... WHERE d >= \$1::DATE AND d < \$2::DATE"`.
- **Reserved words as names:** `/v1/schema` returns column names bare, but
  DuckDB needs double quotes around those that are keywords (`"at"`,
  `"end"`, `"order"`, `"table"`...). A 400 "syntax error at or near" on a
  name you copied from the schema is this.
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
- on `allow`, the `limits` of your role (`max_rows`, `timeout`,
  `max_concurrency`) and, at the top level, **`max_rows`: the effective row
  limit** for this request, the smallest of the server's, your role's and
  the one you asked for. Plan exports on this one, not on
  `limits.max_rows`;
- on `allow`, the `row_filters` and `masked_columns` that would be applied.
  An allowed query over a masked column runs fine and returns masked
  values, so `sum(amount)` of a masked `amount` is null with status 200:
  check `count(col)` against `count(*)` before trusting an aggregate.

Use it before an expensive query, before any write, and when a 403 does
not make the reason clear. A policy denial is just `{"error":"forbidden"}`,
without saying which table failed; `dry_run` shows which tables were
considered. `decided_by` says who refused: `policy` (the access rules),
`engine` (a fixed server rule, with `reason`) or `protection` (the row
filters or masks cannot be applied to this statement, e.g. a protected
table read through a view: query the table directly).

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
split them: first `count(*)` and `min`/`max` of a key (or the periods), then
one request per range with `-p` bounds, each range **smaller than**
`max_rows` so a full chunk is never mistaken for a cut one, and check the
assembled total against the count. Or explain that the account's limit
prevents a full export.

An error once the stream is under way drops the connection or comes in the
`X-Curral-Error` trailer. An incomplete response is never a valid result.

### 5. Handle errors by status

| Status | Meaning | What to do |
|---|---|---|
| 400 | invalid SQL (parser/binder) or malformed request; DuckDB's message comes in `error`, without name suggestions ("did you mean") | fix the SQL; check names in `/v1/schema` |
| 401 | missing or wrong credential | do not guess and do not ask for the secret in the chat; ask the user to run `curral.sh login` again in their terminal |
| 403 | the policy denied it (table without access, statement not allowed, indirect read of a protected table) | do not work around it; use `dry_run` to understand and explain the restriction to the user |
| 429 | too many of your queries at once, or a lockout after failed logins (`Retry-After`) | run queries one after another; wait `Retry-After` seconds |
| 499 | the client disconnected | — |
| 503 | queue full or audit unavailable (`Retry-After`) | wait and retry, a few times at most |
| 504 | exceeded the timeout (global or your role's) | reduce the work: filter by period, aggregate, select fewer columns |

Every response carries `X-Request-Id`; the script prints it on stderr as
`HTTP <status> (request <id>)`. Include it when reporting an unexpected
error, because it ties the case to the server's audit log.

## Writing semantic documents

Semantic documents are how knowledge about the data survives the
conversation: the next agent (or person) reads them before writing SQL, so
every join, unit or caveat you had to work out is worth a few lines there.
When you have just learned something non-obvious (a wrong-looking total
explained by a row filter, the right join key, a code's meaning confirmed
by the user), offer to record it; write only when the user agrees, and
only if the policy lets their account write (writes by others get 403; the
example policy grants the `poet` role). A document looks like:

```json
{"header": {"title": "Monthly revenue", "description": "...", "used_for": ["finance reports"]},
 "context": {"tables": ["lake.analytics.monthly_revenue"], "body": "what the columns mean, caveats...",
             "sqls": [{"sql": "SELECT ...", "description": "revenue per customer"}]}}
```

`title` and `body` are required; the server fills `id`, `author` and the
timestamps. With the script, the JSON comes from a file or stdin (`-`):

```sh
scripts/curral.sh doc-create doc.json
scripts/curral.sh doc-patch -e '"<etag>"' ID patch.json    # merge patch: only the fields to change; null removes
scripts/curral.sh doc-update -e '"<etag>"' ID doc.json     # replaces the whole content
scripts/curral.sh doc-delete -e '"<etag>"' ID
```

Pass the ETag from your last read with `-e` (`If-Match`): a 412 means
someone changed the document in the meantime, so read it again and redo
your change on top. Some care, because documents outlive the conversation:
- **Every authenticated user reads every document**, whatever tables they
  may query. So write nothing you would not show to all of them: no values
  you saw (masked or not), no personal data, and no description of other
  roles' row filters or masks beyond "analysts see a subset". A document's
  existence never implies access to its tables, for you or for readers.
- **Only verified facts.** Put in sample SQL that you ran successfully and
  descriptions you checked against `/v1/schema` or the data. If you cannot
  read the table, say so instead of writing a document from guesses.
- **One document per subject.** Check `docs table=...` first and update the
  existing document rather than creating a near duplicate. If you find
  duplicates, tell the user; merge them only when they ask.

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
  reuse it, and name the semantic document or table comment you relied on.
- Say when the result was **truncated**, when the table has a **row
  filter** (totals are partial) and when columns arrived **masked**.
- Convert DECIMAL strings before adding or comparing, and state the units
  and the period considered.
