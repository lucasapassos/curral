# Authorization

How the Rego policy decides each request, and the controls layered on top of it: per-role limits, per-user fairness, row filters and column masks.

## Policy input

Each statement is prepared (not executed) first, and the policy receives what
DuckDB says it does:

```json
{
  "user": "analyst", "roles": ["analyst"], "sql": "...",
  "statement_type": "SELECT",
  "database": "sales",
  "tables":    ["sales.main.orders"],
  "targets":   [],
  "functions": ["range"],
  "databases": ["sales"],
  "resolved":  true
}
```

- **`tables`**: base tables read, with views expanded. They come from DuckDB's own **unoptimized** logical plan, so JOIN/USING, CTEs, subqueries and views cannot slip through.
- **`targets`**: objects written, created or dropped. DuckDB does not expose these, so they come from a tokenizer.
  - When the target cannot be determined, `resolved` is `false` and the policy should deny.
  - Formats: `secret:<name>` for secrets and `db.schema.*` for schemas.
- **`functions`**: table functions used as sources (`read_parquet`, `range`, ...). They bypass table grants, so the policy must allow them explicitly.
- **`EXPLAIN ANALYZE <stmt>`**: is authorized as `<stmt>`, because it executes the statement.
- **`hidden_remote_scans`**: scans of lake (Iceberg) tables that are not direct references in the query, for example a local view over a lake table. The tables read this way are unknown, so `resolved` is `false`.
- **External catalogs (Iceberg etc.)**: DuckDB's plan does not carry the table name for these scans. For SELECT, the tables come from the parser's AST (`json_serialize_sql`), respecting CTE scope. Any other statement that reads these catalogs (e.g. `INSERT ... SELECT`, `CREATE TABLE AS`) arrives with `resolved=false`.

`examples/policy.rego` provides a model with `admin` (everything), `analyst`
(read per database, with denied tables) and `etl` (DML on writable databases).
The per-role data lives in `examples/roles.json`, passed as a second
`--policy`. The decision rule is `data.curral.allow` by default
(`--policy-query`).

## Per-role limits

With `--policy-limits-query data.curral.limits`, once the policy allows the
request, this rule can return limits for it:

```rego
limits := {"timeout": "30s", "max_rows": 10000} if "analyst" in input.roles
```

- **`timeout`:** a duration string or seconds; applies to execution.
- **`max_rows`:** cuts the response, with the trailer `X-Curral-Error: row limit reached`.
- **Global ceiling:** `--query-timeout` and `--max-rows` still apply, and the most restrictive value always wins.
- **No limits:** an undefined result means no limits.
- **Fail-closed:** if the rule fails (invalid format, conflicting values), the request is denied with 500.
- **Where they show up:** in the dry-run response and in the audit event (`limits`).
- **Ready-made example:** `examples/policy.rego` reads limits from `data.roles[role].limits`. In the example, the analyst gets 30 s, 10 thousand rows and 2 concurrent queries.

## Fairness between users

`--max-concurrency` is the instance-wide total of concurrent queries. To keep
one user from taking every slot, there are two ways to set a per-user quota:

- **In the policy**, with `max_concurrency` in the limits rule.
- **As a default**, with `--max-concurrency-per-user`, which applies when the
  policy sets nothing.

```rego
limits := {"max_concurrency": 2} if "analyst" in input.roles                   # per user
limits := {"max_concurrency": 4, "concurrency_group": "role:etl"} if "etl" in input.roles  # role-wide quota
```

- **The quota is per user by default.** With `concurrency_group`, every user
  in the group shares the same quota.
- **Over the quota you get 429 immediately** (`Retry-After: 1`) instead of
  waiting in the queue. Waiting would hold a global slot and a transaction,
  which is exactly what this is meant to avoid.
- **Tracking:** the refusal is audited (`decided_by: concurrency`) and counted
  in `curral_queries_throttled_total`.
- **Dry run:** shows the quota but does not consume it.

Measured with `--max-concurrency 4`, one user firing 12 heavy queries and
another running a simple query:

| | regular user | abusive user |
|---|---|---|
| no quota | waited 5 s and got **503** | 8 ran, 4 got 503 |
| `--max-concurrency-per-user 2` | **200 in 2 ms** | 2 ran, 10 got 429 |

## Data protection: row filters (RLS) and column masking

Beyond allowing or denying tables, curral can restrict **which rows** a user
sees and **mask sensitive columns**.

### Row filters

`--row-filters rls.yaml`, reloaded on `SIGHUP`:

```yaml
tables:
  lake.analytics.customers:         # catalog.schema.table
    rules:
      - roles: [analyst_north]
        where: "region = 'north'"
      - users: ["ana@example.com", "*@corp.example.com"]
        where: "region IN (SELECT region FROM ctl.main.acl WHERE usr = getvariable('curral_user'))"
```

- **Rule scope:** rules apply only to whoever matches them, by role or by user
  (exact or `*@domain`). Several rules for the same user are combined with `OR`.
- **Users who match no rule** are not filtered. Whether they may read the
  table at all is up to the policy.
- **User context:** `getvariable('curral_user')` and
  `getvariable('curral_roles')` let you use an ACL table, so access changes by
  editing data, not configuration.
- **Validation:** each `where` is validated against the real table at startup,
  in `check` and on reload. An error aborts startup; on reload, the previous
  file is kept.

See `examples/rls.yaml`.

### Column masking

Through the policy (`--policy-masks-query data.curral.masks`):

```rego
masks := {"lake.analytics.customers": {"ssn": "last:2", "name": "redact", "birth_date": "null"}} if {
	not "pii_reader" in input.roles
}
```

- **Presets:** `null` (keeps the column type), `redact` (`'***'`) and
  `last:N`. For special cases, `{"sql": "<expression>"}`.

### How it is applied

Each reference to the table in the user's query becomes, in DuckDB's own
syntax tree, a subquery that **first** filters the rows and masks the columns.
The original query runs on top of that subquery, which has three consequences:

- **No oracle:** `WHERE ssn = '...'`, joins and groupings operate on the masked
  values, so the real value cannot be found by elimination.
- **SELECT only:** a non-SELECT that reads a protected table (`INSERT ...
  SELECT`, `CREATE TABLE AS`) gets 403.
- **Fail-closed:** the query is also denied, with `decided_by: protection` in
  the audit log, when:
  - the table is read **indirectly**, through a view or macro (the number of
    scans in the plan does not match the references in the query). This
    includes a local view over a lake table: the Iceberg plan does not say
    which table was read. In that case the inspection is `resolved: false`,
    with `hidden_remote_scans > 0`, and anyone with a filter or mask on any
    lake table is denied even under a policy that accepts unresolved queries;
  - the query does not survive the SQL → tree → SQL round trip intact;
  - the table uses `TABLESAMPLE` or time travel (`AT`);
  - the query is a `PIVOT`.

**Tracking:** the dry run and the audit log show `row_filters` and
`masked_columns`, and rewritten queries count in
`curral_queries_rewritten_total`.

**Verification:** a differential test compares each protected query with the
same query over a copy of the table that is already filtered and masked; the
results must be identical. It runs in CI, and the `FuzzProtectDifferential`
fuzzer runs weekly.

**Cost:** each query's rewrite is cached, keyed by query text and applied
rules. The indirect-read check still runs on every request, against that
request's plan. Session variables are only set when some rule uses
`getvariable()` or a user macro. Measured over HTTP:

| Point lookup | no protection | RLS | mask | RLS + mask |
|---|---|---|---|---|
| local, p50 with 1 client | 1.3 ms | 1.7 ms | 1.7 ms | 1.8 ms |
| local, throughput with 8 clients | 2,524 req/s | 2,098 | 1,879 | 1,992 |
| Iceberg on R2, p50 with 1 client | 7.2 ms | 8.6 ms | 9.7 ms | 8.7 ms |

On aggregations over the whole table the difference disappears into the
query's own time. With RLS, a query can even get faster, because the filter
reduces the data read. Queries with no protected table are unchanged.

See also: [Configuration](configuration.md) · [API](api.md) · [Authentication](authentication.md) · [Security](security.md) · [Operations](operations.md)
