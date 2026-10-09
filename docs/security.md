# Security model

The protections that hold regardless of the policy, the audit trail, how the inspection is verified, and the known limitations.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Guarantees independent of the policy

- **`lock_configuration`**: after startup the configuration is locked and clients cannot change settings.
- **External access**: `enable_external_access=false` by default. `read_*`, `COPY ... TO` and new `ATTACH`es are blocked.
- **Extensions**: autoinstall/autoload and community extensions are turned off.
- **Always-denied statements**: `ATTACH`, `DETACH`, `LOAD`, `INSTALL` and `UPDATE EXTENSIONS`, whatever the policy says.
- **Fail-closed inspection**:
  - Statements with lexical constructs the tokenizer does not model exactly like DuckDB (`$$...$$`, nested comments, `E'...'`) get `resolved=false`.
  - The verb found by the tokenizer must match the type DuckDB prepared.
  - Types without explicit handling (CALL, VACUUM, COPY DATABASE...) also get `resolved=false`.
- **Clean environment**: the variables referenced in the catalog (`${R2_TOKEN}`...) are removed from the process environment after startup.
- **Multi-statement**: rejected before anything executes.
- **New connection per request**: TEMP tables, variables and `USE` do not leak between users.
- **One transaction per request**: inspection, authorization and execution see the same snapshot. Remote catalog metadata is fetched once per request; failures roll back.
- **No metadata in errors**: binder hints that could name objects the caller cannot read are stripped from responses (see [API](api.md#post-v1query)).

## Audit log

With `--audit-log`, each request produces one JSON line in a dedicated file,
separate from the operational log. Authentication failures and denials also
produce events.

```json
{"ts":"...","event":"query","request_id":"1a1147f8f9b0...","user":"analyst","roles":["analyst"],
 "remote_addr":"10.0.0.7","database":"sales","statement_type":"SELECT",
 "sql":"SELECT count(*) FROM orders WHERE amount > ?","sql_sha256":"...","params_count":0,
 "tables":["sales.main.orders"],"resolved":true,"decision":"allow","decided_by":"policy",
 "policy_sha256":"...","status":200,"rows":1,"bytes":42,
 "timing_ms":{"queue":0,"inspect":1.2,"authorize":0.25,"execute":1.7,"total":3.3},
 "curral_version":"0.2.0"}
```

- **`decision`** is `allow`, `deny` or `error`. **`decided_by`** says who decided: `policy`, `engine` (ATTACH, multi-statement, invalid SQL), `auth`, `queue`, `audit` or `request` (also `protection` and `concurrency`, see [Authorization](authorization.md)).
- **`policy_sha256`** is the hash of the policy files, to prove which version of the rules decided.
- **`request_id`** is also returned in the `X-Request-Id` header and appears in the operational log.
- **SQL:** by default literals become `?`, because they may contain personal data. If the SQL uses constructs the tokenizer cannot read safely, only `sql_sha256` is kept. `params` values are never logged, only their count. Passwords never appear. Change this with `--audit-sql` (`redacted`, `full`, `hash`).
- **Fail-closed:** before executing, curral reserves room in the audit queue. If the file cannot be written (disk full, permissions) or the queue is full, the query responds **503** and does not execute. Recovery is checked every 5 s by writing an `audit_recovered` event.
- **Rotation:** move the file and send `SIGHUP` (`copytruncate` is not needed). The new file starts with an `audit_reopened` event.
- **Cost:** imperceptible in measurements (asynchronous, batched writes).

Limitation: a process crash between the commit of a write and the recording of
its event can lose that event. The up-front reservation covers full disks and
permission failures, but not the process dying.

## Verifying the inspection

RBAC depends on the inspection correctly reporting what a statement writes.
This is checked against DuckDB's real behavior by a **differential fuzzer**
(`internal/engine/fuzz_test.go`):

1. It executes each generated statement.
2. It compares a snapshot of every catalog (rows, columns, tables, views, schemas, sequences and macros) before and after.
3. It fails if any changed object is missing from the `targets` of an inspection marked `resolved`.

```sh
go test ./internal/engine -run '^$' -fuzz FuzzWriteTargets -fuzztime 5m         # free mutation
go test ./internal/engine -run '^$' -fuzz FuzzWriteTargetsGrammar -fuzztime 5m  # DML/DDL grammar
```

- **Regular CI** runs the seed corpus and an exhaustive sweep (templates × name spellings).
- **Weekly**, the `fuzz` workflow runs both fuzzers for 10 minutes each.
- **Findings from this process**, all fixed and covered by regression tests:
  - a bypass with `$$...$$`;
  - `ALTER ... RENAME TO` missing the new name from the targets;
  - `memory.t` resolved in the wrong catalog;
  - object names with invalid UTF-8 breaking DuckDB's metadata.

Row filters and masks have their own differential test; see
[Authorization](authorization.md#how-it-is-applied).

## Known limitations

- **Materialized results**: the Go driver materializes the whole result inside DuckDB before delivering the first row. Use `--memory-limit`/`--temp-dir` and, if needed, `--max-rows`.
- **Bind before authorization**: the inspection binds the query before the policy runs, so a remote `read_csv` could be "sniffed" at bind time. With external access off (the default), DuckDB blocks this.
- **Bind before authorization on remote sources**: binding `iceberg_scan('s3://...')` reads metadata (within `--allowed-path`) before the policy. No data is returned, but the error message can reveal whether a table exists or its schema.
- **Iceberg latency without `cache_ttl`**: every request goes to the REST catalog (~0.3–1 s on R2), and concurrent calls do not benefit from parallelism.
- **Name formats in write targets**: two-part names (`x.t`) resolve as `database.main.t` when `x` is a catalog database, and as `schema.t` in the current database otherwise.

See also: [Configuration](configuration.md) · [API](api.md) · [Authentication](authentication.md) · [Authorization](authorization.md) · [Operations](operations.md)
