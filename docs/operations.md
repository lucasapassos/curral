# Operations

Metrics, alerting, performance figures and the release process.

## Metrics

With `--metrics-listen`, `/metrics` (Prometheus format) is served on a port
separate from the API and **without authentication**. Keep that port on the
internal network.

| Metric | Type | Labels |
|---|---|---|
| `curral_queries_total` | counter | `status`, `decision`, `decided_by`, `statement_type` |
| `curral_policy_decisions_total` | counter | `role`, `decision` (each of the user's roles counts once) |
| `curral_query_stage_seconds` | histogram | `stage`: `queue`, `inspect`, `authorize`, `execute`, `total` |
| `curral_queries_running` / `curral_queries_waiting` / `curral_query_slots` | gauge | |
| `curral_rows_returned_total` / `curral_response_bytes_total` | counter | |
| `curral_auth_failures_total` | counter | |
| `curral_audit_events_written_total` / `curral_audit_events_dropped_total` | counter | |
| `curral_audit_healthy` | gauge | 0 = queries are being refused |
| `curral_catalog_cache_requests_total` | counter | `database`, `result` (`hit`, `miss`) |
| `curral_build_info` | gauge | `version`, `commit`, `duckdb`, `policy_sha256` |

Other metrics are documented next to their features:
`curral_auth_failures_total{method}`, `curral_auth_lockouts_total{scope}` and
`curral_auth_blocked_total{scope}` ([Authentication](authentication.md)),
`curral_queries_throttled_total` and `curral_queries_rewritten_total`
([Authorization](authorization.md)), `curral_config_reloads_total` and
`curral_policy_info` ([Configuration](configuration.md#reload-without-restart)).
The standard Go runtime and process metrics (`go_*`, `process_*`) are exported
too.

Suggested alerts:

- `curral_audit_healthy == 0`: queries are being refused.
- `rate(curral_queries_total{status="503"}[5m]) > 0`: queue full or audit down.
- `curral_queries_waiting > 0` for a long time: raise `--max-concurrency`.
- A spike in `curral_policy_decisions_total{decision="deny"}` or in `curral_auth_failures_total`.

## Performance

Measured on the full HTTP path (auth, inspection, policy, execution and
serialization), on a 6-core machine:

| Scenario | Time |
|---|---|
| `SELECT 1` / point lookup | ~0.7 ms / ~0.9 ms per request |
| 1 million rows (4 columns), CSV | ~570 ms |
| 1 million rows, JSON | ~580 ms |
| 1 million rows, **Arrow** | **~140 ms** |
| Iceberg on R2 with `cache_ttl` | ~8 ms (no cache: 250–900 ms) |

- **Large results: prefer `format: arrow`.** DuckDB converts whole vectors
  straight to Arrow, without converting value by value. Clients such as
  pyarrow, polars and DuckDB itself read the stream directly.
- **CSV and JSON:** the decimal, date and CSV formatters are hand-written and
  tested against the Go standard library's and the driver's reference
  implementations.
- **Small queries:** latency is dominated by DuckDB's fixed cost. About
  0.25 ms comes from guarantees kept on purpose: a new connection per request
  (isolation between users) and the inspection that feeds the policy.

For the cost of row filters, masks and per-user quotas, see
[Authorization](authorization.md).

## Releasing

Releases are published from [GitHub releases](https://github.com/lucasapassos/curral/releases)
and Docker Hub (`lucasapassos/curral`, multi-arch linux/amd64 and linux/arm64).

To publish a version, add a `## [vX.Y.Z]` section to `CHANGELOG.md` and push
the tag:

```sh
git tag v0.2.0 && git push origin v0.2.0
```

The `release` workflow then:

1. runs the tests;
2. builds the binaries for both architectures;
3. publishes the image to Docker Hub (needs the secret `DOCKERHUB_TOKEN` in the `release` environment, which only `v*` tags can use; the user name defaults to `lucasapassos` and can be overridden with the repository variable `DOCKERHUB_USERNAME`);
4. creates the release with the notes from that changelog section.

The release tarballs (Linux, glibc 2.35+) ship with the `httpfs`, `avro` and
`iceberg` extensions pre-installed:

```sh
tar xzf curral_vX.Y.Z_linux_amd64.tar.gz && cd curral_vX.Y.Z_linux_amd64
./curral serve --extension-dir ./extensions --catalog ... --users ... --policy ...
```

See also: [Configuration](configuration.md) · [API](api.md) · [Authentication](authentication.md) · [Authorization](authorization.md) · [Security](security.md)
