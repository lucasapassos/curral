# Contributing to curral

Thanks for your interest. Bug reports, documentation fixes and pull requests
are welcome. For security issues, follow [SECURITY.md](SECURITY.md) instead
of opening an issue. Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

For anything larger than a small fix, open an issue first to discuss the
approach. curral's main promise is that the policy sees exactly what a
statement reads and writes, so changes to inspection, rewriting or
authorization get extra scrutiny and need tests that prove they fail closed.

## Development setup

Requirements: Go 1.27+ and a C compiler (cgo, for DuckDB).

```sh
go build -tags duckdb_arrow -o bin/curral ./cmd/curral
go test -race -tags duckdb_arrow ./...
```

The `duckdb_arrow` tag enables Arrow IPC output; CI also runs the server and
engine tests without it. The Cloudflare R2 integration tests skip themselves
unless the `R2_*` variables are set (see `examples/r2.env.example`).

Fuzzers for the statement inspection (run them when touching
`internal/engine`):

```sh
go test ./internal/engine -run '^$' -fuzz FuzzWriteTargets -fuzztime 5m
go test ./internal/engine -run '^$' -fuzz FuzzWriteTargetsGrammar -fuzztime 5m
go test ./internal/engine -run '^$' -fuzz FuzzProtectDifferential -fuzztime 5m
```

The Python client lives in `clients/python` and is tested against a running
server (see the `python-client` job in `.github/workflows/ci.yml`).

## Pull requests

- Run `gofmt`, `go vet ./...` and the tests; CI checks all three.
- Add a test for every bug fix and behavior change.
- Add an entry to the `## [Unreleased]` section of [CHANGELOG.md](CHANGELOG.md)
  (create it if missing) describing the user-visible change.
- Update the docs under `docs/` when you change flags, API or behavior.
- Keep commits focused; write the message in the imperative
  ("Hide binder errors on denied objects").

By contributing you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE).
