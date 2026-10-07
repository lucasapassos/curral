package engine

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	_ "github.com/duckdb/duckdb-go/v2"

	"curral/internal/config"
)

// seed creates a DuckDB file with the given statements.
func seed(t testing.TB, path string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("duckdb", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("seed %q: %v", s, err)
		}
	}
}

func newEngine(t testing.TB, opts Options) *Engine {
	t.Helper()
	dir := t.TempDir()
	sales := filepath.Join(dir, "sales.duckdb")
	logs := filepath.Join(dir, "logs.duckdb")
	seed(t, sales,
		"CREATE TABLE orders(id INT, amount DECIMAL(10,2))",
		"INSERT INTO orders VALUES (1, 10.50), (2, 20.00)",
		"CREATE TABLE salaries(name VARCHAR, value INT)",
		"CREATE SCHEMA crm",
		"CREATE TABLE crm.clients(id INT)",
		"CREATE VIEW big_orders AS SELECT * FROM orders WHERE amount > 15",
	)
	seed(t, logs, "CREATE TABLE events(id INT)", "INSERT INTO events VALUES (1)")

	cat := &config.Catalog{
		Databases: []config.Database{
			{Name: "sales", Path: sales},
			{Name: "logs", Path: logs, Options: map[string]any{"READ_ONLY": true}},
		},
		Default: "sales",
	}
	if opts.MaxConcurrency == 0 {
		opts.MaxConcurrency = 4
	}
	e, err := Open(context.Background(), cat, opts, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func allowAll(context.Context, Inspection) error { return nil }

// run executes a query and returns all rows as driver values.
func run(e *Engine, req Request, authz func(context.Context, Inspection) error) (Inspection, [][]driver.Value, error) {
	var insp Inspection
	var out [][]driver.Value
	err := e.Query(context.Background(), req,
		func(ctx context.Context, i Inspection) error {
			insp = i
			if authz != nil {
				return authz(ctx, i)
			}
			return nil
		},
		func(cols []Column, rows Rows) error {
			for {
				dest := make([]driver.Value, len(cols))
				if err := rows.Next(dest); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}
					return err
				}
				out = append(out, dest)
			}
		})
	return insp, out, err
}

func TestQueryBasics(t *testing.T) {
	e := newEngine(t, Options{})
	_, rows, err := run(e, Request{SQL: "SELECT id FROM orders WHERE id = ? ORDER BY id", Params: []any{int64(2)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0][0] != int32(2) {
		t.Fatalf("rows = %v", rows)
	}

	_, rows, err = run(e, Request{SQL: "SELECT count(*) FROM events", Database: "logs"}, nil)
	if err != nil || rows[0][0] != int64(1) {
		t.Fatalf("USE logs: rows=%v err=%v", rows, err)
	}

	if _, _, err := run(e, Request{SQL: "SELECT 1", Database: "nope"}, nil); !isQueryErr(err) {
		t.Fatalf("unknown database: %v", err)
	}
}

func isQueryErr(err error) bool {
	var qe *QueryError
	return errors.As(err, &qe)
}

func TestInspect(t *testing.T) {
	e := newEngine(t, Options{})
	cases := []struct {
		sql      string
		typ      string
		tables   []string
		targets  []string
		resolved bool
	}{
		{"SELECT * FROM orders", "SELECT", []string{"sales.main.orders"}, nil, true},
		{"select * from sales.main.orders o join sales.orders x using(id)", "SELECT", []string{"sales.main.orders"}, nil, true},
		{"SELECT * FROM big_orders", "SELECT", []string{"sales.main.orders"}, nil, true},
		{"SELECT * FROM orders WHERE false", "SELECT", []string{"sales.main.orders"}, nil, true},
		{"WITH t AS (SELECT * FROM crm.clients) SELECT * FROM t, logs.events", "SELECT", []string{"logs.main.events", "sales.crm.clients"}, nil, true},
		{"SELECT 1", "SELECT", nil, nil, true},
		{"SELECT * FROM range(3), orders", "SELECT", []string{"sales.main.orders"}, nil, true},
		{"INSERT INTO orders VALUES (3, 1)", "INSERT", nil, []string{"sales.main.orders"}, true},
		{"INSERT INTO sales.orders SELECT id, 1 FROM crm.clients", "INSERT", []string{"sales.crm.clients"}, []string{"sales.main.orders"}, true},
		{"UPDATE orders SET amount = 0 WHERE id IN (SELECT id FROM crm.clients)", "UPDATE", []string{"sales.crm.clients", "sales.main.orders"}, []string{"sales.main.orders"}, true},
		{"DELETE FROM \"orders\" WHERE id = 1", "DELETE", []string{"sales.main.orders"}, []string{"sales.main.orders"}, true},
		{"WITH x AS (SELECT 1 AS id) DELETE FROM orders WHERE id IN (SELECT id FROM x)", "DELETE", []string{"sales.main.orders"}, []string{"sales.main.orders"}, true},
		{"CREATE TABLE crm.copy AS SELECT * FROM salaries", "CREATE", []string{"sales.main.salaries"}, []string{"sales.crm.copy"}, true},
		{"CREATE TEMP TABLE scratch(a INT)", "CREATE", nil, []string{"temp.main.scratch"}, true},
		{"DROP TABLE IF EXISTS crm.clients", "DROP", nil, []string{"sales.crm.clients"}, true},
		{"DROP SCHEMA logs.x", "DROP", nil, []string{"logs.x.*"}, true},
		{"ALTER TABLE orders ADD COLUMN note VARCHAR", "ALTER", nil, []string{"sales.main.orders"}, true},
		{"CREATE INDEX idx ON orders(id)", "CREATE", []string{"sales.main.orders"}, []string{"sales.main.orders"}, true},
		{"EXPLAIN SELECT * FROM salaries", "EXPLAIN", []string{"sales.main.salaries"}, nil, true},
		{"EXPLAIN ANALYZE DELETE FROM orders", "DELETE", []string{"sales.main.orders"}, []string{"sales.main.orders"}, true},
		{"/* DELETE FROM x */ SELECT 'DROP TABLE y' FROM orders -- UPDATE z", "SELECT", []string{"sales.main.orders"}, nil, true},
	}
	for _, c := range cases {
		t.Run(c.sql, func(t *testing.T) {
			var got Inspection
			err := e.Query(context.Background(), Request{SQL: c.sql},
				func(_ context.Context, i Inspection) error { got = i; return ErrForbidden },
				func([]Column, Rows) error { t.Fatal("must not execute"); return nil })
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("err = %v", err)
			}
			if c.sql == "SELECT * FROM range(3), orders" && !slices.Equal(got.Functions, []string{"range"}) {
				t.Fatalf("functions = %v", got.Functions)
			}
			if got.StatementType != c.typ || got.Resolved != c.resolved ||
				!slices.Equal(got.Tables, nonNil(c.tables)) || !slices.Equal(got.Targets, nonNil(c.targets)) {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func TestPragmasAndTransactions(t *testing.T) {
	e := newEngine(t, Options{})
	for _, q := range []string{"PRAGMA version", "PRAGMA table_info('orders')", "SELECT * FROM duckdb_tables()", "CALL pragma_version()", "SHOW TABLES", "DESCRIBE orders", "SUMMARIZE orders"} {
		if _, _, err := run(e, Request{SQL: q}, nil); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	if _, _, err := run(e, Request{SQL: "BEGIN TRANSACTION"}, nil); !isQueryErr(err) {
		t.Errorf("BEGIN: %v", err)
	}
	// A failing write rolls back and leaves no trace.
	if _, _, err := run(e, Request{SQL: "INSERT INTO orders VALUES (9, 'x')"}, nil); err == nil {
		t.Fatal("expected cast error")
	}
	_, rows, _ := run(e, Request{SQL: "SELECT count(*) FROM orders"}, nil)
	if rows[0][0] != int64(2) {
		t.Fatalf("rows = %v", rows)
	}
}

func TestDeniedNeverExecutes(t *testing.T) {
	e := newEngine(t, Options{})
	err := e.Query(context.Background(), Request{SQL: "DELETE FROM orders"},
		func(context.Context, Inspection) error { return ErrForbidden },
		func([]Column, Rows) error { return nil })
	if !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	_, rows, _ := run(e, Request{SQL: "SELECT count(*) FROM orders"}, nil)
	if rows[0][0] != int64(2) {
		t.Fatalf("rows were deleted: %v", rows)
	}
}

func TestMultiStatementRejected(t *testing.T) {
	e := newEngine(t, Options{})
	_, _, err := run(e, Request{SQL: "DELETE FROM orders; SELECT 1"}, nil)
	if !isQueryErr(err) {
		t.Fatalf("err = %v", err)
	}
	_, rows, _ := run(e, Request{SQL: "SELECT count(*) FROM orders"}, nil)
	if rows[0][0] != int64(2) {
		t.Fatalf("first statement ran: %v", rows)
	}
}

func TestHardening(t *testing.T) {
	e := newEngine(t, Options{})
	forbidden := []string{
		"ATTACH '/tmp/x.duckdb' AS x",
		"DETACH logs",
		"LOAD httpfs",
		"INSTALL httpfs",
	}
	for _, q := range forbidden {
		if _, _, err := run(e, Request{SQL: q}, nil); !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: err = %v", q, err)
		}
	}
	failing := []string{
		"SELECT * FROM read_csv('/etc/passwd')",
		"COPY (SELECT 1) TO '/tmp/curral-test.csv'",
		"SET threads = 1",
		"SET enable_external_access = true",
		"INSERT INTO logs.events VALUES (2)", // READ_ONLY
	}
	for _, q := range failing {
		if _, _, err := run(e, Request{SQL: q}, nil); err == nil {
			t.Errorf("%s: expected error", q)
		}
	}
	// Writes to attached files still work after lockdown.
	if _, _, err := run(e, Request{SQL: "INSERT INTO orders VALUES (3, 3)"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(e, Request{SQL: "CHECKPOINT"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSessionIsolation(t *testing.T) {
	e := newEngine(t, Options{MaxConcurrency: 1})
	if _, _, err := run(e, Request{SQL: "CREATE TEMP TABLE leak AS SELECT 42 AS v"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(e, Request{SQL: "SELECT * FROM leak"}, nil); err == nil {
		t.Fatal("temp table visible to the next request")
	}
	if _, _, err := run(e, Request{SQL: "SELECT 1", Database: "logs"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(e, Request{SQL: "SELECT count(*) FROM orders"}, nil); err != nil {
		t.Fatalf("USE leaked between requests: %v", err)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	e := newEngine(t, Options{MaxConcurrency: 1, QueueTimeout: 50 * time.Millisecond})
	hold, release := make(chan struct{}), make(chan struct{})
	go e.Query(context.Background(), Request{SQL: "SELECT 1"}, allowAll,
		func([]Column, Rows) error { close(hold); <-release; return nil })
	<-hold
	_, _, err := run(e, Request{SQL: "SELECT 1"}, nil)
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("err = %v", err)
	}
	close(release)
	time.Sleep(10 * time.Millisecond)
	if _, _, err := run(e, Request{SQL: "SELECT 1"}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestQueryTimeout(t *testing.T) {
	e := newEngine(t, Options{QueryTimeout: 100 * time.Millisecond})
	start := time.Now()
	_, _, err := run(e, Request{SQL: "SELECT count(*) FROM range(10000000000) a"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("query was not interrupted")
	}
}

// Secrets created from the catalog must not be readable through SQL.
func TestSecretsNotExposed(t *testing.T) {
	const value = "curral-test-secret-value-1234"
	cat := &config.Catalog{
		Extensions: []string{"httpfs"},
		Secrets: []config.Secret{{Name: "s", Type: "s3", Params: map[string]any{
			"KEY_ID": "AKIA-curral-test", "SECRET": value,
		}}},
		Databases: []config.Database{{Name: "m", Path: ":memory:"}},
	}
	e, err := Open(context.Background(), cat, Options{MaxConcurrency: 1}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Skipf("httpfs unavailable: %v", err)
	}
	defer e.Close()
	for _, q := range []string{
		"SELECT * FROM duckdb_secrets()",
		"SELECT secret_string FROM duckdb_secrets()",
		"SELECT which_secret('s3://bucket/x', 's3')",
		"SELECT current_setting('s3_secret_access_key')",
		"SELECT * FROM duckdb_settings()",
	} {
		_, rows, err := run(e, Request{SQL: q}, nil)
		if strings.Contains(fmt.Sprint(rows, err), value) {
			t.Errorf("%s exposed the secret", q)
		}
	}
}
