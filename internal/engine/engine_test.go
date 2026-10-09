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

	"github.com/lucasapassos/curral/internal/config"
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
		{"CREATE TABLE memory.scratch(a INT)", "CREATE", nil, []string{"memory.main.scratch"}, true},
		{"CREATE TABLE crm.scratch(a INT)", "CREATE", nil, []string{"sales.crm.scratch"}, true},
		{"DROP TABLE IF EXISTS crm.clients", "DROP", nil, []string{"sales.crm.clients"}, true},
		{"DROP SCHEMA logs.x", "DROP", nil, []string{"logs.x.*"}, true},
		{"ALTER TABLE orders ADD COLUMN note VARCHAR", "ALTER", nil, []string{"sales.main.orders"}, true},
		{"ALTER TABLE crm.clients RENAME TO c2", "ALTER", nil, []string{"sales.crm.c2", "sales.crm.clients"}, true},
		{"ALTER TABLE orders RENAME COLUMN amount TO total", "ALTER", nil, []string{"sales.main.orders"}, true},
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
	for _, q := range []string{"PRAGMA version", "PRAGMA table_info('orders')", "SELECT * FROM duckdb_databases()", "CALL pragma_version()", "DESCRIBE orders", "SUMMARIZE orders"} {
		if _, _, err := run(e, Request{SQL: q}, nil); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
	if _, _, err := run(e, Request{SQL: "CREATE TABLE \xff(a INT)"}, nil); !isQueryErr(err) {
		t.Errorf("invalid UTF-8: %v", err)
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

func TestExecTimeout(t *testing.T) {
	e := newEngine(t, Options{QueryTimeout: time.Minute})
	limit := 100 * time.Millisecond
	start := time.Now()
	_, _, err := run(e, Request{SQL: "SELECT count(*) FROM range(10000000000) a", ExecTimeout: &limit}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("err=%v after %v", err, time.Since(start))
	}
	// A write within its limit still commits.
	if _, _, err := run(e, Request{SQL: "INSERT INTO orders VALUES (7, 7)", ExecTimeout: &limit}, nil); err != nil {
		t.Fatal(err)
	}
	_, rows, _ := run(e, Request{SQL: "SELECT count(*) FROM orders WHERE id = 7"}, nil)
	if rows[0][0] != int64(1) {
		t.Fatalf("write with exec timeout not committed: %v", rows)
	}
}

// DESCRIBE and SHOW are answered while binding: the plan reads no table, so
// the tables whose metadata they reveal come from the parse tree.
func TestInspectDescribe(t *testing.T) {
	e := newEngine(t, Options{})
	cases := []struct {
		sql      string
		tables   []string
		resolved bool
	}{
		{"DESCRIBE salaries", []string{"sales.main.salaries"}, true},
		{"DESC salaries", []string{"sales.main.salaries"}, true},
		{"SHOW salaries", []string{"sales.main.salaries"}, true},
		{"describe sales.crm.clients", []string{"sales.crm.clients"}, true},
		{"SELECT * FROM (DESCRIBE salaries) WHERE column_name = 'value'", []string{"sales.main.salaries"}, true},
		{"DESCRIBE SELECT name FROM salaries", []string{"sales.main.salaries"}, true},
		{"SELECT * FROM orders, (DESCRIBE logs.events)", []string{"logs.main.events", "sales.main.orders"}, true},
		{"DESCRIBE big_orders", []string{"sales.main.orders"}, true}, // a view: its base table
		{"SUMMARIZE orders", []string{"sales.main.orders"}, true},
		{"SHOW TABLES", []string{}, false},
		{"SHOW ALL TABLES", []string{}, false},
		{"SELECT id FROM orders ORDER BY id DESC", []string{"sales.main.orders"}, true},
		{"EXPLAIN DESCRIBE salaries", []string{"sales.main.salaries"}, true},
		// Writes that would store DESCRIBE output: DuckDB cannot serialize
		// them to JSON, so they are unresolved.
		{"INSERT INTO orders SELECT 1, length(column_name) FROM (DESCRIBE salaries)", []string{}, false},
		{"CREATE TABLE leak AS SELECT * FROM (DESC salaries)", []string{}, false},
		{"CREATE VIEW leakv AS SELECT * FROM (SHOW salaries)", []string{}, false},
		// Ordinary writes stay resolved, DESC included.
		{"INSERT INTO orders SELECT id + 10, amount FROM orders ORDER BY id DESC", []string{"sales.main.orders"}, true},
		{"INSERT INTO orders SELECT id, amount FROM orders ORDER BY abs(id) DESC, \"amount\" DESC NULLS LAST", []string{"sales.main.orders"}, true},
		{"INSERT INTO orders VALUES (5, 1) -- describe show", []string{}, true},
	}
	for _, c := range cases {
		insp, _, err := run(e, Request{SQL: c.sql}, func(context.Context, Inspection) error { return ErrForbidden })
		if !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: %v", c.sql, err)
			continue
		}
		if !slices.Equal(nonNil(insp.Tables), c.tables) || insp.Resolved != c.resolved {
			t.Errorf("%s: tables=%v resolved=%v, want %v %v", c.sql, insp.Tables, insp.Resolved, c.tables, c.resolved)
		}
	}
}

func TestPublicErrorHidesSuggestions(t *testing.T) {
	e := newEngine(t, Options{})
	for _, c := range []struct{ sql, leak string }{
		{"SELECT * FROM salarie", `"salaries"`}, // Did you mean "salaries"?
		{"SELECT * FROM crm.client", "clients"}, // Did you mean "crm.clients"?
		{"SELECT nam FROM salaries", `"name"`},  // Candidate bindings
		{"SELECT * FROM orders o JOIN salaries s ON o.id = s.nam", `"name"`},
	} {
		_, _, err := run(e, Request{SQL: c.sql}, allowAll)
		if err == nil {
			t.Fatalf("%s: no error", c.sql)
		}
		if !strings.Contains(err.Error(), c.leak) {
			t.Fatalf("%s: DuckDB no longer suggests %s (test needs updating): %q", c.sql, c.leak, err)
		}
		msg := PublicError(err)
		if strings.Contains(msg, c.leak) || strings.Contains(msg, "Did you mean") || strings.Contains(msg, "Candidate") {
			t.Errorf("%s: leaks: %q", c.sql, msg)
		}
		if !strings.Contains(msg, "/v1/schema") || !strings.Contains(msg, "LINE 1") {
			t.Errorf("%s: message lost context: %q", c.sql, msg)
		}
	}
	// Messages without suggestions are untouched.
	_, _, err := run(e, Request{SQL: "SELEC 1"}, allowAll)
	if PublicError(err) != err.Error() {
		t.Errorf("parser error changed: %q", PublicError(err))
	}
}

// Catalog listings can crash DuckDB on Iceberg catalogs: refused before the
// policy is asked, whatever the caller's role.
func TestCatalogListingsRefused(t *testing.T) {
	e := newEngine(t, Options{})
	for _, q := range []string{
		"SELECT * FROM duckdb_tables()",
		"FROM duckdb_views()",
		"SELECT * FROM information_schema.tables",
		"SELECT * FROM information_schema.columns",
		"SELECT * FROM (SELECT table_name FROM duckdb_tables() UNION ALL SELECT view_name FROM duckdb_views())",
		"SELECT * FROM pg_catalog.pg_class",
		"SELECT * FROM sqlite_master",
		"SHOW TABLES",
		"SHOW ALL TABLES",
		"PRAGMA show_tables",
		"pragma SHOW_TABLES_EXPANDED",
		"CALL duckdb_tables()",
		"/* x */ CALL \"duckdb_columns\"()",
		"EXPLAIN SELECT * FROM duckdb_schemas()",
		"SELECT * FROM orders WHERE id IN (SELECT 1 FROM duckdb_functions())",
		"SET VARIABLE n = (SELECT count(*) FROM duckdb_views())",
		"CREATE TABLE leak AS FROM information_schema.tables",
		"INSERT INTO orders SELECT 1, count(*) FROM duckdb_columns()",
		"CALL query('SELECT * FROM duckdb_tables()')",
		"CALL query_table('information_schema.tables')",
		"SELECT * FROM query('SELECT * FROM duck' || 'db_tables()')",
	} {
		called := false
		_, _, err := run(e, Request{SQL: q}, func(context.Context, Inspection) error { called = true; return nil })
		if !errors.Is(err, ErrForbidden) || called {
			t.Errorf("%s: err=%v policy asked=%v", q, err, called)
		}
	}
	for _, q := range []string{"SELECT * FROM duckdb_databases()", "PRAGMA version", "DESCRIBE orders", "SELECT 'duckdb_tables' AS s"} {
		if _, _, err := run(e, Request{SQL: q}, allowAll); err != nil {
			t.Errorf("%s: %v", q, err)
		}
	}
}

// A view or table macro wrapping DESCRIBE describes a table nobody named in
// the statement: the plan shows a bind-time result the statement does not
// account for, so it is unresolved.
func TestHiddenDescribe(t *testing.T) {
	e := newEngine(t, Options{})
	for _, q := range []string{
		"CREATE VIEW meta AS SELECT * FROM (DESCRIBE salaries)",
		"CREATE MACRO m() AS TABLE SELECT * FROM (DESCRIBE salaries)",
	} {
		if _, _, err := run(e, Request{SQL: q}, allowAll); err != nil {
			t.Fatal(q, err)
		}
	}
	for q, resolved := range map[string]bool{
		"SELECT * FROM meta":                                  false,
		"SELECT * FROM m()":                                   false,
		"SELECT * FROM (DESCRIBE orders), meta":               false, // one DESCRIBE, two results
		"INSERT INTO orders SELECT 1, 1 FROM meta":            false,
		"SELECT * FROM (DESCRIBE orders)":                     true,
		"SELECT * FROM (DESCRIBE orders), (SHOW logs.events)": true,
	} {
		insp, _, err := run(e, Request{SQL: q}, func(context.Context, Inspection) error { return ErrForbidden })
		if !errors.Is(err, ErrForbidden) || insp.Resolved != resolved {
			t.Errorf("%s: resolved=%v err=%v, want resolved=%v", q, insp.Resolved, err, resolved)
		}
	}
}

func TestPublicErrorAnyError(t *testing.T) {
	for in, want := range map[string]string{
		"Catalog Error: Type with name x does not exist! Did you mean \"secret_type\"?": "Catalog Error: Type with name x does not exist!",
		"wrapped: Binder Error: no column\nCandidate bindings: \"cpf\"\n\nLINE 1":       "wrapped: Binder Error: no column\n\nLINE 1",
	} {
		got := PublicError(errors.New(in))
		if !strings.HasPrefix(got, want) || strings.Contains(got, "secret_type") || strings.Contains(got, "cpf") {
			t.Errorf("%q -> %q", in, got)
		}
	}
}
