package engine

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"curral/internal/config"
)

// Integration tests against a real Cloudflare R2 Data Catalog. They run only
// when R2_CATALOG_URI, R2_WAREHOUSE, R2_TOKEN and R2_TEST_TABLE are set
// (see examples/r2.env.example):
//
//	source .env.r2 && go test ./internal/engine -run R2 -v

func r2Env(t *testing.T) (table string) {
	t.Helper()
	for _, k := range []string{"R2_CATALOG_URI", "R2_WAREHOUSE", "R2_TOKEN", "R2_TEST_TABLE"} {
		if os.Getenv(k) == "" {
			t.Skipf("%s not set", k)
		}
	}
	return os.Getenv("R2_TEST_TABLE")
}

func r2Catalog(t *testing.T) *config.Catalog {
	t.Helper()
	cat, err := config.LoadCatalog("../../examples/catalog.r2.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

// TestR2Raw attaches the catalog without any hardening and logs what DuckDB
// sees: tables, the logical plan shape and timings.
func TestR2Raw(t *testing.T) {
	table := r2Env(t)
	stmts, err := bootStatements(r2Catalog(t))
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	conn, _ := db.Conn(ctx)
	defer conn.Close()
	for _, s := range append(stmts, stmt{"SET explain_output = 'all'", ""}) {
		start := time.Now()
		if _, err := conn.ExecContext(ctx, s.sql); err != nil {
			t.Fatalf("%s: %v", s.log, err)
		}
		t.Logf("%-60s %v", s.log, time.Since(start))
	}

	logQuery := func(q string) {
		start := time.Now()
		rows, err := conn.QueryContext(ctx, q)
		if err != nil {
			t.Logf("%s\n  ERROR: %v", q, err)
			return
		}
		defer rows.Close()
		cols, _ := rows.Columns()
		var out []string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...)
			var parts []string
			for _, v := range vals {
				parts = append(parts, strings.TrimSpace(strings.ReplaceAll(toString(v), "\n", "\n    ")))
			}
			out = append(out, "  "+strings.Join(parts, " | "))
		}
		t.Logf("%s  (%v)\n%s", q, time.Since(start), strings.Join(out, "\n"))
	}

	logQuery("SELECT database_name, schema_name, table_name FROM duckdb_tables() WHERE database_name = 'lake'")
	logQuery("SELECT * FROM lake." + table + " LIMIT 3")
	logQuery("EXPLAIN (FORMAT JSON) SELECT * FROM lake." + table + " LIMIT 3")
	logQuery("EXPLAIN ANALYZE SELECT count(*) FROM lake." + table)
}

func toString(v any) string {
	switch t := v.(type) {
	case nil:
		return "NULL"
	case []byte:
		return string(t)
	}
	return fmt.Sprint(v)
}

// TestR2Engine runs the hardened engine against the catalog and checks what
// the policy would see. R2_ALLOWED_PATH (e.g. s3://bucket/) adds a variant with
// external access off but the bucket allowed.
func TestR2Engine(t *testing.T) {
	table := r2Env(t)
	variants := []struct {
		name string
		opts Options
	}{
		{"external-access off", Options{}},
		{"external-access on", Options{ExternalAccess: true}},
	}
	if p := os.Getenv("R2_ALLOWED_PATH"); p != "" {
		variants = append(variants, struct {
			name string
			opts Options
		}{"external-access off + allowed path", Options{AllowedPaths: []string{p}}})
	}
	qualified := "lake." + table
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			v.opts.MaxConcurrency = 2
			start := time.Now()
			e, err := Open(context.Background(), r2Catalog(t), v.opts, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatalf("boot: %v", err)
			}
			defer e.Close()
			t.Logf("boot %v", time.Since(start))

			cases := []struct {
				sql       string
				wantTable string // must appear in Tables
				wantFunc  string // must appear in Functions
				resolved  bool
			}{
				{"SELECT * FROM " + table + " LIMIT 3", qualified, "", true},
				{"SELECT count(*) FROM " + qualified, qualified, "", true},
				{"WITH x AS (SELECT * FROM " + qualified + ") SELECT count(*) FROM x a JOIN x b USING (customer)", qualified, "", true},
				{"SELECT * FROM iceberg_scan('s3://nowhere/t') LIMIT 1", "", "iceberg_scan", true},
				{"CREATE TEMP TABLE tmp AS SELECT * FROM " + qualified, "", "iceberg_scan", false},
			}
			for _, c := range cases {
				var insp Inspection
				var inspAt time.Duration
				start := time.Now()
				_, rows, err := run(e, Request{SQL: c.sql}, func(_ context.Context, i Inspection) error {
					insp, inspAt = i, time.Since(start)
					return nil
				})
				t.Logf("%s\n  inspection (%v): %+v\n  total %v rows=%d err=%v",
					c.sql, inspAt, insp, time.Since(start), len(rows), oneLineErr(err))
				if insp.StatementType == "" {
					continue // failed before inspection; logged above
				}
				if insp.Resolved != c.resolved ||
					(c.wantTable != "" && !slices.Contains(insp.Tables, c.wantTable)) ||
					(c.wantFunc != "" && !slices.Contains(insp.Functions, c.wantFunc)) {
					t.Errorf("unexpected inspection for %s", c.sql)
				}
			}
		})
	}
}

// TestR2HiddenScans: a local view over a lake table hides the table from the
// plan; inspection must flag it (unresolved, hidden scans) so the policy and
// row filters cannot be bypassed through the view.
func TestR2HiddenScans(t *testing.T) {
	table := r2Env(t)
	e, err := Open(context.Background(), r2Catalog(t), Options{MaxConcurrency: 1, ExternalAccess: true}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if _, err := e.db.Exec("CREATE VIEW memory.main.v AS SELECT * FROM lake." + table); err != nil {
		t.Fatal(err)
	}
	for sql, hidden := range map[string]int{
		"SELECT count(*) FROM memory.main.v":                                 1,
		"SELECT count(*) FROM lake." + table:                                 0,
		"SELECT count(*) FROM lake." + table + " a, memory.main.v b LIMIT 1": 1,
	} {
		var insp Inspection
		run(e, Request{SQL: sql}, func(_ context.Context, i Inspection) error { insp = i; return ErrForbidden })
		if insp.HiddenRemoteScans != hidden || insp.Resolved == (hidden > 0) {
			t.Errorf("%s: hidden=%d resolved=%v", sql, insp.HiddenRemoteScans, insp.Resolved)
		}
	}
}

// TestR2Protection applies a row filter and a mask to a real lake table and
// compares with the same filter written by hand.
func TestR2Protection(t *testing.T) {
	table := r2Env(t)
	e, err := Open(context.Background(), r2Catalog(t), Options{MaxConcurrency: 1, ExternalAccess: true}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	q := "lake." + table
	prot := map[string]Protection{q: {Filter: "region = 'north'", Masks: map[string]string{"customer": "'***'"}}}
	got, err := runProtected(e, "SELECT count(*), count(DISTINCT region), count(*) FILTER (customer <> '***') FROM "+q, prot)
	if err != nil {
		t.Fatal(err)
	}
	_, want, err := run(e, Request{SQL: "SELECT count(*), 1::BIGINT, 0::BIGINT FROM " + q + " WHERE region = 'north'"}, nil)
	if err != nil || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("protected %v, expected %v (err %v)", got, want, err)
	}
	// A join with another lake table goes through the rewrite as well.
	if _, err := runProtected(e, "SELECT count(*) FROM "+q+" a JOIN "+q+" b USING (contract_id) WHERE a.customer = b.customer", prot); err != nil {
		t.Fatalf("self-join: %v", err)
	}
}

func oneLineErr(err error) string {
	if err == nil {
		return "<nil>"
	}
	return strings.Join(strings.Fields(err.Error()), " ")
}

// TestR2CacheProbe measures per-request latency and the HTTP requests DuckDB
// makes (by kind) under different cache settings. It enables DuckDB's HTTP
// log, which records credentials, so it only lives in tests.
func TestR2CacheProbe(t *testing.T) {
	table := r2Env(t)
	configs := []struct {
		name     string
		settings map[string]any
		cacheTTL string
	}{
		{"defaults", nil, ""},
		{"curral catalog cache 30s", nil, "30s"},
		{"connection caching", map[string]any{"httpfs_connection_caching": true}, ""},
	}
	queries := []string{
		"SELECT count(*) FROM " + table,
		"SELECT region, sum(revenue) FROM " + table + " GROUP BY 1",
	}
	for _, c := range configs {
		t.Run(c.name, func(t *testing.T) {
			cat := r2Catalog(t)
			cat.Settings = c.settings
			cat.Databases[0].CacheTTL = c.cacheTTL
			cat.InitSQL = []string{"CALL enable_logging('HTTP')"}
			e, err := Open(context.Background(), cat, Options{MaxConcurrency: 1, AllowedPaths: []string{os.Getenv("R2_ALLOWED_PATH")}}, slog.New(slog.DiscardHandler))
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			for _, q := range queries {
				for i := range 4 {
					clearLogs(t, e)
					start := time.Now()
					if _, _, err := run(e, Request{SQL: q}, nil); err != nil {
						t.Fatalf("%s: %v", q, err)
					}
					t.Logf("%-55.55s run %d: %6dms  %s", q, i+1, time.Since(start).Milliseconds(), httpSummary(t, e))
				}
			}
			if hits, misses, ok := e.CacheStats("lake"); ok {
				t.Logf("catalog cache: hits=%d misses=%d", hits, misses)
			}
		})
	}
}

func clearLogs(t *testing.T, e *Engine) {
	t.Helper()
	if _, err := e.db.Exec("CALL truncate_duckdb_logs()"); err != nil {
		t.Fatal(err)
	}
}

// httpSummary groups logged HTTP requests by kind: count and summed duration.
func httpSummary(t *testing.T, e *Engine) string {
	t.Helper()
	rows, err := e.db.Query(`
		WITH r AS (
			SELECT regexp_extract(message, '''type'': (\w+)', 1) AS method,
			       regexp_extract(message, '''url'': ''([^'']+)''', 1) AS url,
			       regexp_extract(message, '''duration_ms'': (\d+)', 1)::INT AS ms
			FROM duckdb_logs WHERE type = 'HTTP')
		SELECT CASE WHEN url LIKE '%catalog.cloudflarestorage.com%' THEN 'catalog'
		            WHEN url LIKE '%.metadata.json%' THEN 'metadata.json'
		            WHEN url LIKE '%.avro%' THEN 'avro'
		            WHEN url LIKE '%.parquet%' THEN 'parquet'
		            ELSE 'other' END || '/' || method AS kind,
		       count(*), sum(ms)
		FROM r GROUP BY 1 ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var kind string
		var n, ms int64
		rows.Scan(&kind, &n, &ms)
		parts = append(parts, fmt.Sprintf("%s=%d(%dms)", kind, n, ms))
	}
	if len(parts) == 0 {
		return "no http"
	}
	return strings.Join(parts, " ")
}
