package engine

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// FuzzWriteTargets checks the property the policy relies on: when inspection
// says it fully resolved a statement, every object the statement actually
// changes is among the reported targets. It executes each input for real and
// diffs a snapshot of all catalogs (rows, columns, objects) before and after.
//
//	go test ./internal/engine -run '^$' -fuzz FuzzWriteTargets -fuzztime 2m
//
// Without -fuzz only the seed corpus runs, as a regular test.
func FuzzWriteTargets(f *testing.F) {
	for _, s := range writeSeeds {
		f.Add(s)
	}
	e := newEngine(f, Options{MaxConcurrency: 1, QueryTimeout: 2 * time.Second})
	f.Fuzz(func(t *testing.T, sql string) {
		if len(sql) > 4096 {
			return
		}
		resetFixtures(t, e)
		before := snapshot(t, e)
		var insp Inspection
		var inspected bool
		_, _, err := run(e, Request{SQL: sql}, func(_ context.Context, i Inspection) error {
			insp, inspected = i, true
			return nil
		})
		after := snapshot(t, e)
		changed := diff(before, after)
		if len(changed) == 0 {
			return
		}
		if !inspected {
			t.Fatalf("objects changed without reaching authorization: %v\nsql: %q\nerr: %v", changed, sql, err)
		}
		if !insp.Resolved {
			return // the policy is told it cannot trust the inspection
		}
		for _, obj := range changed {
			if !covered(obj, insp.Targets) {
				t.Fatalf("BYPASS: %s changed but inspection reported targets %v (resolved)\nsql: %q\nerr: %v",
					obj, insp.Targets, sql, err)
			}
		}
	})
}

var writeSeeds = []string{
	"INSERT INTO orders VALUES (10, 1)",
	"INSERT INTO sales.orders VALUES (10, 1)",
	"INSERT INTO sales.main.orders VALUES (10, 1)",
	`INSERT INTO "orders" VALUES (10, 1)`,
	`insert into "ORDERS" values (10, 1)`,
	"INSERT OR REPLACE INTO orders VALUES (1, 2)",
	"INSERT INTO orders BY NAME SELECT 11 AS id, 2 AS amount",
	"INSERT INTO crm.clients SELECT id FROM orders",
	"WITH x AS (SELECT 1 AS id) INSERT INTO crm.clients SELECT id FROM x",
	"WITH x AS (SELECT $$) INSERT INTO logs.events VALUES (1) -- $$) INSERT INTO crm.clients VALUES (42)",
	"WITH x AS (SELECT /* /* */ ) INSERT INTO logs.events VALUES (1) -- */ 1) INSERT INTO crm.clients VALUES (42)",
	"INSERT /* INTO crm.clients */ INTO orders VALUES (12, 1)",
	"INSERT INTO -- crm.clients\norders VALUES (13, 1)",
	"UPDATE orders SET amount = amount + 1",
	"UPDATE orders SET amount = c.id FROM crm.clients c WHERE c.id = orders.id",
	"UPDATE orders o SET amount = 0 WHERE o.id = 1",
	"DELETE FROM orders WHERE id = 1",
	"DELETE FROM orders USING crm.clients c WHERE c.id = orders.id",
	"TRUNCATE orders",
	"TRUNCATE TABLE crm.clients",
	"MERGE INTO orders USING (SELECT 1 AS id) s ON orders.id = s.id WHEN MATCHED THEN DELETE",
	"MERGE INTO crm.clients c USING orders o ON c.id = o.id WHEN NOT MATCHED THEN INSERT VALUES (o.id)",
	"CREATE TABLE t1 AS SELECT * FROM orders",
	"CREATE OR REPLACE TABLE orders AS SELECT 1 AS id, 2 AS amount",
	"CREATE TABLE IF NOT EXISTS crm.t2 (a INT)",
	"CREATE TABLE memory.t3 (a INT)",
	"CREATE TABLE memory.main.t4 (a INT)",
	"CREATE VIEW v1 AS SELECT * FROM orders",
	"CREATE OR REPLACE VIEW big_orders AS SELECT 1 AS x",
	"CREATE SCHEMA s1",
	"CREATE SCHEMA IF NOT EXISTS sales.s2",
	"CREATE SEQUENCE seq1",
	"CREATE MACRO m1(a) AS a + 1",
	"CREATE OR REPLACE MACRO m2(a) AS TABLE SELECT a",
	"CREATE INDEX i1 ON orders(id)",
	"DROP TABLE orders",
	"DROP TABLE IF EXISTS crm.clients",
	"DROP VIEW big_orders",
	"DROP SCHEMA crm CASCADE",
	"DROP SEQUENCE IF EXISTS seq1",
	"ALTER TABLE orders ADD COLUMN note VARCHAR",
	"ALTER TABLE orders RENAME TO orders_old",
	"ALTER TABLE orders RENAME COLUMN amount TO total",
	"ALTER TABLE crm.clients RENAME TO c2",
	"ALTER VIEW big_orders RENAME TO bo",
	"COMMENT ON TABLE orders IS 'x'",
	"SELECT * FROM orders",
	"SELECT nextval('seq1')",
	"CHECKPOINT",
	"COPY orders FROM '/tmp/x.csv'",
}

// resetFixtures recreates what earlier inputs may have dropped or renamed.
func resetFixtures(t *testing.T, e *Engine) {
	t.Helper()
	for _, q := range []string{
		"CREATE OR REPLACE TABLE sales.main.orders(id INT, amount DECIMAL(10,2))",
		"INSERT INTO sales.main.orders VALUES (1, 10.50), (2, 20.00)",
		"CREATE SCHEMA IF NOT EXISTS sales.crm",
		"CREATE OR REPLACE TABLE sales.crm.clients(id INT)",
		"CREATE OR REPLACE VIEW sales.main.big_orders AS SELECT * FROM sales.main.orders WHERE amount > 15",
		"CREATE OR REPLACE TABLE memory.main.scratch(id INT)",
	} {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

// snapshot fingerprints every user object in every catalog.
func snapshot(t *testing.T, e *Engine) map[string]string {
	t.Helper()
	out := map[string]string{}
	add := func(q string, withData bool) {
		rows, err := e.db.Query(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		var objs [][3]string
		for rows.Next() {
			var db, schema, name, extra string
			if err := rows.Scan(&db, &schema, &name, &extra); err != nil {
				t.Fatal(err)
			}
			key := db + "." + schema + "." + name
			out[key] = extra
			objs = append(objs, [3]string{db, schema, name})
		}
		rows.Close()
		if !withData {
			return
		}
		for _, o := range objs {
			var fp string
			q := fmt.Sprintf(`SELECT count(*) || ':' || coalesce(sum(hash(t))::VARCHAR, '') FROM %s.%s.%s t`,
				quoteIdent(o[0]), quoteIdent(o[1]), quoteIdent(o[2]))
			if err := e.db.QueryRow(q).Scan(&fp); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
			out[o[0]+"."+o[1]+"."+o[2]] += "|" + fp
		}
	}
	add(`SELECT database_name, schema_name, table_name,
	        (SELECT string_agg(column_name || ' ' || data_type, ',' ORDER BY column_index)
	         FROM duckdb_columns() c WHERE c.table_oid = t.table_oid) || '|' || coalesce(comment::VARCHAR, '')
	     FROM duckdb_tables() t WHERE NOT internal AND database_name NOT IN ('system', 'temp')`, true)
	add(`SELECT database_name, schema_name, view_name, sql FROM duckdb_views()
	     WHERE NOT internal AND database_name NOT IN ('system', 'temp')`, false)
	add(`SELECT database_name, schema_name, '*', 'schema' FROM duckdb_schemas()
	     WHERE NOT internal AND database_name NOT IN ('system', 'temp')`, false)
	add(`SELECT database_name, schema_name, sequence_name, 'sequence' FROM duckdb_sequences()
	     WHERE database_name NOT IN ('system', 'temp')`, false)
	add(`SELECT database_name, schema_name, function_name, coalesce(macro_definition, '') FROM duckdb_functions()
	     WHERE NOT internal AND function_type IN ('macro', 'table_macro') AND database_name NOT IN ('system', 'temp')`, false)
	return out
}

// diff lists objects created, dropped or modified.
func diff(before, after map[string]string) []string {
	var out []string
	for k, v := range before {
		if a, ok := after[k]; !ok || a != v {
			out = append(out, k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

// covered reports whether obj (catalog.schema.name, or catalog.schema.* for a
// schema) is among targets, case-insensitively. A schema target covers
// everything inside it.
func covered(obj string, targets []string) bool {
	parts := strings.SplitN(obj, ".", 3)
	for _, t := range targets {
		switch {
		case strings.EqualFold(t, obj):
			return true
		case strings.HasSuffix(t, ".*") && len(parts) == 3 &&
			strings.EqualFold(strings.TrimSuffix(t, ".*"), parts[0]+"."+parts[1]):
			return true
		}
	}
	return false
}

// FuzzWriteTargetsGrammar builds valid statements from templates, varying
// object names and the noise between tokens (comments that mention other
// tables, newlines, quoting, case), so most inputs reach execution.
//
//	go test ./internal/engine -run '^$' -fuzz FuzzWriteTargetsGrammar -fuzztime 2m
func FuzzWriteTargetsGrammar(f *testing.F) {
	for i := range 64 {
		f.Add(uint8(i), uint8(i*7), uint8(i*13), uint64(i)*0x9e3779b97f4a7c15)
	}
	e := newEngine(f, Options{MaxConcurrency: 1, QueryTimeout: 2 * time.Second})
	f.Fuzz(func(t *testing.T, tmpl, tgt, src uint8, seed uint64) {
		sql := buildStatement(tmpl, tgt, src, seed)
		resetFixtures(t, e)
		before := snapshot(t, e)
		var insp Inspection
		var inspected bool
		_, _, err := run(e, Request{SQL: sql}, func(_ context.Context, i Inspection) error {
			insp, inspected = i, true
			return nil
		})
		changed := diff(before, snapshot(t, e))
		if len(changed) == 0 {
			return
		}
		if !inspected {
			t.Fatalf("objects changed without reaching authorization: %v\nsql: %q\nerr: %v", changed, sql, err)
		}
		if !insp.Resolved {
			return
		}
		for _, obj := range changed {
			if !covered(obj, insp.Targets) {
				t.Fatalf("BYPASS: %s changed but inspection reported targets %v (resolved)\nsql: %q", obj, insp.Targets, sql)
			}
		}
	})
}

var grammarTemplates = []string{
	"INSERT INTO {T} SELECT * FROM {S}",
	"INSERT OR REPLACE INTO {T} SELECT * FROM {S}",
	"WITH w AS ( SELECT * FROM {S} ) INSERT INTO {T} SELECT * FROM w",
	"UPDATE {T} SET id = id + 1",
	"UPDATE {T} SET id = s.id FROM {S} s",
	"DELETE FROM {T}",
	"DELETE FROM {T} USING {S} s WHERE true",
	"TRUNCATE {T}",
	"CREATE TABLE {N} AS SELECT * FROM {S}",
	"CREATE OR REPLACE TABLE {N} ( id INT )",
	"CREATE TABLE IF NOT EXISTS {N} ( id INT )",
	"CREATE VIEW {N} AS SELECT * FROM {S}",
	"CREATE SEQUENCE {N}",
	"CREATE MACRO {N} ( a ) AS a",
	"DROP TABLE {T}",
	"DROP TABLE IF EXISTS {T}",
	"ALTER TABLE {T} ADD COLUMN extra INT",
	"ALTER TABLE {T} RENAME TO renamed",
	"ALTER TABLE IF EXISTS {T} RENAME TO renamed2",
	"MERGE INTO {T} USING {S} s ON false WHEN NOT MATCHED THEN INSERT VALUES ( s.id )",
	"COMMENT ON TABLE {T} IS 'c'",
	"COMMENT ON COLUMN {T}.id IS 'c'",
	"CREATE SCHEMA {SC}",
	"DROP SCHEMA {SC} CASCADE",
}

// Tables with a compatible single INT "id" column, written several ways.
var grammarTables = []string{
	"crm.clients", "sales.crm.clients", `"crm"."clients"`, `CRM.CLIENTS`, `"sales".crm."clients"`,
	"orders", "sales.orders", "sales.main.orders", `"orders"`, "ORDERS", "main.orders",
	"logs.events", "memory.scratch",
}

var grammarNames = []string{
	"n1", "crm.n2", "sales.crm.n3", "memory.n4", "memory.main.n5", `"n 6"`, "temp.n7", "main.n8", "sales.n9",
}

var grammarSchemas = []string{"sc1", "crm", "sales.sc2", "memory.sc3", "logs.sc4"}

var grammarNoise = []string{
	" ", "  ", "\n", "\t", " /* c */ ", "\n-- INTO crm.clients\n", " /* INSERT INTO sales.crm.clients */ ",
	" /* ' \" */ ", "\n\n",
}

func buildStatement(tmpl, tgt, src uint8, seed uint64) string {
	r := seed | 1
	next := func(n int) int { // xorshift64
		r ^= r << 13
		r ^= r >> 7
		r ^= r << 17
		return int(r % uint64(n))
	}
	t := grammarTemplates[int(tmpl)%len(grammarTemplates)]
	t = strings.ReplaceAll(t, "{T}", grammarTables[int(tgt)%len(grammarTables)])
	t = strings.ReplaceAll(t, "{S}", grammarTables[int(src)%len(grammarTables)])
	t = strings.ReplaceAll(t, "{N}", grammarNames[int(tgt)%len(grammarNames)])
	t = strings.ReplaceAll(t, "{SC}", grammarSchemas[int(tgt)%len(grammarSchemas)])
	words := strings.Split(t, " ")
	var b strings.Builder
	for i, w := range words {
		if i > 0 {
			b.WriteString(grammarNoise[next(len(grammarNoise))])
		}
		if next(4) == 0 && !strings.ContainsAny(w, `"'.()`) {
			w = strings.ToLower(w)
		}
		b.WriteString(w)
	}
	return b.String()
}

// TestWriteTargetsExhaustive runs every grammar template against every target
// spelling (two noise seeds each) and checks the same property as the fuzzers.
// It also reports how many statements changed something while resolved, so a
// harness that silently stopped exercising writes would be noticed.
func TestWriteTargetsExhaustive(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	e := newEngine(t, Options{MaxConcurrency: 1, QueryTimeout: 2 * time.Second})
	var resolvedWrites, unresolvedWrites, noChange int
	unresolvedBy := map[string]int{}
	for tmpl := range len(grammarTemplates) {
		for tgt := range max(len(grammarTables), len(grammarNames), len(grammarSchemas)) {
			for _, seed := range []uint64{1, 0xdeadbeef} {
				sql := buildStatement(uint8(tmpl), uint8(tgt), uint8(tgt+3), seed)
				resetFixtures(t, e)
				before := snapshot(t, e)
				var insp Inspection
				run(e, Request{SQL: sql}, func(_ context.Context, i Inspection) error { insp = i; return nil })
				changed := diff(before, snapshot(t, e))
				switch {
				case len(changed) == 0:
					noChange++
				case !insp.Resolved:
					unresolvedWrites++
					unresolvedBy[grammarTemplates[tmpl]]++
				default:
					resolvedWrites++
					for _, obj := range changed {
						if !covered(obj, insp.Targets) {
							t.Errorf("BYPASS: %s changed, targets %v\nsql: %q", obj, insp.Targets, sql)
						}
					}
				}
			}
		}
	}
	t.Logf("resolved writes checked: %d, unresolved writes (denied by policy): %d, no change: %d",
		resolvedWrites, unresolvedWrites, noChange)
	for k, v := range unresolvedBy {
		t.Logf("  unresolved: %-70s %d", k, v)
	}
	if resolvedWrites < 100 {
		t.Fatalf("only %d resolved writes exercised; the harness is not reaching execution", resolvedWrites)
	}
}
