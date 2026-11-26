package engine

import (
	"context"
	"crypto/sha256"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lucasapassos/curral/internal/policy"
)

// TestProtectDifferential checks the rewrite against an oracle: engine A
// reads orders through a row filter and a mask; engine B holds a copy of
// orders that already contains only those filtered, masked rows, with no
// protection. Every query must return the same result on both. A leak of a
// hidden row or a real value would make them differ.
var diffProt = map[string]Protection{"sales.main.orders": {
	Filter: "id % 3 <> 0 AND getvariable('curral_user') = 'ana'",
	Masks:  map[string]string{"amount": "CASE WHEN false THEN amount END", "note": "'***' || right(note, 1)"},
}}

// diffEngines returns the protected engine and its oracle.
func diffEngines(t testing.TB) (a, b *Engine) {
	prot := diffProt
	setup := []string{
		"ALTER TABLE sales.main.orders ADD COLUMN note VARCHAR",
		"INSERT INTO sales.main.orders SELECT range, range * 1.25, 'n' || range FROM range(3, 60)",
		"INSERT INTO sales.crm.clients SELECT range FROM range(0, 60, 2)",
		"CREATE VIEW sales.main.v_orders AS SELECT id, amount, note FROM sales.main.orders WHERE id > 5",
		"CREATE VIEW sales.main.v_orders_nested AS SELECT id, note FROM sales.main.v_orders WHERE id < 45",
		"CREATE VIEW sales.main.v_orders_alias(oid, amt, tag) AS SELECT id, amount, note FROM sales.main.orders",
		"CREATE SCHEMA sales.analytics",
		"CREATE VIEW sales.analytics.v_orders AS SELECT id, amount, note FROM sales.main.orders WHERE id >= 10",
	}
	a = newEngine(t, Options{QueryTimeout: 2 * time.Second})
	b = newEngine(t, Options{QueryTimeout: 2 * time.Second})
	for _, e := range []*Engine{a, b} {
		for _, q := range setup {
			if _, err := e.db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The oracle: materialize exactly what the protection should expose.
	conn, _ := b.db.Conn(context.Background())
	conn.ExecContext(context.Background(), "SET VARIABLE curral_user = 'ana'")
	if _, err := conn.ExecContext(context.Background(),
		"CREATE OR REPLACE TABLE sales.main.orders AS "+protectionSQL("sales.main.orders", prot["sales.main.orders"])); err != nil {
		t.Fatal(err)
	}
	conn.Close()
	return a, b
}

// diffRun runs sql and returns its rows sorted, as text.
func diffRun(e *Engine, sql string, p map[string]Protection) (string, error) {
	var out []string
	err := e.Query(context.Background(), Request{SQL: sql, Protect: &p, User: "ana"},
		func(context.Context, Inspection) error { return nil },
		func(cols []Column, rs Rows) error {
			for {
				dest := make([]driver.Value, len(cols))
				if err := rs.Next(dest); err != nil {
					return nil
				}
				out = append(out, fmt.Sprint(dest))
			}
		})
	slices.Sort(out)
	return strings.Join(out, "\n"), err
}

func TestProtectDifferential(t *testing.T) {
	a, b := diffEngines(t)
	queries := []string{
		"SELECT * FROM orders",
		"SELECT count(*), count(amount), sum(id) FROM orders",
		"SELECT id FROM orders WHERE amount > 10",
		"SELECT id FROM orders WHERE amount IS NULL",
		"SELECT note FROM orders WHERE note LIKE 'n1%'",
		"SELECT id, note FROM orders WHERE note = 'n4'",
		"SELECT o.id FROM orders o JOIN crm.clients c ON c.id = o.id",
		"SELECT count(*) FROM orders a JOIN orders b ON a.id = b.id + 1",
		"SELECT c.id FROM crm.clients c WHERE c.id NOT IN (SELECT id FROM orders)",
		"SELECT id % 5 AS k, count(*), max(note) FROM orders GROUP BY ALL",
		"WITH x AS (SELECT * FROM orders WHERE id > 20) SELECT count(*) FROM x a, x b WHERE a.id < b.id",
		"SELECT id, row_number() OVER (ORDER BY id DESC) FROM orders QUALIFY row_number() OVER (ORDER BY id DESC) <= 5",
		"SELECT * FROM orders ORDER BY id LIMIT 3 OFFSET 2",
		"SELECT exists(SELECT 1 FROM orders WHERE id = 3), exists(SELECT 1 FROM orders WHERE id = 4)",
		"SELECT (SELECT max(id) FROM orders) - (SELECT min(id) FROM orders)",
		"SELECT * FROM orders UNION SELECT * FROM orders",
		"SELECT * FROM orders EXCEPT SELECT * FROM orders WHERE id > 10",
		"SELECT list(id ORDER BY id) FROM orders",
		"SELECT o.* EXCLUDE (amount) FROM orders o WHERE o.id BETWEEN 5 AND 15",
		"FROM orders SELECT note, id WHERE id < 9",
		"SELECT id FROM orders, LATERAL (SELECT orders.id * 2 AS d) WHERE d > 40",
		"SELECT DISTINCT length(note) FROM orders",
		"SELECT * FROM v_orders",
		"SELECT id, note FROM v_orders_nested ORDER BY id",
		"SELECT oid, amt, tag FROM v_orders_alias WHERE oid < 25",
		"SELECT u.x, u.y FROM v_orders_alias AS u(x, y, z) WHERE u.x < 25",
		"SELECT id, amount, note FROM analytics.v_orders WHERE id < 30",
		"SELECT v.id, o.note FROM v_orders v JOIN orders o ON v.id = o.id WHERE v.id < 20",
		"SELECT v.id, c.id FROM v_orders v JOIN crm.clients c ON v.id = c.id",
	}
	for _, q := range queries {
		got, err := diffRun(a, q, diffProt)
		if err != nil {
			t.Errorf("%s: protected run failed: %v", q, err)
			continue
		}
		want, err := diffRun(b, q, nil)
		if err != nil {
			t.Fatalf("%s: oracle failed: %v", q, err)
		}
		if got != want {
			t.Errorf("%s\n protected:\n%.300s\n oracle:\n%.300s", q, got, want)
		}
	}
}

// FuzzProtectDifferential composes SELECTs over the protected table from
// random parts and compares them with the oracle. Statements the protected
// side refuses (fail closed) are fine; different results are a leak.
//
//	go test ./internal/engine -run '^$' -fuzz FuzzProtectDifferential -fuzztime 2m
func FuzzProtectDifferential(f *testing.F) {
	for i := range 32 {
		f.Add(uint8(i), uint8(i*3), uint8(i*5), uint8(i*7))
	}
	a, b := diffEngines(f)
	sel := []string{"*", "count(*)", "id, amount", "note", "sum(id), max(note)", "amount IS NULL, count(*)", "DISTINCT id % 4", "o.id, c.id"}
	from := []string{"orders o", "v_orders o", "orders o JOIN crm.clients c ON c.id = o.id", "orders o, LATERAL (SELECT o.id + 1 AS z) l",
		"(SELECT * FROM orders WHERE id < 40) o", "orders o LEFT JOIN crm.clients c USING (id)", "crm.clients c JOIN orders o ON o.id = c.id + 1"}
	where := []string{"", "WHERE o.id > 10", "WHERE o.amount = 5", "WHERE o.note LIKE 'n2%'", "WHERE o.id IN (SELECT id FROM orders)",
		"WHERE NOT EXISTS (SELECT 1 FROM orders x WHERE x.id = o.id + 1)", "WHERE o.amount > 0 OR o.amount IS NULL", "WHERE o.note = '***5'"}
	tail := []string{"", "GROUP BY ALL", "ORDER BY 1 LIMIT 3", "UNION ALL SELECT 1"}
	f.Fuzz(func(t *testing.T, s, fr, w, tl uint8) {
		q := fmt.Sprintf("SELECT %s FROM %s %s %s", sel[int(s)%len(sel)], from[int(fr)%len(from)], where[int(w)%len(where)], tail[int(tl)%len(tail)])
		want, err := diffRun(b, q, nil)
		if err != nil {
			return // not a valid query for this shape
		}
		got, err := diffRun(a, q, diffProt)
		if err != nil {
			if errors.Is(err, ErrForbidden) {
				return // refused: safe
			}
			t.Fatalf("%s: protected run failed but oracle succeeded: %v", q, err)
		}
		if got != want {
			t.Fatalf("LEAK or loss: %s\n protected:\n%.300s\n oracle:\n%.300s", q, got, want)
		}
	})
}

func TestProtectMaskPresets(t *testing.T) {
	ctx := context.Background()
	e := newEngine(t, Options{QueryTimeout: 5 * time.Second})
	setup := []string{
		`CREATE TABLE sales.main.customers (id INT, uid VARCHAR, email VARCHAR, name VARCHAR)`,
		`INSERT INTO sales.main.customers VALUES
			(1, 'u-100', 'alice@example.com', 'Alice'),
			(2, 'u-100', 'no-at-sign', 'Bo'),
			(3, 'u-200', '@nodomain.com', 'C'),
			(4, NULL, NULL, NULL)`,
		`CREATE TABLE sales.main.events (event_id INT, uid VARCHAR)`,
		`INSERT INTO sales.main.events VALUES
			(10, 'u-100'),
			(11, 'u-200'),
			(12, 'u-999'),
			(13, NULL)`,
	}
	for _, q := range setup {
		if _, err := e.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}

	regoFile := filepath.Join(t.TempDir(), "masks.rego")
	if err := os.WriteFile(regoFile, []byte(`package curral
import rego.v1
allow := true
masks := {
	"sales.main.customers": {
		"uid": "hash",
		"email": "email",
		"name": "first:2",
	},
	"sales.main.events": {
		"uid": "hash",
	},
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.LoadQueries(ctx, []string{regoFile}, policy.Queries{
		Allow: "data.curral.allow",
		Masks: "data.curral.masks",
	})
	if err != nil {
		t.Fatal(err)
	}
	masks, err := pol.Masks(ctx, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	prot := map[string]Protection{}
	for tbl, cols := range masks {
		prot[tbl] = Protection{Masks: cols}
	}

	run := func(sql, salt string) ([][]driver.Value, error) {
		var rows [][]driver.Value
		err := e.Query(ctx, Request{SQL: sql, Protect: &prot, User: "ana", MaskSalt: salt},
			func(context.Context, Inspection) error { return nil },
			func(cols []Column, rs Rows) error {
				for {
					dest := make([]driver.Value, len(cols))
					if err := rs.Next(dest); err != nil {
						return nil
					}
					rows = append(rows, dest)
				}
			})
		return rows, err
	}

	// Fail-closed when MaskSalt is empty.
	if _, err := run("SELECT id, uid FROM sales.main.customers", ""); !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "hash mask requires --mask-salt") {
		t.Fatalf("empty salt: got err=%v, want ErrForbidden with 'hash mask requires --mask-salt'", err)
	}

	salt := "s3cr3t-salt"
	wantHash := func(v string) string {
		sum := sha256.Sum256([]byte(salt + ":" + v))
		return hex.EncodeToString(sum[:])
	}

	// Verify hash, email, first:2 values and NULL preservation.
	rows, err := run("SELECT id, uid, email, name FROM sales.main.customers ORDER BY id", salt)
	if err != nil {
		t.Fatalf("select customers: %v", err)
	}
	wantRows := [][]driver.Value{
		{int32(1), wantHash("u-100"), "a***@example.com", "Al***"},
		{int32(2), wantHash("u-100"), "***", "Bo***"},
		{int32(3), wantHash("u-200"), "***", "C***"},
		{int32(4), nil, nil, nil},
	}
	if len(rows) != len(wantRows) {
		t.Fatalf("got %d rows, want %d: %v", len(rows), len(wantRows), rows)
	}
	for i := range wantRows {
		if fmt.Sprint(rows[i]) != fmt.Sprint(wantRows[i]) {
			t.Errorf("row %d: got %#v, want %#v", i, rows[i], wantRows[i])
		}
	}

	// Different salt produces a different hash.
	otherRows, err := run("SELECT uid FROM sales.main.customers WHERE id = 1", "other-salt")
	if err != nil {
		t.Fatalf("other salt: %v", err)
	}
	if len(otherRows) != 1 || otherRows[0][0] == wantHash("u-100") {
		t.Fatalf("different salt should change hash: got %v", otherRows)
	}

	// Deterministic COUNT(DISTINCT uid) on hash-masked column (u-100, u-200; NULL ignored).
	distinctRows, err := run("SELECT COUNT(DISTINCT uid) FROM sales.main.customers", salt)
	if err != nil {
		t.Fatalf("count distinct: %v", err)
	}
	if len(distinctRows) != 1 || fmt.Sprint(distinctRows[0][0]) != "2" {
		t.Fatalf("count distinct uid = %v, want 2", distinctRows)
	}

	// Deterministic JOIN across two hash-masked tables (NULLs don't join).
	joinRows, err := run(`
		SELECT c.id, e.event_id
		FROM sales.main.customers c
		JOIN sales.main.events e ON c.uid = e.uid
		ORDER BY c.id, e.event_id`, salt)
	if err != nil {
		t.Fatalf("join on hashed uid: %v", err)
	}
	wantJoin := [][]driver.Value{
		{int32(1), int32(10)},
		{int32(2), int32(10)},
		{int32(3), int32(11)},
	}
	if fmt.Sprint(joinRows) != fmt.Sprint(wantJoin) {
		t.Fatalf("join rows = %v, want %v", joinRows, wantJoin)
	}

	// Salt must NOT be exposed via DuckDB session variables or EXPLAIN.
	if leakRows, err := run("SELECT getvariable('curral_mask_salt') FROM sales.main.customers LIMIT 1", salt); err == nil {
		if strings.Contains(fmt.Sprint(leakRows), salt) {
			t.Fatalf("curral_mask_salt leaked via getvariable: %v", leakRows)
		}
	}
	if _, err := run("EXPLAIN SELECT uid FROM sales.main.customers", salt); !errors.Is(err, ErrForbidden) {
		t.Fatalf("EXPLAIN on hash-masked table: got err=%v, want ErrForbidden", err)
	}
}
