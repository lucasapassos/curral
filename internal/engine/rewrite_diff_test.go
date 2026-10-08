package engine

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
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
	from := []string{"orders o", "orders o JOIN crm.clients c ON c.id = o.id", "orders o, LATERAL (SELECT o.id + 1 AS z) l",
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
