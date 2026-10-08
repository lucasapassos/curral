package engine

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// runProtected runs sql with orders protected (only id=1 visible, amount
// masked to 0) unless prot is given.
func runProtected(e *Engine, sql string, prot map[string]Protection, params ...any) ([][]driver.Value, error) {
	if prot == nil {
		prot = map[string]Protection{"sales.main.orders": {Filter: "id = 1", Masks: map[string]string{"amount": "0"}}}
	}
	var rows [][]driver.Value
	err := e.Query(context.Background(), Request{SQL: sql, Params: params, Protect: &prot, User: "ana", Roles: []string{"analyst"}},
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

func TestProtectRewrite(t *testing.T) {
	e := newEngine(t, Options{})
	cases := []struct {
		sql  string
		want string
	}{
		{"SELECT id, amount FROM orders ORDER BY id", "[[1 0]]"},
		{"SELECT o.id, o.amount FROM sales.main.orders AS o", "[[1 0]]"},
		{"SELECT count(*) FROM orders a JOIN orders b USING (id)", "[[1]]"},
		{"SELECT count(*) FROM crm.clients WHERE id IN (SELECT id FROM orders)", "[[0]]"},
		{"SELECT count(*) FROM orders WHERE amount = 10.50", "[[0]]"}, // no oracle on the real value
		{"SELECT max(amount) FROM orders", "[[0]]"},
		{"WITH orders AS (SELECT 5 AS id) SELECT id FROM orders", "[[5]]"}, // a CTE, not the table
		{"WITH x AS (SELECT * FROM orders) SELECT count(*) FROM x a, x b", "[[1]]"},
		{"SELECT p.x FROM orders AS p(x, y)", "[[1]]"},
		{"SELECT count(*) FROM orders, LATERAL (SELECT orders.id + 1 AS z)", "[[1]]"},
	}
	for _, c := range cases {
		rows, err := runProtected(e, c.sql, nil)
		if err != nil || fmt.Sprint(rows) != c.want {
			t.Errorf("%s\n  got %v err=%v, want %s", c.sql, rows, err, c.want)
		}
	}

	// Parameters survive the rewrite.
	if rows, err := runProtected(e, "SELECT id FROM orders WHERE id = $1", nil, int64(1)); err != nil || fmt.Sprint(rows) != "[[1]]" {
		t.Errorf("params: %v %v", rows, err)
	}
	// Session variables reach filters.
	prot := map[string]Protection{"sales.main.orders": {Filter: "getvariable('curral_user') = 'ana' AND list_contains(getvariable('curral_roles'), 'analyst')"}}
	if rows, err := runProtected(e, "SELECT count(*) FROM orders", prot); err != nil || fmt.Sprint(rows) != "[[2]]" {
		t.Errorf("session variables: %v %v", rows, err)
	}
	// Unprotected queries are untouched.
	if rows, err := runProtected(e, "SELECT count(*) FROM crm.clients", nil); err != nil || fmt.Sprint(rows) != "[[0]]" {
		t.Errorf("unprotected: %v %v", rows, err)
	}
}

func TestProtectRefusals(t *testing.T) {
	e := newEngine(t, Options{})
	for sql, want := range map[string]string{
		"SELECT * FROM big_orders":                      "indirectly", // view over the table
		"INSERT INTO crm.clients SELECT id FROM orders": "only be read with SELECT",
		"CREATE TABLE crm.copy AS SELECT * FROM orders": "only be read with SELECT",
		"SELECT * FROM orders TABLESAMPLE 50%":          "TABLESAMPLE",
		"EXPLAIN SELECT * FROM orders":                  "only be read with SELECT",
	} {
		_, err := runProtected(e, sql, nil)
		if !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", sql, err)
		}
	}
	// PIVOT expands into several statements and is refused before any check.
	if _, err := runProtected(e, "PIVOT orders ON id USING sum(amount)", nil); err == nil {
		t.Error("PIVOT accepted")
	}
	// The refused write left the table alone.
	_, rows, _ := run(e, Request{SQL: "SELECT count(*) FROM crm.clients"}, nil)
	if rows[0][0] != int64(0) {
		t.Fatalf("write happened: %v", rows)
	}
}

func TestCheckProtection(t *testing.T) {
	e := newEngine(t, Options{})
	ctx := context.Background()
	if err := e.CheckProtection(ctx, "sales.main.orders", Protection{Filter: "id > 0", Masks: map[string]string{"amount": "0"}}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []Protection{{Filter: "nope > 0"}, {Masks: map[string]string{"nope": "0"}}, {Filter: "id >"}} {
		if err := e.CheckProtection(ctx, "sales.main.orders", p); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	if err := e.CheckProtection(ctx, "orders", Protection{}); err == nil {
		t.Error("unqualified table accepted")
	}
}

// The rewrite cache must not skip the indirect-read check: a cached query
// whose view is later redefined to read the protected table is refused.
func TestProtectCacheStillChecksPlan(t *testing.T) {
	e := newEngine(t, Options{})
	if _, err := e.db.Exec("CREATE VIEW sales.crm.v AS SELECT id FROM sales.crm.clients"); err != nil {
		t.Fatal(err)
	}
	q := "SELECT count(*) FROM orders, crm.v"
	for i := range 2 { // second run is served from the cache
		if _, err := runProtected(e, q, nil); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if e.rewrites.len() == 0 {
		t.Fatal("rewrite not cached")
	}
	if _, err := e.db.Exec("CREATE OR REPLACE VIEW sales.crm.v AS SELECT id FROM sales.main.orders"); err != nil {
		t.Fatal(err)
	}
	if _, err := runProtected(e, q, nil); !errors.Is(err, ErrForbidden) || !strings.Contains(err.Error(), "indirectly") {
		t.Fatalf("redefined view through cached rewrite: %v", err)
	}
	// Same text, different protections: a separate cache entry.
	prot := map[string]Protection{"sales.main.orders": {Filter: "id = 2"}}
	if rows, err := runProtected(e, "SELECT id FROM orders", prot); err != nil || fmt.Sprint(rows) != "[[2]]" {
		t.Fatalf("different protection: %v %v", rows, err)
	}
	if rows, err := runProtected(e, "SELECT id FROM orders", nil); err != nil || fmt.Sprint(rows) != "[[1]]" {
		t.Fatalf("original protection: %v %v", rows, err)
	}
}

func TestLRU(t *testing.T) {
	c := newLRU[int](2)
	c.put("a", 1)
	c.put("b", 2)
	c.get("a") // a is now most recent
	c.put("c", 3)
	if _, ok := c.get("b"); ok {
		t.Fatal("b should have been evicted")
	}
	if v, ok := c.get("a"); !ok || v != 1 || c.len() != 2 {
		t.Fatalf("a=%v ok=%v len=%d", v, ok, c.len())
	}
}

func TestUsesSessionVariables(t *testing.T) {
	e := newEngine(t, Options{})
	if _, err := e.db.Exec("CREATE MACRO sales.main.my_user() AS getvariable('curral_user')"); err != nil {
		t.Fatal(err)
	}
	conn, _ := e.db.Conn(context.Background())
	defer conn.Close()
	for filter, want := range map[string]bool{
		"id > 1":                                  false,
		"upper(CAST(id AS VARCHAR)) <> 'x'":       false,
		"getvariable('curral_user') = 'ana'":      true,
		"GETVARIABLE('curral_roles') IS NOT NULL": true,
		"sales.main.my_user() = 'ana'":            true, // a user macro might read variables
	} {
		var got bool
		conn.Raw(func(dc any) error {
			got, _ = e.usesSessionVariables(context.Background(), dc.(*duckdb.Conn), protectionSQL("sales.main.orders", Protection{Filter: filter}))
			return nil
		})
		if got != want {
			t.Errorf("%s: got %v", filter, got)
		}
	}
	// A filter through a user macro still sees the caller.
	prot := map[string]Protection{"sales.main.orders": {Filter: "sales.main.my_user() = 'ana'"}}
	if rows, err := runProtected(e, "SELECT count(*) FROM orders", prot); err != nil || fmt.Sprint(rows) != "[[2]]" {
		t.Fatalf("macro filter: %v %v", rows, err)
	}
}
