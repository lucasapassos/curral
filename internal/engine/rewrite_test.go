package engine

import (
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"strings"
	"testing"
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
