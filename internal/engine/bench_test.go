package engine

import (
	"context"
	duckdb "github.com/duckdb/duckdb-go/v2"
	"testing"
)

func BenchmarkQuerySelect1(b *testing.B) {
	e := newEngine(b, Options{MaxConcurrency: 8})
	for b.Loop() {
		if _, _, err := run(e, Request{SQL: "SELECT 1"}, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkQueryTable(b *testing.B) {
	e := newEngine(b, Options{MaxConcurrency: 8})
	for b.Loop() {
		if _, _, err := run(e, Request{SQL: "SELECT * FROM orders WHERE id = 1"}, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkConnUse(b *testing.B) {
	e := newEngine(b, Options{MaxConcurrency: 8})
	ctx := context.Background()
	for b.Loop() {
		c, _ := e.db.Conn(ctx)
		c.ExecContext(ctx, `USE "sales"`)
		c.Close()
	}
}

func BenchmarkPlanTables(b *testing.B) {
	e := newEngine(b, Options{MaxConcurrency: 8})
	ctx := context.Background()
	c, _ := e.db.Conn(ctx)
	defer c.Close()
	for b.Loop() {
		c.Raw(func(dc any) error {
			_, _, err := planSources(ctx, dc.(*duckdb.Conn), "SELECT * FROM orders WHERE id = 1", nil)
			return err
		})
	}
}
