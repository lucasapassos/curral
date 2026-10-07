package engine

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"testing"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

func TestASTSources(t *testing.T) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, _ := db.Conn(context.Background())
	defer conn.Close()

	cases := []struct {
		sql    string
		tables []string
		funcs  []string
	}{
		{"SELECT * FROM lake.s.t", []string{"lake.s.t"}, nil},
		{"SELECT * FROM a JOIN b USING (id)", []string{"a", "b"}, nil},
		{"WITH c AS (SELECT * FROM s.real) SELECT * FROM c", []string{"s.real"}, nil},
		// A CTE only hides names inside the query node that defines it.
		{"SELECT * FROM (WITH pii AS (SELECT 1) SELECT * FROM pii), pii", []string{"pii"}, nil},
		// A qualified name is never a CTE.
		{"WITH t AS (SELECT 1) SELECT * FROM t, s.t", []string{"s.t"}, nil},
		{"WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT * FROM r", nil, nil},
		{"SELECT * FROM x WHERE id IN (SELECT id FROM y) UNION SELECT * FROM iceberg_scan('s3://b/t')", []string{"x", "y"}, []string{"iceberg_scan"}},
	}
	for _, c := range cases {
		var tables [][]string
		var funcs []string
		err := conn.Raw(func(dc any) error {
			var err error
			tables, funcs, err = astSources(context.Background(), dc.(*duckdb.Conn), c.sql)
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", c.sql, err)
		}
		var got []string
		for _, p := range tables {
			got = append(got, strings.Join(p, "."))
		}
		slices.Sort(got)
		if !slices.Equal(got, c.tables) || !slices.Equal(funcs, c.funcs) {
			t.Errorf("%s\n  tables=%v funcs=%v", c.sql, got, funcs)
		}
	}
}
