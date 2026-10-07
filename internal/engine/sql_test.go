package engine

import (
	"strings"
	"testing"

	"curral/internal/config"
)

func TestBootStatements(t *testing.T) {
	stmts, err := bootStatements(&config.Catalog{
		Extensions: []string{"iceberg"},
		Settings:   map[string]any{"s3_region": "us-east-1"},
		Secrets: []config.Secret{{Name: "s", Type: "s3", Params: map[string]any{
			"KEY_ID": "AK", "SECRET": "it's", "SCOPE": []any{"s3://a"},
		}}},
		Databases: []config.Database{
			{Name: "lake", Path: "wh", Options: map[string]any{"ENDPOINT": "http://x", "TYPE": "iceberg", "READ_ONLY": true}},
			{Name: "plain", Path: "/d/p.duckdb"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var sqls, logs []string
	for _, s := range stmts {
		sqls = append(sqls, s.sql)
		logs = append(logs, s.log)
	}
	want := []string{
		"INSTALL iceberg",
		"LOAD iceberg",
		"SET GLOBAL s3_region = 'us-east-1'",
		`CREATE OR REPLACE SECRET "s" (TYPE 's3', KEY_ID 'AK', SCOPE ['s3://a'], SECRET 'it''s')`,
		`ATTACH 'wh' AS "lake" (TYPE 'iceberg', ENDPOINT 'http://x', READ_ONLY true)`,
		`ATTACH '/d/p.duckdb' AS "plain"`,
	}
	if strings.Join(sqls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s", strings.Join(sqls, "\n"))
	}
	all := strings.Join(logs, "\n")
	if strings.Contains(all, "AK") || strings.Contains(all, "it''s") || strings.Contains(all, "/d/p.duckdb") {
		t.Fatalf("secret leaked to log:\n%s", all)
	}
}
