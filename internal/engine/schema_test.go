package engine

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"curral/internal/config"
)

func TestSchema(t *testing.T) {
	e := newEngine(t, Options{MaxConcurrency: 2})
	ctx := context.Background()
	_, _, err := run(e, Request{SQL: "CREATE TABLE notes(id INT NOT NULL, body VARCHAR)"}, allowAll)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"COMMENT ON TABLE notes IS 'free text'",
		"COMMENT ON COLUMN notes.body IS 'markdown'",
		"CREATE VIEW short_notes AS SELECT id FROM notes",
	} {
		if _, _, err := run(e, Request{SQL: s}, allowAll); err != nil {
			t.Fatal(s, err)
		}
	}

	all := func(context.Context, TableSchema, Inspection) (bool, error) { return true, nil }
	got, err := e.Schema(ctx, SchemaFilter{}, all)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]TableSchema{}
	for _, ts := range got {
		byName[ts.Qualified()] = ts
		if ts.Database != "sales" && ts.Database != "logs" {
			t.Errorf("non-catalog database listed: %s", ts.Qualified())
		}
	}
	notes, ok := byName["sales.main.notes"]
	if !ok || notes.Kind != "table" || notes.Comment != "free text" || len(notes.Columns) != 2 {
		t.Fatalf("notes: %+v", notes)
	}
	if c := notes.Columns[0]; c.Name != "id" || c.Type != "INTEGER" || c.Nullable {
		t.Errorf("id column: %+v", c)
	}
	if c := notes.Columns[1]; c.Name != "body" || !c.Nullable || c.Comment != "markdown" {
		t.Errorf("body column: %+v", c)
	}
	if v := byName["sales.main.short_notes"]; v.Kind != "view" || len(v.Columns) != 1 {
		t.Errorf("view: %+v", v)
	}

	// The callback sees the same inspection a SELECT * would get: a view's
	// base table, not the view.
	var seen Inspection
	got, err = e.Schema(ctx, SchemaFilter{Table: "SHORT_NOTES"}, func(_ context.Context, _ TableSchema, i Inspection) (bool, error) {
		seen = i
		return true, nil
	})
	if err != nil || len(got) != 1 {
		t.Fatalf("filter: %v %+v", err, got)
	}
	if len(seen.Tables) != 1 || seen.Tables[0] != "sales.main.notes" || seen.StatementType != "SELECT" || !seen.Resolved {
		t.Errorf("inspection: %+v", seen)
	}

	// Denied objects are left out.
	got, err = e.Schema(ctx, SchemaFilter{Database: "sales"}, func(_ context.Context, ts TableSchema, _ Inspection) (bool, error) {
		return ts.Name != "notes", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ts := range got {
		if ts.Name == "notes" || ts.Database != "sales" {
			t.Errorf("unexpected %s", ts.Qualified())
		}
	}
	if got, _ := e.Schema(ctx, SchemaFilter{Database: "nope"}, all); got == nil || len(got) != 0 {
		t.Errorf("empty listing must be [], got %#v", got)
	}
}

// A view whose base table was dropped cannot be queried, so it is skipped
// without failing the listing or the objects after it.
func TestSchemaBrokenView(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.duckdb")
	seed(t, path, "CREATE TABLE t(a INT)", "CREATE VIEW v AS SELECT a FROM t", "DROP TABLE t",
		"CREATE TABLE z(b INT)")
	cat := &config.Catalog{Databases: []config.Database{{Name: "x", Path: path}}, Default: "x"}
	e, err := Open(context.Background(), cat, Options{MaxConcurrency: 1}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	got, err := e.Schema(context.Background(), SchemaFilter{}, func(context.Context, TableSchema, Inspection) (bool, error) { return true, nil })
	if err != nil || len(got) != 1 || got[0].Name != "z" || len(got[0].Columns) != 1 {
		t.Fatalf("%v %+v", err, got)
	}
}

func TestSchemaCache(t *testing.T) {
	e := newEngine(t, Options{MaxConcurrency: 1, SchemaCacheTTL: time.Hour})
	ctx := context.Background()
	all := func(context.Context, TableSchema, Inspection) (bool, error) { return true, nil }
	has := func(name string) bool {
		got, err := e.Schema(ctx, SchemaFilter{Table: name}, all)
		if err != nil {
			t.Fatal(err)
		}
		return len(got) == 1
	}
	if !has("orders") {
		t.Fatal("orders missing")
	}

	// A cached listing needs no engine slot.
	e.sem <- struct{}{}
	done := make(chan bool)
	go func() { done <- has("orders") }()
	select {
	case ok := <-done:
		if !ok {
			t.Error("cached listing lost orders")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cached listing waited for a slot")
	}
	<-e.sem

	// Callers flagging columns do not change the snapshot.
	got, _ := e.Schema(ctx, SchemaFilter{Table: "orders"}, all)
	got[0].Columns[0].Masked = true
	if got, _ = e.Schema(ctx, SchemaFilter{Table: "orders"}, all); got[0].Columns[0].Masked {
		t.Error("snapshot shared with callers")
	}

	// DDL through the engine reloads it.
	if _, _, err := run(e, Request{SQL: "CREATE TABLE fresh(x INT)"}, allowAll); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !has("fresh") {
		if time.Now().After(deadline) {
			t.Fatal("new table never showed up")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, err := run(e, Request{SQL: "DROP TABLE fresh"}, allowAll); err != nil {
		t.Fatal(err)
	}
	for has("fresh") {
		if time.Now().After(deadline) {
			t.Fatal("dropped table still listed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
