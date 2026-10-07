package engine

import (
	"context"
	"errors"
	"testing"
)

func TestTokenizeFailsClosed(t *testing.T) {
	unsafe := []string{
		"SELECT $$ x $$",
		"SELECT $tag$ x $tag$",
		"SELECT /* outer /* inner */ still comment */ 1",
		"SELECT E'it\\'s'",
		"SELECT 'unterminated",
		"SELECT 1 /* unterminated",
	}
	for _, q := range unsafe {
		if _, ok := tokenize(q); ok {
			t.Errorf("%q: expected tokenizer to refuse", q)
		}
	}
	safe := []string{
		"SELECT $1, $2",
		"SELECT * FROM t WHERE a = $name",
		"SELECT 'it''s', \"a\"\"b\" -- $$ in a comment",
		"SELECT /* $$ */ 1",
		"SELECT e FROM t WHERE e = 'x'",
		"SELECT price$usd FROM t",
	}
	for _, q := range safe {
		if _, ok := tokenize(q); !ok {
			t.Errorf("%q: unexpectedly refused", q)
		}
	}
}

// Regression: a dollar-quoted string made the tokenizer report one INSERT
// target while DuckDB executed another.
func TestParserDifferentialFailsClosed(t *testing.T) {
	e := newEngine(t, Options{})
	exploits := []string{
		"WITH x AS (SELECT $$) INSERT INTO logs.events VALUES (1) -- $$) INSERT INTO crm.clients VALUES (42)",
		"WITH x AS (SELECT /* /* */ ) INSERT INTO logs.events VALUES (1) -- */ 1) INSERT INTO crm.clients VALUES (42)",
	}
	for _, q := range exploits {
		var insp Inspection
		err := e.Query(context.Background(), Request{SQL: q},
			func(_ context.Context, i Inspection) error { insp = i; return ErrForbidden },
			func([]Column, Rows) error { t.Fatal("must not execute"); return nil })
		if err != nil && !errors.Is(err, ErrForbidden) {
			continue // DuckDB rejected it outright: fine
		}
		if insp.Resolved {
			t.Errorf("%q: inspection must be unresolved, got %+v", q, insp)
		}
	}
	_, rows, _ := run(e, Request{SQL: "SELECT count(*) FROM crm.clients"}, nil)
	if rows[0][0] != int64(0) {
		t.Fatalf("crm.clients was written: %v", rows)
	}
}

func TestMergeInspection(t *testing.T) {
	e := newEngine(t, Options{})
	var insp Inspection
	err := e.Query(context.Background(), Request{SQL: "MERGE INTO orders USING (SELECT 1 AS id) s ON orders.id = s.id WHEN MATCHED THEN DELETE"},
		func(_ context.Context, i Inspection) error { insp = i; return ErrForbidden },
		func([]Column, Rows) error { return nil })
	if !errors.Is(err, ErrForbidden) || insp.StatementType != "MERGE" || !insp.Resolved ||
		len(insp.Targets) != 1 || insp.Targets[0] != "sales.main.orders" {
		t.Fatalf("err=%v inspection=%+v", err, insp)
	}
}

func TestUnhandledTypesUnresolved(t *testing.T) {
	e := newEngine(t, Options{})
	for _, q := range []string{"CALL pragma_version()", "VACUUM orders", "ANALYZE orders", "PRAGMA version"} {
		var insp Inspection
		e.Query(context.Background(), Request{SQL: q},
			func(_ context.Context, i Inspection) error { insp = i; return ErrForbidden },
			func([]Column, Rows) error { return nil })
		if insp.StatementType != "" && insp.Resolved {
			t.Errorf("%s: %s must be unresolved", q, insp.StatementType)
		}
	}
	if _, _, err := run(e, Request{SQL: "UPDATE EXTENSIONS"}, nil); !errors.Is(err, ErrForbidden) {
		t.Errorf("UPDATE EXTENSIONS: %v", err)
	}
}

func TestRedactSQL(t *testing.T) {
	cases := map[string]string{
		"SELECT * FROM t WHERE cpf = '123.456.789-00' AND age > 42":                  "SELECT * FROM t WHERE cpf = ? AND age > ?",
		"SELECT \"col 1\", x.y FROM t2 -- secret note\nWHERE v IN (1.5e3, .5, 0x1F)": "SELECT \"col 1\", x.y FROM t2 WHERE v IN (?, ?, ?)",
		"SELECT /* 999 */ a1, $1, $name FROM t":                                      "SELECT a1, $1, $name FROM t",
		"INSERT INTO t VALUES ('it''s', -7)":                                         "INSERT INTO t VALUES (?, -?)",
	}
	for in, want := range cases {
		got, ok := RedactSQL(in)
		if !ok || got != want {
			t.Errorf("%q\n got %q\nwant %q", in, got, want)
		}
	}
	if _, ok := RedactSQL("SELECT $$ secret $$"); ok {
		t.Error("dollar-quoted SQL must not be redacted")
	}
}
