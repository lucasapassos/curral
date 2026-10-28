package docs

import "testing"

func TestScopeReadable(t *testing.T) {
	// Two databases share a salaries table; the reader may query only one
	// of them, plus orders. An unqualified "main" and the bare catalog of
	// the sandbox database add nothing readable.
	all := []string{"sales.main.orders", "Sales.Main.Orders", "sales.main.salaries", "hr.main.salaries", "hr.main.reviews", "logs.main.events", "orphan"}
	s := NewScope(all, []string{"SALES.main.orders", "sales.main.salaries", "orphan"})
	doc := func(tables, schemas []string) Doc {
		return Doc{Context: Context{Tables: tables, Schemas: schemas}}
	}
	for _, c := range []struct {
		name    string
		d       Doc
		want    bool
		because string
	}{
		{"no context", doc(nil, nil), true, "a document about nothing in particular is in every scope"},
		{"qualified readable", doc([]string{"sales.main.salaries"}, nil), true, "names a readable table"},
		{"qualified unreadable", doc([]string{"hr.main.salaries"}, nil), false, "names only an unreadable table"},
		{"short ambiguous", doc([]string{"salaries"}, nil), false, "fits an unreadable table too"},
		{"partly qualified ambiguous", doc([]string{"main.salaries"}, nil), false, "fits an unreadable table too"},
		{"short unambiguous", doc([]string{" Orders "}, nil), true, "fits only a readable table, whatever the case or spaces"},
		{"one readable among many", doc([]string{"hr.main.reviews", "orders"}, nil), true, "one readable name suffices"},
		{"unknown", doc([]string{"nope"}, nil), false, "fits nothing in the catalog"},
		{"unqualified catalog entry", doc([]string{"orphan"}, nil), true, "a table without schema is matched as is"},
		{"schema qualified", doc(nil, []string{"sales.main"}), true, "a schema with a readable table"},
		{"schema unreadable", doc(nil, []string{"hr.main"}), false, "no readable table in it"},
		{"schema short ambiguous", doc(nil, []string{"main"}), false, "every database has a main schema"},
		{"schema is not a database", doc(nil, []string{"sales"}), false, "a database name fits no schema"},
		{"schema unknown", doc(nil, []string{"crm.main"}), false, "fits nothing in the catalog"},
		{"tables over schemas", doc([]string{"hr.main.salaries"}, []string{"sales.main"}), false, "tables decide when named"},
		{"tables over schemas, readable", doc([]string{"orders"}, []string{"hr.main"}), true, "tables decide when named"},
	} {
		if got := s.Readable(c.d); got != c.want {
			t.Errorf("%s: readable=%v, want %v (%s)", c.name, got, c.want, c.because)
		}
	}
	if NewScope(nil, nil).Readable(doc([]string{"orders"}, nil)) {
		t.Error("an empty catalog shows no document about a table")
	}
}
