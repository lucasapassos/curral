package docs

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestCatalogNormalize(t *testing.T) {
	c := NewCatalog([]string{"Sales.main.Orders", "sales.main.salaries", "hr.main.salaries", "logs.main.events", "sales.main.orders"})
	doc := func(tables, schemas []string) *Doc {
		return &Doc{Context: Context{Tables: tables, Schemas: schemas}}
	}
	// Every name resolves: short, partly qualified, qualified in any case,
	// and duplicates collapse.
	d := doc([]string{"orders", " ORDERS ", "main.events", "HR.main.salaries"}, []string{"sales.MAIN", "hr.main"})
	if un, err := c.Normalize(d, true); err != nil || len(un) != 0 ||
		!slices.Equal(d.Context.Tables, []string{"Sales.main.Orders", "logs.main.events", "hr.main.salaries"}) ||
		!slices.Equal(d.Context.Schemas, []string{"Sales.main", "hr.main"}) {
		t.Fatalf("resolved: %v %v %+v", un, err, d.Context)
	}
	// Strict refuses unknown and ambiguous names, naming each, and changes
	// nothing.
	d = doc([]string{"orders", "salaries", "nope"}, []string{"main", "sales"})
	_, err := c.Normalize(d, true)
	var invalid *ValidationError
	if !errors.As(err, &invalid) || d.Context.Tables[0] != "orders" {
		t.Fatalf("strict: %v %+v", err, d.Context)
	}
	for _, want := range []string{
		`context.tables[1]: "salaries" fits several tables: sales.main.salaries, hr.main.salaries`,
		`context.tables[2]: "nope" is not a table in the catalog`,
		`context.schemas[0]: "main" fits several schemas: Sales.main, hr.main`,
		`context.schemas[1]: "sales" is not a schema in the catalog`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	// Lenient keeps what it cannot resolve, as written, and says which.
	un, err := c.Normalize(d, false)
	if err != nil || !slices.Equal(un, []string{"salaries", "nope", "main", "sales"}) ||
		!slices.Equal(d.Context.Tables, []string{"Sales.main.Orders", "salaries", "nope"}) ||
		!slices.Equal(d.Context.Schemas, []string{"main", "sales"}) {
		t.Fatalf("lenient: %v %v %+v", un, err, d.Context)
	}
	// Nothing to resolve is fine in an empty catalog.
	if un, err := NewCatalog(nil).Normalize(doc(nil, nil), true); err != nil || len(un) != 0 {
		t.Fatalf("empty: %v %v", un, err)
	}
}
