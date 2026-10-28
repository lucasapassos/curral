package docs

import (
	"fmt"
	"slices"
	"strings"
)

// Catalog resolves the table and schema names a writer gives to the objects
// of the catalog, so documents are saved with fully qualified names and
// readers (and scopes) match them exactly. Names are compared ignoring
// case; the catalog's own spelling is kept.
type Catalog struct {
	tables  map[string][]string // the tables a name fits, by each suffix
	schemas map[string][]string // the schemas a name fits, likewise
}

// NewCatalog indexes the qualified names (database.schema.table) of every
// table in the catalog, and the schemas they are in.
func NewCatalog(tables []string) *Catalog {
	c := &Catalog{tables: map[string][]string{}, schemas: map[string][]string{}}
	seen := map[string]bool{}
	for _, t := range tables {
		if k := strings.ToLower(t); !seen[k] {
			seen[k] = true
			indexAs(c.tables, t)
		}
		if sc := schemaOf(t); sc != "" {
			if k := strings.ToLower(sc); !seen[k] {
				seen[k] = true
				indexAs(c.schemas, sc)
			}
		}
	}
	return c
}

// indexAs is index keeping the original spelling as the value.
func indexAs(m map[string][]string, name string) {
	parts := strings.Split(strings.ToLower(name), ".")
	for i := range parts {
		k := strings.Join(parts[i:], ".")
		m[k] = append(m[k], name)
	}
}

// resolve names the one object name fits, or says why it fits none. The
// candidates of an ambiguous name are not listed: the writer learns that
// the name exists in several places, not where.
func resolve(idx map[string][]string, kind, name string) (string, error) {
	objs := idx[strings.ToLower(strings.TrimSpace(name))]
	switch len(objs) {
	case 0:
		return "", fmt.Errorf("%q is not a %s in the catalog", name, kind)
	case 1:
		return objs[0], nil
	}
	return "", fmt.Errorf("%q fits several %ss; qualify it", name, kind)
}

// Normalize rewrites the tables and schemas d names to their qualified
// catalog names, dropping duplicates. A name that fits nothing or several
// objects is an error (the write is refused) when strict; otherwise it is
// kept as written and returned, for the caller to log.
func (c *Catalog) Normalize(d *Doc, strict bool) (unresolved []string, err error) {
	var problems []string
	fix := func(idx map[string][]string, field, kind string, names []string) []string {
		var out []string
		for i, n := range names {
			q, err := resolve(idx, kind, n)
			if err != nil {
				problems = append(problems, fmt.Sprintf("context.%s[%d]: %v", field, i, err))
				unresolved = append(unresolved, n)
				q = n
			}
			if !slices.ContainsFunc(out, func(s string) bool { return strings.EqualFold(s, q) }) {
				out = append(out, q)
			}
		}
		return out
	}
	tables := fix(c.tables, "tables", "table", d.Context.Tables)
	schemas := fix(c.schemas, "schemas", "schema", d.Context.Schemas)
	if strict && len(problems) > 0 {
		return nil, invalid("%s", strings.Join(problems, "; "))
	}
	d.Context.Tables, d.Context.Schemas = tables, schemas
	return unresolved, nil
}
