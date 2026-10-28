package docs

import "strings"

// Scope is what a reader may see of a catalog: every table in it and the
// ones the reader may query, fully qualified as database.schema.table. It
// decides which documents the reader is shown.
type Scope struct {
	tables  map[string][]string // the tables a name fits, by each suffix of their names
	schemas map[string][]string // the schemas a name fits, likewise
	visible map[string]bool     // the readable tables and their schemas
}

// NewScope indexes the catalog (all) for a reader who may query visible.
// Names are compared ignoring case.
func NewScope(all, visible []string) *Scope {
	s := &Scope{tables: map[string][]string{}, schemas: map[string][]string{}, visible: map[string]bool{}}
	tables, schemas := map[string]bool{}, map[string]bool{}
	for _, t := range all {
		t = strings.ToLower(t)
		if tables[t] {
			continue
		}
		tables[t] = true
		index(s.tables, t)
		if sc := schemaOf(t); sc != "" && !schemas[sc] {
			schemas[sc] = true
			index(s.schemas, sc)
		}
	}
	for _, t := range visible {
		t = strings.ToLower(t)
		s.visible[t] = true
		if sc := schemaOf(t); sc != "" {
			s.visible[sc] = true
		}
	}
	return s
}

// index records name under each of its dot-separated suffixes, so
// "sales.main.orders" is found by "orders", "main.orders" and itself.
func index(m map[string][]string, name string) {
	parts := strings.Split(name, ".")
	for i := range parts {
		k := strings.Join(parts[i:], ".")
		m[k] = append(m[k], name)
	}
}

// schemaOf is the schema part of a qualified table name, empty when the
// name has none.
func schemaOf(table string) string {
	if i := strings.LastIndex(table, "."); i > 0 {
		return table[:i]
	}
	return ""
}

// Readable reports whether d may be shown to the reader: a document about
// no table or schema in particular always, one that names tables when it
// names a readable one, one that names only schemas when it names a schema
// with a readable table. A name matches a qualified name exactly or by its
// last parts, as in Filter, so a short name may fit several objects; it
// counts only when every object it fits is readable, so a name shared
// across databases never shows a document to someone who may read only
// one of them. A name fitting nothing in the catalog never counts.
func (s *Scope) Readable(d Doc) bool {
	if d.Unscoped() {
		return true
	}
	if len(d.Context.Tables) > 0 {
		return s.anyReadable(s.tables, d.Context.Tables)
	}
	return s.anyReadable(s.schemas, d.Context.Schemas)
}

// anyReadable reports whether some name in names fits only readable objects.
func (s *Scope) anyReadable(idx map[string][]string, names []string) bool {
	for _, n := range names {
		objs := idx[strings.ToLower(strings.TrimSpace(n))]
		if len(objs) == 0 {
			continue
		}
		readable := true
		for _, o := range objs {
			if !s.visible[o] {
				readable = false
				break
			}
		}
		if readable {
			return true
		}
	}
	return false
}
