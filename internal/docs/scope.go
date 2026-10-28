package docs

import "strings"

// Scope is what a reader may see of a catalog: every table in it and the
// ones the reader may query, fully qualified as database.schema.table. It
// decides which documents the reader is shown.
type Scope struct {
	*Catalog
	visible map[string]bool // the readable tables and their schemas, lowercase
}

// NewScope indexes the catalog (all) for a reader who may query visible.
// Names are compared ignoring case.
func NewScope(all, visible []string) *Scope {
	s := &Scope{Catalog: NewCatalog(all), visible: map[string]bool{}}
	for _, t := range visible {
		t = strings.ToLower(t)
		s.visible[t] = true
		if sc := schemaOf(t); sc != "" {
			s.visible[sc] = true
		}
	}
	return s
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
		if s.readable(idx, n) {
			return true
		}
	}
	return false
}

// readable reports whether name fits at least one object in idx and every
// object it fits is readable.
func (s *Scope) readable(idx map[string][]string, name string) bool {
	objs := idx[strings.ToLower(strings.TrimSpace(name))]
	if len(objs) == 0 {
		return false
	}
	for _, o := range objs {
		if !s.visible[strings.ToLower(o)] {
			return false
		}
	}
	return true
}

// Split sorts the tables d names into those the reader may query and the
// rest, by the rule of Readable (a name counts when every object it fits
// is readable; one fitting nothing in the catalog is not accessible). Both
// lists are non-nil, so a document about no table has two empty ones.
func (s *Scope) Split(d Doc) (accessible, inaccessible []string) {
	accessible, inaccessible = []string{}, []string{}
	for _, t := range d.Context.Tables {
		if s.readable(s.tables, t) {
			accessible = append(accessible, t)
		} else {
			inaccessible = append(inaccessible, t)
		}
	}
	return accessible, inaccessible
}
