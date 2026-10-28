package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/lucasapassos/curral/internal/audit"
	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/engine"
)

// Semantic documents: every authenticated user reads them (all of them, or
// with --docs-scope schema only those about tables they may query); the
// policy's docs decision says who creates, updates and deletes them.

var (
	errDocDenied  = errors.New("not allowed to write semantic documents")
	errDocPolicy  = errors.New("policy evaluation failed")
	errDocCatalog = errors.New("catalog unavailable: write refused")
)

// Values of --docs-scope.
const (
	DocsScopeAll    = "all"    // every authenticated user reads every document
	DocsScopeSchema = "schema" // documents about tables need a readable table
)

// ValidDocsScope reports whether v is a --docs-scope value.
func ValidDocsScope(v string) bool { return v == DocsScopeAll || v == DocsScopeSchema }

// Values of --docs-validate-names.
const (
	DocsNamesOff    = "off"    // tables and schemas are saved as written
	DocsNamesWarn   = "warn"   // resolved names are qualified; the rest logged
	DocsNamesStrict = "strict" // a name not resolving to one object is a 400
)

// ValidDocsNames reports whether v is a --docs-validate-names value.
func ValidDocsNames(v string) bool {
	return v == DocsNamesOff || v == DocsNamesWarn || v == DocsNamesStrict
}

// docCatalog loads the catalog a write resolves its tables and schemas
// against, as --docs-validate-names asks; nil when off, empty without an
// engine (nothing resolves). It is loaded before the store is locked and
// before the write's audit slot is taken: a cold schema snapshot can take
// seconds and must hold up neither document reads nor other audited
// requests. The catalog is read whole, not through the writer's policy: a
// writer thus learns whether a name exists, which is documented, but never
// what the object holds.
func (s *Server) docCatalog(ctx context.Context, ev *audit.Event) (*docs.Catalog, error) {
	if mode := s.DocsValidateNames; mode == "" || mode == DocsNamesOff {
		return nil, nil
	}
	if s.Engine == nil {
		return docs.NewCatalog(nil), nil
	}
	var names []string
	_, err := s.Engine.Schema(ctx, engine.SchemaFilter{}, func(_ context.Context, t engine.TableSchema, _ engine.Inspection) (bool, error) {
		names = append(names, t.Qualified())
		return false, nil // the names are all that is needed
	})
	if err != nil {
		s.Log.Error("document write refused: catalog unavailable", "request_id", ev.RequestID, "err", err)
		return nil, errDocCatalog
	}
	return docs.NewCatalog(names), nil
}

// resolveDocNames rewrites the tables and schemas d names to their
// qualified names in catalog (nil: leave them): under strict a name
// fitting none or several objects is an error (a 400), which warn only
// logs.
func (s *Server) resolveDocNames(catalog *docs.Catalog, ev *audit.Event, d *docs.Doc) error {
	if catalog == nil {
		return nil
	}
	unresolved, err := catalog.Normalize(d, s.DocsValidateNames == DocsNamesStrict)
	if err != nil {
		return err
	}
	if len(unresolved) > 0 {
		s.Log.Warn("document names not in the catalog", "request_id", ev.RequestID, "user", ev.User, "names", unresolved)
	}
	return nil
}

// docsScope is the configured scope, DocsScopeAll when unset.
func (s *Server) docsScope() string {
	if s.DocsScope == "" {
		return DocsScopeAll
	}
	return s.DocsScope
}

// catalogScope indexes the catalog for p: every table in it and those p
// may read, listed as for /v1/schema (same policy, same audit event, kind
// "docs_scope"); see docs.Scope. Without an engine the catalog is empty. A
// status other than 200 comes with the message the client may see.
func (s *Server) catalogScope(r *http.Request, p *auth.Principal) (*docs.Scope, int, string) {
	if s.Engine == nil {
		return docs.NewScope(nil, nil), http.StatusOK, ""
	}
	var all []string
	tables, status, msg := s.listSchema(r.Context(), p, s.newEvent(r, "docs_scope", p), engine.SchemaFilter{},
		func(t engine.TableSchema) bool { all = append(all, t.Qualified()); return true })
	if status != http.StatusOK {
		return nil, status, msg
	}
	return docs.NewScope(all, qualifiedNames(tables)), http.StatusOK, ""
}

// qualifiedNames are the database.schema.table names of tables.
func qualifiedNames(tables []engine.TableSchema) []string {
	out := make([]string, len(tables))
	for i, t := range tables {
		out[i] = t.Qualified()
	}
	return out
}

// docAccess is what a listing or search knows of the caller's catalog: the
// scope, to tell which of a document's tables the caller may query, and
// under DocsScopeSchema the condition documents must pass. Under
// DocsScopeSchema the scope is listed anyway, so the annotation is always
// there; under DocsScopeAll it is listed only when the caller asks for the
// annotation (access), so a plain listing stays an in-memory read that
// needs no policy, no audit slot and no engine.
type docAccess struct {
	scope *docs.Scope         // nil: no annotation
	allow func(docs.Doc) bool // nil: every document is shown
}

func (s *Server) docAccess(r *http.Request, p *auth.Principal, access bool) (docAccess, int, string) {
	schema := s.docsScope() == DocsScopeSchema
	if !schema && !access {
		return docAccess{}, http.StatusOK, ""
	}
	scope, status, msg := s.catalogScope(r, p)
	if status != http.StatusOK {
		return docAccess{}, status, msg
	}
	a := docAccess{scope: scope}
	if schema {
		a.allow = scope.Readable
	}
	return a, http.StatusOK, ""
}

// accessParam reads the access query parameter: empty or a boolean.
func accessParam(v string) (bool, error) {
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, errors.New("access must be true or false")
	}
	return b, nil
}

// access says which of the tables a document names the caller may query
// and which not (as in docs.Scope.Split); a document naming no table has
// two empty lists.
type access struct {
	AccessibleTables   []string `json:"accessible_tables"`
	InaccessibleTables []string `json:"inaccessible_tables"`
}

// A document as served: whole, or its header, plus access when annotated.
type (
	fullDoc struct {
		docs.Doc
		*access
	}
	headerDoc struct {
		docSummary
		*access
	}
)

// split is the access of d within scope.
func split(scope *docs.Scope, d docs.Doc) *access {
	var x access
	x.AccessibleTables, x.InaccessibleTables = scope.Split(d)
	return &x
}

// view renders d for the caller: the whole document or, with header, its
// summary, annotated with the tables the caller may query when the scope
// is known. The annotation is also returned, nil when there is none.
func (a docAccess) view(d docs.Doc, header bool) (any, *access) {
	var x *access
	if a.scope != nil {
		x = split(a.scope, d)
	}
	if header {
		return headerDoc{summary(d), x}, x
	}
	return fullDoc{d, x}, x
}

// countDocs sets Docs on each listed table: how many documents are about
// it, by the rule of the document filters. Under DocsScopeSchema only the
// documents the caller may read count, so a count never reveals a document
// the listing would hide; deciding that takes the caller's scope, given
// when the listing already made it (an unfiltered one is the scope) and
// otherwise listed and audited as for the documents themselves. A status
// other than 200 comes with the message the client may see.
func (s *Server) countDocs(r *http.Request, p *auth.Principal, tables []engine.TableSchema, scope *docs.Scope) (int, string) {
	var allow func(docs.Doc) bool
	if s.docsScope() == DocsScopeSchema {
		if scope == nil {
			var status int
			var msg string
			if scope, status, msg = s.catalogScope(r, p); status != http.StatusOK {
				return status, msg
			}
		}
		allow = scope.Readable
	}
	names := qualifiedNames(tables)
	counts := s.Docs.Count(names, allow)
	for i := range tables {
		tables[i].Docs = counts[names[i]]
	}
	return http.StatusOK, ""
}

// retryAfter marks a 503 or 429 as transient.
func retryAfter(w http.ResponseWriter, status int) {
	if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
}

// writeSchemaError answers an error from listSchema, marking a 503 or 429
// as transient.
func writeSchemaError(w http.ResponseWriter, status int, msg string) {
	retryAfter(w, status)
	writeError(w, status, msg)
}

// maxFilterNames caps the tables and schemas lists of a listing or search.
const maxFilterNames = 100

// nameFilter checks the single (table) and list (tables) forms of a name
// filter: both at once is a mistake, and a list is capped. Blank items are
// dropped.
func nameFilter(field, one string, list []string) ([]string, error) {
	var out []string
	for _, n := range list {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	switch {
	case one != "" && len(out) > 0:
		return nil, fmt.Errorf("%s and %ss cannot both be given", field, field)
	case len(out) > maxFilterNames:
		return nil, fmt.Errorf("%ss has %d items; the limit is %d", field, len(out), maxFilterNames)
	}
	return out, nil
}

// listedNames reads a list parameter given repeated (?tables=a&tables=b)
// or comma-separated (?tables=a,b).
func listedNames(values []string) []string {
	var out []string
	for _, v := range values {
		out = append(out, strings.Split(v, ",")...)
	}
	return out
}

func (s *Server) docRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/docs", s.authed(s.listDocs))
	mux.HandleFunc("GET /v1/docs/{id}", s.authed(s.getDoc))
	mux.HandleFunc("POST /v1/docs/search", s.authed(s.searchDocs))
	mux.HandleFunc("POST /v1/docs", s.authedOn(surfaceWrite, s.docWriter("create")))
	mux.HandleFunc("PUT /v1/docs/{id}", s.authedOn(surfaceWrite, s.docWriter("update")))
	mux.HandleFunc("PATCH /v1/docs/{id}", s.authedOn(surfaceWrite, s.docWriter("update")))
	mux.HandleFunc("DELETE /v1/docs/{id}", s.authedOn(surfaceWrite, s.docWriter("delete")))
}

// docSummary is a document without its body and SQL, for ?fields=header.
type docSummary struct {
	ID      string      `json:"id"`
	Header  docs.Header `json:"header"`
	Context struct {
		Schemas []string `json:"schemas,omitempty"`
		Tables  []string `json:"tables,omitempty"`
	} `json:"context"`
}

func summary(d docs.Doc) docSummary {
	out := docSummary{ID: d.ID, Header: d.Header}
	out.Context.Schemas, out.Context.Tables = d.Context.Schemas, d.Context.Tables
	return out
}

// listDocs lists documents, most recently updated first. ?table= (or
// ?tables=, a list), ?schema= (or ?schemas=) and ?q= narrow the list;
// ?fields=header leaves out bodies and SQL. Each document says which of
// its tables the caller may query under --docs-scope schema, or when
// ?access=true asks for it.
func (s *Server) listDocs(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	q := r.URL.Query()
	header := q.Get("fields") == "header"
	if !header && q.Get("fields") != "" {
		writeError(w, http.StatusBadRequest, "fields must be header or empty")
		return
	}
	access, err := accessParam(q.Get("access"))
	f := docs.Filter{Table: q.Get("table"), Schema: q.Get("schema"), Q: q.Get("q")}
	if err == nil {
		f.Tables, err = nameFilter("table", f.Table, listedNames(q["tables"]))
	}
	if err == nil {
		f.Schemas, err = nameFilter("schema", f.Schema, listedNames(q["schemas"]))
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a, status, msg := s.docAccess(r, p, access)
	if status != http.StatusOK {
		writeSchemaError(w, status, msg)
		return
	}
	f.Allow = a.allow
	list, tags := s.Docs.ListTagged(f)
	out := make([]any, len(list))
	// The collection's ETag covers what the response shows: which
	// documents, in which version, with which tables accessible to this
	// caller (when annotated), in which view. It changes with any write to
	// them and when the caller's scope changes the set or the split.
	sum := sha256.New()
	fmt.Fprintf(sum, "%v %v\n", header, a.scope != nil)
	for i, d := range list {
		v, x := a.view(d, header)
		out[i] = v
		fmt.Fprintf(sum, "%s %s", d.ID, tags[i])
		if x != nil {
			fmt.Fprintf(sum, " %q", x.AccessibleTables)
		}
		fmt.Fprintln(sum)
	}
	tag := `"` + hex.EncodeToString(sum.Sum(nil)[:16]) + `"`
	w.Header().Set("ETag", tag)
	if inm := r.Header.Get("If-None-Match"); inm != "" && docs.ETagMatches(inm, tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": out})
}

// getDoc serves one document, annotated with the tables the caller may
// query under --docs-scope schema or when ?access=true asks for it.
func (s *Server) getDoc(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	if !docs.ValidID(id) {
		writeError(w, http.StatusNotFound, docs.ErrNotFound.Error())
		return
	}
	access, err := accessParam(r.URL.Query().Get("access"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	d, tag, err := s.Docs.Get(id)
	schema := s.docsScope() == DocsScopeSchema
	var scope *docs.Scope
	switch {
	case schema && err == nil && d.Unscoped():
		// In every scope, and about no table: nothing to list.
		scope = docs.NewScope(nil, nil)
	case schema || (err == nil && access):
		// Under DocsScopeSchema any other id, missing or not, settles the
		// scope first, so an unknown id and an out-of-scope one answer
		// alike (404, or both 503 while the audit log is down): the id
		// must not reveal the document.
		var status int
		var msg string
		if scope, status, msg = s.catalogScope(r, p); status != http.StatusOK {
			writeSchemaError(w, status, msg)
			return
		}
	}
	if err != nil || (schema && !scope.Readable(d)) {
		writeError(w, http.StatusNotFound, docs.ErrNotFound.Error())
		return
	}
	w.Header().Set("ETag", tag)
	if scope == nil {
		writeJSON(w, http.StatusOK, d)
		return
	}
	writeJSON(w, http.StatusOK, fullDoc{d, split(scope, d)})
}

// docWriter handles POST, PUT, PATCH (RFC 7396 merge patch) and DELETE.
// PUT, PATCH and DELETE honor If-Match. Writes are audited and, like
// queries, refused while the audit log cannot record them.
func (s *Server) docWriter(action string) handler {
	return func(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
		start := time.Now()
		ev := s.newEvent(r, "doc_"+action, p)
		ev.Doc = r.PathValue("id")
		ev.PolicySHA256 = s.Policy().SHA256
		var reservation *audit.Reservation
		finish := func(status int, decision, decidedBy, msg string) {
			if msg != "" {
				writeError(w, status, msg)
			}
			if s.Audit == nil {
				return
			}
			ev.Decision, ev.DecidedBy, ev.Status, ev.Error = decision, decidedBy, status, msg
			ev.TimingMS = map[string]float64{"total": ms(time.Since(start))}
			if reservation != nil {
				reservation.Write(ev)
			} else {
				s.Audit.Record(ev)
			}
		}

		if r.Method != http.MethodPost && !docs.ValidID(ev.Doc) {
			finish(http.StatusNotFound, "error", "request", docs.ErrNotFound.Error())
			return
		}
		var body []byte
		if r.Method != http.MethodDelete {
			var err error
			if body, err = io.ReadAll(http.MaxBytesReader(w, r.Body, s.MaxBody)); err != nil {
				status := http.StatusBadRequest
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				finish(status, "error", "request", "invalid request body: "+err.Error())
				return
			}
		}

		// Under --docs-scope schema a document out of the caller's scope is
		// as good as missing on writes too: a write would otherwise read it
		// back (PATCH returns the document) or reveal it by its status. As
		// for a read, a document about nothing in particular needs no
		// listing; any other id, missing or not, settles the scope first.
		// The version checked here is the one written: the client's
		// If-Match (none and "*" included) is settled against it now, and
		// the store then insists on exactly this version, so a document
		// changed in between is never written, or read back, unchecked.
		ifMatch := r.Header.Get("If-Match")
		if r.Method != http.MethodPost && s.docsScope() == DocsScopeSchema {
			cur, tag, err := s.Docs.Get(ev.Doc)
			if err != nil || !cur.Unscoped() {
				scope, status, msg := s.catalogScope(r, p)
				if status != http.StatusOK {
					retryAfter(w, status)
					finish(status, "error", "scope", msg)
					return
				}
				if err != nil || !scope.Readable(cur) {
					finish(http.StatusNotFound, "error", "scope", docs.ErrNotFound.Error())
					return
				}
			}
			if !docs.ETagMatches(ifMatch, tag) {
				finish(http.StatusPreconditionFailed, "error", "request", docs.ErrPrecondition.Error())
				return
			}
			ifMatch = tag
		}

		var catalog *docs.Catalog
		if r.Method != http.MethodDelete {
			var err error
			if catalog, err = s.docCatalog(r.Context(), ev); err != nil {
				w.Header().Set("Retry-After", "1")
				finish(http.StatusServiceUnavailable, "error", "catalog", err.Error())
				return
			}
		}

		// The scope lookup reserves its own audit event and the catalog may
		// take a while to load: both are done before holding a slot for the
		// write, so no reservation waits on another or on the engine.
		if s.Audit != nil {
			var err error
			if reservation, err = s.Audit.Reserve(time.Second); err != nil {
				s.Log.Error("document write refused: audit unavailable", "request_id", ev.RequestID, "err", err)
				w.Header().Set("Retry-After", "1")
				finish(http.StatusServiceUnavailable, "error", "audit", "audit log unavailable: write refused")
				return
			}
		}

		pol := s.Policy()
		// The names are resolved first, so the policy sees qualified ones.
		// The policy sees both versions: a rule scoped to some tables must
		// check what the document is about now (current) as well as what it
		// will be about (doc), or an update could take over any document.
		// A delegated write (docs_write key) carries the identity and the
		// actor, so the policy can tie what a service may write to its users.
		check := func(old, next *docs.Doc) error {
			if next != nil {
				if err := s.resolveDocNames(catalog, ev, next); err != nil {
					return err
				}
			}
			input := map[string]any{"action": action, "user": p.Name, "roles": p.Roles}
			policyIdentity(input, p)
			if old != nil {
				input["doc_id"], input["author"], input["current"] = old.ID, old.Header.Author, docPolicyView(old)
			}
			if next != nil {
				input["doc_id"], input["doc"] = next.ID, docPolicyView(next)
			}
			ok, err := pol.AllowDocs(r.Context(), input)
			if err != nil {
				s.Log.Error("docs policy evaluation failed", "request_id", ev.RequestID, "err", err)
				return errDocPolicy
			}
			if !ok {
				return errDocDenied
			}
			return nil
		}

		var (
			d   docs.Doc
			tag string
			err error
		)
		switch r.Method {
		case http.MethodPost:
			var in docs.Doc
			if in, err = docs.Decode(body); err == nil {
				d, tag, err = s.Docs.Create(in, p.Name, check)
			}
		case http.MethodPut:
			var in docs.Doc
			if in, err = docs.Decode(body); err == nil {
				d, tag, err = s.Docs.Replace(ev.Doc, in, p.Name, ifMatch, check)
			}
		case http.MethodPatch:
			d, tag, err = s.Docs.Patch(ev.Doc, body, p.Name, ifMatch, check)
		case http.MethodDelete:
			err = s.Docs.Delete(ev.Doc, ifMatch, check)
		}

		var invalid *docs.ValidationError
		switch {
		case errors.As(err, &invalid):
			finish(http.StatusBadRequest, "error", "request", err.Error())
		case errors.Is(err, docs.ErrNotFound):
			finish(http.StatusNotFound, "error", "request", err.Error())
		case errors.Is(err, docs.ErrPrecondition):
			finish(http.StatusPreconditionFailed, "error", "request", err.Error())
		case errors.Is(err, errDocDenied):
			finish(http.StatusForbidden, "deny", "policy", err.Error())
		case errors.Is(err, errDocPolicy):
			finish(http.StatusInternalServerError, "error", "policy", err.Error())
		case err != nil:
			s.Log.Error("document write failed", "request_id", ev.RequestID, "err", err)
			finish(http.StatusInternalServerError, "error", "docs", "could not save the document")
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
			finish(http.StatusNoContent, "allow", "policy", "")
		default:
			status := http.StatusOK
			if r.Method == http.MethodPost {
				status = http.StatusCreated
				w.Header().Set("Location", "/v1/docs/"+d.ID)
			}
			ev.Doc = d.ID
			w.Header().Set("ETag", tag)
			writeJSON(w, status, d)
			finish(status, "allow", "policy", "")
		}
	}
}

// docPolicyView is the part of a document the docs policy sees.
func docPolicyView(d *docs.Doc) map[string]any {
	return map[string]any{
		"title": d.Header.Title, "author": d.Header.Author,
		"tables": nonNil(d.Context.Tables), "schemas": nonNil(d.Context.Schemas),
	}
}
