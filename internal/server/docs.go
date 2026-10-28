package server

import (
	"errors"
	"io"
	"net/http"
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
	errDocDenied = errors.New("not allowed to write semantic documents")
	errDocPolicy = errors.New("policy evaluation failed")
)

// Values of --docs-scope.
const (
	DocsScopeAll    = "all"    // every authenticated user reads every document
	DocsScopeSchema = "schema" // documents about tables need a readable table
)

// ValidDocsScope reports whether v is a --docs-scope value.
func ValidDocsScope(v string) bool { return v == DocsScopeAll || v == DocsScopeSchema }

// docsScope is the configured scope, DocsScopeAll when unset.
func (s *Server) docsScope() string {
	if s.DocsScope == "" {
		return DocsScopeAll
	}
	return s.DocsScope
}

// docScope returns the condition documents must pass to be shown to p, nil
// when every document is. Under DocsScopeSchema the tables p may read are
// listed as for /v1/schema (same policy, same audit event, kind
// "docs_scope") and a document naming tables or schemas must name a
// readable one; see docs.Scope. A status other than 200 comes with the
// message the client may see.
func (s *Server) docScope(r *http.Request, p *auth.Principal) (func(docs.Doc) bool, int, string) {
	if s.docsScope() != DocsScopeSchema {
		return nil, http.StatusOK, ""
	}
	var all []string
	tables, status, msg := s.listSchema(r.Context(), p, s.newEvent(r, "docs_scope", p), engine.SchemaFilter{},
		func(t engine.TableSchema) bool { all = append(all, t.Qualified()); return true })
	if status != http.StatusOK {
		return nil, status, msg
	}
	visible := make([]string, len(tables))
	for i, t := range tables {
		visible[i] = t.Qualified()
	}
	return docs.NewScope(all, visible).Readable, http.StatusOK, ""
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

// listDocs lists documents, most recently updated first. ?table=, ?schema=
// and ?q= narrow the list; ?fields=header leaves out bodies and SQL.
func (s *Server) listDocs(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	q := r.URL.Query()
	allow, status, msg := s.docScope(r, p)
	if status != http.StatusOK {
		writeSchemaError(w, status, msg)
		return
	}
	list := s.Docs.List(docs.Filter{Table: q.Get("table"), Schema: q.Get("schema"), Q: q.Get("q"), Allow: allow})
	switch q.Get("fields") {
	case "":
		writeJSON(w, http.StatusOK, map[string]any{"docs": list})
	case "header":
		out := make([]docSummary, len(list))
		for i, d := range list {
			out[i] = summary(d)
		}
		writeJSON(w, http.StatusOK, map[string]any{"docs": out})
	default:
		writeError(w, http.StatusBadRequest, "fields must be header or empty")
	}
}

func (s *Server) getDoc(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	id := r.PathValue("id")
	if !docs.ValidID(id) {
		writeError(w, http.StatusNotFound, docs.ErrNotFound.Error())
		return
	}
	d, tag, err := s.Docs.Get(id)
	// A document about nothing in particular is in every scope and needs
	// no schema listing. Any other id, missing or not, settles the scope
	// first, so an unknown id and an out-of-scope one answer alike (404,
	// or both 503 while the audit log is down): the id must not reveal the
	// document.
	if err != nil || !d.Unscoped() {
		allow, status, msg := s.docScope(r, p)
		if status != http.StatusOK {
			writeSchemaError(w, status, msg)
			return
		}
		if err != nil || (allow != nil && !allow(d)) {
			writeError(w, http.StatusNotFound, docs.ErrNotFound.Error())
			return
		}
	}
	w.Header().Set("ETag", tag)
	writeJSON(w, http.StatusOK, d)
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
		if s.Audit != nil {
			var err error
			if reservation, err = s.Audit.Reserve(time.Second); err != nil {
				s.Log.Error("document write refused: audit unavailable", "request_id", ev.RequestID, "err", err)
				w.Header().Set("Retry-After", "1")
				finish(http.StatusServiceUnavailable, "error", "audit", "audit log unavailable: write refused")
				return
			}
		}

		// Under --docs-scope schema a document out of the caller's scope is
		// as good as missing on writes too: a write would otherwise read it
		// back (PATCH returns the document) or reveal it by its status. The
		// version checked here is the one written: the client's If-Match
		// (none and "*" included) is settled against it now, and the store
		// then insists on exactly this version, so a document changed in
		// between is never written, or read back, unchecked.
		ifMatch := r.Header.Get("If-Match")
		if r.Method != http.MethodPost {
			allow, status, msg := s.docScope(r, p)
			if status != http.StatusOK {
				retryAfter(w, status)
				finish(status, "error", "scope", msg)
				return
			}
			if allow != nil {
				cur, tag, err := s.Docs.Get(ev.Doc)
				if err != nil || !allow(cur) {
					finish(http.StatusNotFound, "error", "scope", docs.ErrNotFound.Error())
					return
				}
				if !docs.ETagMatches(ifMatch, tag) {
					finish(http.StatusPreconditionFailed, "error", "request", docs.ErrPrecondition.Error())
					return
				}
				ifMatch = tag
			}
		}

		pol := s.Policy()
		// The policy sees both versions: a rule scoped to some tables must
		// check what the document is about now (current) as well as what it
		// will be about (doc), or an update could take over any document.
		// A delegated write (docs_write key) carries the identity and the
		// actor, so the policy can tie what a service may write to its users.
		check := func(old, next *docs.Doc) error {
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
