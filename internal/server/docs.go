package server

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/lucasapassos/curral/internal/audit"
	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/docs"
)

// Semantic documents: every authenticated user reads them; the policy's
// docs decision says who creates, updates and deletes them.

var (
	errDocDenied = errors.New("not allowed to write semantic documents")
	errDocPolicy = errors.New("policy evaluation failed")
)

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
func (s *Server) listDocs(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	q := r.URL.Query()
	list := s.Docs.List(docs.Filter{Table: q.Get("table"), Schema: q.Get("schema"), Q: q.Get("q")})
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

func (s *Server) getDoc(w http.ResponseWriter, r *http.Request, _ *auth.Principal) {
	id := r.PathValue("id")
	if !docs.ValidID(id) {
		writeError(w, http.StatusNotFound, docs.ErrNotFound.Error())
		return
	}
	d, tag, err := s.Docs.Get(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
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

		pol := s.Policy()
		// The policy sees both versions: a rule scoped to some tables must
		// check what the document is about now (current) as well as what it
		// will be about (doc), or an update could take over any document.
		check := func(old, next *docs.Doc) error {
			input := map[string]any{"action": action, "user": p.Name, "roles": p.Roles}
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

		ifMatch := r.Header.Get("If-Match")
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
