package server

import (
	"encoding/json"
	"net/http"

	"github.com/lucasapassos/curral/internal/auth"
)

// Execution context headers (HTTP) and metadata keys (Flight SQL).
const (
	executionContextHeader = "X-Curral-Execution-Context"
	callerContextHeader    = "X-Curral-Caller-Context"
	effectiveSubjectHeader = "X-Curral-Effective-Subject"
)

// surface is what a request may do with a delegated identity.
type surface int

const (
	// surfaceRead runs as the effective identity: queries, schema,
	// databases and semantic document reads.
	surfaceRead surface = iota
	// surfaceIntro describes the credential itself (capabilities, the
	// Flight handshake): a delegating key needs no identity there.
	surfaceIntro
	// surfaceWrite changes state on the caller's behalf (document writes):
	// delegated only by a key marked docs_write, and then as the effective
	// identity, which the docs policy still has to allow.
	surfaceWrite
)

func identityJSON(c *auth.ExecutionContext) string {
	if c == nil {
		return ""
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// executionPrincipal resolves who a request runs as. A delegating key must
// name an effective identity on every read and gets nothing of its own; a
// refused or missing identity never falls back to the key. Other API keys
// may attach an audit-only caller context to reads.
func (s *Server) executionPrincipal(p *auth.Principal, effective, caller []string, on surface) (*auth.Principal, error) {
	if len(effective) > 1 || len(caller) > 1 || (len(effective) > 0 && len(caller) > 0) {
		return nil, auth.ErrExecutionIdentity
	}
	switch {
	case len(effective) == 1:
		if on != surfaceRead && !(on == surfaceWrite && p.DocsWrite) {
			return nil, auth.ErrExecutionIdentity
		}
		c, err := auth.DecodeExecutionContext(effective[0])
		if err != nil {
			return nil, err
		}
		return s.authn.Load().Delegate(p, c)
	case p.Delegation:
		if on == surfaceIntro && len(caller) == 0 {
			return p, nil
		}
		return nil, auth.ErrExecutionIdentity
	case len(caller) == 1:
		if on != surfaceRead || p.Method != auth.MethodAPIKey {
			return nil, auth.ErrExecutionIdentity
		}
		c, err := auth.DecodeExecutionContext(caller[0])
		if err != nil {
			return nil, err
		}
		out := *p
		out.Caller = c
		return &out, nil
	}
	return p, nil
}

// policyIdentity adds the delegation attributes to a policy input.
func policyIdentity(input map[string]any, p *auth.Principal) {
	if p.Identity != nil {
		input["identity"] = p.Identity.Fields
		input["actor"] = map[string]any{"name": p.Actor, "auth_method": p.Method, "attributes": stringMap(p.Attributes)}
	}
	if p.Caller != nil {
		input["caller"] = p.Caller.Fields
	}
}

// delegated reports whether p runs on behalf of someone else, which makes
// the request read-only whatever the policy says.
func delegated(p *auth.Principal) bool { return p.Identity != nil || p.Caller != nil }

func stringMap(m map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *Server) capabilities(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	w.Header().Set("Cache-Control", "no-store")
	attrs := p.Attributes
	if attrs == nil {
		attrs = map[string]string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"execution_context_version": 1, "version": s.Version,
		"delegation_required": p.Delegation, "subject": p.Name, "attributes": attrs,
		"formats": []string{"json", "csv", "ndjson", "arrow"}, "docs": s.docsCapability(p)})
}

// docsCapability tells a client whether /v1/docs is served, whether documents
// are scoped to the tables the identity may read, what ranks a search (jev
// when a Judge is configured, bm25 otherwise) and whether this key may
// write documents on behalf of the identities it names.
func (s *Server) docsCapability(p *auth.Principal) map[string]any {
	if s.Docs == nil {
		return map[string]any{"enabled": false}
	}
	ranker := "bm25"
	if s.Judge != nil {
		ranker = "jev"
	}
	return map[string]any{"enabled": true, "scope": s.docsScope(), "ranker": ranker, "delegated_writes": p.Delegation && p.DocsWrite}
}
