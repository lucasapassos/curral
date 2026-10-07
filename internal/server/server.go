// Package server exposes the REST API.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"curral/internal/audit"
	"curral/internal/auth"
	"curral/internal/encode"
	"curral/internal/engine"
	"curral/internal/metrics"
	"curral/internal/policy"
)

// SQL text modes for audit events.
const (
	AuditSQLRedacted = "redacted"
	AuditSQLFull     = "full"
	AuditSQLHash     = "hash"
)

type Server struct {
	Engine  *engine.Engine
	Log     *slog.Logger
	MaxRows int64
	MaxBody int64

	Metrics  *metrics.Metrics // nil disables metrics
	OIDC     *auth.OIDC       // nil disables bearer JWTs
	Audit    *audit.Writer    // nil disables auditing
	AuditSQL string           // redacted (default), full or hash
	Version  string

	// Swapped atomically on reload; in-flight requests keep the version
	// they started with.
	authn atomic.Pointer[auth.Authenticator]
	pol   atomic.Pointer[policy.Policy]
}

func (s *Server) SetAuth(a *auth.Authenticator) { s.authn.Store(a) }
func (s *Server) SetPolicy(p *policy.Policy)    { s.pol.Store(p) }
func (s *Server) Policy() *policy.Policy        { return s.pol.Load() }

// Reload swaps in new users and policy (validated by the caller) and records
// the change in the audit log. A non-nil err reports a failed reload attempt;
// the previous configuration stays in effect.
func (s *Server) Reload(a *auth.Authenticator, p *policy.Policy, err error) {
	ev := &audit.Event{TS: time.Now().UTC(), Event: "config_reload", Version: s.Version}
	if err != nil {
		ev.Decision, ev.Error = "error", oneLine(err.Error())
		ev.PolicySHA256 = s.Policy().SHA256
		s.Log.Error("reload failed; keeping previous users and policy", "err", err)
		s.Metrics.Reload("error")
	} else {
		old := s.Policy().SHA256
		s.SetAuth(a)
		s.SetPolicy(p)
		ev.Decision, ev.PolicySHA256 = "allow", p.SHA256
		s.Log.Info("users and policy reloaded", "policy_sha256", p.SHA256, "policy_changed", old != p.SHA256)
		s.Metrics.Reload("ok")
	}
	if s.Audit != nil {
		s.Audit.Record(ev)
	}
}

// errAudit means the query was refused because it could not be audited.
var errAudit = errors.New("audit log unavailable: query refused")

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/query", s.authed(s.query))
	mux.HandleFunc("GET /v1/databases", s.authed(s.databases))
	mux.HandleFunc("GET /healthz", s.health)
	return withRequestID(mux)
}

type ctxKey struct{}

// withRequestID tags every request with an ID, returned in X-Request-Id and
// used in both operational and audit logs.
func withRequestID(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := newRequestID()
		w.Header().Set("X-Request-Id", id)
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

func newRequestID() string {
	var b [8]byte
	rand.Read(b[:])
	return fmt.Sprintf("%011x%s", time.Now().UnixMilli(), hex.EncodeToString(b[:]))
}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(ctxKey{}).(string)
	return id
}

type handler func(http.ResponseWriter, *http.Request, *auth.Principal)

func (s *Server) authed(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, method, user, reason := s.authenticate(r)
		if p == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="curral", charset="UTF-8"`)
			if s.OIDC != nil {
				w.Header().Add("WWW-Authenticate", `Bearer realm="curral"`)
			}
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			s.Log.Info("auth failed", "method", method, "user", user, "reason", reason,
				"remote", r.RemoteAddr, "request_id", requestID(r))
			s.Metrics.AuthFailure(method)
			if s.Audit != nil {
				ev := s.newEvent(r, "auth_failure", nil)
				ev.User, ev.AuthMethod, ev.Error = user, method, reason
				ev.Decision, ev.DecidedBy, ev.Status = "deny", "auth", http.StatusUnauthorized
				s.Audit.Record(ev)
			}
			return
		}
		h(w, r, p)
	}
}

// authenticate picks the method from the Authorization header: Basic for
// local users, "Bearer curral_..." for API keys, any other Bearer for OIDC
// JWTs. On failure it returns the attempted method, the claimed user (if
// any) and a reason for the logs; the client only ever sees 401.
func (s *Server) authenticate(r *http.Request) (p *auth.Principal, method, user, reason string) {
	h := r.Header.Get("Authorization")
	scheme, cred, _ := strings.Cut(h, " ")
	cred = strings.TrimSpace(cred)
	switch {
	case h == "":
		return nil, "none", "", "no credentials"
	case strings.EqualFold(scheme, "Basic"):
		user, pass, ok := r.BasicAuth()
		if !ok {
			return nil, auth.MethodBasic, "", "malformed basic credentials"
		}
		if p = s.authn.Load().Authenticate(user, pass); p == nil {
			return nil, auth.MethodBasic, user, "wrong user or password"
		}
		return p, auth.MethodBasic, user, ""
	case strings.EqualFold(scheme, "Bearer") && strings.HasPrefix(cred, auth.APIKeyPrefix):
		if p = s.authn.Load().AuthenticateAPIKey(cred); p == nil {
			return nil, auth.MethodAPIKey, "", "unknown or expired api key"
		}
		return p, auth.MethodAPIKey, p.Name, ""
	case strings.EqualFold(scheme, "Bearer"):
		if s.OIDC == nil {
			return nil, auth.MethodJWT, "", "jwt authentication not configured"
		}
		p, err := s.OIDC.Authenticate(cred)
		if err != nil {
			return nil, auth.MethodJWT, "", oneLine(err.Error())
		}
		return p, auth.MethodJWT, p.Name, ""
	}
	return nil, "unknown", "", "unsupported authorization scheme"
}

func (s *Server) newEvent(r *http.Request, kind string, p *auth.Principal) *audit.Event {
	ev := &audit.Event{
		TS:           time.Now().UTC(),
		Event:        kind,
		RequestID:    requestID(r),
		RemoteAddr:   r.RemoteAddr,
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		Version:      s.Version,
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ev.RemoteAddr = host
	}
	if pol := s.Policy(); pol != nil {
		ev.PolicySHA256 = pol.SHA256
	}
	if p != nil {
		ev.User, ev.Roles, ev.AuthMethod = p.Name, p.Roles, p.Method
	}
	return ev
}

// setSQL records the statement according to the audit SQL mode. The hash is
// always kept so a known statement can be matched later.
func (s *Server) setSQL(ev *audit.Event, sql string) {
	sum := sha256.Sum256([]byte(sql))
	ev.SQLSHA256 = hex.EncodeToString(sum[:])
	switch s.AuditSQL {
	case AuditSQLFull:
		ev.SQL = sql
	case AuditSQLHash:
	default:
		if red, ok := engine.RedactSQL(sql); ok {
			ev.SQL = red
		}
	}
}

type queryRequest struct {
	SQL      string `json:"sql"`
	Params   []any  `json:"params"`
	Database string `json:"database"`
	Format   string `json:"format"`
	DryRun   bool   `json:"dry_run"` // inspect and decide, never execute
}

// errDryRun stops a dry run right after the policy decision.
var errDryRun = errors.New("dry run")

// dryRunResponse is what a dry run reports instead of executing.
type dryRunResponse struct {
	DryRun        bool           `json:"dry_run"`
	Decision      string         `json:"decision"`
	DecidedBy     string         `json:"decided_by"`
	Reason        string         `json:"reason,omitempty"`
	StatementType string         `json:"statement_type,omitempty"`
	Database      string         `json:"database,omitempty"`
	Tables        []string       `json:"tables"`
	Targets       []string       `json:"targets"`
	Functions     []string       `json:"functions"`
	Databases     []string       `json:"databases"`
	Resolved      bool           `json:"resolved"`
	Limits        map[string]any `json:"limits,omitempty"`
	PolicySHA256  string         `json:"policy_sha256"`
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.n += int64(n)
	return n, err
}

func (s *Server) query(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	start := time.Now()
	ev := s.newEvent(r, "query", p)

	// Requests rejected before anything runs are recorded best-effort.
	reject := func(status int, msg string) {
		writeError(w, status, msg)
		s.Metrics.ObserveQuery(metrics.Query{
			Status: strconv.Itoa(status), Decision: "error", DecidedBy: "request", Roles: p.Roles,
			Stages: map[string]time.Duration{metrics.StageTotal: time.Since(start)},
		})
		if s.Audit != nil {
			ev.Decision, ev.DecidedBy, ev.Status, ev.Error = "error", "request", status, msg
			s.Audit.Record(ev)
		}
	}

	var req queryRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.MaxBody))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		reject(http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	s.setSQL(ev, req.SQL)
	ev.ParamsCount = len(req.Params)
	ev.Database = req.Database
	if strings.TrimSpace(req.SQL) == "" {
		reject(http.StatusBadRequest, "sql is required")
		return
	}
	params, err := convertParams(req.Params)
	if err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	format, ok := pickFormat(req.Format, r)
	if !ok {
		reject(http.StatusBadRequest, "unsupported format (csv, json, ndjson)")
		return
	}

	// One policy version for the whole request, recorded in its audit event.
	pol := s.Policy()
	ev.PolicySHA256 = pol.SHA256

	var (
		insp         engine.Inspection
		rows         int64
		bytes        countingWriter
		started      bool
		policyCalled bool
		allowed      bool
		policyE      error
		auditE       error
		reservation  *audit.Reservation
		limits       policy.Limits
		execTimeout  time.Duration
		timing       engine.Timing
	)
	bytes.w = w
	authorize := func(ctx context.Context, i engine.Inspection) error {
		insp = i
		policyCalled = true
		input := map[string]any{
			"user":           p.Name,
			"roles":          p.Roles,
			"sql":            req.SQL,
			"statement_type": i.StatementType,
			"database":       i.Database,
			"tables":         i.Tables,
			"targets":        i.Targets,
			"functions":      i.Functions,
			"databases":      i.Databases,
			"resolved":       i.Resolved,
		}
		ok, err := pol.Allow(ctx, input)
		if err == nil && ok {
			// Limits are part of the decision: if they cannot be
			// computed, the request is not allowed.
			limits, err = pol.Limits(ctx, input)
			execTimeout = limits.Timeout
		}
		if err != nil {
			policyE = err
			return err
		}
		if req.DryRun {
			allowed = ok
			return errDryRun
		}
		if !ok {
			return engine.ErrForbidden
		}
		allowed = true
		// Fail closed: nothing executes without room to record it.
		if s.Audit != nil {
			if reservation, auditE = s.Audit.Reserve(time.Second); auditE != nil {
				s.Log.Error("query refused: audit unavailable", "request_id", ev.RequestID, "err", auditE)
				return errAudit
			}
		}
		return nil
	}
	emit := func(cols []engine.Column, rs engine.Rows) error {
		started = true
		h := w.Header()
		h.Set("Content-Type", format.ContentType())
		h.Set("X-Curral-Statement-Type", insp.StatementType)
		h.Set("Trailer", "X-Curral-Error, X-Curral-Row-Count")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		n, err := encode.Write(&bytes, format, cols, rs, encode.Options{
			MaxRows: minLimit(s.MaxRows, limits.MaxRows),
			Flush:   func() { _ = rc.Flush() },
		})
		rows = n
		h.Set("X-Curral-Row-Count", fmt.Sprint(n))
		if err != nil {
			h.Set("X-Curral-Error", oneLine(err.Error()))
		}
		return err
	}

	err = s.Engine.Query(r.Context(), engine.Request{
		SQL: req.SQL, Params: params, Database: req.Database, Timing: &timing, ExecTimeout: &execTimeout,
	}, authorize, emit)

	if req.DryRun {
		s.finishDryRun(w, ev, insp, limits, err, allowed, policyCalled, policyE)
		return
	}

	status := http.StatusOK
	if err != nil && !started {
		status = statusOf(err, policyE)
		msg := err.Error()
		if policyE != nil {
			msg = "policy evaluation failed"
		}
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, status, msg)
	}

	attrs := []any{
		"request_id", ev.RequestID, "user", p.Name, "status", status, "type", insp.StatementType,
		"databases", insp.Databases, "rows", rows, "format", format,
		"duration", time.Since(start),
	}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	s.Log.Info("query", attrs...)

	decision, decidedBy := decisionOf(err, allowed, policyCalled, policyE, auditE)
	policyResult := ""
	switch {
	case allowed:
		policyResult = "allow"
	case policyCalled && policyE == nil:
		policyResult = "deny"
	}
	total := time.Since(start)
	s.Metrics.ObserveQuery(metrics.Query{
		Status: strconv.Itoa(status), Decision: decision, DecidedBy: decidedBy,
		StatementType: insp.StatementType, Roles: p.Roles, PolicyResult: policyResult,
		Rows: rows, Bytes: bytes.n,
		Stages: map[string]time.Duration{
			metrics.StageQueue: timing.Queue, metrics.StageInspect: timing.Inspect,
			metrics.StageAuthorize: timing.Authorize, metrics.StageExecute: timing.Execute,
			metrics.StageTotal: total,
		},
	})

	if s.Audit == nil {
		return
	}
	if insp.StatementType != "" {
		ev.StatementType = insp.StatementType
		ev.Database = insp.Database
		ev.Tables, ev.Targets, ev.Functions = insp.Tables, insp.Targets, insp.Functions
		resolved := insp.Resolved
		ev.Resolved = &resolved
	}
	ev.Status, ev.Rows, ev.Bytes = status, rows, bytes.n
	ev.Limits = limitsJSON(limits)
	if err != nil {
		ev.Error = oneLine(err.Error())
	}
	ev.Decision, ev.DecidedBy = decision, decidedBy
	ev.TimingMS = map[string]float64{
		"queue":     ms(timing.Queue),
		"inspect":   ms(timing.Inspect),
		"authorize": ms(timing.Authorize),
		"execute":   ms(timing.Execute),
		"total":     ms(total),
	}
	if reservation != nil {
		reservation.Write(ev)
	} else {
		s.Audit.Record(ev)
	}
}

// finishDryRun answers a dry run with the inspection and the decision. SQL
// errors and policy failures are reported as for a real query.
func (s *Server) finishDryRun(w http.ResponseWriter, ev *audit.Event, insp engine.Inspection,
	limits policy.Limits, err error, allowed, policyCalled bool, policyE error,
) {
	resp := dryRunResponse{
		DryRun: true, PolicySHA256: ev.PolicySHA256,
		StatementType: insp.StatementType, Database: insp.Database,
		Tables: nonNil(insp.Tables), Targets: nonNil(insp.Targets),
		Functions: nonNil(insp.Functions), Databases: nonNil(insp.Databases),
		Resolved: insp.Resolved,
	}
	status := http.StatusOK
	switch {
	case policyCalled && policyE == nil:
		resp.DecidedBy = "policy"
		resp.Decision = "deny"
		if allowed {
			resp.Decision = "allow"
			resp.Limits = limitsJSON(limits)
			ev.Limits = resp.Limits
		}
	case errors.Is(err, engine.ErrForbidden):
		resp.Decision, resp.DecidedBy, resp.Reason = "deny", "engine", err.Error()
	default:
		status = statusOf(err, policyE)
		msg := err.Error()
		if policyE != nil {
			msg = "policy evaluation failed"
		}
		writeError(w, status, msg)
	}
	if status == http.StatusOK {
		writeJSON(w, status, resp)
	}
	if s.Audit != nil {
		ev.Event, ev.Status = "dry_run", status
		if insp.StatementType != "" {
			ev.StatementType, ev.Database = insp.StatementType, insp.Database
			ev.Tables, ev.Targets, ev.Functions = insp.Tables, insp.Targets, insp.Functions
			resolved := insp.Resolved
			ev.Resolved = &resolved
		}
		if resp.Decision != "" {
			ev.Decision, ev.DecidedBy = resp.Decision, resp.DecidedBy
		} else {
			ev.Decision, ev.DecidedBy, ev.Error = "error", "engine", oneLine(err.Error())
		}
		s.Audit.Record(ev)
	}
}

// limitsJSON renders policy limits for responses and audit events.
func limitsJSON(l policy.Limits) map[string]any {
	if l == (policy.Limits{}) {
		return nil
	}
	m := map[string]any{}
	if l.Timeout > 0 {
		m["timeout"] = l.Timeout.String()
	}
	if l.MaxRows > 0 {
		m["max_rows"] = l.MaxRows
	}
	return m
}

// minLimit is the stricter of two limits where 0 means unlimited.
func minLimit(a, b int64) int64 {
	if a == 0 || (b > 0 && b < a) {
		return b
	}
	return a
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// decisionOf classifies the outcome for the audit log: whether the request
// was allowed, denied or failed, and which component decided.
func decisionOf(err error, allowed, policyCalled bool, policyE, auditE error) (decision, by string) {
	switch {
	case auditE != nil:
		return "error", "audit"
	case allowed:
		return "allow", "policy" // execution errors are in the error field
	case policyE != nil:
		return "error", "policy"
	case policyCalled:
		return "deny", "policy"
	case errors.Is(err, engine.ErrForbidden):
		return "deny", "engine"
	case errors.Is(err, engine.ErrBusy):
		return "error", "queue"
	}
	return "error", "engine"
}

func ms(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

func statusOf(err, policyErr error) int {
	var qe *engine.QueryError
	switch {
	case policyErr != nil:
		return http.StatusInternalServerError
	case errors.Is(err, engine.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, engine.ErrBusy), errors.Is(err, errAudit):
		return http.StatusServiceUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled):
		return 499 // client closed request
	case errors.As(err, &qe):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func pickFormat(body string, r *http.Request) (encode.Format, bool) {
	if body != "" {
		return encode.ParseFormat(body)
	}
	if q := r.URL.Query().Get("format"); q != "" {
		return encode.ParseFormat(q)
	}
	for part := range strings.SplitSeq(r.Header.Get("Accept"), ",") {
		mt, _, _ := strings.Cut(part, ";")
		if f, ok := encode.ParseFormat(mt); ok {
			return f, true
		}
	}
	return encode.JSON, true
}

// convertParams maps JSON values to driver values. Numbers become int64 when
// integral, float64 otherwise.
func convertParams(in []any) ([]any, error) {
	out := make([]any, len(in))
	for i, v := range in {
		switch t := v.(type) {
		case nil, string, bool:
			out[i] = t
		case json.Number:
			if n, err := t.Int64(); err == nil {
				out[i] = n
			} else if f, err := t.Float64(); err == nil {
				out[i] = f
			} else {
				return nil, fmt.Errorf("params[%d]: invalid number %s", i, t)
			}
		default:
			return nil, fmt.Errorf("params[%d]: only scalar values are supported", i)
		}
	}
	return out, nil
}

func (s *Server) databases(w http.ResponseWriter, _ *http.Request, _ *auth.Principal) {
	writeJSON(w, http.StatusOK, map[string]any{"databases": s.Engine.Databases()})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Engine.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
