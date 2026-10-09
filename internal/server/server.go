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
	"maps"
	"net/http"
	"net/netip"
	"slices"
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
	"curral/internal/rls"
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

	Metrics *metrics.Metrics // nil disables metrics
	OIDC    *auth.OIDC       // nil disables bearer JWTs

	// Brute-force protection: failures are counted per client IP and per
	// claimed user name; nil disables either.
	IPLimiter   *auth.Limiter
	UserLimiter *auth.Limiter
	// TrustedProxies may set X-Forwarded-For; only then is it used to find
	// the client address (for limits and audit).
	TrustedProxies []netip.Prefix

	// MaxConcurrencyPerUser applies when the policy sets no max_concurrency
	// (0 = no per-user limit).
	MaxConcurrencyPerUser int64
	groups                groupSlots
	Audit                 *audit.Writer // nil disables auditing
	AuditSQL              string        // redacted (default), full or hash
	Version               string

	// Swapped atomically on reload; in-flight requests keep the version
	// they started with.
	authn      atomic.Pointer[auth.Authenticator]
	pol        atomic.Pointer[policy.Policy]
	rowFilters atomic.Pointer[rls.Rules]
}

func (s *Server) SetAuth(a *auth.Authenticator) { s.authn.Store(a) }

// SetRowFilters swaps in a validated RLS rule set (nil: none).
func (s *Server) SetRowFilters(r *rls.Rules) { s.rowFilters.Store(r) }

// protections combines the caller's row filters (RLS file) and column masks
// (policy) for the tables the statement reads. Tables with neither are
// left out, so their queries run unchanged.
func (s *Server) protections(ctx context.Context, pol *policy.Policy, input map[string]any,
	insp engine.Inspection, p *auth.Principal,
) (map[string]engine.Protection, error) {
	masks, err := pol.Masks(ctx, input)
	if err != nil {
		return nil, err
	}
	rules := s.rowFilters.Load()
	// Remote tables (Iceberg) read through a view or macro are invisible to
	// the rewrite. If this user is filtered or masked on any remote table,
	// such a statement could read it unprotected: refuse it.
	if insp.HiddenRemoteScans > 0 {
		limited := rules.TablesFor(p.Name, p.Roles)
		for t := range masks {
			limited = append(limited, t)
		}
		for _, t := range limited {
			if s.Engine.IsRemote(t) {
				return nil, fmt.Errorf("%w: %s may be read indirectly (view or macro over a lake table); query it directly",
					errProtection, t)
			}
		}
	}
	out := map[string]engine.Protection{}
	for _, t := range insp.Tables {
		var pr engine.Protection
		if where, ok := rules.Filter(t, p.Name, p.Roles); ok {
			pr.Filter = where
		}
		for mt, cols := range masks {
			if strings.EqualFold(mt, t) {
				pr.Masks = cols
			}
		}
		if pr.Filter != "" || len(pr.Masks) > 0 {
			out[t] = pr
		}
	}
	return out, nil
}
func (s *Server) SetPolicy(p *policy.Policy) { s.pol.Store(p) }
func (s *Server) Policy() *policy.Policy     { return s.pol.Load() }

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

// errProtection means row filters or masks could not be guaranteed.
var errProtection = engine.ErrForbidden

// errConcurrency means the caller already runs its share of queries.
var errConcurrency = errors.New("too many concurrent queries for this user")

// errAudit means the query was refused because it could not be audited.
var errAudit = errors.New("audit log unavailable: query refused")

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/query", s.authed(s.query))
	mux.HandleFunc("GET /v1/databases", s.authed(s.databases))
	mux.HandleFunc("GET /v1/schema", s.authed(s.schema))
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
		ip := s.clientIP(r)
		claimed := ""
		if u, _, ok := r.BasicAuth(); ok {
			claimed = u
		}
		// Blocked callers are turned away before any credential check.
		if left, scope, blocked := s.blocked(ip, claimed); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(int(left.Seconds())+1))
			writeError(w, http.StatusTooManyRequests, "too many failed authentication attempts; try again later")
			s.Metrics.AuthBlocked(scope)
			if s.Audit != nil {
				ev := s.newEvent(r, "auth_blocked", nil)
				ev.User, ev.Error = claimed, scope+" locked out"
				ev.Decision, ev.DecidedBy, ev.Status = "deny", "auth", http.StatusTooManyRequests
				s.Audit.Record(ev)
			}
			return
		}

		p, method, user, reason := s.authenticate(r)
		if p == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="curral", charset="UTF-8"`)
			if s.OIDC != nil {
				w.Header().Add("WWW-Authenticate", `Bearer realm="curral"`)
			}
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			s.Log.Info("auth failed", "method", method, "user", user, "reason", reason,
				"client", ip, "request_id", requestID(r))
			s.Metrics.AuthFailure(method)
			s.recordFailure(ip, user)
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

func (s *Server) blocked(ip, user string) (time.Duration, string, bool) {
	if left, ok := s.IPLimiter.Blocked(ip); ok {
		return left, "ip", true
	}
	if user != "" {
		if left, ok := s.UserLimiter.Blocked(strings.ToLower(user)); ok {
			return left, "user", true
		}
	}
	return 0, "", false
}

func (s *Server) recordFailure(ip, user string) {
	if s.IPLimiter.Fail(ip) {
		s.Metrics.AuthLockout("ip")
		s.Log.Warn("client locked out after repeated authentication failures", "client", ip)
	}
	if user != "" && s.UserLimiter.Fail(strings.ToLower(user)) {
		s.Metrics.AuthLockout("user")
		s.Log.Warn("user locked out after repeated authentication failures", "user", user)
	}
}

// clientIP is the peer address, or, when the peer is a trusted proxy, the
// right-most address in X-Forwarded-For that is not itself a trusted proxy.
// Addresses a client writes into the header are never trusted.
func (s *Server) clientIP(r *http.Request) string {
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	addr := peer.Addr().Unmap()
	if !s.trusted(addr) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // garbage: stop at the last address we could vouch for
		}
		addr = hop.Unmap()
		if !s.trusted(addr) {
			break
		}
	}
	return addr.String()
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
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
		// Roles from the users file's identities (reloadable) join the
		// token's own roles, e.g. for providers like Google that send none.
		return s.authn.Load().MapIdentity(p), auth.MethodJWT, p.Name, ""
	}
	return nil, "unknown", "", "unsupported authorization scheme"
}

func (s *Server) newEvent(r *http.Request, kind string, p *auth.Principal) *audit.Event {
	ev := &audit.Event{
		TS:           time.Now().UTC(),
		Event:        kind,
		RequestID:    requestID(r),
		RemoteAddr:   s.clientIP(r),
		ForwardedFor: r.Header.Get("X-Forwarded-For"),
		Version:      s.Version,
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
	// MaxRows lowers the row limit for this request (0 = the server's and
	// the role's limits only); it can never raise them.
	MaxRows int64 `json:"max_rows"`
}

// errDryRun stops a dry run right after the policy decision.
var errDryRun = errors.New("dry run")

// dryRunResponse is what a dry run reports instead of executing.
type dryRunResponse struct {
	DryRun        bool                `json:"dry_run"`
	Decision      string              `json:"decision"`
	DecidedBy     string              `json:"decided_by"`
	Reason        string              `json:"reason,omitempty"`
	StatementType string              `json:"statement_type,omitempty"`
	Database      string              `json:"database,omitempty"`
	Tables        []string            `json:"tables"`
	Targets       []string            `json:"targets"`
	Functions     []string            `json:"functions"`
	Databases     []string            `json:"databases"`
	Resolved      bool                `json:"resolved"`
	Limits        map[string]any      `json:"limits,omitempty"`
	MaxRows       int64               `json:"max_rows,omitempty"` // effective row limit
	RowFilters    []string            `json:"row_filters,omitempty"`
	MaskedColumns map[string][]string `json:"masked_columns,omitempty"`
	PolicySHA256  string              `json:"policy_sha256"`
}

// startOnWrite calls start before the first write.
type startOnWrite struct {
	w       io.Writer
	start   func()
	started bool
}

func (s *startOnWrite) Write(b []byte) (int, error) {
	if !s.started {
		s.started = true
		s.start()
	}
	return s.w.Write(b)
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
	if req.MaxRows < 0 {
		reject(http.StatusBadRequest, "max_rows must be >= 0")
		return
	}
	params, err := convertParams(req.Params)
	if err != nil {
		reject(http.StatusBadRequest, err.Error())
		return
	}
	format, ok := pickFormat(req.Format, r)
	if !ok {
		reject(http.StatusBadRequest, "unsupported format (csv, json, ndjson, arrow)")
		return
	}

	// One policy version for the whole request, recorded in its audit event.
	pol := s.Policy()
	ev.PolicySHA256 = pol.SHA256

	var (
		insp             engine.Inspection
		rows             int64
		bytes            countingWriter
		started          bool
		policyCalled     bool
		allowed          bool
		policyE          error
		auditE           error
		reservation      *audit.Reservation
		limits           policy.Limits
		protect          map[string]engine.Protection
		throttled        bool
		protectionDenied bool
		heldGroup        string
		execTimeout      time.Duration
		timing           engine.Timing
	)
	bytes.w = w
	// The strictest of the server's, the role's and the request's limits.
	rowLimit := func() int64 { return minLimit(minLimit(s.MaxRows, limits.MaxRows), req.MaxRows) }
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
			// Lake scans behind views/macros, whose tables are unknown.
			"hidden_remote_scans": i.HiddenRemoteScans,
		}
		ok, err := pol.Allow(ctx, input)
		if err == nil && ok {
			// Limits are part of the decision: if they cannot be
			// computed, the request is not allowed.
			limits, err = pol.Limits(ctx, input)
			execTimeout = limits.Timeout
			if err == nil {
				// Row filters and masks, like limits, are part of the
				// decision: failing to compute them refuses the request.
				protect, err = s.protections(ctx, pol, input, i, p)
				if errors.Is(err, engine.ErrForbidden) {
					protectionDenied = true
					return err
				}
			}
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
		// Fair share: a caller over its concurrency is refused right away.
		if max := limits.MaxConcurrency; max > 0 || s.MaxConcurrencyPerUser > 0 {
			if max == 0 {
				max = s.MaxConcurrencyPerUser
			}
			group := limits.ConcurrencyGroup
			if group == "" {
				group = "user:" + p.Name
			}
			if !s.groups.tryAcquire(group, max) {
				throttled = true
				return fmt.Errorf("%w (limit %d for %s)", errConcurrency, max, group)
			}
			heldGroup = group
		}
		// Fail closed: nothing executes without room to record it.
		if s.Audit != nil {
			if reservation, auditE = s.Audit.Reserve(time.Second); auditE != nil {
				s.Log.Error("query refused: audit unavailable", "request_id", ev.RequestID, "err", auditE)
				return errAudit
			}
		}
		return nil
	}
	defer func() {
		if heldGroup != "" {
			s.groups.release(heldGroup)
		}
	}()
	emit := func(cols []engine.Column, rs engine.Rows) error {
		started = true
		h := w.Header()
		h.Set("Content-Type", format.ContentType())
		h.Set("X-Curral-Statement-Type", insp.StatementType)
		h.Set("Trailer", "X-Curral-Error, X-Curral-Row-Count")
		if max := rowLimit(); max > 0 {
			// Clients that cannot read trailers can still tell that a
			// result with exactly this many rows may have been cut.
			h.Set("X-Curral-Max-Rows", strconv.FormatInt(max, 10))
		}
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		n, err := encode.Write(&bytes, format, cols, rs, encode.Options{
			MaxRows: rowLimit(),
			Flush:   func() { _ = rc.Flush() },
		})
		rows = n
		h.Set("X-Curral-Row-Count", fmt.Sprint(n))
		if err != nil {
			h.Set("X-Curral-Error", oneLine(err.Error()))
		}
		return err
	}

	startStream := func(contentType string) {
		started = true
		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("X-Curral-Statement-Type", insp.StatementType)
		h.Set("Trailer", "X-Curral-Error, X-Curral-Row-Count")
		if max := rowLimit(); max > 0 {
			// Clients that cannot read trailers can still tell that a
			// result with exactly this many rows may have been cut.
			h.Set("X-Curral-Max-Rows", strconv.FormatInt(max, 10))
		}
		w.WriteHeader(http.StatusOK)
	}
	var emitArrow func(engine.ArrowWriter) error
	if format == encode.Arrow {
		emitArrow = func(write engine.ArrowWriter) error {
			// Headers go out with the first byte, so a query that fails
			// before producing data still gets a proper error status.
			out := &startOnWrite{w: &bytes, start: func() { startStream(format.ContentType()) }}
			n, err := write(out, rowLimit())
			rows = n
			if started {
				w.Header().Set("X-Curral-Row-Count", fmt.Sprint(n))
				if err != nil {
					w.Header().Set("X-Curral-Error", oneLine(err.Error()))
				}
			}
			return err
		}
	}

	err = s.Engine.Query(r.Context(), engine.Request{
		EmitArrow: emitArrow,
		SQL:       req.SQL, Params: params, Database: req.Database, Timing: &timing, ExecTimeout: &execTimeout,
		Protect: &protect, User: p.Name, Roles: p.Roles,
	}, authorize, emit)

	if req.DryRun {
		s.finishDryRun(w, ev, insp, limits, rowLimit(), protect, err, allowed, policyCalled, policyE)
		return
	}

	status := http.StatusOK
	if err != nil && !started {
		status = statusOf(err, policyE)
		msg := engine.PublicError(err)
		if policyE != nil {
			msg = "policy evaluation failed"
		}
		if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
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
	if throttled {
		decision, decidedBy = "error", "concurrency"
		s.Metrics.Throttled()
	}
	if protectionDenied {
		decision, decidedBy = "deny", "protection"
	}
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

	// A real failure after the 200 went out: abort the connection so every
	// HTTP client sees an incomplete body, not a short result that looks
	// complete (many clients cannot read the X-Curral-Error trailer). The
	// row limit is not a failure; it ends cleanly.
	if started && err != nil && !errors.Is(err, engine.ErrMaxRows) {
		defer panic(http.ErrAbortHandler)
	}

	if s.Audit == nil {
		return
	}
	if insp.StatementType != "" {
		ev.StatementType = insp.StatementType
		ev.Database = insp.Database
		ev.Tables, ev.Targets, ev.Functions = insp.Tables, insp.Targets, insp.Functions
		resolved := insp.Resolved
		ev.Resolved = &resolved
		ev.HiddenRemoteScans = insp.HiddenRemoteScans
	}
	ev.Status, ev.Rows, ev.Bytes = status, rows, bytes.n
	ev.Limits = limitsJSON(limits)
	ev.RowFilters, ev.MaskedColumns = protectionSummary(protect)
	if len(protect) > 0 && err == nil {
		s.Metrics.Rewritten()
	}
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
	limits policy.Limits, maxRows int64, protect map[string]engine.Protection, err error, allowed, policyCalled bool, policyE error,
) {
	resp := dryRunResponse{
		DryRun: true, PolicySHA256: ev.PolicySHA256,
		StatementType: insp.StatementType, Database: insp.Database,
		Tables: nonNil(insp.Tables), Targets: nonNil(insp.Targets),
		Functions: nonNil(insp.Functions), Databases: nonNil(insp.Databases),
		Resolved: insp.Resolved,
	}
	status := http.StatusOK
	var qe *engine.QueryError
	switch {
	case errors.As(err, &qe) && policyE == nil && (allowed || !policyCalled):
		// A statement that failed to bind, which the policy would allow:
		// report the error (one it denies is reported as denied, below).
		status = http.StatusBadRequest
		writeError(w, status, engine.PublicError(err))
	case policyCalled && policyE == nil:
		resp.DecidedBy = "policy"
		resp.Decision = "deny"
		if allowed {
			resp.Decision = "allow"
			resp.Limits = limitsJSON(limits)
			resp.MaxRows = maxRows
			ev.Limits = resp.Limits
			resp.RowFilters, resp.MaskedColumns = protectionSummary(protect)
			ev.RowFilters, ev.MaskedColumns = resp.RowFilters, resp.MaskedColumns
		}
	case errors.Is(err, engine.ErrForbidden):
		resp.Decision, resp.DecidedBy, resp.Reason = "deny", "engine", err.Error()
	default:
		status = statusOf(err, policyE)
		msg := engine.PublicError(err)
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

// protectionSummary lists filtered tables and masked columns (names only)
// for audit events and dry runs.
func protectionSummary(prot map[string]engine.Protection) (filtered []string, masked map[string][]string) {
	for t, p := range prot {
		if p.Filter != "" {
			filtered = append(filtered, t)
		}
		if len(p.Masks) > 0 {
			if masked == nil {
				masked = map[string][]string{}
			}
			masked[t] = slices.Sorted(maps.Keys(p.Masks))
		}
	}
	slices.Sort(filtered)
	return filtered, masked
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
	if l.MaxConcurrency > 0 {
		m["max_concurrency"] = l.MaxConcurrency
	}
	if l.ConcurrencyGroup != "" {
		m["concurrency_group"] = l.ConcurrencyGroup
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
	case allowed && errors.Is(err, engine.ErrForbidden):
		return "deny", "protection" // filters/masks could not be applied safely
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
	case errors.Is(err, errConcurrency):
		return http.StatusTooManyRequests
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

// schemaResponse lists what the caller may query, for clients (and AI
// agents) that need the structure before writing SQL.
type schemaResponse struct {
	DefaultDatabase string                `json:"default_database"`
	Databases       []engine.DatabaseInfo `json:"databases"`
	Tables          []engine.TableSchema  `json:"tables"`
}

// schema lists tables and views with their columns, keeping only those the
// caller could read with "SELECT * FROM object": each one goes through the
// same inspection, policy and protections as a query. Masked columns and
// row-filtered tables are flagged. ?database=, ?schema= and ?table= narrow
// the listing.
func (s *Server) schema(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	start := time.Now()
	ev := s.newEvent(r, "schema", p)
	q := r.URL.Query()
	f := engine.SchemaFilter{Database: q.Get("database"), Schema: q.Get("schema"), Table: q.Get("table")}
	ev.Database = f.Database
	pol := s.Policy()
	ev.PolicySHA256 = pol.SHA256

	fail := func(status int, msg, decidedBy string) {
		if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, status, msg)
		if s.Audit != nil {
			ev.Decision, ev.DecidedBy, ev.Status, ev.Error = "error", decidedBy, status, msg
			s.Audit.Record(ev)
		}
	}
	if max := s.MaxConcurrencyPerUser; max > 0 {
		group := "user:" + p.Name
		if !s.groups.tryAcquire(group, max) {
			s.Metrics.Throttled()
			fail(http.StatusTooManyRequests, fmt.Sprintf("%v (limit %d for %s)", errConcurrency, max, group), "concurrency")
			return
		}
		defer s.groups.release(group)
	}
	// Fail closed, as for queries: nothing is listed without room to record it.
	var reservation *audit.Reservation
	if s.Audit != nil {
		var err error
		if reservation, err = s.Audit.Reserve(time.Second); err != nil {
			s.Log.Error("schema refused: audit unavailable", "request_id", ev.RequestID, "err", err)
			fail(http.StatusServiceUnavailable, errAudit.Error(), "audit")
			return
		}
	}

	prot := map[string]map[string]engine.Protection{}
	var policyE error
	tables, err := s.Engine.Schema(r.Context(), f, func(ctx context.Context, t engine.TableSchema, i engine.Inspection) (bool, error) {
		input := map[string]any{
			"user":                p.Name,
			"roles":               p.Roles,
			"sql":                 "SELECT * FROM " + t.Qualified(),
			"statement_type":      i.StatementType,
			"database":            i.Database,
			"tables":              i.Tables,
			"targets":             i.Targets,
			"functions":           i.Functions,
			"databases":           i.Databases,
			"resolved":            i.Resolved,
			"hidden_remote_scans": i.HiddenRemoteScans,
		}
		ok, err := pol.Allow(ctx, input)
		if err == nil && ok {
			var pr map[string]engine.Protection
			pr, err = s.protections(ctx, pol, input, i, p)
			if errors.Is(err, engine.ErrForbidden) {
				return false, nil // a query on it would be refused too
			}
			prot[t.Qualified()] = pr
		}
		if err != nil {
			policyE = err
		}
		return ok, err
	})
	if err != nil {
		status := statusOf(err, policyE)
		msg := engine.PublicError(err)
		if policyE != nil {
			msg = "policy evaluation failed"
		}
		if status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, status, msg)
		s.Log.Info("schema", "request_id", ev.RequestID, "user", p.Name, "status", status, "err", err)
		if s.Audit != nil {
			ev.Decision, ev.DecidedBy = decisionOf(err, false, false, policyE, nil)
			ev.Status, ev.Error = status, oneLine(err.Error())
			reservation.Write(ev)
		}
		return
	}

	listed := make([]string, len(tables))
	for i := range tables {
		t := &tables[i]
		listed[i] = t.Qualified()
		masked := map[string]bool{}
		// A view's protections are on its base tables: it is flagged when
		// any of them is filtered, and so are columns named like a masked one.
		for _, pr := range prot[t.Qualified()] {
			if pr.Filter != "" {
				t.RowFiltered = true
			}
			for c := range pr.Masks {
				masked[strings.ToLower(c)] = true
			}
		}
		for j := range t.Columns {
			t.Columns[j].Masked = masked[strings.ToLower(t.Columns[j].Name)]
		}
	}
	writeJSON(w, http.StatusOK, schemaResponse{
		DefaultDatabase: s.Engine.Default(), Databases: s.Engine.Databases(), Tables: tables,
	})
	s.Log.Info("schema", "request_id", ev.RequestID, "user", p.Name, "status", http.StatusOK,
		"tables", len(tables), "duration", time.Since(start))
	if s.Audit != nil {
		ev.Decision, ev.DecidedBy, ev.Status = "allow", "policy", http.StatusOK
		ev.Tables, ev.Rows = listed, int64(len(tables))
		ev.TimingMS = map[string]float64{"total": ms(time.Since(start))}
		reservation.Write(ev)
	}
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
