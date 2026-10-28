// Package server exposes the REST API and, optionally, Flight SQL.
package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"

	"github.com/lucasapassos/curral/internal/audit"
	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/encode"
	"github.com/lucasapassos/curral/internal/engine"
	"github.com/lucasapassos/curral/internal/metrics"
	"github.com/lucasapassos/curral/internal/policy"
	"github.com/lucasapassos/curral/internal/rerank"
	"github.com/lucasapassos/curral/internal/rls"
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

	Docs *docs.Store // semantic documents; nil disables /v1/docs
	// DocsScope is DocsScopeAll (every authenticated user reads every
	// document) or DocsScopeSchema (a document about tables is served only
	// when the caller may read one of them).
	DocsScope string
	// DocsValidateNames is DocsNamesOff (tables and schemas are saved as
	// written), DocsNamesWarn or DocsNamesStrict: writes resolve them to
	// qualified catalog names, logging or refusing those that do not.
	DocsValidateNames string
	// Judge, when set, decides which documents /v1/docs/search returns and
	// ranks them; nil ranks by BM25 alone.
	Judge           rerank.Judge
	SearchThreshold float64 // minimum Judge probability to match: 0.7
	SearchFloor     float64 // minimum to return when none matches (0 = any)
	SearchShortlist int     // best BM25 candidates handed to Judge: 20

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
	filters, err := pol.RowFilters(ctx, input)
	if err != nil {
		return nil, err
	}
	rules := s.rowFilters.Load()
	// Remote tables (Iceberg) read through a view or macro are invisible to
	// the rewrite. If this user is filtered or masked on any remote table,
	// such a statement could read it unprotected: refuse it.
	if insp.HiddenRemoteScans > 0 {
		limited := rules.TablesFor(p.Name, p.Roles)
		for t := range filters {
			limited = append(limited, t)
		}
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
		for ft, predicate := range filters {
			if strings.EqualFold(ft, t) {
				if pr.Filter != "" {
					pr.Filter = "(" + pr.Filter + ") AND (" + predicate + ")"
				} else {
					pr.Filter = predicate
				}
			}
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
	mux.HandleFunc("GET /v1/capabilities", s.authedOn(surfaceIntro, s.capabilities))
	mux.HandleFunc("POST /v1/query", s.authed(s.query))
	mux.HandleFunc("GET /v1/databases", s.authed(s.databases))
	mux.HandleFunc("GET /v1/schema", s.authed(s.schema))
	mux.HandleFunc("GET /healthz", s.health)
	if s.Docs != nil {
		s.docRoutes(mux)
	}
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

// authed authenticates a read: a delegated identity may run it.
func (s *Server) authed(h handler) http.HandlerFunc { return s.authedOn(surfaceRead, h) }

func (s *Server) authedOn(on surface, h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, blockedFor, blocked := s.login(s.httpCaller(r), r.Header.Get("Authorization"), nil)
		switch {
		case blocked:
			w.Header().Set("Retry-After", strconv.Itoa(int(blockedFor.Seconds())+1))
			writeError(w, http.StatusTooManyRequests, errLockedOut)
		case p == nil:
			w.Header().Set("WWW-Authenticate", `Basic realm="curral", charset="UTF-8"`)
			if s.OIDC != nil {
				w.Header().Add("WWW-Authenticate", `Bearer realm="curral"`)
			}
			writeError(w, http.StatusUnauthorized, "invalid credentials")
		default:
			effective, err := s.executionPrincipal(p, r.Header.Values(executionContextHeader), r.Header.Values(callerContextHeader), on)
			if err != nil {
				s.delegationDenied(s.httpCaller(r), p)
				writeError(w, http.StatusForbidden, "execution identity refused")
				return
			}
			w.Header().Set(effectiveSubjectHeader, effective.Name)
			h(w, r, effective)
		}
	}
}

func (s *Server) delegationDenied(c caller, p *auth.Principal) {
	if s.Audit != nil {
		ev := s.event(c, "delegation_denied", p)
		ev.Decision, ev.DecidedBy, ev.Status = "deny", "delegation", http.StatusForbidden
		s.Audit.Record(ev)
	}
}

const errLockedOut = "too many failed authentication attempts; try again later"

// login authenticates the Authorization header of a request from c. A nil
// principal turns the caller away: locked out after repeated failures
// (blocked, for blockedFor) or with wrong credentials. Locked-out callers
// are refused before any credential check. Failures are logged, counted
// towards lockouts and audited. sessions, when set, also accepts its bearer
// tokens.
func (s *Server) login(c caller, header string, sessions *auth.Sessions) (p *auth.Principal, blockedFor time.Duration, blocked bool) {
	claimed, _, _ := parseBasic(header)
	if left, scope, ok := s.blocked(c.addr, claimed); ok {
		s.Metrics.AuthBlocked(scope)
		if s.Audit != nil {
			ev := s.event(c, "auth_blocked", nil)
			ev.User, ev.Error = claimed, scope+" locked out"
			ev.Decision, ev.DecidedBy, ev.Status = "deny", "auth", http.StatusTooManyRequests
			s.Audit.Record(ev)
		}
		return nil, left, true
	}
	p, method, user, reason := s.authenticate(header, sessions)
	if p == nil {
		s.Log.Info("auth failed", "method", method, "user", user, "reason", reason,
			"client", c.addr, "request_id", c.requestID)
		s.Metrics.AuthFailure(method)
		s.recordFailure(c.addr, user)
		if s.Audit != nil {
			ev := s.event(c, "auth_failure", nil)
			ev.User, ev.AuthMethod, ev.Error = user, method, reason
			ev.Decision, ev.DecidedBy, ev.Status = "deny", "auth", http.StatusUnauthorized
			s.Audit.Record(ev)
		}
	}
	return p, 0, false
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
	return s.clientAddr(r.RemoteAddr, r.Header.Values("X-Forwarded-For"))
}

// clientAddr resolves the client address from the peer's host:port and the
// X-Forwarded-For values received, as clientIP does.
func (s *Server) clientAddr(remote string, forwardedFor []string) string {
	peer, err := netip.ParseAddrPort(remote)
	if err != nil {
		return remote
	}
	addr := peer.Addr().Unmap()
	if !s.trusted(addr) {
		return addr.String()
	}
	hops := strings.Split(strings.Join(forwardedFor, ","), ",")
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

// authenticate picks the method from an Authorization header: Basic for
// local users, "Bearer curral_..." for API keys, a bearer token of sessions
// (when given) for a Basic login made earlier, any other Bearer for OIDC
// JWTs. On failure it returns the attempted method, the claimed user (if
// any) and a reason for the logs; the client only ever sees 401.
func (s *Server) authenticate(h string, sessions *auth.Sessions) (p *auth.Principal, method, user, reason string) {
	scheme, cred, _ := strings.Cut(h, " ")
	cred = strings.TrimSpace(cred)
	switch {
	case h == "":
		return nil, "none", "", "no credentials"
	case strings.EqualFold(scheme, "Basic"):
		user, pass, ok := parseBasic(h)
		if !ok {
			return nil, auth.MethodBasic, "", "malformed basic credentials"
		}
		if p = s.authn.Load().Authenticate(user, pass); p == nil {
			return nil, auth.MethodBasic, user, "wrong user or password"
		}
		return p, auth.MethodBasic, user, ""
	case strings.EqualFold(scheme, "Bearer") && sessions != nil && strings.HasPrefix(cred, auth.SessionPrefix):
		if p = sessions.Check(s.authn.Load(), cred); p == nil {
			return nil, auth.MethodBasic, "", "invalid or expired session token"
		}
		return p, auth.MethodBasic, p.Name, ""
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

// parseBasic reads "Basic base64(user:password)", with or without base64
// padding (gRPC clients often leave it out).
func parseBasic(h string) (user, pass string, ok bool) {
	scheme, cred, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", "", false
	}
	cred = strings.TrimSpace(cred)
	b, err := base64.StdEncoding.DecodeString(cred)
	if err != nil {
		if b, err = base64.RawStdEncoding.DecodeString(cred); err != nil {
			return "", "", false
		}
	}
	return strings.Cut(string(b), ":")
}

// caller is where a request came from, for logs, lockouts and audit.
type caller struct {
	requestID    string
	addr         string // client address, resolved through trusted proxies
	forwardedFor string // X-Forwarded-For as received
}

func (s *Server) httpCaller(r *http.Request) caller {
	return caller{requestID: requestID(r), addr: s.clientIP(r), forwardedFor: r.Header.Get("X-Forwarded-For")}
}

func (s *Server) newEvent(r *http.Request, kind string, p *auth.Principal) *audit.Event {
	return s.event(s.httpCaller(r), kind, p)
}

func (s *Server) event(c caller, kind string, p *auth.Principal) *audit.Event {
	ev := &audit.Event{
		TS:           time.Now().UTC(),
		Event:        kind,
		RequestID:    c.requestID,
		RemoteAddr:   c.addr,
		ForwardedFor: c.forwardedFor,
		Version:      s.Version,
	}
	if pol := s.Policy(); pol != nil {
		ev.PolicySHA256 = pol.SHA256
	}
	if p != nil {
		ev.User, ev.Roles, ev.AuthMethod = p.Name, p.Roles, p.Method
		ev.Actor = p.Actor
		if p.Identity != nil {
			ev.Identity = p.Identity.Fields
		}
		if p.Caller != nil {
			ev.Caller = p.Caller.Fields
		}
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

	var (
		bytes   = countingWriter{w: w}
		started bool
	)
	startStream := func(insp engine.Inspection, maxRows int64) {
		started = true
		h := w.Header()
		h.Set("Content-Type", format.ContentType())
		h.Set("X-Curral-Statement-Type", insp.StatementType)
		h.Set("Trailer", "X-Curral-Error, X-Curral-Row-Count")
		if maxRows > 0 {
			// Clients that cannot read trailers can still tell that a
			// result with exactly this many rows may have been cut.
			h.Set("X-Curral-Max-Rows", strconv.FormatInt(maxRows, 10))
		}
		w.WriteHeader(http.StatusOK)
	}
	trailers := func(rows int64, err error) {
		w.Header().Set("X-Curral-Row-Count", fmt.Sprint(rows))
		if err != nil {
			w.Header().Set("X-Curral-Error", oneLine(err.Error()))
		}
	}
	sink := resultSink{
		rows: func(insp engine.Inspection, maxRows int64, cols []engine.Column, rs engine.Rows) (int64, int64, error) {
			startStream(insp, maxRows)
			rc := http.NewResponseController(w)
			n, err := encode.Write(&bytes, format, cols, rs, encode.Options{
				MaxRows: maxRows,
				Flush:   func() { _ = rc.Flush() },
			})
			trailers(n, err)
			return n, bytes.n, err
		},
		started: func() bool { return started },
	}
	if format == encode.Arrow {
		sink.records = func(insp engine.Inspection, maxRows int64, rr array.RecordReader) (int64, int64, error) {
			// Headers go out with the first byte, so a query that fails
			// before producing data still gets a proper error status.
			out := &startOnWrite{w: &bytes, start: func() { startStream(insp, maxRows) }}
			n, err := writeIPC(out, rr, maxRows)
			if started {
				trailers(n, err)
			}
			return n, bytes.n, err
		}
	}

	run := s.runQuery(r.Context(), p, ev, queryCall{
		sql: req.SQL, params: params, database: req.Database, maxRows: req.MaxRows,
		dryRun: req.DryRun, format: string(format), sink: sink,
	})
	if req.DryRun {
		s.finishDryRun(w, ev, run)
		return
	}
	if run.err != nil && !started {
		if run.status == http.StatusServiceUnavailable || run.status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, run.status, run.publicError())
	}
	// A real failure after the 200 went out: abort the connection so every
	// HTTP client sees an incomplete body, not a short result that looks
	// complete (many clients cannot read the X-Curral-Error trailer). The
	// row limit is not a failure; it ends cleanly.
	if started && run.err != nil && !errors.Is(run.err, engine.ErrMaxRows) {
		panic(http.ErrAbortHandler)
	}
}

// resultSink delivers an authorized statement's result to the client. Once
// the policy allowed the statement, the run calls records (Arrow, when set)
// or rows with the effective row limit; they report the rows and bytes
// sent. started tells afterwards whether any of the result reached the
// client: past that point an error can no longer change the response.
type resultSink struct {
	rows    func(insp engine.Inspection, maxRows int64, cols []engine.Column, rs engine.Rows) (rows, bytes int64, err error)
	records func(insp engine.Inspection, maxRows int64, rr array.RecordReader) (rows, bytes int64, err error)
	started func() bool
}

// queryCall is one statement to run for an authenticated caller.
type queryCall struct {
	sql      string
	params   []any
	database string
	maxRows  int64  // the request's own row limit (0 = none); it only lowers the others
	dryRun   bool   // inspect and decide, never execute
	format   string // for the log line
	// describe, when set, stops the statement right before it would run
	// and receives its description (engine.Request.Describe). Descriptions
	// are logged and audited but kept out of the query metrics.
	describe func(engine.Description) error
	sink     resultSink
}

// queryRun is how a statement ended, for the transport to answer with.
type queryRun struct {
	err     error
	status  int // HTTP status, also in the audit event and metrics (unset for dry runs)
	insp    engine.Inspection
	limits  policy.Limits
	maxRows int64 // effective row limit
	protect map[string]engine.Protection
	// The policy ran (policyCalled) and allowed the statement, or failed
	// (policyE).
	allowed, policyCalled bool
	policyE               error
}

// publicError is what the client may see of the run's error.
func (r *queryRun) publicError() string {
	if r.policyE != nil {
		return "policy evaluation failed"
	}
	return engine.PublicError(r.err)
}

// runQuery inspects, authorizes and executes one statement for p, sending
// the result through q.sink, and records it: log, metrics and the audit
// event ev (dry runs are left to finishDryRun). Nothing executes without
// the policy's approval and, with an audit log, room to record it.
func (s *Server) runQuery(ctx context.Context, p *auth.Principal, ev *audit.Event, q queryCall) queryRun {
	start := time.Now()
	// One policy version for the whole request, recorded in its audit event.
	pol := s.Policy()
	ev.PolicySHA256 = pol.SHA256

	var (
		run              queryRun
		rows, bytes      int64
		auditE           error
		reservation      *audit.Reservation
		throttled        bool
		protectionDenied bool
		heldGroup        string
		execTimeout      time.Duration
		timing           engine.Timing
	)
	// The strictest of the server's, the role's and the request's limits.
	rowLimit := func() int64 { return minLimit(minLimit(s.MaxRows, run.limits.MaxRows), q.maxRows) }
	authorize := func(ctx context.Context, i engine.Inspection) error {
		run.insp = i
		run.policyCalled = true
		input := map[string]any{
			"user":           p.Name,
			"roles":          p.Roles,
			"sql":            q.sql,
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
		policyIdentity(input, p)
		if delegated(p) && i.StatementType != "SELECT" {
			return engine.ErrForbidden
		}
		ok, err := pol.Allow(ctx, input)
		if err == nil && ok {
			// Limits are part of the decision: if they cannot be
			// computed, the request is not allowed.
			run.limits, err = pol.Limits(ctx, input)
			execTimeout = run.limits.Timeout
			if err == nil {
				// Row filters and masks, like limits, are part of the
				// decision: failing to compute them refuses the request.
				run.protect, err = s.protections(ctx, pol, input, i, p)
				if errors.Is(err, engine.ErrForbidden) {
					protectionDenied = true
					return err
				}
			}
		}
		if err != nil {
			run.policyE = err
			return err
		}
		if q.dryRun {
			run.allowed = ok
			return errDryRun
		}
		if !ok {
			return engine.ErrForbidden
		}
		run.allowed = true
		// Fair share: a caller over its concurrency is refused right away.
		if max := run.limits.MaxConcurrency; max > 0 || s.MaxConcurrencyPerUser > 0 {
			if max == 0 {
				max = s.MaxConcurrencyPerUser
			}
			group := run.limits.ConcurrencyGroup
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
		var err error
		rows, bytes, err = q.sink.rows(run.insp, rowLimit(), cols, rs)
		return err
	}
	var emitArrow func(array.RecordReader) error
	if q.sink.records != nil {
		emitArrow = func(rr array.RecordReader) error {
			var err error
			rows, bytes, err = q.sink.records(run.insp, rowLimit(), rr)
			return err
		}
	}

	err := s.Engine.Query(ctx, engine.Request{
		EmitArrow: emitArrow, Describe: q.describe,
		SQL: q.sql, Params: q.params, Database: q.database, Timing: &timing, ExecTimeout: &execTimeout,
		Protect: &run.protect, User: p.Name, Roles: p.Roles, IdentityJSON: identityJSON(p.Identity),
	}, authorize, emit)
	run.err, run.maxRows = err, rowLimit()
	if q.dryRun {
		return run
	}

	run.status = http.StatusOK
	if err != nil && !q.sink.started() {
		run.status = statusOf(err, run.policyE)
	}

	attrs := []any{
		"request_id", ev.RequestID, "user", p.Name, "status", run.status, "type", run.insp.StatementType,
		"databases", run.insp.Databases, "rows", rows, "format", q.format,
		"duration", time.Since(start),
	}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	s.Log.Info(ev.Event, attrs...)

	decision, decidedBy := decisionOf(err, run.allowed, run.policyCalled, run.policyE, auditE)
	if throttled {
		decision, decidedBy = "error", "concurrency"
		s.Metrics.Throttled()
	}
	if protectionDenied {
		decision, decidedBy = "deny", "protection"
	}
	policyResult := ""
	switch {
	case run.allowed:
		policyResult = "allow"
	case run.policyCalled && run.policyE == nil:
		policyResult = "deny"
	}
	total := time.Since(start)
	if q.describe == nil {
		s.Metrics.ObserveQuery(metrics.Query{
			Status: strconv.Itoa(run.status), Decision: decision, DecidedBy: decidedBy,
			StatementType: run.insp.StatementType, Roles: p.Roles, PolicyResult: policyResult,
			Rows: rows, Bytes: bytes,
			Stages: map[string]time.Duration{
				metrics.StageQueue: timing.Queue, metrics.StageInspect: timing.Inspect,
				metrics.StageAuthorize: timing.Authorize, metrics.StageExecute: timing.Execute,
				metrics.StageTotal: total,
			},
		})
	}

	if s.Audit == nil {
		return run
	}
	if insp := run.insp; insp.StatementType != "" {
		ev.StatementType = insp.StatementType
		ev.Database = insp.Database
		ev.Tables, ev.Targets, ev.Functions = insp.Tables, insp.Targets, insp.Functions
		resolved := insp.Resolved
		ev.Resolved = &resolved
		ev.HiddenRemoteScans = insp.HiddenRemoteScans
	}
	ev.Status, ev.Rows, ev.Bytes = run.status, rows, bytes
	ev.Limits = limitsJSON(run.limits)
	ev.RowFilters, ev.MaskedColumns = protectionSummary(run.protect)
	if len(run.protect) > 0 && err == nil && q.describe == nil {
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
	return run
}

// writeIPC writes rr to w as an Arrow IPC stream, cut at maxRows rows (> 0).
func writeIPC(w io.Writer, rr array.RecordReader, maxRows int64) (int64, error) {
	iw := ipc.NewWriter(w, ipc.WithSchema(rr.Schema()))
	n, err := eachRecord(rr, maxRows, iw.Write)
	if cerr := iw.Close(); cerr != nil && err == nil {
		err = cerr
	}
	return n, err
}

// eachRecord hands rr's record batches to fn. With maxRows > 0 the result
// is cut there, and ErrMaxRows reports the cut when more rows existed.
func eachRecord(rr array.RecordReader, maxRows int64, fn func(arrow.RecordBatch) error) (int64, error) {
	var n int64
	for rr.Next() {
		rec := rr.RecordBatch()
		rows := rec.NumRows()
		if maxRows > 0 && n+rows > maxRows {
			cut := rec.NewSlice(0, maxRows-n)
			err := fn(cut)
			cut.Release()
			if err != nil {
				return n, err
			}
			return maxRows, engine.ErrMaxRows
		}
		if err := fn(rec); err != nil {
			return n, err
		}
		n += rows
	}
	return n, rr.Err()
}

// finishDryRun answers a dry run with the inspection and the decision. SQL
// errors and policy failures are reported as for a real query.
func (s *Server) finishDryRun(w http.ResponseWriter, ev *audit.Event, run queryRun) {
	insp, err := run.insp, run.err
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
	case errors.As(err, &qe) && run.policyE == nil && (run.allowed || !run.policyCalled):
		// A statement that failed to bind, which the policy would allow:
		// report the error (one it denies is reported as denied, below).
		status = http.StatusBadRequest
		writeError(w, status, engine.PublicError(err))
	case run.policyCalled && run.policyE == nil:
		resp.DecidedBy = "policy"
		resp.Decision = "deny"
		if run.allowed {
			resp.Decision = "allow"
			resp.Limits = limitsJSON(run.limits)
			resp.MaxRows = run.maxRows
			ev.Limits = resp.Limits
			resp.RowFilters, resp.MaskedColumns = protectionSummary(run.protect)
			ev.RowFilters, ev.MaskedColumns = resp.RowFilters, resp.MaskedColumns
		}
	case errors.Is(err, engine.ErrForbidden):
		resp.Decision, resp.DecidedBy, resp.Reason = "deny", "engine", err.Error()
	default:
		status = statusOf(err, run.policyE)
		writeError(w, status, run.publicError())
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
// caller could read; see listSchema. ?database=, ?schema= and ?table=
// narrow the listing. With semantic documents, each table says how many
// are about it.
func (s *Server) schema(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	q := r.URL.Query()
	f := engine.SchemaFilter{Database: q.Get("database"), Schema: q.Get("schema"), Table: q.Get("table")}
	tables, status, msg := s.listSchema(r.Context(), p, s.newEvent(r, "schema", p), f, nil)
	if status == http.StatusOK && s.Docs != nil {
		status, msg = s.countDocs(r, p, tables)
	}
	if status != http.StatusOK {
		writeSchemaError(w, status, msg)
		return
	}
	writeJSON(w, http.StatusOK, schemaResponse{
		DefaultDatabase: s.Engine.Default(), Databases: s.Engine.Databases(), Tables: tables,
	})
}

// listSchema lists the tables and views matching f (and match, when set)
// that p could read with "SELECT * FROM object": each one goes through the
// same inspection, policy and protections as a query. Masked columns and
// row-filtered tables are flagged. The listing is logged and audited as ev.
// A status other than 200 comes with the message the client may see.
func (s *Server) listSchema(ctx context.Context, p *auth.Principal, ev *audit.Event, f engine.SchemaFilter,
	match func(engine.TableSchema) bool,
) (tables []engine.TableSchema, status int, msg string) {
	start := time.Now()
	ev.Database = f.Database
	pol := s.Policy()
	ev.PolicySHA256 = pol.SHA256

	fail := func(status int, msg, decidedBy string) ([]engine.TableSchema, int, string) {
		if s.Audit != nil {
			ev.Decision, ev.DecidedBy, ev.Status, ev.Error = "error", decidedBy, status, msg
			s.Audit.Record(ev)
		}
		return nil, status, msg
	}
	if max := s.MaxConcurrencyPerUser; max > 0 {
		group := "user:" + p.Name
		if !s.groups.tryAcquire(group, max) {
			s.Metrics.Throttled()
			return fail(http.StatusTooManyRequests, fmt.Sprintf("%v (limit %d for %s)", errConcurrency, max, group), "concurrency")
		}
		defer s.groups.release(group)
	}
	// Fail closed, as for queries: nothing is listed without room to record it.
	var reservation *audit.Reservation
	if s.Audit != nil {
		var err error
		if reservation, err = s.Audit.Reserve(time.Second); err != nil {
			s.Log.Error("schema refused: audit unavailable", "request_id", ev.RequestID, "err", err)
			return fail(http.StatusServiceUnavailable, errAudit.Error(), "audit")
		}
	}

	prot := map[string]map[string]engine.Protection{}
	var policyE error
	tables, err := s.Engine.Schema(ctx, f, func(ctx context.Context, t engine.TableSchema, i engine.Inspection) (bool, error) {
		if match != nil && !match(t) {
			return false, nil
		}
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
		policyIdentity(input, p)
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
		s.Log.Info("schema", "request_id", ev.RequestID, "user", p.Name, "status", status, "err", err)
		if s.Audit != nil {
			ev.Decision, ev.DecidedBy = decisionOf(err, false, false, policyE, nil)
			ev.Status, ev.Error = status, oneLine(err.Error())
			reservation.Write(ev)
		}
		return nil, status, msg
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
	s.Log.Info("schema", "request_id", ev.RequestID, "user", p.Name, "status", http.StatusOK,
		"tables", len(tables), "duration", time.Since(start))
	if s.Audit != nil {
		ev.Decision, ev.DecidedBy, ev.Status = "allow", "policy", http.StatusOK
		ev.Tables, ev.Rows = listed, int64(len(tables))
		ev.TimingMS = map[string]float64{"total": ms(time.Since(start))}
		reservation.Write(ev)
	}
	return tables, http.StatusOK, ""
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
