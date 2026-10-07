// Package metrics exposes curral's Prometheus metrics.
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Sources are read at scrape time, so values already counted elsewhere (the
// engine's slots, the audit writer, catalog caches) are not duplicated.
type Sources struct {
	Load        func() (running, waiting, limit int)
	CacheStats  func(database string) (hits, misses int64, ok bool)
	CachedDBs   []string
	AuditStats  func() (written, dropped int64, healthy bool) // nil: audit disabled
	PolicySHA   func() string                                 // hash of the policy in effect
	BuildLabels map[string]string                             // version, commit, duckdb
}

type Metrics struct {
	reg       *prometheus.Registry
	requests  *prometheus.CounterVec
	decisions *prometheus.CounterVec
	stage     *prometheus.HistogramVec
	rows      prometheus.Counter
	bytes     prometheus.Counter
	authFail  *prometheus.CounterVec
	reloads   *prometheus.CounterVec
	lockouts  *prometheus.CounterVec
	blocked   *prometheus.CounterVec
	policy    *policyCollector
}

// SetPolicySource sets where curral_policy_info reads the current hash.
func (m *Metrics) SetPolicySource(f func() string) {
	if m != nil {
		m.policy.mu.Lock()
		m.policy.sha = f
		m.policy.mu.Unlock()
	}
}

// Stages of a query, as reported in its timing.
const (
	StageQueue     = "queue"
	StageInspect   = "inspect"
	StageAuthorize = "authorize"
	StageExecute   = "execute"
	StageTotal     = "total"
)

func New(src Sources) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "curral_queries_total",
			Help: "Query requests by HTTP status, decision (allow, deny, error), deciding component and statement type.",
		}, []string{"status", "decision", "decided_by", "statement_type"}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "curral_policy_decisions_total",
			Help: "Policy decisions per role of the requesting user (a user with several roles counts once per role).",
		}, []string{"role", "decision"}),
		stage: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "curral_query_stage_seconds",
			Help:    "Time per query stage: queue, inspect, authorize, execute (incl. streaming) and total.",
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10, 30, 60},
		}, []string{"stage"}),
		rows: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "curral_rows_returned_total", Help: "Rows sent to clients.",
		}),
		bytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "curral_response_bytes_total", Help: "Result bytes sent to clients.",
		}),
		authFail: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "curral_auth_failures_total", Help: "Requests rejected for invalid credentials, by attempted method.",
		}, []string{"method"}),
		lockouts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "curral_auth_lockouts_total", Help: "Lockouts started after repeated authentication failures, by scope (ip, user).",
		}, []string{"scope"}),
		blocked: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "curral_auth_blocked_total", Help: "Requests refused (429) because their client or user is locked out, by scope.",
		}, []string{"scope"}),
		reloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "curral_config_reloads_total", Help: "Users/policy reloads (SIGHUP) by result (ok, error).",
		}, []string{"result"}),
	}
	reg.MustRegister(m.requests, m.decisions, m.stage, m.rows, m.bytes, m.authFail, m.reloads, m.lockouts, m.blocked,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	if src.Load != nil {
		gauge := func(name, help string, pick func(r, w, l int) int) prometheus.GaugeFunc {
			return prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, func() float64 {
				r, w, l := src.Load()
				return float64(pick(r, w, l))
			})
		}
		reg.MustRegister(
			gauge("curral_queries_running", "Queries holding a concurrency slot.", func(r, _, _ int) int { return r }),
			gauge("curral_queries_waiting", "Queries waiting for a concurrency slot.", func(_, w, _ int) int { return w }),
			gauge("curral_query_slots", "Configured concurrency limit (--max-concurrency).", func(_, _, l int) int { return l }),
		)
	}
	if src.AuditStats != nil {
		reg.MustRegister(
			prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "curral_audit_events_written_total", Help: "Audit events written."},
				func() float64 { w, _, _ := src.AuditStats(); return float64(w) }),
			prometheus.NewCounterFunc(prometheus.CounterOpts{Name: "curral_audit_events_dropped_total", Help: "Audit events lost (write failure or full queue)."},
				func() float64 { _, d, _ := src.AuditStats(); return float64(d) }),
			prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "curral_audit_healthy", Help: "1 while the audit log is writable; 0 means queries are being refused."},
				func() float64 {
					if _, _, ok := src.AuditStats(); ok {
						return 1
					}
					return 0
				}),
		)
	}
	if src.CacheStats != nil && len(src.CachedDBs) > 0 {
		reg.MustRegister(&cacheCollector{src: src, desc: prometheus.NewDesc(
			"curral_catalog_cache_requests_total",
			"Catalog metadata cache lookups by database and result (hit, miss).",
			[]string{"database", "result"}, nil)})
	}
	m.policy = &policyCollector{sha: src.PolicySHA, desc: prometheus.NewDesc(
		"curral_policy_info", "The policy in effect, by hash of its files; always 1.", []string{"sha256"}, nil)}
	reg.MustRegister(m.policy)
	if src.BuildLabels != nil {
		reg.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "curral_build_info", Help: "Build and policy identity; always 1.", ConstLabels: src.BuildLabels,
		}, func() float64 { return 1 }))
	}
	return m
}

type policyCollector struct {
	mu   sync.Mutex
	sha  func() string
	desc *prometheus.Desc
}

func (c *policyCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *policyCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	f := c.sha
	c.mu.Unlock()
	if f != nil {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, 1, f())
	}
}

type cacheCollector struct {
	src  Sources
	desc *prometheus.Desc
}

func (c *cacheCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *cacheCollector) Collect(ch chan<- prometheus.Metric) {
	for _, db := range c.src.CachedDBs {
		hits, misses, ok := c.src.CacheStats(db)
		if !ok {
			continue
		}
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(hits), db, "hit")
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(misses), db, "miss")
	}
}

// Query is one finished query request.
type Query struct {
	Status        string
	Decision      string
	DecidedBy     string
	StatementType string
	Roles         []string
	PolicyResult  string // allow or deny when the policy was evaluated, else ""
	Rows, Bytes   int64
	Stages        map[string]time.Duration
}

func (m *Metrics) ObserveQuery(q Query) {
	if m == nil {
		return
	}
	st := q.StatementType
	if st == "" {
		st = "none"
	}
	m.requests.WithLabelValues(q.Status, q.Decision, q.DecidedBy, st).Inc()
	if q.PolicyResult != "" {
		for _, role := range q.Roles {
			m.decisions.WithLabelValues(role, q.PolicyResult).Inc()
		}
	}
	for stage, d := range q.Stages {
		m.stage.WithLabelValues(stage).Observe(d.Seconds())
	}
	m.rows.Add(float64(q.Rows))
	m.bytes.Add(float64(q.Bytes))
}

func (m *Metrics) Reload(result string) {
	if m != nil {
		m.reloads.WithLabelValues(result).Inc()
	}
}

func (m *Metrics) AuthLockout(scope string) {
	if m != nil {
		m.lockouts.WithLabelValues(scope).Inc()
	}
}

func (m *Metrics) AuthBlocked(scope string) {
	if m != nil {
		m.blocked.WithLabelValues(scope).Inc()
	}
}

func (m *Metrics) AuthFailure(method string) {
	if m != nil {
		m.authFail.WithLabelValues(method).Inc()
	}
}

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}
