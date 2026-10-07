package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrape(t *testing.T, m *Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func TestScrapeTimeSources(t *testing.T) {
	healthy := true
	m := New(Sources{
		Load: func() (int, int, int) { return 3, 7, 8 },
		CacheStats: func(db string) (int64, int64, bool) {
			return 40, 2, db == "lake"
		},
		CachedDBs:  []string{"lake"},
		AuditStats: func() (int64, int64, bool) { return 100, 1, healthy },
	})
	body := scrape(t, m)
	for _, want := range []string{
		"curral_queries_running 3", "curral_queries_waiting 7", "curral_query_slots 8",
		`curral_catalog_cache_requests_total{database="lake",result="hit"} 40`,
		`curral_catalog_cache_requests_total{database="lake",result="miss"} 2`,
		"curral_audit_events_written_total 100", "curral_audit_events_dropped_total 1",
		"curral_audit_healthy 1",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	healthy = false
	if !strings.Contains(scrape(t, m), "curral_audit_healthy 0") {
		t.Error("audit health not refreshed at scrape time")
	}
}

func TestPolicyDecisionsPerRole(t *testing.T) {
	m := New(Sources{})
	m.ObserveQuery(Query{Status: "503", Decision: "error", DecidedBy: "audit", Roles: []string{"a", "b"},
		PolicyResult: "allow", Stages: map[string]time.Duration{StageTotal: time.Millisecond}})
	body := scrape(t, m)
	for _, want := range []string{
		`curral_policy_decisions_total{decision="allow",role="a"} 1`,
		`curral_policy_decisions_total{decision="allow",role="b"} 1`,
		`curral_queries_total{decided_by="audit",decision="error",statement_type="none",status="503"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	var nilM *Metrics
	nilM.ObserveQuery(Query{}) // disabled metrics are a no-op
	nilM.AuthFailure("basic")
}
