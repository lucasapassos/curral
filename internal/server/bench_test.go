package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"curral/internal/engine"
)

func benchQuery(b *testing.B, body string) {
	ts, _ := newServerWithAudit(b, "")
	h := lastServer.Handler()
	_ = ts
	b.ReportAllocs()
	var bytes int64
	for b.Loop() {
		req := httptest.NewRequest("POST", "/v1/query", strings.NewReader(body))
		req.SetBasicAuth("analyst", "analyst-pw")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("%d %s", rec.Code, rec.Body.String())
		}
		bytes = int64(rec.Body.Len())
	}
	b.SetBytes(bytes)
}

func BenchmarkSelect1(b *testing.B) { benchQuery(b, `{"sql":"SELECT 1"}`) }
func BenchmarkPointLookup(b *testing.B) {
	benchQuery(b, `{"sql":"SELECT id, amount FROM orders WHERE id = 2"}`)
}
func BenchmarkLargeCSV(b *testing.B) {
	benchQuery(b, `{"sql":"SELECT range AS id, range * 1.5 AS v, 'name-' || range AS s, DATE '2026-01-01' + (range % 365)::INT AS d FROM range(1000000)","format":"csv"}`)
}
func BenchmarkLargeJSON(b *testing.B) {
	benchQuery(b, `{"sql":"SELECT range AS id, range * 1.5 AS v, 'name-' || range AS s, DATE '2026-01-01' + (range % 365)::INT AS d FROM range(1000000)","format":"json"}`)
}

func BenchmarkLargeArrow(b *testing.B) {
	if !engine.ArrowAvailable {
		b.Skip("build with -tags duckdb_arrow")
	}
	benchQuery(b, `{"sql":"SELECT range AS id, range * 1.5 AS v, 'name-' || range AS s, DATE '2026-01-01' + (range % 365)::INT AS d FROM range(1000000)","format":"arrow"}`)
}
