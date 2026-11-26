//go:build !duckdb_arrow

package server

import (
	"strings"
	"testing"
)

func TestArrowUnavailable(t *testing.T) {
	ts := newServer(t)
	for _, format := range []string{"arrow", "parquet"} {
		r := do(t, ts, "analyst", `{"sql":"SELECT 1","format":"`+format+`"}`)
		if r.status != 501 || !strings.Contains(r.body, "duckdb_arrow") {
			t.Fatalf("format=%s status=%d body=%s", format, r.status, r.body)
		}
	}
}
