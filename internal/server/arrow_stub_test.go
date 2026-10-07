//go:build !duckdb_arrow

package server

import (
	"strings"
	"testing"
)

func TestArrowUnavailable(t *testing.T) {
	ts := newServer(t)
	r := do(t, ts, "analyst", `{"sql":"SELECT 1","format":"arrow"}`)
	if r.status != 400 || !strings.Contains(r.body, "duckdb_arrow") {
		t.Fatalf("status=%d body=%s", r.status, r.body)
	}
}
