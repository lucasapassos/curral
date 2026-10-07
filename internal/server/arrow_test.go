//go:build duckdb_arrow

package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"

	"curral/internal/policy"
)

func TestArrowFormat(t *testing.T) {
	ts := newServer(t)
	r := do(t, ts, "analyst", `{"sql":"SELECT id, amount, 'x' || id AS s FROM orders ORDER BY id","format":"arrow"}`)
	if r.status != 200 || r.header.Get("Content-Type") != "application/vnd.apache.arrow.stream" ||
		r.trailer.Get("X-Curral-Row-Count") != "2" {
		t.Fatalf("status=%d headers=%v trailer=%v", r.status, r.header, r.trailer)
	}
	rd, err := ipc.NewReader(strings.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Release()
	if got := rd.Schema().String(); !strings.Contains(got, "id: type=int32") || !strings.Contains(got, "amount: type=decimal") {
		t.Fatalf("schema: %s", got)
	}
	var ids []int32
	for rd.Next() {
		rec := rd.RecordBatch()
		col := rec.Column(0).(*array.Int32)
		for i := range int(rec.NumRows()) {
			ids = append(ids, col.Value(i))
		}
		if s := rec.Column(2).(*array.String).Value(0); s != "x1" {
			t.Fatalf("string column: %q", s)
		}
	}
	if len(ids) != 2 || ids[0] != 1 || ids[1] != 2 {
		t.Fatalf("ids = %v", ids)
	}

	// Runtime error before any data: a real error status, not an empty 200.
	if r := do(t, ts, "analyst", `{"sql":"SELECT 'x'::INT FROM orders","format":"arrow"}`); r.status != 400 {
		t.Fatalf("error before data: %d %s", r.status, r.body)
	}
	// Authorization applies as for any other format.
	if r := do(t, ts, "analyst", `{"sql":"SELECT * FROM salaries","format":"arrow"}`); r.status != 403 {
		t.Fatalf("policy: %d", r.status)
	}
}

func TestArrowMaxRows(t *testing.T) {
	ts := newServer(t)
	f := filepath.Join(t.TempDir(), "p.rego")
	os.WriteFile(f, []byte("package curral\nimport rego.v1\nallow := true\nlimits := {\"max_rows\": 1500}\n"), 0o600)
	pol, err := policy.Load(context.Background(), "data.curral.allow", []string{f}, "data.curral.limits")
	if err != nil {
		t.Fatal(err)
	}
	lastServer.SetPolicy(pol)
	r := do(t, ts, "analyst", `{"sql":"SELECT * FROM range(100000)","format":"arrow"}`)
	if r.trailer.Get("X-Curral-Row-Count") != "1500" || r.trailer.Get("X-Curral-Error") != "row limit reached" {
		t.Fatalf("trailer=%v", r.trailer)
	}
	rd, err := ipc.NewReader(strings.NewReader(r.body))
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Release()
	var n int64
	for rd.Next() {
		n += rd.RecordBatch().NumRows()
	}
	if n != 1500 {
		t.Fatalf("rows in stream = %d", n)
	}
}
