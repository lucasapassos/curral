//go:build duckdb_arrow

package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/ipc"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"

	"github.com/lucasapassos/curral/internal/policy"
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

func TestParquetOutput(t *testing.T) {
	ts := newServer(t)

	// 1. format: "parquet" returns valid Parquet bytes readable via pqarrow.
	r := do(t, ts, "analyst", `{"sql":"SELECT id, amount, 'x' || id AS s FROM orders ORDER BY id","format":"parquet"}`)
	if r.status != 200 || r.header.Get("Content-Type") != "application/vnd.apache.parquet" ||
		r.trailer.Get("X-Curral-Row-Count") != "2" {
		t.Fatalf("status=%d headers=%v trailer=%v", r.status, r.header, r.trailer)
	}
	tbl, err := pqarrow.ReadTable(context.Background(), bytes.NewReader([]byte(r.body)), nil, pqarrow.ArrowReadProperties{}, memory.DefaultAllocator)
	if err != nil {
		t.Fatalf("read parquet: %v", err)
	}
	defer tbl.Release()
	if tbl.NumRows() != 2 || tbl.NumCols() != 3 {
		t.Fatalf("parquet shape = %dx%d", tbl.NumRows(), tbl.NumCols())
	}
	if got := tbl.Schema().String(); !strings.Contains(got, "id: type=int32") || !strings.Contains(got, "amount: type=decimal") {
		t.Fatalf("schema: %s", got)
	}
	idChunk := tbl.Column(0).Data().Chunk(0).(*array.Int32)
	if idChunk.Value(0) != 1 || idChunk.Value(1) != 2 {
		t.Fatalf("ids = [%d, %d]", idChunk.Value(0), idChunk.Value(1))
	}
	sChunk := tbl.Column(2).Data().Chunk(0).(*array.String)
	if sChunk.Value(0) != "x1" || sChunk.Value(1) != "x2" {
		t.Fatalf("strings = [%q, %q]", sChunk.Value(0), sChunk.Value(1))
	}

	// 2. Accept: application/vnd.apache.parquet selects Parquet without format field.
	req, err := http.NewRequest("POST", ts.URL+"/v1/query", strings.NewReader(`{"sql":"SELECT id FROM orders ORDER BY id"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth("analyst", "analyst-pw")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.apache.parquet")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/vnd.apache.parquet" {
		t.Fatalf("accept parquet: status=%d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	tblAccept, err := pqarrow.ReadTable(context.Background(), bytes.NewReader(bodyBytes), nil, pqarrow.ArrowReadProperties{}, memory.DefaultAllocator)
	if err != nil {
		t.Fatalf("read accept parquet: %v", err)
	}
	defer tblAccept.Release()
	if tblAccept.NumRows() != 2 {
		t.Fatalf("accept parquet rows = %d", tblAccept.NumRows())
	}

	// 3. Empty result set produces a valid 0-row Parquet file with schema.
	emptyRes := do(t, ts, "analyst", `{"sql":"SELECT id, amount FROM orders WHERE 1 = 0","format":"parquet"}`)
	if emptyRes.status != 200 || emptyRes.header.Get("Content-Type") != "application/vnd.apache.parquet" ||
		emptyRes.trailer.Get("X-Curral-Row-Count") != "0" {
		t.Fatalf("empty status=%d headers=%v trailer=%v", emptyRes.status, emptyRes.header, emptyRes.trailer)
	}
	tblEmpty, err := pqarrow.ReadTable(context.Background(), bytes.NewReader([]byte(emptyRes.body)), nil, pqarrow.ArrowReadProperties{}, memory.DefaultAllocator)
	if err != nil {
		t.Fatalf("read empty parquet: %v", err)
	}
	defer tblEmpty.Release()
	if tblEmpty.NumRows() != 0 || tblEmpty.NumCols() != 2 {
		t.Fatalf("empty parquet shape = %dx%d", tblEmpty.NumRows(), tblEmpty.NumCols())
	}

	// 4. Runtime error before data and policy denial work as for other formats.
	if r := do(t, ts, "analyst", `{"sql":"SELECT 'x'::INT FROM orders","format":"parquet"}`); r.status != 400 {
		t.Fatalf("error before data: %d %s", r.status, r.body)
	}
	if r := do(t, ts, "analyst", `{"sql":"SELECT * FROM salaries","format":"parquet"}`); r.status != 403 {
		t.Fatalf("policy: %d", r.status)
	}

	// 5. max_rows truncation writes a valid Parquet file with exactly max_rows rows.
	truncRes := do(t, ts, "analyst", `{"sql":"SELECT * FROM range(100000)","format":"parquet","max_rows":1500}`)
	if truncRes.status != 200 || truncRes.trailer.Get("X-Curral-Row-Count") != "1500" ||
		truncRes.trailer.Get("X-Curral-Error") != "row limit reached" {
		t.Fatalf("trunc status=%d trailer=%v", truncRes.status, truncRes.trailer)
	}
	tblTrunc, err := pqarrow.ReadTable(context.Background(), bytes.NewReader([]byte(truncRes.body)), nil, pqarrow.ArrowReadProperties{}, memory.DefaultAllocator)
	if err != nil {
		t.Fatalf("read truncated parquet: %v", err)
	}
	defer tblTrunc.Release()
	if tblTrunc.NumRows() != 1500 {
		t.Fatalf("truncated parquet rows = %d", tblTrunc.NumRows())
	}
}
