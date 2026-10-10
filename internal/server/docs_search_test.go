package server

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/rerank"
)

// fakeJudge rates documents by title; a missing title fails.
type fakeJudge struct {
	p    map[string]float64
	seen []string // titles of the last candidates
}

func (f *fakeJudge) Judge(_ context.Context, _ string, ds []docs.Doc) []rerank.Judgment {
	out := make([]rerank.Judgment, len(ds))
	f.seen = nil
	for i, d := range ds {
		f.seen = append(f.seen, d.Header.Title)
		if p, ok := f.p[d.Header.Title]; ok {
			out[i].P = p
		} else {
			out[i].Err = errors.New("unavailable")
		}
	}
	return out
}

type searchResult struct {
	Ranker         string
	BelowThreshold bool `json:"below_threshold"`
	Results        []struct {
		Score  float64
		Judged bool
		Doc    map[string]any
	}
}

func (r searchResult) titles() (out []string) {
	for _, h := range r.Results {
		out = append(out, h.Doc["header"].(map[string]any)["title"].(string))
	}
	return
}

// seedDocs writes documents to dir before a server loads it.
func seedDocs(t *testing.T, dir string) {
	t.Helper()
	store, err := docs.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []struct{ title, body, table string }{
		{"Monthly revenue", "Sum orders.amount per month.", "sales.main.orders"},
		{"Customer churn", "A customer churns after 90 days without an order.", "crm.main.customers"},
		{"Refunds", "Refunded orders have status refunded.", "sales.main.refunds"},
	} {
		in := docs.Doc{Header: docs.Header{Title: d.title}, Context: docs.Context{Tables: []string{d.table}, Body: d.body}}
		if _, _, err := store.Create(in, "poet", nil); err != nil {
			t.Fatal(err)
		}
	}
}

func search(t *testing.T, r result) searchResult {
	t.Helper()
	if r.status != 200 {
		t.Fatalf("search: %d %s", r.status, r.body)
	}
	var out searchResult
	if err := json.Unmarshal([]byte(r.body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDocsSearchBM25(t *testing.T) {
	dir := t.TempDir()
	seedDocs(t, dir)
	ts, _ := newDocsServer(t, dir, filepath.Join(t.TempDir(), "audit.jsonl"))

	if r := docReq(t, ts, "POST", "", "/v1/docs/search", `{"q":"revenue"}`); r.status != 401 {
		t.Fatalf("anonymous: %d", r.status)
	}
	for _, body := range []string{`{}`, `{"q":"the"}`, `{"q":"x","limit":51}`, `{"q":"x","fields":"body"}`, `{"q":"x","other":1}`, `nope`} {
		if r := docReq(t, ts, "POST", "analyst", "/v1/docs/search", body); r.status != 400 {
			t.Errorf("%s: %d %s", body, r.status, r.body)
		}
	}

	got := search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"what was the monthly revenue?"}`))
	if got.Ranker != "bm25" || !slices.Equal(got.titles(), []string{"Monthly revenue"}) || got.Results[0].Judged {
		t.Fatalf("revenue: %+v", got)
	}
	// Documents without any question word are left out.
	got = search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"inventory"}`))
	if len(got.Results) != 0 {
		t.Fatalf("inventory: %+v", got)
	}
	got = search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"orders","limit":1,"fields":"header"}`))
	if len(got.Results) != 1 || got.Results[0].Doc["context"].(map[string]any)["body"] != nil {
		t.Fatalf("header only: %+v", got)
	}
	got = search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"orders","table":"refunds"}`))
	if !slices.Equal(got.titles(), []string{"Refunds"}) {
		t.Fatalf("table filter: %v", got.titles())
	}
}

func TestDocsSearchJudged(t *testing.T) {
	dir := t.TempDir()
	seedDocs(t, dir)
	judge := &fakeJudge{p: map[string]float64{"Monthly revenue": 0.8, "Refunds": 0.95, "Customer churn": 0.1}}
	ts, _ := newDocsServer(t, dir, filepath.Join(t.TempDir(), "audit.jsonl"), func(s *Server) {
		s.Judge, s.SearchShortlist = judge, 2
	})

	// Every candidate is judged, ranked by probability; churn is below the threshold.
	got := search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"orders","limit":3}`))
	if got.Ranker != "jev" || got.BelowThreshold || !slices.Equal(got.titles(), []string{"Refunds", "Monthly revenue"}) || !got.Results[0].Judged || got.Results[0].Score != 0.95 {
		t.Fatalf("orders: %+v", got)
	}
	// The judge sees max(shortlist, limit) candidates.
	if len(judge.seen) != 3 {
		t.Fatalf("judge saw %v", judge.seen)
	}
	got = search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"orders","limit":1}`))
	if len(judge.seen) != 2 || len(got.Results) != 1 {
		t.Fatalf("judge saw %v, results %+v", judge.seen, got)
	}

	// Nothing reaches the threshold: the best judged ones, flagged.
	got = search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"churn","table":"customers"}`))
	if !got.BelowThreshold || !slices.Equal(got.titles(), []string{"Customer churn"}) {
		t.Fatalf("churn: %+v", got)
	}

	// With a floor, weak matches below it are left out.
	floored, _ := newDocsServer(t, dir, filepath.Join(t.TempDir(), "audit.jsonl"), func(s *Server) {
		s.Judge, s.SearchFloor = judge, 0.2
	})
	got = search(t, docReq(t, floored, "POST", "analyst", "/v1/docs/search", `{"q":"churn","table":"customers"}`))
	if got.BelowThreshold || len(got.Results) != 0 {
		t.Fatalf("floor: %+v", got)
	}
	judge.p["Customer churn"] = 0.3
	got = search(t, docReq(t, floored, "POST", "analyst", "/v1/docs/search", `{"q":"churn","table":"customers"}`))
	if !got.BelowThreshold || !slices.Equal(got.titles(), []string{"Customer churn"}) {
		t.Fatalf("above the floor: %+v", got)
	}

	// A document the judge cannot rate keeps its BM25 place after matches.
	delete(judge.p, "Monthly revenue")
	got = search(t, docReq(t, ts, "POST", "analyst", "/v1/docs/search", `{"q":"monthly revenue orders","limit":3}`))
	if !slices.Equal(got.titles(), []string{"Refunds", "Monthly revenue"}) || got.Results[1].Judged {
		t.Fatalf("judge failure: %+v", got)
	}
}
