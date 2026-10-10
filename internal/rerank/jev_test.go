package rerank

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lucasapassos/curral/internal/docs"
)

func doc(title string) docs.Doc {
	return docs.Doc{
		Header:  docs.Header{Title: title},
		Context: docs.Context{Tables: []string{"sales.main.orders"}, Body: strings.Repeat("x", 5000)},
	}
}

// fake answers with the probability named in the document title.
func fake(t *testing.T, status func(n int64) int) (*httptest.Server, *atomic.Int64) {
	var calls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer k" {
			t.Errorf("authorization %q", got)
		}
		var req struct {
			Model string `json:"model"`
			State struct {
				Question string  `json:"question"`
				Document docView `json:"document"`
			} `json:"state"`
			Questions map[string]map[string]any `json:"questions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.Model != "jev-latest" || req.State.Question != "revenue?" || req.Questions["relevant"]["type"] != "noul" {
			t.Errorf("request %+v", req)
		}
		if n := len([]rune(req.State.Document.Body)); n != maxBody+1 {
			t.Errorf("body sent with %d characters", n)
		}
		if status != nil {
			if s := status(n); s != http.StatusOK {
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(s)
				return
			}
		}
		if req.State.Document.Title == "broken" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, `{"model":"jev-1","answers":{"relevant":{"type":"noul","noul":%s}}}`, req.State.Document.Title)
	}))
	t.Cleanup(ts.Close)
	return ts, &calls
}

func TestJudge(t *testing.T) {
	ts, _ := fake(t, nil)
	j := &Jev{Key: "k", URL: ts.URL, Concurrency: 2}
	got := j.Judge(context.Background(), "revenue?", []docs.Doc{doc("0.9"), doc("broken"), doc("0.1")})
	if got[0].Err != nil || got[0].P != 0.9 || got[2].Err != nil || got[2].P != 0.1 {
		t.Fatalf("judgments %+v", got)
	}
	if got[1].Err == nil || !strings.Contains(got[1].Err.Error(), "500") {
		t.Fatalf("broken doc: %+v", got[1])
	}
}

func TestJudgeRetriesWhenRateLimited(t *testing.T) {
	ts, calls := fake(t, func(n int64) int {
		if n < 3 {
			return http.StatusTooManyRequests
		}
		return http.StatusOK
	})
	j := &Jev{Key: "k", URL: ts.URL}
	got := j.Judge(context.Background(), "revenue?", []docs.Doc{doc("0.8")})
	if got[0].Err != nil || got[0].P != 0.8 || calls.Load() != 3 {
		t.Fatalf("judgment %+v after %d calls", got[0], calls.Load())
	}

	// Still limited after the retries: an error, not a hang.
	ts, _ = fake(t, func(int64) int { return 529 })
	j = &Jev{Key: "k", URL: ts.URL}
	if got := j.Judge(context.Background(), "revenue?", []docs.Doc{doc("0.8")}); got[0].Err == nil {
		t.Fatal("expected an error")
	}
}

func TestJudgeTimeout(t *testing.T) {
	release := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer ts.Close()
	defer close(release)
	j := &Jev{Key: "k", URL: ts.URL, Timeout: 50 * time.Millisecond}
	start := time.Now()
	got := j.Judge(context.Background(), "revenue?", []docs.Doc{doc("0.8"), doc("0.7")})
	if time.Since(start) > 2*time.Second || got[0].Err == nil || got[1].Err == nil {
		t.Fatalf("judgments %+v after %v", got, time.Since(start))
	}
}
