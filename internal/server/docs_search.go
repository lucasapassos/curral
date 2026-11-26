package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/docs"
	"github.com/lucasapassos/curral/internal/rerank"
)

// Search answers "which documents help with this question?" in up to three
// layers: the table/schema filters, a BM25 shortlist, and, when a Judge is
// configured, a per-document judgment that decides what matches and in
// which order.

const (
	defaultSearchLimit     = 5
	maxSearchLimit         = 50
	defaultSearchShortlist = 20
)

type searchRequest struct {
	Q       string   `json:"q"`
	Table   string   `json:"table"`
	Tables  []string `json:"tables"` // any of them; not with Table
	Schema  string   `json:"schema"`
	Schemas []string `json:"schemas"` // any of them; not with Schema
	Limit   int      `json:"limit"`
	Fields  string   `json:"fields"`
	Access  bool     `json:"access"` // annotate results with the caller's access under --docs-scope all
}

// searchHit is one result. Score is the Judge's probability when Judged,
// otherwise the BM25 score (not comparable between the two). Matched says
// which question terms the document holds and in which fields: a reason
// for the match when the ranker is BM25 alone.
type searchHit struct {
	Score   float64             `json:"score"`
	Judged  bool                `json:"judged"`
	Matched map[string][]string `json:"matched"`
	Doc     any                 `json:"doc"`
}

type searchResponse struct {
	Ranker string `json:"ranker"`
	// BelowThreshold: no document reached the threshold, so the best judged
	// ones at or above the floor are returned anyway; treat them as weak
	// matches.
	BelowThreshold bool        `json:"below_threshold,omitempty"`
	Results        []searchHit `json:"results"`
}

func (s *Server) searchDocs(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	start := time.Now()
	ranker := "bm25"
	if s.Judge != nil {
		ranker = "jev"
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.MaxBody))
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(status), time.Since(start))
		writeError(w, status, "invalid request body: "+err.Error())
		return
	}
	var in searchRequest
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(http.StatusBadRequest), time.Since(start))
		writeError(w, http.StatusBadRequest, "invalid search request: "+err.Error())
		return
	}
	switch {
	case len(docs.Tokenize(in.Q)) == 0:
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(http.StatusBadRequest), time.Since(start))
		writeError(w, http.StatusBadRequest, "q is required")
		return
	case in.Limit < 0 || in.Limit > maxSearchLimit:
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(http.StatusBadRequest), time.Since(start))
		writeError(w, http.StatusBadRequest, "limit must be between 1 and 50")
		return
	case in.Fields != "" && in.Fields != "full" && in.Fields != "header":
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(http.StatusBadRequest), time.Since(start))
		writeError(w, http.StatusBadRequest, "fields must be full or header")
		return
	}
	if in.Limit == 0 {
		in.Limit = defaultSearchLimit
	}
	// The filters apply before ranking, so documents outside them take no
	// place in the shortlist or the limit.
	f := docs.Filter{Table: in.Table, Schema: in.Schema}
	if f.Tables, err = nameFilter("table", in.Table, in.Tables); err == nil {
		f.Schemas, err = nameFilter("schema", in.Schema, in.Schemas)
	}
	if err != nil {
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(http.StatusBadRequest), time.Since(start))
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	a, status, msg := s.docAccess(r, p, in.Access)
	if status != http.StatusOK {
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(status), time.Since(start))
		writeSchemaError(w, status, msg)
		return
	}
	hit := func(score float64, judged bool, d docs.Doc) searchHit {
		v, _ := a.view(d, in.Fields == "header")
		return searchHit{score, judged, d.MatchedTerms(in.Q), v}
	}
	f.Allow = a.allow

	if s.Judge == nil {
		out := searchResponse{Ranker: "bm25", Results: []searchHit{}}
		for _, h := range s.Docs.Search(in.Q, f, in.Limit) {
			if h.Score > 0 {
				out.Results = append(out.Results, hit(h.Score, false, h.Doc))
			}
		}
		s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(http.StatusOK), time.Since(start))
		writeJSON(w, http.StatusOK, out)
		return
	}

	shortlist, threshold := s.SearchShortlist, s.SearchThreshold
	if shortlist <= 0 {
		shortlist = defaultSearchShortlist
	}
	if threshold <= 0 {
		threshold = rerank.DefaultThreshold
	}
	hits := s.Docs.Search(in.Q, f, max(shortlist, in.Limit))
	ds := make([]docs.Doc, len(hits))
	for i, h := range hits {
		ds[i] = h.Doc
	}
	jevStart := time.Now()
	js := s.Judge.Judge(r.Context(), in.Q, ds)
	jevDur := time.Since(jevStart)

	// A document the Judge could not rate keeps its BM25 place after the
	// judged matches rather than failing the search.
	var matched, weak, unjudged []searchHit
	failed := 0
	for i, h := range hits {
		switch j := js[i]; {
		case j.Err != nil:
			if failed++; failed == 1 {
				s.Log.Warn("document search: judge failed", "doc", h.Doc.ID, "err", j.Err)
			}
			if h.Score > 0 {
				unjudged = append(unjudged, hit(h.Score, false, h.Doc))
			}
		case j.P >= threshold:
			matched = append(matched, hit(j.P, true, h.Doc))
		case j.P >= s.SearchFloor:
			weak = append(weak, hit(j.P, true, h.Doc))
		}
	}
	if len(hits) > 0 {
		s.Metrics.ObserveJev(len(hits)-failed, failed, jevDur)
	}
	if failed > 1 {
		s.Log.Warn("document search: judge failed for several documents", "failed", failed, "candidates", len(hits))
	}
	byScore := func(a, b searchHit) int {
		switch {
		case a.Score > b.Score:
			return -1
		case a.Score < b.Score:
			return 1
		}
		return 0
	}
	slices.SortStableFunc(matched, byScore)
	slices.SortStableFunc(weak, byScore)
	out := searchResponse{Ranker: "jev", Results: matched}
	if len(matched) == 0 && len(weak) > 0 {
		out.BelowThreshold, out.Results = true, weak
	}
	out.Results = append(out.Results, unjudged...)
	if len(out.Results) > in.Limit {
		out.Results = out.Results[:in.Limit]
	}
	if out.Results == nil {
		out.Results = []searchHit{}
	}
	s.Metrics.ObserveDocsSearch(ranker, strconv.Itoa(http.StatusOK), time.Since(start))
	writeJSON(w, http.StatusOK, out)
}
