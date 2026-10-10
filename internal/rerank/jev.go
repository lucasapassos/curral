// Package rerank judges how well semantic documents fit a question with
// TypeSafe's Jev model, one document per request, so /v1/docs/search can
// keep the documents that help write the SQL and rank them.
package rerank

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/lucasapassos/curral/internal/docs"
)

// DefaultURL is TypeSafe's System One endpoint.
const DefaultURL = "https://api.typesafe.ai/v1/systemone"

// Judgment is the probability that a document helps answer the question.
// Err is set when the document could not be judged; P is then 0.
type Judgment struct {
	P   float64
	Err error
}

// Judge rates each document against a question; the result has one
// Judgment per document, in order.
type Judge interface {
	Judge(ctx context.Context, question string, ds []docs.Doc) []Judgment
}

// Jev calls the TypeSafe API. Zero fields take the defaults below.
type Jev struct {
	Key         string
	URL         string        // DefaultURL
	Model       string        // jev-latest
	Concurrency int           // requests in flight: 8
	Timeout     time.Duration // for the whole batch: 5s
	Client      *http.Client  // http.DefaultClient
}

// Limits on what is sent per document: enough to judge, bounded in tokens.
const (
	maxBody = 4000
	maxSQL  = 500
)

func (j *Jev) Judge(ctx context.Context, question string, ds []docs.Doc) []Judgment {
	timeout, conc := j.Timeout, j.Concurrency
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if conc <= 0 {
		conc = 8
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out := make([]Judgment, len(ds))
	sem := make(chan struct{}, conc)
	var wg sync.WaitGroup
	for i, d := range ds {
		wg.Go(func() {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out[i].Err = ctx.Err()
				return
			}
			out[i].P, out[i].Err = j.judge(ctx, question, d)
		})
	}
	wg.Wait()
	return out
}

// The question asks whether the query would use the document, not whether
// they share a topic. A document covering only part of the question still
// counts (one with no date column for "last month"), and so does one whose
// rule the query must invert (excluded cancelled orders for "cancelled
// sales"); a close topic over other data does not. Asking whether the
// document holds everything the query needs left such partial matches near
// 0.4. Keep the false example off the domain of real documents.
var relevant = map[string]any{
	"type":         "noul",
	"instructions": "Would the SQL query that answers `question` use data or rules described in `document`? The question and the document may use different languages and words for the same thing.",
	"criteria": map[string]string{
		"true":  "The query would read a table or column the document describes, compute a metric it defines, or need to apply or invert a business rule it states (such as which rows to include or exclude), even if the document covers only part of the question.",
		"false": "The query would read none of the data the document describes and need none of its rules, even if the topic sounds close, such as a document on job openings for a question about employee turnover.",
	},
}

type sqlView struct {
	Description string `json:"description,omitempty"`
	SQL         string `json:"sql"`
}

type docView struct {
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	UsedFor     []string  `json:"used_for,omitempty"`
	Schemas     []string  `json:"schemas,omitempty"`
	Tables      []string  `json:"tables,omitempty"`
	Body        string    `json:"body"`
	SQLs        []sqlView `json:"sqls,omitempty"`
}

func view(d docs.Doc) docView {
	v := docView{
		Title: d.Header.Title, Description: d.Header.Description, UsedFor: d.Header.UsedFor,
		Schemas: d.Context.Schemas, Tables: d.Context.Tables, Body: truncate(d.Context.Body, maxBody),
	}
	for _, q := range d.Context.SQLs {
		v.SQLs = append(v.SQLs, sqlView{q.Description, truncate(q.SQL, maxSQL)})
	}
	return v
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

type response struct {
	Answers map[string]struct {
		Noul *float64 `json:"noul"`
	} `json:"answers"`
}

// judge sends one request, retrying while the service is rate limited or
// overloaded.
func (j *Jev) judge(ctx context.Context, question string, d docs.Doc) (float64, error) {
	url, model, client := j.URL, j.Model, j.Client
	if url == "" {
		url = DefaultURL
	}
	if model == "" {
		model = "jev-latest"
	}
	if client == nil {
		client = http.DefaultClient
	}
	body, err := json.Marshal(map[string]any{
		"model":     model,
		"state":     map[string]any{"question": question, "document": view(d)},
		"questions": map[string]any{"relevant": relevant},
	})
	if err != nil {
		return 0, err
	}
	backoff := 250 * time.Millisecond
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+j.Key)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if err != nil {
			return 0, err
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			var r response
			if err := json.Unmarshal(b, &r); err != nil {
				return 0, fmt.Errorf("jev: invalid response: %w", err)
			}
			if a, ok := r.Answers["relevant"]; ok && a.Noul != nil {
				return *a.Noul, nil
			}
			return 0, errors.New("jev: response has no answer")
		case (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 529) && attempt < 2:
			wait := backoff << attempt
			if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
				wait = time.Duration(s) * time.Second
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return 0, ctx.Err()
			}
		default:
			return 0, fmt.Errorf("jev: %s: %s", resp.Status, truncate(string(b), 200))
		}
	}
}
