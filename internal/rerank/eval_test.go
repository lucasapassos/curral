package rerank

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lucasapassos/curral/internal/docs"
)

// TestJevEval checks the question asked of Jev against labeled cases, through
// the real TypeSafe API. It runs only when CURRAL_JEV_KEY is set:
//
//	set -a; . ./.env; set +a; go test ./internal/rerank -run JevEval -v
//
// Each case lists the documents that must match (at DefaultThreshold or
// above) and those that may; every other document must stay below. The log
// shows each probability, so a change to the question or the threshold can
// be compared with the previous run. CURRAL_JEV_EVAL points to another file
// in the same format, such as one with your own documents and questions
// (documents as GET /v1/docs/{id} returns them); keep it out of the repo.
func TestJevEval(t *testing.T) {
	key := os.Getenv("CURRAL_JEV_KEY")
	if key == "" {
		t.Skip("CURRAL_JEV_KEY not set")
	}
	path := os.Getenv("CURRAL_JEV_EVAL")
	if path == "" {
		path = "testdata/eval.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Docs  map[string]docs.Doc
		Cases []struct {
			Q     string
			Match []string
			May   []string
		}
	}
	if err := json.Unmarshal(b, &set); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	names := make([]string, 0, len(set.Docs))
	for name := range set.Docs {
		names = append(names, name)
	}
	slices.Sort(names)
	ds := make([]docs.Doc, len(names))
	for i, name := range names {
		ds[i] = set.Docs[name]
	}

	j := &Jev{Key: key, Timeout: time.Minute}
	minMatch, maxOther := 1.0, 0.0
	for _, c := range set.Cases {
		for _, name := range slices.Concat(c.Match, c.May) {
			if _, ok := set.Docs[name]; !ok {
				t.Fatalf("%q: no document %q", c.Q, name)
			}
		}
		js := j.Judge(context.Background(), c.Q, ds)
		var line strings.Builder
		for i, name := range names {
			if js[i].Err != nil {
				t.Fatalf("%q, %s: %v", c.Q, name, js[i].Err)
			}
			p := js[i].P
			mark := " "
			switch {
			case slices.Contains(c.Match, name):
				mark, minMatch = "+", min(minMatch, p)
				if p < DefaultThreshold {
					t.Errorf("%q: %s should match, got %.2f", c.Q, name, p)
				}
			case slices.Contains(c.May, name):
				mark = "~"
			default:
				maxOther = max(maxOther, p)
				if p >= DefaultThreshold {
					t.Errorf("%q: %s should not match, got %.2f", c.Q, name, p)
				}
			}
			fmt.Fprintf(&line, " %s%s=%.2f", mark, name, p)
		}
		t.Logf("%-45s%s", c.Q, line.String())
	}
	t.Logf("threshold %.2f: lowest match %.2f, highest non-match %.2f", DefaultThreshold, minMatch, maxOther)
}
