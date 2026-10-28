package docs

import (
	"math"
	"slices"
	"strings"
	"unicode"
)

// Search ranks documents against a question with BM25 over weighted fields.
// Every document's terms are computed when it is loaded or written; term
// statistics are summed per query, which is cheap at the sizes a semantic
// layer reaches (thousands of documents, not millions).

// Field weights: a word in the title says more about a document than the
// same word in its body.
const (
	wTitle   = 3
	wUsedFor = 2.5
	wNames   = 2 // tables and schemas
	wDesc    = 1.5
	wBody    = 1 // body, SQL text and SQL descriptions
)

// BM25 parameters (the usual defaults).
const (
	bm25K1 = 1.2
	bm25B  = 0.75
)

// terms is a document's weighted term frequencies and total weighted length.
type terms struct {
	tf  map[string]float64
	len float64
}

func docTerms(d Doc) terms {
	t := terms{tf: map[string]float64{}}
	add := func(w float64, texts ...string) {
		for _, s := range texts {
			for _, tok := range Tokenize(s) {
				t.tf[tok] += w
				t.len += w
			}
		}
	}
	h, c := d.Header, d.Context
	add(wTitle, h.Title)
	add(wUsedFor, h.UsedFor...)
	add(wNames, c.Tables...)
	add(wNames, c.Schemas...)
	add(wDesc, h.Description)
	add(wBody, c.Body)
	for _, q := range c.SQLs {
		add(wBody, q.SQL, q.Description)
	}
	return t
}

// Hit is a document and its relevance to a question (0 when no question
// term occurs in it).
type Hit struct {
	Doc   Doc
	Score float64
}

// Search returns at most k documents passing f (f.Q is ignored), the most
// relevant to q first. Documents scoring 0 are included when fewer than k
// score higher, so a small filtered set comes back whole; ties keep the
// most recently updated first.
func (s *Store) Search(q string, f Filter, k int) []Hit {
	f.Q = ""
	qt := uniq(Tokenize(q))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.ids) == 0 || k <= 0 {
		return nil
	}
	var total float64
	df := make(map[string]int, len(qt))
	for _, e := range s.ids {
		total += e.terms.len
		for _, tok := range qt {
			if e.terms.tf[tok] > 0 {
				df[tok]++
			}
		}
	}
	n := float64(len(s.ids))
	avg := total / n
	if avg == 0 {
		avg = 1
	}
	hits := make([]Hit, 0, len(s.ids))
	for _, e := range s.ids {
		if !e.doc.Matches(f) {
			continue
		}
		var score float64
		for _, tok := range qt {
			tf := e.terms.tf[tok]
			if tf == 0 {
				continue
			}
			idf := math.Log(1 + (n-float64(df[tok])+0.5)/(float64(df[tok])+0.5))
			score += idf * tf * (bm25K1 + 1) / (tf + bm25K1*(1-bm25B+bm25B*e.terms.len/avg))
		}
		hits = append(hits, Hit{e.doc, score})
	}
	slices.SortFunc(hits, func(a, b Hit) int {
		if a.Score != b.Score {
			if a.Score > b.Score {
				return -1
			}
			return 1
		}
		if c := b.Doc.Header.UpdatedAt.Compare(a.Doc.Header.UpdatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.Doc.ID, b.Doc.ID)
	})
	if len(hits) > k {
		hits = hits[:k]
	}
	return hits
}

// MatchedTerms says which terms of question q occur in d and where: each
// term found maps to the fields holding it, in the order title, used_for,
// tables, schemas, description, body, sql (SQL text and descriptions). The
// terms are tokenized as for Search, so "orders" is reported as "order".
// A document with none has an empty, non-nil map.
func (d Doc) MatchedTerms(q string) map[string][]string {
	h, c := d.Header, d.Context
	var sqls []string
	for _, s := range c.SQLs {
		sqls = append(sqls, s.SQL, s.Description)
	}
	fields := []struct {
		name  string
		texts []string
	}{
		{"title", []string{h.Title}}, {"used_for", h.UsedFor}, {"tables", c.Tables}, {"schemas", c.Schemas},
		{"description", []string{h.Description}}, {"body", []string{c.Body}}, {"sql", sqls},
	}
	out := map[string][]string{}
	qt := uniq(Tokenize(q))
	for _, f := range fields {
		present := map[string]bool{}
		for _, text := range f.texts {
			for _, tok := range Tokenize(text) {
				present[tok] = true
			}
		}
		for _, tok := range qt {
			if present[tok] {
				out[tok] = append(out[tok], f.name)
			}
		}
	}
	return out
}

// Tokenize splits text into lowercase, accent-free words. Identifiers split
// on "_" and "." as well, so "sales.main.order_items" yields "sale",
// "main", "order" and "item". Stopwords are dropped and a plural "s" is
// cut, so "orders" matches "order".
func Tokenize(s string) []string {
	var out []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			if w := b.String(); !stopwords[w] {
				out = append(out, singular(w))
			}
			b.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		if f, ok := fold[r]; ok {
			r = f
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// singular cuts the plural "s" of English and Portuguese words (orders,
// vendas), not of "ss" (address). Crude, but the same on both sides of a
// match, which is what counts.
func singular(w string) string {
	if len(w) > 3 && strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss") {
		return w[:len(w)-1]
	}
	return w
}

func uniq(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// fold maps the accented Latin letters of Portuguese, Spanish, French and
// German to their base letter, so "relatório" matches "relatorio".
var fold = func() map[rune]rune {
	m := map[rune]rune{}
	for base, accented := range map[rune]string{
		'a': "áàâãäå", 'e': "éèêë", 'i': "íìîï", 'o': "óòôõö",
		'u': "úùûü", 'c': "ç", 'n': "ñ", 'y': "ýÿ",
	} {
		for _, r := range accented {
			m[r] = base
		}
	}
	return m
}()

// stopwords are common English and Portuguese words that carry no meaning
// for matching (written without accents: tokens are folded first).
var stopwords = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`
		a an and are as at be by do does for from has have how i in is it its
		me my of on or our show that the their this to was we what when where
		which who why will with you your give get list
		o os as um uma uns umas de do da dos das no na nos nas em e ou que
		para por com sem se ao aos qual quais quanto quantos quantas como
		onde quando foi sao ser esta este estes estas isso isto meu minha
		nosso nossa me mostre mostrar liste listar pelo pela pelos pelas
	`) {
		m[w] = true
	}
	return m
}()
