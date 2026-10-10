package docs

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTokenize(t *testing.T) {
	for in, want := range map[string]string{
		"Relatório de Vendas":            "relatorio venda",
		"sales.main.order_items":         "sale main order item",
		"What is the monthly REVENUE?":   "monthly revenue",
		"  ":                             "",
		"Ação, preço e conversão (2026)": "acao preco conversao 2026",
	} {
		if got := strings.Join(Tokenize(in), " "); got != want {
			t.Errorf("Tokenize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSearch(t *testing.T) {
	s, _ := Open(t.TempDir())
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	mk := func(title, body string, tables ...string) Doc {
		d, _, err := s.Create(Doc{
			Header:  Header{Title: title},
			Context: Context{Tables: tables, Body: body},
		}, "ana", nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	revenue := mk("Monthly revenue", "Sum orders.amount per month.", "sales.main.orders")
	churn := mk("Customer churn", "A customer churns after 90 days without an order.", "crm.main.customers")
	items := mk("Order items", "One row per product in an order.", "sales.main.order_items")
	report := mk("Relatório de devoluções", "Devoluções por mês.", "sales.main.returns")

	top := func(q string, f Filter, k int) []string {
		var out []string
		for _, h := range s.Search(q, f, k) {
			if h.Score > 0 {
				out = append(out, h.Doc.ID)
			}
		}
		return out
	}
	for _, c := range []struct {
		q    string
		f    Filter
		want []string
	}{
		{"what was the revenue last month?", Filter{}, []string{revenue.ID}},
		{"which customers churned", Filter{}, []string{churn.ID}},
		// The title outranks a mention in the body.
		{"customer", Filter{}, []string{churn.ID}},
		{"relatorio devolucoes", Filter{}, []string{report.ID}},
		{"order", Filter{Table: "order_items"}, []string{items.ID}},
		{"nothing matches this", Filter{}, nil},
	} {
		if got := top(c.q, c.f, 10); !slices.Equal(got, c.want) {
			t.Errorf("%q %+v: got %v want %v", c.q, c.f, got, c.want)
		}
	}

	// Table names split into words and plurals fold: every doc about orders
	// matches, the one about order items first.
	if got := top("order items", Filter{}, 10); len(got) != 3 || got[0] != items.ID {
		t.Errorf("order items: %v", got)
	}

	// k bounds the result; zero-score documents fill it, newest first.
	if got := s.Search("revenue", Filter{}, 2); len(got) != 2 || got[0].Doc.ID != revenue.ID || got[1].Doc.ID != report.ID {
		t.Fatalf("k=2: %+v", got)
	}
	if got := s.Search("revenue", Filter{}, 0); got != nil {
		t.Fatalf("k=0: %+v", got)
	}
}

func TestSearchAfterReload(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	d, _, _ := s.Create(sample("Monthly revenue"), "ana", nil)
	path := filepath.Join(dir, d.ID+".json")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"title": "Monthly revenue"`, `"title": "Refunds"`, 1)), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if h := s.Search("refunds", Filter{}, 1); len(h) != 1 || h[0].Score == 0 {
		t.Fatalf("reload did not reindex: %+v", h)
	}
}
