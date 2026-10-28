package docs

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sample(title string) Doc {
	return Doc{
		Header: Header{Title: title, Description: " Revenue per month ", UsedFor: []string{"finance", " "}},
		Context: Context{
			Tables: []string{"sales.main.orders"},
			Body:   "orders.amount is the gross value.",
			SQLs:   []SQL{{SQL: "SELECT sum(amount) FROM sales.main.orders", Description: "total"}},
		},
	}
}

func TestCreateGetPersist(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	in := sample("Monthly revenue")
	in.Header.Author = "forged" // server-set fields are ignored
	d, tag, err := s.Create(in, "ana", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidID(d.ID) || tag == "" {
		t.Fatalf("id %q etag %q", d.ID, tag)
	}
	if d.Header.Author != "ana" || d.Header.CreatedAt.IsZero() || !d.Header.CreatedAt.Equal(d.Header.UpdatedAt) {
		t.Fatalf("header %+v", d.Header)
	}
	if d.Header.Description != "Revenue per month" || len(d.Header.UsedFor) != 1 {
		t.Fatalf("not normalized: %+v", d.Header)
	}

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != d.ID+".json" {
		t.Fatalf("files %v", entries)
	}

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, tag2, err := s2.Get(d.ID)
	if err != nil || tag2 != tag || got.Header.Title != "Monthly revenue" || got.Header.Author != "ana" {
		t.Fatalf("reopened: %+v %q %v", got, tag2, err)
	}
}

func TestValidation(t *testing.T) {
	s, _ := Open(t.TempDir())
	for name, mod := range map[string]func(*Doc){
		"no title": func(d *Doc) { d.Header.Title = "  " },
		"no body":  func(d *Doc) { d.Context.Body = "" },
		"long":     func(d *Doc) { d.Header.Title = strings.Repeat("x", MaxTitle+1) },
		"no sql":   func(d *Doc) { d.Context.SQLs = []SQL{{Description: "x"}} },
	} {
		d := sample("t")
		mod(&d)
		var ve *ValidationError
		if _, _, err := s.Create(d, "ana", nil); !errors.As(err, &ve) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := Decode([]byte(`{"header":{"title":"x","titel":"y"}}`)); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestUpdatePatchDelete(t *testing.T) {
	s, _ := Open(t.TempDir())
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	d, tag, _ := s.Create(sample("A"), "ana", nil)

	if _, _, err := s.Replace(d.ID, sample("B"), "bia", `"stale"`, nil); !errors.Is(err, ErrPrecondition) {
		t.Fatalf("stale If-Match: %v", err)
	}
	r, tag2, err := s.Replace(d.ID, sample("B"), "bia", tag, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Header.Title != "B" || r.Header.Author != "ana" || r.Header.UpdatedBy != "bia" ||
		!r.Header.UpdatedAt.After(r.Header.CreatedAt) || tag2 == tag {
		t.Fatalf("replace: %+v", r.Header)
	}

	p, _, err := s.Patch(d.ID, []byte(`{"header":{"description":null,"used_for":["ops"]},"context":{"sqls":null}}`), "caio", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Header.Title != "B" || p.Header.Description != "" || p.Header.UsedFor[0] != "ops" ||
		p.Context.SQLs != nil || p.Context.Body == "" || p.Header.UpdatedBy != "caio" {
		t.Fatalf("patch: %+v", p)
	}
	if _, _, err := s.Patch(d.ID, []byte(`{"context":{"body":null}}`), "caio", "", nil); err == nil {
		t.Fatal("patch removing the body accepted")
	}
	if _, _, err := s.Patch(d.ID, []byte(`[1]`), "caio", "", nil); err == nil {
		t.Fatal("non-object patch accepted")
	}

	if err := s.Delete(d.ID, "", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Get(d.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
	if err := s.Delete(d.ID, "", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 0 {
		t.Fatalf("files left: %v", entries)
	}
}

func TestListFilters(t *testing.T) {
	s, _ := Open(t.TempDir())
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { clock = clock.Add(time.Minute); return clock }
	a, _, _ := s.Create(sample("Monthly revenue"), "ana", nil)
	other := sample("Customer churn")
	other.Context.Tables, other.Context.Schemas = []string{"crm.main.customers"}, []string{"crm.main"}
	other.Header.Description, other.Header.UsedFor = "", nil
	b, _, _ := s.Create(other, "ana", nil)

	ids := func(ds []Doc) (out []string) {
		for _, d := range ds {
			out = append(out, d.ID)
		}
		return
	}
	for _, c := range []struct {
		f    Filter
		want []string
	}{
		{Filter{}, []string{b.ID, a.ID}},
		{Filter{Table: "orders"}, []string{a.ID}},
		{Filter{Table: "MAIN.ORDERS"}, []string{a.ID}},
		{Filter{Table: "ders"}, nil},
		{Filter{Schema: "main"}, []string{b.ID}},
		{Filter{Q: "CHURN"}, []string{b.ID}},
		{Filter{Q: "finance"}, []string{a.ID}},
		// Lists match any of their names, alone or with the single form.
		{Filter{Tables: []string{"nope", "orders"}}, []string{a.ID}},
		{Filter{Tables: []string{"nope"}}, nil},
		{Filter{Table: "nope", Tables: []string{"orders"}}, []string{a.ID}},
		{Filter{Schemas: []string{"other", "MAIN"}}, []string{b.ID}},
		{Filter{Tables: []string{"orders"}, Schemas: []string{"main"}}, nil},
	} {
		if got := ids(s.List(c.f)); strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%+v: got %v want %v", c.f, got, c.want)
		}
	}
}

func TestReload(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	d, _, _ := s.Create(sample("A"), "ana", nil)
	path := filepath.Join(dir, d.ID+".json")
	b, _ := os.ReadFile(path)
	os.WriteFile(path, []byte(strings.Replace(string(b), `"title": "A"`, `"title": "Edited"`, 1)), 0o640)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get(d.ID); got.Header.Title != "Edited" {
		t.Fatalf("title %q", got.Header.Title)
	}

	os.WriteFile(filepath.Join(dir, "BAD.json"), []byte(`{}`), 0o640)
	if err := s.Reload(); err == nil {
		t.Fatal("invalid file name accepted")
	}
	if s.Len() != 1 {
		t.Fatal("failed reload dropped documents")
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("Open accepted an invalid file")
	}
}

func TestValidID(t *testing.T) {
	for id, ok := range map[string]bool{
		"0192f1c3a4b9f2e1": true, "../etc/passwd": false, "short": false, "UPPERCASE1": false, "": false,
	} {
		if ValidID(id) != ok {
			t.Errorf("ValidID(%q) = %v", id, !ok)
		}
	}
}

func TestCheck(t *testing.T) {
	s, _ := Open(t.TempDir())
	deny := errors.New("denied")
	if _, _, err := s.Create(sample("A"), "ana", func(old, next *Doc) error {
		if old != nil || next == nil || next.Header.Title != "A" || next.Header.Author != "ana" {
			t.Errorf("create check got old=%v next=%v", old, next)
		}
		return deny
	}); err != deny || s.Len() != 0 {
		t.Fatalf("denied create: %v, %d docs", err, s.Len())
	}
	if entries, _ := os.ReadDir(s.Dir()); len(entries) != 0 {
		t.Fatalf("denied create wrote %v", entries)
	}
	d, _, _ := s.Create(sample("A"), "ana", nil)
	if _, _, err := s.Patch(d.ID, []byte(`{"header":{"title":"B"}}`), "bia", "", func(old, next *Doc) error {
		if old.Header.Title != "A" || next.Header.Title != "B" {
			t.Errorf("patch check got %q -> %q", old.Header.Title, next.Header.Title)
		}
		return deny
	}); err != deny {
		t.Fatalf("denied patch: %v", err)
	}
	if err := s.Delete(d.ID, "", func(old, next *Doc) error {
		if old == nil || next != nil {
			t.Error("delete check arguments")
		}
		return deny
	}); err != deny {
		t.Fatalf("denied delete: %v", err)
	}
	if got, _, _ := s.Get(d.ID); got.Header.Title != "A" {
		t.Fatalf("denied writes changed the document: %+v", got.Header)
	}
}

func TestStoreCount(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for title, tables := range map[string][]string{
		"a": {"orders"}, "b": {"SALES.main.orders", " orders "}, "c": {"salaries"}, "d": {"main.salaries", "nope"}, "e": nil,
	} {
		if _, _, err := s.Create(Doc{Header: Header{Title: title}, Context: Context{Tables: tables, Body: "b"}}, "u", nil); err != nil {
			t.Fatal(err)
		}
	}
	tables := []string{"sales.main.orders", "hr.main.salaries", "Sales.Main.Salaries", "logs.main.events"}
	got := s.Count(tables, nil)
	want := map[string]int{"sales.main.orders": 2, "hr.main.salaries": 2, "Sales.Main.Salaries": 2}
	if len(got) != len(want) {
		t.Fatalf("count: %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %d, want %d", k, got[k], v)
		}
	}
	// A condition narrows what counts; nothing matching leaves no keys.
	only := func(d Doc) bool { return d.Header.Title == "c" }
	if got := s.Count(tables, only); len(got) != 2 || got["hr.main.salaries"] != 1 {
		t.Errorf("filtered count: %v", got)
	}
	if got := s.Count(tables, func(Doc) bool { return false }); len(got) != 0 {
		t.Errorf("empty count: %v", got)
	}
}
