// Package docs stores semantic documents: human-written notes on what
// schemas and tables mean and which SQL answers which question, kept as one
// JSON file each so AI agents can use them as a semantic layer.
package docs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Doc is one semantic document. Author, CreatedAt, UpdatedAt and UpdatedBy
// are set by the server; everything else comes from the writer.
type Doc struct {
	ID      string  `json:"id"`
	Header  Header  `json:"header"`
	Context Context `json:"context"`
}

type Header struct {
	Author      string    `json:"author"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	Title       string    `json:"title"`
	Description string    `json:"description,omitempty"`
	UsedFor     []string  `json:"used_for,omitempty"`
}

type Context struct {
	Schemas []string `json:"schemas,omitempty"`
	Tables  []string `json:"tables,omitempty"`
	Body    string   `json:"body"`
	SQLs    []SQL    `json:"sqls,omitempty"`
}

type SQL struct {
	SQL         string `json:"sql"`
	Description string `json:"description,omitempty"`
}

// MaxTitle is the longest title accepted, in characters.
const MaxTitle = 200

// ValidationError is a document the writer must fix.
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, a ...any) error {
	return &ValidationError{fmt.Sprintf(format, a...)}
}

// Decode reads a document sent by a writer. Unknown fields are refused so a
// typo is not silently dropped; the server-set fields are accepted (a GET
// response can be sent back as is) but ignored.
func Decode(b []byte) (Doc, error) {
	var d Doc
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return Doc{}, invalid("invalid document: %v", err)
	}
	if dec.More() {
		return Doc{}, invalid("invalid document: trailing data after the JSON object")
	}
	return d, nil
}

// normalize trims the writer's fields, drops empty list items and checks the
// required ones.
func (d *Doc) normalize() error {
	h, c := &d.Header, &d.Context
	h.Title = strings.TrimSpace(h.Title)
	h.Description = strings.TrimSpace(h.Description)
	h.UsedFor = trimList(h.UsedFor)
	c.Schemas = trimList(c.Schemas)
	c.Tables = trimList(c.Tables)
	if strings.TrimSpace(c.Body) == "" {
		return invalid("context.body is required")
	}
	if h.Title == "" {
		return invalid("header.title is required")
	}
	if n := len([]rune(h.Title)); n > MaxTitle {
		return invalid("header.title has %d characters; the limit is %d", n, MaxTitle)
	}
	for i := range c.SQLs {
		c.SQLs[i].SQL = strings.TrimSpace(c.SQLs[i].SQL)
		c.SQLs[i].Description = strings.TrimSpace(c.SQLs[i].Description)
		if c.SQLs[i].SQL == "" {
			return invalid("context.sqls[%d].sql is required", i)
		}
	}
	if len(c.SQLs) == 0 {
		c.SQLs = nil
	}
	return nil
}

func trimList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// userFields is the part of a document a writer controls, as JSON, for
// merge patches.
func (d Doc) userFields() map[string]any {
	h, c := d.Header, d.Context
	return map[string]any{
		"header": map[string]any{
			"title": h.Title, "description": h.Description, "used_for": h.UsedFor,
		},
		"context": map[string]any{
			"schemas": c.Schemas, "tables": c.Tables, "body": c.Body, "sqls": c.SQLs,
		},
	}
}

// mergePatch applies an RFC 7396 JSON merge patch: objects merge
// recursively, null removes a member, anything else replaces it.
func mergePatch(target, patch any) any {
	p, ok := patch.(map[string]any)
	if !ok {
		return patch
	}
	t, ok := target.(map[string]any)
	if !ok {
		t = map[string]any{}
	}
	for k, v := range p {
		if v == nil {
			delete(t, k)
		} else {
			t[k] = mergePatch(t[k], v)
		}
	}
	return t
}

// Matches reports whether d passes f. Empty filter fields match everything;
// comparisons ignore case.
func (d Doc) Matches(f Filter) bool {
	if f.Table != "" && !nameIn(f.Table, d.Context.Tables) {
		return false
	}
	if f.Schema != "" && !nameIn(f.Schema, d.Context.Schemas) {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(f.Q)); q != "" {
		text := strings.ToLower(strings.Join(append([]string{d.Header.Title, d.Header.Description}, d.Header.UsedFor...), "\n"))
		if !strings.Contains(text, q) {
			return false
		}
	}
	if f.Allow != nil && !f.Allow(d) {
		return false
	}
	return true
}

// Readable reports whether d may be shown to someone who can read the
// fully qualified tables in visible: a document that names tables must
// name at least one of them; a document about no table in particular is
// always readable.
func (d Doc) Readable(visible []string) bool {
	if len(d.Context.Tables) == 0 {
		return true
	}
	for _, t := range d.Context.Tables {
		if nameIn(t, visible) {
			return true
		}
	}
	return false
}

// nameIn matches a name exactly or as the last parts of a qualified one, so
// "orders" and "main.orders" both find "sales.main.orders".
func nameIn(name string, list []string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, s := range list {
		s = strings.ToLower(s)
		if s == name || strings.HasSuffix(s, "."+name) {
			return true
		}
	}
	return false
}

// Filter narrows a listing.
type Filter struct {
	Table  string // a table the document is about
	Schema string // a schema the document is about
	Q      string // substring of title, description or used_for
	// Allow, when set, is an extra condition every document must pass
	// (used to scope documents to the tables a caller may read).
	Allow func(Doc) bool
}
