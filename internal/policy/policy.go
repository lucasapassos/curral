// Package policy evaluates Rego policies in-process with the OPA SDK.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

type Policy struct {
	query  rego.PreparedEvalQuery
	limits *rego.PreparedEvalQuery // optional per-request limits
	masks  *rego.PreparedEvalQuery // optional column masks
	// SHA256 identifies the policy and data files loaded, so audit records
	// show which version of the rules made each decision.
	SHA256 string
}

// Load compiles the given .rego files (and optional JSON/YAML data files,
// loaded under data.*) once. query is the decision, e.g. data.curral.allow;
// limitsQuery (optional, e.g. data.curral.limits) yields per-request limits.
func Load(ctx context.Context, query string, files []string, limitsQuery ...string) (*Policy, error) {
	q := Queries{Allow: query}
	if len(limitsQuery) > 0 {
		q.Limits = limitsQuery[0]
	}
	return LoadQueries(ctx, files, q)
}

// Queries names the rules a policy is evaluated with.
type Queries struct {
	Allow  string // required decision, e.g. data.curral.allow
	Limits string // optional, e.g. data.curral.limits
	Masks  string // optional, e.g. data.curral.masks
}

// LoadQueries compiles the policy files once for every configured query.
func LoadQueries(ctx context.Context, files []string, q Queries) (*Policy, error) {
	query := q.Allow
	if len(files) == 0 {
		return nil, fmt.Errorf("no policy files given")
	}
	prepare := func(q string) (rego.PreparedEvalQuery, error) {
		return rego.New(
			rego.Query(q),
			rego.Load(files, nil),
			rego.StrictBuiltinErrors(true),
		).PrepareForEval(ctx)
	}
	pq, err := prepare(query)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p := &Policy{query: pq}
	if q.Limits != "" {
		lq, err := prepare(q.Limits)
		if err != nil {
			return nil, fmt.Errorf("policy limits: %w", err)
		}
		p.limits = &lq
	}
	if q.Masks != "" {
		mq, err := prepare(q.Masks)
		if err != nil {
			return nil, fmt.Errorf("policy masks: %w", err)
		}
		p.masks = &mq
	}
	if p.SHA256, err = hashFiles(files); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return p, nil
}

// Limits narrow what an allowed request may use. Zero means no limit.
type Limits struct {
	Timeout time.Duration `json:"timeout,omitempty"`
	MaxRows int64         `json:"max_rows,omitempty"`
	// MaxConcurrency caps simultaneous queries of ConcurrencyGroup (by
	// default the user). Requests over it are refused, not queued.
	MaxConcurrency   int64  `json:"max_concurrency,omitempty"`
	ConcurrencyGroup string `json:"concurrency_group,omitempty"`
}

// Limits evaluates the limits query, if configured. An undefined result means
// no limits. timeout accepts a duration string ("30s") or seconds; max_rows a
// number.
func (p *Policy) Limits(ctx context.Context, input map[string]any) (Limits, error) {
	var l Limits
	if p.limits == nil {
		return l, nil
	}
	v, err := ast.InterfaceToValue(input)
	if err != nil {
		return l, err
	}
	rs, err := p.limits.Eval(ctx, rego.EvalParsedInput(v))
	if err != nil {
		return l, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return l, nil
	}
	obj, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return l, fmt.Errorf("limits must be an object, got %T", rs[0].Expressions[0].Value)
	}
	for k, val := range obj {
		switch k {
		case "timeout":
			switch t := val.(type) {
			case string:
				if l.Timeout, err = time.ParseDuration(t); err != nil {
					return l, fmt.Errorf("limits.timeout: %w", err)
				}
			case json.Number:
				f, err := t.Float64()
				if err != nil {
					return l, fmt.Errorf("limits.timeout: %w", err)
				}
				l.Timeout = time.Duration(f * float64(time.Second))
			default:
				return l, fmt.Errorf("limits.timeout: unsupported %T", val)
			}
		case "max_rows":
			n, ok := val.(json.Number)
			if !ok {
				return l, fmt.Errorf("limits.max_rows: unsupported %T", val)
			}
			if l.MaxRows, err = n.Int64(); err != nil {
				return l, fmt.Errorf("limits.max_rows: %w", err)
			}
		case "max_concurrency":
			n, ok := val.(json.Number)
			if !ok {
				return l, fmt.Errorf("limits.max_concurrency: unsupported %T", val)
			}
			if l.MaxConcurrency, err = n.Int64(); err != nil {
				return l, fmt.Errorf("limits.max_concurrency: %w", err)
			}
		case "concurrency_group":
			g, ok := val.(string)
			if !ok || g == "" {
				return l, fmt.Errorf("limits.concurrency_group must be a non-empty string")
			}
			l.ConcurrencyGroup = g
		default:
			return l, fmt.Errorf("limits: unknown key %q", k)
		}
	}
	if l.Timeout < 0 || l.MaxRows < 0 || l.MaxConcurrency < 0 {
		return l, fmt.Errorf("limits must not be negative")
	}
	return l, nil
}

// Masks evaluates the masks query, if configured: table -> column -> SQL
// expression replacing the column. An undefined result means no masks.
// Values are presets ("null", "redact", "last:N") or {"sql": "..."}.
// Anything malformed is an error, so the request is refused.
func (p *Policy) Masks(ctx context.Context, input map[string]any) (map[string]map[string]string, error) {
	if p.masks == nil {
		return nil, nil
	}
	v, err := ast.InterfaceToValue(input)
	if err != nil {
		return nil, err
	}
	rs, err := p.masks.Eval(ctx, rego.EvalParsedInput(v))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, nil
	}
	tables, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("masks must be an object of tables, got %T", rs[0].Expressions[0].Value)
	}
	out := map[string]map[string]string{}
	for table, cols := range tables {
		if len(strings.Split(table, ".")) != 3 {
			return nil, fmt.Errorf("masks: table %q must be catalog.schema.table", table)
		}
		colMap, ok := cols.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("masks.%s must be an object of columns", table)
		}
		out[table] = map[string]string{}
		for col, m := range colMap {
			expr, err := maskSQL(col, m)
			if err != nil {
				return nil, fmt.Errorf("masks.%s.%s: %w", table, col, err)
			}
			out[table][col] = expr
		}
	}
	return out, nil
}

func maskSQL(col string, m any) (string, error) {
	c := `"` + strings.ReplaceAll(col, `"`, `""`) + `"`
	switch v := m.(type) {
	case string:
		switch {
		case v == "null":
			return "CASE WHEN false THEN " + c + " END", nil // NULL of the column's type
		case v == "redact":
			return "'***'", nil
		case strings.HasPrefix(v, "last:"):
			n, err := strconv.Atoi(strings.TrimPrefix(v, "last:"))
			if err != nil || n < 0 {
				return "", fmt.Errorf("invalid preset %q", v)
			}
			return fmt.Sprintf("'***' || right(CAST(%s AS VARCHAR), %d)", c, n), nil
		}
		return "", fmt.Errorf("unknown preset %q (null, redact, last:N or {\"sql\": ...})", v)
	case map[string]any:
		s, ok := v["sql"].(string)
		if !ok || strings.TrimSpace(s) == "" || len(v) != 1 {
			return "", fmt.Errorf(`custom masks are {"sql": "<expression>"}`)
		}
		return s, nil
	}
	return "", fmt.Errorf("unsupported mask %T", m)
}

// hashFiles hashes names and contents of the given files, walking
// directories in lexical order.
func hashFiles(paths []string) (string, error) {
	h := sha256.New()
	for _, root := range paths {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			fmt.Fprintf(h, "%s\x00%d\x00", filepath.ToSlash(path), len(b))
			h.Write(b)
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Allow evaluates the decision. Anything but a single literal true is a deny.
func (p *Policy) Allow(ctx context.Context, input map[string]any) (bool, error) {
	// Converting to an AST value up front skips OPA's JSON round-trip.
	v, err := ast.InterfaceToValue(input)
	if err != nil {
		return false, err
	}
	rs, err := p.query.Eval(ctx, rego.EvalParsedInput(v))
	if err != nil {
		return false, err
	}
	return rs.Allowed(), nil
}
