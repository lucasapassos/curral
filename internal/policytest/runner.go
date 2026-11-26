// Package policytest loads and runs declarative policy test suites against a
// dry-run evaluator.
package policytest

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/lucasapassos/curral/internal/auth"
)

// Suite is a declarative set of policy test cases loaded from YAML.
type Suite struct {
	Cases []Case `yaml:"cases"`
}

// Case describes a single dry-run policy assertion.
type Case struct {
	Name       string            `yaml:"name"`
	User       string            `yaml:"user"`             // direct user name (optional when Actor+Identity given)
	Roles      []string          `yaml:"roles"`            // roles for direct or delegated principal
	Actor      string            `yaml:"actor"`            // delegating API key name (optional)
	ActorAttrs map[string]string `yaml:"actor_attributes"` // delegating API key attributes (optional)
	Identity   map[string]any    `yaml:"identity"`         // delegated execution context (requires subject)
	Database   string            `yaml:"database"`
	SQL        string            `yaml:"sql"`
	MaxRows    int64             `yaml:"max_rows"`
	Expect     Expect            `yaml:"expect"`
}

// Expect holds the expected outcome of a dry-run evaluation.
type Expect struct {
	Decision      string              `yaml:"decision"`       // "allow", "deny", or "error" (400)
	DecidedBy     string              `yaml:"decided_by"`     // optional: "policy", "engine", "protection"
	RowFilters    []string            `yaml:"row_filters"`    // optional exact set check when non-nil
	MaskedColumns map[string][]string `yaml:"masked_columns"` // optional exact check when non-nil
	MaxRows       *int64              `yaml:"max_rows"`       // optional effective max_rows check
	Timeout       string              `yaml:"timeout"`        // optional limits.timeout check
}

// DryRunResult mirrors the fields of server.dryRunResponse relevant to policy
// assertions.
type DryRunResult struct {
	Decision      string              `json:"decision"`
	DecidedBy     string              `json:"decided_by"`
	Reason        string              `json:"reason,omitempty"`
	Tables        []string            `json:"tables"`
	Targets       []string            `json:"targets"`
	RowFilters    []string            `json:"row_filters,omitempty"`
	MaskedColumns map[string][]string `json:"masked_columns,omitempty"`
	Limits        map[string]any      `json:"limits,omitempty"`
	MaxRows       int64               `json:"max_rows,omitempty"`
}

// Evaluator runs a single dry-run query for principal p and returns the
// dry-run result and HTTP status code.
type Evaluator func(ctx context.Context, p *auth.Principal, sql, database string, maxRows int64) (DryRunResult, int, error)

// Result is the outcome of running one Case.
type Result struct {
	Name     string
	Passed   bool
	Failures []string
}

var reservedIdentityFields = []string{"roles", "groups", "actor"}

// Load reads, decodes (with KnownFields), and validates a YAML policy test suite.
func Load(path string) (*Suite, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Suite
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

func (s *Suite) validate() error {
	if len(s.Cases) == 0 {
		return errors.New("suite must define at least one case")
	}
	for i, c := range s.Cases {
		label := caseName(c, i)
		if strings.TrimSpace(c.SQL) == "" {
			return fmt.Errorf("%s: sql is required", label)
		}
		switch c.Expect.Decision {
		case "allow", "deny", "error":
		default:
			return fmt.Errorf("%s: expect.decision must be allow, deny, or error (got %q)", label, c.Expect.Decision)
		}
		if c.MaxRows < 0 {
			return fmt.Errorf("%s: max_rows must be >= 0", label)
		}
	}
	return nil
}

// BuildPrincipal constructs an *auth.Principal for a test case: either a direct
// basic-auth user or, when Identity is set, a delegated API-key principal.
func BuildPrincipal(c Case) (*auth.Principal, error) {
	if c.Identity == nil {
		return &auth.Principal{
			Name:   c.User,
			Roles:  slices.Clone(c.Roles),
			Method: auth.MethodBasic,
		}, nil
	}
	for _, reserved := range reservedIdentityFields {
		if _, ok := c.Identity[reserved]; ok {
			return nil, fmt.Errorf("identity must not contain reserved field %q", reserved)
		}
	}
	rawSubj, ok := c.Identity["subject"]
	subject, isStr := rawSubj.(string)
	if !ok || !isStr || strings.TrimSpace(subject) == "" {
		return nil, errors.New("identity requires a non-empty string subject")
	}
	var kind string
	if rawKind, hasKind := c.Identity["kind"]; hasKind {
		k, ok := rawKind.(string)
		if !ok || strings.TrimSpace(k) == "" {
			return nil, errors.New("identity.kind must be a non-empty string")
		}
		kind = k
	}
	return &auth.Principal{
		Name:       subject,
		Roles:      slices.Clone(c.Roles),
		Method:     auth.MethodAPIKey,
		Delegation: true,
		Actor:      c.Actor,
		Attributes: maps.Clone(c.ActorAttrs),
		Identity: &auth.ExecutionContext{
			Subject: subject,
			Kind:    kind,
			Fields:  maps.Clone(c.Identity),
		},
	}, nil
}

// Run executes every case in s using eval and returns one Result per case.
func Run(ctx context.Context, eval Evaluator, s *Suite) []Result {
	if s == nil {
		return nil
	}
	results := make([]Result, len(s.Cases))
	for i, c := range s.Cases {
		results[i] = runCase(ctx, eval, c, i)
	}
	return results
}

func runCase(ctx context.Context, eval Evaluator, c Case, idx int) Result {
	res := Result{Name: caseName(c, idx)}
	if eval == nil {
		res.Failures = []string{"evaluator is nil"}
		return res
	}
	p, err := BuildPrincipal(c)
	if err != nil {
		res.Failures = []string{fmt.Sprintf("principal: %v", err)}
		return res
	}
	got, status, err := eval(ctx, p, c.SQL, c.Database, c.MaxRows)
	if err != nil {
		res.Failures = []string{fmt.Sprintf("evaluation error: %v", err)}
		return res
	}

	actualDecision := got.Decision
	if status == http.StatusBadRequest {
		actualDecision = "error"
	} else if status != 0 && status != http.StatusOK && actualDecision == "" {
		actualDecision = fmt.Sprintf("http %d", status)
	}

	var failures []string
	if c.Expect.Decision != "" && actualDecision != c.Expect.Decision {
		msg := fmt.Sprintf("decision: got %q, want %q", actualDecision, c.Expect.Decision)
		if got.Reason != "" {
			msg += fmt.Sprintf(" (reason: %s)", got.Reason)
		}
		failures = append(failures, msg)
	}
	if c.Expect.DecidedBy != "" && got.DecidedBy != c.Expect.DecidedBy {
		failures = append(failures, fmt.Sprintf("decided_by: got %q, want %q", got.DecidedBy, c.Expect.DecidedBy))
	}
	if c.Expect.RowFilters != nil {
		gotFilters := sortedClone(got.RowFilters)
		wantFilters := sortedClone(c.Expect.RowFilters)
		if !slices.Equal(gotFilters, wantFilters) {
			failures = append(failures, fmt.Sprintf("row_filters: got %v, want %v", gotFilters, wantFilters))
		}
	}
	if c.Expect.MaskedColumns != nil {
		gotMasks := normalizeMasks(got.MaskedColumns)
		wantMasks := normalizeMasks(c.Expect.MaskedColumns)
		if !masksEqual(gotMasks, wantMasks) {
			failures = append(failures, fmt.Sprintf("masked_columns: got %s, want %s", formatMasks(gotMasks), formatMasks(wantMasks)))
		}
	}
	if c.Expect.MaxRows != nil && got.MaxRows != *c.Expect.MaxRows {
		failures = append(failures, fmt.Sprintf("max_rows: got %d, want %d", got.MaxRows, *c.Expect.MaxRows))
	}
	if c.Expect.Timeout != "" {
		gotTimeout, _ := got.Limits["timeout"].(string)
		if !timeoutsEqual(gotTimeout, c.Expect.Timeout) {
			failures = append(failures, fmt.Sprintf("limits.timeout: got %q, want %q", gotTimeout, c.Expect.Timeout))
		}
	}

	res.Failures = failures
	res.Passed = len(failures) == 0
	return res
}

func caseName(c Case, idx int) string {
	if c.Name != "" {
		return c.Name
	}
	return fmt.Sprintf("case[%d]", idx)
}

func sortedClone(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

func normalizeMasks(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for table, cols := range in {
		out[table] = sortedClone(cols)
	}
	return out
}

func masksEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || !slices.Equal(va, vb) {
			return false
		}
	}
	return true
}

func formatMasks(m map[string][]string) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := slices.Sorted(maps.Keys(m))
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s:%v", k, m[k])
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func timeoutsEqual(got, want string) bool {
	if got == want {
		return true
	}
	if got == "" || want == "" {
		return false
	}
	gd, gerr := time.ParseDuration(got)
	wd, werr := time.ParseDuration(want)
	return gerr == nil && werr == nil && gd == wd
}
