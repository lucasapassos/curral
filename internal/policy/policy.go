// Package policy evaluates Rego policies in-process with the OPA SDK.
package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
)

type Policy struct {
	query rego.PreparedEvalQuery
	// SHA256 identifies the policy and data files loaded, so audit records
	// show which version of the rules made each decision.
	SHA256 string
}

// Load compiles the given .rego files (and optional JSON/YAML data files,
// loaded under data.*) once. query is the decision, e.g. data.curral.allow.
func Load(ctx context.Context, query string, files []string) (*Policy, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("no policy files given")
	}
	pq, err := rego.New(
		rego.Query(query),
		rego.Load(files, nil),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	sum, err := hashFiles(files)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &Policy{query: pq, SHA256: sum}, nil
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
