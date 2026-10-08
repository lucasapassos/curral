// Package rls loads row-level security rules: per table, which rows the
// users matching a rule may see.
package rls

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"curral/internal/config"
)

// File is the content of the --row-filters file.
//
//	tables:
//	  lake.analytics.customers:
//	    rules:
//	      - roles: [analyst_north]
//	        where: "region = 'north'"
//	      - users: ["ana@gmail.com", "*@corp.com"]
//	        where: "region IN (SELECT region FROM ctl.main.acl WHERE usr = getvariable('curral_user'))"
type File struct {
	Tables map[string]struct {
		Rules []Rule `yaml:"rules"`
	} `yaml:"tables"`
}

// Rule limits the rows of one table for the users it matches: anyone with
// one of Roles, or whose name matches one of Users (exact or *@domain).
type Rule struct {
	Roles []string `yaml:"roles"`
	Users []string `yaml:"users"`
	Where string   `yaml:"where"`
}

// Rules is a loaded, validated rule set.
type Rules struct {
	tables map[string]table // lower(name) -> table
}

type table struct {
	name  string
	rules []Rule
}

// Load reads and validates the file (syntax only; callers check the
// predicates against the real tables).
func Load(path string) (*Rules, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	var f File
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r := &Rules{tables: map[string]table{}}
	for name, t := range f.Tables {
		if len(strings.Split(name, ".")) != 3 {
			return nil, fmt.Errorf("%s: table %q must be catalog.schema.table", path, name)
		}
		key := strings.ToLower(name)
		if _, dup := r.tables[key]; dup {
			return nil, fmt.Errorf("%s: table %q listed twice", path, name)
		}
		for i, rule := range t.Rules {
			if strings.TrimSpace(rule.Where) == "" {
				return nil, fmt.Errorf("%s: %s rule %d has no where", path, name, i+1)
			}
			if len(rule.Roles) == 0 && len(rule.Users) == 0 {
				return nil, fmt.Errorf("%s: %s rule %d matches nobody (roles or users)", path, name, i+1)
			}
			for _, u := range rule.Users {
				m := u
				if d, ok := strings.CutPrefix(m, "*@"); ok {
					m = d
				}
				if m == "" || strings.Contains(m, "*") {
					return nil, fmt.Errorf("%s: %s rule %d: user %q must be exact or *@domain", path, name, i+1, u)
				}
			}
		}
		r.tables[key] = table{name: name, rules: t.Rules}
	}
	return r, nil
}

// Each calls fn for every rule (for validation against the database).
func (r *Rules) Each(fn func(table string, rule Rule) error) error {
	if r == nil {
		return nil
	}
	for _, k := range slices.Sorted(maps.Keys(r.tables)) {
		t := r.tables[k]
		for _, rule := range t.rules {
			if err := fn(t.name, rule); err != nil {
				return err
			}
		}
	}
	return nil
}

// Filter returns the predicate a user must read table with: the OR of every
// matching rule. ok is false when no rule matches: the user is not limited.
func (r *Rules) Filter(tableName, user string, roles []string) (where string, ok bool) {
	if r == nil {
		return "", false
	}
	t, found := r.tables[strings.ToLower(tableName)]
	if !found {
		return "", false
	}
	var parts []string
	for _, rule := range t.rules {
		if matches(rule, user, roles) {
			parts = append(parts, "("+rule.Where+")")
		}
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, " OR "), true
}

// Len is the number of tables with rules.
func (r *Rules) Len() int {
	if r == nil {
		return 0
	}
	return len(r.tables)
}

func matches(rule Rule, user string, roles []string) bool {
	for _, role := range rule.Roles {
		if slices.Contains(roles, role) {
			return true
		}
	}
	for _, u := range rule.Users {
		if (config.Identity{Match: u}).Matches(user) {
			return true
		}
	}
	return false
}
