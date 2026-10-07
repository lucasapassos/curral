package engine

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"curral/internal/config"
)

// stmt is a boot statement plus a log-safe rendering of it.
type stmt struct {
	sql string
	log string
}

func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

func quoteString(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// literal renders a YAML value as a DuckDB literal.
func literal(v any) (string, error) {
	switch t := v.(type) {
	case nil:
		return "NULL", nil
	case string:
		return quoteString(t), nil
	case bool:
		return strconv.FormatBool(t), nil
	case int:
		return strconv.Itoa(t), nil
	case int64:
		return strconv.FormatInt(t, 10), nil
	case uint64:
		return strconv.FormatUint(t, 10), nil
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64), nil
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			s, err := literal(e)
			if err != nil {
				return "", err
			}
			parts[i] = s
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case map[string]any:
		parts := make([]string, 0, len(t))
		for _, k := range slices.Sorted(maps.Keys(t)) {
			s, err := literal(t[k])
			if err != nil {
				return "", err
			}
			parts = append(parts, quoteString(k)+": "+s)
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	}
	return "", fmt.Errorf("unsupported value %v (%T)", v, v)
}

// optionList renders (KEY value, ...) with keys sorted for stable output.
// TYPE goes first since it reads naturally that way in logs.
func optionList(opts map[string]any, redact bool) (string, error) {
	keys := slices.SortedFunc(maps.Keys(opts), func(a, b string) int {
		ta, tb := strings.EqualFold(a, "TYPE"), strings.EqualFold(b, "TYPE")
		if ta != tb {
			if ta {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		val, err := literal(opts[k])
		if err != nil {
			return "", fmt.Errorf("%s: %w", k, err)
		}
		if redact && !strings.EqualFold(k, "TYPE") {
			val = "'***'"
		}
		parts = append(parts, strings.ToUpper(k)+" "+val)
	}
	return strings.Join(parts, ", "), nil
}

// bootStatements renders the catalog into the SQL executed at startup, in order.
func bootStatements(c *config.Catalog) ([]stmt, error) {
	var out []stmt
	add := func(sql, log string) { out = append(out, stmt{sql, log}) }

	for _, e := range c.Extensions {
		s := "INSTALL " + e
		add(s, s)
		s = "LOAD " + e
		add(s, s)
	}
	for _, k := range slices.Sorted(maps.Keys(c.Settings)) {
		val, err := literal(c.Settings[k])
		if err != nil {
			return nil, fmt.Errorf("setting %s: %w", k, err)
		}
		add(fmt.Sprintf("SET GLOBAL %s = %s", k, val), fmt.Sprintf("SET GLOBAL %s = ***", k))
	}
	for _, s := range c.Secrets {
		params := maps.Clone(s.Params)
		if params == nil {
			params = map[string]any{}
		}
		params["TYPE"] = s.Type
		real, err := optionList(params, false)
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", s.Name, err)
		}
		redacted, _ := optionList(params, true)
		head := "CREATE OR REPLACE SECRET " + quoteIdent(s.Name)
		add(head+" ("+real+")", head+" ("+redacted+")")
	}
	for _, d := range c.Databases {
		head := "ATTACH " + quoteString(d.Path) + " AS " + quoteIdent(d.Name)
		logHead := "ATTACH '***' AS " + quoteIdent(d.Name)
		if len(d.Options) == 0 {
			add(head, logHead)
			continue
		}
		real, err := optionList(d.Options, false)
		if err != nil {
			return nil, fmt.Errorf("database %s: %w", d.Name, err)
		}
		redacted, _ := optionList(d.Options, true)
		add(head+" ("+real+")", logHead+" ("+redacted+")")
	}
	for i, s := range c.InitSQL {
		add(s, fmt.Sprintf("init_sql[%d]", i))
	}
	return out, nil
}
