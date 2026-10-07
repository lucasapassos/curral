package engine

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// resolveCatalogScans fills in the tables behind scans of attached non-DuckDB
// catalogs (e.g. ICEBERG_SCAN), whose plan nodes carry no table name. The
// names come from the parsed statement (json_serialize_sql), which DuckDB only
// supports for SELECT; anything else that reads such a catalog is marked
// unresolved so the policy fails closed.
func (e *Engine) resolveCatalogScans(ctx context.Context, c *duckdb.Conn, typ duckdb.StmtType, query, database string, insp *Inspection) {
	var scans bool
	others := []string{}
	for _, f := range insp.Functions {
		if e.scanFuncs[f] {
			scans = true
		} else {
			others = append(others, f)
		}
	}
	if !scans {
		return
	}
	if typ != duckdb.STATEMENT_TYPE_SELECT {
		insp.Resolved = false
		return
	}
	tables, funcs, err := astSources(ctx, c, query)
	if err != nil {
		e.log.Debug("json_serialize_sql failed", "err", err)
		insp.Resolved = false
		return
	}
	for _, t := range tables {
		insp.Tables = append(insp.Tables, e.qualify(t, database))
	}
	// A direct iceberg_scan('s3://...') call shows up here as a table
	// function and stays subject to the function allowlist.
	insp.Functions = append(others, funcs...)
}

// astSources lists base table references (minus CTE names in scope) and table
// function calls of a SELECT, from DuckDB's own parser.
func astSources(ctx context.Context, c *duckdb.Conn, query string) (tables [][]string, funcs []string, err error) {
	ds, err := c.Prepare("SELECT json_serialize_sql($1::VARCHAR)::VARCHAR")
	if err != nil {
		return nil, nil, err
	}
	defer ds.Close()
	rows, err := ds.(*duckdb.Stmt).QueryContext(ctx, []driver.NamedValue{{Ordinal: 1, Value: query}})
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	dest := make([]driver.Value, 1)
	if err := rows.Next(dest); err != nil {
		if errors.Is(err, io.EOF) {
			err = errors.New("json_serialize_sql returned nothing")
		}
		return nil, nil, err
	}
	raw, _ := dest[0].(string)

	var doc struct {
		Error        bool   `json:"error"`
		ErrorMessage string `json:"error_message"`
		Statements   []any  `json:"statements"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, nil, err
	}
	if doc.Error {
		return nil, nil, errors.New(doc.ErrorMessage)
	}

	var walk func(n any, ctes []string)
	walk = func(n any, ctes []string) {
		switch v := n.(type) {
		case []any:
			for _, x := range v {
				walk(x, ctes)
			}
		case map[string]any:
			// CTEs defined on a query node are visible in that whole node,
			// including their own bodies (recursive CTEs).
			if cm, ok := v["cte_map"].(map[string]any); ok {
				entries, _ := cm["map"].([]any)
				for _, en := range entries {
					if m, ok := en.(map[string]any); ok {
						if k, ok := m["key"].(string); ok {
							ctes = append(ctes[:len(ctes):len(ctes)], strings.ToLower(k))
						}
					}
				}
			}
			switch v["type"] {
			case "BASE_TABLE":
				cat, _ := v["catalog_name"].(string)
				sch, _ := v["schema_name"].(string)
				name, _ := v["table_name"].(string)
				if cat == "" && sch == "" && contains(ctes, strings.ToLower(name)) {
					break
				}
				var parts []string
				for _, p := range []string{cat, sch, name} {
					if p != "" {
						parts = append(parts, p)
					}
				}
				tables = append(tables, parts)
			case "TABLE_FUNCTION":
				if fn, ok := v["function"].(map[string]any); ok {
					if name, ok := fn["function_name"].(string); ok {
						funcs = append(funcs, strings.ToLower(name))
					}
				}
			}
			for _, x := range v {
				walk(x, ctes)
			}
		}
	}
	walk(doc.Statements, nil)
	return tables, funcs, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
