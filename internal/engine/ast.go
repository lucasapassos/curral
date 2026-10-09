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
	scans := 0
	others := []string{}
	for _, f := range insp.Functions {
		if e.scanFuncs[f] {
			scans++
		} else {
			others = append(others, f)
		}
	}
	if scans == 0 {
		return
	}
	if typ != duckdb.STATEMENT_TYPE_SELECT {
		insp.Resolved = false
		insp.HiddenRemoteScans = scans // none can be attributed to a table
		return
	}
	tables, funcs, err := astSources(ctx, c, query)
	if err != nil {
		e.log.Debug("json_serialize_sql failed", "err", err)
		insp.Resolved = false
		insp.HiddenRemoteScans = scans
		return
	}
	// Every remote scan in the plan must be a direct reference in the
	// statement: a table of a remote catalog, or a direct scan function
	// call (kept in Functions for the allowlist). More scans than that
	// means a view or macro reads a remote table the policy cannot see.
	direct := 0
	for _, t := range tables {
		q := e.qualify(t, database)
		insp.Tables = append(insp.Tables, q)
		if e.IsRemote(q) {
			direct++
		}
	}
	for _, f := range funcs {
		if e.scanFuncs[f] {
			direct++
		}
	}
	if scans > direct {
		insp.Resolved = false
		insp.HiddenRemoteScans = scans - direct
	}
	// A direct iceberg_scan('s3://...') call shows up here as a table
	// function and stays subject to the function allowlist.
	insp.Functions = append(others, funcs...)
}

// scalar runs a one-value query with a single VARCHAR parameter.
func scalar(ctx context.Context, c *duckdb.Conn, query, arg string) (string, error) {
	ds, err := c.Prepare(query)
	if err != nil {
		return "", err
	}
	defer ds.Close()
	rows, err := ds.(*duckdb.Stmt).QueryContext(ctx, []driver.NamedValue{{Ordinal: 1, Value: arg}})
	if err != nil {
		return "", err
	}
	defer rows.Close()
	dest := make([]driver.Value, 1)
	if err := rows.Next(dest); err != nil {
		if errors.Is(err, io.EOF) {
			err = errors.New("no result")
		}
		return "", err
	}
	v, _ := dest[0].(string)
	return v, nil
}

// parseSQL returns the statements of DuckDB's parse tree (json_serialize_sql,
// which only supports SELECT).
func parseSQL(ctx context.Context, c *duckdb.Conn, query string) ([]any, error) {
	raw, err := scalar(ctx, c, "SELECT json_serialize_sql($1::VARCHAR)::VARCHAR", query)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Error        bool   `json:"error"`
		ErrorMessage string `json:"error_message"`
		Statements   []any  `json:"statements"`
	}
	// Numbers stay json.Number: query_location is often MaxUint64, which a
	// float64 round trip would corrupt for json_deserialize_sql.
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if doc.Error {
		return nil, errors.New(doc.ErrorMessage)
	}
	return doc.Statements, nil
}

// mayShow reports whether a statement could contain DESCRIBE, SHOW or
// SUMMARIZE. Keywords always appear literally, so a plain substring test
// never misses one (ORDER BY ... DESC merely costs a parse).
func mayShow(query string) bool {
	q := strings.ToLower(query)
	return strings.Contains(q, "desc") || strings.Contains(q, "show") || strings.Contains(q, "summarize")
}

// inspectShows covers DESCRIBE and SHOW, which DuckDB answers while binding:
// their plan reads no table (a CHUNK_GET), so the plan-based inspection sees
// nothing and the metadata of any table would be readable. Each DESCRIBE's
// inner query is inspected as if it ran, so the policy sees the tables whose
// columns it reveals. SHOW of the catalog itself (SHOW TABLES, SHOW
// DATABASES, ...) lists objects the policy cannot attribute: unresolved.
// SUMMARIZE scans its input, so the plan already covers it.
func (e *Engine) inspectShows(ctx context.Context, c *duckdb.Conn, query string, args []driver.NamedValue, database string, insp *Inspection) error {
	stmts, err := parseSQL(ctx, c, query)
	if err != nil {
		e.log.Debug("json_serialize_sql failed", "err", err)
		insp.Resolved = false
		return nil
	}
	var inner []any
	unresolved := false
	var walk func(n any)
	walk = func(n any) {
		switch v := n.(type) {
		case []any:
			for _, x := range v {
				walk(x)
			}
		case map[string]any:
			if v["type"] == "SHOW_REF" {
				switch q, ok := v["query"].(map[string]any); {
				case v["show_type"] == "SUMMARY":
				case v["show_type"] == "DESCRIBE" && ok:
					inner = append(inner, q)
				default:
					unresolved = true
				}
			}
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(stmts)
	if unresolved {
		insp.Resolved = false
	}
	for _, node := range inner {
		doc, err := json.Marshal(map[string]any{
			"error":      false,
			"statements": []any{map[string]any{"node": node, "named_param_map": []any{}}},
		})
		if err != nil {
			return err
		}
		sub, err := scalar(ctx, c, "SELECT json_deserialize_sql($1::JSON)::VARCHAR", string(doc))
		if err != nil {
			e.log.Debug("json_deserialize_sql failed", "err", err)
			insp.Resolved = false
			continue
		}
		si, err := e.inspect(ctx, c, duckdb.STATEMENT_TYPE_SELECT, sub, args, database)
		if err != nil {
			return err
		}
		insp.Tables = append(insp.Tables, si.Tables...)
		insp.Functions = append(insp.Functions, si.Functions...)
		insp.Resolved = insp.Resolved && si.Resolved
		insp.HiddenRemoteScans += si.HiddenRemoteScans
	}
	return nil
}

// astSources lists base table references (minus CTE names in scope) and table
// function calls of a SELECT, from DuckDB's own parser.
func astSources(ctx context.Context, c *duckdb.Conn, query string) (tables [][]string, funcs []string, err error) {
	stmts, err := parseSQL(ctx, c, query)
	if err != nil {
		return nil, nil, err
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
	walk(stmts, nil)
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
