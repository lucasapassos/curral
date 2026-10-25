package engine

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"slices"
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

// showKeyword reports DESCRIBE, SHOW or SUMMARIZE in a statement, or DESC
// used as DESCRIBE: at the start of a (sub)query rather than after an ORDER
// BY expression. Statements the lexer cannot read reliably count as yes.
func showKeyword(query string) bool {
	toks, ok := tokenize(query)
	if !ok {
		return true
	}
	for i, t := range toks {
		if t.kind != tokWord {
			continue
		}
		switch t.up {
		case "DESCRIBE", "SHOW", "SUMMARIZE":
			return true
		case "DESC":
			if i == 0 {
				return true
			}
			// After an expression (name, literal, closing parenthesis) DESC
			// orders; anything else (an opening parenthesis, a keyword such
			// as AS or UNION) starts a DESCRIBE.
			p := toks[i-1]
			switch {
			case p.kind == tokQuoted, p.kind == tokNumber, p.kind == tokString,
				p.kind == tokPunct && p.text == ")",
				p.kind == tokWord && !showStarters[p.up]:
			default:
				return true
			}
		}
	}
	return false
}

// Keywords after which DESC begins a DESCRIBE rather than ordering.
var showStarters = map[string]bool{
	"AS": true, "UNION": true, "ALL": true, "INTERSECT": true, "EXCEPT": true,
	"FROM": true, "JOIN": true, "SELECT": true, "INSERT": true, "INTO": true, "TABLE": true,
	"DISTINCT": true, "BY": true, "WITH": true,
}

// inspectShows covers DESCRIBE and SHOW, which DuckDB answers while binding:
// their plan reads no table (a CHUNK_GET, or a PRAGMA_SHOW scan for SHOW of
// a bare name), so the plan-based inspection sees nothing and the metadata of
// any table would be readable. Each DESCRIBE's inner query is inspected as if
// it ran, so the policy sees the tables whose columns it reveals; SHOW of a
// bare name is inspected as SELECT * FROM that name. SHOW of the catalog
// itself (SHOW TABLES, SHOW DATABASES, ...) lists objects the policy cannot
// attribute: unresolved. SUMMARIZE scans its input, so the plan already
// covers it.
//
// It returns the number of DESCRIBEs found, to be matched against the plan.
func (e *Engine) inspectShows(ctx context.Context, c *duckdb.Conn, query string, args []driver.NamedValue, database string, insp *Inspection) (int, error) {
	stmts, err := parseSQL(ctx, c, query)
	if err != nil {
		e.log.Debug("json_serialize_sql failed", "err", err)
		insp.Resolved = false
		return 0, nil
	}
	var inner []any
	var named []string    // SHOW <bare name>, answered by a pragma_show scan
	directPragmaShow := 0 // pragma_show('...') written as a table function
	unresolved := false
	var walk func(n any, inCTE bool)
	walk = func(n any, inCTE bool) {
		switch v := n.(type) {
		case []any:
			for _, x := range v {
				walk(x, inCTE)
			}
		case map[string]any:
			switch v["type"] {
			case "SHOW_REF":
				// DuckDB does not plan a CTE nobody reads, so a DESCRIBE or
				// SHOW there would be counted below without a result in the
				// plan, leaving room for one hidden in a view.
				if inCTE && v["show_type"] != "SUMMARY" {
					unresolved = true
				}
				q, ok := v["query"].(map[string]any)
				switch v["show_type"] {
				case "SUMMARY":
				case "DESCRIBE":
					if !ok {
						unresolved = true
						break
					}
					inner = append(inner, q)
				case "SHOW":
					if ok {
						// SHOW SELECT ... and SHOW of a qualified name, which
						// DuckDB describes through this inner query.
						inner = append(inner, q)
					} else if name, ok := showName(v); ok {
						named = append(named, name)
					} else {
						unresolved = true
					}
				default:
					// SHOW_SPECIAL (TABLES, DATABASES, ...), SHOW_FROM and
					// anything newer.
					unresolved = true
				}
			case "TABLE_FUNCTION":
				if fn, ok := v["function"].(map[string]any); ok {
					if name, ok := fn["function_name"].(string); ok && strings.EqualFold(name, "pragma_show") {
						directPragmaShow++
					}
				}
			}
			for k, x := range v {
				walk(x, inCTE || k == "cte_map")
			}
		}
	}
	walk(stmts, false)
	if unresolved {
		insp.Resolved = false
	}
	subs := make([]string, 0, len(inner)+len(named))
	for _, node := range inner {
		doc, err := json.Marshal(map[string]any{
			"error":      false,
			"statements": []any{map[string]any{"node": node, "named_param_map": []any{}}},
		})
		if err != nil {
			return 0, err
		}
		sub, err := scalar(ctx, c, "SELECT json_deserialize_sql($1::JSON)::VARCHAR", string(doc))
		if err != nil {
			e.log.Debug("json_deserialize_sql failed", "err", err)
			insp.Resolved = false
			continue
		}
		subs = append(subs, sub)
	}
	for _, name := range named {
		// DuckDB describes the table or view of that name, falling back to a
		// setting when there is none; the SELECT then fails to plan, which
		// leaves the statement unresolved.
		subs = append(subs, "SELECT * FROM "+quoteIdent(name))
	}
	for _, sub := range subs {
		si, err := e.inspect(ctx, c, duckdb.STATEMENT_TYPE_SELECT, sub, args, database)
		if err != nil {
			return 0, err
		}
		insp.Tables = append(insp.Tables, si.Tables...)
		insp.Functions = append(insp.Functions, si.Functions...)
		insp.Resolved = insp.Resolved && si.Resolved
		insp.HiddenRemoteScans += si.HiddenRemoteScans
	}
	// Each SHOW of a bare name runs as one pragma_show scan, which is how
	// DuckDB answers it, not a function the caller chose. The plan does not
	// say which name a scan reads, so the scans are taken off the functions
	// only when they are exactly those SHOWs. Otherwise the statement is
	// unresolved: a direct pragma_show('...') call next to a SHOW cannot be
	// told apart from it, and any scan beyond the statement's own is hidden
	// in a view or table macro, describing a table nobody named. Direct
	// calls always stay in the functions, for the allowlist to decide.
	pragmaShows := 0
	for _, f := range insp.Functions {
		if f == "pragma_show" {
			pragmaShows++
		}
	}
	switch {
	case pragmaShows != len(named)+directPragmaShow, len(named) > 0 && directPragmaShow > 0:
		insp.Resolved = false
	case len(named) > 0:
		insp.Functions = slices.DeleteFunc(insp.Functions, func(f string) bool { return f == "pragma_show" })
	}
	return len(inner), nil
}

// showName returns the table a DuckDB 2.0 SHOW of a bare name describes. Its
// name reaches pragma_show as a string that DuckDB parses again as a
// qualified name, and the catalog listings (SHOW TABLES, ...) are matched,
// ignoring case, on names carrying literal quotes or __show_tables_expanded,
// so only a plain name, without dots or quotes and none of those, is taken
// at face value; anything else is unresolved.
// Names DuckDB's SHOW answers with a catalog listing, without their quotes.
var showListings = map[string]bool{"tables": true, "databases": true, "schemas": true, "variables": true}

func showName(ref map[string]any) (string, bool) {
	name, _ := ref["table_name"].(string)
	cat, _ := ref["catalog_name"].(string)
	sch, _ := ref["schema_name"].(string)
	qn, _ := ref["qualified_name"].(map[string]any)
	path, _ := qn["path"].([]any)
	if name == "" || cat != "" || sch != "" || len(path) != 1 || path[0] != name {
		return "", false
	}
	if strings.ContainsAny(name, `."`) || showListings[strings.ToLower(name)] || strings.HasPrefix(strings.ToLower(name), "__show") {
		return "", false
	}
	return name, true
}

// astSources lists base table references (minus CTE names in scope) and table
// function calls of a SELECT, from DuckDB's own parser. Tables named by SHOW
// count as references (CTEs do not shadow them); a SHOW whose table cannot be
// told (a catalog listing, a name DuckDB parses again) is an error.
func astSources(ctx context.Context, c *duckdb.Conn, query string) (tables [][]string, funcs []string, err error) {
	stmts, err := parseSQL(ctx, c, query)
	if err != nil {
		return nil, nil, err
	}

	unknownShow := false
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
			case "SHOW_REF":
				// With an inner query, its tables are found below.
				if _, ok := v["query"].(map[string]any); ok {
					if t := v["show_type"]; t != "DESCRIBE" && t != "SUMMARY" && t != "SHOW" {
						unknownShow = true
					}
				} else if name, ok := showName(v); ok && v["show_type"] == "SHOW" {
					tables = append(tables, []string{name})
				} else {
					unknownShow = true
				}
			case "BASE_TABLE":
				parts := tableParts(v)
				if len(parts) == 1 && contains(ctes, strings.ToLower(parts[0])) {
					break
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
	if unknownShow {
		return nil, nil, errors.New("SHOW of a catalog listing or an unparseable name")
	}
	return tables, funcs, nil
}

// tableParts returns the name of a BASE_TABLE reference as written. Since
// DuckDB 2.0 a name may have more than three parts (nested schemas), which
// catalog_name, schema_name and table_name cannot hold: the full path is in
// qualified_name, and the separate fields are only a fallback.
func tableParts(ref map[string]any) []string {
	qn, _ := ref["qualified_name"].(map[string]any)
	if path, ok := qn["path"].([]any); ok && len(path) > 0 {
		parts := make([]string, 0, len(path))
		for _, p := range path {
			if s, ok := p.(string); ok && s != "" {
				parts = append(parts, s)
			}
		}
		if len(parts) == len(path) {
			return parts
		}
	}
	var parts []string
	for _, k := range []string{"catalog_name", "schema_name", "table_name"} {
		if p, _ := ref[k].(string); p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
