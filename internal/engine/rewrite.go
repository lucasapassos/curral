package engine

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strings"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// Protection is how one table must be read: rows limited by Filter (a SQL
// predicate; empty for none) and columns replaced by Masks (column -> SQL
// expression). Both come from configuration and policy, never from users.
type Protection struct {
	Filter string            `json:"filter,omitempty"`
	Masks  map[string]string `json:"masks,omitempty"`
}

// maxSubqCache bounds cached protection subqueries.
const maxSubqCache = 1024

// maxViewDepth caps recursive local view expansion during protection rewriting.
const maxViewDepth = 8

// errProtected marks a statement refused because of protected tables.
func errProtected(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrForbidden, fmt.Sprintf(format, a...))
}

// protect rewrites a SELECT so every reference to a protected table reads a
// filtered, masked subquery instead:
//
//	FROM pii AS b  ->  FROM (SELECT * REPLACE (<mask> AS col) FROM cat.sch.pii WHERE (<filter>)) AS b
//
// The rewrite edits DuckDB's own parse tree and turns it back into SQL with
// DuckDB, so there is no hand-written SQL parsing. It refuses (fails
// closed) when the statement round-trips unstably through the parse tree,
// when a protected table is read in a way the rewrite cannot reach (a view,
// a macro), or when a reference uses sampling or time travel.
func (e *Engine) protect(ctx context.Context, c *duckdb.Conn, query string, args []driver.NamedValue,
	database string, prot map[string]Protection, insp Inspection,
) (string, bool, error) {
	// The rewrite depends only on the statement, the current database and
	// the protections, so repeated queries reuse it. The check against the
	// plan below runs on every request: a view created later is still seen.
	key := rewriteKey(query, database, prot)
	rw, ok := e.rewrites.get(key)
	if !ok {
		var err error
		if rw, err = e.buildRewrite(ctx, c, query, database, prot); err != nil {
			return "", false, err
		}
		e.rewrites.put(key, rw)
	}

	// Every read of a protected table must be one of the references the
	// rewrite replaced; a view or macro reading it would bypass protection.
	tables, funcs := insp.planTables, insp.planFuncs
	if !insp.planned { // not expected for SELECT, but never skip the check
		var err error
		if tables, funcs, _, err = planSources(ctx, c, query, args); err != nil {
			return "", false, errProtected("cannot plan statement: %v", err)
		}
	}
	scans := map[string]int{}
	for _, t := range tables {
		scans[strings.ToLower(t)]++
	}
	remoteScans := 0
	for _, f := range funcs {
		if e.scanFuncs[f] {
			remoteScans++
		}
	}
	// References inside a DESCRIBE or SHOW return column metadata only and
	// are answered while binding, so the plan has no scan for them.
	for _, t := range slices.Sorted(maps.Keys(prot)) {
		if e.IsRemote(t) {
			if remoteScans != rw.remoteRefs-rw.metaRemoteRefs {
				return "", false, errProtected("%s may be read indirectly (view or macro); query it directly", t)
			}
			continue
		}
		if scans[strings.ToLower(t)] != rw.refs[t]-rw.metaRefs[t] {
			return "", false, errProtected("%s is read indirectly (view or macro); query it directly", t)
		}
	}
	return rw.sql, rw.needVars, nil
}

// rewrite is a statement with its protected tables replaced, plus how many
// direct references it had (per protected table, and to remote catalogs),
// and how many of those sit inside a DESCRIBE or SHOW: they reveal column
// names and types, as GET /v1/schema does, never rows, and the plan does
// not scan them.
type rewrite struct {
	sql            string
	refs, metaRefs map[string]int
	remoteRefs     int
	metaRemoteRefs int
	// needVars: some filter or mask reads getvariable() directly or calls a
	// user macro (which might), so the session variables must be set.
	needVars bool
}

// rewriteKey identifies a rewrite: statement, database and protections.
func rewriteKey(query, database string, prot map[string]Protection) string {
	var b strings.Builder
	b.WriteString(database)
	b.WriteByte(0)
	b.WriteString(query)
	for _, t := range slices.Sorted(maps.Keys(prot)) {
		p := prot[t]
		fmt.Fprintf(&b, "\x00%s\x00%s", t, p.Filter)
		for _, col := range slices.Sorted(maps.Keys(p.Masks)) {
			fmt.Fprintf(&b, "\x00%s=%s", col, p.Masks[col])
		}
	}
	return b.String()
}

func (e *Engine) buildRewrite(ctx context.Context, c *duckdb.Conn, query, database string, prot map[string]Protection) (*rewrite, error) {
	byKey := map[string]string{} // lower(qualified) -> qualified
	for t := range prot {
		byKey[strings.ToLower(t)] = t
	}

	raw, again, err := serializeRoundTrip(ctx, c, query)
	if err != nil {
		return nil, errProtected("statement cannot be checked for protected tables: %v", err)
	}
	if err := checkRoundTrip(raw, again); err != nil {
		return nil, err
	}
	doc, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}

	// Replace references, counting them per table (and references to remote
	// catalogs, whose plan scans carry no table name). Local DuckDB views that
	// read protected tables are expanded inline into subqueries so the
	// protection applies transparently.
	refs, metaRefs := map[string]int{}, map[string]int{}
	remoteRefs, metaRemoteRefs := 0, 0
	var subqueryErr error
	// meta: inside a DESCRIBE or SHOW (not SUMMARIZE, which reads the rows).
	var walk func(n any, ctes []string, meta bool, curDB, curSchema string, depth int, seenViews map[string]bool) any
	walk = func(n any, ctes []string, meta bool, curDB, curSchema string, depth int, seenViews map[string]bool) any {
		switch v := n.(type) {
		case []any:
			for i := range v {
				v[i] = walk(v[i], ctes, meta, curDB, curSchema, depth, seenViews)
			}
		case map[string]any:
			if v["type"] == "SHOW_REF" && v["show_type"] != "SUMMARY" {
				meta = true
			}
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
			// SHOW of a bare name describes the table without a reference
			// the rewrite can replace, nor a scan in the plan: metadata
			// only, like DESCRIBE.
			if _, ok := v["query"].(map[string]any); v["type"] == "SHOW_REF" && !ok {
				if name, ok := showName(v); ok {
					if table, ok := byKey[strings.ToLower(e.qualify([]string{name}, curDB))]; ok {
						refs[table]++
						metaRefs[table]++
					}
				}
			}
			if v["type"] == "BASE_TABLE" {
				parts := tableParts(v)
				if len(parts) == 1 && contains(ctes, strings.ToLower(parts[0])) {
					return v // a CTE, not a table
				}
				var qualified, viewSQL string
				var isView, checkedView bool
				if len(parts) == 1 && curSchema != "" && !strings.EqualFold(curSchema, e.schemas[curDB]) {
					cand := curDB + "." + curSchema + "." + parts[0]
					if _, ok := byKey[strings.ToLower(cand)]; ok {
						qualified = cand
					} else if !e.IsRemote(cand) {
						vs, found, err := lookupLocalView(ctx, c, curDB, curSchema, parts[0])
						if err != nil {
							subqueryErr = errProtected("cannot inspect view %s: %v", cand, err)
							return v
						}
						if found {
							qualified, viewSQL, isView, checkedView = cand, vs, true, true
						} else {
							qualified = e.qualify(parts, curDB)
						}
					} else {
						qualified = cand
					}
				} else {
					qualified = e.qualify(parts, curDB)
				}
				if e.IsRemote(qualified) {
					remoteRefs++
					if meta {
						metaRemoteRefs++
					}
				}
				if table, ok := byKey[strings.ToLower(qualified)]; ok {
					refs[table]++
					if meta {
						metaRefs[table]++
					}
					if v["sample"] != nil || v["at_clause"] != nil {
						subqueryErr = errProtected("TABLESAMPLE/AT on protected table %s is not supported", table)
						return v
					}
					sub, err := e.protectedSubquery(ctx, c, table, prot[table], v)
					if err != nil {
						subqueryErr = err
						return v
					}
					return sub
				}
				if e.IsRemote(qualified) {
					return v
				}
				qParts := strings.Split(qualified, ".")
				if len(qParts) != 3 {
					return v
				}
				if !checkedView {
					vs, found, err := lookupLocalView(ctx, c, qParts[0], qParts[1], qParts[2])
					if err != nil {
						subqueryErr = errProtected("cannot inspect view %s: %v", qualified, err)
						return v
					}
					viewSQL, isView = vs, found
				}
				if !isView {
					return v
				}
				viewKey := strings.ToLower(qualified)
				if depth >= maxViewDepth {
					subqueryErr = errProtected("view nesting depth exceeds %d at %s", maxViewDepth, qualified)
					return v
				}
				if seenViews[viewKey] {
					subqueryErr = errProtected("cyclic view reference at %s", qualified)
					return v
				}
				viewAliases, selectSQL, ok := parseViewSQL(viewSQL)
				if !ok {
					subqueryErr = errProtected("view %s definition cannot be parsed for protected tables", qualified)
					return v
				}
				vRaw, vAgain, err := serializeRoundTrip(ctx, c, selectSQL)
				if err != nil {
					subqueryErr = errProtected("view %s cannot be checked for protected tables: %v", qualified, err)
					return v
				}
				if err := checkRoundTrip(vRaw, vAgain); err != nil {
					subqueryErr = err
					return v
				}
				vDoc, err := decodeJSON(vRaw)
				if err != nil {
					subqueryErr = errProtected("view %s parse tree error: %v", qualified, err)
					return v
				}
				vStmts, _ := vDoc.(map[string]any)["statements"].([]any)
				if len(vStmts) != 1 {
					subqueryErr = errProtected("view %s is not a single SELECT statement", qualified)
					return v
				}
				nextSeen := maps.Clone(seenViews)
				if nextSeen == nil {
					nextSeen = map[string]bool{}
				}
				nextSeen[viewKey] = true

				refsBefore := totalRefCount(refs)
				remoteBefore := remoteRefs
				viewStmt := walk(vStmts[0], nil, meta, qParts[0], qParts[1], depth+1, nextSeen)
				if subqueryErr != nil {
					return v
				}
				if totalRefCount(refs) == refsBefore && remoteRefs == remoteBefore {
					return v // view touches no protected tables or remote catalogs
				}
				if v["sample"] != nil || v["at_clause"] != nil {
					subqueryErr = errProtected("TABLESAMPLE/AT on view %s over protected table is not supported", qualified)
					return v
				}
				alias, _ := v["alias"].(string)
				if alias == "" {
					alias, _ = v["table_name"].(string)
				}
				return map[string]any{
					"type":              "SUBQUERY",
					"alias":             alias,
					"column_name_alias": mergeColumnAliases(viewAliases, v["column_name_alias"]),
					"sample":            nil,
					"query_location":    v["query_location"],
					"subquery":          viewStmt,
				}
			}
			for k, x := range v {
				v[k] = walk(x, ctes, meta, curDB, curSchema, depth, seenViews)
			}
		}
		return n
	}
	walk(doc, nil, false, database, e.schemas[database], 0, nil)
	if subqueryErr != nil {
		return nil, subqueryErr
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	sql, err := deserializeSQL(ctx, c, string(out))
	if err != nil {
		return nil, err
	}
	needVars := false
	for _, t := range slices.Sorted(maps.Keys(prot)) {
		if needVars {
			break
		}
		if needVars, err = e.usesSessionVariables(ctx, c, protectionSQL(t, prot[t])); err != nil {
			return nil, err
		}
	}
	return &rewrite{sql: sql, refs: refs, metaRefs: metaRefs, remoteRefs: remoteRefs, metaRemoteRefs: metaRemoteRefs, needVars: needVars}, nil
}

// usesSessionVariables reports whether a protection query calls
// getvariable() or any user-defined macro (which could call it).
func (e *Engine) usesSessionVariables(ctx context.Context, c *duckdb.Conn, query string) (bool, error) {
	raw, err := serializeSQL(ctx, c, query)
	if err != nil {
		return true, nil // cannot tell: set them
	}
	doc, err := decodeJSON(raw)
	if err != nil {
		return true, nil
	}
	var names []string
	var walk func(n any)
	walk = func(n any) {
		switch v := n.(type) {
		case []any:
			for _, x := range v {
				walk(x)
			}
		case map[string]any:
			if fn, ok := v["function_name"].(string); ok {
				names = append(names, strings.ToLower(fn))
			}
			for _, x := range v {
				walk(x)
			}
		}
	}
	walk(doc)
	if slices.Contains(names, "getvariable") {
		return true, nil
	}
	names = uniq(names)
	if len(names) == 0 {
		return false, nil
	}
	// Only inspect local catalogs (and memory/temp) for user-defined macros:
	// calling duckdb_functions() across attached remote catalogs (Iceberg) can
	// race with concurrent queries.
	localDBs := []string{"'memory'", "'temp'"}
	for _, d := range e.databases {
		if d.Type == "duckdb" {
			localDBs = append(localDBs, quoteString(d.Name))
		}
	}
	quotedNames := make([]string, len(names))
	for i, n := range names {
		quotedNames[i] = quoteString(n)
	}
	q := "SELECT count(*)::VARCHAR FROM duckdb_functions() WHERE NOT internal AND database_name IN (" +
		strings.Join(localDBs, ", ") + ") AND lower(function_name) IN (" + strings.Join(quotedNames, ", ") + ")"
	macro, err := scalarString(ctx, c, q)
	if err != nil || macro != "0" {
		return true, nil
	}
	return false, nil
}

// protectionSQL is the query a protected table is replaced with.
func protectionSQL(table string, p Protection) string {
	var b strings.Builder
	b.WriteString("SELECT *")
	if len(p.Masks) > 0 {
		b.WriteString(" REPLACE (")
		for i, col := range slices.Sorted(maps.Keys(p.Masks)) {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "(%s) AS %s", p.Masks[col], quoteIdent(col))
		}
		b.WriteString(")")
	}
	b.WriteString(" FROM ")
	for i, part := range strings.SplitN(table, ".", 3) {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(quoteIdent(part))
	}
	if p.Filter != "" {
		fmt.Fprintf(&b, " WHERE (%s)", p.Filter)
	}
	return b.String()
}

// CheckProtection prepares a protection against its table, so a broken
// filter or mask is reported at load time instead of on every query.
func (e *Engine) CheckProtection(ctx context.Context, table string, p Protection) error {
	if len(strings.Split(table, ".")) != 3 {
		return fmt.Errorf("%s: use catalog.schema.table", table)
	}
	conn, err := e.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Raw(func(dc any) error {
		ds, err := dc.(*duckdb.Conn).Prepare(protectionSQL(table, p) + " LIMIT 0")
		if err != nil {
			return fmt.Errorf("%s: %w", table, err)
		}
		return ds.Close()
	})
}

// protectedSubquery builds the replacement for one table reference,
// keeping its alias (or name) so qualified column references still work.
func (e *Engine) protectedSubquery(ctx context.Context, c *duckdb.Conn, table string, p Protection, ref map[string]any) (map[string]any, error) {
	query := protectionSQL(table, p)
	var raw string
	if v, ok := e.subqCache.Load(query); ok {
		raw = v.(string)
	} else {
		var err error
		if raw, err = serializeSQL(ctx, c, query); err != nil {
			return nil, fmt.Errorf("protection for %s: %w", table, err)
		}
		// Bounded: a policy that builds masks per user must not grow it forever.
		if e.subqCount.Load() < maxSubqCache {
			if _, loaded := e.subqCache.LoadOrStore(query, raw); !loaded {
				e.subqCount.Add(1)
			}
		}
	}
	doc, err := decodeJSON(raw)
	if err != nil {
		return nil, err
	}
	stmts, _ := doc.(map[string]any)["statements"].([]any)
	if len(stmts) != 1 {
		return nil, fmt.Errorf("protection for %s is not a single statement", table)
	}
	alias, _ := ref["alias"].(string)
	if alias == "" {
		alias, _ = ref["table_name"].(string)
	}
	colAlias := ref["column_name_alias"]
	if colAlias == nil {
		colAlias = []any{}
	}
	return map[string]any{
		"type":              "SUBQUERY",
		"alias":             alias,
		"column_name_alias": colAlias,
		"sample":            nil,
		"query_location":    ref["query_location"],
		"subquery":          stmts[0],
	}, nil
}

// IsRemote reports whether a qualified table lives in an attached
// non-DuckDB catalog (e.g. Iceberg), whose plan scans have no table name.
func (e *Engine) IsRemote(qualified string) bool {
	cat := strings.SplitN(qualified, ".", 2)[0]
	for _, d := range e.databases {
		if strings.EqualFold(d.Name, cat) {
			return d.Type != "duckdb"
		}
	}
	return false
}

// checkRoundTrip refuses statements whose parse tree does not survive
// being turned back into SQL and parsed again (ignoring source positions):
// the rewrite relies on that conversion being faithful.
func checkRoundTrip(raw, again string) error {
	a, err1 := decodeJSON(raw)
	b, err2 := decodeJSON(again)
	if err1 != nil || err2 != nil || !reflect.DeepEqual(stripLocations(a), stripLocations(b)) {
		return errProtected("statement does not survive rewriting unchanged; simplify it to read protected tables")
	}
	return nil
}

// serializeRoundTrip parses query and, in the same call, turns the tree
// back into SQL and parses that again.
func serializeRoundTrip(ctx context.Context, c *duckdb.Conn, query string) (raw, again string, err error) {
	ds, err := c.Prepare(`SELECT s, json_serialize_sql(json_deserialize_sql(s::JSON))::VARCHAR
		FROM (SELECT json_serialize_sql($1::VARCHAR)::VARCHAR AS s)`)
	if err != nil {
		return "", "", err
	}
	defer ds.Close()
	rows, err := ds.(*duckdb.Stmt).QueryContext(ctx, []driver.NamedValue{{Ordinal: 1, Value: query}})
	if err != nil {
		// json_deserialize_sql fails on the error document of an
		// unparsable statement; report the parser's message instead.
		if _, serr := serializeSQL(ctx, c, query); serr != nil {
			return "", "", serr
		}
		return "", "", err
	}
	defer rows.Close()
	dest := make([]driver.Value, 2)
	if err := rows.Next(dest); err != nil {
		return "", "", err
	}
	raw, _ = dest[0].(string)
	again, _ = dest[1].(string)
	return raw, again, nil
}

func stripLocations(n any) any {
	switch v := n.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			if k != "query_location" && k != "query_location_length" {
				out[k] = stripLocations(x)
			}
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = stripLocations(x)
		}
		return out
	}
	return n
}

// decodeJSON keeps numbers as json.Number so nothing changes in transit.
func decodeJSON(s string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v any
	return v, dec.Decode(&v)
}

func serializeSQL(ctx context.Context, c *duckdb.Conn, query string) (string, error) {
	s, err := scalarString(ctx, c, "SELECT json_serialize_sql($1::VARCHAR)::VARCHAR", query)
	if err != nil {
		return "", err
	}
	var head struct {
		Error        bool   `json:"error"`
		ErrorMessage string `json:"error_message"`
	}
	if err := json.Unmarshal([]byte(s), &head); err != nil {
		return "", err
	}
	if head.Error {
		return "", errors.New(head.ErrorMessage)
	}
	return s, nil
}

func deserializeSQL(ctx context.Context, c *duckdb.Conn, doc string) (string, error) {
	return scalarString(ctx, c, "SELECT json_deserialize_sql($1::JSON)", doc)
}

// lookupLocalView returns the CREATE VIEW SQL for a non-internal local DuckDB
// view, or ("", false, nil) if no such view exists.
func lookupLocalView(ctx context.Context, c *duckdb.Conn, db, schema, name string) (string, bool, error) {
	ds, err := c.Prepare(`SELECT sql FROM duckdb_views()
		WHERE NOT internal
		  AND lower(database_name) = lower($1)
		  AND lower(schema_name) = lower($2)
		  AND lower(view_name) = lower($3)
		LIMIT 1`)
	if err != nil {
		return "", false, err
	}
	defer ds.Close()
	rows, err := ds.(*duckdb.Stmt).QueryContext(ctx, []driver.NamedValue{
		{Ordinal: 1, Value: db},
		{Ordinal: 2, Value: schema},
		{Ordinal: 3, Value: name},
	})
	if err != nil {
		return "", false, err
	}
	defer rows.Close()
	dest := make([]driver.Value, 1)
	if err := rows.Next(dest); err != nil {
		if errors.Is(err, io.EOF) {
			return "", false, nil
		}
		return "", false, err
	}
	s, _ := dest[0].(string)
	return s, true, nil
}

// parseViewSQL extracts optional declared column aliases and the underlying
// SELECT statement from a CREATE VIEW DDL string returned by duckdb_views().
func parseViewSQL(viewSQL string) (aliases []string, selectSQL string, ok bool) {
	toks, lexOK := tokenize(viewSQL)
	if !lexOK {
		return nil, "", false
	}
	c := &cursor{toks: toks}
	if !c.accept("CREATE") {
		return nil, "", false
	}
	if c.accept("OR") && !c.accept("REPLACE") {
		return nil, "", false
	}
	c.accept("TEMP", "TEMPORARY")
	c.accept("RECURSIVE")
	if !c.accept("VIEW") {
		return nil, "", false
	}
	if c.accept("IF") && !(c.accept("NOT") && c.accept("EXISTS")) {
		return nil, "", false
	}
	if _, ok := c.name(); !ok {
		return nil, "", false
	}
	if p := c.peek(); p.kind == tokPunct && p.text == "(" {
		c.i++
		for {
			t := c.peek()
			if t.kind != tokWord && t.kind != tokQuoted {
				return nil, "", false
			}
			aliases = append(aliases, t.text)
			c.i++
			if p := c.peek(); p.kind == tokPunct && p.text == "," {
				c.i++
				continue
			}
			if p := c.peek(); p.kind == tokPunct && p.text == ")" {
				c.i++
				break
			}
			return nil, "", false
		}
	}
	if !c.accept("AS") {
		return nil, "", false
	}
	if c.i >= len(c.toks) {
		return nil, "", false
	}
	start := c.toks[c.i].pos
	end := len(viewSQL)
	if last := c.toks[len(c.toks)-1]; last.kind == tokPunct && last.text == ";" {
		end = last.pos
	}
	selectSQL = strings.TrimSpace(viewSQL[start:end])
	if selectSQL == "" {
		return nil, "", false
	}
	return aliases, selectSQL, true
}

// mergeColumnAliases combines a view's declared column aliases with any outer
// FROM v AS u(c, d) column alias list, with outer aliases overriding positionally.
func mergeColumnAliases(viewAliases []string, outer any) []any {
	outerList, _ := outer.([]any)
	if len(viewAliases) == 0 {
		if outerList == nil {
			return []any{}
		}
		return outerList
	}
	n := max(len(viewAliases), len(outerList))
	out := make([]any, n)
	for i, a := range viewAliases {
		out[i] = a
	}
	for i, a := range outerList {
		out[i] = a
	}
	return out
}

func totalRefCount(refs map[string]int) int {
	total := 0
	for _, n := range refs {
		total += n
	}
	return total
}

func scalarString(ctx context.Context, c *duckdb.Conn, query string, args ...any) (string, error) {
	ds, err := c.Prepare(query)
	if err != nil {
		return "", err
	}
	defer ds.Close()
	named := make([]driver.NamedValue, len(args))
	for i, a := range args {
		named[i] = driver.NamedValue{Ordinal: i + 1, Value: a}
	}
	rows, err := ds.(*duckdb.Stmt).QueryContext(ctx, named)
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
	switch v := dest[0].(type) {
	case string:
		return v, nil
	case []byte:
		return string(bytes.Clone(v)), nil
	}
	b, err := json.Marshal(dest[0])
	return string(b), err
}
