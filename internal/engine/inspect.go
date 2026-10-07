package engine

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	mapping "github.com/duckdb/duckdb-go-bindings"
	duckdb "github.com/duckdb/duckdb-go/v2"
)

// Statement types the driver does not export constants for.
var (
	stmtMergeInto        = duckdb.StmtType(mapping.StatementTypeMergeInto)
	stmtCopyDatabase     = duckdb.StmtType(mapping.StatementTypeCopyDatabase)
	stmtUpdateExtensions = duckdb.StmtType(mapping.StatementTypeUpdateExtensions)
)

var stmtTypeNames = map[duckdb.StmtType]string{
	duckdb.STATEMENT_TYPE_INVALID:      "INVALID",
	duckdb.STATEMENT_TYPE_SELECT:       "SELECT",
	duckdb.STATEMENT_TYPE_INSERT:       "INSERT",
	duckdb.STATEMENT_TYPE_UPDATE:       "UPDATE",
	duckdb.STATEMENT_TYPE_EXPLAIN:      "EXPLAIN",
	duckdb.STATEMENT_TYPE_DELETE:       "DELETE",
	duckdb.STATEMENT_TYPE_PREPARE:      "PREPARE",
	duckdb.STATEMENT_TYPE_CREATE:       "CREATE",
	duckdb.STATEMENT_TYPE_EXECUTE:      "EXECUTE",
	duckdb.STATEMENT_TYPE_ALTER:        "ALTER",
	duckdb.STATEMENT_TYPE_TRANSACTION:  "TRANSACTION",
	duckdb.STATEMENT_TYPE_COPY:         "COPY",
	duckdb.STATEMENT_TYPE_ANALYZE:      "ANALYZE",
	duckdb.STATEMENT_TYPE_VARIABLE_SET: "VARIABLE_SET",
	duckdb.STATEMENT_TYPE_CREATE_FUNC:  "CREATE_FUNC",
	duckdb.STATEMENT_TYPE_DROP:         "DROP",
	duckdb.STATEMENT_TYPE_EXPORT:       "EXPORT",
	duckdb.STATEMENT_TYPE_PRAGMA:       "PRAGMA",
	duckdb.STATEMENT_TYPE_VACUUM:       "VACUUM",
	duckdb.STATEMENT_TYPE_CALL:         "CALL",
	duckdb.STATEMENT_TYPE_SET:          "SET",
	duckdb.STATEMENT_TYPE_LOAD:         "LOAD",
	duckdb.STATEMENT_TYPE_RELATION:     "RELATION",
	duckdb.STATEMENT_TYPE_EXTENSION:    "EXTENSION",
	duckdb.STATEMENT_TYPE_LOGICAL_PLAN: "LOGICAL_PLAN",
	duckdb.STATEMENT_TYPE_ATTACH:       "ATTACH",
	duckdb.STATEMENT_TYPE_DETACH:       "DETACH",
	duckdb.STATEMENT_TYPE_MULTI:        "MULTI",
	stmtMergeInto:                      "MERGE",
	stmtCopyDatabase:                   "COPY_DATABASE",
	stmtUpdateExtensions:               "UPDATE_EXTENSIONS",
}

func stmtTypeName(t duckdb.StmtType) string {
	if n, ok := stmtTypeNames[t]; ok {
		return n
	}
	return "UNKNOWN"
}

// Statement types whose logical plan lists the tables they read.
var planned = map[duckdb.StmtType]bool{
	duckdb.STATEMENT_TYPE_SELECT: true,
	duckdb.STATEMENT_TYPE_INSERT: true,
	duckdb.STATEMENT_TYPE_UPDATE: true,
	duckdb.STATEMENT_TYPE_DELETE: true,
	duckdb.STATEMENT_TYPE_CREATE: true,
	stmtMergeInto:                true,
}

// Statement types whose writes the tokenizer extracts.
var writes = map[duckdb.StmtType]bool{
	duckdb.STATEMENT_TYPE_INSERT:      true,
	duckdb.STATEMENT_TYPE_UPDATE:      true,
	duckdb.STATEMENT_TYPE_DELETE:      true,
	duckdb.STATEMENT_TYPE_CREATE:      true,
	duckdb.STATEMENT_TYPE_CREATE_FUNC: true,
	duckdb.STATEMENT_TYPE_DROP:        true,
	duckdb.STATEMENT_TYPE_ALTER:       true,
	duckdb.STATEMENT_TYPE_COPY:        true,
	stmtMergeInto:                     true,
}

// inspect resolves what a prepared statement reads and writes. Reads come from
// DuckDB's own unoptimized logical plan (views, aliases and USING already
// resolved). DuckDB does not expose write targets, so those come from a small
// tokenizer; when either side cannot be determined, Resolved is false and the
// policy should fail closed.
func (e *Engine) inspect(ctx context.Context, c *duckdb.Conn, typ duckdb.StmtType, query string, args []driver.NamedValue, database string) (Inspection, error) {
	insp := Inspection{StatementType: stmtTypeName(typ), Database: database, Resolved: true}

	if typ == duckdb.STATEMENT_TYPE_EXPLAIN {
		// EXPLAIN ANALYZE executes the inner statement, so it is authorized as
		// that statement; plain EXPLAIN only needs read access to its tables.
		inner, analyze, ok := stripExplain(query)
		if !ok {
			insp.Resolved = false
			return insp, nil
		}
		ds, err := c.Prepare(inner)
		if err != nil {
			return insp, &QueryError{err}
		}
		innerType, err := ds.(*duckdb.Stmt).StatementType()
		ds.Close()
		if err != nil {
			return insp, &QueryError{err}
		}
		if alwaysDenied[innerType] {
			return insp, ErrForbidden
		}
		sub, err := e.inspect(ctx, c, innerType, inner, args, database)
		if err != nil {
			return insp, err
		}
		if analyze {
			return sub, nil
		}
		sub.StatementType = insp.StatementType
		sub.Targets = []string{}
		return sub, nil
	}

	if planned[typ] {
		tables, funcs, err := planSources(ctx, c, query, args)
		if err != nil {
			// Some statements (PRAGMA, ...) cannot be EXPLAINed. The failure
			// aborted the request's transaction, so start a fresh one and
			// leave the decision to the policy.
			e.log.Debug("explain failed", "err", err)
			if err := restartTx(ctx, c); err != nil {
				return insp, err
			}
			insp.Resolved = false
		} else {
			insp.Tables = tables
			insp.Functions = funcs
			e.resolveCatalogScans(ctx, c, typ, query, database, &insp)
		}
	}

	if !planned[typ] && !writes[typ] {
		// No way to tell what this statement type touches (CALL, VACUUM,
		// COPY DATABASE, future types...): leave it to the policy, fail closed.
		insp.Resolved = false
	}
	if writes[typ] {
		verb, targets, reads, ok := writeTargets(query)
		// The verb the tokenizer found must be the statement DuckDB prepared;
		// anything else means the two parsers disagree, so fail closed.
		if !ok || !verbMatches(verb, typ) {
			insp.Resolved = false
		}
		for _, t := range targets {
			insp.Targets = append(insp.Targets, e.qualify(t, database))
		}
		for _, t := range reads {
			insp.Tables = append(insp.Tables, e.qualify(t, database))
		}
	}

	insp.Tables = uniq(insp.Tables)
	insp.Targets = uniq(insp.Targets)
	insp.Functions = uniq(insp.Functions)
	dbs := []string{}
	for _, n := range append(slices.Clone(insp.Tables), insp.Targets...) {
		if strings.HasPrefix(n, "secret:") {
			continue
		}
		dbs = append(dbs, strings.SplitN(n, ".", 2)[0])
	}
	insp.Databases = uniq(dbs)
	return insp, nil
}

func verbMatches(verb string, typ duckdb.StmtType) bool {
	switch verb {
	case "INSERT":
		return typ == duckdb.STATEMENT_TYPE_INSERT
	case "UPDATE":
		return typ == duckdb.STATEMENT_TYPE_UPDATE
	case "DELETE", "TRUNCATE":
		return typ == duckdb.STATEMENT_TYPE_DELETE
	case "CREATE":
		return typ == duckdb.STATEMENT_TYPE_CREATE || typ == duckdb.STATEMENT_TYPE_CREATE_FUNC
	case "DROP":
		return typ == duckdb.STATEMENT_TYPE_DROP
	case "ALTER", "COMMENT":
		return typ == duckdb.STATEMENT_TYPE_ALTER
	case "COPY":
		return typ == duckdb.STATEMENT_TYPE_COPY
	case "MERGE":
		return typ == stmtMergeInto
	}
	return false
}

func restartTx(ctx context.Context, c *duckdb.Conn) error {
	if _, err := c.ExecContext(ctx, "ROLLBACK", nil); err != nil {
		return err
	}
	_, err := c.ExecContext(ctx, "BEGIN TRANSACTION", nil)
	return err
}

func uniq(s []string) []string {
	if len(s) == 0 {
		return []string{}
	}
	slices.Sort(s)
	return slices.Compact(s)
}

// qualify turns a 1-3 part name into catalog.schema.name.
func (e *Engine) qualify(parts []string, database string) string {
	if parts[0] == secretMark {
		return "secret:" + parts[1]
	}
	switch len(parts) {
	case 1:
		return database + "." + e.schemas[database] + "." + parts[0]
	case 2:
		// DuckDB reads x.t as catalog x (its main schema) when x is an
		// attached catalog, else as schema x of the current catalog; when
		// both exist it refuses the statement as ambiguous.
		if name, ok := e.catalogs[strings.ToLower(parts[0])]; ok {
			return name + ".main." + parts[1]
		}
		return database + "." + parts[0] + "." + parts[1]
	default:
		if name, ok := e.catalogs[strings.ToLower(parts[0])]; ok {
			parts[0] = name
		}
		return strings.Join(parts, ".")
	}
}

type planNode struct {
	Name      string          `json:"name"`
	Children  []planNode      `json:"children"`
	ExtraInfo json.RawMessage `json:"extra_info"`
}

// Leaf operators of a logical plan that are not table functions.
var plainLeaves = map[string]bool{
	"DUMMY_SCAN": true, "EMPTY_RESULT": true, "CHUNK_GET": true, "COLUMN_DATA_GET": true,
	"CTE_SCAN": true, "CTE_REF": true, "DELIM_GET": true, "EXPRESSION_GET": true,
}

// planSources returns the tables (from scan nodes carrying a Table) and the
// table functions (other leaf scans, e.g. read_csv, range) of the statement's
// unoptimized logical plan.
func planSources(ctx context.Context, c *duckdb.Conn, query string, args []driver.NamedValue) (tables, funcs []string, err error) {
	ds, err := c.Prepare("EXPLAIN (FORMAT JSON) " + query)
	if err != nil {
		return nil, nil, err
	}
	defer ds.Close()
	rows, err := ds.(*duckdb.Stmt).QueryContext(ctx, args)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	dest := make([]driver.Value, 2)
	for {
		if err := rows.Next(dest); err != nil {
			if errors.Is(err, io.EOF) {
				return nil, nil, errors.New("no logical plan in EXPLAIN output")
			}
			return nil, nil, err
		}
		if k, _ := dest[0].(string); k != "logical_plan" {
			continue
		}
		plan, _ := dest[1].(string)
		var roots []planNode
		if err := json.Unmarshal([]byte(plan), &roots); err != nil {
			return nil, nil, err
		}
		var walk func([]planNode)
		walk = func(ns []planNode) {
			for _, n := range ns {
				var info struct {
					Table string `json:"Table"`
				}
				switch {
				case json.Unmarshal(n.ExtraInfo, &info) == nil && info.Table != "":
					tables = append(tables, info.Table)
				case len(n.Children) == 0 && !plainLeaves[n.Name]:
					funcs = append(funcs, strings.ToLower(n.Name))
				}
				walk(n.Children)
			}
		}
		walk(roots)
		return tables, funcs, nil
	}
}
