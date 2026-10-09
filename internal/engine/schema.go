package engine

import (
	"context"
	"database/sql"
	"slices"
	"strings"
	"sync"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// SchemaFilter narrows a schema listing; empty fields match everything.
// Names match case-insensitively.
type SchemaFilter struct {
	Database, Schema, Table string
}

// TableSchema describes a table or view of a catalog database.
type TableSchema struct {
	Database string         `json:"database"`
	Schema   string         `json:"schema"`
	Name     string         `json:"name"`
	Kind     string         `json:"kind"` // table or view
	Comment  string         `json:"comment,omitempty"`
	Columns  []SchemaColumn `json:"columns"`
	// Set by the caller from its own protections, not by the engine.
	RowFiltered bool `json:"row_filtered,omitempty"`
}

// Qualified is catalog.schema.name, as in Inspection.Tables.
func (t TableSchema) Qualified() string { return t.Database + "." + t.Schema + "." + t.Name }

// SchemaColumn describes a column of a table or view.
type SchemaColumn struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Comment  string `json:"comment,omitempty"`
	Masked   bool   `json:"masked,omitempty"` // set by the caller
}

// schemaEntry is one object of the cached snapshot, with the inspection of
// "SELECT * FROM object", which does not depend on who asks.
type schemaEntry struct {
	table TableSchema
	insp  Inspection
}

// schemaCache holds the last snapshot of every catalog object. Loading it
// from remote catalogs is slow (Iceberg: about a second per table), while
// filtering it per caller is not, so callers share one snapshot.
type schemaCache struct {
	mu         sync.Mutex
	snap       []schemaEntry
	built      time.Time // zero: stale
	gen        uint64    // bumped by invalidate
	refreshing bool
	build      sync.Mutex // one build at a time
}

// Schema lists the tables and views of the catalog databases matching f, with
// their columns, keeping those whose "SELECT * FROM object" inspection allow
// accepts: a caller sees exactly what it could query. The listing comes from
// a snapshot cached for Options.SchemaCacheTTL; an expired one is still
// served while a fresh one loads in the background.
func (e *Engine) Schema(ctx context.Context, f SchemaFilter,
	allow func(context.Context, TableSchema, Inspection) (bool, error),
) ([]TableSchema, error) {
	snap, err := e.schemaSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	match := func(want, got string) bool { return want == "" || strings.EqualFold(want, got) }
	out := []TableSchema{}
	for _, s := range snap {
		t := s.table
		if !match(f.Database, t.Database) || !match(f.Schema, t.Schema) || !match(f.Table, t.Name) {
			continue
		}
		ok, err := allow(ctx, t, s.insp)
		if err != nil {
			return nil, err
		}
		if ok {
			t.Columns = slices.Clone(t.Columns) // callers flag columns
			out = append(out, t)
		}
	}
	return out, nil
}

// InvalidateSchema marks the cached schema stale and reloads it in the
// background, e.g. after DDL.
func (e *Engine) InvalidateSchema() {
	c := &e.schema
	c.mu.Lock()
	c.gen++
	c.built = time.Time{}
	c.mu.Unlock()
	e.WarmSchema()
}

// WarmSchema loads the schema snapshot in the background unless a load is
// already running.
func (e *Engine) WarmSchema() {
	c := &e.schema
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.opts.SchemaCacheTTL <= 0 || c.refreshing {
		return
	}
	c.refreshing = true
	go func() {
		_, err := e.buildSchema(context.Background())
		c.mu.Lock()
		c.refreshing = false
		c.mu.Unlock()
		if err != nil {
			e.log.Warn("schema cache refresh failed; serving the previous snapshot", "err", err)
		}
	}()
}

func (e *Engine) schemaSnapshot(ctx context.Context) ([]schemaEntry, error) {
	if e.opts.SchemaCacheTTL <= 0 {
		return e.loadSchema(ctx)
	}
	c := &e.schema
	c.mu.Lock()
	snap := c.snap
	stale := c.built.IsZero() || time.Since(c.built) >= e.opts.SchemaCacheTTL
	c.mu.Unlock()
	if snap == nil {
		return e.buildSchema(ctx)
	}
	if stale {
		e.WarmSchema()
	}
	return snap, nil
}

// buildSchema loads and stores a snapshot. Concurrent callers wait for the
// running build and share its result.
func (e *Engine) buildSchema(ctx context.Context) ([]schemaEntry, error) {
	c := &e.schema
	c.mu.Lock()
	gen, before := c.gen, c.built
	c.mu.Unlock()

	c.build.Lock()
	defer c.build.Unlock()
	c.mu.Lock()
	if c.snap != nil && c.gen == gen && c.built.After(before) {
		snap := c.snap // built while we waited
		c.mu.Unlock()
		return snap, nil
	}
	gen = c.gen
	c.mu.Unlock()

	start := time.Now()
	snap, err := e.loadSchema(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.snap = snap
	if c.gen == gen {
		c.built = time.Now()
	} else {
		c.built = time.Time{} // invalidated meanwhile: reload on next use
	}
	c.mu.Unlock()
	e.log.Info("schema cache loaded", "objects", len(snap), "duration", time.Since(start).Round(time.Millisecond))
	return snap, nil
}

// loadSchema reads every table and view of the catalog databases. Like a
// query, it takes one concurrency slot.
func (e *Engine) loadSchema(ctx context.Context) ([]schemaEntry, error) {
	if err := e.acquire(ctx); err != nil {
		return nil, err
	}
	defer func() { <-e.sem }()
	if e.opts.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.opts.QueryTimeout)
		defer cancel()
	}

	conn, err := e.db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "USE "+quoteIdent(e.def)+"."+quoteIdent(e.schemas[e.def])); err != nil {
		return nil, err
	}
	// One snapshot, and remote catalogs load each table's metadata once.
	if _, err := conn.ExecContext(ctx, "BEGIN TRANSACTION"); err != nil {
		return nil, err
	}
	defer func() { _, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK") }()

	objs, err := e.schemaObjects(ctx, conn)
	if err != nil {
		return nil, err
	}
	comments, err := e.columnComments(ctx, conn)
	if err != nil {
		return nil, err
	}
	var out []schemaEntry
	for _, o := range objs {
		cols, err := describe(ctx, conn, o)
		if err != nil {
			// e.g. a view whose base table is gone: not queryable either.
			// The failed statement aborted the transaction.
			e.log.Debug("schema: skipping object", "object", o.Qualified(), "err", err)
			if err := restart(ctx, conn); err != nil {
				return nil, err
			}
			continue
		}
		for i := range cols {
			cols[i].Comment = comments[o.Qualified()+"."+cols[i].Name]
		}
		o.Columns = cols
		// What inspecting "SELECT * FROM table" yields, without the EXPLAIN:
		// for Iceberg that plans the scan. Views need the real inspection to
		// resolve their base tables.
		insp := Inspection{
			StatementType: "SELECT", Database: o.Database, Resolved: true,
			Tables: []string{o.Qualified()}, Targets: []string{}, Functions: []string{},
			Databases: []string{o.Database},
		}
		if o.Kind == "view" {
			q := "SELECT * FROM " + quoteQualified(o)
			err = conn.Raw(func(dc any) error {
				insp, err = e.inspect(ctx, dc.(*duckdb.Conn), duckdb.STATEMENT_TYPE_SELECT, q, nil, o.Database)
				return err
			})
			if err != nil {
				return nil, err
			}
		}
		out = append(out, schemaEntry{o, insp})
	}
	return out, nil
}

func quoteQualified(t TableSchema) string {
	return quoteIdent(t.Database) + "." + quoteIdent(t.Schema) + "." + quoteIdent(t.Name)
}

func restart(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, "ROLLBACK"); err != nil {
		return err
	}
	_, err := conn.ExecContext(ctx, "BEGIN TRANSACTION")
	return err
}

// schemaObjects lists the tables and views of the catalog file's databases.
func (e *Engine) schemaObjects(ctx context.Context, conn *sql.Conn) ([]TableSchema, error) {
	// Two statements, not one UNION ALL: DuckDB may run both branches on
	// parallel threads, and the Iceberg catalog crashes (SIGSEGV) when two
	// threads list it at once.
	var out []TableSchema
	for _, q := range []string{
		`SELECT database_name, schema_name, table_name, 'table', comment FROM duckdb_tables() WHERE NOT internal AND NOT temporary`,
		`SELECT database_name, schema_name, view_name, 'view', comment FROM duckdb_views() WHERE NOT internal AND NOT temporary`,
	} {
		rows, err := conn.QueryContext(ctx, q)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var t TableSchema
			var comment sql.NullString
			if err := rows.Scan(&t.Database, &t.Schema, &t.Name, &t.Kind, &comment); err != nil {
				rows.Close()
				return nil, err
			}
			if _, ok := e.known[strings.ToLower(t.Database)]; ok { // not memory, temp, system
				t.Comment = comment.String
				out = append(out, t)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	slices.SortFunc(out, func(a, b TableSchema) int { return strings.Compare(a.Qualified(), b.Qualified()) })
	return out, nil
}

// columnComments maps catalog.schema.table.column to its comment, for the
// local (DuckDB) databases only: duckdb_columns() over a remote catalog
// reloads every table (seconds each), and Iceberg columns carry none.
func (e *Engine) columnComments(ctx context.Context, conn *sql.Conn) (map[string]string, error) {
	var local []string
	for _, d := range e.databases {
		if d.Type == "duckdb" {
			local = append(local, quoteString(d.Name))
		}
	}
	out := map[string]string{}
	if len(local) == 0 {
		return out, nil
	}
	rows, err := conn.QueryContext(ctx, `
		SELECT database_name || '.' || schema_name || '.' || table_name || '.' || column_name, comment
		FROM duckdb_columns() WHERE comment IS NOT NULL AND database_name IN (`+strings.Join(local, ", ")+`)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, c string
		if err := rows.Scan(&k, &c); err != nil {
			return nil, err
		}
		out[k] = c
	}
	return out, rows.Err()
}

// describe returns an object's columns. For remote catalogs this is what
// loads the table's metadata.
func describe(ctx context.Context, conn *sql.Conn, t TableSchema) ([]SchemaColumn, error) {
	rows, err := conn.QueryContext(ctx, "DESCRIBE "+quoteQualified(t))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := []SchemaColumn{}
	for rows.Next() {
		var name, typ string
		var null, key, def, extra sql.NullString
		if err := rows.Scan(&name, &typ, &null, &key, &def, &extra); err != nil {
			return nil, err
		}
		cols = append(cols, SchemaColumn{Name: name, Type: typ, Nullable: null.String != "NO"})
	}
	return cols, rows.Err()
}
