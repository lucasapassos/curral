// Package engine owns the embedded DuckDB instance: boot from the catalog,
// hardening, concurrency limits and statement inspection/execution.
package engine

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"curral/internal/catalogcache"
	"curral/internal/config"
)

// Options are the resource and safety knobs set from the command line.
type Options struct {
	MaxConcurrency int
	QueueTimeout   time.Duration
	QueryTimeout   time.Duration
	Threads        int
	MemoryLimit    string
	TempDir        string
	MaxTempSize    string
	ExtensionDir   string
	ExternalAccess bool     // keep enable_external_access on (needed by some remote sources)
	AllowedPaths   []string // extra allowed_directories when external access is off
}

var (
	ErrBusy      = errors.New("too many concurrent queries")
	ErrForbidden = errors.New("forbidden")
)

// QueryError is a problem with the submitted SQL (parse/bind/runtime).
type QueryError struct{ Err error }

func (e *QueryError) Error() string { return e.Err.Error() }
func (e *QueryError) Unwrap() error { return e.Err }

// DatabaseInfo is the public view of an attached database.
type DatabaseInfo struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Schema   string `json:"schema"`
	ReadOnly bool   `json:"read_only"`
}

type Engine struct {
	db        *sql.DB
	sem       chan struct{}
	opts      Options
	def       string
	databases []DatabaseInfo
	known     map[string]string // lower(name) -> name
	schemas   map[string]string // name -> schema used by USE
	scanFuncs map[string]bool   // table functions that scan attached non-DuckDB catalogs
	caches    map[string]*catalogcache.Proxy
	waiting   atomic.Int64 // requests waiting for a slot
	log       *slog.Logger
}

// Open creates the DuckDB instance, mounts the catalog and locks it down.
func Open(ctx context.Context, cat *config.Catalog, opts Options, log *slog.Logger) (*Engine, error) {
	if opts.MaxConcurrency < 1 {
		opts.MaxConcurrency = 1
	}
	connector, err := duckdb.NewConnector("", nil)
	if err != nil {
		return nil, err
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(opts.MaxConcurrency + 1)
	// Fresh connection per request: temp objects, variables and USE never
	// leak between users. A DuckDB connection costs microseconds.
	db.SetMaxIdleConns(0)

	e := &Engine{
		db:        db,
		sem:       make(chan struct{}, opts.MaxConcurrency),
		opts:      opts,
		def:       cat.Default,
		known:     map[string]string{},
		schemas:   map[string]string{},
		scanFuncs: map[string]bool{},
		caches:    map[string]*catalogcache.Proxy{},
		log:       log,
	}
	for _, d := range cat.Databases {
		e.databases = append(e.databases, DatabaseInfo{Name: d.Name, Type: d.Type(), Schema: d.DefaultSchema(), ReadOnly: d.ReadOnly()})
		e.known[strings.ToLower(d.Name)] = d.Name
		e.schemas[d.Name] = d.DefaultSchema()
		if d.Type() != "duckdb" {
			// e.g. ICEBERG_SCAN: these plan nodes carry no table name.
			e.scanFuncs[d.Type()+"_scan"] = true
		}
	}
	cat, err = e.startCaches(cat)
	if err != nil {
		e.Close()
		return nil, err
	}
	if err := e.boot(ctx, cat); err != nil {
		e.Close()
		return nil, err
	}
	return e, nil
}

// startCaches puts a caching proxy in front of every catalog with cache_ttl
// and returns a copy of the catalog whose ENDPOINTs point at the proxies.
func (e *Engine) startCaches(cat *config.Catalog) (*config.Catalog, error) {
	out := *cat
	out.Databases = slices.Clone(cat.Databases)
	for i, d := range out.Databases {
		ttl := d.CacheDuration()
		if ttl <= 0 {
			continue
		}
		p, err := catalogcache.Start(d.Endpoint(), ttl, e.log)
		if err != nil {
			return nil, fmt.Errorf("database %s: %w", d.Name, err)
		}
		e.caches[d.Name] = p
		opts := maps.Clone(d.Options)
		for k := range opts {
			if strings.EqualFold(k, "ENDPOINT") {
				opts[k] = p.URL()
			}
		}
		out.Databases[i].Options = opts
		e.log.Info("catalog metadata cache enabled", "database", d.Name, "ttl", ttl.String())
	}
	return &out, nil
}

// DuckDBVersion returns the embedded DuckDB version.
func (e *Engine) DuckDBVersion(ctx context.Context) string {
	var v string
	if err := e.db.QueryRowContext(ctx, "SELECT version()").Scan(&v); err != nil {
		return "unknown"
	}
	return v
}

// Load reports queries executing, queries waiting for a slot, and the limit.
func (e *Engine) Load() (running, waiting, limit int) {
	return len(e.sem), int(e.waiting.Load()), cap(e.sem)
}

// CacheStats reports hits/misses of a database's catalog cache, if enabled.
func (e *Engine) CacheStats(database string) (hits, misses int64, ok bool) {
	p, ok := e.caches[database]
	if !ok {
		return 0, 0, false
	}
	return p.Hits.Load(), p.Misses.Load(), true
}

// CachedDatabases lists databases with a catalog metadata cache.
func (e *Engine) CachedDatabases() []string {
	return slices.Sorted(maps.Keys(e.caches))
}

func (e *Engine) boot(ctx context.Context, cat *config.Catalog) error {
	conn, err := e.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	var stmts []stmt
	set := func(name string, val any) {
		lit, _ := literal(val)
		s := fmt.Sprintf("SET GLOBAL %s = %s", name, lit)
		stmts = append(stmts, stmt{s, s})
	}
	if e.opts.Threads > 0 {
		set("threads", e.opts.Threads)
	}
	if e.opts.MemoryLimit != "" {
		set("memory_limit", e.opts.MemoryLimit)
	}
	if e.opts.TempDir != "" {
		set("temp_directory", e.opts.TempDir)
	}
	if e.opts.MaxTempSize != "" {
		set("max_temp_directory_size", e.opts.MaxTempSize)
	}
	if e.opts.ExtensionDir != "" {
		set("extension_directory", e.opts.ExtensionDir)
	}
	// Unoptimized logical plans list every referenced table, even ones the
	// optimizer would prune; inspect() relies on that.
	set("explain_output", "all")

	catStmts, err := bootStatements(cat)
	if err != nil {
		return err
	}
	stmts = append(stmts, catStmts...)
	stmts = append(stmts, e.hardening(cat)...)

	for _, s := range stmts {
		e.log.Debug("boot", "sql", s.log)
		if _, err := conn.ExecContext(ctx, s.sql); err != nil {
			return fmt.Errorf("boot: %s: %w", s.log, err)
		}
	}
	return nil
}

func (e *Engine) hardening(cat *config.Catalog) []stmt {
	var out []stmt
	add := func(s string) { out = append(out, stmt{s, s}) }
	if !e.opts.ExternalAccess {
		// allowed_directories takes prefixes (dirs, s3://bucket/), allowed_paths
		// exact files.
		dirs := toAny(e.opts.AllowedPaths)
		if e.opts.TempDir != "" {
			dirs = append(dirs, strings.TrimRight(e.opts.TempDir, "/")+"/")
		}
		var files []any
		for _, d := range cat.Databases {
			// Attached files must stay reachable (WAL, checkpoints).
			if d.Type() == "duckdb" && d.Path != ":memory:" {
				files = append(files, d.Path, d.Path+".wal")
			}
		}
		if len(dirs) > 0 {
			lit, _ := literal(dirs)
			add("SET GLOBAL allowed_directories = " + lit)
		}
		if len(files) > 0 {
			lit, _ := literal(files)
			add("SET GLOBAL allowed_paths = " + lit)
		}
		add("SET GLOBAL enable_external_access = false")
	}
	add("SET GLOBAL autoinstall_known_extensions = false")
	add("SET GLOBAL autoload_known_extensions = false")
	add("SET GLOBAL allow_community_extensions = false")
	add("SET GLOBAL lock_configuration = true")
	return out
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func (e *Engine) Close() error {
	err := e.db.Close()
	for _, p := range e.caches {
		p.Close()
	}
	return err
}

func (e *Engine) Databases() []DatabaseInfo { return e.databases }

func (e *Engine) Ping(ctx context.Context) error { return e.db.PingContext(ctx) }

// Request is one statement to run.
type Request struct {
	SQL      string
	Params   []any
	Database string  // catalog to USE; empty means the default
	Timing   *Timing // filled in when not nil
	// ExecTimeout, read once authorize returns, bounds execution (e.g. a
	// per-role limit from the policy). The engine's QueryTimeout still caps
	// the whole request.
	ExecTimeout *time.Duration
}

// Timing breaks a request's time down by stage.
type Timing struct {
	Queue     time.Duration // waiting for a concurrency slot
	Inspect   time.Duration // connection, prepare and inspection
	Authorize time.Duration // the authorize callback
	Execute   time.Duration // execution, streaming and commit
}

// Inspection is what authorization gets to see before anything executes.
type Inspection struct {
	StatementType string   `json:"statement_type"`
	Database      string   `json:"database"`
	Tables        []string `json:"tables"`    // catalog.schema.table read by the statement
	Targets       []string `json:"targets"`   // catalog.schema.object written/created/dropped
	Functions     []string `json:"functions"` // table functions used as sources (read_csv, range, ...)
	Databases     []string `json:"databases"`
	Resolved      bool     `json:"resolved"` // false: tables/targets may be incomplete
}

// Column describes a result column.
type Column struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Rows is a forward-only cursor over raw driver values.
type Rows interface {
	Next(dest []driver.Value) error
}

// Statement types that change the instance itself are never allowed,
// whatever the policy says.
var alwaysDenied = map[duckdb.StmtType]bool{
	duckdb.STATEMENT_TYPE_ATTACH:    true,
	duckdb.STATEMENT_TYPE_DETACH:    true,
	duckdb.STATEMENT_TYPE_LOAD:      true,
	duckdb.STATEMENT_TYPE_EXTENSION: true,
	stmtUpdateExtensions:            true,
}

// Query inspects the statement, asks authorize, executes it and hands the
// result to emit. Nothing runs before authorize returns nil.
func (e *Engine) Query(ctx context.Context, req Request,
	authorize func(context.Context, Inspection) error,
	emit func([]Column, Rows) error,
) error {
	tm := req.Timing
	if tm == nil {
		tm = &Timing{}
	}
	mark := time.Now()
	lap := func(d *time.Duration) {
		now := time.Now()
		*d += now.Sub(mark)
		mark = now
	}
	err := e.acquire(ctx)
	lap(&tm.Queue)
	if err != nil {
		return err
	}
	defer func() { <-e.sem }()
	defer lap(&tm.Execute)

	if e.opts.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.opts.QueryTimeout)
		defer cancel()
	}

	database := e.def
	if req.Database != "" {
		name, ok := e.known[strings.ToLower(req.Database)]
		if !ok {
			return &QueryError{fmt.Errorf("unknown database %q", req.Database)}
		}
		database = name
	}

	conn, err := e.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "USE "+quoteIdent(database)+"."+quoteIdent(e.schemas[database])); err != nil {
		return err
	}

	args := make([]driver.NamedValue, len(req.Params))
	for i, p := range req.Params {
		args[i] = driver.NamedValue{Ordinal: i + 1, Value: p}
	}

	// One transaction around inspection and execution: both see the same
	// snapshot, and remote catalogs (Iceberg REST) are only asked for table
	// metadata once instead of once per prepare/EXPLAIN.
	if _, err := conn.ExecContext(ctx, "BEGIN TRANSACTION"); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()

	// Narrowed by ExecTimeout after authorization; also covers COMMIT.
	execCtx, cancelExec := ctx, context.CancelFunc(func() {})
	defer func() { cancelExec() }()
	err = conn.Raw(func(dc any) error {
		c := dc.(*duckdb.Conn)
		// Prepare (not PrepareContext): it refuses multi-statement input
		// instead of executing all but the last statement.
		ds, err := c.Prepare(req.SQL)
		if err != nil {
			return &QueryError{err}
		}
		st := ds.(*duckdb.Stmt)
		defer st.Close()

		typ, err := st.StatementType()
		if err != nil {
			return &QueryError{err}
		}
		if alwaysDenied[typ] {
			return fmt.Errorf("%w: %s statements are not allowed", ErrForbidden, stmtTypeName(typ))
		}
		if typ == duckdb.STATEMENT_TYPE_TRANSACTION {
			return &QueryError{errors.New("transaction statements are not supported: each request runs in its own transaction")}
		}

		insp, err := e.inspect(ctx, c, typ, req.SQL, args, database)
		lap(&tm.Inspect)
		if err != nil {
			return err
		}
		err = authorize(ctx, insp)
		lap(&tm.Authorize)
		if err != nil {
			return err
		}

		if req.ExecTimeout != nil && *req.ExecTimeout > 0 {
			execCtx, cancelExec = context.WithTimeout(ctx, *req.ExecTimeout)
		}
		dr, err := st.QueryContext(execCtx, args)
		if err != nil {
			return &QueryError{err}
		}
		defer dr.Close()

		names := dr.Columns()
		cols := make([]Column, len(names))
		typed, _ := dr.(driver.RowsColumnTypeDatabaseTypeName)
		for i, n := range names {
			cols[i] = Column{Name: n}
			if typed != nil {
				cols[i].Type = typed.ColumnTypeDatabaseTypeName(i)
			}
		}
		return emit(cols, dr)
	})
	if err != nil {
		return err
	}
	if err := execCtx.Err(); err != nil {
		return err // timed out while streaming: roll back
	}
	if _, err := conn.ExecContext(execCtx, "COMMIT"); err != nil {
		return &QueryError{err}
	}
	committed = true
	return nil
}

func (e *Engine) acquire(ctx context.Context) error {
	select {
	case e.sem <- struct{}{}:
		return nil
	default:
	}
	if e.opts.QueueTimeout <= 0 {
		return ErrBusy
	}
	e.waiting.Add(1)
	defer e.waiting.Add(-1)
	t := time.NewTimer(e.opts.QueueTimeout)
	defer t.Stop()
	select {
	case e.sem <- struct{}{}:
		return nil
	case <-t.C:
		return ErrBusy
	case <-ctx.Done():
		return ctx.Err()
	}
}
