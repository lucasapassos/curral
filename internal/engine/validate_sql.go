package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// ValidateSQL parses and binds query against the engine's catalog without
// executing it. It enforces the same UTF-8, single-statement, always-denied,
// and transaction restrictions as Query, and sanitizes DuckDB parse/bind
// errors with PublicError so catalog suggestions are never leaked.
func (e *Engine) ValidateSQL(ctx context.Context, query string) error {
	if !utf8.ValidString(query) {
		return &QueryError{errors.New("sql is not valid UTF-8")}
	}
	if err := e.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-e.sem }()

	if e.opts.QueryTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.opts.QueryTimeout)
		defer cancel()
	}

	conn, err := e.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if e.def != "" {
		if _, err := conn.ExecContext(ctx, "USE "+quoteIdent(e.def)+"."+quoteIdent(e.schemas[e.def])); err != nil {
			return err
		}
	}

	if _, err := conn.ExecContext(ctx, "BEGIN TRANSACTION"); err != nil {
		return err
	}
	defer func() {
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
	}()

	return conn.Raw(func(dc any) error {
		c := dc.(*duckdb.Conn)
		// Prepare (not PrepareContext): refuses multi-statement input instead
		// of executing all but the last statement.
		ds, err := c.Prepare(query)
		if err != nil {
			if strings.Contains(err.Error(), "multi-statement") {
				return &QueryError{errors.New("one statement per request: send each statement in its own request, without ';' between them")}
			}
			return &QueryError{errors.New(PublicError(err))}
		}
		st := ds.(*duckdb.Stmt)
		defer st.Close()

		typ, err := st.StatementType()
		if err != nil {
			return &QueryError{errors.New(PublicError(err))}
		}
		if alwaysDenied[typ] {
			return fmt.Errorf("%w: %s statements are not allowed", ErrForbidden, stmtTypeName(typ))
		}
		if typ == duckdb.STATEMENT_TYPE_TRANSACTION {
			return &QueryError{errors.New("transaction statements are not supported: each request runs in its own transaction")}
		}
		return nil
	})
}
