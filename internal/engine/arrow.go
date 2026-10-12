//go:build duckdb_arrow

package engine

import (
	"context"
	"database/sql/driver"

	"github.com/apache/arrow-go/v18/arrow/array"
	duckdb "github.com/duckdb/duckdb-go/v2"
)

// ArrowAvailable reports whether this build can return Arrow results
// (built with -tags duckdb_arrow): Arrow IPC over HTTP and Flight SQL.
const ArrowAvailable = true

// queryArrow runs the statement on c and returns its result as Arrow record
// batches. DuckDB converts whole vectors to Arrow natively, skipping the
// per-value conversion of the row path.
func queryArrow(ctx context.Context, c *duckdb.Conn, query string, args []driver.NamedValue) (array.RecordReader, error) {
	a, err := duckdb.NewArrowFromConn(c)
	if err != nil {
		return nil, err
	}
	vals := make([]any, len(args))
	for i, nv := range args {
		vals[i] = nv.Value
	}
	rr, err := a.QueryContext(ctx, query, vals...)
	if err != nil {
		return nil, &QueryError{err}
	}
	return rr, nil
}
