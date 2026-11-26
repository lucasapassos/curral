//go:build !duckdb_arrow

package engine

import (
	"context"
	"database/sql/driver"
	"io"

	"github.com/apache/arrow-go/v18/arrow/array"
	duckdb "github.com/duckdb/duckdb-go/v2"
)

// ArrowAvailable reports whether this build can return Arrow results
// (built with -tags duckdb_arrow): Arrow IPC over HTTP, Parquet, and Flight SQL.
const ArrowAvailable = false

func queryArrow(context.Context, *duckdb.Conn, string, []driver.NamedValue) (array.RecordReader, error) {
	return nil, &QueryError{ErrArrowUnavailable}
}

// WriteParquet is unavailable without -tags duckdb_arrow.
func WriteParquet(io.Writer, array.RecordReader, int64) (int64, error) {
	return 0, ErrArrowUnavailable
}
