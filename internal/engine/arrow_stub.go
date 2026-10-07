//go:build !duckdb_arrow

package engine

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// ArrowAvailable reports whether this build can return Arrow IPC streams
// (built with -tags duckdb_arrow).
const ArrowAvailable = false

func writeArrow(context.Context, *duckdb.Conn, string, []driver.NamedValue, io.Writer, int64) (int64, error) {
	return 0, &QueryError{errors.New("arrow output is not available in this build (needs -tags duckdb_arrow)")}
}
