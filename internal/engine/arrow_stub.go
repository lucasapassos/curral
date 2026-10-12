//go:build !duckdb_arrow

package engine

import (
	"context"
	"database/sql/driver"
	"errors"

	"github.com/apache/arrow-go/v18/arrow/array"
	duckdb "github.com/duckdb/duckdb-go/v2"
)

// ArrowAvailable reports whether this build can return Arrow results
// (built with -tags duckdb_arrow): Arrow IPC over HTTP and Flight SQL.
const ArrowAvailable = false

func queryArrow(context.Context, *duckdb.Conn, string, []driver.NamedValue) (array.RecordReader, error) {
	return nil, &QueryError{errors.New("arrow output is not available in this build (needs -tags duckdb_arrow)")}
}
