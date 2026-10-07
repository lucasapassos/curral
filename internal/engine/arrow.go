//go:build duckdb_arrow

package engine

import (
	"context"
	"database/sql/driver"
	"io"

	"github.com/apache/arrow-go/v18/arrow/ipc"
	duckdb "github.com/duckdb/duckdb-go/v2"
)

// ArrowAvailable reports whether this build can return Arrow IPC streams
// (built with -tags duckdb_arrow).
const ArrowAvailable = true

// writeArrow runs the statement on c and streams the result as an Arrow IPC
// stream. DuckDB converts whole vectors to Arrow natively, skipping the
// per-value conversion of the row path.
func writeArrow(ctx context.Context, c *duckdb.Conn, query string, args []driver.NamedValue, w io.Writer, maxRows int64) (int64, error) {
	a, err := duckdb.NewArrowFromConn(c)
	if err != nil {
		return 0, err
	}
	vals := make([]any, len(args))
	for i, nv := range args {
		vals[i] = nv.Value
	}
	rr, err := a.QueryContext(ctx, query, vals...)
	if err != nil {
		return 0, &QueryError{err}
	}
	defer rr.Release()

	iw := ipc.NewWriter(w, ipc.WithSchema(rr.Schema()))
	var n int64
	var rerr error
	for rr.Next() {
		rec := rr.RecordBatch()
		rows := rec.NumRows()
		if maxRows > 0 && n+rows > maxRows {
			cut := rec.NewSlice(0, maxRows-n)
			err := iw.Write(cut)
			cut.Release()
			if err != nil {
				return n, err
			}
			n = maxRows
			rerr = ErrMaxRows
			break
		}
		if err := iw.Write(rec); err != nil {
			return n, err
		}
		n += rows
	}
	if rerr == nil {
		rerr = rr.Err()
	}
	if err := iw.Close(); err != nil && rerr == nil {
		rerr = err
	}
	return n, rerr
}
