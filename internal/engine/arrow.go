//go:build duckdb_arrow

package engine

import (
	"context"
	"database/sql/driver"
	"io"

	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"
	duckdb "github.com/duckdb/duckdb-go/v2"
)

// ArrowAvailable reports whether this build can return Arrow results
// (built with -tags duckdb_arrow): Arrow IPC over HTTP, Parquet, and Flight SQL.
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

// WriteParquet streams rr to w as an Apache Parquet file, enforcing maxRows
// (> 0). If more rows exist than maxRows, the last batch is sliced so exactly
// maxRows rows are written, the Parquet footer is finalized, and ErrMaxRows is
// returned.
func WriteParquet(w io.Writer, rr array.RecordReader, maxRows int64) (int64, error) {
	// Advance to the first batch before creating the Parquet writer so a
	// runtime error on the first batch returns without writing any bytes.
	hasBatch := rr.Next()
	if !hasBatch {
		if err := rr.Err(); err != nil {
			return 0, err
		}
	}
	fw, err := pqarrow.NewFileWriter(
		rr.Schema(),
		w,
		parquet.NewWriterProperties(),
		pqarrow.NewArrowWriterProperties(pqarrow.WithStoreSchema()),
	)
	if err != nil {
		return 0, err
	}

	var n int64
	for hasBatch {
		rec := rr.RecordBatch()
		rows := rec.NumRows()
		if maxRows > 0 && n+rows > maxRows {
			rem := maxRows - n
			if rem > 0 {
				cut := rec.NewSlice(0, rem)
				werr := fw.Write(cut)
				cut.Release()
				if werr != nil {
					_ = fw.Close()
					return n, werr
				}
			}
			if cerr := fw.Close(); cerr != nil {
				return maxRows, cerr
			}
			return maxRows, ErrMaxRows
		}
		if werr := fw.Write(rec); werr != nil {
			_ = fw.Close()
			return n, werr
		}
		n += rows
		hasBatch = rr.Next()
	}

	rerr := rr.Err()
	if cerr := fw.Close(); cerr != nil && rerr == nil {
		rerr = cerr
	}
	return n, rerr
}
