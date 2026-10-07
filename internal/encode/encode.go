// Package encode streams DuckDB rows as CSV, JSON or NDJSON.
package encode

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"curral/internal/engine"
)

type Format string

const (
	CSV    Format = "csv"
	JSON   Format = "json"
	NDJSON Format = "ndjson"
)

// ParseFormat accepts a format name or a media type.
func ParseFormat(s string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "csv", "text/csv":
		return CSV, true
	case "json", "application/json":
		return JSON, true
	case "ndjson", "jsonl", "application/x-ndjson", "application/jsonl":
		return NDJSON, true
	}
	return "", false
}

func (f Format) ContentType() string {
	switch f {
	case CSV:
		return "text/csv; charset=utf-8"
	case NDJSON:
		return "application/x-ndjson"
	}
	return "application/json"
}

// Options control a single Write call.
type Options struct {
	MaxRows    int64         // 0 = unlimited
	Flush      func()        // called periodically so slow queries trickle out
	FlushEvery time.Duration // default 100ms
}

// ErrMaxRows is returned (after writing MaxRows rows) when more rows exist.
var ErrMaxRows = errors.New("row limit reached")

// Write streams rows to w and returns how many rows were written. If reading
// rows fails midway, the error is returned after the output is closed off in
// a format-appropriate way (JSON gets an "error" field).
func Write(w io.Writer, f Format, cols []engine.Column, rows engine.Rows, opts Options) (int64, error) {
	if opts.FlushEvery == 0 {
		opts.FlushEvery = 100 * time.Millisecond
	}
	fmts := make([]valueKind, len(cols))
	for i, c := range cols {
		fmts[i] = kindOf(c.Type)
	}
	dest := make([]driver.Value, len(cols))
	lastFlush := time.Now()
	var n int64

	var enc rowEncoder
	switch f {
	case CSV:
		enc = newCSV(w, cols, fmts)
	case NDJSON:
		enc = newJSONRows(w, cols, fmts, false)
	default:
		enc = newJSONRows(w, cols, fmts, true)
	}
	if err := enc.begin(); err != nil {
		return 0, err
	}

	var rerr error
	for {
		if err := rows.Next(dest); err != nil {
			if !errors.Is(err, io.EOF) {
				rerr = err
			}
			break
		}
		if opts.MaxRows > 0 && n >= opts.MaxRows {
			rerr = ErrMaxRows
			break
		}
		if err := enc.row(dest); err != nil {
			return n, err // client is gone; nothing more to say
		}
		n++
		if opts.Flush != nil && time.Since(lastFlush) >= opts.FlushEvery {
			if err := enc.flush(); err != nil {
				return n, err
			}
			opts.Flush()
			lastFlush = time.Now()
		}
	}
	if err := enc.end(n, rerr); err != nil {
		return n, err
	}
	return n, rerr
}

type rowEncoder interface {
	begin() error
	row([]driver.Value) error
	flush() error
	end(n int64, err error) error
}

// ---- CSV ----

type csvEncoder struct {
	w     *csv.Writer
	cols  []engine.Column
	kinds []valueKind
	rec   []string
	buf   []byte
}

func newCSV(w io.Writer, cols []engine.Column, kinds []valueKind) *csvEncoder {
	return &csvEncoder{w: csv.NewWriter(w), cols: cols, kinds: kinds, rec: make([]string, len(cols))}
}

func (e *csvEncoder) begin() error {
	for i, c := range e.cols {
		e.rec[i] = c.Name
	}
	return e.w.Write(e.rec)
}

func (e *csvEncoder) row(vals []driver.Value) error {
	for i, v := range vals {
		if v == nil {
			e.rec[i] = ""
			continue
		}
		if s, ok := v.(string); ok {
			e.rec[i] = s
			continue
		}
		e.buf = appendText(e.buf[:0], v, e.kinds[i])
		e.rec[i] = string(e.buf)
	}
	return e.w.Write(e.rec)
}

func (e *csvEncoder) flush() error {
	e.w.Flush()
	return e.w.Error()
}

func (e *csvEncoder) end(int64, error) error { return e.flush() }

// ---- JSON / NDJSON ----

type jsonEncoder struct {
	w        io.Writer
	cols     []engine.Column
	kinds    []valueKind
	keys     [][]byte // pre-encoded `"name":`
	envelope bool
	buf      []byte
	rowsOut  int64
}

func newJSONRows(w io.Writer, cols []engine.Column, kinds []valueKind, envelope bool) *jsonEncoder {
	e := &jsonEncoder{w: w, cols: cols, kinds: kinds, envelope: envelope}
	for _, c := range cols {
		k := appendJSONString(nil, c.Name)
		e.keys = append(e.keys, append(k, ':'))
	}
	return e
}

func (e *jsonEncoder) begin() error {
	if !e.envelope {
		return nil
	}
	head, _ := json.Marshal(e.cols)
	b := append([]byte(`{"columns":`), head...)
	b = append(b, `,"data":[`...)
	_, err := e.w.Write(b)
	return err
}

func (e *jsonEncoder) row(vals []driver.Value) error {
	b := e.buf[:0]
	if e.envelope && e.started() {
		b = append(b, ',')
	}
	b = append(b, '{')
	for i, v := range vals {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, e.keys[i]...)
		b = appendJSON(b, v, e.kinds[i])
	}
	b = append(b, '}')
	if !e.envelope {
		b = append(b, '\n')
	}
	e.buf = b
	e.rowsOut++
	_, err := e.w.Write(b)
	return err
}

func (e *jsonEncoder) started() bool { return e.rowsOut > 0 }

func (e *jsonEncoder) flush() error { return nil }

func (e *jsonEncoder) end(n int64, rerr error) error {
	if !e.envelope {
		return nil
	}
	b := fmt.Appendf(nil, `],"row_count":%d`, n)
	if rerr != nil {
		b = append(b, `,"error":`...)
		b = appendJSONString(b, rerr.Error())
	}
	b = append(b, "}\n"...)
	_, err := e.w.Write(b)
	return err
}

// ---- value formatting ----

type valueKind int

const (
	kindDefault valueKind = iota
	kindDate
	kindTime
	kindTimestamp
	kindTimestampTZ
	kindUUID
)

func kindOf(dbType string) valueKind {
	switch strings.ToUpper(dbType) {
	case "DATE":
		return kindDate
	case "TIME", "TIME_NS":
		return kindTime
	case "TIMESTAMP", "TIMESTAMP_S", "TIMESTAMP_MS", "TIMESTAMP_NS", "DATETIME":
		return kindTimestamp
	case "TIMESTAMPTZ", "TIMESTAMP WITH TIME ZONE", "TIMETZ", "TIME WITH TIME ZONE":
		return kindTimestampTZ
	case "UUID":
		return kindUUID
	}
	return kindDefault
}

func appendTime(b []byte, t time.Time, k valueKind) []byte {
	switch k {
	case kindDate:
		return t.AppendFormat(b, "2006-01-02")
	case kindTime:
		return t.AppendFormat(b, "15:04:05.999999999")
	case kindTimestampTZ:
		return t.AppendFormat(b, time.RFC3339Nano)
	}
	return t.AppendFormat(b, "2006-01-02T15:04:05.999999999")
}

func appendUUID(b []byte, u []byte) []byte {
	if len(u) != 16 {
		return hex.AppendEncode(b, u)
	}
	var s [36]byte
	hex.Encode(s[0:8], u[0:4])
	s[8] = '-'
	hex.Encode(s[9:13], u[4:6])
	s[13] = '-'
	hex.Encode(s[14:18], u[6:8])
	s[18] = '-'
	hex.Encode(s[19:23], u[8:10])
	s[23] = '-'
	hex.Encode(s[24:], u[10:])
	return append(b, s[:]...)
}

// appendText renders a value for CSV. Nested values become JSON text.
func appendText(b []byte, v any, k valueKind) []byte {
	switch t := v.(type) {
	case string:
		return append(b, t...)
	case bool:
		return strconv.AppendBool(b, t)
	case int8, int16, int32, int64, uint8, uint16, uint32, uint64, int, uint:
		return fmt.Append(b, t)
	case float32:
		return appendNumber(b, float64(t), 32)
	case float64:
		return appendNumber(b, t, 64)
	case time.Time:
		return appendTime(b, t, k)
	case []byte:
		if k == kindUUID {
			return appendUUID(b, t)
		}
		return base64.StdEncoding.AppendEncode(b, t)
	case *big.Int:
		return t.Append(b, 10)
	case duckdb.Decimal:
		return append(b, t.String()...)
	}
	return appendJSON(b, v, k)
}

// appendJSON renders any driver value as JSON, with fast paths for scalars.
func appendJSON(b []byte, v any, k valueKind) []byte {
	switch t := v.(type) {
	case nil:
		return append(b, "null"...)
	case string:
		return appendJSONString(b, t)
	case bool:
		return strconv.AppendBool(b, t)
	case int8:
		return strconv.AppendInt(b, int64(t), 10)
	case int16:
		return strconv.AppendInt(b, int64(t), 10)
	case int32:
		return strconv.AppendInt(b, int64(t), 10)
	case int64:
		return strconv.AppendInt(b, t, 10)
	case uint8:
		return strconv.AppendUint(b, uint64(t), 10)
	case uint16:
		return strconv.AppendUint(b, uint64(t), 10)
	case uint32:
		return strconv.AppendUint(b, uint64(t), 10)
	case uint64:
		return strconv.AppendUint(b, t, 10)
	case float32:
		return appendFloat(b, float64(t), 32)
	case float64:
		return appendFloat(b, t, 64)
	case time.Time:
		b = append(b, '"')
		b = appendTime(b, t, k)
		return append(b, '"')
	case []byte:
		b = append(b, '"')
		if k == kindUUID {
			b = appendUUID(b, t)
		} else {
			b = base64.StdEncoding.AppendEncode(b, t)
		}
		return append(b, '"')
	case *big.Int:
		// Strings keep full precision for JavaScript clients.
		b = append(b, '"')
		b = t.Append(b, 10)
		return append(b, '"')
	case duckdb.Decimal:
		return appendJSONString(b, t.String())
	case duckdb.UUID:
		b = append(b, '"')
		b = appendUUID(b, t[:])
		return append(b, '"')
	case []any:
		b = append(b, '[')
		for i, e := range t {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendJSON(b, e, kindDefault)
		}
		return append(b, ']')
	case map[string]any:
		b = append(b, '{')
		i := 0
		for key, e := range t {
			if i > 0 {
				b = append(b, ',')
			}
			i++
			b = appendJSONString(b, key)
			b = append(b, ':')
			b = appendJSON(b, e, kindDefault)
		}
		return append(b, '}')
	case duckdb.OrderedMap:
		// MAP keys may be any type; render as [{"key":..,"value":..}] so
		// order and non-string keys survive.
		b = append(b, '[')
		keys, vals := t.Keys(), t.Values()
		for i := range keys {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, `{"key":`...)
			b = appendJSON(b, keys[i], kindDefault)
			b = append(b, `,"value":`...)
			b = appendJSON(b, vals[i], kindDefault)
			b = append(b, '}')
		}
		return append(b, ']')
	case duckdb.Union:
		b = append(b, `{"tag":`...)
		b = appendJSONString(b, t.Tag)
		b = append(b, `,"value":`...)
		b = appendJSON(b, t.Value, kindDefault)
		return append(b, '}')
	}
	j, err := json.Marshal(v)
	if err != nil {
		return appendJSONString(b, fmt.Sprint(v))
	}
	return append(b, j...)
}

func appendFloat(b []byte, f float64, bits int) []byte {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return append(b, "null"...)
	}
	return appendNumber(b, f, bits)
}

// appendNumber writes the shortest representation, in plain decimal notation
// between 1e-6 and 1e21 (the encoding/json rule), so 105761971.5 does not
// become 1.057619715e+08.
func appendNumber(b []byte, f float64, bits int) []byte {
	if abs := math.Abs(f); abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		return strconv.AppendFloat(b, f, 'g', -1, bits)
	}
	return strconv.AppendFloat(b, f, 'f', -1, bits)
}

const hexDigits = "0123456789abcdef"

func appendJSONString(b []byte, s string) []byte {
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			if c >= 0x20 && c != '"' && c != '\\' {
				i++
				continue
			}
			b = append(b, s[start:i]...)
			switch c {
			case '"', '\\':
				b = append(b, '\\', c)
			case '\n':
				b = append(b, '\\', 'n')
			case '\r':
				b = append(b, '\\', 'r')
			case '\t':
				b = append(b, '\\', 't')
			default:
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			}
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b = append(b, s[start:i]...)
			b = append(b, `�`...)
			i++
			start = i
			continue
		}
		if r == ' ' || r == ' ' {
			b = append(b, s[start:i]...)
			b = append(b, '\\', 'u', '2', '0', '2', hexDigits[r&0xf])
			i += size
			start = i
			continue
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}
