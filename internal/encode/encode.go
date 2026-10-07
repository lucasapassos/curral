// Package encode streams DuckDB rows as CSV, JSON or NDJSON.
package encode

import (
	"bufio"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"curral/internal/engine"
)

type Format string

const (
	CSV    Format = "csv"
	JSON   Format = "json"
	NDJSON Format = "ndjson"
	Arrow  Format = "arrow" // Arrow IPC stream; written by the engine, not here
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
	case "arrow", "application/vnd.apache.arrow.stream":
		return Arrow, true
	}
	return "", false
}

func (f Format) ContentType() string {
	switch f {
	case CSV:
		return "text/csv; charset=utf-8"
	case NDJSON:
		return "application/x-ndjson"
	case Arrow:
		return "application/vnd.apache.arrow.stream"
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
var ErrMaxRows = engine.ErrMaxRows

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

	// Rows are small writes; batch them before they reach the response.
	bw := writerPool.Get().(*bufio.Writer)
	bw.Reset(w)
	defer func() {
		bw.Reset(nil)
		writerPool.Put(bw)
	}()
	var enc rowEncoder
	switch f {
	case CSV:
		enc = newCSV(bw, cols, fmts)
	case NDJSON:
		enc = newJSONRows(bw, cols, fmts, false)
	default:
		enc = newJSONRows(bw, cols, fmts, true)
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
		if opts.Flush != nil && n%256 == 0 && time.Since(lastFlush) >= opts.FlushEvery {
			if err := enc.flush(); err != nil {
				return n, err
			}
			if err := bw.Flush(); err != nil {
				return n, err
			}
			opts.Flush()
			lastFlush = time.Now()
		}
	}
	if err := enc.end(n, rerr); err != nil {
		return n, err
	}
	if err := bw.Flush(); err != nil {
		return n, err
	}
	return n, rerr
}

var writerPool = sync.Pool{New: func() any { return bufio.NewWriterSize(nil, 64<<10) }}

type rowEncoder interface {
	begin() error
	row([]driver.Value) error
	flush() error
	end(n int64, err error) error
}

// ---- CSV ----

type csvEncoder struct {
	w     io.Writer
	cols  []engine.Column
	kinds []valueKind
	line  []byte
	field []byte
}

func newCSV(w io.Writer, cols []engine.Column, kinds []valueKind) *csvEncoder {
	return &csvEncoder{w: w, cols: cols, kinds: kinds}
}

func (e *csvEncoder) begin() error {
	e.line = e.line[:0]
	for i, c := range e.cols {
		if i > 0 {
			e.line = append(e.line, ',')
		}
		e.line = appendCSVField(e.line, []byte(c.Name))
	}
	_, err := e.w.Write(append(e.line, '\n'))
	return err
}

func (e *csvEncoder) row(vals []driver.Value) error {
	e.line = e.line[:0]
	for i, v := range vals {
		if i > 0 {
			e.line = append(e.line, ',')
		}
		switch t := v.(type) {
		case nil:
		case string:
			e.line = appendCSVString(e.line, t)
		case bool, int8, int16, int32, int64, uint8, uint16, uint32, uint64,
			float32, float64, time.Time, *big.Int, duckdb.Decimal:
			// Never contain separators, quotes or leading spaces.
			e.line = appendText(e.line, v, e.kinds[i])
		default:
			e.field = appendText(e.field[:0], v, e.kinds[i])
			e.line = appendCSVField(e.line, e.field)
		}
	}
	e.line = append(e.line, '\n')
	_, err := e.w.Write(e.line)
	return err
}

func (e *csvEncoder) flush() error { return nil }

func (e *csvEncoder) end(int64, error) error { return nil }

// csvNeedsQuotes follows encoding/csv: quote fields containing a comma,
// quote, CR or LF, starting with a space, or equal to \. (which some
// readers take as end of data).
func csvNeedsQuotes(f []byte) bool {
	if len(f) == 0 {
		return false
	}
	if len(f) == 2 && f[0] == '\\' && f[1] == '.' {
		return true
	}
	for _, c := range f {
		if c == ',' || c == '"' || c == '\r' || c == '\n' {
			return true
		}
	}
	r, _ := utf8.DecodeRune(f)
	return unicode.IsSpace(r)
}

func appendCSVField(b, f []byte) []byte {
	if !csvNeedsQuotes(f) {
		return append(b, f...)
	}
	b = append(b, '"')
	for _, c := range f {
		if c == '"' {
			b = append(b, '"')
		}
		b = append(b, c)
	}
	return append(b, '"')
}

func appendCSVString(b []byte, s string) []byte {
	// Avoid copying the string just to inspect it.
	return appendCSVField(b, unsafe.Slice(unsafe.StringData(s), len(s)))
}

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
	if y := t.Year(); y < 0 || y > 9999 || k == kindTimestampTZ {
		return appendTimeSlow(b, t, k)
	}
	switch k {
	case kindDate:
		return appendDate(b, t)
	case kindTime:
		return appendClock(b, t)
	}
	b = appendDate(b, t)
	b = append(b, 'T')
	return appendClock(b, t)
}

// appendTimeSlow is the reference formatting the fast paths must match.
func appendTimeSlow(b []byte, t time.Time, k valueKind) []byte {
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

func appendDate(b []byte, t time.Time) []byte {
	y, m, d := t.Date()
	b = append(b, byte('0'+y/1000), byte('0'+y/100%10), byte('0'+y/10%10), byte('0'+y%10), '-')
	b = append(b, byte('0'+int(m)/10), byte('0'+int(m)%10), '-')
	return append(b, byte('0'+d/10), byte('0'+d%10))
}

// appendClock writes hh:mm:ss with the fraction trimmed of trailing zeros.
func appendClock(b []byte, t time.Time) []byte {
	h, mi, sec := t.Clock()
	b = append(b, byte('0'+h/10), byte('0'+h%10), ':', byte('0'+mi/10), byte('0'+mi%10), ':',
		byte('0'+sec/10), byte('0'+sec%10))
	ns := t.Nanosecond()
	if ns == 0 {
		return b
	}
	var frac [9]byte
	for i := 8; i >= 0; i-- {
		frac[i] = byte('0' + ns%10)
		ns /= 10
	}
	n := 9
	for frac[n-1] == '0' {
		n--
	}
	b = append(b, '.')
	return append(b, frac[:n]...)
}

// appendDecimal matches duckdb.Decimal.String (trailing fractional zeros
// trimmed) without big.Int formatting when the value fits in an int64.
func appendDecimal(b []byte, d duckdb.Decimal) []byte {
	if d.Value == nil || !d.Value.IsInt64() {
		return append(b, d.String()...)
	}
	v := d.Value.Int64()
	if v == 0 {
		return append(b, '0')
	}
	u := uint64(v)
	if v < 0 {
		b = append(b, '-')
		u = uint64(^v) + 1
	}
	var digits [20]byte
	all := strconv.AppendUint(digits[:0], u, 10)
	trimmed := all
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == '0' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	scale := int(d.Scale) - (len(all) - len(trimmed))
	switch {
	case scale <= 0:
		b = append(b, trimmed...)
		for range -scale {
			b = append(b, '0')
		}
	case len(trimmed) <= scale:
		b = append(b, '0', '.')
		for range scale - len(trimmed) {
			b = append(b, '0')
		}
		b = append(b, trimmed...)
	default:
		b = append(b, trimmed[:len(trimmed)-scale]...)
		b = append(b, '.')
		b = append(b, trimmed[len(trimmed)-scale:]...)
	}
	return b
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
		return appendDecimal(b, t)
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
		b = append(b, '"')
		b = appendDecimal(b, t)
		return append(b, '"')
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
