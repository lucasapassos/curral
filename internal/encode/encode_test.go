package encode

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	duckdb "github.com/duckdb/duckdb-go/v2"

	"curral/internal/engine"
)

// query runs SQL on an in-memory DuckDB and encodes the result.
func query(t *testing.T, f Format, q string, opts Options) (string, error) {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, _ := db.Conn(context.Background())
	defer conn.Close()

	var buf bytes.Buffer
	var werr error
	err = conn.Raw(func(dc any) error {
		s, err := dc.(*duckdb.Conn).Prepare(q)
		if err != nil {
			return err
		}
		defer s.Close()
		rows, err := s.(*duckdb.Stmt).QueryContext(context.Background(), nil)
		if err != nil {
			return err
		}
		defer rows.Close()
		typed := rows.(driver.RowsColumnTypeDatabaseTypeName)
		var cols []engine.Column
		for i, n := range rows.Columns() {
			cols = append(cols, engine.Column{Name: n, Type: typed.ColumnTypeDatabaseTypeName(i)})
		}
		_, werr = Write(&buf, f, cols, rows, opts)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return buf.String(), werr
}

const allTypes = `SELECT
	1::TINYINT AS ti, 170141183460469231731687303715884105727::HUGEINT AS h,
	18446744073709551615::UBIGINT AS ub, 1.5::DOUBLE AS d, 'nan'::DOUBLE AS nan,
	123.45::DECIMAL(10,2) AS dec, 'a"b\n'::VARCHAR AS s, NULL::INT AS n, true AS b,
	'00112233-4455-6677-8899-aabbccddeeff'::UUID AS u,
	DATE '2026-10-06' AS dt, TIME '12:34:56.5' AS tm, TIMESTAMP '2026-10-06 01:02:03.25' AS ts,
	TIMESTAMPTZ '2026-10-06 01:02:03+00' AS tz, INTERVAL 3 DAY AS iv, '\x01\x02'::BLOB AS bl,
	[1, 2] AS l, {'a': 1, 'b': [true]} AS st, MAP {'k': 1.5} AS m`

func TestJSONAllTypes(t *testing.T) {
	out, err := query(t, JSON, allTypes, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Columns  []engine.Column
		Data     []map[string]any
		RowCount int `json:"row_count"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	r := doc.Data[0]
	want := map[string]any{
		"ti": 1.0, "h": "170141183460469231731687303715884105727", "ub": 18446744073709551615.0,
		"d": 1.5, "nan": nil, "dec": "123.45", "s": "a\"b\\n", "n": nil, "b": true,
		"u": "00112233-4455-6677-8899-aabbccddeeff", "dt": "2026-10-06", "tm": "12:34:56.5",
		"ts": "2026-10-06T01:02:03.25", "bl": "AQI=",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s = %#v, want %#v", k, r[k], v)
		}
	}
	if !strings.HasPrefix(r["tz"].(string), "2026-10-06T") {
		t.Errorf("tz = %v", r["tz"])
	}
	if doc.RowCount != 1 || len(doc.Columns) != len(r) {
		t.Errorf("row_count=%d columns=%d", doc.RowCount, len(doc.Columns))
	}
	nested, _ := json.Marshal([]any{r["l"], r["st"], r["m"], r["iv"]})
	if string(nested) != `[[1,2],{"a":1,"b":[true]},[{"key":"k","value":"1.5"}],{"days":3,"micros":0,"months":0}]` {
		t.Errorf("nested = %s", nested)
	}
}

func TestCSV(t *testing.T) {
	out, err := query(t, CSV, `SELECT 1 AS id, 'x,"y"' AS s, NULL AS n, [1,2] AS l, DATE '2026-01-02' AS d`, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := "id,s,n,l,d\n1,\"x,\"\"y\"\"\",,\"[1,2]\",2026-01-02\n"
	if out != want {
		t.Fatalf("got %q", out)
	}
}

func TestFloatNotation(t *testing.T) {
	out, err := query(t, CSV, "SELECT 105761971.5000002::DOUBLE AS a, 1e22::DOUBLE AS b, 0.0000001::DOUBLE AS c, 0.5::FLOAT AS d, 'inf'::DOUBLE AS e", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want := "a,b,c,d,e\n105761971.5000002,1e+22,1e-07,0.5,+Inf\n"; out != want {
		t.Fatalf("got %q", out)
	}
}

func TestNDJSONAndMaxRows(t *testing.T) {
	out, err := query(t, NDJSON, "SELECT range AS i FROM range(5)", Options{MaxRows: 3})
	if !errors.Is(err, ErrMaxRows) {
		t.Fatalf("err = %v", err)
	}
	if out != "{\"i\":0}\n{\"i\":1}\n{\"i\":2}\n" {
		t.Fatalf("got %q", out)
	}
	out, _ = query(t, JSON, "SELECT range AS i FROM range(5)", Options{MaxRows: 2})
	if !strings.HasSuffix(out, `"row_count":2,"error":"row limit reached"}`+"\n") {
		t.Fatalf("got %q", out)
	}
}

func TestJSONStringEscaping(t *testing.T) {
	for _, s := range []string{"plain", "q\"b\\s", "\x00\x1f", "ünï", " ", "bad\xffutf8"} {
		var got string
		if err := json.Unmarshal(appendJSONString(nil, s), &got); err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if want := strings.ToValidUTF8(s, "�"); got != want {
			t.Errorf("%q -> %q", s, got)
		}
	}
}

type errRows struct{ n int }

func (r *errRows) Next(dest []driver.Value) error {
	if r.n == 0 {
		return errors.New("boom")
	}
	r.n--
	dest[0] = int64(r.n)
	return nil
}

func TestMidStreamError(t *testing.T) {
	var buf bytes.Buffer
	n, err := Write(&buf, JSON, []engine.Column{{Name: "x", Type: "BIGINT"}}, &errRows{n: 2}, Options{})
	if err == nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil || doc["error"] != "boom" {
		t.Fatalf("doc=%s err=%v", buf.String(), err)
	}
}
