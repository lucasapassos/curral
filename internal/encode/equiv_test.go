package encode

import (
	"bytes"
	"encoding/csv"
	"math"
	"math/big"
	"math/rand/v2"
	"testing"
	"time"

	duckdb "github.com/duckdb/duckdb-go/v2"
)

// The fast formatters must produce exactly what the reference ones do.

func TestDecimalMatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	edge := []int64{0, 1, -1, 10, -10, 100, 5, -5, math.MaxInt64, math.MinInt64, 1_000_000, -1_000_000}
	for i := range 200_000 {
		var v int64
		if i < len(edge) {
			v = edge[i]
		} else {
			v = r.Int64N(1<<62) - 1<<61
			if r.IntN(4) == 0 {
				v = v / int64(math.Pow10(r.IntN(18))) * int64(math.Pow10(r.IntN(3))) // trailing zeros
			}
		}
		d := duckdb.Decimal{Width: 18, Scale: uint8(r.IntN(19)), Value: big.NewInt(v)}
		if got, want := string(appendDecimal(nil, d)), d.String(); got != want {
			t.Fatalf("%d scale %d: got %q want %q", v, d.Scale, got, want)
		}
	}
	// Beyond int64 falls back to big.Int.
	huge, _ := new(big.Int).SetString("123456789012345678901234567890", 10)
	d := duckdb.Decimal{Width: 38, Scale: 4, Value: huge}
	if got := string(appendDecimal(nil, d)); got != d.String() {
		t.Fatalf("huge: %q", got)
	}
}

func TestTimeMatchesReference(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	zones := []*time.Location{time.UTC, time.FixedZone("x", -3*3600)}
	for range 200_000 {
		sec := r.Int64N(400*365*86400) - 100*365*86400 // ~1870..2270
		ns := int64(0)
		switch r.IntN(4) {
		case 1:
			ns = r.Int64N(1e9)
		case 2:
			ns = r.Int64N(1e6) * 1000
		case 3:
			ns = r.Int64N(1000) * 1e6
		}
		tm := time.Unix(sec, ns).In(zones[r.IntN(2)])
		for _, k := range []valueKind{kindDate, kindTime, kindTimestamp, kindTimestampTZ} {
			if got, want := string(appendTime(nil, tm, k)), string(appendTimeSlow(nil, tm, k)); got != want {
				t.Fatalf("%v kind %d: got %q want %q", tm, k, got, want)
			}
		}
	}
	for _, y := range []int{-1, 0, 1, 9999, 10000} {
		tm := time.Date(y, 3, 4, 5, 6, 7, 0, time.UTC)
		if got, want := string(appendTime(nil, tm, kindDate)), string(appendTimeSlow(nil, tm, kindDate)); got != want {
			t.Fatalf("year %d: got %q want %q", y, got, want)
		}
	}
}

func TestCSVMatchesEncodingCSV(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	alphabet := []string{"a", "Z", "1", ",", "\"", "\n", "\r", " ", "\t", "\\", ".", "ç", " ", "日"}
	for range 50_000 {
		fields := make([]string, 1+r.IntN(4))
		for i := range fields {
			var b []byte
			for range r.IntN(6) {
				b = append(b, alphabet[r.IntN(len(alphabet))]...)
			}
			fields[i] = string(b)
		}
		if r.IntN(50) == 0 {
			fields[0] = `\.`
		}
		var want bytes.Buffer
		cw := csv.NewWriter(&want)
		cw.Write(fields)
		cw.Flush()
		var got []byte
		for i, f := range fields {
			if i > 0 {
				got = append(got, ',')
			}
			got = appendCSVString(got, f)
		}
		got = append(got, '\n')
		if string(got) != want.String() {
			t.Fatalf("fields %q\n got %q\nwant %q", fields, got, want.String())
		}
	}
}
