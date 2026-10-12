//go:build duckdb_arrow

package server

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/apache/arrow-go/v18/arrow/flight/flightsql"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/policy"
)

// startFlight serves Flight SQL for a new test server and returns its
// address, with the server's HTTP API.
func startFlight(t *testing.T) (string, *httptest.Server) {
	t.Helper()
	ts := newServer(t)
	g, err := lastServer.Flight(nil)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go g.Serve(lis)
	t.Cleanup(g.Stop)
	return lis.Addr().String(), ts
}

func flightClient(t *testing.T, addr string) *flightsql.Client {
	t.Helper()
	cl, err := flightsql.NewClient(addr, nil, nil, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	return cl
}

// flightLogin logs user in (password user-pw) and returns the context
// carrying the session token.
func flightLogin(t *testing.T, cl *flightsql.Client, user string) context.Context {
	t.Helper()
	ctx, err := cl.Client.AuthenticateBasicToken(context.Background(), user, user+"-pw")
	if err != nil {
		t.Fatalf("login %s: %v", user, err)
	}
	return ctx
}

// fetch reads every endpoint of info as rows of ValueStr cells.
func fetch(ctx context.Context, cl *flightsql.Client, info *flight.FlightInfo, err error) ([][]string, *arrow.Schema, error) {
	if err != nil {
		return nil, nil, err
	}
	var rows [][]string
	var schema *arrow.Schema
	for _, ep := range info.Endpoint {
		rd, err := cl.DoGet(ctx, ep.Ticket)
		if err != nil {
			return nil, nil, err
		}
		schema = rd.Schema()
		for rd.Next() {
			rec := rd.RecordBatch()
			for i := range int(rec.NumRows()) {
				row := make([]string, rec.NumCols())
				for j, col := range rec.Columns() {
					row[j] = col.ValueStr(i)
				}
				rows = append(rows, row)
			}
		}
		err = rd.Err()
		rd.Release()
		if err != nil {
			return nil, nil, err
		}
	}
	return rows, schema, nil
}

func query(ctx context.Context, cl *flightsql.Client, sql string) ([][]string, *arrow.Schema, error) {
	info, err := cl.Execute(ctx, sql)
	return fetch(ctx, cl, info, err)
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if status.Code(err) != code {
		t.Fatalf("got %v, want %v", err, code)
	}
}

func TestFlightQueries(t *testing.T) {
	addr, _ := startFlight(t)
	cl := flightClient(t, addr)
	analyst := flightLogin(t, cl, "analyst")

	rows, schema, err := query(analyst, cl, "SELECT id, amount FROM orders ORDER BY id")
	if err != nil || !slices.Equal(rows[0], []string{"1", "10.5"}) || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if got := schema.Field(1).Type.String(); got != "decimal(10, 2)" {
		t.Fatalf("amount type %s", got)
	}

	// The policy and the engine decide as over HTTP.
	_, _, err = query(analyst, cl, "SELECT * FROM salaries")
	wantCode(t, err, codes.PermissionDenied)
	_, _, err = query(analyst, cl, "SELECT * FROM information_schema.tables")
	wantCode(t, err, codes.PermissionDenied)
	_, _, err = query(analyst, cl, "SELEC 1")
	wantCode(t, err, codes.InvalidArgument)
	_, err = cl.ExecuteUpdate(analyst, "DELETE FROM orders")
	wantCode(t, err, codes.PermissionDenied)

	etl := flightLogin(t, cl, "etl")
	if n, err := cl.ExecuteUpdate(etl, "INSERT INTO orders VALUES (3, 1), (4, 2)"); err != nil || n != 2 {
		t.Fatalf("insert: %d %v", n, err)
	}

	// The database header picks the catalog for unqualified names.
	logs := metadata.AppendToOutgoingContext(analyst, "database", "logs")
	if rows, _, err := query(logs, cl, "SELECT count(*) FROM events"); err != nil || rows[0][0] != "0" {
		t.Fatalf("logs: %v %v", rows, err)
	}
}

func TestFlightSessionCatalog(t *testing.T) {
	addr, _ := startFlight(t)
	cl, err := flightsql.NewClient(addr, nil, []flight.ClientMiddleware{flight.NewClientCookieMiddleware()},
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cl.Close() })
	ctx := flightLogin(t, cl, "analyst")
	set := func(catalog string) *flight.SetSessionOptionsResult {
		t.Helper()
		opts, _ := flight.NewSessionOptionValues(map[string]any{"catalog": catalog})
		res, err := cl.SetSessionOptions(ctx, &flight.SetSessionOptionsRequest{SessionOptions: opts})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	// JDBC's setCatalog: unqualified names resolve in the picked database
	// on the calls that follow.
	if res := set("logs"); len(res.Errors) != 0 {
		t.Fatalf("set logs: %v", res.Errors)
	}
	if _, _, err := query(ctx, cl, "SELECT count(*) FROM events"); err != nil {
		t.Fatal(err)
	}
	if res := set("nope"); res.Errors["catalog"].GetValue() != flight.SetSessionOptionsResultErrorInvalidValue {
		t.Fatalf("set nope: %v", res.Errors)
	}
	set("sales")
	if _, _, err := query(ctx, cl, "SELECT count(*) FROM orders"); err != nil {
		t.Fatal(err)
	}
}

func TestFlightAuth(t *testing.T) {
	addr, ts := startFlight(t)
	cl := flightClient(t, addr)
	if _, err := cl.Client.AuthenticateBasicToken(context.Background(), "analyst", "wrong"); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong password: %v", err)
	}
	_, err := cl.Execute(context.Background(), "SELECT 1")
	wantCode(t, err, codes.Unauthenticated)

	// A password login trades the password for a session token.
	ctx, err := cl.Client.AuthenticateBasicToken(context.Background(), "analyst", "analyst-pw")
	if err != nil {
		t.Fatal(err)
	}
	md, _ := metadata.FromOutgoingContext(ctx)
	if tok := md.Get("authorization"); len(tok) != 1 || !strings.HasPrefix(tok[0], "Bearer "+auth.SessionPrefix) {
		t.Fatalf("token %v", tok)
	}
	if _, _, err := query(ctx, cl, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	// Session tokens are for Flight SQL only.
	req, _ := http.NewRequest("POST", ts.URL+"/v1/query", strings.NewReader(`{"sql":"SELECT 1"}`))
	req.Header.Set("Authorization", md.Get("authorization")[0])
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session token over HTTP: %d", resp.StatusCode)
	}
}

func TestFlightPreparedStatements(t *testing.T) {
	addr, _ := startFlight(t)
	cl := flightClient(t, addr)
	analyst := flightLogin(t, cl, "analyst")

	// Queries carry their result schema (JDBC drivers up to 19 tell
	// queries from updates by it) and their parameter types.
	ps, err := cl.Prepare(analyst, "SELECT id FROM orders WHERE id = $1")
	if err != nil {
		t.Fatal(err)
	}
	if up, ok := ps.IsUpdate(); !ok || up {
		t.Fatalf("is_update %v %v", up, ok)
	}
	if ds := ps.DatasetSchema(); ds == nil || ds.NumFields() != 1 || ds.Field(0).Type.ID() != arrow.INT32 {
		t.Fatalf("dataset schema %v", ds)
	}
	if p := ps.ParameterSchema(); p == nil || p.NumFields() != 1 || p.Field(0).Type.ID() != arrow.INT32 {
		t.Fatalf("parameter schema %v", p)
	}
	b := array.NewRecordBuilder(memory.DefaultAllocator, ps.ParameterSchema())
	b.Field(0).(*array.Int32Builder).Append(2)
	ps.SetParameters(b.NewRecordBatch())
	info, err := ps.Execute(analyst)
	rows, _, err := fetch(analyst, cl, info, err)
	if err != nil || len(rows) != 1 || rows[0][0] != "2" {
		t.Fatalf("bound query: %v %v", rows, err)
	}

	// A refused statement fails when prepared.
	_, err = cl.Prepare(analyst, "SELECT * FROM salaries")
	wantCode(t, err, codes.PermissionDenied)

	etl := flightLogin(t, cl, "etl")
	up, err := cl.Prepare(etl, "INSERT INTO orders VALUES ($1, $2)")
	if err != nil {
		t.Fatal(err)
	}
	if isUp, ok := up.IsUpdate(); !ok || !isUp || (up.DatasetSchema() != nil && up.DatasetSchema().NumFields() != 0) {
		t.Fatalf("update: is_update %v %v, dataset %v", isUp, ok, up.DatasetSchema())
	}
	// DECIMAL parameters travel as text, which DuckDB casts.
	if p := up.ParameterSchema(); p.NumFields() != 2 || p.Field(0).Type.ID() != arrow.INT32 || p.Field(1).Type.ID() != arrow.STRING {
		t.Fatalf("update params %v", p)
	}
	pb := array.NewRecordBuilder(memory.DefaultAllocator, up.ParameterSchema())
	pb.Field(0).(*array.Int32Builder).AppendValues([]int32{7, 8}, nil)
	pb.Field(1).(*array.StringBuilder).AppendValues([]string{"1.25", "2.50"}, nil)
	up.SetParameters(pb.NewRecordBatch())
	if n, err := up.ExecuteUpdate(etl); err != nil || n != 2 {
		t.Fatalf("executemany: %d %v", n, err)
	}
	rows, _, err = query(analyst, cl, "SELECT amount FROM orders WHERE id >= 7 ORDER BY id")
	if err != nil || len(rows) != 2 || rows[1][0] != "2.5" {
		t.Fatalf("inserted: %v %v", rows, err)
	}
}

func TestFlightMetadata(t *testing.T) {
	addr, _ := startFlight(t)
	cl := flightClient(t, addr)
	analyst := flightLogin(t, cl, "analyst")

	info, err := cl.GetTables(analyst, &flightsql.GetTablesOpts{IncludeSchema: true})
	rows, _, err := fetch(analyst, cl, info, err)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range rows {
		names = append(names, r[0]+"."+r[1]+"."+r[2])
	}
	// salaries is denied to analysts: it is not listed.
	if !slices.Equal(names, []string{"logs.main.events", "sales.main.orders"}) {
		t.Fatalf("tables %v", names)
	}

	pattern := "ord%"
	info, err = cl.GetTables(analyst, &flightsql.GetTablesOpts{TableNameFilterPattern: &pattern, IncludeSchema: true})
	if err != nil {
		t.Fatal(err)
	}
	rd, err := cl.DoGet(analyst, info.Endpoint[0].Ticket)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Release()
	if !rd.Next() || rd.RecordBatch().NumRows() != 1 || rd.RecordBatch().Column(2).ValueStr(0) != "orders" {
		t.Fatalf("pattern ord%%: %v", rd.RecordBatch())
	}
	ts, err := flight.DeserializeSchema(rd.RecordBatch().Column(4).(*array.Binary).Value(0), memory.DefaultAllocator)
	if err != nil {
		t.Fatal(err)
	}
	amount, _ := ts.FieldsByName("amount")
	md, _ := amount[0].Metadata.GetValue(flightsql.TypeNameKey)
	if len(amount) != 1 || amount[0].Type.String() != "decimal(10, 2)" || md != "DECIMAL(10,2)" {
		t.Fatalf("orders schema %v", ts)
	}

	info, err = cl.GetDBSchemas(analyst, &flightsql.GetDBSchemasOpts{})
	rows, _, err = fetch(analyst, cl, info, err)
	if err != nil || len(rows) != 2 || rows[0][0] != "logs" || rows[1][1] != "main" {
		t.Fatalf("schemas %v %v", rows, err)
	}
	info, err = cl.GetCatalogs(analyst)
	rows, _, err = fetch(analyst, cl, info, err)
	if err != nil || len(rows) != 2 {
		t.Fatalf("catalogs %v %v", rows, err)
	}
}

func TestFlightRowLimit(t *testing.T) {
	addr, _ := startFlight(t)
	f := filepath.Join(t.TempDir(), "p.rego")
	os.WriteFile(f, []byte("package curral\nimport rego.v1\nallow := true\nlimits := {\"max_rows\": 1500}\n"), 0o600)
	pol, err := policy.Load(context.Background(), "data.curral.allow", []string{f}, "data.curral.limits")
	if err != nil {
		t.Fatal(err)
	}
	lastServer.SetPolicy(pol)
	cl := flightClient(t, addr)
	ctx := flightLogin(t, cl, "analyst")
	// The result is cut at the limit and ends cleanly, as over HTTP.
	rows, _, err := query(ctx, cl, "SELECT * FROM range(100000)")
	if err != nil || len(rows) != 1500 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
}
