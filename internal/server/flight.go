package server

// Flight SQL front end: JDBC and ADBC clients (DBeaver, DataGrip, pandas,
// polars...) connect over gRPC and go through the same authentication,
// policy, protections, limits, audit and metrics as the HTTP API. Results
// stream as the Arrow record batches DuckDB produces.

import (
	"context"
	"crypto/tls"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/apache/arrow-go/v18/arrow/flight/flightsql"
	"github.com/apache/arrow-go/v18/arrow/flight/flightsql/schema_ref"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/arrow/util"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/lucasapassos/curral/internal/auth"
	"github.com/lucasapassos/curral/internal/engine"
)

// FlightSessionTTL is how long a Flight SQL login (user and password) lasts
// before the client has to log in again.
const FlightSessionTTL = 12 * time.Hour

// Flight returns a gRPC server answering Flight SQL, to Serve on a
// listener; tlsConf nil serves plaintext. Results are Arrow record batches,
// so the build needs -tags duckdb_arrow.
func (s *Server) Flight(tlsConf *tls.Config) (*grpc.Server, error) {
	if !engine.ArrowAvailable {
		return nil, errors.New("flight sql needs a build with -tags duckdb_arrow")
	}
	f := &flightServer{s: s, sessions: auth.NewSessions(FlightSessionTTL)}
	for id, v := range map[flightsql.SqlInfo]any{
		flightsql.SqlInfoFlightSqlServerName:         "curral",
		flightsql.SqlInfoFlightSqlServerVersion:      s.Version,
		flightsql.SqlInfoFlightSqlServerArrowVersion: arrow.PkgVersion,
		flightsql.SqlInfoFlightSqlServerReadOnly:     false,
		flightsql.SqlInfoFlightSqlServerSql:          true,
		flightsql.SqlInfoFlightSqlServerSubstrait:    false,
		// Each statement runs in its own transaction.
		flightsql.SqlInfoFlightSqlServerTransaction: int32(flightsql.SqlTransactionNone),
		flightsql.SqlInfoTransactionsSupported:      false,
		flightsql.SqlInfoFlightSqlServerCancel:      false,
		flightsql.SqlInfoDDLCatalog:                 false,
		flightsql.SqlInfoDDLSchema:                  true,
		flightsql.SqlInfoDDLTable:                   true,
		flightsql.SqlInfoIdentifierQuoteChar:        `"`,
		flightsql.SqlInfoSearchStringEscape:         `\`,
		flightsql.SqlInfoCatalogTerm:                "database",
		flightsql.SqlInfoSchemaTerm:                 "schema",
		flightsql.SqlInfoCatalogAtStart:             true,
		flightsql.SqlInfoSupportsColumnAliasing:     true,
		flightsql.SqlInfoNullPlusNullIsNull:         true,
	} {
		if err := f.RegisterSqlInfo(id, v); err != nil {
			return nil, err
		}
	}
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(f.unary),
		grpc.ChainStreamInterceptor(f.stream),
		// Stop returns once handlers are done, so none can still write to
		// an audit log being closed.
		grpc.WaitForHandlers(true),
	}
	if tlsConf != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConf)))
	}
	g := grpc.NewServer(opts...)
	flight.RegisterFlightServiceServer(g, flightsql.NewFlightServer(f))
	return g, nil
}

type flightServer struct {
	flightsql.BaseServer
	s        *Server
	sessions *auth.Sessions
}

// flightCall is an authenticated Flight SQL call.
type flightCall struct {
	caller caller
	p      *auth.Principal
	// The catalog for unqualified names: the one the client picked for its
	// session (catalogCookie), else the "database" header.
	database string
}

type flightCallKey struct{}

func callOf(ctx context.Context) *flightCall {
	c, _ := ctx.Value(flightCallKey{}).(*flightCall)
	return c
}

const handshakeMethod = "/arrow.flight.protocol.FlightService/Handshake"

// begin authenticates a call as the HTTP API does a request, lockouts and
// audit included, and returns a context carrying it. setHeader sends the
// response headers: the request ID and, on a handshake, the bearer token
// for the calls that follow (a session token after a password login).
func (f *flightServer) begin(ctx context.Context, method string, setHeader func(metadata.MD) error) (context.Context, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	remote := ""
	if pr, ok := peer.FromContext(ctx); ok && pr.Addr != nil {
		remote = pr.Addr.String()
	}
	xff := md.Get("x-forwarded-for")
	c := caller{requestID: newRequestID(), addr: f.s.clientAddr(remote, xff), forwardedFor: firstOf(xff)}
	authz := firstOf(md.Get("authorization"))
	out := metadata.Pairs("x-request-id", c.requestID)

	p, _, blocked := f.s.login(c, authz, f.sessions)
	switch {
	case blocked:
		_ = setHeader(out)
		return nil, status.Error(codes.ResourceExhausted, errLockedOut)
	case p == nil:
		_ = setHeader(out)
		return nil, status.Error(codes.Unauthenticated, "invalid credentials")
	}
	if method == handshakeMethod {
		bearer := authz
		if token, ok := f.sessions.Issue(f.s.authn.Load(), p); ok {
			bearer = "Bearer " + token
		}
		out.Set("authorization", bearer)
	}
	if err := setHeader(out); err != nil {
		return nil, err
	}
	database := firstOf(md.Get("database"))
	if picked := sessionCatalog(md); picked != "" {
		database = picked
	}
	return context.WithValue(ctx, flightCallKey{}, &flightCall{caller: c, p: p, database: database}), nil
}

func (f *flightServer) unary(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	callCtx, err := f.begin(ctx, info.FullMethod, func(md metadata.MD) error { return grpc.SetHeader(ctx, md) })
	if err != nil {
		return nil, err
	}
	return handler(callCtx, req)
}

func (f *flightServer) stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := f.begin(ss.Context(), info.FullMethod, ss.SetHeader)
	if err != nil {
		return err
	}
	return handler(srv, &callStream{ServerStream: ss, ctx: ctx})
}

type callStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (c *callStream) Context() context.Context { return c.ctx }

func firstOf(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// catalogCookie carries the catalog a client picked with the "catalog"
// session option (JDBC's setCatalog) from call to call, so the server keeps
// no session state. Like the "database" header it grants nothing: it only
// names the catalog for unqualified names.
const catalogCookie = "curral_catalog"

func sessionCatalog(md metadata.MD) string {
	for _, line := range md.Get("cookie") {
		cookies, err := http.ParseCookie(line)
		if err != nil {
			continue
		}
		for _, c := range cookies {
			if c.Name == catalogCookie {
				name, err := base64.RawURLEncoding.DecodeString(c.Value)
				if err == nil {
					return string(name)
				}
			}
		}
	}
	return ""
}

// SetSessionOptions supports one option, "catalog": an attached database,
// used for unqualified names from then on (an unset value goes back to the
// default).
func (f *flightServer) SetSessionOptions(ctx context.Context, req *flight.SetSessionOptionsRequest) (*flight.SetSessionOptionsResult, error) {
	res := &flight.SetSessionOptionsResult{Errors: map[string]*flight.SetSessionOptionsResultError{}}
	for name, v := range req.GetSessionOptions() {
		if name != "catalog" {
			res.Errors[name] = &flight.SetSessionOptionsResultError{Value: flight.SetSessionOptionsResultErrorInvalidName}
			continue
		}
		cookie := &http.Cookie{Name: catalogCookie, Path: "/", MaxAge: -1} // unset: delete it
		if v.GetOptionValue() != nil {
			i := slices.IndexFunc(f.s.Engine.Databases(), func(d engine.DatabaseInfo) bool { return strings.EqualFold(d.Name, v.GetStringValue()) })
			if i < 0 {
				res.Errors[name] = &flight.SetSessionOptionsResultError{Value: flight.SetSessionOptionsResultErrorInvalidValue}
				continue
			}
			cookie = &http.Cookie{Name: catalogCookie, Path: "/", Value: base64.RawURLEncoding.EncodeToString([]byte(f.s.Engine.Databases()[i].Name))}
		}
		if err := grpc.SetHeader(ctx, metadata.Pairs("set-cookie", cookie.String())); err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (f *flightServer) GetSessionOptions(ctx context.Context, _ *flight.GetSessionOptionsRequest) (*flight.GetSessionOptionsResult, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	opts := map[string]any{}
	if c := sessionCatalog(md); c != "" {
		opts["catalog"] = c
	}
	values, err := flight.NewSessionOptionValues(opts)
	if err != nil {
		return nil, err
	}
	return &flight.GetSessionOptionsResult{SessionOptions: values}, nil
}

// CloseSession forgets the session's catalog.
func (f *flightServer) CloseSession(ctx context.Context, _ *flight.CloseSessionRequest) (*flight.CloseSessionResult, error) {
	cookie := &http.Cookie{Name: catalogCookie, Path: "/", MaxAge: -1}
	if err := grpc.SetHeader(ctx, metadata.Pairs("set-cookie", cookie.String())); err != nil {
		return nil, err
	}
	return &flight.CloseSessionResult{Status: flight.CloseSessionResultClosed}, nil
}

// flightStatement is both statement handle and ticket: the request itself,
// so the server keeps no state between calls. It grants nothing: whoever
// redeems it runs it with their own credentials and policy.
type flightStatement struct {
	SQL      string        `json:"sql"`
	Database string        `json:"database,omitempty"`
	Params   []flightParam `json:"params,omitempty"`
}

// flightParam is a bound parameter, typed so that it survives the trip
// through a statement handle.
type flightParam struct {
	Type  string `json:"t"` // null, bool, int, uint, float, string, bytes, time
	Value string `json:"v,omitempty"`
}

var errNoTransactions = status.Error(codes.Unimplemented, "transactions are not supported: each statement runs in its own transaction")

func (f *flightServer) newStatement(ctx context.Context, query string, txn []byte) (flightStatement, error) {
	if len(txn) > 0 {
		return flightStatement{}, errNoTransactions
	}
	if strings.TrimSpace(query) == "" {
		return flightStatement{}, status.Error(codes.InvalidArgument, "sql is required")
	}
	return flightStatement{SQL: query, Database: callOf(ctx).database}, nil
}

func decodeStatement(handle []byte) (flightStatement, error) {
	var st flightStatement
	if err := json.Unmarshal(handle, &st); err != nil || strings.TrimSpace(st.SQL) == "" {
		return st, status.Error(codes.InvalidArgument, "invalid statement handle")
	}
	return st, nil
}

func (st flightStatement) handle() []byte {
	b, _ := json.Marshal(st) // strings only: cannot fail
	return b
}

// args turns the bound parameters into driver values.
func (st flightStatement) args() ([]any, error) {
	out := make([]any, len(st.Params))
	for i, p := range st.Params {
		var err error
		switch p.Type {
		case "null":
		case "bool":
			out[i], err = strconv.ParseBool(p.Value)
		case "int":
			out[i], err = strconv.ParseInt(p.Value, 10, 64)
		case "uint":
			out[i], err = strconv.ParseUint(p.Value, 10, 64)
		case "float":
			out[i], err = strconv.ParseFloat(p.Value, 64)
		case "string":
			out[i] = p.Value
		case "bytes":
			out[i], err = base64.StdEncoding.DecodeString(p.Value)
		case "time":
			out[i], err = time.Parse(time.RFC3339Nano, p.Value)
		default:
			err = errors.New("unknown type " + strconv.Quote(p.Type))
		}
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parameter %d: %v", i+1, err)
		}
	}
	return out, nil
}

// readParams reads the parameter sets bound to a prepared statement: one
// per row of the record batches sent.
func readParams(rdr flight.MessageReader) ([][]flightParam, error) {
	var sets [][]flightParam
	for rdr.Next() {
		rec := rdr.RecordBatch()
		for row := range int(rec.NumRows()) {
			set := make([]flightParam, rec.NumCols())
			for i, col := range rec.Columns() {
				set[i] = paramOf(col, row)
			}
			sets = append(sets, set)
		}
	}
	if err := rdr.Err(); err != nil && !errors.Is(err, io.EOF) {
		return nil, status.Errorf(codes.InvalidArgument, "reading parameters: %v", err)
	}
	return sets, nil
}

func paramOf(col arrow.Array, i int) flightParam {
	if col.IsNull(i) {
		return flightParam{Type: "null"}
	}
	integer := func(v int64) flightParam { return flightParam{"int", strconv.FormatInt(v, 10)} }
	unsigned := func(v uint64) flightParam { return flightParam{"uint", strconv.FormatUint(v, 10)} }
	float := func(v float64) flightParam { return flightParam{"float", strconv.FormatFloat(v, 'g', -1, 64)} }
	timestamp := func(t time.Time) flightParam { return flightParam{"time", t.UTC().Format(time.RFC3339Nano)} }
	switch a := col.(type) {
	case *array.Boolean:
		return flightParam{"bool", strconv.FormatBool(a.Value(i))}
	case *array.Int8:
		return integer(int64(a.Value(i)))
	case *array.Int16:
		return integer(int64(a.Value(i)))
	case *array.Int32:
		return integer(int64(a.Value(i)))
	case *array.Int64:
		return integer(a.Value(i))
	case *array.Uint8:
		return unsigned(uint64(a.Value(i)))
	case *array.Uint16:
		return unsigned(uint64(a.Value(i)))
	case *array.Uint32:
		return unsigned(uint64(a.Value(i)))
	case *array.Uint64:
		return unsigned(a.Value(i))
	case *array.Float32:
		return float(float64(a.Value(i)))
	case *array.Float64:
		return float(a.Value(i))
	case *array.Binary:
		return flightParam{"bytes", base64.StdEncoding.EncodeToString(a.Value(i))}
	case *array.LargeBinary:
		return flightParam{"bytes", base64.StdEncoding.EncodeToString(a.Value(i))}
	case *array.Date32:
		return timestamp(a.Value(i).ToTime())
	case *array.Date64:
		return timestamp(a.Value(i).ToTime())
	case *array.Timestamp:
		return timestamp(a.Value(i).ToTime(a.DataType().(*arrow.TimestampType).Unit))
	}
	// Strings, decimals and the rest: DuckDB casts the text as needed.
	return flightParam{"string", col.ValueStr(i)}
}

// query runs st for the call and streams the result. Its schema is only
// known once the statement runs, so this returns when the first result
// arrives or the statement fails.
func (f *flightServer) query(ctx context.Context, st flightStatement) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	c := callOf(ctx)
	args, err := st.args()
	if err != nil {
		return nil, nil, err
	}
	ev := f.s.event(c.caller, "query", c.p)
	f.s.setSQL(ev, st.SQL)
	ev.ParamsCount, ev.Database = len(args), st.Database

	type start struct {
		schema *arrow.Schema
		err    error
	}
	first := make(chan start, 1)
	chunks := make(chan flight.StreamChunk)
	go func() {
		defer close(chunks)
		started := false
		run := f.s.runQuery(ctx, c.p, ev, queryCall{
			sql: st.SQL, params: args, database: st.Database, format: "flight",
			sink: resultSink{
				records: func(_ engine.Inspection, maxRows int64, rr array.RecordReader) (int64, int64, error) {
					started = true
					first <- start{schema: rr.Schema()}
					var bytes int64
					n, err := eachRecord(rr, maxRows, func(rec arrow.RecordBatch) error {
						bytes += util.TotalRecordSize(rec)
						rec.Retain() // the reader reuses its batch; DoGet releases ours
						select {
						case chunks <- flight.StreamChunk{Data: rec}:
							return nil
						case <-ctx.Done():
							rec.Release()
							return ctx.Err()
						}
					})
					return n, bytes, err
				},
				started: func() bool { return started },
			},
		})
		switch {
		case !started:
			first <- start{err: flightError(run)}
		case errors.Is(run.err, engine.ErrMaxRows):
			// The result was cut at the row limit; it ends cleanly, as
			// over HTTP, with the reason in a trailer.
			_ = grpc.SetTrailer(ctx, metadata.Pairs("x-curral-error", engine.ErrMaxRows.Error()))
		case run.err != nil:
			select {
			case chunks <- flight.StreamChunk{Err: flightError(run)}:
			case <-ctx.Done():
			}
		}
	}()
	s := <-first
	if s.err != nil {
		return nil, nil, s.err
	}
	return s.schema, chunks, nil
}

// update runs st for the call and returns its update count: DuckDB answers
// DML with a single Count row.
func (f *flightServer) update(ctx context.Context, st flightStatement) (int64, error) {
	c := callOf(ctx)
	args, err := st.args()
	if err != nil {
		return 0, err
	}
	ev := f.s.event(c.caller, "query", c.p)
	f.s.setSQL(ev, st.SQL)
	ev.ParamsCount, ev.Database = len(args), st.Database

	var count int64
	run := f.s.runQuery(ctx, c.p, ev, queryCall{
		sql: st.SQL, params: args, database: st.Database, format: "flight",
		sink: resultSink{
			rows: func(_ engine.Inspection, _ int64, cols []engine.Column, rs engine.Rows) (int64, int64, error) {
				vals := make([]driver.Value, len(cols))
				if err := rs.Next(vals); err != nil {
					if errors.Is(err, io.EOF) {
						return 0, 0, nil
					}
					return 0, 0, err
				}
				if len(cols) == 1 && strings.EqualFold(cols[0].Name, "Count") {
					switch v := vals[0].(type) {
					case int64:
						count = v
					case int32:
						count = int64(v)
					}
				}
				return 1, 0, nil
			},
			// Nothing reaches the client before the count.
			started: func() bool { return false },
		},
	})
	if run.err != nil {
		return 0, flightError(run)
	}
	return count, nil
}

// flightError is a failed run as a gRPC status, with what the client may
// see of it.
func flightError(run queryRun) error {
	return status.Error(grpcCode(statusOf(run.err, run.policyE)), run.publicError())
}

// grpcCode maps the HTTP status curral answers with to a gRPC code.
func grpcCode(httpStatus int) codes.Code {
	switch httpStatus {
	case http.StatusBadRequest:
		return codes.InvalidArgument
	case http.StatusUnauthorized:
		return codes.Unauthenticated
	case http.StatusForbidden:
		return codes.PermissionDenied
	case http.StatusTooManyRequests:
		return codes.ResourceExhausted
	case 499:
		return codes.Canceled
	case http.StatusServiceUnavailable:
		return codes.Unavailable
	case http.StatusGatewayTimeout:
		return codes.DeadlineExceeded
	}
	return codes.Internal
}

// info describes the result of desc's command, fetched with a ticket that
// is the command itself.
func info(desc *flight.FlightDescriptor, schema *arrow.Schema) *flight.FlightInfo {
	fi := &flight.FlightInfo{
		Endpoint:         []*flight.FlightEndpoint{{Ticket: &flight.Ticket{Ticket: desc.Cmd}}},
		FlightDescriptor: desc,
		TotalRecords:     -1,
		TotalBytes:       -1,
	}
	if schema != nil {
		fi.Schema = flight.SerializeSchema(schema, memory.DefaultAllocator)
	}
	return fi
}

func (f *flightServer) GetFlightInfoStatement(ctx context.Context, cmd flightsql.StatementQuery, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	st, err := f.newStatement(ctx, cmd.GetQuery(), cmd.GetTransactionId())
	if err != nil {
		return nil, err
	}
	tkt, err := flightsql.CreateStatementQueryTicket(st.handle())
	if err != nil {
		return nil, err
	}
	return &flight.FlightInfo{
		Endpoint:         []*flight.FlightEndpoint{{Ticket: &flight.Ticket{Ticket: tkt}}},
		FlightDescriptor: desc,
		TotalRecords:     -1,
		TotalBytes:       -1,
	}, nil
}

func (f *flightServer) DoGetStatement(ctx context.Context, tkt flightsql.StatementQueryTicket) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	st, err := decodeStatement(tkt.GetStatementHandle())
	if err != nil {
		return nil, nil, err
	}
	return f.query(ctx, st)
}

func (f *flightServer) DoPutCommandStatementUpdate(ctx context.Context, cmd flightsql.StatementUpdate) (int64, error) {
	st, err := f.newStatement(ctx, cmd.GetQuery(), cmd.GetTransactionId())
	if err != nil {
		return 0, err
	}
	return f.update(ctx, st)
}

// CreatePreparedStatement inspects and authorizes the statement without
// running it (a "prepare" audit event), so a refusal shows up at once, and
// describes its parameters and result. JDBC drivers up to 19 take a
// statement with an empty result schema for an update, so the result
// schema is only sent for statements answered with rows; is_update says
// the same to newer clients. The statement is authorized again when it
// runs: the handle grants nothing.
func (f *flightServer) CreatePreparedStatement(ctx context.Context, req flightsql.ActionCreatePreparedStatementRequest) (flightsql.ActionCreatePreparedStatementResult, error) {
	var res flightsql.ActionCreatePreparedStatementResult
	st, err := f.newStatement(ctx, req.GetQuery(), req.GetTransactionId())
	if err != nil {
		return res, err
	}
	d, err := f.describe(ctx, st)
	if err != nil {
		return res, err
	}
	params := make([]arrow.Field, len(d.Params))
	for i, t := range d.Params {
		params[i] = arrow.Field{Name: "$" + strconv.Itoa(i+1), Type: arrowType(t), Nullable: true}
	}
	res.Handle, res.ParameterSchema = st.handle(), arrow.NewSchema(params, nil)
	rows := engine.ReturnsRows(st.SQL)
	if rows {
		cols := make([]arrow.Field, len(d.Columns))
		for i, c := range d.Columns {
			md := flightsql.NewColumnMetadataBuilder().TypeName(c.Type).Metadata()
			cols[i] = arrow.Field{Name: c.Name, Type: arrowType(c.Type), Nullable: true, Metadata: md}
		}
		res.DatasetSchema = arrow.NewSchema(cols, nil)
	}
	isUpdate := !rows
	res.IsUpdate = &isUpdate
	return res, nil
}

// describe inspects, authorizes and describes st for the call without
// running it.
func (f *flightServer) describe(ctx context.Context, st flightStatement) (engine.Description, error) {
	c := callOf(ctx)
	args, err := st.args()
	if err != nil {
		return engine.Description{}, err
	}
	ev := f.s.event(c.caller, "prepare", c.p)
	f.s.setSQL(ev, st.SQL)
	ev.ParamsCount, ev.Database = len(args), st.Database
	var d engine.Description
	run := f.s.runQuery(ctx, c.p, ev, queryCall{
		sql: st.SQL, params: args, database: st.Database, format: "flight",
		describe: func(desc engine.Description) error { d = desc; return nil },
		sink:     resultSink{started: func() bool { return false }},
	})
	if run.err != nil {
		return d, flightError(run)
	}
	return d, nil
}

func (f *flightServer) ClosePreparedStatement(context.Context, flightsql.ActionClosePreparedStatementRequest) error {
	return nil // handles hold no server state
}

func (f *flightServer) GetFlightInfoPreparedStatement(_ context.Context, cmd flightsql.PreparedStatementQuery, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	if _, err := decodeStatement(cmd.GetPreparedStatementHandle()); err != nil {
		return nil, err
	}
	return info(desc, nil), nil
}

func (f *flightServer) DoGetPreparedStatement(ctx context.Context, cmd flightsql.PreparedStatementQuery) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	st, err := decodeStatement(cmd.GetPreparedStatementHandle())
	if err != nil {
		return nil, nil, err
	}
	return f.query(ctx, st)
}

// DoPutPreparedStatementQuery binds parameters by returning a new handle
// that carries them.
func (f *flightServer) DoPutPreparedStatementQuery(_ context.Context, cmd flightsql.PreparedStatementQuery, rdr flight.MessageReader, _ flight.MetadataWriter) ([]byte, error) {
	st, err := decodeStatement(cmd.GetPreparedStatementHandle())
	if err != nil {
		return nil, err
	}
	sets, err := readParams(rdr)
	if err != nil {
		return nil, err
	}
	switch len(sets) {
	case 0:
	case 1:
		st.Params = sets[0]
	default:
		return nil, status.Error(codes.InvalidArgument, "a query takes a single set of parameters")
	}
	return st.handle(), nil
}

// DoPutPreparedStatementUpdate runs the statement once per parameter set
// sent (or once with the parameters already bound) and adds up the counts.
func (f *flightServer) DoPutPreparedStatementUpdate(ctx context.Context, cmd flightsql.PreparedStatementUpdate, rdr flight.MessageReader) (int64, error) {
	st, err := decodeStatement(cmd.GetPreparedStatementHandle())
	if err != nil {
		return 0, err
	}
	sets, err := readParams(rdr)
	if err != nil {
		return 0, err
	}
	if len(sets) == 0 {
		return f.update(ctx, st)
	}
	var total int64
	for _, set := range sets {
		st.Params = set
		n, err := f.update(ctx, st)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// listSchema lists what the caller may query, as GET /v1/schema does.
func (f *flightServer) listSchema(ctx context.Context, filter engine.SchemaFilter, match func(engine.TableSchema) bool) ([]engine.TableSchema, error) {
	c := callOf(ctx)
	tables, code, msg := f.s.listSchema(ctx, c.p, f.s.event(c.caller, "schema", c.p), filter, match)
	if code != http.StatusOK {
		return nil, status.Error(grpcCode(code), msg)
	}
	return tables, nil
}

// likePattern reads a Flight SQL filter pattern (SQL LIKE: % any run, _ any
// character, \ escapes the next one). It returns the name to narrow the
// engine's listing with when the pattern is a plain name, and a matcher.
// Names compare case-insensitively, as in GET /v1/schema.
func likePattern(p *string) (exact string, match func(string) bool) {
	if p == nil || *p == "" || *p == "%" {
		return "", func(string) bool { return true }
	}
	var re, lit strings.Builder
	re.WriteString("(?is)^")
	plain, escaped := true, false
	for _, r := range *p {
		switch {
		case escaped:
			re.WriteString(regexp.QuoteMeta(string(r)))
			lit.WriteRune(r)
			escaped = false
		case r == '\\':
			escaped = true
		case r == '%':
			re.WriteString(".*")
			plain = false
		case r == '_':
			re.WriteString(".")
			plain = false
		default:
			re.WriteString(regexp.QuoteMeta(string(r)))
			lit.WriteRune(r)
		}
	}
	re.WriteString("$")
	if plain {
		name := lit.String()
		return name, func(s string) bool { return strings.EqualFold(s, name) }
	}
	return "", regexp.MustCompile(re.String()).MatchString
}

// catalogFilter matches a Flight SQL catalog: an exact name, or any.
func catalogFilter(c *string) (exact string, match func(string) bool) {
	if c == nil || *c == "" {
		return "", func(string) bool { return true }
	}
	name := *c
	return name, func(s string) bool { return strings.EqualFold(s, name) }
}

// batch streams one record batch built by fill.
func batch(schema *arrow.Schema, fill func(b *array.RecordBuilder)) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	b := array.NewRecordBuilder(memory.DefaultAllocator, schema)
	defer b.Release()
	if fill != nil {
		fill(b)
	}
	ch := make(chan flight.StreamChunk, 1)
	ch <- flight.StreamChunk{Data: b.NewRecordBatch()}
	close(ch)
	return schema, ch, nil
}

func (f *flightServer) GetFlightInfoCatalogs(_ context.Context, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.Catalogs), nil
}

// DoGetCatalogs lists the attached databases, as GET /v1/databases does.
func (f *flightServer) DoGetCatalogs(context.Context) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	return batch(schema_ref.Catalogs, func(b *array.RecordBuilder) {
		for _, d := range f.s.Engine.Databases() {
			b.Field(0).(*array.StringBuilder).Append(d.Name)
		}
	})
}

func (f *flightServer) GetFlightInfoSchemas(_ context.Context, _ flightsql.GetDBSchemas, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.DBSchemas), nil
}

// DoGetDBSchemas lists each database's default schema and the schemas
// holding something the caller may query.
func (f *flightServer) DoGetDBSchemas(ctx context.Context, cmd flightsql.GetDBSchemas) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	catalog, matchCatalog := catalogFilter(cmd.GetCatalog())
	schema, matchSchema := likePattern(cmd.GetDBSchemaFilterPattern())
	tables, err := f.listSchema(ctx, engine.SchemaFilter{Database: catalog, Schema: schema},
		func(t engine.TableSchema) bool { return matchSchema(t.Schema) })
	if err != nil {
		return nil, nil, err
	}
	var found [][2]string
	for _, d := range f.s.Engine.Databases() {
		if matchCatalog(d.Name) && matchSchema(d.Schema) {
			found = append(found, [2]string{d.Name, d.Schema})
		}
	}
	for _, t := range tables {
		found = append(found, [2]string{t.Database, t.Schema})
	}
	slices.SortFunc(found, func(a, b [2]string) int { return strings.Compare(a[0]+"\x00"+a[1], b[0]+"\x00"+b[1]) })
	found = slices.Compact(found)
	return batch(schema_ref.DBSchemas, func(b *array.RecordBuilder) {
		for _, s := range found {
			b.Field(0).(*array.StringBuilder).Append(s[0])
			b.Field(1).(*array.StringBuilder).Append(s[1])
		}
	})
}

func (f *flightServer) GetFlightInfoTables(_ context.Context, cmd flightsql.GetTables, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	if cmd.GetIncludeSchema() {
		return info(desc, schema_ref.TablesWithIncludedSchema), nil
	}
	return info(desc, schema_ref.Tables), nil
}

// DoGetTables lists the tables and views the caller may query, with their
// columns when asked; column types come from DuckDB's type names.
func (f *flightServer) DoGetTables(ctx context.Context, cmd flightsql.GetTables) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	catalog, _ := catalogFilter(cmd.GetCatalog())
	schema, matchSchema := likePattern(cmd.GetDBSchemaFilterPattern())
	table, matchTable := likePattern(cmd.GetTableNameFilterPattern())
	types := cmd.GetTableTypes()
	tables, err := f.listSchema(ctx, engine.SchemaFilter{Database: catalog, Schema: schema, Table: table},
		func(t engine.TableSchema) bool {
			return matchSchema(t.Schema) && matchTable(t.Name) &&
				(len(types) == 0 || slices.ContainsFunc(types, func(k string) bool { return strings.EqualFold(k, t.Kind) }))
		})
	if err != nil {
		return nil, nil, err
	}
	out := schema_ref.Tables
	if cmd.GetIncludeSchema() {
		out = schema_ref.TablesWithIncludedSchema
	}
	return batch(out, func(b *array.RecordBuilder) {
		for _, t := range tables {
			b.Field(0).(*array.StringBuilder).Append(t.Database)
			b.Field(1).(*array.StringBuilder).Append(t.Schema)
			b.Field(2).(*array.StringBuilder).Append(t.Name)
			b.Field(3).(*array.StringBuilder).Append(strings.ToUpper(t.Kind))
			if cmd.GetIncludeSchema() {
				b.Field(4).(*array.BinaryBuilder).Append(flight.SerializeSchema(tableSchema(t), memory.DefaultAllocator))
			}
		}
	})
}

// tableSchema describes a table's columns as Arrow fields, with the
// DuckDB type name and comments as Flight SQL column metadata.
func tableSchema(t engine.TableSchema) *arrow.Schema {
	fields := make([]arrow.Field, len(t.Columns))
	for i, col := range t.Columns {
		typ := arrowType(col.Type)
		md := flightsql.NewColumnMetadataBuilder().
			CatalogName(t.Database).SchemaName(t.Schema).TableName(t.Name).
			TypeName(col.Type).Remarks(col.Comment)
		if d, ok := typ.(*arrow.Decimal128Type); ok {
			md.Precision(d.Precision).Scale(d.Scale)
		}
		fields[i] = arrow.Field{Name: col.Name, Type: typ, Nullable: col.Nullable, Metadata: md.Metadata()}
	}
	return arrow.NewSchema(fields, nil)
}

var decimalType = regexp.MustCompile(`^(?:DECIMAL|NUMERIC)\((\d+),\s*(\d+)\)$`)

// arrowType is the Arrow type DuckDB produces for a column of a given
// type name. Types without a simple equivalent (nested types, enums...)
// are described as text; their DuckDB name travels in the metadata.
func arrowType(duck string) arrow.DataType {
	t := strings.ToUpper(strings.TrimSpace(duck))
	if m := decimalType.FindStringSubmatch(t); m != nil {
		p, perr := strconv.ParseInt(m[1], 10, 32)
		s, serr := strconv.ParseInt(m[2], 10, 32)
		if perr == nil && serr == nil {
			return &arrow.Decimal128Type{Precision: int32(p), Scale: int32(s)}
		}
	}
	switch t {
	case "BOOLEAN":
		return arrow.FixedWidthTypes.Boolean
	case "TINYINT":
		return arrow.PrimitiveTypes.Int8
	case "SMALLINT":
		return arrow.PrimitiveTypes.Int16
	case "INTEGER":
		return arrow.PrimitiveTypes.Int32
	case "BIGINT":
		return arrow.PrimitiveTypes.Int64
	case "UTINYINT":
		return arrow.PrimitiveTypes.Uint8
	case "USMALLINT":
		return arrow.PrimitiveTypes.Uint16
	case "UINTEGER":
		return arrow.PrimitiveTypes.Uint32
	case "UBIGINT":
		return arrow.PrimitiveTypes.Uint64
	case "HUGEINT", "UHUGEINT":
		return &arrow.Decimal128Type{Precision: 38, Scale: 0}
	case "FLOAT":
		return arrow.PrimitiveTypes.Float32
	case "DOUBLE":
		return arrow.PrimitiveTypes.Float64
	case "DATE":
		return arrow.FixedWidthTypes.Date32
	case "TIME", "TIME WITH TIME ZONE":
		return arrow.FixedWidthTypes.Time64us
	case "TIMESTAMP":
		return arrow.FixedWidthTypes.Timestamp_us
	case "TIMESTAMP WITH TIME ZONE", "TIMESTAMPTZ":
		return &arrow.TimestampType{Unit: arrow.Microsecond, TimeZone: "UTC"}
	case "TIMESTAMP_S":
		return arrow.FixedWidthTypes.Timestamp_s
	case "TIMESTAMP_MS":
		return arrow.FixedWidthTypes.Timestamp_ms
	case "TIMESTAMP_NS":
		return arrow.FixedWidthTypes.Timestamp_ns
	case "INTERVAL":
		return arrow.FixedWidthTypes.MonthDayNanoInterval
	case "BLOB":
		return arrow.BinaryTypes.Binary
	}
	return arrow.BinaryTypes.String
}

func (f *flightServer) GetFlightInfoTableTypes(_ context.Context, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.TableTypes), nil
}

func (f *flightServer) DoGetTableTypes(context.Context) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	return batch(schema_ref.TableTypes, func(b *array.RecordBuilder) {
		b.Field(0).(*array.StringBuilder).AppendValues([]string{"TABLE", "VIEW"}, nil)
	})
}

// Keys and type information are not part of the schema listing: clients
// get empty answers rather than errors.

func (f *flightServer) GetFlightInfoPrimaryKeys(_ context.Context, _ flightsql.TableRef, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.PrimaryKeys), nil
}

func (f *flightServer) DoGetPrimaryKeys(context.Context, flightsql.TableRef) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	return batch(schema_ref.PrimaryKeys, nil)
}

func (f *flightServer) GetFlightInfoImportedKeys(_ context.Context, _ flightsql.TableRef, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.ImportedKeys), nil
}

func (f *flightServer) DoGetImportedKeys(context.Context, flightsql.TableRef) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	return batch(schema_ref.ImportedKeys, nil)
}

func (f *flightServer) GetFlightInfoExportedKeys(_ context.Context, _ flightsql.TableRef, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.ExportedKeys), nil
}

func (f *flightServer) DoGetExportedKeys(context.Context, flightsql.TableRef) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	return batch(schema_ref.ExportedKeys, nil)
}

func (f *flightServer) GetFlightInfoCrossReference(_ context.Context, _ flightsql.CrossTableRef, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.CrossReference), nil
}

func (f *flightServer) DoGetCrossReference(context.Context, flightsql.CrossTableRef) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	return batch(schema_ref.CrossReference, nil)
}

func (f *flightServer) GetFlightInfoXdbcTypeInfo(_ context.Context, _ flightsql.GetXdbcTypeInfo, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	return info(desc, schema_ref.XdbcTypeInfo), nil
}

func (f *flightServer) DoGetXdbcTypeInfo(context.Context, flightsql.GetXdbcTypeInfo) (*arrow.Schema, <-chan flight.StreamChunk, error) {
	return batch(schema_ref.XdbcTypeInfo, nil)
}
