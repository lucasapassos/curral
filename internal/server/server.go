// Package server exposes the REST API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"curral/internal/auth"
	"curral/internal/encode"
	"curral/internal/engine"
	"curral/internal/policy"
)

type Server struct {
	Engine  *engine.Engine
	Auth    *auth.Authenticator
	Policy  *policy.Policy
	Log     *slog.Logger
	MaxRows int64
	MaxBody int64
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/query", s.authed(s.query))
	mux.HandleFunc("GET /v1/databases", s.authed(s.databases))
	mux.HandleFunc("GET /healthz", s.health)
	return mux
}

type handler func(http.ResponseWriter, *http.Request, *auth.Principal)

func (s *Server) authed(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		var p *auth.Principal
		if ok {
			p = s.Auth.Authenticate(user, pass)
		}
		if p == nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="curral", charset="UTF-8"`)
			writeError(w, http.StatusUnauthorized, "invalid credentials")
			s.Log.Info("auth failed", "user", user, "remote", r.RemoteAddr)
			return
		}
		h(w, r, p)
	}
}

type queryRequest struct {
	SQL      string `json:"sql"`
	Params   []any  `json:"params"`
	Database string `json:"database"`
	Format   string `json:"format"`
}

func (s *Server) query(w http.ResponseWriter, r *http.Request, p *auth.Principal) {
	start := time.Now()
	var req queryRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, s.MaxBody))
	dec.UseNumber()
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if strings.TrimSpace(req.SQL) == "" {
		writeError(w, http.StatusBadRequest, "sql is required")
		return
	}
	params, err := convertParams(req.Params)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	format, ok := pickFormat(req.Format, r)
	if !ok {
		writeError(w, http.StatusBadRequest, "unsupported format (csv, json, ndjson)")
		return
	}

	var (
		insp    engine.Inspection
		rows    int64
		started bool
		policyE error
	)
	authorize := func(ctx context.Context, i engine.Inspection) error {
		insp = i
		allowed, err := s.Policy.Allow(ctx, map[string]any{
			"user":           p.Name,
			"roles":          p.Roles,
			"sql":            req.SQL,
			"statement_type": i.StatementType,
			"database":       i.Database,
			"tables":         i.Tables,
			"targets":        i.Targets,
			"functions":      i.Functions,
			"databases":      i.Databases,
			"resolved":       i.Resolved,
		})
		if err != nil {
			policyE = err
			return err
		}
		if !allowed {
			return engine.ErrForbidden
		}
		return nil
	}
	emit := func(cols []engine.Column, rs engine.Rows) error {
		started = true
		h := w.Header()
		h.Set("Content-Type", format.ContentType())
		h.Set("X-Curral-Statement-Type", insp.StatementType)
		h.Set("Trailer", "X-Curral-Error, X-Curral-Row-Count")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		n, err := encode.Write(w, format, cols, rs, encode.Options{
			MaxRows: s.MaxRows,
			Flush:   func() { _ = rc.Flush() },
		})
		rows = n
		h.Set("X-Curral-Row-Count", fmt.Sprint(n))
		if err != nil {
			h.Set("X-Curral-Error", oneLine(err.Error()))
		}
		return err
	}

	err = s.Engine.Query(r.Context(), engine.Request{SQL: req.SQL, Params: params, Database: req.Database}, authorize, emit)

	status := http.StatusOK
	if err != nil && !started {
		status = statusOf(err, policyE)
		msg := err.Error()
		if policyE != nil {
			msg = "policy evaluation failed"
		}
		if status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, status, msg)
	}
	attrs := []any{
		"user", p.Name, "status", status, "type", insp.StatementType,
		"databases", insp.Databases, "rows", rows, "format", format,
		"duration", time.Since(start),
	}
	if err != nil {
		attrs = append(attrs, "err", err)
	}
	s.Log.Info("query", attrs...)
}

func statusOf(err, policyErr error) int {
	var qe *engine.QueryError
	switch {
	case policyErr != nil:
		return http.StatusInternalServerError
	case errors.Is(err, engine.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, engine.ErrBusy):
		return http.StatusServiceUnavailable
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout
	case errors.Is(err, context.Canceled):
		return 499 // client closed request
	case errors.As(err, &qe):
		return http.StatusBadRequest
	}
	return http.StatusInternalServerError
}

func pickFormat(body string, r *http.Request) (encode.Format, bool) {
	if body != "" {
		return encode.ParseFormat(body)
	}
	if q := r.URL.Query().Get("format"); q != "" {
		return encode.ParseFormat(q)
	}
	for part := range strings.SplitSeq(r.Header.Get("Accept"), ",") {
		mt, _, _ := strings.Cut(part, ";")
		if f, ok := encode.ParseFormat(mt); ok {
			return f, true
		}
	}
	return encode.JSON, true
}

// convertParams maps JSON values to driver values. Numbers become int64 when
// integral, float64 otherwise.
func convertParams(in []any) ([]any, error) {
	out := make([]any, len(in))
	for i, v := range in {
		switch t := v.(type) {
		case nil, string, bool:
			out[i] = t
		case json.Number:
			if n, err := t.Int64(); err == nil {
				out[i] = n
			} else if f, err := t.Float64(); err == nil {
				out[i] = f
			} else {
				return nil, fmt.Errorf("params[%d]: invalid number %s", i, t)
			}
		default:
			return nil, fmt.Errorf("params[%d]: only scalar values are supported", i)
		}
	}
	return out, nil
}

func (s *Server) databases(w http.ResponseWriter, _ *http.Request, _ *auth.Principal) {
	writeJSON(w, http.StatusOK, map[string]any{"databases": s.Engine.Databases()})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Engine.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
