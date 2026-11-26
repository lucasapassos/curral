package server

import (
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/lucasapassos/curral/internal/encode"
)

var gzipPool = sync.Pool{
	New: func() any {
		w, _ := gzip.NewWriterLevel(io.Discard, gzip.DefaultCompression)
		return w
	},
}

// withCompression gzip-compresses responses when the client advertises
// Accept-Encoding: gzip (with non-zero quality), skipping empty statuses and
// Arrow IPC streams. Trailers and periodic flushes are preserved; if the
// handler panics (e.g. http.ErrAbortHandler) the gzip trailer is intentionally
// omitted so the client sees an incomplete body.
func withCompression(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !acceptsGzip(r.Header.Get("Accept-Encoding")) {
			h.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		gw := &gzipResponseWriter{ResponseWriter: w}
		h.ServeHTTP(gw, r)
		gw.close()
	})
}

func acceptsGzip(h string) bool {
	for part := range strings.SplitSeq(h, ",") {
		enc, params, _ := strings.Cut(part, ";")
		if !strings.EqualFold(strings.TrimSpace(enc), "gzip") {
			continue
		}
		for p := range strings.SplitSeq(params, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(p), "=")
			if ok && strings.EqualFold(strings.TrimSpace(k), "q") {
				v = strings.TrimSpace(v)
				if v == "0" || v == "0.0" || v == "0.00" || v == "0.000" {
					return false
				}
			}
		}
		return true
	}
	return false
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
	bypass      bool
}

func (w *gzipResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	ct := w.Header().Get("Content-Type")
	if code == http.StatusNoContent || code == http.StatusNotModified ||
		strings.HasPrefix(ct, encode.Arrow.ContentType()) ||
		w.Header().Get("Content-Encoding") != "" {
		w.bypass = true
		w.ResponseWriter.WriteHeader(code)
		return
	}
	w.Header().Del("Content-Length")
	w.Header().Set("Content-Encoding", "gzip")
	gz := gzipPool.Get().(*gzip.Writer)
	gz.Reset(w.ResponseWriter)
	w.gz = gz
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.bypass {
		return w.ResponseWriter.Write(b)
	}
	return w.gz.Write(b)
}

func (w *gzipResponseWriter) Flush() {
	if w.gz != nil {
		_ = w.gz.Flush()
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *gzipResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *gzipResponseWriter) close() {
	if w.gz == nil {
		return
	}
	_ = w.gz.Close()
	w.gz.Reset(io.Discard)
	gzipPool.Put(w.gz)
	w.gz = nil
}
