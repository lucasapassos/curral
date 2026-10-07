// Package catalogcache is a loopback caching proxy for Iceberg REST catalogs.
//
// DuckDB asks the catalog for table metadata (loadTable) once per transaction,
// and nothing in DuckDB caches it across transactions; against a remote
// catalog that round trip is most of a query's latency. The proxy caches
// successful GET responses for a TTL, collapses concurrent identical requests,
// and drops the whole cache on any write (commits go through untouched).
package catalogcache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// maxBody bounds what is kept in memory per cached response.
const maxBody = 16 << 20

// credentialMargin is how long before vended credentials expire a cached
// response stops being served.
const credentialMargin = time.Minute

type entry struct {
	header  http.Header
	body    []byte
	expires time.Time
}

type Proxy struct {
	upstream *url.URL
	ttl      time.Duration
	client   *http.Client
	ln       net.Listener
	srv      *http.Server
	log      *slog.Logger

	mu      sync.RWMutex
	entries map[string]entry
	gen     uint64 // bumped on invalidation so in-flight fills are discarded
	group   singleflight.Group

	Hits, Misses, Passthrough atomic.Int64
}

// Start listens on a random loopback port and proxies to upstream, the
// catalog endpoint as given to ATTACH (scheme, host and base path).
func Start(upstream string, ttl time.Duration, log *slog.Logger) (*Proxy, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("catalog cache: invalid endpoint %q", upstream)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &Proxy{
		upstream: u,
		ttl:      ttl,
		client: &http.Client{
			Timeout:   60 * time.Second,
			Transport: &http.Transport{MaxIdleConnsPerHost: 16, IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true},
			// Hand redirects back to DuckDB instead of following them with
			// forwarded credentials.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		ln:      ln,
		log:     log,
		entries: map[string]entry{},
	}
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second}
	go p.srv.Serve(ln)
	return p, nil
}

// URL is the endpoint to give DuckDB instead of the upstream one.
func (p *Proxy) URL() string {
	return "http://" + p.ln.Addr().String() + strings.TrimRight(p.upstream.Path, "/")
}

func (p *Proxy) Close() error { return p.srv.Close() }

// Invalidate drops every cached response.
func (p *Proxy) Invalidate() {
	p.mu.Lock()
	p.entries = map[string]entry{}
	p.gen++
	p.mu.Unlock()
}

var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Content-Length", "Content-Encoding",
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, strings.TrimRight(p.upstream.Path, "/")+"/") {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		// Writes change catalog state: forget everything, then forward.
		p.Invalidate()
		p.Passthrough.Add(1)
		p.forward(w, r)
		return
	}

	key := cacheKey(r)
	p.mu.RLock()
	e, ok := p.entries[key]
	p.mu.RUnlock()
	if ok && time.Now().Before(e.expires) {
		p.Hits.Add(1)
		writeEntry(w, e)
		return
	}

	p.Misses.Add(1)
	v, err, _ := p.group.Do(key, func() (any, error) {
		p.mu.RLock()
		startGen := p.gen
		p.mu.RUnlock()
		start := time.Now()
		resp, err := p.do(r)
		p.log.Debug("catalog cache miss", "path", r.URL.Path, "duration", time.Since(start), "err", err)
		if err != nil {
			return nil, err
		}
		if resp.status == http.StatusOK && len(resp.body) <= maxBody {
			expires := time.Now().Add(p.ttl)
			if credExp, ok := credentialExpiry(resp.body); ok && credExp.Add(-credentialMargin).Before(expires) {
				expires = credExp.Add(-credentialMargin)
			}
			p.mu.Lock()
			if p.gen == startGen && time.Now().Before(expires) {
				p.entries[key] = entry{header: resp.header, body: resp.body, expires: expires}
			}
			p.mu.Unlock()
		}
		return resp, nil
	})
	if err != nil {
		http.Error(w, "catalog cache: "+err.Error(), http.StatusBadGateway)
		return
	}
	resp := v.(*response)
	if resp.status == http.StatusOK {
		writeEntry(w, entry{header: resp.header, body: resp.body})
		return
	}
	copyHeader(w.Header(), resp.header)
	w.WriteHeader(resp.status)
	w.Write(resp.body)
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (p *Proxy) do(r *http.Request) (*response, error) {
	req, err := p.outgoing(r, nil)
	if err != nil {
		return nil, err
	}
	res, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	h := res.Header.Clone()
	for _, k := range hopHeaders {
		h.Del(k)
	}
	return &response{status: res.StatusCode, header: h, body: body}, nil
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req, err := p.outgoing(r, body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	res, err := p.client.Do(req)
	if err != nil {
		http.Error(w, "catalog cache: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer res.Body.Close()
	copyHeader(w.Header(), res.Header)
	for _, k := range hopHeaders {
		w.Header().Del(k)
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}

func (p *Proxy) outgoing(r *http.Request, body []byte) (*http.Request, error) {
	target := *p.upstream
	target.Path = r.URL.Path
	target.RawPath = r.URL.RawPath
	target.RawQuery = r.URL.RawQuery
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), rd)
	if err != nil {
		return nil, err
	}
	req.Header = r.Header.Clone()
	for _, k := range hopHeaders {
		req.Header.Del(k)
	}
	// Let the Go transport negotiate and undo compression.
	req.Header.Del("Accept-Encoding")
	req.Host = p.upstream.Host
	return req, nil
}

// credentialExpiry finds the earliest "...expires-at-ms" value in a loadTable
// response (config and storage-credentials, per the Iceberg REST spec), so a
// cached response never hands out expired vended credentials.
func credentialExpiry(body []byte) (time.Time, bool) {
	var doc struct {
		Config             map[string]any `json:"config"`
		StorageCredentials []struct {
			Config map[string]any `json:"config"`
		} `json:"storage-credentials"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return time.Time{}, false
	}
	var earliest time.Time
	check := func(m map[string]any) {
		for k, v := range m {
			if !strings.HasSuffix(strings.ToLower(k), "expires-at-ms") {
				continue
			}
			var ms int64
			switch t := v.(type) {
			case string:
				ms, _ = strconv.ParseInt(t, 10, 64)
			case float64:
				ms = int64(t)
			}
			if ms > 0 {
				if exp := time.UnixMilli(ms); earliest.IsZero() || exp.Before(earliest) {
					earliest = exp
				}
			}
		}
	}
	check(doc.Config)
	for _, c := range doc.StorageCredentials {
		check(c.Config)
	}
	return earliest, !earliest.IsZero()
}

// cacheKey separates callers by credentials: a local process without the
// catalog token never gets a response (and its vended credentials) cached
// for someone else.
func cacheKey(r *http.Request) string {
	h := sha256.New()
	for _, k := range []string{"Authorization", "X-Iceberg-Access-Delegation", "Accept"} {
		h.Write([]byte(k + "=" + r.Header.Get(k) + "\n"))
	}
	return r.URL.RequestURI() + "#" + hex.EncodeToString(h.Sum(nil))
}

func writeEntry(w http.ResponseWriter, e entry) {
	copyHeader(w.Header(), e.header)
	w.WriteHeader(http.StatusOK)
	w.Write(e.body)
}

func copyHeader(dst, src http.Header) {
	for k, vs := range src {
		dst[k] = append([]string(nil), vs...)
	}
}
