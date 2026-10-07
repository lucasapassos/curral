package catalogcache

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func setup(t *testing.T, ttl time.Duration, handler http.HandlerFunc) (*Proxy, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		handler(w, r)
	}))
	t.Cleanup(up.Close)
	p, err := Start(up.URL+"/acct/bucket", ttl, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	return p, &calls
}

func get(t *testing.T, url, auth string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func echo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Authorization"))
}

func TestCachesGETs(t *testing.T) {
	p, calls := setup(t, time.Minute, echo)
	url := p.URL() + "/v1/ns/tables/t?x=1"
	for range 3 {
		code, body := get(t, url, "Bearer a")
		if code != 200 || body != "GET /acct/bucket/v1/ns/tables/t?x=1 Bearer a" {
			t.Fatalf("%d %q", code, body)
		}
	}
	if calls.Load() != 1 || p.Hits.Load() != 2 {
		t.Fatalf("calls=%d hits=%d", calls.Load(), p.Hits.Load())
	}
	// Different credentials never share an entry.
	if _, body := get(t, url, ""); strings.Contains(body, "Bearer a") || calls.Load() != 2 {
		t.Fatalf("cache shared across credentials: %q", body)
	}
}

func TestTTLExpiry(t *testing.T) {
	p, calls := setup(t, 30*time.Millisecond, echo)
	get(t, p.URL()+"/v1/t", "a")
	time.Sleep(50 * time.Millisecond)
	get(t, p.URL()+"/v1/t", "a")
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestWritesInvalidate(t *testing.T) {
	p, calls := setup(t, time.Minute, echo)
	get(t, p.URL()+"/v1/t", "a")
	resp, err := http.Post(p.URL()+"/v1/t", "application/json", strings.NewReader(`{"commit":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(b), "POST /acct/bucket/v1/t") {
		t.Fatalf("post: %q", b)
	}
	get(t, p.URL()+"/v1/t", "a")
	if calls.Load() != 3 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestErrorsNotCached(t *testing.T) {
	p, calls := setup(t, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	})
	for range 2 {
		if code, _ := get(t, p.URL()+"/v1/missing", "a"); code != 404 {
			t.Fatal(code)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestCollapsesConcurrentMisses(t *testing.T) {
	p, calls := setup(t, time.Minute, func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		echo(w, r)
	})
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() { get(t, p.URL()+"/v1/t", "a") })
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestRejectsPathsOutsideEndpoint(t *testing.T) {
	p, calls := setup(t, time.Minute, echo)
	base := strings.TrimSuffix(p.URL(), "/acct/bucket")
	if code, _ := get(t, base+"/other/v1/t", "a"); code != 404 || calls.Load() != 0 {
		t.Fatalf("code=%d calls=%d", code, calls.Load())
	}
}

func TestCredentialExpiryCapsTTL(t *testing.T) {
	soon := time.Now().Add(time.Minute + 200*time.Millisecond).UnixMilli()
	p, calls := setup(t, time.Hour, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"config":{"s3.session-token-expires-at-ms":"%d"}}`, soon)
	})
	get(t, p.URL()+"/v1/t", "a")
	get(t, p.URL()+"/v1/t", "a")
	if calls.Load() != 1 {
		t.Fatalf("calls=%d", calls.Load())
	}
	time.Sleep(300 * time.Millisecond) // past expiry minus the 1 minute margin
	get(t, p.URL()+"/v1/t", "a")
	if calls.Load() != 2 {
		t.Fatalf("expired credentials served from cache: calls=%d", calls.Load())
	}
}

func TestCredentialExpiryParsing(t *testing.T) {
	exp, ok := credentialExpiry([]byte(`{"config":{"a":"b"},"storage-credentials":[{"config":{"s3.session-token-expires-at-ms":1700000000000}},{"config":{"x.expires-at-ms":"1600000000000"}}]}`))
	if !ok || exp.UnixMilli() != 1600000000000 {
		t.Fatalf("exp=%v ok=%v", exp, ok)
	}
	if _, ok := credentialExpiry([]byte(`{"config":{"s3.access-key-id":"k"}}`)); ok {
		t.Fatal("no expiry expected")
	}
}
