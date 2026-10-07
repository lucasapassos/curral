package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParamFlag(t *testing.T) {
	var p paramFlag
	for _, v := range []string{"42", "1.5", "true", "null", `"quoted"`, "plain text"} {
		if err := p.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := json.Marshal([]any(p))
	if string(b) != `[42,1.5,true,null,"quoted","plain text"]` {
		t.Fatalf("%s", b)
	}
	if err := p.Set(`[1,2]`); err == nil {
		t.Fatal("array accepted")
	}
}

func TestRunQuery(t *testing.T) {
	var got map[string]any
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		switch got["sql"] {
		case "DENY":
			w.Header().Set("X-Request-Id", "rid-1")
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
		case "CUT":
			w.Header().Set("Trailer", "X-Curral-Error, X-Curral-Row-Count")
			w.Write([]byte("a\n1\n"))
			w.Header().Set("X-Curral-Row-Count", "1")
			w.Header().Set("X-Curral-Error", "row limit reached")
		default:
			w.Write([]byte("a\n1\n"))
		}
	}))
	defer srv.Close()
	t.Setenv("CURRAL_URL", srv.URL)
	t.Setenv("CURRAL_TOKEN", "curral_ABC\n")
	out := filepath.Join(t.TempDir(), "out.csv")

	if err := runQuery([]string{"-o", out, "-p", "7", "-d", "sales", "SELECT", "1"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); string(b) != "a\n1\n" {
		t.Fatalf("output %q", b)
	}
	if auth != "Bearer curral_ABC" || got["sql"] != "SELECT 1" || got["database"] != "sales" ||
		got["format"] != "csv" || got["params"].([]any)[0] != float64(7) {
		t.Fatalf("request: auth=%q body=%v", auth, got)
	}
	if err := runQuery([]string{"-o", out, "DENY"}); err == nil || !strings.Contains(err.Error(), "403") ||
		!strings.Contains(err.Error(), "rid-1") || !strings.Contains(err.Error(), "forbidden") {
		t.Fatalf("403: %v", err)
	}
	if err := runQuery([]string{"-o", out, "CUT"}); err == nil || !strings.Contains(err.Error(), "row limit reached") {
		t.Fatalf("trailer error not reported: %v", err)
	}
	t.Setenv("CURRAL_TOKEN", "")
	t.Setenv("CURRAL_USER", "")
	if err := runQuery([]string{"SELECT 1"}); err == nil || !strings.Contains(err.Error(), "no credentials") {
		t.Fatalf("no credentials: %v", err)
	}
}
