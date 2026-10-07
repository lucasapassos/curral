package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func readEvents(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var ev Event
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("invalid line %q: %v", sc.Text(), err)
		}
		out = append(out, ev)
	}
	return out
}

func TestWriteAndReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := Open(path, 8, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	r, err := w.Reserve(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	r.Write(&Event{Event: "query", User: "a", Decision: "allow", Status: 200})
	r.Write(&Event{Event: "query", User: "dup"}) // second use is ignored
	w.Record(&Event{Event: "auth_failure", User: "b", Decision: "deny"})

	// logrotate: move the file away, then reopen.
	time.Sleep(50 * time.Millisecond)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := w.Reopen(); err != nil {
		t.Fatal(err)
	}
	w.Record(&Event{Event: "query", User: "c"})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	old, cur := readEvents(t, path+".1"), readEvents(t, path)
	if len(old) != 2 || old[0].User != "a" || old[1].User != "b" {
		t.Fatalf("rotated file: %+v", old)
	}
	if len(cur) != 2 || cur[0].Event != "audit_reopened" || cur[1].User != "c" {
		t.Fatalf("new file: %+v", cur)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestQueueFull(t *testing.T) {
	w, err := Open(filepath.Join(t.TempDir(), "a.jsonl"), 1, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, err := w.Reserve(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Reserve(20 * time.Millisecond); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("err = %v", err)
	}
	w.Record(&Event{Event: "auth_failure"})
	if w.Dropped.Load() != 1 {
		t.Fatalf("dropped = %d", w.Dropped.Load())
	}
	r.Release()
	if _, err := w.Reserve(0); err != nil {
		t.Fatalf("slot not released: %v", err)
	}
}

func TestFailClosedAndRecovery(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("no /dev/full")
	}
	w, err := Open("/dev/full", 8, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	r, _ := w.Reserve(0)
	r.Write(&Event{Event: "query"})
	deadline := time.Now().Add(2 * time.Second)
	for w.Healthy() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if w.Healthy() == nil {
		t.Fatal("write to a full disk not detected")
	}
	if _, err := w.Reserve(0); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("reserve on failed sink: %v", err)
	}
	// Reopening the same full device keeps it failed...
	if err := w.Reopen(); err == nil || w.Healthy() == nil {
		t.Fatal("reopen of a full device must stay failed")
	}
	// ...a working destination recovers it.
	w.setPath(filepath.Join(t.TempDir(), "ok.jsonl"))
	if err := w.Reopen(); err != nil || w.Healthy() != nil {
		t.Fatalf("recovery: %v / %v", err, w.Healthy())
	}
	if _, err := w.Reserve(0); err != nil {
		t.Fatalf("reserve after recovery: %v", err)
	}
}
