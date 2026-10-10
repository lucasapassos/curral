//go:build linux

package docs

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Isolate the process-wide file size limit from the rest of the test suite.
func TestWriteFailurePreservesDocument(t *testing.T) {
	if os.Getenv("CURRAL_TEST_WRITE_FAILURE") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWriteFailurePreservesDocument$", "-test.v")
		cmd.Env = append(os.Environ(), "CURRAL_TEST_WRITE_FAILURE=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("subprocess: %v\n%s", err, out)
		}
		return
	}
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, tag, err := s.Create(sample("original"), "ana", nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(s.path(d.ID))
	if err != nil {
		t.Fatal(err)
	}
	var prev syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &prev); err != nil {
		t.Fatal(err)
	}
	limit := prev
	limit.Cur = 100
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	_, _, saveErr := s.Replace(d.ID, sample("replacement"), "bia", tag, nil)
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &prev); err != nil {
		t.Fatal(err)
	}
	if saveErr == nil {
		t.Error("partial write reported success")
	}
	after, err := os.ReadFile(s.path(d.ID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("failed write replaced the original file")
	}
	got, gotTag, err := s.Get(d.ID)
	if err != nil || got.Header.Title != d.Header.Title || gotTag != tag {
		t.Errorf("failed write changed index: %+v %s %v", got, gotTag, err)
	}
	files, err := os.ReadDir(s.Dir())
	if err != nil || len(files) != 1 {
		t.Errorf("temporary files left behind: %v %v", files, err)
	}
}

func TestReloadSerializesWithWrites(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d, tag, err := s.Create(sample("before"), "ana", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Glob sorts this FIFO after the document. It pauses reload after reading
	// the old version, before committing its snapshot to memory.
	fifo := filepath.Join(s.Dir(), "zzzzzzzz.json")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.Reload() }()
	var fd int
	deadline := time.Now().Add(5 * time.Second)
	for {
		fd, err = syscall.Open(fifo, syscall.O_WRONLY|syscall.O_NONBLOCK, 0600)
		if err == nil {
			break
		}
		if err != syscall.ENXIO || time.Now().After(deadline) {
			t.Fatalf("waiting for reload: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
	writer := os.NewFile(uintptr(fd), fifo)
	defer writer.Close()
	if s.mu.TryLock() {
		s.mu.Unlock()
		t.Error("reload does not hold the write lock while reading files")
	}
	updated := make(chan error, 1)
	go func() { _, _, err := s.Replace(d.ID, sample("after"), "bia", tag, nil); updated <- err }()
	b, err := json.Marshal(sample("barrier"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(b); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-updated; err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Get(d.ID)
	if err != nil || got.Header.Title != "after" {
		t.Fatalf("update lost after reload: %+v %v", got, err)
	}
	disk, err := os.ReadFile(s.path(d.ID))
	if err != nil {
		t.Fatal(err)
	}
	var persisted Doc
	if err := json.Unmarshal(disk, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Header.Title != got.Header.Title {
		t.Fatal("disk and index disagree")
	}
}
