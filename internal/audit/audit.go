// Package audit writes one JSON line per request decision to a dedicated
// sink (a file or stdout), separate from operational logs.
//
// Writes are asynchronous so disk latency stays off the query path. Queries
// fail closed: before anything executes the server reserves a slot, which
// fails while the sink is unhealthy or the queue is full, so no query runs
// without room to record it. Events for requests that execute nothing
// (denials, auth failures) are best-effort.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Event is one audit record. Fields are stable: consumers parse them.
type Event struct {
	TS            time.Time          `json:"ts"`
	Event         string             `json:"event"` // query, auth_failure
	RequestID     string             `json:"request_id"`
	User          string             `json:"user"`
	Roles         []string           `json:"roles,omitempty"`
	RemoteAddr    string             `json:"remote_addr"`
	ForwardedFor  string             `json:"forwarded_for,omitempty"`
	Database      string             `json:"database,omitempty"`
	StatementType string             `json:"statement_type,omitempty"`
	SQL           string             `json:"sql,omitempty"`
	SQLSHA256     string             `json:"sql_sha256,omitempty"`
	ParamsCount   int                `json:"params_count"`
	Tables        []string           `json:"tables,omitempty"`
	Targets       []string           `json:"targets,omitempty"`
	Functions     []string           `json:"functions,omitempty"`
	Resolved      *bool              `json:"resolved,omitempty"`
	Decision      string             `json:"decision"`   // allow, deny, error
	DecidedBy     string             `json:"decided_by"` // policy, engine, auth, queue, audit, request
	PolicySHA256  string             `json:"policy_sha256,omitempty"`
	Status        int                `json:"status"`
	Rows          int64              `json:"rows"`
	Bytes         int64              `json:"bytes"`
	TimingMS      map[string]float64 `json:"timing_ms,omitempty"`
	Error         string             `json:"error,omitempty"`
	Version       string             `json:"curral_version"`
}

var (
	ErrUnavailable = errors.New("audit log unavailable")
	ErrQueueFull   = errors.New("audit queue full")
)

// Writer serializes events to the sink in the background.
type Writer struct {
	path    string // "-" for stdout; read under mu
	name    string // path at Open, for logs
	log     *slog.Logger
	ch      chan []byte
	slots   chan struct{} // one per event queued or reserved
	done    chan struct{}
	closing sync.Once

	mu   sync.Mutex // guards f and bw
	f    *os.File
	bw   *bufio.Writer
	out  io.Writer
	fail atomic.Pointer[error]

	Written, Dropped atomic.Int64
}

// Open starts a writer for path ("-" = stdout) with room for queue events.
func Open(path string, queue int, log *slog.Logger) (*Writer, error) {
	if queue < 1 {
		queue = 1
	}
	w := &Writer{
		path:  path,
		name:  path,
		log:   log,
		ch:    make(chan []byte, queue),
		slots: make(chan struct{}, queue),
		done:  make(chan struct{}),
	}
	if err := w.open(); err != nil {
		return nil, err
	}
	go w.loop()
	go w.recover()
	return w, nil
}

func (w *Writer) open() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.path == "-" {
		w.bw = bufio.NewWriterSize(os.Stdout, 64<<10)
		return nil
	}
	f, err := os.OpenFile(w.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if w.f != nil {
		w.bw.Flush()
		w.f.Close()
	}
	w.f = f
	w.bw = bufio.NewWriterSize(f, 64<<10)
	return nil
}

// Reopen reopens the sink (e.g. after logrotate moved the file) and proves
// it writable by recording an audit_reopened event; only then is a previous
// failure cleared.
func (w *Writer) Reopen() error { return w.reopenAndProbe("audit_reopened") }

func (w *Writer) setPath(p string) {
	w.mu.Lock()
	w.path = p
	w.mu.Unlock()
}

func (w *Writer) reopenAndProbe(event string) error {
	if err := w.open(); err != nil {
		w.setFail(err)
		return err
	}
	line, _ := json.Marshal(&Event{TS: time.Now().UTC(), Event: event})
	w.mu.Lock()
	_, err := w.bw.Write(append(line, '\n'))
	if err == nil {
		err = w.bw.Flush()
	}
	w.mu.Unlock()
	if err != nil {
		w.setFail(err)
		return err
	}
	if w.fail.Swap(nil) != nil {
		w.log.Info("audit log recovered", "path", w.name)
	}
	return nil
}

// Healthy returns the last write error, if the sink is failing.
func (w *Writer) Healthy() error {
	if p := w.fail.Load(); p != nil {
		return *p
	}
	return nil
}

func (w *Writer) setFail(err error) {
	if w.fail.Swap(&err) == nil {
		w.log.Error("audit log write failed; queries are rejected until it recovers", "path", w.name, "err", err)
	}
}

// Reservation is a queue slot held for one event.
type Reservation struct {
	w    *Writer
	used atomic.Bool
}

// Reserve claims room for one event, waiting up to wait for a free slot.
// It fails while the sink is unhealthy.
func (w *Writer) Reserve(wait time.Duration) (*Reservation, error) {
	if err := w.Healthy(); err != nil {
		return nil, ErrUnavailable
	}
	select {
	case w.slots <- struct{}{}:
		return &Reservation{w: w}, nil
	default:
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case w.slots <- struct{}{}:
		return &Reservation{w: w}, nil
	case <-t.C:
		return nil, ErrQueueFull
	}
}

// Write queues ev using the reservation. It never blocks.
func (r *Reservation) Write(ev *Event) {
	if !r.used.CompareAndSwap(false, true) {
		return
	}
	b, err := json.Marshal(ev)
	if err != nil {
		<-r.w.slots
		r.w.log.Error("audit event marshal failed", "err", err)
		return
	}
	r.w.ch <- append(b, '\n') // a slot is held, so ch has room
}

// Release frees an unused reservation.
func (r *Reservation) Release() {
	if r.used.CompareAndSwap(false, true) {
		<-r.w.slots
	}
}

// Record writes ev if there is room right now; otherwise it is dropped and
// counted. For events whose request executed nothing.
func (w *Writer) Record(ev *Event) {
	r, err := w.Reserve(0)
	if err != nil {
		w.Dropped.Add(1)
		w.log.Warn("audit event dropped", "event", ev.Event, "request_id", ev.RequestID, "err", err)
		return
	}
	r.Write(ev)
}

func (w *Writer) loop() {
	defer close(w.done)
	for b := range w.ch {
		w.mu.Lock()
		_, err := w.bw.Write(b)
		if err == nil && len(w.ch) == 0 {
			err = w.bw.Flush() // batch: flush once the queue drains
		}
		w.mu.Unlock()
		<-w.slots
		if err != nil {
			w.Dropped.Add(1)
			w.setFail(err)
			continue
		}
		w.Written.Add(1)
	}
	w.mu.Lock()
	if err := w.bw.Flush(); err != nil {
		w.setFail(err)
	}
	if w.f != nil {
		w.f.Close()
	}
	w.mu.Unlock()
}

// recover periodically retries a failing sink.
func (w *Writer) recover() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-t.C:
			if w.Healthy() != nil {
				w.reopenAndProbe("audit_recovered")
			}
		}
	}
}

// Close drains the queue and closes the sink.
func (w *Writer) Close() error {
	w.closing.Do(func() { close(w.ch) })
	<-w.done
	return w.Healthy()
}
