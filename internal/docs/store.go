package docs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotFound = errors.New("document not found")
	// ErrPrecondition means If-Match named a version that is no longer current.
	ErrPrecondition = errors.New("document changed since it was read (If-Match does not match)")
)

var idRE = regexp.MustCompile(`^[a-z0-9]{8,64}$`)

// ValidID reports whether id can name a document file.
func ValidID(id string) bool { return idRE.MatchString(id) }

type entry struct {
	doc   Doc
	etag  string
	terms terms // for Search
}

// Store keeps every document in memory and one file per document,
// <dir>/<id>.json, written atomically. Writes are serialized.
type Store struct {
	dir string
	mu  sync.RWMutex
	ids map[string]entry
	now func() time.Time
}

// Open loads every document in dir, creating the directory if needed. A file
// that cannot be read or parsed is an error.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("docs: no directory given")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("docs: %w", err)
	}
	s := &Store{dir: dir, now: time.Now}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir is the directory the documents live in.
func (s *Store) Dir() string { return s.dir }

// Reload re-reads the directory, picking up files edited by hand. On error
// the documents already loaded stay in effect.
func (s *Store) Reload() error {
	// Keep the disk snapshot and index swap serialized with API writes.
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := filepath.Glob(filepath.Join(s.dir, "*.json"))
	if err != nil {
		return fmt.Errorf("docs: %w", err)
	}
	ids := make(map[string]entry, len(files))
	for _, path := range files {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		if !ValidID(id) {
			return fmt.Errorf("docs: %s: file name must be <id>.json with an id of 8-64 lowercase letters or digits", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("docs: %w", err)
		}
		var d Doc
		if err := json.Unmarshal(b, &d); err != nil {
			return fmt.Errorf("docs: %s: %w", path, err)
		}
		if err := d.normalize(); err != nil {
			return fmt.Errorf("docs: %s: %w", path, err)
		}
		d.ID = id
		ids[id] = entry{d, etag(b), docTerms(d)}
	}
	s.ids = ids
	return nil
}

// Len is the number of documents.
func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.ids)
}

// Get returns a document and its ETag.
func (s *Store) Get(id string) (Doc, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.ids[id]
	if !ok {
		return Doc{}, "", ErrNotFound
	}
	return e.doc, e.etag, nil
}

// List returns the documents matching f, most recently updated first.
func (s *Store) List(f Filter) []Doc {
	out, _ := s.ListTagged(f)
	return out
}

// ListTagged is List with each document's ETag, in the same order.
func (s *Store) ListTagged(f Filter) ([]Doc, []string) {
	s.mu.RLock()
	hits := make([]entry, 0, len(s.ids))
	for _, e := range s.ids {
		if e.doc.Matches(f) {
			hits = append(hits, e)
		}
	}
	s.mu.RUnlock()
	slices.SortFunc(hits, func(a, b entry) int {
		if c := b.doc.Header.UpdatedAt.Compare(a.doc.Header.UpdatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.doc.ID, b.doc.ID)
	})
	out, tags := make([]Doc, len(hits)), make([]string, len(hits))
	for i, e := range hits {
		out[i], tags[i] = e.doc, e.etag
	}
	return out, tags
}

// Count returns, for each qualified table name in tables, how many
// documents passing allow (every one when nil) are about it: a document
// counts when one of its tables names it exactly or by its last parts, as
// in Filter, and once however many of its names fit. Keys are the names as
// given.
func (s *Store) Count(tables []string, allow func(Doc) bool) map[string]int {
	bySuffix := map[string][]string{}
	for _, t := range tables {
		index(bySuffix, strings.ToLower(t))
	}
	out := make(map[string]int, len(tables))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.ids {
		if allow != nil && !allow(e.doc) {
			continue
		}
		seen := map[string]bool{}
		for _, n := range e.doc.Context.Tables {
			for _, t := range bySuffix[strings.ToLower(strings.TrimSpace(n))] {
				if !seen[t] {
					seen[t] = true
					out[t]++
				}
			}
		}
	}
	// Keys as given: index lowercased them.
	if len(out) > 0 {
		named := make(map[string]int, len(out))
		for _, t := range tables {
			if n := out[strings.ToLower(t)]; n > 0 {
				named[t] = n
			}
		}
		out = named
	}
	return out
}

// Check vets a write just before it is saved: old is the current document
// (nil on create), next the one about to be saved (nil on delete). An error
// cancels the write and is returned as is. A check may rewrite next's
// tables and schemas (to qualified names); what it leaves is saved.
type Check func(old, next *Doc) error

// Create stores a new document written by user.
func (s *Store) Create(in Doc, user string, check Check) (Doc, string, error) {
	if err := in.normalize(); err != nil {
		return Doc{}, "", err
	}
	now := s.now().UTC()
	d := Doc{ID: newID(now), Header: in.Header, Context: in.Context}
	d.Header.Author, d.Header.CreatedAt, d.Header.UpdatedAt, d.Header.UpdatedBy = user, now, now, ""
	if check != nil {
		if err := check(nil, &d); err != nil {
			return Doc{}, "", err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(d)
}

// Replace overwrites the writer's fields of a document. ifMatch, when not
// empty, must be its current ETag (or "*").
func (s *Store) Replace(id string, in Doc, user, ifMatch string, check Check) (Doc, string, error) {
	return s.update(id, user, ifMatch, check, func(Doc) (Doc, error) { return in, nil })
}

// Patch applies an RFC 7396 JSON merge patch to the writer's fields.
func (s *Store) Patch(id string, patch []byte, user, ifMatch string, check Check) (Doc, string, error) {
	var p any
	if err := json.Unmarshal(patch, &p); err != nil {
		return Doc{}, "", invalid("invalid merge patch: %v", err)
	}
	if _, ok := p.(map[string]any); !ok {
		return Doc{}, "", invalid("merge patch must be a JSON object")
	}
	return s.update(id, user, ifMatch, check, func(cur Doc) (Doc, error) {
		b, err := json.Marshal(mergePatch(cur.userFields(), p))
		if err != nil {
			return Doc{}, err
		}
		return Decode(b)
	})
}

func (s *Store) update(id, user, ifMatch string, check Check, change func(Doc) (Doc, error)) (Doc, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ids[id]
	if !ok {
		return Doc{}, "", ErrNotFound
	}
	if !ETagMatches(ifMatch, e.etag) {
		return Doc{}, "", ErrPrecondition
	}
	in, err := change(e.doc)
	if err != nil {
		return Doc{}, "", err
	}
	if err := in.normalize(); err != nil {
		return Doc{}, "", err
	}
	d := Doc{ID: id, Header: in.Header, Context: in.Context}
	d.Header.Author, d.Header.CreatedAt = e.doc.Header.Author, e.doc.Header.CreatedAt
	d.Header.UpdatedAt, d.Header.UpdatedBy = s.now().UTC(), user
	if check != nil {
		if err := check(&e.doc, &d); err != nil {
			return Doc{}, "", err
		}
	}
	return s.write(d)
}

// Delete removes a document.
func (s *Store) Delete(id, ifMatch string, check Check) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.ids[id]
	if !ok {
		return ErrNotFound
	}
	if !ETagMatches(ifMatch, e.etag) {
		return ErrPrecondition
	}
	if check != nil {
		if err := check(&e.doc, nil); err != nil {
			return err
		}
	}
	if err := os.Remove(s.path(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("docs: %w", err)
	}
	delete(s.ids, id)
	return nil
}

// write saves d (temp file, fsync, rename) and indexes it. s.mu must be held.
func (s *Store) write(d Doc) (Doc, string, error) {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return Doc{}, "", err
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(s.dir, "."+d.ID+".*.tmp")
	if err != nil {
		return Doc{}, "", fmt.Errorf("docs: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after the rename
	if err = tmp.Chmod(0o640); err == nil {
		if _, err = tmp.Write(b); err == nil {
			err = tmp.Sync()
		}
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), s.path(d.ID))
	}
	if err != nil {
		return Doc{}, "", fmt.Errorf("docs: %w", err)
	}
	if dir, err := os.Open(s.dir); err == nil {
		dir.Sync() // persist the rename; best effort
		dir.Close()
	}
	tag := etag(b)
	s.ids[d.ID] = entry{d, tag, docTerms(d)}
	return d, tag, nil
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

// ETagMatches reports whether an If-Match (or If-None-Match) header names
// tag: no header and "*" match anything, otherwise one of the listed tags,
// weak or not, must be it.
func ETagMatches(ifMatch, tag string) bool {
	if ifMatch == "" || ifMatch == "*" {
		return true
	}
	for c := range strings.SplitSeq(ifMatch, ",") {
		if strings.TrimPrefix(strings.TrimSpace(c), "W/") == tag {
			return true
		}
	}
	return false
}

func etag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// newID is time-ordered (milliseconds) plus 64 random bits.
func newID(now time.Time) string {
	var b [8]byte
	rand.Read(b[:])
	return fmt.Sprintf("%011x%s", now.UnixMilli(), hex.EncodeToString(b[:]))
}
