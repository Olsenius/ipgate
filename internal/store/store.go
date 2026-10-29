// Package store holds the IP allowlist in memory and persists it to a JSON file.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

// Entry is one allowlisted address.
type Entry struct {
	IP        netip.Addr `json:"ip"`
	Sub       string     `json:"sub"`
	User      string     `json:"user"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UserAgent string     `json:"user_agent"`
}

// Key returns the prefix an address is matched on: the exact address for IPv4,
// the /64 for IPv6 (privacy addresses rotate inside a /64).
func Key(a netip.Addr) netip.Prefix {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

// ErrNotDurable means a change was written and renamed into place (it is visible
// on disk and in memory) but syncing the directory failed, so it may not survive
// a crash. Callers should report and log it; the change itself is in effect.
var ErrNotDurable = errors.New("allowlist change applied but not confirmed durable")

// fileOps are the filesystem steps of a write, replaceable in tests to inject faults.
type fileOps struct {
	createTemp func(dir, pattern string) (*os.File, error)
	write      func(f *os.File, b []byte) error
	syncFile   func(f *os.File) error
	rename     func(oldpath, newpath string) error
	syncDir    func(dir string) error
}

var osOps = fileOps{
	createTemp: os.CreateTemp,
	write:      func(f *os.File, b []byte) error { _, err := f.Write(b); return err },
	syncFile:   (*os.File).Sync,
	rename:     os.Rename,
	syncDir: func(dir string) error {
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		if err := d.Sync(); err != nil {
			d.Close()
			return err
		}
		return d.Close()
	},
}

// Store is a concurrency-safe allowlist backed by a JSON file.
//
// Readers (Lookup, List) never wait for disk I/O: mutations are serialized by
// wmu, build a new map, write it to disk without holding mu, and only then
// publish it with a brief exclusive lock. Published maps are never modified.
type Store struct {
	path string
	now  func() time.Time
	ops  fileOps

	wmu     sync.Mutex   // serializes mutations and file writes
	mu      sync.RWMutex // guards the entries pointer only
	entries map[netip.Prefix]Entry
}

// Open loads the allowlist from path. A missing file yields an empty store; a
// corrupt or malformed file is an error and is left untouched. Expired entries are
// dropped at load. The directory must exist and be writable.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{path: path, now: now, ops: osOps, entries: map[netip.Prefix]Entry{}}
	if err := checkDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read allowlist: %w", err)
	}
	list, err := decode(b)
	if err != nil {
		return nil, fmt.Errorf("allowlist %s is corrupt (fix or remove it; ipgate will not overwrite it): %w", path, err)
	}
	// Every record has been validated above, before anything is pruned or written.
	t := now()
	pruned := false
	for _, e := range list {
		if !e.ExpiresAt.After(t) {
			pruned = true
			continue
		}
		s.entries[Key(e.IP)] = e
	}
	if pruned {
		if err := s.persist(s.entries); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// checkDir verifies that dir exists, is a directory and is writable, so that a
// misconfigured DATA_DIR fails at startup instead of on the first allow.
func checkDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("data directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("data directory %s is not a directory", dir)
	}
	f, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return fmt.Errorf("data directory %s is not writable: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("data directory %s: %w", dir, err)
	}
	return nil
}

// decode parses and validates the whole file: a JSON array of complete entries,
// no unknown fields, no trailing data, at most one entry per match key.
func decode(b []byte) ([]Entry, error) {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errors.New("not a JSON array")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var list []Entry
	if err := dec.Decode(&list); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON array")
	}
	seen := make(map[netip.Prefix]int, len(list))
	for i := range list {
		e := &list[i]
		e.IP = e.IP.Unmap().WithZone("")
		if err := Validate(*e); err != nil {
			return nil, fmt.Errorf("entry %d: %w", i, err)
		}
		k := Key(e.IP)
		if j, dup := seen[k]; dup {
			return nil, fmt.Errorf("entries %d and %d both cover %s", j, i, k)
		}
		seen[k] = i
	}
	return list, nil
}

// Validate checks that an entry is complete and consistent. The same rules apply
// when loading and when adding, so ipgate never writes a file it would refuse to load.
func Validate(e Entry) error {
	switch {
	case !e.IP.IsValid():
		return errors.New("missing or invalid ip")
	case e.Sub == "":
		return errors.New("missing sub")
	case e.User == "":
		return errors.New("missing user")
	case e.CreatedAt.IsZero():
		return errors.New("missing created_at")
	case e.ExpiresAt.IsZero():
		return errors.New("missing expires_at")
	case !e.ExpiresAt.After(e.CreatedAt):
		return errors.New("expires_at is not after created_at")
	}
	return nil
}

// snapshot returns the current published map. It must not be modified.
func (s *Store) snapshot() map[netip.Prefix]Entry {
	s.mu.RLock()
	m := s.entries
	s.mu.RUnlock()
	return m
}

// Lookup reports whether a is covered by an unexpired entry. It does no I/O and
// never waits for a write in progress.
func (s *Store) Lookup(a netip.Addr) (Entry, bool) {
	k := Key(a)
	s.mu.RLock()
	e, ok := s.entries[k]
	s.mu.RUnlock()
	if !ok || !e.ExpiresAt.After(s.now()) {
		return Entry{}, false
	}
	return e, true
}

// commit writes next to disk and publishes it. Caller holds wmu. If the write
// fails before the rename, nothing changed and the old map stays published. If
// only the directory sync fails, the new file is in place, so next is published
// (memory matches disk) and the ErrNotDurable error is returned.
func (s *Store) commit(next map[netip.Prefix]Entry) error {
	err := s.persist(next)
	if err != nil && !errors.Is(err, ErrNotDurable) {
		return err
	}
	s.mu.Lock()
	s.entries = next
	s.mu.Unlock()
	return err
}

// Put adds or refreshes the entry for e.IP (taking ownership) and persists the
// change. A returned ErrNotDurable means the entry is active but may not survive
// a crash.
func (s *Store) Put(e Entry) error {
	e.IP = e.IP.Unmap().WithZone("")
	if err := Validate(e); err != nil {
		return err
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	next := maps.Clone(s.snapshot())
	next[Key(e.IP)] = e
	return s.commit(next)
}

// RemoveIf deletes the entry covering a if allow returns true for it. found reports
// whether an (unexpired) entry existed; removed whether the removal is in effect
// (it is also in effect when err is ErrNotDurable).
func (s *Store) RemoveIf(a netip.Addr, allow func(Entry) bool) (e Entry, found, removed bool, err error) {
	k := Key(a)
	s.wmu.Lock()
	defer s.wmu.Unlock()
	cur := s.snapshot()
	e, ok := cur[k]
	if !ok || !e.ExpiresAt.After(s.now()) {
		return Entry{}, false, false, nil
	}
	if !allow(e) {
		return e, true, false, nil
	}
	next := maps.Clone(cur)
	delete(next, k)
	if err := s.commit(next); err != nil {
		return e, true, errors.Is(err, ErrNotDurable), err
	}
	return e, true, true, nil
}

// List returns unexpired entries, latest expiry first, filtered by keep (nil = all).
func (s *Store) List(keep func(Entry) bool) []Entry {
	t := s.now()
	m := s.snapshot()
	out := make([]Entry, 0, len(m))
	for _, e := range m {
		if e.ExpiresAt.After(t) && (keep == nil || keep(e)) {
			out = append(out, e)
		}
	}
	sortEntries(out)
	return out
}

// Prune removes expired entries and persists if anything changed. The count is
// also returned with ErrNotDurable (the removal is in effect).
func (s *Store) Prune() (int, error) {
	t := s.now()
	s.wmu.Lock()
	defer s.wmu.Unlock()
	cur := s.snapshot()
	next := make(map[netip.Prefix]Entry, len(cur))
	for k, e := range cur {
		if e.ExpiresAt.After(t) {
			next[k] = e
		}
	}
	n := len(cur) - len(next)
	if n == 0 {
		return 0, nil
	}
	if err := s.commit(next); err != nil {
		if errors.Is(err, ErrNotDurable) {
			return n, err
		}
		return 0, err
	}
	return n, nil
}

// RunPruner calls Prune every interval until ctx is done.
func (s *Store) RunPruner(ctx context.Context, interval time.Duration, onResult func(int, error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := s.Prune()
			if onResult != nil {
				onResult(n, err)
			}
		}
	}
}

func sortEntries(es []Entry) {
	slices.SortFunc(es, func(a, b Entry) int {
		if c := b.ExpiresAt.Compare(a.ExpiresAt); c != 0 {
			return c
		}
		return a.IP.Compare(b.IP)
	})
}

// persist atomically replaces the file with entries: temp file in the same
// directory, write, fsync, rename, fsync directory. Errors before the rename leave
// the old file in place. A failed directory sync is wrapped in ErrNotDurable.
func (s *Store) persist(entries map[netip.Prefix]Entry) error {
	list := make([]Entry, 0, len(entries))
	for _, e := range entries {
		list = append(list, e)
	}
	sortEntries(list)
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(s.path)
	f, err := s.ops.createTemp(dir, ".allowlist-*.tmp")
	if err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	tmp := f.Name()
	renamed := false
	defer func() {
		if !renamed {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	if err := s.ops.write(f, b); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	if err := s.ops.syncFile(f); err != nil {
		return fmt.Errorf("write allowlist: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	if err := s.ops.rename(tmp, s.path); err != nil {
		return fmt.Errorf("write allowlist: rename: %w", err)
	}
	renamed = true
	if err := s.ops.syncDir(dir); err != nil {
		return fmt.Errorf("%w: directory fsync: %v", ErrNotDurable, err)
	}
	return nil
}

// SetDirSyncForTest replaces the directory-sync step so other packages' tests can
// simulate ErrNotDurable. Not for production use.
func (s *Store) SetDirSyncForTest(f func(dir string) error) {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	s.ops.syncDir = f
}
