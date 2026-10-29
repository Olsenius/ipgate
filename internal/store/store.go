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

// Store is a concurrency-safe allowlist backed by a JSON file.
type Store struct {
	path string
	now  func() time.Time

	mu      sync.RWMutex
	entries map[netip.Prefix]Entry
}

// Open loads the allowlist from path. A missing file yields an empty store; a corrupt
// file is an error. Expired entries are dropped at load.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{path: path, now: now, entries: make(map[netip.Prefix]Entry)}
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
		if err := s.writeLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
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

// Lookup reports whether a is covered by an unexpired entry. It does no I/O.
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

// Put adds or refreshes the entry for e.IP (taking ownership) and persists the change.
func (s *Store) Put(e Entry) error {
	e.IP = e.IP.Unmap().WithZone("")
	if err := Validate(e); err != nil {
		return err
	}
	k := Key(e.IP)
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.entries[k]
	s.entries[k] = e
	if err := s.writeLocked(); err != nil {
		if had {
			s.entries[k] = old
		} else {
			delete(s.entries, k)
		}
		return err
	}
	return nil
}

// RemoveIf deletes the entry covering a if allow returns true for it. found reports
// whether an (unexpired) entry existed; removed whether it was deleted.
func (s *Store) RemoveIf(a netip.Addr, allow func(Entry) bool) (e Entry, found, removed bool, err error) {
	k := Key(a)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[k]
	if !ok || !e.ExpiresAt.After(s.now()) {
		return Entry{}, false, false, nil
	}
	if !allow(e) {
		return e, true, false, nil
	}
	delete(s.entries, k)
	if err := s.writeLocked(); err != nil {
		s.entries[k] = e
		return e, true, false, err
	}
	return e, true, true, nil
}

// List returns unexpired entries, soonest expiry last, filtered by keep (nil = all).
func (s *Store) List(keep func(Entry) bool) []Entry {
	t := s.now()
	s.mu.RLock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if e.ExpiresAt.After(t) && (keep == nil || keep(e)) {
			out = append(out, e)
		}
	}
	s.mu.RUnlock()
	sortEntries(out)
	return out
}

// Prune removes expired entries and persists if anything changed.
func (s *Store) Prune() (int, error) {
	t := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := map[netip.Prefix]Entry{}
	for k, e := range s.entries {
		if !e.ExpiresAt.After(t) {
			removed[k] = e
			delete(s.entries, k)
		}
	}
	if len(removed) == 0 {
		return 0, nil
	}
	if err := s.writeLocked(); err != nil {
		for k, e := range removed {
			s.entries[k] = e
		}
		return 0, err
	}
	return len(removed), nil
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

// writeLocked atomically writes the allowlist: temp file in the same directory,
// fsync, rename, fsync directory. Caller holds s.mu.
func (s *Store) writeLocked() error {
	list := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		list = append(list, e)
	}
	sortEntries(list)
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, ".allowlist-*.tmp")
	if err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("write allowlist: %w", err)
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
