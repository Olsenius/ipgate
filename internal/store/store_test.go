package store

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)} }

func open(t *testing.T, path string, c *clock) *Store {
	t.Helper()
	s, err := Open(path, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func entry(ip string, sub string, now time.Time, ttl time.Duration) Entry {
	return Entry{IP: netip.MustParseAddr(ip), Sub: sub, User: sub + "-name", CreatedAt: now, ExpiresAt: now.Add(ttl), UserAgent: "test"}
}

func TestAddLookupRefresh(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)

	if _, ok := s.Lookup(netip.MustParseAddr("203.0.113.5")); ok {
		t.Fatal("empty store allowed an address")
	}
	if err := s.Put(entry("203.0.113.5", "alice", c.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(netip.MustParseAddr("203.0.113.5")); !ok {
		t.Fatal("added address not allowed")
	}
	if _, ok := s.Lookup(netip.MustParseAddr("::ffff:203.0.113.5")); !ok {
		t.Fatal("IPv4-mapped form not matched")
	}
	if _, ok := s.Lookup(netip.MustParseAddr("203.0.113.6")); ok {
		t.Fatal("neighbouring IPv4 address allowed")
	}

	// Refresh by another user takes ownership and extends expiry.
	if err := s.Put(entry("203.0.113.5", "bob", c.Now(), 48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	all := s.List(nil)
	if len(all) != 1 || all[0].Sub != "bob" || !all[0].ExpiresAt.Equal(c.Now().Add(48*time.Hour)) {
		t.Fatalf("refresh did not replace entry: %+v", all)
	}
}

func TestIPv6Slash64(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	if err := s.Put(entry("2001:db8:1:2:aaaa::1", "alice", c.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(netip.MustParseAddr("2001:db8:1:2:ffff:eeee:dddd:cccc")); !ok {
		t.Error("address in same /64 not allowed")
	}
	if _, ok := s.Lookup(netip.MustParseAddr("2001:db8:1:3::1")); ok {
		t.Error("address in other /64 allowed")
	}
	// Re-allowing from another address in the same /64 refreshes the same entry.
	if err := s.Put(entry("2001:db8:1:2::99", "alice", c.Now(), 2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := len(s.List(nil)); n != 1 {
		t.Errorf("expected one entry per /64, got %d", n)
	}
}

func TestExpiry(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	ip := netip.MustParseAddr("198.51.100.1")
	s.Put(entry(ip.String(), "alice", c.Now(), time.Hour))
	c.Add(time.Hour)
	if _, ok := s.Lookup(ip); ok {
		t.Error("expired entry still allowed before pruning")
	}
	if n := len(s.List(nil)); n != 0 {
		t.Errorf("List returned %d expired entries", n)
	}
	if _, found, _, _ := s.RemoveIf(ip, func(Entry) bool { return true }); found {
		t.Error("RemoveIf found expired entry")
	}
}

func TestRemoveIf(t *testing.T) {
	c := newClock()
	path := filepath.Join(t.TempDir(), "allowlist.json")
	s := open(t, path, c)
	ip := netip.MustParseAddr("198.51.100.1")
	s.Put(entry(ip.String(), "alice", c.Now(), time.Hour))

	_, found, removed, err := s.RemoveIf(ip, func(e Entry) bool { return e.Sub == "bob" })
	if err != nil || !found || removed {
		t.Fatalf("non-owner removal: found=%v removed=%v err=%v", found, removed, err)
	}
	e, found, removed, err := s.RemoveIf(ip, func(e Entry) bool { return e.Sub == "alice" })
	if err != nil || !found || !removed || e.Sub != "alice" {
		t.Fatalf("owner removal: found=%v removed=%v err=%v", found, removed, err)
	}
	if _, ok := s.Lookup(ip); ok {
		t.Error("revoked entry still allowed")
	}
	if _, found, _, _ := s.RemoveIf(netip.MustParseAddr("192.0.2.1"), func(Entry) bool { return true }); found {
		t.Error("found nonexistent entry")
	}
	// Persisted.
	s2 := open(t, path, c)
	if len(s2.List(nil)) != 0 {
		t.Error("revocation was not persisted")
	}
}

func TestPersistReloadAndPrune(t *testing.T) {
	c := newClock()
	path := filepath.Join(t.TempDir(), "allowlist.json")
	s := open(t, path, c)
	s.Put(entry("198.51.100.1", "alice", c.Now(), time.Hour))
	s.Put(entry("198.51.100.2", "bob", c.Now(), 3*time.Hour))
	s.Put(entry("2001:db8::1", "carol", c.Now(), 3*time.Hour))

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %o, want 600", perm)
	}

	s2 := open(t, path, c)
	if got := len(s2.List(nil)); got != 3 {
		t.Fatalf("reloaded %d entries, want 3", got)
	}
	e, ok := s2.Lookup(netip.MustParseAddr("198.51.100.2"))
	if !ok || e.Sub != "bob" || e.User != "bob-name" || e.UserAgent != "test" {
		t.Errorf("reloaded entry mismatch: %+v", e)
	}

	// Expired entries are pruned at load (and the file rewritten).
	c.Add(2 * time.Hour)
	s3 := open(t, path, c)
	if got := len(s3.List(nil)); got != 2 {
		t.Fatalf("after load-prune %d entries, want 2", got)
	}
	var onDisk []Entry
	b, _ := os.ReadFile(path)
	if err := json.Unmarshal(b, &onDisk); err != nil || len(onDisk) != 2 {
		t.Fatalf("file not rewritten after load prune: %v %d", err, len(onDisk))
	}

	// Explicit prune.
	c.Add(2 * time.Hour)
	n, err := s3.Prune()
	if err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v; want 2", n, err)
	}
	if n, _ := s3.Prune(); n != 0 {
		t.Errorf("second Prune removed %d", n)
	}
	b, _ = os.ReadFile(path)
	if strings.TrimSpace(string(b)) != "[]" {
		t.Errorf("file after prune = %s", b)
	}
}

func TestFileFormat(t *testing.T) {
	c := newClock()
	path := filepath.Join(t.TempDir(), "allowlist.json")
	s := open(t, path, c)
	s.Put(entry("198.51.100.1", "alice", c.Now(), time.Hour))
	b, _ := os.ReadFile(path)
	var raw []map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ip", "sub", "user", "created_at", "expires_at", "user_agent"} {
		if _, ok := raw[0][k]; !ok {
			t.Errorf("field %q missing from %s", k, b)
		}
	}
	if raw[0]["ip"] != "198.51.100.1" {
		t.Errorf("ip = %v", raw[0]["ip"])
	}
}

func TestAtomicWriteLeavesNoTempFiles(t *testing.T) {
	c := newClock()
	dir := t.TempDir()
	s := open(t, filepath.Join(dir, "allowlist.json"), c)
	for i := range 20 {
		s.Put(entry(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}).String(), "alice", c.Now(), time.Hour))
	}
	names, _ := os.ReadDir(dir)
	if len(names) != 1 || names[0].Name() != "allowlist.json" {
		var got []string
		for _, n := range names {
			got = append(got, n.Name())
		}
		t.Errorf("directory contents = %v", got)
	}
}

func TestWriteFailureRollsBack(t *testing.T) {
	c := newClock()
	dir := t.TempDir()
	s := open(t, filepath.Join(dir, "allowlist.json"), c)
	s.Put(entry("198.51.100.1", "alice", c.Now(), time.Hour))
	// Make the directory unwritable so CreateTemp fails.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		f.Close()
		t.Skip("directory still writable (running as root?)")
	}
	if err := s.Put(entry("198.51.100.2", "bob", c.Now(), time.Hour)); err == nil {
		t.Fatal("Put succeeded despite unwritable directory")
	}
	if _, ok := s.Lookup(netip.MustParseAddr("198.51.100.2")); ok {
		t.Error("failed Put left entry in memory")
	}
	if _, _, removed, err := s.RemoveIf(netip.MustParseAddr("198.51.100.1"), func(Entry) bool { return true }); err == nil || removed {
		t.Error("RemoveIf succeeded despite unwritable directory")
	}
	if _, ok := s.Lookup(netip.MustParseAddr("198.51.100.1")); !ok {
		t.Error("failed RemoveIf dropped entry from memory")
	}
}

func TestCorruptFile(t *testing.T) {
	const ok = `"sub":"alice","user":"Alice","created_at":"2026-10-29T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"`
	for name, content := range map[string]string{
		"garbage":                "{not json",
		"empty file":             "",
		"null document":          "null",
		"object not array":       `{"ip":"1.2.3.4"}`,
		"bad ip":                 `[{"ip":"nope",` + ok + `}]`,
		"missing ip":             `[{` + ok + `}]`,
		"missing expires_at":     `[{"ip":"203.0.113.5","sub":"alice","user":"Alice","created_at":"2026-10-29T00:00:00Z"}]`,
		"missing created_at":     `[{"ip":"203.0.113.5","sub":"alice","user":"Alice","expires_at":"2030-01-01T00:00:00Z"}]`,
		"missing sub":            `[{"ip":"203.0.113.5","user":"Alice","created_at":"2026-10-29T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}]`,
		"empty sub":              `[{"ip":"203.0.113.5","sub":"","user":"Alice","created_at":"2026-10-29T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}]`,
		"missing user":           `[{"ip":"203.0.113.5","sub":"alice","created_at":"2026-10-29T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}]`,
		"expiry before creation": `[{"ip":"203.0.113.5","sub":"alice","user":"Alice","created_at":"2030-01-02T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}]`,
		"expiry equals creation": `[{"ip":"203.0.113.5","sub":"alice","user":"Alice","created_at":"2030-01-01T00:00:00Z","expires_at":"2030-01-01T00:00:00Z"}]`,
		"bad timestamp":          `[{"ip":"203.0.113.5","sub":"alice","user":"Alice","created_at":"yesterday","expires_at":"2030-01-01T00:00:00Z"}]`,
		"unknown field":          `[{"ip":"203.0.113.5",` + ok + `,"extra":1}]`,
		"null record":            `[null]`,
		"trailing data":          `[{"ip":"203.0.113.5",` + ok + `}] []`,
		"duplicate ip":           `[{"ip":"203.0.113.5",` + ok + `},{"ip":"203.0.113.5",` + ok + `}]`,
		"duplicate ipv6 /64":     `[{"ip":"2001:db8::1",` + ok + `},{"ip":"2001:db8::2",` + ok + `}]`,
		"valid then missing exp": `[{"ip":"203.0.113.6",` + ok + `},{"ip":"203.0.113.5","sub":"alice","user":"Alice","created_at":"2026-10-29T00:00:00Z"}]`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "allowlist.json")
			os.WriteFile(path, []byte(content), 0o600)
			// The clock is far in the future, so a lenient loader would prune the
			// valid-looking records and rewrite the file.
			c := &clock{t: time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)}
			if _, err := Open(path, c.Now); err == nil {
				t.Fatal("Open accepted corrupt file")
			}
			// The file must be left untouched.
			b, _ := os.ReadFile(path)
			if string(b) != content {
				t.Error("corrupt file was modified")
			}
		})
	}
}

func TestExpiredCompleteRecordsArePruned(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowlist.json")
	os.WriteFile(path, []byte(`[{"ip":"203.0.113.5","sub":"alice","user":"Alice","created_at":"2026-10-28T00:00:00Z","expires_at":"2026-10-29T00:00:00Z","user_agent":""}]`), 0o600)
	s, err := Open(path, newClock().Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List(nil)) != 0 {
		t.Error("expired record kept")
	}
	b, _ := os.ReadFile(path)
	if strings.TrimSpace(string(b)) != "[]" {
		t.Errorf("file not rewritten after pruning: %s", b)
	}
}

func TestPutValidates(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	good := entry("203.0.113.5", "alice", c.Now(), time.Hour)
	for name, mutate := range map[string]func(*Entry){
		"no ip":       func(e *Entry) { e.IP = netip.Addr{} },
		"no sub":      func(e *Entry) { e.Sub = "" },
		"no user":     func(e *Entry) { e.User = "" },
		"no created":  func(e *Entry) { e.CreatedAt = time.Time{} },
		"no expiry":   func(e *Entry) { e.ExpiresAt = time.Time{} },
		"exp<created": func(e *Entry) { e.ExpiresAt = e.CreatedAt.Add(-time.Second) },
	} {
		e := good
		mutate(&e)
		if err := s.Put(e); err == nil {
			t.Errorf("%s: Put accepted invalid entry", name)
		}
	}
	if len(s.List(nil)) != 0 {
		t.Error("invalid entries stored")
	}
}

func TestMissingFileIsEmpty(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "allowlist.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.List(nil)) != 0 {
		t.Error("expected empty store")
	}
}

func TestListFilterAndOrder(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	s.Put(entry("198.51.100.1", "alice", c.Now(), time.Hour))
	s.Put(entry("198.51.100.2", "bob", c.Now(), 2*time.Hour))
	s.Put(entry("198.51.100.3", "alice", c.Now(), 3*time.Hour))
	mine := s.List(func(e Entry) bool { return e.Sub == "alice" })
	if len(mine) != 2 || mine[0].IP.String() != "198.51.100.3" || mine[1].IP.String() != "198.51.100.1" {
		t.Errorf("filtered list = %+v", mine)
	}
}

func TestRunPruner(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	s.Put(entry("198.51.100.1", "alice", c.Now(), time.Hour))
	c.Add(2 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go s.RunPruner(ctx, time.Millisecond, func(n int, err error) {
		if n > 0 {
			select {
			case done <- n:
			default:
			}
		}
	})
	select {
	case n := <-done:
		if n != 1 {
			t.Errorf("pruned %d", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pruner did not run")
	}
	cancel()
}

func TestConcurrentAccess(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
			for range 20 {
				s.Put(Entry{IP: ip, Sub: "x", User: "x", CreatedAt: c.Now(), ExpiresAt: c.Now().Add(time.Hour)})
				s.Lookup(ip)
				s.List(nil)
			}
		})
	}
	wg.Wait()
	if n := len(s.List(nil)); n != 8 {
		t.Errorf("got %d entries", n)
	}
}

func BenchmarkLookup(b *testing.B) {
	s, _ := Open(filepath.Join(b.TempDir(), "allowlist.json"), nil)
	for i := range 100 {
		s.Put(Entry{IP: netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), Sub: "x", User: "x", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	}
	ip := netip.MustParseAddr("198.51.100.50")
	b.ReportAllocs()
	for b.Loop() {
		s.Lookup(ip)
	}
}
