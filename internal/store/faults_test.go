package store

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReadersDoNotWaitForSlowStorage blocks a write inside fsync and checks that
// Lookup and List still answer immediately with the last committed state
// (review F2).
func TestReadersDoNotWaitForSlowStorage(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	old := netip.MustParseAddr("203.0.113.1")
	if err := s.Put(entry(old.String(), "alice", c.Now(), time.Hour)); err != nil {
		t.Fatal(err)
	}

	inSync := make(chan struct{})
	release := make(chan struct{})
	s.ops.syncFile = func(f *os.File) error {
		close(inSync)
		<-release
		return f.Sync()
	}
	newIP := netip.MustParseAddr("203.0.113.2")
	putDone := make(chan error, 1)
	go func() { putDone <- s.Put(entry(newIP.String(), "bob", c.Now(), time.Hour)) }()
	<-inSync // the writer is now stuck in fsync

	readsDone := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(readsDone)
		for range 1000 {
			if _, ok := s.Lookup(old); !ok {
				t.Error("committed entry not visible during write")
				return
			}
			if _, ok := s.Lookup(newIP); ok {
				t.Error("uncommitted entry visible before its write finished")
				return
			}
			s.List(nil)
		}
	}()
	select {
	case <-readsDone:
		if d := time.Since(start); d > time.Second {
			t.Errorf("1000 reads took %v during a stalled write", d)
		}
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("readers blocked behind stalled storage write")
	}

	close(release)
	if err := <-putDone; err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(newIP); !ok {
		t.Error("entry not visible after write completed")
	}
}

// TestMutationsAreSerialized: a second writer waits for the first and sees its result.
func TestMutationsAreSerialized(t *testing.T) {
	c := newClock()
	s := open(t, filepath.Join(t.TempDir(), "allowlist.json"), c)
	inSync := make(chan struct{}, 2)
	release := make(chan struct{})
	s.ops.syncFile = func(f *os.File) error {
		inSync <- struct{}{}
		<-release
		return f.Sync()
	}
	go s.Put(entry("203.0.113.1", "alice", c.Now(), time.Hour))
	<-inSync
	done := make(chan struct{})
	go func() {
		s.Put(entry("203.0.113.2", "bob", c.Now(), time.Hour))
		close(done)
	}()
	select {
	case <-inSync:
		t.Fatal("second write entered fsync while the first was in progress")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	<-done
	if n := len(s.List(nil)); n != 2 {
		t.Errorf("got %d entries, want 2 (a write was lost)", n)
	}
	s2 := open(t, s.path, c)
	if n := len(s2.List(nil)); n != 2 {
		t.Errorf("file has %d entries, want 2", n)
	}
}

// TestWriteFaultsBeforeRename: failures in any step up to and including the
// rename leave memory and the file unchanged and report an ordinary error (F4).
func TestWriteFaultsBeforeRename(t *testing.T) {
	boom := errors.New("injected EIO")
	cases := map[string]func(*fileOps){
		"create temp": func(o *fileOps) { o.createTemp = func(string, string) (*os.File, error) { return nil, boom } },
		"write":       func(o *fileOps) { o.write = func(*os.File, []byte) error { return boom } },
		"file fsync":  func(o *fileOps) { o.syncFile = func(*os.File) error { return boom } },
		"rename":      func(o *fileOps) { o.rename = func(string, string) error { return boom } },
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			c := newClock()
			dir := t.TempDir()
			path := filepath.Join(dir, "allowlist.json")
			s := open(t, path, c)
			keep := netip.MustParseAddr("203.0.113.1")
			s.Put(entry(keep.String(), "alice", c.Now(), time.Hour))
			before, _ := os.ReadFile(path)
			inject(&s.ops)

			if err := s.Put(entry("203.0.113.2", "bob", c.Now(), time.Hour)); err == nil || errors.Is(err, ErrNotDurable) {
				t.Errorf("Put err = %v, want ordinary error", err)
			}
			if _, ok := s.Lookup(netip.MustParseAddr("203.0.113.2")); ok {
				t.Error("failed Put is visible")
			}
			_, found, removed, err := s.RemoveIf(keep, func(Entry) bool { return true })
			if err == nil || errors.Is(err, ErrNotDurable) || !found || removed {
				t.Errorf("RemoveIf = found %v removed %v err %v", found, removed, err)
			}
			if _, ok := s.Lookup(keep); !ok {
				t.Error("failed RemoveIf dropped the entry")
			}
			c.Add(2 * time.Hour)
			if n, err := s.Prune(); err == nil || n != 0 {
				t.Errorf("Prune = %d, %v", n, err)
			}
			c.Add(-2 * time.Hour)
			if _, ok := s.Lookup(keep); !ok {
				t.Error("failed Prune dropped the entry")
			}

			after, _ := os.ReadFile(path)
			if string(after) != string(before) {
				t.Error("file changed despite failed write")
			}
			names, _ := os.ReadDir(dir)
			for _, n := range names {
				if strings.HasSuffix(n.Name(), ".tmp") {
					t.Errorf("temp file left behind: %s", n.Name())
				}
			}
		})
	}
}

// TestDirectorySyncFailure: after a successful rename the change is in effect on
// disk, so memory follows it and ErrNotDurable is reported instead of a silent
// success or a rollback that would diverge from disk (F4).
func TestDirectorySyncFailure(t *testing.T) {
	c := newClock()
	path := filepath.Join(t.TempDir(), "allowlist.json")
	s := open(t, path, c)
	ip := netip.MustParseAddr("203.0.113.1")
	s.Put(entry(ip.String(), "alice", c.Now(), time.Hour))
	s.ops.syncDir = func(string) error { return errors.New("injected EIO") }

	err := s.Put(entry("203.0.113.2", "bob", c.Now(), time.Hour))
	if !errors.Is(err, ErrNotDurable) {
		t.Fatalf("Put err = %v, want ErrNotDurable", err)
	}
	if _, ok := s.Lookup(netip.MustParseAddr("203.0.113.2")); !ok {
		t.Error("entry written to disk but not visible in memory")
	}

	e, found, removed, err := s.RemoveIf(ip, func(Entry) bool { return true })
	if !errors.Is(err, ErrNotDurable) || !found || !removed || e.Sub != "alice" {
		t.Fatalf("RemoveIf = found %v removed %v err %v", found, removed, err)
	}
	if _, ok := s.Lookup(ip); ok {
		t.Error("revoked entry still allowed after directory sync failure (must fail closed)")
	}

	c.Add(2 * time.Hour)
	if n, err := s.Prune(); n != 1 || !errors.Is(err, ErrNotDurable) {
		t.Errorf("Prune = %d, %v", n, err)
	}

	// Memory and disk agree.
	s.ops = osOps
	s2 := open(t, path, c)
	if a, b := len(s.List(nil)), len(s2.List(nil)); a != b {
		t.Errorf("memory has %d entries, disk %d", a, b)
	}
}
