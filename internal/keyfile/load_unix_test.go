// syscall.Mkfifo does not exist on aix, solaris and illumos.

//go:build unix && !aix && !solaris

package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func loadWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := load(path)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("load(%s) did not return", path)
		return nil
	}
}

// blockedWriter starts a goroutine that opens fifo for writing, which blocks until a reader opens it,
// and returns once that goroutine is about to make the call. The channel yields the writer when the open returns.
func blockedWriter(t *testing.T, fifo string) chan *os.File {
	t.Helper()
	opened := make(chan *os.File, 1)
	ready := make(chan struct{})
	go func() {
		close(ready)
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Error(err)
		}
		opened <- w
	}()
	<-ready
	runtime.Gosched()
	t.Cleanup(func() {
		r, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if w := <-opened; w != nil {
			w.Close()
		}
		r.Close()
	})
	return opened
}

// Proves the O_NONBLOCK open: without it, opening the swapped-in FIFO blocks.
func TestLoadFIFOSwappedAfterStat(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := afterStat
	defer func() { afterStat = orig }()
	afterStat = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Errorf("cannot create a FIFO: %v", err)
		}
	}
	if err := loadWithin(t, path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a FIFO swapped in after Lstat returned %v, want %v", err, ErrInvalid)
	}
}

// Proves the fstat check: the swapped-in FIFO has a writer and 32 buffered
// bytes, so without the check the open and the reads succeed.
func TestLoadFIFOWithDataSwappedAfterStat(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := afterStat
	defer func() { afterStat = orig }()
	afterStat = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Errorf("cannot create a FIFO: %v", err)
			return
		}
		w, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			t.Error(err)
			return
		}
		if _, err := w.Write(make([]byte, 32)); err != nil {
			t.Error(err)
		}
		t.Cleanup(func() { w.Close() })
	}
	if err := loadWithin(t, path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a FIFO with data swapped in after Lstat returned %v, want %v", err, ErrInvalid)
	}
}

// An absolute symlink to a FIFO swapped in after the Lstat is not followed (openat
// with O_NOFOLLOW, or os.Root, which refuses absolute links), so the blocked writer's open never returns.
func TestLoadSymlinkSwappedAfterStatNotFollowed(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	fifo := filepath.Join(dir, "fifo")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	opened := blockedWriter(t, fifo)
	orig := afterStat
	defer func() { afterStat = orig }()
	afterStat = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(fifo, p); err != nil {
			t.Error(err)
		}
	}
	if err := loadWithin(t, path); err == nil || noFollowOpen && !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a symlink to a FIFO swapped in after Lstat returned %v, want %v", err, ErrInvalid)
	}
	select {
	case w := <-opened:
		opened <- w
		t.Fatal("Load followed the symlink and opened the FIFO: the blocked writer's open returned")
	case <-time.After(200 * time.Millisecond):
	}
}

// A relative symlink to a FIFO in the key directory, swapped in after the Lstat,
// must not be followed either: the blocked writer's open never returns.
func TestLoadRelativeSymlinkSwappedAfterStatNotFollowed(t *testing.T) {
	if !noFollowOpen {
		t.Skip("os.Root follows a relative symlink inside the directory on this platform")
	}
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	fifo := filepath.Join(dir, "fifo")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create a FIFO: %v", err)
	}
	opened := blockedWriter(t, fifo)
	orig := afterStat
	defer func() { afterStat = orig }()
	afterStat = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := os.Symlink("fifo", p); err != nil {
			t.Error(err)
		}
	}
	if err := loadWithin(t, path); err == nil || noFollowOpen && !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a symlink to a FIFO swapped in after Lstat returned %v, want %v", err, ErrInvalid)
	}
	select {
	case w := <-opened:
		opened <- w
		t.Fatal("Load followed the symlink and opened the FIFO: the blocked writer's open returned")
	case <-time.After(200 * time.Millisecond):
	}
}

// returnsWithin runs f and returns an error if it does not return within 5s; opening
// fifo for writing then releases a reader blocked in open.
func returnsWithin(t *testing.T, fifo string, f func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- f() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			defer w.Close()
		}
		<-done
		return errors.New("did not return within 5s: it blocked opening the FIFO")
	}
}

// Proves the directory pre-open: a FIFO, or a symlink to one, swapped in for the
// key directory after its Lstat must not block Load, Save or SaveNew.
func TestKeyDirSwappedForFIFO(t *testing.T) {
	for _, viaSymlink := range []bool{false, true} {
		for name, op := range map[string]func(string) error{
			"Load":    func(p string) error { _, err := load(p); return err },
			"Save":    func(p string) error { id, _ := generate(); return id.Save(p) },
			"SaveNew": func(p string) error { id, _ := generate(); return id.SaveNew(p) },
		} {
			base := keyDir(t)
			dir := filepath.Join(base, "keys")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			fifo := dir
			if viaSymlink {
				fifo = filepath.Join(base, "fifo")
			}
			orig := afterLstatDir
			afterLstatDir = func(string) {
				afterLstatDir = orig
				if err := os.Rename(dir, dir+".old"); err != nil {
					t.Error(err)
				}
				if err := syscall.Mkfifo(fifo, 0o600); err != nil {
					t.Error(err)
				}
				if viaSymlink {
					if err := os.Symlink(fifo, dir); err != nil {
						t.Error(err)
					}
				}
			}
			err := returnsWithin(t, fifo, func() error { return op(filepath.Join(dir, "id.key")) })
			afterLstatDir = orig
			if !errors.Is(err, ErrInsecure) {
				t.Errorf("%s (symlink %v): %v, want %v", name, viaSymlink, err, ErrInsecure)
			}
		}
	}
}

// Proves O_NOFOLLOW in openDirNoFollow: a symlink to an unreadable directory swapped in
// after the Lstat is refused as a symlink (ErrInsecure), not followed (EACCES).
func TestKeyDirSwappedForSymlinkNotFollowed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode 0000 directory")
	}
	for name, op := range map[string]func(string) error{
		"Load":    func(p string) error { _, err := load(p); return err },
		"Save":    func(p string) error { id, _ := generate(); return id.Save(p) },
		"SaveNew": func(p string) error { id, _ := generate(); return id.SaveNew(p) },
	} {
		base := keyDir(t)
		dir, target := filepath.Join(base, "keys"), filepath.Join(base, "target")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(target, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(target, 0o700) })
		orig := afterLstatDir
		afterLstatDir = func(string) {
			afterLstatDir = orig
			if err := os.Rename(dir, dir+".old"); err != nil {
				t.Error(err)
			}
			if err := os.Symlink(target, dir); err != nil {
				t.Error(err)
			}
		}
		err := op(filepath.Join(dir, "id.key"))
		afterLstatDir = orig
		if !errors.Is(err, ErrInsecure) {
			t.Errorf("%s: %v, want %v", name, err, ErrInsecure)
		}
	}
}
