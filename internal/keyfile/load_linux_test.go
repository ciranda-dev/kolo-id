package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Proves the O_PATH open: a FIFO swapped in after the Lstat is never opened,
// so the blocked writer's open never returns.
func TestLoadNeverOpensFIFOSwappedAfterStat(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	var opened chan *os.File
	orig := afterStat
	defer func() { afterStat = orig }()
	afterStat = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Error(err)
		}
		opened = blockedWriter(t, p)
	}
	if err := loadWithin(t, path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a FIFO swapped in after Lstat returned %v, want %v", err, ErrInvalid)
	}
	select {
	case w := <-opened:
		opened <- w
		t.Fatal("Load opened the FIFO swapped in after Lstat: the blocked writer's open returned")
	case <-time.After(200 * time.Millisecond):
	}
}

// Runs only as root, which can create a device node; CI runs it with sudo.
func TestLoadDeviceSwappedAfterStat(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create a device node")
	}
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
		// Major 240 is reserved for local use, so no driver answers: an open would fail with ENXIO.
		if err := syscall.Mknod(p, syscall.S_IFCHR|0o600, makedev(240, 0)); err != nil {
			t.Error(err)
		}
	}
	if _, err := load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a device swapped in after Lstat returned %v, want %v", err, ErrInvalid)
	}
}

// Proves the key-file reopen fails closed: without /proc it must not reopen by name,
// where a FIFO swapped in after the O_PATH check would be opened.
func TestKeyFileReopenFailsClosed(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	var opened chan *os.File
	origDir, origStat, origCheck := fdDir, afterStat, afterPathCheck
	defer func() { fdDir, afterStat, afterPathCheck = origDir, origStat, origCheck }()
	afterStat = func(string) { fdDir = filepath.Join(dir, "missing") + "/" }
	afterPathCheck = func(string) {
		if err := os.Remove(path); err != nil {
			t.Error(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Error(err)
		}
		opened = blockedWriter(t, path)
	}
	if err := loadWithin(t, path); !errors.Is(err, ErrInsecure) {
		t.Fatalf("Load with /proc unavailable returned %v, want %v", err, ErrInsecure)
	}
	select {
	case w := <-opened:
		opened <- w
		t.Fatal("Load reopened the key file by name: the blocked writer's open returned")
	case <-time.After(200 * time.Millisecond):
	}
}

func makedev(major, minor uint64) int {
	return int(minor&0xff | (major&0xfff)<<8 | (minor&^0xff)<<12 | (major&^0xfff)<<32)
}
