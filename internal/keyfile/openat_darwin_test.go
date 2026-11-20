package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKeyFileOpenGoesThroughOpenat(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := openat
	defer func() { openat = orig }()
	const want = unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOCTTY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	calls := 0
	openat = func(dirfd int, name string, flags int, mode uint32) (int, error) {
		calls++
		if dirfd < 0 || name != "id.key" || flags != want {
			t.Errorf("openat(%d, %q, %#x), want a directory fd, %q and %#x", dirfd, name, flags, "id.key", want)
		}
		if calls == 1 {
			return -1, unix.EINTR
		}
		return orig(dirfd, name, flags, mode)
	}
	if _, err := load(path); err != nil || calls != 2 {
		t.Fatalf("Load = %v after %d openat calls, want nil after an EINTR retry", err, calls)
	}
	for _, e := range []error{unix.EIO, unix.ENOSYS} {
		calls = 0
		openat = func(int, string, int, uint32) (int, error) { calls++; return -1, e }
		_, err := load(path)
		if !errors.Is(err, e) || errors.Is(err, fs.ErrNotExist) || calls != 1 {
			t.Errorf("openat failing with %v: Load = %v after %d calls, want that error after one call", e, err, calls)
		}
	}
}
