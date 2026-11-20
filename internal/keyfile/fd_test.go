//go:build linux || darwin

package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func closeOnExec(t *testing.T, f *os.File) bool {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags uintptr
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) { flags, _, errno = syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0) }); err != nil || errno != 0 {
		t.Fatalf("fcntl(F_GETFD): %v %v", err, errno)
	}
	return flags&syscall.FD_CLOEXEC != 0
}

func TestDescriptorsCloseOnExec(t *testing.T) {
	dir := keyDir(t)
	if err := os.WriteFile(filepath.Join(dir, "id.key"), make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := openDirNoFollow(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !closeOnExec(t, d) {
		t.Error("the directory descriptor from openDirNoFollow lacks FD_CLOEXEC")
	}
	root, err := rootFromDir(d, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if !strings.HasPrefix(root.Name(), fdDir) {
		t.Errorf("rootFromDir opened %q, want a path under %s", root.Name(), fdDir)
	}
	lst, err := root.Lstat("id.key")
	if err != nil {
		t.Fatal(err)
	}
	f, err := openKeyFile(root, d, "id.key", lst)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if !closeOnExec(t, f) {
		t.Error("the key file descriptor from openKeyFile lacks FD_CLOEXEC")
	}
}

// Proves rootFromDir fails closed: without fdDir it must not reopen the directory by path,
// where a FIFO swapped in after the directory was opened would block.
func TestFDDirUnavailableFailsClosed(t *testing.T) {
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
		origDir, origHook := fdDir, afterOpenDir
		fdDir = filepath.Join(base, "missing") + string(filepath.Separator)
		afterOpenDir = func(string) {
			afterOpenDir = origHook
			if err := os.Rename(dir, dir+".old"); err != nil {
				t.Error(err)
			}
			if err := syscall.Mkfifo(dir, 0o600); err != nil {
				t.Error(err)
			}
		}
		err := returnsWithin(t, dir, func() error { return op(filepath.Join(dir, "id.key")) })
		fdDir, afterOpenDir = origDir, origHook
		if !errors.Is(err, ErrInsecure) || errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s with fdDir unavailable: %v, want %v (and not fs.ErrNotExist)", name, err, ErrInsecure)
		}
	}
}
