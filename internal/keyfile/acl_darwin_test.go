package keyfile

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// A macOS version where fgetattrlist fails or replies in an unknown layout must reject, not accept.
func TestACLReadFailureRejected(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	orig := fgetattrlist
	defer func() { fgetattrlist = orig }()
	for name, fake := range map[string]func(uintptr, *unix.Attrlist, []byte) (uintptr, syscall.Errno){
		"call fails":  func(uintptr, *unix.Attrlist, []byte) (uintptr, syscall.Errno) { return 0, syscall.ENOTSUP },
		"EPERM":       func(uintptr, *unix.Attrlist, []byte) (uintptr, syscall.Errno) { return 0, syscall.EPERM },
		"EINVAL":      func(uintptr, *unix.Attrlist, []byte) (uintptr, syscall.Errno) { return 0, syscall.EINVAL },
		"EINTR":       func(uintptr, *unix.Attrlist, []byte) (uintptr, syscall.Errno) { return 0, syscall.EINTR }, // not retried
		"empty reply": func(uintptr, *unix.Attrlist, []byte) (uintptr, syscall.Errno) { return 0, 0 },
		"nonzero r1 with a deny-only reply": func(_ uintptr, _ *unix.Attrlist, b []byte) (uintptr, syscall.Errno) {
			copy(b, aclReply(aceDeny))
			return 1, 0
		},
		"unknown layout": func(_ uintptr, _ *unix.Attrlist, b []byte) (uintptr, syscall.Errno) {
			copy(b, withU32(aclReply(aceDeny), 32, 0)) // a deny-only filesec without its magic
			return 0, 0
		},
	} {
		fgetattrlist = fake
		if _, err := load(path); !errors.Is(err, ErrInsecure) {
			t.Errorf("%s: Load returned %v, want %v", name, err, ErrInsecure)
		}
		if err := id.Save(filepath.Join(dir, "new.key")); !errors.Is(err, ErrInsecure) {
			t.Errorf("%s: Save returned %v, want %v", name, err, ErrInsecure)
		}
	}
}
