package keyfile

import (
	"io/fs"

	"golang.org/x/sys/unix"
)

// fdDir is a variable only so tests can make it unavailable.
var fdDir = "/dev/fd/"

// openat is a test seam; package syscall does not export Openat on darwin, x/sys/unix calls libc.
var openat = unix.Openat

// Darwin has no O_PATH, so a device swapped in after the Lstat is opened here (never read).
func openatNoFollow(dirfd int, name string, _ fs.FileInfo) (int, error) {
	return openat(dirfd, name, keyFileFlags|unix.O_CLOEXEC, 0)
}
