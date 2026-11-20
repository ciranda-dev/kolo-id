package keyfile

import (
	"io/fs"
	"strconv"
	"syscall"
)

// fdDir is a variable only so tests can make it unavailable.
var fdDir = "/proc/self/fd/"

// oPath is O_PATH on every Linux architecture Go supports; package syscall lacks it on amd64, 386 and arm.
const oPath = 0x200000

// openatNoFollow opens name with O_PATH first, so a device swapped in after the Lstat is never opened,
// checks it is the regular file lst describes, and only then opens it for reading through /proc.
func openatNoFollow(dirfd int, name string, lst fs.FileInfo) (int, error) {
	pfd, err := syscall.Openat(dirfd, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(pfd)
	var st syscall.Stat_t
	if err := syscall.Fstat(pfd, &st); err != nil {
		return -1, err
	}
	lt, ok := lst.Sys().(*syscall.Stat_t)
	if !ok || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Dev != lt.Dev || st.Ino != lt.Ino {
		return -1, ErrInvalid
	}
	afterPathCheck(name)
	fd, err := syscall.Open(fdDir+strconv.Itoa(pfd), keyFileFlags&^syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		return -1, fdDirUnavailable(err) // never reopen by name, where a device may have been swapped in
	}
	return fd, err
}

// afterPathCheck is a test seam between the O_PATH check and the reopen; only tests reassign it.
var afterPathCheck = func(name string) {}
