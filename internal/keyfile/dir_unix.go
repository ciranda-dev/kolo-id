//go:build unix

package keyfile

import (
	"os"
	"syscall"
)

// openDirNoFollow opens dir only if it is a directory, without following a symlink, blocking or taking a terminal.
func openDirNoFollow(dir string) (*os.File, error) {
	const flags = syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_NOCTTY | syscall.O_CLOEXEC
	fd, err := syscall.Open(dir, flags, 0)
	for err == syscall.EINTR {
		fd, err = syscall.Open(dir, flags, 0)
	}
	if isNoFollowErr(err) || err == syscall.ENOTDIR {
		return nil, ErrInsecure // not the directory Lstat saw
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return os.NewFile(uintptr(fd), dir), nil
}
