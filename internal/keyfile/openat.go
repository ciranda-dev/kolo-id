//go:build linux || darwin

package keyfile

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"syscall"
)

// noFollowOpen reports whether openKeyFile never follows a symlink at name.
const noFollowOpen = true

// dirByFD reports whether rootFromDir opens the directory through its descriptor, not its path.
const dirByFD = true

// rootFromDir opens an os.Root on the directory d through fdDir, never by path; without fdDir it fails closed.
func rootFromDir(d *os.File, _ string) (*os.Root, error) {
	rc, err := d.SyscallConn()
	if err != nil {
		return nil, err
	}
	var root *os.Root
	var rerr error
	if err := rc.Control(func(fd uintptr) { root, rerr = os.OpenRoot(fdDir + strconv.Itoa(int(fd))) }); err != nil {
		return nil, err
	}
	if rerr != nil {
		return nil, fdDirUnavailable(rerr)
	}
	return root, nil
}

// fdDirUnavailable wraps ErrInsecure; err is formatted with %v so the result never matches fs.ErrNotExist.
func fdDirUnavailable(err error) error {
	return fmt.Errorf("%w: cannot reopen through %s: %v", ErrInsecure, fdDir, err)
}

// openKeyFile opens name with openat relative to the directory handle d, without following a symlink.
func openKeyFile(_ *os.Root, d *os.File, name string, lst fs.FileInfo) (*os.File, error) {
	rc, err := d.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var oerr error
	if err := rc.Control(func(dirfd uintptr) {
		for {
			if fd, oerr = openatNoFollow(int(dirfd), name, lst); oerr != syscall.EINTR {
				return
			}
		}
	}); err != nil {
		return nil, err
	}
	if isNoFollowErr(oerr) || errors.Is(oerr, ErrInvalid) {
		return nil, ErrInvalid // a symlink or other file swapped in after the Lstat
	}
	if errors.Is(oerr, ErrInsecure) {
		return nil, oerr
	}
	if oerr != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: oerr}
	}
	return os.NewFile(uintptr(fd), name), nil
}
