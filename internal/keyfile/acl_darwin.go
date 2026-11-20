package keyfile

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// aclAllowsAccess reports whether f has an ACL entry that allows access, or its ACL cannot be read.
func aclAllowsAccess(f *os.File) bool {
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY}
	var buf [4096]byte
	rc, err := f.SyscallConn()
	if err != nil {
		return true
	}
	var r1 uintptr
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) { r1, errno = fgetattrlist(fd, &attrs, buf[:]) }); err != nil {
		return true
	}
	return aclReplyAllows(r1, uintptr(errno), buf[:])
}

// A raw syscall: x/sys/unix has no Fgetattrlist and getxattr("com.apple.system.Security") returns EPERM.
// aclReplyAllows fails closed on any errno or unexpected layout.
var fgetattrlist = func(fd uintptr, attrs *unix.Attrlist, buf []byte) (uintptr, syscall.Errno) {
	//lint:ignore SA1019 x/sys has no fgetattrlist wrapper; a failed call fails closed (ErrInsecureKeyFile)
	r1, _, errno := unix.Syscall6(unix.SYS_FGETATTRLIST, fd, uintptr(unsafe.Pointer(attrs)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0)
	return r1, errno
}

// ownersIgnored reports whether d is on a volume mounted with MNT_IGNORE_OWNERSHIP,
// where every file reports the caller as owner, or the mount flags cannot be read.
func ownersIgnored(d *os.File) bool {
	rc, err := d.SyscallConn()
	if err != nil {
		return true
	}
	var st syscall.Statfs_t
	var serr error
	if err := rc.Control(func(fd uintptr) { serr = syscall.Fstatfs(int(fd), &st) }); err != nil || serr != nil {
		return true
	}
	return st.Flags&unix.MNT_IGNORE_OWNERSHIP != 0
}
