package keyfile

import "syscall"

// isNoFollowErr reports whether err is how O_NOFOLLOW refuses a symlink; NetBSD returns EFTYPE.
func isNoFollowErr(err error) bool { return err == syscall.ELOOP || err == syscall.EFTYPE }
