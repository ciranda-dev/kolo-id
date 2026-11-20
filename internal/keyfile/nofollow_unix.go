//go:build unix && !freebsd && !dragonfly && !netbsd

package keyfile

import "syscall"

// isNoFollowErr reports whether err is how O_NOFOLLOW refuses a symlink.
func isNoFollowErr(err error) bool { return err == syscall.ELOOP }
