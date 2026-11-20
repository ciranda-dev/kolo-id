//go:build freebsd || dragonfly

package keyfile

import "syscall"

// isNoFollowErr reports whether err is how O_NOFOLLOW refuses a symlink; FreeBSD and DragonFly return EMLINK.
func isNoFollowErr(err error) bool { return err == syscall.ELOOP || err == syscall.EMLINK }
