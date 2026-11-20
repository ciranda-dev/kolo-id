//go:build unix

package keyfile

import (
	"io/fs"
	"os"
	"syscall"
)

// O_NONBLOCK so opening a FIFO returns at once instead of waiting for a writer;
// O_NOCTTY so a terminal swapped in after the Lstat never becomes the controlling terminal;
// O_NOFOLLOW so a symlink swapped in after the Lstat is not followed (only through openat; see openKeyFile).
const keyFileFlags = os.O_RDONLY | syscall.O_NONBLOCK | syscall.O_NOCTTY | syscall.O_NOFOLLOW

func insecure(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || fi.Mode().Perm()&0o077 != 0 || int(st.Uid) != os.Geteuid()
}
