//go:build !linux && !darwin

package keyfile

import (
	"io/fs"
	"os"
)

// noFollowOpen is false: os.Root.OpenFile follows a relative symlink that stays inside the directory.
const noFollowOpen = false

const dirByFD = false

// rootFromDir opens the directory by path again; checkKeyDir's SameFile check rejects a swapped one,
// but a FIFO or device swapped in after openDirNoFollow can still block or be opened here.
func rootFromDir(_ *os.File, dir string) (*os.Root, error) {
	return os.OpenRoot(dir)
}

func openKeyFile(root *os.Root, _ *os.File, name string, _ fs.FileInfo) (*os.File, error) {
	return root.OpenFile(name, keyFileFlags, 0)
}
