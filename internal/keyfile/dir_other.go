//go:build !unix

package keyfile

import "os"

func openDirNoFollow(dir string) (*os.File, error) {
	return os.Open(dir)
}
