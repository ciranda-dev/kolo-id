//go:build !unix

package keyfile

import (
	"io/fs"
	"os"
)

const keyFileFlags = os.O_RDONLY

// File modes on non-unix systems do not show who else can read the file.
func insecure(fs.FileInfo) bool { return false }
