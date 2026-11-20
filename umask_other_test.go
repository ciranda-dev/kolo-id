//go:build !unix

package koloid

import "testing"

func umask0(*testing.T) {}
