//go:build !darwin

package keyfile

import "os"

func aclAllowsAccess(*os.File) bool { return false }

func ownersIgnored(*os.File) bool { return false }
