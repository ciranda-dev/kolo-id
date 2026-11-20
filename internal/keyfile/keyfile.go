// Package keyfile reads and writes kolo-id key files; koloid.Load and Identity.Save document the behavior.
package keyfile

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// The koloid package re-exports these errors under its own names.
var (
	ErrInvalid        = errors.New("koloid: invalid key file")
	ErrInsecure       = errors.New("koloid: key file or its directory is accessible to others or owned by another user")
	ErrSavedNotSynced = errors.New("koloid: key file saved but directory sync failed")
	ErrTempLeft       = errors.New("koloid: temporary key file left on disk")
)

// SeedSize is the size of a key file.
const SeedSize = ed25519.SeedSize

// Write writes seed to path, replacing what is there (rename) or never replacing anything (link).
func Write(path string, seed []byte, replace bool) error { return WriteBlob(path, seed, replace) }

// WriteBlob is like Write for any data: the same directory checks, mode 0600 and atomic replace.
func WriteBlob(path string, data []byte, replace bool) (err error) {
	dir, name, err := splitKeyPath(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	root, d, err := openKeyDir(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	defer d.Close()
	tmp, f, err := createTemp(root)
	if err != nil {
		return err
	}
	defer func() {
		if tmp != "" {
			f.Close()
			if rmErr := root.Remove(tmp); rmErr != nil {
				err = errors.Join(err, fmt.Errorf("%w, key not saved: %s: %w", ErrTempLeft, filepath.Join(dir, tmp), rmErr))
			}
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	var tempLeft error
	if replace {
		if err = root.Rename(tmp, name); err != nil {
			return err
		}
		tmp = ""
	} else {
		if err = root.Link(tmp, name); err != nil { // unlike rename, link fails if anything exists at name
			if errors.Is(err, fs.ErrExist) {
				err = fmt.Errorf("koloid: %s: %w", path, fs.ErrExist)
			}
			return err
		}
		if rmErr := root.Remove(tmp); rmErr != nil {
			tempLeft = fmt.Errorf("%w, key saved: %s: %w", ErrTempLeft, filepath.Join(dir, tmp), rmErr)
		}
		tmp = ""
	}
	if err = syncDir(d); err != nil {
		err = fmt.Errorf("%w: %w", ErrSavedNotSynced, err)
	}
	return errors.Join(tempLeft, err)
}

// splitKeyPath returns the directory and file name of path, which must end in a file name.
func splitKeyPath(path string) (dir, name string, err error) {
	name = filepath.Base(path)
	// Win32 path normalization drops trailing dots and spaces, so "id.key." would open "id.key".
	trailing := runtime.GOOS == "windows" && strings.TrimRight(name, ". ") != name
	if path == "" || os.IsPathSeparator(path[len(path)-1]) || name == "." || name == ".." || trailing {
		return "", "", fmt.Errorf("%w: %q does not end in a file name", ErrInvalid, path)
	}
	return filepath.Dir(path), name, nil
}

// openKeyDir opens dir without following a symlink at it and checks it on the open handle.
func openKeyDir(dir string) (*os.Root, *os.File, error) {
	lst, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, err
	}
	if lst.Mode()&fs.ModeSymlink != 0 {
		return nil, nil, ErrInsecure
	}
	afterLstatDir(dir)
	d, err := openDirNoFollow(dir)
	if err != nil {
		return nil, nil, err
	}
	afterOpenDir(dir)
	root, err := checkKeyDir(d, dir, lst)
	if err != nil {
		d.Close()
		return nil, nil, err
	}
	return root, d, nil
}

// checkKeyDir checks the open directory d against lst and returns an os.Root for that same directory.
func checkKeyDir(d *os.File, dir string, lst fs.FileInfo) (*os.Root, error) {
	st, err := d.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(lst, st) || insecure(st) || aclAllowsAccess(d) || ownersIgnored(d) {
		return nil, ErrInsecure // not the directory Lstat saw, or exposed
	}
	root, err := rootFromDir(d, dir)
	if err != nil {
		return nil, err
	}
	if rst, err := root.Stat("."); err != nil || !os.SameFile(st, rst) {
		root.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrInsecure
	}
	return root, nil
}

type tempFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

// Test seams; only tests reassign them.
var (
	createTemp = func(r *os.Root) (string, tempFile, error) {
		name := ".koloid-" + rand.Text() + ".key" // the .key suffix lets a leftover match a *.key gitignore rule
		f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", nil, err
		}
		return name, f, nil
	}
	syncDir       = syncDirectory
	afterLstatDir = func(dir string) {}
	afterOpenDir  = func(dir string) {}
	afterStat     = func(path string) {}
	afterFstat    = func(path string) {}
)

func syncDirectory(d *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	return d.Sync()
}

// Read reads the seed in the key file at path into seed; the caller clears it.
func Read(path string, seed *[SeedSize]byte) error {
	b, err := readFile(path, SeedSize, SeedSize)
	defer clear(b)
	if err != nil {
		return err
	}
	copy(seed[:], b)
	return nil
}

// ReadBlob reads a file of 1 to limit bytes with the same checks as Read; any other size is ErrInvalid.
func ReadBlob(path string, limit int) ([]byte, error) {
	return readFile(path, 1, int64(limit))
}

func readFile(path string, minSize, maxSize int64) ([]byte, error) {
	dir, name, err := splitKeyPath(path)
	if err != nil {
		return nil, err
	}
	root, d, err := openKeyDir(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	defer d.Close()
	// Filter first so a device or symlink is never opened; the fstat below is the real check.
	lst, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !lst.Mode().IsRegular() {
		return nil, ErrInvalid
	}
	afterStat(path)
	f, err := openKeyFile(root, d, name, lst)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	// Where openKeyFile falls back to os.Root, a symlink inside the directory is followed; require the file Lstat saw.
	if !st.Mode().IsRegular() || st.Size() < minSize || st.Size() > maxSize || !os.SameFile(lst, st) {
		return nil, ErrInvalid
	}
	if insecure(st) || aclAllowsAccess(f) {
		return nil, ErrInsecure
	}
	afterFstat(path)
	buf := make([]byte, st.Size())
	if _, err := io.ReadFull(f, buf); err != nil {
		clear(buf)
		return nil, ErrInvalid
	}
	if n, _ := f.Read(make([]byte, 1)); n != 0 { // the file grew after fstat
		clear(buf)
		return nil, ErrInvalid
	}
	return buf, nil
}
