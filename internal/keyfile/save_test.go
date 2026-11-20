package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var errInjected = errors.New("injected failure")

type failingFile struct {
	*os.File
	failAt string
}

func (f failingFile) Write(b []byte) (int, error) {
	if f.failAt == "write" {
		return 0, errInjected
	}
	return f.File.Write(b)
}

func (f failingFile) Sync() error {
	if f.failAt == "sync" {
		return errInjected
	}
	return f.File.Sync()
}

func (f failingFile) Close() error {
	err := f.File.Close()
	if f.failAt == "close" {
		return errInjected
	}
	return err
}

func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".koloid-") {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestSaveCleansUpOnFailure(t *testing.T) {
	for _, step := range []string{"write", "sync", "close"} {
		t.Run(step, func(t *testing.T) {
			orig := createTemp
			defer func() { createTemp = orig }()

			dir := keyDir(t)
			path := filepath.Join(dir, "id.key")
			old, err := generate()
			if err != nil {
				t.Fatal(err)
			}
			if err := old.Save(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}

			createTemp = func(r *os.Root) (string, tempFile, error) {
				name, f, err := orig(r)
				if err != nil {
					return "", nil, err
				}
				return name, failingFile{File: f.(*os.File), failAt: step}, nil
			}
			id, err := generate()
			if err != nil {
				t.Fatal(err)
			}
			if err := id.Save(path); !errors.Is(err, errInjected) {
				t.Fatalf("Save error = %v, want %v", err, errInjected)
			}
			if left := tempFiles(t, dir); len(left) != 0 {
				t.Fatalf("temporary files left after a %s failure: %v", step, left)
			}
			got, err := load(path)
			if err != nil {
				t.Fatal(err)
			}
			if !got.PublicKey().Equal(old.PublicKey()) {
				t.Fatalf("old key lost after a %s failure", step)
			}
		})
	}
}

func TestSaveDirectorySyncFailure(t *testing.T) {
	orig := syncDir
	syncDir = func(*os.File) error { return errInjected }
	defer func() { syncDir = orig }()

	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	err = id.Save(path)
	if !errors.Is(err, ErrSavedNotSynced) || !errors.Is(err, errInjected) {
		t.Fatalf("Save error = %v, want ErrSavedNotSynced wrapping the sync error", err)
	}
	got, err := load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PublicKey().Equal(id.PublicKey()) {
		t.Fatal("key file does not hold the new key after ErrSavedNotSynced")
	}
	if left := tempFiles(t, dir); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

type lockingFile struct {
	*os.File
	dir string
}

// Close makes the temp file's directory read-only, so the link succeeds but the remove fails.
func (f lockingFile) Close() error {
	return errors.Join(f.File.Close(), os.Chmod(f.dir, 0o500))
}

func TestSaveNewReportsLeftoverTempFile(t *testing.T) {
	dir := keyDir(t)
	sub := lockTempDir(t, dir)
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id.key")
	err = id.SaveNew(path)
	left := tempFiles(t, sub)
	if len(left) != 1 {
		t.Fatalf("temp files in the locked directory = %v, want one leftover", left)
	}
	if err == nil {
		t.Fatal("SaveNew reported success with a leftover copy of the seed")
	}
	if !strings.HasPrefix(err.Error(), "koloid: ") || !strings.Contains(err.Error(), left[0]) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("SaveNew error = %v, want a koloid: error naming %s and wrapping the remove error", err, left[0])
	}
	if !errors.Is(err, ErrTempLeft) || !strings.Contains(err.Error(), "key saved") {
		t.Fatalf("SaveNew error = %v, want %v saying the key was saved", err, ErrTempLeft)
	}
	if got, err := load(path); err != nil || !got.PublicKey().Equal(id.PublicKey()) {
		t.Fatalf("key file not left in place after a successful link: %v", err)
	}
}

// lockTempDir makes createTemp put the temp file in dir/sub, which Close makes read-only.
func lockTempDir(t *testing.T, dir string) string {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions and a non-root user")
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(sub, 0o700) })
	orig := createTemp
	t.Cleanup(func() { createTemp = orig })
	createTemp = func(r *os.Root) (string, tempFile, error) {
		name := filepath.Join("sub", ".koloid-test.key")
		f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return "", nil, err
		}
		return name, lockingFile{File: f, dir: sub}, nil
	}
	return sub
}

func TestSaveReportsLeftoverTempFile(t *testing.T) {
	dir := keyDir(t)
	sub := lockTempDir(t, dir)
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	err = id.Save(filepath.Join(dir, "id.key")) // the rename out of the read-only sub fails
	left := tempFiles(t, sub)
	if len(left) != 1 {
		t.Fatalf("temp files in the locked directory = %v, want one leftover", left)
	}
	if err == nil || !strings.Contains(err.Error(), left[0]) {
		t.Fatalf("Save error = %v, want the rename error joined with an error naming the leftover %s", err, left[0])
	}
	if !errors.Is(err, ErrTempLeft) || !strings.Contains(err.Error(), "key not saved") {
		t.Fatalf("Save error = %v, want %v saying the key was not saved", err, ErrTempLeft)
	}
}

func TestSaveNewReportsLeftoverAfterFailedLink(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := lockTempDir(t, dir)
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	err = id.SaveNew(path)
	left := tempFiles(t, sub)
	if len(left) != 1 {
		t.Fatalf("temp files in the locked directory = %v, want one leftover", left)
	}
	if !errors.Is(err, fs.ErrExist) || !errors.Is(err, ErrTempLeft) || !strings.Contains(err.Error(), left[0]) || !strings.Contains(err.Error(), "key not saved") {
		t.Fatalf("SaveNew error = %v, want fs.ErrExist and %v naming the leftover %s and saying the key was not saved", err, ErrTempLeft, left[0])
	}
}
