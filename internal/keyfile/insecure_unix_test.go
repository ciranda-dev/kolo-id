//go:build unix

package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type fakeFileInfo struct {
	mode fs.FileMode
	sys  any
}

func (f fakeFileInfo) Name() string { return "id.key" }

func (f fakeFileInfo) Size() int64 { return 32 }

func (f fakeFileInfo) Mode() fs.FileMode { return f.mode }

func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }

func (f fakeFileInfo) IsDir() bool { return false }

func (f fakeFileInfo) Sys() any { return f.sys }

func TestInsecureOwnerAndMode(t *testing.T) {
	me := uint32(os.Geteuid())
	for _, tc := range []struct {
		name string
		fi   fakeFileInfo
		want bool
	}{
		{"own 0600", fakeFileInfo{0o600, &syscall.Stat_t{Uid: me}}, false},
		{"own 0644", fakeFileInfo{0o644, &syscall.Stat_t{Uid: me}}, true},
		{"other user 0600", fakeFileInfo{0o600, &syscall.Stat_t{Uid: me + 1}}, true},
		{"no Stat_t", fakeFileInfo{0o600, nil}, true},
		{"own directory 0700", fakeFileInfo{fs.ModeDir | 0o700, &syscall.Stat_t{Uid: me}}, false},
		{"own directory 0755", fakeFileInfo{fs.ModeDir | 0o755, &syscall.Stat_t{Uid: me}}, true},
		{"other user's directory 0700", fakeFileInfo{fs.ModeDir | 0o700, &syscall.Stat_t{Uid: me + 1}}, true},
	} {
		if got := insecure(tc.fi); got != tc.want {
			t.Errorf("%s: insecure = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// swapKeyDir makes afterOpenDir move dir aside to dir+".old" with oldMode and
// put a new 0700 dir holding newSeed (if any) at the old path.
func swapKeyDir(t *testing.T, dir string, oldMode os.FileMode, newSeed []byte) {
	t.Helper()
	orig := afterOpenDir
	t.Cleanup(func() { afterOpenDir = orig })
	afterOpenDir = func(string) {
		afterOpenDir = orig
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Chmod(dir+".old", oldMode); err != nil {
			t.Error(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Error(err)
		}
		if newSeed != nil {
			if err := os.WriteFile(filepath.Join(dir, "id.key"), newSeed, 0o600); err != nil {
				t.Error(err)
			}
		}
	}
}

func savedKeyDir(t *testing.T) (dir string, id *testKey) {
	t.Helper()
	dir = filepath.Join(keyDir(t), "keys")
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(filepath.Join(dir, "id.key")); err != nil {
		t.Fatal(err)
	}
	return dir, id
}

func TestLoadUsesOpenedDirectory(t *testing.T) {
	if !dirByFD {
		t.Skip("os.Root reopens the directory by path on this platform")
	}
	dir, id := savedKeyDir(t)
	swapKeyDir(t, dir, 0o700, make([]byte, 32))
	got, err := load(filepath.Join(dir, "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	if !got.PublicKey().Equal(id.PublicKey()) {
		t.Fatal("Load read the directory swapped in after it opened the key directory")
	}
}

func TestLoadChecksOpenedDirectory(t *testing.T) {
	dir, _ := savedKeyDir(t)
	swapKeyDir(t, dir, 0o755, make([]byte, 32))
	if _, err := load(filepath.Join(dir, "id.key")); !errors.Is(err, ErrInsecure) {
		t.Fatalf("Load with the opened directory made 755 returned %v, want %v", err, ErrInsecure)
	}
}

func TestSaveUsesOpenedDirectory(t *testing.T) {
	if !dirByFD {
		t.Skip("os.Root reopens the directory by path on this platform")
	}
	for name, save := range map[string]func(*testKey, string) error{"Save": (*testKey).Save, "SaveNew": (*testKey).SaveNew} {
		dir := filepath.Join(keyDir(t), "keys")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		id, err := generate()
		if err != nil {
			t.Fatal(err)
		}
		swapKeyDir(t, dir, 0o700, nil)
		if err := save(id, filepath.Join(dir, "id.key")); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := os.Lstat(filepath.Join(dir, "id.key")); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s wrote into the directory swapped in after it opened the key directory", name)
		}
		got, err := load(filepath.Join(dir+".old", "id.key"))
		if err != nil || !got.PublicKey().Equal(id.PublicKey()) {
			t.Errorf("%s did not write into the opened directory: %v", name, err)
		}
	}
}

func TestSaveChecksOpenedDirectory(t *testing.T) {
	for name, save := range map[string]func(*testKey, string) error{"Save": (*testKey).Save, "SaveNew": (*testKey).SaveNew} {
		dir := filepath.Join(keyDir(t), "keys")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		id, err := generate()
		if err != nil {
			t.Fatal(err)
		}
		swapKeyDir(t, dir, 0o755, nil)
		if err := save(id, filepath.Join(dir, "id.key")); !errors.Is(err, ErrInsecure) {
			t.Errorf("%s with the opened directory made 755 returned %v, want %v", name, err, ErrInsecure)
		}
		for _, d := range []string{dir, dir + ".old"} {
			if entries, err := os.ReadDir(d); err != nil || len(entries) != 0 {
				t.Errorf("%s left files in %s: %v, %v", name, d, entries, err)
			}
		}
	}
}

// A relative symlink swapped in after the Lstat is refused by openat with O_NOFOLLOW,
// or, where os.Root follows it, by the check that the opened file is the one Lstat saw.
func TestLoadRejectsRelativeSymlinkSwappedAfterStat(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	for _, p := range []string{path, filepath.Join(dir, "other.key")} {
		if err := os.WriteFile(p, make([]byte, 32), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	orig := afterStat
	defer func() { afterStat = orig }()
	afterStat = func(p string) {
		if err := os.Remove(p); err != nil {
			t.Error(err)
		}
		if err := os.Symlink("other.key", p); err != nil {
			t.Error(err)
		}
	}
	if _, err := load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a relative symlink swapped in after Lstat returned %v, want %v", err, ErrInvalid)
	}
}

// Proves the SameFile check on the directory: a symlink swapped in between
// the Lstat and the open would otherwise lead to another private directory.
func TestKeyDirSwappedForSymlinkBeforeOpen(t *testing.T) {
	base := keyDir(t)
	dir := filepath.Join(base, "keys")
	target := filepath.Join(base, "other")
	for _, d := range []string{dir, target} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	other, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Save(filepath.Join(target, "id.key")); err != nil {
		t.Fatal(err)
	}
	orig := afterLstatDir
	defer func() { afterLstatDir = orig }()
	afterLstatDir = func(d string) {
		if err := os.Rename(dir, dir+".old"); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(target, dir); err != nil {
			t.Error(err)
		}
	}
	restore := func() {
		if err := os.Remove(dir); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(dir+".old", dir); err != nil {
			t.Fatal(err)
		}
	}
	id, err := generate()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := load(filepath.Join(dir, "id.key")); !errors.Is(err, ErrInsecure) {
		t.Errorf("Load returned %v, want %v", err, ErrInsecure)
	}
	restore()
	if err := id.Save(filepath.Join(dir, "id.key")); !errors.Is(err, ErrInsecure) {
		t.Errorf("Save returned %v, want %v", err, ErrInsecure)
	}
	restore()
	if err := id.SaveNew(filepath.Join(dir, "new.key")); !errors.Is(err, ErrInsecure) {
		t.Errorf("SaveNew returned %v, want %v", err, ErrInsecure)
	}
	restore()
	afterLstatDir = orig
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 1 || entries[0].Name() != "id.key" {
		t.Fatalf("target directory holds %v, %v, want only id.key", entries, err)
	}
	if got, err := load(filepath.Join(target, "id.key")); err != nil || !got.PublicKey().Equal(other.PublicKey()) {
		t.Fatalf("target key changed: %v", err)
	}
}
