package koloid

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

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

func TestSaveNewRefusesExistingFile(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.SaveNew(path); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("SaveNew over an existing file returned %v, want %v", err, fs.ErrExist)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "existing" {
		t.Fatalf("existing file changed: %q, %v", b, err)
	}
	if left := tempFiles(t, dir); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestSaveNewRefusesDanglingSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra privileges on Windows")
	}
	dir := keyDir(t)
	target := filepath.Join(dir, "unmounted", "id.key")
	path := filepath.Join(dir, "id.key")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.SaveNew(path); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("SaveNew over a dangling symlink returned %v, want %v", err, fs.ErrExist)
	}
	if got, err := os.Readlink(path); err != nil || got != target {
		t.Fatalf("symlink changed: %q, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Dir(target)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("symlink target directory was created: %v", err)
	}
	if left := tempFiles(t, dir); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestSaveNewConcurrent(t *testing.T) {
	for range 20 {
		dir := keyDir(t)
		path := filepath.Join(dir, "id.key")
		var ids [2]*Identity
		var errs [2]error
		var wg sync.WaitGroup
		for n := range ids {
			id, err := Generate()
			if err != nil {
				t.Fatal(err)
			}
			ids[n] = id
			wg.Go(func() { errs[n] = id.SaveNew(path) })
		}
		wg.Wait()
		winner := -1
		for n, err := range errs {
			switch {
			case err == nil:
				if winner >= 0 {
					t.Fatal("both concurrent SaveNew calls succeeded")
				}
				winner = n
			case !errors.Is(err, fs.ErrExist):
				t.Fatalf("losing SaveNew returned %v, want %v", err, fs.ErrExist)
			}
		}
		if winner < 0 {
			t.Fatal("no concurrent SaveNew call succeeded")
		}
		got, err := Load(path)
		if err != nil {
			t.Fatal(err)
		}
		if !got.PublicKey().Equal(ids[winner].PublicKey()) {
			t.Fatal("key file does not hold the winner's key")
		}
		if left := tempFiles(t, dir); len(left) != 0 {
			t.Fatalf("temporary files left: %v", left)
		}
	}
}

func TestSaveNewRoundTrip(t *testing.T) {
	umask0(t)
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.SaveNew(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("file mode = %o, want 600", got)
		}
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PublicKey().Equal(id.PublicKey()) {
		t.Fatal("public key differs after Load")
	}
	if left := tempFiles(t, dir); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
	var invalid *Identity
	if err := invalid.SaveNew(filepath.Join(dir, "other.key")); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("SaveNew of a nil Identity returned %v, want %v", err, ErrInvalidIdentity)
	}
}

func TestSaveCreatesPrivateParentDirectories(t *testing.T) {
	umask0(t)
	for name, save := range map[string]func(*Identity, string) error{"Save": (*Identity).Save, "SaveNew": (*Identity).SaveNew} {
		root := keyDir(t)
		path := filepath.Join(root, "a", "b", "id.key")
		id, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := save(id, path); err != nil {
			t.Fatalf("%s into a missing nested directory: %v", name, err)
		}
		for _, d := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")} {
			info, err := os.Stat(d)
			if err != nil {
				t.Fatal(err)
			}
			if got := info.Mode().Perm(); runtime.GOOS != "windows" && got != 0o700 {
				t.Errorf("%s created %s with mode %o, want 700", name, d, got)
			}
		}
		got, err := Load(path)
		if err != nil {
			t.Fatalf("Load after %s: %v", name, err)
		}
		if !got.PublicKey().Equal(id.PublicKey()) {
			t.Fatalf("public key differs after %s and Load", name)
		}
	}
}
