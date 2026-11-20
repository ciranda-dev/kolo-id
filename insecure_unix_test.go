//go:build unix

package koloid

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLoadRejectsAccessibleKeyFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o700} {
		path := filepath.Join(keyDir(t), "id.key")
		if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if want := mode&0o077 != 0; want && !errors.Is(err, ErrInsecureKeyFile) {
			t.Errorf("Load of a %o key file returned %v, want %v", mode, err, ErrInsecureKeyFile)
		} else if !want && err != nil {
			t.Errorf("Load of a %o key file returned %v, want nil", mode, err)
		}
	}
}

func TestLoadRejectsAccessibleKeyDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o750, 0o705, 0o770, 0o700} {
		dir := filepath.Join(keyDir(t), "keys")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "id.key")
		if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if want := mode&0o077 != 0; want && !errors.Is(err, ErrInsecureKeyFile) {
			t.Errorf("Load from a %o directory returned %v, want %v", mode, err, ErrInsecureKeyFile)
		} else if !want && err != nil {
			t.Errorf("Load from a %o directory returned %v, want nil", mode, err)
		}
	}
}

func TestSaveRejectsInsecureDirectory(t *testing.T) {
	for name, save := range map[string]func(*Identity, string) error{"Save": (*Identity).Save, "SaveNew": (*Identity).SaveNew} {
		base := keyDir(t)
		dir := filepath.Join(base, "keys")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(base, "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		id, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		if err := save(id, filepath.Join(dir, "id.key")); !errors.Is(err, ErrInsecureKeyFile) {
			t.Errorf("%s into a 755 directory returned %v, want %v", name, err, ErrInsecureKeyFile)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := save(id, filepath.Join(link, "id.key")); !errors.Is(err, ErrInsecureKeyFile) {
			t.Errorf("%s through a symlinked directory returned %v, want %v", name, err, ErrInsecureKeyFile)
		}
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Errorf("%s left files in the directory: %v, %v", name, entries, err)
		}
	}
}

// Runs only as root, which can chown to another user; CI runs it with sudo.
func TestForeignOwnerRejected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	const nobody = 65534
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(keyDir(t), "keys")
	path := filepath.Join(dir, "id.key")
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("Load of a key file owned by uid %d returned %v, want %v", nobody, err, ErrInsecureKeyFile)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("Load from a directory owned by uid %d returned %v, want %v", nobody, err, ErrInsecureKeyFile)
	}
	if err := id.Save(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("Save into a directory owned by uid %d returned %v, want %v", nobody, err, ErrInsecureKeyFile)
	}
	if err := id.SaveNew(filepath.Join(dir, "new.key")); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("SaveNew into a directory owned by uid %d returned %v, want %v", nobody, err, ErrInsecureKeyFile)
	}
}

// umask0 clears the process umask for the test, so a created mode comes only
// from the code under test. Tests that call it must not run in parallel.
func umask0(t *testing.T) {
	old := syscall.Umask(0)
	t.Cleanup(func() { syscall.Umask(old) })
}
