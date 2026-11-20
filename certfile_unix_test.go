//go:build unix

package koloid

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveCertMode(t *testing.T) {
	umask0(t)
	w := newWorld(t)
	path := filepath.Join(keyDir(t), "device.cert")
	if err := SaveCert(path, w.certD); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, %v", fi.Mode(), err)
	}
	if err := SaveCert(path, w.certE); err != nil {
		t.Fatal(err)
	}
}

func TestSaveCertFixesExistingFileMode(t *testing.T) {
	umask0(t)
	w := newWorld(t)
	path := filepath.Join(keyDir(t), "device.cert")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := SaveCert(path, w.certE); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode())
	}
}

func TestCertFileDirectoryChecks(t *testing.T) {
	w := newWorld(t)
	for _, mode := range []os.FileMode{0o755, 0o750, 0o705, 0o770} {
		dir := filepath.Join(keyDir(t), "keys")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "device.cert")
		if err := SaveCert(path, w.certE); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCert(path); !errors.Is(err, ErrInsecureKeyFile) {
			t.Errorf("LoadCert from a %o directory: %v", mode, err)
		}
		if err := SaveCert(path, w.certE); !errors.Is(err, ErrInsecureKeyFile) {
			t.Errorf("SaveCert into a %o directory: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660} {
		path := filepath.Join(keyDir(t), "device.cert")
		if err := SaveCert(path, w.certE); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadCert(path); !errors.Is(err, ErrInsecureKeyFile) {
			t.Errorf("LoadCert of a %o file: %v", mode, err)
		}
	}
	base := keyDir(t)
	real, link := filepath.Join(base, "real"), filepath.Join(base, "link")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := SaveCert(filepath.Join(link, "device.cert"), w.certE); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("SaveCert through a symlinked directory: %v", err)
	}
}
