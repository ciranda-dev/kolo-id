package koloid

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadCert(t *testing.T) {
	w := newWorld(t)
	dir := keyDir(t)
	keyPath, certPath := filepath.Join(dir, "device.key"), filepath.Join(dir, "device.cert")
	if err := w.D.Save(keyPath); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*DeviceCert{w.certD, w.certE} {
		if err := SaveCert(certPath, c); err != nil {
			t.Fatal(err)
		}
		got, err := LoadCert(certPath)
		if err != nil || !bytes.Equal(got.Encode(), c.Encode()) {
			t.Fatalf("LoadCert: %v", err)
		}
		if err := got.Verify(w.opts); err != nil {
			t.Fatalf("a loaded certificate verifies: %v", err)
		}
	}
	if id, err := Load(keyPath); err != nil || id.PublicKeyString() != w.D.PublicKeyString() {
		t.Fatalf("the key file next to the certificate: %v", err)
	}
	if names := tempFiles(t, dir); len(names) != 0 {
		t.Fatalf("temporary files left: %v", names)
	}
}

func TestSaveCertRefusesBadCert(t *testing.T) {
	path := filepath.Join(keyDir(t), "device.cert")
	if err := SaveCert(path, nil); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("nil: %v", err)
	}
	if err := SaveCert(path, &DeviceCert{}); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("zero: %v", err)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Error("a refused certificate was written")
	}
}

func TestLoadCertInvalid(t *testing.T) {
	w := newWorld(t)
	dir := keyDir(t)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	enc := w.certD.Encode()
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrInvalidKeyFile},
		{"515 bytes", append(bytes.Clone(enc), make([]byte, 515-len(enc))...), ErrInvalidKeyFile},
		{"a megabyte", make([]byte, 1<<20), ErrInvalidKeyFile},
		{"truncated", enc[:len(enc)-1], ErrInvalidCert},
		{"trailing byte inside the bound", append(bytes.Clone(enc[:len(enc)-1]), enc[len(enc)-1], 0), ErrInvalidCert},
		{"garbage", bytes.Repeat([]byte{0xff}, 300), ErrInvalidCert},
		{"a 32-byte key file", bytes.Repeat([]byte{7}, 32), ErrInvalidCert},
	}
	for _, c := range cases {
		if got, err := LoadCert(write(c.name+".cert", c.data)); got != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: %v, %v", c.name, got, err)
		}
	}
	if _, err := LoadCert(filepath.Join(dir, "missing.cert")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := LoadCert(dir + string(os.PathSeparator)); !errors.Is(err, ErrInvalidKeyFile) {
		t.Errorf("directory path: %v", err)
	}
	// A file of exactly 514 bytes is read (and then refused as a certificate), not refused for its size.
	if _, err := LoadCert(write("exact.cert", make([]byte, 514))); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("514 bytes: %v", err)
	}
}

// A seed file is exactly 32 bytes; the generic blob reader must not loosen that.
func TestLoadStillRequiresExactSeedSize(t *testing.T) {
	dir := keyDir(t)
	for _, n := range []int{0, 1, 31, 33, 514} {
		p := filepath.Join(dir, "id.key")
		if err := os.WriteFile(p, make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("%d bytes: %v", n, err)
		}
	}
}

func TestSaveCertReplacesSymlink(t *testing.T) {
	w := newWorld(t)
	dir := keyDir(t)
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "device.cert")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks are not available: %v", err)
	}
	if err := SaveCert(link, w.certE); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("the symlink target was written: %q", b)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("the symlink was not replaced: %v", err)
	}
	if _, err := LoadCert(link); err != nil {
		t.Fatal(err)
	}
}
