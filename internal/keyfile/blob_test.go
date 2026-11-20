package keyfile

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestBlobRoundTripAndBounds(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "x.cert")
	for _, n := range []int{1, 100, 514} {
		data := bytes.Repeat([]byte{byte(n)}, n)
		if err := WriteBlob(path, data, true); err != nil {
			t.Fatal(err)
		}
		got, err := ReadBlob(path, 514)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: %v", n, err)
		}
	}
	for _, n := range []int{0, 515, 4096} {
		if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadBlob(path, 514); got != nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("%d bytes: %v, %v", n, got, err)
		}
	}
}

func TestWriteBlobNeverReplacesWhenAsked(t *testing.T) {
	path := filepath.Join(keyDir(t), "x.cert")
	if err := WriteBlob(path, []byte("one"), false); err != nil {
		t.Fatal(err)
	}
	if err := WriteBlob(path, []byte("two"), false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second write: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "one" {
		t.Fatalf("content %q", b)
	}
}

// The grown-file probe of the shared reader also guards blobs.
func TestBlobRejectsFileGrownAfterFstat(t *testing.T) {
	path := filepath.Join(keyDir(t), "x.cert")
	if err := os.WriteFile(path, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := afterFstat
	defer func() { afterFstat = orig }()
	afterFstat = func(p string) {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()
		f.Write([]byte{0})
	}
	if _, err := ReadBlob(path, 514); !errors.Is(err, ErrInvalid) {
		t.Fatalf("ReadBlob of a grown file: %v", err)
	}
}
