package keyfile

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// keyDir returns a temp directory with mode 0700, as Load requires; t.TempDir honors the umask.
func keyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// Proves the trailing 1-byte probe: the file grows after the fstat size check.
func TestLoadRejectsFileGrownAfterFstat(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
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
		if _, err := f.Write([]byte{0}); err != nil {
			t.Error(err)
		}
	}
	if _, err := load(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load of a file grown after fstat returned %v, want %v", err, ErrInvalid)
	}
}

// Guards the build tags: these platforms must never fall back to os.Root path opens.
func TestNoFollowPlatforms(t *testing.T) {
	want := slices.Contains([]string{"linux", "android", "darwin", "ios"}, runtime.GOOS)
	for name, got := range map[string]bool{"noFollowOpen": noFollowOpen, "dirByFD": dirByFD} {
		if got != want {
			t.Errorf("on %s %s = %v, want %v", runtime.GOOS, name, got, want)
		}
	}
}

// testKey stands in for koloid.Identity.
type testKey struct{ seed [SeedSize]byte }

func generate() (*testKey, error) {
	var k testKey
	_, err := rand.Read(k.seed[:])
	return &k, err
}

func (k *testKey) Save(path string) error    { return Write(path, k.seed[:], true) }
func (k *testKey) SaveNew(path string) error { return Write(path, k.seed[:], false) }

func (k *testKey) PublicKey() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(k.seed[:]).Public().(ed25519.PublicKey)
}

func load(path string) (*testKey, error) {
	var k testKey
	if err := Read(path, &k.seed); err != nil {
		return nil, err
	}
	return &k, nil
}
