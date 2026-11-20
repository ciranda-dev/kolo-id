package koloid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testContext = "kolo-id/test/v0"

// keyDir returns a temp directory with mode 0700, as Load requires; t.TempDir honors the umask.
func keyDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSignVerify(t *testing.T) {
	i, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello kolo")
	sig, err := i.Sign(testContext, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(i.PublicKey(), testContext, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	msg[0] ^= 1
	if Verify(i.PublicKey(), testContext, msg, sig) {
		t.Fatal("tampered message accepted")
	}
}

func TestSignatureBoundToContext(t *testing.T) {
	i, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello kolo")
	sig, err := i.Sign("kolo-a/v0", msg)
	if err != nil {
		t.Fatal(err)
	}
	if Verify(i.PublicKey(), "kolo-b/v0", msg, sig) {
		t.Fatal("signature accepted under another context")
	}
	if ed25519.Verify(i.PublicKey(), msg, sig) {
		t.Fatal("context signature accepted as plain Ed25519")
	}
}

func TestInvalidContext(t *testing.T) {
	i, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello kolo")
	sig, err := i.Sign(testContext, msg)
	if err != nil {
		t.Fatal(err)
	}
	for _, ctx := range []string{"", strings.Repeat("x", 256)} {
		if _, err := i.Sign(ctx, msg); !errors.Is(err, ErrInvalidContext) {
			t.Errorf("Sign with a %d-byte context returned %v, want %v", len(ctx), err, ErrInvalidContext)
		}
		if Verify(i.PublicKey(), ctx, msg, sig) {
			t.Errorf("Verify accepted a %d-byte context", len(ctx))
		}
	}
	if _, err := i.Sign(strings.Repeat("x", 255), msg); err != nil {
		t.Errorf("Sign rejected a 255-byte context: %v", err)
	}
}

func TestSignKnownAnswer(t *testing.T) {
	// RFC 8032, section 7.2, Ed25519ctx vector "foo".
	seed := mustHex(t, "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6")
	msg := mustHex(t, "f726936d19c800494e3fdaff20b276a8")
	want := mustHex(t, "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a"+
		"8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d")
	i, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := i.PublicKeyString(); got != "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292" {
		t.Fatalf("public key = %s", got)
	}
	sig, err := i.Sign("foo", msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, want) {
		t.Fatalf("signature = %x, want %x", sig, want)
	}
	if !Verify(i.PublicKey(), "foo", msg, want) {
		t.Fatal("RFC 8032 signature rejected")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSaveLoad(t *testing.T) {
	i, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(keyDir(t), "id.key")
	if err := i.Save(path); err != nil {
		t.Fatal(err)
	}
	j, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !i.PublicKey().Equal(j.PublicKey()) {
		t.Fatal("public key differs after Load")
	}
}

func TestLoadInvalid(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, make([]byte, 10), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("Load returned %v, want %v", err, ErrInvalidKeyFile)
	}
}

func TestFromSeedInvalid(t *testing.T) {
	for _, n := range []int{0, 10, 31, 33, 64} {
		if _, err := FromSeed(make([]byte, n)); err == nil {
			t.Errorf("FromSeed accepted a %d-byte seed", n)
		}
	}
	if _, err := FromSeed(nil); err == nil {
		t.Error("FromSeed accepted a nil seed")
	}
}

func TestFromSeedDeterministic(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	a, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	b, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !a.PublicKey().Equal(b.PublicKey()) {
		t.Fatal("same seed produced different public keys")
	}
}

func TestPublicKeyString(t *testing.T) {
	// Test vector 1 from RFC 8032, section 7.1.
	seed := []byte{
		0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
		0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
		0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
		0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	}
	want := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	i, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if got := i.PublicKeyString(); got != want {
		t.Fatalf("PublicKeyString() = %s, want %s", got, want)
	}
}

func TestVerifyBadPublicKey(t *testing.T) {
	i, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello kolo")
	sig, err := i.Sign(testContext, msg)
	if err != nil {
		t.Fatal(err)
	}
	pub := i.PublicKey()
	bad := [][]byte{nil, {}, pub[:31], append(pub, 0), make([]byte, 64)}
	for _, key := range bad {
		if Verify(key, testContext, msg, sig) {
			t.Errorf("Verify accepted a %d-byte public key", len(key))
		}
	}
}

func TestSaveFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes are not supported on Windows")
	}
	umask0(t)
	i, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(keyDir(t), "id.key")
	if err := i.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}
}

func TestSaveFixesExistingFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file modes are not supported on Windows")
	}
	umask0(t)
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	i, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := i.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}
	j, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !i.PublicKey().Equal(j.PublicKey()) {
		t.Fatal("public key differs after Load")
	}
}

func TestKeyPathMustNameAFile(t *testing.T) {
	dir := keyDir(t)
	t.Chdir(dir)
	keys := filepath.Join(dir, "keys")
	if err := os.Mkdir(keys, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	paths := []string{keys + sep, keys + "/", keys + sep + ".", keys + sep + "..", ""}
	if runtime.GOOS == "windows" { // Win32 path normalization drops trailing dots and spaces
		for _, name := range []string{". ", "...", ".. ", "id.key.", "id.key "} {
			paths = append(paths, keys+sep+name)
		}
	}
	for _, p := range paths {
		if err := id.Save(p); !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("Save(%q) returned %v, want %v", p, err, ErrInvalidKeyFile)
		}
		if err := id.SaveNew(p); !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("SaveNew(%q) returned %v, want %v", p, err, ErrInvalidKeyFile)
		}
		if _, err := Load(p); !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("Load(%q) returned %v, want %v", p, err, ErrInvalidKeyFile)
		}
	}
	for _, d := range []string{dir, keys} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		if want := map[string]int{dir: 1, keys: 0}[d]; len(entries) != want {
			t.Errorf("%s holds %v, want %d entries", d, entries, want)
		}
	}
}
