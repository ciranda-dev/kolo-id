package koloid

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// skipUnlessCI skips the test, or fails it in CI, where the tool must work.
func skipUnlessCI(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Fatalf(format, args...)
	}
	t.Skipf(format, args...)
}

func chmodACL(t *testing.T, entry, path string) {
	t.Helper()
	if out, err := exec.Command("/bin/chmod", "+a", entry, path).CombinedOutput(); err != nil {
		skipUnlessCI(t, "cannot set an ACL: %v %s", err, out)
	}
}

func TestLoadRejectsAllowACL(t *testing.T) {
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	chmodACL(t, "everyone deny write", path)
	if _, err := Load(path); err != nil {
		t.Fatalf("Load of a key file with only a deny ACL returned %v, want nil", err)
	}
	chmodACL(t, "everyone allow read", path)
	if _, err := Load(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Fatalf("Load of a key file with an allow ACL returned %v, want %v", err, ErrInsecureKeyFile)
	}
}

func TestLoadAndSaveRejectDirectoryAllowACL(t *testing.T) {
	dir := keyDir(t)
	path := filepath.Join(dir, "id.key")
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	chmodACL(t, "everyone allow list", dir)
	if _, err := Load(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("Load from a directory with an allow ACL returned %v, want %v", err, ErrInsecureKeyFile)
	}
	if err := id.Save(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("Save into a directory with an allow ACL returned %v, want %v", err, ErrInsecureKeyFile)
	}
}

func TestRejectsVolumeIgnoringOwners(t *testing.T) {
	base := keyDir(t)
	img, mnt := filepath.Join(base, "vol.dmg"), filepath.Join(base, "mnt")
	if err := os.Mkdir(mnt, 0o700); err != nil {
		t.Fatal(err)
	}
	hdiutil := func(args ...string) ([]byte, error) {
		return exec.Command("/usr/bin/hdiutil", args...).CombinedOutput()
	}
	if out, err := hdiutil("create", "-size", "4m", "-fs", "HFS+", "-volname", "koloidtest", "-o", img); err != nil {
		skipUnlessCI(t, "hdiutil create: %v %s", err, out)
	}
	if out, err := hdiutil("attach", img, "-owners", "off", "-nobrowse", "-mountpoint", mnt); err != nil {
		skipUnlessCI(t, "hdiutil attach: %v %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := hdiutil("detach", mnt, "-force"); err != nil {
			t.Errorf("hdiutil detach: %v %s", err, out)
		}
	})
	dir := filepath.Join(mnt, "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id.key")
	if err := id.Save(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("Save on a volume that ignores ownership returned %v, want %v", err, ErrInsecureKeyFile)
	}
	if err := os.WriteFile(path, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInsecureKeyFile) {
		t.Errorf("Load on a volume that ignores ownership returned %v, want %v", err, ErrInsecureKeyFile)
	}
}

func TestDenyOnlyDirectoryACLAccepted(t *testing.T) {
	dir := keyDir(t)
	chmodACL(t, "everyone deny add_subdirectory", dir)
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id.key")
	if err := id.Save(path); err != nil {
		t.Fatalf("Save into a directory with only a deny ACL: %v", err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load from a directory with only a deny ACL: %v", err)
	}
}

func TestSaveNewRejectsDirectoryAllowACL(t *testing.T) {
	dir := keyDir(t)
	chmodACL(t, "everyone allow list", dir)
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.SaveNew(filepath.Join(dir, "id.key")); !errors.Is(err, ErrInsecureKeyFile) {
		t.Fatalf("SaveNew into a directory with an allow ACL returned %v, want %v", err, ErrInsecureKeyFile)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("SaveNew left files: %v, %v", entries, err)
	}
}
