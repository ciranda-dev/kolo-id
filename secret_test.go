package koloid

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Distinct bytes 0x10..0x2f, easy to spot in any output.
func leakSeed() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(0x10 + i)
	}
	return s
}

func assertNoSeed(t *testing.T, how, out string, seed []byte) {
	t.Helper()
	priv := append([]byte(nil), seed...) // the seed is the first half of the private key
	forms := []string{
		string(seed),
		hex.EncodeToString(seed[:8]),
		strings.ToUpper(hex.EncodeToString(seed[:8])),
		base64.StdEncoding.EncodeToString(priv)[:10],
		base64.RawURLEncoding.EncodeToString(priv)[:10],
		"16 17 18 19 20",         // decimal, as fmt prints byte slices
		"0x10, 0x11, 0x12, 0x13", // %#v of a byte slice
		`\x10\x11\x12\x13`,       // %q
	}
	for _, f := range forms {
		if strings.Contains(out, f) {
			t.Errorf("%s leaks the seed (found %q) in: %s", how, f, out)
		}
	}
}

func TestIdentityNeverPrintsSeed(t *testing.T) {
	seed := leakSeed()
	id, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub := id.PublicKeyString()

	verbs := []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q"}
	values := map[string]any{
		"*Identity":              id,
		"Identity":               *id,
		"exported pointer field": struct{ ID *Identity }{id},
		"exported value field":   struct{ ID Identity }{*id},
		"unexported value field": struct{ id Identity }{*id},
		"slice":                  []*Identity{id},
		"map":                    map[string]Identity{"me": *id},
	}
	for name, v := range values {
		for _, verb := range verbs {
			out := fmt.Sprintf(verb, v)
			assertNoSeed(t, fmt.Sprintf("fmt %s of %s", verb, name), out, seed)
		}
		assertNoSeed(t, "fmt.Sprint of "+name, fmt.Sprint(v), seed)
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if out := fmt.Sprintf(verb, id); !strings.Contains(out, pub) {
			t.Errorf("fmt %s = %q, want the public key %s", verb, out, pub)
		}
	}

	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		l := slog.New(h)
		l.Info("identity", "ptr", id, "val", *id, "nested", struct{ id Identity }{*id})
	}
	assertNoSeed(t, "log/slog", buf.String(), seed)
	if !strings.Contains(buf.String(), pub) {
		t.Errorf("log/slog output has no public key: %s", buf.String())
	}

	jsonValues := map[string]any{
		"*Identity":              id,
		"Identity":               *id,
		"value field":            struct{ ID Identity }{*id},
		"pointer to value field": &struct{ ID Identity }{*id},
		"pointer field":          struct{ ID *Identity }{id},
	}
	for name, v := range jsonValues {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal(%s): %v", name, err)
		}
		assertNoSeed(t, "encoding/json of "+name, string(b), seed)
	}
	for _, name := range []string{"*Identity", "pointer to value field", "pointer field"} {
		b, _ := json.Marshal(jsonValues[name])
		if !strings.Contains(string(b), `"`+pub+`"`) {
			t.Errorf("encoding/json of %s = %s, want the public key", name, b)
		}
	}
	// A plain Identity value encodes as {}, as documented; how fmt prints it is not pinned.
	for name, want := range map[string]string{"Identity": `{}`, "value field": `{"ID":{}}`} {
		if b, _ := json.Marshal(jsonValues[name]); string(b) != want {
			t.Errorf("encoding/json of %s = %s, want %s", name, b, want)
		}
	}
}

func TestIdentityNotDecodable(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	text, err := id.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	if err := new(Identity).UnmarshalText(text); !errors.Is(err, ErrNotDecodable) {
		t.Errorf("UnmarshalText error = %v, want %v", err, ErrNotDecodable)
	}
	if err := new(Identity).UnmarshalJSON([]byte(`"` + string(text) + `"`)); !errors.Is(err, ErrNotDecodable) {
		t.Errorf("UnmarshalJSON error = %v, want %v", err, ErrNotDecodable)
	}
	var v Identity
	for _, in := range []string{`"` + string(text) + `"`, `{}`, `null`, `{"seed":"00"}`, `123`} {
		if err := json.Unmarshal([]byte(in), &v); !errors.Is(err, ErrNotDecodable) {
			t.Errorf("json.Unmarshal(%s) into Identity = %v, want %v", in, err, ErrNotDecodable)
		}
	}
	if b, err := json.Marshal(id); err != nil || string(b) != `"`+id.PublicKeyString()+`"` {
		t.Errorf("json.Marshal(*Identity) = %s, %v, want the public key string", b, err)
	}
	if _, err := json.Marshal(&Identity{}); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("json.Marshal of a zero Identity = %v, want %v", err, ErrInvalidIdentity)
	}
	var p struct{ ID *Identity }
	if err := json.Unmarshal([]byte(`{"ID":"`+string(text)+`"}`), &p); !errors.Is(err, ErrNotDecodable) {
		t.Errorf("json.Unmarshal into a *Identity field = %v, want %v", err, ErrNotDecodable)
	}
	if p.ID.valid() {
		t.Error("json.Unmarshal produced a usable identity")
	}
}

// Pins the documented edge cases: neither yields a usable Identity.
func TestIdentityPointerFieldDecoding(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	p := struct{ ID *Identity }{id}
	if err := json.Unmarshal([]byte(`{"ID":null}`), &p); err != nil || p.ID != nil {
		t.Errorf(`json.Unmarshal({"ID":null}) = %v, ID = %v, want nil error and a nil ID`, err, p.ID)
	}

	var q struct{ ID *Identity }
	if err := json.Unmarshal([]byte(`{"ID":"`+id.PublicKeyString()+`"}`), &q); !errors.Is(err, ErrNotDecodable) {
		t.Fatalf("json.Unmarshal into a *Identity field = %v, want %v", err, ErrNotDecodable)
	}
	if q.ID == nil {
		t.Fatal("failed decode left a nil ID, want a non-nil zero Identity")
	}
	if _, err := q.ID.Sign(testContext, []byte("x")); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("Sign on the zero Identity left by a failed decode = %v, want %v", err, ErrInvalidIdentity)
	}
	path := filepath.Join(keyDir(t), "id.key")
	if err := q.ID.Save(path); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("Save on the zero Identity left by a failed decode = %v, want %v", err, ErrInvalidIdentity)
	}
}

type fmtState struct{ strings.Builder }

func (*fmtState) Width() (int, bool)     { return 0, false }
func (*fmtState) Precision() (int, bool) { return 0, false }
func (*fmtState) Flag(int) bool          { return false }

func TestZeroIdentity(t *testing.T) {
	for name, id := range map[string]*Identity{"nil": nil, "zero": {}} {
		if k := id.PublicKey(); k != nil {
			t.Errorf("%s: PublicKey = %x, want nil", name, k)
		}
		if s := id.PublicKeyString(); s != "" {
			t.Errorf("%s: PublicKeyString = %q, want empty", name, s)
		}
		if _, err := id.Sign(testContext, []byte("x")); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: Sign error = %v, want %v", name, err, ErrInvalidIdentity)
		}
		path := filepath.Join(keyDir(t), "id.key")
		if err := id.Save(path); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: Save error = %v, want %v", name, err, ErrInvalidIdentity)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: Save created a file", name)
		}
		// Direct calls: fmt and slog would swallow a panic.
		for _, s := range []string{id.String(), id.GoString(), id.LogValue().String()} {
			if s != "koloid.Identity{invalid}" {
				t.Errorf("%s: got %q, want koloid.Identity{invalid}", name, s)
			}
		}
		if _, err := id.MarshalText(); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: MarshalText error = %v, want %v", name, err, ErrInvalidIdentity)
		}
		var st fmtState
		id.Format(&st, 'v')
		if st.String() != "koloid.Identity{invalid}" {
			t.Errorf("%s: Format wrote %q, want koloid.Identity{invalid}", name, st.String())
		}
		want := strings.TrimSpace(strings.Repeat("koloid.Identity{invalid} ", 5))
		if out := fmt.Sprintf("%v %+v %#v %s %x", id, id, id, id, id); out != want {
			t.Errorf("%s: fmt = %q, want %q", name, out, want)
		}
	}
}

func TestSaveReplacesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra privileges on Windows")
	}
	umask0(t)
	dir := keyDir(t)
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id.key")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		t.Fatalf("path is %v after Save, want a regular file", info.Mode())
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %o, want 600", got)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "untouched" {
		t.Fatalf("symlink target changed: %q, %v", b, err)
	}
	j, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !id.PublicKey().Equal(j.PublicKey()) {
		t.Fatal("public key differs after Load")
	}
}

func TestSaveOldDescriptorNeverSeesSeed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename over an open file")
	}
	path := filepath.Join(keyDir(t), "id.key")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	old, err := os.Open(path) // a reader that opened the file while it was 0644
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	id, err := FromSeed(leakSeed())
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(path); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, _ := old.ReadAt(b, 0)
	if string(b[:n]) != "old" {
		t.Fatalf("old descriptor reads %x, want the old contents", b[:n])
	}
}

func TestSaveLeavesNoTempFiles(t *testing.T) {
	dir := keyDir(t)
	id, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := id.Save(filepath.Join(dir, "id.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := id.Save(filepath.Join(dir, "sub")); err == nil {
		t.Fatal("Save over a directory succeeded")
	}
	if err := id.Save(filepath.Join(dir, "id.key", "id.key")); err == nil {
		t.Fatal("Save under a regular file succeeded")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "id.key,sub" {
		t.Fatalf("directory holds %v, want [id.key sub]", names)
	}
}

func TestLoadRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need extra privileges on Windows")
	}
	dir := keyDir(t)
	target := filepath.Join(dir, "real.key")
	if err := os.WriteFile(target, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "id.key")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); !errors.Is(err, ErrInvalidKeyFile) {
		t.Fatalf("Load of a symlink to a valid key file returned %v, want %v", err, ErrInvalidKeyFile)
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	dir := keyDir(t)
	for _, n := range []int{0, 31, 33, 1 << 20} {
		path := filepath.Join(dir, fmt.Sprintf("size-%d.key", n))
		if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); !errors.Is(err, ErrInvalidKeyFile) {
			t.Errorf("Load of a %d-byte file returned %v, want %v", n, err, ErrInvalidKeyFile)
		}
	}
	if _, err := Load(dir); !errors.Is(err, ErrInvalidKeyFile) {
		t.Errorf("Load of a directory returned %v, want %v", err, ErrInvalidKeyFile)
	}
	if _, err := Load(filepath.Join(dir, "missing.key")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load of a missing file returned %v, want os.ErrNotExist", err)
	}
}
