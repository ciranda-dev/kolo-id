package slip10

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func parsePath(t testing.TB, s string) []uint32 {
	t.Helper()
	var path []uint32
	for _, part := range strings.Split(s, "/")[1:] {
		n, err := strconv.ParseUint(strings.TrimSuffix(part, "H"), 10, 32)
		if err != nil || !strings.HasSuffix(part, "H") {
			t.Fatalf("path %q", s)
		}
		path = append(path, uint32(n)+Hardened)
	}
	return path
}

// The two ed25519 vectors of SLIP-0010: every chain, checking chain code, private key and public key.
func TestSLIP10Ed25519Vectors(t *testing.T) {
	f, err := os.Open("testdata/slip-0010-ed25519.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var seed []byte
	var seeds, chains int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		switch {
		case len(fields) == 0 || fields[0] == "#":
		case fields[0] == "seed":
			seed, _ = hex.DecodeString(fields[1])
			seeds++
		case fields[0] == "chain":
			key, chain, err := Derive(seed, parsePath(t, fields[1]))
			if err != nil {
				t.Fatal(err)
			}
			pub := ed25519.NewKeyFromSeed(key[:]).Public().(ed25519.PublicKey)
			if hex.EncodeToString(chain[:]) != fields[2] || hex.EncodeToString(key[:]) != fields[3] || "00"+hex.EncodeToString(pub) != fields[4] {
				t.Fatalf("chain %s: chain %x key %x pub %x", fields[1], chain, key, pub)
			}
			chains++
		}
	}
	if seeds != 2 || chains != 12 {
		t.Fatalf("%d seeds and %d chains in the vector file, want 2 and 12", seeds, chains)
	}
}

func TestSLIP10NonHardenedRejected(t *testing.T) {
	seed := make([]byte, 32)
	for _, path := range [][]uint32{{0}, {Hardened - 1}, {Hardened, 1}, {Hardened, Hardened, 0x7fffffff}} {
		if _, _, err := Derive(seed, path); !errors.Is(err, ErrNotHardened) {
			t.Fatalf("path %v: %v", path, err)
		}
	}
	if _, _, err := Derive(seed, []uint32{Hardened, 0xffffffff}); err != nil {
		t.Fatal(err)
	}
}

func TestSLIP10SeedLength(t *testing.T) {
	for n := 0; n <= 70; n++ {
		_, _, err := Derive(make([]byte, n), nil)
		if ok := n >= 16 && n <= 64; ok != (err == nil) || (!ok && !errors.Is(err, ErrSeedLength)) {
			t.Fatalf("seed of %d bytes: %v", n, err)
		}
	}
}

// FuzzSLIP10Path: no panic; a non-hardened index is refused; the output is 32 bytes and deterministic.
func FuzzSLIP10Path(f *testing.F) {
	f.Add(make([]byte, 16), uint32(Hardened), uint32(5))
	f.Add(make([]byte, 64), uint32(0), uint32(Hardened))
	f.Fuzz(func(t *testing.T, seed []byte, a, b uint32) {
		key, chain, err := Derive(seed, []uint32{a, b})
		switch {
		case len(seed) < 16 || len(seed) > 64:
			if !errors.Is(err, ErrSeedLength) {
				t.Fatalf("seed length %d: %v", len(seed), err)
			}
		case a < Hardened || b < Hardened:
			if !errors.Is(err, ErrNotHardened) {
				t.Fatalf("indices %d %d: %v", a, b, err)
			}
		default:
			k2, c2, err2 := Derive(seed, []uint32{a, b})
			if err != nil || err2 != nil || key != k2 || chain != c2 {
				t.Fatalf("derive: %v %v", err, err2)
			}
		}
	})
}

// Under GODEBUG=fips140=only hmac.New panics on the 12-byte master key; Derive must return an error before any hmac.New call.
func TestDeriveFIPSOnly(t *testing.T) {
	if os.Getenv("KOLO_ID_FIPS_CHILD") == "1" {
		for _, path := range [][]uint32{nil, {Hardened}} {
			_, _, err := Derive(make([]byte, 32), path)
			if !errors.Is(err, ErrFIPSOnly) || !errors.Is(err, errors.ErrUnsupported) || !strings.HasPrefix(err.Error(), "koloid: ") {
				t.Fatalf("Derive under fips140=only = %v", err)
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDeriveFIPSOnly$", "-test.v")
	cmd.Env = append(os.Environ(), "KOLO_ID_FIPS_CHILD=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestDeriveFIPSOnly") {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
}
