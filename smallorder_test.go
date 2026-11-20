package koloid

import (
	"crypto/ed25519"
	"fmt"
	"testing"
)

// The y coordinates of the small-order points (orders 1, 2, 4 and 8), canonical and not,
// little-endian, sign bit clear.
var smallOrderBlocklist = [][32]byte{
	{0x00}, // 0, order 4
	{0x01}, // 1, order 1 (the identity)
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}, // order 8
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}, // order 8
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p-1, order 2
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p, non-canonical 0, order 4
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p+1, non-canonical 1, order 1
}

// smallOrderEncodings returns the 14 encodings: each blocklist entry with the sign bit clear and set.
func smallOrderEncodings() [][32]byte {
	var out [][32]byte
	for _, y := range smallOrderBlocklist {
		neg := y
		neg[31] |= 0x80
		out = append(out, y, neg)
	}
	return out
}

// forgedSig is R = the identity point, S = 0: it verifies for any message whose
// challenge k makes [k]A the identity, which a small-order A allows without any private key.
func forgedSig() []byte {
	sig := make([]byte, 64)
	sig[0] = 1
	return sig
}

// forgedMessage returns a message for which Go's crypto/ed25519 accepts forgedSig under pub, if one is found.
func forgedMessage(pub []byte) ([]byte, bool) {
	for i := range 256 { // an order-8 key misses all 256 with probability (7/8)^256, about 1e-15
		msg := []byte(fmt.Sprintf("forged %d", i))
		if ed25519.VerifyWithOptions(pub, msg, forgedSig(), &ed25519.Options{Context: testContext}) == nil {
			return msg, true
		}
	}
	return nil, false
}

func TestVerifyRejectsSmallOrderKeys(t *testing.T) {
	encs := smallOrderEncodings()
	if len(encs) != 14 {
		t.Fatalf("got %d small-order encodings, want 14", len(encs))
	}
	for _, enc := range encs {
		pub := enc[:]
		msg, ok := forgedMessage(pub)
		if !ok {
			t.Errorf("%x: crypto/ed25519 accepts no forged signature, so it is not an encoding Go accepts", pub)
			continue
		}
		if Verify(pub, testContext, msg, forgedSig()) {
			t.Errorf("Verify accepted a signature forged without a private key for the small-order key %x", pub)
		}
	}
}

func TestGeneratedKeysAreNotSmallOrder(t *testing.T) {
	encs := smallOrderEncodings()
	check := func(id *Identity) {
		t.Helper()
		pub := id.PublicKey()
		if smallOrder(pub) {
			t.Fatalf("smallOrder(%x) is true for a generated key", pub)
		}
		for _, enc := range encs {
			if string(pub) == string(enc[:]) {
				t.Fatalf("key %x is a small-order point", pub)
			}
		}
		if _, ok := forgedMessage(pub); ok {
			t.Fatalf("a signature forged without a private key verifies under %x", pub)
		}
	}
	for _, seed := range [][]byte{make([]byte, 32), {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		id, err := FromSeed(seed)
		if err != nil {
			t.Fatal(err)
		}
		check(id)
	}
	for range 32 {
		id, err := Generate()
		if err != nil {
			t.Fatal(err)
		}
		check(id)
	}
}

func TestVerifyNeverPanicsOn32ByteKeys(t *testing.T) {
	keys := [][]byte{make([]byte, 32), bytesOf(0xff, 32), bytesOf(0x80, 32)}
	for _, enc := range smallOrderEncodings() {
		keys = append(keys, enc[:])
	}
	for b := range 256 {
		k := make([]byte, 32)
		k[0], k[31] = byte(b), byte(b)
		keys = append(keys, k)
	}
	for _, k := range keys {
		Verify(k, testContext, []byte("m"), forgedSig())
		Verify(k, testContext, []byte("m"), make([]byte, 64))
	}
}

func bytesOf(b byte, n int) []byte {
	s := make([]byte, n)
	for i := range s {
		s[i] = b
	}
	return s
}

// Cross-checks the list on the only non-canonical encodings, y = p+i for i < 19 (p = 2^255-19):
// crypto/ed25519 accepts a forged signature exactly for the two the list names, p and p+1.
func TestNonCanonicalSmallOrderEncodings(t *testing.T) {
	listed := map[[32]byte]bool{}
	for _, enc := range smallOrderEncodings() {
		listed[enc] = true
	}
	for i := range 19 {
		for _, sign := range []byte{0, 0x80} {
			var enc [32]byte
			copy(enc[:], bytesOf(0xff, 32))
			enc[0] = byte(0xed + i)
			enc[31] = 0x7f | sign
			_, forged := forgedMessage(enc[:])
			if forged != listed[enc] {
				t.Errorf("%x: forgery accepted = %v, listed = %v", enc, forged, listed[enc])
			}
		}
	}
}
