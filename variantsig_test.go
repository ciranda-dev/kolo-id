package koloid

import (
	"crypto/ed25519"
	"crypto/sha512"
	"math/big"
	"testing"
)

// Ed25519 signatures are not unique: the key holder can pick another nonce. This is a small stdlib-only (math/big) signer that does so,
// so the tests can build a real second valid signature of the same message. It is test code and never used by the library.
var (
	edP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edL = func() *big.Int {
		l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		return l
	}()
	edD = func() *big.Int {
		n := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), edP))
		return n.Mod(n, edP)
	}()
	edBase = func() [2]*big.Int {
		x, _ := new(big.Int).SetString("15112221349535400772501151409588531511454012693041857206046113283949847762202", 10)
		y, _ := new(big.Int).SetString("46316835694926478169428394003475163141307993866256225615783033603165251855960", 10)
		return [2]*big.Int{x, y}
	}()
)

func edAdd(a, b [2]*big.Int) [2]*big.Int {
	m := func(x, y *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(x, y), edP) }
	x1y2, x2y1, y1y2, x1x2 := m(a[0], b[1]), m(b[0], a[1]), m(a[1], b[1]), m(a[0], b[0])
	t := m(edD, m(x1x2, y1y2))
	xn := new(big.Int).Mod(new(big.Int).Add(x1y2, x2y1), edP)
	xd := new(big.Int).Mod(new(big.Int).Add(big.NewInt(1), t), edP)
	yn := new(big.Int).Mod(new(big.Int).Add(y1y2, x1x2), edP)
	yd := new(big.Int).Mod(new(big.Int).Sub(big.NewInt(1), t), edP)
	return [2]*big.Int{m(xn, new(big.Int).ModInverse(xd, edP)), m(yn, new(big.Int).ModInverse(yd, edP))}
}

func edMul(k *big.Int, p [2]*big.Int) [2]*big.Int {
	r := [2]*big.Int{big.NewInt(0), big.NewInt(1)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = edAdd(r, r)
		if k.Bit(i) == 1 {
			r = edAdd(r, p)
		}
	}
	return r
}

func edEncode(p [2]*big.Int) []byte {
	out := make([]byte, 32)
	y := p[1].Bytes() // big endian
	for i, b := range y {
		out[len(y)-1-i] = b
	}
	out[31] |= byte(p[0].Bit(0)) << 7
	return out
}

func leInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// variantSignature signs msg under context with the key of id, like Identity.sign but with a nonce derived from salt, so it differs from the
// deterministic signature of the same message.
func variantSignature(t testing.TB, id *Identity, context string, msg []byte, salt string) []byte {
	t.Helper()
	h := sha512.Sum512(id.key().Seed())
	h0 := append([]byte(nil), h[:32]...)
	h0[0] &= 248
	h0[31] &= 127
	h0[31] |= 64
	a := leInt(h0)
	pub := edEncode(edMul(a, edBase))
	if string(pub) != string(id.PublicKey()) {
		t.Fatal("the test signer does not reproduce the public key")
	}
	dom := append([]byte("SigEd25519 no Ed25519 collisions"), 0, byte(len(context)))
	dom = append(dom, context...)
	rh := sha512.Sum512(append(append([]byte(salt), h[32:]...), msg...))
	r := new(big.Int).Mod(leInt(rh[:]), edL)
	R := edEncode(edMul(r, edBase))
	kh := sha512.New()
	kh.Write(dom)
	kh.Write(R)
	kh.Write(pub)
	kh.Write(msg)
	k := new(big.Int).Mod(leInt(kh.Sum(nil)), edL)
	S := new(big.Int).Mod(new(big.Int).Add(r, new(big.Int).Mul(k, a)), edL)
	sb := S.Bytes()
	sig := make([]byte, 64)
	copy(sig, R)
	for i, b := range sb {
		sig[32+len(sb)-1-i] = b
	}
	if err := ed25519.VerifyWithOptions(id.PublicKey(), msg, sig, &ed25519.Options{Context: context}); err != nil {
		t.Fatalf("the variant signature does not verify: %v", err)
	}
	return sig
}

func TestVariantSignatureIsAnotherValidSignature(t *testing.T) {
	id := idFrom(t, 0x51)
	msg := []byte("same message")
	a := mustSign(t, id, testContext, msg)
	b := variantSignature(t, id, testContext, msg, "x")
	if string(a) == string(b) {
		t.Fatal("not different")
	}
	if !Verify(id.PublicKey(), testContext, msg, a) || !Verify(id.PublicKey(), testContext, msg, b) {
		t.Fatal("both must verify")
	}
}
