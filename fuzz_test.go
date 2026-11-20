package koloid

import (
	"bytes"
	"testing"
)

func FuzzVerify(f *testing.F) {
	id, err := FromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		f.Fatal(err)
	}
	msg := []byte("hello kolo")
	sig, err := id.Sign(testContext, msg)
	if err != nil {
		f.Fatal(err)
	}
	pub := id.PublicKey()
	f.Add([]byte(pub), testContext, msg, sig)
	f.Add([]byte{}, "", []byte{}, []byte{})
	f.Add([]byte(pub[:31]), testContext, msg, sig[:63])
	f.Add(make([]byte, 32), testContext, msg, forgedSig())
	f.Add(append([]byte{1}, make([]byte, 31)...), testContext, msg, forgedSig())

	f.Fuzz(func(t *testing.T, pub2 []byte, ctx string, msg2, sig2 []byte) {
		ok := Verify(pub2, ctx, msg2, sig2)
		real := bytes.Equal(pub2, pub) && ctx == testContext && bytes.Equal(msg2, msg)
		if ok && real && !bytes.Equal(sig2, sig) {
			t.Fatalf("a different signature verified: %x", sig2)
		}
		if ok && bytes.Equal(pub2, pub) && !real {
			t.Fatal("signature verified for another context or message")
		}
		if ok && smallOrder(pub2) {
			t.Fatalf("a signature verified under the small-order key %x", pub2)
		}
	})
}
