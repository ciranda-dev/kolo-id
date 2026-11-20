package koloid

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

// A second certificate of the approver key of w, for the same person.
func secondApproverCert(t testing.TB, w *world) *DeviceCert {
	return issue(t, w.P, w.A, w.P.PublicKey(), &IssueOptions{Serial: 2, IssuedAt: baseTime, Approver: true})
}

// The issuer signature of a leaf covers the SHA-256 of its parent, so the leaf cannot move to another certificate of the same approver key.
func TestLeafBoundToParent(t *testing.T) {
	w := newWorld(t)
	moved := *w.certD
	moved.parent = secondApproverCert(t, w)
	if _, err := DecodeDeviceCert(moved.Encode()); err != nil {
		t.Fatalf("the moved leaf is structurally valid: %v", err)
	}
	wantErr(t, "Verify", moved.Verify(w.opts), ErrCertSignature)
	sig := mustSign(t, w.D, testContext, []byte("m"))
	wantErr(t, "VerifyDevice", VerifyDevice(&moved, w.opts, testContext, []byte("m"), sig), ErrCertSignature)

	offer, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	other := *offer
	other.parent = moved.parent
	wantErr(t, "Accept", acceptErr(w.D, &other, w.P.PublicKey()), ErrCertSignature)
	if _, err := w.D.AcceptDeviceCert(offer, w.P.PublicKey()); err != nil {
		t.Errorf("the real parent: %v", err)
	}

	bodyOnly := *w.certD
	bodyOnly.issuerSig = [64]byte(mustSign(t, w.A, contextDeviceLink, w.certD.body.signedBytes()))
	wantErr(t, "a signature over the body alone", bodyOnly.Verify(w.opts), ErrCertSignature)
	// A root-issued certificate has no parent to bind: its signature is over the body alone.
	if err := w.certE.Verify(w.opts); err != nil {
		t.Errorf("root-issued: %v", err)
	}
}

// The signature of an approver-signed revocation covers the SHA-256 of its signer certificate.
func TestRevocationBoundToSignerCert(t *testing.T) {
	w := newWorld(t)
	r := revoke(t, w.A, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), SignerCert: w.certA, Target: w.certD})
	moved := *r
	moved.signerCert = secondApproverCert(t, w)
	if _, err := DecodeRevocation(moved.Encode()); err != nil {
		t.Fatalf("the moved record is structurally valid: %v", err)
	}
	wantErr(t, "Verify", moved.Verify(w.opts, w.certD), ErrCertSignature)
	if err := w.certD.Verify(w.with(&moved)); err != nil {
		t.Errorf("a moved record counted: %v", err)
	}
	bodyOnly := *r
	bodyOnly.sig = [64]byte(mustSign(t, w.A, contextDeviceRevoke, r.signedBytes()))
	wantErr(t, "a signature over the body alone", bodyOnly.Verify(w.opts, w.certD), ErrCertSignature)
	if err := r.Verify(w.opts, w.certD); err != nil {
		t.Errorf("the real record: %v", err)
	}
}

func TestReservedContexts(t *testing.T) {
	w := newWorld(t)
	for _, ctx := range []string{contextDeviceLink, contextDeviceAccept, contextDeviceRevoke, "kolo-id/device-", "kolo-id/device-x", "kolo-id/device-" + strings.Repeat("y", 200)} {
		if s, err := w.D.Sign(ctx, []byte("m")); s != nil || !errors.Is(err, ErrInvalidContext) {
			t.Errorf("Sign under %q: %v, %v", ctx, s, err)
		}
		// A signature made by the library under the context is refused by VerifyDevice, even though it is a real device signature.
		sig := mustSign(t, w.D, ctx, []byte("m"))
		wantErr(t, "VerifyDevice under "+ctx, VerifyDevice(w.certD, w.opts, ctx, []byte("m"), sig), ErrInvalidArgument)
		if !Verify(w.D.PublicKey(), ctx, []byte("m"), sig) {
			t.Errorf("plain Verify must still check %q: the library uses it", ctx)
		}
	}
	for _, ctx := range []string{"kolo-id/device", "kolo-id/devices/v0", "kolo-id/Device-x", "kolo-id/test/v0", "xkolo-id/device-x", "kolo-ids/device-x"} {
		sig, err := w.D.Sign(ctx, []byte("m"))
		if err != nil {
			t.Errorf("Sign under %q: %v", ctx, err)
			continue
		}
		if err := VerifyDevice(w.certD, w.opts, ctx, []byte("m"), sig); err != nil {
			t.Errorf("VerifyDevice under %q: %v", ctx, err)
		}
	}
	var none *Identity
	if _, err := none.Sign("kolo-id/device-x", nil); err == nil {
		t.Error("nil identity")
	}
}

func TestIdentityClear(t *testing.T) {
	id := idFrom(t, 0x41)
	pub := id.PublicKey()
	cp := *id // a copy shares the key, so it must be cleared too
	key := id.key()
	if len(key) != 64 || bytes.Equal(key, make([]byte, 64)) {
		t.Fatal("setup")
	}
	id.Clear()
	if !bytes.Equal(key, make([]byte, 64)) {
		t.Error("the private key bytes were not zeroed")
	}
	for name, i := range map[string]*Identity{"original": id, "copy": &cp} {
		if i.valid() || i.PublicKey() != nil {
			t.Errorf("%s: still valid after Clear", name)
		}
		if _, err := i.Sign(testContext, []byte("m")); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: Sign = %v", name, err)
		}
		if err := i.Save(t.TempDir() + "/id.key"); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: Save = %v", name, err)
		}
		if _, err := i.OfferDeviceCert(pub, &IssueOptions{Serial: 1}); !errors.Is(err, ErrInvalidIdentity) {
			t.Errorf("%s: OfferDeviceCert = %v", name, err)
		}
		if s := i.String(); s != "koloid.Identity{invalid}" {
			t.Errorf("%s: String = %q", name, s)
		}
	}
	id.Clear()
	(*Identity)(nil).Clear()
	(&Identity{}).Clear()
	// Another identity from the same seed is not affected.
	again := idFrom(t, 0x41)
	if !bytes.Equal(again.PublicKey(), pub) {
		t.Error("a new identity from the same seed")
	}
	again.Clear()
	seed := bytes.Repeat([]byte{0x42}, 32)
	made, err := FromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	made.Clear()
	if !bytes.Equal(seed, bytes.Repeat([]byte{0x42}, 32)) {
		t.Error("Clear changed the caller's seed")
	}
}

func TestOfferExpiryAtOrBeforeTheEpoch(t *testing.T) {
	w := newWorld(t)
	for _, exp := range []time.Time{time.Unix(0, 0), time.Unix(-1, 0), time.Unix(0, 999_999_999), time.Unix(-1<<40, 0)} {
		offer, err := w.P.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: time.Unix(0, 0), ExpiresAt: exp})
		if offer != nil || !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("ExpiresAt %v: %v, %v", exp, offer, err)
		}
	}
	// One second after the epoch is a real expiry; the zero time is "never".
	c := issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: time.Unix(0, 0), ExpiresAt: time.Unix(1, 0)})
	if !c.ExpiresAt().Equal(time.Unix(1, 0)) {
		t.Errorf("ExpiresAt = %v", c.ExpiresAt())
	}
	if c := issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: time.Unix(0, 0)}); !c.ExpiresAt().IsZero() {
		t.Errorf("never: %v", c.ExpiresAt())
	}
}

func TestTimesAreWholeSeconds(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	c := issue(t, w.P, w.E, pp, &IssueOptions{Serial: 1, IssuedAt: baseTime.Add(500 * time.Millisecond), ExpiresAt: baseTime.Add(10*time.Second + 900*time.Millisecond)})
	if !c.IssuedAt().Equal(baseTime) || !c.ExpiresAt().Equal(baseTime.Add(10*time.Second)) {
		t.Errorf("issued %v expires %v", c.IssuedAt(), c.ExpiresAt())
	}
	// A fractional expiry comes up to a second early.
	wantErr(t, "at the truncated second", c.Verify(&VerifyOptions{Person: pp, Now: baseTime.Add(10 * time.Second)}), ErrCertExpired)
	if err := c.Verify(&VerifyOptions{Person: pp, Now: baseTime.Add(9 * time.Second)}); err != nil {
		t.Errorf("a second before: %v", err)
	}
	// An expiry in the issue second is not after the issue time.
	_, err := w.P.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime, ExpiresAt: baseTime.Add(900 * time.Millisecond)})
	wantErr(t, "expiry in the issue second", err, ErrInvalidArgument)
	r := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.E.PublicKey(), UpToSerial: 1, At: baseTime.Add(999 * time.Millisecond)})
	if r.revokedAt != uint64(baseTime.Unix()) {
		t.Errorf("revokedAt = %d", r.revokedAt)
	}
}

// The sizes of docs/limits.md at the largest values, and the bound is checked before parsing.
func TestOfferAndLimitSizes(t *testing.T) {
	w := newWorld(t)
	big, max := time.Unix(math.MaxInt64-1, 0), time.Unix(math.MaxInt64, 0)
	a := issue(t, w.P, w.A, w.P.PublicKey(), &IssueOptions{Serial: math.MaxUint64, IssuedAt: big, ExpiresAt: max, Approver: true})
	child, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: a, Serial: math.MaxUint64, IssuedAt: big, ExpiresAt: max})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(child.Encode()); n != 450 || maxOfferSize != 450 {
		t.Errorf("offer with a parent is %d bytes, want 450", n)
	}
	rootOffer, err := w.P.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Serial: math.MaxUint64, IssuedAt: big, ExpiresAt: max})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(rootOffer.Encode()); n != 192 {
		t.Errorf("root-issued offer is %d bytes, want 192", n)
	}
	if _, err := DecodeCertOffer(child.Encode()); err != nil {
		t.Errorf("the largest offer: %v", err)
	}
	tooLarge := func(what string, err error, want error) {
		t.Helper()
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "too large") {
			t.Errorf("%s: %v", what, err)
		}
	}
	_, err = DecodeCertOffer(append(child.Encode(), 0))
	tooLarge("451-byte offer", err, ErrInvalidCert)
	d := issue(t, w.A, w.D, w.P.PublicKey(), &IssueOptions{Parent: a, Serial: math.MaxUint64, IssuedAt: big, ExpiresAt: max})
	_, err = DecodeDeviceCert(append(d.Encode(), 0))
	tooLarge("515-byte certificate", err, ErrInvalidCert)
	r := revoke(t, w.A, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), SignerCert: a, Target: d, At: max})
	_, err = DecodeRevocation(append(r.Encode(), 0))
	tooLarge("473-byte revocation", err, ErrInvalidRevocation)
	if n := len(r.Encode()); n != 472 || maxRevocationSize != 472 {
		t.Errorf("revocation is %d bytes, want 472", n)
	}
	if _, err := DecodeRevocation(r.Encode()); err != nil {
		t.Errorf("the largest revocation: %v", err)
	}
}

// Every error is one line that starts with "koloid:", and both sentinels of a combined error still match.
func TestErrorsAreOneLine(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	var errs []error
	add := func(err error) { errs = append(errs, err) }

	_, err := w.P.OfferDeviceCert(pp, &IssueOptions{Serial: 1})
	wantErr(t, "offer for the person key", err, ErrInvalidArgument)
	wantErr(t, "offer for the person key", err, ErrInvalidCert)
	add(err)
	_, err = w.P.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Serial: 0})
	wantErr(t, "offer, serial zero", err, ErrInvalidArgument)
	wantErr(t, "offer, serial zero", err, ErrInvalidCert)
	if err.Error() != "koloid: invalid argument: serial is zero" {
		t.Errorf("offer, serial zero: %q", err)
	}
	add(err)
	_, err = w.P.RevokeDevice(&RevokeOptions{Person: pp, Device: dev, UpToSerial: 0})
	wantErr(t, "revoke, serial zero", err, ErrInvalidArgument)
	wantErr(t, "revoke, serial zero", err, ErrInvalidRevocation)
	if err.Error() != "koloid: invalid argument: serial is zero" {
		t.Errorf("revoke, serial zero: %q", err)
	}
	add(err)
	_, err = w.E.RevokeDevice(&RevokeOptions{Person: pp, Device: dev, UpToSerial: 1})
	wantErr(t, "revoke without a signer certificate", err, ErrInvalidArgument)
	wantErr(t, "revoke without a signer certificate", err, ErrInvalidRevocation)
	add(err)
	_, err = w.A.RevokeDevice(&RevokeOptions{Person: pp, Device: dev, SignerCert: foreignApprover(t, w.A), Target: w.certD})
	wantErr(t, "revoke, foreign signer certificate", err, ErrInvalidArgument)
	wantErr(t, "revoke, foreign signer certificate", err, ErrInvalidRevocation)
	add(err)
	_, err = w.D.Sign(contextDeviceLink, nil)
	add(err)
	_, err = w.D.Sign("", nil)
	add(err)
	add(VerifyDevice(w.certD, w.opts, contextDeviceRevoke, nil, nil))

	r := revoke(t, w.A, &RevokeOptions{Person: pp, Device: dev, SignerCert: w.certA, Target: w.certD})
	offer, err := w.A.OfferDeviceCert(dev, &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range [][]byte{w.certD.Encode(), w.certE.Encode(), offer.Encode(), r.Encode()} {
		for i := range enc {
			mut := bytes.Clone(enc)
			mut[i] ^= 0xff
			for _, cut := range [][]byte{mut, enc[:i], append(bytes.Clone(enc), mut[i:]...)} {
				_, e1 := DecodeDeviceCert(cut)
				_, e2 := DecodeCertOffer(cut)
				_, e3 := DecodeRevocation(cut)
				add(e1)
				add(e2)
				add(e3)
			}
			if rv, e := DecodeRevocation(mut); e == nil {
				add(rv.Verify(w.opts, w.certD))
				add(rv.Verify(w.opts, nil))
			}
			if c, e := DecodeDeviceCert(mut); e == nil {
				add(c.Verify(w.opts))
			}
		}
	}
	// A hand-built revocation whose signer certificate breaks a structure rule.
	for _, mod := range []func(c *DeviceCert){func(c *DeviceCert) { c.body.serial = 0 }, func(c *DeviceCert) { c.body.flags = 2 }} {
		c := *w.certA
		mod(&c)
		bad := handRecord(t, w, w.A, &c, w.certD, 1)
		err := bad.Verify(w.opts, w.certD)
		wantErr(t, "signer certificate structure", err, ErrInvalidRevocation)
		wantErr(t, "signer certificate structure", err, ErrInvalidCert)
		if !strings.HasPrefix(err.Error(), "koloid: invalid revocation: signer certificate: ") {
			t.Errorf("signer certificate structure: %q", err)
		}
		add(err)
	}
	add(r.Verify(w.opts, nil))
	add(r.Verify(nil, nil))
	add((*Revocation)(nil).Verify(w.opts, nil))
	add(w.certD.Verify(&VerifyOptions{Person: w.E.PublicKey()}))
	add(SaveCert(t.TempDir()+"/x.cert", nil))
	_, e := ParsePhrase("abandon")
	add(e)
	_, e = ParsePhrase(strings.Repeat("abandon ", 24))
	add(e)
	_, e = ParsePhrase(strings.Repeat("zzz ", 24))
	add(e)

	seen := 0
	for _, e := range errs {
		if e == nil {
			continue
		}
		seen++
		if s := e.Error(); !strings.HasPrefix(s, "koloid: ") || strings.ContainsAny(s, "\r\n") || strings.Count(s, "koloid:") != 1 {
			t.Fatalf("error text %q is not one line with one koloid: prefix", s)
		}
	}
	if seen < 100 {
		t.Fatalf("only %d errors collected", seen)
	}
}

// A hostile list costs at most one signature check per record and two per distinct signer certificate; v.checks counts them.
func TestRevocationWorkIsBounded(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	const n = 2000
	record := func(i int, device []byte, signerCert *DeviceCert) *Revocation {
		r := &Revocation{upToSerial: 1, revokedAt: uint64(i + 1), signerCert: signerCert, target: certHash(w.certD)}
		copy(r.person[:], pp)
		copy(r.device[:], device)
		copy(r.signer[:], w.A.PublicKey())
		r.sig = [64]byte(mustSign(t, w.A, contextDeviceRevoke, r.sigBytes()))
		return r
	}
	run := func(revs []*Revocation) (checks int, err error) {
		v, err := newVerifier(w.with(revs...))
		if err != nil {
			t.Fatal(err)
		}
		err = v.cert(w.certD)
		return v.checks, err
	}
	broken := func() *DeviceCert { c := *w.certA; c.deviceSig[0] ^= 1; return &c } // a distinct pointer, the same content

	// Valid record signatures, the same broken signer certificate each time: one check per record and two for the certificate.
	var sharedSigner []*Revocation
	for i := range n {
		sharedSigner = append(sharedSigner, record(i, dev, broken()))
	}
	if checks, err := run(sharedSigner); err != nil || checks != n+2 {
		t.Errorf("shared signer certificate: %d checks, %v; want %d, nil", checks, err, n+2)
	}
	// Bad record signatures: one check each, and the signer certificate is not looked at.
	var badSig []*Revocation
	for i := range n {
		r := record(i, dev, w.certA)
		r.sig[0] ^= 1
		badSig = append(badSig, r)
	}
	if checks, err := run(badSig); err != nil || checks != n {
		t.Errorf("bad signatures: %d checks, %v; want %d, nil", checks, err, n)
	}
	// The same record n times: one check.
	same := record(0, dev, broken())
	rep := make([]*Revocation, n)
	for i := range rep {
		rep[i] = same
	}
	if checks, err := run(rep); err != nil || checks != 3 {
		t.Errorf("one record repeated: %d checks, %v; want 3, nil", checks, err)
	}
	// Records for other devices cost nothing, and nil records are skipped.
	var other []*Revocation
	for i := range n {
		other = append(other, record(i, w.E.PublicKey(), broken()), nil)
	}
	if checks, err := run(other); err != nil || checks != 0 {
		t.Errorf("unrelated records: %d checks, %v; want 0, nil", checks, err)
	}
	// A valid record ends the scan at once.
	good := revoke(t, w.A, &RevokeOptions{Person: pp, Device: dev, SignerCert: w.certA, Target: w.certD})
	if checks, err := run(append([]*Revocation{good}, sharedSigner...)); !errors.Is(err, ErrCertRevoked) || checks != 3 {
		t.Errorf("a valid record first: %d checks, %v; want 3, revoked", checks, err)
	}
}

// The hash binds a leaf to the parent bytes it was given, not to a valid parent: an approver can sign a leaf over a parent
// with broken signatures, and every signature of that parent must still be checked.
func TestParentSignaturesCheckedBeyondTheHash(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	for name, mod := range map[string]func(c *DeviceCert){
		"issuer signature of the parent": func(c *DeviceCert) { c.issuerSig[2] ^= 1 },
		"device signature of the parent": func(c *DeviceCert) { c.deviceSig[2] ^= 1 },
	} {
		p := *w.certA
		mod(&p)
		b := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1}
		copy(b.person[:], pp)
		copy(b.device[:], w.D.PublicKey())
		copy(b.issuer[:], w.A.PublicKey())
		offer := &CertOffer{body: b, parent: &p}
		copy(offer.issuerSig[:], mustSign(t, w.A, contextDeviceLink, b.chainBytes(&p)))
		wantErr(t, name+" at accept", acceptErr(w.D, offer, pp), ErrCertSignature)
		c := &DeviceCert{body: b, parent: &p, issuerSig: offer.issuerSig}
		copy(c.deviceSig[:], mustSign(t, w.D, contextDeviceAccept, b.chainBytes(&p)))
		wantErr(t, name+" at verify", c.Verify(w.opts), ErrCertSignature)
	}
}

// The encodings of the test world are pinned, so the signed bytes (including the parent and signer certificate hashes) cannot change unnoticed.
func TestEncodingKnownAnswers(t *testing.T) {
	w := newWorld(t)
	r := revoke(t, w.A, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), SignerCert: w.certA, Target: w.certD, At: baseTime})
	offer, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		enc  []byte
		size int
		sum  string
	}{
		{"root-issued certificate", w.certE.Encode(), 235, "ba540abe02324d000b60c104314d17bd748ea21132748c26e2f66d1ca22c943c"},
		{"approver certificate", w.certA.Encode(), 235, "02974f2684693f85f8b0afd3cf41e3e9d586f3fec19c3f5bf8d8a83def936ab9"},
		{"approver-issued certificate", w.certD.Encode(), 472, "054c144d26819204fdfbb0cd9bed743f5735b05e7bfc73b901d7872634ba5a83"},
		{"offer with a parent", offer.Encode(), 408, "3f23eae257a63a948645abb8e2104118c7c701f835d51ed872e5e091acbdc289"},
		{"approver-signed revocation", r.Encode(), 438, "3f5a3e719b67a8190d0ccfd9beebf78c82c06b063146161fc3b0969ce8aa1e21"},
	} {
		if sum := sha256.Sum256(c.enc); len(c.enc) != c.size || hex.EncodeToString(sum[:]) != c.sum {
			t.Errorf("%s: %d bytes, sha256 %x", c.name, len(c.enc), sum)
		}
	}
}

// handRecord builds an approver-signed revocation of target by hand, so the checks of RevokeDevice do not apply, and signs it with signer.
func handRecord(t testing.TB, w *world, signer *Identity, signerCert, target *DeviceCert, at uint64) *Revocation {
	r := &Revocation{upToSerial: target.body.serial, revokedAt: at, signerCert: signerCert, target: certHash(target)}
	copy(r.person[:], w.P.PublicKey())
	copy(r.device[:], target.body.device[:])
	copy(r.signer[:], signer.PublicKey())
	r.sig = [64]byte(mustSign(t, signer, contextDeviceRevoke, r.sigBytes()))
	return r
}

func signedRecord(t testing.TB, w *world, signerCert *DeviceCert, at uint64) *Revocation {
	return handRecord(t, w, w.A, signerCert, w.certD, at)
}

// Signer certificate results are shared by content: a bad certificate never decides for a good one, whatever the order.
func TestSignerCertResultsAreKeyedByContent(t *testing.T) {
	w := newWorld(t)
	badDeviceSig := *w.certA
	badDeviceSig.deviceSig[0] ^= 1
	badIssuerSig := *w.certA
	badIssuerSig.issuerSig[0] ^= 1
	tampered := *w.certA
	tampered.body.serial = 9
	good := signedRecord(t, w, w.certA, 1)
	for name, bad := range map[string]*DeviceCert{"device signature": &badDeviceSig, "issuer signature": &badIssuerSig, "body": &tampered} {
		for order, revs := range map[string][]*Revocation{
			"bad first":  {signedRecord(t, w, bad, 2), good},
			"good again": {good, signedRecord(t, w, bad, 2)},
		} {
			err := w.certD.Verify(w.with(revs...))
			if !errors.Is(err, ErrCertRevoked) {
				t.Errorf("signer certificate with a bad %s, %s: %v", name, order, err)
			}
		}
		if err := w.certD.Verify(w.with(signedRecord(t, w, bad, 2), signedRecord(t, w, bad, 3))); err != nil {
			t.Errorf("only bad %s: %v", name, err)
		}
	}
}

// The device signs the chain it accepts: its signature does not move to another parent, even if the issuer signs the leaf again.
func TestDeviceAcceptanceCoversTheParent(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	a2 := secondApproverCert(t, w)
	// The approver signs the leaf over the second certificate, as a rogue approver could; the device signature is from the first chain.
	moved := *w.certD
	moved.parent = a2
	moved.issuerSig = [64]byte(mustSign(t, w.A, contextDeviceLink, moved.body.chainBytes(a2)))
	wantErr(t, "device signature over another parent", moved.Verify(w.opts), ErrCertSignature)
	// A device signature over the body alone is not accepted for a certificate with a parent.
	bodyOnly := *w.certD
	bodyOnly.deviceSig = [64]byte(mustSign(t, w.D, contextDeviceAccept, w.certD.body.signedBytes()))
	wantErr(t, "device signature over the body alone", bodyOnly.Verify(w.opts), ErrCertSignature)
	// The accepted chain verifies, and accepting against another parent gives another signature.
	offer, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	c1, err := w.D.AcceptDeviceCert(offer, pp)
	if err != nil {
		t.Fatal(err)
	}
	offer2, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: a2, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := w.D.AcceptDeviceCert(offer2, pp)
	if err != nil {
		t.Fatal(err)
	}
	if c1.deviceSig == c2.deviceSig {
		t.Error("the device signature does not depend on the parent")
	}
	for _, c := range []*DeviceCert{c1, c2} {
		if err := c.Verify(w.opts); err != nil {
			t.Errorf("accepted chain: %v", err)
		}
	}
}

// An approver revokes one exact certificate; the person key revokes by serial.
func TestApproverRevocationNamesOneCertificate(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	byApprover := revoke(t, w.A, &RevokeOptions{Person: pp, Device: w.D.PublicKey(), SignerCert: w.certA, Target: w.certD})
	d2 := issue(t, w.A, w.D, pp, &IssueOptions{Parent: w.certA, Serial: 2, IssuedAt: baseTime})
	d1b := issue(t, w.A, w.D, pp, &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime.Add(time.Second)})
	// The same body and issuer under another certificate of the approver is another certificate.
	otherParent := issue(t, w.A, w.D, pp, &IssueOptions{Parent: secondApproverCert(t, w), Serial: 1, IssuedAt: baseTime})
	wantErr(t, "the named certificate", w.certD.Verify(w.with(byApprover)), ErrCertRevoked)
	for name, c := range map[string]*DeviceCert{"serial 2": d2, "serial 1, another certificate": d1b, "same body, another parent": otherParent, "another device": w.certE} {
		if err := c.Verify(w.with(byApprover)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	byPerson := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.D.PublicKey(), UpToSerial: 1})
	wantErr(t, "person, the named certificate", w.certD.Verify(w.with(byPerson)), ErrCertRevoked)
	wantErr(t, "person, serial 1, another certificate", d1b.Verify(w.with(byPerson)), ErrCertRevoked)
	if err := d2.Verify(w.with(byPerson)); err != nil {
		t.Errorf("person, serial 2: %v", err)
	}
}

// Signatures are not unique, so a revocation names a certificate by what no key holder can vary: the same body, issuer and serial with another
// valid deviceSig (the device key holder) or issuerSig (the issuer) is still the revoked certificate.
func TestApproverRevocationSurvivesResigning(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	for name, c := range map[string]struct {
		cert           *DeviceCert
		device, issuer *Identity
	}{
		"approver-issued": {w.certD, w.D, w.A},
		"root-issued":     {w.certE, w.E, w.P},
	} {
		r := revoke(t, w.A, &RevokeOptions{Person: pp, Device: c.cert.Device(), SignerCert: w.certA, Target: c.cert})
		chain := c.cert.body.chainBytes(c.cert.parent)
		devOnly, issOnly, both := *c.cert, *c.cert, *c.cert
		devOnly.deviceSig = [64]byte(variantSignature(t, c.device, contextDeviceAccept, chain, "v1"))
		issOnly.issuerSig = [64]byte(variantSignature(t, c.issuer, contextDeviceLink, chain, "v2"))
		both.deviceSig, both.issuerSig = devOnly.deviceSig, issOnly.issuerSig
		for what, v := range map[string]*DeviceCert{"deviceSig": &devOnly, "issuerSig": &issOnly, "both": &both} {
			if bytes.Equal(v.Encode(), c.cert.Encode()) {
				t.Fatalf("%s %s: the variant has the same bytes", name, what)
			}
			if err := v.Verify(w.opts); err != nil {
				t.Fatalf("%s %s: the variant is a valid certificate: %v", name, what, err)
			}
			if certHash(v) != certHash(c.cert) {
				t.Errorf("%s %s: the name changed with the signature", name, what)
			}
			wantErr(t, name+" "+what+" Verify", v.Verify(w.with(r)), ErrCertRevoked)
			msgSig := mustSign(t, c.device, testContext, []byte("m"))
			wantErr(t, name+" "+what+" VerifyDevice", VerifyDevice(v, w.with(r), testContext, []byte("m"), msgSig), ErrCertRevoked)
			if err := r.Verify(w.opts, v); err != nil {
				t.Errorf("%s %s: Revocation.Verify: %v", name, what, err)
			}
		}
		// Altered bytes that are not valid signatures reach the same answer, because the revoked check comes before the signature checks.
		junk := *c.cert
		junk.deviceSig[0] ^= 1
		junk.issuerSig[0] ^= 1
		wantErr(t, name+" junk signatures", junk.Verify(w.with(r)), ErrCertRevoked)
	}
}

func TestRevocationSigner(t *testing.T) {
	w := newWorld(t)
	byApprover := revoke(t, w.A, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), SignerCert: w.certA, Target: w.certD})
	x := byApprover.Signer()
	if !bytes.Equal(x, w.A.PublicKey()) {
		t.Errorf("Signer = %x", x)
	}
	x[0] ^= 1
	if !bytes.Equal(byApprover.Signer(), w.A.PublicKey()) {
		t.Error("Signer returns the internal slice")
	}
	if s := revoke(t, w.P, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), UpToSerial: 1}).Signer(); s != nil {
		t.Errorf("person-signed Signer = %x", s)
	}
	if s := revoke(t, w.D, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), UpToSerial: 1}).Signer(); s != nil {
		t.Errorf("self-signed Signer = %x", s)
	}
	if (*Revocation)(nil).Signer() != nil {
		t.Error("nil Signer")
	}
}
