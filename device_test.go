package koloid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

var baseTime = time.Unix(1_700_000_000, 0)

func idFrom(t testing.TB, b byte) *Identity {
	t.Helper()
	id, err := FromSeed(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// A small world: a person key P, an approver device A (certificate from P), an ordinary device D certified by A, and E certified by P.
type world struct {
	P, A, D, E          *Identity
	certA, certD, certE *DeviceCert
	opts                *VerifyOptions
}

func issue(t testing.TB, signer, device *Identity, person ed25519.PublicKey, o *IssueOptions) *DeviceCert {
	t.Helper()
	offer, err := signer.OfferDeviceCert(device.PublicKey(), o)
	if err != nil {
		t.Fatalf("OfferDeviceCert: %v", err)
	}
	offer, err = DecodeCertOffer(offer.Encode())
	if err != nil {
		t.Fatalf("DecodeCertOffer: %v", err)
	}
	c, err := device.AcceptDeviceCert(offer, person)
	if err != nil {
		t.Fatalf("AcceptDeviceCert: %v", err)
	}
	c2, err := DecodeDeviceCert(c.Encode())
	if err != nil {
		t.Fatalf("DecodeDeviceCert: %v", err)
	}
	return c2
}

func newWorld(t testing.TB) *world {
	t.Helper()
	w := &world{P: idFrom(t, 1), A: idFrom(t, 2), D: idFrom(t, 3), E: idFrom(t, 4)}
	pp := w.P.PublicKey()
	w.certA = issue(t, w.P, w.A, pp, &IssueOptions{Serial: 1, IssuedAt: baseTime, Approver: true})
	w.certD = issue(t, w.A, w.D, pp, &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	w.certE = issue(t, w.P, w.E, pp, &IssueOptions{Serial: 1, IssuedAt: baseTime})
	w.opts = &VerifyOptions{Person: pp, Now: baseTime.Add(time.Hour)}
	return w
}

func (w *world) with(revs ...*Revocation) *VerifyOptions {
	o := *w.opts
	o.Revocations = revs
	return &o
}

func revoke(t testing.TB, signer *Identity, o *RevokeOptions) *Revocation {
	t.Helper()
	r, err := signer.RevokeDevice(o)
	if err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	r2, err := DecodeRevocation(r.Encode())
	if err != nil {
		t.Fatalf("DecodeRevocation: %v", err)
	}
	return r2
}

func wantErr(t *testing.T, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: got %v, want %v", what, err, want)
	}
}

func TestCertRoundTrip(t *testing.T) {
	w := newWorld(t)
	for name, c := range map[string]*DeviceCert{"approver": w.certA, "approver-issued": w.certD, "root-issued": w.certE} {
		if err := c.Verify(w.opts); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		again, err := DecodeDeviceCert(c.Encode())
		if err != nil || !bytes.Equal(again.Encode(), c.Encode()) {
			t.Errorf("%s: re-encode differs: %v", name, err)
		}
	}
	if !w.certA.Approver() || w.certD.Approver() || w.certE.Approver() {
		t.Error("approver flags")
	}
	if !bytes.Equal(w.certD.Person(), w.P.PublicKey()) || !bytes.Equal(w.certD.Device(), w.D.PublicKey()) || !bytes.Equal(w.certD.Issuer(), w.A.PublicKey()) {
		t.Error("accessors of the approver-issued certificate")
	}
	if !bytes.Equal(w.certE.Issuer(), w.P.PublicKey()) {
		t.Error("root-issued issuer must be the person")
	}
	if w.certD.Serial() != 1 || !w.certD.IssuedAt().Equal(baseTime) || !w.certD.ExpiresAt().IsZero() {
		t.Error("serial and times")
	}
	exp := baseTime.Add(24 * time.Hour)
	c := issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: 7, IssuedAt: baseTime, ExpiresAt: exp})
	if c.Serial() != 7 || !c.ExpiresAt().Equal(exp) {
		t.Error("expiry accessor")
	}
	pub := w.certD.Person()
	pub[0] ^= 1
	if bytes.Equal(pub, w.certD.Person()) {
		t.Error("Person returns the internal slice")
	}
}

func TestCertAccessorsOnNil(t *testing.T) {
	var c *DeviceCert
	if c.Person() != nil || c.Device() != nil || c.Issuer() != nil || c.Serial() != 0 || !c.IssuedAt().IsZero() || !c.ExpiresAt().IsZero() || c.Approver() || c.Encode() != nil {
		t.Error("nil certificate accessors must be zero")
	}
	var o *CertOffer
	if o.Encode() != nil {
		t.Error("nil offer Encode")
	}
	var r *Revocation
	if r.Person() != nil || r.Device() != nil || r.UpToSerial() != 0 || r.Encode() != nil {
		t.Error("nil revocation accessors must be zero")
	}
}

// The sizes of docs/formats.md: 256 bytes, 514 with a parent, 472 for a revocation, at the largest values.
func TestMaxSizes(t *testing.T) {
	w := newWorld(t)
	big := time.Unix(math.MaxInt64-1, 0)
	max := time.Unix(math.MaxInt64, 0)
	a := issue(t, w.P, w.A, w.P.PublicKey(), &IssueOptions{Serial: math.MaxUint64, IssuedAt: big, ExpiresAt: max, Approver: true})
	d := issue(t, w.A, w.D, w.P.PublicKey(), &IssueOptions{Parent: a, Serial: math.MaxUint64, IssuedAt: big, ExpiresAt: max})
	if n := len(a.Encode()); n != 256 {
		t.Errorf("certificate is %d bytes, want 256", n)
	}
	if n := len(d.Encode()); n != 514 {
		t.Errorf("certificate with parent is %d bytes, want 514", n)
	}
	r := revoke(t, w.A, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), SignerCert: a, Target: d, At: max})
	if n := len(r.Encode()); n != 472 {
		t.Errorf("revocation is %d bytes, want 472", n)
	}
	if err := d.Verify(&VerifyOptions{Person: w.P.PublicKey(), Now: baseTime}); err != nil {
		t.Errorf("largest certificate: %v", err)
	}
}

func TestOfferErrors(t *testing.T) {
	w := newWorld(t)
	dev := w.E.PublicKey()
	ok := func() *IssueOptions { return &IssueOptions{Serial: 1, IssuedAt: baseTime} }
	cases := []struct {
		name   string
		signer *Identity
		device ed25519.PublicKey
		mod    func(o *IssueOptions)
		want   error
	}{
		{"nil options", w.P, dev, nil, ErrInvalidArgument},
		{"serial zero", w.P, dev, func(o *IssueOptions) { o.Serial = 0 }, ErrInvalidArgument},
		{"expiry equals issue time", w.P, dev, func(o *IssueOptions) { o.ExpiresAt = baseTime }, ErrInvalidArgument},
		{"expiry before issue time", w.P, dev, func(o *IssueOptions) { o.ExpiresAt = baseTime.Add(-time.Second) }, ErrInvalidArgument},
		{"expiry before 1970", w.P, dev, func(o *IssueOptions) { o.IssuedAt = time.Unix(-5, 0); o.ExpiresAt = time.Unix(-1, 0) }, ErrInvalidArgument},
		{"issued before 1970", w.P, dev, func(o *IssueOptions) { o.IssuedAt = time.Unix(-1, 0) }, ErrInvalidArgument},
		{"approver with parent", w.A, dev, func(o *IssueOptions) { o.Parent = w.certA; o.Approver = true }, ErrInvalidArgument},
		{"nil device key", w.P, nil, nil, ErrInvalidArgument},
		{"short device key", w.P, dev[:31], func(o *IssueOptions) {}, ErrInvalidArgument},
		{"small-order device key", w.P, smallOrderKey(), func(o *IssueOptions) {}, ErrInvalidArgument},
		{"device is the person", w.P, w.P.PublicKey(), func(o *IssueOptions) {}, ErrInvalidArgument},
		{"device is the approver", w.A, w.A.PublicKey(), func(o *IssueOptions) { o.Parent = w.certA }, ErrInvalidArgument},
		{"parent of another device", w.D, dev, func(o *IssueOptions) { o.Parent = w.certA }, ErrInvalidArgument},
		{"parent is not an approver", w.D, dev, func(o *IssueOptions) { o.Parent = w.certD }, ErrNotApprover},
		{"parent is a root-issued ordinary device", w.E, w.D.PublicKey(), func(o *IssueOptions) { o.Parent = w.certE }, ErrNotApprover},
		{"parent with a broken signature", w.A, dev, func(o *IssueOptions) { o.Parent = corrupt(w.certA) }, ErrCertSignature},
		{"zero parent", w.A, dev, func(o *IssueOptions) { o.Parent = &DeviceCert{} }, ErrInvalidCert},
	}
	for _, c := range cases {
		var o *IssueOptions
		if c.mod != nil {
			o = ok()
			c.mod(o)
		}
		offer, err := c.signer.OfferDeviceCert(c.device, o)
		if offer != nil {
			t.Errorf("%s: got an offer", c.name)
		}
		wantErr(t, c.name, err, c.want)
	}
	var none *Identity
	if _, err := none.OfferDeviceCert(dev, ok()); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("nil identity: %v", err)
	}
}

func smallOrderKey() ed25519.PublicKey {
	k := smallOrderEncodings()[0]
	return k[:]
}

func corrupt(c *DeviceCert) *DeviceCert {
	x := *c
	x.issuerSig[0] ^= 1
	return &x
}

func TestAcceptErrors(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	offer, err := w.P.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	// Proof of possession: only the device named in the offer can accept it.
	if c, err := w.D.AcceptDeviceCert(offer, pp); c != nil || !errors.Is(err, ErrInvalidCert) {
		t.Errorf("accept by another device: %v, %v", c, err)
	}
	wantErr(t, "wrong person", acceptErr(w.E, offer, w.A.PublicKey()), ErrCertPerson)
	wantErr(t, "nil person", acceptErr(w.E, offer, nil), ErrInvalidArgument)
	wantErr(t, "small-order person", acceptErr(w.E, offer, smallOrderKey()), ErrInvalidArgument)
	wantErr(t, "nil offer", acceptErr(w.E, nil, pp), ErrInvalidCert)
	wantErr(t, "zero offer", acceptErr(w.E, &CertOffer{}, pp), ErrInvalidCert)
	tampered := *offer
	tampered.issuerSig[5] ^= 0x10
	wantErr(t, "bad issuer signature", acceptErr(w.E, &tampered, pp), ErrCertSignature)
	tampered = *offer
	tampered.body.serial = 2
	wantErr(t, "changed serial", acceptErr(w.E, &tampered, pp), ErrCertSignature)
	var none *Identity
	wantErr(t, "nil identity", acceptErr(none, offer, pp), ErrInvalidIdentity)

	childOffer, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	bad := *childOffer
	bad.parent = corrupt(w.certA)
	wantErr(t, "bad parent signature", acceptErr(w.D, &bad, pp), ErrCertSignature)
	if _, err := w.D.AcceptDeviceCert(childOffer, pp); err != nil {
		t.Errorf("good approver-issued offer: %v", err)
	}
}

func acceptErr(id *Identity, o *CertOffer, person ed25519.PublicKey) error {
	_, err := id.AcceptDeviceCert(o, person)
	return err
}

func TestCertWrongPerson(t *testing.T) {
	w := newWorld(t)
	other := idFrom(t, 9).PublicKey()
	for _, c := range []*DeviceCert{w.certE, w.certD, w.certA} {
		wantErr(t, "Verify", c.Verify(&VerifyOptions{Person: other, Now: baseTime}), ErrCertPerson)
	}
	// The approver is the issuer's key, not the person: a chain "ending" at the approver is not accepted.
	wantErr(t, "approver as person", w.certD.Verify(&VerifyOptions{Person: w.A.PublicKey(), Now: baseTime}), ErrCertPerson)
	sig, _ := w.E.Sign(testContext, []byte("m"))
	wantErr(t, "VerifyDevice", VerifyDevice(w.certE, &VerifyOptions{Person: other}, testContext, []byte("m"), sig), ErrCertPerson)
}

func TestCertWrongDevice(t *testing.T) {
	w := newWorld(t)
	msg := []byte("hello")
	sigE, _ := w.E.Sign(testContext, msg)
	sigD, _ := w.D.Sign(testContext, msg)
	if err := VerifyDevice(w.certE, w.opts, testContext, msg, sigE); err != nil {
		t.Fatal(err)
	}
	wantErr(t, "message signed by another device", VerifyDevice(w.certE, w.opts, testContext, msg, sigD), ErrCertSignature)
	// A certificate whose device signature came from another key is not accepted.
	forged := *w.certE
	copy(forged.deviceSig[:], mustSign(t, w.D, contextDeviceAccept, forged.body.signedBytes()))
	wantErr(t, "device signature of another device", forged.Verify(w.opts), ErrCertSignature)
}

func mustSign(t testing.TB, id *Identity, ctx string, msg []byte) []byte {
	t.Helper()
	s, err := id.sign(ctx, msg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCertForge(t *testing.T) {
	w := newWorld(t)
	for name, c := range map[string]*DeviceCert{"root-issued": w.certE, "approver-issued": w.certD} {
		enc := c.Encode()
		for i := range enc {
			for bit := 0; bit < 8; bit++ {
				mut := bytes.Clone(enc)
				mut[i] ^= 1 << bit
				d, err := DecodeDeviceCert(mut)
				if err != nil {
					continue
				}
				if err := d.Verify(w.opts); err == nil {
					t.Fatalf("%s: flipping bit %d of byte %d still verifies", name, bit, i)
				}
			}
		}
	}
}

func TestCertExpiry(t *testing.T) {
	w := newWorld(t)
	exp := baseTime.Add(time.Hour)
	leaf := issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime, ExpiresAt: exp})
	at := func(now time.Time) *VerifyOptions { return &VerifyOptions{Person: w.P.PublicKey(), Now: now} }
	if err := leaf.Verify(at(exp.Add(-time.Second))); err != nil {
		t.Errorf("one second before expiry: %v", err)
	}
	wantErr(t, "at the expiry second", leaf.Verify(at(exp)), ErrCertExpired)
	wantErr(t, "after expiry", leaf.Verify(at(exp.Add(time.Second))), ErrCertExpired)
	wantErr(t, "far after expiry", leaf.Verify(at(exp.Add(1000*time.Hour))), ErrCertExpired)
	if err := w.certE.Verify(at(baseTime.Add(100 * 365 * 24 * time.Hour))); err != nil {
		t.Errorf("a certificate without expiry: %v", err)
	}
	// The expiry of the approver in the chain counts too, and the leaf's own expiry is independent of it.
	shortA := issue(t, w.P, w.A, w.P.PublicKey(), &IssueOptions{Serial: 2, IssuedAt: baseTime, ExpiresAt: exp, Approver: true})
	child := issue(t, w.A, w.D, w.P.PublicKey(), &IssueOptions{Parent: shortA, Serial: 1, IssuedAt: baseTime})
	if err := child.Verify(at(exp.Add(-time.Second))); err != nil {
		t.Errorf("approver not yet expired: %v", err)
	}
	wantErr(t, "approver expired", child.Verify(at(exp)), ErrCertExpired)
	// VerifyDevice uses the same clock; a zero Now means the current time.
	old := issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime, ExpiresAt: baseTime.Add(time.Second)})
	sig := mustSign(t, w.E, testContext, []byte("m"))
	wantErr(t, "zero Now", VerifyDevice(old, &VerifyOptions{Person: w.P.PublicKey()}, testContext, []byte("m"), sig), ErrCertExpired)
	fresh := issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: 1, ExpiresAt: time.Now().Add(time.Hour)})
	if err := VerifyDevice(fresh, &VerifyOptions{Person: w.P.PublicKey()}, testContext, []byte("m"), sig); err != nil {
		t.Errorf("zero Now with a live certificate: %v", err)
	}
}

// issuedAt is signed by the issuer and decides nothing: a back-dated or future certificate verifies, and a revocation still voids it.
func TestCertBackDatedIssuedAt(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	old := issue(t, w.A, w.D, pp, &IssueOptions{Parent: w.certA, Serial: 5, IssuedAt: time.Unix(0, 0)})
	if err := old.Verify(w.opts); err != nil {
		t.Errorf("issued at the epoch: %v", err)
	}
	future := issue(t, w.A, w.D, pp, &IssueOptions{Parent: w.certA, Serial: 6, IssuedAt: baseTime.Add(10 * 365 * 24 * time.Hour)})
	if err := future.Verify(w.opts); err != nil {
		t.Errorf("issued in the future: %v", err)
	}
	// Issued before the approver's own certificate, so before the approver existed: still decided by the chain rule only.
	if !old.IssuedAt().Before(w.certA.IssuedAt()) {
		t.Fatal("setup")
	}
	r := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.A.PublicKey(), UpToSerial: 1, At: time.Unix(0, 0)})
	wantErr(t, "back-dated leaf of a revoked approver", old.Verify(w.with(r)), ErrCertRevoked)
	// A revocation dated before the certificate was issued still applies: revokedAt decides nothing.
	r2 := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.D.PublicKey(), UpToSerial: 6, At: time.Unix(0, 0)})
	wantErr(t, "revocation older than the certificate", future.Verify(w.with(r2)), ErrCertRevoked)
}

func TestCertRevoked(t *testing.T) {
	w := newWorld(t)
	pp, dev, apr := w.P.PublicKey(), w.D.PublicKey(), w.A.PublicKey()
	base := func(d ed25519.PublicKey, serial uint64) *RevokeOptions {
		return &RevokeOptions{Person: pp, Device: d, UpToSerial: serial, At: baseTime}
	}
	byPerson := revoke(t, w.P, base(dev, 1))
	bySelf := revoke(t, w.D, base(dev, 1))
	byApprover := revoke(t, w.A, &RevokeOptions{Person: pp, Device: dev, SignerCert: w.certA, Target: w.certD, At: baseTime})

	for _, r := range []*Revocation{byPerson, bySelf, byApprover} {
		if err := r.Verify(w.opts, w.certD); err != nil {
			t.Fatal(err)
		}
	}
	for name, r := range map[string]*Revocation{"person": byPerson, "self": bySelf, "approver": byApprover} {
		wantErr(t, name+" revokes the leaf", w.certD.Verify(w.with(r)), ErrCertRevoked)
		sig := mustSign(t, w.D, testContext, []byte("m"))
		wantErr(t, name+" VerifyDevice", VerifyDevice(w.certD, w.with(r), testContext, []byte("m"), sig), ErrCertRevoked)
		if err := w.certE.Verify(w.with(r)); err != nil {
			t.Errorf("%s: revocation of D must not affect E: %v", name, err)
		}
	}
	// An approver cannot revoke an approver: signing is refused, and a hand-built record is refused by verification.
	other := idFrom(t, 5)
	certA2 := issue(t, w.P, other, pp, &IssueOptions{Serial: 1, IssuedAt: baseTime, Approver: true})
	if _, err := other.RevokeDevice(&RevokeOptions{Person: pp, Device: apr, SignerCert: certA2, Target: w.certA}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("an approver revoking an approver: %v", err)
	}
	approverRevokesApprover := handRecord(t, w, other, certA2, w.certA, 1)
	wantErr(t, "Verify", approverRevokesApprover.Verify(w.opts, w.certA), ErrInvalidRevocation)
	if err := w.certA.Verify(w.with(approverRevokesApprover)); err != nil {
		t.Errorf("approver revoked by another approver must stay valid: %v", err)
	}
	if err := w.certD.Verify(w.with(approverRevokesApprover)); err != nil {
		t.Errorf("leaf of an approver revoked by another approver must stay valid: %v", err)
	}
	// The person revokes the approver: its certificate is void and so is every leaf it issued.
	revA := revoke(t, w.P, base(apr, 1))
	wantErr(t, "revoked approver", w.certA.Verify(w.with(revA)), ErrCertRevoked)
	wantErr(t, "leaf of a revoked approver", w.certD.Verify(w.with(revA)), ErrCertRevoked)
	if err := w.certE.Verify(w.with(revA)); err != nil {
		t.Errorf("a leaf issued by the person is not affected: %v", err)
	}
	// The approver revokes itself: same effect on its leaves.
	selfA := revoke(t, w.A, base(apr, 1))
	wantErr(t, "approver retires itself", w.certD.Verify(w.with(selfA)), ErrCertRevoked)

	// Serials: a revocation covers serials up to upToSerial only.
	v2 := issue(t, w.P, w.E, pp, &IssueOptions{Serial: 2, IssuedAt: baseTime})
	rE := revoke(t, w.P, base(w.E.PublicKey(), 1))
	wantErr(t, "serial 1", w.certE.Verify(w.with(rE)), ErrCertRevoked)
	if err := v2.Verify(w.with(rE)); err != nil {
		t.Errorf("serial 2 after revoking up to 1: %v", err)
	}
	rE2 := revoke(t, w.P, base(w.E.PublicKey(), 2))
	wantErr(t, "serial 2 boundary", v2.Verify(w.with(rE2)), ErrCertRevoked)
	burn := revoke(t, w.P, base(w.E.PublicKey(), math.MaxUint64))
	v3 := issue(t, w.P, w.E, pp, &IssueOptions{Serial: math.MaxUint64, IssuedAt: baseTime})
	wantErr(t, "burned key", v3.Verify(w.with(burn)), ErrCertRevoked)

	// Records that do not count: nil, another person, another device, a bad signature, an expired approver signer.
	otherPerson := idFrom(t, 8)
	foreign := revoke(t, otherPerson, &RevokeOptions{Person: otherPerson.PublicKey(), Device: dev, UpToSerial: 9})
	unrelated := revoke(t, w.P, base(w.E.PublicKey(), 9))
	forged := *byPerson
	forged.sig[0] ^= 1
	forgedByOther := *byPerson
	forgedByOther.sig = [64]byte(mustSign(t, w.D, contextDeviceRevoke, byPerson.sigBytes())) // signed by the device, claims the person
	wrongCtx := *byPerson
	wrongCtx.sig = [64]byte(mustSign(t, w.P, contextDeviceLink, byPerson.sigBytes()))
	for name, r := range map[string]*Revocation{"nil": nil, "other person": foreign, "other device": unrelated, "bad signature": &forged, "signature of another key": &forgedByOther, "signature under another context": &wrongCtx} {
		if err := w.certD.Verify(w.with(r)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := w.certD.Verify(w.with(nil, foreign, unrelated, &forged, byPerson)); !errors.Is(err, ErrCertRevoked) {
		t.Errorf("a valid record among invalid ones: %v", err)
	}
	// Revocations are permanent: an approver-signed record keeps counting after the approver expires, is revoked or retires itself.
	shortA := issue(t, w.P, other, pp, &IssueOptions{Serial: 2, IssuedAt: baseTime, ExpiresAt: baseTime.Add(time.Minute), Approver: true})
	byShort := revoke(t, other, &RevokeOptions{Person: pp, Device: dev, SignerCert: shortA, Target: w.certD})
	wantErr(t, "signer live", w.certD.Verify(&VerifyOptions{Person: pp, Now: baseTime, Revocations: []*Revocation{byShort}}), ErrCertRevoked)
	wantErr(t, "signer expired", w.certD.Verify(&VerifyOptions{Person: pp, Now: baseTime.Add(time.Hour), Revocations: []*Revocation{byShort}}), ErrCertRevoked)
	revOther := revoke(t, w.P, base(other.PublicKey(), 2))
	wantErr(t, "signer revoked by the person", w.certD.Verify(w.with(byShort, revOther)), ErrCertRevoked)
	sBy := revoke(t, other, base(other.PublicKey(), 2)) // the approver retires itself
	wantErr(t, "signer retired itself", w.certD.Verify(w.with(byShort, sBy)), ErrCertRevoked)
}

// D1: revocations are monotone tombstones. An approver revokes one exact certificate, so the way back is a new certificate.
func TestRevocationsAreMonotone(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	thief := idFrom(t, 0x31) // a stolen approver
	thiefCert := issue(t, w.P, thief, pp, &IssueOptions{Serial: 1, IssuedAt: baseTime, ExpiresAt: baseTime.Add(3 * time.Hour), Approver: true})
	phone := idFrom(t, 0x32)
	phoneCert := issue(t, thief, phone, pp, &IssueOptions{Parent: thiefCert, Serial: 1, IssuedAt: baseTime})
	at := func(d time.Duration, revs ...*Revocation) *VerifyOptions {
		return &VerifyOptions{Person: pp, Now: baseTime.Add(d), Revocations: revs}
	}

	// An approver that expires later: its earlier revocation of a phone still applies after the expiry.
	stolenPhone := idFrom(t, 0x33)
	stolenCert := issue(t, w.P, stolenPhone, pp, &IssueOptions{Serial: 1, IssuedAt: baseTime})
	byApprover := revoke(t, thief, &RevokeOptions{Person: pp, Device: stolenPhone.PublicKey(), SignerCert: thiefCert, Target: stolenCert})
	wantErr(t, "before the approver expires", stolenCert.Verify(at(time.Minute, byApprover)), ErrCertRevoked)
	wantErr(t, "after the approver expired", stolenCert.Verify(at(48*time.Hour, byApprover)), ErrCertRevoked)
	if err := byApprover.Verify(at(48*time.Hour), stolenCert); err != nil {
		t.Errorf("Revocation.Verify after the approver expired: %v", err)
	}

	// A stolen approver revokes the person's device E; the person revokes the approver; the revocation still stands.
	hostile := revoke(t, thief, &RevokeOptions{Person: pp, Device: w.E.PublicKey(), SignerCert: thiefCert, Target: w.certE})
	revThief := revoke(t, w.P, &RevokeOptions{Person: pp, Device: thief.PublicKey(), UpToSerial: 1})
	revs := []*Revocation{hostile, revThief}
	wantErr(t, "E stays revoked after the approver is revoked", w.certE.Verify(w.with(revs...)), ErrCertRevoked)
	wantErr(t, "the approver's own certificate", thiefCert.Verify(w.with(revs...)), ErrCertRevoked)
	wantErr(t, "the approver's leaf", phoneCert.Verify(w.with(revs...)), ErrCertRevoked)

	// Recovery: the person certifies E again as a new certificate. The record names the old one only.
	e2 := issue(t, w.P, w.E, pp, &IssueOptions{Serial: 2, IssuedAt: baseTime})
	if err := e2.Verify(w.with(revs...)); err != nil {
		t.Errorf("re-certified: %v", err)
	}
	sig := mustSign(t, w.E, testContext, []byte("m"))
	if err := VerifyDevice(e2, w.with(revs...), testContext, []byte("m"), sig); err != nil {
		t.Errorf("VerifyDevice after re-certifying: %v", err)
	}
	wantErr(t, "the old certificate", w.certE.Verify(w.with(revs...)), ErrCertRevoked)
	// A new certificate with the same serial is another certificate too: only the exact one is named.
	same := issue(t, w.P, w.E, pp, &IssueOptions{Serial: 1, IssuedAt: baseTime.Add(time.Second)})
	if err := same.Verify(w.with(hostile)); err != nil {
		t.Errorf("another certificate with the same serial: %v", err)
	}
	// The thief revokes the new one too, because it exists; the next one is clean, so a stolen approver always trails the person.
	hostile2 := revoke(t, thief, &RevokeOptions{Person: pp, Device: w.E.PublicKey(), SignerCert: thiefCert, Target: e2})
	wantErr(t, "a certificate the thief can name", e2.Verify(w.with(hostile, hostile2)), ErrCertRevoked)
	e3 := issue(t, w.P, w.E, pp, &IssueOptions{Serial: 3, IssuedAt: baseTime})
	if err := e3.Verify(w.with(hostile, hostile2, revThief)); err != nil {
		t.Errorf("the certificate after: %v", err)
	}
	// A record signed in advance for a certificate that does not exist yet names nothing: it hashes another certificate.
	future := issue(t, w.P, w.E, pp, &IssueOptions{Serial: 4, IssuedAt: baseTime})
	guess := *hostile
	guess.target = [32]byte{1}
	guess.sig = [64]byte(mustSign(t, thief, contextDeviceRevoke, guess.sigBytes()))
	if err := future.Verify(w.with(&guess)); err != nil {
		t.Errorf("a record for a certificate that did not exist: %v", err)
	}
	// Revoking the approver still voids what it issued; the legitimate device must be certified again.
	d2 := issue(t, w.P, w.D, pp, &IssueOptions{Serial: 2, IssuedAt: baseTime})
	if err := d2.Verify(w.with(revs...)); err != nil {
		t.Errorf("re-certified by the person: %v", err)
	}
	// The person key still burns: a person-signed record covers every serial up to its number.
	burn := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.E.PublicKey(), UpToSerial: math.MaxUint64})
	wantErr(t, "burned by the person", issue(t, w.P, w.E, pp, &IssueOptions{Serial: math.MaxUint64, IssuedAt: baseTime}).Verify(w.with(burn)), ErrCertRevoked)
}

// The signer certificate of an approver-signed record is judged by structure and signatures only.
func TestRevocationSignerCertSignatures(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	build := func(mod func(c *DeviceCert)) *Revocation {
		c := *w.certA
		mod(&c)
		r := &Revocation{upToSerial: 1, revokedAt: 5, signerCert: &c, target: certHash(w.certD)}
		copy(r.person[:], pp)
		copy(r.device[:], dev)
		copy(r.signer[:], w.A.PublicKey())
		r.sig = [64]byte(mustSign(t, w.A, contextDeviceRevoke, r.sigBytes()))
		return r
	}
	if err := build(func(*DeviceCert) {}).Verify(w.opts, w.certD); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	wantErr(t, "signer certificate issuer signature", build(func(c *DeviceCert) { c.issuerSig[3] ^= 1 }).Verify(w.opts, w.certD), ErrCertSignature)
	wantErr(t, "signer certificate device signature", build(func(c *DeviceCert) { c.deviceSig[3] ^= 1 }).Verify(w.opts, w.certD), ErrCertSignature)
	// Both signatures are by the right keys but the issuer signature is not the person's.
	wantErr(t, "signer certificate signed by another issuer", build(func(c *DeviceCert) {
		c.issuerSig = [64]byte(mustSign(t, w.E, contextDeviceLink, c.body.signedBytes()))
	}).Verify(w.opts, w.certD), ErrCertSignature)
	if err := w.certD.Verify(w.with(build(func(c *DeviceCert) { c.deviceSig[3] ^= 1 }))); err != nil {
		t.Errorf("a record with a forged signer certificate counted: %v", err)
	}
}

func TestCertReplayOldSerial(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	// Serial 1 was an approver; the person downgrades the device with serial 2 and revokes up to 1.
	v2 := issue(t, w.P, w.A, pp, &IssueOptions{Serial: 2, IssuedAt: baseTime})
	r := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.A.PublicKey(), UpToSerial: 1})
	wantErr(t, "old approver certificate", w.certA.Verify(w.with(r)), ErrCertRevoked)
	wantErr(t, "leaf of the old approver certificate", w.certD.Verify(w.with(r)), ErrCertRevoked)
	if err := v2.Verify(w.with(r)); err != nil {
		t.Errorf("new certificate: %v", err)
	}
	if v2.Approver() {
		t.Error("downgraded certificate is still an approver")
	}
	// The downgraded device can no longer sign offers as an approver.
	if _, err := w.A.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Parent: v2, Serial: 1}); !errors.Is(err, ErrNotApprover) {
		t.Errorf("offer under a downgraded certificate: %v", err)
	}
}

func TestCertDepth(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	// An approver cannot issue an approver (OfferDeviceCert refuses) ...
	if _, err := w.A.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 1, Approver: true}); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("approver offering an approver certificate: %v", err)
	}
	// ... and a forged one, correctly signed by the approver, is refused by decode and verify.
	b := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1, flags: flagApprover}
	copy(b.person[:], pp)
	copy(b.device[:], w.D.PublicKey())
	copy(b.issuer[:], w.A.PublicKey())
	forged := &DeviceCert{body: b, parent: w.certA}
	copy(forged.issuerSig[:], mustSign(t, w.A, contextDeviceLink, b.chainBytes(forged.parent)))
	copy(forged.deviceSig[:], mustSign(t, w.D, contextDeviceAccept, b.chainBytes(forged.parent)))
	wantErr(t, "approver issued by approver: decode", decodeErr(forged.Encode()), ErrInvalidCert)
	wantErr(t, "approver issued by approver: verify", forged.Verify(w.opts), ErrInvalidCert)

	// Depth 3: person -> approver -> approver -> device.
	l2 := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1}
	copy(l2.person[:], pp)
	copy(l2.device[:], w.E.PublicKey())
	copy(l2.issuer[:], w.D.PublicKey())
	deep := &DeviceCert{body: l2, parent: w.certD}
	copy(deep.issuerSig[:], mustSign(t, w.D, contextDeviceLink, l2.chainBytes(deep.parent)))
	copy(deep.deviceSig[:], mustSign(t, w.E, contextDeviceAccept, l2.chainBytes(deep.parent)))
	wantErr(t, "depth 3: decode", decodeErr(deep.Encode()), ErrInvalidCert)
	wantErr(t, "depth 3: verify", deep.Verify(w.opts), ErrInvalidCert)
	sig := mustSign(t, w.E, testContext, []byte("m"))
	wantErr(t, "depth 3: VerifyDevice", VerifyDevice(deep, w.opts, testContext, []byte("m"), sig), ErrInvalidCert)
	// An ordinary device (not an approver) cannot issue.
	if _, err := w.D.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Parent: w.certD, Serial: 1}); !errors.Is(err, ErrNotApprover) {
		t.Errorf("ordinary device offering: %v", err)
	}
	// A certificate whose approver parent is an ordinary device, forged with valid signatures.
	l3 := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1}
	copy(l3.person[:], pp)
	copy(l3.device[:], w.D.PublicKey())
	copy(l3.issuer[:], w.E.PublicKey())
	notApprover := &DeviceCert{body: l3, parent: w.certE}
	copy(notApprover.issuerSig[:], mustSign(t, w.E, contextDeviceLink, l3.chainBytes(notApprover.parent)))
	copy(notApprover.deviceSig[:], mustSign(t, w.D, contextDeviceAccept, l3.chainBytes(notApprover.parent)))
	wantErr(t, "parent is not an approver", notApprover.Verify(w.opts), ErrInvalidCert)
}

func decodeErr(b []byte) error {
	_, err := DecodeDeviceCert(b)
	return err
}

// Someone else's device key certified under a hostile person key does not verify without that device's own signature.
func TestCertNoProofOfPossession(t *testing.T) {
	victim := idFrom(t, 6)
	hostile := idFrom(t, 7)
	offer, err := hostile.OfferDeviceCert(victim.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	opts := &VerifyOptions{Person: hostile.PublicKey(), Now: baseTime}
	c := &DeviceCert{body: offer.body, issuerSig: offer.issuerSig}
	wantErr(t, "no device signature", c.Verify(opts), ErrCertSignature)
	copy(c.deviceSig[:], mustSign(t, hostile, contextDeviceAccept, c.body.signedBytes()))
	wantErr(t, "device signature by the hostile person", c.Verify(opts), ErrCertSignature)
	if _, err := hostile.AcceptDeviceCert(offer, hostile.PublicKey()); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("accepting an offer for another device: %v", err)
	}
	if _, err := victim.AcceptDeviceCert(offer, hostile.PublicKey()); err != nil {
		t.Errorf("the victim itself may accept: %v", err)
	}
}

// Each message type has its own context: only (device-link, device-accept) verifies for the two signatures of a certificate.
func TestCertContextSeparation(t *testing.T) {
	w := newWorld(t)
	contexts := []string{contextDeviceLink, contextDeviceAccept, contextDeviceRevoke, testContext}
	body := w.certE.body.signedBytes()
	for _, ci := range contexts {
		for _, cd := range contexts {
			c := *w.certE
			copy(c.issuerSig[:], mustSign(t, w.P, ci, body))
			copy(c.deviceSig[:], mustSign(t, w.E, cd, body))
			err := c.Verify(w.opts)
			if ci == contextDeviceLink && cd == contextDeviceAccept {
				if err != nil {
					t.Errorf("right contexts: %v", err)
				}
			} else if !errors.Is(err, ErrCertSignature) {
				t.Errorf("issuer context %q and device context %q: %v", ci, cd, err)
			}
		}
	}
	// A revocation signature is not a certificate signature and the other way round.
	r := revoke(t, w.P, &RevokeOptions{Person: w.P.PublicKey(), Device: w.E.PublicKey(), UpToSerial: 1})
	for _, ctx := range []string{contextDeviceLink, contextDeviceAccept, testContext} {
		x := *r
		x.sig = [64]byte(mustSign(t, w.P, ctx, r.sigBytes()))
		if err := w.certE.Verify(w.with(&x)); err != nil {
			t.Errorf("revocation signed under %q counted: %v", ctx, err)
		}
	}
	if !Verify(w.P.PublicKey(), contextDeviceRevoke, r.sigBytes(), r.sig[:]) {
		t.Error("setup: the real revocation signature must verify under its own context")
	}
	// A device signature made for an application context is not a certificate signature.
	msgSig := mustSign(t, w.E, testContext, body)
	c := *w.certE
	copy(c.deviceSig[:], msgSig)
	wantErr(t, "application signature as device signature", c.Verify(w.opts), ErrCertSignature)
}

func TestCertSmallOrderKeys(t *testing.T) {
	w := newWorld(t)
	for _, enc := range smallOrderEncodings() {
		key := enc[:]
		for slot := 0; slot < 3; slot++ {
			b := w.certE.body
			switch slot {
			case 0:
				copy(b.person[:], key)
				copy(b.issuer[:], key)
			case 1:
				copy(b.device[:], key)
			case 2:
				copy(b.issuer[:], key)
			}
			c := &DeviceCert{body: b, issuerSig: w.certE.issuerSig, deviceSig: w.certE.deviceSig}
			wantErr(t, "decode", decodeErr(c.Encode()), ErrInvalidCert)
			wantErr(t, "verify", c.Verify(&VerifyOptions{Person: w.P.PublicKey(), Now: baseTime}), ErrInvalidCert)
		}
		wantErr(t, "VerifyOptions.Person", w.certE.Verify(&VerifyOptions{Person: key}), ErrInvalidArgument)
		if _, err := w.P.OfferDeviceCert(key, &IssueOptions{Serial: 1}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("offer for a small-order device key: %v", err)
		}
		if _, err := w.P.RevokeDevice(&RevokeOptions{Person: w.P.PublicKey(), Device: key, UpToSerial: 1}); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("revocation of a small-order device key: %v", err)
		}
	}
	// A zero certificate is all small-order keys.
	wantErr(t, "zero certificate", (&DeviceCert{}).Verify(w.opts), ErrInvalidCert)
}

func TestVerifyDeviceMessage(t *testing.T) {
	w := newWorld(t)
	msg := []byte("hello kolo")
	sig := mustSign(t, w.D, testContext, msg)
	for name, c := range map[string]*DeviceCert{"approver-issued": w.certD} {
		if err := VerifyDevice(c, w.opts, testContext, msg, sig); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := VerifyDevice(w.certE, w.opts, testContext, msg, mustSign(t, w.E, testContext, msg)); err != nil {
		t.Errorf("root-issued: %v", err)
	}
	wantErr(t, "wrong message", VerifyDevice(w.certD, w.opts, testContext, []byte("other"), sig), ErrCertSignature)
	wantErr(t, "wrong context", VerifyDevice(w.certD, w.opts, "kolo-id/other/v0", msg, sig), ErrCertSignature)
	wantErr(t, "empty signature", VerifyDevice(w.certD, w.opts, testContext, msg, nil), ErrCertSignature)
	wantErr(t, "short signature", VerifyDevice(w.certD, w.opts, testContext, msg, sig[:63]), ErrCertSignature)
	wantErr(t, "nil certificate", VerifyDevice(nil, w.opts, testContext, msg, sig), ErrInvalidCert)
	wantErr(t, "zero certificate", VerifyDevice(&DeviceCert{}, w.opts, testContext, msg, sig), ErrInvalidCert)
	wantErr(t, "nil options", VerifyDevice(w.certD, nil, testContext, msg, sig), ErrInvalidArgument)
	wantErr(t, "no person", VerifyDevice(w.certD, &VerifyOptions{Now: baseTime}, testContext, msg, sig), ErrInvalidArgument)
	wantErr(t, "short person", VerifyDevice(w.certD, &VerifyOptions{Person: w.P.PublicKey()[:31]}, testContext, msg, sig), ErrInvalidArgument)
	wantErr(t, "empty context", VerifyDevice(w.certD, w.opts, "", msg, sig), ErrInvalidArgument)
	wantErr(t, "long context", VerifyDevice(w.certD, w.opts, strings.Repeat("x", 256), msg, sig), ErrInvalidArgument)
	// The person key's own signature is not a device signature; there is no "certificate optional" mode.
	personSig := mustSign(t, w.P, testContext, msg)
	wantErr(t, "message signed by the person key", VerifyDevice(w.certD, w.opts, testContext, msg, personSig), ErrCertSignature)
	wantErr(t, "message signed by the approver", VerifyDevice(w.certD, w.opts, testContext, msg, mustSign(t, w.A, testContext, msg)), ErrCertSignature)
}

// A device key is an ordinary key: plain Verify accepts it under the device key and refuses it under the person key.
func TestVerifyUnchanged(t *testing.T) {
	w := newWorld(t)
	msg := []byte("m")
	sig := mustSign(t, w.D, testContext, msg)
	if !Verify(w.D.PublicKey(), testContext, msg, sig) {
		t.Error("device signature under the device key")
	}
	if Verify(w.P.PublicKey(), testContext, msg, sig) {
		t.Error("device signature accepted under the person key")
	}
}

// Raw encodings for the decoder tests; nil fields take the value of a valid root-issued certificate.
type raw struct {
	typ, version         uint64
	person, device, iss  []byte
	serial               []byte
	issuedAt, expiresAt  []byte
	flags                []byte
	issuerSig, deviceSig []byte
	noDeviceSig          bool
	hasParent            byte
	parent               []byte
	extra                []byte
}

func uv(v uint64) []byte {
	var e kolocodec.Encoder
	e.PutUvarint(v)
	return e.Bytes()
}

func (r raw) bytes(w *world) []byte {
	def := func(b, d []byte) []byte {
		if b == nil {
			return d
		}
		return b
	}
	typ := r.typ
	if typ == 0 {
		typ = 2
	}
	var out []byte
	out = append(out, uv(typ)...)
	out = append(out, uv(r.version)...)
	out = append(out, def(r.person, w.P.PublicKey())...)
	out = append(out, def(r.device, w.E.PublicKey())...)
	out = append(out, def(r.iss, w.P.PublicKey())...)
	out = append(out, def(r.serial, uv(1))...)
	out = append(out, def(r.issuedAt, uv(uint64(baseTime.Unix())))...)
	out = append(out, def(r.expiresAt, uv(0))...)
	out = append(out, def(r.flags, uv(0))...)
	out = append(out, def(r.issuerSig, make([]byte, 64))...)
	if !r.noDeviceSig {
		out = append(out, def(r.deviceSig, make([]byte, 64))...)
	}
	out = append(out, r.hasParent)
	if r.hasParent == 1 {
		out = append(out, uv(uint64(len(r.parent)))...)
		out = append(out, r.parent...)
	}
	return append(out, r.extra...)
}

func TestDecodeRejectsStructure(t *testing.T) {
	w := newWorld(t)
	if _, err := DecodeDeviceCert(raw{}.bytes(w)); err != nil {
		t.Fatalf("the baseline raw certificate must decode: %v", err)
	}
	ten := func(n int) []byte { return bytes.Repeat([]byte{0x80}, n) }
	cases := map[string]raw{
		"offer type":                             {typ: 1},
		"revocation type":                        {typ: 3},
		"type 0":                                 {typ: 0xff},
		"version 1":                              {version: 1},
		"serial zero":                            {serial: uv(0)},
		"non-minimal serial":                     {serial: []byte{0x81, 0x00}},
		"overflowing serial":                     {serial: append(ten(9), 0x02)},
		"issuedAt over MaxInt64":                 {issuedAt: uv(1 << 63)},
		"expiresAt over MaxInt64":                {expiresAt: uv(1 << 63), issuedAt: uv(5)},
		"expiresAt equals issuedAt":              {expiresAt: uv(uint64(baseTime.Unix()))},
		"expiresAt before issuedAt":              {expiresAt: uv(uint64(baseTime.Unix()) - 1)},
		"flag 2":                                 {flags: uv(2)},
		"flag 3":                                 {flags: uv(3)},
		"non-minimal flags":                      {flags: []byte{0x80, 0x00}},
		"device equals person":                   {device: w.P.PublicKey()},
		"device equals issuer":                   {device: w.A.PublicKey(), iss: w.A.PublicKey()},
		"issuer is an approver without a parent": {iss: w.A.PublicKey()},
		"root-issued with a parent":              {hasParent: 1, parent: w.certA.Encode()},
		"hasParent byte 2":                       {hasParent: 2},
		"parent flag without bytes":              {hasParent: 1, parent: nil},
		"short key":                              {person: w.P.PublicKey()[:31]},
		"trailing byte":                          {extra: []byte{0}},
		"short signature":                        {issuerSig: make([]byte, 63)},
	}
	for name, r := range cases {
		if _, err := DecodeDeviceCert(r.bytes(w)); !errors.Is(err, ErrInvalidCert) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Approver-issued shapes.
	d := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1}
	copy(d.person[:], w.P.PublicKey())
	copy(d.device[:], w.D.PublicKey())
	copy(d.issuer[:], w.A.PublicKey())
	good := (&DeviceCert{body: d, parent: w.certA}).Encode()
	if _, err := DecodeDeviceCert(good); err != nil {
		t.Fatalf("baseline approver-issued: %v", err)
	}
	shapes := map[string]func(c *DeviceCert){
		"parent for another person":          func(c *DeviceCert) { p := *c.parent; p.body.person[0] ^= 1; c.parent = &p },
		"parent is another device":           func(c *DeviceCert) { copy(c.body.issuer[:], w.E.PublicKey()) },
		"parent is not an approver":          func(c *DeviceCert) { c.parent = w.certE; c.body.issuer = w.certE.body.device },
		"child is an approver":               func(c *DeviceCert) { c.body.flags = flagApprover },
		"parent issued by an approver":       func(c *DeviceCert) { c.parent = w.certD; c.body.issuer = w.certD.body.device },
		"device equals issuer, valid parent": func(c *DeviceCert) { c.body.device = c.body.issuer },
	}
	for name, mod := range shapes {
		c := &DeviceCert{body: d, parent: w.certA}
		mod(c)
		if _, err := DecodeDeviceCert(c.Encode()); !errors.Is(err, ErrInvalidCert) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A parent that itself carries a parent is refused even if the outer shape is fine.
	nested := raw{typ: 2, hasParent: 1, parent: w.certD.Encode(), iss: w.A.PublicKey(), device: w.E.PublicKey()}
	if _, err := DecodeDeviceCert(nested.bytes(w)); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("nested parent: %v", err)
	}
}

func TestDecodeRejectsSizes(t *testing.T) {
	w := newWorld(t)
	for name, enc := range map[string][]byte{"root-issued": w.certE.Encode(), "approver-issued": w.certD.Encode()} {
		if _, err := DecodeDeviceCert(enc); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for n := 0; n < len(enc); n++ {
			if _, err := DecodeDeviceCert(enc[:n]); !errors.Is(err, ErrInvalidCert) {
				t.Fatalf("%s truncated to %d: %v", name, n, err)
			}
		}
		if _, err := DecodeDeviceCert(append(bytes.Clone(enc), 0)); !errors.Is(err, ErrInvalidCert) {
			t.Errorf("%s with a trailing byte: %v", name, err)
		}
		if _, err := DecodeDeviceCert(append(bytes.Clone(enc), make([]byte, 600)...)); !errors.Is(err, ErrInvalidCert) {
			t.Errorf("%s oversized: %v", name, err)
		}
	}
	if _, err := DecodeDeviceCert(nil); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("nil: %v", err)
	}
	// The size bound is checked before parsing: 515 bytes are refused even when a prefix is a valid certificate.
	if _, err := DecodeDeviceCert(append(bytes.Clone(w.certD.Encode()), 0)); err == nil {
		t.Error("515 bytes")
	}
	// A certificate with a parent is refused where no parent is allowed: the nested parent has a 256-byte limit.
	big := raw{typ: 2, hasParent: 1, parent: make([]byte, 257), iss: w.A.PublicKey()}
	if _, err := DecodeDeviceCert(big.bytes(w)); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("257-byte parent: %v", err)
	}
	// Offers: same rules; a certificate is not an offer and an offer is not a certificate.
	offer, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	enc := offer.Encode()
	if o, err := DecodeCertOffer(enc); err != nil || !bytes.Equal(o.Encode(), enc) {
		t.Fatalf("offer round trip: %v", err)
	}
	for n := 0; n < len(enc); n++ {
		if _, err := DecodeCertOffer(enc[:n]); !errors.Is(err, ErrInvalidCert) {
			t.Fatalf("offer truncated to %d: %v", n, err)
		}
	}
	for name, b := range map[string][]byte{"trailing": append(bytes.Clone(enc), 1), "oversized": append(bytes.Clone(enc), make([]byte, 600)...), "a certificate": w.certD.Encode(), "a revocation": nil} {
		if _, err := DecodeCertOffer(b); !errors.Is(err, ErrInvalidCert) {
			t.Errorf("offer from %s: %v", name, err)
		}
	}
	if _, err := DecodeDeviceCert(enc); !errors.Is(err, ErrInvalidCert) {
		t.Errorf("certificate from an offer: %v", err)
	}
}

// Errors carry fixed text only: no key, signature or input byte appears in any message.
func TestNoSecretInErrors(t *testing.T) {
	w := newWorld(t)
	enc := w.certD.Encode()
	var errs []error
	for i := range enc {
		mut := bytes.Clone(enc)
		mut[i] ^= 0xff
		_, err := DecodeDeviceCert(mut)
		errs = append(errs, err)
		if c, err := DecodeDeviceCert(mut); err == nil {
			errs = append(errs, c.Verify(w.opts))
		}
		_, err = DecodeDeviceCert(enc[:i])
		errs = append(errs, err)
	}
	errs = append(errs, w.certD.Verify(&VerifyOptions{Person: w.E.PublicKey()}), w.certD.Verify(nil))
	for _, e := range errs {
		if e == nil {
			continue
		}
		s := e.Error()
		if !strings.HasPrefix(s, "koloid: ") || len(s) > 120 {
			t.Fatalf("unexpected error text %q", s)
		}
		for _, secret := range [][]byte{w.P.PublicKey(), w.A.PublicKey(), w.D.PublicKey(), w.certD.issuerSig[:], leakSeed()} {
			if strings.Contains(s, string(secret[:8])) || strings.Contains(s, hex.EncodeToString(secret[:8])) {
				t.Fatalf("error %q holds input bytes", s)
			}
		}
	}
}

func BenchmarkVerifyDevice(b *testing.B) {
	w := newWorld(b)
	msg := []byte("hello kolo")
	sig := mustSign(b, w.D, testContext, msg)
	opts := w.with(revoke(b, w.P, &RevokeOptions{Person: w.P.PublicKey(), Device: w.E.PublicKey(), UpToSerial: 1}))
	b.ResetTimer()
	for range b.N {
		if err := VerifyDevice(w.certD, opts, testContext, msg, sig); err != nil {
			b.Fatal(err)
		}
	}
}

// Hand-built chains with valid signatures: the structure rules do not depend on the signatures being bad.
func TestCertParentStructure(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	leaf := func(parent *DeviceCert) *DeviceCert {
		b := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1}
		copy(b.person[:], pp)
		copy(b.device[:], w.D.PublicKey())
		copy(b.issuer[:], w.A.PublicKey())
		c := &DeviceCert{body: b, parent: parent}
		copy(c.issuerSig[:], mustSign(t, w.A, contextDeviceLink, b.chainBytes(parent)))
		copy(c.deviceSig[:], mustSign(t, w.D, contextDeviceAccept, b.chainBytes(parent)))
		return c
	}
	approver := func(mod func(b *certBody)) *DeviceCert {
		b := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1, flags: flagApprover}
		copy(b.person[:], pp)
		copy(b.device[:], w.A.PublicKey())
		copy(b.issuer[:], pp)
		mod(&b)
		c := &DeviceCert{body: b}
		copy(c.issuerSig[:], mustSign(t, w.P, contextDeviceLink, b.signedBytes()))
		copy(c.deviceSig[:], mustSign(t, w.A, contextDeviceAccept, b.signedBytes()))
		return c
	}
	if err := leaf(approver(func(*certBody) {})).Verify(w.opts); err != nil {
		t.Fatalf("baseline hand-built chain: %v", err)
	}
	cases := map[string]func(b *certBody){
		"parent serial zero":            func(b *certBody) { b.serial = 0 },
		"parent unknown flag":           func(b *certBody) { b.flags = flagApprover | 2 },
		"parent expiry not after issue": func(b *certBody) { b.expiresAt = b.issuedAt },
		"parent time over MaxInt64":     func(b *certBody) { b.issuedAt = 1 << 63 },
		"parent device is the person":   func(b *certBody) { copy(b.device[:], pp) },
	}
	for name, mod := range cases {
		parent := approver(mod)
		wantErr(t, name, leaf(parent).Verify(w.opts), ErrInvalidCert)
		wantErr(t, name+" (decode)", decodeErr(leaf(parent).Encode()), ErrInvalidCert)
	}
	// A parent that holds a parent of its own, with the person as its issuer.
	nested := approver(func(*certBody) {})
	nested.parent = w.certA
	wantErr(t, "root-issued parent with a parent", leaf(nested).Verify(w.opts), ErrInvalidCert)
}

// Each signature of the parent counts when an offer is accepted or an approver signs.
func TestParentSignaturesChecked(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	offer, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(c *DeviceCert){
		"issuer signature of the parent": func(c *DeviceCert) { c.issuerSig[1] ^= 1 },
		"device signature of the parent": func(c *DeviceCert) { c.deviceSig[1] ^= 1 },
	} {
		p := *w.certA
		mod(&p)
		bad := *offer
		bad.parent = &p
		wantErr(t, name+" at accept", acceptErr(w.D, &bad, pp), ErrCertSignature)
		if _, err := w.A.OfferDeviceCert(w.E.PublicKey(), &IssueOptions{Parent: &p, Serial: 1}); !errors.Is(err, ErrCertSignature) {
			t.Errorf("%s at offer: %v", name, err)
		}
		child := *w.certD
		child.parent = &p
		wantErr(t, name+" at verify", child.Verify(w.opts), ErrCertSignature)
	}
	// Leaf signatures are checked separately too.
	for name, mod := range map[string]func(c *DeviceCert){
		"issuer signature": func(c *DeviceCert) { c.issuerSig[1] ^= 1 },
		"device signature": func(c *DeviceCert) { c.deviceSig[1] ^= 1 },
	} {
		c := *w.certD
		mod(&c)
		wantErr(t, name, c.Verify(w.opts), ErrCertSignature)
	}
}

// The largest values still decode and verify: nothing stops at MaxInt64 or MaxUint64 by accident.
func TestCertLargestValues(t *testing.T) {
	w := newWorld(t)
	max := time.Unix(math.MaxInt64, 0)
	c := issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: math.MaxUint64, IssuedAt: max})
	if err := c.Verify(&VerifyOptions{Person: w.P.PublicKey(), Now: baseTime}); err != nil {
		t.Errorf("issued at MaxInt64: %v", err)
	}
	if !c.IssuedAt().Equal(max) || c.Serial() != math.MaxUint64 {
		t.Error("accessors at the largest values")
	}
	c = issue(t, w.P, w.E, w.P.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime, ExpiresAt: max})
	if err := c.Verify(&VerifyOptions{Person: w.P.PublicKey(), Now: baseTime}); err != nil {
		t.Errorf("expires at MaxInt64: %v", err)
	}
}

// Structure rules that no other check implies, on hand-built chains whose signatures are all valid.
func TestCertStructureRulesAlone(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	sign := func(c *DeviceCert, issuer, device *Identity) *DeviceCert {
		copy(c.issuerSig[:], mustSign(t, issuer, contextDeviceLink, c.body.chainBytes(c.parent)))
		copy(c.deviceSig[:], mustSign(t, device, contextDeviceAccept, c.body.chainBytes(c.parent)))
		return c
	}
	body := func(device, issuer *Identity, person ed25519.PublicKey) certBody {
		b := certBody{issuedAt: uint64(baseTime.Unix()), serial: 1}
		copy(b.person[:], person)
		copy(b.device[:], device.PublicKey())
		copy(b.issuer[:], issuer.PublicKey())
		return b
	}
	// The person key as a device, certified by an approver.
	asDevice := sign(&DeviceCert{body: body(w.P, w.A, pp), parent: w.certA}, w.A, w.P)
	wantErr(t, "device is the person (approver-issued)", asDevice.Verify(w.opts), ErrInvalidCert)
	wantErr(t, "device is the person (decode)", decodeErr(asDevice.Encode()), ErrInvalidCert)
	// Times beyond MaxInt64 on a hand-built certificate are a structure error, not an expiry.
	for name, mod := range map[string]func(b *certBody){
		"expiresAt over MaxInt64": func(b *certBody) { b.expiresAt = 1 << 63 },
		"issuedAt over MaxInt64":  func(b *certBody) { b.issuedAt = 1 << 63 },
		"expiresAt max uint64":    func(b *certBody) { b.expiresAt = math.MaxUint64 },
	} {
		b := body(w.E, w.P, pp)
		mod(&b)
		c := sign(&DeviceCert{body: b}, w.P, w.E)
		wantErr(t, name, c.Verify(w.opts), ErrInvalidCert)
		wantErr(t, name+" (decode)", decodeErr(c.Encode()), ErrInvalidCert)
	}
	// An approver certificate of the same device key under another person is not a parent of this person's certificate.
	b := body(w.D, w.A, pp)
	foreign := foreignApprover(t, w.A)
	wantErr(t, "parent of another person", sign(&DeviceCert{body: b, parent: foreign}, w.A, w.D).Verify(w.opts), ErrInvalidCert)
	// An offer from an issuer that is neither the person nor proven by a parent is refused by the device.
	ob := body(w.D, w.A, pp)
	offer := &CertOffer{body: ob}
	copy(offer.issuerSig[:], mustSign(t, w.A, contextDeviceLink, ob.signedBytes()))
	wantErr(t, "offer without a parent", acceptErr(w.D, offer, pp), ErrInvalidCert)
}
