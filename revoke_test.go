package koloid

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"
)

func TestRevokeDeviceErrors(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	ok := func() *RevokeOptions { return &RevokeOptions{Person: pp, Device: dev, UpToSerial: 1} }
	cases := []struct {
		name   string
		signer *Identity
		mod    func(o *RevokeOptions)
		want   error
	}{
		{"nil options", w.P, nil, ErrInvalidArgument},
		{"serial zero", w.P, func(o *RevokeOptions) { o.UpToSerial = 0 }, ErrInvalidArgument},
		{"nil person", w.P, func(o *RevokeOptions) { o.Person = nil }, ErrInvalidArgument},
		{"short device", w.P, func(o *RevokeOptions) { o.Device = dev[:31] }, ErrInvalidArgument},
		{"device is the person", w.P, func(o *RevokeOptions) { o.Device = pp }, ErrInvalidArgument},
		{"time before 1970", w.P, func(o *RevokeOptions) { o.At = time.Unix(-1, 0) }, ErrInvalidArgument},
		{"person key with a signer certificate", w.P, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Target = w.certD }, ErrInvalidArgument},
		{"person key with a target", w.P, func(o *RevokeOptions) { o.Target = w.certD }, ErrInvalidArgument},
		{"device itself with a target", w.D, func(o *RevokeOptions) { o.Target = w.certD }, ErrInvalidArgument},
		{"device itself with a signer certificate", w.D, func(o *RevokeOptions) { o.SignerCert = w.certD; o.Target = w.certD }, ErrNotApprover},
		{"stranger without a certificate", w.E, nil, ErrInvalidArgument},
		{"approver without a certificate", w.A, nil, ErrInvalidArgument},
		{"signer certificate of another device", w.E, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Target = w.certD }, ErrInvalidArgument},
		{"signer certificate is not an approver", w.E, func(o *RevokeOptions) { o.SignerCert = w.certE; o.Target = w.certD }, ErrNotApprover},
		{"signer certificate of another person", w.A, func(o *RevokeOptions) { o.SignerCert = foreignApprover(t, w.A); o.Target = w.certD }, ErrInvalidArgument},
		{"signer certificate with a bad signature", w.A, func(o *RevokeOptions) { o.SignerCert = corrupt(w.certA); o.Target = w.certD }, ErrCertSignature},
		{"approver without a target", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA }, ErrInvalidArgument},
		{"target is an approver", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Device = w.A.PublicKey(); o.Target = w.certA }, ErrInvalidArgument},
		{"target of another device", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Target = w.certE }, ErrInvalidArgument},
		{"target of another person", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Person = w.E.PublicKey(); o.Target = w.certD }, ErrInvalidArgument},
		{"serial that is not the target's", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Target = w.certD; o.UpToSerial = 2 }, ErrInvalidArgument},
		{"target with a bad signature", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Target = corrupt(w.certD) }, ErrCertSignature},
		{"target of another person with the same device", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Target = foreignDevice(t, w.D) }, ErrInvalidArgument},
		{"zero target", w.A, func(o *RevokeOptions) { o.SignerCert = w.certA; o.Target = &DeviceCert{} }, ErrInvalidCert},
	}
	for _, c := range cases {
		var o *RevokeOptions
		if c.mod != nil {
			o = ok()
			c.mod(o)
		}
		r, err := c.signer.RevokeDevice(o)
		if r != nil {
			t.Errorf("%s: got a revocation", c.name)
		}
		wantErr(t, c.name, err, c.want)
	}
	var none *Identity
	if _, err := none.RevokeDevice(ok()); !errors.Is(err, ErrInvalidIdentity) {
		t.Errorf("nil identity: %v", err)
	}
	for _, s := range []*Identity{w.P, w.D} {
		if _, err := s.RevokeDevice(ok()); err != nil {
			t.Errorf("person and device may sign: %v", err)
		}
	}
	for _, serial := range []uint64{0, 1} { // zero takes the target's serial
		r, err := w.A.RevokeDevice(&RevokeOptions{Person: pp, Device: dev, UpToSerial: serial, SignerCert: w.certA, Target: w.certD})
		if err != nil || r.UpToSerial() != 1 || !bytes.Equal(r.TargetHash(), func() []byte { h := certHash(w.certD); return h[:] }()) {
			t.Errorf("approver may sign for serial %d: %v", serial, err)
		}
	}
	if h := revoke(t, w.A, &RevokeOptions{Person: pp, Device: dev, SignerCert: w.certA, Target: w.certD}); true {
		x := h.TargetHash()
		x[0] ^= 1
		if bytes.Equal(x, h.TargetHash()) {
			t.Error("TargetHash returns the internal slice")
		}
	}
	if h := (*Revocation)(nil).TargetHash(); h != nil {
		t.Error("nil TargetHash")
	}
	if h := revoke(t, w.P, ok()).TargetHash(); h != nil {
		t.Errorf("person-signed TargetHash = %x", h)
	}
}

// An ordinary certificate for the same device key under a different person.
func foreignDevice(t testing.TB, device *Identity) *DeviceCert {
	other := idFrom(t, 0x78)
	return issue(t, other, device, other.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime})
}

// An approver certificate for the same device key under a different person.
func foreignApprover(t testing.TB, device *Identity) *DeviceCert {
	other := idFrom(t, 0x77)
	return issue(t, other, device, other.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime, Approver: true})
}

func TestRevocationVerifyRules(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	byPerson := revoke(t, w.P, &RevokeOptions{Person: pp, Device: dev, UpToSerial: 1})
	if err := byPerson.Verify(w.opts, nil); err != nil {
		t.Errorf("person-signed with no target: %v", err)
	}
	o := &RevokeOptions{Person: pp, Device: dev, SignerCert: w.certA, Target: w.certD}
	byApprover := revoke(t, w.A, o)
	if err := byApprover.Verify(w.opts, w.certD); err != nil {
		t.Errorf("approver-signed: %v", err)
	}
	wantErr(t, "approver-signed without a target", byApprover.Verify(w.opts, nil), ErrInvalidRevocation)
	wantErr(t, "approver-signed, target of another device", byApprover.Verify(w.opts, w.certE), ErrInvalidRevocation)
	wantErr(t, "approver-signed, target an approver", byApprover.Verify(w.opts, w.certA), ErrInvalidRevocation)
	// The record names one exact certificate: another certificate of the same device, with another serial or not, is refused.
	d2 := issue(t, w.A, w.D, pp, &IssueOptions{Parent: w.certA, Serial: 2, IssuedAt: baseTime})
	wantErr(t, "approver-signed, another serial", byApprover.Verify(w.opts, d2), ErrInvalidRevocation)
	d1b := issue(t, w.A, w.D, pp, &IssueOptions{Parent: w.certA, Serial: 1, IssuedAt: baseTime.Add(time.Second)})
	wantErr(t, "approver-signed, same serial, another certificate", byApprover.Verify(w.opts, d1b), ErrInvalidRevocation)
	wrongSerial := *byApprover
	wrongSerial.upToSerial = 2
	wantErr(t, "approver-signed, serial that is not the target's", wrongSerial.Verify(w.opts, w.certD), ErrInvalidRevocation)
	retargeted := *byApprover
	retargeted.target[0] ^= 1
	wantErr(t, "approver-signed, other hash", retargeted.Verify(w.opts, w.certD), ErrInvalidRevocation)
	// A record that names a certificate of another person, hash and all, is refused for its person.
	foreign := foreignDevice(t, w.D)
	wantErr(t, "approver-signed, target of another person with a matching hash", handRecord(t, w, w.A, w.certA, foreign, 1).Verify(w.opts, foreign), ErrInvalidRevocation)
	otherPerson := &DeviceCert{body: w.certD.body, issuerSig: w.certD.issuerSig, deviceSig: w.certD.deviceSig, parent: w.certD.parent}
	otherPerson.body.person[0] ^= 1
	wantErr(t, "approver-signed, target of another person", byApprover.Verify(w.opts, otherPerson), ErrInvalidRevocation)
	wantErr(t, "wrong person", byPerson.Verify(&VerifyOptions{Person: w.E.PublicKey()}, nil), ErrInvalidRevocation)
	wantErr(t, "nil revocation", (*Revocation)(nil).Verify(w.opts, nil), ErrInvalidRevocation)
	wantErr(t, "zero revocation", (&Revocation{}).Verify(w.opts, nil), ErrInvalidRevocation)
	wantErr(t, "bad options", byPerson.Verify(nil, nil), ErrInvalidArgument)

	short := issue(t, w.P, w.A, pp, &IssueOptions{Serial: 2, IssuedAt: baseTime, ExpiresAt: baseTime.Add(time.Minute), Approver: true})
	o.SignerCert = short
	byShort := revoke(t, w.A, o)
	if err := byShort.Verify(&VerifyOptions{Person: pp, Now: baseTime.Add(time.Hour)}, w.certD); err != nil {
		t.Errorf("signer expired: a revocation is permanent: %v", err)
	}
	bad := *byPerson
	bad.sig[10] ^= 4
	wantErr(t, "bad signature", bad.Verify(w.opts, nil), ErrCertSignature)
	// A signer certificate whose own signature is broken.
	broken := *byApprover
	broken.signerCert = corrupt(w.certA)
	wantErr(t, "signer certificate signature", broken.Verify(w.opts, w.certD), ErrCertSignature)
	// The signature covers the target hash: a signed hash is not interchangeable.
	rehashed := *byApprover
	rehashed.target = certHash(w.certE)
	wantErr(t, "hash replaced after signing", rehashed.Verify(w.opts, w.certE), ErrInvalidRevocation)
	// The signature covers the serial: changing upToSerial invalidates it.
	raised := *byPerson
	raised.upToSerial = 99
	wantErr(t, "raised serial", raised.Verify(w.opts, nil), ErrCertSignature)
	moved := *byPerson
	copy(moved.device[:], w.E.PublicKey())
	wantErr(t, "retargeted device", moved.Verify(w.opts, nil), ErrCertSignature)
}

type rawRev struct {
	typ, version           uint64
	person, device, signer []byte
	upTo, at               []byte
	sig                    []byte
	has                    byte
	target                 []byte
	signerCert             []byte
	extra                  []byte
}

func (r rawRev) bytes(w *world) []byte {
	def := func(b, d []byte) []byte {
		if b == nil {
			return d
		}
		return b
	}
	typ := r.typ
	if typ == 0 {
		typ = 3
	}
	var out []byte
	out = append(out, uv(typ)...)
	out = append(out, uv(r.version)...)
	person, device, signer := def(r.person, w.P.PublicKey()), def(r.device, w.E.PublicKey()), def(r.signer, w.P.PublicKey())
	out = append(out, person...)
	out = append(out, device...)
	out = append(out, signer...)
	out = append(out, def(r.upTo, uv(1))...)
	out = append(out, def(r.at, uv(5))...)
	if !bytes.Equal(signer, person) && !bytes.Equal(signer, device) { // an approver signed: the body names the target
		out = append(out, def(r.target, make([]byte, 32))...)
	}
	out = append(out, def(r.sig, make([]byte, 64))...)
	out = append(out, r.has)
	if r.has == 1 {
		out = append(out, uv(uint64(len(r.signerCert)))...)
		out = append(out, r.signerCert...)
	}
	return append(out, r.extra...)
}

func TestDecodeRevocationRejects(t *testing.T) {
	w := newWorld(t)
	if _, err := DecodeRevocation(rawRev{}.bytes(w)); err != nil {
		t.Fatalf("baseline person-signed revocation: %v", err)
	}
	if _, err := DecodeRevocation(rawRev{signer: w.A.PublicKey(), has: 1, signerCert: w.certA.Encode()}.bytes(w)); err != nil {
		t.Fatalf("baseline approver-signed revocation: %v", err)
	}
	if _, err := DecodeRevocation(rawRev{signer: w.E.PublicKey()}.bytes(w)); err != nil {
		t.Fatalf("baseline self-signed revocation: %v", err)
	}
	cases := map[string]rawRev{
		"certificate type":                       {typ: 2},
		"offer type":                             {typ: 1},
		"version 1":                              {version: 1},
		"serial zero":                            {upTo: uv(0)},
		"non-minimal serial":                     {upTo: []byte{0x81, 0x00}},
		"time over MaxInt64":                     {at: uv(1 << 63)},
		"device equals person":                   {device: w.P.PublicKey()},
		"short key":                              {device: w.E.PublicKey()[:31]},
		"person-signed with a certificate":       {has: 1, signerCert: w.certA.Encode()},
		"self-signed with a certificate":         {signer: w.E.PublicKey(), has: 1, signerCert: w.certE.Encode()},
		"approver-signed without certificate":    {signer: w.A.PublicKey()},
		"approver certificate of another device": {signer: w.D.PublicKey(), has: 1, signerCert: w.certA.Encode()},
		"signer certificate not an approver":     {signer: w.E.PublicKey(), device: w.D.PublicKey(), has: 1, signerCert: w.certE.Encode()},
		"signer certificate with a parent":       {signer: w.D.PublicKey(), has: 1, signerCert: w.certD.Encode()},
		"signer certificate of another person":   {signer: w.A.PublicKey(), has: 1, signerCert: foreignApprover(t, w.A).Encode()},
		"bool 2":                                 {has: 2},
		"trailing byte":                          {extra: []byte{0}},
		"short signature":                        {sig: make([]byte, 63)},
		"oversized signer certificate":           {signer: w.A.PublicKey(), has: 1, signerCert: make([]byte, 257)},
		"short target hash":                      {signer: w.A.PublicKey(), has: 1, signerCert: w.certA.Encode(), target: make([]byte, 31)},
	}
	for name, r := range cases {
		if _, err := DecodeRevocation(r.bytes(w)); !errors.Is(err, ErrInvalidRevocation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	o := &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), SignerCert: w.certA, Target: w.certD}
	enc := revoke(t, w.A, o).Encode()
	for n := 0; n < len(enc); n++ {
		if _, err := DecodeRevocation(enc[:n]); !errors.Is(err, ErrInvalidRevocation) {
			t.Fatalf("truncated to %d: %v", n, err)
		}
	}
	for name, b := range map[string][]byte{"nil": nil, "oversized": append(bytes.Clone(enc), make([]byte, 473)...), "one byte over": append(bytes.Clone(enc), 0), "a certificate": w.certD.Encode()} {
		if _, err := DecodeRevocation(b); !errors.Is(err, ErrInvalidRevocation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	over := make([]byte, 473)
	if _, err := DecodeRevocation(over); !errors.Is(err, ErrInvalidRevocation) {
		t.Errorf("473 bytes: %v", err)
	}
}

func TestRevocationForge(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	for name, r := range map[string]*Revocation{
		"person":   revoke(t, w.P, &RevokeOptions{Person: pp, Device: dev, UpToSerial: 1}),
		"approver": revoke(t, w.A, &RevokeOptions{Person: pp, Device: dev, SignerCert: w.certA, Target: w.certD}),
	} {
		enc := r.Encode()
		for i := range enc {
			for bit := 0; bit < 8; bit++ {
				mut := bytes.Clone(enc)
				mut[i] ^= 1 << bit
				d, err := DecodeRevocation(mut)
				if err != nil {
					continue
				}
				if err := d.Verify(w.opts, w.certD); err == nil {
					t.Fatalf("%s: flipping bit %d of byte %d still verifies", name, bit, i)
				}
			}
		}
	}
}

func TestRevocationTimeDecidesNothing(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	far := time.Unix(math.MaxInt64, 0)
	for _, at := range []time.Time{time.Unix(0, 0), baseTime.Add(-1000 * time.Hour), far} {
		r := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.E.PublicKey(), UpToSerial: 1, At: at})
		wantErr(t, "revokedAt", w.certE.Verify(w.with(r)), ErrCertRevoked)
	}
}

func TestRevocationAccessors(t *testing.T) {
	w := newWorld(t)
	r := revoke(t, w.P, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), UpToSerial: 7})
	if !bytes.Equal(r.Person(), w.P.PublicKey()) || !bytes.Equal(r.Device(), w.D.PublicKey()) || r.UpToSerial() != 7 {
		t.Error("accessors")
	}
	p := r.Person()
	p[0] ^= 1
	if !bytes.Equal(r.Person(), w.P.PublicKey()) {
		t.Error("Person returns the internal slice")
	}
}

func TestRevokeDeviceShortKeys(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	for name, o := range map[string]*RevokeOptions{
		"short person": {Person: pp[:31], Device: dev, UpToSerial: 1},
		"long person":  {Person: append(bytes.Clone(pp), 0), Device: dev, UpToSerial: 1},
		"short device": {Person: pp, Device: dev[:31], UpToSerial: 1},
		"serial zero":  {Person: pp, Device: dev, UpToSerial: 0},
	} {
		if r, err := w.P.RevokeDevice(o); r != nil || !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: %v, %v", name, r, err)
		}
	}
}

// Structure rules on hand-built revocations with valid signatures: Verify enforces them without a decoder.
func TestRevocationStructureAlone(t *testing.T) {
	w := newWorld(t)
	pp, dev := w.P.PublicKey(), w.D.PublicKey()
	resign := func(r *Revocation, signer *Identity) *Revocation {
		r.sig = [64]byte(mustSign(t, signer, contextDeviceRevoke, r.sigBytes()))
		return r
	}
	base := func() *Revocation {
		r := &Revocation{upToSerial: 1, revokedAt: 5}
		copy(r.person[:], pp)
		copy(r.device[:], dev)
		copy(r.signer[:], pp)
		return r
	}
	if err := resign(base(), w.P).Verify(w.opts, nil); err != nil {
		t.Fatalf("baseline: %v", err)
	}
	cases := map[string]func(r *Revocation){
		"serial zero":             func(r *Revocation) { r.upToSerial = 0 },
		"revokedAt over MaxInt64": func(r *Revocation) { r.revokedAt = 1 << 63 },
		"device is the person":    func(r *Revocation) { r.device = r.person },
	}
	for name, mod := range cases {
		r := base()
		mod(r)
		wantErr(t, name, resign(r, w.P).Verify(w.opts, nil), ErrInvalidRevocation)
	}
	// A self-signed record has no certificate to vouch for the person key, so the person key is checked on its own.
	for _, enc := range smallOrderEncodings() {
		r := base()
		copy(r.person[:], enc[:])
		copy(r.signer[:], dev)
		wantErr(t, "small-order person", resign(r, w.D).Verify(w.opts, nil), ErrInvalidRevocation)
		wantErr(t, "small-order person (decode)", decodeRevErr(r.Encode()), ErrInvalidRevocation)
		r = base()
		copy(r.device[:], enc[:])
		wantErr(t, "small-order device", resign(r, w.P).Verify(w.opts, nil), ErrInvalidRevocation)
		wantErr(t, "small-order device (decode)", decodeRevErr(r.Encode()), ErrInvalidRevocation)
	}
	// An approver-signed record whose signer certificate breaks a structure rule that nothing else implies.
	for name, mod := range map[string]func(c *DeviceCert){
		"signer certificate serial zero":        func(c *DeviceCert) { c.body.serial = 0 },
		"signer certificate time over MaxInt64": func(c *DeviceCert) { c.body.issuedAt = 1 << 63 },
		"signer certificate unknown flag":       func(c *DeviceCert) { c.body.flags = flagApprover | 2 },
	} {
		c := *w.certA
		mod(&c)
		r := base()
		copy(r.signer[:], w.A.PublicKey())
		r.signerCert, r.target = &c, certHash(w.certD)
		wantErr(t, name, resign(r, w.A).Verify(w.opts, w.certD), ErrInvalidRevocation)
	}
}

func decodeRevErr(b []byte) error {
	_, err := DecodeRevocation(b)
	return err
}

// The same invalid record twice, and a valid one twice, give the same answers: nothing is remembered wrongly.
func TestRevocationRepeatedRecord(t *testing.T) {
	w := newWorld(t)
	pp := w.P.PublicKey()
	good := revoke(t, w.P, &RevokeOptions{Person: pp, Device: w.E.PublicKey(), UpToSerial: 1})
	bad := *good
	bad.sig[2] ^= 1
	if err := w.certE.Verify(w.with(&bad, &bad, &bad)); err != nil {
		t.Errorf("a record with a bad signature, repeated: %v", err)
	}
	wantErr(t, "a good record, repeated", w.certE.Verify(w.with(good, good)), ErrCertRevoked)
	wantErr(t, "bad, then good", w.certE.Verify(w.with(&bad, good, &bad)), ErrCertRevoked)
}
