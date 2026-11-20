package koloid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"math"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// Revocation is public, immutable and permanent. The person key or the device itself voids a device's certificates up to a serial;
// an approver voids one ordinary-device certificate, named by the hash of its body and parent.
type Revocation struct {
	person, device, signer [32]byte
	upToSerial             uint64
	revokedAt              uint64   // Unix seconds, signed but never used to decide anything
	target                 [32]byte // certHash of the certificate an approver revoked; zero otherwise
	sig                    [64]byte
	signerCert             *DeviceCert // the signer's approver certificate; nil unless the signer is an approver device
}

// RevokeOptions are the choices of [Identity.RevokeDevice].
type RevokeOptions struct {
	Person ed25519.PublicKey
	Device ed25519.PublicKey
	// UpToSerial is at least 1 for the person key or the device itself, and voids the certificates of Device up to it; math.MaxUint64 burns the key.
	// An approver signs for one certificate: UpToSerial is zero or Target's serial.
	UpToSerial uint64
	// SignerCert is the signing device's approver certificate; nil when the signer is the person key or the device itself.
	SignerCert *DeviceCert
	// Target is the ordinary-device certificate an approver revokes, required with SignerCert and nil otherwise.
	Target *DeviceCert
	// At is zero for now; it is truncated to whole seconds and never decides validity.
	At time.Time
}

// RevokeDevice signs a revocation of o.Device with i, the person key, the device itself or an approver device (o.SignerCert, o.Target).
func (i *Identity) RevokeDevice(o *RevokeOptions) (*Revocation, error) {
	if !i.valid() {
		return nil, ErrInvalidIdentity
	}
	if o == nil || !validKey(o.Person) || !validKey(o.Device) {
		return nil, ErrInvalidArgument
	}
	at := o.At
	if at.IsZero() {
		at = time.Now()
	}
	r := &Revocation{upToSerial: o.UpToSerial, revokedAt: uint64(at.Unix()), signerCert: o.SignerCert}
	copy(r.person[:], o.Person)
	copy(r.device[:], o.Device)
	copy(r.signer[:], i.PublicKey())
	if r.signerCert != nil {
		if err := r.signerCert.checkSelf(); err != nil {
			return nil, err
		}
		if !r.signerCert.Approver() {
			return nil, ErrNotApprover
		}
	}
	if (o.Target != nil) != (r.signerCert != nil) {
		return nil, ErrInvalidArgument
	}
	if t := o.Target; t != nil {
		if err := t.checkSelf(); err != nil {
			return nil, err
		}
		if t.Approver() || t.body.person != r.person || t.body.device != r.device || (o.UpToSerial != 0 && o.UpToSerial != t.body.serial) {
			return nil, ErrInvalidArgument
		}
		r.upToSerial, r.target = t.body.serial, certHash(t)
	}
	if err := r.check(); err != nil {
		return nil, invalidArgument(err)
	}
	sig, err := i.sign(contextDeviceRevoke, r.sigBytes())
	if err != nil {
		return nil, err
	}
	copy(r.sig[:], sig)
	return r, nil
}

// Person returns the person key the revocation is for, or nil for a nil revocation.
func (r *Revocation) Person() ed25519.PublicKey {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.person[:])
}

// Device returns the revoked device key, or nil for a nil revocation.
func (r *Revocation) Device() ed25519.PublicKey {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.device[:])
}

// TargetHash returns the hash of the body, issuer and parent of the certificate an approver revoked, never of its signatures; nil when the person key or the device itself signed.
func (r *Revocation) TargetHash() []byte {
	if r == nil || !r.approverSigned() {
		return nil
	}
	return bytes.Clone(r.target[:])
}

// Signer returns the approver device key that signed an approver-form revocation, so an application can drop the records of a retired approver; nil when the person key or the device itself signed.
func (r *Revocation) Signer() ed25519.PublicKey {
	if r == nil || !r.approverSigned() {
		return nil
	}
	return bytes.Clone(r.signer[:])
}

// UpToSerial returns the highest serial the revocation voids; for an approver it is the serial of the one certificate it names.
func (r *Revocation) UpToSerial() uint64 {
	if r == nil {
		return 0
	}
	return r.upToSerial
}

func (r *Revocation) approverSigned() bool { return r.signer != r.person && r.signer != r.device }

func badRevocation(reason string) error {
	return &reasonError{kind: ErrInvalidRevocation, reason: reason}
}

// certHash names a certificate by its body and parent (chainBytes), never by its signatures: Ed25519 signatures are not unique,
// so a device key holder can re-sign the same acceptance into other bytes and must not be able to change the name a revocation uses.
func certHash(c *DeviceCert) [32]byte { return sha256.Sum256(c.body.chainBytes(c.parent)) }

// check enforces the structure rules of a revocation; it does not look at signatures.
func (r *Revocation) check() error {
	switch {
	case !validKey(r.person[:]) || !validKey(r.device[:]):
		return badRevocation("invalid key")
	case r.device == r.person:
		return badRevocation("device key equals person key")
	case r.upToSerial < 1:
		return badRevocation("serial is zero")
	case r.revokedAt > math.MaxInt64:
		return badRevocation("invalid time")
	case r.approverSigned() != (r.signerCert != nil):
		return badRevocation("signer certificate is present exactly for an approver signer")
	}
	if c := r.signerCert; c != nil {
		if err := c.body.check(nil); err != nil {
			var re *reasonError
			if errors.As(err, &re) {
				return &reasonError{kind: ErrInvalidRevocation, reason: "signer certificate: " + re.reason, also: []error{ErrInvalidCert}}
			}
			return badRevocation("signer certificate")
		}
		if c.body.device != r.signer || c.body.person != r.person || c.body.flags&flagApprover == 0 {
			return badRevocation("signer certificate does not match")
		}
	}
	return nil
}

// sigBytes is what the signer signs: the body and, for an approver signer, the SHA-256 of the signer certificate's encoding.
// The signer certificate is hashed whole because the signer chose its bytes.
func (r *Revocation) sigBytes() []byte {
	out := r.signedBytes()
	if r.signerCert != nil {
		sum := sha256.Sum256(r.signerCert.Encode())
		out = append(out, sum[:]...)
	}
	return out
}

func (r *Revocation) signedBytes() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(0) // version
	e.PutFixed(r.person[:])
	e.PutFixed(r.device[:])
	e.PutFixed(r.signer[:])
	e.PutUvarint(r.upToSerial)
	e.PutUvarint(r.revokedAt)
	if r.approverSigned() {
		e.PutFixed(r.target[:])
	}
	return e.Bytes()
}

func (r *Revocation) decodeBody(d *kolocodec.Decoder) (err error) {
	if _, err = d.UvarintMax(0); err != nil { // version
		return err
	}
	for _, k := range []*[32]byte{&r.person, &r.device, &r.signer} {
		raw, err := d.Fixed(32)
		if err != nil {
			return err
		}
		copy(k[:], raw)
	}
	if r.upToSerial, err = d.Uvarint(); err != nil {
		return err
	}
	if r.revokedAt, err = d.Uvarint(); err != nil {
		return err
	}
	if r.approverSigned() {
		raw, err := d.Fixed(32)
		if err != nil {
			return err
		}
		copy(r.target[:], raw)
	}
	return nil
}

// Encode returns the canonical encoding of r, at most 472 bytes; nil for a nil revocation.
func (r *Revocation) Encode() []byte {
	if r == nil {
		return nil
	}
	var e kolocodec.Encoder
	e.PutUvarint(typeRevocation)
	e.PutFixed(r.signedBytes())
	e.PutFixed(r.sig[:])
	e.PutBool(r.signerCert != nil)
	if r.signerCert != nil {
		e.PutBytes(r.signerCert.Encode())
	}
	return e.Bytes()
}

// Verify checks r for opts.Person: structure, signatures and the right of the signer to revoke target, which an approver-signed r needs and must name by hash; opts.Now is not used.
// Errors: [ErrInvalidArgument], [ErrInvalidRevocation], [ErrCertSignature].
func (r *Revocation) Verify(opts *VerifyOptions, target *DeviceCert) error {
	v, err := newVerifier(opts)
	if err != nil {
		return err
	}
	return v.revocation(r, target)
}

func (v *verifier) revocation(r *Revocation, target *DeviceCert) error {
	if r == nil {
		return ErrInvalidRevocation
	}
	if err := r.check(); err != nil {
		return err
	}
	if r.person != v.person {
		return ErrInvalidRevocation
	}
	if r.approverSigned() {
		if target == nil || target.body.person != r.person || target.body.device != r.device || target.Approver() ||
			target.body.serial != r.upToSerial || certHash(target) != r.target {
			return ErrInvalidRevocation
		}
	}
	ok, seen := v.sigOK[r]
	if !seen {
		v.checks++
		ok = Verify(r.signer[:], contextDeviceRevoke, r.sigBytes(), r.sig[:])
		if v.sigOK == nil {
			v.sigOK = map[*Revocation]bool{}
		}
		v.sigOK[r] = ok
	}
	if !ok || (r.approverSigned() && !v.signerSigsOK(r.signerCert)) {
		return ErrCertSignature
	}
	return nil
}

// signerSigsOK checks the two signatures of a signer certificate once per distinct certificate; expiry and later revocation are not looked at.
func (v *verifier) signerSigsOK(c *DeviceCert) bool {
	k := certKey{c.body, c.issuerSig, c.deviceSig}
	ok, seen := v.signerOK[k]
	if !seen {
		v.checks++
		ok = c.body.issuerSigOK(&c.issuerSig, nil)
		if ok {
			v.checks++
			ok = c.body.deviceSigOK(&c.deviceSig, nil)
		}
		if v.signerOK == nil {
			v.signerOK = map[certKey]bool{}
		}
		v.signerOK[k] = ok
	}
	return ok
}
