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

var (
	// ErrInvalidArgument is returned for bad options: a zero serial, an expiry not after the issue time, a missing or small-order key, an empty, long or reserved context.
	ErrInvalidArgument = errors.New("koloid: invalid argument")
	// ErrInvalidCert is returned for a certificate or offer that is nil, truncated, oversized, not canonical, has trailing bytes or breaks a structure rule.
	ErrInvalidCert = errors.New("koloid: invalid device certificate")
	// ErrNotApprover is returned by [Identity.OfferDeviceCert] and [Identity.RevokeDevice] when the signing certificate is not an approver certificate.
	ErrNotApprover = errors.New("koloid: signer is not an approver")
	// ErrCertSignature is returned when a certificate, offer or revocation signature, or the message signature, does not verify.
	ErrCertSignature = errors.New("koloid: device certificate signature does not verify")
	// ErrCertPerson is returned when the certificate chain does not end at the expected person key.
	ErrCertPerson = errors.New("koloid: device certificate is for another person")
	// ErrCertExpired is returned when a certificate in the chain is past its expiry.
	ErrCertExpired = errors.New("koloid: device certificate expired")
	// ErrCertRevoked is returned when a valid revocation covers a certificate in the chain.
	ErrCertRevoked = errors.New("koloid: device certificate revoked")
	// ErrInvalidRevocation is returned for a revocation that is malformed, unrelated to the expected person or not allowed to revoke its target.
	ErrInvalidRevocation = errors.New("koloid: invalid revocation")
)

// Signing contexts; each message type has its own, so a signature made for one is never valid for another.
const (
	contextDeviceLink   = "kolo-id/device-link/v0"
	contextDeviceAccept = "kolo-id/device-accept/v0"
	contextDeviceRevoke = "kolo-id/device-revoke/v0"

	// contextReservedPrefix is refused by [Identity.Sign] and [VerifyDevice], so no application signature can pass as a certificate message.
	contextReservedPrefix = "kolo-id/device-"
)

const (
	flagApprover  = 1
	maxUnixSecond = math.MaxInt64
)

// certBody is the part of a certificate that the issuer and the device sign.
type certBody struct {
	person, device, issuer [32]byte
	serial                 uint64
	issuedAt, expiresAt    uint64 // Unix seconds, at most MaxInt64; expiresAt 0 means never
	flags                  uint64
}

// DeviceCert says that a device key belongs to a person key; it is public, immutable and trusted only after [VerifyDevice] or [DeviceCert.Verify].
type DeviceCert struct {
	body      certBody
	issuerSig [64]byte
	deviceSig [64]byte
	parent    *DeviceCert // the issuer's approver certificate; nil when the person key issued this one
}

// CertOffer is a certificate signed by its issuer that the device has not accepted yet.
type CertOffer struct {
	body      certBody
	issuerSig [64]byte
	parent    *DeviceCert
}

// Person returns the person key the certificate claims, an unverified claim that is never a trust anchor; nil for a nil certificate.
func (c *DeviceCert) Person() ed25519.PublicKey {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.body.person[:])
}

// Device returns the certified device key, or nil for a nil certificate.
func (c *DeviceCert) Device() ed25519.PublicKey {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.body.device[:])
}

// Issuer returns the key that claims to have signed the certificate, an unverified claim that is never a trust anchor; nil for a nil certificate.
func (c *DeviceCert) Issuer() ed25519.PublicKey {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.body.issuer[:])
}

// Serial returns the serial chosen by the issuer; a revocation covers the serials up to its UpToSerial.
func (c *DeviceCert) Serial() uint64 {
	if c == nil {
		return 0
	}
	return c.body.serial
}

// IssuedAt returns the issue time in whole seconds; it is informational, because a thief can back-date it.
func (c *DeviceCert) IssuedAt() time.Time {
	if c == nil {
		return time.Time{}
	}
	return unixTime(c.body.issuedAt)
}

// ExpiresAt returns the expiry in whole seconds, or the zero time for never; a fractional expiry given to the issuer was truncated, so it came up to 1 s early.
func (c *DeviceCert) ExpiresAt() time.Time {
	if c == nil || c.body.expiresAt == 0 {
		return time.Time{}
	}
	return unixTime(c.body.expiresAt)
}

// Approver reports whether the device may certify and revoke ordinary devices without the phrase.
func (c *DeviceCert) Approver() bool { return c != nil && c.body.flags&flagApprover != 0 }

func unixTime(sec uint64) time.Time { return time.Unix(int64(sec), 0).UTC() }

// reasonError is a sentinel with a reason; its text has a single "koloid:" prefix and it matches every sentinel in kind and also.
type reasonError struct {
	kind   error
	reason string
	also   []error
}

func (e *reasonError) Error() string   { return e.kind.Error() + ": " + e.reason }
func (e *reasonError) Unwrap() []error { return append([]error{e.kind}, e.also...) }

func badCert(reason string) error { return &reasonError{kind: ErrInvalidCert, reason: reason} }

// invalidArgument turns a structure error into an [ErrInvalidArgument] that still matches the original sentinels.
func invalidArgument(err error) error {
	var re *reasonError
	if !errors.As(err, &re) {
		return ErrInvalidArgument
	}
	return &reasonError{kind: ErrInvalidArgument, reason: re.reason, also: append([]error{re.kind}, re.also...)}
}

func validKey(k []byte) bool { return len(k) == ed25519.PublicKeySize && !smallOrder(k) }

// check enforces the structure rules of a certificate body and its optional parent; it does not look at signatures.
func (b *certBody) check(parent *DeviceCert) error {
	// The person key is the issuer or the parent's person, so the checks of those cover it.
	if !validKey(b.device[:]) || !validKey(b.issuer[:]) {
		return badCert("invalid key")
	}
	if b.device == b.person || b.device == b.issuer {
		return badCert("device key equals person or issuer key")
	}
	if b.serial < 1 {
		return badCert("serial is zero")
	}
	if b.issuedAt > maxUnixSecond || b.expiresAt > maxUnixSecond || (b.expiresAt != 0 && b.expiresAt <= b.issuedAt) {
		return badCert("invalid time")
	}
	if b.flags&^flagApprover != 0 {
		return badCert("unknown flag")
	}
	if b.issuer == b.person {
		if parent != nil {
			return badCert("root-issued certificate has a parent")
		}
		return nil
	}
	if parent == nil || parent.parent != nil {
		return badCert("approver-issued certificate needs one root-issued parent")
	}
	if err := parent.body.check(nil); err != nil {
		return err
	}
	if parent.body.device != b.issuer || parent.body.person != b.person {
		return badCert("parent does not match")
	}
	if parent.body.flags&flagApprover == 0 || b.flags&flagApprover != 0 {
		return badCert("approvers cannot issue approvers")
	}
	return nil
}

// signedBytes is the encoding that the issuer and the device sign.
func (b *certBody) signedBytes() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(0) // version
	e.PutFixed(b.person[:])
	e.PutFixed(b.device[:])
	e.PutFixed(b.issuer[:])
	e.PutUvarint(b.serial)
	e.PutUvarint(b.issuedAt)
	e.PutUvarint(b.expiresAt)
	e.PutUvarint(b.flags)
	return e.Bytes()
}

// chainBytes is what the issuer and the device sign: the body and, for an approver-issued certificate, the SHA-256 of the parent's encoding.
// The parent is hashed whole because its signer chose its bytes; a revocation names a certificate by these bytes, see certHash.
func (b *certBody) chainBytes(parent *DeviceCert) []byte {
	out := b.signedBytes()
	if parent != nil {
		sum := sha256.Sum256(parent.Encode())
		out = append(out, sum[:]...)
	}
	return out
}

// issuerSigOK verifies the issuer signature of b over its body and parent.
func (b *certBody) issuerSigOK(sig *[64]byte, parent *DeviceCert) bool {
	return Verify(b.issuer[:], contextDeviceLink, b.chainBytes(parent), sig[:])
}

// deviceSigOK verifies the device acceptance signature of b over its body and parent.
func (b *certBody) deviceSigOK(sig *[64]byte, parent *DeviceCert) bool {
	return Verify(b.device[:], contextDeviceAccept, b.chainBytes(parent), sig[:])
}

// chainSigsOK verifies the signatures of the parent, if any, and the issuer signature of b.
func chainSigsOK(b *certBody, issuerSig *[64]byte, parent *DeviceCert) bool {
	if parent != nil && !(parent.body.issuerSigOK(&parent.issuerSig, nil) && parent.body.deviceSigOK(&parent.deviceSig, nil)) {
		return false
	}
	return b.issuerSigOK(issuerSig, parent)
}

// IssueOptions are the choices of [Identity.OfferDeviceCert].
type IssueOptions struct {
	// Parent is nil when the signing identity is the person key; otherwise the signer's own approver certificate.
	Parent *DeviceCert
	// Serial is at least 1 and chosen by the caller; the library keeps no state.
	Serial uint64
	// IssuedAt is zero for now; it is truncated to whole seconds.
	IssuedAt time.Time
	// ExpiresAt is zero for never, otherwise after IssuedAt; it is truncated to whole seconds, so a fraction expires up to 1 s early.
	ExpiresAt time.Time
	// Approver gives the device the right to certify and revoke ordinary devices; only the person key may set it.
	Approver bool
}

// OfferDeviceCert signs an offer that makes device a device of a person, with i as the person key (o.Parent nil) or an approver (o.Parent its certificate).
// The device completes the certificate with [Identity.AcceptDeviceCert].
func (i *Identity) OfferDeviceCert(device ed25519.PublicKey, o *IssueOptions) (*CertOffer, error) {
	if !i.valid() {
		return nil, ErrInvalidIdentity
	}
	if o == nil || !validKey(device) {
		return nil, ErrInvalidArgument
	}
	issuedAt := o.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	b := certBody{serial: o.Serial, issuedAt: uint64(issuedAt.Unix())}
	if !o.ExpiresAt.IsZero() {
		if o.ExpiresAt.Unix() <= 0 {
			return nil, ErrInvalidArgument
		}
		b.expiresAt = uint64(o.ExpiresAt.Unix())
	}
	copy(b.device[:], device)
	copy(b.issuer[:], i.PublicKey())
	if o.Parent == nil {
		b.person = b.issuer
		if o.Approver {
			b.flags = flagApprover
		}
	} else {
		if o.Approver {
			return nil, ErrInvalidArgument
		}
		if err := o.Parent.checkSelf(); err != nil {
			return nil, err
		}
		if !o.Parent.Approver() {
			return nil, ErrNotApprover
		}
		b.person = o.Parent.body.person
	}
	if err := b.check(o.Parent); err != nil {
		return nil, invalidArgument(err)
	}
	sig, err := i.sign(contextDeviceLink, b.chainBytes(o.Parent))
	if err != nil {
		return nil, err
	}
	offer := &CertOffer{body: b, parent: o.Parent}
	copy(offer.issuerSig[:], sig)
	return offer, nil
}

// checkSelf checks the structure and every signature of c and its parent, without person, expiry or revocation.
func (c *DeviceCert) checkSelf() error {
	if err := c.body.check(c.parent); err != nil {
		return err
	}
	if !chainSigsOK(&c.body, &c.issuerSig, c.parent) || !c.body.deviceSigOK(&c.deviceSig, c.parent) {
		return ErrCertSignature
	}
	return nil
}

// AcceptDeviceCert completes o into a certificate signed by the device key i, which proves the device holds it; person comes from the linking exchange, never from o.
func (i *Identity) AcceptDeviceCert(o *CertOffer, person ed25519.PublicKey) (*DeviceCert, error) {
	if !i.valid() {
		return nil, ErrInvalidIdentity
	}
	if !validKey(person) {
		return nil, ErrInvalidArgument
	}
	if o == nil {
		return nil, badCert("no offer")
	}
	if err := o.body.check(o.parent); err != nil {
		return nil, err
	}
	if !bytes.Equal(o.body.device[:], i.PublicKey()) {
		return nil, badCert("offer is for another device")
	}
	if !bytes.Equal(o.body.person[:], person) {
		return nil, ErrCertPerson
	}
	if !chainSigsOK(&o.body, &o.issuerSig, o.parent) {
		return nil, ErrCertSignature
	}
	sig, err := i.sign(contextDeviceAccept, o.body.chainBytes(o.parent))
	if err != nil {
		return nil, err
	}
	c := &DeviceCert{body: o.body, issuerSig: o.issuerSig, parent: o.parent}
	copy(c.deviceSig[:], sig)
	return c, nil
}

// VerifyOptions are the expectations of a verifier.
type VerifyOptions struct {
	// Person is required: the person key the caller expects. A certificate never names its own trust anchor.
	Person ed25519.PublicKey
	// Now is the time for expiry checks; zero is time.Now().
	Now time.Time
	// Revocations are the records the caller holds; invalid or unrelated ones are ignored. Keep only records that passed [Revocation.Verify], and bound the slice.
	Revocations []*Revocation
}

// certKey identifies a certificate by content, so equal signer certificates share one signature result.
type certKey struct {
	body                 certBody
	issuerSig, deviceSig [64]byte
}

// verifier holds the state of one verification call.
type verifier struct {
	person   [32]byte
	now      int64
	byDevice map[[32]byte][]*Revocation // the records, indexed once
	sigOK    map[*Revocation]bool       // result of each record's own signature
	signerOK map[certKey]bool           // result of each signer certificate's signatures
	checks   int                        // test seam: signature checks done for revocations
}

func newVerifier(o *VerifyOptions) (*verifier, error) {
	if o == nil || !validKey(o.Person) {
		return nil, ErrInvalidArgument
	}
	v := &verifier{now: o.Now.Unix()}
	if o.Now.IsZero() {
		v.now = time.Now().Unix()
	}
	for _, r := range o.Revocations {
		if r != nil {
			if v.byDevice == nil {
				v.byDevice = map[[32]byte][]*Revocation{}
			}
			v.byDevice[r.device] = append(v.byDevice[r.device], r)
		}
	}
	copy(v.person[:], o.Person)
	return v, nil
}

// cert runs the checks of [DeviceCert.Verify].
func (v *verifier) cert(c *DeviceCert) error {
	if c == nil {
		return badCert("no certificate")
	}
	if err := c.body.check(c.parent); err != nil {
		return err
	}
	if c.body.person != v.person {
		return ErrCertPerson
	}
	chain := []*DeviceCert{c}
	if c.parent != nil {
		chain = append(chain, c.parent)
	}
	for _, x := range chain {
		if x.body.expiresAt != 0 && int64(x.body.expiresAt) <= v.now {
			return ErrCertExpired
		}
	}
	for _, x := range chain {
		if v.revoked(x) {
			return ErrCertRevoked
		}
	}
	for _, x := range chain {
		if !x.body.issuerSigOK(&x.issuerSig, x.parent) || !x.body.deviceSigOK(&x.deviceSig, x.parent) {
			return ErrCertSignature
		}
	}
	return nil
}

// revoked reports whether a valid revocation in the list covers c: by serial for the person key and the device itself, by hash for an approver.
func (v *verifier) revoked(c *DeviceCert) bool {
	var h [32]byte
	hashed := false
	for _, r := range v.byDevice[c.body.device] {
		if r.approverSigned() {
			if !hashed {
				h, hashed = certHash(c), true
			}
			if r.target != h {
				continue
			}
		} else if c.body.serial > r.upToSerial {
			continue
		}
		if v.revocation(r, c) == nil {
			return true
		}
	}
	return false
}

// Verify checks that c is valid for opts.Person at opts.Now: structure, person, expiry, revocation and every signature. It never panics.
func (c *DeviceCert) Verify(opts *VerifyOptions) error {
	v, err := newVerifier(opts)
	if err != nil {
		return err
	}
	return v.cert(c)
}

// VerifyDevice reports nil when sig is a signature of msg under context by a device of opts.Person, after [DeviceCert.Verify].
// A context that starts with "kolo-id/device-" is reserved and is [ErrInvalidArgument].
func VerifyDevice(c *DeviceCert, opts *VerifyOptions, context string, msg, sig []byte) error {
	v, err := newVerifier(opts)
	if err != nil {
		return err
	}
	if !validContext(context) || reservedContext(context) {
		return ErrInvalidArgument
	}
	if err := v.cert(c); err != nil {
		return err
	}
	if !Verify(c.body.device[:], context, msg, sig) {
		return ErrCertSignature
	}
	return nil
}
