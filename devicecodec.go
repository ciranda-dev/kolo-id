package koloid

import (
	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// Message types of the outer layout, and the size bounds that follow from the layouts in docs/formats.md.
const (
	typeCertOffer  = 1
	typeDeviceCert = 2
	typeRevocation = 3

	maxCertSize       = 1 + 126 + 64 + 64 + 1                   // type, body, two signatures, no parent: 256
	maxCertWithParent = maxCertSize + 2 + maxCertSize           // a certificate with a parent: 514
	maxOfferSize      = 1 + 126 + 64 + 1 + 2 + maxCertSize      // type, body, issuer signature, flag, length, parent: 450
	maxRevocationSize = 1 + 116 + 32 + 64 + 1 + 2 + maxCertSize // type, body, target hash, signature, flag, length, signer certificate: 472
)

func (b *certBody) decode(d *kolocodec.Decoder) (err error) {
	if _, err = d.UvarintMax(0); err != nil { // version
		return err
	}
	for _, k := range []*[32]byte{&b.person, &b.device, &b.issuer} {
		raw, err := d.Fixed(32)
		if err != nil {
			return err
		}
		copy(k[:], raw)
	}
	if b.serial, err = d.Uvarint(); err != nil {
		return err
	}
	if b.issuedAt, err = d.Uvarint(); err != nil {
		return err
	}
	if b.expiresAt, err = d.Uvarint(); err != nil {
		return err
	}
	b.flags, err = d.Uvarint()
	return err
}

func decodeSig(d *kolocodec.Decoder, sig *[64]byte) error {
	raw, err := d.Fixed(64)
	if err != nil {
		return err
	}
	copy(sig[:], raw)
	return nil
}

type certParts struct {
	body                 certBody
	issuerSig, deviceSig [64]byte
	parent               *DeviceCert
}

// decodeParts reads the body, the signatures and the optional parent of an offer (withDeviceSig false) or a certificate.
func decodeParts(b []byte, typ uint64, maxSize int, withDeviceSig bool) (*certParts, error) {
	if len(b) > maxSize {
		return nil, badCert("too large")
	}
	d := kolocodec.NewDecoder(b)
	if t, _ := d.Uvarint(); t != typ { // t is 0 when the read fails, and no type is 0
		return nil, badCert("wrong message type")
	}
	p := &certParts{}
	if err := p.read(d, withDeviceSig); err != nil {
		return nil, badCert("malformed encoding")
	}
	if err := p.body.check(p.parent); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *certParts) read(d *kolocodec.Decoder, withDeviceSig bool) error {
	if err := p.body.decode(d); err != nil {
		return err
	}
	if err := decodeSig(d, &p.issuerSig); err != nil {
		return err
	}
	if withDeviceSig {
		if err := decodeSig(d, &p.deviceSig); err != nil {
			return err
		}
	}
	has, err := d.Bool()
	if err != nil {
		return err
	}
	if has {
		raw, err := d.Bytes(maxCertSize)
		if err != nil {
			return err
		}
		if p.parent, err = decodeCert(raw, maxCertSize); err != nil {
			return err
		}
	}
	return d.Done()
}

func decodeCert(b []byte, maxSize int) (*DeviceCert, error) {
	p, err := decodeParts(b, typeDeviceCert, maxSize, true)
	if err != nil {
		return nil, err
	}
	return &DeviceCert{body: p.body, issuerSig: p.issuerSig, deviceSig: p.deviceSig, parent: p.parent}, nil
}

// DecodeDeviceCert decodes a certificate written by [DeviceCert.Encode], checking structure but no signature.
// Input over 514 bytes is refused before parsing; every error wraps [ErrInvalidCert].
func DecodeDeviceCert(b []byte) (*DeviceCert, error) { return decodeCert(b, maxCertWithParent) }

// DecodeCertOffer decodes an offer written by [CertOffer.Encode] like [DecodeDeviceCert]; input over 450 bytes is refused.
func DecodeCertOffer(b []byte) (*CertOffer, error) {
	p, err := decodeParts(b, typeCertOffer, maxOfferSize, false)
	if err != nil {
		return nil, err
	}
	return &CertOffer{body: p.body, issuerSig: p.issuerSig, parent: p.parent}, nil
}

func encodeTail(e *kolocodec.Encoder, parent *DeviceCert) {
	e.PutBool(parent != nil)
	if parent != nil {
		e.PutBytes(parent.Encode())
	}
}

// Encode returns the canonical encoding of c, at most 256 bytes or 514 with a parent; nil for a nil certificate.
func (c *DeviceCert) Encode() []byte {
	if c == nil {
		return nil
	}
	var e kolocodec.Encoder
	e.PutUvarint(typeDeviceCert)
	e.PutFixed(c.body.signedBytes())
	e.PutFixed(c.issuerSig[:])
	e.PutFixed(c.deviceSig[:])
	encodeTail(&e, c.parent)
	return e.Bytes()
}

// Encode returns the canonical encoding of o, at most 450 bytes; nil for a nil offer.
func (o *CertOffer) Encode() []byte {
	if o == nil {
		return nil
	}
	var e kolocodec.Encoder
	e.PutUvarint(typeCertOffer)
	e.PutFixed(o.body.signedBytes())
	e.PutFixed(o.issuerSig[:])
	encodeTail(&e, o.parent)
	return e.Bytes()
}

// DecodeRevocation decodes a revocation written by [Revocation.Encode], checking structure but no signature.
// Input over 472 bytes is refused before parsing; every error wraps [ErrInvalidRevocation].
func DecodeRevocation(b []byte) (*Revocation, error) {
	if len(b) > maxRevocationSize {
		return nil, badRevocation("too large")
	}
	d := kolocodec.NewDecoder(b)
	if t, _ := d.Uvarint(); t != typeRevocation {
		return nil, badRevocation("wrong message type")
	}
	r := &Revocation{}
	if err := r.read(d); err != nil {
		return nil, badRevocation("malformed encoding")
	}
	if err := r.check(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Revocation) read(d *kolocodec.Decoder) error {
	if err := r.decodeBody(d); err != nil {
		return err
	}
	if err := decodeSig(d, &r.sig); err != nil {
		return err
	}
	has, err := d.Bool()
	if err != nil {
		return err
	}
	if has {
		raw, err := d.Bytes(maxCertSize)
		if err != nil {
			return err
		}
		if r.signerCert, err = decodeCert(raw, maxCertSize); err != nil {
			return err
		}
	}
	return d.Done()
}
