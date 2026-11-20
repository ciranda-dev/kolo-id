package koloid

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
)

var phraseErrorText = regexp.MustCompile(`^koloid: (invalid phrase|a phrase has 24 words|phrase checksum does not match|unknown word in phrase|unknown word at position [0-9]+)$`)

func FuzzParsePhrase(f *testing.F) {
	f.Add(abandonPhrase)
	f.Add(strings.ToUpper(abandonPhrase))
	f.Add(strings.ReplaceAll(abandonPhrase, " ", "\t\r\n"))
	f.Add(strings.Replace(abandonPhrase, " ", " ", 3))
	f.Add(strings.Replace(abandonPhrase, "art", "arm", 1))
	f.Add("")
	f.Add(strings.Repeat("zoo ", 24))
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParsePhrase(s)
		if err != nil {
			if p != nil || !phraseErrorText.MatchString(err.Error()) {
				t.Fatalf("error %q is not one of the fixed messages", err)
			}
			return
		}
		words := p.Words()
		if len(words) != 24 || len(s) > 1024 {
			t.Fatalf("%d words from %d bytes", len(words), len(s))
		}
		q, err := ParseWords(words)
		if err != nil || !equalStrings(q.Words(), words) {
			t.Fatalf("Words does not parse back: %v", err)
		}
		if _, err := ParsePhrase(strings.Join(words, " ")); err != nil {
			t.Fatal(err)
		}
	})
}

// oneLine reports whether err is a single line that starts with "koloid:".
func oneLine(err error) bool {
	s := err.Error()
	return strings.HasPrefix(s, "koloid: ") && !strings.ContainsAny(s, "\r\n")
}

func seedCerts(t testing.TB) (*world, [][]byte) {
	w := newWorld(t)
	offer, err := w.A.OfferDeviceCert(w.D.PublicKey(), &IssueOptions{Parent: w.certA, Serial: 2, IssuedAt: baseTime})
	if err != nil {
		t.Fatal(err)
	}
	rev := revoke(t, w.A, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), SignerCert: w.certA, Target: w.certD})
	byPerson := revoke(t, w.P, &RevokeOptions{Person: w.P.PublicKey(), Device: w.D.PublicKey(), UpToSerial: 1})
	return w, [][]byte{w.certA.Encode(), w.certD.Encode(), w.certE.Encode(), offer.Encode(), rev.Encode(), byPerson.Encode(), nil, {2}, bytes.Repeat([]byte{0xff}, 600)}
}

func FuzzDecodeDeviceCert(f *testing.F) {
	w, seeds := seedCerts(f)
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeDeviceCert(b)
		if err != nil {
			if c != nil || !oneLine(err) {
				t.Fatalf("decode: %v, %v", c, err)
			}
			return
		}
		if len(b) > 514 || !bytes.Equal(c.Encode(), b) {
			t.Fatalf("decoded %d bytes that do not re-encode to the input", len(b))
		}
		_ = c.Verify(w.opts)
	})
}

func FuzzDecodeCertOffer(f *testing.F) {
	_, seeds := seedCerts(f)
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := DecodeCertOffer(b)
		if err != nil {
			if o != nil || !oneLine(err) {
				t.Fatal("offer with an error")
			}
			return
		}
		if len(b) > 514 || !bytes.Equal(o.Encode(), b) {
			t.Fatalf("decoded %d bytes that do not re-encode to the input", len(b))
		}
	})
}

func FuzzDecodeRevocation(f *testing.F) {
	w, seeds := seedCerts(f)
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := DecodeRevocation(b)
		if err != nil {
			if r != nil || !oneLine(err) {
				t.Fatal("revocation with an error")
			}
			return
		}
		if len(b) > 472 || !bytes.Equal(r.Encode(), b) {
			t.Fatalf("decoded %d bytes that do not re-encode to the input", len(b))
		}
		_ = r.Verify(w.opts, w.certD)
		_ = w.certD.Verify(w.with(r))
	})
}

// FuzzVerifyDevice: arbitrary certificate bytes, message, signature and context never panic, and a nil error only ever comes
// for the exact certificates the test world issued: anything else would be a forged chain.
func FuzzVerifyDevice(f *testing.F) {
	w, seeds := seedCerts(f)
	msg := []byte("hello kolo")
	sig := mustSign(f, w.D, testContext, msg)
	known := [][]byte{w.certA.Encode(), w.certD.Encode(), w.certE.Encode()}
	for _, s := range seeds {
		f.Add(s, msg, sig, testContext)
	}
	f.Add(w.certE.Encode(), msg, mustSign(f, w.E, testContext, msg), testContext)
	f.Add(w.certD.Encode(), msg, sig, "")
	f.Add(w.certD.Encode(), []byte{}, []byte{}, testContext)
	// A forged chain: the approver certificate of a stranger and a certificate of the stranger's own device under P.
	stranger := idFrom(f, 0x55)
	forged := issue(f, stranger, w.D, stranger.PublicKey(), &IssueOptions{Serial: 1, IssuedAt: baseTime})
	f.Add(forged.Encode(), msg, sig, testContext)
	// A leaf moved to another certificate of the same approver key, and a reserved context.
	moved := *w.certD
	moved.parent = secondApproverCert(f, w)
	f.Add(moved.Encode(), msg, sig, testContext)
	f.Add(w.certD.Encode(), msg, mustSign(f, w.D, contextDeviceLink, msg), contextDeviceLink)
	f.Fuzz(func(t *testing.T, cert, m, s []byte, ctx string) {
		c, err := DecodeDeviceCert(cert)
		var verr error
		if err == nil {
			verr = VerifyDevice(c, w.opts, ctx, m, s)
		} else {
			verr = VerifyDevice(nil, w.opts, ctx, m, s)
		}
		if verr != nil && !oneLine(verr) {
			t.Fatalf("error text %q", verr)
		}
		if verr == nil {
			ok := false
			for _, k := range known {
				ok = ok || bytes.Equal(k, cert)
			}
			if !ok {
				t.Fatalf("verified a certificate that the world never issued: %x", cert)
			}
			if !Verify(c.Device(), ctx, m, s) {
				t.Fatal("VerifyDevice accepted a message that plain Verify refuses")
			}
		}
	})
}
