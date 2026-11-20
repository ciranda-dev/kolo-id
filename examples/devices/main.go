// Command devices shows a recovery phrase, a person key and two device certificates, all in a temporary directory.
// It never prints the phrase.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	koloid "github.com/ciranda-dev/kolo-id"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

// run returns errors instead of exiting, so the deferred cleanup always runs.
func run() error {
	dir, err := os.MkdirTemp("", "koloid-devices")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	// The person key comes from 24 words. An app shows them once and never stores them.
	phrase, err := koloid.GeneratePhrase()
	if err != nil {
		return err
	}
	person, err := phrase.Person()
	if err != nil {
		return err
	}
	words := phrase.Words()
	phrase.Clear()
	// Every device and verifier pins this key. It is never read out of a certificate that is being checked.
	personKey := person.PublicKey()
	fmt.Println("person:", person, "words:", len(words))

	// The first device gets an approver certificate. Each device has its own random key.
	laptop, err := koloid.Generate()
	if err != nil {
		return err
	}
	offer, err := person.OfferDeviceCert(laptop.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
	if err != nil {
		return err
	}
	laptopCert, err := laptop.AcceptDeviceCert(offer, personKey)
	if err != nil {
		return err
	}
	if err := save(dir, "laptop", laptop, laptopCert); err != nil {
		return err
	}

	// The laptop adds a phone without the phrase: the offer travels to the phone, the acceptance proves the phone holds its key.
	laptop, laptopCert, err = load(dir, "laptop")
	if err != nil {
		return err
	}
	phone, err := koloid.Generate()
	if err != nil {
		return err
	}
	offer, err = laptop.OfferDeviceCert(phone.PublicKey(), &koloid.IssueOptions{Parent: laptopCert, Serial: 1})
	if err != nil {
		return err
	}
	// A real phone learns personKey from the linking exchange, not from the offer.
	phoneCert, err := phone.AcceptDeviceCert(offer, personKey)
	if err != nil {
		return err
	}
	if err := save(dir, "phone", phone, phoneCert); err != nil {
		return err
	}

	// A verifier states the person it expects. A message from the phone verifies through its certificate.
	const ctx = "kolo-id/example/v0"
	msg := []byte("hello from the phone")
	sig, err := phone.Sign(ctx, msg)
	if err != nil {
		return err
	}
	opts := &koloid.VerifyOptions{Person: personKey}
	fmt.Println("phone message:", koloid.VerifyDevice(phoneCert, opts, ctx, msg, sig))

	// The laptop revokes the phone's certificate. A verifier that holds the revocation refuses that certificate from now on; revocations are permanent, so keep them.
	rev, err := laptop.RevokeDevice(&koloid.RevokeOptions{Person: personKey, Device: phone.PublicKey(), SignerCert: laptopCert, Target: phoneCert})
	if err != nil {
		return err
	}
	opts.Revocations = []*koloid.Revocation{rev}
	err = koloid.VerifyDevice(phoneCert, opts, ctx, msg, sig)
	fmt.Println("after revoking:", errors.Is(err, koloid.ErrCertRevoked))

	// The same words give the same person key on any new install.
	again, err := koloid.ParseWords(words)
	if err != nil {
		return err
	}
	restored, err := again.Person()
	if err != nil {
		return err
	}
	fmt.Println("restored the same person:", bytes.Equal(restored.PublicKey(), personKey))
	return nil
}

func save(dir, name string, id *koloid.Identity, cert *koloid.DeviceCert) error {
	if err := id.Save(filepath.Join(dir, name+".key")); err != nil {
		return err
	}
	return koloid.SaveCert(filepath.Join(dir, name+".cert"), cert)
}

func load(dir, name string) (*koloid.Identity, *koloid.DeviceCert, error) {
	id, err := koloid.Load(filepath.Join(dir, name+".key"))
	if err != nil {
		return nil, nil, err
	}
	cert, err := koloid.LoadCert(filepath.Join(dir, name+".cert"))
	return id, cert, err
}
