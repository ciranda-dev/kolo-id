// Command basic shows how to create, use, save and load a Kolo identity.
package main

import (
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
	// Generate a new identity. Printing it shows only the public key.
	me, err := koloid.Generate()
	if err != nil {
		return err
	}
	fmt.Println("identity:", me)

	// Sign a message under this program's context and verify the signature.
	const ctx = "kolo-id/example/v0"
	msg := []byte("hello kolo")
	sig, err := me.Sign(ctx, msg)
	if err != nil {
		return err
	}
	fmt.Println("valid:", koloid.Verify(me.PublicKey(), ctx, msg, sig))

	// Tamper with one byte and verify again.
	msg[0] ^= 1
	fmt.Println("tampered:", koloid.Verify(me.PublicKey(), ctx, msg, sig))

	// A signature never verifies under another context.
	msg[0] ^= 1
	fmt.Println("other context:", koloid.Verify(me.PublicKey(), "kolo-other/v0", msg, sig))

	// Save the identity to a temporary directory and load it back.
	dir, err := os.MkdirTemp("", "koloid-example")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, "id.key")
	if err := me.Save(path); err != nil {
		return err
	}
	loaded, err := koloid.Load(path)
	if err != nil {
		return err
	}
	fmt.Println("same key:", me.PublicKey().Equal(loaded.PublicKey()))
	return nil
}
