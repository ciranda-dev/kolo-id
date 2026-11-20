# kolo-id

Ed25519 node identity for Kolo.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

A Kolo node is known by its Ed25519 public key. kolo-id signs with Ed25519ctx from [RFC 8032](https://www.rfc-editor.org/info/rfc8032), and turns a 24-word recovery phrase into a person key with [BIP-39](https://github.com/bitcoin/bips/blob/0d1b892ddb21c22def4af4541bfed7a2a3480e4a/bip-0039.mediawiki) and [SLIP-0010](https://github.com/satoshilabs/slips/blob/a00312491693714d9bc1b6e4cb5b2e356e6c511e/slip-0010.md). It creates and stores the node key pair, signs messages and checks signatures from other peers. Only the 32-byte seed is stored on disk, in a file that is written with mode 0600 and checked again when it is loaded.

Every signature carries a context string, so a signature made for one protocol or message type is never accepted by another.

One person can use several devices. A 24-word recovery phrase gives a person key; each device keeps its own random key and a certificate signed by that person key, so a lost device is revoked without losing the identity. The phrase follows BIP-39 and SLIP-0010, and the certificates use the kolo-codec encoding.

It is pure Go with no cgo. Its dependencies are `golang.org/x/sys`, for the libc-backed `openat` on macOS, and kolo-codec.

## Install

```sh
go get github.com/ciranda-dev/kolo-id
```

## Quick start

Load the identity from a file, or create it on the first run, then sign a message and verify the signature. The program takes the key file path as its only argument; use a path in a temporary directory to try it. Save it outside the repository and run it with `go run . <key file>` in a module that requires kolo-id.

```go
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	koloid "github.com/ciranda-dev/kolo-id"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: myapp <key file>")
	}
	path := os.Args[1]

	me, err := koloid.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		if me, err = koloid.Generate(); err != nil {
			log.Fatal(err)
		}
		err = me.SaveNew(path)
	}
	if err != nil {
		log.Fatal(err)
	}

	const ctx = "myapp/hello/v0"
	sig, err := me.Sign(ctx, []byte("hello"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(me, koloid.Verify(me.PublicKey(), ctx, []byte("hello"), sig))
}
```

The program prints the identity, which shows only its public key, and `true`:

```text
$ go run . "$(mktemp -d)/node.key"
koloid.Identity{<public key in hex>} true
```

The identity is created on the first run only, so the node keeps the same public key across restarts. `SaveNew` never replaces an existing file, so a second process that races to create the key, or a dangling symlink to an unmounted volume, makes it fail instead of destroying a key. Keep the key file outside your project directory so it never ends up in a commit.

## API

| Symbol | What it does |
|---|---|
| `Generate()` | Create a random identity |
| `FromSeed(seed)` | Derive an identity from a 32-byte seed |
| `Sign(context, msg)` | Sign with Ed25519ctx (RFC 8032); the context is 1 to 255 bytes |
| `Verify(pub, context, msg, sig)` | Return false on any bad input; never panics |
| `Load(path)` | Read the seed from a key file after checking the file and its directory |
| `Save(path)` | Replace the key file atomically |
| `SaveNew(path)` | Create the key file; never replace anything at the path |
| `PublicKey()`, `PublicKeyString()` | The public key, and the same as hex |
| `Clear()` | Erase the private key held in memory (best effort) |
| `GeneratePhrase()`, `ParsePhrase(s)`, `ParseWords(words)` | Make or read a 24-word recovery phrase (BIP-39, English, ASCII) |
| `Phrase.Words()`, `Phrase.Person()`, `Phrase.Clear()` | The words, the person key at `m/1802464367'/0'/0'`, and erase the phrase |
| `OfferDeviceCert(device, opts)`, `AcceptDeviceCert(offer, person)` | The issuer offers a certificate; the device accepts it with its own key |
| `RevokeDevice(opts)` | Void a device's certificates up to a serial, or for an approver one exact certificate |
| `VerifyDevice(cert, opts, context, msg, sig)` | Check that a message came from a device of the expected person |
| `DeviceCert.Verify`, `Revocation.Verify` | Check a certificate or a revocation |
| `DecodeDeviceCert`, `DecodeCertOffer`, `DecodeRevocation`, `Encode` | The wire forms |
| `SaveCert(path, cert)`, `LoadCert(path)` | Keep the certificate next to the device key |

Use one context per protocol and message type, such as `"kolo-<lib>/<message>/v0"`. `Verify` rejects small-order public keys, for which a signature can be forged without a private key.

Hold identities as `*Identity`. Printing one with `fmt` or `log/slog` shows only the public key, and the seed is never printed, logged or serialized.

Hold a `*Phrase` the same way: it prints as redacted and never encodes. A phrase is shown once and never stored by the library. A certificate is not a credential: a verifier passes the person it expects, and a message always needs the device's private key.

Errors work with `errors.Is`: `ErrInvalidContext`, `ErrInvalidKeyFile`, `ErrInsecureKeyFile`, `ErrSavedNotSynced`, `ErrTempLeft`, `ErrInvalidIdentity` and `ErrNotDecodable`; the phrase and certificate errors are in [docs/guide.md](docs/guide.md). A key file that already exists makes `SaveNew` return an error wrapping `fs.ErrExist`.

## Platforms

How strictly a key file is checked depends on the system: Linux and macOS open the key through its directory descriptor, other unix systems check owner and mode bits, and non-unix systems check nothing. On Windows a saved file takes the access rules of its directory. The checks, per system, are in [docs/guide.md](docs/guide.md).

## More

- [docs/guide.md](docs/guide.md): saving and loading keys, the checks, printing and JSON, the recovery phrase and device certificates.
- [docs/security.md](docs/security.md): what the words, a stolen device and a revoked device can and cannot do.
- [docs/formats.md](docs/formats.md): the key file, the JSON form, the phrase and certificate layouts, and references.
- [docs/limits.md](docs/limits.md): bounds and what is rejected.
- [examples/basic](examples/basic/main.go) and [examples/devices](examples/devices/main.go): runnable examples.
- [third_party/licenses/NOTICE.md](third_party/licenses/NOTICE.md): the word list and test data from other projects, with source and license.
- [SECURITY.md](SECURITY.md): security policy.

## Status

Experimental. The API may change before v1.0.0.

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.
