# Guide

Walkthrough of the API. The key file and JSON forms are in [formats.md](formats.md) and the bounds in [limits.md](limits.md). A complete program is in the README. [examples/basic](../examples/basic/main.go) creates, uses, saves and loads an identity in a temporary directory, and [examples/devices](../examples/devices/main.go) does the same for a recovery phrase and device certificates. What the phrase and a lost device can and cannot do is in [security.md](security.md).

## Create and sign

- `Generate()` creates a random identity. `FromSeed(seed)` derives one from a 32-byte seed.
- `(*Identity).Sign(context, msg)` signs with Ed25519ctx (RFC 8032). The context must be 1 to 255 bytes, otherwise `ErrInvalidContext`. Use one context per protocol and message type: a signature never verifies under another context.
- Never sign untrusted bytes under a `kolo-id/...` context. The library enforces this for the contexts it owns: `Sign` refuses every context that starts with `kolo-id/device-` (`ErrInvalidContext`), and `VerifyDevice` refuses them too (`ErrInvalidArgument`), so no application signature can pass as a certificate or a revocation. Plain `Verify` still checks them.
- `Verify(pub, context, msg, sig) bool` returns false on any bad input, including a public key of the wrong size, and never panics. It rejects small-order public keys, for which a signature can be forged without a private key.
- `PublicKey()` returns the public key and `PublicKeyString()` the same as hex.
- A nil or zero `Identity` returns `ErrInvalidIdentity` from `Sign`, `Save` and `SaveNew` instead of panicking.
- `(*Identity).Clear()` zeroes the private key the identity holds. Afterwards the identity, and every copy of the value, is invalid (`ErrInvalidIdentity`). It is not safe to call while another goroutine uses the identity. It cannot erase copies made by the Go runtime or the standard library: `crypto/ed25519` expands the seed when it signs, the garbage collector may move memory, and none of that is zeroed by `Clear`. It narrows the window; it does not remove it. See [security.md](security.md).

## Save

- `(*Identity).Save(path)` atomically replaces the file with the 32-byte seed, mode 0600 (on Windows the file takes the access rules of its directory). A symlink at the path is replaced, not followed. A missing parent directory is created with mode 0700. The path must end in a file name (`ErrInvalidKeyFile`).
- The directory is opened without following a symlink at it, checked like in `Load` before anything is written (`ErrInsecureKeyFile`), and the key is written through that open directory.
- If only the final directory sync fails, the new key is already in place and the error wraps `ErrSavedNotSynced`. If the temporary file cannot be removed, the error wraps `ErrTempLeft`, names that file and says the key was not saved.
- `(*Identity).SaveNew(path)` does the same but never replaces anything at the path, not even a dangling symlink: if something exists there it returns an error wrapping `fs.ErrExist`. It needs a filesystem with hard links. If the key is in place but its temporary file cannot be removed, the error wraps `ErrTempLeft`, names that file and says the key was saved.

## Load

`Load(path)` accepts only a path that ends in a file name (on Windows, not one ending in a dot or space) and names a regular file of exactly 32 bytes (`ErrInvalidKeyFile`). The path must not be a symlink. It does not block on a FIFO or a device.

On unix the directory is opened first with `O_DIRECTORY` and `O_NOFOLLOW` (`ErrInsecureKeyFile` if it is a symlink or not a directory), then checked and read only through that open directory.

- Linux and macOS: the directory is reached through its descriptor (`/proc/self/fd` or `/dev/fd`; if that is unavailable, `Load`, `Save` and `SaveNew` fail with `ErrInsecureKeyFile` instead of reopening by path) and the key file is opened with `openat` and `O_NOFOLLOW`, so nothing swapped in after the checks is followed. On Linux the key file is first opened with `O_PATH`, so a device swapped in is never opened; on macOS it is opened but never read.
- Other systems: `os.Root` reopens the directory by path, so a FIFO swapped in at that moment can still block, and it may follow a symlink inside the directory, which `Load` then rejects.

## Insecure key files

`ErrInsecureKeyFile` means the key file or its directory is not owned by the effective user or has group or other mode bits set. What is checked depends on the system:

| System | Checked |
|---|---|
| Every unix system | Owner and mode bits |
| Linux | POSIX ACLs too, because they show in the group bits (the ACL mask) |
| macOS | Also ACL entries that allow access (an ACL it cannot read exactly counts as one), and volumes mounted to ignore ownership |
| FreeBSD and illumos | NFSv4 ACLs (as on ZFS) are not checked |
| Non-unix systems | Nothing |

## Recovery phrase

A `Phrase` is 24 words in the BIP-39 English list: 256 bits of entropy and an 8-bit checksum. The words are the root of a person's identity; a person with several devices holds one phrase and one random key per device.

- `GeneratePhrase()` makes a phrase from `crypto/rand`. Show `Words()` once, let the user write them down, then call `Clear()` and drop the strings. The library never writes a phrase to disk, never prints it and has no function that shows a phrase again later. Go strings cannot be erased, so keep the words out of logs, state stores and crash reports. Create the phrase on a trusted device.
- `ParsePhrase(s)` reads 24 words separated by spaces, tabs or line breaks and ignores case. `ParseWords(words)` does the same for a split list. Only ASCII is accepted: a non-breaking space, an accent or a zero-width character makes the word unknown, because the library does no Unicode normalization. Input over 1024 bytes is refused.
- Errors are `ErrPhraseLength`, `ErrUnknownWord` (an `*UnknownWordError` that says the 1-based position of the word, never the word), `ErrPhraseChecksum` and `ErrInvalidPhrase` (nil, zero or cleared). No error text holds a word of the input. `Words` returns nil for an invalid phrase. A `Phrase` is not safe for concurrent use with `Clear`, and the strings that `Words` already returned are not erased.
- The embedded word list is checked at first use (2048 words and its SHA-256). If the check ever failed, `ParsePhrase`, `ParseWords`, `Words` and `Person` return an error and never panic.
- `Phrase.Person()` derives the person key: BIP-39 seed (empty passphrase, 2048 rounds of PBKDF2-HMAC-SHA512), then SLIP-0010 for Ed25519 at the hardened path `m/1802464367'/0'/0'`. The first number is the ASCII bytes of "kolo" as a BIP-43 purpose, then role 0 (person key) and account 0. The path can never change: another path would give another person key for the same words. Nothing else is derived from the phrase, and device keys are never derived from it.
- There is no BIP-39 passphrase. A mistyped passphrase would silently give another valid identity, and a second secret doubles the ways to lose the account.
- Under `GODEBUG=fips140=only`, Go's PBKDF2 refuses the 8-byte BIP-39 salt and its HMAC refuses the 12-byte SLIP-0010 master key, so `Person` returns an error that wraps `errors.ErrUnsupported` before any key is derived. It does not panic.
- A phrase that has a valid checksum but a typo is a different valid identity: one random typing error in 256 passes the checksum. A restore screen should show the person key (`PublicKeyString`) so the user can see it is the expected one.
- Never type the words anywhere but the restore screen. A `*Phrase` prints as `koloid.Phrase{redacted}` for every `fmt` verb and in `log/slog`, and `MarshalText`, `MarshalJSON` and the decoders return `ErrNotEncodable`.

## Device certificates

A person key never lives on a device. The first device gets an approver certificate, signed by the person key from the phrase. An approver adds and revokes ordinary devices without the phrase; only the phrase adds or revokes an approver. A chain is at most person, approver, device.

Add a device in two steps. The issuer signs an offer that names the device key; the device signs the finished certificate, which proves it holds its key:

```go
// The person key (from the phrase) certifies the first device as an approver.
// Every device and every verifier pins personKey; it never comes out of a certificate that is being checked.
personKey := person.PublicKey()
offer, err := person.OfferDeviceCert(laptop.PublicKey(), &koloid.IssueOptions{Serial: 1, Approver: true})
laptopCert, err := laptop.AcceptDeviceCert(offer, personKey)

// Later, the laptop adds a phone with no phrase.
// A real phone gets personKey from the linking exchange, not from the offer or the certificate.
offer, err = laptop.OfferDeviceCert(phone.PublicKey(), &koloid.IssueOptions{Parent: laptopCert, Serial: 1})
phoneCert, err := phone.AcceptDeviceCert(offer, personKey)

// A verifier states the person it expects.
err = koloid.VerifyDevice(phoneCert, &koloid.VerifyOptions{Person: personKey, Revocations: revocations}, "myapp/message/v0", msg, sig)
```

- `IssueOptions`: `Serial` is at least 1 and chosen by the caller (the library keeps no state), `IssuedAt` is zero for now, `ExpiresAt` is zero for never, `Approver` is allowed only for the person key, and `Parent` is the signer's own approver certificate when an approver signs. Times are truncated to whole seconds: a fractional `ExpiresAt` expires up to 1 s early, and an `ExpiresAt` in the same second as `IssuedAt` is `ErrInvalidArgument`. An `ExpiresAt` at or before 1970 is `ErrInvalidArgument` too, so it can never become "never".
- `DeviceCert.Person()` and `DeviceCert.Issuer()` are claims in unverified bytes. Never use them as a trust anchor: pin the person key in your own state, as in the snippet.
- `Encode` and `DecodeCertOffer`, `DecodeDeviceCert` and `DecodeRevocation` move the objects over the network. Decoders refuse oversized input before parsing (certificate 256 or 514 bytes, offer 450, revocation 472), check every structure rule and never panic. They do not check signatures.
- `SaveCert(path, cert)` and `LoadCert(path)` keep the certificate next to the device key, for example `device.key` and `device.cert`: mode 0600 and the same directory checks as `Save` and `Load`. A loaded file is untrusted input; verify it before use.
- `VerifyDevice(cert, opts, context, msg, sig)` checks that a message was signed by a device of `opts.Person`. The verifier must pass the person it expects: a certificate never names its own trust anchor, and there is no mode that accepts a message without a certificate. `cert.Verify(opts)` runs the same checks without a message. Checks: structure, person, expiry at `opts.Now` (zero means now), revocation, every signature. A context that starts with `kolo-id/device-` is reserved and refused.
- The issuer signature and the device's acceptance signature of an approver-issued certificate cover the SHA-256 of the parent certificate's encoding, and the signature of an approver-signed revocation covers the SHA-256 of its signer certificate's encoding. A leaf cannot be moved to another certificate of the same approver key, and the device signs the whole chain it accepts. These hashes add nothing to the encoded sizes.
- `Revocations` in `VerifyOptions` is the list of records the caller holds. Invalid or unrelated records are ignored. Keep only records that already passed `Revocation.Verify`, bound the list, and keep every one: a verifier that keeps none cannot see a revoked device. The work is linear in the list: see [limits.md](limits.md).
- `RevokeDevice` has two forms. The person key (any device) or the device itself signs a revocation by serial: certificates of that key with a serial up to `UpToSerial` are void, and `math.MaxUint64` burns the key. An approver (`SignerCert`) revokes one ordinary-device certificate: `Target` is required, the signed body carries its hash, and `UpToSerial` is zero or the target's serial. `TargetHash` returns that hash, which covers the certificate's body, issuer and parent but not its signatures, and `Signer` returns the approver key that signed such a record (nil for the other two forms). Revoking an approver (by the person key) also voids every certificate it issued.
- Revocations are permanent. A revocation signed by an approver is judged by its signer certificate's structure and signatures, which must chain to the expected person; it does not matter whether the approver has since expired, been revoked or retired. A verified revocation never lapses and never un-revokes, so an application must keep every verified revocation. An approver's revocation applies only to the certificate it names: the same body, issuer and serial, whatever signature bytes it carries (a device key holder can re-sign its own acceptance into other valid bytes, so signatures are not part of the name). The way back from a hostile or mistaken approver revocation is a new certificate for the same device key with a new serial: it is another certificate, so the record does not cover it (the same body, issuer and serial would be the revoked certificate, whatever its signatures). A thief of an approver key keeps the power to sign such records after it is revoked: a record signed for a certificate that exists counts for good, and the library is stateless, so the caller decides which records to pass. Keep the time you first saw each record and, when the person revokes an approver, stop passing the approver-form records of that `Signer` first seen after that revocation. Never use a record's own time for this: a thief can back-date it. See [security.md](security.md). A person-signed or self-signed revocation covers serials up to its number, so recovery from it needs a serial above that number, and a burned key (`math.MaxUint64`) cannot recover: use a new key.
- `issuedAt` and a revocation's time are signed but decide nothing, because a thief can back-date them. Only the chain rule, the expiry and the serials decide.
- Signing contexts are `kolo-id/device-link/v0` (issuer), `kolo-id/device-accept/v0` (device) and `kolo-id/device-revoke/v0` (revocation), so a signature for one is never valid for another. Applications must use their own contexts for their own messages.
- Errors: `ErrInvalidArgument`, `ErrInvalidCert`, `ErrNotApprover`, `ErrCertSignature`, `ErrCertPerson`, `ErrCertExpired`, `ErrCertRevoked` and `ErrInvalidRevocation`. Each error is one line with a single `koloid:` prefix, wraps a fixed message and never holds input bytes. An option error from `OfferDeviceCert` or `RevokeDevice` has the text `koloid: invalid argument: <reason>` and matches both `ErrInvalidArgument` and the reason's sentinel (`ErrInvalidCert` or `ErrInvalidRevocation`). `ErrNotApprover` comes only from `OfferDeviceCert` and `RevokeDevice`. `Revocation.Verify` returns `ErrInvalidArgument`, `ErrInvalidRevocation` or `ErrCertSignature`.

## Printing

Hold identities as `*Identity`. Printing one with `fmt` or `log/slog` shows only the public key, and the seed is never printed, logged or serialized. A plain `Identity` value (not a pointer) prints an opaque code address, so do not log it; log the `*Identity`.

## Errors

For `errors.Is`: `ErrInvalidContext`, `ErrInvalidIdentity`, `ErrInvalidKeyFile`, `ErrInsecureKeyFile`, `ErrSavedNotSynced`, `ErrTempLeft` and `ErrNotDecodable`. The phrase and certificate errors are listed in their sections above. `SaveNew` on an existing path returns an error that wraps `fs.ErrExist`, and `Load` of a missing file returns one that wraps `fs.ErrNotExist`.
