# Limits

This page is reference material: the README does not repeat it.

| What | Bound | Error |
|---|---|---|
| Signing context | 1 to 255 bytes | `ErrInvalidContext` |
| Seed in `FromSeed` | exactly 32 bytes | an error that starts with `koloid:` |
| Key file | a regular file of exactly 32 bytes; not a symlink; the path ends in a file name | `ErrInvalidKeyFile` |
| Key file and directory ownership and mode | owned by the effective user, no group or other mode bits (see [guide.md](guide.md) for what each system checks) | `ErrInsecureKeyFile` |
| Public key in `Verify` | 32 bytes, not of small order | `Verify` returns false |
| Key file mode written | 0600; a created parent directory 0700 | |
| Phrase | exactly 24 words of the BIP-39 English list, ASCII only | `ErrPhraseLength`, `ErrUnknownWord`, `ErrPhraseChecksum` |
| Phrase input in `ParsePhrase` | at most 1024 bytes (a phrase is 215 bytes at most; the rest is room for whitespace) | `ErrPhraseLength` |
| Certificate | at most 256 bytes, or 514 with an approver parent; the nested parent at most 256 | `ErrInvalidCert` |
| Offer | at most 450 bytes (192 without a parent); the nested parent at most 256 | `ErrInvalidCert` |
| Revocation | at most 472 bytes (182 for the person key or the device itself) | `ErrInvalidRevocation` |
| Certificate file | 1 to 514 bytes | `ErrInvalidKeyFile` |
| Chain depth | person, approver, device: at most 2 certificates; an approver cannot issue an approver | `ErrInvalidCert` |
| Serial | at least 1 | `ErrInvalidArgument`, `ErrInvalidCert` |
| Times in a certificate | Whole Unix seconds from 0 to 2^63-1 (fractions are truncated); `expiresAt` 0 means never, otherwise after `issuedAt`; an `ExpiresAt` option at or before 1970 is refused | `ErrInvalidArgument`, `ErrInvalidCert` |
| Signing context | `Sign` refuses a context that starts with `kolo-id/device-`; `VerifyDevice` refuses it too | `ErrInvalidContext`, `ErrInvalidArgument` |
| Work per `VerifyDevice` | at most 4 certificate signatures and 1 message signature, plus for the revocations: indexing the list once, at most 1 signature check per record that names the device and covers the serial, and 2 per distinct signer certificate | |

- `Verify` returns false on any bad input and never panics.
- `Load` does not block on a FIFO or a device.
- `SaveNew` needs a filesystem with hard links.
- On Linux and macOS, if the directory descriptor path (`/proc/self/fd` or `/dev/fd`) is unavailable, `Load`, `Save` and `SaveNew` fail with `ErrInsecureKeyFile` instead of reopening by path.
- The seed and the phrase are never printed, logged, serialized or put in an error message.
- The size bounds are arithmetic from the layouts in [formats.md](formats.md), not tuned values: each is the true maximum of its structure (a certificate 256, with a parent 514, an offer 450, a revocation 472). Decoders refuse input over its bound before parsing and never allocate from an untrusted length.
- The `Revocations` slice of `VerifyOptions` is bounded by the caller. The work is linear in its length: the list is indexed once by device, a record for another device costs no signature check, every other record costs at most one, and signer certificates with the same content are checked once together. A record repeated in the list is checked once. Keep only records that passed `Revocation.Verify`.
- `Phrase.Person` fails under `GODEBUG=fips140=only`, where PBKDF2 refuses the 8-byte salt that BIP-39 fixes and HMAC refuses the 12-byte SLIP-0010 master key.
