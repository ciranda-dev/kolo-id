# Formats

## Key file

The key file holds the raw 32-byte Ed25519 seed and nothing else.

## Certificate file

A `.cert` file holds the encoding of one device certificate (below), 256 bytes or at most 514 with an approver parent. It is written with mode 0600 next to the device key file, which is unchanged. It is public data, but it gets the same directory checks as a key file.

## JSON

In JSON, a `*Identity` is its public key as a lowercase hex string. A plain `Identity` value (not a pointer) encodes as `{}`.

An identity cannot be decoded from JSON or text: `UnmarshalJSON` and `UnmarshalText` always return `ErrNotDecodable`; use `Load` or `FromSeed`. Decoding JSON `null` into a `*Identity` field sets the field to nil with no error. A failed decode into a `*Identity` field leaves a non-nil zero `Identity` there, which `Sign` and `Save` reject with `ErrInvalidIdentity`.

## Signatures

A signature is Ed25519ctx (RFC 8032). The context string is part of what is signed, so it must match when verifying.

## Recovery phrase

24 words of the BIP-39 English list, joined by one ASCII space. The list is `internal/bip39/english.txt`; its source and hash are in [third_party/licenses/NOTICE.md](../third_party/licenses/NOTICE.md). The person key is at `m/1802464367'/0'/0'` of SLIP-0010 for Ed25519 under the BIP-39 seed of the empty passphrase. The key at that path is the Ed25519 seed of the person key.

## Certificates and revocations

Encoded with kolo-codec: minimal uvarints, fixed-size keys and signatures, one valid encoding per value. The first field of every message is its type: 1 offer, 2 certificate, 3 revocation.

Body, the bytes that the issuer and the device sign (at most 126 bytes):

```text
uvarint  version = 0
fixed32  person
fixed32  device
fixed32  issuer          the person key for a root-issued certificate, else the approver device
uvarint  serial          at least 1
uvarint  issuedAt        Unix seconds, at most 2^63-1
uvarint  expiresAt       0 = never, else greater than issuedAt
uvarint  flags           bit 0 = approver; any other bit is invalid
```

Messages:

```text
offer        uvarint 1 || body || fixed64 issuerSig || bool hasParent || [bytes parent]
certificate  uvarint 2 || body || fixed64 issuerSig || fixed64 deviceSig || bool hasParent || [bytes parent]
revocation   uvarint 3 || rbody || fixed64 sig || bool hasSignerCert || [bytes signerCert]
rbody        uvarint version = 0 || fixed32 person || fixed32 device || fixed32 signer || uvarint upToSerial || uvarint revokedAt || [fixed32 target]
```

`target` is present exactly when an approver signed the revocation (the signer is neither the person nor the device). It is the SHA-256 of the bytes the issuer and the device sign for the one certificate that the revocation names (its body and, for an approver-issued certificate, the SHA-256 of its parent), and never of its signatures, because the same signer can sign the same message into different valid bytes (Ed25519 signatures are not unique). `upToSerial` is that certificate's serial. For the person key or the device itself, `upToSerial` covers every serial up to it and there is no `target`.

`parent` is the encoding of a certificate with no parent of its own. Signatures are Ed25519ctx; the context is not part of the encoding:

| Signature | Signer | Context | Signed bytes |
|---|---|---|---|
| `issuerSig` | the issuer | `kolo-id/device-link/v0` | the body; for a certificate with a parent, the body then SHA-256 of the parent's encoding (32 bytes) |
| `deviceSig` | the device | `kolo-id/device-accept/v0` | the same bytes as `issuerSig`: the body, and for a certificate with a parent, the SHA-256 of the parent's encoding |
| revocation `sig` | the signer | `kolo-id/device-revoke/v0` | `rbody`; for a signer certificate, `rbody` then SHA-256 of the signer certificate's encoding (32 bytes) |

The parent and signer certificate hashes are part of the signed bytes only, so they add nothing to the encoded sizes. They bind a certificate to its exact parent, the device's acceptance to the chain it accepts, and a revocation to its exact signer certificate; those are hashed whole because the signer chose their bytes. The `target` hash of an approver's revocation is part of `rbody` and is encoded. The contexts that start with `kolo-id/device-` are reserved for these signatures: `Sign` refuses them.

Rules a decoder enforces: keys of 32 bytes and not of small order; the device key differs from the person and issuer keys; a root-issued certificate (issuer equals person) has no parent; any other certificate has a parent that is root-issued, an approver, for the same person, whose device is the issuer, and the certificate itself is not an approver; serial at least 1; no unknown flag; input equal to its own re-encoding. In a revocation the signer certificate is present exactly when the signer is neither the person nor the device, and it is a root-issued approver certificate of that signer for the same person. Sizes: certificate 256, with parent 514, offer 450 with a parent (192 without), revocation 472 with a signer certificate (182 for the person key or the device itself), as limits in [limits.md](limits.md).

## References

- [RFC 8032, Edwards-Curve Digital Signature Algorithm (EdDSA)](https://www.rfc-editor.org/info/rfc8032) (Informational, January 2017).
  Takes: Ed25519ctx (5.1) with a context of 1 to 255 bytes, and rejection of small-order public keys.
  Not implemented: Ed25519ph and Ed448.
- [BIP-39, Mnemonic code for generating deterministic keys](https://github.com/bitcoin/bips/blob/0d1b892ddb21c22def4af4541bfed7a2a3480e4a/bip-0039.mediawiki) (Status: Deployed).
  Takes: the English word list, 24 words with an 8-bit checksum, and the PBKDF2-HMAC-SHA512 seed.
  Not implemented: other word lists and lengths, the passphrase, and NFKD normalization (only ASCII is accepted).
- [SLIP-0010, Universal private key derivation from master private key](https://github.com/satoshilabs/slips/blob/a00312491693714d9bc1b6e4cb5b2e356e6c511e/slip-0010.md) (Standard, Final).
  Takes: Ed25519 derivation at the hardened path m/1802464367'/0'/0'.
  Not implemented: other curves; Ed25519 has no non-hardened children.
- [BIP-43, Purpose Field for Deterministic Wallets](https://github.com/bitcoin/bips/blob/24e96e870fffaa257b465ce1f0370c14aac588e8/bip-0043.mediawiki) (Status: Deployed).
  Takes: a first path element that names the purpose, here the ASCII bytes of "kolo".
  Not implemented: any wallet hierarchy below it.
- [RFC 8018, PKCS #5: Password-Based Cryptography Specification Version 2.1](https://www.rfc-editor.org/info/rfc8018) (Informational, January 2017).
  Takes: PBKDF2, as BIP-39 uses it.
  Not implemented: nothing else from it.
