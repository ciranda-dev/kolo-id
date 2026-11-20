# Security

What the recovery phrase, a stolen device and a revoked device can and cannot do. The functions are in [guide.md](guide.md) and the bounds in [limits.md](limits.md). To report a problem, see [SECURITY.md](../SECURITY.md).

## What each secret allows

| Holder of | Can | Cannot |
|---|---|---|
| The 24 words | Derive the person key; certify any device key, approver or not; revoke any device; sign as the person | Read group data that only devices hold (the library has no encryption); change what is already settled |
| An approver device key | Everything an ordinary device can; certify new ordinary devices; revoke ordinary devices | Certify an approver; revoke an approver |
| An ordinary device key | Sign messages as that device; revoke itself | Certify or revoke other devices |
| A certificate alone | Nothing: it is public and is not a credential | Sign anything; a message needs the device's private key |

The library keeps no state. Everything below that depends on what a verifier has heard (revocations, highest serial) depends on the application keeping and distributing those records.

## The words

- Whoever has the words is the person, permanently. A leaked phrase cannot be repaired inside the same identity: create a new phrase and tell your contacts. There is no second factor, because the BIP-39 passphrase is deliberately not supported.
- A phrase is guarded by being shown once, never stored by the library, never printed (`Phrase` is redacted for every `fmt` verb and in `log/slog`, and cannot be encoded) and never put in an error message. `Clear` zeroes the entropy the library holds; Go strings that `Words` returned cannot be zeroed, so show them and drop them.
- `Person` copies the whole phrase sentence into a Go string that it passes to PBKDF2. `Clear` cannot erase that string, and it stays in memory until the garbage collector reuses it. Derive the person key as late and as briefly as possible, and treat the process as holding the phrase for that time.
- Erasing is best effort. `Phrase.Clear` and `Identity.Clear` zero the memory the library holds. The Go runtime and the standard library keep their own copies that no library code can reach: `crypto/ed25519` expands the seed when it signs, PBKDF2 and HMAC keep state while they run, the garbage collector may move memory before it is zeroed, and the operating system may swap pages to disk. After `Clear` a key can still be in memory a while and in a crash dump or a swap file. Treat a process that held a key as one that may still contain it.
- A user-chosen phrase is as strong as the user's choice. Any 24 words with a valid checksum are accepted, including famous example phrases. An application must generate the words and never let the user pick them.
- The words are a standard BIP-39 phrase, so any wallet accepts them, and the same words typed into a wallet would create wallets at other paths. Keep them out of every other tool.
- Typed words that pass the checksum can still be wrong: one random typing error in 256 passes. Show the person key after a restore.
- Never ask for the words except in a restore flow. A look-alike screen that asks for them is the most damaging attack, and no library can stop it.
- A device that is compromised while the words are shown or typed defeats every software control. Create the phrase on a clean device.

## A stolen device

- An ordinary device: the thief can act as that device until verifiers learn of a revocation. Revoke it from an approver device or with the phrase. The thief cannot add devices.
- An approver device: the thief can also certify new ordinary devices, and these stay valid until the approver is revoked. Only the phrase revokes an approver. When it is revoked, every certificate it issued is void, including the legitimate devices it certified, which must be certified again. This is strict on purpose: `issuedAt` is signed by the thief and could be back-dated, so time cannot keep the older ones.
- A stolen approver can revoke the person's other ordinary devices, which is a denial of service. Revocations are permanent, so revoking the approver afterwards does not undo what it revoked. But an approver's revocation names one certificate by the hash of its body, issuer and parent, never a range of serials and never a key, so it cannot burn a device key and it cannot cover a certificate that does not exist yet. The name leaves out the signatures on purpose: Ed25519 signatures are not unique, and a thief of a device could otherwise re-sign its own acceptance into other valid bytes and escape the record. The person recovers a device by certifying its key again: the new certificate is not the one the record names, so the record does not touch it. A thief can only revoke certificates it can name, that is, ones that already exist; it cannot sign in advance for the next one.
- A revoked or expired approver keeps the power to sign revocations, and a thief of an approver key can go on revoking ordinary-device certificates it can see after the person revoked that approver. This is the price of permanent revocations: if a record stopped counting when its signer was revoked, a thief would revive the phones it had revoked. It is a denial of service on the person's ordinary devices, not a burn and not impersonation: each record names one existing certificate and the person answers it with a new certificate. No remedy short of a new person key stops a thief who still sees the roster from revoking the certificates it can see. The library is stateless, so the caller chooses which records to pass to `VerifyDevice`. Recommended policy: store every verified revocation when you first see it, with the time you received it. When the person revokes an approver, stop passing the approver-form records (`Revocation.Signer` is that approver) that you first saw after that revocation, and keep passing the earlier ones. Never rely on a record's own time field for this: a thief can back-date it.
- A stolen device and no other approver and no phrase: the identity cannot be cleaned. Keep the phrase, and certify a second approver when you have two devices.
- The device key file is not encrypted. A thief with the unlocked disk has the key; disk encryption is the operating system's job.
- Everything the device already received stays readable by the thief. Revocation protects the future only.

## A revoked device

- Verifiers that hold the revocation refuse its certificate and its messages from then on. Verifiers that have not received it still accept it: revocation is as fresh as the records a verifier holds, so applications must carry revocations to every verifier and keep them.
- It keeps what it already has: its local data, and any keys or files it already received. The library cannot take that back.
- A revocation by the person key or the device itself voids certificates up to a serial. A burned key (`math.MaxUint64`) can never be certified again; a lower value lets the person certify the same key with a higher serial.
- Revocations are permanent tombstones. A revocation signed by an approver is judged by the structure and the signatures of its signer certificate, which must chain to the expected person. It is not judged by the signer's expiry or by whether the signer was revoked later, so it never lapses and never un-revokes. Applications must keep every verified revocation. An approver's revocation applies only to the one certificate whose hash it carries; only the person key or the device itself can revoke by serial, and only they can burn a key.

## Replay and downgrade

- An expired certificate is refused. A certificate without an expiry never expires by itself, and a verifier with a clock that runs behind accepts certificates that have expired.
- An old certificate with a lower serial is refused once its revocation is held. A verifier that stores no revocations is open to replay of revoked certificates. Keep only records that passed `Revocation.Verify`, and keep all of them.
- The person is chosen by the verifier, never read from the certificate. A certificate for one person never verifies for another.
- Each signature has its own context, so a signature made for a certificate cannot be used as a device acceptance or a revocation, and the reverse. Application messages need their own contexts. The contexts that start with `kolo-id/device-` are reserved: `Sign` refuses them and `VerifyDevice` refuses them, so an application that signs attacker-chosen bytes cannot be made to produce a certificate or a revocation. Never sign untrusted bytes under any `kolo-id/...` context.
- The issuer signature and the device's acceptance signature of an approver-issued certificate cover the SHA-256 of its parent's encoding, and the signature of an approver-signed revocation covers the SHA-256 of its signer certificate's encoding and carries the hash of the certificate it revokes. A leaf or a revocation cannot be moved to another certificate of the same approver key, for example one with a later expiry, and the device signs the whole chain it accepts.
- `VerifyDevice` has no mode without a certificate and needs the expected person. The person key does not sign application messages, so a device signature never verifies under the person key through plain `Verify`. An application that still accepts a bare key for a person who uses certificates can be downgraded; refuse it once a person is known to use certificates.
- Two device keys of one person are visibly one person to anyone who sees the certificates.

## Hostile input

- A device key is certified only with its own acceptance signature, so a hostile person key cannot claim someone else's device key.
- Decoders and the phrase parser never panic and refuse oversized input before parsing. Verification does at most four certificate signature checks and one message signature check. For the revocations it indexes the list once by device, and for each record that names the certificate's device and covers its serial it does one signature check of the record and, only if that passes for an approver-signed record, two of its signer certificate. The results are kept for the call: a record that is repeated costs one check, and signer certificates with the same content cost two checks together. So the work is linear in the length of the list, with at most one check per record and two per distinct signer certificate; records for other devices cost only the indexing. The caller bounds the list.
- Small-order public keys are refused everywhere, as `Verify` does.
- A phrase fails with a fixed error message and a position, never a word. Under `GODEBUG=fips140=only` the phrase seed is not available and `Person` returns an error.

## Supply chain

The word list is embedded and pinned by a test (its SHA-256, 2048 words, first and last word), and the official test vectors of BIP-39 and SLIP-0010 are checked on every test run. A change to a word breaks both. The library also checks the size and the SHA-256 of the list at first use; if that ever failed, the phrase functions return an error and never panic or derive a key from a wrong list. Sources and licenses are in [third_party/licenses/NOTICE.md](../third_party/licenses/NOTICE.md).
