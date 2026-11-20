# Third-party data

kolo-id contains no third-party code. It embeds one data file and ships test data copied
from three public sources. Each file below is unchanged from its upstream version unless the
table says otherwise. The code of this repository is MIT OR Apache-2.0 (see the root licenses);
the files below keep their own terms.

| File in this repository | Upstream | Commit | SHA-256 | License |
|---|---|---|---|---|
| `internal/bip39/english.txt` (embedded in the library) | https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt | `ce1862ac6bcffa1dd20aad858380e51e66e949ea` (2014-02-07, the only commit that touched the file) | `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` | MIT, declared by BIP-39 for the BIP; text in `BIP-39-license.txt` |
| `internal/bip39/testdata/vectors.json` (tests only) | https://github.com/trezor/python-mnemonic/blob/master/vectors.json | `b57a5ad77a981e743f4167ab2f7927a55c1e82a8` (authored 2024-08-17, committed 2024-08-27) | `fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8` | MIT, Copyright (c) 2013-2016 Pavol Rusnak; text in `MIT-python-mnemonic.txt` |
| `internal/slip10/testdata/slip-0010-ed25519.txt` (tests only) | https://github.com/satoshilabs/slips/blob/master/slip-0010.md, sections "Test vector 1 for ed25519" and "Test vector 2 for ed25519" | `a00312491693714d9bc1b6e4cb5b2e356e6c511e` (2025-04-15) | `dbd5a324f2a6014bf78fc8cfa85833e4a16256a02283b93d648fccba18ed1ce7` (the whole spec file) | CC-BY-SA-4.0 for the repository; text in `CC-BY-SA-4.0-slips.txt` |

Notes:

- `english.txt` and `vectors.json` are byte for byte the upstream files; neither has a header. The
  BIP-39 text declares the MIT license for the BIP; it does not say separately that the word list
  file carries it, and the file has no license header. This notice records that statement and
  nothing more.
- `slip-0010-ed25519.txt` is not an upstream file: its values are copied from the two ed25519 test
  vectors in the SLIP-0010 text and re-laid out one chain per line, with a header that names the
  source, commit, hash and license. The values are numbers from the specification.
- The word list is also pinned by a test (hash, count, first and last word), so a changed copy
  fails the build.
