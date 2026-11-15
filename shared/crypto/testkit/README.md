# shared/crypto/testkit

Reusable test infrastructure for cryptographic primitives: a Wycheproof loader, a differential
harness, reference vectors computed with OpenSSL, and the generator that writes them.

The crate is test-only and `std`: a crate under test reaches it as a dev-dependency, so nothing
in it is linked into a shipped binary or into xtask. Its one dependency is the in-tree JSON reader
[`shared/json`](../../json/README.md); it depends on no registry crate
([coding-standards.md](../../../docs/coding-standards.md) § Dependencies). It does not depend on
the crates it tests: each maps its own results to the outcomes the testkit defines (a `Verdict`,
a digest), which keeps one copy of the tested crate's types in a test build. Its tests and the
tests that use it run under `cargo xtask test`, on the host and under riscv64 emulation.

---

## Wycheproof loader

`wycheproof::load` reads a vendored Wycheproof test file into typed groups and cases, and
`wycheproof::run` runs every case against an implementation and returns a report of every case
whose verdict differs from the expected one. The loader refuses a file that declares another
schema than its `Source` names, holds a group of another type, holds another number of cases than
its `numberOfTests`, or repeats a `tcId`, so a case cannot be dropped silently. An `acceptable`
case (one the standard lets an implementation take either way) is judged by a policy the caller
states, never skipped.

A file for another algorithm is one more `Source` constant, and a new schema one more group type
beside `eddsa` and `aead`. Every loader of the crate reads its JSON through `shared/json` and the
field readers of `vectors`, which name a missing or mistyped field in the load error.

## Differential harness

`differential::compare` runs each input through the implementation under test and through a
reference, both mapped to one outcome type, and reports every disagreement with its input. An
outcome finer than accept or reject (the `ed25519::Verdict` names the failed check) makes the
harness check the reason for a rejection too. Its inputs are fixed: the reference vectors below,
or inputs from `rng::Rng`, a seeded generator, so every run is deterministic
([coding-standards.md](../../../docs/coding-standards.md) § D. Testing Invariants).

## Reference vectors

`vectors/reference/` holds each primitive's inputs with the reference's outcome, computed with
OpenSSL. `ed25519::load` and `sha512::load` read them, checking the schema the file declares and
that it holds as many cases as its `numberOfTests`; a test compares the implementation's outcome
on every input with the file's.

| File | Inputs | Reference outcome |
|---|---|---|
| `ed25519.json` | `generated`: 128 rounds from seed `0x5e4a_ed25`, each a valid signature over a random message under a random key, with one-bit flips of the signature, message and key, a random key and a random signature. `edgeCases`: S + kL and the S range boundary, non-canonical and small-order R, every non-canonical public-key encoding, the torsion points as keys, and mixed-order keys with signatures crafted to satisfy or fail the cofactorless equation. `wycheproofAcceptable`: every case the vendored Wycheproof file marks acceptable | The first RFC 8032 check that fails, in order: S below L, then the public key the canonical encoding of a point (OpenSSL decodes such keys leniently, so the generator checks the encoding itself), then OpenSSL's cofactorless verification |
| `sha512.json` | Every length from 0 to 300 bytes and 64 longer messages, from seed `0x5e4a_9512`, each with the split points of an incremental hash | OpenSSL's digest |

The `generate` module writes both files, and the `crypto-reference-vectors` binary runs it:
`cargo xtask crypto-vectors` regenerates them, and with `--check` fails unless they regenerate
byte-identically ([xtask/README.md](../../../xtask/README.md) § `cargo xtask crypto-vectors`). It
builds the inputs (the generated ones from `rng::Rng`, the edge cases with the edwards25519
arithmetic of `generate::edwards` and `generate::nat`, which are independent of
`shared/crypto`) and gives each to the `openssl` command, which signs, verifies and hashes. The
generator fails when OpenSSL accepts an S at or above L, when a crafted case does not reach the
verdict it is built for, and when the public key OpenSSL derives from a secret differs from the
one the edwards25519 arithmetic derives. The files in the tree were produced with OpenSSL 4.1.0;
the outcomes are fixed by RFC 8032 and FIPS 180-4, so another conforming OpenSSL writes the same
bytes.

## Vendored vectors

`vectors/wycheproof/` holds upstream Wycheproof files verbatim, with upstream's Apache-2.0
`LICENSE`. They are test data, embedded only in test binaries.

| File | Upstream | SHA-256 |
|---|---|---|
| `ed25519_test.json` | `C2SP/wycheproof`, `testvectors_v1/ed25519_test.json` at commit `65ca494727a52944c204441c860b039e6786b99b` | `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` |
| `chacha20_poly1305_test.json` | `C2SP/wycheproof`, `testvectors_v1/chacha20_poly1305_test.json` at commit `65ca494727a52944c204441c860b039e6786b99b` | `fe61d25f90e1bde4461d00eafe61049e5f29bd999f36b766df9cda90906ad53d` |

A file is updated by replacing it whole from an upstream commit and recording the commit and
checksum here.

---

## Source Layout

```
shared/crypto/testkit/
├── Cargo.toml
├── README.md
├── src/
│   ├── lib.rs                  # Crate root
│   ├── wycheproof.rs           # Wycheproof loader and runner; EddsaVerify, AeadTest schemas
│   ├── differential.rs         # Differential driver and report
│   ├── ed25519.rs              # Ed25519 reference vectors: Verdict, Input, load
│   ├── sha512.rs               # SHA-512 reference vectors: Input, load
│   ├── vectors.rs              # LoadError; JSON field readers the loaders share
│   ├── rng.rs                  # Seeded input generator (SplitMix64)
│   ├── hex.rs                  # Hex encoding and decoding
│   ├── generate/
│   │   ├── mod.rs              # The reference vector generator
│   │   ├── openssl.rs          # The openssl command: sign, verify, hash
│   │   ├── edwards.rs          # edwards25519 points and encodings, scalars mod L
│   │   └── nat.rs              # 256-bit integers, arithmetic modulo a prime
│   └── bin/
│       └── crypto-reference-vectors.rs  # Writes or checks vectors/reference/
└── vectors/
    ├── reference/
    │   ├── ed25519.json        # Ed25519 inputs with OpenSSL's verdicts
    │   └── sha512.json         # SHA-512 inputs with OpenSSL's digests
    └── wycheproof/
        ├── LICENSE             # Upstream's Apache-2.0 license
        ├── chacha20_poly1305_test.json  # ChaCha20-Poly1305 AEAD cases
        └── ed25519_test.json   # Ed25519 verification cases
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/coding-standards.md](../../../docs/coding-standards.md) | § D. Testing Invariants: deterministic tests |

---

## Summarized By

[shared/crypto/README.md](../README.md)
