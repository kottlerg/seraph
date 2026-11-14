# shared/crypto/testkit

Reusable test infrastructure for cryptographic primitives: a Wycheproof loader, a differential
harness, and host-only reference implementations.

The crate is test-only and `std`: a crate under test reaches it as a dev-dependency, so nothing
in it, and none of its dependencies, is linked into a shipped binary or into xtask. It does not
depend on the crates it tests: each maps its own results to the outcomes the testkit defines (a
`Verdict`, a digest), which keeps one copy of the tested crate's types in a test build. Its tests
and the tests that use it run under `cargo xtask test`, on the host and under riscv64 emulation.

---

## Wycheproof loader

`wycheproof::load` reads a vendored Wycheproof test file into typed groups and cases, and
`wycheproof::run` runs every case against an implementation and returns a report of every case
whose verdict differs from the expected one. The loader refuses a file that declares another
schema than its `Source` names, holds a group of another type, holds another number of cases than
its `numberOfTests`, or repeats a `tcId`, so a case cannot be dropped silently. An `acceptable`
case (one the standard lets an implementation take either way) is judged by a policy the caller
states, never skipped.

The module is the only one that parses JSON. A file for another algorithm is one more `Source`
constant, and a new schema one more group type beside `eddsa`.

## Differential harness

`differential::compare` runs each input through the implementation under test and through a
reference, both mapped to one outcome type, and reports every disagreement with its input. An
outcome finer than accept or reject (the `ed25519::Verdict` names the failed check) makes the
harness check the reason for a rejection too. Inputs come from `rng::Rng`, a seeded generator,
so every run is deterministic
([coding-standards.md](../../../docs/coding-standards.md) § D. Testing Invariants).

## References and inputs

| Module | Reference | Inputs |
|---|---|---|
| `ed25519` | `ed25519-dalek`'s cofactorless `verify`, after the RFC 8032 checks in order: S below L, then the public key the canonical encoding of a point (`ed25519-dalek` decodes such keys leniently, so the reference checks the encoding itself) | `generated`: random keys and messages, each valid signature with one-bit flips of the signature, message and key, a random key and a random signature. `edge_cases`: S + kL and the S range boundary, non-canonical and small-order R, every non-canonical public-key encoding, the torsion points as keys, and mixed-order keys with signatures crafted to satisfy or fail the cofactorless equation |
| `sha512` | `RustCrypto` `sha2` | every length from 0 to 300 bytes and longer messages, each with the split points of an incremental hash |

## Vendored vectors

`vectors/wycheproof/` holds upstream Wycheproof files verbatim, with upstream's Apache-2.0
`LICENSE`. They are test data, embedded only in test binaries.

| File | Upstream | SHA-256 |
|---|---|---|
| `ed25519_test.json` | `C2SP/wycheproof`, `testvectors_v1/ed25519_test.json` at commit `65ca494727a52944c204441c860b039e6786b99b` | `ea80ffebac085e21cb9d3e903e7fa2b448d96702da5b31f061d0b83b430b74b3` |

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
│   ├── wycheproof.rs           # Wycheproof loader and runner; EddsaVerify schema
│   ├── differential.rs         # Differential driver and report
│   ├── ed25519.rs              # Ed25519 reference verdict, generated and edge-case inputs
│   ├── sha512.rs               # SHA-512 reference digest and generated inputs
│   ├── rng.rs                  # Seeded input generator (SplitMix64)
│   └── hex.rs                  # Hex encoding and decoding
└── vectors/
    └── wycheproof/
        ├── LICENSE             # Upstream's Apache-2.0 license
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
