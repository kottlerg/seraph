# shared/crypto

In-OS cryptographic primitives for Seraph: SHA-512 hashing and Ed25519
signature verification.

`no_std`, no allocation, no external dependencies. Provides a vetted hash and a
verify-only signature primitive usable by the bootloader/loader and userspace
services. Does no I/O and holds no keys. Today its only dependent is ktest, which
runs the known-answer tests on target.

The per-binary signing chain of trust (#124), which will own key management, the
signature trailer, and xtask signing, and will consume `ed25519_verify`, is design
intent; not yet implemented.

---

## Surface

| Item | Purpose |
|---|---|
| `sha512(&[u8]) -> [u8; 64]` | One-shot SHA-512 (FIPS 180-4). |
| `Sha512` (`new`/`update`/`finalize`) | Incremental SHA-512, so large inputs (e.g. module bodies) hash without being buffered whole. |
| `ed25519_verify(&[u8;32], &[u8], &[u8;64]) -> Result<(), VerifyError>` | Ed25519 verification per RFC 8032, public-key decoding included: non-canonical encodings (a y coordinate ≥ p, or x = 0 with the sign bit set) are refused. Verify-only; no signing or key generation. |
| `VerifyError` | `BadPublicKey`, `NonCanonicalS`, `Mismatch`. |
| `sha512::DIGEST_LEN` | SHA-512 digest length in bytes (64). |
| `run_sha512_kats()` / `run_ed25519_kats()` `-> Result<(), &'static str>` | Known-answer-test drivers shared by the host tests and ktest. |

### Design notes

- **SHA-512 only.** Ed25519 mandates SHA-512 internally (RFC 8032 §5.1); one
  core serves both the public hash and the signature's internal hashing.
  SHA-256/BLAKE-family hashes are not provided (no consumer).
- **Verify-only, variable-time.** Verification touches only public data
  (public key, signature, message), so the field arithmetic is variable-time
  by design and carries no side-channel obligation. The mandatory `S < L`
  range check (RFC 8032 §5.1.7) runs first; every failure path is a single
  terminal `Err` with no fallback.
- **Field representation.** Field elements are 16 signed limbs of radix 2^16
  (the `TweetNaCl` `gf` model) — the most conservative basis for a
  from-scratch verifier, keeping every intermediate product inside `i64`.
- **Independent of the kernel entropy subsystem.** The kernel's
  `entropy/{keccak,sponge}` Keccak/SHAKE256 sponge is kernel-internal and
  coupled to the CSPRNG; it is intentionally not shared with this crate.
  Consolidating hash primitives is out of scope.

### Validation

Known-answer tests run identically on host (`cargo xtask test`) and on-target
under QEMU on both x86_64 and riscv64 (ktest `crypto::sha512_kats` /
`crypto::ed25519_kats`): FIPS 180-4 SHA-512 vectors and RFC 8032 §7.1 Ed25519
vectors, plus tamper negatives (flipped signature/message, wrong key,
non-canonical S, invalid public key, and the two non-canonical public-key
encodings).

The host tests also run, under `cargo xtask test` on the host and under riscv64
emulation, the infrastructure of [`testkit/`](testkit/README.md), the crate's
only dev-dependency:

- **Wycheproof.** Every case of the vendored `ed25519_test.json`: valid cases
  verify, invalid ones are refused (a signature of another length than 64 bytes
  is refused by the API's `&[u8; 64]`), and an acceptable one (a small- or
  mixed-order public key) verifies exactly when the cofactorless equation holds,
  which the reference judges.
- **Differential.** `ed25519_verify` against the `ed25519-dalek` reference, on
  generated signatures with one-bit corruptions and on an edge-case corpus
  (malleability, the S range check, degenerate and non-canonical public keys,
  small-order and non-canonical R), comparing which check fails, not only
  acceptance; `sha512` and `Sha512` against `RustCrypto` `sha2` over every
  length to 300 bytes and longer messages, fed whole and in pieces.

Any disagreement fails the test. The loader, the harness and the references are
reusable by any crate that tests a primitive: it takes `crypto-testkit` as a
dev-dependency (see its README for adding a Wycheproof file or schema).

---

## Source Layout

```
shared/crypto/
├── Cargo.toml                  # Workspace member; no_std library; no dependencies
├── README.md
├── testkit/                    # Test-only: Wycheproof loader, differential
│                               # harness, references (crypto-testkit)
└── src/
    ├── lib.rs                  # Crate doc, public re-exports
    ├── sha512.rs               # SHA-512 (one-shot + incremental) + KATs
    ├── ed25519.rs              # ed25519_verify, VerifyError + KATs
    ├── field.rs                # GF(2^255-19) field arithmetic
    ├── edwards.rs              # edwards25519 group: points, scalar mul, decompression
    └── scalar.rs               # arithmetic mod L: S<L check, 64-byte reduction
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [testkit/README.md](testkit/README.md) | The test infrastructure the host tests run |

---

## Summarized By

None
