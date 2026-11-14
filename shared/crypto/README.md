# shared/crypto

In-OS cryptographic primitives for Seraph: SHA-512 hashing, Ed25519 signature
verification, and ChaCha20-Poly1305 authenticated encryption.

`no_std`, no allocation, no external dependencies. Provides a vetted hash, a
verify-only signature primitive, and an AEAD usable by the bootloader/loader and
userspace services. Does no I/O and holds no keys: an AEAD caller passes its key
on every call. Today its only dependent is ktest, which runs the known-answer
tests on target.

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
| `chacha20poly1305::seal(&[u8;32], &[u8;12], &[u8], &mut [u8]) -> Result<[u8;16], SealError>` | `AEAD_CHACHA20_POLY1305` (RFC 8439 § 2.8): encrypts the buffer in place under the key and nonce, and returns the tag over the ciphertext and the AAD. |
| `chacha20poly1305::open(&[u8;32], &[u8;12], &[u8], &mut [u8], &[u8;16]) -> Result<(), OpenError>` | Checks the tag over the ciphertext and the AAD, and only on a match decrypts the buffer in place; on any error the buffer is unchanged. |
| `SealError`, `OpenError` | `SealError::TooLong`; `OpenError::TooLong`, `OpenError::TagMismatch`. |
| `chacha20poly1305::{KEY_LEN, NONCE_LEN, TAG_LEN, MAX_LEN}` | 32, 12 and 16 bytes; the longest buffer, `2^32 - 1` keystream blocks of 64 bytes, since the 32-bit block counter must not wrap. |
| `sha512::DIGEST_LEN` | SHA-512 digest length in bytes (64). |
| `run_sha512_kats()` / `run_ed25519_kats()` / `run_chacha20_poly1305_kats()` `-> Result<(), &'static str>` | Known-answer-test drivers shared by the host tests and ktest. |

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
- **AEAD in place, tag detached.** `seal` and `open` work on the caller's
  buffer and return or take the tag separately, so a caller seals fixed-size
  chunks (pages) with no second buffer and keeps each tag beside its chunk.
  `open` verifies before it decrypts, so a buffer whose tag fails is never
  decrypted. The caller MUST NOT seal two buffers under one key with one
  nonce: they would share keystream and the Poly1305 key.
- **AEAD in constant time.** The AEAD handles secret data, so no branch and
  no memory index depends on the key, the keystream, the plaintext, the
  Poly1305 accumulator, or a tag; branches and indices depend on the buffer
  and AAD lengths only. ChaCha20 is additions, exclusive ors and rotations by
  constants; Poly1305 adds the 64-bit multiply, whose latency is independent
  of its operands on both targets: the riscv64 platform floor of
  [docs/platform-requirements.md](../../docs/platform-requirements.md) is RVA23
  silicon, whose mandatory set includes Zkt, which covers `mul` and `mulhu`; on
  x86-64, Intel lists `MUL` among its data-operand-independent-timing
  instructions. Two values pass through
  `core::hint::black_box`, so the optimiser cannot rewrite them into a branch:
  the mask that picks the fully reduced Poly1305 result, and the 128-bit
  difference of the two tags, which `open` tests once, after both tags are
  whole. Both functions are kept out of line. No secret is wiped after use:
  copies stay in the caller's address space, which holds the key anyway.
- **Independent of the kernel entropy subsystem.** The kernel's
  `entropy/{keccak,sponge}` Keccak/SHAKE256 sponge is kernel-internal and
  coupled to the CSPRNG; it is intentionally not shared with this crate.
  Consolidating hash primitives is out of scope.

### Validation

Known-answer tests run identically on host (`cargo xtask test`) and on-target
under QEMU on both x86_64 and riscv64 (ktest `crypto::sha512_kats` /
`crypto::ed25519_kats` / `crypto::chacha20_poly1305_kats`): FIPS 180-4 SHA-512
vectors and RFC 8032 §7.1 Ed25519 vectors, plus tamper negatives (flipped
signature/message, wrong key, non-canonical S, invalid public key, and the two
non-canonical public-key encodings); every RFC 8439 vector of § 2 and Appendix A
for the ChaCha20 block function and cipher, Poly1305 (its reduction edge cases
among them), the Poly1305 key derivation and the AEAD, plus tamper negatives (a
flipped bit of the tag, ciphertext, nonce or AAD, and another key, each refused
with the buffer unchanged).

The host tests also run, under `cargo xtask test` on the host and under riscv64
emulation, the infrastructure of [`testkit/`](testkit/README.md), the crate's
only dev-dependency:

- **Wycheproof.** Every case of the vendored `ed25519_test.json`: valid cases
  verify, invalid ones are refused (a signature of another length than 64 bytes
  is refused by the API's `&[u8; 64]`), and an acceptable one (a small- or
  mixed-order public key) verifies exactly when the cofactorless equation holds,
  which the reference judges. Every case of the vendored
  `chacha20_poly1305_test.json`: `open` turns a valid case's ciphertext into its
  plaintext and refuses an invalid one (a modified tag; a nonce of another size
  than 12 bytes is refused by the API's `&[u8; 12]`), and `seal` turns a valid
  case's plaintext into exactly its ciphertext and tag.
- **AEAD properties.** `open` returns what `seal` sealed at every length from 0
  to 300 bytes and at page sizes; every one-bit change to a sealed page's tag,
  nonce and AAD, a bit of every ciphertext byte, a truncation and another key
  are refused with the buffer unchanged; the length bound holds at `MAX_LEN`
  and one byte past it.
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
    ├── chacha20poly1305.rs     # seal, open, SealError, OpenError + KATs
    ├── chacha20.rs             # ChaCha20 block function and keystream
    ├── poly1305.rs             # Poly1305 authenticator
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
| [docs/platform-requirements.md](../../docs/platform-requirements.md) | The riscv64 floor (RVA23) whose Zkt the AEAD's constant time rests on |
| [testkit/README.md](testkit/README.md) | The test infrastructure the host tests run |

---

## Summarized By

None
