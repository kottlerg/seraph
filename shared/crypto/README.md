# shared/crypto

In-OS cryptographic primitives for Seraph: SHA-512 hashing and Ed25519
signature verification.

`no_std`, no allocation, no external dependencies. Provides a vetted hash and a
verify-only signature primitive usable by the bootloader/loader and userspace
services. Does no I/O and holds no keys.

The crate is the reusable primitive that the per-binary signing chain of trust
(#124) builds on; #124 owns key management, the `.seraph.sig` ELF section, and
xtask signing, and is the consumer of `ed25519_verify`.

---

## Surface

| Item | Purpose |
|---|---|
| `sha512(&[u8]) -> [u8; 64]` | One-shot SHA-512 (FIPS 180-4). |
| `Sha512` (`new`/`update`/`finalize`) | Incremental SHA-512, so large inputs (e.g. module bodies) hash without being buffered whole. |
| `ed25519_verify(&[u8;32], &[u8], &[u8;64]) -> Result<(), VerifyError>` | RFC 8032 Ed25519 verification. Verify-only; no signing or key generation. |
| `VerifyError` | `BadPublicKey`, `NonCanonicalS`, `Mismatch`. |

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
non-canonical S, invalid public key).

---

## Source Layout

```
shared/crypto/
├── Cargo.toml                  # Workspace member; no_std library; no dependencies
├── README.md
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
| [docs/capability-model.md](../../docs/capability-model.md) | System security model the signing chain layers onto |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
