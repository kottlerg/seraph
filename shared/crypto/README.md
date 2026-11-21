# shared/crypto

In-OS cryptographic primitives for Seraph: SHA-512 hashing, the Keccak-f[1600]
permutation and the SHAKE128 and SHAKE256 extendable-output functions, Ed25519
and ML-DSA-65 signature verification, and ChaCha20-Poly1305 authenticated
encryption; and, for the host signer, Ed25519 and ML-DSA-65 key generation and
signing.

`no_std`, no allocation, no external dependencies. Provides vetted hashes,
signature verifiers, and an AEAD usable by the kernel, the bootloader/loader and
userspace services, and signers for the build host. Does no I/O and holds no keys: an
AEAD caller passes its key on every call, and a signer's caller its secret seed.
Its dependents are the kernel, whose entropy sponge runs the Keccak-f[1600] permutation of
`keccak` ([core/kernel/docs/entropy.md](../../core/kernel/docs/entropy.md) § Keccak duplex
construction); ktest, which runs the known-answer tests on target; and
[`shared/objsig`](../objsig/README.md), which implements the signature trailer,
certificate and trust-store codec and the verifier of the per-binary signing
chain of trust ([docs/signing.md](../../docs/signing.md)) on `ed25519_verify`,
`ml_dsa::verify` and `sha512`, and composes the signers into its composite
signature. xtask uses the composite signer for its key management and signing
([xtask/README.md](../../xtask/README.md) § Signing), and enables the `sign` feature through
`objsig`'s; core/boot enables it as a dev-dependency only, since its host tests sign fixtures. The
bootloader verifies the kernel and every bundle entry through `objsig`, and procmgr every image it
creates.

---

## Surface

| Item | Purpose |
|---|---|
| `sha512(&[u8]) -> [u8; 64]` | One-shot SHA-512 (FIPS 180-4). |
| `Sha512` (`new`/`update`/`finalize`) | Incremental SHA-512, so large inputs (e.g. module bodies) hash without being buffered whole. |
| `ed25519_verify(&[u8;32], &[u8], &[u8;64]) -> Result<(), VerifyError>` | Ed25519 verification per RFC 8032, public-key decoding included: non-canonical encodings (a y coordinate ≥ p, or x = 0 with the sign bit set) are refused. |
| `ed25519_public_key(&[u8;32]) -> [u8;32]` | The public key of a 32-byte secret seed (RFC 8032 § 5.1.5). `sign` feature only. |
| `ed25519_sign(&[u8;32], &[u8]) -> [u8;64]` | The deterministic signature R ‖ S of a message under a secret seed (RFC 8032 § 5.1.6), with S below L. `sign` feature only. |
| `VerifyError` | `BadPublicKey`, `NonCanonicalS`, `Mismatch`. |
| `chacha20poly1305::seal(&[u8;32], &[u8;12], &[u8], &mut [u8]) -> Result<[u8;16], SealError>` | `AEAD_CHACHA20_POLY1305` (RFC 8439 § 2.8): encrypts the buffer in place under the key and nonce, and returns the tag over the ciphertext and the AAD. |
| `chacha20poly1305::open(&[u8;32], &[u8;12], &[u8], &mut [u8], &[u8;16]) -> Result<(), OpenError>` | Checks the tag over the ciphertext and the AAD, and only on a match decrypts the buffer in place; on any error the buffer is unchanged. |
| `SealError`, `OpenError` | `SealError::TooLong`; `OpenError::TooLong`, `OpenError::TagMismatch`. |
| `chacha20poly1305::{KEY_LEN, NONCE_LEN, TAG_LEN, MAX_LEN}` | 32, 12 and 16 bytes; the longest buffer, `2^32 - 1` keystream blocks of 64 bytes, since the 32-bit block counter must not wrap. |
| `sha512::DIGEST_LEN` | SHA-512 digest length in bytes (64). |
| `keccak::keccak_f1600(&mut [u64; 25])`, `keccak::LANES` | The Keccak-f[1600] permutation (FIPS 202 § 3.3) on 25 little-endian lanes. |
| `shake::shake128(&[u8], &mut [u8])` / `shake::shake256(&[u8], &mut [u8])` | One-shot SHAKE128 and SHAKE256 (FIPS 202 § 6.2): the first `out.len()` bytes of the output. |
| `shake::Shake128` / `shake::Shake256` (`new`/`update`/`finalize`), `shake::XofReader` (`read`) | Incremental absorbing, then squeezing in reads of any length; `shake::{SHAKE128_RATE, SHAKE256_RATE}` are the rates, 168 and 136 bytes. |
| `ml_dsa::verify(&[u8; 1952], &[u8], &[u8], &[u8; 3309]) -> Result<(), ml_dsa::VerifyError>` | ML-DSA-65 verification (FIPS 204 Algorithm 3, the pure form) of a signature over a message with a context string of at most 255 bytes. |
| `ml_dsa::VerifyError` | `ContextTooLong`, `MalformedHint`, `ZOutOfRange`, `Mismatch`. |
| `ml_dsa::public_key(&[u8; 32]) -> [u8; 1952]` | The ML-DSA-65 public key of a 32-byte key-generation seed (FIPS 204 Algorithm 6). `sign` feature only. |
| `ml_dsa::sign(&[u8; 32], &[u8], &[u8]) -> Result<[u8; 3309], ml_dsa::SignError>` | The deterministic ML-DSA-65 signature (FIPS 204 Algorithm 2, the pure form, with the all-zero rnd) of a message with a context string, under the key of a seed. `sign` feature only. |
| `ml_dsa::SignError` | `ContextTooLong`. |
| `ml_dsa::{NAME, PUBLIC_KEY_LEN, SIGNATURE_LEN, SEED_LEN, MAX_CONTEXT_LEN}` | `"ML-DSA-65"`; 1952, 3309, 32 and 255 bytes. |
| `run_sha512_kats()` / `run_ed25519_kats()` / `run_chacha20_poly1305_kats()` / `run_shake_kats()` / `run_ml_dsa_kats()` `-> Result<(), &'static str>` | Known-answer-test drivers shared by the host tests and ktest. |

### Design notes

- **SHA-512 and SHAKE.** Ed25519 mandates SHA-512 internally (RFC 8032 §5.1);
  one core serves both the public hash and the signature's internal hashing.
  ML-DSA mandates SHAKE128 and SHAKE256 (FIPS 204 § 3.7), which the crate
  provides on the one Keccak-f[1600] permutation it shares with the kernel.
  SHA-256/BLAKE-family hashes are not provided (no consumer).
- **One Keccak.** The Keccak-f[1600] permutation lives here, and the kernel's
  entropy sponge and the crate's SHAKE both run it. The sponge itself, a duplex
  construction with fast key erasure coupled to the CSPRNG, stays in the kernel
  ([core/kernel/docs/entropy.md](../../core/kernel/docs/entropy.md) § Keccak
  duplex construction). The permutation is exclusive ors, ands, negations and
  rotations by constants, with its round constants indexed by the round number,
  so it takes the sponge's secret state in constant time. The kernel depends on
  the crate with no feature and calls nothing but the permutation.
- **Verification, variable-time.** Verification touches only public data
  (public key, signature, message), so its S range check, point decompression
  and field equality are variable-time by design and carry no side-channel
  obligation. The mandatory `S < L` range check (RFC 8032 §5.1.7) runs first;
  every failure path is a single terminal `Err` with no fallback.
- **Signing behind a feature.** The signers (Ed25519 and ML-DSA) compile only
  with the crate's `sign` feature, and in the crate's own tests. Only a host
  tool may enable it: xtask, the host signer, enables it, and no component built
  for the target does. A component built for the target MUST NOT enable it, so
  that a loader (the bootloader, procmgr) compiles no signing code: `cargo xtask
  build` builds the components of one build profile in a single Cargo
  invocation, which resolves one feature set for all of them, so a feature one
  component enables reaches every loader built beside it. xtask is a host
  binary, built in an invocation of its own outside every component group.
- **Key generation from the caller's seed.** A key is a 32-byte secret seed and
  the public key `ed25519_public_key` derives from it; the crate draws no
  randomness. The caller draws the seed from its platform's random source (for
  xtask, the host operating system's, as
  [docs/signing.md](../../docs/signing.md) § Signing specifies)
  and passes it on every call, so the crate keeps no key between calls.
- **Signing in constant time.** No branch and no memory index depends on a
  secret value (the seed, the secret scalar, the nonce prefix, the nonce), only
  on the message length and on public values. The signer's path is SHA-512
  (additions, rotations and logic operations, branching on lengths only); the
  reduction mod L and `mul_add`, which forms S (signed-limb arithmetic in loops
  of fixed bounds, arithmetic shifts); scalar multiplication by the base point,
  a ladder over all 256 bits of the scalar with the complete twisted Edwards
  addition formula, two additions and two conditional swaps per bit; and point
  encoding (inversion by a fixed exponent, then the canonical reduction). Every
  select, the ladder's swaps and the canonical reduction's, is a mask that
  passes through `core::hint::black_box`, so the optimiser cannot rewrite it
  into a branch. The verifier's variable-time steps take no secret. Tests count
  the field multiplications and conditional swaps that the ladder makes for
  extreme scalars, and that a signature makes for different seeds and for
  nonces with a zero and a full top byte, and require the counts equal: a
  ladder that skips bits, or a branch on a secret that chooses field work,
  fails them. A branch inside one field operation, or one the compiler
  introduces, changes no count; the review of a change to this path checks
  for one. The signer runs on the build host, whose processor fixes the
  latency of the 64-bit multiply: the platform-floor argument of the AEAD note
  below (Zkt, DOITM) is the target's and does not reach the host. No secret is
  wiped after use, as for the AEAD: the caller holds the seed.
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
  constants; Poly1305 adds the 64-bit multiply. On riscv64 its latency is
  architecturally independent of its operands: the platform floor of
  [docs/platform-requirements.md](../../docs/platform-requirements.md) is RVA23
  silicon, whose mandatory set includes Zkt, which covers `mul` and `mulhu`. On
  x86-64, Intel lists `MUL` among its data-operand-independent-timing (DOIT)
  instructions, but on its parts that enumerate the DOITM control (Ice Lake and
  later, inside the platform floor) it guarantees that timing only while DOITM
  is set, and the kernel sets DOITM on every CPU that enumerates it
  ([core/kernel/docs/transient-execution.md](../../core/kernel/docs/transient-execution.md)
  § Data-operand-independent timing). Two values
  pass through `core::hint::black_box`, so the optimiser cannot rewrite them
  into a branch: the mask that picks the fully reduced Poly1305 result, and the
  128-bit difference of the two tags, which `open` tests once, after both tags
  are whole. Both functions are kept out of line. No secret is wiped after use:
  copies stay in the caller's address space, which holds the key anyway.
- **ML-DSA-65, one parameter set.** ML-DSA is built for ML-DSA-65 alone. Its
  parameters (FIPS 204 Tables 1 and 2) are the first block of constants in
  `ml_dsa/params.rs`, and everything else, the encodings' bit widths and
  lengths among them, is derived from them, so ML-DSA-44 and ML-DSA-87 differ
  only in that block. Only the pure form with a context string is provided;
  HashML-DSA is not.
- **ML-DSA verification, bounded and variable-time.** `ml_dsa::verify` makes
  every check FIPS 204 Algorithm 8 makes of a signature, in its order, and each
  failure is a single terminal `Err` naming it: the context length, the hint
  section's encoding (HintBitUnpack, Algorithm 21: every row end at most OMEGA
  and not below the previous one, positions strictly increasing within a row,
  every slot past the last end zero), the norm bound of z (every coefficient
  below GAMMA1 - BETA in magnitude), then the commitment hash. A key or
  signature of another length is refused by the API's arrays. It allocates
  nothing and holds no matrix and no vector: it samples each entry of A as it
  multiplies it, transforms z and t1 from their bytes again for every row, and
  absorbs each row of w1 into the hash as it is formed, so its frames hold at
  most three polynomials (1 KiB each), two SHAKE states and a SHAKE128 block,
  and the message is absorbed as it is read: its stack does not depend on the
  message length. Its largest frame, that of `Verify_internal`, which holds
  the three polynomials, is over the 4 KiB `stack-size-threshold` of
  `shared/clippy.toml`, and its `#[expect]` says what it holds; a host test
  runs the verifier over a 1 MiB message on a thread of 16 KiB, the size of
  init's stack, the smallest it runs on (the ktest run of its known answers).
  It touches only public data, so it branches on the hints, the range checks
  and the comparison.
- **ML-DSA signing in constant time, but for the rejections.** `ml_dsa::sign`
  derives the key from the seed (FIPS 204 Algorithm 6) on every call, keeps s1,
  s2 and t0 in NTT form for the attempts, and signs deterministically (rnd of 32
  zero bytes). No branch and no memory index depends on a secret coefficient:
  reduction, Power2Round, Decompose and MakeHint are arithmetic and masks (the
  division by 2 GAMMA2 is a multiplication by a reciprocal, exact over [0, q)),
  and SampleInBall, which also runs on the challenge of every rejected attempt,
  swaps under masks over every coefficient up to the one it places. Each attempt
  evaluates every bound (z, the low bits of r0, c t0, the hint count) as a mask
  and branches once on their union. What timing reveals is the number of
  attempts, which bytes the samplers draw and discard (a discarded byte is not a
  coefficient), and the lengths of the message and context. The signer runs on
  the build host, as Ed25519's does; no secret is wiped after use.

### Validation

Known-answer tests run identically on host (`cargo xtask test`) and on-target
under QEMU on both x86_64 and riscv64 (ktest `crypto::sha512_kats` /
`crypto::ed25519_kats` / `crypto::chacha20_poly1305_kats` /
`crypto::shake_kats` / `crypto::ml_dsa_kats`): FIPS 180-4 SHA-512
vectors and RFC 8032 §7.1 Ed25519 vectors, plus tamper negatives (flipped
signature/message, wrong key, non-canonical S, invalid public key, and the two
non-canonical public-key encodings); every RFC 8439 vector of § 2 and Appendix A
for the ChaCha20 block function and cipher, Poly1305 (its reduction edge cases
among them), the Poly1305 key derivation and the AEAD, plus tamper negatives (a
flipped bit of the tag, ciphertext, nonce or AAD, and another key, each refused
with the buffer unchanged); the FIPS 202 Keccak-f[1600] zero-state vector,
SHAKE128 and SHAKE256 of the empty message and NIST ACVP cases (messages and
outputs across the rate), and incremental absorbing and squeezing against the
one-shot output; and for ML-DSA-65, NIST ACVP signature-verification cases (a
valid signature with a context string through `verify`, and a valid and
three modified signatures through the message representative), with
refusals of the valid signature that reach each check: an over-long context, a
changed context or message, a changed commitment hash, a row end past OMEGA,
a decreasing row end, a non-zero trailing slot, positions out of order, and z
at its norm bound with either sign and at GAMMA1, while z just inside it is
refused only by the hash.

The host tests also run, under `cargo xtask test` on the host and under riscv64
emulation, the infrastructure of [`testkit/`](testkit/README.md), the crate's
only dev-dependency:

- **Wycheproof.** Every case of the vendored `ed25519_test.json`: valid cases
  verify, invalid ones are refused (a signature of another length than 64 bytes
  is refused by the API's `&[u8; 64]`), and an acceptable one (a small- or
  mixed-order public key) verifies exactly when the cofactorless equation holds,
  as OpenSSL's verdict in the reference vectors states. Every case of the vendored
  `chacha20_poly1305_test.json`: `open` turns a valid case's ciphertext into its
  plaintext and refuses an invalid one (a modified tag; a nonce of another size
  than 12 bytes is refused by the API's `&[u8; 12]`), and `seal` turns a valid
  case's plaintext into exactly its ciphertext and tag.
- **AEAD properties.** `open` returns what `seal` sealed at every length from 0
  to 300 bytes and at page sizes; every one-bit change to a sealed page's tag,
  nonce and AAD, a bit of every ciphertext byte, a truncation and another key
  are refused with the buffer unchanged; the length bound holds at `MAX_LEN`
  and one byte past it.
- **Wycheproof, ML-DSA.** Every case of the vendored `mldsa_65_verify_test.json`
  (valid signatures, modified ones, hint encodings HintBitUnpack refuses, z
  past its norm bound, an over-long context; a key or signature of another
  length is refused by the API's arrays), and every case of
  `mldsa_65_sign_seed_test.json`: the key of each seed, and each
  deterministic signature byte for byte, through `sign` for a message and
  through the internal interface for a message representative or a given rnd;
  an over-long context and a seed of another length are refused.
- **Differential.** `ed25519_verify` against reference vectors computed with
  OpenSSL, on generated signatures with one-bit corruptions and on an edge-case
  corpus (malleability, the S range check, degenerate and non-canonical public
  keys, small-order and non-canonical R), comparing which check fails, not only
  acceptance; `sha512` and `Sha512` against OpenSSL's digests over every
  length to 300 bytes and longer messages, fed whole and in pieces; `shake128`,
  `shake256` and the incremental forms against OpenSSL's output over every
  message length to one byte past the rate and longer messages, absorbed and
  squeezed whole and in pieces; and `ml_dsa::verify` against OpenSSL on
  signatures with one-bit flips of the signature, key, message and context,
  z set at and inside its norm bound, and hint sections broken in each way
  HintBitUnpack refuses, comparing which check fails, not only acceptance.
- **Signing.** `ed25519_public_key` and `ed25519_sign` against the reference
  vectors' signing inputs, byte for byte: the RFC 8032 § 7.1 secrets, the
  all-zero and all-one seeds, and generated seeds over messages either side of
  the hash's padding and block boundaries and of random lengths. Every
  signature over generated seeds and messages verifies under
  `ed25519_verify`; `mul_add` agrees with the testkit's independent 256-bit
  arithmetic at the largest inputs the signer forms; and the constant-time
  counts of § Design notes hold. `ml_dsa::public_key` and `ml_dsa::sign`
  against the reference vectors' signing inputs, byte for byte: generated
  seeds over messages of random lengths up to 4 KiB with context strings from
  empty to 255 bytes, each signature verifying under `ml_dsa::verify`; the
  masked SampleInBall equals the indexed one of FIPS 204's text, and every
  rounding function its definition over all of [0, q). The signers are not
  compiled into ktest, so they run in the host tests only.

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
│                               # harness, OpenSSL reference vectors and their
│                               # generator (crypto-testkit)
└── src/
    ├── lib.rs                  # Crate doc, public re-exports
    ├── sha512.rs               # SHA-512 (one-shot + incremental) + KATs
    ├── keccak.rs               # Keccak-f[1600] permutation (FIPS 202)
    ├── shake.rs                # SHAKE128, SHAKE256 (one-shot + incremental) + KATs
    ├── kat_hex.rs              # Compile-time hex decoding of KAT vectors
    ├── chacha20poly1305.rs     # seal, open, SealError, OpenError + KATs
    ├── chacha20.rs             # ChaCha20 block function and keystream
    ├── poly1305.rs             # Poly1305 authenticator
    ├── ed25519.rs              # ed25519_verify, VerifyError + KATs
    ├── ed25519_sign.rs         # ed25519_public_key, ed25519_sign (sign feature)
    ├── field.rs                # GF(2^255-19) field arithmetic
    ├── edwards.rs              # edwards25519 group: points, scalar mul, decompression
    ├── scalar.rs               # arithmetic mod L: S<L check, 64-byte reduction, S = r + k·a
    └── ml_dsa/                 # ML-DSA-65 (FIPS 204)
        ├── mod.rs              # Module doc, public re-exports
        ├── params.rs           # The parameter set and the lengths derived from it
        ├── poly.rs             # Arithmetic mod q, NTT and its inverse
        ├── rounding.rs         # Power2Round, Decompose, MakeHint, UseHint
        ├── sample.rs           # ExpandA entries, ExpandS, ExpandMask, SampleInBall
        ├── encode.rs           # Bit packing, the hint and z range checks, hint packing
        ├── verify.rs           # verify, VerifyError
        ├── sign.rs             # public_key, sign, SignError (sign feature)
        ├── kat.rs              # run_ml_dsa_kats: ACVP cases, refusals by check
        └── tests.rs            # Host tests: Wycheproof, OpenSSL references, stack bound
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [docs/signing.md](../../docs/signing.md) | The chain of trust the crate's verifier and signer serve; what the signer guarantees (§ Signing) |
| [docs/platform-requirements.md](../../docs/platform-requirements.md) | The riscv64 floor (RVA23) whose Zkt the AEAD's constant time rests on |
| [core/kernel/docs/entropy.md](../../core/kernel/docs/entropy.md) | The kernel's entropy sponge, which runs the crate's Keccak-f[1600] |
| [testkit/README.md](testkit/README.md) | The test infrastructure the host tests run |

---

## Summarized By

None
