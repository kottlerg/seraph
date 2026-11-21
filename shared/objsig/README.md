# shared/objsig

Codec and verifier of Seraph's signed objects: the signature trailer, the certificate and the
trust store whose formats [docs/signing.md](../../docs/signing.md) specifies byte by byte, and the
verification policy of its § Verification.

`no_std`, no allocation; its one dependency is [`shared/crypto`](../crypto/README.md) (SHA-512,
`ed25519_verify` and `ml_dsa::verify`, and, behind the `sign` feature, their signers). xtask links
it, to sign and to verify each signed object before writing it; the bootloader links it to verify
the kernel and every bundle entry, procmgr to parse the trust store it receives and verify against
it, and init-log-levels and devmgr-firmware to take the body of a data module through `split`. No
stability obligation; internal code reuse only.

---

## Interface

| Item | Role |
|---|---|
| `split` | Parses a signed object, `body \|\| records \|\| footer`, with every parse check of the format and no signature check; returns the body and its records. A consumer of a data module the bootloader verified takes the body through it |
| `verify` | Verifies a signed object against a `TrustStore` and the caller's `Expectation` (the roles it accepts, the name, the architecture); returns the body with the attributes and anchor of the record that passed, or one `Refusal` |
| `verify_cached`, `CertificateCache` | `verify` with a cache the caller keeps across objects: a certificate whose signature verified is held as the SHA-512 of its issuer key and its bytes (`CERTIFICATE_CACHE_LEN`, 4, the oldest replaced first), and the same pair is not verified again ([docs/signing.md](../../docs/signing.md) § Verification) |
| `TrustStore::parse` | Parses and checks a whole trust store; `anchor` finds an anchor by key id and `is_revoked` a revoked key id, each by binary search |
| `composite::{verify, public_key, sign}` | The composite signature of Ed25519 and ML-DSA-65 ([docs/signing.md](../../docs/signing.md) § Composite Signature): `verify` refuses a signature either half of which fails; `public_key` and `sign`, from the 64-byte secret of both halves' seeds, compile with the `sign` feature alone, which only a host tool enables, as [shared/crypto](../crypto/README.md)'s |
| `Attributes`, `Certificate` | Decode and encode the signed attributes and the certificate; a parsed certificate, record or anchor borrows its keys and signatures from the bytes it was parsed from, so no 2 to 5 KiB copy lands on a loader's stack |
| `encode_trailer`, `TrustStore::encode` | Write a trailer and a store into a caller's buffer, for the host signer |
| `embed::{MARKER, Embedded, find}` | The layout that embeds a trust store in a bootloader image, `MARKER` (16 bytes) `\|\| len` (`u32` LE) `\|\| store`, and `find`, which locates the one `Embedded` store in an image's bytes |
| `key_id` | The key id of a composite public key: the first 16 bytes of the SHA-512 of all 1,984 bytes |
| `index::{Index, encode}` | The signed index of a configuration directory ([docs/signing.md](../../docs/signing.md) § Configuration): `Index::parse` checks the format (one canonical path component per line, `\n`-terminated, strictly ascending byte for byte, never `index` itself) and `encode` writes it, refusing what the parser refuses |

A `Refusal` is a parse error, `Untrusted` when no record names an anchor of the store (by
`signer_key_id` without a certificate, by the certificate's `issuer_key_id` with one), or the
`RecordFailure` of the first record that names one and fails a check.

Every parser is a total function over an arbitrary byte slice: it reads byte-wise and only inside
the slice, never panics, and refuses anything the format does not define, so each is a fuzz entry
point as it stands. Every encoder refuses what the parsers refuse, so what it writes parses.

`MAX_RECORDS` (8) and `CERTIFICATE_CACHE_LEN` (4) are the crate's bounds beside the formats'
field widths ([docs/limits.md](../../docs/limits.md)); the codec holds no array sized from a count.

## Tests

The host tests (`cargo xtask test`) pin each format's layout to the specification, round-trip
every encoder through its parser, refuse each malformed field with its own error, and check every
verification outcome: a record of a root and of a certified key passing, the object passing on any
one record, and each `RecordFailure`. A record or a certificate whose composite signature has
either half invalid, the other valid, is refused. A flip of a bit of a signed object is refused
(every bit outside its keys and signatures, a sample of the bits inside them), and seeded random
mutations and noise are refused without a panic. The tests sign with the composite signer, whose
halves `shared/crypto` tests against their reference vectors, and test that each half is the
primitive's signature under the stated context.

---

## Source Layout

```
shared/objsig/
├── Cargo.toml                  # Workspace member; no_std library
├── README.md
└── src/
    ├── lib.rs                  # Kinds, architectures, usage masks, key ids, errors
    ├── attrs.rs                # Signed attributes
    ├── cert.rs                 # Certificate
    ├── composite.rs            # Composite signature: Ed25519 and ML-DSA-65
    ├── embed.rs                # Trust store embedded in a bootloader image: marker, find
    ├── index.rs                # Signed index of a configuration directory
    ├── store.rs                # Trust store
    ├── trailer.rs              # Signed object: split, records, trailer encoder
    ├── verify.rs               # Verifier and its policy
    ├── wire.rs                 # Byte-wise little-endian reader and writer
    └── testutil.rs             # Test keys and fixture builders (tests only)
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/signing.md](../../docs/signing.md) | Threat model, formats, trust store, verification, verifier discipline |
| [shared/crypto/README.md](../crypto/README.md) | SHA-512, Ed25519 and ML-DSA-65 verification and signing |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
