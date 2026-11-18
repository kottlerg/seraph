# shared/objsig

Codec and verifier of Seraph's signed objects: the signature trailer, the certificate and the
trust store whose formats [docs/signing.md](../../docs/signing.md) specifies byte by byte, and the
verification policy of its § Verification.

`no_std`, no allocation; its one dependency is [`shared/crypto`](../crypto/README.md) (SHA-512 and
`ed25519_verify`). xtask links it, to sign and to verify each signed object before writing it; the
bootloader links it to verify the kernel and every bundle entry, procmgr to parse the trust store it
receives and verify against it, and init-log-levels and devmgr-firmware to take the body of a data
module through `split`. No stability obligation; internal code reuse only.

---

## Interface

| Item | Role |
|---|---|
| `split` | Parses a signed object, `body \|\| records \|\| footer`, with every parse check of the format and no signature check; returns the body and its records. A consumer of a data module the bootloader verified takes the body through it |
| `verify` | Verifies a signed object against a `TrustStore` and the caller's `Expectation` (the roles it accepts, the name, the architecture); returns the body with the attributes and anchor of the record that passed, or one `Refusal` |
| `verify_cached`, `CertificateCache` | `verify` with a cache the caller keeps across objects: a certificate whose signature verified is held with its issuer key (`CERTIFICATE_CACHE_LEN`, 4, the oldest replaced first), and the same pair is not verified again ([docs/signing.md](../../docs/signing.md) § Verification) |
| `TrustStore::parse` | Parses and checks a whole trust store; `anchor` finds an anchor by key id and `is_revoked` a revoked key id, each by binary search |
| `Attributes`, `Certificate` | Decode and encode the signed attributes and the certificate |
| `encode_trailer`, `TrustStore::encode` | Write a trailer and a store into a caller's buffer, for the host signer |
| `embed::{MARKER, Embedded, find}` | The layout that embeds a trust store in a bootloader image, `MARKER` (16 bytes) `\|\| len` (`u32` LE) `\|\| store`, and `find`, which locates the one `Embedded` store in an image's bytes |
| `key_id` | The key id of an Ed25519 public key: the first 16 bytes of its SHA-512 |

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
one record, and each `RecordFailure`. A flip of any bit of a signed object is refused, and seeded
random mutations and noise are refused without a panic. The tests sign with RFC 8032 signatures
computed on the edwards25519 arithmetic of [`shared/crypto/testkit`](../crypto/testkit/README.md),
which is independent of `shared/crypto`, checked against RFC 8032's test vector.

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
    ├── embed.rs                # Trust store embedded in a bootloader image: marker, find
    ├── store.rs                # Trust store
    ├── trailer.rs              # Signed object: split, records, trailer encoder
    ├── verify.rs               # Verifier and its policy
    ├── wire.rs                 # Byte-wise little-endian reader and writer
    └── testutil.rs             # Test signer and fixture builders (tests only)
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/signing.md](../../docs/signing.md) | Threat model, formats, trust store, verification, verifier discipline |
| [shared/crypto/README.md](../crypto/README.md) | SHA-512 and Ed25519 verification |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
