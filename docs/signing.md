# Signing and Chain of Trust

How Seraph establishes that every object it boots and every image it runs was produced by a key the
system trusts: the threat model, the signed-object and certificate formats, the trust store, the
stage that verifies each object, and the discipline every verifier follows.

---

## Scope

This document is authoritative for:

- The threat model of the chain of trust: what it defends against and what it leaves to other
  mechanisms.
- Which stage verifies which object, and against what.
- The signed-object format (the trailer), the certificate format, the trust-store format, and the
  canonical form of the hashed bytes.
- The verification algorithm and the policy it applies.
- The verifier discipline every verifying stage follows.
- The policy-bearing configuration files, their consumers, and the signed index of a configuration
  directory.
- Where keys live, how objects are signed, and what the trust store holds.

The cryptographic primitives (SHA-512, Ed25519 verification, key generation and signing) are
specified in [shared/crypto/README.md](../shared/crypto/README.md). The bootloader's boot steps are
specified in
[core/boot/docs/boot-flow.md](../core/boot/docs/boot-flow.md), procmgr's creation interface in
[services/procmgr/docs/ipc-interface.md](../services/procmgr/docs/ipc-interface.md), and the
platform's firmware baseline in [platform-requirements.md](platform-requirements.md).

---

## Implementation Status

The primitives exist: [`shared/crypto`](../shared/crypto/README.md) provides `ed25519_verify`,
`ml_dsa::verify` and `Sha512`, tested against known-answer vectors, Wycheproof, and reference
vectors computed with OpenSSL, and, behind its `sign` feature, the key generation and signing that
§ Signing requires of it (`ed25519_public_key`, `ed25519_sign`, `ml_dsa::public_key`,
`ml_dsa::sign`), tested against the same reference vectors and the verifiers. The composite
signature of § Composite Signature, the formats of § Signed Object Format, § Certificate Format and
§ Trust Store, and the verification of § Verification, are implemented and host-tested in
[`shared/objsig`](../shared/objsig/README.md), which xtask and the bootloader link; its `sign`
feature, which enables `shared/crypto`'s, composes the signers. xtask, the host signer, enables the
feature, and core/boot enables it as a dev-dependency only, since its host tests sign fixtures.
xtask's keys and signing of § Signing are implemented: every build signs the kernel, every ELF image
of the root filesystem, the files of its data trees and the data files the bundle lists name, each
once, in the sysroot, under the role set and the name of § Signed Attributes, the configuration
files of § Configuration with the index of each of their directories, composes the ESP by
copying the installed files, builds the trust store at the path § Signing names, and embeds it in
the bootloader. The bootloader verifies the kernel and every bundle entry against that store, each
entry under `/config/` in the configuration role, refuses a bundle without the boot-time policy (§
Configuration), and hands the store to procmgr (§ Trust Store), which parses it and keeps it.
procmgr verifies every
image it creates against that store before it parses it (§ Verifier Discipline), under its creator's
signature policy and the name the creator gives (§ Signature Policy in procmgr), and verifies a data
file in the data role, or a configuration file in the configuration role, at its reader's request
(`procmgr_labels::READ_VERIFIED`, § Verifier Discipline), which svctest's `procmgr_read_verified`
phase exercises on both architectures, which devmgr uses for the platform description tables, and
which svcmgr uses for its service recipes and device class files, read through each directory's
signed index (§ Configuration). The override that § Signature Policy in
procmgr describes is design intent, not yet implemented: no creator can hold it, so procmgr creates
no process from an image that does not verify. `cargo xtask test signing` boots each refusal on both
architectures: a tampered kernel, a tampered bundle entry, a revoked signing key, a bundle without
its boot-time policy, and a policy signed by a key not trusted for the configuration role in the
bootloader; a tampered service, one signed without a role its creator's policy admits and one
signed by an untrusted key in procmgr, beside a kernel and a program whose untrusted record both
verifiers skip; configuration files tampered with, unsigned, or signed by a key not trusted for the
configuration role, a service signed by a key trusted for configuration alone, a recipe validly
signed over a body other than its index line's, and a directory index that names a missing file and
omits a present one; and both indexes tampered with
([testing.md](testing.md) § Gating, Signature refusals). The bootloader keeps the machine's
security floor in a boot-services-only UEFI variable, raises it, and refuses itself below it
(§ Rollback Floor); `cargo xtask test rollback` boots the floor written, raised, and refusing an
older bootloader on both architectures ([testing.md](testing.md) § Gating, Rollback floor). The
bootloader keeps the enrolled trust store in firmware storage and applies trust requests to it
(§ Trust Store); `cargo xtask test enrolment` boots a root enrolled by a signed request and by
one confirmed at the console, a request refused at the timeout and by the commit rule, and the
build's roots revoked, on both architectures ([testing.md](testing.md) § Gating, Root
enrolment). The local signer of § Configuration is design intent, not yet implemented.

[boot-media.md](boot-media.md) states why one object carries one signature, and how the bundle
lists in configuration choose the bundle's entries.

---

## Principles

Implemented, apart from the override of the third principle, which is design intent, not yet
implemented (§ Signature Policy in procmgr).

- **Verify at the loader.** An object is verified by the stage that turns its bytes into running
  code or into input that code trusts: the bootloader for what it loads, procmgr for every image it
  creates. procmgr is the only runtime loader
  ([process-lifecycle.md](process-lifecycle.md) § Steady-State Process Creation) and the only
  holder of the trust store at run time, so it is the only runtime verifier: a process that reads a
  data file as trusted input has procmgr verify it and parses only the body procmgr returns.
- **The kernel verifies nothing.** The kernel provides mechanism only; it parses no signature and
  holds no key.
- **The right to run an unverified image is a capability**, held on procmgr's record of the
  creator, never a flag a caller asserts ([capability-model.md](capability-model.md)).
- **The deployer decides which roots a system trusts.** The project's root, when one exists, is one
  root among any number; a deployer may add roots beside it or replace it.
- **No private key enters the work tree.**

---

## Threat Model

The attacker can write the storage the system boots and runs from: the EFI System Partition (ESP),
the bootstrap bundle on it, and the root filesystem. The attacker does not hold a private key the
system trusts. Firmware, the bootloader once it runs, the kernel, init, memmgr and procmgr are
trusted to execute as built.

| Threat | Defence | What remains |
|---|---|---|
| **Tampering.** Change the bytes of a signed object. | The signed attributes carry the SHA-512 of the body and the body's length; the verifier hashes the bytes it will load. | None within the chain. |
| **Signature substitution.** Copy a valid record onto another body. | The record signs the body's hash, so it verifies only over the body it was made for. | None. |
| **Object swap.** Put one legitimately signed object where another is expected (a signed program in place of a service, `fatfs` in place of `procmgr`). | The signed attributes carry the object's roles and name; the verifier requires a role its caller accepts and the name it is loading. | An image packed with a test harness in its `init` slot carries the harness signed `init` (§ Signing); a system whose store trusts the key that signed that image boots the harness if it is copied into its own `init` slot. |
| **Replay.** Replace an object with an older, legitimately signed one that has a known vulnerability. | The signed attributes carry a security version; the trust store sets a floor, a key's certificate bounds the versions it may sign, and a compromised key is revoked. | Without Secure Boot, a whole older image boots whose bootloader ignores the machine's floor in firmware storage (§ Rollback Floor); with it, every Seraph bootloader the firmware admits refuses itself below that floor. A platform whose firmware refuses the floor's write keeps the build-time floor alone. |
| **Key compromise.** Steal a signing key. | A key signs only the object roles and security versions its certificate names; the chain is at most two keys deep; a revoked key id is refused. | Revocation reaches a system whose bootloader carries the updated trust store, or that has applied a trust request revoking the key id (§ Trust Store). A key trusted for the enrolment role enrols roots on every system that trusts it, so its compromise is that of the systems' stores. A locally generated root's compromise is its builder's own risk. |
| **Verifier bypass.** Reach a path that loads without verifying, or that continues after a failed check. | Every check has one exit on failure and no fallback; the verifier returns the body only on success, and loaders read only what it returns. | None. |
| **Carrier confusion.** Duplicate, nested, truncated or malformed trailers, or bytes after the trailer. | The footer and every record parse strictly; any parse error rejects the whole object; a body that itself ends in a trailer is rejected. | None. |
| **TOCTOU.** Change the bytes between verification and use. | The verifier reads the object once into memory no other process can write, verifies that copy, and the loader parses and loads only from it. | None. |
| **Trust-store substitution.** Replace the roots the system trusts. | The built-in trust store is built into the bootloader; replacing it means replacing the bootloader. The enrolled store lies in a variable boot services alone reach, and changes only by a trust request that a key the store trusts signed in the enrolment role, or that someone at the console confirms after seeing each change (§ Trust Store). | Without Secure Boot, an attacker who can write the ESP replaces the bootloader and its roots: the chain is as strong as the ESP's integrity (§ Secure Boot). Someone at the console who confirms a request an attacker placed on the ESP enrols its roots. An attacker at the firmware's shell can delete the enrolled store, and its revocations with it. |
| **Configuration tampering.** Change a policy-bearing configuration file (`/config/svcmgr/services/*.svc`) so a verified binary runs under altered policy. | Each policy-bearing file is signed in the configuration role, which no binary is accepted in, and its consumer has procmgr verify it before it parses it (§ Configuration). | None within the chain. |
| **Configuration removal, addition or mixing.** Delete a recipe from a configuration directory, add one beside the files it holds, or put back an older signed copy of one. | The directory's signed index names each file it held at signing time with the SHA-512 of its body; the consumer reads only the files the index names, refuses a body whose hash is not its line's, and reports a named file that is missing and a file the index does not name (§ Configuration). | A whole older directory with its older index, all signed at a security version the machine's floor admits, verifies: the floor rises only with a revoking release (§ Rollback Floor), so the configuration of any release since the last raise is accepted. An index whose freshness a TPM counter attests is [#1416](https://github.com/kottlerg/seraph/issues/1416). |

---

## Which Stage Verifies What

| Object | Verified by | Against | Expected role and name |
|---|---|---|---|
| Bootloader (PE) | Firmware, when Secure Boot is enabled | The firmware's db (§ Secure Boot) | Not applicable |
| Kernel (`\EFI\seraph\kernel`) | Bootloader | The trust store built into it | kernel, `kernel` |
| The bundle entry `init` | Bootloader | The same store | init, `init` |
| A bundle entry whose name lies under `/config/`, the boot-time configuration (§ Configuration) | Bootloader | The same store | configuration, its entry name: the file's install path |
| Every other bundle entry | Bootloader | The same store | boot module, its entry name: the object's install path |
| (nothing) | Kernel | Not applicable | Not applicable |
| memmgr, procmgr | init loads them from boot modules the bootloader verified | Nothing further | Not applicable |
| Every image procmgr creates, from a file or a Memory cap | procmgr | The store the bootloader hands forward | The roles the creator's policy allows; the name the creator gives, an install path |
| A data file a process reads from the root filesystem as trusted input (a platform description table devmgr reads) | procmgr, at the reader's request (`procmgr_labels::READ_VERIFIED`) | The same store | data, its install path |
| A policy-bearing configuration file, and the index of its directory (§ Configuration) | procmgr, at its consumer's request (`procmgr_labels::READ_VERIFIED`) | The same store | configuration, its install path |

The bundle container itself is not signed: the bootloader parses its header with the bounds-checking
parser of [`abi/boot-protocol::bundle`](../abi/boot-protocol/src/bundle.rs) and verifies each entry
under its entry name before it uses the entry. An entry other than `init` is named by its object's
install path, which the entry-name field holds whole, up to `objsig::NAME_MAX` (256 bytes) like any
signed name ([limits.md](limits.md) § Bootloader and boot ABIs), and the bootloader refuses any
other entry name. An attacker who edits the header can drop an entry, which fails the boot when the
entry is needed, or rename one, which its signed name refuses. Dropping the boot-time policy fails
every boot: the bootloader refuses a bundle without it (§ Configuration).

---

## Signed Object Format

Implemented by [`shared/objsig`](../shared/objsig/README.md), which xtask links to sign and the
bootloader to verify.

A signed object is its body followed by a trailer of one or more records and a fixed footer:

```
body || record_1 || ... || record_n || footer
```

The trailer is appended to the object as it is, so any object can be signed: an ELF image, the
riscv64 platform description table, a configuration file. ELF parsers and the bundle ignore the
trailing bytes; the verifier returns the body alone, and a loader never sees the trailer. Adding a
record rewrites the one trailer and leaves the body, and so every other record, valid: a deployer
signs an object the project signed without rebuilding it.

Every integer is little-endian. No field is aligned and no padding exists, so a decoder reads every
field byte-wise from an unaligned slice.

### Footer

The footer is the object's last 16 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `records_len`: the length in bytes of the record block |
| 4 | 2 | `record_count`: the number of records, 1 to `MAX_RECORDS` (8) |
| 6 | 2 | `version`: 2 |
| 8 | 8 | magic `SERAPHSG` |

`MAX_RECORDS` bounds the work a verifier does for one object, since every record that chains to a
trusted root costs up to two composite signature verifications.

### Record

`record_count` records lie back to back in the record block, which ends where the footer begins:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `record_len`: the record's length in bytes, this field included |
| 4 | 1 | `algorithm`: 2 = the composite of Ed25519 and ML-DSA-65 (§ Composite Signature) |
| 5 | 1 | `cert_count`: 0 or 1 |
| 6 | 2 | `attrs_len`: the length of the signed attributes |
| 8 | 16 | `signer_key_id`: the key id of the key that made `signature` |
| 24 | `attrs_len` | The signed attributes |
| 24 + `attrs_len` | 5,409 × `cert_count` | The certificate of the signing key, when it is not a root |
| `record_len` − 3,373 | 3,373 | `signature`: the composite signature over the signed attributes |

`record_len` is exactly 3,397 + `attrs_len` + 5,409 × `cert_count`, and the records' lengths add
up exactly to `records_len`. A record with a certificate and a name of 20 bytes is 8,925 bytes.

A key id is the first 16 bytes of the SHA-512 of the key's 1,984-byte composite public key, both
halves. It is always
computed from a key and never taken from the wire as the identity of one: a record's
`signer_key_id` selects a key, and the verifier checks that the key it selected has that id.

### Signed Attributes

The signature covers the encoded attributes and nothing else:

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | Domain tag: `seraph/obj/v3` padded with NUL bytes to 16 |
| 16 | 8 | `body_len`: the body's length in bytes |
| 24 | 4 | `security_version` |
| 28 | 4 | `roles`: the set of roles the object may be loaded in (below) |
| 32 | 64 | `body_hash`: the SHA-512 of the body |
| 96 | 2 | `name_len`: 1 or more |
| 98 | 1 | `arch`: 1 = x86-64, 2 = riscv64 |
| 99 | `name_len` | `name` |

`attrs_len` is exactly 99 + `name_len`. The fixed fields lie at the offsets their widths would
align them to, the one-byte `arch` last, though no decoder relies on it. The domain tag keeps an
object signature from ever being read as a certificate signature, whose signed bytes begin with
another tag, and names the attributes' version: a record whose attributes carry the tag of another
version does not parse, so a single kind of an older encoding is never read as a set.

An object has one identity: one record per signer states every role it may be loaded in, under
one name.

**Role bits.** Every 32-bit set of roles in the system has one numbering: a record's `roles`, and
the `usage` of a certificate (§ Certificate Format) and of an anchor (§ Trust Store). Bit `n` is
role `n` of the table below, for bits 1 to 9. Bit 31 is `CERTIFY`, the right to issue
certificates, valid in a `usage` alone and refused in a record's `roles`. Bit 0 and bits 10 to 30
are no role: a set with any of them set is refused wherever it appears, until a role is defined for
the bit. A record's `roles` has at least one role, and a set that holds kernel, init or enrolment
holds no other role.

| Role `n` | Name | Objects |
|---|---|---|
| 1 | kernel | The kernel image |
| 2 | init | The object of the bundle's `init` slot (init, or a harness such as ktest in it) |
| 3 | boot module | An object the bootloader may load as a bundle entry other than `init` and outside `/config/`, whatever its content |
| 4 | service | A service image |
| 5 | driver | A driver image |
| 6 | program | A program image |
| 7 | data | A data file procmgr verifies for its reader (§ Verifier Discipline) |
| 8 | configuration | A policy-bearing configuration file, or a configuration directory's index, procmgr verifies for its consumer, or the bootloader as a bundle entry under `/config/` (§ Configuration) |
| 9 | enrolment | A trust request the bootloader applies to the enrolled trust store with no one present (§ Trust Store) |

A role is a permission the signer grants, not a place: an installed service the bootstrap needs
carries service and boot module, and the bundle's copy of it is the same bytes.

The `name` is `kernel` for a set holding kernel, `init` for a set holding init, `trust-request` for
a set holding enrolment, and for every other object its install path from the root of the root
filesystem (`/services/svcmgr`), wherever the object lies, a bundle entry's included. Names are
compared byte for byte, so each has one canonical form, in which the signer signs it and procmgr
requires a creator to give it: 1 to 256 bytes of UTF-8, and either one of the three slot names or
`/` followed by components separated by single `/` (an install path), each component nonempty,
holding no `/` and no NUL, and neither `.` nor `..`. `objsig::name_is_canonical` is the one check of
it, which xtask's signer and procmgr both call; procmgr accepts an install path alone. The
comparison is case-exact: the root filesystem resolves names without regard to letter case, so a
path spelled in another case reaches the same file, but no signature names that spelling, and
procmgr refuses the object under it. A creator names an object by its install path as xtask installs
it.

### Hashed Bytes

The hash covers exactly the body: bytes `[0, len − 16 − records_len)` of the object, where `len`
is the object's length. The signed `body_len` MUST equal that length. Nothing else is hashed and
nothing is skipped, so the canonical form needs no knowledge of the body's format.

---

## Composite Signature

Implemented by [`shared/objsig`](../shared/objsig/README.md) (`objsig::composite`), on the
primitives of [`shared/crypto`](../shared/crypto/README.md).

Every signature in the system is one composite: an Ed25519 signature and an ML-DSA-65 signature
over the same message, valid only when both verify. It is algorithm 2, the one algorithm a record
names, and it signs every record and every certificate; every key a record, a certificate or an
anchor holds is a composite key. There is no other algorithm, no transition state and no policy
over algorithms: a record naming any algorithm but 2 does not parse, and refuses the object. The
earlier format, Ed25519 alone (algorithm 1, footer version 1, certificate tag `seraph/cert/v1`,
store version 1), is not read.

| Part | Size | Layout |
|---|---|---|
| Public key | 1,984 | The Ed25519 public key (32) then the ML-DSA-65 public key (1,952) |
| Signature | 3,373 | The Ed25519 signature (64) then the ML-DSA-65 signature (3,309) |
| Secret | 64 | The Ed25519 secret seed (32) then the ML-DSA-65 key-generation seed (32) |

- **The Ed25519 half** is RFC 8032 Ed25519, pure, over the message.
- **The ML-DSA-65 half** is FIPS 204 ML-DSA-65, the pure form, over the message with the context
  string `seraph/sig/ed25519+ml-dsa-65` (28 bytes), signed deterministically. The context string
  binds the half to this construction: an ML-DSA-65 signature the same key made in any other use
  does not verify as the half of a composite.
- **Verification** checks the Ed25519 half, then the ML-DSA-65 half, and refuses the signature on
  the first that fails. A forgery needs both schemes broken: Ed25519 falls to a quantum attacker,
  and ML-DSA rests on a lattice assumption younger than Ed25519's and on the project's own code.
  Against a quantum attacker the composite is as strong as ML-DSA-65.
- **The secret** is two seeds, each drawn on its own from the host's random source: neither half's
  key is derived from the other's, nor from a seed they share. Each half derives its key from its
  seed as its standard specifies (RFC 8032 § 5.1.5, FIPS 204 Algorithm 6).

**Cost.** In the bootloader, the Ed25519 half of a verification takes about 0.9 ms and the
ML-DSA-65 half about 0.13 ms on x86_64 under KVM, which runs the code at the speed of the host's
CPU, and about 6.6 to 7.2 ms and 0.7 to 0.8 ms on riscv64 under QEMU's TCG emulation: the
ML-DSA-65 half is the cheaper on both. The SHA-512 of the body, which every verification adds,
runs at about 600 MB/s on x86_64 and 120 to 170 MB/s on riscv64. A boot of the default image
verifies ten objects (the kernel and the bundle's entries) and the signer's certificate once
(§ Verification), in about 16 to 18 ms on x86_64 and 100 to 120 ms on riscv64, the hashes
included. A verification with an empty certificate cache, the deepest, uses under 11 KiB of
stack, against the 128 KiB of firmware stack the bootloader runs on
([core/boot/docs/uefi-environment.md](../core/boot/docs/uefi-environment.md) § Stack). The
figures were measured in the debug and the release build, which differ by little here, at
4 vCPUs beside no other QEMU; the riscv64 figures are the emulator's, and no rule bounds the cost.

The messages are short and carry their own domain tags (`seraph/obj/v3` for a record's signed
attributes, `seraph/cert/v2` for a certificate's signed bytes), so neither half hashes the message
first and the Ed25519 half needs no context of its own. Seraph's encoding of the composite is its
own, like the formats above, and not the X.509 encoding of the IETF composite signature drafts.

---

## Certificate Format

Implemented by [`shared/objsig`](../shared/objsig/README.md), which xtask links to sign and the
bootloader to verify.

Seraph's certificate is a fixed 5,409-byte record, not X.509: no ASN.1 parser enters the
bootloader, and the composite is the only algorithm (§ Composite Signature). A root (an anchor of
the trust store) issues it to a signing key:

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | Domain tag: `seraph/cert/v2` padded with NUL bytes to 16 |
| 16 | 1,984 | `subject_key`: the signing key's composite public key |
| 2,000 | 16 | `issuer_key_id`: the key id of the root that issued it |
| 2,016 | 8 | `serial` |
| 2,024 | 4 | `usage` (below) |
| 2,028 | 4 | `min_security_version` |
| 2,032 | 4 | `max_security_version`, at least `min_security_version` |
| 2,036 | 3,373 | `signature`: the issuer's composite signature over bytes 0 to 2,035 |

The `usage` mask is a set of roles in the numbering of § Signed Attributes (Role bits): the roles
the key may sign, and `CERTIFY` when the key may issue certificates. A certificate's `CERTIFY` bit
is clear: the chain is at most two keys deep (a root, a signing key, the object), so
a signing key certifies nothing. A root signs an object directly when its record carries no
certificate.

A certificate has no validity dates: the system has no trusted clock at boot
([platform-requirements.md](platform-requirements.md) lists the RTC as no boot dependency).
Security versions and revocation take the place of expiry: `min_security_version` and
`max_security_version` bound what the key may sign, so a key of one release line cannot sign an
object of a later one.

---

## Trust Store

Implemented by [`shared/objsig`](../shared/objsig/README.md), which xtask links to sign and the
bootloader to verify.

The trust store is one public blob: the roots a system trusts, the key ids it refuses, and the
lowest security version it runs.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `SRPHTRST` |
| 8 | 2 | `version`: 2 |
| 10 | 2 | `anchor_count`: 1 or more |
| 12 | 2 | `revoked_count` |
| 14 | 4 | `security_floor` |
| 18 | 2,024 × `anchor_count` | The anchors |
| 18 + 2,024 × `anchor_count` | 16 × `revoked_count` | The revoked key ids |

An anchor is 2,024 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1,984 | `key`: the root's composite public key |
| 1,984 | 4 | `usage`: as a certificate's, `CERTIFY` allowed |
| 1,988 | 4 | `flags`: bit 0, `LOCAL`, marks a root generated on the build machine; every other bit is zero |
| 1,992 | 32 | `label`: a nonempty UTF-8 name, padded with NUL bytes |

The anchors are sorted by key id, strictly ascending, so no two share one and a lookup is a binary
search; the revoked key ids are sorted the same way. The blob's length is exactly the sum of its
parts. A store that breaks any rule of this section is refused whole.

**Where it lives.** A boot runs on two stores, merged. The built-in store is built into the
bootloader, which firmware Secure Boot covers on a platform that enables it; a deployer replaces or
extends it by building the bootloader with their own (§ Signing). The enrolled store lives in
firmware storage and changes without a rebuild: the bootloader enrols roots into it, and revokes
key ids through it, by applying a trust request (below). The bootloader verifies the boot with, and
hands procmgr, the merge of the two: the anchors of both (the built-in anchor kept where both hold a
key id), the revoked key ids of both, and the built-in store's floor. A revoked key id beats an
anchor from either store, since § Verification refuses a record whose anchor or signing key is
revoked, so an enrolled revocation retires a built-in root. No copy is built into procmgr, which
would drift from the bootloader's.

The enrolled store is the UEFI variable `TrustStore` under the Seraph vendor GUID
`a53c3964-9d31-4f44-843a-526baa1271b8`, non-volatile and reachable by boot services alone, so
nothing running after `ExitBootServices` can write it:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `SRPHENRL` |
| 8 | 2 | `version`: 1 |
| 10 | 2 | `anchor_count`: 0 to 3 |
| 12 | 2 | `revoked_count`: 0 to 120 |
| 14 | 2,024 × `anchor_count` | The anchors, in the trust store's layout |
| 14 + 2,024 × `anchor_count` | 16 × `revoked_count` | The revoked key ids |

The lists are sorted as the trust store's are, and no anchor's key id is among the revoked ones. It
carries no floor: the floor is the built-in store's, and the machine's is § Rollback Floor's. A
later layout, the store spread over several variables among them, takes another version. A variable
that does not parse, is longer than the bound, carries other attributes, or does not merge with the
built-in store refuses the boot, since a boot past it would drop the revocations it holds; the fatal
line names the recovery, deleting the variable from the UEFI shell (`dmpstore -d TrustStore -guid
a53c3964-9d31-4f44-843a-526baa1271b8`), which drops every enrolment with it. A read the firmware
fails boots on the built-in store alone and applies no request, with a warning.

**Bound.** The enrolled store holds at most 3 anchors and 120 revoked key ids, 8,006 bytes. The
bound is set so the store fits in one variable on every firmware met so far: the smallest limit, the
riscv64 EDK2's, is 8,132 bytes of name and data, which leaves 8,110 bytes of data beside the
22-byte name. Before it writes, the bootloader asks the firmware's `QueryVariableInfo` for its
largest variable where the firmware provides it, and refuses a store that would not fit. A request
whose result would pass the bound is refused whole, the log naming the bound; nothing of it is
applied.

**Trust requests.** A trust request is the file `\EFI\seraph\trust-request` on the ESP
([boot-media.md](boot-media.md) § The ESP), at most 64 KiB:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `SRPHTREQ` |
| 8 | 2 | `version`: 1 |
| 10 | 2 | `anchor_count`: the roots to enrol |
| 12 | 2 | `revoked_count`: the key ids to revoke |
| 14 | 2,024 × `anchor_count` | The anchors, in the trust store's layout |
| 14 + 2,024 × `anchor_count` | 16 × `revoked_count` | The key ids |

It is sorted as the enrolled store is, and adds an anchor or revokes a key id. A request may end in
a signature trailer (§ Signed Object Format) over the request, in the enrolment role under the name
`trust-request`. Applying it to the enrolled store adds each anchor that neither store holds and
neither has revoked, so a revoked key id is never enrolled again; revokes each key id the enrolled
store has not; and drops an enrolled anchor it revokes, whose key id stays revoked. On every boot
that finds a request, the bootloader, once it has read the kernel and the bundle and before it
verifies either for loading:

1. Skips a request that changes nothing, which every replay of an applied request does, and logs
   that it was skipped. A request is therefore left on the ESP without harm.
2. Refuses a request whose result would pass the bound.
3. Refuses a request under whose resulting store the kernel or a bundle entry would not verify
   (the commit rule), so no request leaves the bootloader unable to load the kernel and the
   bundle. The rule checks only the objects the bootloader loads: an object procmgr verifies later
   (svcmgr, a service, a configuration file) must already verify under the resulting store before
   a request revokes the key that signed it.
4. Applies a request the current store verifies in the enrolment role. Otherwise it shows the
   request at the console, why no signature authorizes it, each root it adds with its label,
   roles and key id, and each key id it revokes, and applies it only when `yes` and Enter are
   typed within 60 seconds; any other answer, no answer, or a console it cannot read refuses it.
5. Writes the new enrolled store before the security floor (§ Rollback Floor), and boots on the new
   merged store. A write the firmware refuses refuses the request, and the log reports the
   firmware's free space and largest variable.

A refused request changes nothing, and the boot runs on the current store. `cargo xtask
trust-request` writes a request from trust store files and key ids, unsigned or signed by the
build's identity, into the sysroot's ESP for the next pack or to a file
([xtask/README.md](../xtask/README.md#cargo-xtask-trust-request)).

**Hand-off.** The bootloader copies the store into a page allocation of its own and exposes it as
the last boot module of `BootInfo.modules`, named `trust-store`, a name it refuses on a bundle
entry. The kernel mints its Memory cap as for any boot module, and init passes that cap to procmgr
alone, in procmgr's bootstrap. procmgr copies the store into its own memory and parses it once at
startup; a store that is missing, or that procmgr cannot parse, stops procmgr, which then creates
no process.

**On every boot** the bootloader logs what it read of the enrolled store, then each anchor of the
store it runs on with its label, key id and source (built in, or enrolled), marking an anchor with
`LOCAL` as locally generated and one whose key id is revoked as revoked, then the store's counts
and floor. Here and at the console prompt a label is written in printable ASCII, with a backslash,
a double quote and every other character escaped as `\u{..}`, since a request's label is
untrusted input that a terminal escape sequence could otherwise turn into hidden lines.

---

## Rollback Floor

Implemented by the bootloader
([core/boot/src/rollback.rs](../core/boot/src/rollback.rs)).

The store's floor travels with the bootloader that carries it, so on its own it refuses an older
object only beside a bootloader as new as the floor: an attacker who writes the ESP installs a whole
older image, its bootloader and its older floor included. The bootloader therefore keeps the
highest floor a machine has booted under in firmware storage, in one UEFI variable:

| Property | Value |
|---|---|
| Name | `SecurityFloor` |
| Vendor GUID | `A53C3964-9D31-4F44-843A-526BAA1271B8`, the Seraph vendor GUID |
| Attributes | `NON_VOLATILE \| BOOTSERVICE_ACCESS` (`0x3`): kept across resets, reachable before `ExitBootServices` alone |
| Data | 4 bytes: the floor, a `u32`, little-endian |

On every boot:

1. Once the trust store parses, before it loads any object, the bootloader reads the variable. An
   absent variable is a floor of 0. A floor above the store's refuses the boot
   (`BootError::FloorAboveStore`): this bootloader is older than one the machine has run. A
   variable of another length or with other attributes, which no bootloader wrote, refuses the boot
   as malformed (`BootError::FloorMalformed`). A read the firmware fails (no variable services, a
   store that fails) is one warning, after which the boot runs on the store's floor and writes
   none.
2. Once the kernel and every bundle entry have verified, ahead of the memory-map reads of the steps
   that lead to `ExitBootServices`, the bootloader writes the store's floor when it is above the
   variable's, an absent variable included. A write the firmware refuses is one warning: the boot
   continues on the build-time floor, the store's, and the machine keeps the floor it had.

A bootloader that passes step 1 carries a floor at least the machine's, so the store copy procmgr
reads (§ Trust Store) already holds the effective floor: `BootInfo`, `shared/objsig`, procmgr and
the kernel do not read the variable. Both variable calls come before `ExitBootServices` and none
follows it ([core/boot/docs/uefi-environment.md](../core/boot/docs/uefi-environment.md)
§ Variable Services); without runtime access, nothing that runs after the exit, the kernel and a
compromised driver included, can reach the variable.

The floor rises only when a release raises its store's floor (§ Signing), a deliberate revocation,
and not on every release. Once a bootloader with the raised floor has booted a machine, the earlier
release no longer boots there: a revoking release cannot be backed out.

**The Secure Boot condition.** Without Secure Boot the floor is no security boundary: an attacker
who writes the ESP installs a bootloader that ignores the variable, and the floor stops only an
accidental rollback, such as the reinstall of an older release. Under Secure Boot (§ Secure Boot)
the firmware admits only a bootloader signed with a key in its db, and every Seraph bootloader so
signed carries step 1, so an older one refuses itself. No storage
stronger than the variable store adds a defence: no storage stops an older bootloader from running,
only firmware does, and Secure Boot's own keys live in the same store. Rollback protection sealed to
the measured boot with a TPM counter is [#1416](https://github.com/kottlerg/seraph/issues/1416).

**Recovery.** A machine refused for a floor above its bootloader's boots again with a bootloader
whose store carries at least that floor. Clearing the firmware's variables, from its setup or by
deleting the variable from the UEFI shell (`dmpstore -d SecurityFloor -guid
A53C3964-9D31-4F44-843A-526BAA1271B8`), resets the floor to the store's floor of the next bootloader
to run, and recovers a machine refused for a malformed variable the same way.

---

## Verification

Implemented by [`shared/objsig`](../shared/objsig/README.md), which xtask links to sign and the
bootloader to verify.

The verifier takes the object's bytes, the trust store, and what the caller expects: the set of
roles it accepts, the name it is loading, and the architecture it runs. It returns the body, with
the attributes and the anchor of the record that passed, or one refusal.

1. **Footer.** The object is at least 16 bytes long; its footer's magic and version match;
   `record_count` is 1 to `MAX_RECORDS`; `records_len` is at most the object's length less 16.
2. **Records.** Every record parses: its lengths obey § Record and § Signed Attributes, its
   `algorithm` is 2, its attributes carry their domain tag, a `roles` set that obeys § Signed
   Attributes and a defined `arch` value, its certificate (when present) carries its domain tag, a
   clear `CERTIFY` bit, no undefined usage bit and a range whose maximum is at least its minimum,
   and the records fill the record block exactly. A body whose last 8 bytes are the footer magic is
   a nested trailer. Any of these errors refuses the object, whatever the other records hold.
3. **Hash.** The verifier computes the SHA-512 of the body once.
4. **Records in order.** The object passes on the first record that passes every check below. A
   record passes when:
   - its signing key chains to an anchor: with no certificate, `signer_key_id` is an anchor's key
     id and the anchor is the signing key; with a certificate, `issuer_key_id` is an anchor's key
     id, that anchor's `usage` has `CERTIFY`, the certificate's composite signature verifies under
     the anchor's key, and `signer_key_id` is the key id of `subject_key`;
   - neither the anchor's key id nor the signing key's is revoked;
   - every role of `roles` is in the signing key's usage (with a certificate, in both the
     certificate's and the anchor's), and `roles` holds a role of the caller's set;
   - `name` and `arch` equal the caller's;
   - `body_len` and `body_hash` equal the body's length and hash;
   - `security_version` is at least the store's floor and, with a certificate, inside the
     certificate's range;
   - `signature` verifies under the signing key as a composite signature, both halves
     (§ Composite Signature).
5. **Refusal.** When no record passes, the object is refused. The refusal says whether any record
   named an anchor (by `signer_key_id` without a certificate, by the certificate's
   `issuer_key_id` with one) and, when one did, the check the first such record failed, so a log
   tells an object from an untrusted root from one whose trusted record failed.

A verifier that checks several objects MAY hold, for each certificate whose signature has
verified, the SHA-512 of the anchor key it verified under followed by the certificate, and take
the signature check of a record whose anchor key and certificate give a held digest as passed.
The check is a function of those bytes alone, and a digest stands for them unless SHA-512
collides, on which every signature already rests, so the result is the one a fresh verification
gives; every other check of step 4 is made for every record. A digest is 64 bytes where the key
and the certificate are 7,393. The bootloader holds the certificates for the whole boot, so the
certificate every object of one signing key carries is verified once.

A record that chains to no anchor is how one object carries the signatures of several parties:
each system passes over the records of roots it does not trust and accepts the object on the one
it does.

---

## Verifier Discipline

The bootloader and procmgr follow it. procmgr follows it for a data file it verifies at its reader's
request too (`procmgr_labels::READ_VERIFIED`): it refuses a file past
`procmgr_labels::READ_VERIFIED_MAX` (32 KiB) before it reads any byte, copies the file once into
one run of frames it requests on the reader's account and maps in its own address space alone,
verifies that copy in the role the reader names, data or configuration, and under the name the
reader gives, and gives the reader the run
through a capability that maps it read-only, keeping none of its own, so the reader parses only the
verified body, in bytes no process but memmgr can write
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Label 31: `READ_VERIFIED`).

- **Verify before parse.** No stage parses an object's body (its ELF headers, its table text)
  before the verifier has accepted it.
- **One read, one buffer.** The verifier works on a copy of the object that no other process can
  write, and the loader parses and loads only from that copy, through the body the verifier
  returned. A loader never reads the object from its source a second time.
- **Single exit, no fallback.** Every check fails to one refusal. No path loads an object after a
  refusal, retries it under a weaker policy, or treats a missing or malformed trailer as unsigned.
- **Strict parsing.** A parse error anywhere in the trailer refuses the object; a decoder reads
  only inside the slice it is given and never panics.

The bootloader reads the kernel and the bundle whole into its own allocations before it uses them
([boot-flow.md](../core/boot/docs/boot-flow.md) § Step 2: Load Bootstrap Bundle and § Step 3: Load
Kernel ELF). It verifies the kernel before it validates the kernel's ELF header, and every bundle
entry before it parses `init` or exposes a module; any refusal is one terminal `BootError` naming
the object, which halts the boot.

procmgr copies every image into frames it allocates on the child's account before it verifies it,
from a file and from a Memory cap alike: a boot module's Memory cap carries full rights
([capability-model.md](capability-model.md) § Memory), so its holder can still write the frames,
and a file server can still write a cache page it lends procmgr. It reads the object once, the
length the creator gives, page by page from the file server's cache or whole from the Memory cap,
into frames only procmgr maps; verifies the copy; parses and loads only the body the verifier
returned; and returns the frames to memmgr once the segments are copied into the child, or into
its binary's image object
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Image Verification). Any
refusal is one reply, `SIGNATURE_REFUSED`, logged with the name and the verifier's reason, and
creates nothing.

A boot module keeps its trailer: `BootModule.size` is the length of the signed object, so procmgr
verifies an image created from a boot module as it does one read from a file. A consumer of a data
module the bootloader verified (the log-level configuration, the boot-time policy, or a platform
description table a bundle list names) takes the body through the codec's parse-only split, which
applies the parse checks of § Verification and no signature check; no loader uses it.

---

## Signature Policy in procmgr

procmgr requires a verified signature for every image it creates. procmgr's record of each creator
carries its signature policy, the set of roles its creates may load, and a create's object is
verified with that set as the roles it accepts. The un-badged creator (init, and svcmgr's mint
source) loads services, drivers and programs; the kernel and `init` are loaded by the bootloader
alone, the boot-module role is the bootloader's permission alone, and a data or configuration object
is never code.
So every process procmgr creates, from a bundle entry's Memory cap or from a file, is verified in
the role it runs in. A child takes its creator's set, narrowed to programs when its object's set
holds program: a program starts programs and nothing else, and no child holds more than its
creator.

Both creation labels carry the name the creator expects, in the canonical form of § Signed
Attributes, which procmgr checks before it reads the object: `CREATE_FROM_FILE` the install path of
the file, `CREATE_PROCESS` the install path the image was signed under (a bundle entry's name is
its install path). The creator chooses the name, so the check binds the object to what the creator
asked for: a creator can load only an object signed under the name it gives, in a role its own
policy admits. It cannot pass one object off as another, or start a role its policy does not hold,
whatever name it gives.

The override, a mark on a creator's record that would let it create from an image no record
verifies, is design intent, not yet implemented (§ Implementation Status). init, svcmgr and devmgr
never hold it: every service or driver they start is verified. In the default image no process
holds it. The boundary between system software, which is always verified, and user programs, which
a deployer may let run unverified, is therefore which creators hold the override: a capability, not
a mode or a mount. How a deployer grants the override, and changes the grant on a running system,
is decided with the authority work of [#152](https://github.com/kottlerg/seraph/issues/152) and the
package manager, and the record carries it from then.

Each create therefore costs one composite verification of its image, with the SHA-512 of the
image, and one more, of the signer's certificate, when procmgr's certificate cache
(`CERTIFICATE_CACHE_LEN`, 4, the oldest replaced first) does not hold it, or when another create's
write-back of the cache lost it ([`shared/objsig`](../shared/objsig/README.md)). A composite
verification is one Ed25519 verification and one ML-DSA-65 verification (§ Composite Signature
states their cost in the bootloader). On x86_64 under KVM they cost procmgr about what they cost
the bootloader: about 0.9 to 1.4 ms and 0.12 to 0.19 ms. On riscv64 under QEMU's TCG emulation
both are slower in procmgr than in the bootloader, at 4 vCPUs: the Ed25519 half about 50 to 70 ms
per verification in a debug build and 10 ms in a release build, against about 10 ms for the same
debug code built without the vector extension, and the ML-DSA-65 half about 1.4 ms in a debug
build and 3.9 ms in a release build. Userspace is built for
`xtask/targets/riscv64a23-seraph.json`, which enables the vector extension (`+v`), so LLVM
vectorizes the field multiplication, the conditional swap and the point addition of
[`shared/crypto`](../shared/crypto/README.md) with RVV instructions; the bootloader's target has
no vector extension, and its copy is scalar. TCG emulates each vector instruction element by
element through helper calls, so the vector code is the slower one there. The figures are the
emulator's: the code is the one the target's hardware runs, and no rule bounds the cost.

---

## Configuration

Implemented, apart from the local signer, which is design intent, not yet implemented.

**Policy-bearing files.** A file is policy-bearing when a process on the running system reads it
and acts on it with authority. Each is signed, and verified by its consumer before it parses it:

| Files | Consumer | Signed in |
|---|---|---|
| `/config/svcmgr/services/*.svc`, the service recipes | svcmgr, at handover | configuration, with the directory's index |
| `/config/devmgr/classes/*.class`, the device class files | svcmgr, at handover | configuration, with the directory's index |
| `/config/devmgr/platform/*.platform`, the platform description tables | devmgr | data (§ Verifier Discipline) |
| `/config/init/log-levels.conf`, the log-level configuration | init, from its boot module | configuration, verified by the bootloader (below) |
| `/config/boot/policy.conf`, the boot-time policy | devmgr, from its boot module | configuration, verified by the bootloader (below) |

No guest reads the other files under `config/`, so none is signed: the bundle lists, which xtask
reads when it packs, and the recipe and class sources of `/config/svcmgr/debug/`,
`/config/svcmgr/tests/` and `/config/devmgr/tests/`, which a pack that stages them copies into
the two indexed directories, where it signs them.

**Boot-time configuration.** A policy-bearing file read before the root filesystem is mounted
travels in the bundle: a file on the root filesystem is read through drivers its policy may govern.
The bootloader verifies a bundle entry whose name lies under `/config/`
(`boot_protocol::bundle::is_configuration`) in the configuration role, under its name, before it
exposes any module, so a key whose usage lacks the configuration role cannot sign one
(`Failed(KeyUsage)`). All boot-time policy is one file, `/config/boot/policy.conf`
(`boot_protocol::bundle::POLICY_ENTRY_NAME`), whose format and keys
[`shared/boot-policy`](../shared/boot-policy/README.md) defines; its one key is `dma-confinement`
([device-management.md](device-management.md) § DMA Safety Model). init forwards it to devmgr with
the other boot modules outside its bootstrap set, and devmgr reads it before the first driver
starts. The bundle container is not signed, so a requirement that held only while its file was
present would be turned off by deleting the entry. Every bundle therefore carries the policy, each
key at its default written out; the bootloader refuses a bundle with no policy entry or with two
(`BootError::InvalidBundle`); xtask refuses to pack a bundle without it, or with a policy
`boot-policy` refuses; and a consumer handed no policy, or one that does not parse, applies every
requirement. An older validly signed policy still verifies, as an older signed configuration file
does (§ Threat Model, Configuration removal, addition or mixing); a policy whose freshness a TPM
counter attests is [#1416](https://github.com/kottlerg/seraph/issues/1416).

**Directory index.** A per-file signature does not show that a file was removed: a consumer that
lists a directory starts a system without the recipe an attacker deleted. Each directory svcmgr
reads therefore holds a file `index` beside the files it names, signed in the configuration role
under `<directory>/index`: UTF-8 text, one line per file, each ending in `\n`: the file's name,
one space, and the 128 lowercase hex digits of the SHA-512 of its body, the file less its signature
trailer, so signing a file again leaves its line unchanged. The names are strictly ascending byte
for byte, each one path component in the canonical form of § Signed Attributes and none `index`
(`objsig::index`). An index naming no file is empty. The index binds the set of files the
directory held when it was signed and the body of each, so an older signed copy of one file under
the current index is refused. A whole older directory with its older index verifies (§ Threat
Model, Configuration removal, addition or mixing).

svcmgr reads the index through procmgr's verified read, then each file the index names, refuses a
body whose SHA-512 is not the one its line holds, and parses only the bodies it accepts. It
reports, and passes over, a named file that is missing, that procmgr refuses, or whose body does
not match its line, as it does a file that does not parse; it reports a file of the directory the
index does not name, and does not read it. When the index is missing or refused, svcmgr reads no
file of the directory: for `services/` it launches no service from a recipe, and reports each
service init registered as one without a definition, which it does not supervise; for `classes/`
it configures no device class. procmgr's refusal and svcmgr's report of each are logged lines on
the console ([svcmgr Service Definitions](../services/svcmgr/docs/service-definitions.md)
§ Reconciliation).

**Roles and anchors.** A consumer of configuration accepts a chain to any anchor whose usage holds
the configuration role, and no binary is accepted in it. An anchor's usage scopes it by role
(§ Trust Store), so a store can carry, beside the anchors of the system's software, an anchor
trusted for configuration alone, which signs configuration and no image. A record signed by a key
whose usage lacks the configuration role is refused for configuration (`Failed(KeyUsage)`), as a
record of a configuration-only key is for any image.

**Local signer.** Design intent, not yet implemented
([#1416](https://github.com/kottlerg/seraph/issues/1416)). Some configuration is per system, and
some is later edited on a running system by a user allowed to edit it. A signature defends against
an edit made from outside the running system (a powered-off disk, a side channel to the storage);
an edit from inside is userspace policy. Against a powered-off disk the local signing key MUST NOT
be readable from that disk: it is held outside the machine or sealed to the measured boot, and a
service of the running system signs an edit, and the directory's index, on behalf of a user allowed
to make it. The index is per directory, so a directory of per-system configuration is signed by a
local anchor trusted for configuration alone, and one of distributed configuration by the
distributor's key; a file needs no second signature. The local anchor is enrolled per machine by a
trust request (§ Trust Store).

---

## Signing

Implemented in xtask; the options are in
[xtask/README.md](../xtask/README.md#signing) § Signing.

**Keys.** Every builder generates a local root and a signing key on its first build, in a per-user
directory outside the work tree (`seraph/signing/ed25519-ml-dsa-65-roles-1-9` in the user's data
directory, or the directory `SERAPH_SIGNING_DIR` names); the root certifies the signing key for
every role, and the store lists the root with `LOCAL`, trusted for every role. The root's secret key
certifies the signing key once and is never written: the directory holds the signing key's secret,
its two seeds (§ Composite Signature), readable by its owner alone, its certificate, and the store
of the anchors it contributes. The default directory's last component names the signature algorithm
and the roles, 1 to 9, the key is certified for, so an identity of the earlier Ed25519 format, or
one certified before the configuration or the enrolment role existed, in the directory it used, is
never loaded;
xtask refuses a directory `SERAPH_SIGNING_DIR` names that holds one of another format, saying that
its format is the reason, and a signing key the build's trust store does not trust for every role,
naming the roles it lacks. xtask refuses a directory or a key file whose canonical path lies inside
the work tree, `target/` included. CI generates its keys per job in the runner's temporary directory
and discards them.

**External signer.** In place of a key file, xtask runs a configured signer command
(`SERAPH_SIGNER`): it receives the encoded signed attributes on its standard input and writes the
3,373-byte composite signature to its standard output, which is how a hardware token or a CI secret
signs. The identity directory then holds the signing key's certificate, or its public key when it is
a root, and the store, and no secret. xtask verifies every signed object under the trust store it
builds, with each of its roles, its name and the architecture its loaders expect, before it writes
it, so a faulty signer, or a store that does not trust the key, fails the pack instead of writing an
object its loader would refuse.

**Store and bootloader.** Each command derives the store from the signing identity and the
deployer's store its environment names. The bootloader's build embeds the store in the image's
read-only data, behind a 16-byte marker and the store's length (`objsig::embed`), the same layout on
a PE image and on a flat one. Every pack after that, the build's own included, reads the store out
of the installed bootloader (`/boot/boot.efi`, which the pack copies to `\EFI\seraph\boot.efi`
and to the removable-media fallback) and refuses to sign unless it holds exactly one marker and a
store equal to its own: a pack whose environment changed since the bootloader was built would
otherwise sign under a store that bootloader refuses.

**Implementation.** The host signer is Seraph's own: no crate from a registry is a dependency
([coding-standards.md](coding-standards.md) § Dependencies). Ed25519 key generation and signing
join verification in [`shared/crypto`](../shared/crypto/README.md), and ML-DSA-65's beside
them; `objsig::composite` composes them. xtask, the host caller, draws each half's 32-byte seed
from the host's operating-system random source and passes it in. For ML-DSA-65, `shared/crypto`
guarantees what its README states (the key from FIPS 204 Algorithm 6, the deterministic signature
of Algorithm 2, its timing). For Ed25519, `shared/crypto`, which does no I/O, guarantees:

- a public key is derived from its seed as RFC 8032 § 5.1.5 specifies;
- a signature is deterministic, as RFC 8032 § 5.1.6 specifies: one key and one message give one
  signature, whose S is below the group order L;
- no branch and no memory index depends on a secret value (the seed, the secret scalar, the nonce
  prefix, or the nonce), only on the message length and on public values;
- the primitive holds no key between calls: its caller passes the seed on every call;
- tests show that a key and a signature equal, byte for byte, the ones the testkit's OpenSSL
  reference vectors give for the same seed and message, and that every signature it makes verifies
  under `ed25519_verify`.

A deterministic signature keeps a build reproducible under one key: two builds of the same sources
with the same key produce the same image.

**What is signed.** xtask signs each object once, in the sysroot, under the roles and the name of §
Signed Attributes: the kernel, and every ELF image it installs under `services/`, `programs/` and
`tests/` ([build-system.md](build-system.md) § Build Output: the Sysroot). An image under a
`drivers/` directory is a driver, one under a `programs/` directory a program, and every other a
service; an image a bundle list names as an entry carries boot module beside that role. The kernel,
installed at `/boot/kernel`, is signed `kernel`, and `/services/init`, the object of the init
harness's `init` slot, `init`, each with its one role. `/tests/ktest`, the ktest harness's, is
signed `init` with the init role only in an image packed with the ktest harness's bundle, and in
every other image as the service its location makes it, so an image that does not boot the harness
carries no second object that boots as init. The configuration files a bundle list names (the
log-level configuration, `/config/init/log-levels.conf`, and the boot-time policy,
`/config/boot/policy.conf`) are installed files, each signed with the configuration role, in which
the bootloader verifies a bundle entry under `/config/` (§ Which Stage Verifies What), and their
readers take the body through the parse-only split (§ Verifier Discipline). A platform
table, installed at `/config/devmgr/platform/`, is signed with the data role alone, and procmgr
verifies it for devmgr before devmgr parses it (§ Which Stage Verifies What). Every regular file
under a data tree (`DATA_TREES` in `xtask/src/signing/mod.rs`: `/config/devmgr/platform/` and
`/data/svctest/signed/`, svctest's fixture of the verified read) is signed with the data role under
its install path, beside the role the bootloader verifies its bundle entry in when a bundle list
names it (configuration under `/config/`, boot module elsewhere). Every regular file of a
configuration directory (`CONFIG_TREES` in `xtask/src/signing/mod.rs`: `/config/svcmgr/services/`,
whose files are `.svc` recipes, and `/config/devmgr/classes/`, whose files are `.class` files) is
signed with the configuration role under its install path, and the pack writes the directory's index
from the files the directory then holds and their bodies, and signs it the same way
(§ Configuration); a subdirectory, or a file of another suffix, fails the pack. Every path that
stages a file into a configuration directory (`mkdisk --repack-only`, the debug stub, the harness
test cases) stages it before the pack, so the pack signs it and names it in the index. The ESP is
composed by copying installed files and signs nothing, so each object on it, each bundle entry
included, is its installed file byte for byte ([boot-media.md](boot-media.md) § The ESP). The
sysroot's objects are signed in place each time
a disk image is packed, before the pack composes the ESP, for the harness whose bundle it composes.
The refusal test's pack alone writes objects as it is given them, in place of the sysroot's files in
the images and never in the sysroot, so no later pack signs a tampered body. Signing replaces a
trailer the object already carries, and is deterministic, so re-signing an unchanged image writes
the same bytes. The other files under `config/` and `data/` carry no trailer, since no process reads
them as trusted input (§ Configuration), and neither does the bootloader, which Secure Boot covers
(§ Secure Boot). The security version is one integer in the tree (`SECURITY_VERSION` in
`xtask/src/signing/mod.rs`), raised by a security fix that MUST make older images unbootable; every
record carries it, and the store's floor is at least it. A machine that boots a bootloader with the
raised floor keeps it, and refuses every older bootloader from then on (§ Rollback Floor).

**The trust store** is built from public key files: by default the builder's local root. A build
option (`SERAPH_TRUST_STORE`) names a deployer's store, which is merged with the default or, as
`SERAPH_TRUST_STORE_MODE` chooses, replaces it; its floor is the higher of the stores' floors and
the tree's security version. xtask writes the store to `target/xtask/signing/trust-store` before
it builds the bootloader, which embeds it.

---

## Secure Boot

Firmware verifies the bootloader only when the platform enables UEFI Secure Boot. Secure Boot is
used when it is enabled and is never a default boot dependency
([platform-requirements.md](platform-requirements.md)): the chain from the bootloader onward does
not depend on it, and without it the chain is as strong as the ESP's integrity. Secure Boot is
also what makes the machine's security floor a boundary (§ Rollback Floor). The project ships no
shim and relies on no third-party certificate authority; a deployer remains free to boot through a
shim of their own.

**Signing.** The bootloader is Authenticode-signed with a key the deployer enrols in the
firmware's db. `cargo xtask build` signs the installed bootloader, `/boot/boot.efi`, in place
with the db key that `SERAPH_SECURE_BOOT_KEY` and `SERAPH_SECURE_BOOT_CERT` name, a PEM key and
its X.509 certificate set together, and checks the signature against the certificate before the
image is packed; both ESP copies are then the signed file
([xtask/README.md](../xtask/README.md#signing)). With neither set, the bootloader is not signed.
The signature is a PE Authenticode signature (`sbsign`) on both architectures, the hand-built
riscv64 PE included, which carries the certificate-table slot it needs. Until the project's db
certificate exists (§ Roots), every deployer signs with a key of their own.

**Enrolment.** The firmware verifies the bootloader against its db once its platform key (PK) is
enrolled; with no PK it is in setup mode and verifies nothing. A deployer enrols, through the
firmware's setup menu or an enrolment tool that runs in setup mode, a PK of their own, a key
exchange key (KEK) the PK signs, and the certificate the bootloader is signed with in db. Keys
already in db, a vendor's or the Microsoft UEFI CA, may stay beside it; the project needs none of
them. Each key is RSA-2048 with SHA-256, the form every UEFI implementation takes. Secure Boot is
then turned on in the firmware's setup, which with a PK enrolled refuses every image db does not
admit, a tampered bootloader among them.

**State.** The bootloader reads the firmware's `SecureBoot` and `SetupMode` variables, under the
global GUID, and logs the state on every boot: `on`, `off` with its reason (the firmware does
not implement Secure Boot, setup mode, or keys enrolled with verification off), or `unknown` for
a `SecureBoot` of another shape. A variable that is not exactly one byte of 0 or 1 with the
boot-services and runtime attributes is not the firmware's, and never reads as `on`: with
`SecureBoot` at 0, a `SetupMode` of another shape, or none, reads as `off` with that as its
reason. No state stops the boot: that Secure Boot is on is reported, not required. A system's
signed configuration may require it (design intent;
[#1416](https://github.com/kottlerg/seraph/issues/1416)).

**Testing.** `cargo xtask test secureboot` signs the bootloader with development keys, enrols
them in a variable store, and checks that the firmware boots the signed bootloader and refuses it
tampered or unsigned, on both architectures ([testing.md](testing.md) § Gating, Secure Boot).

---

## Roots

The project holds no trust root until a central repository exists. Every builder, the project's own
release build included, signs with a locally generated root, and an image is verified against the
root of the build that made it; the bootloader labels that root as locally generated on every boot.
A release image therefore carries no provenance a user can check beyond the release's
`SHA256SUMS`.

The project root and release signing are [#1073](https://github.com/kottlerg/seraph/issues/1073).
When the root is created, its key is held offline by the maintainer and certifies one release
signing key per minor-version line, held only as a secret of a protected CI environment whose every
run the maintainer approves. A system that trusts the project root may trust other roots beside it,
or none but its own: an object signed by both carries both records, and each system accepts the one
it trusts. On-box key enrolment for self-hosted builds is
[#1072](https://github.com/kottlerg/seraph/issues/1072).

---

## Summarized By

[Boot Media](boot-media.md), [System Bootstrap](bootstrap.md),
[shared/objsig/README.md](../shared/objsig/README.md)
