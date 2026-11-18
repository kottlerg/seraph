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
- Where keys live, how objects are signed, and what the trust store holds.

The cryptographic primitives (SHA-512, Ed25519 verification, key generation and signing) are
specified in [shared/crypto/README.md](../shared/crypto/README.md). The bootloader's boot steps are
specified in
[core/boot/docs/boot-flow.md](../core/boot/docs/boot-flow.md), procmgr's creation interface in
[services/procmgr/docs/ipc-interface.md](../services/procmgr/docs/ipc-interface.md), and the
platform's firmware baseline in [platform-requirements.md](platform-requirements.md).

---

## Implementation Status

The primitives exist: [`shared/crypto`](../shared/crypto/README.md) provides `ed25519_verify` and
`Sha512`, tested against known-answer vectors, Wycheproof, and reference vectors computed with
OpenSSL, and, behind its `sign` feature, the key generation and signing that § Signing requires of
it (`ed25519_public_key`, `ed25519_sign`), tested against the same reference vectors and the
verifier; xtask, the host signer, enables the feature, and core/boot enables it as a dev-dependency
only, since its host tests sign fixtures. The formats of § Signed Object Format, § Certificate
Format and § Trust Store, and the verification of § Verification, are implemented and host-tested,
apart from what the next paragraph names, in [`shared/objsig`](../shared/objsig/README.md), which
xtask and the bootloader link. xtask's keys and signing of § Signing are implemented: every build
signs the kernel, every bundle entry and every ELF image of the root filesystem, builds the trust
store at the path § Signing names, and embeds it in the bootloader. The bootloader verifies the
kernel and every bundle entry against that store and hands the store to procmgr (§ Trust Store),
which parses it and keeps it. procmgr verifies every image it creates against that store before it
parses it (§ Verifier Discipline), under its creator's signature policy and the name the creator
gives (§ Signature Policy in procmgr). The override that § Signature Policy in procmgr describes is
design intent, not yet implemented: no creator can hold it, so procmgr creates no process from an
image that does not verify. `cargo xtask test-signing` boots each refusal on both architectures: a
tampered kernel, a tampered bundle entry and a revoked signing key in the bootloader, and a tampered
service, one signed under the wrong kind and one signed by an untrusted key in procmgr, beside a
kernel and a program whose untrusted record both verifiers skip ([testing.md](testing.md) § Gating,
Signature refusals).

The role set and the names of § Signed Attributes, their checks in § Verification and § Signature
Policy in procmgr, and the copied bundle entries of § Signing are design intent, not yet implemented
([#1263](https://github.com/kottlerg/seraph/issues/1263); the bundle list and the installed data
entries, [#1264](https://github.com/kottlerg/seraph/issues/1264)). The code encodes each record's
attributes under the domain tag `seraph/obj/v1` with one `kind` in place of the role set (byte 28
holds the role's value, 1 to 7, not its bit), names a bundle entry by a short entry name (`devmgr`),
signs the bundle's copy of an installed image again as a boot module under that name, and gives
procmgr's creators the boot-module kind. [boot-media.md](boot-media.md) states why one object
carries one signature.

---

## Principles

Implemented, apart from the override of the third principle, which is design intent, not yet
implemented (§ Signature Policy in procmgr).

- **Verify at the loader.** An object is verified by the stage that turns its bytes into running
  code or into input that code trusts: the bootloader for what it loads, procmgr for every image it
  creates. procmgr is the only runtime loader
  ([process-lifecycle.md](process-lifecycle.md) § Steady-State Process Creation), so it is the only
  runtime verifier.
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
| **Object swap.** Put one legitimately signed object where another is expected (a signed program in place of a service, `fatfs` in place of `procmgr`). | The signed attributes carry the object's roles and name; the verifier requires a role its caller accepts and the name it is loading. | None. |
| **Replay.** Replace an object with an older, legitimately signed one that has a known vulnerability. | The signed attributes carry a security version; the trust store sets a floor, a key's certificate bounds the versions it may sign, and a compromised key is revoked. | A whole older image, bootloader included, boots: its trust store holds the older floor. Persistent anti-rollback is [#1070](https://github.com/kottlerg/seraph/issues/1070). |
| **Key compromise.** Steal a signing key. | A key signs only the object roles and security versions its certificate names; the chain is at most two keys deep; a revoked key id is refused. | Revocation reaches only systems whose bootloader carries the updated trust store. A locally generated root's compromise is its builder's own risk. |
| **Verifier bypass.** Reach a path that loads without verifying, or that continues after a failed check. | Every check has one exit on failure and no fallback; the verifier returns the body only on success, and loaders read only what it returns. | None. |
| **Carrier confusion.** Duplicate, nested, truncated or malformed trailers, or bytes after the trailer. | The footer and every record parse strictly; any parse error rejects the whole object; a body that itself ends in a trailer is rejected. | None. |
| **TOCTOU.** Change the bytes between verification and use. | The verifier reads the object once into memory no other process can write, verifies that copy, and the loader parses and loads only from it. | None. |
| **Trust-store substitution.** Replace the roots the system trusts. | The trust store is built into the bootloader; replacing it means replacing the bootloader. | Without Secure Boot, an attacker who can write the ESP replaces the bootloader and its roots: the chain is as strong as the ESP's integrity (§ Secure Boot). |
| **Unsigned configuration.** Change a configuration file (`/config/svcmgr/services/*.svc`) that decides what runs. | Not defended. | Configuration is not signed; [#1071](https://github.com/kottlerg/seraph/issues/1071) covers it. |

---

## Which Stage Verifies What

| Object | Verified by | Against | Expected role and name |
|---|---|---|---|
| Bootloader (PE) | Firmware, when Secure Boot is enabled | The firmware's db (§ Secure Boot) | Not applicable |
| Kernel (`\EFI\seraph\kernel`) | Bootloader | The trust store built into it | kernel, `kernel` |
| The bundle entry `init` | Bootloader | The same store | init, `init` |
| Every other bundle entry | Bootloader | The same store | boot module, its entry name: the object's install path |
| (nothing) | Kernel | Not applicable | Not applicable |
| memmgr, procmgr | init loads them from boot modules the bootloader verified | Nothing further | Not applicable |
| Every image procmgr creates, from a file or a Memory cap | procmgr | The store the bootloader hands forward | The roles the creator's policy allows; the name the creator gives, an install path |

The bundle container itself is not signed: the bootloader parses its header with the bounds-checking
parser of [`abi/boot-protocol::bundle`](../abi/boot-protocol/src/bundle.rs) and verifies each entry
under its entry name before it uses the entry. An entry other than `init` is named by its object's
install path, which the entry-name field holds whole, up to `objsig::NAME_MAX` (256 bytes) like any
signed name ([limits.md](limits.md) § Bootloader and boot ABIs), and the bootloader refuses any
other entry name. An attacker who edits the header can drop an entry, which fails the boot when the
entry is needed, or rename one, which its signed name refuses.

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
| 6 | 2 | `version`: 1 |
| 8 | 8 | magic `SERAPHSG` |

`MAX_RECORDS` bounds the work a verifier does for one object, since every record that chains to a
trusted root costs up to two signature verifications.

### Record

`record_count` records lie back to back in the record block, which ends where the footer begins:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | `record_len`: the record's length in bytes, this field included |
| 4 | 1 | `algorithm`: 1 = Ed25519 |
| 5 | 1 | `cert_count`: 0 or 1 |
| 6 | 2 | `attrs_len`: the length of the signed attributes |
| 8 | 16 | `signer_key_id`: the key id of the key that made `signature` |
| 24 | `attrs_len` | The signed attributes |
| 24 + `attrs_len` | 148 × `cert_count` | The certificate of the signing key, when it is not a root |
| `record_len` − 64 | 64 | `signature`: Ed25519 (RFC 8032, pure) over the signed attributes |

`record_len` is exactly 88 + `attrs_len` + 148 × `cert_count`, and the records' lengths add up
exactly to `records_len`.

A key id is the first 16 bytes of the SHA-512 of the key's 32-byte Ed25519 public key. It is always
computed from a key and never taken from the wire as the identity of one: a record's
`signer_key_id` selects a key, and the verifier checks that the key it selected has that id.

### Signed Attributes

The signature covers the encoded attributes and nothing else:

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | Domain tag: `seraph/obj/v2` padded with NUL bytes to 16 |
| 16 | 8 | `body_len`: the body's length in bytes |
| 24 | 4 | `security_version` |
| 28 | 1 | `roles`: the set of roles the object may be loaded in (below) |
| 29 | 1 | `arch`: 1 = x86-64, 2 = riscv64 |
| 30 | 2 | `name_len`: 1 or more |
| 32 | 64 | `body_hash`: the SHA-512 of the body |
| 96 | `name_len` | `name` |

`attrs_len` is exactly 96 + `name_len`. The domain tag keeps an object signature from ever being
read as a certificate signature, whose signed bytes begin with another tag, and names the
attributes' version: a record whose attributes carry the tag of another version does not parse,
so a single kind of an older encoding is never read as a set.

An object has one identity: one record per signer states every role it may be loaded in, under
one name. `roles` has bit `n` set for each role `n` of the table below, the bits a certificate's
`usage` uses for the same roles (§ Certificate Format). Bit 0 is zero, at least one bit is set,
and a set that holds kernel or init holds no other role.

| Role `n` | Name | Objects |
|---|---|---|
| 1 | kernel | The kernel image |
| 2 | init | The object of the bundle's `init` slot (init, or a harness such as ktest in it) |
| 3 | boot module | An object the bootloader may load as a bundle entry other than `init`, whatever its content |
| 4 | service | A service image |
| 5 | driver | A driver image |
| 6 | program | A program image |
| 7 | data | A data file (no verifier reads this role yet) |

A role is a permission the signer grants, not a place: an installed service the bootstrap needs
carries service and boot module, and the bundle's copy of it is the same bytes.

The `name` is `kernel` for a set holding kernel, `init` for a set holding init, and for every
other object its install path from the root of the root filesystem (`/services/svcmgr`),
wherever the object lies, a bundle entry's included. Names are compared byte for byte, so each has
one canonical form, in which the signer signs it and procmgr requires a creator to give it: 1 to
256 bytes of UTF-8, and either one of the two slot names or `/` followed by components separated
by single `/` (an install path), each component nonempty, holding no `/` and no NUL, and neither
`.` nor `..`. `objsig::name_is_canonical` is the one check of it, which xtask's signer and
procmgr both call; procmgr accepts an install path alone. The comparison is case-exact: the root
filesystem resolves names without regard to letter case, so a path spelled in another case
reaches the same file, but no signature names that spelling, and procmgr refuses the object
under it. A creator names an object by its install path as xtask installs it.

### Hashed Bytes

The hash covers exactly the body: bytes `[0, len − 16 − records_len)` of the object, where `len`
is the object's length. The signed `body_len` MUST equal that length. Nothing else is hashed and
nothing is skipped, so the canonical form needs no knowledge of the body's format.

---

## Certificate Format

Implemented by [`shared/objsig`](../shared/objsig/README.md), which xtask links to sign and the
bootloader to verify.

Seraph's certificate is a fixed 148-byte record, not X.509: no ASN.1 parser enters the bootloader,
and Ed25519 is the only algorithm. A root (an anchor of the trust store) issues it to a signing key:

| Offset | Size | Field |
|---|---|---|
| 0 | 16 | Domain tag: `seraph/cert/v1` padded with NUL bytes to 16 |
| 16 | 32 | `subject_key`: the signing key's Ed25519 public key |
| 48 | 16 | `issuer_key_id`: the key id of the root that issued it |
| 64 | 8 | `serial` |
| 72 | 4 | `usage` (below) |
| 76 | 4 | `min_security_version` |
| 80 | 4 | `max_security_version`, at least `min_security_version` |
| 84 | 64 | `signature`: Ed25519 by the issuer over bytes 0 to 83 |

The `usage` mask has bit `n` set for each role `n` the key may sign (bits 1 to 7) and bit 31,
`CERTIFY`, set when the key may issue certificates. Every other bit is zero. A certificate's
`CERTIFY` bit is clear: the chain is at most two keys deep (a root, a signing key, the object), so
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
| 8 | 2 | `version`: 1 |
| 10 | 2 | `anchor_count`: 1 or more |
| 12 | 2 | `revoked_count` |
| 14 | 4 | `security_floor` |
| 18 | 72 × `anchor_count` | The anchors |
| 18 + 72 × `anchor_count` | 16 × `revoked_count` | The revoked key ids |

An anchor is 72 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | `key`: the root's Ed25519 public key |
| 32 | 4 | `usage`: as a certificate's, `CERTIFY` allowed |
| 36 | 4 | `flags`: bit 0, `LOCAL`, marks a root generated on the build machine; every other bit is zero |
| 40 | 32 | `label`: a nonempty UTF-8 name, padded with NUL bytes |

The anchors are sorted by key id, strictly ascending, so no two share one and a lookup is a binary
search; the revoked key ids are sorted the same way. The blob's length is exactly the sum of its
parts. A store that breaks any rule of this section is refused whole.

**Where it lives.** The store is built into the bootloader, which firmware Secure Boot covers on a
platform that enables it. There is one copy: no Seraph variable in firmware storage, and no copy
built into procmgr, which would drift from the bootloader's. A deployer replaces or extends the
store by building the bootloader with their own (§ Signing). Enrolment and rotation of roots
without a rebuild are [#1074](https://github.com/kottlerg/seraph/issues/1074).

**Hand-off.** The bootloader copies the store into a page allocation of its own and exposes it as
the last boot module of `BootInfo.modules`, named `trust-store`, a name it refuses on a bundle
entry. The kernel mints its Memory cap as for any boot module, and init passes that cap to procmgr
alone, in procmgr's bootstrap. procmgr copies the store into its own memory and parses it once at
startup; a store that is missing, or that procmgr cannot parse, stops procmgr, which then creates
no process.

**On every boot** the bootloader logs each anchor's label and key id, and marks an anchor with
`LOCAL` as locally generated.

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
   `algorithm` is 1, its attributes carry their domain tag, a `roles` set that obeys § Signed
   Attributes and a defined `arch` value, its certificate (when present) carries its domain tag, a
   clear `CERTIFY` bit, no undefined usage bit and a range whose maximum is at least its minimum,
   and the records fill the record block exactly. A body whose last 8 bytes are the footer magic is
   a nested trailer. Any of these errors refuses the object, whatever the other records hold.
3. **Hash.** The verifier computes the SHA-512 of the body once.
4. **Records in order.** The object passes on the first record that passes every check below. A
   record passes when:
   - its signing key chains to an anchor: with no certificate, `signer_key_id` is an anchor's key
     id and the anchor is the signing key; with a certificate, `issuer_key_id` is an anchor's key
     id, that anchor's `usage` has `CERTIFY`, the certificate's signature verifies under the
     anchor's key, and `signer_key_id` is the key id of `subject_key`;
   - neither the anchor's key id nor the signing key's is revoked;
   - every role of `roles` is in the signing key's usage (with a certificate, in both the
     certificate's and the anchor's), and `roles` holds a role of the caller's set;
   - `name` and `arch` equal the caller's;
   - `body_len` and `body_hash` equal the body's length and hash;
   - `security_version` is at least the store's floor and, with a certificate, inside the
     certificate's range;
   - `signature` verifies under the signing key with
     [`ed25519_verify`](../shared/crypto/README.md).
5. **Refusal.** When no record passes, the object is refused. The refusal says whether any record
   named an anchor (by `signer_key_id` without a certificate, by the certificate's
   `issuer_key_id` with one) and, when one did, the check the first such record failed, so a log
   tells an object from an untrusted root from one whose trusted record failed.

A verifier that checks several objects MAY hold each certificate whose signature has verified,
with the anchor key it verified under, and take the signature check of a record whose
certificate and anchor key equal a held pair as passed. The check is a function of those bytes
alone, so the result is the one a fresh verification gives, and every other check of step 4 is
made for every record. The bootloader holds the certificates for the whole boot, so the
certificate every object of one signing key carries is verified once.

A record that chains to no anchor is how one object carries the signatures of several parties:
each system passes over the records of roots it does not trust and accepts the object on the one
it does.

---

## Verifier Discipline

The bootloader and procmgr follow it.

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
returned; and returns the frames to memmgr once the segments are copied into the child
([procmgr IPC Interface](../services/procmgr/docs/ipc-interface.md) § Image Verification). Any
refusal is one reply, `SIGNATURE_REFUSED`, logged with the name and the verifier's reason, and
creates nothing.

A boot module keeps its trailer: `BootModule.size` is the length of the signed object, so procmgr
verifies an image created from a boot module as it does one read from a file. A consumer of a data
module the bootloader verified (the log-level configuration, a platform description table) takes
the body through the codec's parse-only split, which applies the parse checks of § Verification and
no signature check; no loader uses it.

---

## Signature Policy in procmgr

procmgr requires a verified signature for every image it creates. procmgr's record of each creator
carries its signature policy, the set of roles its creates may load, and a create's object is
verified with that set as the roles it accepts. The un-badged creator (init, and svcmgr's mint
source) loads services, drivers and programs; the kernel and `init` are loaded by the bootloader
alone, the boot-module role is the bootloader's permission alone, and a data object is never code.
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

---

## Signing

Implemented in xtask; the options are in
[xtask/README.md](../xtask/README.md#signing) § Signing.

**Keys.** Every builder generates a local root and a signing key on its first build, in a per-user
directory outside the work tree (`seraph/signing` in the user's data directory, or the directory
`SERAPH_SIGNING_DIR` names); the root certifies the signing key, and the store lists the root
with `LOCAL`. The root's secret key certifies the signing key once and is never written: the
directory holds the signing key's secret seed, readable by its owner alone, its certificate, and
the store of the anchors it contributes. xtask refuses a directory or a key file whose canonical
path lies inside the work tree, `target/` included. CI generates its keys per job in the runner's
temporary directory and discards them.

**External signer.** In place of a key file, xtask runs a configured signer command
(`SERAPH_SIGNER`): it receives the encoded signed attributes on its standard input and writes the
64-byte signature to its standard output, which is how a hardware token or a CI secret signs. The
identity directory then holds the signing key's certificate, or its public key when it is a root,
and the store, and no secret. xtask verifies every signed object under the trust store it builds,
with each of its roles, its name and the architecture its loaders expect, before it writes it, so a
faulty signer, or a store that does not trust the key, fails the pack instead of writing an object
its loader would refuse.

**Store and bootloader.** Each command derives the store from the signing identity and the
deployer's store its environment names. The bootloader's build embeds the store in the image's
read-only data, behind a 16-byte marker and the store's length (`objsig::embed`), the same layout on
a PE image and on a flat one. Every pack after that, the build's own included, reads the store out
of each installed bootloader image (the one at `\EFI\seraph\` and the removable-media fallback) and
refuses to sign unless both hold exactly one marker and a store equal to its own: a pack whose
environment changed since the bootloader was built would otherwise sign under a store that
bootloader refuses.

**Implementation.** The host signer is Seraph's own: no crate from a registry is a dependency
([coding-standards.md](coding-standards.md) § Dependencies). Ed25519 key generation and signing
join verification in [`shared/crypto`](../shared/crypto/README.md). xtask, the host caller, draws
each key's 32-byte secret seed from the host's operating-system random source and passes it in;
`shared/crypto`, which does no I/O, guarantees:

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

**What is signed.** xtask signs each object once, in the sysroot, under the roles and the name of
§ Signed Attributes: the kernel, and every ELF image it installs under `services/`, `programs/` and
`tests/` ([build-system.md](build-system.md) § Build Output: the Sysroot). An image under a
`drivers/` directory is a driver, one under a `programs/` directory a program, and every other a
service; an image the bundle list names carries boot module beside that role. The kernel is
signed `kernel`, and the object of the bundle's `init` slot (`/services/init`, or `/tests/ktest`
for the ktest harness) `init`, each with its one role. The bundle's data entries (the platform
tables and the log-level configuration) are installed files signed with the boot-module role, and
their readers take the body through the parse-only split (§ Verifier Discipline). The bundle is
composed by copying installed files and signs nothing, so each entry is its installed file byte
for byte ([boot-media.md](boot-media.md) § The ESP). The sysroot's objects are signed in place
each time a disk image is packed. The refusal test's pack alone writes objects as it is given
them, in place of the sysroot's files in the images and never in the sysroot, so no later pack
signs a tampered body. Signing replaces a trailer the object already carries, and is
deterministic, so re-signing an unchanged image writes the same bytes. The files under `config/`
and `data/` carry no trailer, since their readers take each file whole and configuration is not
signed (§ Threat Model), and neither does the bootloader, which Secure Boot covers (§ Secure
Boot). Role 7 is reserved for a data file whose reader verifies it. The security version is one
integer in the tree (`SECURITY_VERSION` in `xtask/src/signing/mod.rs`), raised by a security fix
that MUST make older images unbootable; every record carries it, and the store's floor is at least
it.

**The trust store** is built from public key files: by default the builder's local root. A build
option (`SERAPH_TRUST_STORE`) names a deployer's store, which is merged with the default or, as
`SERAPH_TRUST_STORE_MODE` chooses, replaces it; its floor is the higher of the stores' floors and
the tree's security version. xtask writes the store to `target/xtask/signing/trust-store` before
it builds the bootloader, which embeds it.

---

## Secure Boot

Firmware verifies the bootloader only when the platform enables UEFI Secure Boot. Secure Boot is
preferred and never required: [platform-requirements.md](platform-requirements.md) lists it as no
boot dependency, and the chain from the bootloader onward does not depend on it. Without it, the
chain is as strong as the ESP's integrity. The project ships no shim and relies on no third-party
certificate authority; a deployer remains free to boot through a shim of their own. The preferred
path is a bootloader Authenticode-signed with a key the deployer enrols in the firmware's db
(design intent; not yet implemented, [#1075](https://github.com/kottlerg/seraph/issues/1075)).

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
it trusts. A move to a post-quantum scheme through the record's `algorithm` field is
[#1076](https://github.com/kottlerg/seraph/issues/1076); on-box key enrolment for self-hosted builds
is [#1072](https://github.com/kottlerg/seraph/issues/1072).

---

## Summarized By

[Boot Media](boot-media.md), [System Bootstrap](bootstrap.md),
[shared/objsig/README.md](../shared/objsig/README.md)
