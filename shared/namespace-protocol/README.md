# namespace-protocol

Wire-format specification, name validation, rights composition, and IPC
dispatch loop shared by every Seraph namespace server. Filesystem
drivers (`fs/fat`, future `fs/ext4`, future `tmpfs`) and composing
servers (`vfsd`'s synthetic root) embed this crate; they implement
[`NamespaceBackend`] for their storage layer and the crate owns every
security-relevant code path.

---

## Authority

This crate is authoritative for the **wire format and dispatch
semantics** of the `NS_*` namespace protocol — labels, request and
reply layouts, error codes, name rules, token shape, and rights
composition.

The high-level capability model (cap-as-namespace, sandboxing,
visibility filtering as policy) is authoritatively specified in
[`docs/namespace-model.md`](../../docs/namespace-model.md). This
README implements it.

---

## Wire labels

All requests and replies follow the [`ipc::IpcMessage`] shape: a 64-bit
label, an inline data buffer of up to 64 `u64` words, and up to four
capability slots. Numeric label values live in [`ipc::ns_labels`] in
`shared/ipc`.

| Opcode | Label | Direction | Purpose |
|---:|---|---|---|
| 20 | `NS_LOOKUP` | client → server | Walk one path component within a directory cap |
| 21 | `NS_STAT` | client → server | Attribute snapshot for the addressed node |
| 22 | `NS_READDIR` | client → server | Enumerate one entry of a directory by index |

The label's low 16 bits carry the opcode; the high 16 bits carry an
opcode-defined header (today: name length for `NS_LOOKUP`).

Error replies use the matching [`NsError`] discriminant value as the
reply label; success replies use label `0`.

---

## Token shape

Every node capability is a tokened SEND on a server's namespace
endpoint. The token is opaque to the kernel; servers decode it on
every request. Layout (low-to-high):

| Bits | Field | Meaning |
|---:|---|---|
| 0..40 | `node_id` | Server-private inode identifier ([`NodeId`]) |
| 40..64 | `rights` | 24-bit [`NamespaceRights`] mask |

`node_id == 0` is conventionally the server's root directory. [`pack`]
and [`unpack`] are the canonical conversions. Backends that need more
than 2^40 distinct nodes per server lifetime MUST split into multiple
servers; the protocol does not provide token expansion.

---

## NS_LOOKUP

Walk one component within the directory addressed by the caller's
token.

**Request**

| Field | Value |
|---|---|
| `label` low 16 bits | `20` |
| `label` high 16 bits | `name_len` (1..=255) |
| `data[0]` | Caller-requested rights (low 24 bits; sentinel `0xFFFF` requests "everything I am allowed") |
| `data[1..]` | Name bytes packed little-endian, `name_len` bytes total |
| `caps` | empty |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | Entry kind: `0 = File`, `1 = Dir` |
| `data[1]` | Cached size hint in bytes (zero for directories) |
| `caps[0]` | Tokened SEND on the owning server's namespace endpoint |

**Reply (error)** — label is the matching [`NsError`] code (no caps).

The server MUST:

1. Reject with `PermissionDenied` if the caller's token lacks the
   `LOOKUP` rights bit.
2. Reject with `InvalidName` if the requested name fails
   [`validate_name`].
3. Resolve `(parent_node, name)` via [`NamespaceBackend::lookup`].
4. Reject with `NotFound` for hidden entries per the rule
   `parent_rights & entry.visible_requires == entry.visible_requires`.
   Hidden and absent MUST be indistinguishable to the caller.
5. Compute returned rights as
   `parent_rights ∩ entry.max_rights ∩ caller_requested`.
6. Mint the child cap from the server's namespace endpoint via
   `cap_derive_token` for [`EntryTarget::Local`], or via `cap_derive`
   of a stored cap for [`EntryTarget::External`] (mount points and
   other cross-server entries).

The dispatch crate's [`dispatch_request`] enforces all of the above;
backends own only the storage lookup.

---

## NS_STAT

Attribute snapshot for the node addressed by the caller's token.

**Request**

| Field | Value |
|---|---|
| `label` | `21` |
| body | empty |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | Size in bytes |
| `data[1]` | `mtime_us` (best-effort; zero on backends that do not track) |
| `data[2]` | Kind: `0 = File`, `1 = Dir` |

**Reply (error)** — label is the matching [`NsError`] code.

The server MUST reject with `PermissionDenied` if the caller's token
lacks the `STAT` rights bit.

---

## NS_READDIR

Enumerate one directory entry by zero-based index. Clients iterate by
incrementing the index until the reply label is `END_OF_DIR`. Hidden
entries (per the visibility rule above) MUST be skipped without
contributing to the index.

**Request**

| Field | Value |
|---|---|
| `label` | `22` |
| `data[0]` | Zero-based entry index |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | Kind: `0 = File`, `1 = Dir` |
| `data[1]` | Name length in bytes |
| `data[2..]` | Name bytes packed little-endian |

**Reply (end of directory)** — `label == ipc::fs_labels::END_OF_DIR`
(value `6`), empty body. The label is shared with the surviving
fs-driver surface to keep one end-of-iteration sentinel across the
two protocols.

**Reply (error)** — label is the matching [`NsError`] code.

The server MUST reject with `PermissionDenied` if the caller's token
lacks the `READDIR` rights bit.

`NS_READDIR` returns names only; clients follow up with `NS_LOOKUP`
to obtain a node cap for an entry of interest.

---

## Names

A name accepted by `NS_LOOKUP` MUST satisfy [`validate_name`]:

- UTF-8 encoded.
- Length 1..=255 bytes ([`MAX_NAME_LEN`]).
- MUST NOT contain `/` (0x2F) or `\0` (0x00).
- MUST NOT be `.` or `..`.

Path resolution is client-side: a multi-component name is one
`NS_LOOKUP` per component against the cap returned by the previous
step. There is no `..` operation; walking up requires a separately-
held parent cap.

Backends MAY further restrict (reserved words, on-disk encoding
limits, case-sensitivity rules); such restrictions surface as
`NotFound` or `InvalidName` from the backend's `lookup` method.

---

## Rights

Namespace rights are a 24-bit mask packed in token bits 40..64. Eight
bits are defined; sixteen are reserved.

| Bit | Constant | Meaning |
|---:|---|---|
| 0 | `LOOKUP` | `NS_LOOKUP` into this directory |
| 1 | `READDIR` | `NS_READDIR` enumeration |
| 2 | `STAT` | `NS_STAT` |
| 3 | `READ` | `NS_READ` / `NS_READ_FRAME` (file) |
| 4 | `WRITE` | `NS_WRITE` (deferred; reserved) |
| 5 | `EXEC` | File is executable; consumed by ELF loaders |
| 6 | `MUTATE_DIR` | `NS_CREATE` / `NS_UNLINK` (deferred; reserved) |
| 7 | `ADMIN` | Visibility-gating bit |
| 8..23 | — | Reserved; MUST be zero on derive, ignored on read |

Every node cap is a `SEND` cap from the kernel's perspective; the
rights mask above is opaque to the kernel and inspected only by the
server. Rights MUST narrow on every walk; the dispatch crate enforces
this through the intersection at step 5 of `NS_LOOKUP`.

---

## Errors

[`NsError`] discriminants are stable wire codes:

| Code | Variant | Meaning |
|---:|---|---|
| 1 | `NotFound` | Name absent or hidden by visibility |
| 2 | `PermissionDenied` | Caller's token lacks the required right |
| 3 | `NotADirectory` | Operation requires a directory; node is a file |
| 4 | `IsADirectory` | Operation requires a file; node is a directory |
| 5 | `InvalidName` | Name failed [`validate_name`] |
| 6 | `InvalidOffset` | Read past EOF |
| 7 | `InvalidFrameCap` | `NS_READ_FRAME` reply target frame-cap shape wrong |
| 8 | `InvalidCookie` | Frame-cap cookie zero or duplicate |
| 9 | `Evicted` | Frame referenced by a held cookie has been evicted |
| 10 | `IoError` | Backend storage failed |
| 11 | `NotSupported` | Operation not implemented on this server |
| 12 | `OutOfResources` | Server resource exhaustion |

Reordering or renumbering breaks the wire contract. The crate's
`tests::error_codes_match_protocol_specification` test guards against
accidental edits.

---

## Backend trait

Servers implement [`NamespaceBackend`] over their storage layer. The
trait's methods are called by [`dispatch_request`] after the crate
has performed name validation, rights composition, and visibility
filtering — backends never re-implement those checks.

| Method | Called from |
|---|---|
| `lookup` | `NS_LOOKUP` |
| `readdir_entry` | `NS_READDIR` |
| `stat` | `NS_STAT` |
| `read_inline` | future `NS_READ` |
| `read_frame` | future `NS_READ_FRAME` |
| `release_frame` | future `NS_RELEASE_FRAME` |
| `close` | future `NS_CLOSE` (best-effort cleanup hint) |

Frame-cap reads continue to use the [`ipc::fs_labels::FS_READ_FRAME`]
surface today; they are documented in
[`services/fs/docs/fs-driver-protocol.md`](../../services/fs/docs/fs-driver-protocol.md).
Migration of the read surface to `NS_*` labels is a follow-up phase.

---

## Composing servers

A server MAY return entries whose target is a node cap on a different
server's namespace endpoint ([`EntryTarget::External`]). `NS_LOOKUP`
hands such a cap to the caller verbatim (with rights intersected) and
subsequent operations bypass the composing server. This is how
filesystem mounting works:
[`services/vfsd/docs/namespace-composition.md`](../../services/vfsd/docs/namespace-composition.md)
describes vfsd's synthetic-root composition in detail.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/namespace-model.md](../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing, visibility |
| [docs/capability-model.md](../../docs/capability-model.md) | Token semantics, derivation tree |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC message format |
| [services/fs/docs/fs-driver-protocol.md](../../services/fs/docs/fs-driver-protocol.md) | Surviving fs-driver-specific labels |
| [services/vfsd/docs/namespace-composition.md](../../services/vfsd/docs/namespace-composition.md) | vfsd's synthetic root and root-mount delegation |

---

## Summarized By

[shared/README.md](../README.md), [services/vfsd/README.md](../../services/vfsd/README.md), [services/fs/README.md](../../services/fs/README.md), [services/fs/docs/fs-driver-protocol.md](../../services/fs/docs/fs-driver-protocol.md), [services/vfsd/docs/namespace-composition.md](../../services/vfsd/docs/namespace-composition.md), [services/vfsd/docs/vfs-ipc-interface.md](../../services/vfsd/docs/vfs-ipc-interface.md)
