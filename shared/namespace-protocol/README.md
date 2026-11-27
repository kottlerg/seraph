# namespace-protocol

Wire-format specification, name validation, rights composition, and
per-request dispatch (`dispatch_request`) that every Seraph namespace
server calls from its own receive loop.

The request and reply decoders read hostile input, so they carry the parser rule's property and
its three drivers ([docs/testing.md](../../docs/testing.md#fuzzing) § Fuzzing, § Bounded
verification). The property, `property::namespace_protocol_holds`, holds each decoder to its
documented contract on any input: a server's rights gate (`gate`, `gate_open`), its rights
composition of a forwarded lookup (`compose_forward_lookup_rights`), its decode of an
`NS_LOOKUP` path (`validate_name` on each component), and a client's decode of a lookup reply
(`PathWalk::advance`). Its drivers are the fuzz target `namespace-protocol`
(`xtask/fuzz/targets`), which starts from the seeds under `fuzz/namespace-protocol/seeds/`; the
replay of those seeds and any `fuzz/namespace-protocol/regressions/` in the crate's tests; and the
Kani proofs in `badge.rs`, `gate.rs`, `name.rs`, `lib.rs` and `client.rs`, whose module
comments state their bounds and how the name and path checks compose from proven steps.

---

## Authority

This crate is authoritative for the **wire format and dispatch
semantics** of the `NS_*` namespace protocol — labels, request and
reply layouts, error codes, name rules, badge shape, and rights
composition.

The high-level capability model (cap-as-namespace, sandboxing,
visibility filtering as policy) is authoritatively specified in
[`docs/namespace-model.md`](../../docs/namespace-model.md). This
README implements it.

---

## Wire labels

All requests and replies follow the `ipc::IpcMessage` shape: a 64-bit
label, an inline data buffer of up to 64 `u64` words, and up to four
capability slots ([docs/ipc-design.md](../../docs/ipc-design.md)
§ Message Format). Numeric label values live in `ipc::ns_labels` in
`shared/ipc`.

| Opcode | Label | Direction | Purpose |
|---:|---|---|---|
| 20 | `NS_LOOKUP` | client → server | Walk a path of one or more components from a directory cap |
| 21 | `NS_STAT` | client → server | Attribute snapshot for the addressed node |
| 22 | `NS_READDIR` | client → server | Enumerate one entry of a directory by index |

Label bits 0..16 carry the opcode; bits 16..32 carry an opcode-defined
header (today: path length for `NS_LOOKUP`); bits 32..64 are zero.

Error replies use the matching `NsError` discriminant value as the
reply label; success replies use label `0`.

No `NS_*` request carries a capability. A server deletes every capability
an `NS_*` request carries, and every one a request carries that it answers
without taking it, such as one with a label it does not serve:
`dispatch_request` neither reads nor deletes them, and one left in place
holds a slot of the server's `CSpace` for the server's life. A label of
another protocol on the same endpoint keeps the capabilities its own
protocol gives it (a filesystem driver's `FS_*` labels,
[`services/fs/docs/fs-driver-protocol.md`](../../services/fs/docs/fs-driver-protocol.md)).

---

## Badge shape

Every node capability is a badged SEND on a server's namespace
endpoint ([docs/namespace-model.md](../../docs/namespace-model.md)
§ Node Capabilities). The badge is opaque to the kernel; servers decode
it on every request. Layout (low-to-high):

| Bits | Field | Meaning |
|---:|---|---|
| 0..40 | `node_id` | Server-private inode identifier (`NodeId`) |
| 40..64 | `rights` | 24-bit `NamespaceRights` mask |

`node_id == 0` is conventionally the server's root directory. `pack` is
the public encoder; a server decodes a badged request through `gate`
(§ Rights gate below), which also applies the operation's rights
requirement. Backends that need more
than 2^40 distinct nodes per server lifetime MUST split into multiple
servers; the protocol does not provide badge expansion.

**Open-instance caps.** Bit 48 (bit 8 of the rights field, the lowest
reserved one) is `OPEN_INSTANCE`, a badge-kind flag and not a right. A
badge carrying it is an open cap a filesystem driver minted at `FS_OPEN`
([services/fs/docs/fs-driver-protocol.md](../../services/fs/docs/fs-driver-protocol.md)
§ Label 18): it holds a 54-bit server-private open id instead of a
`NodeId` (Session caps, below, gives the id's bits), and bits 40..48 the
rights as above. `pack_open` is its encoder and `gate_open` its decoder. `gate` refuses such a badge
(`GateError::WrongKind`), and `dispatch_request` answers every `NS_*` on
it `NotSupported`, so no backend can read an open id as a node. Open ids
are kept out of the `NodeId` space so that opens do not share the node
bound, and so that a backend unaware of opens never acts on whichever
node shares an open's number.

**Session caps.** Bit 49 (bit 9 of the rights field) is `SESSION`, a
second badge-kind flag. It marks a session cap a filesystem driver minted
at `FS_SESSION` (fs-driver-protocol.md § Label 23), which carries no
rights. A badge carries at most one of the two flags; one with both names
nothing, and `gate_open` and `session_id` refuse it. An open or a session
badge holds a 54-bit server-private identifier (`KIND_ID_BITS`): its low
40 bits in badge bits 0..40 and its high 14 bits in badge bits 50..64,
which a node cap keeps reserved. `pack_session` is the encoder,
`session_id` reads a session cap's badge, and `gate_open` decodes an
open's (`OpenRef`). `gate` refuses every badge with a kind flag
(`is_kind_flagged`), and `dispatch_request` answers every `NS_*` on one
`NotSupported`.

---

## NS_LOOKUP

Walk a relative path of one or more components from the directory
addressed by the caller's badge, as far as the server that answers it owns
the entries.

**Request**

| Field | Value |
|---|---|
| `label` bits 0..16 | `20` |
| `label` bits 16..32 | `path_len` (1..=504, `MAX_LOOKUP_PATH_LEN`: the data words after `data[0]`) |
| `data[0]` | Caller-requested rights (low 24 bits; sentinel `0xFFFF` requests "everything I am allowed") |
| `data[1..]` | Path bytes packed little-endian, `path_len` bytes total: one or more components joined by single `/` |
| `caps` | empty |

A path of one component is a single name.

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `0` |
| `data[0]` | Kind of the last entry walked: `0 = File`, `1 = Dir` |
| `data[1]` | Its cached size hint in bytes (zero for directories) |
| `data[2]` | Components consumed, `1` up to the number the request carried |
| `caps[0]` | Badged SEND on the owning server's namespace endpoint for the last entry walked (with GRANT, for a local entry and across a mount alike) |

**Reply (error)**: label is the matching `NsError` code, `data[0]` the
zero-based index in the request's path of the component that failed, and
no caps.

The server MUST:

1. Reject with `PermissionDenied` if the caller's badge lacks the
   `LOOKUP` rights bit.
2. Reject with `InvalidName` if `path_len` is zero, larger than
   `MAX_LOOKUP_PATH_LEN`, or larger than the request's data, or if a
   component (an empty one, from a leading, trailing or doubled `/`,
   included) fails `validate_name`.
3. Walk the components in order from the caller's node, each with the
   checks a separate request for it would apply, against the node and the
   rights the previous component reached (for the first, the caller's
   badge):
   1. Reject with `PermissionDenied` if those rights lack `LOOKUP` (for a
      component after the first).
   2. Resolve `(parent_node, name)` via `NamespaceBackend::lookup`.
   3. Reject with `NotFound` for hidden entries per the rule
      `parent_rights & entry.visible_requires == entry.visible_requires`.
      Hidden and absent MUST be indistinguishable to the caller
      ([docs/namespace-model.md](../../docs/namespace-model.md) § Per-Entry Rights and Visibility).
   4. Compute the entry's rights as
      `parent_rights ∩ entry.max_rights ∩ caller_requested`
      ([docs/namespace-model.md](../../docs/namespace-model.md) § Per-Entry Rights and Visibility).
      Reject with `PermissionDenied` if they are empty, whatever the
      entry's node: a cap with no rights can do nothing.
4. Stop the walk at the last component; at an entry that is not
   `EntryTarget::Local` (a mount point or another cross-server entry,
   whose components another server resolves); and at a local directory
   for which `NamespaceBackend::continues_walk` returns `false`. Reject
   with `NotADirectory` a local entry that is not a directory with
   components after it.
5. Mint the cap of the entry the walk stopped at, and no other, carrying
   that entry's rights via `cap_derive_badge`: for `EntryTarget::Local`,
   on the server's own namespace endpoint at the entry's `NodeId`; for
   `EntryTarget::External`, on the peer server's namespace endpoint at
   the peer node. External mints afresh from the peer's *unbadged*
   endpoint — rather than copying a stored cap — because the kernel
   forbids re-badging an already-badged cap
   ([docs/capability-model.md](../../docs/capability-model.md)
   § Badges), so attenuation can only cross the boundary by a fresh mint
   ([docs/namespace-model.md](../../docs/namespace-model.md) § Cross-server entries).

An error names the component it failed at: steps 1 and 2 name component
0 or the failing one, step 3 and step 4's `NotADirectory` the component
being walked, and a failed mint the last component consumed.

Each component is checked against exactly the node and rights the cap of
the previous one would carry, so the walk reaches the cap, the rights and
the error a walk of one request per component reaches, and the client
gets no authority that walk would not give it.

The dispatch crate's `dispatch_request` enforces all of the above;
backends own only the storage lookup.

**The client's walk.** A client sends the components of its path it has
not yet walked, as many whole ones as fit `MAX_LOOKUP_PATH_LEN`, and
continues from the returned cap with the components the reply did not
consume, until none are left. It refuses a reply whose consumed count is
zero or more than the request carried, and one that reached a file with
components after it. `client::PathWalk` holds that state, for std's walk
and `shared/ns-client`'s alike.

---

## NS_STAT

Attribute snapshot for the node addressed by the caller's badge.

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

**Reply (error)** — label is the matching `NsError` code.

The server MUST reject with `PermissionDenied` if the caller's badge
lacks the `STAT` rights bit.

---

## NS_READDIR

Enumerate one directory entry by zero-based index. Clients iterate by
incrementing the index until the reply label is `END_OF_DIR`. Hidden
entries (per the visibility rule above and [docs/namespace-model.md](../../docs/namespace-model.md)
§ Per-Entry Rights and Visibility) MUST be skipped without contributing to
the index.

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

**Reply (error)** — label is the matching `NsError` code.

The server MUST reject with `PermissionDenied` if the caller's badge
lacks the `READDIR` rights bit.

`NS_READDIR` returns names only; clients follow up with `NS_LOOKUP`
to obtain a node cap for an entry of interest.

---

## Names

Each component of an `NS_LOOKUP` path MUST satisfy `validate_name`:

- UTF-8 encoded.
- Length 1..=255 bytes (`MAX_NAME_LEN`).
- MUST NOT contain `/` (0x2F) or `\0` (0x00).
- MUST NOT be `.` or `..`.

Path resolution is client-side ([docs/namespace-model.md](../../docs/namespace-model.md)
§ Walking): a client sends the components of its path in `NS_LOOKUP`
requests (§ `NS_LOOKUP`), each against the cap the previous one returned,
and each server walks as many of them as it owns. There is no `..`
operation; walking up requires a separately-held parent cap.

Backends MAY further restrict (reserved words, on-disk encoding
limits, case-sensitivity rules); such restrictions surface as
`NotFound` or `InvalidName` from the backend's `lookup` method.

---

## Rights

Namespace rights are a 24-bit mask packed in badge bits 40..64. Eight
bits are defined, bits 8 and 9 are the `OPEN_INSTANCE` and `SESSION` kind
flags (§ Badge shape), and fourteen are reserved.

| Bit | Constant | Meaning |
|---:|---|---|
| 0 | `LOOKUP` | `NS_LOOKUP` into this directory |
| 1 | `READDIR` | `NS_READDIR` enumeration |
| 2 | `STAT` | `NS_STAT` |
| 3 | `READ` | `FS_READ` / `FS_READ_MEMORY` (file) |
| 4 | `WRITE` | `FS_WRITE` / `FS_WRITE_MEMORY` / `FS_TRUNCATE` (file) |
| 5 | `EXEC` | File is executable (design intent; not yet implemented: no loader tests it) |
| 6 | `MUTATE_DIR` | `FS_CREATE` / `FS_REMOVE` / `FS_MKDIR` / `FS_RENAME` (directory) |
| 7 | `ADMIN` | Visibility-gating bit |
| 8 | `OPEN_INSTANCE` | Not a right: marks an open cap's badge (§ Badge shape); never part of a `NamespaceRights` value |
| 9 | `SESSION` | Not a right: marks a session cap's badge (§ Badge shape); a badge with both kind flags names nothing; never part of a `NamespaceRights` value |
| 10..23 | — | Reserved in a node cap's badge; MUST be zero on derive, ignored on read. A badge with a kind flag holds its identifier's high bits there (§ Badge shape) |

Every node cap is a `SEND` cap from the kernel's perspective; the
rights mask above is opaque to the kernel and inspected only by the
server. Rights MUST narrow on every walk ([docs/namespace-model.md](../../docs/namespace-model.md)
§ Namespace Rights); the dispatch crate enforces
this through the intersection at step 5 of `NS_LOOKUP`.

### Rights gate

`gate(label, badge)` is the only public path from a badged request to its `NodeId` and rights. It
looks the opcode up in the crate's per-label table, applies the requirement in the table above
(`FS_RELEASE_MEMORY`, `FS_CLOSE`, `FS_OPEN`, and `FS_SESSION` require only a non-empty rights mask),
and returns `GateError::UnknownLabel` for an opcode the table does not list, `GateError::WrongKind`
for a badge with a kind flag (an open's or a session's), or `GateError::PermissionDenied` when the
badge lacks the requirement. `gate_open(label, badge)` applies the same table to an open-instance
badge and returns the open it names (`OpenRef`) and its rights, with
`GateError::WrongKind` for a node or session badge, or one with both kind flags. Unbadged
service-level labels (`FS_MOUNT`, `FS_UNMOUNT`) are dispatched outside both.

---

## Errors

`NsError` discriminants are stable wire codes:

| Code | Variant | Meaning |
|---:|---|---|
| 1 | `NotFound` | Name absent or hidden by visibility |
| 2 | `PermissionDenied` | Caller's badge lacks the required right, or an `NS_LOOKUP` would mint a cap with no rights |
| 3 | `NotADirectory` | Operation requires a directory; node is a file |
| 4 | `IsADirectory` | Operation requires a file; node is a directory |
| 5 | `InvalidName` | Name failed `validate_name` |
| 6 | `InvalidOffset` | Read past EOF |
| 7 | `InvalidMemoryCap` | `FS_READ_MEMORY` reply target Memory-cap shape wrong |
| 8 | `InvalidCookie` | Memory-cap cookie zero or duplicate |
| 9 | `Evicted` | Page referenced by a held cookie has been evicted |
| 10 | `IoError` | Backend storage failed |
| 11 | `NotSupported` | Operation not implemented on this server |
| 12 | `OutOfResources` | Server resource exhaustion |

Reordering or renumbering breaks the wire contract. The crate's
`tests::error_codes_match_protocol_specification` test guards against
accidental edits.

---

## Backend trait

Filesystem drivers (`fs/fat`, future `fs/ext4`, future `tmpfs`) and
composing servers (`vfsd`'s synthetic root) embed this crate: they implement
`NamespaceBackend` over their storage layer, and the crate owns every
security-relevant code path. `dispatch_request` decodes each request and
runs the caller-rights checks (and, for `NS_LOOKUP`, the name validation)
before it calls a trait method; it then filters what `lookup` and
`readdir_entry` return by visibility and, for a lookup, composes the
rights of each component it walks and of the minted cap. Backends never re-implement those checks.

| Method | Called from |
|---|---|
| `lookup` | `NS_LOOKUP`, once per component walked |
| `continues_walk` | `NS_LOOKUP`, at a local directory with components after it |
| `readdir_entry` | `NS_READDIR` |
| `may_hide_entries` | `NS_READDIR` |
| `stat` | `NS_STAT` |
| `read_inline` | not called; reserved for an `NS_READ` label (design intent; not yet implemented) |
| `read_memory` | not called; reserved for an `NS_READ_MEMORY` label (design intent; not yet implemented) |
| `release_memory` | not called; reserved for an `NS_RELEASE_MEMORY` label (design intent; not yet implemented) |
| `close` | not called; reserved for an `NS_CLOSE` label, a best-effort cleanup hint (design intent; not yet implemented) |

`may_hide_entries` (default `true`) reports whether any entry of a
directory may be hidden. When it returns `false`, `NS_READDIR` serves the
client's index with one `readdir_entry` call; otherwise the crate scans
the directory from index 0 on each request, skipping hidden entries. A
hidden entry returned on the direct path makes the crate fall back to that
filtered scan, so a wrong `false` cannot reveal a hidden name.

`continues_walk` (default `true`) reports whether an `NS_LOOKUP` walk that
reached a local directory may look its next component up there. A backend
returns `false` for a directory whose lookups another dispatcher may answer:
vfsd's synthetic nodes with a fall-through
([services/vfsd/docs/namespace-composition.md](../../services/vfsd/docs/namespace-composition.md)).
The walk then stops at the directory and the client sends the rest of its
path to the directory's cap, where that dispatcher sees it.

Memory-cap reads continue to use the `ipc::fs_labels::FS_READ_MEMORY`
surface today; they are documented in
[`services/fs/docs/fs-driver-protocol.md`](../../services/fs/docs/fs-driver-protocol.md).
Migrating the read surface to `NS_*` labels is design intent; not yet implemented.

---

## Composing servers

A server MAY return entries whose target lies on a different server's
namespace endpoint (`EntryTarget::External`). `NS_LOOKUP` mints a
fresh cap on that peer endpoint carrying the composed rights
(`parent_rights ∩ entry.max_rights ∩ caller_requested`), and subsequent
operations bypass the composing server ([docs/namespace-model.md](../../docs/namespace-model.md)
§ Cross-server entries). This is how filesystem mounting works:
[`services/vfsd/docs/namespace-composition.md`](../../services/vfsd/docs/namespace-composition.md)
describes vfsd's synthetic-root composition in detail.

---

## Source Layout

```
namespace-protocol/
├── Cargo.toml
├── README.md
├── fuzz/
│   └── namespace-protocol/
│       └── seeds/     # Checked-in inputs of the `namespace-protocol` fuzz target
└── src/
    ├── lib.rs         # NodeKind, NodeStat, EntryName, EntryTarget, EntryView, MemoryReply,
    │                  #   NamespaceBackend, dispatch_request, the NS_LOOKUP walk and its path
    │                  #   scan, MAX_LOOKUP_PATH_LEN; the proofs of the path decode
    ├── badge.rs       # NodeId and badge packing (pack)
    ├── client.rs      # PathWalk: the client's NS_LOOKUP requests and continuation
    ├── gate.rs        # gate, GateError, compose_forward_lookup_rights, the per-label table
    ├── name.rs        # validate_name and its character scan, MAX_NAME_LEN
    ├── property.rs    # The decoders' contract as one property (host tests, proofs and
    │                  #   fuzzing only)
    ├── rights.rs      # NamespaceRights and the bit constants
    └── wire.rs        # NsError wire codes
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/namespace-model.md](../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing, visibility |
| [docs/capability-model.md](../../docs/capability-model.md) | Badge semantics, derivation tree |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC message format |
| [services/fs/docs/fs-driver-protocol.md](../../services/fs/docs/fs-driver-protocol.md) | Surviving fs-driver-specific labels |
| [services/vfsd/docs/namespace-composition.md](../../services/vfsd/docs/namespace-composition.md) | vfsd's synthetic root and root-mount delegation |

---

## Summarized By

[Namespace Model](../../docs/namespace-model.md),
[services/fs/README.md](../../services/fs/README.md),
[Filesystem Driver Protocol](../../services/fs/docs/fs-driver-protocol.md),
[services/fs/fat/README.md](../../services/fs/fat/README.md),
[Synthetic Root and Namespace Composition](../../services/vfsd/docs/namespace-composition.md),
[shared/ns-client/README.md](../ns-client/README.md)
