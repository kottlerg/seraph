# Namespace Model

The namespace is a graph of capabilities. Holding a node capability *is* the
authority to interact with that node and the entries reachable through it.
There is no system-wide path, no ambient lookup, and no identity-based
override.

---

## Principles

- The capability *is* the namespace. A directory capability conveys access
  to that directory's subtree and nothing else.
- No process-global filesystem authority exists. A process given zero
  namespace capabilities has no namespace access. A process given several
  holds them independently.
- No surface for enumeration outside what was granted. Operations on a
  capability MUST NOT reveal entries, parents, mounts, or metadata not
  reachable through that capability.
- Walking is monotonically attenuating. A capability obtained by walking
  from a parent capability MUST NOT carry rights that exceed the parent's.
- Authority is delivered, not discovered. Every namespace capability a
  process holds arrived via the per-process bootstrap-cap handover or via
  IPC from another process that already held it.

---

## Node Capabilities

A **node capability** is a tokened send capability on a namespace server's
endpoint. The token encodes:

| Field | Width | Meaning |
|---|---:|---|
| `node_id` | 40 bits | Server-private inode identifier |
| `rights`  | 24 bits | Namespace rights (see below) |

The kernel does not interpret token bits. Token semantics are owned by
the namespace-protocol contract; servers decode the token on every
request to identify the addressed node and the caller's rights.

A node capability is one of two kinds, distinguished only by the rights
the server permits and the operations the server accepts on the
addressed node:

- **Directory capability** — references a directory node. Operations:
  `NS_LOOKUP`, `NS_READDIR`, `NS_STAT`.
- **File capability** — references a file node. Operations: `NS_READ`,
  `NS_READ_FRAME`, `NS_RELEASE_FRAME`/`_ACK`, `NS_STAT`.

The kernel layer holds no notion of "directory" or "file." Type
distinctions are server-private and surface to clients via the
`kind` field of the `NS_LOOKUP` reply.

### Derivation root

Every node capability the system ever issues derives from a server's
**namespace endpoint capability**: an un-tokened send capability the
server holds in its own CSpace. All node caps a server issues share
this single kernel-derivation parent.

This is mandated by the kernel's `cap_derive_token` contract, which
forbids deriving a tokened cap from an already-tokened source. The
namespace tree therefore lives in server state, not in the kernel's
derivation graph.

### Revocation

`cap_revoke` on a server's namespace endpoint capability revokes every
node capability that server has ever issued. This is the
"kill the server" hammer.

`cap_revoke` on a single derived node capability invalidates only that
capability. Already-derived descendants in the namespace tree remain
valid until their holders close them or the server is killed.

Per-namespace-subtree revocation requires server-side bookkeeping
(revocation epochs in the token, or per-server revoked-subtree
tracking). A server MAY implement it; the protocol contract does
not require it.

---

## Namespace Rights

Namespace rights are a 24-bit mask packed into the high bits of the
node-capability token. They are distinct from the kernel's
[capability rights](capability-model.md#rights-and-attenuation), which
govern the cap-as-send-capability layer (`SEND`, `MAP`, etc.). Every
node capability is a `SEND` cap from the kernel's perspective; namespace
rights are only inspected by the server.

| Bit | Name | Meaning |
|----:|------|---------|
| 0 | `LOOKUP` | NS_LOOKUP into this directory is permitted |
| 1 | `READDIR` | NS_READDIR enumeration of this directory is permitted |
| 2 | `STAT` | NS_STAT on this node is permitted |
| 3 | `READ` | NS_READ / NS_READ_FRAME on this file is permitted |
| 4 | `WRITE` | NS_WRITE on this file is permitted (deferred; reserved) |
| 5 | `EXEC` | This file is executable (consumed by ELF loaders) |
| 6 | `MUTATE_DIR` | NS_CREATE / NS_UNLINK in this directory are permitted (deferred; reserved) |
| 7 | `ADMIN` | Reserved for visibility gating (see Per-Entry Visibility) |
| 8..23 | — | Reserved; MUST be zero on derive, ignored on read |

Servers MUST reject any operation requiring a rights bit that is not
set in the caller's token. Servers MUST NOT promote rights at any
operation; rights can only narrow.

---

## Per-Entry Rights and Visibility

Each entry in a directory's storage carries two namespace-rights masks
in addition to the child's `node_id` and `kind`:

- `max_rights` — the ceiling on rights any child capability minted for
  this entry MAY carry. Independent of the parent directory's rights.
- `visible_requires` — the rights the caller's directory capability
  MUST hold for this entry to be visible at lookup or readdir.

`NS_LOOKUP` semantics, executed uniformly by the namespace-protocol
crate (not by individual drivers):

1. Decode the caller's token into `(parent_node, parent_rights)`.
2. If `parent_rights & LOOKUP == 0`, reply `PERMISSION_DENIED`.
3. Validate the requested name (see Naming).
4. Resolve `(parent_node, name)` to an `EntryView` via the backend.
5. If `(parent_rights & entry.visible_requires) != entry.visible_requires`,
   reply `NOT_FOUND`. The caller MUST NOT be able to distinguish
   "hidden" from "absent."
6. Compute `returned_rights = parent_rights ∩ entry.max_rights ∩ caller_requested_rights`.
7. Mint the child capability via `cap_derive_token` from the server's
   namespace endpoint, with token `(entry.child_node, returned_rights)`.
8. Reply with the child capability, its `kind`, and a size hint for files.

`NS_READDIR` applies the same visibility filter: entries hidden from
this caller are skipped. Hidden entries do not appear in enumeration.

This composition is what gives the namespace its security properties:

- A read-only file inside a writable directory is expressed by setting
  the entry's `max_rights` accordingly, not by per-file owner overrides.
- A directory invisible to unprivileged callers is expressed by setting
  `visible_requires` to require a rights bit (e.g., `ADMIN`) the
  unprivileged caller does not hold. Such an entry does not appear in
  readdir and lookup returns `NOT_FOUND`.
- Higher rights to a node are obtainable only from a separately
  delivered capability, minted at the source by a holder of the higher
  rights. The two capabilities name the same node with different
  rights; possessing the lesser tells the holder nothing about the
  greater's existence.

---

## Walking

Path resolution is client-side. A client holding a directory capability
walks a multi-component name by issuing one `NS_LOOKUP` per component
against the capability returned by the previous step. The client drops
intermediate capabilities as it advances.

There is no `..` operation. Walking up requires a separately held
capability for the parent. There is no kernel-level "absolute path";
a leading `/` in a string path is stripped and the walk begins at
whatever directory capability the client has chosen as its root.

Servers MUST reject `..` and `.` as component names along with any
name containing `/` (0x2F) or `\0` (0x00). See Naming.

### Current working directory

Relative-path resolution anchors at a process's *current directory
capability* — a tokened SEND on some namespace endpoint addressing
a directory node. The cwd cap is independent of the root cap and
need not be related to it; a process can hold a root cap addressing
`/` and a cwd cap addressing some restricted subtree, or vice versa,
or neither, or only one. There is no kernel mechanism that ties
them.

Spawners install the child's initial cwd cap via the same wire that
delivers the root cap (`procmgr_labels::CONFIGURE_NAMESPACE`,
`caps[1]`). A child without a delivered cwd cap holds no cwd cap;
relative-path resolution fails until the child obtains one (typically
by walking its root cap to a directory). The convention in std is
that `File::open` resolves a leading-`/` path against the root cap
and any other path against the cwd cap, but this is a userspace
convention — the namespace protocol does not interpret path strings.

---

## Naming

A name accepted by `NS_LOOKUP` is a single component:

- UTF-8 encoded.
- Length 1..=255 bytes.
- MUST NOT contain `/` (0x2F) or `\0` (0x00).
- MUST NOT be `.` or `..`.

Backends MAY further restrict (reserved words, on-disk encoding limits,
case-sensitivity rules). Such restrictions MUST be enforced inside the
backend and surfaced as `NOT_FOUND` or `INVALID_NAME` per the
namespace protocol.

Case sensitivity is backend-defined. The protocol contract does not
mandate either policy.

---

## Backends and Composition

A namespace server is any process that implements the
`NamespaceBackend` trait and serves a namespace endpoint. The protocol
crate (`shared/namespace-protocol`) owns the IPC dispatch loop, name
validation, rights composition, visibility filtering, and capability
minting. Backends own only their storage layer.

This isolates the security-relevant code in a single place. Adding a
new filesystem driver is an exercise in implementing
`NamespaceBackend`; it does not re-implement namespace semantics or
access checks.

### Cross-server entries

A directory entry's stored target is one of:

- a backend-internal `node_id` — `NS_LOOKUP` mints a fresh node cap on
  this server, or
- a node capability on a different server — `NS_LOOKUP` returns a copy
  of that capability with rights intersected per the per-entry policy.

This is how mounting works: there is no runtime mount-resolution table.
A "mount" is a directory entry whose stored target is a capability into
the mounted filesystem's server. The composing server holds those
capabilities at boot or from runtime mount events; lookups crossing the
mount point return cross-server capabilities and subsequent operations
go directly to the owning backend with no proxy hop.

A "view" — for example, a per-process sandbox root — is a directory
constructed in any backend (typically a small in-memory backend) whose
entries are capabilities chosen by the view's constructor.
[Sandboxing](#sandboxing) is the application of this primitive.

---

## Initial Capability Delivery

A process that needs namespace access receives one or more node
capabilities at process bootstrap. The mechanism is the same per-process
[bootstrap-cap handover](process-lifecycle.md) used to deliver every
other per-process capability.

A process that is delivered no namespace capability has no namespace
access. The runtime library (`std`) treats this as the absence of
filesystem support and returns `Unsupported` from `std::fs` operations.

There is no ambient namespace endpoint, no global lookup service, and
no `ProcessInfo` field carrying a default fs capability. Namespace
authority is positively granted, never inherited.

---

## Sandboxing

A sandboxed child process is constructed by delivering a capability
that is not the system root. The capability MAY be:

- a directory in the spawner's own subtree, derived with attenuated
  rights;
- the root of a synthetic directory composed by the spawner with
  cap entries pointing wherever the spawner chose;
- the null capability (no namespace access at all).

There is no chroot syscall, no mount namespace, no per-process mount
table, and no permission-check syscall. The capability delivered *is*
the sandbox boundary.

The wire mechanism is `procmgr_labels::CONFIGURE_NAMESPACE`, called
on a tokened process handle between `CREATE_PROCESS` /
`CREATE_FROM_FILE` and `START_PROCESS`. The supplied cap is the sole
source of the child's `ProcessInfo.system_root_cap` — without this
call the slot stays zero and the child runs with no namespace
authority. Procmgr holds no namespace cap of its own; the spawner is
the cap-distribution authority on every spawn. The cap is typically
either a `cap_copy` of the spawner's own `root_dir_cap` (parent-
inherit default for `Command::spawn`) or a walk-and-attenuated view
the spawner constructed for sandboxing. From std, the seraph-
specific `std::os::seraph::process::CommandExt::namespace_cap`
extension overrides the parent-inherit default with an explicit cap.

---

## Policy is Configuration

The namespace mechanism is policy-free. Whether a system is restrictive
or permissive is a function of how capabilities are distributed at
spawn time, not of the underlying mechanism. A configuration in which
every process receives the system root capability with full rights is
valid; a configuration in which every process receives a tightly
attenuated subview is equally valid; mixed configurations are valid.

This makes the mechanism agnostic to:

- **No-identity systems** — a single root capability is distributed
  per spawner policy. No user notion exists.
- **Single-user systems** — the operator's process holds the system
  root. Other processes hold attenuations.
- **Multi-user systems** — a per-user capability-distribution service
  composes per-user views and delivers them at session establishment.
  Per-user identity becomes the policy-layer mapping from authenticated
  identity to a particular root capability.

The user/identity layer is deferred. When introduced, it operates
above this mechanism by composing views and minting per-identity
capabilities; the namespace surface itself does not change.

---

## What This Model Does Not Do

- **No path-based authority.** A path string carries no authority. The
  authority for any operation is a held capability.
- **No ambient lookup.** A process cannot ask "what files exist on this
  system" except through capabilities it holds. Discovery beyond a
  granted subtree is structurally impossible.
- **No setuid-equivalent.** A program does not gain rights by being
  marked or by its on-disk metadata. A program's rights are exactly
  the capabilities its spawner delivers.
- **No identity-based override.** No "root user" with implicit
  override. Authority is held capabilities, nothing else.

---

## Summarized By

[docs/capability-model.md](capability-model.md), [shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md), [services/vfsd/docs/namespace-composition.md](../services/vfsd/docs/namespace-composition.md)
