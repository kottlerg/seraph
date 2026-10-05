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
  process holds arrived via the spawner's delivery at process creation
  (see [Initial Capability Delivery](#initial-capability-delivery)) or via
  IPC from another process that already held it.

---

## Node Capabilities

A **node capability** is a badged send capability on a namespace
server's endpoint. The badge packs a server-private node identifier and
a namespace rights mask (layout in
[shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md)
§ Badge shape; see [Namespace Rights](#namespace-rights)). See
[capability-model.md](capability-model.md) §"Badges" for the
kernel-side derivation and set-once semantics that govern these caps.

A node capability is one of two kinds, distinguished only by the rights
the server permits and the operations the server accepts on the
addressed node:

- **Directory capability** — references a directory node. Operations:
  `NS_LOOKUP`, `NS_READDIR`, `NS_STAT`, and the `MUTATE_DIR`-gated
  `FS_CREATE`, `FS_REMOVE`, `FS_MKDIR`, `FS_RENAME`.
- **File capability** — references a file node. Operations: `NS_STAT`,
  plus the file labels `FS_READ`, `FS_READ_MEMORY`,
  `FS_RELEASE_MEMORY`/`FS_RELEASE_ACK`, `FS_WRITE`, `FS_WRITE_MEMORY`,
  `FS_TRUNCATE`, and `FS_CLOSE`; `namespace_protocol::gate` checks each
  request label against the caller's namespace rights.

The kernel layer holds no notion of "directory" or "file." Type
distinctions are server-private and surface to clients via the
kind word of the `NS_LOOKUP`, `NS_STAT`, and `NS_READDIR` replies.

### Derivation root

Every node capability the system ever issues derives from a server's
**namespace endpoint capability**: the un-badged endpoint capability the
server receives on, or the un-badged SEND copy of it that a composing
server holds to mint caps across a mount (see
[Cross-server entries](#cross-server-entries)). The namespace tree
therefore lives in server state, not in the kernel's derivation graph.

### Revocation

`cap_revoke` on a server's namespace endpoint capability revokes every
node capability that server has ever issued. This is the
"kill the server" hammer.

`cap_revoke` on a single derived node capability invalidates only that
capability's derivation descendants; the target capability itself is
preserved (see [docs/capability-model.md](capability-model.md)
§Revocation). Node capabilities derived elsewhere in the namespace tree
remain valid until their holders close them or the server is killed.

Per-namespace-subtree revocation requires server-side bookkeeping
(revocation epochs in the badge, or per-server revoked-subtree
tracking). A server MAY implement it; the protocol contract does
not require it.

---

## Namespace Rights

Namespace rights are a 24-bit mask packed into the high bits of the
node-capability badge. They are distinct from the kernel's
[capability rights](capability-model.md#rights-and-attenuation), which
govern the cap-as-send-capability layer (`SEND`, `MAP`, etc.). Every
node capability is a `SEND` cap from the kernel's perspective; namespace
rights are only inspected by the server.

Bit assignments and their gated operations are specified in
[shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md)
§ Rights.

Servers MUST reject any operation requiring a rights bit that is not
set in the caller's badge. Servers MUST NOT promote rights at any
operation; rights can only narrow.

---

## Per-Entry Rights and Visibility

Each entry in a directory's storage carries two namespace-rights masks
in addition to the child's target (a local `node_id` or a peer namespace
endpoint; see [Cross-server entries](#cross-server-entries)) and `kind`:

- `max_rights` — the ceiling on rights any child capability minted for
  this entry MAY carry. Independent of the parent directory's rights.
- `visible_requires` — the rights the caller's directory capability
  MUST hold for this entry to be visible at lookup or readdir.

On `NS_LOOKUP`, the returned child rights equal
`parent_rights ∩ entry.max_rights ∩ caller_requested_rights`; entries
failing the `visible_requires` check appear as `NsError::NotFound` (the caller
MUST NOT be able to distinguish "hidden" from "absent"). The
namespace-protocol crate executes this uniformly for every backend; see
[`shared/namespace-protocol/README.md`](../shared/namespace-protocol/README.md)
§`NS_LOOKUP` for the wire-level dispatch.

`NS_READDIR` applies the same visibility filter: entries hidden from
this caller are skipped. Hidden entries do not appear in enumeration.

This composition is what gives the namespace its security properties:

- A read-only file inside a writable directory is expressed by setting
  the entry's `max_rights` accordingly, not by per-file owner overrides.
- A directory invisible to unprivileged callers is expressed by setting
  `visible_requires` to require a rights bit (e.g., `ADMIN`) the
  unprivileged caller does not hold. Such an entry does not appear in
  readdir and lookup returns `NsError::NotFound`.
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

Servers reject `.`, `..`, and names containing `/` or NUL per
[shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md) § Names.

### Current working directory

Relative-path resolution anchors at a process's *current directory
capability* — a badged SEND on some namespace endpoint addressing
a directory node. The cwd cap is independent of the root cap and
need not be related to it; a process can hold a root cap addressing
`/` and a cwd cap addressing some restricted subtree, or vice versa,
or neither, or only one. There is no kernel mechanism that ties
them.

Spawners install the child's initial cwd cap via the same wire that
delivers the root cap (`procmgr_labels::CONFIGURE_NAMESPACE`,
`caps[1]`; see [services/procmgr/README.md](../services/procmgr/README.md)).
A child without a delivered cwd cap holds no cwd cap;
relative-path resolution fails until the child obtains one (typically
by walking its root cap to a directory). The convention in std is
that `File::open` resolves a leading-`/` path against the root cap
and any other path against the cwd cap, but this is a userspace
convention — the namespace protocol does not interpret path strings.
The std bindings are specified in
[runtime/ruststd/README.md](../runtime/ruststd/README.md).

---

## Naming

Names are single components; the encoding, length, forbidden-byte and
reserved-name rules, and how backend-specific restrictions surface, are
specified in
[shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md)
§ Names. Case sensitivity is backend-defined.

---

## Backends and Composition

A namespace server is any process that implements the
`NamespaceBackend` trait and serves a namespace endpoint. The protocol
crate ([shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md))
owns per-message dispatch (`dispatch_request`), the per-label rights
gate (`gate`), name validation, rights composition, visibility
filtering, and capability minting; each backend runs its own receive
loop and owns only its storage layer.

This isolates the security-relevant code in a single place. Adding a
new filesystem driver is an exercise in implementing
`NamespaceBackend`; it does not re-implement namespace semantics or
access checks.

### Cross-server entries

A directory entry's stored target is one of:

- a backend-internal `node_id` — `NS_LOOKUP` mints a fresh node cap on
  this server, or
- another server's namespace endpoint (a mount point) — `NS_LOOKUP`
  mints a fresh node cap on *that* server, with rights intersected per
  the per-entry policy. Minting afresh — rather than copying a stored
  cap — is what carries attenuation across the mount boundary: a node
  cap's rights live in its badge, and the kernel forbids re-badging an
  already-badged capability, so a stored cross-server cap could only be
  copied at its original rights, laundering authority (see
  [shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md)
  § NS_LOOKUP and [docs/capability-model.md](capability-model.md)
  § Badges). The composing
  server therefore stores the peer's unbadged endpoint and badges each
  crossing lookup's result itself.

This is how mounting works: there is no runtime mount-resolution table.
A "mount" is a directory entry whose stored target is the mounted
filesystem server's namespace endpoint. The composing server holds those
endpoints at boot or from runtime mount events; lookups crossing the
mount point mint cross-server capabilities and subsequent operations
go directly to the owning backend with no proxy hop. A composing server
MAY instead forward a lookup to a peer through a held badged cap (vfsd's
root-mount fall-through; see
[services/vfsd/docs/namespace-composition.md](../services/vfsd/docs/namespace-composition.md));
the forwarder MUST intersect the caller's rights into the forwarded
request so walking stays monotonically attenuating.

A "view" — for example, a per-process sandbox root — is a directory
constructed in any backend (typically a small in-memory backend) whose
entries are capabilities chosen by the view's constructor.
[Sandboxing](#sandboxing) is the application of this primitive.

---

## Initial Capability Delivery

A process that needs namespace access receives one or more node
capabilities at process bootstrap. The spawner supplies them through
procmgr's `CONFIGURE_NAMESPACE` call between create and start; procmgr
installs them in the child's CSpace and records their slots in
`ProcessInfo.system_root_cap` and `ProcessInfo.current_dir_cap` (see
[process-lifecycle.md](process-lifecycle.md) § ProcessInfo / InitInfo
Handover Discipline).

A process that is delivered no namespace capability has no namespace
access. The runtime library (`std`) treats this as the absence of
filesystem support and returns `Unsupported` from `std::fs` operations (see
[runtime/ruststd/README.md](../runtime/ruststd/README.md)).

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
- no capability: the spawner skips `CONFIGURE_NAMESPACE`, and the child has no namespace
  access at all.

There is no chroot syscall, no mount namespace, no per-process mount
table, and no permission-check syscall. The capability delivered *is*
the sandbox boundary.

The spawner is the cap-distribution authority on every spawn: it
delivers the child's root capability at process-creation time, and
absent delivery the child has no namespace access. Procmgr holds no
namespace cap of its own. For the wire mechanism see
[`services/procmgr/README.md`](../services/procmgr/README.md); for the
std bindings see
[`runtime/ruststd/README.md`](../runtime/ruststd/README.md).

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

---

## Summarized By

[Capability Model](capability-model.md), [Storage](storage.md),
[runtime/ruststd/README.md](../runtime/ruststd/README.md),
[services/procmgr/README.md](../services/procmgr/README.md),
[`.svc` Service Definitions](../services/svcmgr/docs/service-definitions.md),
[Synthetic Root and Namespace Composition](../services/vfsd/docs/namespace-composition.md),
[shared/namespace-protocol/README.md](../shared/namespace-protocol/README.md)
