# Synthetic Root and Namespace Composition

vfsd is a namespace server that owns no on-disk storage. Its
[`NamespaceBackend`] implementation, [`VfsdRootBackend`], composes a
synthetic system root from per-mount tokened SEND caps captured at
boot time and on each successful `MOUNT`. Clients holding the
system-root cap walk into mounted filesystems through this
composition; the cross-server reply hands them a cap on the owning
filesystem driver directly, after which vfsd is out of the path.

---

## Authority

This document is authoritative for vfsd's namespace-server behavior:
the shape of the synthetic root, the mount-tree representation, the
two-derive-not-`cap_copy` invariant, and fall-through delegation to
the root mount.

The wire protocol is defined by
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md).
The cap-as-namespace model is defined by
[`docs/namespace-model.md`](../../../docs/namespace-model.md).

---

## Synthetic root state

[`VfsdRootBackend`] owns a single fixed-capacity tree of
[`TreeNode`]s. Each node carries:

| Field | Purpose |
|---|---|
| `name` / `name_len` | Path component captured at install time |
| `parent` / `first_child` / `next_sibling` | Tree links |
| `terminal_cap` | Tokened SEND on the underlying driver's namespace endpoint, set on a node that is itself a mount point; zero on a synthetic intermediate |
| `fallthrough_cap` | Tokened SEND on the root mount's namespace endpoint addressing the directory at this node's path in the root filesystem; zero if no such fall-through is available |

The synthetic root is `NodeId::ROOT` (pool index 0) and is always
active; its `fallthrough_cap` carries the root mount cap captured
when `MOUNT path="/"` succeeds. `MAX_TREE_NODES` is `32` and
`MAX_ENTRY_NAME` is `64` bytes; both are file-local constants in
[`services/vfsd/src/root_backend.rs`](../src/root_backend.rs).

Multi-component mount paths (`/srv/data`) install through the tree
by walking components, creating synthetic intermediates on demand,
and setting `terminal_cap` on the final node. After install the
caller (`do_mount`) walks the root mount component-by-component via
`NS_LOOKUP` to populate each new intermediate's `fallthrough_cap`.

---

## NS_LOOKUP composition

`NS_LOOKUP(parent, name)` against any cap on vfsd's namespace
endpoint dispatches in two stages, from `vfsd::namespace_loop`:

1. **Local-child match.** [`VfsdRootBackend::lookup`] walks the
   parent node's child list. A match on a *terminal* child returns
   an [`EntryTarget::External`] view; the namespace-protocol crate
   replies with a `cap_derive`-d copy of the stored `terminal_cap`.
   The reply cap belongs to the underlying filesystem driver's
   namespace endpoint; subsequent walks bypass vfsd entirely. A
   match on a *synthetic intermediate* child returns an
   [`EntryTarget::Local`] view; the protocol crate mints a
   `cap_derive_token` on `namespace_ep` addressing the intermediate's
   `NodeId`, so the next `NS_LOOKUP` lands back on vfsd.

2. **Fall-through.** If no local child matches and the parent has a
   `fallthrough_cap`, vfsd's dispatcher (`try_forward_lookup_fallthrough`
   in `services/vfsd/src/main.rs`) forwards the `NS_LOOKUP` to the
   fall-through cap and replies with the upstream response. The
   request body is repacked before forwarding: vfsd extracts the
   caller's parent rights from the inbound cap's token, intersects
   them with the request's `caller_requested` word
   (via `namespace_protocol::compose_forward_lookup_rights`), and
   writes the resulting mask into the outbound message's `word(0)`.
   The label, name bytes, and overall shape are preserved; the reply
   travels back unchanged. This is required because the fall-through
   cap was minted by vfsd's own walk and carries full namespace
   rights — the receiving fs driver composes its returned rights
   against the destination cap's token, so without the repack the
   caller's attenuation would be discarded. Repacking preserves the
   `docs/namespace-model.md` § "Walking" invariant
   (walk-monotonic-attenuation) across mount boundaries: a child cap
   minted at the fs driver carries at most the caller's parent
   rights, intersected with the entry's `max_rights` ceiling.

   The fall-through preserves the namespace-model rule that root-fs
   entries remain reachable unless explicitly shadowed by a
   registered mount: paths like `/bin/svcmgr` reach the root fs
   through the synthetic root's fall-through, and paths like
   `/srv/test.txt` reach the root fs's `/srv/test.txt` through the
   synthetic intermediate created for `/srv/data`'s mount.

   Mount-point names take precedence so that a future `/bin` mount
   (if installed) shadows the root-fs entry without changing the
   root filesystem's on-disk contents.

3. If neither stage matches, the dispatch loop falls through to the
   protocol crate, which replies `NotFound`.

`NS_READDIR` and `NS_STAT` against synthetic tree nodes see only
the local children — root-fs contents reachable via fall-through are
not enumerated through the synthetic surface; clients walk to them
by name.

---

## Two derives, not cap_copy

A successful `MOUNT` mints **two** tokened SEND caps on the driver's
namespace endpoint, both addressing the driver's root at full
namespace rights:

- `caller_root_cap` is returned to the `MOUNT` caller (or dropped if
  the caller is `INGEST_CONFIG_MOUNTS` itself).
- `synthetic_root_cap` is captured into [`VfsdRootBackend`] so the
  composition above can `cap_derive` from it on every `NS_LOOKUP`.

Two derives instead of one `cap_copy` because vfsd must be able to
`cap_delete` either slot in isolation — e.g. an unmount drops the
synthetic-root entry without forcing the `MOUNT` caller to drop its
copy.

### Revocation

Per-cap `cap_delete` is *not* revocation. Only the slot named goes
away; descendants and sibling derivations remain valid. The
namespace-model invariant is that the supported revocation primitive
for a mount is **destroy the fs driver**: `cap_revoke` on the
driver's namespace endpoint cascades through the kernel derivation
graph and invalidates every cap ever derived from it (synthetic-root
entry, `MOUNT` caller copies, every per-file cap previously walked).
This is the `kill the server` shape documented in
[`docs/namespace-model.md`](../../../docs/namespace-model.md#revocation).

Per-mount per-cap revocation (revoke the synthetic-root entry without
affecting the caller's copy of the same node) is not supported by
this scheme. Calling `cap_revoke` on `synthetic_root_cap` would
behave like `cap_revoke` on any tokened SEND derived from the
endpoint and trigger the kernel's per-cap revocation, which on the
namespace endpoint cascades to every sibling derivation — equivalent
to the destroy-driver hammer for callers' purposes. The two-derive
shape buys per-slot ownership for `cap_delete` ergonomics, not
per-cap revocation.

---

## Two endpoints, one process

vfsd holds two un-tokened endpoints:

- **Service endpoint** — `MOUNT`, `INGEST_CONFIG_MOUNTS`,
  `GET_SYSTEM_ROOT_CAP`. Multi-threaded recv (4 handlers today) so
  that a handler blocked on a worker pool order does not deadlock
  the system: `CREATE_FROM_FILE` for a fatfs respawn re-enters
  vfsd's namespace dispatcher (procmgr issues `FS_READ` against the
  caller-supplied file cap, which lands on a vfs node), which must
  remain serviceable while a service-thread is awaiting the mount
  transaction.
- **Namespace endpoint** — `NS_LOOKUP`, `NS_STAT`, `NS_READDIR`.
  Single dispatcher thread; the `NamespaceBackend` methods are
  bounded by `MAX_TREE_NODES` and the only blocking call is the
  optional fall-through `ipc_call`. The same endpoint is the
  kernel-derivation parent for every system-root cap vfsd ever
  issues via `cap_derive_token` (the synthetic root cap, plus a
  fresh cap per synthetic intermediate descent).

vfsd is also the owner of fs-process lifecycle: `MOUNT` spawns the
fatfs driver via `worker_pool` (or, on the very first mount, from
the boot module). The first-mount `CREATE_PROCESS` is permanent and
structural — `/bin/fatfs` is unreachable until root mounts, so
moving spawn responsibility elsewhere is a chicken-and-egg
inversion.

Wire-label numbers for both surfaces live in [`ipc::vfsd_labels`] and
[`ipc::ns_labels`].

---

## Lifetime

A successful `install` retains the `synthetic_root_cap` (terminal
nodes) and any walked `fallthrough_cap`s (synthetic intermediates)
for the lifetime of the vfsd process. Unmount is not implemented;
the mount-tree is permanent until vfsd exits. The deferred follow-
ups in [`TODO.md`](../../../TODO.md) cover per-process
`system_root_cap` distribution (different processes seeing different
roots) and `cap_revoke`-driven unmount.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | NS_* wire surface and dispatch crate |
| [docs/namespace-model.md](../../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing |
| [services/fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md) | Filesystem-driver-specific labels (FS_READ, FS_READ_FRAME, …) |
| [services/vfsd/docs/vfs-ipc-interface.md](vfs-ipc-interface.md) | vfsd service-endpoint surface (MOUNT, INGEST_CONFIG_MOUNTS) |

---

## Summarized By

[services/vfsd/README.md](../README.md)
