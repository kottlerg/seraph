# Synthetic Root and Namespace Composition

vfsd is a namespace server that owns no on-disk storage. Its
[`NamespaceBackend`] implementation, [`VfsdRootBackend`], composes a
synthetic system root from per-mount driver namespace endpoints
captured at boot time and on each successful `MOUNT`. Clients holding
the system-root cap walk into mounted filesystems through this
composition; the cross-server reply mints them a freshly-attenuated cap
on the owning filesystem driver directly, after which vfsd is out of the
path.

---

## Authority

This document is authoritative for vfsd's namespace-server behavior:
the shape of the synthetic root, the mount-tree representation, the
mount-crossing mint that attenuates rights across a terminal mount, and
fall-through delegation to the root mount.

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
| `terminal_endpoint` | *Unbadged* SEND on the underlying driver's namespace endpoint, set on a node that is itself a mount point; zero on a synthetic intermediate. Each crossing `NS_LOOKUP` mints a fresh attenuated badged SEND from it |
| `fallthrough_cap` | Badged SEND on the root mount's namespace endpoint addressing the directory at this node's path in the root filesystem; zero if no such fall-through is available |

The synthetic root is `NodeId::ROOT` (pool index 0) and is always
active; its `fallthrough_cap` carries the root mount cap captured
when `MOUNT path="/"` succeeds. `MAX_TREE_NODES` is `32` and
`MAX_ENTRY_NAME` is `64` bytes; both are file-local constants in
[`services/vfsd/src/root_backend.rs`](../src/root_backend.rs).

Multi-component mount paths install through the tree by walking
components, creating synthetic intermediates on demand, and setting
`terminal_endpoint` on the final node. After install the caller
(`do_mount`) walks the root mount component-by-component via
`NS_LOOKUP` to populate each new intermediate's `fallthrough_cap`.
The in-tree mount set is the root mount (`/`) plus the single-component
`/esp` and `/data` auto-mounts; the multi-component install path
remains supported but is currently unexercised in production.

---

## NS_LOOKUP composition

`NS_LOOKUP(parent, name)` against any cap on vfsd's namespace
endpoint dispatches in two stages, from `vfsd::namespace_loop`:

1. **Local-child match.** [`VfsdRootBackend::lookup`] walks the
   parent node's child list. A match on a *terminal* child returns
   an [`EntryTarget::External`] view carrying the driver's unbadged
   endpoint and the peer root node; the namespace-protocol crate mints
   a fresh `cap_derive_badge` on that endpoint carrying the composed
   `parent_rights ∩ entry.max_rights ∩ caller_requested` rights. The
   reply cap belongs to the underlying filesystem driver's namespace
   endpoint; subsequent walks bypass vfsd entirely. A match on a
   *synthetic intermediate* child returns an [`EntryTarget::Local`]
   view; the protocol crate mints a `cap_derive_badge` on
   `namespace_ep` addressing the intermediate's `NodeId`, so the next
   `NS_LOOKUP` lands back on vfsd.

2. **Fall-through.** If no local child matches and the parent has a
   `fallthrough_cap`, vfsd's dispatcher (`try_forward_lookup_fallthrough`
   in `services/vfsd/src/main.rs`) forwards the `NS_LOOKUP` to the
   fall-through cap and replies with the upstream response. The
   request body is repacked before forwarding: vfsd extracts the
   caller's parent rights from the inbound cap's badge, intersects
   them with the request's `caller_requested` word
   (via `namespace_protocol::compose_forward_lookup_rights`), and
   writes the resulting mask into the outbound message's `word(0)`.
   The label, name bytes, and overall shape are preserved; the reply
   travels back unchanged. This is required because the fall-through
   cap was minted by vfsd's own walk and carries full namespace
   rights — the receiving fs driver composes its returned rights
   against the destination cap's badge, so without the repack the
   caller's attenuation would be discarded. Repacking preserves the
   `docs/namespace-model.md` § "Walking" invariant
   (walk-monotonic-attenuation) across mount boundaries: a child cap
   minted at the fs driver carries at most the caller's parent
   rights, intersected with the entry's `max_rights` ceiling.

   The fall-through preserves the namespace-model rule that root-fs
   entries remain reachable unless explicitly shadowed by a
   registered mount: paths like `/services/svcmgr` reach the root
   fs through the synthetic root's fall-through. Mount-point names
   take precedence so that a future `/services` mount (if installed)
   shadows the root-fs entry without changing the root filesystem's
   on-disk contents.

3. If neither stage matches, the dispatch loop falls through to the
   protocol crate, which replies `NotFound`.

`NS_READDIR` against a synthetic tree node enumerates its local
children first, then the fall-through directory's entries (skipping
any name shadowed by a local child), via
`try_forward_readdir_fallthrough` in `services/vfsd/src/main.rs`. A
listing therefore shows both the node's mounts and the underlying
root-fs contents, consistent with lookup fall-through. `NS_STAT`
against a synthetic node reports the node itself (a directory) and
does not consult the fall-through.

---

## Mount-crossing mint

A successful terminal `MOUNT` mints **one** badged SEND on the driver's
namespace endpoint at full rights — `caller_root_cap`, returned to the
`MOUNT` caller (or dropped on the internal `auto_mount_role` path that
handles the `/esp` and `/data` mounts without a synchronous caller). The
backend then retains the driver's **unbadged** namespace endpoint
(`driver_ep`) as the terminal node's `terminal_endpoint`.

Every `NS_LOOKUP` that crosses the mount mints a *fresh* badged SEND on
that endpoint carrying the composed
`parent_rights ∩ entry.max_rights ∩ caller_requested` rights (the
[`EntryTarget::External`] arm of `handle_lookup`). Storing the unbadged
endpoint — rather than a pre-badged root cap — is what carries
attenuation across the mount boundary: a node cap's rights live in its
badge, and the kernel forbids re-badging an already-badged cap
(`SYS_CAP_DERIVE_BADGE` rejects a badged source), so a stored badged cap
could only ever be `cap_derive`-copied at its original full rights,
laundering authority. The root mount is the exception — its
`fallthrough_cap` is a *badged* SEND on the root fs (see fall-through
above), safe because the forwarder pre-composes the caller's rights into
each forwarded request rather than minting a reply cap.

### Revocation

The supported revocation primitive for a mount is **destroy the fs
driver**: `cap_revoke` on the driver's namespace endpoint cascades
through the kernel derivation graph and invalidates every cap ever
derived from it — the `terminal_endpoint`, every per-lookup reply cap,
and the `MOUNT` caller's copy. This is the `kill the server` shape
documented in
[`docs/namespace-model.md`](../../../docs/namespace-model.md#revocation).
Retaining the unbadged endpoint in the backend (rather than leaking it,
as the pre-attenuation design did) means vfsd now holds that revocation
authority by name. Per-cap revocation — invalidating one issued node cap
without affecting its siblings — is not supported by this scheme.

---

## Two endpoints, one process

vfsd holds two un-badged endpoints:

- **Service endpoint** — `MOUNT` and `GET_SYSTEM_ROOT_CAP`.
  Multi-threaded recv (4 handlers today) so
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
  issues via `cap_derive_badge` (the synthetic root cap, plus a
  fresh cap per synthetic intermediate descent).

vfsd is also the owner of fs-process lifecycle: `MOUNT` spawns the
fatfs driver via `worker_pool` (or, on the very first mount, from
the boot module). The first-mount `CREATE_PROCESS` is permanent and
structural — `/services/fs/fatfs` is unreachable until root mounts, so
moving spawn responsibility elsewhere is a chicken-and-egg
inversion.

Wire-label numbers for both surfaces live in [`ipc::vfsd_labels`] and
[`ipc::ns_labels`].

---

## Lifetime

A successful `install` retains the `terminal_endpoint` (terminal
nodes) and any walked `fallthrough_cap`s (synthetic intermediates, plus
the root mount's badged fall-through cap) for the lifetime of the vfsd
process. Unmount is not implemented;
the mount-tree is permanent until vfsd exits. Deferred follow-ups:
per-process `system_root_cap` distribution (different processes
seeing different roots) and `cap_revoke`-driven unmount.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | NS_* wire surface and dispatch crate |
| [docs/namespace-model.md](../../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing |
| [services/fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md) | Filesystem-driver-specific labels (FS_READ, FS_READ_MEMORY, …) |
| [services/vfsd/docs/vfs-ipc-interface.md](vfs-ipc-interface.md) | vfsd service-endpoint surface (MOUNT, GET_SYSTEM_ROOT_CAP) |

---

## Summarized By

[services/vfsd/README.md](../README.md), [docs/storage.md](../../../docs/storage.md)
