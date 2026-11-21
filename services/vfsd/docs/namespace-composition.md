# Synthetic Root and Namespace Composition

vfsd is a namespace server that owns no on-disk storage. Its
`NamespaceBackend` implementation, `VfsdRootBackend`, composes a
synthetic system root from per-mount driver namespace endpoints
captured at boot time and on each successful `MOUNT`. Clients holding
the system-root cap walk into mounted filesystems through this
composition; the cross-server reply mints them a freshly-attenuated cap
on the owning filesystem driver directly, after which vfsd is out of the
path.

---

## Authority

This document is authoritative for vfsd's namespace-server behavior:
the shape of the synthetic root, the mount-tree representation and the
record each mount keeps, the mount-crossing mint that attenuates rights
across a terminal mount, and fall-through delegation to the root mount.

The wire protocol is defined by
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md).
The cap-as-namespace model is defined by
[`docs/namespace-model.md`](../../../docs/namespace-model.md).

---

## Synthetic root state

`VfsdRootBackend` owns a single tree of `TreeNode`s that grows on
vfsd's heap. Each node carries:

| Field | Purpose |
|---|---|
| `name` / `name_len` | Path component captured at install time |
| `parent` / `first_child` / `next_sibling` | Tree links |
| `slot` | The node's mount, with its state (§ Mount record): none, mounted, restarting, or being removed |
| `live` | Count of mounted and restarting mounts in the node's subtree, the node's own included; a node other than the root is *visible* exactly when it is non-zero |
| `fallthrough_cap` | Badged SEND on the root mount's namespace endpoint addressing the directory at this node's path in the root filesystem; zero if no such fall-through is available |

The synthetic root is `NodeId::ROOT` (pool index 0) and always
exists; its `fallthrough_cap` carries the root mount cap captured
when `MOUNT path="/"` succeeds. An install adds one node per path
component not yet in the tree, and nodes are never freed: a removed
mount leaves its node vacant and a later install reuses it, so a node's
pool index is its `NodeId` for the life of vfsd. A node is a *terminal*
when it holds a mounted mount, a *synthetic intermediate* when it holds
none but is visible, and *vacant* otherwise.
The tree holds at most `MAX_MOUNTS` (1023) mounts, the root mount and
those restarting or being removed included: each is one member of the watch set beside
the class watch (§ Driver death and device loss). An install past that
count, or one that cannot allocate its nodes, is refused and leaves the
tree unchanged; no fixed count bounds the nodes. A component follows the
namespace protocol's name rule (`namespace_protocol::validate_name`, at
most `MAX_NAME_LEN`, 255 bytes), and a `MOUNT` path is bounded only by
the bytes the request carries (`MAX_MOUNT_PATH_LEN`; see
[`vfs-ipc-interface.md`](vfs-ipc-interface.md#label-10-mount)). The tree
is the `vfsd-root-backend` crate
([`services/vfsd/root-backend/src/lib.rs`](../root-backend/src/lib.rs)).

Multi-component mount paths install through the tree by walking
components, creating synthetic intermediates on demand, and storing the
mount record on the final node. After install the caller
(`do_mount`) walks the root mount component-by-component via
`NS_LOOKUP` to populate the `fallthrough_cap` of each intermediate the
install made visible (a node it created, or a vacant node it reused) that
has none. Only one install makes a node visible, so concurrent `MOUNT`s
never walk for the same node, and the tree refuses a walked cap for a node
that has one by then, which vfsd deletes.
The in-tree mount set is the root mount (`/`) plus the single-component
`/esp` and `/data` auto-mounts; svctest's unmount phases exercise the
multi-component install path by mounting the data partition at
`/config/svcmgr/tests`.

### Mount record

Every mount, the root mount included, keeps one record on the node it
is mounted on (`root_backend::Mount`), holding what vfsd needs to reach
the mount's driver and to tear it down:

| Field | Holds |
|---|---|
| `cap` | The cap the tree resolves the mount through: below `/`, the *unbadged* SEND on the driver's namespace endpoint (§ Mount-crossing mint); for `/`, the badged SEND on the root fs, also the synthetic root's `fallthrough_cap` |
| `endpoint` | The driver's service endpoint as vfsd created it, from which every cap on it derives (§ Revocation) |
| `process` | procmgr's process handle for the driver, from the create reply |
| `death_queue` | `RECV` on the driver's death queue (below) |
| `partition` | The partition cap virtio-blk returned on `REGISTER_PARTITION`; the driver holds a `cap_derive` (`SEND_GRANT`) of it, so `cap_revoke_all` on this cap cuts the driver off the partition |
| `disk` | The index, in vfsd's disk list, of the disk that holds the partition |
| `first_lba` | The partition's first LBA on that disk; with `disk`, it names the partition, so a `MOUNT` of a partition a record holds, mounted or being removed, is refused before its driver is spawned and one driver serves a partition |

The death queue is an event queue of capacity 1 with no death-observer
node. The create request carries a `POST`-only derivation of the queue
under `CREATE_DEATH_RELAY`, to which procmgr posts the driver's end
once, after its teardown, whoever ends it, a terminal fault in any of
its threads included, with the one exit reason procmgr gives the process
([procmgr IPC
interface](../../procmgr/docs/ipc-interface.md#label-1-create_process)
§ Label 1, **Death relay**). That post is the queue's only entry. vfsd
binds no thread of the driver to the queue, and deletes the create
reply's `Thread` cap unused: a thread's own end is the process's only
when it is the first
([docs/process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason)
§ Exit reason), so a main-thread binding could post a reason the driver
did not end with ahead of the relay's. Both spawn paths,
`CREATE_PROCESS` from the boot module and `CREATE_FROM_FILE`, carry the
relay. While lookups cross the mount, the queue is a member of the watch
set, and its death restarts the mount's driver or ends the mount
(§ Driver restart); an unmount waits on it for the driver's death
(§ Unmount).

A record is in one of three states. While *mounted*, lookups cross it.
While *restarting*, its driver has died and vfsd is starting another
(§ Driver restart): the node stays visible, so its name never falls
through to the root filesystem, and a lookup that would cross it is
answered `IoError`. Removing a mount below `/` takes two steps:
`VfsdRootBackend::begin_unmount` moves the record to *being removed*,
after which no lookup crosses it and no install may take the node, and
`VfsdRootBackend::remove_mount` clears the record once the caller has
torn the driver down, leaving the node vacant unless a mount below it
keeps it visible as an intermediate.
`VfsdRootBackend::restore_mount` instead moves a record being removed
back to *mounted*, when the driver refuses the unmount. The tree keeps a
restart budget with each record (§ Driver restart), which a restore keeps.
The root mount is never removed or restarted: its loss ends vfsd (§ Driver
death and device loss).
`NS_LOOKUP`, `NS_READDIR`, the shadowing of fall-through entries, and a
node's child count skip a node that is not visible, so the name of a
vacant node, or of a node whose own mount is being removed with no
mount below it, falls through to the root filesystem as an absent name
does. Only those two requests fall through: `NS_STAT` on a synthetic
node is answered locally (§ NS_LOOKUP composition), and any other
request on one is answered `NotSupported`, so nothing is created on the
root filesystem through one. An `UNMOUNT` (§ Unmount), a driver's
death once its mount's restart budget is spent, and a disk's loss (§ Driver
death and device loss) are the callers of `begin_unmount`; a restart that
cannot start its driver ends as a removal too (§ Driver restart).

A `MOUNT` that fails after its driver started releases what its record
would have held: it revokes and deletes the partition cap, revokes the
driver's service endpoint (which stops the driver), and deletes the
process handle and the death queue.

### Unmount

`UNMOUNT` ([`vfs-ipc-interface.md`](vfs-ipc-interface.md#label-11-unmount) § Label 11) removes
the mount at a path in this order:

1. `find` the path's node and `begin_unmount` it, so no lookup crosses the mount from here on,
   taking its death queue out of the watch set in the same hold (§ Driver death and device loss).
   A node with no mount, or one whose removal or restart is under way, is refused, as is `/`.
2. Send the driver `FS_UNMOUNT` on a SEND derived from the record's `endpoint`, bounded by a
   timeout, with `UNMOUNT_FORCE` when the request carries it. A `BUSY` answer to an unforced
   request ends the unmount: `restore_mount` puts the record back, and its death queue back in
   the watch set, and vfsd replies `BUSY`. When the mount's disk was lost meanwhile, vfsd then
   unmounts the mount as the loss does (§ Driver death and device loss) and replies `NO_MOUNT`.
3. Otherwise, whether the driver answered `SUCCESS` (it has released every open and exits),
   anything else, or nothing in time, tear the driver down without relying on it: revoke and
   delete the record's `partition`, so the driver reaches the disk no more; revoke and delete
   its `endpoint`, which invalidates every cap derived from it (§ Revocation) and stops a driver
   still receiving; wait, bounded, for the death on the record's `death_queue`; then send
   `DESTROY_PROCESS` on the record's `process`, which a driver that exited takes as a no-op, and
   delete the process handle and the death queue.
4. `remove_mount` the record. When the node stays visible because a mount below it remains, it
   is now a synthetic intermediate with no fall-through cap (`needs_fallthrough`); vfsd walks the
   root mount for it as an install walks for the intermediates it makes visible. Then reply
   `SUCCESS`.

Only the request that began a node's removal ends it, so a concurrent `MOUNT` at the path is
refused (`TABLE_FULL`) and a concurrent `UNMOUNT` of it finds the removal under way (`NO_MOUNT`)
until then. The node stays in the tree with its index, and a later `MOUNT` at the path installs
on it.

### Driver death and device loss

Once it has spawned the service threads, vfsd's main thread is the *watch thread*: it waits on one
wait set, the *watch set*, of `WAIT_SET_MAX_MEMBERS` (1024) members, made whole at startup so no
growth replaces it under the blocked waiter. The set holds vfsd's watch of devmgr's `block` class
(`devmgr_labels::WATCH_CLASS`, registered before the startup discovery, so no change after it is
missed) and the death queue of every mount lookups cross; its size is what bounds the tree to
`MAX_MOUNTS` (§ Synthetic root state). A death or a class change from before the thread first
waits stays pending in the set.

Whoever begins a mount's removal (an `UNMOUNT`, a death, a loss) or its restart (a death) takes
the mount's death queue out of the set in the same hold of the tree's lock as `begin_unmount` or
`begin_restart`; a refused `UNMOUNT` puts the queue back in the hold that restores the mount, a
`MOUNT` adds it in the hold that installs the mount, and a restart adds the new driver's queue in
the hold that ends the restart. The watch thread acts on a readiness only when, in one hold, the
queue belongs to a mount lookups cross and yields a death entry, so a readiness taken before another
remover claimed the mount, or one for a node a later mount reuses, finds nothing to act on.

- **A driver's death.** The watch thread claims the mount: it begins its restart (§ Driver
  restart), or, when the mount's restart budget is spent, its removal, and tears it down without
  the driver, which no longer answers: it revokes the partition cap and the driver's service
  endpoint, as an unmount does (§ Unmount), destroys what is left of the process, and removes the
  record. The path then falls through to the root filesystem. Either way every cap a client held
  through the mount dies. The thread then probes the mount's disk, since a driver whose block
  device was revoked exits at its next block request
  ([docs/storage.md](../../../docs/storage.md#failure-and-revocation-invariants) § Failure and
  Revocation Invariants).
- **A change of the class.** devmgr signals the watch when it serves a block driver and when it
  withdraws one. The watch thread probes every held disk. A discovery of new disks (before a
  runtime role lookup) probes each once it is held, since devmgr can withdraw one after discovery
  asked about it and before the watch thread can see it held.
- **The probe** asks devmgr about the disk's instance ordinal (`QUERY_DEVICE` on the `block`
  class); `WITHDRAWN` means the disk is gone for good, since devmgr never serves an ordinal
  again. The probe does not call the disk's own cap: devmgr takes a removed device's driver out of
  its class, signalling the watches, before it revokes the driver's endpoint
  ([devmgr hotplug](../../devmgr/docs/hotplug.md#removal) § Removal), and a call on a driver that is
  live but wedged would block the watch thread.
- **A disk's loss.** A disk found withdrawn is marked removed: its whole-disk cap is deleted and
  its partitions leave every role lookup, while it keeps its index in the disk list, which the
  records of its mounts name. Each mount on it is claimed and unmounted as a forced `UNMOUNT` is
  (§ Unmount): `FS_UNMOUNT` with `UNMOUNT_FORCE`, bounded, then the teardown, whether the driver
  answered or not. An idle driver, or one serving from its page cache, has touched no block since
  the removal and has not exited; the class watch is what sees its disk go. A mount the claims
  passed, because a `MOUNT` installed it or a refused `UNMOUNT` restored it after them, is torn
  down the same way by that request, which checks the disk after the install or the restore and
  replies `NO_MOUNT`; the disk is marked removed before the claims, so the claims or that check
  see the mount. The claims pass a mount that is restarting, whose restart checks the disk
  itself (§ Driver restart).
- **The root.** Once vfsd has mounted the root, before it serves anything, it sends
  `DECLINE_RESTART` on its `block` class SEND for the root disk's ordinal, so devmgr does not
  restart that disk's driver. The death of the root mount's driver, or the loss of its disk, ends
  vfsd: it logs `FATAL: root filesystem lost` with the cause and exits with code 1 through
  `sys_aspace_exit`, which ends the whole process whichever thread makes it
  ([docs/process-lifecycle.md](../../../docs/process-lifecycle.md#exit-reason)
  § Exit reason). vfsd is critical and never restarted
  ([vfsd.svc](../../../rootfs/config/svcmgr/services/vfsd.svc)), so svcmgr shuts the system down
  ([docs/supervision.md](../../../docs/supervision.md)).

### Driver restart

A mount below `/` whose driver dies is restarted in place, in the revoke-and-re-resolve shape
([docs/supervision.md](../../../docs/supervision.md#restart-shapes) § Restart Shapes): a node cap's
badge names state in the dead instance, which a new one cannot honour. The root mount is never
restarted: its driver's death ends vfsd (§ Driver death and device loss).

- **Budget.** The tree keeps a restart budget with each mount's record
  ([shared/restart-budget](../../../shared/restart-budget/README.md): `RESTART_BURST`, 3,
  restarts in a `RESTART_WINDOW_NS`, 60 s, window). A `MOUNT` starts it whole; a restart, and a
  refused `UNMOUNT`'s restore, keep it. A death that finds it spent tears the mount down, as
  § Driver death and device loss says.
- **Begin.** In the hold that takes the death, the watch thread charges the budget and holds the
  mount *restarting* (`VfsdRootBackend::begin_restart`), and takes its death queue out of the set.
  While restarting, the mount is crossed by no lookup and its name stays visible: a lookup that
  would cross it is answered `IoError`, never resolved through the root filesystem, an `UNMOUNT`
  of it is answered `NO_MOUNT` and a `MOUNT` at its path `TABLE_FULL`, as during a removal, and
  a disk's loss passes it. The watch thread then tears the dead instance down: it revokes what the
  driver held of the partition, keeping the record's `partition` for the next driver; revokes and
  deletes the driver's service endpoint, which invalidates every cap derived from it, every cap a
  client holds through the mount among them, so each fails closed; and destroys what is left of the
  process and deletes its handle and death queue. It starts the new driver on a thread of its own,
  since that start reads the root filesystem and can block, while the watch thread must stay free
  to see the root's death and a disk's loss.
- **Start.** The restart thread checks that the disk is not removed, derives a new partition cap
  from the record's `partition`, and starts a driver on a new service endpoint, with a new death
  queue, as a runtime `MOUNT` does: from the installed `/services/fs/fatfs`, through
  `CREATE_FROM_FILE`, never from the boot module, named `fatfs:` and the mount's path, and
  probed with `FS_MOUNT`. Every spawn, a `MOUNT`'s and a restart's, ends: the wait for the new
  driver's bootstrap round ends at its death, and the probe at a bound (`PROBE_TIMEOUT_MS`,
  10 s), after which a driver that did not answer is destroyed.
- **End.** In one hold the new driver's death queue joins the set and its record replaces the dead
  one's (`VfsdRootBackend::finish_restart`); lookups cross into it from then on, so a client
  resolves the mount's path again and reaches the new driver. The thread then checks the disk again,
  as a `MOUNT` does after its install, and tears the mount down as a forced `UNMOUNT` when the
  disk was lost meanwhile.
- **Failure.** A removed disk, a driver that does not start, or a death queue the set refuses ends
  the restart as a removal (`VfsdRootBackend::abandon_restart`): the partition cap is revoked and
  the record removed as at the end of an unmount, and the path falls through to the root
  filesystem.

A disk added or inserted again is a new driver at a new ordinal. vfsd mounts none of its
partitions on its own: each runtime role lookup first queries devmgr for the disks served since
the last query and holds them, so a `MOUNT` resolves its role across every disk devmgr serves
([`vfs-ipc-interface.md`](vfs-ipc-interface.md#label-10-mount) § Label 10).

---

## NS_LOOKUP composition

`NS_LOOKUP(parent, name)` against any cap on vfsd's namespace
endpoint dispatches in two stages, from `vfsd::namespace_loop`:

1. **Local-child match.** `VfsdRootBackend::lookup` walks the
   parent node's visible children (§ Mount record). A match on a child
   whose mount is restarting is answered `IoError` (§ Driver restart). A
   match on a *terminal* child returns
   an `EntryTarget::External` view carrying the driver's unbadged
   endpoint and the peer root node; the namespace-protocol crate
   ([`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
   § NS_LOOKUP) mints a fresh `cap_derive_badge` on that endpoint carrying the
   composed `parent_rights ∩ entry.max_rights ∩ caller_requested` rights. The
   reply cap belongs to the underlying filesystem driver's namespace
   endpoint; subsequent walks bypass vfsd entirely. A match on a
   *synthetic intermediate* child returns an `EntryTarget::Local`
   view; the protocol crate mints a `cap_derive_badge` on
   `namespace_ep` addressing the intermediate's `NodeId`, so the next
   `NS_LOOKUP` lands back on vfsd.

2. **Fall-through.** If no local child matches and the parent has a
   `fallthrough_cap`, vfsd's dispatcher (`try_forward_lookup_fallthrough`
   in `services/vfsd/src/main.rs`) forwards the `NS_LOOKUP` to the
   fall-through cap and replies with the upstream response, or with
   `IoError` when the call has not returned within `FALLTHROUGH_TIMEOUT_MS`
   (10 s). The
   request body is repacked before forwarding: vfsd extracts the
   caller's parent rights from the inbound cap's badge, intersects
   them with the request's `caller_requested` word
   (via `namespace_protocol::compose_forward_lookup_rights`), and
   writes the resulting mask into the outbound message's `word(0)`.
   The label, name bytes, and overall shape are preserved; the reply
   travels back unchanged. This is required because the fall-through
   cap was minted by vfsd's own walk and carries full namespace
   rights — the receiving fs driver composes its returned rights
   against the destination cap's badge
   ([`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
   § NS_LOOKUP), so without the repack the
   caller's attenuation would be discarded. Repacking keeps walking
   monotonically attenuating across mount boundaries, as
   [`docs/namespace-model.md`](../../../docs/namespace-model.md#cross-server-entries)
   § Cross-server entries requires of a forwarder: a child cap minted
   at the fs driver carries at most the caller's parent rights,
   intersected with the entry's `max_rights` ceiling.

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
(`driver_ep`) as the `cap` of the terminal node's mount record.

Every `NS_LOOKUP` that crosses the mount mints a *fresh* badged SEND on
that endpoint carrying the composed
`parent_rights ∩ entry.max_rights ∩ caller_requested` rights (the
`EntryTarget::External` arm of `handle_lookup`; see
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md)
§ NS_LOOKUP). Storing the unbadged
endpoint — rather than a pre-badged root cap — is what carries
attenuation across the mount boundary
([`docs/namespace-model.md`](../../../docs/namespace-model.md#cross-server-entries)
§ Cross-server entries): a node cap's rights live in its
badge, and the kernel forbids re-badging an already-badged cap
(`SYS_CAP_DERIVE_BADGE` rejects a badged source; see
[`docs/capability-model.md`](../../../docs/capability-model.md#kernel-guarantees)
§ Kernel guarantees), so a stored badged cap
could only ever be `cap_derive`-copied at its original full rights,
laundering authority. The root mount is the exception — its
`fallthrough_cap` is a *badged* SEND on the root fs (see fall-through
above), safe because the forwarder pre-composes the caller's rights into
each forwarded request rather than minting a reply cap.

### Revocation

The supported revocation primitive for a mount is **destroy the fs
driver**: `cap_revoke` on the driver's namespace endpoint cascades
through the kernel derivation graph and invalidates every cap ever
derived from it — the mount record's `cap`, every per-lookup reply cap,
and the `MOUNT` caller's copy. This is the `kill the server` shape
documented in
[`docs/namespace-model.md`](../../../docs/namespace-model.md#revocation).
That authority is the driver's original endpoint (a driver's service and
namespace endpoint are one), which vfsd keeps in the mount record
(`endpoint`, § Mount record): the record's `cap`, the root mount's
badged fall-through cap, and the driver's own receive copy all derive
from it. The driver's block-device authority is revoked the same way,
through the record's `partition`, from which the driver's partition cap
derives.
Revoking a cap the backend retains reaches only that cap's descendants,
not the driver's receive copy, so it does not stop the server.
Per-cap revocation — invalidating one issued node cap without affecting
its siblings — is not supported by this scheme.

---

## Two endpoints, one process

vfsd holds two un-badged endpoints:

- **Service endpoint** — `MOUNT`, `UNMOUNT`, `GET_SYSTEM_ROOT_CAP` and
  `GET_SWAP_PARTITION`. Multi-threaded recv (`SERVICE_THREAD_COUNT`
  handlers) so that independent requests proceed while one handler
  waits on a fatfs spawn. The count is a concurrency knob, not a
  correctness bound: no service-endpoint request waits on another's
  IPC, since what a `MOUNT` handler blocks on (the worker pool,
  procmgr's `CREATE_FROM_FILE`, whose `FS_READ_MEMORY`s go to the fs driver
  that minted the file cap, the `/services/fs/fatfs` walk the namespace
  dispatcher serves, the new driver's bootstrap round, which its death ends, and the `FS_MOUNT`
  probe, within a bound) and what an `UNMOUNT`
  handler blocks on (the driver's `FS_UNMOUNT` and its death, each
  within a bound, procmgr's `DESTROY_PROCESS`, and the root-mount walk
  for a fall-through cap) never calls the service endpoint, and neither
  does the discovery of new disks a `MOUNT` and the first
  `GET_SWAP_PARTITION` run before their role lookup: devmgr's
  `QUERY_DEVICE`, the GPT reads of each new disk on its block driver, a
  scratch page from memmgr when a failed read lost the one held, and
  the forced unmount of a mount on a new disk found withdrawn, which
  blocks as an `UNMOUNT` does. A `GET_SWAP_PARTITION` also waits for
  the discovery lock, held across one discovery, and for the swap lock,
  which its holder keeps across the first request's discovery and one
  `REGISTER_PARTITION` call to the block driver. Neither devmgr, nor
  memmgr, nor a block driver calls vfsd. A request past the last free
  handler waits in the endpoint queue.
- **Namespace endpoint** — `NS_LOOKUP`, `NS_STAT`, `NS_READDIR`.
  Single dispatcher thread; the `NamespaceBackend` methods are
  in-memory walks of one node's children or ancestors, and the only
  blocking call is the optional fall-through call, bounded by
  `FALLTHROUGH_TIMEOUT_MS` (10 s): a root driver that stops answering
  holds the dispatcher up to that bound per fall-through call, so a
  lookup queued behind such calls waits up to the bound for each of them,
  and a lookup that crosses another mount never reaches the root driver
  itself. The same endpoint is the kernel-derivation parent for every
  system-root cap vfsd ever
  issues via `cap_derive_badge` (the synthetic root cap, plus a
  fresh cap per synthetic intermediate descent).

At startup vfsd spawns the namespace dispatcher first, then self-mounts
root, `/esp`, and `/data`, then spawns the service threads, and its
main thread becomes the watch thread (§ Driver death and device loss). The
dispatcher runs first because the `/esp` and `/data` mounts take the
post-boot fatfs spawn path: vfsd resolves `/services/fs/fatfs` with an
`NS_LOOKUP` walk through its own system-root cap, which re-enters the
namespace endpoint, before handing the file cap to procmgr's
`CREATE_FROM_FILE`. Service threads start only after the self-mounts,
so `GET_SYSTEM_ROOT_CAP` is never served against an unmounted root; its
reply contract, including `NO_MOUNT` when the root self-mount failed,
is specified in [`vfs-ipc-interface.md`](vfs-ipc-interface.md).

vfsd is also the owner of fs-process lifecycle: `MOUNT` spawns the
fatfs driver via `worker_pool` (or, on the very first mount, from the
boot module). Each create names its binary for procmgr's verification
by its install path, `/services/fs/fatfs`, the boot module's name and the
on-disk file's alike. Each driver's `argv[0]` is `fatfs:` and its mount path
(`fatfs:/`, `fatfs:/data`), the name procmgr's `LIST_PROCESSES` reports
for it. The first-mount `CREATE_PROCESS` is permanent and structural —
`/services/fs/fatfs` is unreachable until root mounts, so moving spawn
responsibility elsewhere is a chicken-and-egg inversion.

Wire-label numbers for both surfaces live in `ipc::vfsd_labels` and
`ipc::ns_labels`.

---

## Lifetime

A successful `install` stores the mount's record (§ Mount record) and
any walked `fallthrough_cap`s (synthetic intermediates, plus the root
mount's badged fall-through cap); the tree keeps them until the mount is
removed, and the record's caps are vfsd's to release. A mount below `/`
lasts until an `UNMOUNT` (§ Unmount), its driver's death with its
restart budget spent, a restart that fails (§ Driver restart), or its
disk's loss (§ Driver death and device loss) removes it, which releases the
record's caps, a restart replacing the driver's caps in the record and
keeping its partition cap; the root mount, and a node's walked `fallthrough_cap`,
last until vfsd exits, which the root mount's loss makes it do. Per-process
`system_root_cap` distribution (different processes seeing different
roots) is not implemented.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | NS_* wire surface and dispatch crate |
| [docs/namespace-model.md](../../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing |
| [services/fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md) | Filesystem-driver-specific labels (FS_READ, FS_READ_MEMORY, …) |
| [services/vfsd/docs/vfs-ipc-interface.md](vfs-ipc-interface.md) | vfsd service-endpoint surface (MOUNT, UNMOUNT, GET_SYSTEM_ROOT_CAP, GET_SWAP_PARTITION) |

---

## Summarized By

[Storage](../../../docs/storage.md), [services/fs/README.md](../../fs/README.md),
[services/vfsd/README.md](../README.md)
