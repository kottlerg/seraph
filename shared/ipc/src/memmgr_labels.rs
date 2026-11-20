// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/memmgr_labels.rs

//! IPC labels for the memory manager (`memmgr`).
//!
//! memmgr owns the userspace RAM frame pool. All std-built processes
//! bootstrap their heap by calling `REQUEST_MEMORY_CAPS` on a badged SEND
//! cap installed in `ProcessInfo.memmgr_endpoint_cap`. Procmgr is the
//! privileged caller that registers and retires process badges.
//!
//! See `services/memmgr/docs/ipc-interface.md` for the authoritative wire
//! shape.

/// Allocate one or more Memory caps covering `want_pages` pages, or fewer
/// for a best-effort partial grant, whose caller requests the remainder
/// again; with `REQUIRE_CONTIGUOUS`, exactly one cap covering all
/// `want_pages`, or a failure. Callable from any badged cap;
/// [`super::memmgr_grant_layout`] checks the reply shape. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 1:
/// `REQUEST_MEMORY_CAPS`.
pub const REQUEST_MEMORY_CAPS: u64 = 1;
/// Return previously granted regions to the pool mid-life, named by the
/// opaque region id the grant reply reported, from any badged cap.
/// Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 2:
/// `RELEASE_MEMORY_CAPS`.
pub const RELEASE_MEMORY_CAPS: u64 = 2;
/// Procmgr-only: register a new process and receive the badged SEND cap
/// procmgr installs in the new process's `ProcessInfo.memmgr_endpoint_cap`.
/// `data[1]` carries the flags ([`REGISTER_PHYS_CLASS`],
/// [`REGISTER_RESERVE`], [`REGISTER_MAX`]), `data[2]` the memmgr badge of
/// the process whose budget node is the new node's parent (0 for a
/// top-level node), and `data[3]` the max in pages with [`REGISTER_MAX`].
/// The reply carries the badge in `data[0]` and the max the node took, after
/// memmgr's clamp, in `data[1]`, the process's SEND in `caps[0]`, and with
/// [`REGISTER_NODE_HANDLE`] the new node's handle in `caps[1]`. With
/// [`REGISTER_CHARGE_NODE`] the request's `caps[0]` is a node handle whose
/// node is the parent in place of `data[2]`'s. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 3:
/// `REGISTER_PROCESS`.
pub const REGISTER_PROCESS: u64 = 3;
/// [`REGISTER_PROCESS`] flag (`data[1]` bit 0): register the process
/// phys-class, so its grants keep `RIGHTS_MEM_PHYS`. procmgr sets it only
/// for a child created with
/// [`CREATE_PHYS_ACCESS`](super::procmgr_labels::CREATE_PHYS_ACCESS)
/// (devmgr and the IOMMU drivers).
pub const REGISTER_PHYS_CLASS: u64 = 1 << 0;
/// [`REGISTER_PROCESS`] flag (`data[1]` bit 1): the new budget node is in
/// the system reserve. memmgr refuses it under a parent outside the
/// reserve.
pub const REGISTER_RESERVE: u64 = 1 << 1;
/// [`REGISTER_PROCESS`] flag (`data[1]` bit 2): `data[3]` carries the new
/// budget node's max in pages, which memmgr clamps to what the parent and
/// every ancestor have left. Without it the node has no max.
pub const REGISTER_MAX: u64 = 1 << 2;
/// [`REGISTER_PROCESS`] flag (`data[1]` bit 3): the reply carries a node
/// handle ([`NODE_HANDLE_TAG`]) to the new process's budget node in
/// `caps[1]`.
pub const REGISTER_NODE_HANDLE: u64 = 1 << 3;
/// [`REGISTER_PROCESS`] flag (`data[1]` bit 4): the request's `caps[0]` is
/// a node handle ([`NODE_HANDLE_TAG`]), and the new budget node is made
/// under the node it names, `data[2]` being ignored. memmgr reads the
/// handle's badge with `SYS_ENDPOINT_BADGE` and refuses a cap that is not
/// a SEND on its endpoint carrying a live node handle's key.
pub const REGISTER_CHARGE_NODE: u64 = 1 << 4;
/// The bit of a memmgr process badge that marks a phys-class process
/// ([`REGISTER_PHYS_CLASS`]). memmgr draws the bits outside
/// [`VERB_BIT_MASK`](crate::VERB_BIT_MASK) at random and keeps every other
/// verb bit clear. init clears every verb bit in the badge it mints for
/// procmgr on memmgr's endpoint, so procmgr's own grants lack
/// `RIGHTS_MEM_PHYS` and its badge is no node handle.
pub const PHYS_CLASS_BADGE_BIT: u64 = 1 << 63;
/// Badge bit of a node handle: a SEND on memmgr's endpoint badged with
/// this bit and a random key, which names one budget node and is the
/// authority to serve the node labels ([`NODE_SET_MAX`] to
/// [`NODE_RELEASE`]) on it. No process badge carries it, so memmgr serves
/// the node labels only on a badge carrying it and the other labels only
/// on one without it, and refuses the rest with `UNAUTHORIZED`. Specified
/// in `services/memmgr/docs/ipc-interface.md` § Node Handles.
pub const NODE_HANDLE_TAG: u64 = 1 << 62;
const _: () = core::assert!(
    NODE_HANDLE_TAG & crate::VERB_BIT_MASK != 0 && NODE_HANDLE_TAG != PHYS_CLASS_BADGE_BIT
);
/// Badge bit of the swap authority: a SEND on memmgr's endpoint badged with
/// this bit alone, which init mints, is the authority to serve the swap
/// labels ([`SWAP_REGISTER`] to [`SWAP_WANTED`]), the swap service's
/// interface to memmgr's disk tier. No process badge or node handle carries
/// it, so memmgr serves the swap labels only on a badge carrying it and the
/// other labels only on one without it, and refuses the rest with
/// `UNAUTHORIZED`. Specified in `services/memmgr/docs/ipc-interface.md`
/// § Badge Discipline.
pub const SWAP_AUTHORITY: u64 = 1 << 61;
const _: () = core::assert!(
    SWAP_AUTHORITY & crate::VERB_BIT_MASK != 0
        && SWAP_AUTHORITY != NODE_HANDLE_TAG
        && SWAP_AUTHORITY != PHYS_CLASS_BADGE_BIT
);
/// Procmgr-only: notify process death. `data[0]` carries the dead process's
/// memmgr badge (no cap is required); memmgr reclaims every Memory cap
/// it had issued to that badge, runs coalescing, and clears the
/// per-process record. Idempotent on unknown badges.
pub const PROCESS_DIED: u64 = 4;
/// Procmgr-only: permanently transfer a batch of Memory caps into
/// memmgr's pool; the caller is procmgr's init reap (donated set:
/// `docs/process-lifecycle.md` § Init reap). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 5:
/// `DONATE_MEMORY_CAPS`.
pub const DONATE_MEMORY_CAPS: u64 = 5;
/// Read-only query of the all-RAM-accounted identity. Callable from any
/// badged cap; returns aggregate counts only — no caps, no state change.
///
/// Wire format: request carries no words. Reply (`SUCCESS`):
///
/// * `data[0]` — `system_ram_bytes`: total installed RAM the kernel
///   computed at boot (delivered to memmgr via the bootstrap facts).
/// * `data[1]` — `kernel_reserved_bytes`: the fixed kernel reserve
///   (`system_ram_bytes` minus every `owns_memory` page minted to init).
/// * `data[2]` — `pool_total_bytes`: every page memmgr owns, across free
///   runs, in-use bootstrap arenas, and reap donations.
/// * `data[3]` — `free_bytes`: the subset of `pool_total_bytes` currently
///   in free runs (owned by memmgr, lent to no process, grantable). Unlike
///   `pool_total` it falls on allocation and rises on reclamation
///   (`PROCESS_DIED`, `RELEASE_MEMORY_CAPS`, `UNREGISTER_REGION`) of a
///   frame no other process can still reach.
/// * `data[4]` — `deferred_bytes`: the subset of `pool_total_bytes`
///   reclaimed from a process but held out of the free runs because
///   another process can still reach it, through a capability to it, a
///   kernel object retyped from it, or a user mapping of it; it moves to
///   `free_bytes` once a later reclamation's recheck finds it
///   unreachable. A caller polls `free_bytes` and `deferred_bytes`
///   together to confirm a dead process's pages were reclaimed.
/// * `data[5]` — `largest_free_bytes`: the largest single free run.
/// * `data[6]` — `reserve_bytes`: the system reserve, the free pages only a
///   charge to a reserve node may take.
/// * `data[7]` — the memory-pressure level: [`PRESSURE_NORMAL`],
///   [`PRESSURE_LOW`] or [`PRESSURE_CRITICAL`]. A [`REGISTER_PRESSURE`]
///   bit says it changed; this read is the level.
/// * `data[8]` — `promised_bytes`: what the committed regions
///   ([`REGION_COMMIT`]) can still take from the free runs: their pages
///   that hold no frame yet, with bounds on the page tables and metadata
///   they can need. Every admission reads `data[3]` less this.
/// * `data[9]` — `store_bytes`: the subset of `pool_total_bytes` the
///   compressed store holds, the stored pages of every evicted chunk.
/// * `data[10]` — `swapped_bytes`: the pages of every evicted chunk, in
///   either tier (compressed in the store, being written, on disk, or
///   lost; a chunk held raw on its own frames for a swap slot counts once
///   written), which their processes' budget nodes stay charged for.
/// * `data[11]` — `growth_floor_bytes`: the free pages outside
///   `promised` a charge to a budget node outside the reserve may not take:
///   the system reserve and, while chunks are swapped, the restore headroom
///   above it, `data[6]` plus the lesser of `data[10]` and `data[6]`. What
///   such a node can still be granted is `data[3]` less `data[8]` less
///   this; the level is [`PRESSURE_CRITICAL`] at or below it.
/// * `data[12]` — `disk_bytes`: the pages of every chunk on disk, the
///   subset of `data[10]` the swap service's slots alone hold.
/// * `data[13]` — `swap_slots_free`: the swap slots registered and not
///   taken, `0` while no swap service is registered.
/// * `data[14]` — `evictions`: the evictions memmgr has begun, a count, not
///   bytes, that only moves up, wrapping. An eviction is the one way a chunk
///   leaves the resident state, so a reader that finds the same count
///   before and after making a range resident knows no chunk of it was
///   evicted, held raw or being evicted at the second read.
///
/// The all-RAM-accounted identity is `data[0] == data[1] + data[2]`: every
/// page of RAM is either fixed kernel reserve or in memmgr's pool, with no
/// invisible residue. A nonzero `data[0] - data[1] - data[2]` is leaked
/// "dark" memory. `data[3]` to `data[14]` are appended fields — readers
/// needing only the identity may ignore them.
pub const QUERY_POOL_STATUS: u64 = 6;
/// Register a demand-paged anonymous region for the calling process.
///
/// Universal label — attributed to the caller by `recv.badge` (the
/// per-process badge minted at [`REGISTER_PROCESS`], carried by the
/// badged SEND cap installed in `ProcessInfo.memmgr_endpoint_cap`).
/// memmgr records the region against that badge's tracking entry; a
/// later page fault inside a registered region is backed on demand by
/// the fault-handler arm, while a fault outside every registered region
/// is declined (the faulting thread is killed, or, for the fault of a
/// restartable syscall's user copy, that syscall fails with
/// `InvalidAddress`), preserving segfault semantics.
///
/// Wire format:
/// * `data[0]` — `va_base` (page-aligned virtual address).
/// * `data[1]` — `len_bytes` (region length; page-multiple, nonzero).
/// * `data[2]` — `prot` (MAP_* protection bits; W^X enforced).
/// * `data[3]` — flags: [`REGION_COMMIT`], [`REGION_NO_EVICT`]; 0 for none.
///
/// Reply: `memmgr_errors::SUCCESS`; `INVALID_ARGUMENT` (bad alignment,
/// zero length, W^X violation, unknown prot or flag bit, unknown badge, or
/// overlap); `QUOTA` (metadata arena could not grow — system RAM
/// exhausted); or, for a committed region, `LIMIT` or
/// `OUT_OF_MEMORY_BEST_EFFORT` when its commitment is refused. No mapping
/// is installed here — backing happens lazily on fault, and only once
/// procmgr has delegated the process `AddressSpace` cap via
/// [`DELEGATE_ASPACE`]. Reverse with [`UNREGISTER_REGION`]. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 7: `REGISTER_REGION`.
pub const REGISTER_REGION: u64 = 7;
/// [`REGISTER_REGION`] flag (`data[3]` bit 0): commit the region. memmgr
/// admits and charges its whole length when it registers it, so a fault
/// in it is declined only in the cases
/// `services/memmgr/docs/ipc-interface.md` § Committed fault declines
/// lists, and only a committed region grows by [`EXTEND_REGION`] or shrinks by
/// [`SHRINK_REGION`]. A reply that does not reach the caller undoes the
/// registration, so a caller whose call was interrupted makes it again.
/// The std heap grows this way.
pub const REGION_COMMIT: u64 = 1 << 0;
/// [`REGISTER_REGION`] flag (`data[3]` bit 1): memmgr never evicts a page
/// of the region into its compressed store, so every page a fault backed
/// stays mapped until the region is unregistered or discarded
/// (`services/memmgr/docs/ipc-interface.md` § Label 7).
pub const REGION_NO_EVICT: u64 = 1 << 1;
/// Procmgr-only: delegate a demand-paged child's `AddressSpace` cap to
/// memmgr so the pager can map frames into it on fault.
///
/// Sent at process finalize for demand-paged processes — the default;
/// not those created with the
/// [`CREATE_PINNED`](super::procmgr_labels::CREATE_PINNED) flag — after the child
/// address space exists (so it cannot ride on the earlier
/// [`REGISTER_PROCESS`] handshake).
/// memmgr stores the transferred cap against the child's tracking
/// entry, keyed by the badge minted at [`REGISTER_PROCESS`].
///
/// Wire format:
/// * `data[0]` — `child_memmgr_badge` (from the child's
///   `REGISTER_PROCESS` reply).
/// * `caps[0]` — the child `AddressSpace` cap (MAP rights); ownership
///   transfers to memmgr.
///
/// Reply: `memmgr_errors::SUCCESS`; `UNAUTHORIZED` (caller is not
/// procmgr); or `INVALID_ARGUMENT` (unknown badge or missing cap — a
/// stray transferred cap is dropped).
pub const DELEGATE_ASPACE: u64 = 8;

/// Unregister a demand-paged region previously [`REGISTER_REGION`]'d,
/// reclaiming every frame memmgr mapped inside it.
///
/// Universal label — attributed to the caller by `recv.badge`. memmgr
/// finds the exact-match region, unmaps each backing frame from the
/// caller's `AddressSpace`, returns the frame to the pool, and frees the
/// region. The reverse of [`REGISTER_REGION`] plus the on-fault backing;
/// used when a demand-paged stack (or other anonymous region) is torn down
/// mid-life — e.g. ruststd freeing a joined thread's guarded stack.
///
/// Wire format:
/// * `data[0]` — `va_base` (must equal the registered base).
/// * `data[1]` — `len_bytes` (must equal the registered length).
///
/// Reply: `memmgr_errors::SUCCESS`; `INVALID_ARGUMENT` (unknown badge or no
/// region matches `[va_base, len)` exactly).
pub const UNREGISTER_REGION: u64 = 9;

/// Read the caller's own budget usage, in pages. Universal label,
/// attributed by `recv.badge`; read-only.
///
/// Reply (`SUCCESS`): `data[0]` the pages charged to the caller's budget
/// node, `data[1]` its max (`u64::MAX` for none), `data[2]` the pages
/// charged to it and every node below it, `data[3]` the pages of `data[0]`
/// resident, and `data[4]` those swapped, in either tier, which the node
/// stays charged for. `INVALID_ARGUMENT` for an
/// unknown badge. Specified in `services/memmgr/docs/ipc-interface.md`
/// § Label 10: `QUERY_MEMORY_USAGE`.
pub const QUERY_MEMORY_USAGE: u64 = 10;

/// Register a Notification for the caller's memory-pressure signal.
/// Universal label, attributed by `recv.badge`.
///
/// Wire format:
/// * `data[0]` — the bits to send; nonzero.
/// * `caps[0]` — a Notification cap with Notify rights; ownership
///   transfers to memmgr.
///
/// On every change of the pressure level memmgr sends the bits on the
/// cap, without blocking; the receiver reads the level from
/// [`QUERY_POOL_STATUS`] `data[7]`. A process holds one registration: a
/// second replaces the first, and `PROCESS_DIED` drops it. The std runtime
/// registers every process at start.
///
/// Reply: `memmgr_errors::SUCCESS`; or `INVALID_ARGUMENT` (unknown badge,
/// zero bits, or `caps[0]` missing or not a Notification with Notify; the
/// cap is deleted). Specified in `services/memmgr/docs/ipc-interface.md`
/// § Label 11: `REGISTER_PRESSURE`.
pub const REGISTER_PRESSURE: u64 = 11;

/// Grow a committed region ([`REGION_COMMIT`]) of the caller in place, its
/// base kept. Universal label, attributed by `recv.badge`.
///
/// Wire format:
/// * `data[0]` — `va_base` (the registered base).
/// * `data[1]` — `new_len_bytes` (page-multiple, at least the length).
///
/// memmgr admits and charges the growth as a committed registration of
/// it. A reply that does not reach the caller undoes the growth, so a
/// caller whose call was interrupted makes it again.
///
/// Reply: `memmgr_errors::SUCCESS` (also for the current length);
/// `INVALID_ARGUMENT` (unknown badge, no committed region at `va_base`, a
/// length unaligned, smaller, or past the address space, or growth that
/// meets another region); `QUOTA`; `LIMIT`; or
/// `OUT_OF_MEMORY_BEST_EFFORT`. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 12: `EXTEND_REGION`.
pub const EXTEND_REGION: u64 = 12;

/// Lower the top of a committed region ([`REGION_COMMIT`]) of the caller,
/// its base kept. Universal label, attributed by `recv.badge`.
///
/// Wire format:
/// * `data[0]` — `va_base` (the registered base).
/// * `data[1]` — `new_len_bytes` (a nonzero multiple of the 64 KiB demand
///   chunk, at most the length).
///
/// memmgr unmaps the pages past the new top, takes back the frames that
/// backed them, and releases their commitment.
///
/// Reply: `memmgr_errors::SUCCESS` (also for the current length); or
/// `INVALID_ARGUMENT` (unknown badge, no committed region at `va_base`,
/// or a length that is zero, not a chunk multiple, or larger). Specified
/// in `services/memmgr/docs/ipc-interface.md` § Label 13:
/// `SHRINK_REGION`.
pub const SHRINK_REGION: u64 = 13;

/// Set the max of the handle's budget node, on a node handle
/// ([`NODE_HANDLE_TAG`]). `data[0]` is the max in pages, `u64::MAX` for
/// none; memmgr clamps it to the node's usage plus what its parent chain
/// has left. A max below the usage reclaims and kills nothing: it refuses
/// every later charge until the usage falls below it. Reply (`SUCCESS`):
/// `data[0]` the max the node took. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 14: `NODE_SET_MAX`.
pub const NODE_SET_MAX: u64 = 14;

/// Create a sub-node under the handle's budget node, on a node handle.
/// `data[0]` is its max in pages, `u64::MAX` for none, clamped as
/// [`NODE_SET_MAX`] clamps. Reply (`SUCCESS`): `data[0]` the max it took,
/// `caps[0]` its node handle. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 15: `NODE_CREATE`.
pub const NODE_CREATE: u64 = 15;

/// Read the usage of the handle's budget node, on a node handle. Reply
/// (`SUCCESS`): as [`QUERY_MEMORY_USAGE`], `data[0]` its own pages,
/// `data[1]` its max, `data[2]` its subtree's pages. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 16: `NODE_QUERY_USAGE`.
pub const NODE_QUERY_USAGE: u64 = 16;

/// Register a Notification for the limit event of the handle's budget
/// node, on a node handle. `data[0]` is the bits to send, nonzero;
/// `caps[0]` a Notification cap with Notify rights, whose ownership
/// transfers to memmgr; `caps[1]` the registrant's own memmgr SEND (a
/// copy), which names the process the registration goes with: memmgr
/// reads its badge with `SYS_ENDPOINT_BADGE`, deletes it, and drops the
/// registration when that process dies, when the handle state goes, or
/// when a later registration replaces it. memmgr sends the bits, without
/// blocking, when the node's subtree reaches its max or its max refuses a
/// charge. One registration per node: a second replaces the first.
/// Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 17:
/// `NODE_REGISTER_LIMIT`.
pub const NODE_REGISTER_LIMIT: u64 = 17;

/// Release a sub-node's handle state, on a node handle to a node made by
/// [`NODE_CREATE`] or [`CREATE_SUB_NODE`]: every handle to the node is
/// refused from then on, and the node goes once no process or charge
/// refers to it. Refused for a process's own node, whose handle state
/// goes with the process. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 18: `NODE_RELEASE`.
pub const NODE_RELEASE: u64 = 18;

/// Create a sub-node under the caller's own budget node, attributed by
/// `recv.badge`, so the caller can charge processes it creates to one
/// budget they share inside its own. `data[0]` and the reply as
/// [`NODE_CREATE`]. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 19: `CREATE_SUB_NODE`.
pub const CREATE_SUB_NODE: u64 = 19;

/// Bytes of one memmgr demand chunk, the unit a region's chunk table records
/// and `SHRINK_REGION` and [`DISCARD_RANGE`] cut and discard a region in,
/// counted from the region's base.
pub const DEMAND_CHUNK_BYTES: u64 = 64 * 1024;

/// Discard pages of a demand region of the caller, attributed by
/// `recv.badge`: memmgr unmaps them and takes back the frames that backed
/// them, and the next touch of a page of them faults in a zero-filled page.
/// A committed region keeps its commitment, so that touch is admitted as
/// its first was, and declined only in the cases
/// `services/memmgr/docs/ipc-interface.md` § Committed fault declines lists.
///
/// Wire format:
/// * `data[0]` — `va` (a whole number of 64 KiB demand chunks above the
///   region's base).
/// * `data[1]` — `len_bytes` (nonzero; a whole number of chunks, or
///   reaching the region's end).
///
/// Reply: `memmgr_errors::SUCCESS` (also for a range already discarded);
/// `INVALID_ARGUMENT` (unknown badge, no region holding `va`, or a range
/// that breaks the rule above or leaves the region); or `UNAUTHORIZED` (a
/// node handle). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 20: `DISCARD_RANGE`.
pub const DISCARD_RANGE: u64 = 20;

/// Procmgr-only: make a range of a process's demand regions resident, for a
/// debugger's read (`procmgr_labels::MAKE_RESIDENT`). memmgr restores each
/// evicted chunk of the range from its compressed store and maps it into
/// the process; a page no fault has backed stays not present.
///
/// Wire format:
/// * `data[0]` — the process's memmgr badge (from its `REGISTER_PROCESS`
///   reply).
/// * `data[1]` — `va`.
/// * `data[2]` — `len_bytes` (nonzero).
///
/// memmgr makes at most a few chunks resident per request and walks only
/// the chunks that have an entry. A chunk on disk it cannot restore itself:
/// with a swap service registered with a want Notification ([`SWAP_REGISTER`])
/// it posts the chunk's slot word to the swap service, which restores it ahead
/// of a fault ([`SWAP_WANTED`]), and the reply says the range is pending
/// there; a lost chunk, or one on disk with no swap service to ask, is passed
/// over.
///
/// Reply: `memmgr_errors::SUCCESS` with `data[0]` where memmgr stopped:
/// `va + len_bytes` when the whole range is done, else the address to send
/// the request again from; `data[1]` [`RESIDENT_PENDING`] when that
/// address is a chunk on disk the swap service was asked to restore, else
/// `0`; and `data[2]` where the walk stopped: `data[0]` when not pending,
/// else past every chunk on disk memmgr posted, from which a reader that will
/// wait no longer asks again, passing those chunks over;
/// `UNAUTHORIZED` (caller is not procmgr);
/// `INVALID_ARGUMENT` (unknown badge, zero length, or a range
/// past the address space); or `OUT_OF_MEMORY_BEST_EFFORT` (a chunk could
/// not be restored, for want of free RAM or a map). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 21: `MAKE_RESIDENT`.
pub const MAKE_RESIDENT: u64 = 21;
/// [`MAKE_RESIDENT`] reply `data[1]`: memmgr stopped at a chunk on disk whose
/// slot word it posted to the swap service; the sender asks again from
/// `data[0]` once the swap service has had time to restore it.
pub const RESIDENT_PENDING: u64 = 1;
/// Swap authority only ([`SWAP_AUTHORITY`]): register the swap service.
/// `caps[0`] is a SEND on the endpoint memmgr redirects each fault on an
/// on-disk chunk to; `data[0]` the swap slots the service's partition holds,
/// each [`DEMAND_CHUNK_BYTES`]; `caps[1]`, optional, a Notification with the
/// Notify right memmgr sends `data[1]` (nonzero) on when [`MAKE_RESIDENT`]
/// posts a slot word for the swap service to take with [`SWAP_WANTED`]. A
/// registration replaces the one before it and ends every write in flight,
/// each writing chunk staying in memmgr, compressed on its store runs or raw
/// on its runs.
/// Reply: `SUCCESS` with `data[0]` the slots memmgr uses; `INVALID_ARGUMENT`
/// when `caps[0]` is no endpoint cap, the count is below a slot ever taken,
/// or `caps[1]` is present and no Notification with the Notify right or
/// `data[1]` is zero.
/// Specified in `services/memmgr/docs/ipc-interface.md` § Label 22:
/// `SWAP_REGISTER`.
pub const SWAP_REGISTER: u64 = 22;
/// Swap authority only: take one evicted chunk for a swap slot. `caps[0]`
/// is a Memory cap of at least [`DEMAND_CHUNK_BYTES`] memmgr writes the
/// slot's bytes into (the chunk's stream, encrypted and authenticated under
/// memmgr's per-boot key, and its tag, or a chunk held raw because its
/// stream gained nothing, its backed pages sealed alone, memmgr keeping the
/// tag). Reply: `SUCCESS` with `data[0]` the
/// slot, `data[1]` its byte count and `data[2]` its slot word, the word a
/// fault on the chunk is redirected with, or an error code; `caps[0]` moved
/// back on every reply. Specified in `services/memmgr/docs/ipc-interface.md`
/// § Label 23: `SWAP_TAKE`.
pub const SWAP_TAKE: u64 = 23;
/// Swap authority only: end the write of a slot [`SWAP_TAKE`] named.
/// `data[0]` the slot, `data[1]` 0 when the slot is written, else nonzero.
/// Specified in `services/memmgr/docs/ipc-interface.md` § Label 24:
/// `SWAP_DONE`.
pub const SWAP_DONE: u64 = 24;
/// Swap authority only: hand memmgr a slot's bytes, read back for a fault
/// redirected to the swap service or ahead of one. `data[0]` the slot word
/// of the redirect or of [`SWAP_TAKE`]'s reply, `caps[0]` a Memory cap
/// holding the slot's bytes from offset 0. memmgr checks the tag, decrypts,
/// and makes the chunk resident. Reply: `SUCCESS`; `RESTORE_DECLINED` with
/// `data[0]` the decline word the swap service forwards the held fault
/// with; or `RESTORE_STALE` for a word that names no chunk on disk, after
/// which the swap service resumes the held fault; `caps[0]` moved back on
/// every reply.
/// Specified in `services/memmgr/docs/ipc-interface.md` § Label 25:
/// `SWAP_RESTORE`.
pub const SWAP_RESTORE: u64 = 25;
/// Swap authority only: take the slot words of the chunks on disk
/// [`MAKE_RESIDENT`] asked for, which memmgr posted since the last request,
/// oldest first, and empty memmgr's list of them. The swap service reads each
/// slot and hands memmgr its bytes with [`SWAP_RESTORE`], ahead of a fault.
/// Reply: `SUCCESS` with `data[0]` the count, at most
/// [`SWAP_WANTED_WORDS`], and the words in `data[1]` on. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 26: `SWAP_WANTED`.
pub const SWAP_WANTED: u64 = 26;
/// The most slot words memmgr holds for the swap service, and so the most one
/// [`SWAP_WANTED`] reply carries: a full list drops its oldest word for a new
/// one, which the reader posts again when it asks again.
pub const SWAP_WANTED_WORDS: u64 = 8;

/// [`QUERY_POOL_STATUS`] `data[7]`: the free pages no committed region is
/// promised are at or above the low threshold.
pub const PRESSURE_NORMAL: u64 = 0;
/// [`QUERY_POOL_STATUS`] `data[7]`: the free pages no committed region is
/// promised are below the low threshold.
pub const PRESSURE_LOW: u64 = 1;
/// [`QUERY_POOL_STATUS`] `data[7]`: the free pages no committed region is
/// promised are at or below the growth floor (the system reserve and, while
/// chunks are swapped, the restore headroom), so a grant to a process outside
/// the reserve is refused.
pub const PRESSURE_CRITICAL: u64 = 2;

/// `REQUEST_MEMORY_CAPS` flag: reply MUST contain exactly one Memory cap
/// covering all `want_pages`, or fail with
/// `memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS`. Bit position 0 within
/// the flags half of `data[0]`.
pub const REQUIRE_CONTIGUOUS: u32 = 1 << 0;
