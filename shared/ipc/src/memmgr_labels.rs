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
/// `want_pages`, or a failure. Callable from any badged cap but a node
/// handle, the swap authority or an object handle;
/// [`super::memmgr_grant_layout`] checks the reply shape. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 1:
/// `REQUEST_MEMORY_CAPS`. With [`REQUEST_CHARGE_NODE`] the grant is
/// charged to the node of the node handle in `caps[0]`.
pub const REQUEST_MEMORY_CAPS: u64 = 1;
/// Return previously granted regions to the pool mid-life, named by the
/// opaque region id the grant reply reported, from any badged cap but a
/// node handle, the swap authority or an object handle. Specified in
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
/// authority to serve the node labels ([`is_node_label`]) on it. No process
/// badge carries it, so memmgr serves the node labels only on a badge
/// carrying it and the other labels only on one without it, and refuses the
/// rest with `UNAUTHORIZED`. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Node Handles.
pub const NODE_HANDLE_TAG: u64 = 1 << 62;
const _: () = core::assert!(
    NODE_HANDLE_TAG & crate::VERB_BIT_MASK != 0 && NODE_HANDLE_TAG != PHYS_CLASS_BADGE_BIT
);
/// Badge bit of a charge-only node handle, beside [`NODE_HANDLE_TAG`] and
/// the key of the node's handles: [`NODE_CHARGE_HANDLE`] returns one. It
/// names the same node, which a grant may be charged to
/// ([`REQUEST_CHARGE_NODE`]) and whose usage it may read, but it serves only
/// the charge-only labels ([`is_charge_only_label`]), refusing the other node
/// labels with `UNAUTHORIZED`, and is no node handle to `REGISTER_PROCESS`
/// ([`REGISTER_CHARGE_NODE`]). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Node Handles.
pub const NODE_CHARGE_ONLY: u64 = 1 << 59;
const _: () = core::assert!(
    NODE_CHARGE_ONLY & crate::VERB_BIT_MASK != 0
        && NODE_CHARGE_ONLY != NODE_HANDLE_TAG
        && NODE_CHARGE_ONLY != PHYS_CLASS_BADGE_BIT
        && NODE_CHARGE_ONLY != SWAP_AUTHORITY
        && NODE_CHARGE_ONLY != OBJECT_HANDLE_TAG
);
/// Whether `opcode` is a node label, which memmgr serves only on a node
/// handle ([`NODE_HANDLE_TAG`]): [`NODE_SET_MAX`] to [`NODE_RELEASE`],
/// [`NODE_SET_RECLAIM`] and [`NODE_CHARGE_HANDLE`]. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Badge Discipline.
#[must_use]
pub const fn is_node_label(opcode: u64) -> bool
{
    core::matches!(
        opcode,
        NODE_SET_MAX..=NODE_RELEASE | NODE_SET_RECLAIM | NODE_CHARGE_HANDLE
    )
}
/// Whether `opcode` is a node label memmgr serves on a charge-only node
/// handle ([`NODE_CHARGE_ONLY`]): [`NODE_QUERY_USAGE`] and
/// [`NODE_CHARGE_HANDLE`]. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Badge Discipline.
#[must_use]
pub const fn is_charge_only_label(opcode: u64) -> bool
{
    core::matches!(opcode, NODE_QUERY_USAGE | NODE_CHARGE_HANDLE)
}
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
/// Badge bit of an object handle: a SEND on memmgr's endpoint badged with
/// this bit and a random key, which names one memory object
/// ([`SEAL_OBJECT`]). It is the authority to attach the object
/// ([`ATTACH_OBJECT`]), to read its pages ([`OBJECT_READ`]) and to back the
/// caller's own pages with copies of them ([`FILL_REGION`]), each of which
/// is sent on the caller's own memmgr SEND and takes the handle as a cap, and
/// to release the object's handle state ([`OBJECT_RELEASE`], the object label
/// of [`is_object_label`]), which is sent on the handle itself. No process
/// badge, node handle or swap authority carries it, so memmgr serves the
/// object label only on a badge carrying it and the other labels only on one
/// without it, and refuses the rest with `UNAUTHORIZED`. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Object Handles.
pub const OBJECT_HANDLE_TAG: u64 = 1 << 60;
const _: () = core::assert!(
    OBJECT_HANDLE_TAG & crate::VERB_BIT_MASK != 0
        && OBJECT_HANDLE_TAG != SWAP_AUTHORITY
        && OBJECT_HANDLE_TAG != NODE_HANDLE_TAG
        && OBJECT_HANDLE_TAG != PHYS_CLASS_BADGE_BIT
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
/// badged cap but a node handle, the swap authority or an object handle;
/// returns aggregate counts only — no caps, no state change.
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
///   level bit says it changed; this read is the level.
/// * `data[8]` — `promised_bytes`: what the committed regions
///   ([`REGION_COMMIT`]) can still take from the free runs: their pages
///   that hold no frame yet, with bounds on the page tables and metadata
///   they can need. A commitment is admitted against `data[3]` plus
///   `data[15]` less this; every other admission reads the free pages
///   outside `promised`, `data[17]`.
/// * `data[9]` — `store_bytes`: the subset of `pool_total_bytes` the
///   compressed store holds, the stored pages of every evicted chunk.
/// * `data[10]` — `swapped_bytes`: the pages of every evicted chunk, in
///   either tier (compressed in the store, being written, on disk, or
///   lost; a chunk held raw on its own frames for a swap slot counts once
///   written), which their processes' budget nodes stay charged for.
/// * `data[11]` — `growth_floor_bytes`: the free pages outside
///   `promised` a charge to a budget node outside the reserve may not take:
///   the system reserve and, while chunks of uncommitted regions are
///   swapped, the restore headroom above it, `data[6]` plus the lesser of
///   their swapped pages (`data[10]` less those of committed regions) and
///   `data[6]`. What
///   such a node can still be granted is the free pages outside `promised`
///   (`data[17]`) less this; the level is [`PRESSURE_CRITICAL`] at or below
///   it.
/// * `data[12]` — `disk_bytes`: the pages of every chunk on disk, the
///   subset of `data[10]` the swap service's slots alone hold.
/// * `data[13]` — `swap_slots_free`: the swap slots registered and not
///   taken, `0` while no swap service is registered.
/// * `data[14]` — `evictions`: the evictions memmgr has begun, a count, not
///   bytes, that only moves up, wrapping. An eviction is the one way a chunk
///   leaves the resident state, so a reader that finds the same count
///   before and after a `MAKE_RESIDENT` walk over a range that completed
///   with no reply pending knows no chunk of the range was being evicted,
///   held raw, compressed or being written at the second read. A chunk on
///   disk or lost can remain: `data[10]` counts both, `data[12]` only a
///   chunk on disk.
/// * `data[15]` — `allowance_bytes`: the overcommit allowance, what
///   `promised` may exceed `data[3]` by: a chunk's pages for every free
///   swap slot (`data[13]`), less the pages compression already freed from
///   the chunks evicted and not on disk, plus the pages of the evicted
///   chunks of committed regions, which `data[8]` holds again; `0` while
///   no swap service is registered.
/// * `data[16]` — `draw_room_bytes`: the free pages a fault on a committed
///   page of a process outside the system reserve may take now: all of
///   `data[3]` while no swap slot is registered or `data[3]` covers
///   `data[8]`, else those above the growth floor, `data[11]`. memmgr declines such a
///   fault as a commit overrun (decline code 11) when it finds none. The
///   draw room is open at [`DEMAND_CHUNK_BYTES`] or more, room for any one
///   committed draw (a fault's, or the restore of a committed chunk), and a
///   [`REGISTER_PRESSURE`] draw-room bit says it opened.
/// * `data[17]` — `uncommitted_free_bytes`: the free pages outside
///   `promised`, which a charge that takes frames now may take and the
///   pressure level reads: `data[3]` plus `data[15]` less `data[8]`, and
///   at most `data[3]`. While `data[15]` is `0` it is `data[3]` less
///   `data[8]`; with an allowance it can be all of `data[3]`.
/// * `data[18]` — `committed_swapped_bytes`: the part of `data[8]` the
///   evicted chunks of committed regions hold for their restores, the subset
///   of `data[10]` in committed regions. An eviction or a restore of such a
///   chunk moves `data[8]` and this alike, so `data[8]` less this is the
///   promised total net of eviction.
/// * `data[19]` — `cspace_used_slots`: the used slots of memmgr's own
///   `CSpace`, a count, not bytes. memmgr funds its `CSpace` from its pool,
///   so a cap it kept by mistake raises this for good rather than wedge it.
///
/// The all-RAM-accounted identity is `data[0] == data[1] + data[2]`: every
/// page of RAM is either fixed kernel reserve or in memmgr's pool, with no
/// invisible residue. A nonzero `data[0] - data[1] - data[2]` is leaked
/// "dark" memory. `data[3]` to `data[19]` are appended fields — readers
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
/// * `data[0]` — the bits to send on a change of the pressure level;
///   nonzero, within the low 32 bits.
/// * `data[1]` — the bits to send on an opening of the draw room
///   (`QUERY_POOL_STATUS` `data[16]`), within the low 32 bits; `0` for
///   none.
/// * `caps[0]` — a Notification cap with Notify rights; ownership
///   transfers to memmgr.
///
/// memmgr sends the level bits on the cap on every change of the pressure
/// level and the draw-room bits on every opening of the draw room, without
/// blocking; the receiver reads the level from [`QUERY_POOL_STATUS`]
/// `data[7]` and the draw room from `data[16]`. A process holds one registration: a
/// second replaces the first, and `PROCESS_DIED` drops it. The std runtime
/// registers every process at start.
///
/// Reply: `memmgr_errors::SUCCESS`; or `INVALID_ARGUMENT` (unknown badge,
/// zero level bits, a bit of either mask above the low 32, or `caps[0]` missing or not a Notification with Notify; the
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
/// has left, and on a reserve sub-node ([`SUB_NODE_RESERVE`]) first to the
/// node's current max, so that max only falls. A max below the usage reclaims and kills
/// nothing: it refuses every later charge until the usage falls below it.
/// Reply (`SUCCESS`): `data[0]` the max the node took. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 14: `NODE_SET_MAX`.
pub const NODE_SET_MAX: u64 = 14;

/// Create a sub-node under the handle's budget node, on a node handle.
/// `data[0]` is its max in pages, `u64::MAX` for none, clamped as
/// [`NODE_SET_MAX`] clamps; `data[1]` its flags, [`SUB_NODE_RESERVE`] or
/// none, any other bit refused `INVALID_ARGUMENT`. Reply (`SUCCESS`):
/// `data[0]` the max it took, `caps[0]` its node handle. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 15: `NODE_CREATE`.
pub const NODE_CREATE: u64 = 15;

/// [`NODE_CREATE`] and [`CREATE_SUB_NODE`] flag (`data[1]`): make the
/// sub-node in the system reserve, so a charge to it may take the free pages
/// a node outside the reserve must leave. Honoured only under a reserve
/// parent and with a finite max, which bounds what the sub-node's subtree can
/// take of the reserve and which [`NODE_SET_MAX`] may lower but never raise;
/// refused `INVALID_ARGUMENT` otherwise. Specified in
/// `services/memmgr/docs/memory-pool.md` § Distribution policy, **System
/// reserve**.
pub const SUB_NODE_RESERVE: u64 = 1;

/// Read the usage of the handle's budget node, on a node handle. Reply
/// (`SUCCESS`): as [`QUERY_MEMORY_USAGE`], `data[0]` its own pages,
/// `data[1]` its max, `data[2]` its subtree's pages; `data[3]` its floor
/// and `data[4]` its weight ([`NODE_SET_RECLAIM`]), and `data[5]` its
/// subtree's evictable resident pages, which the floor is held against.
/// Specified in
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
/// refers to it. A grant charged to the node ([`REQUEST_CHARGE_NODE`])
/// stays charged there until its holder releases it; each holder's
/// [`REGISTER_DONATION_END`] registration is signalled. Refused for a process's own node, whose handle state
/// goes with the process. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 18: `NODE_RELEASE`.
pub const NODE_RELEASE: u64 = 18;

/// Create a sub-node under the caller's own budget node, attributed by
/// `recv.badge`, so the caller can charge processes it creates to one
/// budget they share inside its own. `data[0]`, `data[1]` and the reply as
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
/// the process, and maps an attachment's page with no copy of its own to its
/// origin, read-only; a page of an ordinary region no fault has backed stays
/// not present.
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
/// when `caps[0]` is no endpoint cap, the count is 0 or below a slot ever
/// taken, or `caps[1]` is present and no Notification with the Notify right or
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

/// Seal grants of the caller, attributed by `recv.badge`, into an immutable
/// memory object. `data[0]` is the count of grants, 1 to
/// [`SEAL_OBJECT_MAX_GRANTS`], and the words after it name each by the region
/// id its grant reply reported, in the order of the object's pages. The caller
/// hands back the grants' Memory caps with the request, as for
/// [`RELEASE_MEMORY_CAPS`], and has unmapped them: memmgr seals only grants
/// no process holds a cap to, maps or has retyped, and otherwise changes
/// nothing. A grant charged to a node handle's node ([`REQUEST_CHARGE_NODE`]),
/// whose charge the object, which outlives the caller, could not return,
/// refuses the seal whole. The frames stay charged to the caller's budget
/// node until the object is freed. Reply: `SUCCESS` with `data[0]` the
/// object's pages and `caps[0]` an object handle ([`OBJECT_HANDLE_TAG`]);
/// `INVALID_ARGUMENT` (unknown badge, a count out of range, an id that names
/// no grant of the caller or is named twice, a grant charged to a node
/// handle's node, or a grant still held, mapped or retyped);
/// `UNAUTHORIZED` (a phys-class caller); `QUOTA` (memmgr's metadata or
/// `CSpace` is full, or its object zone holds no span of the object's pages);
/// or `OUT_OF_MEMORY_BEST_EFFORT` (memmgr could not map its own read-only
/// view of the frames, which every sealed object keeps). A reply that does
/// not reach the caller undoes the seal.
/// Specified in `services/memmgr/docs/ipc-interface.md` § Label 27:
/// `SEAL_OBJECT`.
pub const SEAL_OBJECT: u64 = 27;
/// The most grants one [`SEAL_OBJECT`] names: the data words after the count.
pub const SEAL_OBJECT_MAX_GRANTS: u64 = 63;
/// Attach pages of a memory object as a region of the caller, attributed by
/// `recv.badge`. `caps[0]` is the object handle ([`OBJECT_HANDLE_TAG`]),
/// which memmgr deletes, or absent for the zero object, whose every page reads
/// as zeros. `data[0]` the region's base, `data[1]` its length in bytes (both
/// page-aligned, the length nonzero), `data[2]` its protection (`MAP_READ`,
/// `MAP_WRITABLE`, `MAP_EXECUTABLE`, never writable and executable both,
/// and never executable for the zero object), `data[3]` the object page the
/// region starts at (0 for the zero object), and `data[4]` the flags
/// ([`ATTACH_PRIVATE`]). A shared attachment maps the object's pages and is
/// never writable; a private one maps them until the caller writes a page,
/// which then gets a copy of its own. A text write of
/// `SYS_THREAD_WRITE_MEM` to an object page is refused while the page maps
/// the object's frame; [`MAKE_PRIVATE`] gives the page a copy first. The
/// caller's budget node is charged the region's length and its page-table
/// reservation either way, and a private attachment is committed as
/// [`REGION_COMMIT`] commits a region, so a fault in it is declined only in
/// the cases `services/memmgr/docs/ipc-interface.md` § Committed fault
/// declines lists. Reply: `SUCCESS`; `INVALID_ARGUMENT` (unknown
/// badge, a bad range, protection or flag, a cap that is no live object
/// handle, pages past the object's end, or a range overlapping a region of the
/// caller); `LIMIT` or `OUT_OF_MEMORY_BEST_EFFORT` as for a committed
/// `REGISTER_REGION`, `LIMIT` also for an object attached as often as
/// memmgr lets one be or a zero-object region longer than one zero frame
/// backs (§ Memory objects, Mapping bound, of
/// `services/memmgr/docs/memory-pool.md`), split into shorter ones; or
/// `QUOTA`. A reply that does not reach the caller
/// detaches the region again. [`UNREGISTER_REGION`] detaches it. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 28: `ATTACH_OBJECT`.
pub const ATTACH_OBJECT: u64 = 28;
/// [`ATTACH_OBJECT`] flag (`data[4]` bit 0): attach the pages private, so
/// a write to one copies it for the caller alone. Without it the attachment
/// is shared and `MAP_WRITABLE` is refused.
pub const ATTACH_PRIVATE: u64 = 1 << 0;
/// Release an object handle's state, on an object handle: every handle to the
/// object is refused from then on, and the object's frames are freed once no
/// region attaches it. The sealer's death releases every object it sealed the
/// same way. Reply: `SUCCESS`, or `INVALID_ARGUMENT` for a handle already
/// released. Specified in `services/memmgr/docs/ipc-interface.md` § Label 29:
/// `OBJECT_RELEASE`.
pub const OBJECT_RELEASE: u64 = 29;
/// procmgr only: give each page of a range of a process's attachments that
/// maps its object's frame, or its zero frame, a copy of its own, as a write
/// fault in a private attachment does, so a debugger's text write of
/// `SYS_THREAD_WRITE_MEM` patches the process alone. The copy keeps the
/// region's protection.
///
/// Wire format:
/// * `data[0]` — the process's memmgr badge (from its `REGISTER_PROCESS`
///   reply).
/// * `data[1]` — `va`.
/// * `data[2]` — `len_bytes` (nonzero).
///
/// Pages outside every attachment, and pages with a copy already, are passed
/// over. A shared attachment's copy is promised a page as it is made; a
/// private one's was promised when it attached.
///
/// Reply: `memmgr_errors::SUCCESS` with `data[0]` where memmgr stopped:
/// `va + len_bytes` when the whole range is done, else the address to send
/// the request again from, memmgr making at most a few copies per request;
/// `UNAUTHORIZED` (caller is not procmgr); `INVALID_ARGUMENT` (unknown badge,
/// zero length, or a range past the address space); `QUOTA` (memmgr's
/// metadata is full); or `OUT_OF_MEMORY_BEST_EFFORT` (a shared attachment's
/// copy is refused a page, as a committed `REGISTER_REGION` is, or a copy
/// could not be made or mapped). Specified in `services/memmgr/docs/ipc-interface.md` § Label 30:
/// `MAKE_PRIVATE`.
pub const MAKE_PRIVATE: u64 = 30;
/// Procmgr-only: describe every page of a process's regions, and copy the
/// content memmgr holds of them into Memory caps the request carries, for
/// `SNAPSHOT` (`procmgr_labels::SNAPSHOT`). memmgr walks the process's
/// regions in `[cursor, end)`, demand regions and attachments alike, and
/// describes each region (its extent and the arguments that made it), then
/// each of its chunks: a chunk with an entry, and each chunk of an attachment
/// of an object other than the image the request names, by what memmgr holds
/// of each page; whole chunks with no entry by one range, whose pages are what
/// the region's origin gives. It writes the pages it holds bytes of into the
/// next pages of the destination, in page order: a chunk's backed pages from
/// its frames when it is resident, being evicted, or raw, decoded from its
/// store when it is compressed, and an attachment's pages with no copy of their
/// own from the object, for an object other than the image. It maps nothing
/// into the process, draws no frame, and evicts nothing. A chunk on disk it
/// posts to the swap service, as [`MAKE_RESIDENT`] does, and reports
/// pending; a lost one, one on disk with no swap service to ask, and one it
/// cannot read (its stored bytes fail to decode, or its frames or store runs
/// cannot be mapped) it reports with its backed pages unwritten.
///
/// Wire format (`crate::memmgr_capture`):
/// * `data[0]` — the process's memmgr badge (from its `REGISTER_PROCESS`
///   reply).
/// * `data[1]` — the cursor, where the walk starts: page-aligned, and the
///   base of a chunk when it lies in a region.
/// * `data[2]` — the end, past the cursor, aligned as the cursor is.
/// * `data[3]` — flags: [`CAPTURE_COUNT`], [`CAPTURE_IMAGE`], or 0.
/// * `data[4]` — the page offset into `caps[0]` where the destination starts.
/// * `data[5 + i]` — the destination pages of `caps[i]`, from that offset for
///   `caps[0]`.
/// * `caps` — Memory caps with the map and write rights, then, with
///   [`CAPTURE_IMAGE`], the process's image object handle; memmgr deletes
///   each once it has served the request.
///
/// Reply: `memmgr_errors::SUCCESS` with `data[0]` the cursor the next
/// request goes on from (the end when the walk is done), `data[1]` the
/// destination pages written, `data[2]` the destination pages the chunk at
/// `data[0]` needs when the walk stopped for want of them (else 0),
/// `data[3]` the descriptor count, and the descriptors from `data[4]`
/// (`memmgr_capture::Descriptor`). With [`CAPTURE_COUNT`]: `data[0]` the
/// cursor, `data[1]` the pages a copy request would write that the process
/// does not map, and `data[2]` the chunks on disk walked whose slot word
/// memmgr posted. `UNAUTHORIZED` (caller is not procmgr); `INVALID_ARGUMENT`
/// (unknown badge, an end not past the cursor, a cursor or an end inside a
/// chunk, a flag bit not defined, a page count missing for a cap, or an image
/// handle that names no live object); `OUT_OF_MEMORY_BEST_EFFORT` (a
/// destination page could not be mapped). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 31: `CAPTURE_CHUNKS`.
pub const CAPTURE_CHUNKS: u64 = 31;
/// [`CAPTURE_CHUNKS`] request `data[3]` bit: copy nothing, count the pages a
/// copy would write that the process does not map and the chunks on disk,
/// posting each chunk on disk to the swap service. The request carries no
/// destination cap.
pub const CAPTURE_COUNT: u64 = 1;
/// [`CAPTURE_CHUNKS`] request `data[3]` bit: the last cap is the process's
/// image object handle, whose attachments memmgr describes as the image's
/// pages and does not copy.
pub const CAPTURE_IMAGE: u64 = 1 << 1;

/// Set the floor and the weight of the handle's budget node, on a node
/// handle ([`NODE_HANDLE_TAG`]). `data[0]` is the floor in pages, 0 for
/// none: eviction never takes the evictable resident pages of the node's
/// subtree below it. `data[1]` is the weight, [`NODE_WEIGHT_MIN`] to
/// [`NODE_WEIGHT_MAX`]: above its floor the subtree is reclaimed from in
/// proportion to the pages it holds above the floor over its weight. Neither
/// reserves a free page or changes admission. Reply (`SUCCESS`): `data[0]`
/// the floor and `data[1]` the weight the node took. `INVALID_ARGUMENT` (no
/// live handle state, or a weight out of range). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 32: `NODE_SET_RECLAIM`.
pub const NODE_SET_RECLAIM: u64 = 32;
/// The least weight [`NODE_SET_RECLAIM`] takes: reclaimed from fastest.
pub const NODE_WEIGHT_MIN: u32 = 1;
/// The weight of a node none was set on.
pub const NODE_WEIGHT_DEFAULT: u32 = 100;
/// The greatest weight [`NODE_SET_RECLAIM`] takes: reclaimed from
/// `NODE_WEIGHT_MAX` times slower than a node of [`NODE_WEIGHT_MIN`] holding
/// as much above its floor.
pub const NODE_WEIGHT_MAX: u32 = 10_000;

/// [`QUERY_POOL_STATUS`] `data[7]`: the free pages no committed region is
/// promised are at or above the low threshold.
pub const PRESSURE_NORMAL: u64 = 0;
/// [`QUERY_POOL_STATUS`] `data[7]`: the free pages no committed region is
/// promised are below the low threshold.
pub const PRESSURE_LOW: u64 = 1;
/// [`QUERY_POOL_STATUS`] `data[7]`: the free pages no committed region is
/// promised are at or below the growth floor (the system reserve and, while
/// chunks are swapped, the restore headroom), so a grant charged to a budget
/// node outside the reserve is refused.
pub const PRESSURE_CRITICAL: u64 = 2;

/// `REQUEST_MEMORY_CAPS` flag: reply MUST contain exactly one Memory cap
/// covering all `want_pages`, or fail with
/// `memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS`. Bit position 0 within
/// the flags half of `data[0]`.
pub const REQUIRE_CONTIGUOUS: u32 = 1 << 0;

/// `REQUEST_MEMORY_CAPS` flag (bit 1 of the flags half of `data[0]`):
/// `caps[0]` is a node handle, full or charge-only ([`NODE_CHARGE_ONLY`]),
/// and the grant is charged to its node, admitted against that node's chain
/// (`memmgr_errors::LIMIT` at a max), not to the caller's. The pages are the
/// caller's to map and release as any grant's; the caller is counted a holder
/// of the node, signalled by [`REGISTER_DONATION_END`] when the node's handle
/// state ends. memmgr reads the handle's badge with `SYS_ENDPOINT_BADGE` and
/// deletes it, and refuses a cap that is not a SEND on its endpoint carrying
/// a live node handle's key. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 1.
pub const REQUEST_CHARGE_NODE: u32 = 1 << 1;

/// Return a charge-only handle ([`NODE_CHARGE_ONLY`]) to the handle's budget
/// node, on a node handle, full or charge-only. Reply (`SUCCESS`): `caps[0]`
/// the charge-only handle, which lives as the handle state does. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 33: `NODE_CHARGE_HANDLE`.
pub const NODE_CHARGE_HANDLE: u64 = 33;

/// Register `caps[0]`, a Notification cap with Notify rights whose ownership
/// transfers to memmgr, to receive the bits `data[0]`, nonzero, when the
/// handle state of a node the caller holds grants charged to
/// ([`REQUEST_CHARGE_NODE`]) ends: on [`NODE_RELEASE`] or at its owner's
/// death. One registration per process: a second replaces the first, whose
/// cap memmgr deletes; it goes when the process does. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 34:
/// `REGISTER_DONATION_END`.
pub const REGISTER_DONATION_END: u64 = 34;

/// Copy pages of a memory object into Memory caps the request carries, sent
/// on the caller's own memmgr SEND. `caps[0]` is the object handle
/// ([`OBJECT_HANDLE_TAG`]), the authority to read the object, which memmgr
/// reads with `SYS_ENDPOINT_BADGE`, so the reply comes from memmgr whoever
/// handed the caller the handle.
///
/// Wire format:
/// * `data[0]` — the first object page to copy.
/// * `data[1]` — the page offset into `caps[1]` at which the destination
///   starts.
/// * `data[2 + i]` — the destination pages of `caps[1 + i]`, from that
///   offset for `caps[1]`.
/// * `caps[0]` — the object handle.
/// * `caps[1..]` — Memory caps with the map and write rights, at most
///   `syscall_abi::MSG_CAP_SLOTS_MAX` less one; none to read only the
///   reply's words.
///
/// memmgr deletes every cap, whatever the reply.
///
/// memmgr copies the object's pages from `data[0]` on, in order, into the
/// destination, at most [`OBJECT_READ_PAGES`] of them and none past the
/// object's end. Reply: `SUCCESS` with `data[0]` the pages copied,
/// `data[1]` the object's flags ([`OBJECT_CHECKPOINT`]) and `data[2]` its
/// pages; `INVALID_ARGUMENT` (no cap, a cap that is no live object handle,
/// a first page past the object's end, or a destination page count missing
/// for a cap); `UNAUTHORIZED` (a badge that is a handle or the swap
/// authority); or `OUT_OF_MEMORY_BEST_EFFORT` (a destination page could not
/// be mapped). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 35: `OBJECT_READ`.
pub const OBJECT_READ: u64 = 35;
/// The most pages one [`OBJECT_READ`] copies.
pub const OBJECT_READ_PAGES: u64 = 64;
/// [`OBJECT_READ`] reply flag (`data[1]` bit 0): the object carries the
/// checkpoint mark ([`MARK_CHECKPOINT`]).
pub const OBJECT_CHECKPOINT: u64 = 1 << 0;

/// Back pages of chunks of the caller's own regions with copies of a memory
/// object's pages, as a write fault backs a page, attributed by
/// `recv.badge`. `caps[0]` is the object handle ([`OBJECT_HANDLE_TAG`]),
/// which memmgr deletes.
///
/// Wire format:
/// * `data[0]` — the first object page the copies take.
/// * `data[1]` — `n`, the chunks, 1 to [`FILL_CHUNKS`].
/// * `data[2 + 2i]` — chunk `i`'s base: a chunk's base in a demand region
///   of the caller, or in a private attachment of the zero object; the
///   chunks in ascending order.
/// * `data[3 + 2i]` — chunk `i`'s page mask, bit `j` for its page `j`,
///   none past the chunk's pages.
///
/// Each page a mask names takes the next object page, in chunk and page
/// order, so the request copies as many object pages as its masks name bits.
/// The page is backed, charged and mapped as a write fault backs it; a page
/// no mask names stays as it is, and so does a named page that holds data
/// already, its object page passed over: a repeat of a request, after a
/// failure part way or a reply that did not arrive, backs only the named
/// pages still holding none. Reply: `SUCCESS` with
/// `data[0]` the pages backed; `INVALID_ARGUMENT` (unknown badge, no
/// delegated address space, a count out of range, a base off a chunk of such
/// a region or not above the one before, mask bits past a chunk, a cap that
/// is no live object handle, object pages past its end, or a named page
/// holding no data in a chunk that is not resident); `UNAUTHORIZED`
/// (a badge that is a handle or the swap authority); `LIMIT`,
/// `OUT_OF_MEMORY_BEST_EFFORT` or `QUOTA` as for the fault that would back
/// the page, and `OUT_OF_MEMORY_BEST_EFFORT` when the request's own draws
/// evicted a chunk it names, the pages before staying backed; the
/// `INVALID_ARGUMENT` refusals come before anything is backed. Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 36: `FILL_REGION`.
pub const FILL_REGION: u64 = 36;
/// The most chunks one [`FILL_REGION`] names: a bound on the pages one
/// request backs, 64, as for [`OBJECT_READ_PAGES`].
pub const FILL_CHUNKS: u64 = 4;

/// procmgr only: mark a memory object as a checkpoint. `caps[0]` is the
/// object handle and `caps[1]` the account, a SEND on memmgr's endpoint;
/// memmgr deletes both. memmgr marks the object when the handle names a live
/// object and the account's badge is that of the process record that sealed
/// it; the mark stays with the object for its life, and [`OBJECT_READ`]
/// reports it. Reply: `SUCCESS`; `INVALID_ARGUMENT` (a cap missing, a
/// handle that names no live object, or an account that is not memmgr's or
/// names another record than the object's sealer); or `UNAUTHORIZED` (the
/// caller is not procmgr). Specified in
/// `services/memmgr/docs/ipc-interface.md` § Label 37: `MARK_CHECKPOINT`.
pub const MARK_CHECKPOINT: u64 = 37;

/// Whether `opcode` is an object label, served only over an object handle
/// ([`OBJECT_HANDLE_TAG`]): [`OBJECT_RELEASE`] alone. The labels that
/// answer about an object (`OBJECT_READ`, `FILL_REGION`) take its handle
/// as a cap on the caller's own memmgr SEND instead, so a process never
/// relies on an answer from a cap another party handed it.
#[must_use]
pub const fn is_object_label(opcode: u64) -> bool
{
    opcode == OBJECT_RELEASE
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_node_labels_are_node_set_max_to_node_release_node_set_reclaim_and_node_charge_handle()
    {
        for op in NODE_SET_MAX..=NODE_RELEASE
        {
            assert!(is_node_label(op), "label {op}");
        }
        assert!(is_node_label(NODE_SET_RECLAIM));
        assert!(is_node_label(NODE_CHARGE_HANDLE));
        for op in [
            NODE_SET_MAX - 1,
            CREATE_SUB_NODE,
            SWAP_REGISTER,
            OBJECT_RELEASE,
            REGISTER_DONATION_END,
        ]
        {
            assert!(!is_node_label(op), "label {op}");
        }
    }

    // Defect guarded: a label that answers about an object served over a
    // handle another party handed the caller, which may be a SEND on that
    // party's own endpoint answering in memmgr's place.
    #[test]
    fn the_only_object_label_is_object_release()
    {
        assert!(is_object_label(OBJECT_RELEASE));
        for op in [
            OBJECT_READ,
            SEAL_OBJECT,
            ATTACH_OBJECT,
            FILL_REGION,
            MARK_CHECKPOINT,
            MAKE_PRIVATE,
        ]
        {
            assert!(!is_object_label(op), "label {op}");
        }
    }

    #[test]
    fn a_charge_only_handle_is_served_node_query_usage_and_node_charge_handle_alone()
    {
        for op in 0..=MARK_CHECKPOINT
        {
            let served = op == NODE_QUERY_USAGE || op == NODE_CHARGE_HANDLE;
            assert_eq!(is_charge_only_label(op), served, "label {op}");
            assert!(!is_charge_only_label(op) || is_node_label(op), "label {op}");
        }
    }
}
