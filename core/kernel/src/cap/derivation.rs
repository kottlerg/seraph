// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/derivation.rs

//! Global derivation tree lock and tree manipulation.
//!
//! The derivation tree tracks parent/child relationships between capability
//! slots across all `CSpaces.` All mutations require the write lock; traversals
//! require the read lock.
//!
//! The lock is spin-based: sufficient for single-threaded boot and
//! forward-compatible with SMP — no changes to call sites when SMP is added.
//!
//! ## State encoding
//!
//! - `state == 0`: unlocked
//! - `0 < state < u32::MAX`: that many concurrent readers hold the lock
//! - `state == u32::MAX`: one writer holds the lock
//!
//! ## Tree structure
//!
//! Each slot has four derivation pointers:
//! - `deriv_parent`: the slot this was derived from
//! - `deriv_first_child`: head of this slot's children (doubly-linked via next/prev)
//! - `deriv_next_sibling` / `deriv_prev_sibling`: intrusive doubly-linked list
//!   of slots derived from the same parent
//!
//! When `tag == Null`, `deriv_parent` and `deriv_first_child` are repurposed
//! for the free list (successor and predecessor); do not read derivation
//! fields on Null slots — every derivation-field access here resolves
//! through the occupancy gate in `resolve_slot_mut`. (`unlink_free_collect`
//! reaches its slot directly for the free itself, on an id the revoke walk
//! has already gated.)
//!
//! ## Adding new operations
//!
//! All functions here assume `DERIVATION_LOCK` write lock is held by the caller.
//! Resolve `SlotIds` via [`crate::cap::lookup_cspace`].

use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicU64, Ordering};

use super::object::KernelObjectHeader;
use super::slot::SlotId;

const WRITE_LOCKED: u32 = u32::MAX;

/// Shared derivation tree lock.
///
/// Acquire before reading or modifying any slot's `deriv_*` fields across
/// `CSpace` boundaries. Within a single `CSpace`, the `CSpace`'s own lock (future
/// phases) is sufficient.
pub static DERIVATION_LOCK: DerivationLock = DerivationLock::new();

/// Spin-based reader/writer lock protecting the capability derivation tree.
///
/// The `holder_*` fields are diagnostic only, read by the softlockup
/// watchdog dump: `holder` names the CPU while the write lock is held, and
/// the others describe the most recent acquisition (they stay set after the
/// release, so a hold the watchdog finds without a live holder still names
/// its origin).
pub struct DerivationLock
{
    state: AtomicU32,
    /// Holder CPU plus one while the write lock is held; 0 otherwise.
    holder: AtomicU32,
    /// Thread id of the most recent write holder (0 before the scheduler has
    /// dispatched a thread; the idle thread carries an ordinary id).
    holder_tid: AtomicU32,
    /// Syscall number the most recent write holder was executing
    /// (`u64::MAX` outside a syscall).
    holder_nr: AtomicU64,
    /// Source location of the most recent acquiring `write_lock` call.
    holder_site: AtomicPtr<core::panic::Location<'static>>,
}

/// Snapshot of a [`DerivationLock`] for the softlockup watchdog dump.
#[derive(Clone, Copy)]
pub struct DerivationLockSnapshot
{
    /// Raw state word: 0, a reader count, or `u32::MAX` for a held write lock.
    pub state: u32,
    /// Write holder's CPU plus one; 0 when unheld.
    pub holder: u32,
    /// Thread id of the most recent write holder.
    pub tid: u32,
    /// Syscall number of the most recent write holder.
    pub syscall_nr: u64,
    /// Acquiring call site of the most recent write holder.
    pub site: Option<&'static core::panic::Location<'static>>,
}

impl DerivationLock
{
    /// Construct an unlocked `DerivationLock`. Const for static initialisation.
    pub const fn new() -> Self
    {
        Self {
            state: AtomicU32::new(0),
            holder: AtomicU32::new(0),
            holder_tid: AtomicU32::new(0),
            holder_nr: AtomicU64::new(u64::MAX),
            holder_site: AtomicPtr::new(core::ptr::null_mut()),
        }
    }

    /// Acquire a shared read lock. Spins while a writer holds the lock.
    ///
    /// Multiple readers may hold the lock simultaneously. Blocks writers.
    ///
    /// Currently unused: all derivation operations take an exclusive write
    /// lock. Read-locking is reserved for SMP — concurrent cap-lookup
    /// traversals (read-only) will share this lock instead of serialising.
    #[allow(dead_code)]
    pub fn read_lock(&self)
    {
        loop
        {
            let cur = self.state.load(Ordering::Relaxed);
            // Refuse to increment if a writer holds the lock.
            if cur != WRITE_LOCKED
                && self
                    .state
                    .compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }
    }

    /// Release a shared read lock previously acquired with [`read_lock`].
    #[allow(dead_code)]
    pub fn read_unlock(&self)
    {
        self.state.fetch_sub(1, Ordering::Release);
    }

    /// Acquire the write lock. Spins until no readers or writers hold it.
    ///
    /// A contended wait is recorded in the calling CPU's lock-wait
    /// breadcrumb for the softlockup watchdog; the uncontended path
    /// records nothing. The acquisition stamps the holder fields.
    #[track_caller]
    pub fn write_lock(&self)
    {
        let site = core::panic::Location::caller();
        crate::sched::check_lock_hold_preemptible(crate::sched::LOCK_WAIT_DERIVATION, site);
        // The uncontended probe is a strong CAS: a spurious weak failure
        // would divert an uncontended acquisition into the breadcrumb path.
        if self
            .state
            .compare_exchange(0, WRITE_LOCKED, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            crate::sched::lock_wait_enter(
                crate::sched::LOCK_WAIT_DERIVATION,
                core::ptr::from_ref(&self.state).expose_provenance(),
            );
            loop
            {
                if self
                    .state
                    .compare_exchange_weak(0, WRITE_LOCKED, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
                core::hint::spin_loop();
            }
            crate::sched::lock_wait_exit();
        }
        let (tid, nr) = crate::sched::holder_info();
        self.holder_tid.store(tid, Ordering::Relaxed);
        self.holder_nr.store(nr, Ordering::Relaxed);
        self.holder_site
            .store(core::ptr::from_ref(site).cast_mut(), Ordering::Relaxed);
        self.holder
            .store(crate::sched::cpu_stamp(), Ordering::Relaxed);
    }

    /// Release the write lock previously acquired with [`write_lock`].
    pub fn write_unlock(&self)
    {
        self.holder.store(0, Ordering::Relaxed);
        self.state.store(0, Ordering::Release);
    }

    /// Snapshot the lock for the softlockup watchdog dump.
    pub fn debug_snapshot(&self) -> DerivationLockSnapshot
    {
        let site = self.holder_site.load(Ordering::Relaxed);
        DerivationLockSnapshot {
            state: self.state.load(Ordering::Relaxed),
            holder: self.holder.load(Ordering::Relaxed),
            tid: self.holder_tid.load(Ordering::Relaxed),
            syscall_nr: self.holder_nr.load(Ordering::Relaxed),
            // SAFETY: the pointer is null or a `Location::caller()` result,
            // which is `'static` program data.
            site: unsafe { site.cast_const().as_ref() },
        }
    }
}

// ── Tree manipulation ─────────────────────────────────────────────────────────

/// Resolve a [`SlotId`] to a mutable slot reference.
///
/// Returns `None` if the `CSpace` is not registered, the index is invalid,
/// or the slot is Null (freed — see the occupancy gate below).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` (write lock). The returned reference
/// is valid only while the lock is held and the `CSpace` is live.
unsafe fn resolve_slot_mut(id: SlotId) -> Option<&'static mut super::slot::CapabilitySlot>
{
    let cs_ptr = crate::cap::lookup_cspace(id.cspace_id, id.epoch)?;
    // SAFETY: cspace registry lookup validated; CSpace pointer lives as long as the registry entry.
    let cs = unsafe { &mut *cs_ptr };
    let slot = cs.slot_mut(id.index.get())?;
    // Occupancy gate: a Null slot is not a derivation node — its `deriv_*`
    // fields are free-list state (successor in `deriv_parent`, predecessor
    // in `deriv_first_child`), which a derivation-side write would corrupt
    // into handing out an occupied slot. A stale `SlotId` naming a freed
    // slot (e.g. `link_child` after an unlocked source resolution raced a
    // concurrent delete) resolves to `None` and the caller skips the edit.
    // The gate is stable under `DERIVATION_LOCK`: every occupied-to-free
    // transition happens with the lock held (delete, revoke's
    // `unlink_free_collect`, the teardown drain, the split consume/rollback
    // paths, and the memory-merge tail release).
    if slot.is_null()
    {
        return None;
    }
    Some(slot)
}

/// Link `child` as a new child of `parent` in the derivation tree.
///
/// Prepends `child` to `parent`'s child list (child becomes `first_child`).
/// Updates `child.deriv_parent` and the prev/next sibling chain.
///
/// The link is all-or-nothing: if either end fails to resolve (gone, or
/// freed; see the occupancy gate in `resolve_slot_mut`), neither slot is
/// mutated and `false` is returned. A one-sided write in either direction
/// would leave a live slot holding a dangling `SlotId` that a later recycle
/// of the index could alias onto an unrelated live slot. Callers linking
/// under a parent in the caller's own registered `CSpace` (copy, derive,
/// the revoke hoist) assert on the result in debug builds — for them a
/// dropped link is an invariant violation. Callers linking under a foreign
/// derivation parent (the reparent walk, the split tails) tolerate a parent
/// whose `CSpace` has since unregistered — a dead link, see
/// `truncate_dead_link` — and leave the child a clean root.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock.
#[must_use]
pub unsafe fn link_child(parent: SlotId, child: SlotId) -> bool
{
    // Probe the child before touching the parent: the lock is held for the
    // whole call, so a child that resolves here still resolves below.
    // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
    if unsafe { resolve_slot_mut(child) }.is_none()
    {
        return false;
    }

    // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
    let old_first = if let Some(parent_slot) = unsafe { resolve_slot_mut(parent) }
    {
        let old = parent_slot.deriv_first_child;
        parent_slot.deriv_first_child = Some(child);
        old
    }
    else
    {
        return false;
    };

    // SAFETY: DERIVATION_LOCK held; the child resolved above and nothing
    // can free it while the lock is held.
    if let Some(child_slot) = unsafe { resolve_slot_mut(child) }
    {
        child_slot.deriv_parent = Some(parent);
        child_slot.deriv_prev_sibling = None;
        child_slot.deriv_next_sibling = old_first;
    }

    // Wire the former first_child's prev pointer to the new child.
    if let Some(old_first_id) = old_first
    {
        // SAFETY: DERIVATION_LOCK held; old_first_id retrieved from parent's child list.
        if let Some(old_first_slot) = unsafe { resolve_slot_mut(old_first_id) }
        {
            old_first_slot.deriv_prev_sibling = Some(child);
        }
    }
    true
}

/// Remove `node` from the derivation tree without affecting its children.
///
/// Updates the parent's `first_child` pointer and the sibling chain around
/// `node`. Clears `node`'s `deriv_parent` and sibling pointers.
///
/// Each neighbour is written only if it still points back at `node`. In a
/// consistent tree that always holds; it fails only for a node abandoned
/// behind a dead link (see [`truncate_dead_link`]) whose recorded parent
/// or sibling index has since been recycled — the guard keeps such a node
/// from editing the unrelated slot now at that index. The node itself
/// leaves the tree either way.
///
/// Children of `node` are left dangling (caller should call
/// [`reparent_children`] first if needed).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock.
pub unsafe fn unlink_node(node: SlotId)
{
    // Read node's current pointers.
    // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
    let (parent, prev, next) = if let Some(slot) = unsafe { resolve_slot_mut(node) }
    {
        let p = slot.deriv_parent;
        let pr = slot.deriv_prev_sibling;
        let nx = slot.deriv_next_sibling;
        // Clear node's own pointers.
        slot.deriv_parent = None;
        slot.deriv_prev_sibling = None;
        slot.deriv_next_sibling = None;
        (p, pr, nx)
    }
    else
    {
        return;
    };

    // Splice node out of the sibling chain.
    if let Some(prev_id) = prev
    {
        // SAFETY: DERIVATION_LOCK held; prev_id retrieved from node's sibling pointer.
        if let Some(prev_slot) = unsafe { resolve_slot_mut(prev_id) }
            && prev_slot.deriv_next_sibling == Some(node)
        {
            prev_slot.deriv_next_sibling = next;
        }
    }
    else if let Some(parent_id) = parent
    {
        // node was the first child; update parent's first_child.
        // SAFETY: DERIVATION_LOCK held; parent_id retrieved from node's parent pointer.
        if let Some(parent_slot) = unsafe { resolve_slot_mut(parent_id) }
            && parent_slot.deriv_first_child == Some(node)
        {
            parent_slot.deriv_first_child = next;
        }
    }

    if let Some(next_id) = next
    {
        // SAFETY: DERIVATION_LOCK held; next_id retrieved from node's sibling pointer.
        if let Some(next_slot) = unsafe { resolve_slot_mut(next_id) }
            && next_slot.deriv_prev_sibling == Some(node)
        {
            next_slot.deriv_prev_sibling = prev;
        }
    }
}

/// Maximum children re-linked per [`reparent_children`] call — the batch
/// size for `SYS_CAP_DELETE` and the range splits, which move a consumed
/// slot's children under its parent. Same bound and rationale as
/// [`MAX_REVOKE_EDITS`]: any slot can have been derived from up to the
/// structural ceiling of every `CSpace`, and that walk must not hold the
/// derivation lock end to end. The one walk that does is a range split's
/// rollback of a child it inserted in the same call (`split.rs`,
/// `rollback_child`): it covers only what a sibling derived from that child
/// inside one lock-release window, nothing can extend the list under the
/// lock, and it must complete atomically with the child's free.
pub const MAX_REPARENT_EDITS: usize = MAX_REVOKE_EDITS;

/// Liveness backstop for the callers' [`reparent_children`] loops: more
/// batches than this that still report children remaining mean a
/// concurrent deriver is extending the child list at least as fast as it
/// is being moved; the caller returns `Interrupted` instead of looping
/// in-kernel forever.
pub const MAX_REPARENT_BATCHES: u32 = 1 << 20;

/// Move up to `max_edits` children of `node` to `new_parent` (or make them
/// tree roots), head-first. Returns `true` when `node` has no children
/// left, `false` when the budget ran out with children remaining — the
/// caller releases `DERIVATION_LOCK`, revalidates `node`, and calls again.
///
/// Used by `SYS_CAP_DELETE` and the range splits so grandchildren remain
/// revocable by the grandparent after the intermediate slot is consumed.
/// Each child is detached into a clean derivation root by [`unlink_node`]
/// and then re-linked by [`link_child`], which is all-or-nothing: a
/// `new_parent` that fails to resolve leaves the child a root rather than
/// holding a dangling parent pointer and stale sibling links. A head that
/// fails to resolve, or whose pop makes no progress (a chain that does not
/// lead back to `node`), is contained like the revoke walk's dead link:
/// log, cut `node`'s child list, report done.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock.
pub unsafe fn reparent_children(node: SlotId, new_parent: Option<SlotId>, max_edits: usize)
-> bool
{
    let mut edits = 0usize;
    loop
    {
        // SAFETY: DERIVATION_LOCK held; ensures exclusive access to derivation tree.
        let Some(head) = (unsafe { resolve_slot_mut(node) }).and_then(|s| s.deriv_first_child)
        else
        {
            return true;
        };
        // SAFETY: DERIVATION_LOCK held (see above).
        if unsafe { resolve_slot_mut(head) }.is_none()
        {
            // SAFETY: DERIVATION_LOCK held (caller contract).
            unsafe { truncate_dead_link(node, head, "reparent child list") };
            return true;
        }
        if edits >= max_edits
        {
            return false;
        }
        // SAFETY: DERIVATION_LOCK held; head resolved above, so the pop
        // cannot no-op on the head itself.
        unsafe { unlink_node(head) };
        // SAFETY: DERIVATION_LOCK held.
        let still_head = (unsafe { resolve_slot_mut(node) }).and_then(|s| s.deriv_first_child);
        if still_head == Some(head)
        {
            // head's own parent link did not lead back to node, so the pop
            // spliced it out of some other list and left node's unchanged.
            // SAFETY: DERIVATION_LOCK held (caller contract).
            unsafe { truncate_dead_link(node, head, "reparent child list") };
            return true;
        }
        if let Some(np) = new_parent
        {
            // SAFETY: DERIVATION_LOCK held; head is a clean root. A new
            // parent that no longer resolves is a dead link (see
            // `truncate_dead_link`); head then stays a clean root.
            let _ = unsafe { link_child(np, head) };
        }
        edits += 1;
    }
}

/// Maximum number of O(1) tree edits (hoists + frees) a single
/// [`revoke_subtree_batch`] call performs — the revoke batch size.
///
/// Frees never exceed edits, so this also bounds the BSS dealloc-output
/// buffer (`MAX_REVOKE_EDITS` entries × 8 bytes = 2 KiB). The caller copies
/// the output buffer to a stack-local array of the same bound (so the
/// DERIVATION write lock can be released before the dealloc loop), so
/// keeping `MAX_REVOKE_EDITS` small enough to fit on a 16 KiB kernel stack
/// with breathing room is the binding constraint. Subtrees larger than one
/// batch are handled by calling [`revoke_subtree_batch`] repeatedly until
/// it reports no more work; the batch size bounds lock hold time and stack
/// cost per call, not the revocable subtree size.
pub const MAX_REVOKE_EDITS: usize = 256;

/// Output buffer for [`revoke_subtree_batch`]. `static mut` because the
/// surrounding `DERIVATION_LOCK` write lock guarantees a single in-flight
/// caller across all CPUs.
static mut REVOKE_OBJECTS: [Option<NonNull<KernelObjectHeader>>; MAX_REVOKE_EDITS] =
    [None; MAX_REVOKE_EDITS];

/// How a [`revoke_subtree_batch`] call ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchStatus
{
    /// The root has no children left; the subtree is fully cleared.
    Cleared,
    /// The edit budget ran out with work remaining; call again after
    /// releasing the lock, deallocating the collected objects, and
    /// revalidating the root.
    MoreWork,
    /// A derivation link failed to resolve — genuine corruption, or the
    /// narrow teardown self-race the pre-unregister drain documents (the
    /// dying process wiring a link during its own drain window). The
    /// dangling chain was truncated for containment; the
    /// caller must surface an error rather than report a clean revoke.
    DeadLink,
}

/// Revoke descendants of `root` with at most [`MAX_REVOKE_EDITS`] O(1) tree
/// edits, returning a slice of object pointers for the caller to
/// `dec_ref`/deallocate outside the lock, and how the batch ended.
///
/// The root slot itself is NOT touched. On [`BatchStatus::MoreWork`] the
/// caller must call again (re-acquiring the lock and revalidating the root
/// in between); such a call performed exactly [`MAX_REVOKE_EDITS`] edits,
/// and clearing a subtree of N nodes needs at most 2N edits in total (each
/// node is hoisted at most once and freed exactly once), so repeated calls
/// terminate against any fixed subtree in O(N) total work. Nodes derived
/// concurrently between batches are still cleared, because the walk only
/// ever operates on root's current child list.
///
/// Each edit acts on the head `H` of root's child list in O(1):
///
/// - `H` has a child: unlink that child and re-link it directly under root
///   (a *hoist* — it becomes the new list head, ahead of `H`).
/// - `H` is childless: unlink it, free its slot, collect its object.
///
/// Hoisting flattens the subtree in place: while a multi-batch revoke is in
/// flight, surviving descendants may temporarily appear as direct children
/// of root. They remain descendants of root and of every ancestor above it,
/// so ancestor revocation reach is preserved; intermediate parent→child
/// edges inside the subtree are destroyed as the flattening proceeds, which
/// is why the syscall pins the root against delete/move for the whole
/// multi-batch operation (see `CapabilitySlot::revoke_in_progress`) — an
/// abandoned half-flattened subtree would otherwise permanently outlive the
/// intermediate holders' revocation authority.
///
/// The returned slice borrows from [`REVOKE_OBJECTS`]; the caller must
/// finish consuming it before any other call. The `DERIVATION_LOCK` held
/// across this call enforces that exclusivity.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock. Derivation links
/// reachable from a live slot resolve — `drain_dying_cspace_batch` unlinks
/// every dying slot from the forest before a `CSpace` unregisters, save
/// for the narrow teardown self-race window it documents (the dying
/// process wiring a link during its own drain). A link that fails to
/// resolve — vanished `CSpace`, or a Null slot still chained into the tree
/// (every free unlinks first under this lock, so that is corruption) — is
/// contained either way: the walk truncates the chain hanging from it,
/// logs it, and reports [`BatchStatus::DeadLink`].
pub unsafe fn revoke_subtree_batch(
    root: SlotId,
) -> (&'static [Option<NonNull<KernelObjectHeader>>], BatchStatus)
{
    // SAFETY: DERIVATION_LOCK held → single-threaded access to the static
    // output buffer. Entries are written before `out_count` advances and
    // callers read only `..out_count`, so stale entries beyond the returned
    // length are never observed.
    let out = unsafe { &mut *core::ptr::addr_of_mut!(REVOKE_OBJECTS) };
    let mut out_count: usize = 0;
    // Tree edits this batch (hoists + frees). Distinct from `out_count`:
    // hoists and objectless slots produce no dealloc entry, and the batch
    // bound caps lock hold time by edits performed, not objects collected.
    let mut steps: usize = 0;

    loop
    {
        // SAFETY: DERIVATION_LOCK held; ensures exclusive access to the tree.
        let Some(head) = (unsafe { resolve_slot_mut(root) }).and_then(|s| s.deriv_first_child)
        else
        {
            // Childless root: subtree cleared. (An unresolvable root lands
            // here too; the caller's per-batch revalidation is what tells a
            // vanished root apart from a cleared subtree.)
            return (&out[..out_count], BatchStatus::Cleared);
        };

        // SAFETY: DERIVATION_LOCK held; ensures exclusive access to the tree.
        let Some(head_slot) = (unsafe { resolve_slot_mut(head) })
        else
        {
            // SAFETY: DERIVATION_LOCK held (see Safety: corruption path).
            unsafe { truncate_dead_link(root, head, "root child list") };
            return (&out[..out_count], BatchStatus::DeadLink);
        };
        let grandchild = head_slot.deriv_first_child;

        if let Some(g) = grandchild
        {
            // SAFETY: DERIVATION_LOCK held; ensures exclusive access to the tree.
            if unsafe { resolve_slot_mut(g) }.is_none()
            {
                // SAFETY: DERIVATION_LOCK held (see Safety: corruption path).
                unsafe { truncate_dead_link(head, g, "child chain") };
                return (&out[..out_count], BatchStatus::DeadLink);
            }
            // Hoist: g leaves head's child list and becomes root's first
            // child (head keeps its own list position).
            // SAFETY: DERIVATION_LOCK held; g and root are live.
            let linked = unsafe {
                unlink_node(g);
                link_child(root, g)
            };
            debug_assert!(linked, "revoke hoist link dropped under DERIVATION_LOCK");
        }
        else
        {
            // Head is childless: unlink, free its slot, collect its object.
            // SAFETY: DERIVATION_LOCK held; head is a valid, live SlotId.
            if let Some(ptr) = unsafe { unlink_free_collect(head) }
            {
                out[out_count] = Some(ptr);
                out_count += 1;
            }
        }

        steps += 1;
        if steps >= MAX_REVOKE_EDITS
        {
            return (&out[..out_count], BatchStatus::MoreWork);
        }
    }
}

/// Containment for a dead derivation link: log it and cut `owner`'s
/// `deriv_first_child`, abandoning the unreachable chain behind `dead`.
///
/// Cutting the whole chain is the tightest containment available: the dead
/// node's sibling links lived in storage reclaimed with its `CSpace`, so
/// the rest of the chain cannot be located to splice past it. Any live
/// nodes chained behind the dead link are abandoned — which is why the
/// revoke walk reports [`BatchStatus::DeadLink`] and its syscall surfaces
/// an error instead of claiming a clean revoke; the reparent walk has no
/// status to report and completes with the chain abandoned, and its
/// callers then free `owner` — `SYS_CAP_DELETE` and the range splits the
/// slot, the teardown drain the whole owning `CSpace`.
///
/// An abandoned node keeps its `deriv_parent` (naming `owner`) and sibling
/// links, so it is outside every ancestor's revoke reach from here on, and
/// once `owner`'s index is recycled those links alias whatever occupies it.
/// [`unlink_node`] writes a neighbour only if it still points back at the
/// node, so the abandoned node's own later delete or move cannot edit the
/// aliased slot's lists.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock.
pub(crate) unsafe fn truncate_dead_link(owner: SlotId, dead: SlotId, context: &str)
{
    #[cfg(not(test))]
    crate::kprintln!(
        "cap: dead derivation link (cspace {} slot {}) in {}; truncating",
        dead.cspace_id,
        dead.index.get(),
        context
    );
    #[cfg(test)]
    let _ = (dead, context);
    // SAFETY: DERIVATION_LOCK held (caller contract).
    if let Some(owner_slot) = unsafe { resolve_slot_mut(owner) }
    {
        owner_slot.deriv_first_child = None;
    }
}

/// Unlink `id` from the derivation tree, free its slot in its owning
/// `CSpace`, and return its object pointer for the caller to queue for
/// deallocation (`None` if the slot held no object or its `CSpace` is gone).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock. `id` must be childless —
/// its subtree already cleared or hoisted away.
unsafe fn unlink_free_collect(id: SlotId) -> Option<NonNull<KernelObjectHeader>>
{
    // SAFETY: DERIVATION_LOCK held (caller contract).
    unsafe { unlink_node(id) };

    let cs_ptr = crate::cap::lookup_cspace(id.cspace_id, id.epoch)?;

    // Take cspace.lock around the slot read + free_slot so the freelist
    // mutation cannot tear against a concurrent SYS_CAP_CREATE_* on the
    // same cspace. Lock order: DERIVATION_LOCK → cspace.lock.
    // SAFETY: cspace registry lookup validated; CSpace pointer lives as
    // long as the registry entry; lock_raw/unlock_raw paired.
    let saved = unsafe { (*cs_ptr).lock.lock_raw() };
    // SAFETY: lock held; aliasing prevented.
    let cs = unsafe { &mut *cs_ptr };
    let obj_ptr = cs.slot_mut(id.index.get()).and_then(|slot| slot.object);
    cs.free_slot(id.index.get());
    // SAFETY: paired with lock_raw above.
    unsafe { (*cs_ptr).lock.unlock_raw(saved) };

    obj_ptr
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn read_lock_unlock()
    {
        let lock = DerivationLock::new();
        lock.read_lock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 1);
        lock.read_unlock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn multiple_readers()
    {
        let lock = DerivationLock::new();
        lock.read_lock();
        lock.read_lock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 2);
        lock.read_unlock();
        lock.read_unlock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn write_lock_unlock()
    {
        let lock = DerivationLock::new();
        lock.write_lock();
        assert_eq!(lock.state.load(Ordering::Relaxed), WRITE_LOCKED);
        lock.write_unlock();
        assert_eq!(lock.state.load(Ordering::Relaxed), 0);
    }

    // The host stubs stamp cpu 1 (`cpu_stamp() == 1`) and no thread
    // (`holder_info() == (0, u64::MAX)`); the site is this test.
    #[test]
    fn write_lock_stamps_holder_and_unlock_clears_it()
    {
        let lock = DerivationLock::new();
        let before = lock.debug_snapshot();
        assert_eq!((before.state, before.holder), (0, 0));
        assert!(before.site.is_none());

        lock.write_lock();
        let held = lock.debug_snapshot();
        assert_eq!((held.state, held.holder), (WRITE_LOCKED, 1));
        assert_eq!((held.tid, held.syscall_nr), (0, u64::MAX));
        assert_eq!(held.site.map(|loc| loc.file()), Some(file!()));

        lock.write_unlock();
        let released = lock.debug_snapshot();
        assert_eq!((released.state, released.holder), (0, 0));
        assert!(released.site.is_some(), "the last acquisition stays named");
    }

    // ── revoke_subtree_batch (host harness) ──────────────────────────────
    //
    // Each test registers heap-backed CSpaces in the shared test registry
    // under hard-coded ids unique to that test (the registry is a
    // process-wide static and `cargo test` runs tests concurrently). The
    // ids sit far above anything the test-stub `alloc_cspace_id` counter
    // reaches in this suite and below the recycle test's reserved top id;
    // nothing enforces that — a new direct-registration test must pick an
    // unused id. Leaked Boxes are acceptable — the process exits after the
    // run. The global DERIVATION_LOCK is taken for fidelity with the
    // production contract; these tests assert only after `write_unlock`, so
    // a failing assertion unwinds without wedging the other tests on the
    // lock (the `debug_assert!`s reachable under the hold —
    // `revoke_subtree_batch`'s hoist-link check and the free-list link
    // rewrites reached through `free_slot` — guard conditions these tests
    // never provoke).

    use crate::cap::cspace::CSpace;
    use crate::cap::slot::CapTag;
    use core::num::NonZeroU32;

    fn mk_registered_cspace(id: crate::cap::slot::CSpaceId) -> *mut CSpace
    {
        let cs = Box::leak(Box::new(CSpace::new(id)));
        crate::cap::register_cspace(id, cs).expect("register test cspace");
        core::ptr::from_mut(cs)
    }

    /// Populate one slot (Endpoint tag, dangling object pointer — the batch
    /// only collects object pointers, never dereferences them) and return
    /// its stamped `SlotId`.
    fn occupy(cs: *mut CSpace, id: crate::cap::slot::CSpaceId) -> SlotId
    {
        // SAFETY: single-threaded test ownership of the leaked CSpace.
        let idx = unsafe { (*cs).allocate_slot() }.expect("allocate slot");
        // SAFETY: as above.
        let slot = unsafe { (*cs).slot_mut(idx.get()) }.expect("slot_mut");
        slot.tag = CapTag::Endpoint;
        slot.object = Some(NonNull::dangling());
        SlotId::current(id, idx)
    }

    /// Derivation links to hand-write into a slot (see [`set_links`]).
    struct Links
    {
        parent: Option<SlotId>,
        prev: Option<SlotId>,
        next: Option<SlotId>,
    }

    /// Hand-write `id`'s derivation links; `false` if the slot does not
    /// resolve. Callers assert on the result after releasing the lock.
    ///
    /// # Safety
    ///
    /// `DERIVATION_LOCK` must be held.
    unsafe fn set_links(id: SlotId, links: Links) -> bool
    {
        // SAFETY: caller contract.
        match unsafe { resolve_slot_mut(id) }
        {
            Some(slot) =>
            {
                slot.deriv_parent = links.parent;
                slot.deriv_prev_sibling = links.prev;
                slot.deriv_next_sibling = links.next;
                true
            }
            None => false,
        }
    }

    fn count_populated(cs: *mut CSpace) -> usize
    {
        // SAFETY: single-threaded test ownership.
        unsafe { (*cs).populated_count() }
    }

    /// Link pre-occupied `nodes` as a derive chain under `root` (each node
    /// the sole child of the previous). Nodes are allocated by the caller
    /// before locking so no fallible call runs while `DERIVATION_LOCK` is
    /// held. Returns whether every link landed; callers assert on it after
    /// releasing the lock.
    ///
    /// # Safety
    ///
    /// `DERIVATION_LOCK` must be held across the call.
    unsafe fn link_chain(root: SlotId, nodes: &[SlotId]) -> bool
    {
        let mut parent = root;
        let mut linked = true;
        for &child in nodes
        {
            // SAFETY: DERIVATION_LOCK held by caller; both slots live.
            linked &= unsafe { link_child(parent, child) };
            parent = child;
        }
        linked
    }

    /// [`occupy`] `len` slots up front, before the caller takes
    /// `DERIVATION_LOCK` — no fallible allocation may run under the global
    /// lock (a panic there would wedge the whole suite).
    fn occupy_many(
        cs: *mut CSpace,
        id: crate::cap::slot::CSpaceId,
        len: usize,
    ) -> std::vec::Vec<SlotId>
    {
        (0..len).map(|_| occupy(cs, id)).collect()
    }

    #[test]
    fn revoke_batch_clears_mixed_tree_and_preserves_root()
    {
        const ID: crate::cap::slot::CSpaceId = 3101;
        let cs = mk_registered_cspace(ID);
        let root = occupy(cs, ID);
        // Allocate before locking — no fallible call under the global lock.
        let children = occupy_many(cs, ID, 3);
        let grandchildren = occupy_many(cs, ID, 12);
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        for (child, chunk) in children.iter().zip(grandchildren.chunks(4))
        {
            // SAFETY: DERIVATION_LOCK held; both slots live.
            linked &= unsafe { link_child(root, *child) };
            for grandchild in chunk
            {
                // SAFETY: as above.
                linked &= unsafe { link_child(*child, *grandchild) };
            }
        }
        // SAFETY: DERIVATION_LOCK held.
        let (objects, status) = unsafe { revoke_subtree_batch(root) };
        let collected = objects.len();
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup links must land");
        assert_eq!(status, BatchStatus::Cleared);
        assert_eq!(
            collected,
            children.len() + grandchildren.len(),
            "every child and grandchild collected"
        );
        assert_eq!(count_populated(cs), 1, "only the root survives");
        // SAFETY: test ownership.
        let root_slot = unsafe { (*cs).slot_mut(root.index.get()) }.expect("root slot");
        assert_eq!(root_slot.tag, CapTag::Endpoint, "root untouched");
        assert_eq!(root_slot.deriv_first_child, None, "root childless");
        crate::cap::unregister_cspace(ID);
    }

    // A chain of N nodes needs 2N-1 edits (N-1 hoists + N frees), so
    // N = 150 forces exactly one MoreWork boundary at 256 edits.
    const BUDGET_CHAIN: usize = 150;

    #[test]
    fn revoke_batch_stops_at_edit_budget_then_clears()
    {
        const ID: crate::cap::slot::CSpaceId = 3102;
        let cs = mk_registered_cspace(ID);
        let root = occupy(cs, ID);
        let nodes = occupy_many(cs, ID, BUDGET_CHAIN);
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; all nodes live.
        let linked = unsafe { link_chain(root, &nodes) };

        // SAFETY: DERIVATION_LOCK held.
        let (first_objects, first_status) = unsafe { revoke_subtree_batch(root) };
        let first_freed = first_objects.len();
        // SAFETY: DERIVATION_LOCK held.
        let (second_objects, second_status) = unsafe { revoke_subtree_batch(root) };
        let second_freed = second_objects.len();
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup chain must land");
        assert_eq!(first_status, BatchStatus::MoreWork);
        assert!(
            first_freed < BUDGET_CHAIN,
            "budgeted batch must leave survivors ({first_freed} freed)"
        );
        assert_eq!(second_status, BatchStatus::Cleared);
        assert_eq!(first_freed + second_freed, BUDGET_CHAIN);
        assert_eq!(count_populated(cs), 1, "only the root survives");
        crate::cap::unregister_cspace(ID);
    }

    #[test]
    fn revoke_batch_hoists_survivors_under_root_between_batches()
    {
        const ID: crate::cap::slot::CSpaceId = 3105;
        let cs = mk_registered_cspace(ID);
        let root = occupy(cs, ID);
        let nodes = occupy_many(cs, ID, BUDGET_CHAIN);
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; all nodes live.
        let linked = unsafe { link_chain(root, &nodes) };

        // SAFETY: DERIVATION_LOCK held.
        let (first_objects, first_status) = unsafe { revoke_subtree_batch(root) };
        let first_freed = first_objects.len();

        // Between batches, every survivor must be a direct child of root.
        // No panics while the global lock is held — capture, unlock, assert.
        let mut survivors = 0;
        let mut all_hoisted = true;
        // SAFETY: DERIVATION_LOCK held.
        let mut cur = unsafe { resolve_slot_mut(root) }.and_then(|s| s.deriv_first_child);
        let mut all_resolved = true;
        // Bounded: a cyclic list must end the walk, not the suite.
        let expected_survivors = BUDGET_CHAIN - first_freed;
        let mut walk_bounded = true;
        while let Some(node) = cur
        {
            // SAFETY: DERIVATION_LOCK held.
            let Some(slot) = (unsafe { resolve_slot_mut(node) })
            else
            {
                all_resolved = false;
                break;
            };
            all_hoisted &= slot.deriv_parent == Some(root);
            survivors += 1;
            if survivors > expected_survivors
            {
                walk_bounded = false;
                break;
            }
            cur = slot.deriv_next_sibling;
        }
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup chain must land");
        assert!(walk_bounded, "root's child list must not cycle");
        assert_eq!(first_status, BatchStatus::MoreWork);
        assert!(all_resolved, "every survivor must resolve");
        assert!(all_hoisted, "every survivor hoisted under root");
        assert_eq!(survivors, expected_survivors);
        crate::cap::unregister_cspace(ID);
    }

    #[test]
    fn link_child_dead_child_leaves_parent_untouched()
    {
        const ID_A: crate::cap::slot::CSpaceId = 3106;
        const ID_B: crate::cap::slot::CSpaceId = 3107;
        let cs_a = mk_registered_cspace(ID_A);
        let cs_b = mk_registered_cspace(ID_B);
        let root = occupy(cs_a, ID_A);
        let live_child = occupy(cs_a, ID_A);
        let dead_child = occupy(cs_b, ID_B);
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        // SAFETY: DERIVATION_LOCK held; both slots live.
        linked &= unsafe { link_child(root, live_child) };
        // The child's CSpace vanishes before the (stale) link attempt.
        crate::cap::unregister_cspace(ID_B);
        // SAFETY: DERIVATION_LOCK held; the dead end must be tolerated.
        let dead_linked = unsafe { link_child(root, dead_child) };
        // SAFETY: DERIVATION_LOCK held.
        let root_first = unsafe { resolve_slot_mut(root) }.and_then(|s| s.deriv_first_child);
        // SAFETY: DERIVATION_LOCK held.
        let live_prev = unsafe { resolve_slot_mut(live_child) }.map(|s| s.deriv_prev_sibling);
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup links must land");
        assert!(!dead_linked, "a dead child must not link");
        assert_eq!(
            root_first,
            Some(live_child),
            "parent must not point at the dead child"
        );
        assert_eq!(
            live_prev,
            Some(None),
            "former head's prev link must be untouched"
        );
        crate::cap::unregister_cspace(ID_A);
    }

    #[test]
    fn unlink_node_leaves_non_backpointing_neighbours_untouched()
    {
        const ID: crate::cap::slot::CSpaceId = 3114;
        let cs = mk_registered_cspace(ID);
        let parent = occupy(cs, ID);
        let real_first = occupy(cs, ID);
        let prev = occupy(cs, ID);
        let next = occupy(cs, ID);
        let orphan = occupy(cs, ID);
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        // SAFETY: DERIVATION_LOCK held; both slots live.
        linked &= unsafe { link_child(parent, real_first) };
        // Give both siblings a link of their own, so an ungated write of
        // `None` into them would be observable.
        // SAFETY: DERIVATION_LOCK held.
        let mut wrote = unsafe {
            set_links(
                next,
                Links {
                    parent: None,
                    prev: Some(real_first),
                    next: None,
                },
            )
        };
        // SAFETY: DERIVATION_LOCK held.
        wrote &= unsafe {
            set_links(
                prev,
                Links {
                    parent: None,
                    prev: None,
                    next: Some(real_first),
                },
            )
        };

        // The orphan's links name neighbours that do not point back at it —
        // the shape a node abandoned behind a dead link takes once its
        // recorded parent's index has been recycled.
        // SAFETY: DERIVATION_LOCK held.
        wrote &= unsafe {
            set_links(
                orphan,
                Links {
                    parent: Some(parent),
                    prev: None,
                    next: Some(next),
                },
            )
        };
        // SAFETY: DERIVATION_LOCK held.
        unsafe { unlink_node(orphan) };
        // SAFETY: DERIVATION_LOCK held.
        let parent_first = unsafe { resolve_slot_mut(parent) }.and_then(|s| s.deriv_first_child);
        // SAFETY: DERIVATION_LOCK held.
        let next_prev = unsafe { resolve_slot_mut(next) }.map(|s| s.deriv_prev_sibling);
        // SAFETY: DERIVATION_LOCK held.
        let orphan_links = unsafe { resolve_slot_mut(orphan) }
            .map(|s| (s.deriv_parent, s.deriv_prev_sibling, s.deriv_next_sibling));

        // Sibling variant: prev names a predecessor that does not point back.
        // SAFETY: DERIVATION_LOCK held.
        wrote &= unsafe {
            set_links(
                orphan,
                Links {
                    parent: Some(parent),
                    prev: Some(prev),
                    next: None,
                },
            )
        };
        // SAFETY: DERIVATION_LOCK held.
        unsafe { unlink_node(orphan) };
        // SAFETY: DERIVATION_LOCK held.
        let prev_next = unsafe { resolve_slot_mut(prev) }.map(|s| s.deriv_next_sibling);
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup links must land");
        assert!(wrote, "every hand-written slot must resolve");
        assert_eq!(
            parent_first,
            Some(real_first),
            "a parent whose first child is not the node must be untouched"
        );
        assert_eq!(
            next_prev,
            Some(Some(real_first)),
            "a next sibling that does not point back must be untouched"
        );
        assert_eq!(
            orphan_links,
            Some((None, None, None)),
            "the node itself leaves the tree"
        );
        assert_eq!(
            prev_next,
            Some(Some(real_first)),
            "a prev sibling that does not point back must be untouched"
        );
        crate::cap::unregister_cspace(ID);
    }

    #[test]
    fn reparent_children_moves_children_in_batches()
    {
        const ID: crate::cap::slot::CSpaceId = 3108;
        let cs = mk_registered_cspace(ID);
        let root = occupy(cs, ID);
        let mid = occupy(cs, ID);
        let children = occupy_many(cs, ID, 3);
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        // SAFETY: DERIVATION_LOCK held; all slots live.
        linked &= unsafe { link_child(root, mid) };
        for child in &children
        {
            // SAFETY: as above.
            linked &= unsafe { link_child(mid, *child) };
        }
        // SAFETY: DERIVATION_LOCK held.
        let first = unsafe { reparent_children(mid, Some(root), 2) };
        // SAFETY: DERIVATION_LOCK held.
        let second = unsafe { reparent_children(mid, Some(root), 2) };
        // SAFETY: DERIVATION_LOCK held.
        let mid_children = unsafe { resolve_slot_mut(mid) }.and_then(|s| s.deriv_first_child);
        let mut parents_ok = true;
        for child in &children
        {
            // SAFETY: DERIVATION_LOCK held.
            parents_ok &=
                unsafe { resolve_slot_mut(*child) }.is_some_and(|s| s.deriv_parent == Some(root));
        }
        // Bounded: a cyclic list must end the walk, not the suite. The
        // longest legitimate list is `mid` plus its children.
        let expected_list = children.len() + 1;
        let mut root_list = 0;
        let mut walk_bounded = true;
        // SAFETY: DERIVATION_LOCK held.
        let mut cur = unsafe { resolve_slot_mut(root) }.and_then(|s| s.deriv_first_child);
        while let Some(node) = cur
        {
            root_list += 1;
            if root_list > expected_list
            {
                walk_bounded = false;
                break;
            }
            // SAFETY: DERIVATION_LOCK held.
            cur = unsafe { resolve_slot_mut(node) }.and_then(|s| s.deriv_next_sibling);
        }
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup links must land");
        assert!(walk_bounded, "root's child list must not cycle");
        assert!(!first, "a two-edit budget must leave a third child");
        assert!(second, "the second batch must finish the list");
        assert_eq!(mid_children, None, "mid has no children left");
        assert!(parents_ok, "every child now hangs under root");
        assert_eq!(
            root_list, expected_list,
            "root lists mid plus its former grandchildren"
        );
        assert_eq!(count_populated(cs), 5, "reparenting frees nothing");
        crate::cap::unregister_cspace(ID);
    }

    #[test]
    fn reparent_children_unresolvable_new_parent_leaves_clean_roots()
    {
        const ID_A: crate::cap::slot::CSpaceId = 3109;
        const ID_B: crate::cap::slot::CSpaceId = 3110;
        let cs_a = mk_registered_cspace(ID_A);
        let cs_b = mk_registered_cspace(ID_B);
        let parent = occupy(cs_b, ID_B);
        let mid = occupy(cs_a, ID_A);
        let children = occupy_many(cs_a, ID_A, 2);
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; all slots live.
        let mut linked = unsafe { link_child(parent, mid) };
        for child in &children
        {
            // SAFETY: as above.
            linked &= unsafe { link_child(mid, *child) };
        }
        // The grandparent's CSpace vanishes; mid's parent link is now dead.
        crate::cap::unregister_cspace(ID_B);
        // SAFETY: DERIVATION_LOCK held.
        let done = unsafe { reparent_children(mid, Some(parent), MAX_REPARENT_EDITS) };
        let mut clean_roots = true;
        for child in &children
        {
            // SAFETY: DERIVATION_LOCK held.
            clean_roots &= unsafe { resolve_slot_mut(*child) }.is_some_and(|s| {
                s.deriv_parent.is_none()
                    && s.deriv_prev_sibling.is_none()
                    && s.deriv_next_sibling.is_none()
            });
        }
        // SAFETY: DERIVATION_LOCK held.
        let mid_children = unsafe { resolve_slot_mut(mid) }.and_then(|s| s.deriv_first_child);
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup links must land");
        assert!(done);
        assert!(
            clean_roots,
            "children of a vanished grandparent become clean roots"
        );
        assert_eq!(mid_children, None);
        crate::cap::unregister_cspace(ID_A);
    }

    #[test]
    fn reparent_children_dead_child_link_truncates()
    {
        const ID_A: crate::cap::slot::CSpaceId = 3111;
        const ID_B: crate::cap::slot::CSpaceId = 3112;
        let cs_a = mk_registered_cspace(ID_A);
        let cs_b = mk_registered_cspace(ID_B);
        let mid = occupy(cs_a, ID_A);
        let foreign_child = occupy(cs_b, ID_B);
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; both slots live.
        let linked = unsafe { link_child(mid, foreign_child) };
        crate::cap::unregister_cspace(ID_B);
        // SAFETY: DERIVATION_LOCK held.
        let done = unsafe { reparent_children(mid, None, MAX_REPARENT_EDITS) };
        // SAFETY: DERIVATION_LOCK held.
        let mid_children = unsafe { resolve_slot_mut(mid) }.and_then(|s| s.deriv_first_child);
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup link must land");
        assert!(done, "a dead head ends the walk");
        assert_eq!(mid_children, None, "the dangling chain is cut");
        crate::cap::unregister_cspace(ID_A);
    }

    #[test]
    fn revoke_batch_null_slot_in_chain_is_dead_link()
    {
        const ID: crate::cap::slot::CSpaceId = 3113;
        let cs = mk_registered_cspace(ID);
        let root = occupy(cs, ID);
        let child = occupy(cs, ID);
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        // SAFETY: DERIVATION_LOCK held; both slots live.
        linked &= unsafe { link_child(root, child) };
        // Simulate the corruption the free-path invariant forbids: the
        // child is freed without being unlinked first.
        // SAFETY: single-threaded test ownership.
        unsafe { (*cs).free_slot(child.index.get()) };
        // SAFETY: DERIVATION_LOCK held.
        let (objects, status) = unsafe { revoke_subtree_batch(root) };
        let collected = objects.len();
        // SAFETY: DERIVATION_LOCK held.
        let root_child = unsafe { resolve_slot_mut(root) }.and_then(|s| s.deriv_first_child);
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup links must land");
        assert_eq!(status, BatchStatus::DeadLink);
        assert_eq!(
            collected, 0,
            "a Null slot is never collected (or double-freed)"
        );
        assert_eq!(root_child, None, "the chain through the Null slot is cut");
        assert_eq!(count_populated(cs), 1);
        crate::cap::unregister_cspace(ID);
    }

    #[test]
    fn revoke_batch_dead_link_truncates_and_reports()
    {
        const ID_A: crate::cap::slot::CSpaceId = 3103;
        const ID_B: crate::cap::slot::CSpaceId = 3104;
        let cs_a = mk_registered_cspace(ID_A);
        let cs_b = mk_registered_cspace(ID_B);
        let root = occupy(cs_a, ID_A);
        let foreign_child = occupy(cs_b, ID_B);
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        // SAFETY: DERIVATION_LOCK held; both slots live.
        linked &= unsafe { link_child(root, foreign_child) };

        // Simulate the corruption the drain invariant forbids: the child's
        // CSpace vanishes without its foreign back-links being spliced.
        crate::cap::unregister_cspace(ID_B);

        // SAFETY: DERIVATION_LOCK held.
        let (objects, status) = unsafe { revoke_subtree_batch(root) };
        let collected = objects.len();
        // No panics while the global lock is held — capture, unlock, assert.
        // SAFETY: DERIVATION_LOCK held.
        let root_state = unsafe { resolve_slot_mut(root) }.map(|s| s.deriv_first_child);
        DERIVATION_LOCK.write_unlock();

        assert!(linked, "setup links must land");
        assert_eq!(status, BatchStatus::DeadLink);
        assert_eq!(collected, 0, "nothing collectable behind a dead link");
        // Containment: the dangling chain is cut so a retry cannot spin.
        let root_child = root_state.expect("root must still resolve");
        assert_eq!(root_child, None, "root's child list must be cut");
        crate::cap::unregister_cspace(ID_A);
    }
}
