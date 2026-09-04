// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/cap/transfer.rs

//! Capability move — `SYS_CAP_MOVE` and IPC capability transfer.
//!
//! Relocates an occupied slot to a fresh slot in the same or another
//! `CSpace`. The destination takes the source's exact position in the
//! derivation tree: parent, siblings, and every child are repointed onto
//! it, and the source slot is freed. A slot can have arbitrarily many
//! children, so the child migration runs in [`MAX_REPARENT_EDITS`] batches
//! with `DERIVATION_LOCK` released in between; the tree is consistent and
//! every node stays inside every ancestor's revoke reach at each release.
//!
//! Design: [capability-internals.md](../../docs/capability-internals.md)
//! § Move.

use core::num::NonZeroU32;
use core::ptr::NonNull;

use syscall::SyscallError;

use super::cspace::CSpace;
use super::derivation::{
    MAX_REPARENT_EDITS, link_child, reparent_children, resolve_slot_mut, unlink_node,
};
use super::object::KernelObjectHeader;
use super::slot::{CapTag, SlotId};

/// A move whose child migration has not finished: both slots are live and
/// pinned, the destination hangs under the source as its derivation child
/// (so every ancestor's revoke still reaches it and the children already
/// migrated beneath it), and the source keeps the children not yet moved.
#[derive(Clone, Copy, Debug)]
pub struct CapMove
{
    src: SlotId,
    src_gen: u8,
    dst: SlotId,
    dst_gen: u8,
    /// Destination handle (generation + index), minted at insert.
    handle: u32,
    object: NonNull<KernelObjectHeader>,
}

impl CapMove
{
    /// The destination handle the move will return.
    pub fn handle(&self) -> u32
    {
        self.handle
    }
}

/// Outcome of one move step.
#[derive(Debug)]
pub enum MoveStep
{
    /// The move completed. `release` is the object reference the freed
    /// source slot held; the caller drops it with
    /// [`release_moved_object`] after releasing every lock (`None` when a
    /// concurrent operation consumed the source and its reference).
    Done
    {
        handle: u32,
        release: Option<NonNull<KernelObjectHeader>>,
    },
    /// Children remain. Release `DERIVATION_LOCK` and continue with
    /// [`move_cap_drive`].
    Pending(CapMove),
    /// The move cannot complete. `InvalidCapability`: an ancestor's revoke
    /// freed both slots. `InvalidState`: the destination was freed (an
    /// ancestor's revoke reached it after hoisting it, or its `CSpace` was
    /// torn down) while the source is still live — the source keeps the
    /// capability and whatever children remained under it.
    Lost(SyscallError),
    /// The liveness backstop tripped (`MAX_REPARENT_BATCHES`): a concurrent
    /// deriver kept extending the source's child list. Both slots stay
    /// live and unpinned, the destination a derived child of the source —
    /// the same shape `SYS_CAP_COPY` produces — so nothing leaves any
    /// ancestor's reach.
    Abandoned
    {
        handle: u32
    },
}

/// Begin a move: insert the destination, take its object reference, pin
/// both slots, and migrate the first batch of children. Completes inside
/// this hold when the source has at most [`MAX_REPARENT_EDITS`] children.
///
/// `src_handle` carries the caller's generation and is validated here,
/// under the locks, against the slot it names (#349). `dst_idx` `None`
/// auto-allocates; `Some` places at that index (`insert_cap_at`, whose
/// leaves the syscall path pre-grows).
///
/// Nothing is modified when an error is returned.
///
/// # Contract
///
/// - **Caller must hold `DERIVATION_LOCK`** for writing.
/// - **Caller must hold both `CSpace` locks** (or the single lock when the
///   pointers are equal), acquired via `lock_cspace_pair`.
///
/// # Safety
///
/// `src_cspace` and `dst_cspace` must be valid, live `CSpace` pointers.
pub unsafe fn move_cap_begin(
    src_cspace: *mut CSpace,
    src_handle: u32,
    dst_cspace: *mut CSpace,
    dst_idx: Option<NonZeroU32>,
) -> Result<MoveStep, SyscallError>
{
    let src_idx = syscall::cap_handle_index(src_handle);
    let src_idx_nz = NonZeroU32::new(src_idx).ok_or(SyscallError::InvalidCapability)?;

    let (tag, rights, object, badge, src_gen) = {
        // SAFETY: caller contract.
        let cs = unsafe { &*src_cspace };
        let slot = cs.slot(src_idx).ok_or(SyscallError::InvalidCapability)?;
        if slot.tag == CapTag::Null || slot.generation() != syscall::cap_handle_gen(src_handle)
        {
            return Err(SyscallError::InvalidCapability);
        }
        // A multi-batch revoke or move already in flight on this slot
        // (see `CapabilitySlot::pinned`). Transient — retry once it ends.
        if slot.pinned()
        {
            return Err(SyscallError::InvalidState);
        }
        (
            slot.tag,
            slot.rights,
            slot.object.ok_or(SyscallError::InvalidCapability)?,
            slot.badge,
            slot.generation(),
        )
    };

    let dst_idx_nz =
        match dst_idx
        {
            // SAFETY: caller contract; the destination lock is held.
            None => unsafe { (*dst_cspace).insert_cap(tag, rights, object) }
                .map_err(SyscallError::from)?,
            Some(idx) =>
            {
                // SAFETY: caller contract; the destination lock is held.
                unsafe { (*dst_cspace).insert_cap_at(idx.get(), tag, rights, object) }
                    .map_err(SyscallError::from)?;
                idx
            }
        };

    // Two slots name the object until the source is freed; the destination
    // holds its own reference so an ancestor's revoke freeing either slot
    // between batches drops exactly the reference that slot held.
    // SAFETY: object is the live header the source slot holds.
    unsafe { object.as_ref().inc_ref() };

    // SAFETY: caller contract; the destination lock is held.
    let (dst_gen, handle) = unsafe {
        let cs = &mut *dst_cspace;
        if let Some(slot) = cs.slot_mut(dst_idx_nz.get())
        {
            slot.badge = badge;
            slot.pin();
        }
        (
            cs.slot(dst_idx_nz.get())
                .map_or(0, super::slot::CapabilitySlot::generation),
            cs.cap_handle(dst_idx_nz),
        )
    };
    // SAFETY: caller contract; the source lock is held.
    unsafe {
        if let Some(slot) = (*src_cspace).slot_mut(src_idx)
        {
            slot.pin();
        }
    }

    // SAFETY: caller contract.
    let (src_id, dst_id) = unsafe { ((*src_cspace).id(), (*dst_cspace).id()) };
    let mv = CapMove {
        src: SlotId::current(src_id, src_idx_nz),
        src_gen,
        dst: SlotId::current(dst_id, dst_idx_nz),
        dst_gen,
        handle,
        object,
    };
    // SAFETY: DERIVATION_LOCK held (caller contract); both slots live and
    // pinned; the source lock is held by the caller.
    Ok(unsafe { move_cap_step(&mv, true, MAX_REPARENT_EDITS) })
}

/// Drive a pending move to completion, one [`MAX_REPARENT_EDITS`] batch
/// per `DERIVATION_LOCK` hold, revalidating both slots before each. Never
/// returns [`MoveStep::Pending`]; the source's object reference is
/// released here.
pub fn move_cap_drive(mv: CapMove) -> MoveStep
{
    use super::derivation::{DERIVATION_LOCK, MAX_REPARENT_BATCHES};

    // The first batch ran in `move_cap_begin`.
    let mut batches: u32 = 1;
    let mut mv = mv;
    loop
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; `live` resolves through the registry.
        let step = match unsafe {
            (
                live(mv.src, mv.src_gen, mv.object),
                live(mv.dst, mv.dst_gen, mv.object),
            )
        }
        {
            (false, false) => MoveStep::Lost(SyscallError::InvalidCapability),
            (false, true) =>
            {
                // Whoever freed the source (an ancestor's revoke, after
                // hoisting the destination out from under it) dropped the
                // reference it held; the destination is the capability now.
                // SAFETY: DERIVATION_LOCK held; dst resolved live.
                unsafe { unpin(mv.dst) };
                MoveStep::Done {
                    handle: mv.handle,
                    release: None,
                }
            }
            (true, false) =>
            {
                // SAFETY: DERIVATION_LOCK held; src resolved live.
                unsafe { unpin(mv.src) };
                MoveStep::Lost(SyscallError::InvalidState)
            }
            (true, true) =>
            {
                batches += 1;
                // SAFETY: DERIVATION_LOCK held; both slots live and pinned;
                // no CSpace lock is held.
                let step = unsafe { move_cap_step(&mv, false, MAX_REPARENT_EDITS) };
                if let MoveStep::Pending(_) = step
                    && batches >= MAX_REPARENT_BATCHES
                {
                    // Liveness backstop: leave the destination where the
                    // step re-linked it, as a derived child of the source.
                    // SAFETY: DERIVATION_LOCK held; both slots live.
                    unsafe {
                        unpin(mv.src);
                        unpin(mv.dst);
                    }
                    MoveStep::Abandoned { handle: mv.handle }
                }
                else
                {
                    step
                }
            }
        };
        DERIVATION_LOCK.write_unlock();

        match step
        {
            MoveStep::Pending(next) => mv = next,
            MoveStep::Done { handle, release } =>
            {
                if let Some(obj) = release
                {
                    release_moved_object(obj);
                }
                return MoveStep::Done {
                    handle,
                    release: None,
                };
            }
            other => return other,
        }
    }
}

/// Drop the object reference a freed source slot held; frees the object if
/// that was the last reference. Must run outside `DERIVATION_LOCK` —
/// `dealloc_object` may acquire the frame allocator and other inner locks.
pub fn release_moved_object(obj: NonNull<KernelObjectHeader>)
{
    // SAFETY: obj was a live capability object when the move began and the
    // freed source slot's reference is still outstanding.
    let remaining = unsafe { obj.as_ref().dec_ref() };
    #[cfg(not(test))]
    if remaining == 0
    {
        // SAFETY: refcount reached 0; no other references exist.
        unsafe { super::object::dealloc_object(obj) };
    }
    // The host harness leaks its objects; nothing to free.
    #[cfg(test)]
    let _ = remaining;
}

/// One migration batch: detach the destination from wherever it hangs (a
/// clean root fresh from insert, the source's child list between batches,
/// or a revoke root's list after a hoist), move up to `max_edits` of the
/// source's children under it, then either finish the move — the
/// destination takes the source's position, the source is freed — or
/// re-link the destination under the source for the next batch.
///
/// `src_lock_held`: whether the caller holds the source `CSpace` lock
/// (`move_cap_begin` does; the drive loop takes it here for the free).
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` for writing; both slots must have
/// been resolved live under this hold.
pub(crate) unsafe fn move_cap_step(mv: &CapMove, src_lock_held: bool, max_edits: usize)
-> MoveStep
{
    // SAFETY: caller contract.
    unsafe { unlink_node(mv.dst) };
    // SAFETY: caller contract.
    let done = unsafe { reparent_children(mv.src, Some(mv.dst), max_edits) };
    if !done
    {
        // SAFETY: caller contract; both slots live under this hold, so the
        // link cannot be dropped — a destination left a root between
        // batches would sit outside every ancestor's revoke reach.
        let linked = unsafe { link_child(mv.src, mv.dst) };
        debug_assert!(
            linked,
            "move: destination re-link dropped under DERIVATION_LOCK"
        );
        return MoveStep::Pending(*mv);
    }

    // The destination takes the source's position: its own links, then
    // every neighbour that points back at the source.
    // SAFETY: caller contract; short-lived borrows, one slot at a time.
    let (parent, prev, next) = match unsafe { resolve_slot_mut(mv.src) }
    {
        Some(s) => (s.deriv_parent, s.deriv_prev_sibling, s.deriv_next_sibling),
        None => (None, None, None),
    };
    // SAFETY: as above.
    if let Some(d) = unsafe { resolve_slot_mut(mv.dst) }
    {
        d.deriv_parent = parent;
        d.deriv_prev_sibling = prev;
        d.deriv_next_sibling = next;
        d.unpin();
    }
    if let Some(p) = parent
        // SAFETY: as above.
        && let Some(ps) = unsafe { resolve_slot_mut(p) }
        && ps.deriv_first_child == Some(mv.src)
    {
        ps.deriv_first_child = Some(mv.dst);
    }
    if let Some(p) = prev
        // SAFETY: as above.
        && let Some(ps) = unsafe { resolve_slot_mut(p) }
        && ps.deriv_next_sibling == Some(mv.src)
    {
        ps.deriv_next_sibling = Some(mv.dst);
    }
    if let Some(n) = next
        // SAFETY: as above.
        && let Some(ns) = unsafe { resolve_slot_mut(n) }
        && ns.deriv_prev_sibling == Some(mv.src)
    {
        ns.deriv_prev_sibling = Some(mv.dst);
    }

    // Free the source. Its links, pin, and generation are reset by the
    // free path. Lock order: DERIVATION_LOCK → cspace.lock.
    if let Some(cs) = super::lookup_cspace(mv.src.cspace_id, mv.src.epoch)
    {
        // SAFETY: registry-resolved live CSpace; lock_raw/unlock_raw paired.
        unsafe {
            let saved = if src_lock_held
            {
                None
            }
            else
            {
                Some((*cs).lock.lock_raw())
            };
            (*cs).free_slot(mv.src.index.get());
            if let Some(saved) = saved
            {
                (*cs).lock.unlock_raw(saved);
            }
        }
    }
    MoveStep::Done {
        handle: mv.handle,
        release: Some(mv.object),
    }
}

/// Whether `id` still holds the capability the move is relocating: occupied,
/// same generation, same object.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK`.
unsafe fn live(id: SlotId, generation: u8, object: NonNull<KernelObjectHeader>) -> bool
{
    // SAFETY: caller contract.
    unsafe { resolve_slot_mut(id) }.is_some_and(|s| {
        s.tag != CapTag::Null && s.generation() == generation && s.object == Some(object)
    })
}

/// Clear the in-flight pin on `id` if it resolves.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK`.
unsafe fn unpin(id: SlotId)
{
    // SAFETY: caller contract.
    if let Some(s) = unsafe { resolve_slot_mut(id) }
    {
        s.unpin();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cap::derivation::harness::*;
    use crate::cap::derivation::{DERIVATION_LOCK, MAX_REPARENT_EDITS};
    use crate::cap::object::ObjectType;
    use crate::cap::slot::CSpaceId;
    use core::sync::atomic::Ordering;

    /// A real header for the moved capability: the move takes and releases
    /// object references, which the harness's dangling object pointers
    /// cannot carry. Refcount starts at 1, standing in for the source slot.
    fn mk_object() -> NonNull<KernelObjectHeader>
    {
        NonNull::from(Box::leak(Box::new(KernelObjectHeader::new(
            ObjectType::Notification,
        ))))
    }

    fn refcount(obj: NonNull<KernelObjectHeader>) -> u32
    {
        // SAFETY: leaked header, valid for the process lifetime.
        unsafe { obj.as_ref() }.ref_count.load(Ordering::Relaxed)
    }

    /// A tree under `root` in `cs`: `src` (holding `obj`) with `kids`
    /// children, and a sibling `sib` after it in `root`'s list. Returns
    /// `(root, src, sib, kids, src_handle)`; the links are wired under the
    /// lock and asserted after release.
    fn mk_tree(
        cs: *mut CSpace,
        id: CSpaceId,
        kids: usize,
        obj: NonNull<KernelObjectHeader>,
    ) -> (SlotId, SlotId, SlotId, std::vec::Vec<SlotId>, u32)
    {
        let root = occupy(cs, id);
        let src = occupy(cs, id);
        let sib = occupy(cs, id);
        let kids = occupy_many(cs, id, kids);
        // SAFETY: single-threaded test ownership of the leaked CSpace.
        let src_handle = unsafe {
            (*cs).slot_mut(src.index.get()).expect("src slot").object = Some(obj);
            (*cs).cap_handle(src.index)
        };
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        // SAFETY: DERIVATION_LOCK held; all slots live.
        unsafe {
            linked &= link_child(root, sib);
            linked &= link_child(root, src);
            for k in &kids
            {
                linked &= link_child(src, *k);
            }
        }
        DERIVATION_LOCK.write_unlock();
        assert!(linked, "setup links must land");
        (root, src, sib, kids, src_handle)
    }

    /// Snapshot of one slot's derivation links and pin, read under the lock.
    #[derive(Debug, PartialEq, Eq)]
    struct Snap
    {
        parent: Option<SlotId>,
        first_child: Option<SlotId>,
        prev: Option<SlotId>,
        next: Option<SlotId>,
        pinned: bool,
        object: Option<NonNull<KernelObjectHeader>>,
    }

    /// `None` when the slot is Null or its CSpace is gone.
    fn snap(id: SlotId) -> Option<Snap>
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held.
        let s = unsafe { resolve_slot_mut(id) }.map(|s| Snap {
            parent: s.deriv_parent,
            first_child: s.deriv_first_child,
            prev: s.deriv_prev_sibling,
            next: s.deriv_next_sibling,
            pinned: s.pinned(),
            object: s.object,
        });
        DERIVATION_LOCK.write_unlock();
        s
    }

    fn parents_under(kids: &[SlotId], parent: SlotId) -> usize
    {
        kids.iter()
            .filter(|k| snap(**k).is_some_and(|s| s.parent == Some(parent)))
            .count()
    }

    fn dst_of(cs_id: CSpaceId, handle: u32) -> SlotId
    {
        SlotId::current(
            cs_id,
            NonZeroU32::new(syscall::cap_handle_index(handle)).expect("non-zero"),
        )
    }

    /// Run `move_cap_begin` under the lock (the harness holds no CSpace
    /// locks; the test CSpaces are single-threaded).
    fn begin(
        src_cs: *mut CSpace,
        src_handle: u32,
        dst_cs: *mut CSpace,
        dst_idx: Option<NonZeroU32>,
    ) -> Result<MoveStep, SyscallError>
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; test CSpaces are live and unshared.
        let r = unsafe { move_cap_begin(src_cs, src_handle, dst_cs, dst_idx) };
        DERIVATION_LOCK.write_unlock();
        r
    }

    /// Assert the completed shape: `dst` sits where `src` was under `root`
    /// (before `sib`), every kid hangs under it, `src` is Null, no pins.
    fn assert_moved(
        root: SlotId,
        src: SlotId,
        sib: SlotId,
        kids: &[SlotId],
        dst: SlotId,
        obj: NonNull<KernelObjectHeader>,
    )
    {
        let d = snap(dst).expect("destination live");
        assert_eq!(d.parent, Some(root));
        assert_eq!(d.prev, None);
        assert_eq!(d.next, Some(sib));
        assert!(!d.pinned, "destination unpinned once moved");
        assert_eq!(d.object, Some(obj));
        assert_eq!(snap(root).expect("root").first_child, Some(dst));
        assert_eq!(snap(sib).expect("sib").prev, Some(dst));
        assert_eq!(
            parents_under(kids, dst),
            kids.len(),
            "every child under dst"
        );
        assert!(snap(src).is_none(), "source slot freed");
    }

    #[test]
    fn single_batch_move_takes_source_position()
    {
        const ID_A: CSpaceId = 3201;
        const ID_B: CSpaceId = 3202;
        let a = mk_registered_cspace(ID_A);
        let b = mk_registered_cspace(ID_B);
        let obj = mk_object();
        let (root, src, sib, kids, handle) = mk_tree(a, ID_A, 3, obj);

        let step = begin(a, handle, b, None).expect("begin");
        let MoveStep::Done { handle, release } = step
        else
        {
            panic!("three children complete in one batch: {step:?}");
        };
        assert_eq!(
            release,
            Some(obj),
            "the freed source's reference is handed back"
        );
        assert_eq!(
            refcount(obj),
            2,
            "destination reference taken, source's outstanding"
        );
        release_moved_object(obj);
        assert_eq!(refcount(obj), 1);

        let dst = dst_of(ID_B, handle);
        assert_moved(root, src, sib, &kids, dst, obj);
        assert_eq!(count_populated(a), 5, "root, sib, three kids");
        assert_eq!(count_populated(b), 1);
        crate::cap::unregister_cspace(ID_A);
        crate::cap::unregister_cspace(ID_B);
    }

    #[test]
    fn multi_batch_move_keeps_destination_under_source_between_batches()
    {
        const ID_A: CSpaceId = 3203;
        const ID_B: CSpaceId = 3204;
        let a = mk_registered_cspace(ID_A);
        let b = mk_registered_cspace(ID_B);
        let obj = mk_object();
        let kids_n = MAX_REPARENT_EDITS + 44;
        let (root, src, sib, kids, handle) = mk_tree(a, ID_A, kids_n, obj);

        let step = begin(a, handle, b, None).expect("begin");
        let MoveStep::Pending(mv) = step
        else
        {
            panic!("more children than one batch must leave work: {step:?}");
        };
        let dst = dst_of(ID_B, mv.handle());

        // Between batches: dst is src's child, both pinned, src still in
        // root's list, one batch of children already under dst.
        let d = snap(dst).expect("destination live");
        assert_eq!(d.parent, Some(src));
        assert!(d.pinned);
        let s = snap(src).expect("source live");
        assert!(s.pinned);
        assert_eq!(s.parent, Some(root));
        assert_eq!(s.next, Some(sib));
        assert_eq!(
            s.first_child,
            Some(dst),
            "dst re-linked at the head of src's list"
        );
        assert_eq!(snap(root).expect("root").first_child, Some(src));
        assert_eq!(parents_under(&kids, dst), MAX_REPARENT_EDITS);
        assert_eq!(parents_under(&kids, src), 44);
        assert_eq!(refcount(obj), 2);

        let step = move_cap_drive(mv);
        let MoveStep::Done { handle, release } = step
        else
        {
            panic!("the second batch completes: {step:?}");
        };
        assert_eq!(handle, mv.handle());
        assert_eq!(
            release, None,
            "drive releases the source's reference itself"
        );
        assert_eq!(refcount(obj), 1);
        assert_moved(root, src, sib, &kids, dst, obj);
        crate::cap::unregister_cspace(ID_A);
        crate::cap::unregister_cspace(ID_B);
    }

    #[test]
    fn explicit_destination_index()
    {
        const ID_A: CSpaceId = 3205;
        const ID_B: CSpaceId = 3206;
        let a = mk_registered_cspace(ID_A);
        let b = mk_registered_cspace(ID_B);
        let obj = mk_object();
        let (root, src, sib, kids, handle) = mk_tree(a, ID_A, 2, obj);
        let want = NonZeroU32::new(40).expect("non-zero");

        let step = begin(a, handle, b, Some(want)).expect("begin");
        let MoveStep::Done { handle, release } = step
        else
        {
            panic!("two children complete in one batch: {step:?}");
        };
        assert_eq!(syscall::cap_handle_index(handle), want.get());
        release_moved_object(release.expect("release"));
        assert_moved(root, src, sib, &kids, SlotId::current(ID_B, want), obj);
        crate::cap::unregister_cspace(ID_A);
        crate::cap::unregister_cspace(ID_B);
    }

    #[test]
    fn pinned_or_stale_source_is_refused_untouched()
    {
        const ID_A: CSpaceId = 3207;
        const ID_B: CSpaceId = 3208;
        let a = mk_registered_cspace(ID_A);
        let b = mk_registered_cspace(ID_B);
        let obj = mk_object();
        let (_root, src, _sib, _kids, handle) = mk_tree(a, ID_A, 1, obj);

        let stale = syscall::cap_handle_encode(
            src.index.get(),
            syscall::cap_handle_gen(handle).wrapping_add(1),
        );
        assert!(matches!(
            begin(a, stale, b, None),
            Err(SyscallError::InvalidCapability)
        ));

        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; src live.
        unsafe { resolve_slot_mut(src) }.expect("src").pin();
        DERIVATION_LOCK.write_unlock();
        assert!(matches!(
            begin(a, handle, b, None),
            Err(SyscallError::InvalidState)
        ));

        assert_eq!(count_populated(b), 0, "nothing inserted");
        assert_eq!(refcount(obj), 1, "no reference taken");
        assert!(snap(src).is_some_and(|s| s.pinned), "source untouched");
        crate::cap::unregister_cspace(ID_A);
        crate::cap::unregister_cspace(ID_B);
    }

    /// Simulate an ancestor's revoke reaching a pending move: hoist `dst`
    /// under `root`, hoist `src`'s remaining children there too, then
    /// free `src` (dropping the reference its slot held).
    fn revoke_takes_source(cs: *mut CSpace, root: SlotId, src: SlotId, dst: SlotId)
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; all slots live.
        unsafe {
            unlink_node(dst);
            assert!(link_child(root, dst));
            assert!(reparent_children(src, Some(root), usize::MAX));
            unlink_node(src);
            let obj = (*cs).slot(src.index.get()).and_then(|s| s.object);
            (*cs).free_slot(src.index.get());
            obj.expect("object").as_ref().dec_ref();
        }
        DERIVATION_LOCK.write_unlock();
    }

    #[test]
    fn source_consumed_between_batches_completes_without_release()
    {
        const ID_A: CSpaceId = 3209;
        const ID_B: CSpaceId = 3210;
        let a = mk_registered_cspace(ID_A);
        let b = mk_registered_cspace(ID_B);
        let obj = mk_object();
        let (root, src, _sib, _kids, handle) = mk_tree(a, ID_A, MAX_REPARENT_EDITS + 1, obj);
        let MoveStep::Pending(mv) = begin(a, handle, b, None).expect("begin")
        else
        {
            panic!("expected a pending move");
        };
        let dst = dst_of(ID_B, mv.handle());
        revoke_takes_source(a, root, src, dst);
        assert_eq!(refcount(obj), 1, "only the destination's reference remains");

        let step = move_cap_drive(mv);
        assert!(
            matches!(step, MoveStep::Done { release: None, .. }),
            "destination is the capability now: {step:?}"
        );
        assert_eq!(refcount(obj), 1, "nothing further released");
        let d = snap(dst).expect("destination live");
        assert!(!d.pinned);
        assert_eq!(d.parent, Some(root), "left where the revoke hoisted it");
        crate::cap::unregister_cspace(ID_A);
        crate::cap::unregister_cspace(ID_B);
    }

    #[test]
    fn both_slots_gone_is_lost_invalid_capability()
    {
        const ID_A: CSpaceId = 3211;
        const ID_B: CSpaceId = 3212;
        let a = mk_registered_cspace(ID_A);
        let b = mk_registered_cspace(ID_B);
        let obj = mk_object();
        let (root, src, _sib, _kids, handle) = mk_tree(a, ID_A, MAX_REPARENT_EDITS + 1, obj);
        let MoveStep::Pending(mv) = begin(a, handle, b, None).expect("begin")
        else
        {
            panic!("expected a pending move");
        };
        let dst = dst_of(ID_B, mv.handle());
        revoke_takes_source(a, root, src, dst);
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; dst live.
        unsafe {
            assert!(reparent_children(dst, Some(root), usize::MAX));
            unlink_node(dst);
            (*b).free_slot(dst.index.get());
            obj.as_ref().dec_ref();
        }
        DERIVATION_LOCK.write_unlock();

        assert!(matches!(
            move_cap_drive(mv),
            MoveStep::Lost(SyscallError::InvalidCapability)
        ));
        crate::cap::unregister_cspace(ID_A);
        crate::cap::unregister_cspace(ID_B);
    }

    #[test]
    fn destination_gone_is_lost_invalid_state_and_unpins_source()
    {
        const ID_A: CSpaceId = 3213;
        const ID_B: CSpaceId = 3214;
        let a = mk_registered_cspace(ID_A);
        let b = mk_registered_cspace(ID_B);
        let obj = mk_object();
        let (root, src, _sib, kids, handle) = mk_tree(a, ID_A, MAX_REPARENT_EDITS + 1, obj);
        let MoveStep::Pending(mv) = begin(a, handle, b, None).expect("begin")
        else
        {
            panic!("expected a pending move");
        };
        let dst = dst_of(ID_B, mv.handle());
        // The destination's CSpace is torn down: its drain orphans dst's
        // children into roots and unlinks dst.
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; dst live.
        unsafe {
            assert!(reparent_children(dst, None, usize::MAX));
            unlink_node(dst);
            (*b).free_slot(dst.index.get());
            obj.as_ref().dec_ref();
        }
        DERIVATION_LOCK.write_unlock();

        assert!(matches!(
            move_cap_drive(mv),
            MoveStep::Lost(SyscallError::InvalidState)
        ));
        let s = snap(src).expect("source keeps the capability");
        assert!(!s.pinned);
        assert_eq!(s.parent, Some(root));
        assert_eq!(
            parents_under(&kids, src),
            1,
            "the unmigrated child stays under src"
        );
        assert_eq!(refcount(obj), 1);
        crate::cap::unregister_cspace(ID_A);
        crate::cap::unregister_cspace(ID_B);
    }
}
