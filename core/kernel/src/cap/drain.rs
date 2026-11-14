// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/cap/drain.rs

//! Derivation drain of a dying `CSpace`.
//!
//! Before a `CSpace` torn down at refcount zero unregisters, its teardown
//! takes every one of its slots out of the derivation forest. Each capability
//! derived through a dying slot is re-linked under the nearest ancestor
//! outside the dying `CSpace`, as a delete re-links a consumed slot's children
//! under its parent, so it stays inside every revoke above it; it becomes a
//! derivation root only when no such ancestor exists. The drain runs in
//! step-bounded batches under `DERIVATION_LOCK`, its total work linear in what
//! the dying `CSpace` holds whatever the shape of its trees and the order of
//! its indices.
//!
//! Design: [capability-internals.md](../../docs/capability-internals.md)
//! § Teardown Drain.

use core::num::NonZeroU32;

use super::cspace::{CSpace, L2_SIZE};
use super::derivation::{link_child, resolve_slot_mut, truncate_dead_link, unlink_node};
use super::slot::{CSpaceId, SlotId};

/// Maximum drain steps per `DERIVATION_LOCK` hold while draining a dying
/// `CSpace` (mirrors `MAX_REVOKE_EDITS`). Every step is one slot examined, one
/// ascent, or one constant-time link edit, so the teardown of an arbitrarily
/// large donor-funded `CSpace` releases the global lock between batches, and
/// concurrent derivation traffic never stalls behind more than a constant
/// amount of drain work.
pub const MAX_DRAIN_EDITS: usize = 256;

/// The drain's position, kept by the teardown across its lock holds.
///
/// `cursor` is the next slot index the scan examines; it passes a slot only
/// once that slot is out of the forest (no parent, children, or siblings).
/// `pending` is the dying slot the drain is working from: ascending from it
/// to the top of its region, or flattening the region from that top.
pub struct DrainState
{
    cursor: u32,
    pending: Option<NonZeroU32>,
    /// Ascents since the drain last stood on a region top; more than the
    /// `CSpace` has slots can only be a cycle of parent links.
    ascents: u32,
    /// Steps taken across every batch, for the host tests' linear bound.
    #[cfg(test)]
    steps: usize,
}

impl DrainState
{
    /// A drain that has not started.
    pub const fn new() -> Self
    {
        Self {
            cursor: 0,
            pending: None,
            ascents: 0,
            #[cfg(test)]
            steps: 0,
        }
    }
}

/// The dying `CSpace`'s registry identity: a [`SlotId`] that carries it names
/// a dying slot.
#[derive(Clone, Copy)]
struct Dying
{
    id: CSpaceId,
    epoch: u32,
}

impl Dying
{
    fn holds(self, slot: SlotId) -> bool
    {
        slot.cspace_id == self.id && slot.epoch == self.epoch
    }

    fn slot(self, index: NonZeroU32) -> SlotId
    {
        SlotId::with_epoch(self.id, self.epoch, index)
    }
}

/// Drain one batch of a dying `CSpace`'s derivation state: at most
/// [`MAX_DRAIN_EDITS`] steps.
///
/// A *region* is a maximal connected group of dying slots in one derivation
/// tree; its *top* is the dying slot whose parent is outside the dying
/// `CSpace`, or absent. The scan finds each slot still in the forest, ascends
/// to its region's top, and flattens the region from there with the revoke
/// walk's stackless hoist, one constant-time edit per step on the top's head
/// `H`:
///
/// - `H` outside the dying `CSpace`: unlink it and link it under the top's
///   parent `P` (a root when there is none, or when `P` no longer resolves).
/// - `H` dying with a first child `G`: unlink `G`; link it under the top when
///   it is dying (it stays in the region), under `P` when it is not.
/// - `H` dying and childless: unlink it (drained).
/// - No `H`: unlink the top (drained); the scan resumes.
///
/// Every capability outside the dying `CSpace` that hangs under a region is
/// therefore re-linked once, directly under `P`, and every dying slot is
/// ascended over, hoisted and unlinked at most once, so the total work is
/// linear for any shape and index order. `P` is re-read at every step, since
/// a foreign delete can re-link the top between holds.
///
/// The first batch marks the `CSpace` draining ([`CSpace::set_draining`]):
/// from then on no IPC capability transfer or in-flight move takes a
/// capability into or out of it.
///
/// Every edit leaves the forest consistent, so the caller releases
/// `DERIVATION_LOCK` between batches and a foreign traversal in the window
/// sees ordinary nodes: a revoke above a region hoists or frees dying slots
/// like any others, and whatever the drain re-links lands under `P`, inside
/// that revoke's subtree. A slot such a window moves out of its region is
/// examined again, because the scan passes a slot only once it is out of the
/// forest. Work can still arrive between holds — a foreign delete of a slot
/// under a dying one re-links its children there — so the loop is bounded by
/// contention rather than by a constant, and carries no batch backstop (a
/// teardown cannot fail).
///
/// A link that fails to resolve, or an unlink that makes no progress, is
/// contained as everywhere else: the list hanging from it is truncated
/// ([`truncate_dead_link`]) and logged, and the drain continues. More ascents
/// than the `CSpace` has slots can only be a cycle of parent links; the slot
/// it stands on is unlinked from its parent, which breaks the cycle.
///
/// Returns `true` once every slot is out of the forest (the caller then
/// unregisters the `CSpace` in the same hold); `false` when the budget ran
/// out (call again with the same state).
///
/// # Safety
///
/// Caller MUST hold `DERIVATION_LOCK` write lock. `cs_ptr` MUST be a valid
/// `CSpace` whose refcount has reached zero, every thread bound to it
/// stopped, and its registry entry (`dying_id`, `dying_epoch`) still live:
/// the caller unregisters it only after the final batch, in the same hold,
/// so foreign readers see a consistent "drained, then absent" transition.
pub unsafe fn drain_dying_cspace_batch(
    cs_ptr: *mut CSpace,
    dying_id: CSpaceId,
    dying_epoch: u32,
    state: &mut DrainState,
) -> bool
{
    let dying = Dying {
        id: dying_id,
        epoch: dying_epoch,
    };
    // SAFETY: forwarded caller contract.
    unsafe { drain_batch(cs_ptr, dying, state, MAX_DRAIN_EDITS) }
}

/// [`drain_dying_cspace_batch`] with the step budget as a parameter; the
/// host tests run it with small budgets to interleave foreign edits.
///
/// # Safety
///
/// As for [`drain_dying_cspace_batch`].
unsafe fn drain_batch(cs_ptr: *mut CSpace, dying: Dying, st: &mut DrainState, budget: usize)
-> bool
{
    // SAFETY: caller contract: cs_ptr is valid; the flag is atomic, written
    // under DERIVATION_LOCK.
    unsafe { (*cs_ptr).set_draining() };
    // Leaves are contiguous behind the grow cursor, so the leaf count bounds
    // the slot range exactly. `MAX_SLOTS_STRUCTURAL` fits a slot index, so the
    // conversion never fails.
    // SAFETY: caller contract: cs_ptr is valid and uniquely owned.
    let leaves = unsafe { (*cs_ptr).leaf_count() };
    let slot_count = u32::try_from(leaves.saturating_mul(L2_SIZE)).unwrap_or(u32::MAX);
    let mut steps = 0usize;
    loop
    {
        if st.pending.is_none() && st.cursor >= slot_count
        {
            return true;
        }
        if steps >= budget
        {
            return false;
        }
        // Below `budget`, checked above: does not saturate.
        steps = steps.saturating_add(1);
        #[cfg(test)]
        {
            st.steps = st.steps.saturating_add(1);
        }
        match st.pending
        {
            None =>
            {
                // SAFETY: DERIVATION_LOCK held (caller contract).
                unsafe { examine(dying, st) };
            }
            Some(x) =>
            {
                // SAFETY: DERIVATION_LOCK held (caller contract).
                st.pending = unsafe { step(dying, x, slot_count, &mut st.ascents) };
            }
        }
    }
}

/// One scan step: pass the slot at the cursor if it is out of the forest
/// (empty, or occupied with no links), else start working from it.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; the dying `CSpace` is
/// registered.
unsafe fn examine(dying: Dying, st: &mut DrainState)
{
    let index = NonZeroU32::new(st.cursor);
    let in_forest = index.is_some_and(|i| {
        // SAFETY: DERIVATION_LOCK held (caller contract). A Null slot does not
        // resolve (the occupancy gate) and has no derivation links.
        unsafe { resolve_slot_mut(dying.slot(i)) }.is_some_and(|s| {
            s.deriv_parent.is_some()
                || s.deriv_first_child.is_some()
                || s.deriv_prev_sibling.is_some()
                || s.deriv_next_sibling.is_some()
        })
    });
    if in_forest
    {
        st.pending = index;
        st.ascents = 0;
    }
    else
    {
        // The cursor stays below the slot count, which is below `u32::MAX`:
        // does not saturate.
        st.cursor = st.cursor.saturating_add(1);
    }
}

/// One step from the pending dying slot `x`: ascend to its parent if that is
/// dying, else flatten one edit of the region `x` tops. Returns the next
/// pending slot; `None` hands back to the scan.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; the dying `CSpace` is
/// registered.
unsafe fn step(
    dying: Dying,
    x_index: NonZeroU32,
    ascent_limit: u32,
    ascents: &mut u32,
) -> Option<NonZeroU32>
{
    let x = dying.slot(x_index);
    // SAFETY: DERIVATION_LOCK held (caller contract).
    let Some((parent, head)) =
        (unsafe { resolve_slot_mut(x) }).map(|s| (s.deriv_parent, s.deriv_first_child))
    else
    {
        // A foreign revoke freed `x` between holds; the scan examines its
        // own slot again.
        return None;
    };

    if let Some(p) = parent
        && dying.holds(p)
        // SAFETY: DERIVATION_LOCK held (caller contract).
        && unsafe { resolve_slot_mut(p) }.is_some()
    {
        if *ascents < ascent_limit
        {
            // Below `ascent_limit`: does not saturate.
            *ascents = ascents.saturating_add(1);
            return Some(p.index);
        }
        // A chain of dying slots is at most as long as the CSpace has slots,
        // and no edit puts a slot under one of its own descendants, so only a
        // cycle of parent links (corruption) gets here. Cut it at `x`.
        #[cfg(not(test))]
        crate::kprintln!(
            "cap: derivation parent cycle at cspace {} slot {} in teardown drain; unlinking",
            dying.id,
            x_index.get()
        );
        // SAFETY: DERIVATION_LOCK held (caller contract).
        unsafe { unlink_node(x) };
        *ascents = 0;
        return Some(x_index);
    }

    // `x` tops its region; `parent` is the ancestor outside it (or none, or
    // a dying parent that no longer resolves, which no link lands under).
    *ascents = 0;
    let Some(h) = head
    else
    {
        // SAFETY: DERIVATION_LOCK held (caller contract).
        unsafe { unlink_node(x) };
        return None;
    };
    // SAFETY: DERIVATION_LOCK held (caller contract).
    let Some(grandchild) = (unsafe { resolve_slot_mut(h) }).map(|s| s.deriv_first_child)
    else
    {
        // SAFETY: DERIVATION_LOCK held (caller contract).
        unsafe { truncate_dead_link(x, h, "teardown drain") };
        return Some(x_index);
    };

    if !dying.holds(h)
    {
        // SAFETY: DERIVATION_LOCK held (caller contract); h resolves.
        if unsafe { pop_head(x, h) }
            && let Some(p) = parent
        {
            // SAFETY: DERIVATION_LOCK held; h is a clean root. A parent that
            // no longer resolves is a dead link, and h stays a root.
            let _ = unsafe { link_child(p, h) };
        }
        return Some(x_index);
    }

    let Some(g) = grandchild
    else
    {
        // SAFETY: DERIVATION_LOCK held (caller contract); h resolves. `h` is
        // drained once unlinked; a failed pop truncated x's list instead.
        let _ = unsafe { pop_head(x, h) };
        return Some(x_index);
    };
    // SAFETY: DERIVATION_LOCK held (caller contract).
    if unsafe { resolve_slot_mut(g) }.is_none()
    {
        // SAFETY: DERIVATION_LOCK held (caller contract); h resolves.
        unsafe { truncate_dead_link(h, g, "teardown drain") };
        return Some(x_index);
    }
    // SAFETY: DERIVATION_LOCK held (caller contract); g resolves.
    if unsafe { pop_head(h, g) }
    {
        if dying.holds(g)
        {
            // SAFETY: DERIVATION_LOCK held; x and g resolved in this hold.
            let linked = unsafe { link_child(x, g) };
            debug_assert!(linked, "drain hoist link dropped under DERIVATION_LOCK");
        }
        else if let Some(p) = parent
        {
            // SAFETY: DERIVATION_LOCK held; g is a clean root. A parent that
            // no longer resolves is a dead link, and g stays a root.
            let _ = unsafe { link_child(p, g) };
        }
    }
    Some(x_index)
}

/// Unlink `head`, the first child of `owner`; `true` when it left `owner`'s
/// list. A pop that leaves `owner`'s list unchanged (`head`'s own links do
/// not lead back to `owner`) truncates that list, as the revoke and reparent
/// walks do, and returns `false`.
///
/// # Safety
///
/// Caller must hold `DERIVATION_LOCK` write lock; `head` resolves.
unsafe fn pop_head(owner: SlotId, head: SlotId) -> bool
{
    // SAFETY: DERIVATION_LOCK held (caller contract).
    unsafe { unlink_node(head) };
    // SAFETY: DERIVATION_LOCK held (caller contract).
    let still_head = (unsafe { resolve_slot_mut(owner) }).and_then(|s| s.deriv_first_child);
    if still_head == Some(head)
    {
        // SAFETY: DERIVATION_LOCK held (caller contract).
        unsafe { truncate_dead_link(owner, head, "teardown drain") };
        return false;
    }
    true
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::cap::derivation::harness::*;
    use crate::cap::derivation::{BatchStatus, DERIVATION_LOCK, revoke_subtree_batch};
    use crate::cap::registry_epoch;

    /// More drain calls than any test needs: a drain that has not finished by
    /// then does not terminate.
    const CALL_LIMIT: usize = 100_000;

    /// How a run of drain batches went.
    struct Run
    {
        calls: usize,
        /// The most steps one call took.
        max_call: usize,
        done: bool,
    }

    /// Drain `id` to completion (or `CALL_LIMIT` calls), one lock hold per
    /// call, `budget` steps per call; `MAX_DRAIN_EDITS` runs the production
    /// entry point. The `CSpace` stays registered so its slots can be read.
    fn drain_all(cs: *mut CSpace, id: CSpaceId, st: &mut DrainState, budget: usize) -> Run
    {
        let epoch = registry_epoch(id);
        let mut run = Run {
            calls: 0,
            max_call: 0,
            done: false,
        };
        while run.calls < CALL_LIMIT
        {
            let before = st.steps;
            DERIVATION_LOCK.write_lock();
            let done = if budget == MAX_DRAIN_EDITS
            {
                // SAFETY: DERIVATION_LOCK held; the test CSpace is registered
                // and unshared.
                unsafe { drain_dying_cspace_batch(cs, id, epoch, st) }
            }
            else
            {
                // SAFETY: as above.
                unsafe { drain_batch(cs, Dying { id, epoch }, st, budget) }
            };
            DERIVATION_LOCK.write_unlock();
            run.calls += 1;
            run.max_call = run.max_call.max(st.steps - before);
            if done
            {
                run.done = true;
                break;
            }
        }
        run
    }

    /// A slot's `(parent, first_child, prev, next)`.
    type LinkSet = (
        Option<SlotId>,
        Option<SlotId>,
        Option<SlotId>,
        Option<SlotId>,
    );

    /// `id`'s links, `None` when it does not resolve.
    fn links(id: SlotId) -> Option<LinkSet>
    {
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held.
        let l = unsafe { resolve_slot_mut(id) }.map(|s| {
            (
                s.deriv_parent,
                s.deriv_first_child,
                s.deriv_prev_sibling,
                s.deriv_next_sibling,
            )
        });
        DERIVATION_LOCK.write_unlock();
        l
    }

    fn parent_of(id: SlotId) -> Option<SlotId>
    {
        links(id).and_then(|l| l.0)
    }

    /// Occupied and out of the forest.
    fn isolated(id: SlotId) -> bool
    {
        links(id) == Some((None, None, None, None))
    }

    /// `id`'s children, head first; at most `limit + 1` of them, so a cyclic
    /// list ends the walk.
    fn children_of(id: SlotId, limit: usize) -> Vec<SlotId>
    {
        let mut out = Vec::new();
        let mut cur = links(id).and_then(|l| l.1);
        while let Some(c) = cur
        {
            out.push(c);
            if out.len() > limit
            {
                break;
            }
            cur = links(c).and_then(|l| l.3);
        }
        out
    }

    /// Link each `(parent, child)` pair under the lock; whether every link
    /// landed.
    fn link_all(pairs: &[(SlotId, SlotId)]) -> bool
    {
        DERIVATION_LOCK.write_lock();
        let mut linked = true;
        for &(p, c) in pairs
        {
            // SAFETY: DERIVATION_LOCK held; both slots live.
            linked &= unsafe { link_child(p, c) };
        }
        DERIVATION_LOCK.write_unlock();
        linked
    }

    fn slot_count(cs: *mut CSpace) -> usize
    {
        // SAFETY: single-threaded test ownership of the leaked CSpace.
        (unsafe { (*cs).leaf_count() }) * L2_SIZE
    }

    // Defect guarded: a drain that detaches a dying slot's children into
    // roots, taking them out of the revoke reach of the ancestor outside the
    // dying CSpace; and a drain that re-links per slot, whose cost is
    // quadratic when each dying parent sits at a higher index than its child.
    #[test]
    fn a_reverse_index_chain_relinks_every_foreign_child_once_in_linear_steps()
    {
        const ID_F: CSpaceId = 3301;
        const ID_D: CSpaceId = 3302;
        const N: usize = 300;
        let f_cs = mk_registered_cspace(ID_F);
        let d_cs = mk_registered_cspace(ID_D);
        let a = occupy(f_cs, ID_F);
        let d = occupy_many(d_cs, ID_D, N);
        let f = occupy_many(f_cs, ID_F, N);
        // a → d[N-1] → d[N-2] → … → d[0]: every parent at a higher index.
        let mut pairs = vec![(a, d[N - 1])];
        pairs.extend((0..N - 1).map(|i| (d[i + 1], d[i])));
        pairs.extend((0..N).map(|i| (d[i], f[i])));
        assert!(link_all(&pairs), "setup links must land");

        let mut st = DrainState::new();
        let run = drain_all(d_cs, ID_D, &mut st, MAX_DRAIN_EDITS);

        assert!(run.done, "the drain must finish");
        assert!(run.calls > 1, "the drain must span more than one hold");
        assert!(
            run.max_call <= MAX_DRAIN_EDITS,
            "a hold took {}",
            run.max_call
        );
        // Linear: each dying slot examined twice, ascended over, and unlinked
        // once, each foreign child re-linked once, each slot index scanned.
        // A per-slot re-link would take about N²/2 = 45000 steps here.
        let bound = 5 * N + 2 * slot_count(d_cs);
        assert!(st.steps <= bound, "{} steps exceed {bound}", st.steps);
        assert!(
            f.iter().all(|&c| parent_of(c) == Some(a)),
            "every foreign child under a"
        );
        assert_eq!(
            children_of(a, 2 * N).len(),
            N,
            "a lists exactly the foreign children"
        );
        assert!(
            d.iter().all(|&s| isolated(s)),
            "every dying slot out of the forest"
        );
        crate::cap::unregister_cspace(ID_D);
        crate::cap::unregister_cspace(ID_F);
    }

    // Defect guarded: a capability that escapes a revoke running between
    // drain batches, or a drain that leaves a dead link for the revoke to
    // trip over.
    #[test]
    fn a_revoke_between_drain_batches_still_reaches_every_foreign_descendant()
    {
        const ID_F: CSpaceId = 3303;
        const ID_D: CSpaceId = 3304;
        const N: usize = 120;
        let f_cs = mk_registered_cspace(ID_F);
        let d_cs = mk_registered_cspace(ID_D);
        let anc = occupy(f_cs, ID_F);
        let chain = occupy_many(d_cs, ID_D, N);
        let kids = occupy_many(f_cs, ID_F, N);
        let grandkids = occupy_many(f_cs, ID_F, N);
        let inner = occupy_many(d_cs, ID_D, N / 3);
        let inner_kids = occupy_many(f_cs, ID_F, N / 3);
        let mut pairs = vec![(anc, chain[N - 1])];
        pairs.extend((0..N - 1).map(|i| (chain[i + 1], chain[i])));
        pairs.extend((0..N).map(|i| (chain[i], kids[i])));
        pairs.extend((0..N).map(|i| (kids[i], grandkids[i])));
        // A second region under a foreign slot: kids[3k] → inner[k] → inner_kids[k].
        pairs.extend((0..N / 3).map(|k| (kids[3 * k], inner[k])));
        pairs.extend((0..N / 3).map(|k| (inner[k], inner_kids[k])));
        assert!(link_all(&pairs), "setup links must land");

        let epoch = registry_epoch(ID_D);
        let mut st = DrainState::new();
        let mut drained = false;
        let mut cleared = false;
        let mut dead_link = false;
        let mut rounds = 0;
        while !(drained && cleared) && rounds < CALL_LIMIT
        {
            DERIVATION_LOCK.write_lock();
            if !drained
            {
                // SAFETY: DERIVATION_LOCK held; the test CSpace is registered.
                drained = unsafe { drain_batch(d_cs, Dying { id: ID_D, epoch }, &mut st, 17) };
            }
            // SAFETY: DERIVATION_LOCK held; anc is live.
            let (_, status) = unsafe { revoke_subtree_batch(anc) };
            DERIVATION_LOCK.write_unlock();
            dead_link |= status == BatchStatus::DeadLink;
            cleared = status == BatchStatus::Cleared;
            rounds += 1;
        }

        assert!(drained && cleared, "both walks must finish");
        assert!(!dead_link, "the drain leaves no dead link");
        assert_eq!(
            count_populated(f_cs),
            1,
            "the revoke freed every foreign descendant"
        );
        let survivors: Vec<SlotId> = chain
            .iter()
            .chain(&inner)
            .copied()
            .filter(|&s| links(s).is_some())
            .collect();
        assert!(
            survivors.iter().all(|&s| isolated(s)),
            "a dying slot the revoke did not free is out of the forest"
        );
        crate::cap::unregister_cspace(ID_D);
        crate::cap::unregister_cspace(ID_F);
    }

    // Defect guarded: a drain that drops, or invents, structure under a dying
    // root: its foreign children have no ancestor left and become roots, and
    // their own subtrees stay whole.
    #[test]
    fn a_dying_root_leaves_its_foreign_children_roots_with_their_subtrees()
    {
        const ID_F: CSpaceId = 3305;
        const ID_D: CSpaceId = 3306;
        let f_cs = mk_registered_cspace(ID_F);
        let d_cs = mk_registered_cspace(ID_D);
        let d1 = occupy(d_cs, ID_D);
        let d2 = occupy(d_cs, ID_D);
        let f1 = occupy(f_cs, ID_F);
        let f2 = occupy(f_cs, ID_F);
        let f3 = occupy(f_cs, ID_F);
        let f1c = occupy(f_cs, ID_F);
        assert!(link_all(&[
            (d1, f1),
            (d1, f2),
            (d1, d2),
            (d2, f3),
            (f1, f1c)
        ]));

        let mut st = DrainState::new();
        let run = drain_all(d_cs, ID_D, &mut st, MAX_DRAIN_EDITS);

        assert!(run.done);
        for root in [f1, f2, f3]
        {
            let l = links(root).expect("live");
            assert_eq!((l.0, l.2, l.3), (None, None, None), "a clean root");
        }
        assert_eq!(parent_of(f1c), Some(f1), "a foreign subtree stays whole");
        assert!(isolated(d1) && isolated(d2));
        crate::cap::unregister_cspace(ID_D);
        crate::cap::unregister_cspace(ID_F);
    }

    // Defect guarded: a drain that skips an ancestor in another CSpace, or
    // whose second teardown loses what the first re-linked.
    #[test]
    fn children_land_under_a_parent_in_another_cspace_through_two_teardowns()
    {
        const ID_F: CSpaceId = 3307;
        const ID_E: CSpaceId = 3308;
        const ID_D: CSpaceId = 3309;
        let f_cs = mk_registered_cspace(ID_F);
        let e_cs = mk_registered_cspace(ID_E);
        let d_cs = mk_registered_cspace(ID_D);
        let r = occupy(f_cs, ID_F);
        let a = occupy(e_cs, ID_E);
        let d = occupy(d_cs, ID_D);
        let c = occupy(f_cs, ID_F);
        assert!(link_all(&[(r, a), (a, d), (d, c)]));

        let mut st = DrainState::new();
        assert!(drain_all(d_cs, ID_D, &mut st, MAX_DRAIN_EDITS).done);
        crate::cap::unregister_cspace(ID_D);
        assert_eq!(
            parent_of(c),
            Some(a),
            "c under the ancestor in the other CSpace"
        );

        let mut st = DrainState::new();
        assert!(drain_all(e_cs, ID_E, &mut st, MAX_DRAIN_EDITS).done);
        assert_eq!(
            parent_of(c),
            Some(r),
            "the second teardown re-links c under r"
        );
        assert!(isolated(a));
        crate::cap::unregister_cspace(ID_E);
        crate::cap::unregister_cspace(ID_F);
    }

    // Defect guarded: a dead link that pins the drain in a loop, or that
    // leaves a foreign child naming a vanished parent.
    #[test]
    fn dead_heads_grandchildren_and_parents_are_contained()
    {
        const ID_F: CSpaceId = 3310;
        const ID_D: CSpaceId = 3311;
        const ID_X: CSpaceId = 3312;
        let f_cs = mk_registered_cspace(ID_F);
        let d_cs = mk_registered_cspace(ID_D);
        let x_cs = mk_registered_cspace(ID_X);
        // A dying slot whose head dies: d1 → x1.
        let d1 = occupy(d_cs, ID_D);
        let x1 = occupy(x_cs, ID_X);
        // A region whose grandchild dies: f0 → t → h → x2.
        let f0 = occupy(f_cs, ID_F);
        let t = occupy(d_cs, ID_D);
        let h = occupy(d_cs, ID_D);
        let x2 = occupy(x_cs, ID_X);
        // A top whose parent dies: x3 → d3 → c.
        let x3 = occupy(x_cs, ID_X);
        let d3 = occupy(d_cs, ID_D);
        let c = occupy(f_cs, ID_F);
        assert!(link_all(&[
            (d1, x1),
            (f0, t),
            (t, h),
            (h, x2),
            (x3, d3),
            (d3, c)
        ]));
        crate::cap::unregister_cspace(ID_X);

        let mut st = DrainState::new();
        let run = drain_all(d_cs, ID_D, &mut st, MAX_DRAIN_EDITS);

        assert!(run.done, "containment ends every walk");
        assert!([d1, t, h, d3].iter().all(|&s| isolated(s)));
        assert!(
            isolated(c),
            "a child of a top whose parent died becomes a clean root"
        );
        assert_eq!(links(f0).map(|l| l.1), Some(None), "the region left f0");
        crate::cap::unregister_cspace(ID_D);
        crate::cap::unregister_cspace(ID_F);
    }

    // Defect guarded: a scan that passes a dying slot a revoke hoisted out of
    // its region between holds, leaving its foreign children behind.
    #[test]
    fn a_dying_slot_moved_out_of_its_region_between_holds_is_still_drained()
    {
        const ID_F: CSpaceId = 3313;
        const ID_D: CSpaceId = 3314;
        let f_cs = mk_registered_cspace(ID_F);
        let d_cs = mk_registered_cspace(ID_D);
        let a = occupy(f_cs, ID_F);
        let r = occupy(f_cs, ID_F);
        // d2 takes the lower index, so the scan meets it first and ascends.
        let d2 = occupy(d_cs, ID_D);
        let d1 = occupy(d_cs, ID_D);
        let c = occupy(f_cs, ID_F);
        assert!(link_all(&[(a, d1), (d1, d2), (d2, c)]));

        // Slot 0, then d2 (pending), then the ascent to d1.
        let mut st = DrainState::new();
        let dying = Dying {
            id: ID_D,
            epoch: registry_epoch(ID_D),
        };
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; the test CSpace is registered.
        let first_done = unsafe { drain_batch(d_cs, dying, &mut st, 3) };
        let pending = st.pending;
        // Between holds, a revoke rooted at r takes d2 out of the region.
        DERIVATION_LOCK.write_unlock();
        DERIVATION_LOCK.write_lock();
        // SAFETY: DERIVATION_LOCK held; both slots live.
        unsafe { unlink_node(d2) };
        // SAFETY: DERIVATION_LOCK held; both slots live.
        let hoisted = unsafe { link_child(r, d2) };
        DERIVATION_LOCK.write_unlock();
        let rest = drain_all(d_cs, ID_D, &mut st, MAX_DRAIN_EDITS);

        assert!(!first_done);
        assert_eq!(pending, Some(d1.index), "the first hold ascended to d1");
        assert!(hoisted);
        assert!(rest.done);
        assert_eq!(parent_of(c), Some(r), "c under d2's new parent");
        assert!(isolated(d1) && isolated(d2));
        assert_eq!(children_of(a, 1), Vec::<SlotId>::new());
        crate::cap::unregister_cspace(ID_D);
        crate::cap::unregister_cspace(ID_F);
    }

    // Defect guarded: an IPC capability transfer resolving a CSpace whose
    // drain has begun, which could move a capability out of a slot the drain
    // already passed, or wire one in behind its scan.
    #[test]
    fn ipc_resolution_refuses_a_draining_cspace_the_drain_still_resolves()
    {
        const ID_D: CSpaceId = 3315;
        let d_cs = mk_registered_cspace(ID_D);
        // A leaf to scan, so one step leaves the drain unfinished.
        let _ = occupy(d_cs, ID_D);
        let ident = crate::cap::CSpaceIdentity {
            id: ID_D,
            epoch: registry_epoch(ID_D),
        };
        let dying = Dying {
            id: ID_D,
            epoch: ident.epoch,
        };
        let mut st = DrainState::new();
        DERIVATION_LOCK.write_lock();
        let before = ident.lookup().is_some();
        // SAFETY: DERIVATION_LOCK held; the test CSpace is registered.
        let done = unsafe { drain_batch(d_cs, dying, &mut st, 1) };
        let after = ident.lookup().is_some();
        let registered = crate::cap::lookup_cspace(ID_D, ident.epoch).is_some();
        DERIVATION_LOCK.write_unlock();

        assert!(before, "a live CSpace resolves");
        assert!(!done);
        assert!(!after, "a draining CSpace resolves to nothing for IPC");
        assert!(registered, "the drain, delete and revoke still resolve it");
        crate::cap::unregister_cspace(ID_D);
    }
}
