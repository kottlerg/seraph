// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/budget.rs

//! Budget nodes: the tree memmgr charges every page it lends to a process to,
//! with an optional max per node and the system reserve.
//!
//! A [`BudgetNode`] is an arena slot separate from the process record that
//! points at it. It carries a parent link, an optional max in pages, the pages
//! charged to it directly (`own`), and the pages charged to it and every node
//! below it (`subtree`). A charge is admitted ([`admit`]) against the max of
//! the node and of every ancestor, and against the system reserve for a node
//! outside it, before memmgr selects the run; it is then recorded
//! ([`charge`]) where the run is accounted to the process, and released
//! ([`uncharge`]) where the run rejoins the free pool. A node lives while a
//! record or a child node refers to it or a page is charged to it, so a node
//! whose process died stays, charged to its parent, while a run of it waits on
//! the deferred list. See `services/memmgr/docs/memory-pool.md`
//! § Distribution policy.

use crate::arena::{Arena, NODE_NULL, Node, NodeIdx, SlotStore};

/// The max of a node with none: only its ancestors and the reserve limit it.
pub const NO_MAX: u64 = u64::MAX;

/// The system reserve is `pool_total / SYSTEM_RESERVE_DIVISOR` free pages,
/// which only a charge to a reserve node may take ([`reserve_pages`]). A
/// tuning value proportional to RAM, so it bounds no capacity: a floor for the
/// core's allocations under pressure (docs/limits.md § memmgr).
pub const SYSTEM_RESERVE_DIVISOR: u64 = 64;

/// [`BudgetNode::flags`] bit: the node is in the system reserve.
const FLAG_RESERVE: u32 = 1 << 0;

/// One budget node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetNode
{
    /// The parent node, or [`NODE_NULL`] for a top-level node.
    pub parent: NodeIdx,
    /// The most pages the subtree may hold, or [`NO_MAX`].
    pub max: u64,
    /// Pages charged to this node directly.
    pub own: u64,
    /// Pages charged to this node and to every node below it.
    pub subtree: u64,
    /// Process records and child nodes that point at this node. Each holds an
    /// arena slot, and a [`NodeIdx`] is a `u64`, so the count cannot pass
    /// `u64::MAX`.
    pub refs: u64,
    /// [`FLAG_RESERVE`].
    pub flags: u32,
}

impl BudgetNode
{
    /// Whether the node is in the system reserve.
    #[must_use]
    pub const fn reserve(&self) -> bool
    {
        self.flags & FLAG_RESERVE != 0
    }
}

/// What a new node asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeSpec
{
    /// The parent node, or [`NODE_NULL`] for a top-level node.
    pub parent: NodeIdx,
    /// The max asked for, or [`NO_MAX`]. [`create`] clamps it to the parent
    /// chain's headroom.
    pub max: u64,
    /// Whether the node is in the system reserve.
    pub reserve: bool,
}

impl NodeSpec
{
    /// A top-level node outside the reserve, with no max.
    pub const TOP: Self = Self {
        parent: NODE_NULL,
        max: NO_MAX,
        reserve: false,
    };

    /// A top-level reserve node with no max: the boot records'.
    pub const TOP_RESERVE: Self = Self {
        parent: NODE_NULL,
        max: NO_MAX,
        reserve: true,
    };
}

/// Why [`create`] made no node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeError
{
    /// The parent is not a budget node, or a reserve node was asked for under
    /// a parent outside the reserve.
    Parent,
    /// The arena has no free slot outside its reserve.
    NoSlot,
}

/// Why [`admit`] refused a charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeError
{
    /// The charge would take the subtree of the node or of an ancestor over
    /// its max: `LIMIT`, or a fault declined with code 10.
    Limit,
    /// The node is outside the reserve and the charge would leave fewer free
    /// pages than the reserve: system exhaustion, an out-of-memory code or a
    /// fault declined with code 7.
    Reserve,
}

/// Free pages of the system reserve for a pool of `pool_total` pages.
#[must_use]
pub const fn reserve_pages(pool_total: u64) -> u64
{
    pool_total / SYSTEM_RESERVE_DIVISOR
}

/// The budget node in slot `idx`.
#[must_use]
pub fn node<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx) -> Option<BudgetNode>
{
    match arena.get(idx).node
    {
        Node::Budget(b) => Some(b),
        Node::Free
        | Node::Run(_)
        | Node::Deferred(_)
        | Node::Region(_)
        | Node::Frame(_)
        | Node::Process(_)
        | Node::ChunkDir(_)
        | Node::Chunk(_) => None,
    }
}

/// Pages the node `idx` may still be charged: the least, over it and every
/// ancestor, of its max less its subtree. [`NO_MAX`] when no node of the chain
/// has a max.
#[must_use]
pub fn headroom<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx) -> u64
{
    let mut left = NO_MAX;
    let mut cur = idx;
    while let Some(b) = node(arena, cur)
    {
        if b.max != NO_MAX
        {
            left = left.min(b.max.saturating_sub(b.subtree));
        }
        cur = b.parent;
    }
    left
}

/// Make a node for `spec`, with one reference (the record that will point at
/// it), counted as a reference of its parent. A max is clamped to the
/// parent chain's [`headroom`]; [`NO_MAX`] stays unbounded, limited by the
/// chain at each charge.
///
/// # Errors
/// [`NodeError::Parent`] for a parent that is not a node, or a reserve node
/// under a parent outside the reserve; [`NodeError::NoSlot`] for a full arena. Nothing changes
/// then.
pub fn create<S: SlotStore>(arena: &mut Arena<S>, spec: NodeSpec) -> Result<NodeIdx, NodeError>
{
    let mut max = spec.max;
    let parent = if spec.parent == NODE_NULL
    {
        None
    }
    else
    {
        let p = node(arena, spec.parent).ok_or(NodeError::Parent)?;
        if spec.reserve && !p.reserve()
        {
            return Err(NodeError::Parent);
        }
        if max != NO_MAX
        {
            max = max.min(headroom(arena, spec.parent));
        }
        Some(BudgetNode {
            refs: p.refs.saturating_add(1),
            ..p
        })
    };
    let idx = arena
        .alloc(
            Node::Budget(BudgetNode {
                parent: spec.parent,
                max,
                own: 0,
                subtree: 0,
                refs: 1,
                flags: if spec.reserve { FLAG_RESERVE } else { 0 },
            }),
            NODE_NULL,
        )
        .ok_or(NodeError::NoSlot)?;
    if let Some(p) = parent
    {
        arena.set_node(spec.parent, Node::Budget(p));
    }
    Ok(idx)
}

/// Whether `pages` more may be charged to the node `idx`, with `free` pages in
/// the free pool and `reserve` of them in the system reserve. `pending` pages
/// already left the pool for the node and are not yet charged to it (a demand
/// run whose map needs page-table funding first): they count against the max,
/// and are already out of `free`.
///
/// # Errors
/// [`ChargeError::Limit`] when `pages` and `pending` together exceed the
/// [`headroom`] of the node; [`ChargeError::Reserve`] when the node is outside
/// the reserve and the charge would leave fewer than `reserve` free pages.
pub fn admit<S: SlotStore>(
    arena: &Arena<S>,
    idx: NodeIdx,
    pages: u64,
    pending: u64,
    free: u64,
    reserve: u64,
) -> Result<(), ChargeError>
{
    if pages.saturating_add(pending) > headroom(arena, idx)
    {
        return Err(ChargeError::Limit);
    }
    let in_reserve = node(arena, idx).is_some_and(|b| b.reserve());
    if !in_reserve && free.saturating_sub(pages) < reserve
    {
        return Err(ChargeError::Reserve);
    }
    Ok(())
}

/// The most pages, up to `want`, that may be charged to the node `idx`, with
/// `free` pages in the free pool and `reserve` of them in the system reserve:
/// `want`, clamped to the node's [`headroom`] and, for a node outside the
/// reserve, to the free pages above the reserve. A demand fault backs that
/// much of its span.
///
/// # Errors
/// [`ChargeError::Limit`] when the headroom admits no page;
/// [`ChargeError::Reserve`] when the node is outside the reserve and no free
/// page lies above it. A `want` of 0 admits 0.
pub fn admissible<S: SlotStore>(
    arena: &Arena<S>,
    idx: NodeIdx,
    want: u64,
    free: u64,
    reserve: u64,
) -> Result<u64, ChargeError>
{
    if want == 0
    {
        return Ok(0);
    }
    let mut pages = want.min(headroom(arena, idx));
    if pages == 0
    {
        return Err(ChargeError::Limit);
    }
    if !node(arena, idx).is_some_and(|b| b.reserve())
    {
        pages = pages.min(free.saturating_sub(reserve));
        if pages == 0
        {
            return Err(ChargeError::Reserve);
        }
    }
    Ok(pages)
}

/// Charge `pages` to the node `idx`: its own count, and the subtree count of
/// it and every ancestor. Admission is the caller's ([`admit`]); a charge
/// made without it (a bootstrap arena, a run whose return failed) is
/// recorded all the same, so the counts stay equal to what the node holds.
pub fn charge<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx, pages: u64)
{
    walk(arena, idx, |b, first| {
        if first
        {
            b.own = b.own.saturating_add(pages);
        }
        b.subtree = b.subtree.saturating_add(pages);
    });
}

/// Release `pages` charged to the node `idx` ([`charge`]), and free the node
/// when nothing refers to it and nothing is charged to it any more.
pub fn uncharge<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx, pages: u64)
{
    walk(arena, idx, |b, first| {
        if first
        {
            debug_assert!(
                b.own >= pages,
                "uncharge: {pages} pages over the node's own"
            );
            b.own = b.own.saturating_sub(pages);
        }
        b.subtree = b.subtree.saturating_sub(pages);
    });
    release_unused(arena, idx);
}

/// Drop one reference to the node `idx` (a record that pointed at it is
/// gone), and free it when nothing refers to it and nothing is charged to it.
pub fn unref<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx)
{
    if let Some(mut b) = node(arena, idx)
    {
        b.refs = b.refs.saturating_sub(1);
        arena.set_node(idx, Node::Budget(b));
        release_unused(arena, idx);
    }
}

/// Set the max of the node `idx`. A max below the subtree's usage reclaims
/// nothing: it refuses every later charge until the usage falls below it.
pub fn set_max<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx, max: u64)
{
    if let Some(mut b) = node(arena, idx)
    {
        b.max = max;
        arena.set_node(idx, Node::Budget(b));
    }
}

/// Apply `f` to the node `idx` (with `true`) and to each ancestor (with
/// `false`).
fn walk<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx, mut f: impl FnMut(&mut BudgetNode, bool))
{
    let mut cur = idx;
    let mut first = true;
    while let Some(mut b) = node(arena, cur)
    {
        f(&mut b, first);
        arena.set_node(cur, Node::Budget(b));
        first = false;
        cur = b.parent;
    }
}

/// Free the node `idx` if nothing refers to it and nothing is charged to it,
/// then drop its reference on its parent, which can free the parent in turn.
/// A node with no reference has no child, so its subtree is its own count.
fn release_unused<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx)
{
    let mut cur = idx;
    while let Some(b) = node(arena, cur)
    {
        if b.refs != 0 || b.own != 0
        {
            return;
        }
        arena.free(cur);
        cur = b.parent;
        if let Some(mut p) = node(arena, cur)
        {
            p.refs = p.refs.saturating_sub(1);
            arena.set_node(cur, Node::Budget(p));
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::test_store::VecStore;

    fn arena() -> Arena<VecStore>
    {
        let mut a = Arena::new(VecStore::default());
        // SAFETY: VecStore grows on write.
        unsafe { a.add_page() };
        a
    }

    fn under(parent: NodeIdx, max: u64) -> NodeSpec
    {
        NodeSpec {
            parent,
            max,
            reserve: false,
        }
    }

    #[test]
    fn a_charge_counts_on_the_node_and_in_every_ancestors_subtree()
    {
        let mut a = arena();
        let top = create(&mut a, NodeSpec::TOP).unwrap();
        let mid = create(&mut a, under(top, NO_MAX)).unwrap();
        let leaf = create(&mut a, under(mid, NO_MAX)).unwrap();
        charge(&mut a, leaf, 5);
        charge(&mut a, mid, 2);
        let n = |i| node(&a, i).unwrap();
        assert_eq!((n(leaf).own, n(leaf).subtree), (5, 5));
        assert_eq!((n(mid).own, n(mid).subtree), (2, 7));
        assert_eq!((n(top).own, n(top).subtree), (0, 7));
        uncharge(&mut a, leaf, 5);
        let n = |i| node(&a, i).unwrap();
        assert_eq!((n(leaf).own, n(mid).subtree, n(top).subtree), (0, 2, 2));
    }

    #[test]
    fn a_charge_over_the_max_of_the_node_or_an_ancestor_is_a_limit()
    {
        let mut a = arena();
        let top = create(&mut a, under(NODE_NULL, 10)).unwrap();
        let other = create(&mut a, NodeSpec::TOP).unwrap();
        let leaf = create(&mut a, under(top, NO_MAX)).unwrap();
        assert_eq!(admit(&a, leaf, 10, 0, 100, 0), Ok(()));
        assert_eq!(admit(&a, leaf, 11, 0, 100, 0), Err(ChargeError::Limit));
        charge(&mut a, leaf, 8);
        assert_eq!(admit(&a, leaf, 2, 0, 100, 0), Ok(()));
        assert_eq!(admit(&a, leaf, 3, 0, 100, 0), Err(ChargeError::Limit));
        // A sibling top-level node is not limited by another's max.
        assert_eq!(admit(&a, other, 50, 0, 100, 0), Ok(()));
    }

    #[test]
    fn lowering_a_max_below_usage_refuses_charges_and_keeps_the_usage()
    {
        let mut a = arena();
        let n = create(&mut a, NodeSpec::TOP).unwrap();
        charge(&mut a, n, 8);
        set_max(&mut a, n, 4);
        assert_eq!(node(&a, n).map(|b| (b.own, b.subtree)), Some((8, 8)));
        assert_eq!(headroom(&a, n), 0);
        assert_eq!(admit(&a, n, 1, 0, 100, 0), Err(ChargeError::Limit));
        uncharge(&mut a, n, 5);
        assert_eq!(admit(&a, n, 1, 0, 100, 0), Ok(()));
    }

    #[test]
    fn only_a_reserve_node_may_take_the_reserve()
    {
        let mut a = arena();
        let core = create(&mut a, NodeSpec::TOP_RESERVE).unwrap();
        let client = create(&mut a, NodeSpec::TOP).unwrap();
        // 20 free, 4 reserved: an ordinary client may leave 4 free, no fewer.
        assert_eq!(admit(&a, client, 16, 0, 20, 4), Ok(()));
        assert_eq!(admit(&a, client, 17, 0, 20, 4), Err(ChargeError::Reserve));
        assert_eq!(admit(&a, core, 20, 0, 20, 4), Ok(()));
        // A child created as a reserve node under a reserve parent.
        let child = create(
            &mut a,
            NodeSpec {
                parent: core,
                max: NO_MAX,
                reserve: true,
            },
        )
        .unwrap();
        assert_eq!(admit(&a, child, 20, 0, 20, 4), Ok(()));
        assert_eq!(reserve_pages(6400), 100);
    }

    #[test]
    fn pending_pages_count_against_the_max_but_not_against_the_free_pool()
    {
        let mut a = arena();
        let n = create(&mut a, under(NODE_NULL, 20)).unwrap();
        // A 16-page run left the pool uncharged: four more fit under the max,
        // five do not.
        assert_eq!(admit(&a, n, 4, 16, 100, 0), Ok(()));
        assert_eq!(admit(&a, n, 5, 16, 100, 0), Err(ChargeError::Limit));
        // `free` already excludes the pending run: 10 free and 6 reserved
        // leave room for 4.
        let client = create(&mut a, NodeSpec::TOP).unwrap();
        assert_eq!(admit(&a, client, 4, 16, 10, 6), Ok(()));
        assert_eq!(admit(&a, client, 5, 16, 10, 6), Err(ChargeError::Reserve));
    }

    #[test]
    fn admissible_clamps_to_the_headroom_and_the_free_pages_above_the_reserve()
    {
        let mut a = arena();
        let n = create(&mut a, under(NODE_NULL, 20)).unwrap();
        charge(&mut a, n, 15);
        // Five pages of headroom: a 16-page want backs five.
        assert_eq!(admissible(&a, n, 16, 100, 0), Ok(5));
        assert_eq!(admissible(&a, n, 3, 100, 0), Ok(3));
        charge(&mut a, n, 5);
        assert_eq!(admissible(&a, n, 1, 100, 0), Err(ChargeError::Limit));
        // Outside the reserve, the free pages above it bound the want.
        let client = create(&mut a, NodeSpec::TOP).unwrap();
        assert_eq!(admissible(&a, client, 16, 25, 20), Ok(5));
        assert_eq!(
            admissible(&a, client, 16, 20, 20),
            Err(ChargeError::Reserve)
        );
        // A reserve node may take the reserve.
        let core = create(&mut a, NodeSpec::TOP_RESERVE).unwrap();
        assert_eq!(admissible(&a, core, 16, 20, 20), Ok(16));
        assert_eq!(admissible(&a, core, 0, 0, 20), Ok(0));
    }

    #[test]
    fn a_reserve_node_under_a_parent_outside_the_reserve_is_refused()
    {
        let mut a = arena();
        let client = create(&mut a, NodeSpec::TOP).unwrap();
        let free = a.free_count();
        let spec = NodeSpec {
            parent: client,
            max: NO_MAX,
            reserve: true,
        };
        assert_eq!(create(&mut a, spec), Err(NodeError::Parent));
        assert_eq!(node(&a, client).map(|b| b.refs), Some(1));
        assert_eq!(a.free_count(), free);
        // Nor is a parent that is not a budget node.
        let not_a_node = a.alloc(Node::Free, NODE_NULL).unwrap();
        assert_eq!(
            create(&mut a, under(not_a_node, NO_MAX)),
            Err(NodeError::Parent)
        );
    }

    #[test]
    fn a_max_is_clamped_to_what_the_parent_chain_has_left()
    {
        let mut a = arena();
        let top = create(&mut a, under(NODE_NULL, 100)).unwrap();
        let mid = create(&mut a, under(top, 60)).unwrap();
        charge(&mut a, top, 30);
        charge(&mut a, mid, 20);
        // top has 50 left, mid 40: a child asking 1000 gets 40.
        let leaf = create(&mut a, under(mid, 1000)).unwrap();
        assert_eq!(node(&a, leaf).map(|b| b.max), Some(40));
        // A smaller ask is kept, and no max stays none.
        let small = create(&mut a, under(mid, 7)).unwrap();
        assert_eq!(node(&a, small).map(|b| b.max), Some(7));
        let open = create(&mut a, under(mid, NO_MAX)).unwrap();
        assert_eq!(node(&a, open).map(|b| b.max), Some(NO_MAX));
        assert_eq!(headroom(&a, open), 40);
    }

    #[test]
    fn a_node_lives_while_referred_to_or_charged_then_frees_up_the_chain()
    {
        let mut a = arena();
        let free = a.free_count();
        let top = create(&mut a, NodeSpec::TOP).unwrap();
        let child = create(&mut a, under(top, NO_MAX)).unwrap();
        charge(&mut a, child, 3);
        // The parent's record goes: a live child keeps it.
        unref(&mut a, top);
        assert!(node(&a, top).is_some());
        // The child's record goes: its charge keeps it, and its parent,
        // whose subtree still counts the charge.
        unref(&mut a, child);
        assert_eq!(node(&a, child).map(|b| (b.refs, b.own)), Some((0, 3)));
        assert_eq!(node(&a, top).map(|b| (b.refs, b.subtree)), Some((1, 3)));
        // The last charge goes: both nodes are freed.
        uncharge(&mut a, child, 3);
        assert!(node(&a, child).is_none());
        assert!(node(&a, top).is_none());
        assert_eq!(a.free_count(), free);
    }

    #[test]
    fn create_without_a_slot_changes_nothing()
    {
        let mut a = arena();
        let top = create(&mut a, NodeSpec::TOP).unwrap();
        let b = node(&a, top).unwrap();
        while a.alloc(Node::Free, NODE_NULL).is_some()
        {}
        assert_eq!(create(&mut a, under(top, NO_MAX)), Err(NodeError::NoSlot));
        assert_eq!(node(&a, top), Some(b));
    }
}
