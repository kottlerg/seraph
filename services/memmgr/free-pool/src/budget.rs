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
//! the node and of every ancestor, and against the system reserve and the
//! restore headroom ([`growth_floor`]) for a node outside it, before memmgr selects the run; it is then recorded
//! ([`charge`]) where the run is accounted to the process, and released
//! ([`uncharge`]) where the run rejoins the free pool. A node lives while a
//! record or a child node refers to it or a page is charged to it, so a node
//! whose process died stays, charged to its parent, while a run of it waits on
//! the deferred list. See `services/memmgr/docs/memory-pool.md`
//! § Distribution policy.
//!
//! Beside each node, in a slot of its own, is its reclaim state
//! ([`Reclaim`]): a floor of evictable resident pages that eviction never
//! takes its subtree below, the hard guarantee, and a weight that sets how
//! fast the eviction clock reclaims from it beside other nodes, the soft
//! preference ([`rate`], [`visit`]). Neither moves admission: a floor
//! reserves no free page.

use crate::arena::{Arena, NODE_NULL, Node, NodeIdx, SlotStore};
use crate::ledger::Commit;

/// The max of a node with none: only its ancestors and the reserve limit it.
pub const NO_MAX: u64 = u64::MAX;

/// The system reserve is `pool_total / SYSTEM_RESERVE_DIVISOR` free pages,
/// which only a charge to a reserve node may take ([`reserve_pages`]). A
/// tuning value proportional to RAM, so it bounds no capacity: a floor for the
/// core's allocations under pressure (docs/limits.md § memmgr).
pub const SYSTEM_RESERVE_DIVISOR: u64 = 64;

/// [`BudgetNode::flags`] bit: the node is in the system reserve.
const FLAG_RESERVE: u32 = 1 << 0;

/// [`BudgetNode::flags`] bit: the node keeps a finite max ([`set_bounded`]).
const FLAG_BOUNDED: u32 = 1 << 1;

/// The least weight a node takes ([`set_reclaim`]): the eviction clock
/// reclaims from it fastest.
pub const WEIGHT_MIN: u32 = 1;

/// The weight of a node none was set on.
pub const WEIGHT_DEFAULT: u32 = 100;

/// The greatest weight a node takes: the eviction clock reclaims from it
/// `WEIGHT_MAX` times slower than from a node of [`WEIGHT_MIN`] holding as
/// much above its floor.
pub const WEIGHT_MAX: u32 = 10_000;

/// A reclaim rate of one in the fixed point of [`rate`]: a node of weight 1
/// with no floor. Every rate is at most this.
pub const RATE_ONE: u64 = 1 << 32;

/// A whole sweep in the fixed point of [`Reclaim::credit`].
const CREDIT_ONE: u32 = 1 << 16;

/// The resident pages eviction may take ([`evictable_resident`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvictScope
{
    /// Those of uncommitted regions: no swap service has registered slots, so
    /// a committed chunk is not evicted (`crate::Ledger::evictable`).
    Uncommitted,
    /// Those of committed regions too.
    All,
}

/// The reclaim state of one budget node (`services/memmgr/docs/memory-pool.md`
/// § Distribution policy, Floors and weights): its floor and weight, the
/// evictable resident pages of its subtree the floor is held against, the
/// eviction clock's credit, and the node's handle state. A slot of its own,
/// made and freed with the node and named by the node's slot `next` link,
/// since the node fills its slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reclaim
{
    /// The node's handle state ([`crate::NodeHandle`]), or [`NODE_NULL`]
    /// for none.
    pub handle: NodeIdx,
    /// The evictable resident pages of the subtree ([`evictable_resident`])
    /// that eviction leaves: no chunk is evicted that would take them below
    /// it ([`above_floor`]). 0 for none.
    pub floor: u64,
    /// Pages of the resident chunks of the subtree's uncommitted regions
    /// that eviction may take: regions not registered no-evict, of records
    /// whose node is outside the system reserve.
    pub resident: u64,
    /// The same of the subtree's committed regions that are no attachment,
    /// which eviction takes only while a swap service has registered slots.
    pub resident_committed: u64,
    /// [`WEIGHT_MIN`] to [`WEIGHT_MAX`]: the clock reclaims from the node in
    /// inverse proportion to it ([`rate`]).
    pub weight: u32,
    /// The clock's credit toward the node's next sweep, in `1 / 65536` of a
    /// sweep ([`visit`]).
    pub credit: u32,
    /// The clock pass [`Reclaim::swept`] was decided for.
    pub pass: u32,
    /// Whether that pass sweeps the records of the node.
    pub swept: bool,
}

impl Reclaim
{
    /// The state of a new node: no floor, the default weight, nothing
    /// resident, no credit, and no pass decided.
    pub const NEW: Self = Self {
        handle: NODE_NULL,
        floor: 0,
        resident: 0,
        resident_committed: 0,
        weight: WEIGHT_DEFAULT,
        credit: 0,
        pass: u32::MAX,
        swept: false,
    };
}

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
    /// Process records, child nodes and the node's handle state
    /// ([`crate::NodeHandle`]) that point at this node. Each holds an arena
    /// slot, and a [`NodeIdx`] is a `u64`, so the count cannot pass
    /// `u64::MAX`.
    pub refs: u64,
    /// [`FLAG_RESERVE`] and [`FLAG_BOUNDED`].
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

    /// Whether the node keeps a finite max ([`set_bounded`]).
    #[must_use]
    pub const fn bounded(&self) -> bool
    {
        self.flags & FLAG_BOUNDED != 0
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
    /// The charge would take more free pages than the pool holds outside
    /// `promised`, or, for a node outside the reserve, leave fewer of them
    /// than the reserve: system exhaustion, an out-of-memory code or a fault
    /// declined with code 7.
    Reserve,
}

/// Free pages of the system reserve for a pool of `pool_total` pages.
#[must_use]
pub const fn reserve_pages(pool_total: u64) -> u64
{
    pool_total / SYSTEM_RESERVE_DIVISOR
}

/// Free pages above the system reserve that a charge to a node outside the
/// reserve leaves for restores while `swapped` pages of a pool of
/// `pool_total` pages are swapped: the swapped pages, and at most the
/// reserve. A restore is admitted against the reserve alone, so the chunks a
/// process draining the pool made eviction take find their frames there
/// (`services/memmgr/docs/memory-pool.md` § Eviction, Restore headroom).
#[must_use]
pub const fn restore_headroom(pool_total: u64, swapped: u64) -> u64
{
    let reserve = reserve_pages(pool_total);
    if swapped < reserve { swapped } else { reserve }
}

/// The free pages a charge to a node outside the system reserve must leave in
/// a pool of `pool_total` pages while `swapped` of them are swapped: the
/// reserve and the [`restore_headroom`]. With nothing swapped it is the
/// reserve.
#[must_use]
pub const fn growth_floor(pool_total: u64, swapped: u64) -> u64
{
    reserve_pages(pool_total).saturating_add(restore_headroom(pool_total, swapped))
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
        | Node::Pooled(_)
        | Node::Deferred(_)
        | Node::Region(_)
        | Node::Frame(_)
        | Node::Process(_)
        | Node::ChunkDir(_)
        | Node::Chunk(_)
        | Node::Caps(_)
        | Node::Commit(_)
        | Node::Handle(_)
        | Node::Limit(_)
        | Node::Disk(_)
        | Node::Object(_)
        | Node::ZeroFrame(_)
        | Node::Reclaim(_)
        | Node::Holder(_) => None,
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

/// Make a node for `spec`, with its reclaim state ([`Reclaim::NEW`]) and one reference (the record or handle state
/// that will point at it), counted as a reference of its parent. A max is clamped to the
/// parent chain's [`headroom`]; [`NO_MAX`] stays unbounded, limited by the
/// chain at each charge.
///
/// # Errors
/// [`NodeError::Parent`] for a parent that is not a node, or a reserve node
/// under a parent outside the reserve; [`NodeError::NoSlot`] when the arena has fewer than the
/// two free slots the node and its reclaim state take. Nothing changes then.
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
    let reclaim = arena
        .alloc(Node::Reclaim(Reclaim::NEW), NODE_NULL)
        .ok_or(NodeError::NoSlot)?;
    let Some(idx) = arena.alloc(
        Node::Budget(BudgetNode {
            parent: spec.parent,
            max,
            own: 0,
            subtree: 0,
            refs: 1,
            flags: if spec.reserve { FLAG_RESERVE } else { 0 },
        }),
        reclaim,
    )
    else
    {
        arena.free(reclaim);
        return Err(NodeError::NoSlot);
    };
    if let Some(p) = parent
    {
        arena.set_node(spec.parent, Node::Budget(p));
    }
    Ok(idx)
}

/// Whether `pages` more may be charged to the node `idx`, with `free` pages in
/// the free pool outside `promised`, of which a charge to a node outside the
/// system reserve must leave `reserve` (the reserve, and the restore
/// headroom while pages are swapped: [`growth_floor`]): `free - R >= pages`,
/// R being `reserve` for a node outside the reserve and 0 for a reserve node. `pending` pages already left the pool
/// for the node and are not yet charged to it (a demand run whose map needs
/// page-table funding first): they count against the max, and are already out
/// of `free`.
///
/// # Errors
/// [`ChargeError::Limit`] when `pages` and `pending` together exceed the
/// [`headroom`] of the node; [`ChargeError::Reserve`] when the charge would
/// leave fewer than R of the `free` pages.
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
    if free < pages.saturating_add(floor(arena, idx, reserve))
    {
        return Err(ChargeError::Reserve);
    }
    Ok(())
}

/// The most pages, up to `want`, that may be charged to the node `idx`, with
/// `free` pages in the free pool outside `promised`, of which a charge to a
/// node outside the system reserve must leave `reserve` ([`growth_floor`]):
/// `want`, clamped to the node's [`headroom`] and to the
/// `free` pages above R, which is `reserve` for a node outside the reserve and
/// 0 for a reserve node. A demand fault backs that much of its span.
///
/// # Errors
/// [`ChargeError::Limit`] when the headroom admits no page;
/// [`ChargeError::Reserve`] when no `free` page lies above R. A `want` of 0
/// admits 0.
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
    pages = pages.min(free.saturating_sub(floor(arena, idx, reserve)));
    if pages == 0
    {
        return Err(ChargeError::Reserve);
    }
    Ok(pages)
}

/// The free pages a charge to the node `idx` must leave, with `reserve` the
/// ones a charge outside the system reserve must leave: `reserve` for a node
/// outside it, 0 for a reserve node.
fn floor<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx, reserve: u64) -> u64
{
    if node(arena, idx).is_some_and(|b| b.reserve())
    {
        0
    }
    else
    {
        reserve
    }
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

/// The max the node `idx` takes when `max` is asked of it while it lives:
/// `max` clamped to its subtree's usage plus what its parent chain has left
/// ([`headroom`] of the parent), so a node grows only into room its
/// ancestors still have, as [`create`] clamps a new node's; [`NO_MAX`] stays
/// unbounded, limited by the chain at each charge. A max below the usage is
/// kept: it reclaims nothing ([`set_max`]).
#[must_use]
pub fn clamp_max<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx, max: u64) -> u64
{
    match node(arena, idx)
    {
        Some(b) if max != NO_MAX => max.min(b.subtree.saturating_add(headroom(arena, b.parent))),
        Some(_) | None => max,
    }
}

/// Whether the node `b` is at its limit: its subtree holds its max or more,
/// or a charge of `refused` pages it was just asked for would take the
/// subtree over the max. A node with no max never is.
#[must_use]
pub const fn at_limit(b: &BudgetNode, refused: u64) -> bool
{
    b.max != NO_MAX && (b.subtree >= b.max || b.subtree.saturating_add(refused) > b.max)
}

/// Mark the node `idx` as one that keeps a finite max: a reserve sub-node,
/// whose max bounds what its subtree can take of the reserve
/// ([`crate::Ledger::create_sub_node`]), so no later max lifts the bound
/// ([`crate::Ledger::set_node_max`]).
pub fn set_bounded<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx)
{
    if let Some(mut b) = node(arena, idx)
    {
        b.flags |= FLAG_BOUNDED;
        arena.set_node(idx, Node::Budget(b));
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

/// The slot of the reclaim state of the node `idx`, named by the node's
/// slot `next` link; [`NODE_NULL`] when `idx` is not a node.
#[must_use]
pub fn reclaim_slot<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx) -> NodeIdx
{
    if node(arena, idx).is_none()
    {
        return NODE_NULL;
    }
    let slot = arena.get(idx).next;
    if let Node::Reclaim(_) = arena.get(slot).node
    {
        slot
    }
    else
    {
        NODE_NULL
    }
}

/// The reclaim state of the node `idx`.
#[must_use]
pub fn reclaim<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx) -> Option<Reclaim>
{
    if let Node::Reclaim(r) = arena.get(reclaim_slot(arena, idx)).node
    {
        Some(r)
    }
    else
    {
        None
    }
}

/// Apply `f` to the reclaim state of the node `idx`; nothing when `idx` is
/// not a node.
fn update_reclaim<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx, f: impl FnOnce(&mut Reclaim))
{
    let slot = reclaim_slot(arena, idx);
    if let Node::Reclaim(mut r) = arena.get(slot).node
    {
        f(&mut r);
        arena.set_node(slot, Node::Reclaim(r));
    }
}

/// Name `handle` as the handle state of the node `idx` ([`Reclaim::handle`]),
/// [`NODE_NULL`] for none.
pub fn set_handle<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx, handle: NodeIdx)
{
    update_reclaim(arena, idx, |r| r.handle = handle);
}

/// Set the floor of the node `idx` to `floor` pages and its weight to
/// `weight`, clamped to [`WEIGHT_MIN`]..=[`WEIGHT_MAX`]. Neither is bound by
/// the node's ancestors: a floor protects the subtree's own pages, which its
/// processes may exempt from eviction whole by registering their regions
/// no-evict, and the node's max bounds them all the same. Returns the weight
/// it took; `None` when `idx` is not a node.
pub fn set_reclaim<S: SlotStore>(
    arena: &mut Arena<S>,
    idx: NodeIdx,
    floor: u64,
    weight: u32,
) -> Option<u32>
{
    reclaim(arena, idx)?;
    let weight = weight.clamp(WEIGHT_MIN, WEIGHT_MAX);
    update_reclaim(arena, idx, |r| {
        r.floor = floor;
        r.weight = weight;
    });
    Some(weight)
}

/// Count `gained` pages more and `lost` fewer in the evictable resident
/// pages of the node `idx` and of every ancestor: in
/// [`Reclaim::resident_committed`] for the chunks of a committed region, in
/// [`Reclaim::resident`] for the others.
pub fn count_resident<S: SlotStore>(
    arena: &mut Arena<S>,
    idx: NodeIdx,
    commit: Commit,
    gained: u64,
    lost: u64,
)
{
    let mut cur = idx;
    while let Some(b) = node(arena, cur)
    {
        update_reclaim(arena, cur, |r| {
            let count = if commit == Commit::Committed
            {
                &mut r.resident_committed
            }
            else
            {
                &mut r.resident
            };
            debug_assert!(
                count.saturating_add(gained) >= lost,
                "count_resident: {lost} pages over the node's resident"
            );
            *count = count.saturating_add(gained).saturating_sub(lost);
        });
        cur = b.parent;
    }
}

/// The evictable resident pages of the subtree whose reclaim state is `r`:
/// its uncommitted ones, and, for [`EvictScope::All`], its committed ones too.
#[must_use]
pub const fn evictable_resident(r: &Reclaim, scope: EvictScope) -> u64
{
    match scope
    {
        EvictScope::All => r.resident.saturating_add(r.resident_committed),
        EvictScope::Uncommitted => r.resident,
    }
}

/// The reclaim rate of one node, in the fixed point of [`RATE_ONE`]: with no
/// floor `1 / weight`; with one, 0 while its evictable resident pages R are
/// at the floor or below, else `(R - floor) / (R * weight)`, at least the
/// least step of the fixed point, so a node above its floor is swept in
/// time. A node holding twice as much above its floor, or of half the weight,
/// is reclaimed from twice as fast.
#[must_use]
pub fn node_rate(r: &Reclaim, scope: EvictScope) -> u64
{
    let weight = r.weight.max(WEIGHT_MIN);
    if r.floor == 0
    {
        return RATE_ONE.checked_div(u64::from(weight)).unwrap_or(0);
    }
    let held = evictable_resident(r, scope);
    if held <= r.floor
    {
        return 0;
    }
    let above = u128::from(held.saturating_sub(r.floor)).saturating_mul(u128::from(RATE_ONE));
    let rate = above
        .checked_div(u128::from(held).saturating_mul(u128::from(weight)))
        .unwrap_or(0);
    u64::try_from(rate).unwrap_or(RATE_ONE).max(1)
}

/// The reclaim rate of the node `idx` ([`node_rate`]): the least over it and
/// every ancestor, so a node's floor and weight cover its whole subtree and
/// the most protective of a chain holds. 0 when a node of the chain is at its
/// floor or below, or `idx` is not a node.
#[must_use]
pub fn rate<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx, scope: EvictScope) -> u64
{
    let mut least = None;
    let mut cur = idx;
    while let Some(b) = node(arena, cur)
    {
        let own = reclaim(arena, cur).map_or(0, |r| node_rate(&r, scope));
        least = Some(least.map_or(own, |l: u64| l.min(own)));
        cur = b.parent;
    }
    least.unwrap_or(0)
}

/// Whether evicting `pages` evictable resident pages charged to the node
/// `idx` leaves the evictable resident pages of it and of every ancestor at
/// its floor or above ([`Reclaim::floor`]).
#[must_use]
pub fn above_floor<S: SlotStore>(
    arena: &Arena<S>,
    idx: NodeIdx,
    pages: u64,
    scope: EvictScope,
) -> bool
{
    let mut cur = idx;
    while let Some(b) = node(arena, cur)
    {
        if let Some(r) = reclaim(arena, cur)
            && r.floor != 0
            && evictable_resident(&r, scope) < r.floor.saturating_add(pages)
        {
            return false;
        }
        cur = b.parent;
    }
    true
}

/// Whether the eviction clock sweeps the records of the node `idx` in its
/// pass `pass`, at the node's rate `rate` ([`rate`]), when the greatest
/// rate of a node the previous pass found an idle chunk of was `q_max` (0
/// when it found none). The first visit in a pass decides for the pass: the
/// node's credit grows by `rate / q_max`, at most one sweep and, for a rate
/// above 0, at least the least step, and a whole sweep of credit is spent on a
/// sweep. A node of rate 0 is never swept; with `q_max` 0, every other node
/// is. Over many passes a node is swept in proportion to its rate, and the
/// clock reclaims from it in proportion to its idle pages times its rate,
/// `(R - floor) / weight` when every page is idle. `false` when `idx` is
/// not a node.
pub fn visit<S: SlotStore>(
    arena: &mut Arena<S>,
    idx: NodeIdx,
    pass: u32,
    rate: u64,
    q_max: u64,
) -> bool
{
    let Some(mut r) = reclaim(arena, idx)
    else
    {
        return false;
    };
    if r.pass == pass
    {
        return r.swept;
    }
    let step = if rate == 0
    {
        0
    }
    else if q_max == 0 || rate >= q_max
    {
        CREDIT_ONE
    }
    else
    {
        // Rounded up, so a rate a whole fraction of `q_max` sweeps on time.
        let q = u128::from(q_max);
        let share = u128::from(rate)
            .saturating_mul(u128::from(CREDIT_ONE))
            .saturating_add(q.saturating_sub(1))
            .checked_div(q)
            .unwrap_or(0);
        u32::try_from(share).unwrap_or(CREDIT_ONE).max(1)
    };
    let credit = r.credit.saturating_add(step);
    r.swept = credit >= CREDIT_ONE;
    r.credit = if r.swept
    {
        credit.saturating_sub(CREDIT_ONE)
    }
    else
    {
        credit
    };
    r.pass = pass;
    let swept = r.swept;
    update_reclaim(arena, idx, |s| *s = r);
    swept
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

/// Free the node `idx`, with its reclaim state, if nothing refers to it and nothing is charged to it,
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
        let reclaim = reclaim_slot(arena, cur);
        arena.free(cur);
        if reclaim != NODE_NULL
        {
            arena.free(reclaim);
        }
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
        // A reserve node takes the reserve but no page outside the free ones:
        // the pages `promised` to committed regions are already out of `free`.
        assert_eq!(admit(&a, core, 21, 0, 20, 4), Err(ChargeError::Reserve));
        assert_eq!(admissible(&a, core, 16, 10, 4), Ok(10));
        assert_eq!(admissible(&a, core, 16, 0, 4), Err(ChargeError::Reserve));
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
    fn the_restore_headroom_is_the_swapped_pages_up_to_the_reserve()
    {
        // A pool of 6400 pages: reserve 100.
        assert_eq!(restore_headroom(6400, 0), 0);
        assert_eq!(growth_floor(6400, 0), 100);
        assert_eq!(restore_headroom(6400, 37), 37);
        assert_eq!(growth_floor(6400, 37), 137);
        assert_eq!(restore_headroom(6400, 100), 100);
        assert_eq!(restore_headroom(6400, 5000), 100);
        assert_eq!(growth_floor(6400, u64::MAX), 200);
        // A pool too small for a reserve leaves no headroom either.
        assert_eq!(growth_floor(63, 16), 0);
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
    fn a_node_and_its_reclaim_state_are_made_and_freed_together()
    {
        let mut a = arena();
        let free = a.free_count();
        let n = create(&mut a, NodeSpec::TOP).unwrap();
        assert_eq!(a.free_count(), free - 2);
        assert_eq!(reclaim(&a, n), Some(Reclaim::NEW));
        set_handle(&mut a, n, 7);
        assert_eq!(reclaim(&a, n).map(|r| r.handle), Some(7));
        set_handle(&mut a, n, NODE_NULL);
        unref(&mut a, n);
        assert_eq!(a.free_count(), free);
        assert_eq!(reclaim(&a, n), None);
        // With one free slot, the reclaim state is taken and given back.
        while a.available() > 1
        {
            a.alloc(Node::Free, NODE_NULL).unwrap();
        }
        let left = a.free_count();
        assert_eq!(create(&mut a, NodeSpec::TOP), Err(NodeError::NoSlot));
        assert_eq!(a.free_count(), left);
    }

    #[test]
    fn a_rate_falls_with_the_weight_and_to_nothing_at_the_floor()
    {
        let mut a = arena();
        let top = create(&mut a, NodeSpec::TOP).unwrap();
        let leaf = create(&mut a, under(top, NO_MAX)).unwrap();
        count_resident(&mut a, leaf, Commit::Uncommitted, 100, 0);
        count_resident(&mut a, leaf, Commit::Committed, 28, 0);
        let counts =
            |a: &Arena<VecStore>, i| reclaim(a, i).map(|r| (r.resident, r.resident_committed));
        assert_eq!(counts(&a, leaf), Some((100, 28)));
        assert_eq!(counts(&a, top), Some((100, 28)));
        // With no floor, the rate is one over the weight.
        assert_eq!(rate(&a, leaf, EvictScope::Uncommitted), RATE_ONE / 100);
        assert_eq!(set_reclaim(&mut a, leaf, 0, 400), Some(400));
        assert_eq!(rate(&a, leaf, EvictScope::Uncommitted), RATE_ONE / 400);
        // With one, (R - floor) / (R * weight), the committed pages counting
        // in R only while eviction may take them.
        set_reclaim(&mut a, leaf, 50, 100);
        assert_eq!(rate(&a, leaf, EvictScope::Uncommitted), RATE_ONE / 200);
        assert_eq!(rate(&a, leaf, EvictScope::All), 78 * RATE_ONE / (128 * 100));
        assert!(above_floor(&a, leaf, 50, EvictScope::Uncommitted));
        assert!(!above_floor(&a, leaf, 51, EvictScope::Uncommitted));
        // At the floor, nothing.
        set_reclaim(&mut a, leaf, 100, 100);
        assert_eq!(rate(&a, leaf, EvictScope::Uncommitted), 0);
        assert!(!above_floor(&a, leaf, 1, EvictScope::Uncommitted));
        assert!(above_floor(&a, leaf, 28, EvictScope::All));
        // The least over the chain holds: a floor on the parent covers the
        // leaf, and so does a weight.
        set_reclaim(&mut a, leaf, 0, 100);
        set_reclaim(&mut a, top, 128, 100);
        assert_eq!(rate(&a, leaf, EvictScope::All), 0);
        assert!(!above_floor(&a, leaf, 1, EvictScope::All));
        // A weight out of range is clamped to it.
        assert_eq!(set_reclaim(&mut a, top, 0, 0), Some(WEIGHT_MIN));
        assert_eq!(rate(&a, leaf, EvictScope::All), RATE_ONE / 100);
        assert_eq!(set_reclaim(&mut a, top, 0, u32::MAX), Some(WEIGHT_MAX));
        assert_eq!(rate(&a, leaf, EvictScope::All), RATE_ONE / 10_000);
        assert_eq!(set_reclaim(&mut a, NODE_NULL, 0, 100), None);
        // The counts fall up the chain as they rose.
        count_resident(&mut a, leaf, Commit::Uncommitted, 0, 100);
        count_resident(&mut a, leaf, Commit::Committed, 0, 28);
        assert_eq!(counts(&a, top), Some((0, 0)));
    }

    #[test]
    fn a_visit_spends_a_whole_sweep_of_credit_on_each_sweep()
    {
        let mut a = arena();
        let n = create(&mut a, NodeSpec::TOP).unwrap();
        let q = RATE_ONE / 100;
        // With no idle chunk found the pass before, or at the greatest rate,
        // every pass sweeps.
        assert!(visit(&mut a, n, 0, q / 4, 0));
        assert!(visit(&mut a, n, 1, q, q));
        // The first visit in a pass decides for the pass.
        assert!(visit(&mut a, n, 1, 0, q));
        // A quarter of the greatest rate sweeps one pass in four.
        let swept: Vec<bool> = (2..10).map(|p| visit(&mut a, n, p, q / 4, q)).collect();
        assert_eq!(
            swept,
            [false, false, false, true, false, false, false, true]
        );
        // A rate of 0 never sweeps.
        assert!((10..20).all(|p| !visit(&mut a, n, p, 0, q)));
        // A rate far below the greatest still gains credit.
        let before = reclaim(&a, n).map(|r| r.credit);
        assert!(!visit(&mut a, n, 20, 1, RATE_ONE));
        assert_eq!(reclaim(&a, n).map(|r| r.credit), before.map(|c| c + 1));
        assert!(!visit(&mut a, NODE_NULL, 21, q, q));
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
