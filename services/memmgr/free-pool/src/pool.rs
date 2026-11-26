// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/pool.rs

//! The free pool: arena-backed free runs, filed by physical base and by size.
//!
//! Each run is a [`Node::Pooled`] slot on two lists at once. One holds every
//! run, doubly linked in order of `phys_base`, so physically adjacent runs are
//! list neighbours, coalescing is one linear pass, and a run leaves the list
//! without a walk. The other is the list of the run's size class: a
//! two-level segregated fit, whose classes split each power of two of pages
//! into [`CLASS_SPLIT`] equal parts, with a bitmap of the non-empty classes
//! of each power and a bitmap of the non-empty powers. A selection reads one
//! class head and finds the next non-empty class above it by the bitmaps, so
//! its steps do not depend on how many runs the pool holds or the order they
//! came back in. The run count is bounded by the arena, that is by RAM, not by
//! a constant. Grant selection ([`FreePool::select`]) lives here too so its
//! fit and partial-grant rules are host-tested. See
//! `services/memmgr/docs/memory-pool.md` § Free-Pool Data Structure and
//! § Allocation.

use syscall_abi::{MSG_CAP_SLOTS_MAX, PAGE_SIZE};

use crate::FreeRun;
use crate::arena::{Arena, NODE_NULL, Node, NodeIdx, SlotStore};

/// Runs one grant reply can carry: the IPC reply-side cap-slot capacity.
pub const MAX_GRANT_RUNS: usize = MSG_CAP_SLOTS_MAX;

/// One granted entry: `(cap_slot, page_count, phys_base)`.
pub type GrantEntry = (u64, u32, u64);

/// A selection: the granted entries, `count` of them valid. Its page total
/// MAY be below the request for a best-effort grant (see
/// [`FreePool::select`]).
#[derive(Clone, Copy, Debug)]
pub struct Grant
{
    pub entries: [GrantEntry; MAX_GRANT_RUNS],
    pub count: usize,
}

impl Grant
{
    /// The valid entries.
    #[must_use]
    pub fn entries(&self) -> &[GrantEntry]
    {
        self.entries.get(..self.count).unwrap_or(&self.entries)
    }
}

/// How a selection may cover a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fit
{
    /// One run covering the whole request (`REQUIRE_CONTIGUOUS`).
    Contiguous,
    /// Any runs, up to [`MAX_GRANT_RUNS`], possibly covering less than the
    /// request (a partial grant).
    BestEffort,
    /// One run: the whole request when a run covers it, else the largest run
    /// whole, which then covers less than the request (a demand fault's
    /// fallback on a fragmented pool).
    UpTo,
}

/// Why a selection found nothing to grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectError
{
    /// No single run covers a `REQUIRE_CONTIGUOUS` request, or its split
    /// failed; for [`Fit::UpTo`], the pool is empty or the covering run's
    /// split failed.
    Contiguous,
    /// The pool's free pages do not cover a best-effort request, or no run
    /// could be taken.
    BestEffort,
}

/// A run on the free pool: the run, its predecessor in physical order (its
/// successor is the slot's `next` link), and its neighbours on its size
/// class's list. [`NODE_NULL`] ends each list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PooledRun
{
    pub run: FreeRun,
    pub prev: NodeIdx,
    pub class_prev: NodeIdx,
    pub class_next: NodeIdx,
}

/// Size classes per power of two of pages, as a power of two: each power
/// `[2^k, 2^(k+1))` with `k >= CLASS_SPLIT_BITS` splits into [`CLASS_SPLIT`]
/// classes of equal width, and every count below `2 * CLASS_SPLIT` pages is a
/// class of its own.
const CLASS_SPLIT_BITS: u32 = 3;

/// Size classes per power of two of pages.
pub const CLASS_SPLIT: usize = 1 << CLASS_SPLIT_BITS;

/// [`CLASS_SPLIT`] as a page count.
const SPLIT_PAGES: u64 = 1 << CLASS_SPLIT_BITS;

/// Rows of classes: row 0 holds the counts below [`CLASS_SPLIT`], one page
/// each, and row `k - CLASS_SPLIT_BITS + 1` the power `2^k`, up to the
/// largest power a `u64` page count has (`k = 63`). A power of two, so a row
/// number the row bitmap yields indexes the class bitmaps without a bound
/// check; the rows past the last are always empty.
const ROWS: usize = 64;

/// Size classes: [`CLASS_SPLIT`] per row.
const CLASSES: usize = ROWS * CLASS_SPLIT;

/// A class word with only the bit past its last class set: the count of
/// trailing zeros of a word that holds no class at or above some column, with
/// this bit added, is [`CLASS_SPLIT`], so the count needs no test for zero.
const PAST_ROW: u64 = 1 << SPLIT_PAGES;

/// The size class of a run of `pages` pages: `row * CLASS_SPLIT + column`,
/// where the row is the power of two the count lies in and the column the
/// part of it. Computed without a branch on the count. A count of 0, which no
/// run has, falls in class 0.
#[must_use]
pub fn class_of(pages: u64) -> usize
{
    // The highest set bit of `pages`, at least `CLASS_SPLIT_BITS`: the
    // power the count lies in, with the counts below `CLASS_SPLIT` taken as
    // that power's.
    let top = 63u32.wrapping_sub((pages | SPLIT_PAGES).leading_zeros());
    let shift = top.wrapping_sub(CLASS_SPLIT_BITS);
    // 1 for a count at or above `CLASS_SPLIT`, whose row follows its power;
    // 0 for one below, all in row 0.
    let above = pages.wrapping_shr(top) & 1;
    let row = u64::from(shift).wrapping_add(above);
    let column = pages.wrapping_shr(shift) & (SPLIT_PAGES - 1);
    // `row <= 61` and `column < CLASS_SPLIT`, so the class is below `CLASSES`
    // and the conversion is exact.
    usize::try_from(row.wrapping_mul(SPLIT_PAGES).wrapping_add(column)).unwrap_or(0)
}

/// The row of class `class`: the power of two of its page counts.
const fn row_of(class: usize) -> usize
{
    class.wrapping_shr(CLASS_SPLIT_BITS)
}

/// The bit of class `class` in its row's class word.
fn column_bit(class: usize) -> u8
{
    // Below `CLASS_SPLIT`, so the conversion is exact.
    1u8.wrapping_shl(u32::try_from(class & (CLASS_SPLIT - 1)).unwrap_or(0))
}

/// The bit of row `row` in the row word.
fn row_bit(row: usize) -> u64
{
    // Below `ROWS`, so the conversion is exact.
    1u64.wrapping_shl(u32::try_from(row & (ROWS - 1)).unwrap_or(0))
}

/// The first class of row `row`.
const fn row_start(row: usize) -> usize
{
    row.wrapping_shl(CLASS_SPLIT_BITS)
}

/// The free pool: the physical-order list's head, the size classes' list
/// heads and bitmaps, and the running totals.
pub struct FreePool
{
    head: NodeIdx,
    /// The first run of each size class, [`NODE_NULL`] for an empty one.
    class_heads: [NodeIdx; CLASSES],
    /// Bit `c` of row `r`'s word: class `r * CLASS_SPLIT + c` holds a run.
    class_bits: [u8; ROWS],
    /// Bit `r`: row `r` holds a run.
    row_bits: u64,
    free_pages: u64,
    runs: u64,
}

// Every bit of a row's class word names a class of that row.
const _: () = assert!(CLASS_SPLIT == u8::BITS as usize);
// Every row has a bit in the row word.
const _: () = assert!(ROWS == u64::BITS as usize);

impl Default for FreePool
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// The pooled run slot `idx` holds, or `None` when it holds another node
/// (or is [`NODE_NULL`]).
pub(crate) fn pooled_of<S: SlotStore>(arena: &Arena<S>, idx: NodeIdx) -> Option<PooledRun>
{
    match arena.get(idx).node
    {
        Node::Pooled(p) => Some(p),
        Node::Free
        | Node::Run(_)
        | Node::Deferred(_)
        | Node::Budget(_)
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

/// Rewrite the pooled run at `idx` by `f`, keeping its slot link. A slot
/// that holds no pooled run is left as it is.
fn update<S: SlotStore>(arena: &mut Arena<S>, idx: NodeIdx, f: impl FnOnce(&mut PooledRun))
{
    if let Some(mut p) = pooled_of(arena, idx)
    {
        f(&mut p);
        arena.set_node(idx, Node::Pooled(p));
    }
}

impl FreePool
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            head: NODE_NULL,
            class_heads: [NODE_NULL; CLASSES],
            class_bits: [0; ROWS],
            row_bits: 0,
            free_pages: 0,
            runs: 0,
        }
    }

    /// Pages in free runs: owned by memmgr and lent to no process. Falls on
    /// allocation, rises on reclamation; the observable `QUERY_POOL_STATUS`
    /// reports as `free`.
    #[must_use]
    pub const fn free_pages(&self) -> u64
    {
        self.free_pages
    }

    /// Runs on the list.
    #[must_use]
    pub const fn run_count(&self) -> u64
    {
        self.runs
    }

    /// Pages of the largest run, `0` when empty.
    #[must_use]
    pub fn largest_pages<S: SlotStore>(&self, arena: &Arena<S>) -> u64
    {
        self.largest(arena)
            .and_then(|idx| pooled_of(arena, idx))
            .map_or(0, |p| p.run.page_count)
    }

    /// Insert `run` at its sorted position in a fresh slot outside the arena's
    /// reserve.
    ///
    /// # Errors
    /// Returns the run back when the arena has no free slot outside its
    /// reserve; the owner grows the arena and retries.
    pub fn push<S: SlotStore>(&mut self, arena: &mut Arena<S>, run: FreeRun)
    -> Result<(), FreeRun>
    {
        let Some(idx) = arena.alloc(Node::Run(run), NODE_NULL)
        else
        {
            return Err(run);
        };
        self.link_sorted(arena, idx, run);
        Ok(())
    }

    /// Insert `run` like [`FreePool::push`], but into a reserved slot when
    /// no other is free: for the returns the arena's reserve exists for.
    ///
    /// # Errors
    /// Returns the run back when the arena has no free slot at all.
    pub fn push_reserved<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        run: FreeRun,
    ) -> Result<(), FreeRun>
    {
        let Some(idx) = arena.alloc_reserved(Node::Run(run), NODE_NULL)
        else
        {
            return Err(run);
        };
        self.link_sorted(arena, idx, run);
        Ok(())
    }

    /// Insert the run slot `idx` already holds (a [`Node::Run`], such as a
    /// reclaimed frame rewritten in place), so reclamation never needs a fresh
    /// slot. A slot that does not hold a run is ignored.
    pub fn push_node<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx)
    {
        if let Node::Run(run) = arena.get(idx).node
        {
            self.link_sorted(arena, idx, run);
        }
    }

    /// File `run` in slot `idx`: at its sorted position on the physical-order
    /// list, found by a walk, and at the head of its size class.
    fn link_sorted<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx, run: FreeRun)
    {
        let mut prev = NODE_NULL;
        let mut cur = self.head;
        while let Some(p) = pooled_of(arena, cur)
        {
            if p.run.phys_base > run.phys_base
            {
                break;
            }
            prev = cur;
            cur = arena.get(cur).next;
        }
        arena.set(
            idx,
            crate::arena::Slot {
                node: Node::Pooled(PooledRun {
                    run,
                    prev,
                    class_prev: NODE_NULL,
                    class_next: NODE_NULL,
                }),
                next: cur,
            },
        );
        if prev == NODE_NULL
        {
            self.head = idx;
        }
        else
        {
            arena.set_next(prev, idx);
        }
        update(arena, cur, |p| p.prev = idx);
        self.link_class(arena, idx, class_of(run.page_count));
        self.free_pages = self.free_pages.saturating_add(run.page_count);
        // Each linked run holds its own slot, so the count stays below the slot count.
        self.runs = self.runs.saturating_add(1);
    }

    /// Put the pooled run at `idx` at the head of class `class`'s list and
    /// mark the class non-empty.
    fn link_class<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx, class: usize)
    {
        let Some(head) = self.class_heads.get_mut(class)
        else
        {
            return;
        };
        let old = *head;
        *head = idx;
        update(arena, idx, |p| {
            p.class_prev = NODE_NULL;
            p.class_next = old;
        });
        update(arena, old, |p| p.class_prev = idx);
        let row = row_of(class);
        if let Some(bits) = self.class_bits.get_mut(row)
        {
            *bits |= column_bit(class);
        }
        self.row_bits |= row_bit(row);
    }

    /// Take the pooled run `p` at `idx` off class `class`'s list, marking
    /// the class, and its row, empty when it was the last.
    fn unlink_class<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        idx: NodeIdx,
        p: PooledRun,
        class: usize,
    )
    {
        if p.class_prev == NODE_NULL
        {
            if let Some(head) = self.class_heads.get_mut(class)
                && *head == idx
            {
                *head = p.class_next;
            }
        }
        else
        {
            update(arena, p.class_prev, |q| q.class_next = p.class_next);
        }
        update(arena, p.class_next, |q| q.class_prev = p.class_prev);
        if self.class_heads.get(class) == Some(&NODE_NULL)
        {
            let row = row_of(class);
            if let Some(bits) = self.class_bits.get_mut(row)
            {
                *bits &= !column_bit(class);
                if *bits == 0
                {
                    self.row_bits &= !row_bit(row);
                }
            }
        }
    }

    /// Take the pooled run `p` at `idx` off both lists, leaving its slot to
    /// the caller (still holding the run).
    fn unlink<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx, p: PooledRun)
    {
        let next = arena.get(idx).next;
        if p.prev == NODE_NULL
        {
            self.head = next;
        }
        else
        {
            arena.set_next(p.prev, next);
        }
        update(arena, next, |q| q.prev = p.prev);
        self.unlink_class(arena, idx, p, class_of(p.run.page_count));
        // `p` was a linked run, so both counters include it.
        self.free_pages = self.free_pages.saturating_sub(p.run.page_count);
        self.runs = self.runs.saturating_sub(1);
    }

    /// Store `run` in the pooled slot `idx`, at an unchanged physical
    /// position, moving the slot to `run`'s size class when its page count
    /// changed class. Leaves the totals to the caller.
    fn refile<S: SlotStore>(&mut self, arena: &mut Arena<S>, idx: NodeIdx, run: FreeRun)
    {
        let Some(p) = pooled_of(arena, idx)
        else
        {
            return;
        };
        let old = class_of(p.run.page_count);
        let new = class_of(run.page_count);
        if old != new
        {
            self.unlink_class(arena, idx, p, old);
        }
        update(arena, idx, |q| q.run = run);
        if old != new
        {
            self.link_class(arena, idx, new);
        }
    }

    /// The first run of class `class`, [`NODE_NULL`] when it is empty.
    fn class_head(&self, class: usize) -> NodeIdx
    {
        self.class_heads.get(class).copied().unwrap_or(NODE_NULL)
    }

    /// The lowest non-empty class above `class`, found by the bitmaps in a
    /// fixed number of steps, or `None` when every class above it is empty.
    fn class_above(&self, class: usize) -> Option<usize>
    {
        let row = row_of(class);
        // The classes of `class`'s row above it.
        let in_row = u64::from(self.class_bits.get(row).copied().unwrap_or(0))
            & !u64::from(column_bit(class)).wrapping_shl(1).wrapping_sub(1);
        let in_row_at = (in_row | PAST_ROW).trailing_zeros() as usize;
        // The rows above `class`'s; the last row, which no page count reaches,
        // stands in for none.
        let rows = self.row_bits & !row_bit(row).wrapping_shl(1).wrapping_sub(1);
        let up_row = ((rows | row_bit(ROWS - 1)).trailing_zeros() as usize) & (ROWS - 1);
        let up_bits = u64::from(self.class_bits.get(up_row).copied().unwrap_or(0));
        let up_at = (up_bits | PAST_ROW).trailing_zeros() as usize;
        // Choose by mask, so neither outcome takes a branch of its own.
        let here = usize::from(in_row != 0).wrapping_neg();
        let found = (row_start(row).wrapping_add(in_row_at) & here)
            | (row_start(up_row).wrapping_add(up_at) & !here);
        (in_row != 0 || rows != 0).then_some(found)
    }

    /// A run covering at least `want` pages, from the smallest size class
    /// that holds one: the first run of `want`'s own class when it covers
    /// `want`, else the first run of the lowest non-empty class above it,
    /// every run of which does. Neither step depends on the runs the pool
    /// holds. Only when no class above holds a run does it walk `want`'s own
    /// class for a covering run. `None` when no run covers `want`.
    #[must_use]
    pub fn covering<S: SlotStore>(&self, arena: &Arena<S>, want: u64) -> Option<NodeIdx>
    {
        let class = class_of(want);
        let head = self.class_head(class);
        if pooled_of(arena, head).is_some_and(|p| p.run.page_count >= want)
        {
            return Some(head);
        }
        if let Some(above) = self.class_above(class)
        {
            return Some(self.class_head(above));
        }
        self.class_find(arena, class, |r| r.page_count >= want)
    }

    /// The largest run: the largest of the highest non-empty class.
    #[must_use]
    pub fn largest<S: SlotStore>(&self, arena: &Arena<S>) -> Option<NodeIdx>
    {
        let row = 63u32.checked_sub(self.row_bits.leading_zeros())? as usize;
        let bits = self.class_bits.get(row).copied().unwrap_or(0);
        let column = 7u32.checked_sub(bits.leading_zeros())? as usize;
        let class = row_start(row).wrapping_add(column);
        let mut best: Option<(NodeIdx, u64)> = None;
        let mut cur = self.class_head(class);
        while let Some(p) = pooled_of(arena, cur)
        {
            if best.is_none_or(|(_, pages)| p.run.page_count > pages)
            {
                best = Some((cur, p.run.page_count));
            }
            cur = p.class_next;
        }
        best.map(|(idx, _)| idx)
    }

    /// The first run of class `class`'s list that `pick` accepts.
    fn class_find<S: SlotStore>(
        &self,
        arena: &Arena<S>,
        class: usize,
        pick: impl Fn(&FreeRun) -> bool,
    ) -> Option<NodeIdx>
    {
        let mut cur = self.class_head(class);
        while let Some(p) = pooled_of(arena, cur)
        {
            if pick(&p.run)
            {
                return Some(cur);
            }
            cur = p.class_next;
        }
        None
    }

    /// Peel exactly `want` pages off the pooled run at `idx`.
    ///
    /// A run of exactly `want` pages leaves the pool and its slot is freed. A
    /// larger run is split by `split(cap_slot, offset)` (the kernel's
    /// `memory_split`: the cap shrinks in place to the first `offset` bytes
    /// and the returned cap covers the rest), and the remainder keeps the
    /// slot, at an unchanged physical position, filed in its size class.
    /// Returns the cap covering `want` pages and its physical base, or `None`
    /// when the run is too small or the split fails.
    pub fn take_exactly<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        idx: NodeIdx,
        want: u32,
        split: impl FnOnce(u64, u64) -> Option<u64>,
    ) -> Option<(u64, u64)>
    {
        let p = pooled_of(arena, idx)?;
        let run = p.run;
        let want_pages = u64::from(want);
        if run.page_count == want_pages
        {
            self.unlink(arena, idx, p);
            arena.free(idx);
            return Some((run.cap_slot, run.phys_base));
        }
        if run.page_count < want_pages
        {
            return None;
        }
        // `want_pages < run.page_count`, and the run's bytes are within physical address space.
        let offset = want_pages.saturating_mul(PAGE_SIZE);
        let tail = split(run.cap_slot, offset)?;
        self.refile(
            arena,
            idx,
            FreeRun {
                cap_slot: tail,
                page_count: run.page_count.saturating_sub(want_pages),
                phys_base: run.phys_base.saturating_add(offset),
            },
        );
        self.free_pages = self.free_pages.saturating_sub(want_pages);
        Some((run.cap_slot, run.phys_base))
    }

    /// Fold physically adjacent runs together.
    ///
    /// The list is sorted, so mergeable runs are neighbours: each run absorbs
    /// its successors while they start where it ends and `merge(parent,
    /// tail)` (the kernel's `memory_merge`) accepts the pair. A refusal ends
    /// that run's absorption. One `merge` per adjacent pair, O(P) overall.
    pub fn coalesce_with<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        merge: impl Fn(u64, u64) -> bool,
    )
    {
        let mut cur = self.head;
        while let Some(p) = pooled_of(arena, cur)
        {
            let mut run = p.run;
            loop
            {
                let next = arena.get(cur).next;
                let Some(tail) = pooled_of(arena, next)
                else
                {
                    break;
                };
                let adjacent = run
                    .page_count
                    .checked_mul(PAGE_SIZE)
                    .and_then(|b| run.phys_base.checked_add(b))
                    == Some(tail.run.phys_base);
                if !adjacent || !merge(run.cap_slot, tail.run.cap_slot)
                {
                    break;
                }
                // The tail leaves both lists and the totals; its pages come
                // back with `cur`'s.
                self.unlink(arena, next, tail);
                arena.free(next);
                self.free_pages = self.free_pages.saturating_add(tail.run.page_count);
                run.page_count = run.page_count.saturating_add(tail.run.page_count);
            }
            if run != p.run
            {
                self.refile(arena, cur, run);
            }
            cur = arena.get(cur).next;
        }
    }

    /// Select runs for a request of `want` pages.
    ///
    /// - [`Fit::Contiguous`]: a covering run ([`FreePool::covering`]), split
    ///   to size, as one entry; else [`SelectError::Contiguous`].
    /// - [`Fit::BestEffort`]: first a covering run as one entry. Failing
    ///   that, when the pool's free pages cover `want`, runs largest-first up
    ///   to [`MAX_GRANT_RUNS`]; the total MAY then fall short of `want` (a
    ///   partial grant the caller requests again for the rest). When the free
    ///   pages do not cover `want`, or no run could be taken,
    ///   [`SelectError::BestEffort`].
    /// - [`Fit::UpTo`]: a covering run, split to size, as one entry; when no
    ///   run covers `want`, the largest run whole as one entry of fewer pages,
    ///   which needs no split. [`SelectError::Contiguous`] when the pool is
    ///   empty or the covering run's split fails.
    ///
    /// On error the pool is unchanged. `split` is the kernel's
    /// `memory_split`.
    ///
    /// # Errors
    /// As listed above.
    pub fn select<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        want: u32,
        fit: Fit,
        mut split: impl FnMut(u64, u64) -> Option<u64>,
    ) -> Result<Grant, SelectError>
    {
        let mut grant = Grant {
            entries: [(0, 0, 0); MAX_GRANT_RUNS],
            count: 0,
        };
        let covering = self.covering(arena, u64::from(want));
        if let Some(c) = covering
            && let Some((cap, phys)) = self.take_exactly(arena, c, want, &mut split)
        {
            grant.entries[0] = (cap, want, phys);
            grant.count = 1;
            return Ok(grant);
        }
        match fit
        {
            Fit::Contiguous => return Err(SelectError::Contiguous),
            Fit::UpTo => return self.take_largest_whole(arena, covering, grant),
            Fit::BestEffort =>
            {}
        }
        if self.free_pages < u64::from(want)
        {
            return Err(SelectError::BestEffort);
        }
        let mut remaining = want;
        while remaining > 0 && grant.count < MAX_GRANT_RUNS
        {
            let Some(c) = self.largest(arena)
            else
            {
                break;
            };
            let avail = pooled_of(arena, c).map_or(0, |p| p.run.page_count);
            // `avail.min(remaining)` fits u32 because `remaining` does.
            let take = u32::try_from(avail.min(u64::from(remaining))).unwrap_or(remaining);
            let Some((cap, phys)) = self.take_exactly(arena, c, take, &mut split)
            else
            {
                break;
            };
            // The loop condition keeps `grant.count` below `MAX_GRANT_RUNS`.
            let Some(entry) = grant.entries.get_mut(grant.count)
            else
            {
                break;
            };
            *entry = (cap, take, phys);
            grant.count = grant.count.saturating_add(1);
            // `take` is at most `remaining`.
            remaining = remaining.saturating_sub(take);
        }
        if grant.count == 0
        {
            return Err(SelectError::BestEffort);
        }
        Ok(grant)
    }

    /// The [`Fit::UpTo`] fallback once no run could be split to the request:
    /// the largest run whole, as `grant`'s one entry. `covering` is the run
    /// that covers the request, if any; when there is one, its split failed,
    /// and the selection fails rather than take more pages than asked.
    fn take_largest_whole<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        covering: Option<NodeIdx>,
        mut grant: Grant,
    ) -> Result<Grant, SelectError>
    {
        if covering.is_some()
        {
            return Err(SelectError::Contiguous);
        }
        let c = self.largest(arena).ok_or(SelectError::Contiguous)?;
        // No run covers the request, so the largest is below it, a `u32`.
        let pages = pooled_of(arena, c)
            .and_then(|p| u32::try_from(p.run.page_count).ok())
            .ok_or(SelectError::Contiguous)?;
        // An exact take unlinks the run whole and never splits.
        let (cap, phys) = self
            .take_exactly(arena, c, pages, |_, _| None)
            .ok_or(SelectError::Contiguous)?;
        grant.entries[0] = (cap, pages, phys);
        grant.count = 1;
        Ok(grant)
    }

    /// Return `run` to the pool by merging it into the free run that starts
    /// where it ends (the remainder of the split that produced it), so the
    /// return needs no fresh slot. `merge(parent, tail)` is the kernel's
    /// `memory_merge`; on success the follower's slot takes `run`'s cap, base,
    /// and the joined page count, at an unchanged physical position, filed in
    /// the joined count's size class. Returns `false`, changing nothing, when
    /// no free run starts there or the kernel refuses the merge.
    pub fn absorb_front<S: SlotStore>(
        &mut self,
        arena: &mut Arena<S>,
        run: FreeRun,
        merge: impl FnOnce(u64, u64) -> bool,
    ) -> bool
    {
        let Some(end) = run
            .page_count
            .checked_mul(PAGE_SIZE)
            .and_then(|b| run.phys_base.checked_add(b))
        else
        {
            return false;
        };
        let mut cur = self.head;
        while let Some(p) = pooled_of(arena, cur)
        {
            if p.run.phys_base == end
            {
                if !merge(run.cap_slot, p.run.cap_slot)
                {
                    return false;
                }
                self.refile(
                    arena,
                    cur,
                    FreeRun {
                        cap_slot: run.cap_slot,
                        page_count: run.page_count.saturating_add(p.run.page_count),
                        phys_base: run.phys_base,
                    },
                );
                self.free_pages = self.free_pages.saturating_add(run.page_count);
                return true;
            }
            if p.run.phys_base > end
            {
                return false;
            }
            cur = arena.get(cur).next;
        }
        false
    }

    /// Every run, in physical order, for diagnostics and tests.
    pub fn for_each<S: SlotStore>(&self, arena: &Arena<S>, mut f: impl FnMut(FreeRun))
    {
        let mut cur = self.head;
        while let Some(p) = pooled_of(arena, cur)
        {
            f(p.run);
            cur = arena.get(cur).next;
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::arena::test_store::VecStore;
    use crate::arena::{SLOTS_PER_PAGE, Slot};

    fn run(cap_slot: u64, page_count: u64, phys_base: u64) -> FreeRun
    {
        FreeRun {
            cap_slot,
            page_count,
            phys_base,
        }
    }

    fn arena() -> Arena<VecStore>
    {
        let mut a = Arena::new(VecStore::default());
        // SAFETY: VecStore grows on write.
        unsafe { a.add_page() };
        a
    }

    fn runs(pool: &FreePool, arena: &Arena<VecStore>) -> Vec<FreeRun>
    {
        let mut v = Vec::new();
        pool.for_each(arena, |r| v.push(r));
        v
    }

    fn no_split(_: u64, _: u64) -> Option<u64>
    {
        panic!("split must not run")
    }

    #[test]
    fn push_keeps_runs_sorted_by_phys_base_and_counts_pages()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(3, 1, 0x3000), run(1, 2, 0x1000), run(2, 4, 0x8000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        let bases: Vec<u64> = runs(&pool, &a).iter().map(|r| r.phys_base).collect();
        assert_eq!(bases, [0x1000, 0x3000, 0x8000]);
        assert_eq!((pool.free_pages(), pool.run_count()), (7, 3));
    }

    #[test]
    fn push_returns_the_run_when_the_arena_is_full()
    {
        let mut a = Arena::new(VecStore::default());
        let mut pool = FreePool::new();
        assert_eq!(pool.push(&mut a, run(1, 1, 0)).unwrap_err().cap_slot, 1);
        assert_eq!(pool.free_pages(), 0);
    }

    #[test]
    fn page_counts_beyond_u32_are_kept_whole()
    {
        // A 32 TiB run: the old u32 page count truncated it to 16 TiB.
        let mut a = arena();
        let mut pool = FreePool::new();
        let pages = (1u64 << 33) + 5;
        pool.push(&mut a, run(1, pages, 0)).unwrap();
        assert_eq!(pool.free_pages(), pages);
        assert_eq!(pool.largest_pages(&a), pages);
    }

    /// The cap of the run [`FreePool::covering`] picks for `want`.
    fn covering_cap(pool: &FreePool, a: &Arena<impl SlotStore>, want: u64) -> Option<u64>
    {
        pool.covering(a, want)
            .and_then(|c| pooled_of(a, c))
            .map(|p| p.run.cap_slot)
    }

    #[test]
    fn covering_takes_a_run_of_the_smallest_class_that_covers()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(1, 8, 0x10000), run(2, 4, 0x20000), run(3, 16, 0x30000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        assert_eq!(covering_cap(&pool, &a, 4), Some(2));
        assert_eq!(covering_cap(&pool, &a, 5), Some(1));
        assert_eq!(covering_cap(&pool, &a, 17), None);
    }

    #[test]
    fn size_classes_rise_with_the_count_and_are_exact_below_two_rows()
    {
        // A class never holds a count above one of a higher class, so every run
        // of a class above want's covers it; below `2 * CLASS_SPLIT` each count
        // is a class of its own, so a small request gets an exact fit.
        let mut prev = class_of(1);
        for pages in 2..(1u64 << 16)
        {
            let class = class_of(pages);
            assert!(
                class >= prev,
                "class of {pages} below that of {}",
                pages - 1
            );
            if pages < 2 * SPLIT_PAGES
            {
                assert_eq!(class, prev + 1, "{pages} shares a class below two rows");
            }
            prev = class;
        }
        for pages in [1u64 << 40, (1u64 << 52) + 5, u64::MAX]
        {
            assert!(class_of(pages) < CLASSES);
            assert!(class_of(pages) > class_of(pages >> 1));
        }
    }

    #[test]
    fn covering_walks_want_s_own_class_only_when_no_class_above_holds_a_run()
    {
        // 16 and 17 pages share a class. With the 16-page run at its head and
        // nothing above, a 17-page request still finds the 17-page run.
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 17, 0x10000)).unwrap();
        pool.push(&mut a, run(2, 16, 0x40000)).unwrap();
        assert_eq!(class_of(16), class_of(17));
        assert_eq!(covering_cap(&pool, &a, 17), Some(1));
        // With a run in a higher class, that run serves instead, by the bitmaps.
        pool.push(&mut a, run(3, 40, 0x80000)).unwrap();
        assert_eq!(covering_cap(&pool, &a, 17), Some(3));
        assert_eq!(covering_cap(&pool, &a, 16), Some(2));
    }

    /// A slot store that counts the slots read and written, the steps a pool
    /// operation takes.
    #[derive(Default)]
    struct CountingStore
    {
        inner: VecStore,
        touched: core::cell::Cell<u64>,
    }

    impl SlotStore for CountingStore
    {
        unsafe fn read(&self, idx: NodeIdx) -> Slot
        {
            self.touched.set(self.touched.get() + 1);
            // SAFETY: the caller's contract is `VecStore::read`'s.
            unsafe { self.inner.read(idx) }
        }

        unsafe fn write(&mut self, idx: NodeIdx, slot: Slot)
        {
            self.touched.set(self.touched.get() + 1);
            // SAFETY: as in `read`.
            unsafe { self.inner.write(idx, slot) }
        }

        unsafe fn replace(&mut self, idx: NodeIdx, slot: Slot) -> Slot
        {
            self.touched.set(self.touched.get() + 1);
            // SAFETY: as in `read`.
            unsafe { self.inner.replace(idx, slot) }
        }
    }

    /// The slots one 16-page selection touches, split off a 4096-page run,
    /// after `small` runs below 16 pages and `large` runs far above the
    /// 4096-page run's class came back, in the order `stride` permutes them.
    fn select_cost(small: u64, large: u64, stride: u64) -> u64
    {
        let mut a = Arena::new(CountingStore::default());
        let total = small + large;
        for _ in 0..=total / SLOTS_PER_PAGE
        {
            // SAFETY: VecStore grows on write.
            unsafe { a.add_page() };
        }
        let mut pool = FreePool::new();
        for i in 0..total
        {
            // `stride` is odd and `total` a power of two, so this visits each once.
            let k = (i * stride) % total;
            let r = if k < small
            {
                run(k, 1 + k % 15, 0x1_0000_0000 + k * 0x10_0000)
            }
            else
            {
                run(k, 1 << 20, 0x100_0000_0000 + k * 0x1_0000_0000)
            };
            pool.push(&mut a, r).unwrap();
        }
        pool.push(&mut a, run(999, 4096, 0x8000_0000)).unwrap();
        a.store().touched.set(0);
        let g = pool
            .select(&mut a, 16, Fit::UpTo, |cap, _| Some(cap + 1))
            .unwrap();
        assert_eq!(g.entries(), [(999, 16, 0x8000_0000)]);
        a.store().touched.get()
    }

    #[test]
    fn a_selection_touches_the_same_slots_whatever_runs_came_back_before()
    {
        let alone = select_cost(0, 1, 1);
        for (small, large, stride) in [(64, 64, 1), (64, 64, 77), (512, 512, 333), (1024, 0, 5)]
        {
            assert_eq!(
                select_cost(small, large, stride),
                alone,
                "{small} small and {large} large runs, order {stride}"
            );
        }
    }

    #[test]
    fn a_split_remainder_and_a_coalesced_run_are_found_in_their_new_classes()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 20, 0x10_0000)).unwrap();
        // 16 off 20 leaves 4, now in the 4-page class.
        let g = pool
            .select(&mut a, 16, Fit::Contiguous, |_, _| Some(7))
            .unwrap();
        assert_eq!(g.entries(), [(1, 16, 0x10_0000)]);
        assert_eq!(covering_cap(&pool, &a, 4), Some(7));
        assert_eq!(covering_cap(&pool, &a, 5), None);
        // Three adjacent one-page runs fold into one 3-page run; the freed
        // tails are gone from the one-page class.
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(30, 1, 0x3000), run(10, 1, 0x1000), run(20, 1, 0x2000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        pool.coalesce_with(&mut a, |_, _| true);
        assert_eq!(covering_cap(&pool, &a, 1), Some(10));
        assert_eq!(covering_cap(&pool, &a, 3), Some(10));
        assert_eq!(covering_cap(&pool, &a, 4), None);
    }

    #[test]
    fn largest_is_the_largest_run_of_the_top_class_whatever_its_order()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(1, 17, 0x10000), run(2, 16, 0x40000), run(3, 5, 0x80000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        assert_eq!(pool.largest_pages(&a), 17);
        let c = pool.largest(&a).unwrap();
        assert_eq!(pooled_of(&a, c).map(|p| p.run.cap_slot), Some(1));
    }

    #[test]
    fn take_exactly_unlinks_an_exact_run_and_frees_its_slot()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(7, 4, 0x8000)).unwrap();
        let free_before = a.free_count();
        let c = pool.covering(&a, 4).unwrap();
        assert_eq!(pool.take_exactly(&mut a, c, 4, no_split), Some((7, 0x8000)));
        assert_eq!(runs(&pool, &a).len(), 1);
        assert_eq!(a.free_count(), free_before + 1);
        assert_eq!(pool.free_pages(), 2);
    }

    #[test]
    fn take_exactly_splits_a_larger_run_keeping_the_remainder_in_place()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(5, 8, 0x1000)).unwrap();
        let c = pool.largest(&a).unwrap();
        let got = pool.take_exactly(&mut a, c, 3, |cap, off| {
            assert_eq!((cap, off), (5, 3 * PAGE_SIZE));
            Some(99)
        });
        assert_eq!(got, Some((5, 0x1000)));
        let rest = runs(&pool, &a);
        assert_eq!(rest.len(), 1);
        assert_eq!((rest[0].cap_slot, rest[0].page_count), (99, 5));
        assert_eq!(rest[0].phys_base, 0x1000 + 3 * PAGE_SIZE);
        assert_eq!(pool.free_pages(), 5);
    }

    #[test]
    fn take_exactly_refuses_a_run_smaller_than_want_or_a_failed_split()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(5, 3, 0x1000)).unwrap();
        let c = pool.largest(&a).unwrap();
        assert!(pool.take_exactly(&mut a, c, 4, no_split).is_none());
        assert!(pool.take_exactly(&mut a, c, 2, |_, _| None).is_none());
        assert_eq!(pool.free_pages(), 3);
    }

    #[test]
    fn coalesce_folds_adjacent_runs_into_the_lowest_and_frees_slots()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [run(30, 1, 0x3000), run(10, 1, 0x1000), run(20, 1, 0x2000)]
        {
            pool.push(&mut a, r).unwrap();
        }
        let free_before = a.free_count();
        pool.coalesce_with(&mut a, |_, _| true);
        let rest = runs(&pool, &a);
        assert_eq!(rest.len(), 1);
        assert_eq!(
            (rest[0].cap_slot, rest[0].page_count, rest[0].phys_base),
            (10, 3, 0x1000)
        );
        assert_eq!(a.free_count(), free_before + 2);
        assert_eq!((pool.free_pages(), pool.run_count()), (3, 1));
    }

    #[test]
    fn coalesce_skips_gaps_without_asking_and_stops_on_a_refusal()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for r in [
            run(10, 1, 0x1000),
            run(20, 1, 0x2000),
            run(30, 1, 0x3000),
            run(40, 1, 0x9000),
        ]
        {
            pool.push(&mut a, r).unwrap();
        }
        let asked = core::cell::RefCell::new(Vec::new());
        // The kernel refuses 20+30; 40 is not adjacent, so it is never asked.
        pool.coalesce_with(&mut a, |p, t| {
            asked.borrow_mut().push((p, t));
            t != 30
        });
        assert_eq!(*asked.borrow(), [(10, 20), (10, 30)]);
        let rest: Vec<(u64, u64)> = runs(&pool, &a)
            .iter()
            .map(|r| (r.cap_slot, r.page_count))
            .collect();
        assert_eq!(rest, [(10, 2), (30, 1), (40, 1)]);
    }

    #[test]
    fn select_contiguous_fails_when_no_single_run_covers()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 2, 0x8000)).unwrap();
        assert_eq!(
            pool.select(&mut a, 3, Fit::Contiguous, no_split)
                .unwrap_err(),
            SelectError::Contiguous
        );
        assert_eq!(pool.free_pages(), 4);
    }

    #[test]
    fn select_best_effort_returns_a_partial_grant_when_the_ram_exists()
    {
        // Six disjoint one-page runs: no single run and no four runs cover 6.
        let mut a = arena();
        let mut pool = FreePool::new();
        for i in 0..6u32
        {
            pool.push(&mut a, run(u64::from(i), 1, u64::from(i) * 0x10000))
                .unwrap();
        }
        let grant = pool.select(&mut a, 6, Fit::BestEffort, no_split).unwrap();
        assert_eq!(grant.count, MAX_GRANT_RUNS);
        let pages: u32 = grant.entries().iter().map(|e| e.1).sum();
        assert_eq!(pages, u32::try_from(MAX_GRANT_RUNS).unwrap());
        assert_eq!(pool.free_pages(), 6 - MAX_GRANT_RUNS as u64);
    }

    #[test]
    fn select_best_effort_fails_unchanged_when_free_pages_fall_short()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 2, 0x8000)).unwrap();
        assert_eq!(
            pool.select(&mut a, 5, Fit::BestEffort, no_split)
                .unwrap_err(),
            SelectError::BestEffort
        );
        assert_eq!((pool.free_pages(), pool.run_count()), (4, 2));
    }

    #[test]
    fn select_best_effort_covers_from_largest_runs_first()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 2, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 5, 0x10000)).unwrap();
        pool.push(&mut a, run(3, 1, 0x30000)).unwrap();
        // 6 pages: no single run; 5 from cap 2, then 1 split off cap 1.
        let grant = pool
            .select(&mut a, 6, Fit::BestEffort, |cap, _| Some(cap + 100))
            .unwrap();
        let caps: Vec<(u64, u32)> = grant.entries().iter().map(|e| (e.0, e.1)).collect();
        assert_eq!(caps, [(2, 5), (1, 1)]);
        assert_eq!(pool.free_pages(), 2);
    }

    #[test]
    fn select_takes_one_covering_run_whole_or_split_in_either_fit()
    {
        for fit in [Fit::Contiguous, Fit::BestEffort]
        {
            let mut a = arena();
            let mut pool = FreePool::new();
            pool.push(&mut a, run(1, 3, 0x1000)).unwrap();
            pool.push(&mut a, run(2, 8, 0x10000)).unwrap();
            // Exact: the 3-page run leaves whole, no split.
            let g = pool.select(&mut a, 3, fit, no_split).unwrap();
            assert_eq!(g.entries(), [(1, 3, 0x1000)]);
            // Larger: the 8-page run is split, one entry.
            let g = pool.select(&mut a, 2, fit, |_, _| Some(9)).unwrap();
            assert_eq!(g.entries(), [(2, 2, 0x10000)]);
            assert_eq!(pool.free_pages(), 6);
        }
    }

    #[test]
    fn select_contiguous_fails_unchanged_when_the_split_is_refused()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 4, 0x1000)).unwrap();
        assert_eq!(
            pool.select(&mut a, 2, Fit::Contiguous, |_, _| None)
                .unwrap_err(),
            SelectError::Contiguous
        );
        assert_eq!(pool.free_pages(), 4);
    }

    #[test]
    fn select_best_effort_fails_unchanged_when_no_run_can_be_taken()
    {
        // The free pages cover the request, but every split is refused.
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 4, 0x1000)).unwrap();
        assert_eq!(
            pool.select(&mut a, 2, Fit::BestEffort, |_, _| None)
                .unwrap_err(),
            SelectError::BestEffort
        );
        assert_eq!((pool.free_pages(), pool.run_count()), (4, 1));
    }

    #[test]
    fn select_up_to_takes_the_covering_run_split_to_the_request()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 3, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 20, 0x10000)).unwrap();
        pool.push(&mut a, run(3, 40, 0x100_000)).unwrap();
        // 16 pages: the smallest covering run (20) is split, as Contiguous does.
        let g = pool.select(&mut a, 16, Fit::UpTo, |_, _| Some(9)).unwrap();
        assert_eq!(g.entries(), [(2, 16, 0x10000)]);
        assert_eq!((pool.free_pages(), pool.run_count()), (47, 3));
    }

    #[test]
    fn select_up_to_takes_the_largest_run_whole_on_a_fragmented_pool()
    {
        // No run covers 16 pages: the largest (7) leaves whole, unsplit, and
        // the free pages and run count fall by exactly that run.
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 3, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 7, 0x10000)).unwrap();
        pool.push(&mut a, run(3, 5, 0x100_000)).unwrap();
        let g = pool.select(&mut a, 16, Fit::UpTo, no_split).unwrap();
        assert_eq!(g.entries(), [(2, 7, 0x10000)]);
        assert_eq!((pool.free_pages(), pool.run_count()), (8, 2));
        assert_eq!(runs(&pool, &a), [run(1, 3, 0x1000), run(3, 5, 0x100_000)]);
        // Contiguous on the same pool still refuses.
        assert_eq!(
            pool.select(&mut a, 16, Fit::Contiguous, no_split)
                .unwrap_err(),
            SelectError::Contiguous
        );
    }

    #[test]
    fn select_up_to_falls_to_one_page_and_fails_only_on_an_empty_pool()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        for i in 0..3u64
        {
            pool.push(&mut a, run(i, 1, i * 0x10000)).unwrap();
        }
        for _ in 0..3
        {
            let g = pool.select(&mut a, 16, Fit::UpTo, no_split).unwrap();
            assert_eq!(g.count, 1);
            assert_eq!(g.entries()[0].1, 1);
        }
        assert_eq!((pool.free_pages(), pool.run_count()), (0, 0));
        assert_eq!(
            pool.select(&mut a, 16, Fit::UpTo, no_split).unwrap_err(),
            SelectError::Contiguous
        );
    }

    #[test]
    fn select_up_to_fails_unchanged_when_the_covering_split_is_refused()
    {
        // A run covers the request but cannot be split: the selection does not
        // fall back to taking it whole, which would exceed the request.
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 3, 0x1000)).unwrap();
        pool.push(&mut a, run(2, 20, 0x10000)).unwrap();
        assert_eq!(
            pool.select(&mut a, 16, Fit::UpTo, |_, _| None).unwrap_err(),
            SelectError::Contiguous
        );
        assert_eq!((pool.free_pages(), pool.run_count()), (23, 2));
    }

    #[test]
    fn absorb_front_rejoins_a_split_page_without_a_slot()
    {
        let mut a = arena();
        let mut pool = FreePool::new();
        pool.push(&mut a, run(1, 4, 0x1000)).unwrap();
        let c = pool.largest(&a).unwrap();
        let (cap, phys) = pool.take_exactly(&mut a, c, 1, |_, _| Some(7)).unwrap();
        let back = run(cap, 1, phys);
        // A run that does not end where a free run starts is refused.
        assert!(!pool.absorb_front(&mut a, run(5, 1, 0x9000), |_, _| true));
        // The kernel refusing the merge changes nothing.
        assert!(!pool.absorb_front(&mut a, back, |_, _| false));
        assert!(pool.absorb_front(&mut a, back, |p, t| (p, t) == (1, 7)));
        assert_eq!(runs(&pool, &a), [run(1, 4, 0x1000)]);
        assert_eq!((pool.free_pages(), pool.run_count()), (4, 1));
    }

    #[test]
    fn push_reserved_takes_the_reserve_push_leaves()
    {
        let mut a = Arena::new(VecStore::default());
        a.set_reserve(1);
        // SAFETY: VecStore grows on write.
        unsafe { a.add_page() };
        let mut pool = FreePool::new();
        let mut i = 0u32;
        while pool
            .push(&mut a, run(u64::from(i), 1, u64::from(i) * 0x10000))
            .is_ok()
        {
            i += 1;
        }
        assert_eq!(a.free_count(), 1);
        let last = run(9999, 1, 0xFFFF_0000);
        pool.push_reserved(&mut a, last).unwrap();
        assert_eq!(pool.push_reserved(&mut a, last).unwrap_err(), last);
        assert_eq!(pool.run_count(), u64::from(i) + 1);
    }

    #[test]
    fn grant_entries_clamps_a_count_past_the_array_to_every_entry()
    {
        let grant = Grant {
            entries: [(1, 2, 3); MAX_GRANT_RUNS],
            count: MAX_GRANT_RUNS + 1,
        };
        assert_eq!(grant.entries().len(), MAX_GRANT_RUNS);
    }
}
