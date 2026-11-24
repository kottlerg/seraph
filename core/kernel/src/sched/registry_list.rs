// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/registry_list.rs

//! Intrusive doubly linked list whose walks survive the release of its lock
//! between batches — the live-thread registry's storage
//! (`sched::thread_registry`).
//!
//! A walk keeps its place in a [`Cursor`] that the list knows of while the
//! walk lasts: [`RegistryList::remove`] moves every cursor that names the
//! node it unlinks on to that node's successor. A node is linked only at the
//! head, behind every cursor, so the nodes a cursor can still reach are always
//! a subset of the nodes that were linked when its walk began. Hence a walk
//! visits every node linked for the walk's whole span exactly once, never
//! reaches a node after its removal (so never a freed one, as every free
//! follows the removal), and takes at most as many steps as the list was long
//! when it began: a walk that would take more has met a list corrupted into a
//! cycle ([`Step::Cycle`]).
//!
//! The list is not synchronised: its owner serialises every operation, every
//! cursor's steps included, under one lock, and may release that lock between
//! two steps of a walk.

/// The links of a node on a [`RegistryList`], embedded in the node.
pub struct RegistryLinks<T>
{
    next: *mut T,
    prev: *mut T,
}

impl<T> RegistryLinks<T>
{
    /// The links of a node on no list.
    pub const fn new() -> Self
    {
        Self {
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
        }
    }
}

/// A node type a [`RegistryList`] can link.
pub trait RegistryNode: Sized
{
    /// The links embedded in `node`.
    ///
    /// # Safety
    /// `node` is a valid node.
    unsafe fn links(node: *mut Self) -> *mut RegistryLinks<Self>;
}

/// The place of one walk over a [`RegistryList`]: the next node it visits,
/// and the steps left before it has taken as many as the list was long when
/// it began. While attached it is on the list's chain of cursors, so it must
/// not move until [`RegistryList::detach`].
pub struct Cursor<T>
{
    next: *mut T,
    remaining: usize,
    older: *mut Cursor<T>,
    newer: *mut Cursor<T>,
}

impl<T> Cursor<T>
{
    /// A cursor on no list.
    pub const fn new() -> Self
    {
        Self {
            next: core::ptr::null_mut(),
            remaining: 0,
            older: core::ptr::null_mut(),
            newer: core::ptr::null_mut(),
        }
    }
}

/// What a walk's step found.
pub enum Step<T>
{
    /// The next node, which the cursor has now passed.
    Node(*mut T),
    /// The walk has reached the end of the list.
    End,
    /// The walk has taken as many steps as the list was long when it began
    /// and has not reached the end: the list is corrupted into a cycle.
    Cycle,
}

// Compared and printed by the node's address, so `T` needs neither trait (a
// derive would require them of `T`).
#[cfg(test)]
impl<T> PartialEq for Step<T>
{
    fn eq(&self, other: &Self) -> bool
    {
        match (self, other)
        {
            (Self::Node(a), Self::Node(b)) => core::ptr::eq(*a, *b),
            (Self::End, Self::End) | (Self::Cycle, Self::Cycle) => true,
            _ => false,
        }
    }
}

#[cfg(test)]
impl<T> core::fmt::Debug for Step<T>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match self
        {
            Self::Node(p) => write!(f, "Node({:#x})", p.addr()),
            Self::End => f.write_str("End"),
            Self::Cycle => f.write_str("Cycle"),
        }
    }
}

/// The list: its head, its length, and the cursors of the walks in progress.
pub struct RegistryList<T>
{
    head: *mut T,
    len: usize,
    cursors: *mut Cursor<T>,
}

impl<T: RegistryNode> RegistryList<T>
{
    /// An empty list.
    pub const fn new() -> Self
    {
        Self {
            head: core::ptr::null_mut(),
            len: 0,
            cursors: core::ptr::null_mut(),
        }
    }

    /// The number of linked nodes.
    #[cfg(test)]
    pub fn len(&self) -> usize
    {
        self.len
    }

    /// Whether no node is linked.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool
    {
        self.head.is_null()
    }

    /// Link `node` at the head, behind every cursor.
    ///
    /// # Safety
    /// `node` is a valid node on no list, and stays valid until it is removed.
    pub unsafe fn push_front(&mut self, node: *mut T)
    {
        // SAFETY: node is valid (contract).
        let links = unsafe { T::links(node) };
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "both writes are to the links of `node`, valid by the contract"
        )]
        // SAFETY: as above; the owner serialises every access to the links.
        unsafe {
            (*links).prev = core::ptr::null_mut();
            (*links).next = self.head;
        }
        if !self.head.is_null()
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "one write to the links of the head, a linked node, valid until its \
                          removal"
            )]
            // SAFETY: a linked node is valid until removed (push_front's
            // contract).
            unsafe {
                (*T::links(self.head)).prev = node;
            }
        }
        self.head = node;
        self.len = self.len.saturating_add(1);
    }

    /// Unlink `node`, moving every cursor that names it on to its successor.
    /// Returns `false`, changing nothing, for a node that is on no list (both
    /// links null and not the head).
    ///
    /// # Safety
    /// `node` is a valid node, on this list or on none.
    pub unsafe fn remove(&mut self, node: *mut T) -> bool
    {
        // SAFETY: node is valid (contract).
        let links = unsafe { T::links(node) };
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "both reads are of the links of `node`, valid by the contract"
        )]
        // SAFETY: as above.
        let (prev, next) = unsafe { ((*links).prev, (*links).next) };
        if prev.is_null()
        {
            // `node` is the head, or on no list: only a head is unlinked, so
            // a node never linked cannot corrupt the list.
            if !core::ptr::eq(self.head, node)
            {
                return false;
            }
            self.head = next;
        }
        else
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "one write to the links of `prev`, a linked node"
            )]
            // SAFETY: a non-null prev is a linked node, valid until removed.
            unsafe {
                (*T::links(prev)).next = next;
            }
        }
        if !next.is_null()
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "one write to the links of `next`, a linked node"
            )]
            // SAFETY: as for prev.
            unsafe {
                (*T::links(next)).prev = prev;
            }
        }
        let mut cursor = self.cursors;
        while !cursor.is_null()
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is to one attached cursor, which stays in place until \
                          its detach"
            )]
            // SAFETY: an attached cursor is valid until detached (Cursor).
            unsafe {
                if core::ptr::eq((*cursor).next, node)
                {
                    (*cursor).next = next;
                }
                cursor = (*cursor).older;
            }
        }
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "both writes are to the links of `node`, valid by the contract"
        )]
        // SAFETY: node is valid (contract).
        unsafe {
            (*links).next = core::ptr::null_mut();
            (*links).prev = core::ptr::null_mut();
        }
        self.len = self.len.saturating_sub(1);
        true
    }

    /// Begin a walk at the head with `cursor`, attaching it to the list.
    ///
    /// # Safety
    /// `cursor` is valid, attached to no list, and stays in place until
    /// [`Self::detach`].
    pub unsafe fn attach(&mut self, cursor: *mut Cursor<T>)
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to `cursor`, valid by the contract, or to the newest \
                      attached cursor, valid until its detach"
        )]
        // SAFETY: as the reason says.
        unsafe {
            (*cursor).next = self.head;
            (*cursor).remaining = self.len;
            (*cursor).newer = core::ptr::null_mut();
            (*cursor).older = self.cursors;
            if !self.cursors.is_null()
            {
                (*self.cursors).newer = cursor;
            }
        }
        self.cursors = cursor;
    }

    /// End the walk of `cursor`, detaching it from the list.
    ///
    /// # Safety
    /// `cursor` is attached to this list.
    pub unsafe fn detach(&mut self, cursor: *mut Cursor<T>)
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to `cursor` or a neighbour on the chain, each attached \
                      and so valid until its detach"
        )]
        // SAFETY: as the reason says.
        unsafe {
            let (older, newer) = ((*cursor).older, (*cursor).newer);
            if newer.is_null()
            {
                self.cursors = older;
            }
            else
            {
                (*newer).older = older;
            }
            if !older.is_null()
            {
                (*older).newer = newer;
            }
            (*cursor).older = core::ptr::null_mut();
            (*cursor).newer = core::ptr::null_mut();
            (*cursor).next = core::ptr::null_mut();
        }
    }

    /// Whether the walk of `cursor` has a node left to visit.
    ///
    /// # Safety
    /// `cursor` is attached to a list the caller holds exclusively (its
    /// lock).
    pub unsafe fn has_next(cursor: *const Cursor<T>) -> bool
    {
        // SAFETY: an attached cursor is valid (contract).
        !unsafe { (*cursor).next }.is_null()
    }

    /// Take the walk of `cursor` one node on.
    ///
    /// # Safety
    /// `cursor` is attached to a list the caller holds exclusively (its
    /// lock).
    pub unsafe fn step(cursor: *mut Cursor<T>) -> Step<T>
    {
        // SAFETY: an attached cursor is valid (contract).
        let cur = unsafe { &mut *cursor };
        if cur.next.is_null()
        {
            return Step::End;
        }
        if cur.remaining == 0
        {
            return Step::Cycle;
        }
        let node = cur.next;
        // SAFETY: a node a cursor names is linked (remove moves the cursor off
        // a node it unlinks), so valid.
        let links = unsafe { T::links(node) };
        // SAFETY: links of a linked, valid node.
        cur.next = unsafe { (*links).next };
        cur.remaining = cur.remaining.saturating_sub(1);
        Step::Node(node)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    struct Node
    {
        id: usize,
        links: RegistryLinks<Node>,
    }

    impl RegistryNode for Node
    {
        unsafe fn links(node: *mut Self) -> *mut RegistryLinks<Self>
        {
            // SAFETY: node is valid (contract).
            unsafe { &raw mut (*node).links }
        }
    }

    #[expect(
        clippy::vec_box,
        reason = "each node needs its own allocation: the list links the nodes by raw pointer"
    )]
    fn nodes(n: usize) -> Vec<Box<Node>>
    {
        (0..n)
            .map(|id| {
                Box::new(Node {
                    id,
                    links: RegistryLinks::new(),
                })
            })
            .collect()
    }

    fn ptr(nodes: &mut [Box<Node>], i: usize) -> *mut Node
    {
        &raw mut *nodes[i]
    }

    /// The ids a walk with an attached cursor visits from where it stands.
    fn rest(list: &mut RegistryList<Node>, cursor: *mut Cursor<Node>) -> Vec<usize>
    {
        let mut out = Vec::new();
        loop
        {
            // SAFETY: cursor is attached to list.
            match unsafe { RegistryList::<Node>::step(cursor) }
            {
                // SAFETY: a stepped node is a live boxed node.
                Step::Node(n) => out.push(unsafe { (*n).id }),
                Step::End => return out,
                Step::Cycle => panic!("unexpected cycle"),
            }
        }
    }

    /// A small deterministic generator (xorshift64).
    struct Rng(u64);

    impl Rng
    {
        fn next(&mut self) -> u64
        {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: usize) -> usize
        {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }
    }

    // Defect guarded: a walk must visit every node linked for its whole span
    // in list order (newest first) and end at the tail.
    #[test]
    fn a_walk_visits_every_node_newest_first()
    {
        let mut ns = nodes(5);
        let mut list = RegistryList::new();
        for i in 0..5
        {
            // SAFETY: each boxed node is on no list and outlives the list use.
            unsafe { list.push_front(ptr(&mut ns, i)) };
        }
        assert_eq!(list.len(), 5);
        let mut c = Cursor::new();
        // SAFETY: c stays in place until the detach below.
        unsafe { list.attach(&raw mut c) };
        assert_eq!(rest(&mut list, &raw mut c), [4, 3, 2, 1, 0]);
        // SAFETY: c is attached.
        unsafe { list.detach(&raw mut c) };
    }

    // Defect guarded: removing the node a paused walk will visit next must
    // move the walk past it, not leave it naming an unlinked (and then freed)
    // node; removing nodes behind or ahead must not disturb it.
    #[test]
    fn removing_the_next_node_moves_the_cursor_on()
    {
        let mut ns = nodes(4);
        let mut list = RegistryList::new();
        for i in 0..4
        {
            // SAFETY: as above.
            unsafe { list.push_front(ptr(&mut ns, i)) };
        }
        let mut c = Cursor::new();
        // SAFETY: as above.
        unsafe { list.attach(&raw mut c) };
        assert_eq!(
            // SAFETY: c is attached.
            unsafe { RegistryList::<Node>::step(&raw mut c) },
            Step::Node(ptr(&mut ns, 3))
        );
        // The cursor names node 2 next. Remove it, then node 3 (behind).
        // SAFETY: both are linked boxed nodes.
        assert!(unsafe { list.remove(ptr(&mut ns, 2)) });
        // SAFETY: as above.
        assert!(unsafe { list.remove(ptr(&mut ns, 3)) });
        assert_eq!(rest(&mut list, &raw mut c), [1, 0]);
        // SAFETY: c is attached.
        unsafe { list.detach(&raw mut c) };
        assert_eq!(list.len(), 2);
    }

    // Defect guarded: a node never linked, or already removed, must be a
    // no-op to remove (the thread-creation rollback and dealloc remove
    // unconditionally).
    #[test]
    fn removing_an_unlinked_node_changes_nothing()
    {
        let mut ns = nodes(3);
        let mut list = RegistryList::new();
        // SAFETY: as above.
        unsafe { list.push_front(ptr(&mut ns, 0)) };
        // SAFETY: node 1 is a boxed node on no list.
        assert!(!unsafe { list.remove(ptr(&mut ns, 1)) });
        // SAFETY: node 0 is linked.
        assert!(unsafe { list.remove(ptr(&mut ns, 0)) });
        // SAFETY: node 0 is now on no list.
        assert!(!unsafe { list.remove(ptr(&mut ns, 0)) });
        assert!(list.is_empty());
        assert_eq!(list.len(), 0);
    }

    // Defect guarded: a list corrupted into a cycle must end a walk after as
    // many steps as the list was long, rather than loop forever.
    #[test]
    fn a_cycle_ends_the_walk()
    {
        let mut ns = nodes(3);
        let mut list = RegistryList::new();
        for i in 0..3
        {
            // SAFETY: as above.
            unsafe { list.push_front(ptr(&mut ns, i)) };
        }
        // Corrupt the tail (node 0) to point back at node 1.
        let back = ptr(&mut ns, 1);
        ns[0].links.next = back;
        let mut c = Cursor::new();
        // SAFETY: as above.
        unsafe { list.attach(&raw mut c) };
        let mut steps = 0;
        loop
        {
            // SAFETY: c is attached.
            match unsafe { RegistryList::<Node>::step(&raw mut c) }
            {
                Step::Node(_) => steps += 1,
                Step::End => panic!("a cyclic list has no end"),
                Step::Cycle => break,
            }
        }
        assert_eq!(steps, 3);
        // SAFETY: c is attached.
        unsafe { list.detach(&raw mut c) };
    }

    // Defect guarded: with links and removals interleaved between the steps
    // of several concurrent walks, as the registry's lock releases between
    // batches allow, each walk must visit exactly the nodes linked for its
    // whole span, each once, plus possibly nodes removed during it but never
    // a node after its removal or one linked after it began, and take no
    // more steps than the list's length at its start.
    #[test]
    fn interleaved_walks_visit_exactly_what_they_owe()
    {
        const NODES: usize = 400;
        const WALKS: usize = 3;
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        let mut ns = nodes(NODES);
        let mut list = RegistryList::new();
        // linked[i]: node i is on the list now.
        let mut linked = vec![false; NODES];
        for (i, l) in linked.iter_mut().enumerate().take(NODES / 2)
        {
            // SAFETY: as above.
            unsafe { list.push_front(ptr(&mut ns, i)) };
            *l = true;
        }
        for _round in 0..20
        {
            let mut cursors: Vec<Box<Cursor<Node>>> =
                (0..WALKS).map(|_| Box::new(Cursor::new())).collect();
            // Per walk: nodes linked at its start, nodes removed during it,
            // nodes visited, steps allowed, and whether it has ended.
            let mut at_start: Vec<Vec<bool>> = Vec::new();
            let mut removed: Vec<Vec<bool>> = Vec::new();
            let mut visited: Vec<Vec<usize>> = Vec::new();
            let mut budget = Vec::new();
            let mut done = [false; WALKS];
            for c in &mut cursors
            {
                // SAFETY: each boxed cursor stays in place until detached.
                unsafe { list.attach(&raw mut **c) };
                at_start.push(linked.clone());
                removed.push(vec![false; NODES]);
                visited.push(vec![0; NODES]);
                budget.push(list.len());
            }
            while done.iter().any(|d| !d)
            {
                match rng.below(4)
                {
                    0 =>
                    {
                        // Link a node on no list.
                        let i = rng.below(NODES);
                        if !linked[i]
                        {
                            // SAFETY: node i is a boxed node on no list.
                            unsafe { list.push_front(ptr(&mut ns, i)) };
                            linked[i] = true;
                        }
                    }
                    1 =>
                    {
                        // Remove a node, linked or not.
                        let i = rng.below(NODES);
                        // SAFETY: node i is a boxed node, on this list or none.
                        let was = unsafe { list.remove(ptr(&mut ns, i)) };
                        assert_eq!(was, linked[i]);
                        if was
                        {
                            linked[i] = false;
                            for r in &mut removed
                            {
                                r[i] = true;
                            }
                        }
                    }
                    _ =>
                    {
                        // Take one walk a batch of steps on.
                        let w = rng.below(WALKS);
                        if done[w]
                        {
                            continue;
                        }
                        for _ in 0..=rng.below(8)
                        {
                            let c: *mut Cursor<Node> = &raw mut *cursors[w];
                            // SAFETY: c is attached.
                            match unsafe { RegistryList::<Node>::step(c) }
                            {
                                Step::Node(n) =>
                                {
                                    // SAFETY: a stepped node is a live boxed node.
                                    let id = unsafe { (*n).id };
                                    assert!(linked[id], "visited a node after its removal");
                                    assert!(
                                        at_start[w][id],
                                        "visited a node linked after the start"
                                    );
                                    visited[w][id] += 1;
                                    assert!(budget[w] > 0, "more steps than the start length");
                                    budget[w] -= 1;
                                }
                                Step::End =>
                                {
                                    // SAFETY: c is attached.
                                    unsafe { list.detach(c) };
                                    done[w] = true;
                                    break;
                                }
                                Step::Cycle => panic!("no cycle was made"),
                            }
                        }
                    }
                }
            }
            check_walks(&visited, &at_start, &removed);
        }
        check_linked(&mut list, &linked);
    }

    /// Each walk visited every node linked for its whole span exactly once,
    /// and no node twice.
    fn check_walks(visited: &[Vec<usize>], at_start: &[Vec<bool>], removed: &[Vec<bool>])
    {
        for (w, seen) in visited.iter().enumerate()
        {
            for (i, &n) in seen.iter().enumerate()
            {
                assert!(n <= 1, "node {i} visited twice by walk {w}");
                if at_start[w][i] && !removed[w][i]
                {
                    assert_eq!(n, 1, "walk {w} missed node {i}");
                }
            }
        }
    }

    /// A fresh walk of `list` finds exactly the nodes `linked` marks.
    fn check_linked(list: &mut RegistryList<Node>, linked: &[bool])
    {
        let mut c = Cursor::new();
        // SAFETY: as above.
        unsafe { list.attach(&raw mut c) };
        let mut left = rest(list, &raw mut c);
        // SAFETY: c is attached.
        unsafe { list.detach(&raw mut c) };
        left.sort_unstable();
        let expect: Vec<usize> = (0..linked.len()).filter(|&i| linked[i]).collect();
        assert_eq!(left, expect);
        assert_eq!(list.len(), expect.len());
    }
}
