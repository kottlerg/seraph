// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/deadline_heap.rs

//! Intrusive pairing heap of tick deadlines — the sleep list's storage.
//!
//! Every node lives inside the structure it orders (a TCB's `sleep_node`), so
//! the heap holds as many entries as there are threads and allocates nothing.
//! Insertion is O(1); removing the minimum, or any node, costs amortised
//! O(log n). The heap is not synchronised: its owner (the sleep list, under
//! `SLEEP_LIST_LOCK`) serialises every operation and every read of a node's
//! fields (core/kernel/docs/thread-lifecycle-and-sleep.md § Sleep List
//! Invariants).
//!
//! A node's links: `child` is its leftmost child; `next` its right sibling;
//! `prev` its left sibling, or its parent when it is a leftmost child, or null
//! for the root.

/// One heap entry, embedded in the structure it orders.
pub struct DeadlineNode
{
    key: u64,
    child: *mut DeadlineNode,
    next: *mut DeadlineNode,
    prev: *mut DeadlineNode,
    linked: bool,
}

impl DeadlineNode
{
    /// An unlinked node.
    pub const fn new() -> Self
    {
        Self {
            key: 0,
            child: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
            linked: false,
        }
    }

    /// Whether the node is in a heap.
    pub fn is_linked(&self) -> bool
    {
        self.linked
    }

    /// The key the node was inserted with; meaningful while linked.
    pub fn key(&self) -> u64
    {
        self.key
    }
}

/// A min-heap of [`DeadlineNode`]s by key.
pub struct DeadlineHeap
{
    root: *mut DeadlineNode,
    len: usize,
}

// SAFETY: the heap is a root pointer and a count; every access to it and to
// its nodes is serialised by its owner's lock (module docs).
unsafe impl Send for DeadlineHeap {}
// SAFETY: same rationale as `Send`.
unsafe impl Sync for DeadlineHeap {}

impl DeadlineHeap
{
    /// An empty heap.
    pub const fn new() -> Self
    {
        Self {
            root: core::ptr::null_mut(),
            len: 0,
        }
    }

    /// Number of linked nodes.
    pub fn len(&self) -> usize
    {
        self.len
    }

    /// The node with the smallest key, or null when empty.
    pub fn min(&self) -> *mut DeadlineNode
    {
        self.root
    }

    /// Link `node` with `key`.
    ///
    /// # Safety
    /// `node` must be valid, unlinked, and stay valid until removed; the
    /// caller holds the heap's lock.
    pub unsafe fn insert(&mut self, node: *mut DeadlineNode, key: u64)
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a field of `node`, which the caller's contract makes \
                      valid and its heap lock serialises"
        )]
        // SAFETY: node valid and unlinked (contract), and the caller holds the
        // heap's lock.
        unsafe {
            debug_assert!(!(*node).linked, "DeadlineHeap::insert: node already linked");
            (*node).key = key;
            (*node).child = core::ptr::null_mut();
            (*node).next = core::ptr::null_mut();
            (*node).prev = core::ptr::null_mut();
            (*node).linked = true;
        }
        self.root = if self.root.is_null()
        {
            node
        }
        else
        {
            // SAFETY: the root of a non-empty heap is a valid, detached root
            // (null `prev` and `next`); `node` is valid, was unlinked, and its
            // links were just nulled, so it is a detached root distinct from it.
            unsafe { meld(self.root, node) }
        };
        // One per linked node, and every node is a live TCB's: far below
        // saturation.
        self.len = self.len.saturating_add(1);
    }

    /// Unlink `node`.
    ///
    /// # Safety
    /// `node` must be linked in this heap; the caller holds the heap's lock.
    pub unsafe fn remove(&mut self, node: *mut DeadlineNode)
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "both accesses are to fields of `node`, a node linked in this heap, which \
                      the caller's heap lock serialises"
        )]
        // SAFETY: node is linked in this heap (contract), so valid (insert's
        // contract), and the caller serialises the heap.
        let first_child = unsafe {
            debug_assert!((*node).linked, "DeadlineHeap::remove: node not linked");
            (*node).child
        };
        // SAFETY: `first_child` heads `node`'s child list, every node of which
        // is a valid node of this heap (insert's contract) that the caller
        // serialises.
        let children = unsafe { merge_pairs(first_child) };
        if node == self.root
        {
            self.root = children;
        }
        else
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is to a link of a node linked in this heap (`node`, its \
                          parent or left sibling, its right sibling), which the caller's heap \
                          lock serialises"
            )]
            // SAFETY: node, every node reachable from the root, and so its
            // `prev` and `next` are valid (insert's contract), and the caller
            // serialises the heap. A non-root node's `prev` is non-null.
            unsafe {
                let prev = (*node).prev;
                if (*prev).child == node
                {
                    (*prev).child = (*node).next;
                }
                else
                {
                    (*prev).next = (*node).next;
                }
                if !(*node).next.is_null()
                {
                    (*(*node).next).prev = prev;
                }
            }
            if !children.is_null()
            {
                // SAFETY: the root has null `prev` and `next`; `children` is
                // the detached root `merge_pairs` returned, of `node`'s former
                // subtree, which does not hold the root.
                self.root = unsafe { meld(self.root, children) };
            }
        }
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a field of `node`, which the caller's heap lock \
                      serialises"
        )]
        // SAFETY: node is valid (insert's contract), and the caller serialises
        // the heap.
        unsafe {
            (*node).child = core::ptr::null_mut();
            (*node).next = core::ptr::null_mut();
            (*node).prev = core::ptr::null_mut();
            (*node).linked = false;
        }
        // `node` was linked, so the count is at least 1.
        self.len = self.len.saturating_sub(1);
    }

    /// Unlink and return the node with the smallest key, or null when empty.
    ///
    /// # Safety
    /// The caller holds the heap's lock.
    pub unsafe fn pop_min(&mut self) -> *mut DeadlineNode
    {
        let root = self.root;
        if !root.is_null()
        {
            // SAFETY: the root is linked in this heap.
            unsafe { self.remove(root) };
        }
        root
    }

    /// Call `f` on up to `limit` linked nodes, in preorder from the minimum
    /// (so the minimum first). Diagnostic only: it allocates nothing and
    /// bounds its walk by `limit`.
    ///
    /// # Safety
    /// The caller holds the heap's lock, and `f` must not change the heap.
    pub unsafe fn visit(&self, limit: usize, mut f: impl FnMut(*mut DeadlineNode))
    {
        let mut node = self.root;
        let mut seen = 0;
        while !node.is_null() && seen < limit
        {
            f(node);
            seen = seen.saturating_add(1);
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "both reads are of `node`'s child link, a node linked in this heap, \
                          which the caller's heap lock serialises"
            )]
            // SAFETY: every node reachable from the root is valid and linked,
            // and the caller holds the heap's lock.
            unsafe {
                if !(*node).child.is_null()
                {
                    node = (*node).child;
                    continue;
                }
            }
            // SAFETY: `node` is reachable from the root, so it and its
            // ancestors are valid, linked nodes.
            node = unsafe { next_in_preorder(node) };
        }
    }
}

/// The preorder successor of `node` once its subtree is done: its right
/// sibling, else the nearest ancestor's right sibling, else null.
///
/// # Safety
/// `node` and its ancestors are valid, linked nodes.
unsafe fn next_in_preorder(mut node: *mut DeadlineNode) -> *mut DeadlineNode
{
    loop
    {
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access reads a link of `node`, a sibling of it or of an ancestor, or \
                      an ancestor: valid, linked nodes by the contract"
        )]
        // SAFETY: as the contract states: `node`, its siblings, its ancestors
        // and theirs are valid, linked nodes, which the heap's lock serialises.
        let parent = unsafe {
            if !(*node).next.is_null()
            {
                return (*node).next;
            }
            // Walk left to the leftmost sibling; its prev is the parent.
            let mut leftmost = node;
            while !(*leftmost).prev.is_null() && (*(*leftmost).prev).child != leftmost
            {
                leftmost = (*leftmost).prev;
            }
            (*leftmost).prev
        };
        if parent.is_null()
        {
            return core::ptr::null_mut();
        }
        node = parent;
    }
}

/// Meld two detached heap roots (null `prev` and `next`), returning the new
/// root: the larger-keyed root becomes the smaller's leftmost child.
///
/// # Safety
/// `a` and `b` are valid, distinct, detached roots.
unsafe fn meld(a: *mut DeadlineNode, b: *mut DeadlineNode) -> *mut DeadlineNode
{
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every access is to a field of `a`, of `b`, or of the top's first child, valid \
                  nodes of one heap by the contract"
    )]
    // SAFETY: as the contract states; the top's child, when non-null, is a
    // node of the same heap.
    let top = unsafe {
        let (top, sub) = if (*b).key < (*a).key { (b, a) } else { (a, b) };
        (*sub).next = (*top).child;
        if !(*top).child.is_null()
        {
            (*(*top).child).prev = sub;
        }
        (*sub).prev = top;
        (*top).child = sub;
        top
    };
    top
}

/// Meld a sibling list starting at `first` into one detached root (the
/// two-pass pairing merge), or null for an empty list. Pairs are melded left
/// to right, then the pair results right to left; both passes are iterative.
///
/// # Safety
/// Every node of the list is valid and owned by the caller's heap.
unsafe fn merge_pairs(first: *mut DeadlineNode) -> *mut DeadlineNode
{
    if first.is_null()
    {
        return core::ptr::null_mut();
    }
    // Pass 1: meld adjacent pairs, stacking the results through `next`
    // (rightmost on top).
    let mut stacked: *mut DeadlineNode = core::ptr::null_mut();
    let mut cur = first;
    while !cur.is_null()
    {
        let a = cur;
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "every access is to a link of `a`, a node of the caller's list, valid by \
                      the contract"
        )]
        // SAFETY: as the contract states: `a` is a node of the list.
        let b = unsafe {
            let b = (*a).next;
            (*a).prev = core::ptr::null_mut();
            (*a).next = core::ptr::null_mut();
            b
        };
        let pair = if b.is_null()
        {
            cur = core::ptr::null_mut();
            a
        }
        else
        {
            #[expect(
                clippy::multiple_unsafe_ops_per_block,
                reason = "every access is to a link of `b`, a node of the caller's list, valid \
                          by the contract"
            )]
            // SAFETY: as the contract states: `b`, `a`'s right sibling, is a
            // node of the list.
            unsafe {
                cur = (*b).next;
                (*b).prev = core::ptr::null_mut();
                (*b).next = core::ptr::null_mut();
            }
            // SAFETY: `a` and `b` are valid, distinct (`b` is `a`'s right
            // sibling) nodes of the list, each just detached (null `prev` and
            // `next`).
            unsafe { meld(a, b) }
        };
        // SAFETY: `pair` is `a` or the root `meld` returned, a node of the
        // list (contract).
        unsafe { (*pair).next = stacked };
        stacked = pair;
    }
    // Pass 2: meld the stacked pairs right to left.
    let mut root = stacked;
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "both accesses are to the `next` link of `root`, a node of the caller's list, \
                  valid by the contract"
    )]
    // SAFETY: `first` is non-null, so pass 1 stacked at least one pair and
    // `root` is a node of the list (contract).
    unsafe {
        stacked = (*root).next;
        (*root).next = core::ptr::null_mut();
    }
    while !stacked.is_null()
    {
        let n = stacked;
        #[expect(
            clippy::multiple_unsafe_ops_per_block,
            reason = "both accesses are to the `next` link of `n`, a node of the caller's list, \
                      valid by the contract"
        )]
        // SAFETY: `n` is a stacked pair, a node of the list (contract).
        unsafe {
            stacked = (*n).next;
            (*n).next = core::ptr::null_mut();
        }
        // SAFETY: `root` and `n` are valid, distinct pair roots, each
        // detached: pass 1 nulled every pair's `prev`, and its `next` is
        // nulled above.
        root = unsafe { meld(root, n) };
    }
    root
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A heap over `keys.len()` boxed nodes; returns the nodes so the test
    /// can remove specific ones.
    #[expect(
        clippy::vec_box,
        reason = "each node needs its own allocation: the heap links the nodes by raw pointer, and \
                  indexing a flat vector would reborrow every node the heap still points at"
    )]
    fn filled(keys: &[u64]) -> (DeadlineHeap, Vec<Box<DeadlineNode>>)
    {
        let mut heap = DeadlineHeap::new();
        let mut nodes: Vec<Box<DeadlineNode>> =
            keys.iter().map(|_| Box::new(DeadlineNode::new())).collect();
        for (node, &key) in nodes.iter_mut().zip(keys)
        {
            // SAFETY: the boxed node is unlinked and outlives the heap use.
            unsafe { heap.insert(&raw mut **node, key) };
        }
        (heap, nodes)
    }

    fn drain(heap: &mut DeadlineHeap) -> Vec<u64>
    {
        let mut out = Vec::new();
        loop
        {
            // SAFETY: single-threaded test owns the heap.
            let n = unsafe { heap.pop_min() };
            if n.is_null()
            {
                break;
            }
            // SAFETY: n was linked and is still a live boxed node.
            unsafe {
                assert!(!(*n).is_linked());
                out.push((*n).key());
            }
        }
        out
    }

    /// Deterministic scrambled keys with duplicates.
    fn scrambled(n: u64) -> Vec<u64>
    {
        (0..n).map(|i| (i * 7919 + 13) % 97).collect()
    }

    // Defect guarded: a meld or merge that loses or misorders a node would
    // wake a sleeper late, early, or never.
    #[test]
    fn pops_come_out_in_key_order_with_every_node_and_duplicates()
    {
        let keys = scrambled(300);
        let (mut heap, _nodes) = filled(&keys);
        assert_eq!(heap.len(), 300);
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(drain(&mut heap), sorted);
        assert_eq!(heap.len(), 0);
        assert!(heap.min().is_null());
    }

    // Defect guarded: removing a node that is not the root (a leftmost child,
    // an interior sibling, a last sibling, or one with children of its own)
    // must splice its siblings and children back without losing any, as a
    // cancelled sleep does.
    #[test]
    fn removing_arbitrary_nodes_keeps_the_rest_in_order()
    {
        let keys = scrambled(200);
        let (mut heap, mut nodes) = filled(&keys);
        // Force structure: pop once so children are merged into a tree.
        // SAFETY: test owns the heap.
        let first = unsafe { heap.pop_min() };
        assert!(!first.is_null());
        let mut removed = vec![false; nodes.len()];
        for i in (0..nodes.len()).step_by(3)
        {
            let n: *mut DeadlineNode = &raw mut *nodes[i];
            // SAFETY: n is a live boxed node; the test owns the heap.
            unsafe {
                if (*n).is_linked()
                {
                    heap.remove(n);
                    removed[i] = true;
                }
            }
        }
        let mut expect: Vec<u64> = nodes
            .iter()
            .enumerate()
            .filter(|&(i, n)| !removed[i] && n.is_linked())
            .map(|(_, n)| n.key())
            .collect();
        expect.sort_unstable();
        assert_eq!(heap.len(), expect.len());
        assert_eq!(drain(&mut heap), expect);
    }

    // Defect guarded: a node reinserted after removal must behave as new
    // (stale links would corrupt the heap), and the minimum tracks it.
    #[test]
    fn a_removed_node_reinserts_with_a_new_key()
    {
        let (mut heap, mut nodes) = filled(&[50, 40, 30]);
        let n: *mut DeadlineNode = &raw mut *nodes[0];
        // SAFETY: test owns the heap and the node.
        unsafe {
            heap.remove(n);
            heap.insert(n, 5);
            assert_eq!((*heap.min()).key(), 5);
        }
        assert_eq!(drain(&mut heap), [5, 30, 40]);
    }

    // Defect guarded: the diagnostic walk must visit each node once, start
    // at the minimum, and stop at its limit.
    #[test]
    fn visit_sees_every_node_once_from_the_minimum_and_honours_its_limit()
    {
        let keys = scrambled(64);
        let (mut heap, _nodes) = filled(&keys);
        // SAFETY: test owns the heap; reshape it into a deeper tree.
        let popped = unsafe { heap.pop_min() };
        let mut seen = Vec::new();
        // SAFETY: test owns the heap; the closure only reads.
        unsafe { heap.visit(usize::MAX, |n| seen.push((*n).key())) };
        assert_eq!(seen.len(), 63);
        // SAFETY: as above.
        assert_eq!(seen[0], unsafe { (*heap.min()).key() });
        let mut sorted_seen = seen.clone();
        sorted_seen.sort_unstable();
        let mut expect = keys.clone();
        expect.sort_unstable();
        // SAFETY: popped is a live boxed node.
        let popped_key = unsafe { (*popped).key() };
        let pos = expect.iter().position(|&k| k == popped_key).unwrap();
        expect.remove(pos);
        assert_eq!(sorted_seen, expect);
        let mut limited = 0;
        // SAFETY: as above.
        unsafe { heap.visit(5, |_| limited += 1) };
        assert_eq!(limited, 5);
    }
}
