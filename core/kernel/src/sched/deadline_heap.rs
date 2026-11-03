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
        // SAFETY: node valid and unlinked (contract).
        unsafe {
            debug_assert!(!(*node).linked, "DeadlineHeap::insert: node already linked");
            (*node).key = key;
            (*node).child = core::ptr::null_mut();
            (*node).next = core::ptr::null_mut();
            (*node).prev = core::ptr::null_mut();
            (*node).linked = true;
            self.root = if self.root.is_null()
            {
                node
            }
            else
            {
                meld(self.root, node)
            };
        }
        self.len += 1;
    }

    /// Unlink `node`.
    ///
    /// # Safety
    /// `node` must be linked in this heap; the caller holds the heap's lock.
    pub unsafe fn remove(&mut self, node: *mut DeadlineNode)
    {
        // SAFETY: node and every node reachable from the root are valid
        // (insert's contract), and the caller serialises the heap.
        unsafe {
            debug_assert!((*node).linked, "DeadlineHeap::remove: node not linked");
            let children = merge_pairs((*node).child);
            if node == self.root
            {
                self.root = children;
            }
            else
            {
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
                if !children.is_null()
                {
                    self.root = meld(self.root, children);
                }
            }
            (*node).child = core::ptr::null_mut();
            (*node).next = core::ptr::null_mut();
            (*node).prev = core::ptr::null_mut();
            (*node).linked = false;
        }
        self.len -= 1;
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
        // SAFETY: every node reachable from the root is valid and linked.
        unsafe {
            while !node.is_null() && seen < limit
            {
                f(node);
                seen += 1;
                if !(*node).child.is_null()
                {
                    node = (*node).child;
                    continue;
                }
                node = next_in_preorder(node);
            }
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
    // SAFETY: as the contract states.
    unsafe {
        loop
        {
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
            let parent = (*leftmost).prev;
            if parent.is_null()
            {
                return core::ptr::null_mut();
            }
            node = parent;
        }
    }
}

/// Meld two detached heap roots (null `prev` and `next`), returning the new
/// root: the larger-keyed root becomes the smaller's leftmost child.
///
/// # Safety
/// `a` and `b` are valid, distinct, detached roots.
unsafe fn meld(a: *mut DeadlineNode, b: *mut DeadlineNode) -> *mut DeadlineNode
{
    // SAFETY: as the contract states.
    unsafe {
        let (top, sub) = if (*b).key < (*a).key { (b, a) } else { (a, b) };
        (*sub).next = (*top).child;
        if !(*top).child.is_null()
        {
            (*(*top).child).prev = sub;
        }
        (*sub).prev = top;
        (*top).child = sub;
        top
    }
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
    // SAFETY: as the contract states; each node is detached before meld.
    unsafe {
        // Pass 1: meld adjacent pairs, stacking the results through `next`
        // (rightmost on top).
        let mut stacked: *mut DeadlineNode = core::ptr::null_mut();
        let mut cur = first;
        while !cur.is_null()
        {
            let a = cur;
            let b = (*a).next;
            (*a).prev = core::ptr::null_mut();
            (*a).next = core::ptr::null_mut();
            let pair = if b.is_null()
            {
                cur = core::ptr::null_mut();
                a
            }
            else
            {
                cur = (*b).next;
                (*b).prev = core::ptr::null_mut();
                (*b).next = core::ptr::null_mut();
                meld(a, b)
            };
            (*pair).next = stacked;
            stacked = pair;
        }
        // Pass 2: meld the stacked pairs right to left.
        let mut root = stacked;
        stacked = (*root).next;
        (*root).next = core::ptr::null_mut();
        while !stacked.is_null()
        {
            let n = stacked;
            stacked = (*n).next;
            (*n).next = core::ptr::null_mut();
            root = meld(root, n);
        }
        root
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A heap over `keys.len()` boxed nodes; returns the nodes so the test
    /// can remove specific ones.
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
