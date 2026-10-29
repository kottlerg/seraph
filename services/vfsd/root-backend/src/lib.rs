// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/vfsd/root-backend/src/lib.rs

//! Synthetic system-root [`NamespaceBackend`] composed at boot time.
//!
//! `VfsdRootBackend` is vfsd's in-process namespace server. It owns no
//! storage; every directory entry is either the unbadged namespace
//! endpoint of a peer filesystem driver (a *terminal* mount node) or
//! a synthetic intermediate directory created on demand to host a
//! multi-component mount path (a *synthetic intermediate* node). A
//! client holding a badged SEND on vfsd's namespace endpoint at
//! `NodeId::ROOT` walks into mounts via `NS_LOOKUP`; the protocol crate
//! returns either a freshly-minted, rights-attenuated badged SEND on
//! the underlying driver's namespace endpoint (External entry,
//! terminal node) or a badged SEND on vfsd's own namespace endpoint
//! addressing the intermediate's `NodeId` (Local entry, synthetic
//! intermediate).
//!
//! Each synthetic intermediate may also carry a `fallthrough_cap` —
//! a badged SEND on the root mount's namespace endpoint addressing
//! the directory at the corresponding path in the root filesystem.
//! When a `NS_LOOKUP` against an intermediate misses every local
//! child, vfsd's namespace dispatcher forwards the request verbatim
//! to that fall-through cap, preserving the namespace-model
//! invariant that root-fs entries remain reachable unless explicitly
//! shadowed by a registered mount. `NS_READDIR` is consistent with
//! this: the dispatcher enumerates the node's synthetic children
//! first, then the fall-through directory's entries (skipping any
//! shadowed by a local child), so a listing of a synthetic node shows
//! both its mounts and the underlying root-fs contents.
//!
//! The synthetic root (`NodeId::ROOT`) is itself a tree node whose
//! `fallthrough_cap` is the root mount cap captured when
//! `MOUNT path="/"` succeeds.
//!
//! The tree holds cap slot numbers but makes no syscall, so the crate is
//! pure and host-tested — see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

use namespace_protocol::{
    EntryName, EntryTarget, EntryView, MemoryReply, NamespaceBackend, NamespaceRights, NodeId,
    NodeKind, NodeStat, NsError,
};

/// Maximum tree-pool size — enough for every mount path's components
/// plus their synthetic intermediates. The synthetic root occupies
/// index 0; install allocates the rest linearly.
pub const MAX_TREE_NODES: usize = 32;

/// Maximum length of a single path component captured in the tree.
pub const MAX_ENTRY_NAME: usize = 64;

/// Sentinel marking "no node" in `parent` / `first_child` /
/// `next_sibling` links. `u32::MAX` is unambiguous because tree-pool
/// indices are bounded by `MAX_TREE_NODES`.
const NONE: u32 = u32::MAX;

/// One node in the synthetic-root tree.
///
/// A node is either a *terminal* (a mount point installed by `MOUNT`,
/// `terminal_endpoint != 0`) or a *synthetic intermediate* (created on
/// demand to host a multi-component mount path, `terminal_endpoint == 0`).
/// Both forms may carry a `fallthrough_cap` addressing the
/// corresponding directory in the root filesystem; the synthetic
/// root's `fallthrough_cap` is the root mount cap itself.
#[derive(Copy, Clone)]
struct TreeNode
{
    name: [u8; MAX_ENTRY_NAME],
    name_len: u8,
    parent: u32,
    first_child: u32,
    next_sibling: u32,
    /// Unbadged SEND on the mounted driver's namespace endpoint,
    /// captured at MOUNT time. Non-zero on terminal (mount-point)
    /// nodes, zero on synthetic intermediates. Each `NS_LOOKUP` that
    /// crosses this mount mints a freshly-attenuated badged SEND from
    /// it (see `EntryTarget::External`); the endpoint is held here and
    /// never handed out directly.
    terminal_endpoint: u32,
    /// Badged SEND on the root mount's namespace endpoint addressing
    /// the directory at the path corresponding to this node, used to
    /// forward unmatched `NS_LOOKUP` requests so root-fs entries
    /// remain reachable through synthetic intermediates. Zero when no
    /// such fall-through is available (the path does not exist in the
    /// root filesystem, or the root mount has not been installed yet).
    /// On `NodeId::ROOT` this field carries the root mount cap.
    fallthrough_cap: u32,
    active: bool,
}

impl TreeNode
{
    const fn empty() -> Self
    {
        Self {
            name: [0; MAX_ENTRY_NAME],
            name_len: 0,
            parent: NONE,
            first_child: NONE,
            next_sibling: NONE,
            terminal_endpoint: 0,
            fallthrough_cap: 0,
            active: false,
        }
    }
}

/// In-process synthetic root for vfsd.
///
/// Mutated by service-loop threads when a `MOUNT` request lands; read
/// by the namespace-loop thread on each `NS_*` request. Concurrency
/// is supplied by the caller (`VfsdRuntime` wraps this backend in a
/// `Mutex`).
pub struct VfsdRootBackend
{
    nodes: [TreeNode; MAX_TREE_NODES],
}

/// Outcome of a successful [`VfsdRootBackend::install`] call.
///
/// Carries the indices of any synthetic intermediates created to host
/// the path so the caller can compute and install their
/// `fallthrough_cap` via [`VfsdRootBackend::set_fallthrough_cap`]
/// after walking the root mount component-by-component.
pub struct InstallResult
{
    new_intermediates: [u32; MAX_TREE_NODES],
    new_intermediates_len: usize,
}

impl InstallResult
{
    fn empty() -> Self
    {
        Self {
            new_intermediates: [0; MAX_TREE_NODES],
            new_intermediates_len: 0,
        }
    }

    fn push(&mut self, idx: u32) -> bool
    {
        if self.new_intermediates_len >= MAX_TREE_NODES
        {
            return false;
        }
        self.new_intermediates[self.new_intermediates_len] = idx;
        self.new_intermediates_len += 1;
        true
    }

    /// Pool indices of the synthetic intermediates the install created.
    #[must_use]
    pub fn as_slice(&self) -> &[u32]
    {
        &self.new_intermediates[..self.new_intermediates_len]
    }
}

impl Default for VfsdRootBackend
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl VfsdRootBackend
{
    /// An empty tree: only the synthetic root, with no root mount.
    #[must_use]
    pub const fn new() -> Self
    {
        let mut nodes = [TreeNode::empty(); MAX_TREE_NODES];
        // The synthetic root always exists and has no name. `parent`
        // remains NONE so a stray walk never escapes upward.
        nodes[0].active = true;
        Self { nodes }
    }

    /// Install one mount-point entry.
    ///
    /// Walks `path`'s components, creating synthetic intermediates on
    /// demand, and stores `cap` on the final node's `terminal_endpoint`.
    /// The empty path (`/`) instead stores `cap` as the synthetic
    /// root's `fallthrough_cap` (the root mount).
    ///
    /// `cap`'s kind is the caller's responsibility and differs by role:
    /// a terminal mount passes the peer driver's *unbadged* namespace
    /// endpoint (each crossing `NS_LOOKUP` mints an attenuated badge
    /// from it); the root mount passes a *badged* SEND on the root fs
    /// (the fall-through forwarder pre-composes the caller's rights).
    ///
    /// Returns `Some(InstallResult)` listing newly-created
    /// intermediate indices on success; the caller is expected to
    /// compute and store each intermediate's `fallthrough_cap` via
    /// [`Self::set_fallthrough_cap`].
    ///
    /// Returns `None`, leaving the tree unchanged, on tree exhaustion,
    /// oversize component (`> MAX_ENTRY_NAME`), attempting to mount on
    /// top of an already-terminal node, or re-installing the root mount
    /// (see [`Self::can_install`]).
    pub fn install(&mut self, path: &[u8], cap: u32) -> Option<InstallResult>
    {
        // Validate the whole path, and that the pool has a free node for
        // every component the walk must create, before mutating anything.
        self.plan_install(path)?;

        let mut components = path_components(path).peekable();
        if components.peek().is_none()
        {
            self.nodes[0].fallthrough_cap = cap;
            return Some(InstallResult::empty());
        }

        let mut result = InstallResult::empty();
        let mut current: u32 = 0;
        while let Some(component) = components.next()
        {
            let is_last = components.peek().is_none();
            if let Some(child) = self.find_child(current, component)
            {
                if is_last
                {
                    self.nodes[child as usize].terminal_endpoint = cap;
                }
                current = child;
                continue;
            }
            // `plan_install` counted a free node for this component.
            let new_idx = self.alloc_slot()?;
            let parent_first_child = self.nodes[current as usize].first_child;
            let n = &mut self.nodes[new_idx as usize];
            n.active = true;
            n.parent = current;
            n.name[..component.len()].copy_from_slice(component);
            // cast_possible_truncation: `plan_install` bounded the
            // component to MAX_ENTRY_NAME (64) bytes, which fits a u8.
            #[allow(clippy::cast_possible_truncation)]
            {
                n.name_len = component.len() as u8;
            }
            n.first_child = NONE;
            n.next_sibling = parent_first_child;
            n.terminal_endpoint = if is_last { cap } else { 0 };
            n.fallthrough_cap = 0;
            self.nodes[current as usize].first_child = new_idx;
            // The pool has MAX_TREE_NODES - 1 allocatable nodes, so the
            // MAX_TREE_NODES-entry result list cannot overflow.
            if !is_last && !result.push(new_idx)
            {
                return None;
            }
            current = new_idx;
        }
        Some(result)
    }

    /// Whether [`Self::install`] would accept `path` against the current
    /// tree: the root is not yet mounted (for `/`), no component exceeds
    /// `MAX_ENTRY_NAME`, the final node is not already a mount point,
    /// and the pool has a free node for every component that must be
    /// created. The MOUNT path checks this before it registers a
    /// partition or spawns a driver, so a mount `install` would reject
    /// acquires nothing.
    #[must_use]
    pub fn can_install(&self, path: &[u8]) -> bool
    {
        self.plan_install(path).is_some()
    }

    /// Read-only walk behind [`Self::install`] and [`Self::can_install`]:
    /// the number of tree nodes installing `path` would create, or `None`
    /// when `install` must reject it.
    fn plan_install(&self, path: &[u8]) -> Option<usize>
    {
        let mut components = path_components(path).peekable();
        if components.peek().is_none()
        {
            // Root mount: reject a second one rather than overwrite the
            // cap and leak the running root fs driver.
            return (self.nodes[0].fallthrough_cap == 0).then_some(0);
        }

        // `existing` is the node the walk is at while every component so
        // far names an existing node; once one does not, the rest are new.
        let mut existing = Some(0u32);
        let mut new_nodes = 0usize;
        for component in components
        {
            if component.len() > MAX_ENTRY_NAME
            {
                return None;
            }
            existing = existing.and_then(|idx| self.find_child(idx, component));
            if existing.is_none()
            {
                new_nodes += 1;
            }
        }
        if let Some(last) = existing
            && self.nodes[last as usize].terminal_endpoint != 0
        {
            // Path is already a mount point.
            return None;
        }
        (new_nodes <= self.free_node_count()).then_some(new_nodes)
    }

    /// Set a synthetic intermediate's `fallthrough_cap`. Called by the
    /// MOUNT path after walking the root mount to the corresponding
    /// directory.
    pub fn set_fallthrough_cap(&mut self, node_idx: u32, cap: u32)
    {
        if (node_idx as usize) < MAX_TREE_NODES && self.nodes[node_idx as usize].active
        {
            self.nodes[node_idx as usize].fallthrough_cap = cap;
        }
    }

    /// Reconstruct the absolute path of the node at `idx` into `out`,
    /// returning the number of bytes written. The path begins with
    /// `/` and uses `/` separators. Returns `None` if `out` is too
    /// small or the node is inactive.
    pub fn path_of(&self, idx: u32, out: &mut [u8]) -> Option<usize>
    {
        if (idx as usize) >= MAX_TREE_NODES || !self.nodes[idx as usize].active
        {
            return None;
        }
        if idx == 0
        {
            if out.is_empty()
            {
                return None;
            }
            out[0] = b'/';
            return Some(1);
        }
        // Walk to root collecting indices along the way.
        let mut chain = [0u32; MAX_TREE_NODES];
        let mut depth = 0usize;
        let mut cur = idx;
        while cur != 0
        {
            if depth >= MAX_TREE_NODES
            {
                return None;
            }
            chain[depth] = cur;
            depth += 1;
            cur = self.nodes[cur as usize].parent;
            if cur == NONE
            {
                return None;
            }
        }
        // Emit components in root-first order separated by `/`.
        let mut written = 0usize;
        for i in (0..depth).rev()
        {
            let node = &self.nodes[chain[i] as usize];
            let nlen = node.name_len as usize;
            if written + 1 + nlen > out.len()
            {
                return None;
            }
            out[written] = b'/';
            written += 1;
            out[written..written + nlen].copy_from_slice(&node.name[..nlen]);
            written += nlen;
        }
        Some(written)
    }

    /// Badged SEND on the root mount's namespace endpoint, or `0` if
    /// no root mount has been installed. Consulted by mount-config
    /// parsing and the install-time fall-through walk.
    #[must_use]
    pub fn root_mount_cap(&self) -> u32
    {
        self.nodes[0].fallthrough_cap
    }

    /// Resolve `node` to its tree-pool index, returning `None` if
    /// the `NodeId` is out of range or inactive.
    #[must_use]
    pub fn resolve(&self, node: NodeId) -> Option<u32>
    {
        let raw = node.raw();
        if raw >= MAX_TREE_NODES as u64
        {
            return None;
        }
        // Cast is range-safe: raw < MAX_TREE_NODES (≤ u32::MAX).
        #[allow(clippy::cast_possible_truncation)]
        let idx = raw as u32;
        if !self.nodes[idx as usize].active
        {
            return None;
        }
        Some(idx)
    }

    /// Whether the directory at pool index `idx` has an active child
    /// matching `name`. Used by the namespace dispatcher to decide
    /// whether to fall through to `fallthrough_cap`.
    #[must_use]
    pub fn has_local_child(&self, idx: u32, name: &[u8]) -> bool
    {
        self.find_child(idx, name).is_some()
    }

    /// Fall-through cap stored on the node at pool index `idx`, or `0`.
    #[must_use]
    pub fn fallthrough_of(&self, idx: u32) -> u32
    {
        if (idx as usize) >= MAX_TREE_NODES
        {
            return 0;
        }
        self.nodes[idx as usize].fallthrough_cap
    }

    /// Number of active children of the directory at pool index `idx`.
    /// `NS_READDIR` enumerates these synthetic children first; the
    /// dispatcher's fall-through readdir serves higher indices from the
    /// node's `fallthrough_cap`.
    #[must_use]
    pub fn local_child_count(&self, idx: u32) -> u32
    {
        if (idx as usize) >= MAX_TREE_NODES
        {
            return 0;
        }
        let mut count = 0u32;
        let mut cur = self.nodes[idx as usize].first_child;
        while cur != NONE
        {
            let n = &self.nodes[cur as usize];
            if n.active
            {
                count += 1;
            }
            cur = n.next_sibling;
        }
        count
    }

    /// Number of inactive pool nodes `alloc_slot` can still hand out.
    fn free_node_count(&self) -> usize
    {
        self.nodes.iter().skip(1).filter(|n| !n.active).count()
    }

    fn alloc_slot(&self) -> Option<u32>
    {
        // Skip index 0 — that's the synthetic root.
        for (i, n) in self.nodes.iter().enumerate().skip(1)
        {
            if !n.active
            {
                // cast_possible_truncation: `i < MAX_TREE_NODES` (32), so the
                // index fits a u32.
                #[allow(clippy::cast_possible_truncation)]
                return Some(i as u32);
            }
        }
        None
    }

    fn find_child(&self, parent: u32, name: &[u8]) -> Option<u32>
    {
        if (parent as usize) >= MAX_TREE_NODES
        {
            return None;
        }
        let mut cur = self.nodes[parent as usize].first_child;
        while cur != NONE
        {
            let n = &self.nodes[cur as usize];
            if n.active
                && usize::from(n.name_len) == name.len()
                && n.name[..usize::from(n.name_len)] == *name
            {
                return Some(cur);
            }
            cur = n.next_sibling;
        }
        None
    }
}

/// The non-empty `/`-separated components of a mount path; `/`, the empty
/// path, and all-separator paths such as `///` yield none (the root).
fn path_components(path: &[u8]) -> impl Iterator<Item = &[u8]>
{
    path.split(|&b| b == b'/').filter(|c| !c.is_empty())
}

impl NamespaceBackend for VfsdRootBackend
{
    fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<EntryView, NsError>
    {
        let Some(parent_idx) = self.resolve(dir)
        else
        {
            return Err(NsError::NotADirectory);
        };
        let Some(child_idx) = self.find_child(parent_idx, name)
        else
        {
            return Err(NsError::NotFound);
        };
        let child = &self.nodes[child_idx as usize];
        let target = if child.terminal_endpoint != 0
        {
            // Terminal mount: cross into the peer fs by minting a fresh
            // attenuated badge on its endpoint at its root. vfsd mounts
            // whole filesystems, so the peer node is always the root.
            EntryTarget::External {
                endpoint: child.terminal_endpoint,
                node: NodeId::ROOT,
            }
        }
        else
        {
            EntryTarget::Local(NodeId::from_raw_truncated(u64::from(child_idx)))
        };
        Ok(EntryView {
            target,
            kind: NodeKind::Dir,
            size_hint: 0,
            max_rights: NamespaceRights::ALL,
            visible_requires: NamespaceRights::NONE,
        })
    }

    fn readdir_entry(&mut self, dir: NodeId, idx: u32) -> Result<Option<EntryName>, NsError>
    {
        let Some(parent_idx) = self.resolve(dir)
        else
        {
            return Err(NsError::NotADirectory);
        };
        let mut cur = self.nodes[parent_idx as usize].first_child;
        let mut visible = 0u32;
        while cur != NONE
        {
            let n = &self.nodes[cur as usize];
            if n.active
            {
                if visible == idx
                {
                    // Matches the NONE `lookup` reports: no synthetic
                    // node is hidden.
                    return Ok(EntryName::new(
                        &n.name[..usize::from(n.name_len)],
                        NodeKind::Dir,
                        NamespaceRights::NONE,
                    ));
                }
                visible += 1;
            }
            cur = n.next_sibling;
        }
        Ok(None)
    }

    fn may_hide_entries(&mut self, _dir: NodeId) -> bool
    {
        // No synthetic node is hidden: every entry's `visible_requires` is NONE
        // (see `lookup` and `readdir_entry`), so `NS_READDIR` can index the
        // directory directly.
        false
    }

    fn stat(&mut self, node: NodeId) -> Result<NodeStat, NsError>
    {
        if self.resolve(node).is_none()
        {
            return Err(NsError::NotFound);
        }
        Ok(NodeStat {
            size: 0,
            mtime_us: 0,
            kind: NodeKind::Dir,
        })
    }

    fn read_inline(
        &mut self,
        _file: NodeId,
        _offset: u64,
        _max_len: usize,
        _dst: &mut [u8],
    ) -> Result<usize, NsError>
    {
        Err(NsError::NotSupported)
    }

    fn read_memory(
        &mut self,
        _file: NodeId,
        _offset: u64,
        _cookie: u64,
    ) -> Result<MemoryReply, NsError>
    {
        Err(NsError::NotSupported)
    }

    fn release_memory(&mut self, _file: NodeId, _cookie: u64) {}

    fn close(&mut self, _node: NodeId) {}
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Cap value standing in for a driver endpoint; the tree only stores it.
    const CAP: u32 = 7;

    #[test]
    fn a_second_root_mount_is_rejected_and_keeps_the_first()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/", CAP).is_some());
        assert!(!b.can_install(b"/"));
        assert!(!b.can_install(b"///"));
        assert!(b.install(b"///", CAP + 1).is_none());
        assert_eq!(b.root_mount_cap(), CAP);
    }

    #[test]
    fn mounting_on_an_existing_mount_point_is_rejected()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", CAP).is_some());
        assert!(!b.can_install(b"/esp"));
        assert!(b.install(b"/esp", CAP + 1).is_none());
        assert_eq!(b.local_child_count(0), 1);
    }

    #[test]
    fn a_component_longer_than_the_name_limit_is_rejected()
    {
        let mut b = VfsdRootBackend::new();
        let mut path = vec![b'/'];
        path.extend(core::iter::repeat_n(b'a', MAX_ENTRY_NAME + 1));
        assert!(!b.can_install(&path));
        assert!(b.install(&path, CAP).is_none());
        path.truncate(1 + MAX_ENTRY_NAME);
        assert!(b.can_install(&path));
    }

    #[test]
    fn an_install_the_pool_cannot_hold_leaves_the_tree_unchanged()
    {
        let mut b = VfsdRootBackend::new();
        // Fill all but one of the MAX_TREE_NODES - 1 allocatable nodes.
        for i in 0..MAX_TREE_NODES - 2
        {
            assert!(b.install(format!("/m{i}").as_bytes(), CAP).is_some());
        }
        // `/x/y` needs two nodes; one is free.
        assert!(!b.can_install(b"/x/y"));
        assert!(b.install(b"/x/y", CAP).is_none());
        assert!(!b.has_local_child(0, b"x"));
        assert_eq!(b.local_child_count(0), (MAX_TREE_NODES - 2) as u32);
        assert!(b.install(b"/x", CAP).is_some());
    }

    #[test]
    fn a_multi_component_install_reports_its_new_intermediates()
    {
        let mut b = VfsdRootBackend::new();
        let result = b.install(b"/a/b/c", CAP).expect("install fits");
        let mut paths = Vec::new();
        for &idx in result.as_slice()
        {
            let mut buf = [0u8; 64];
            let len = b.path_of(idx, &mut buf).expect("intermediate has a path");
            paths.push(buf[..len].to_vec());
        }
        paths.sort();
        assert_eq!(paths, vec![b"/a".to_vec(), b"/a/b".to_vec()]);
        // A sibling under the existing intermediate creates only its leaf.
        assert_eq!(
            b.install(b"/a/b/d", CAP).map(|r| r.as_slice().len()),
            Some(0)
        );
    }

    #[test]
    fn an_existing_intermediate_can_become_a_mount_point()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/a/b", CAP).is_some());
        assert!(b.can_install(b"/a"));
        assert!(b.install(b"/a", CAP).is_some());
        assert!(!b.can_install(b"/a"));
    }

    /// Pool index of the intermediate `/a` an install of `/a/b` creates.
    fn intermediate_a(b: &mut VfsdRootBackend) -> u32
    {
        let result = b.install(b"/a/b", CAP).expect("install fits");
        result.as_slice()[0]
    }

    #[test]
    fn lookup_of_a_mount_point_crosses_to_the_peer_root()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", CAP).is_some());
        let view = b.lookup(NodeId::ROOT, b"esp").expect("mount point found");
        assert_eq!(
            view.target,
            EntryTarget::External {
                endpoint: CAP,
                node: NodeId::ROOT,
            }
        );
    }

    #[test]
    fn lookup_of_an_intermediate_stays_on_the_synthetic_root()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        let view = b.lookup(NodeId::ROOT, b"a").expect("intermediate found");
        assert_eq!(
            view.target,
            EntryTarget::Local(NodeId::from_raw_truncated(u64::from(a)))
        );
    }

    #[test]
    fn lookup_of_a_missing_name_is_not_found()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", CAP).is_some());
        assert_eq!(
            b.lookup(NodeId::ROOT, b"data").err(),
            Some(NsError::NotFound)
        );
    }

    #[test]
    fn lookup_in_an_unresolvable_directory_is_not_a_directory()
    {
        let mut b = VfsdRootBackend::new();
        let inactive = NodeId::from_raw_truncated(5);
        assert_eq!(b.lookup(inactive, b"x").err(), Some(NsError::NotADirectory));
    }

    #[test]
    fn readdir_lists_each_child_then_ends()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", CAP).is_some());
        assert!(b.install(b"/data", CAP).is_some());
        let mut names = Vec::new();
        for i in 0..2
        {
            let entry = b.readdir_entry(NodeId::ROOT, i).expect("root resolves");
            names.push(entry.expect("entry present").as_bytes().to_vec());
        }
        names.sort();
        assert_eq!(names, vec![b"data".to_vec(), b"esp".to_vec()]);
        assert_eq!(b.readdir_entry(NodeId::ROOT, 2), Ok(None));
    }

    #[test]
    fn readdir_of_an_unresolvable_directory_is_not_a_directory()
    {
        let mut b = VfsdRootBackend::new();
        let out_of_range = NodeId::from_raw_truncated(MAX_TREE_NODES as u64);
        assert_eq!(
            b.readdir_entry(out_of_range, 0),
            Err(NsError::NotADirectory)
        );
    }

    #[test]
    fn resolve_rejects_out_of_range_and_inactive_nodes()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        assert_eq!(b.resolve(NodeId::from_raw_truncated(u64::from(a))), Some(a));
        assert_eq!(
            b.resolve(NodeId::from_raw_truncated(MAX_TREE_NODES as u64)),
            None
        );
        assert_eq!(b.resolve(NodeId::from_raw_truncated(30)), None);
    }

    #[test]
    fn path_of_rejects_a_short_buffer_and_an_inactive_node()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        assert_eq!(b.path_of(a, &mut [0u8; 1]), None);
        assert_eq!(b.path_of(0, &mut []), None);
        assert_eq!(b.path_of(30, &mut [0u8; 64]), None);
    }

    #[test]
    fn path_of_an_index_past_the_pool_is_none()
    {
        let b = VfsdRootBackend::new();
        assert_eq!(b.path_of(MAX_TREE_NODES as u32, &mut [0u8; 64]), None);
    }

    #[test]
    fn stat_of_an_active_node_is_a_directory()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        let stat = b
            .stat(NodeId::from_raw_truncated(u64::from(a)))
            .expect("active node resolves");
        assert_eq!(stat.kind, NodeKind::Dir);
    }

    #[test]
    fn stat_of_an_unresolvable_node_is_not_found()
    {
        let mut b = VfsdRootBackend::new();
        assert_eq!(
            b.stat(NodeId::from_raw_truncated(5)).err(),
            Some(NsError::NotFound)
        );
    }

    #[test]
    fn local_child_count_past_the_pool_is_zero()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", CAP).is_some());
        assert_eq!(b.local_child_count(MAX_TREE_NODES as u32), 0);
    }

    #[test]
    fn path_of_the_root_is_a_single_slash()
    {
        let b = VfsdRootBackend::new();
        let mut buf = [0u8; 64];
        assert_eq!(b.path_of(0, &mut buf), Some(1));
        assert_eq!(buf[0], b'/');
    }

    #[test]
    fn set_fallthrough_cap_applies_only_to_an_active_node()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        b.set_fallthrough_cap(a, CAP);
        assert_eq!(b.fallthrough_of(a), CAP);
        b.set_fallthrough_cap(30, CAP);
        assert_eq!(b.fallthrough_of(30), 0);
        let past_the_pool = MAX_TREE_NODES as u32;
        b.set_fallthrough_cap(past_the_pool, CAP);
        assert_eq!(b.fallthrough_of(past_the_pool), 0);
    }
}
