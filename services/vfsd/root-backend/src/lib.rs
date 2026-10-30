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
//! The tree grows on the heap, one node per installed path component
//! that does not yet exist, and nodes are never freed (vfsd has no
//! unmount), so a node's pool index, which is its `NodeId`, is stable
//! for the life of the process. A component follows the namespace
//! protocol's name rule ([`validate_name`], at most
//! [`MAX_NAME_LEN`](namespace_protocol::MAX_NAME_LEN) bytes).
//!
//! The tree holds cap slot numbers but makes no syscall, so the crate is
//! pure and host-tested — see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use namespace_protocol::{
    EntryName, EntryTarget, EntryView, MemoryReply, NamespaceBackend, NamespaceRights, NodeId,
    NodeKind, NodeStat, NsError, validate_name,
};

/// Sentinel marking "no node" in `parent` / `first_child` /
/// `next_sibling` links. `u32::MAX` is unambiguous because
/// [`VfsdRootBackend::install`] refuses to grow the pool to that many
/// nodes.
const NONE: u32 = u32::MAX;

/// One node in the synthetic-root tree.
///
/// A node is either a *terminal* (a mount point installed by `MOUNT`,
/// `terminal_endpoint != 0`) or a *synthetic intermediate* (created on
/// demand to host a multi-component mount path, `terminal_endpoint == 0`).
/// Both forms may carry a `fallthrough_cap` addressing the
/// corresponding directory in the root filesystem; the synthetic
/// root's `fallthrough_cap` is the root mount cap itself.
struct TreeNode
{
    /// Path component captured at install time; empty on the root.
    name: Vec<u8>,
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
}

/// In-process synthetic root for vfsd.
///
/// Mutated by service-loop threads when a `MOUNT` request lands; read
/// by the namespace-loop thread on each `NS_*` request. Concurrency
/// is supplied by the caller (`VfsdRuntime` wraps this backend in a
/// `Mutex`).
pub struct VfsdRootBackend
{
    /// The synthetic root, pool index 0. Held apart from `nodes` so an
    /// empty tree needs no allocation.
    root: TreeNode,
    /// Every other node; pool index `i` (from 1) is `nodes[i - 1]`.
    nodes: Vec<TreeNode>,
}

/// Outcome of a successful [`VfsdRootBackend::install`] call.
///
/// Carries the indices of any synthetic intermediates created to host
/// the path so the caller can compute and install their
/// `fallthrough_cap` via [`VfsdRootBackend::set_fallthrough_cap`]
/// after walking the root mount component-by-component.
pub struct InstallResult
{
    new_intermediates: Vec<u32>,
}

impl InstallResult
{
    /// Pool indices of the synthetic intermediates the install created.
    #[must_use]
    pub fn as_slice(&self) -> &[u32]
    {
        &self.new_intermediates
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
        Self {
            // The synthetic root has no name. `parent` remains NONE so a
            // stray walk never escapes upward.
            root: TreeNode {
                name: Vec::new(),
                parent: NONE,
                first_child: NONE,
                next_sibling: NONE,
                terminal_endpoint: 0,
                fallthrough_cap: 0,
            },
            nodes: Vec::new(),
        }
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
    /// Returns `None`, leaving the tree unchanged, on a component that
    /// fails [`validate_name`], an attempt to mount on top of an
    /// already-terminal node, a re-install of the root mount (see
    /// [`Self::can_install`]), or a failure to allocate the new nodes.
    pub fn install(&mut self, path: &[u8], cap: u32) -> Option<InstallResult>
    {
        // Validate the whole path, and allocate every node and name the
        // walk creates, before mutating anything.
        let new_nodes = self.plan_install(path)?;
        let component_count = path_components(path).count();
        if component_count == 0
        {
            self.root.fallthrough_cap = cap;
            return Some(InstallResult {
                new_intermediates: Vec::new(),
            });
        }

        // The components past the last existing node are the new ones.
        let mut names: Vec<Vec<u8>> = Vec::new();
        names.try_reserve_exact(new_nodes).ok()?;
        for component in path_components(path).skip(component_count - new_nodes)
        {
            let mut name = Vec::new();
            name.try_reserve_exact(component.len()).ok()?;
            name.extend_from_slice(component);
            names.push(name);
        }
        let mut new_intermediates = Vec::new();
        new_intermediates
            .try_reserve_exact(new_nodes.saturating_sub(1))
            .ok()?;
        self.nodes.try_reserve(new_nodes).ok()?;

        // Nothing below allocates: every push lands in reserved capacity.
        let mut names = names.into_iter();
        let mut components = path_components(path).peekable();
        let mut current: u32 = 0;
        while let Some(component) = components.next()
        {
            let is_last = components.peek().is_none();
            if let Some(child) = self.find_child(current, component)
            {
                if is_last && let Some(node) = self.node_mut(child)
                {
                    node.terminal_endpoint = cap;
                }
                current = child;
                continue;
            }
            // `plan_install` counted this component among the new ones,
            // and the loop above prepared its name.
            let name = names.next()?;
            let new_idx = self.next_index()?;
            let parent_first_child = self.node(current)?.first_child;
            self.nodes.push(TreeNode {
                name,
                parent: current,
                first_child: NONE,
                next_sibling: parent_first_child,
                terminal_endpoint: if is_last { cap } else { 0 },
                fallthrough_cap: 0,
            });
            self.node_mut(current)?.first_child = new_idx;
            if !is_last
            {
                new_intermediates.push(new_idx);
            }
            current = new_idx;
        }
        Some(InstallResult { new_intermediates })
    }

    /// Whether [`Self::install`] would accept `path` against the current
    /// tree: the root is not yet mounted (for `/`), every component
    /// passes [`validate_name`], the final node is not already a mount
    /// point, and the pool can index every node the install would
    /// create. The MOUNT path checks this before it registers a
    /// partition or spawns a driver, so a mount `install` would reject
    /// acquires nothing; only an allocation failure in `install` itself
    /// remains to be handled after the spawn.
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
            return (self.root.fallthrough_cap == 0).then_some(0);
        }

        // `existing` is the node the walk is at while every component so
        // far names an existing node; once one does not, the rest are new.
        let mut existing = Some(0u32);
        let mut new_nodes = 0usize;
        for component in components
        {
            validate_name(component).ok()?;
            existing = existing.and_then(|idx| self.find_child(idx, component));
            if existing.is_none()
            {
                new_nodes += 1;
            }
        }
        if let Some(last) = existing
            && self.node(last)?.terminal_endpoint != 0
        {
            // Path is already a mount point.
            return None;
        }
        // Every index, the root's included, stays below `NONE`.
        let total = self.nodes.len().checked_add(1 + new_nodes)?;
        (total <= NONE as usize).then_some(new_nodes)
    }

    /// Set a synthetic intermediate's `fallthrough_cap`. Called by the
    /// MOUNT path after walking the root mount to the corresponding
    /// directory. An index outside the pool is ignored.
    pub fn set_fallthrough_cap(&mut self, node_idx: u32, cap: u32)
    {
        if let Some(node) = self.node_mut(node_idx)
        {
            node.fallthrough_cap = cap;
        }
    }

    /// The absolute path of the node at `idx`: it begins with `/` and
    /// uses `/` separators. Returns `None` if `idx` is outside the pool
    /// or the path cannot be allocated.
    #[must_use]
    pub fn path_of(&self, idx: u32) -> Option<Vec<u8>>
    {
        // Walk to the root collecting indices; each step moves to a
        // lower index, so the walk ends.
        let mut chain = Vec::new();
        let mut len = 0usize;
        let mut cur = idx;
        while cur != 0
        {
            let node = self.node(cur)?;
            chain.try_reserve(1).ok()?;
            chain.push(cur);
            len += 1 + node.name.len();
            cur = node.parent;
        }
        if idx == 0
        {
            len = 1;
        }
        let mut out = Vec::new();
        out.try_reserve_exact(len).ok()?;
        if idx == 0
        {
            out.push(b'/');
        }
        // Emit components in root-first order separated by `/`.
        for &i in chain.iter().rev()
        {
            out.push(b'/');
            out.extend_from_slice(&self.node(i)?.name);
        }
        Some(out)
    }

    /// Badged SEND on the root mount's namespace endpoint, or `0` if
    /// no root mount has been installed. Consulted by mount-config
    /// parsing and the install-time fall-through walk.
    #[must_use]
    pub fn root_mount_cap(&self) -> u32
    {
        self.root.fallthrough_cap
    }

    /// Resolve `node` to its tree-pool index, returning `None` if
    /// the `NodeId` is outside the pool.
    #[must_use]
    pub fn resolve(&self, node: NodeId) -> Option<u32>
    {
        let idx = u32::try_from(node.raw()).ok()?;
        self.node(idx).map(|_| idx)
    }

    /// Whether the directory at pool index `idx` has a child matching
    /// `name`. Used by the namespace dispatcher to decide whether to
    /// fall through to `fallthrough_cap`.
    #[must_use]
    pub fn has_local_child(&self, idx: u32, name: &[u8]) -> bool
    {
        self.find_child(idx, name).is_some()
    }

    /// Fall-through cap stored on the node at pool index `idx`, or `0`.
    #[must_use]
    pub fn fallthrough_of(&self, idx: u32) -> u32
    {
        self.node(idx).map_or(0, |n| n.fallthrough_cap)
    }

    /// Number of children of the directory at pool index `idx`.
    /// `NS_READDIR` enumerates these synthetic children first; the
    /// dispatcher's fall-through readdir serves higher indices from the
    /// node's `fallthrough_cap`.
    #[must_use]
    pub fn local_child_count(&self, idx: u32) -> u32
    {
        let mut count = 0u32;
        let mut cur = self.node(idx).map_or(NONE, |n| n.first_child);
        while let Some(n) = self.node(cur)
        {
            count += 1;
            cur = n.next_sibling;
        }
        count
    }

    /// The node at pool index `idx`, or `None` outside the pool (`NONE`
    /// included).
    fn node(&self, idx: u32) -> Option<&TreeNode>
    {
        match idx
        {
            0 => Some(&self.root),
            i => self.nodes.get(i as usize - 1),
        }
    }

    fn node_mut(&mut self, idx: u32) -> Option<&mut TreeNode>
    {
        match idx
        {
            0 => Some(&mut self.root),
            i => self.nodes.get_mut(i as usize - 1),
        }
    }

    /// Pool index the next pushed node takes; `plan_install` bounded the
    /// pool below `NONE`.
    fn next_index(&self) -> Option<u32>
    {
        u32::try_from(self.nodes.len() + 1).ok()
    }

    fn find_child(&self, parent: u32, name: &[u8]) -> Option<u32>
    {
        let mut cur = self.node(parent)?.first_child;
        while let Some(n) = self.node(cur)
        {
            if n.name == name
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
        let Some(child) = self.node(child_idx)
        else
        {
            return Err(NsError::NotFound);
        };
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
        let mut cur = self.node(parent_idx).map_or(NONE, |n| n.first_child);
        let mut visible = 0u32;
        while let Some(n) = self.node(cur)
        {
            if visible == idx
            {
                // Matches the NONE `lookup` reports: no synthetic node is
                // hidden. `install` held the name to `MAX_NAME_LEN`.
                return Ok(EntryName::new(
                    &n.name,
                    NodeKind::Dir,
                    NamespaceRights::NONE,
                ));
            }
            visible += 1;
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
    use namespace_protocol::MAX_NAME_LEN;

    use super::*;

    /// Cap value standing in for a driver endpoint; the tree only stores it.
    const CAP: u32 = 7;

    /// A pool index no install below creates.
    const UNUSED_IDX: u32 = 30;

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
    fn a_component_is_bounded_by_the_protocol_name_limit()
    {
        let mut b = VfsdRootBackend::new();
        let mut path = vec![b'/'];
        path.extend(core::iter::repeat_n(b'a', MAX_NAME_LEN + 1));
        assert!(!b.can_install(&path));
        assert!(b.install(&path, CAP).is_none());
        assert_eq!(b.local_child_count(0), 0);
        path.truncate(1 + MAX_NAME_LEN);
        assert!(b.install(&path, CAP).is_some());
        let entry = b
            .readdir_entry(NodeId::ROOT, 0)
            .expect("root resolves")
            .expect("entry present");
        assert_eq!(entry.as_bytes(), &path[1..]);
    }

    #[test]
    fn a_component_the_protocol_cannot_name_is_rejected()
    {
        let mut b = VfsdRootBackend::new();
        assert!(!b.can_install(b"/a/../b"));
        assert!(b.install(b"/a/./b", CAP).is_none());
        assert!(b.install(b"/a\0", CAP).is_none());
        assert_eq!(b.local_child_count(0), 0);
    }

    #[test]
    fn the_tree_grows_past_the_former_fixed_pool()
    {
        let mut b = VfsdRootBackend::new();
        for i in 0..200
        {
            assert!(b.install(format!("/m{i}/leaf").as_bytes(), CAP).is_some());
        }
        assert_eq!(b.local_child_count(0), 200);
        let view = b.lookup(NodeId::ROOT, b"m199").expect("last mount found");
        let EntryTarget::Local(m199) = view.target
        else
        {
            panic!("an intermediate is local");
        };
        assert!(b.lookup(m199, b"leaf").is_ok());
    }

    #[test]
    fn a_multi_component_install_reports_its_new_intermediates()
    {
        let mut b = VfsdRootBackend::new();
        let result = b.install(b"/a/b/c", CAP).expect("install fits");
        let mut paths: Vec<Vec<u8>> = result
            .as_slice()
            .iter()
            .map(|&idx| b.path_of(idx).expect("intermediate has a path"))
            .collect();
        paths.sort();
        assert_eq!(paths, vec![b"/a".to_vec(), b"/a/b".to_vec()]);
        // A sibling under the existing intermediate creates only its leaf.
        assert_eq!(
            b.install(b"/a/b/d", CAP).map(|r| r.as_slice().len()),
            Some(0)
        );
    }

    #[test]
    fn path_of_a_deep_intermediate_is_not_cut_short()
    {
        // Eight 255-byte components: a path well past the 256-byte buffer
        // the fall-through walk once used.
        let component = "c".repeat(MAX_NAME_LEN);
        let mut path = String::new();
        for _ in 0..8
        {
            path.push('/');
            path.push_str(&component);
        }
        let mut b = VfsdRootBackend::new();
        let result = b.install(path.as_bytes(), CAP).expect("install fits");
        let deepest = *result.as_slice().last().expect("seven intermediates");
        let expected = &path.as_bytes()[..7 * (1 + MAX_NAME_LEN)];
        assert_eq!(b.path_of(deepest).as_deref(), Some(expected));
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
        let unused = NodeId::from_raw_truncated(u64::from(UNUSED_IDX));
        assert_eq!(b.lookup(unused, b"x").err(), Some(NsError::NotADirectory));
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
        let unused = NodeId::from_raw_truncated(u64::from(UNUSED_IDX));
        assert_eq!(b.readdir_entry(unused, 0), Err(NsError::NotADirectory));
    }

    #[test]
    fn resolve_accepts_only_indices_inside_the_pool()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        assert_eq!(b.resolve(NodeId::from_raw_truncated(u64::from(a))), Some(a));
        // `/a/b` created two nodes, indices 1 and 2.
        assert_eq!(b.resolve(NodeId::from_raw_truncated(3)), None);
        assert_eq!(b.resolve(NodeId::from_raw_truncated(u64::from(NONE))), None);
        assert_eq!(
            b.resolve(NodeId::from_raw_truncated(u64::from(NONE) + 1)),
            None
        );
    }

    #[test]
    fn path_of_an_index_outside_the_pool_is_none()
    {
        let mut b = VfsdRootBackend::new();
        let _ = intermediate_a(&mut b);
        assert_eq!(b.path_of(UNUSED_IDX), None);
        assert_eq!(b.path_of(NONE), None);
    }

    #[test]
    fn stat_of_an_installed_node_is_a_directory()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        let stat = b
            .stat(NodeId::from_raw_truncated(u64::from(a)))
            .expect("installed node resolves");
        assert_eq!(stat.kind, NodeKind::Dir);
    }

    #[test]
    fn stat_of_an_unresolvable_node_is_not_found()
    {
        let mut b = VfsdRootBackend::new();
        assert_eq!(
            b.stat(NodeId::from_raw_truncated(u64::from(UNUSED_IDX)))
                .err(),
            Some(NsError::NotFound)
        );
    }

    #[test]
    fn local_child_count_outside_the_pool_is_zero()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", CAP).is_some());
        assert_eq!(b.local_child_count(UNUSED_IDX), 0);
    }

    #[test]
    fn path_of_the_root_is_a_single_slash()
    {
        let b = VfsdRootBackend::new();
        assert_eq!(b.path_of(0).as_deref(), Some(&b"/"[..]));
    }

    #[test]
    fn set_fallthrough_cap_applies_only_inside_the_pool()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        b.set_fallthrough_cap(a, CAP);
        assert_eq!(b.fallthrough_of(a), CAP);
        b.set_fallthrough_cap(UNUSED_IDX, CAP);
        assert_eq!(b.fallthrough_of(UNUSED_IDX), 0);
    }
}
