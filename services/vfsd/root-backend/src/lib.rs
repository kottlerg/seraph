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
//! Every mount, the root mount included, keeps its [`Mount`] record on
//! the node it is mounted on, with its state. A mount below `/` is
//! removed in two steps: [`VfsdRootBackend::begin_unmount`] stops every
//! lookup from crossing it, and [`VfsdRootBackend::remove_mount`] clears
//! its record once its driver is torn down. A node no mount holds and
//! below which nothing is mounted is *vacant*: lookups, listings, and
//! shadowing skip it, so its name falls through to the root filesystem
//! as an absent one does. The root mount is never removed.
//!
//! The tree grows on the heap, one node per installed path component
//! that does not yet exist, and nodes are never freed: a removed mount
//! leaves its node vacant, and a later install reuses it, so a node's
//! pool index, which is its `NodeId`, is stable for the life of the
//! process. A component follows the namespace protocol's name rule
//! ([`validate_name`], at most
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

/// The record of one mount: what vfsd holds to reach its driver and to
/// tear it down. The tree stores the record and makes no syscall on it;
/// the meaning of each slot is vfsd's
/// (`services/vfsd/docs/namespace-composition.md` § Mount record).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mount
{
    /// The cap the tree resolves the mount through. Below `/`, the
    /// *unbadged* SEND on the driver's namespace endpoint: each
    /// `NS_LOOKUP` that crosses the mount mints a freshly-attenuated
    /// badged SEND from it (see `EntryTarget::External`), and it is never
    /// handed out directly. For `/`, the *badged* SEND on the root fs that
    /// unmatched lookups on the synthetic root forward to.
    pub cap: u64,
    /// The driver's service endpoint as vfsd created it, from which every
    /// cap on that endpoint derives.
    pub endpoint: u64,
    /// procmgr's process handle for the driver.
    pub process: u64,
    /// `RECV` on the event queue the driver's deaths post to.
    pub death_queue: u64,
    /// The `REGISTER_PARTITION` reply cap, from which the driver's
    /// partition cap derives.
    pub partition: u64,
    /// The index, in vfsd's disk list, of the disk that holds the
    /// mounted partition.
    pub disk: usize,
}

/// Why [`VfsdRootBackend::begin_unmount`] refused a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmountError
{
    /// The node is the synthetic root: the root mount is never removed.
    Root,
    /// No mount is on the node, or the index is outside the pool.
    NotMounted,
    /// The mount's removal has already begun.
    InProgress,
}

/// What a node holds besides its links.
#[derive(Clone, Copy)]
enum Slot
{
    /// No mount: a synthetic intermediate, or a vacant node.
    Empty,
    /// A mount that lookups cross.
    Mounted(Mount),
    /// A mount whose removal has begun: no lookup crosses it, and no
    /// install may take the node until [`VfsdRootBackend::remove_mount`].
    Unmounting(Mount),
}

/// One node in the synthetic-root tree.
///
/// A node holding a mounted [`Slot`] is a *terminal* (a mount point); a
/// node with no mount but a mount somewhere below it is a *synthetic
/// intermediate*, which hosts a multi-component mount path; any other
/// node is vacant. Every node may carry a `fallthrough_cap` addressing
/// the corresponding directory in the root filesystem; the synthetic
/// root's `fallthrough_cap` is the root mount cap itself.
struct TreeNode
{
    /// Path component captured at install time; empty on the root.
    name: Vec<u8>,
    parent: u32,
    first_child: u32,
    next_sibling: u32,
    /// The mount on this node, if any, with its state.
    slot: Slot,
    /// Mounts in [`Slot::Mounted`] state in this node's subtree, the node
    /// itself included. A node other than the root is visible (lookups,
    /// listings, and shadowing see it) exactly when this is non-zero.
    live: u32,
    /// Badged SEND on the root mount's namespace endpoint addressing
    /// the directory at the path corresponding to this node, used to
    /// forward unmatched `NS_LOOKUP` requests so root-fs entries
    /// remain reachable through synthetic intermediates. Zero when no
    /// such fall-through is available (the path does not exist in the
    /// root filesystem, or the root mount has not been installed yet).
    /// On `NodeId::ROOT` this field carries the root mount cap.
    fallthrough_cap: u64,
}

impl TreeNode
{
    /// The mount lookups cross on this node, if one is mounted.
    fn mounted(&self) -> Option<&Mount>
    {
        match &self.slot
        {
            Slot::Mounted(mount) => Some(mount),
            Slot::Empty | Slot::Unmounting(_) => None,
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
    /// The synthetic root, pool index 0. Held apart from `nodes` so an
    /// empty tree needs no allocation.
    root: TreeNode,
    /// Every other node; pool index `i` (from 1) is `nodes[i - 1]`.
    nodes: Vec<TreeNode>,
}

/// Outcome of a successful [`VfsdRootBackend::install`] call.
///
/// Carries the indices of the synthetic intermediates on the installed
/// path that need a `fallthrough_cap` ([`VfsdRootBackend::needs_fallthrough`]:
/// the ones the install created, and any that has none) so the caller
/// can compute and install it via [`VfsdRootBackend::set_fallthrough_cap`]
/// after walking the root mount component-by-component.
pub struct InstallResult
{
    new_intermediates: Vec<u32>,
}

impl InstallResult
{
    /// Pool indices of the intermediates on the path that need a
    /// fall-through cap, root first.
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
                slot: Slot::Empty,
                live: 0,
                fallthrough_cap: 0,
            },
            nodes: Vec::new(),
        }
    }

    /// Install one mount.
    ///
    /// Walks `path`'s components, creating synthetic intermediates on
    /// demand, and stores `mount` on the final node, which lookups then
    /// cross through `mount.cap`. The empty path (`/`) instead stores
    /// `mount` on the synthetic root and `mount.cap` as its
    /// `fallthrough_cap` (the root mount).
    ///
    /// `mount.cap`'s kind is the caller's responsibility and differs by
    /// role: a terminal mount passes the peer driver's *unbadged*
    /// namespace endpoint (each crossing `NS_LOOKUP` mints an attenuated
    /// badge from it); the root mount passes a *badged* SEND on the root
    /// fs (the fall-through forwarder pre-composes the caller's rights).
    ///
    /// Returns `Some(InstallResult)` listing the path's intermediates
    /// that need a fall-through cap; the caller is expected to compute
    /// and store each one's `fallthrough_cap` via
    /// [`Self::set_fallthrough_cap`].
    ///
    /// Returns `None`, leaving the tree unchanged, on a component that
    /// fails [`validate_name`], an attempt to mount on a node that holds
    /// a mount (one being removed included), a re-install of the root
    /// mount (see [`Self::can_install`]), or a failure to allocate the
    /// new nodes.
    pub fn install(&mut self, path: &[u8], mount: Mount) -> Option<InstallResult>
    {
        // Validate the whole path, and allocate every node and name the
        // walk creates, before mutating anything.
        let new_nodes = self.plan_install(path)?;
        let component_count = path_components(path).count();
        if component_count == 0
        {
            self.root.fallthrough_cap = mount.cap;
            self.root.slot = Slot::Mounted(mount);
            self.root.live = self.root.live.saturating_add(1);
            return Some(InstallResult {
                new_intermediates: Vec::new(),
            });
        }

        // The components past the last existing node are the new ones.
        let mut names: Vec<Vec<u8>> = Vec::new();
        names.try_reserve_exact(new_nodes).ok()?;
        for component in path_components(path).skip(component_count.saturating_sub(new_nodes))
        {
            let mut name = Vec::new();
            name.try_reserve_exact(component.len()).ok()?;
            name.extend_from_slice(component);
            names.push(name);
        }
        let mut new_intermediates = Vec::new();
        new_intermediates
            .try_reserve_exact(component_count.saturating_sub(1))
            .ok()?;
        self.nodes.try_reserve(new_nodes).ok()?;

        // Nothing below allocates: every push lands in reserved capacity.
        let mut names = names.into_iter();
        let mut components = path_components(path).peekable();
        let mut current: u32 = 0;
        while let Some(component) = components.next()
        {
            let is_last = components.peek().is_none();
            let next = if let Some(child) = self.find_child(current, component)
            {
                child
            }
            else
            {
                // `plan_install` counted this component among the new
                // ones, and the loop above prepared its name.
                let name = names.next()?;
                let new_idx = self.next_index()?;
                let parent_first_child = self.node(current)?.first_child;
                self.nodes.push(TreeNode {
                    name,
                    parent: current,
                    first_child: NONE,
                    next_sibling: parent_first_child,
                    slot: Slot::Empty,
                    live: 0,
                    fallthrough_cap: 0,
                });
                self.node_mut(current)?.first_child = new_idx;
                new_idx
            };
            if is_last
            {
                self.node_mut(next)?.slot = Slot::Mounted(mount);
            }
            else
            {
                new_intermediates.push(next);
            }
            current = next;
        }
        self.adjust_live(current, u32::saturating_add);
        // `retain` keeps the reserved capacity and does not allocate.
        new_intermediates.retain(|&idx| self.needs_fallthrough(idx));
        Some(InstallResult { new_intermediates })
    }

    /// Whether the node at `idx` is a synthetic intermediate without a
    /// fall-through cap: a node other than the root, holding no mount
    /// lookups cross, with a mount below it, and no `fallthrough_cap`.
    /// An install lists such nodes on its path; a node whose own mount
    /// [`Self::begin_unmount`] stopped while a mount below it stays
    /// becomes one when it had no fall-through cap before.
    #[must_use]
    pub fn needs_fallthrough(&self, idx: u32) -> bool
    {
        idx != 0
            && self
                .node(idx)
                .is_some_and(|n| n.live != 0 && n.mounted().is_none() && n.fallthrough_cap == 0)
    }

    /// The pool index of the existing node `path` names (`0` for `/`),
    /// vacant nodes included, or `None` when a component names no node.
    #[must_use]
    pub fn find(&self, path: &[u8]) -> Option<u32>
    {
        path_components(path).try_fold(0u32, |idx, component| self.find_child(idx, component))
    }

    /// Begin removing the mount on the node at `idx`: from now on no
    /// lookup crosses it, its name falls through to the root filesystem
    /// unless a mount below it keeps the node visible as an intermediate,
    /// and no install may take the node until [`Self::remove_mount`].
    /// Returns the mount's record.
    ///
    /// # Errors
    ///
    /// [`UnmountError::Root`] for the synthetic root,
    /// [`UnmountError::NotMounted`] for a node holding no mount or an
    /// index outside the pool, and [`UnmountError::InProgress`] when the
    /// mount's removal has already begun. A refusal changes nothing.
    pub fn begin_unmount(&mut self, idx: u32) -> Result<Mount, UnmountError>
    {
        if idx == 0
        {
            return Err(UnmountError::Root);
        }
        let node = self.node_mut(idx).ok_or(UnmountError::NotMounted)?;
        let mount = match node.slot
        {
            Slot::Mounted(mount) => mount,
            Slot::Unmounting(_) => return Err(UnmountError::InProgress),
            Slot::Empty => return Err(UnmountError::NotMounted),
        };
        node.slot = Slot::Unmounting(mount);
        self.adjust_live(idx, u32::saturating_sub);
        Ok(mount)
    }

    /// Finish removing the mount whose removal [`Self::begin_unmount`]
    /// began on the node at `idx`: clear its record, which is returned,
    /// and leave the node in the tree with its index, for a later install
    /// to reuse. `None`, changing nothing, when no removal has begun on
    /// the node.
    pub fn remove_mount(&mut self, idx: u32) -> Option<Mount>
    {
        let node = self.node_mut(idx)?;
        let Slot::Unmounting(mount) = node.slot
        else
        {
            return None;
        };
        node.slot = Slot::Empty;
        Some(mount)
    }

    /// Apply `step` to the live-mount count of the node at `idx` and of
    /// each of its ancestors, the root included, as a mount on that node
    /// starts or stops being crossed.
    fn adjust_live(&mut self, idx: u32, step: fn(u32, u32) -> u32)
    {
        let mut cur = idx;
        while let Some(node) = self.node_mut(cur)
        {
            node.live = step(node.live, 1);
            cur = node.parent;
        }
    }

    /// Whether [`Self::install`] would accept `path` against the current
    /// tree: the root is not yet mounted (for `/`), every component
    /// passes [`validate_name`], the final node holds no mount (one being
    /// removed included), and the pool can index every node the install
    /// would create. The MOUNT path checks this before it registers a
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
            return matches!(self.root.slot, Slot::Empty).then_some(0);
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
                // `new_nodes` counts components, so it is below `usize::MAX`.
                new_nodes = new_nodes.saturating_add(1);
            }
        }
        if let Some(last) = existing
            && !matches!(self.node(last)?.slot, Slot::Empty)
        {
            // Path is already a mount point, or one being removed.
            return None;
        }
        // Every index, the root's included, stays below `NONE`.
        let total = self.nodes.len().checked_add(new_nodes.saturating_add(1))?;
        (total <= NONE as usize).then_some(new_nodes)
    }

    /// Set a synthetic intermediate's `fallthrough_cap`. Called by the
    /// MOUNT path after walking the root mount to the corresponding
    /// directory. An index outside the pool is ignored.
    pub fn set_fallthrough_cap(&mut self, node_idx: u32, cap: u64)
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
            len = len.saturating_add(node.name.len().saturating_add(1));
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
    pub fn root_mount_cap(&self) -> u64
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

    /// Whether the directory at pool index `idx` has a visible child
    /// matching `name`, one that is a mount point or has a mount below it.
    /// Used by the namespace dispatcher to decide whether to fall through
    /// to `fallthrough_cap`; a vacant child's name falls through.
    #[must_use]
    pub fn has_local_child(&self, idx: u32, name: &[u8]) -> bool
    {
        self.find_visible_child(idx, name).is_some()
    }

    /// Fall-through cap stored on the node at pool index `idx`, or `0`.
    #[must_use]
    pub fn fallthrough_of(&self, idx: u32) -> u64
    {
        self.node(idx).map_or(0, |n| n.fallthrough_cap)
    }

    /// Number of visible children of the directory at pool index `idx`
    /// (vacant ones are not counted). `NS_READDIR` enumerates these
    /// synthetic children first; the dispatcher's fall-through readdir
    /// serves higher indices from the node's `fallthrough_cap`.
    #[must_use]
    pub fn local_child_count(&self, idx: u32) -> u32
    {
        let mut count = 0u32;
        let mut cur = self.node(idx).map_or(NONE, |n| n.first_child);
        while let Some(n) = self.node(cur)
        {
            if n.live != 0
            {
                count = count.saturating_add(1);
            }
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
            i => (i as usize).checked_sub(1).and_then(|k| self.nodes.get(k)),
        }
    }

    fn node_mut(&mut self, idx: u32) -> Option<&mut TreeNode>
    {
        match idx
        {
            0 => Some(&mut self.root),
            i => (i as usize)
                .checked_sub(1)
                .and_then(|k| self.nodes.get_mut(k)),
        }
    }

    /// Pool index the next pushed node takes; `plan_install` bounded the
    /// pool below `NONE`.
    fn next_index(&self) -> Option<u32>
    {
        u32::try_from(self.nodes.len().saturating_add(1)).ok()
    }

    /// The child of `parent` named `name`, vacant or not.
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

    /// The child of `parent` named `name` when it is visible: a mount
    /// point, or a node with a mount below it.
    fn find_visible_child(&self, parent: u32, name: &[u8]) -> Option<u32>
    {
        self.find_child(parent, name)
            .filter(|&idx| self.node(idx).is_some_and(|n| n.live != 0))
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
        let Some(child_idx) = self.find_visible_child(parent_idx, name)
        else
        {
            return Err(NsError::NotFound);
        };
        let Some(child) = self.node(child_idx)
        else
        {
            return Err(NsError::NotFound);
        };
        let target = if let Some(mount) = child.mounted()
        {
            // Terminal mount: cross into the peer fs by minting a fresh
            // attenuated badge on its endpoint at its root. vfsd mounts
            // whole filesystems, so the peer node is always the root.
            EntryTarget::External {
                endpoint: mount.cap,
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
            if n.live == 0
            {
                // Vacant: its name, if the fall-through directory holds
                // it, is listed from there.
                cur = n.next_sibling;
                continue;
            }
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
            visible = visible.saturating_add(1);
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
    const CAP: u64 = 7;

    /// A pool index no install below creates.
    const UNUSED_IDX: u32 = 30;

    /// A mount record resolved through `cap`, its other slots distinct
    /// values derived from it, so a test can tell two records apart.
    fn mount(cap: u64) -> Mount
    {
        Mount {
            cap,
            endpoint: cap + 100,
            process: cap + 200,
            death_queue: cap + 300,
            partition: cap + 400,
            disk: 1,
        }
    }

    /// Install `path` at `cap` and begin its unmount, returning its node.
    fn unmounting(b: &mut VfsdRootBackend, path: &[u8], cap: u64) -> u32
    {
        assert!(b.install(path, mount(cap)).is_some());
        let idx = b.find(path).expect("installed path has a node");
        assert_eq!(b.begin_unmount(idx), Ok(mount(cap)));
        idx
    }

    #[test]
    fn unmount_returns_the_record_install_stored()
    {
        let mut b = VfsdRootBackend::new();
        let idx = unmounting(&mut b, b"/esp", CAP);
        assert_eq!(b.remove_mount(idx), Some(mount(CAP)));
    }

    #[test]
    fn the_root_mount_cannot_be_unmounted()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/", mount(CAP)).is_some());
        assert_eq!(b.find(b"/"), Some(0));
        assert_eq!(b.begin_unmount(0), Err(UnmountError::Root));
        assert_eq!(b.root_mount_cap(), CAP);
        assert_eq!(b.fallthrough_of(0), CAP);
    }

    #[test]
    fn unmount_of_a_node_without_a_mount_is_refused()
    {
        let mut b = VfsdRootBackend::new();
        let a = intermediate_a(&mut b);
        assert_eq!(b.begin_unmount(a), Err(UnmountError::NotMounted));
        assert_eq!(b.begin_unmount(UNUSED_IDX), Err(UnmountError::NotMounted));
        assert_eq!(b.begin_unmount(NONE), Err(UnmountError::NotMounted));
        // The refusal left the intermediate visible.
        assert!(b.has_local_child(0, b"a"));
    }

    #[test]
    fn a_second_unmount_of_one_mount_is_refused()
    {
        let mut b = VfsdRootBackend::new();
        let idx = unmounting(&mut b, b"/esp", CAP);
        assert_eq!(b.begin_unmount(idx), Err(UnmountError::InProgress));
        // The refusal did not count the mount out twice: a sibling stays
        // visible.
        assert!(b.install(b"/data", mount(CAP)).is_some());
        assert_eq!(b.local_child_count(0), 1);
    }

    #[test]
    fn an_unmounting_mount_point_is_not_crossed_and_its_name_falls_through()
    {
        let mut b = VfsdRootBackend::new();
        let _ = unmounting(&mut b, b"/esp", CAP);
        assert_eq!(
            b.lookup(NodeId::ROOT, b"esp").err(),
            Some(NsError::NotFound)
        );
        assert!(!b.has_local_child(0, b"esp"));
        assert_eq!(b.local_child_count(0), 0);
        assert_eq!(b.readdir_entry(NodeId::ROOT, 0), Ok(None));
    }

    #[test]
    fn a_mount_point_is_not_installable_until_its_removal_finishes()
    {
        let mut b = VfsdRootBackend::new();
        let idx = unmounting(&mut b, b"/esp", CAP);
        assert!(!b.can_install(b"/esp"));
        assert!(b.install(b"/esp", mount(CAP + 1)).is_none());
        assert!(b.remove_mount(idx).is_some());
        assert!(b.can_install(b"/esp"));
    }

    #[test]
    fn remove_mount_finishes_only_a_begun_unmount()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", mount(CAP)).is_some());
        let idx = b.find(b"/esp").expect("installed");
        assert_eq!(b.remove_mount(idx), None);
        assert_eq!(b.remove_mount(UNUSED_IDX), None);
        b.lookup(NodeId::ROOT, b"esp").unwrap();
        let idx = unmounting(&mut b, b"/data", CAP);
        assert!(b.remove_mount(idx).is_some());
        assert_eq!(b.remove_mount(idx), None);
    }

    #[test]
    fn a_remount_reuses_the_node_and_crosses_to_the_new_driver()
    {
        let mut b = VfsdRootBackend::new();
        let idx = unmounting(&mut b, b"/esp", CAP);
        assert!(b.remove_mount(idx).is_some());
        assert!(b.install(b"/esp", mount(CAP + 1)).is_some());
        assert_eq!(b.find(b"/esp"), Some(idx));
        let view = b.lookup(NodeId::ROOT, b"esp").expect("remounted");
        assert_eq!(
            view.target,
            EntryTarget::External {
                endpoint: CAP + 1,
                node: NodeId::ROOT,
            }
        );
    }

    #[test]
    fn an_intermediate_with_no_mount_below_is_vacant()
    {
        let mut b = VfsdRootBackend::new();
        let idx = unmounting(&mut b, b"/a/b", CAP);
        assert!(b.remove_mount(idx).is_some());
        assert_eq!(b.lookup(NodeId::ROOT, b"a").err(), Some(NsError::NotFound));
        assert_eq!(b.local_child_count(0), 0);
        assert_eq!(b.readdir_entry(NodeId::ROOT, 0), Ok(None));
    }

    #[test]
    fn readdir_skips_a_vacant_child_between_visible_ones()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/x", mount(CAP)).is_some());
        let _ = unmounting(&mut b, b"/y", CAP);
        assert!(b.install(b"/z", mount(CAP)).is_some());
        let mut names = Vec::new();
        for i in 0..2
        {
            let entry = b.readdir_entry(NodeId::ROOT, i).expect("root resolves");
            names.push(entry.expect("entry present").as_bytes().to_vec());
        }
        names.sort();
        assert_eq!(names, vec![b"x".to_vec(), b"z".to_vec()]);
        assert_eq!(b.readdir_entry(NodeId::ROOT, 2), Ok(None));
    }

    #[test]
    fn an_unmounted_node_with_a_mount_below_stays_an_intermediate()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/a", mount(CAP)).is_some());
        assert!(b.install(b"/a/b", mount(CAP + 1)).is_some());
        let a = b.find(b"/a").expect("installed");
        assert!(!b.needs_fallthrough(a));
        b.begin_unmount(a).unwrap();
        let view = b.lookup(NodeId::ROOT, b"a").expect("still visible");
        assert_eq!(
            view.target,
            EntryTarget::Local(NodeId::from_raw_truncated(u64::from(a)))
        );
        // It became an intermediate with no fall-through cap.
        assert!(b.needs_fallthrough(a));
        b.set_fallthrough_cap(a, CAP);
        assert!(!b.needs_fallthrough(a));
    }

    #[test]
    fn a_vacant_node_reused_as_an_intermediate_is_reported_for_its_fallthrough()
    {
        let mut b = VfsdRootBackend::new();
        let a = unmounting(&mut b, b"/a", CAP);
        assert!(b.remove_mount(a).is_some());
        let result = b.install(b"/a/b", mount(CAP)).expect("install fits");
        assert_eq!(result.as_slice(), &[a]);
        assert!(matches!(
            b.lookup(NodeId::ROOT, b"a").map(|v| v.target),
            Ok(EntryTarget::Local(_))
        ));
    }

    #[test]
    fn a_second_root_mount_is_rejected_and_keeps_the_first()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/", mount(CAP)).is_some());
        assert!(!b.can_install(b"/"));
        assert!(!b.can_install(b"///"));
        assert!(b.install(b"///", mount(CAP + 1)).is_none());
        assert_eq!(b.root_mount_cap(), CAP);
    }

    #[test]
    fn mounting_on_an_existing_mount_point_is_rejected()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", mount(CAP)).is_some());
        assert!(!b.can_install(b"/esp"));
        assert!(b.install(b"/esp", mount(CAP + 1)).is_none());
        assert_eq!(b.local_child_count(0), 1);
    }

    #[test]
    fn a_component_is_bounded_by_the_protocol_name_limit()
    {
        let mut b = VfsdRootBackend::new();
        let mut path = vec![b'/'];
        path.extend(core::iter::repeat_n(b'a', MAX_NAME_LEN + 1));
        assert!(!b.can_install(&path));
        assert!(b.install(&path, mount(CAP)).is_none());
        assert_eq!(b.local_child_count(0), 0);
        path.truncate(1 + MAX_NAME_LEN);
        assert!(b.install(&path, mount(CAP)).is_some());
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
        assert!(b.install(b"/a/./b", mount(CAP)).is_none());
        assert!(b.install(b"/a\0", mount(CAP)).is_none());
        assert_eq!(b.local_child_count(0), 0);
    }

    #[test]
    fn the_tree_grows_past_the_former_fixed_pool()
    {
        let mut b = VfsdRootBackend::new();
        for i in 0..200
        {
            assert!(
                b.install(format!("/m{i}/leaf").as_bytes(), mount(CAP))
                    .is_some()
            );
        }
        assert_eq!(b.local_child_count(0), 200);
        let view = b.lookup(NodeId::ROOT, b"m199").expect("last mount found");
        let EntryTarget::Local(m199) = view.target
        else
        {
            panic!("an intermediate is local");
        };
        b.lookup(m199, b"leaf").unwrap();
    }

    #[test]
    fn a_multi_component_install_reports_its_new_intermediates()
    {
        let mut b = VfsdRootBackend::new();
        let result = b.install(b"/a/b/c", mount(CAP)).expect("install fits");
        let mut paths: Vec<Vec<u8>> = result
            .as_slice()
            .iter()
            .map(|&idx| b.path_of(idx).expect("intermediate has a path"))
            .collect();
        paths.sort();
        assert_eq!(paths, vec![b"/a".to_vec(), b"/a/b".to_vec()]);
        for &idx in result.as_slice()
        {
            b.set_fallthrough_cap(idx, CAP);
        }
        // A sibling under intermediates that have their fall-through caps
        // reports none.
        assert_eq!(
            b.install(b"/a/b/d", mount(CAP)).map(|r| r.as_slice().len()),
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
        let result = b
            .install(path.as_bytes(), mount(CAP))
            .expect("install fits");
        let deepest = *result.as_slice().last().expect("seven intermediates");
        let expected = &path.as_bytes()[..7 * (1 + MAX_NAME_LEN)];
        assert_eq!(b.path_of(deepest).as_deref(), Some(expected));
    }

    #[test]
    fn an_existing_intermediate_can_become_a_mount_point()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/a/b", mount(CAP)).is_some());
        assert!(b.can_install(b"/a"));
        assert!(b.install(b"/a", mount(CAP)).is_some());
        assert!(!b.can_install(b"/a"));
    }

    /// Pool index of the intermediate `/a` an install of `/a/b` creates.
    fn intermediate_a(b: &mut VfsdRootBackend) -> u32
    {
        let result = b.install(b"/a/b", mount(CAP)).expect("install fits");
        result.as_slice()[0]
    }

    #[test]
    fn lookup_of_a_mount_point_crosses_to_the_peer_root()
    {
        let mut b = VfsdRootBackend::new();
        assert!(b.install(b"/esp", mount(CAP)).is_some());
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
        assert!(b.install(b"/esp", mount(CAP)).is_some());
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
        assert!(b.install(b"/esp", mount(CAP)).is_some());
        assert!(b.install(b"/data", mount(CAP)).is_some());
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
        assert!(b.install(b"/esp", mount(CAP)).is_some());
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
