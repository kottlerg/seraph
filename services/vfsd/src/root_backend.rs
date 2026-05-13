// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// vfsd/src/root_backend.rs

//! Synthetic system-root [`NamespaceBackend`] composed at boot time.
//!
//! `VfsdRootBackend` is vfsd's in-process namespace server. It owns no
//! storage; every directory entry is either a tokened SEND on a peer
//! filesystem driver's namespace endpoint (a *terminal* mount node) or
//! a synthetic intermediate directory created on demand to host a
//! multi-component mount path (a *synthetic intermediate* node). A
//! client holding a tokened SEND on vfsd's namespace endpoint at
//! `NodeId::ROOT` walks into mounts via `NS_LOOKUP`; the protocol crate
//! returns either a `cap_derive`-d copy of the underlying driver's
//! root cap (External entry, terminal node) or a tokened SEND on
//! vfsd's own namespace endpoint addressing the intermediate's
//! `NodeId` (Local entry, synthetic intermediate).
//!
//! Each synthetic intermediate may also carry a `fallthrough_cap` —
//! a tokened SEND on the root mount's namespace endpoint addressing
//! the directory at the corresponding path in the root filesystem.
//! When a `NS_LOOKUP` against an intermediate misses every local
//! child, vfsd's namespace dispatcher forwards the request verbatim
//! to that fall-through cap, preserving the namespace-model
//! invariant that root-fs entries remain reachable unless explicitly
//! shadowed by a registered mount.
//!
//! The synthetic root (`NodeId::ROOT`) is itself a tree node whose
//! `fallthrough_cap` is the root mount cap captured when
//! `MOUNT path="/"` succeeds.

use namespace_protocol::{
    EntryName, EntryTarget, EntryView, FrameReply, NamespaceBackend, NamespaceRights, NodeId,
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
/// `terminal_cap != 0`) or a *synthetic intermediate* (created on
/// demand to host a multi-component mount path, `terminal_cap == 0`).
/// Both forms may carry a `fallthrough_cap` addressing the
/// corresponding directory in the root filesystem; the synthetic
/// root's `fallthrough_cap` is the root mount cap itself.
#[derive(Copy, Clone)]
pub struct TreeNode
{
    pub name: [u8; MAX_ENTRY_NAME],
    pub name_len: u8,
    pub parent: u32,
    pub first_child: u32,
    pub next_sibling: u32,
    /// Tokened SEND on the underlying driver's namespace endpoint,
    /// captured at MOUNT time. Non-zero on terminal nodes, zero on
    /// synthetic intermediates.
    pub terminal_cap: u32,
    /// Tokened SEND on the root mount's namespace endpoint addressing
    /// the directory at the path corresponding to this node, used to
    /// forward unmatched `NS_LOOKUP` requests so root-fs entries
    /// remain reachable through synthetic intermediates. Zero when no
    /// such fall-through is available (the path does not exist in the
    /// root filesystem, or the root mount has not been installed yet).
    /// On `NodeId::ROOT` this field carries the root mount cap.
    pub fallthrough_cap: u32,
    pub active: bool,
}

impl TreeNode
{
    pub const fn empty() -> Self
    {
        Self {
            name: [0; MAX_ENTRY_NAME],
            name_len: 0,
            parent: NONE,
            first_child: NONE,
            next_sibling: NONE,
            terminal_cap: 0,
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
    pub new_intermediates: [u32; MAX_TREE_NODES],
    pub new_intermediates_len: usize,
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

    pub fn as_slice(&self) -> &[u32]
    {
        &self.new_intermediates[..self.new_intermediates_len]
    }
}

impl VfsdRootBackend
{
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
    /// demand, and sets `terminal_cap` on the final node. The empty
    /// path (`/`) installs `cap` as the synthetic root's
    /// `fallthrough_cap`.
    ///
    /// Returns `Some(InstallResult)` listing newly-created
    /// intermediate indices on success; the caller is expected to
    /// compute and store each intermediate's `fallthrough_cap` via
    /// [`Self::set_fallthrough_cap`].
    ///
    /// Returns `None` on tree exhaustion, oversize component
    /// (`> MAX_ENTRY_NAME`), or attempting to mount on top of an
    /// already-terminal node.
    pub fn install(&mut self, path: &[u8], cap: u32) -> Option<InstallResult>
    {
        let stripped = path.strip_prefix(b"/").unwrap_or(path);
        if stripped.is_empty()
        {
            self.nodes[0].fallthrough_cap = cap;
            return Some(InstallResult::empty());
        }

        // Count components; rejects oversize ones up front so the tree
        // is never partially mutated on a failure.
        let mut total = 0usize;
        for component in stripped.split(|&b| b == b'/')
        {
            if component.is_empty()
            {
                continue;
            }
            if component.len() > MAX_ENTRY_NAME
            {
                return None;
            }
            total += 1;
        }
        if total == 0
        {
            // Path was something like `///` — treat as root.
            self.nodes[0].fallthrough_cap = cap;
            return Some(InstallResult::empty());
        }

        let mut result = InstallResult::empty();
        let mut current: u32 = 0;
        let mut i = 0;
        for component in stripped.split(|&b| b == b'/')
        {
            if component.is_empty()
            {
                continue;
            }
            let is_last = i == total - 1;
            i += 1;

            if let Some(child) = self.find_child(current, component)
            {
                if is_last
                {
                    if self.nodes[child as usize].terminal_cap != 0
                    {
                        // Path is already a mount point.
                        return None;
                    }
                    self.nodes[child as usize].terminal_cap = cap;
                }
                current = child;
            }
            else
            {
                let new_idx = self.alloc_slot()?;
                let parent_first_child = self.nodes[current as usize].first_child;
                let n = &mut self.nodes[new_idx as usize];
                n.active = true;
                n.parent = current;
                n.name[..component.len()].copy_from_slice(component);
                #[allow(clippy::cast_possible_truncation)]
                {
                    n.name_len = component.len() as u8;
                }
                n.first_child = NONE;
                n.next_sibling = parent_first_child;
                n.terminal_cap = if is_last { cap } else { 0 };
                n.fallthrough_cap = 0;
                self.nodes[current as usize].first_child = new_idx;
                if !is_last && !result.push(new_idx)
                {
                    return None;
                }
                current = new_idx;
            }
        }
        Some(result)
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

    /// Tokened SEND on the root mount's namespace endpoint, or `0` if
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

    fn alloc_slot(&self) -> Option<u32>
    {
        // Skip index 0 — that's the synthetic root.
        for (i, n) in self.nodes.iter().enumerate().skip(1)
        {
            if !n.active
            {
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
        let target = if child.terminal_cap != 0
        {
            EntryTarget::External(child.terminal_cap)
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
                    return Ok(EntryName::new(
                        &n.name[..usize::from(n.name_len)],
                        NodeKind::Dir,
                    ));
                }
                visible += 1;
            }
            cur = n.next_sibling;
        }
        Ok(None)
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

    fn read_frame(
        &mut self,
        _file: NodeId,
        _offset: u64,
        _cookie: u64,
    ) -> Result<FrameReply, NsError>
    {
        Err(NsError::NotSupported)
    }

    fn release_frame(&mut self, _file: NodeId, _cookie: u64) {}

    fn close(&mut self, _node: NodeId) {}
}
