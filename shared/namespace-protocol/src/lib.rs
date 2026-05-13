// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/lib.rs

//! Shared namespace-protocol implementation.
//!
//! This crate owns the security-relevant code path that every namespace
//! server runs: IPC dispatch, name validation, rights composition,
//! per-entry visibility filtering, and node-cap minting via
//! `cap_derive_token`. Storage backends — fatfs, future ext4, tmpfs,
//! vfsd's synthetic root — implement [`NamespaceBackend`], own their
//! own `ipc_recv` loop on their namespace endpoint, and route each
//! `NS_*` request through [`dispatch_request`]. They do not
//! re-implement namespace semantics or access checks. The model is
//! documented in `docs/namespace-model.md`.

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

pub mod gate;
pub mod name;
pub mod rights;
pub mod token;
pub mod wire;

pub use gate::{GateError, compose_forward_lookup_rights, gate};
pub use name::{MAX_NAME_LEN, MIN_NAME_LEN, NameError, validate_name};
pub use rights::{NamespaceRights, RIGHTS_BITS, RIGHTS_MASK};
pub use token::{NODE_ID_BITS, NODE_ID_MASK, NodeId, pack};
pub use wire::NsError;

/// Whether a node is a directory or a regular file.
///
/// The kernel layer holds no notion of directory or file; this
/// distinction is server-private and surfaces to clients via
/// `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` replies.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum NodeKind
{
    /// A regular file. Permits `NS_READ`, `NS_READ_FRAME`, `NS_STAT`.
    File = 0,
    /// A directory. Permits `NS_LOOKUP`, `NS_READDIR`, `NS_STAT`.
    Dir = 1,
}

/// Attribute snapshot for a node, returned by `NS_STAT`.
///
/// `mtime_us` is best-effort and may be zero on backends that do not
/// track modification time. `size` is in bytes for files; the backend
/// chooses the meaning for directories (typically zero).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NodeStat
{
    /// Size in bytes (file) or backend-defined value (directory).
    pub size: u64,
    /// Modification time in microseconds since the system epoch.
    /// Best-effort; zero if the backend does not track it.
    pub mtime_us: u64,
    /// Whether this node is a file or a directory.
    pub kind: NodeKind,
}

/// One entry in a directory, as surfaced by `NS_READDIR`.
///
/// The name is carried inline as a fixed-capacity byte buffer so that
/// the iteration can be no-alloc on the backend side. Names are
/// validated by [`validate_name`] before serving.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EntryName
{
    bytes: [u8; MAX_NAME_LEN],
    len: u8,
    /// Whether the entry refers to a file or a directory.
    pub kind: NodeKind,
}

impl EntryName
{
    /// Construct an [`EntryName`] from `name` and `kind`. Returns
    /// `None` if `name` exceeds [`MAX_NAME_LEN`].
    #[must_use]
    pub fn new(name: &[u8], kind: NodeKind) -> Option<Self>
    {
        if name.len() > MAX_NAME_LEN
        {
            return None;
        }
        let mut bytes = [0u8; MAX_NAME_LEN];
        bytes[..name.len()].copy_from_slice(name);
        // Cast is range-safe: `name.len() <= MAX_NAME_LEN` (255), fits u8.
        #[allow(clippy::cast_possible_truncation)]
        let len = name.len() as u8;
        Some(Self { bytes, len, kind })
    }

    /// Returns the name's bytes (length-prefixed view of the inline buffer).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Where the cap returned by `NS_LOOKUP` for a directory entry comes from.
///
/// `Local` entries are minted on this server's namespace endpoint via
/// `cap_derive_token` against the entry's stored [`NodeId`] (the common
/// case). `External` entries return a pre-installed cap on a different
/// server's namespace endpoint via `cap_copy` (the mount-point case).
/// The composing backend stores `External` entries when boot-time
/// mount composition installs a child filesystem's root cap into a
/// parent directory.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EntryTarget
{
    /// Backend-internal node — the cap returned by `NS_LOOKUP` is
    /// freshly minted on this server's namespace endpoint.
    Local(NodeId),
    /// Pre-installed cap on a different server's namespace endpoint.
    /// Returned via `cap_copy` with namespace rights intersected per
    /// the per-entry policy.
    External(u32),
}

/// Per-entry directory record returned by [`NamespaceBackend::lookup`].
///
/// The protocol crate composes the caller's rights, the entry's
/// `max_rights` ceiling, and `visible_requires` filter to decide
/// whether the entry is visible and what rights the minted child cap
/// receives.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EntryView
{
    /// Where the cap returned to the caller originates.
    pub target: EntryTarget,
    /// Whether the entry is a file or directory.
    pub kind: NodeKind,
    /// Best-effort cached file size; zero for directories.
    pub size_hint: u64,
    /// Ceiling on rights any child cap minted for this entry can carry.
    /// Independent of the parent directory's rights.
    pub max_rights: NamespaceRights,
    /// Rights the caller's directory cap MUST hold for this entry to
    /// be visible at lookup or readdir.
    pub visible_requires: NamespaceRights,
}

/// Reply payload returned by [`NamespaceBackend::read_frame`].
///
/// `frame_cap` is a single-page Frame cap with `MAP|READ` rights
/// covering the cached file page. The cookie value echoes the
/// caller-supplied request cookie unchanged. `bytes_valid` is bounded
/// by file end, the current backend cluster boundary, and the page
/// tail.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct FrameReply
{
    /// Single-page Frame cap (`MAP|READ`) covering the cached page.
    pub frame_cap: u32,
    /// Bytes of valid file content starting at `frame_data_offset`.
    pub bytes_valid: u32,
    /// Byte offset within the returned frame at which valid content
    /// for the requested file offset begins.
    pub frame_data_offset: u32,
    /// Release cookie echoed from the request.
    pub cookie: u64,
}

/// Storage backend trait implemented by every namespace server.
///
/// [`dispatch_request`] calls these methods after running the
/// protocol's wire decode, rights / visibility / name checks, and
/// child-cap minting; backends own only their storage layer and never
/// the wire surface or the access-control checks.
pub trait NamespaceBackend
{
    /// Look up `name` within the directory identified by `dir`.
    ///
    /// # Errors
    ///
    /// Returns [`NsError::NotFound`] when the name is absent, and
    /// other [`NsError`] variants for backend-defined failures
    /// (storage I/O, malformed on-disk metadata, …).
    fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<EntryView, NsError>;

    /// Return the entry at zero-based index `idx` within `dir`. The
    /// crate iterates by incrementing `idx` until the backend returns
    /// `Ok(None)`, signalling end-of-directory.
    ///
    /// # Errors
    ///
    /// Returns [`NsError`] variants for backend-defined failures.
    fn readdir_entry(&mut self, dir: NodeId, idx: u32) -> Result<Option<EntryName>, NsError>;

    /// Return attribute snapshot for `node` (file or directory).
    ///
    /// # Errors
    ///
    /// Returns [`NsError`] variants for backend-defined failures.
    fn stat(&mut self, node: NodeId) -> Result<NodeStat, NsError>;

    /// Inline read up to `max_len` bytes from `file` at `offset` into
    /// `dst`, returning the number of bytes actually written.
    ///
    /// # Errors
    ///
    /// Returns [`NsError::InvalidOffset`] for offsets past EOF, and
    /// other [`NsError`] variants for backend-defined failures.
    fn read_inline(
        &mut self,
        file: NodeId,
        offset: u64,
        max_len: usize,
        dst: &mut [u8],
    ) -> Result<usize, NsError>;

    /// Frame-cap read: return a Frame cap covering the cached page for
    /// `file` at `offset`, with `cookie` recorded for cooperative
    /// release.
    ///
    /// # Errors
    ///
    /// Returns [`NsError::InvalidCookie`] for malformed cookies and
    /// other [`NsError`] variants for backend-defined failures.
    fn read_frame(&mut self, file: NodeId, offset: u64, cookie: u64)
    -> Result<FrameReply, NsError>;

    /// Best-effort release of a previously-issued frame for `file`
    /// keyed by `cookie`. A cookie not currently outstanding is
    /// silently ignored. Drives the cooperative-release side of the
    /// eviction protocol.
    fn release_frame(&mut self, file: NodeId, cookie: u64);

    /// Best-effort cleanup hint when a holder is closing its cap on
    /// `node`. Cap revocation is the authoritative lifetime signal;
    /// `close` allows backends to drop cached state opportunistically.
    fn close(&mut self, node: NodeId);
}

/// Dispatch a single received namespace request and reply on its behalf.
///
/// Decodes the request's wire shape per `ns_labels::*`, applies the
/// caller-rights / visibility / name-validation checks documented in
/// `docs/namespace-model.md`, calls into `backend` for the underlying
/// storage operation, mints child caps from `namespace_endpoint` via
/// `cap_derive_token`, and writes the reply through `ipc_reply`.
///
/// Each namespace server owns its own `ipc_recv` loop — the receive
/// surface is not bundled here because every realistic backend
/// multiplexes other protocol layers on the same endpoint (filesystems
/// receive their service-level and file-IO opcodes alongside `NS_*`;
/// composers like vfsd interpose synthetic-tree fast-paths before
/// dispatch). Backends select messages whose label is in
/// `ns_labels::*` and pass them here; everything else is theirs to
/// handle.
///
/// `received.token` MUST be the `pack(node_id, rights)` token the
/// kernel delivered with the request. Backends do not see the wire
/// layer — they only see decoded `NodeId` / `&[u8]` / `u64`
/// arguments.
///
/// # Safety
///
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set`.
pub unsafe fn dispatch_request<B: NamespaceBackend>(
    backend: &mut B,
    received: &ipc::IpcMessage,
    namespace_endpoint: u32,
    ipc_buf: *mut u64,
)
{
    let opcode = received.label & 0xFFFF;
    let reply = match opcode
    {
        ipc::ns_labels::NS_LOOKUP => handle_lookup(backend, received, namespace_endpoint),
        ipc::ns_labels::NS_STAT => handle_stat(backend, received),
        ipc::ns_labels::NS_READDIR => handle_readdir(backend, received),
        _ => ipc::IpcMessage::new(NsError::NotSupported.as_label()),
    };
    // SAFETY: `ipc_buf` is the registered IPC buffer page per the
    // function-level safety contract.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Decode an `NS_LOOKUP` request's `caller_requested` word into a
/// [`NamespaceRights`] mask. The `0xFFFF` sentinel means "everything
/// I'm allowed"; any other value has its low [`RIGHTS_BITS`] bits
/// interpreted directly, with reserved bits beyond [`RIGHTS_MASK`]
/// stripped.
///
/// Shared between [`handle_lookup`] and
/// [`gate::compose_forward_lookup_rights`] so the two paths cannot
/// drift on the sentinel's meaning.
#[must_use]
pub(crate) fn decode_caller_requested(raw_req: u64) -> NamespaceRights
{
    if raw_req == 0xFFFF
    {
        NamespaceRights::ALL
    }
    else
    {
        // Cast is range-safe: masking to RIGHTS_MASK (24 bits) fits u32.
        #[allow(clippy::cast_possible_truncation)]
        let bits = (raw_req as u32) & RIGHTS_MASK;
        NamespaceRights::from_raw(bits)
    }
}

fn handle_lookup<B: NamespaceBackend>(
    backend: &mut B,
    msg: &ipc::IpcMessage,
    namespace_endpoint: u32,
) -> ipc::IpcMessage
{
    let (parent, parent_rights) = token::unpack(msg.token);
    if !parent_rights.contains(rights::LOOKUP)
    {
        return ipc::IpcMessage::new(NsError::PermissionDenied.as_label());
    }

    // Cast is range-safe: name_len lives in bits 16..32 of the label.
    #[allow(clippy::cast_possible_truncation)]
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    let data_bytes = msg.data_bytes();
    // First data word carries caller-requested rights; name bytes start
    // at byte 8.
    if name_len == 0 || name_len > MAX_NAME_LEN || data_bytes.len() < 8 + name_len
    {
        return ipc::IpcMessage::new(NsError::InvalidName.as_label());
    }
    let name = &data_bytes[8..8 + name_len];
    if validate_name(name).is_err()
    {
        return ipc::IpcMessage::new(NsError::InvalidName.as_label());
    }

    let caller_requested = decode_caller_requested(msg.word(0));

    let entry = match backend.lookup(parent, name)
    {
        Ok(e) => e,
        Err(err) => return ipc::IpcMessage::new(err.as_label()),
    };

    if !parent_rights.contains(entry.visible_requires.raw())
    {
        // Hidden entries are indistinguishable from absent ones — no
        // information leak about names this caller cannot see.
        return ipc::IpcMessage::new(NsError::NotFound.as_label());
    }

    let returned_rights = parent_rights & entry.max_rights & caller_requested;

    let child_cap = match entry.target
    {
        EntryTarget::Local(node) =>
        {
            let token = pack(node, returned_rights);
            if token == 0
            {
                // cap_derive_token requires non-zero token.
                return ipc::IpcMessage::new(NsError::PermissionDenied.as_label());
            }
            // SEND_GRANT lets the holder attach caps to IPC requests
            // through this node cap (e.g. the per-process release-
            // endpoint SEND that travels in `caps[0]` of the first
            // `FS_READ_FRAME`). It does not widen authority — the
            // recipient still validates every received cap. SEND-only
            // would force the kernel to reject any cap-bearing IPC.
            match syscall::cap_derive_token(
                namespace_endpoint,
                syscall_abi::RIGHTS_SEND_GRANT,
                token,
            )
            {
                Ok(slot) => slot,
                Err(_) => return ipc::IpcMessage::new(NsError::OutOfResources.as_label()),
            }
        }
        EntryTarget::External(src) =>
        {
            // External entries (mount points) carry pre-installed caps
            // on a peer server's namespace endpoint. Forward via
            // cap_derive — the peer's namespace rights enforcement
            // happens at the next NS_LOOKUP hop.
            match syscall::cap_derive(src, syscall_abi::RIGHTS_SEND)
            {
                Ok(slot) => slot,
                Err(_) => return ipc::IpcMessage::new(NsError::OutOfResources.as_label()),
            }
        }
    };

    ipc::IpcMessage::builder(0)
        .word(0, entry.kind as u64)
        .word(1, entry.size_hint)
        .cap(child_cap)
        .build()
}

fn handle_stat<B: NamespaceBackend>(backend: &mut B, msg: &ipc::IpcMessage) -> ipc::IpcMessage
{
    let (node, node_rights) = token::unpack(msg.token);
    if !node_rights.contains(rights::STAT)
    {
        return ipc::IpcMessage::new(NsError::PermissionDenied.as_label());
    }
    match backend.stat(node)
    {
        Ok(stat) => ipc::IpcMessage::builder(0)
            .word(0, stat.size)
            .word(1, stat.mtime_us)
            .word(2, stat.kind as u64)
            .build(),
        Err(err) => ipc::IpcMessage::new(err.as_label()),
    }
}

fn handle_readdir<B: NamespaceBackend>(backend: &mut B, msg: &ipc::IpcMessage) -> ipc::IpcMessage
{
    let (dir, dir_rights) = token::unpack(msg.token);
    if !dir_rights.contains(rights::READDIR)
    {
        return ipc::IpcMessage::new(NsError::PermissionDenied.as_label());
    }
    // Cast is range-safe: index is bounded by directory size; truncation
    // would only occur on dirs >2^32 entries which exceed FAT's space.
    #[allow(clippy::cast_possible_truncation)]
    let idx = msg.word(0) as u32;
    match backend.readdir_entry(dir, idx)
    {
        Ok(Some(entry)) =>
        {
            let name = entry.as_bytes();
            ipc::IpcMessage::builder(0)
                .word(0, entry.kind as u64)
                .word(1, name.len() as u64)
                .bytes(2, name)
                .build()
        }
        Ok(None) => ipc::IpcMessage::new(ipc::fs_labels::END_OF_DIR),
        Err(err) => ipc::IpcMessage::new(err.as_label()),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn entry_name_round_trips_through_as_bytes()
    {
        let n = EntryName::new(b"hello", NodeKind::File).unwrap();
        assert_eq!(n.as_bytes(), b"hello");
        assert_eq!(n.kind, NodeKind::File);
    }

    #[test]
    fn entry_name_rejects_oversize_input()
    {
        let too_long = [b'x'; MAX_NAME_LEN + 1];
        assert!(EntryName::new(&too_long, NodeKind::File).is_none());
    }

    #[test]
    fn entry_name_accepts_max_length_input()
    {
        let max = [b'x'; MAX_NAME_LEN];
        let n = EntryName::new(&max, NodeKind::Dir).unwrap();
        assert_eq!(n.as_bytes().len(), MAX_NAME_LEN);
        assert_eq!(n.kind, NodeKind::Dir);
    }

    #[test]
    fn node_kind_discriminants_are_stable_wire_values()
    {
        assert_eq!(NodeKind::File as u64, 0);
        assert_eq!(NodeKind::Dir as u64, 1);
    }

    #[test]
    fn rights_composition_yields_intersection_of_parent_entry_and_request()
    {
        // Models the NS_LOOKUP rights composition documented in
        // docs/namespace-model.md: returned = parent ∩
        // entry.max_rights ∩ caller_requested.
        let parent = NamespaceRights::from_raw(rights::LOOKUP | rights::READ | rights::STAT);
        let entry_max = NamespaceRights::from_raw(rights::READ | rights::STAT);
        let requested = NamespaceRights::from_raw(rights::READ);
        let returned = parent & entry_max & requested;
        assert_eq!(returned.raw(), rights::READ);
    }

    #[test]
    fn rights_visibility_filter_uses_contains()
    {
        // Models the visibility test documented in
        // docs/namespace-model.md: an entry is visible iff
        // parent_rights & entry.visible_requires == entry.visible_requires.
        let parent = NamespaceRights::from_raw(rights::LOOKUP | rights::ADMIN);
        let visible = NamespaceRights::from_raw(rights::ADMIN);
        let hidden = NamespaceRights::from_raw(rights::ADMIN | rights::MUTATE_DIR);
        assert!(parent.contains(visible.raw()));
        assert!(!parent.contains(hidden.raw()));
    }
}
