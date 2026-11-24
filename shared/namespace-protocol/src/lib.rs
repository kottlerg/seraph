// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/lib.rs

//! Shared namespace-protocol implementation.
//!
//! This crate owns the security-relevant code path that every namespace
//! server runs: IPC dispatch, name validation, rights composition,
//! per-entry visibility filtering at `NS_LOOKUP` and `NS_READDIR`, and
//! node-cap minting via `cap_derive_badge`. Storage backends — fatfs,
//! future ext4, tmpfs, vfsd's synthetic root — implement
//! [`NamespaceBackend`], own their own `ipc_recv` loop on their
//! namespace endpoint, and route each `NS_*` request through
//! [`dispatch_request`]. They do not re-implement namespace semantics
//! or access checks. The model is documented in
//! `docs/namespace-model.md`.

#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(
    feature = "rustc-dep-of-std",
    expect(
        internal_features,
        reason = "`no_core` is an internal feature, needed to build as a dependency of std"
    )
)]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

// Cargo records no source file of a `-Z build-std` unit, only the environment variables it
// reads: reading xtask's digest of the sources of every crate std depends on makes a change to
// any of them rebuild this unit (docs/build-system.md § Build Output: the Sysroot).
#[cfg(feature = "rustc-dep-of-std")]
const _: &str = core::env!("SERAPH_STD_DEPS_DIGEST");

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

pub mod badge;
pub mod client;
pub mod gate;
pub mod name;
pub mod rights;
pub mod wire;

pub use badge::{
    KIND_ID_BITS, KIND_ID_MASK, NODE_ID_BITS, NODE_ID_MASK, NodeId, OPEN_INSTANCE, OpenRef,
    SESSION, is_kind_flagged, is_open_instance, pack, pack_open, pack_session, session_id,
};
pub use gate::{GateError, compose_forward_lookup_rights, gate, gate_open};
pub use name::{MAX_NAME_LEN, MIN_NAME_LEN, NameError, validate_name};
pub use rights::{NamespaceRights, RIGHTS_BITS, RIGHTS_MASK};
pub use wire::NsError;

/// Longest path, in bytes, one `NS_LOOKUP` request carries: the request's
/// data words after its rights word (`README.md` § `NS_LOOKUP`). A client
/// walking a longer path splits it at a component boundary
/// ([`client::PathWalk`]).
pub const MAX_LOOKUP_PATH_LEN: usize = (syscall_abi::MSG_DATA_WORDS_MAX - 1) * 8;

/// Whether a node is a directory or a regular file.
///
/// The kernel layer holds no notion of directory or file; this
/// distinction is server-private and surfaces to clients via
/// `NS_LOOKUP` / `NS_STAT` / `NS_READDIR` replies.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum NodeKind
{
    /// A regular file: `NS_STAT` and the `FS_*` file labels (see
    /// `shared/namespace-protocol/README.md` § Rights).
    File = 0,
    /// A directory: `NS_LOOKUP`, `NS_READDIR`, `NS_STAT`, and the
    /// `MUTATE_DIR` labels.
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
/// the iteration can be no-alloc on the backend side. Names are not
/// validated server-side; clients validate the names they receive.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EntryName
{
    bytes: [u8; MAX_NAME_LEN],
    len: u8,
    /// Whether the entry refers to a file or a directory.
    pub kind: NodeKind,
    /// Rights the caller's directory cap MUST hold for this entry to be
    /// enumerated; the same mask [`NamespaceBackend::lookup`] reports in
    /// [`EntryView::visible_requires`] for the entry.
    pub visible_requires: NamespaceRights,
}

impl EntryName
{
    /// Construct an [`EntryName`] from `name`, `kind`, and the entry's
    /// `visible_requires` mask. Returns `None` if `name` exceeds
    /// [`MAX_NAME_LEN`].
    #[must_use]
    pub fn new(name: &[u8], kind: NodeKind, visible_requires: NamespaceRights) -> Option<Self>
    {
        let mut bytes = [0u8; MAX_NAME_LEN];
        // `None` when `name` is longer than the `MAX_NAME_LEN`-byte buffer.
        bytes.get_mut(..name.len())?.copy_from_slice(name);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "range-safe: `name.len() <= MAX_NAME_LEN` (255), which fits u8"
        )]
        let len = name.len() as u8;
        Some(Self {
            bytes,
            len,
            kind,
            visible_requires,
        })
    }

    /// Returns the name's bytes (length-prefixed view of the inline buffer).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        // `len` is at most `MAX_NAME_LEN` by construction (`new`), so the
        // empty fallback is never taken.
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }
}

/// Where the cap returned by `NS_LOOKUP` for a directory entry comes from.
///
/// `Local` entries are minted on this server's namespace endpoint via
/// `cap_derive_badge` against the entry's stored [`NodeId`] (the common
/// case). `External` entries mint a fresh badged SEND via
/// `cap_derive_badge` on the peer's stored unbadged namespace endpoint
/// (the mount-point case).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum EntryTarget
{
    /// Backend-internal node — the cap returned by `NS_LOOKUP` is
    /// freshly minted on this server's namespace endpoint.
    Local(NodeId),
    /// A mount point: the entry resolves into a *different* server's
    /// namespace (a child filesystem mounted under this directory).
    ///
    /// The cap returned by `NS_LOOKUP` is a fresh badged SEND minted on
    /// `endpoint` at `node`, carrying the composed
    /// `parent ∩ max_rights ∩ requested` rights — identical attenuation
    /// to a [`Local`](Self::Local) entry, applied across the mount
    /// boundary. The composing backend stores the peer's *unbadged*
    /// namespace endpoint, never a pre-badged cap: the kernel forbids
    /// re-badging an already-badged cap (`SYS_CAP_DERIVE_BADGE` rejects
    /// a badged source), so attenuation can only cross the mount by
    /// minting afresh from the endpoint.
    External
    {
        /// Unbadged SEND on the peer server's namespace endpoint, held
        /// by this server and never handed out directly.
        endpoint: u64,
        /// Peer-side node the mount resolves to (`NodeId::ROOT` for a
        /// whole-filesystem mount).
        node: NodeId,
    },
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

/// Reply payload returned by [`NamespaceBackend::read_memory`].
///
/// `memory_cap` is a single-page Memory cap with `MAP` rights
/// (read-only mapping authority) covering the cached file page. The cookie value echoes the
/// caller-supplied request cookie unchanged. `bytes_valid` is bounded
/// by file end, the current backend cluster boundary, and the page
/// tail. Both it and `memory_data_offset` are at most a page, so their
/// `u32` width never truncates.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct MemoryReply
{
    /// Single-page Memory cap (`MAP` rights) covering the cached page.
    pub memory_cap: u64,
    /// Bytes of valid file content starting at `memory_data_offset`.
    pub bytes_valid: u32,
    /// Byte offset within the returned page at which valid content
    /// for the requested file offset begins.
    pub memory_data_offset: u32,
    /// Release cookie echoed from the request.
    pub cookie: u64,
}

/// Storage backend trait implemented by every namespace server.
///
/// [`dispatch_request`] calls these methods after running the
/// protocol's wire decode and rights / name checks, filters what
/// `lookup` and `readdir_entry` return by visibility, and mints child
/// caps; backends own only their storage layer and never the wire
/// surface or the access-control checks.
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

    /// Return the entry at zero-based backend index `idx` within `dir`,
    /// hidden entries included; `Ok(None)` past the last entry produces
    /// `END_OF_DIR`. When [`Self::may_hide_entries`] is `false`, `NS_READDIR`
    /// calls this once with the client-supplied index, which must then
    /// equal the visible index (a hidden entry returned there makes the
    /// crate fall back to the scan); otherwise it scans from index 0 per
    /// request and itself skips the entries whose `visible_requires` the
    /// caller lacks.
    ///
    /// # Errors
    ///
    /// Returns [`NsError`] variants for backend-defined failures.
    fn readdir_entry(&mut self, dir: NodeId, idx: u32) -> Result<Option<EntryName>, NsError>;

    /// Whether any entry of `dir` may carry a non-empty
    /// `visible_requires`. A backend returns `false` only when no entry
    /// of `dir` is hidden from any caller; `NS_READDIR` then serves index
    /// `idx` with one [`Self::readdir_entry`] call instead of scanning
    /// the directory from index 0 to skip hidden entries. The default,
    /// `true`, is always correct.
    fn may_hide_entries(&mut self, _dir: NodeId) -> bool
    {
        true
    }

    /// Whether an `NS_LOOKUP` walk that reached `dir` through one of this
    /// backend's own entries may look the walk's next component up in `dir`.
    /// A backend returns `false` for a directory whose lookups another
    /// dispatcher may answer, such as a vfsd synthetic node with a
    /// fall-through: the walk then ends at `dir` and returns its cap, and the
    /// client sends the rest of its path to that cap, as a separate request
    /// would reach it. The default, `true`, is correct for a backend that
    /// serves every lookup in each of its directories itself.
    fn continues_walk(&mut self, _dir: NodeId) -> bool
    {
        true
    }

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

    /// Memory-cap read: return a Memory cap covering the cached page for
    /// `file` at `offset`, with `cookie` recorded for cooperative
    /// release.
    ///
    /// # Errors
    ///
    /// Returns [`NsError::InvalidCookie`] for malformed cookies and
    /// other [`NsError`] variants for backend-defined failures.
    fn read_memory(
        &mut self,
        file: NodeId,
        offset: u64,
        cookie: u64,
    ) -> Result<MemoryReply, NsError>;

    /// Best-effort release of a previously-issued page for `file`
    /// keyed by `cookie`. A cookie not currently outstanding is
    /// silently ignored. Drives the cooperative-release side of the
    /// eviction protocol.
    fn release_memory(&mut self, file: NodeId, cookie: u64);

    /// Best-effort cleanup hint when a holder is closing its cap on
    /// `node`. Cap revocation is the authoritative lifetime notification;
    /// `close` allows backends to drop cached state opportunistically.
    fn close(&mut self, node: NodeId);
}

/// Dispatch a single received namespace request and reply on its behalf.
///
/// Decodes the request's wire shape per `ns_labels::*`, applies the
/// caller-rights / visibility / name-validation checks documented in
/// `docs/namespace-model.md`, calls into `backend` for the underlying
/// storage operation, mints child caps from `namespace_endpoint` via
/// `cap_derive_badge`, and writes the reply through `ipc_reply`.
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
/// `received.badge` MUST be the badge the kernel delivered with the
/// request. A `pack(node_id, rights)` badge is dispatched; a badge with a
/// kind flag ([`badge::OPEN_INSTANCE`] or [`badge::SESSION`]) is answered
/// [`NsError::NotSupported`]. Backends do not see the wire
/// layer — they only see decoded `NodeId` / `&[u8]` / `u64`
/// arguments.
///
/// No `NS_*` request carries a cap, and this function neither reads nor
/// deletes the caps `received` carries: the server deletes every cap an
/// `NS_*` request carries, and every cap of a request it answers without
/// taking it, such as one with a label it does not serve (README § Wire
/// labels).
///
/// # Safety
///
/// `ipc_buf` must point to the calling thread's 4 KiB-aligned IPC
/// buffer page as registered via `syscall::ipc_buffer_set`.
pub unsafe fn dispatch_request<B: NamespaceBackend>(
    backend: &mut B,
    received: &ipc::IpcMessage,
    namespace_endpoint: u64,
    ipc_buf: *mut u64,
)
{
    let reply = request_reply(backend, received, namespace_endpoint);
    // SAFETY: `ipc_buf` is the registered IPC buffer page per the
    // function-level safety contract.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// The reply [`dispatch_request`] sends for `received`.
fn request_reply<B: NamespaceBackend>(
    backend: &mut B,
    received: &ipc::IpcMessage,
    namespace_endpoint: u64,
) -> ipc::IpcMessage
{
    // A kind-flagged badge's low bits are an open or session id, not a
    // NodeId (badge::is_kind_flagged): decoding one as a node would act on
    // whichever node shares the number.
    if badge::is_kind_flagged(received.badge)
    {
        return ipc::IpcMessage::new(NsError::NotSupported.as_label());
    }
    match received.label & 0xFFFF
    {
        ipc::ns_labels::NS_LOOKUP => handle_lookup(backend, received, namespace_endpoint),
        ipc::ns_labels::NS_STAT => handle_stat(backend, received),
        ipc::ns_labels::NS_READDIR => handle_readdir(backend, received),
        _ => ipc::IpcMessage::new(NsError::NotSupported.as_label()),
    }
}

/// Decode an `NS_LOOKUP` request's `caller_requested` word into a
/// [`NamespaceRights`] mask. The `0xFFFF` sentinel means "everything
/// I'm allowed"; any other value is taken as a rights mask with every
/// bit outside [`rights::DEFINED_MASK`] (reserved and out-of-field)
/// cleared.
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
        #[expect(
            clippy::cast_possible_truncation,
            reason = "range-safe: masking to RIGHTS_MASK (24 bits) fits u32"
        )]
        let bits = (raw_req as u32) & RIGHTS_MASK;
        NamespaceRights::from_raw(bits)
    }
}

/// Where an `NS_LOOKUP` walk ended: the entry its last consumed component
/// names, the rights composed for that entry, and the number of components
/// consumed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct WalkEnd
{
    entry: EntryView,
    rights: NamespaceRights,
    consumed: u64,
}

/// A failed `NS_LOOKUP`: the error and the zero-based index, in the
/// request's path, of the component it failed at.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct WalkError
{
    error: NsError,
    component: u64,
}

impl WalkError
{
    /// The error reply: the error's label, and the component's index in
    /// `data[0]`.
    fn reply(self) -> ipc::IpcMessage
    {
        ipc::IpcMessage::builder(self.error.as_label())
            .word(0, self.component)
            .build()
    }
}

fn handle_lookup<B: NamespaceBackend>(
    backend: &mut B,
    msg: &ipc::IpcMessage,
    namespace_endpoint: u64,
) -> ipc::IpcMessage
{
    let (parent, parent_rights) = badge::unpack(msg.badge);
    if !parent_rights.contains(rights::LOOKUP)
    {
        return ipc::IpcMessage::new(NsError::PermissionDenied.as_label());
    }
    let caller_requested = decode_caller_requested(msg.word(0));
    let walked = lookup_path(msg)
        .and_then(|path| walk_path(backend, parent, parent_rights, path, caller_requested));
    let end = match walked
    {
        Ok(end) => end,
        Err(err) => return err.reply(),
    };
    let child_cap = match mint_entry_cap(end.entry.target, end.rights, namespace_endpoint)
    {
        Ok(cap) => cap,
        Err(error) =>
        {
            let component = end.consumed.saturating_sub(1);
            return WalkError { error, component }.reply();
        }
    };

    ipc::IpcMessage::builder(0)
        .word(0, end.entry.kind as u64)
        .word(1, end.entry.size_hint)
        .word(2, end.consumed)
        .cap(child_cap)
        .build()
}

/// The path of an `NS_LOOKUP` request: its `/`-separated components, each
/// of which passes [`validate_name`].
///
/// # Errors
///
/// [`NsError::InvalidName`] at component 0 when the label's length is zero,
/// longer than [`MAX_LOOKUP_PATH_LEN`], or longer than the request's data;
/// at the first component that fails [`validate_name`] (an empty one, from a
/// leading, trailing or doubled `/`, included) otherwise.
fn lookup_path(msg: &ipc::IpcMessage) -> Result<&[u8], WalkError>
{
    let path_len = ((msg.label >> 16) & 0xFFFF) as usize;
    // The rights word takes data bytes 0..8; the path starts at byte 8.
    let path = msg
        .data_bytes()
        .get(8..)
        .and_then(|rest| rest.get(..path_len))
        .filter(|_| path_len != 0 && path_len <= MAX_LOOKUP_PATH_LEN)
        .ok_or(WalkError {
            error: NsError::InvalidName,
            component: 0,
        })?;
    for (component, name) in (0u64..).zip(path.split(|&b| b == b'/'))
    {
        if validate_name(name).is_err()
        {
            return Err(WalkError {
                error: NsError::InvalidName,
                component,
            });
        }
    }
    Ok(path)
}

/// Walk `path` from directory `dir`, which the caller holds with
/// `dir_rights`, applying at each component the checks a separate
/// `NS_LOOKUP` of that component applies: the parent must hold `LOOKUP`,
/// the backend resolves the name, and [`compose_lookup_rights`] filters
/// visibility and composes the entry's rights, which are the parent rights of
/// the next component.
///
/// The walk ends at the last component; at an entry that is not
/// [`EntryTarget::Local`], whose next components another server resolves;
/// and at a directory the backend does not continue walks into
/// ([`NamespaceBackend::continues_walk`]). A local entry that is not a
/// directory, with components left after it, fails the walk.
///
/// # Errors
///
/// The [`WalkError`] of the first component that fails:
/// [`NsError::PermissionDenied`] when its parent lacks `LOOKUP` or its
/// composed rights are empty, [`NsError::NotFound`] when it is absent or
/// hidden, [`NsError::NotADirectory`] when it is a local file with
/// components after it, and the backend's own error from
/// [`NamespaceBackend::lookup`].
fn walk_path<B: NamespaceBackend>(
    backend: &mut B,
    dir: NodeId,
    dir_rights: NamespaceRights,
    path: &[u8],
    caller_requested: NamespaceRights,
) -> Result<WalkEnd, WalkError>
{
    let mut parent = dir;
    let mut parent_rights = dir_rights;
    let mut component = 0u64;
    let mut names = path.split(|&b| b == b'/').peekable();
    while let Some(name) = names.next()
    {
        let at = |error| WalkError { error, component };
        if !parent_rights.contains(rights::LOOKUP)
        {
            return Err(at(NsError::PermissionDenied));
        }
        let entry = backend.lookup(parent, name).map_err(at)?;
        let rights = compose_lookup_rights(parent_rights, &entry, caller_requested).map_err(at)?;
        // A path holds at most `MAX_LOOKUP_PATH_LEN` components, so the count
        // does not saturate.
        let consumed = component.saturating_add(1);
        let end = WalkEnd {
            entry,
            rights,
            consumed,
        };
        let EntryTarget::Local(node) = entry.target
        else
        {
            return Ok(end);
        };
        if names.peek().is_none()
        {
            return Ok(end);
        }
        if entry.kind != NodeKind::Dir
        {
            return Err(at(NsError::NotADirectory));
        }
        if !backend.continues_walk(node)
        {
            return Ok(end);
        }
        parent = node;
        parent_rights = rights;
        component = consumed;
    }
    // `split` yields at least one item, so the loop returns before this.
    Err(WalkError {
        error: NsError::InvalidName,
        component: 0,
    })
}

/// Mint the cap an `NS_LOOKUP` returns for an entry at `target`, carrying
/// `rights`: on this server's `namespace_endpoint` for a local entry, on the
/// peer's unbadged endpoint for an external one.
///
/// # Errors
///
/// [`NsError::OutOfResources`] when `cap_derive_badge` fails.
fn mint_entry_cap(
    target: EntryTarget,
    rights: NamespaceRights,
    namespace_endpoint: u64,
) -> Result<u64, NsError>
{
    let (endpoint, node) = match target
    {
        EntryTarget::Local(node) => (namespace_endpoint, node),
        // Mount-boundary crossing: the badge is derived from the peer's
        // unbadged endpoint, rather than copied from a pre-badged mount cap,
        // because the kernel forbids re-badging an already-badged cap
        // (`SYS_CAP_DERIVE_BADGE` rejects a badged source), so a stored badged
        // cap could only ever be copied at its original full rights.
        EntryTarget::External { endpoint, node } => (endpoint, node),
    };
    // SEND_GRANT lets the holder attach caps to IPC requests through the
    // node cap (e.g. the release-endpoint SEND that travels in `caps[0]` of
    // `FS_OPEN`, or `FS_WRITE_MEMORY`'s source page), across a mount as on
    // this server. It does not widen authority: the recipient still
    // validates every received cap. SEND-only would force the kernel to
    // reject any cap-bearing IPC.
    syscall::cap_derive_badge(
        endpoint,
        syscall_abi::RIGHTS_EP_SEND_GRANT,
        pack(node, rights),
    )
    .map_err(|_| NsError::OutOfResources)
}

/// Visibility check and rights composition for an `NS_LOOKUP` hit.
///
/// Returns `parent_rights ∩ entry.max_rights ∩ caller_requested`.
///
/// # Errors
///
/// [`NsError::NotFound`] when `parent_rights` lacks a bit of the entry's
/// `visible_requires` (hidden entries are indistinguishable from absent
/// ones); [`NsError::PermissionDenied`] when the composed rights are
/// empty, whatever the node id: a cap with no rights can do nothing,
/// and refusing it also keeps the minted badge non-zero, as
/// `cap_derive_badge` requires.
fn compose_lookup_rights(
    parent_rights: NamespaceRights,
    entry: &EntryView,
    caller_requested: NamespaceRights,
) -> Result<NamespaceRights, NsError>
{
    if !parent_rights.contains(entry.visible_requires.raw())
    {
        return Err(NsError::NotFound);
    }
    let returned = parent_rights & entry.max_rights & caller_requested;
    if returned.is_empty()
    {
        return Err(NsError::PermissionDenied);
    }
    Ok(returned)
}

fn handle_stat<B: NamespaceBackend>(backend: &mut B, msg: &ipc::IpcMessage) -> ipc::IpcMessage
{
    let (node, node_rights) = badge::unpack(msg.badge);
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
    let (dir, dir_rights) = badge::unpack(msg.badge);
    if !dir_rights.contains(rights::READDIR)
    {
        return ipc::IpcMessage::new(NsError::PermissionDenied.as_label());
    }
    // An index beyond u32 cannot name an entry: no backend directory
    // holds 2^32 entries, so it is past the end.
    let Ok(idx) = u32::try_from(msg.word(0))
    else
    {
        return ipc::IpcMessage::new(ipc::fs_labels::END_OF_DIR);
    };
    match nth_visible_entry(backend, dir, dir_rights, idx)
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

/// Return the `idx`-th entry of `dir` that a caller holding `rights` can
/// see, or `Ok(None)` past the last one.
///
/// Hidden entries (those whose `visible_requires` `rights` does not
/// contain) are skipped without contributing to the index, so the
/// client's index counts visible entries only and hidden and absent
/// entries are indistinguishable. When the backend reports that `dir`
/// hides nothing ([`NamespaceBackend::may_hide_entries`]), backend and
/// visible indices coincide and `idx` is served directly; otherwise the
/// scan restarts at backend index 0 on every request, so a full listing
/// costs O(n²) backend calls.
#[expect(
    clippy::large_stack_frames,
    reason = "the `EntryName`s (about 264 B each) of the `readdir_entry` results and the returned \
              `Result<Option<EntryName>, NsError>` temporaries; on its caller's stack, 32 KiB at \
              the smallest (a std service's main thread)"
)]
fn nth_visible_entry<B: NamespaceBackend>(
    backend: &mut B,
    dir: NodeId,
    rights: NamespaceRights,
    idx: u32,
) -> Result<Option<EntryName>, NsError>
{
    if !backend.may_hide_entries(dir)
    {
        match backend.readdir_entry(dir, idx)?
        {
            None => return Ok(None),
            Some(entry) if rights.contains(entry.visible_requires.raw()) =>
            {
                return Ok(Some(entry));
            }
            // A hidden entry contradicts the backend's report; the scan
            // below still enforces the filter.
            Some(_) =>
            {}
        }
    }
    let mut visible = 0u32;
    let mut backend_idx = 0u32;
    loop
    {
        let Some(entry) = backend.readdir_entry(dir, backend_idx)?
        else
        {
            return Ok(None);
        };
        if rights.contains(entry.visible_requires.raw())
        {
            if visible == idx
            {
                return Ok(Some(entry));
            }
            // `visible < idx` here, so the count cannot pass `u32::MAX`.
            visible = visible.saturating_add(1);
        }
        let Some(next) = backend_idx.checked_add(1)
        else
        {
            return Ok(None);
        };
        backend_idx = next;
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn entry_name_round_trips_through_as_bytes()
    {
        let n = EntryName::new(b"hello", NodeKind::File, NamespaceRights::NONE).unwrap();
        assert_eq!(n.as_bytes(), b"hello");
        assert_eq!(n.kind, NodeKind::File);
    }

    #[test]
    fn entry_name_rejects_oversize_input()
    {
        let too_long = [b'x'; MAX_NAME_LEN + 1];
        assert!(EntryName::new(&too_long, NodeKind::File, NamespaceRights::NONE).is_none());
    }

    #[test]
    fn entry_name_accepts_max_length_input()
    {
        let max = [b'x'; MAX_NAME_LEN];
        let n = EntryName::new(&max, NodeKind::Dir, NamespaceRights::NONE).unwrap();
        assert_eq!(n.as_bytes().len(), MAX_NAME_LEN);
        assert_eq!(n.kind, NodeKind::Dir);
    }

    #[test]
    fn node_kind_discriminants_are_stable_wire_values()
    {
        assert_eq!(NodeKind::File as u64, 0);
        assert_eq!(NodeKind::Dir as u64, 1);
    }

    fn entry(max: u32, visible_requires: u32) -> EntryView
    {
        EntryView {
            target: EntryTarget::Local(NodeId::ROOT),
            kind: NodeKind::File,
            size_hint: 0,
            max_rights: NamespaceRights::from_raw(max),
            visible_requires: NamespaceRights::from_raw(visible_requires),
        }
    }

    #[test]
    fn lookup_rights_are_intersection_of_parent_entry_and_request()
    {
        let parent = NamespaceRights::from_raw(rights::LOOKUP | rights::READ | rights::STAT);
        let e = entry(rights::READ | rights::STAT, 0);
        let requested = NamespaceRights::from_raw(rights::READ | rights::WRITE);
        assert_eq!(
            compose_lookup_rights(parent, &e, requested),
            Ok(NamespaceRights::from_raw(rights::READ))
        );
    }

    #[test]
    fn lookup_hides_entry_whose_visibility_the_parent_lacks()
    {
        let parent = NamespaceRights::from_raw(rights::LOOKUP | rights::READ);
        let e = entry(rights::READ, rights::ADMIN);
        assert_eq!(
            compose_lookup_rights(parent, &e, NamespaceRights::ALL),
            Err(NsError::NotFound)
        );
    }

    #[test]
    fn lookup_refuses_empty_composed_rights()
    {
        // A cap with no rights can do nothing, so none is minted.
        let parent = NamespaceRights::from_raw(rights::LOOKUP);
        let e = entry(rights::READ, 0);
        assert_eq!(
            compose_lookup_rights(parent, &e, NamespaceRights::ALL),
            Err(NsError::PermissionDenied)
        );
    }

    /// In-memory directory for the readdir visibility filter: backend
    /// index `i` is `entries[i]`, a `(name, visible_requires)` pair.
    struct ListDir
    {
        entries: &'static [(&'static [u8], u32)],
        /// Backend index at which `readdir_entry` fails with `IoError`.
        fail_at: Option<u32>,
        /// Value `may_hide_entries` reports.
        hides: bool,
    }

    impl NamespaceBackend for ListDir
    {
        fn lookup(&mut self, _dir: NodeId, _name: &[u8]) -> Result<EntryView, NsError>
        {
            Err(NsError::NotFound)
        }

        fn readdir_entry(&mut self, _dir: NodeId, idx: u32) -> Result<Option<EntryName>, NsError>
        {
            if self.fail_at == Some(idx)
            {
                return Err(NsError::IoError);
            }
            Ok(self.entries.get(idx as usize).map(|&(name, vis)| {
                EntryName::new(name, NodeKind::File, NamespaceRights::from_raw(vis)).unwrap()
            }))
        }

        fn may_hide_entries(&mut self, _dir: NodeId) -> bool
        {
            self.hides
        }

        fn stat(&mut self, _node: NodeId) -> Result<NodeStat, NsError>
        {
            Err(NsError::NotSupported)
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

    const MIXED_DIR: &[(&[u8], u32)] = &[(b"a", 0), (b"secret", rights::ADMIN), (b"b", 0)];

    /// Assert that a caller holding `rights` enumerates exactly
    /// `expected`, in order, and then reaches end-of-directory.
    fn assert_listing(rights: u32, expected: &[&[u8]])
    {
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: None,
            hides: true,
        };
        let r = NamespaceRights::from_raw(rights);
        for (i, want) in (0u32..).zip(expected)
        {
            let got = nth_visible_entry(&mut dir, NodeId::ROOT, r, i)
                .unwrap()
                .unwrap();
            assert_eq!(got.as_bytes(), *want, "visible index {i}");
        }
        let past = u32::try_from(expected.len()).unwrap();
        assert!(
            nth_visible_entry(&mut dir, NodeId::ROOT, r, past)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn readdir_skips_hidden_entries_without_counting_them()
    {
        assert_listing(rights::READDIR, &[b"a", b"b"]);
    }

    #[test]
    fn readdir_lists_hidden_entries_to_a_caller_holding_their_rights()
    {
        assert_listing(rights::READDIR | rights::ADMIN, &[b"a", b"secret", b"b"]);
    }

    #[test]
    fn an_open_instance_badge_is_refused_before_it_is_read_as_a_node()
    {
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: None,
            hides: false,
        };
        let r = NamespaceRights::from_raw(rights::READDIR | rights::ADMIN);
        let mut msg = ipc::IpcMessage::builder(ipc::ns_labels::NS_READDIR)
            .word(0, 0)
            .build();
        msg.badge = pack(NodeId::new(5).expect("fits"), r);
        assert_eq!(request_reply(&mut dir, &msg, 0).label, 0);
        // The same number as an open id names no node: refused, not listed.
        msg.badge = badge::pack_open(5, r).expect("fits");
        assert_eq!(
            request_reply(&mut dir, &msg, 0).label,
            NsError::NotSupported.as_label()
        );
    }

    #[test]
    fn readdir_propagates_a_backend_error_met_while_skipping()
    {
        // The failing entry sits at backend index 1, the hidden one: a
        // caller without ADMIN asking for visible index 1 scans through it.
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: Some(1),
            hides: true,
        };
        let r = NamespaceRights::from_raw(rights::READDIR);
        assert_eq!(
            nth_visible_entry(&mut dir, NodeId::ROOT, r, 1),
            Err(NsError::IoError)
        );
    }

    #[test]
    fn readdir_rescans_when_a_backend_reporting_no_hidden_entries_returns_one()
    {
        // A backend that claims to hide nothing but returns a hidden entry
        // must not leak it: the filter still applies.
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: None,
            hides: false,
        };
        let r = NamespaceRights::from_raw(rights::READDIR);
        let got = nth_visible_entry(&mut dir, NodeId::ROOT, r, 1)
            .unwrap()
            .unwrap();
        assert_eq!(got.as_bytes(), b"b");
    }

    #[test]
    fn readdir_serves_backend_index_directly_when_nothing_is_hidden()
    {
        // With `may_hide_entries` false the requested index is the backend
        // index: index 2 is backend entry 2 with no scan from 0.
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: Some(0),
            hides: false,
        };
        let r = NamespaceRights::from_raw(rights::READDIR);
        let got = nth_visible_entry(&mut dir, NodeId::ROOT, r, 2)
            .unwrap()
            .unwrap();
        assert_eq!(got.as_bytes(), b"b");
    }

    #[test]
    fn readdir_index_beyond_u32_is_end_of_directory()
    {
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: None,
            hides: true,
        };
        let badge = pack(NodeId::ROOT, NamespaceRights::from_raw(rights::READDIR));
        let mut msg = ipc::IpcMessage::builder(ipc::ns_labels::NS_READDIR)
            .word(0, u64::from(u32::MAX) + 1)
            .build();
        msg.badge = badge;
        assert_eq!(
            handle_readdir(&mut dir, &msg).label,
            ipc::fs_labels::END_OF_DIR
        );

        // In-range control: the same request with index 0 is served, so
        // END_OF_DIR above comes from the range check, not from an empty
        // directory or a refused badge.
        let mut first = ipc::IpcMessage::builder(ipc::ns_labels::NS_READDIR)
            .word(0, 0)
            .build();
        first.badge = badge;
        assert_eq!(handle_readdir(&mut dir, &first).label, 0);
    }

    #[test]
    fn readdir_direct_path_reports_end_of_directory_without_scanning()
    {
        // `fail_at: Some(0)` proves no scan from index 0 happens.
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: Some(0),
            hides: false,
        };
        let r = NamespaceRights::from_raw(rights::READDIR);
        assert_eq!(nth_visible_entry(&mut dir, NodeId::ROOT, r, 3), Ok(None));
    }

    #[test]
    fn readdir_direct_path_propagates_a_backend_error()
    {
        let mut dir = ListDir {
            entries: MIXED_DIR,
            fail_at: Some(2),
            hides: false,
        };
        let r = NamespaceRights::from_raw(rights::READDIR);
        assert_eq!(
            nth_visible_entry(&mut dir, NodeId::ROOT, r, 2),
            Err(NsError::IoError)
        );
    }

    // ── NS_LOOKUP walks ──────────────────────────────────────────────────

    const ALL: u32 = rights::DEFINED_MASK;
    const PEER_ENDPOINT: u64 = 99;
    const LONG: &[u8] = &[b'l'; 200];

    const fn local(node: u64, kind: NodeKind, max: u32, visible_requires: u32) -> EntryView
    {
        EntryView {
            target: EntryTarget::Local(NodeId::from_raw_truncated(node)),
            kind,
            size_hint: node,
            max_rights: NamespaceRights::from_raw(max),
            visible_requires: NamespaceRights::from_raw(visible_requires),
        }
    }

    const fn dir(node: u64, max: u32) -> EntryView
    {
        local(node, NodeKind::Dir, max, 0)
    }

    const fn file(node: u64, max: u32) -> EntryView
    {
        local(node, NodeKind::File, max, 0)
    }

    /// `(parent, name, entry)`: every entry of the walk tests' tree.
    const TREE: &[(u64, &[u8], EntryView)] = &[
        (0, b"a", dir(1, ALL)),
        (1, b"b", dir(7, ALL & !rights::WRITE)),
        (
            7,
            b"f",
            file(8, rights::READ | rights::WRITE | rights::STAT),
        ),
        (
            0,
            b"ro",
            dir(
                2,
                rights::LOOKUP | rights::READDIR | rights::STAT | rights::READ,
            ),
        ),
        (2, b"w", file(9, rights::WRITE)),
        (2, b"x", dir(10, ALL)),
        (10, b"y", file(14, ALL)),
        (0, b"secret", local(3, NodeKind::Dir, ALL, rights::ADMIN)),
        (3, b"s", file(11, ALL)),
        (0, b"f", file(4, ALL)),
        (
            0,
            b"mnt",
            EntryView {
                target: EntryTarget::External {
                    endpoint: PEER_ENDPOINT,
                    node: NodeId::ROOT,
                },
                kind: NodeKind::Dir,
                size_hint: 0,
                max_rights: NamespaceRights::ALL,
                visible_requires: NamespaceRights::NONE,
            },
        ),
        (0, b"nolook", dir(5, rights::STAT | rights::READ)),
        (5, b"x", file(12, ALL)),
        (0, b"syn", dir(6, ALL)),
        (6, b"x", dir(13, ALL)),
        (0, LONG, dir(20, ALL)),
        (20, LONG, dir(21, ALL)),
        (21, LONG, file(22, ALL)),
    ];

    /// Node 6 is answered by another dispatcher, as a vfsd synthetic node
    /// with a fall-through is.
    const STOP_NODE: u64 = 6;

    struct Tree;

    impl NamespaceBackend for Tree
    {
        fn lookup(&mut self, dir: NodeId, name: &[u8]) -> Result<EntryView, NsError>
        {
            TREE.iter()
                .find(|(parent, n, _)| *parent == dir.raw() && *n == name)
                .map(|&(_, _, entry)| entry)
                .ok_or(NsError::NotFound)
        }

        fn readdir_entry(&mut self, _dir: NodeId, _idx: u32) -> Result<Option<EntryName>, NsError>
        {
            Err(NsError::NotSupported)
        }

        fn continues_walk(&mut self, dir: NodeId) -> bool
        {
            dir.raw() != STOP_NODE
        }

        fn stat(&mut self, _node: NodeId) -> Result<NodeStat, NsError>
        {
            Err(NsError::NotSupported)
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

    /// Where a client walk ended: the entry reached with its rights, or the
    /// error and the index of the failing component in the whole path.
    type Outcome = Result<(EntryView, NamespaceRights), (NsError, u64)>;

    /// The walk one component per request: each request's server checks
    /// `LOOKUP` on the badge of the cap it is sent to, looks the name up and
    /// composes its rights; the client refuses a non-final entry that is not
    /// a directory and sends the next component to the minted cap. A cap
    /// minted on another server ends the walk within this backend.
    fn per_component(dir_rights: u32, path: &[u8], requested: u32) -> Outcome
    {
        let requested = NamespaceRights::from_raw(requested);
        let mut node = NodeId::ROOT;
        let mut parent_rights = NamespaceRights::from_raw(dir_rights);
        let mut names = path.split(|&b| b == b'/').peekable();
        let mut index = 0u64;
        while let Some(name) = names.next()
        {
            if !parent_rights.contains(rights::LOOKUP)
            {
                return Err((NsError::PermissionDenied, index));
            }
            let entry = Tree.lookup(node, name).map_err(|e| (e, index))?;
            let got =
                compose_lookup_rights(parent_rights, &entry, requested).map_err(|e| (e, index))?;
            if names.peek().is_none()
            {
                return Ok((entry, got));
            }
            let EntryTarget::Local(next) = entry.target
            else
            {
                return Ok((entry, got));
            };
            if entry.kind != NodeKind::Dir
            {
                return Err((NsError::NotADirectory, index));
            }
            node = next;
            parent_rights = got;
            index += 1;
        }
        unreachable!("split yields a component")
    }

    /// The walk a client makes with [`client::PathWalk`]: each request
    /// carries the components that fit, the server walks them with
    /// [`walk_path`], and the client continues from the reached entry. Also
    /// returns the number of requests made.
    fn multi_component(dir_rights: u32, path: &[u8], requested: u32) -> (Outcome, u32)
    {
        let requested = NamespaceRights::from_raw(requested);
        let mut walk = client::PathWalk::new(path);
        let mut node = NodeId::ROOT;
        let mut parent_rights = NamespaceRights::from_raw(dir_rights);
        let mut done = 0u64;
        let mut requests = 0u32;
        let mut reached = None;
        while let Some(request) = walk.request()
        {
            requests += 1;
            let end = match walk_path(&mut Tree, node, parent_rights, request.path(), requested)
            {
                Ok(end) => end,
                Err(e) => return (Err((e.error, done + e.component)), requests),
            };
            match walk.advance(&request, end.consumed, end.entry.kind as u64)
            {
                Ok(()) =>
                {}
                Err(client::StepError::NotADirectory) =>
                {
                    return (
                        Err((NsError::NotADirectory, done + end.consumed - 1)),
                        requests,
                    );
                }
                Err(client::StepError::ConsumedOutOfRange) => panic!("consumed out of range"),
            }
            done += end.consumed;
            reached = Some((end.entry, end.rights));
            match end.entry.target
            {
                EntryTarget::Local(next) =>
                {
                    node = next;
                    parent_rights = end.rights;
                }
                EntryTarget::External { .. } => break,
            }
        }
        (reached.ok_or((NsError::InvalidName, 0)), requests)
    }

    /// Assert that the multi-component walk of `path` ends as the
    /// per-component walk does, and return that outcome.
    fn assert_same_walk(dir_rights: u32, path: &[u8], requested: u32) -> Outcome
    {
        let one = per_component(dir_rights, path, requested);
        let (multi, _) = multi_component(dir_rights, path, requested);
        assert_eq!(multi, one, "path {:?}", core::str::from_utf8(path));
        one
    }

    #[test]
    fn a_multi_component_lookup_narrows_rights_at_every_step_as_separate_lookups_do()
    {
        let (entry, got) = assert_same_walk(ALL, b"a/b/f", ALL).unwrap();
        assert_eq!(entry.target, EntryTarget::Local(NodeId::new(8).unwrap()));
        assert_eq!(got, NamespaceRights::from_raw(rights::READ | rights::STAT));
        assert_same_walk(ALL, b"a/b/f", rights::LOOKUP | rights::READ).unwrap();
        assert_same_walk(ALL, b"ro/x/y", ALL).unwrap();
        // The whole path is one request.
        assert_eq!(multi_component(ALL, b"a/b/f", ALL).1, 1);
    }

    #[test]
    fn a_hidden_component_fails_a_multi_component_lookup_as_an_absent_one()
    {
        assert_eq!(
            assert_same_walk(ALL & !rights::ADMIN, b"secret/s", ALL),
            Err((NsError::NotFound, 0))
        );
        assert_same_walk(ALL, b"secret/s", ALL).unwrap();
    }

    #[test]
    fn a_missing_component_is_reported_at_its_index()
    {
        assert_eq!(
            assert_same_walk(ALL, b"a/b/zz", ALL),
            Err((NsError::NotFound, 2))
        );
    }

    #[test]
    fn a_multi_component_lookup_ends_at_a_mount_with_the_cap_a_separate_lookup_mints()
    {
        let end = walk_path(
            &mut Tree,
            NodeId::ROOT,
            NamespaceRights::ALL,
            b"mnt/x/y",
            NamespaceRights::ALL,
        )
        .unwrap();
        assert_eq!(end.consumed, 1);
        assert_eq!(
            end.entry.target,
            EntryTarget::External {
                endpoint: PEER_ENDPOINT,
                node: NodeId::ROOT
            }
        );
        assert_same_walk(rights::LOOKUP | rights::READ, b"mnt/x/y", ALL).unwrap();
    }

    #[test]
    fn a_file_before_the_last_component_is_not_a_directory()
    {
        assert_eq!(
            assert_same_walk(ALL, b"f/x", ALL),
            Err((NsError::NotADirectory, 0))
        );
        assert_eq!(
            assert_same_walk(ALL, b"a/b/f/x", ALL),
            Err((NsError::NotADirectory, 2))
        );
    }

    #[test]
    fn a_directory_reached_without_lookup_refuses_the_next_component()
    {
        assert_eq!(
            assert_same_walk(ALL, b"nolook/x", ALL),
            Err((NsError::PermissionDenied, 1))
        );
    }

    #[test]
    fn a_component_whose_composed_rights_are_empty_is_refused()
    {
        assert_eq!(
            assert_same_walk(ALL, b"ro/w", ALL),
            Err((NsError::PermissionDenied, 1))
        );
    }

    #[test]
    fn a_walk_ends_at_a_directory_the_backend_does_not_continue_into()
    {
        let end = walk_path(
            &mut Tree,
            NodeId::ROOT,
            NamespaceRights::ALL,
            b"syn/x",
            NamespaceRights::ALL,
        )
        .unwrap();
        assert_eq!(end.consumed, 1);
        assert_eq!(
            end.entry.target,
            EntryTarget::Local(NodeId::new(STOP_NODE).unwrap())
        );
        // The client continues from the returned cap.
        assert_same_walk(ALL, b"syn/x", ALL).unwrap();
        assert_eq!(multi_component(ALL, b"syn/x", ALL).1, 2);
    }

    #[test]
    fn a_path_longer_than_one_request_walks_as_separate_lookups_do()
    {
        let mut path = [b'l'; 3 * 201 - 1];
        path[200] = b'/';
        path[401] = b'/';
        let (entry, _) = assert_same_walk(ALL, &path, ALL).unwrap();
        assert_eq!(entry.target, EntryTarget::Local(NodeId::new(22).unwrap()));
        assert_eq!(multi_component(ALL, &path, ALL).1, 2);
        // A failure in the second request names its index in the whole path.
        path[598] = b'z';
        assert_eq!(
            assert_same_walk(ALL, &path, ALL),
            Err((NsError::NotFound, 2))
        );
    }

    /// An `NS_LOOKUP` request for `path` on a root cap holding `rights`.
    fn lookup_request(path: &[u8], len: u64, rights: u32) -> ipc::IpcMessage
    {
        let mut msg = ipc::IpcMessage::builder(ipc::ns_labels::NS_LOOKUP | (len << 16))
            .word(0, 0xFFFF)
            .bytes(1, path)
            .build();
        msg.badge = pack(NodeId::ROOT, NamespaceRights::from_raw(rights));
        msg
    }

    #[test]
    fn an_ns_lookup_error_reply_names_the_failing_component()
    {
        let reply = request_reply(&mut Tree, &lookup_request(b"a/b/zz", 6, ALL), 0);
        assert_eq!(reply.label, NsError::NotFound.as_label());
        assert_eq!(reply.word(0), 2);
        assert_eq!(reply.caps(), &[] as &[u64]);
    }

    #[test]
    fn an_ns_lookup_path_with_an_empty_component_is_an_invalid_name()
    {
        for (path, index) in [(&b"a//b"[..], 1), (b"/a", 0), (b"a/", 1), (b"a/../b", 1)]
        {
            let reply = request_reply(&mut Tree, &lookup_request(path, path.len() as u64, ALL), 0);
            assert_eq!(reply.label, NsError::InvalidName.as_label(), "{path:?}");
            assert_eq!(reply.word(0), index, "{path:?}");
        }
    }

    #[test]
    fn an_ns_lookup_length_outside_the_request_is_an_invalid_name()
    {
        let too_long = (MAX_LOOKUP_PATH_LEN + 1) as u64;
        for len in [0, 7, too_long]
        {
            let reply = request_reply(&mut Tree, &lookup_request(b"a/b/f", len, ALL), 0);
            assert_eq!(reply.label, NsError::InvalidName.as_label(), "len {len}");
        }
    }

    #[test]
    fn an_ns_lookup_without_lookup_is_refused_before_its_path_is_read()
    {
        let reply = request_reply(
            &mut Tree,
            &lookup_request(b"a//b", 4, ALL & !rights::LOOKUP),
            0,
        );
        assert_eq!(reply.label, NsError::PermissionDenied.as_label());
    }
}
