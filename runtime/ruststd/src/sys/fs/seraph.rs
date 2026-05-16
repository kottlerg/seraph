// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! seraph-overlay: std::sys::fs (seraph-only)
//!
//! Hybrid `std::fs::File` backed by vfsd / fs-driver IPC.
//!
//! - Reads under one page (or that don't cross a page boundary) use the
//!   inline `FS_READ` path; payload bytes ride in the IPC buffer.
//! - Larger reads use `FS_READ_FRAME`: the driver returns a Frame cap
//!   covering one cached page; we reserve VA, `mem_map` it read-only,
//!   memcpy out, then proactively release the cache slot via
//!   `FS_RELEASE_FRAME` and tear the mapping down locally.
//!
//! Per-`File` release-endpoint plumbing: a tokened derivation off the
//! per-process release endpoint owned by [`release_handler`] is
//! allocated on every open and transferred to the driver via
//! `caps[0]` of the first [`fs_labels::FS_READ_FRAME`] request for
//! that `File`. The driver records it on the file's `OpenFile` slot;
//! its eviction worker uses it to issue cooperative
//! [`fs_labels::FS_RELEASE_FRAME`] back to us before falling through
//! to hard-revoke. Files that never trigger a frame-read (only
//! inline `FS_READ`) never deliver the cap and get the hard-revoke
//! fallback; the cap is deleted in `Drop`.
//!
//! v1 supports read-only `File` only; write/append/truncate/create are
//! Unsupported. Directory ops, symlinks, metadata mutation, locking,
//! and times are Unsupported.
//!
//! `File::open` walks the path one component at a time via `NS_LOOKUP`
//! against the per-process root directory cap installed by `_start`
//! from `ProcessInfo.system_root_cap`. If the root cap is unset,
//! `File::open` returns `Unsupported`. The inline `FS_READ` path
//! issues `FS_READ` directly against the node cap returned by the
//! final `NS_LOOKUP`; `FS_READ_FRAME` / `FS_RELEASE_FRAME` are
//! preserved verbatim for future cap-native frame-reads.

#![forbid(unsafe_op_in_unsafe_fn)]

use crate::ffi::OsString;
use crate::fmt;
use crate::fs::TryLockError;
use crate::hash::{Hash, Hasher};
use crate::io::{self, BorrowedCursor, IoSlice, IoSliceMut, SeekFrom};
use crate::path::{Path, PathBuf};
pub use crate::sys::fs::common::Dir;
use crate::sync::Arc;
use crate::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use crate::vec::Vec;
use crate::sys::time::SystemTime;
use crate::sys::{unsupported, unsupported_err};

use ipc::{IpcMessage, fs_errors, fs_labels, ns_labels};
use namespace_protocol::{NodeKind, NsError, validate_name};
use syscall_abi::PAGE_SIZE;

// `release_handler` lives in a sibling file (not a subdirectory),
// because the upstream `library/std/src/sys/fs/` directory mixes
// per-target single-file modules (`unsupported.rs`, `motor.rs`, …) with
// per-target subdirectory modules (`unix/`, `windows/`). The explicit
// `#[path]` keeps our extra file alongside `seraph.rs` rather than
// forcing a `seraph/` directory just to host it.
#[path = "release_handler.rs"]
mod release_handler;

use release_handler::{FileEntry, OutstandingMapping};

const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;

/// Per-call crossover threshold between the inline FS_READ path and the
/// zero-copy FS_READ_FRAME path. A `read()` of at most this many bytes
/// that also fits within the current page goes inline; anything larger
/// or page-straddling takes the frame path.
///
/// 504 is the FS_READ IPC reply ceiling: 63 data words × 8 bytes minus
/// the 8-byte length prefix in word 0 (`abi/syscall/MSG_DATA_WORDS_MAX`).
/// At or below this size, a single FS_READ carries the bytes. The
/// `fsbench` numbers in `services/fs/docs/fs-driver-protocol.md` show
/// inline is roughly 2× cheaper per call on both x86_64 and riscv64,
/// so 504 also happens to be the smallest size at which any larger
/// would force ≥ 2 inline calls and lose to one frame call.
const READ_INLINE_THRESHOLD: usize = 504;

// ── Public type stubs ─────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default)]
pub struct FileTimes {}

impl FileTimes
{
    pub fn set_accessed(&mut self, _: SystemTime) {}
    pub fn set_modified(&mut self, _: SystemTime) {}
}

#[derive(Clone, Debug)]
pub struct OpenOptions
{
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
}

impl OpenOptions
{
    pub fn new() -> OpenOptions
    {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
        }
    }

    pub fn read(&mut self, b: bool) { self.read = b; }
    pub fn write(&mut self, b: bool) { self.write = b; }
    pub fn append(&mut self, b: bool) { self.append = b; }
    pub fn truncate(&mut self, b: bool) { self.truncate = b; }
    pub fn create(&mut self, b: bool) { self.create = b; }
    pub fn create_new(&mut self, b: bool) { self.create_new = b; }
}

#[derive(Debug)]
pub struct DirBuilder {}

impl DirBuilder
{
    pub fn new() -> DirBuilder { DirBuilder {} }
    pub fn mkdir(&self, _: &Path) -> io::Result<()> { unsupported() }
}

// ── FileAttr / FilePermissions / FileType ─────────────────────────────────

pub struct FileAttr
{
    size: u64,
}

impl FileAttr
{
    pub fn size(&self) -> u64 { self.size }
    pub fn perm(&self) -> FilePermissions { FilePermissions { readonly: true } }
    pub fn file_type(&self) -> FileType
    {
        FileType { is_dir: false, is_file: true, is_symlink: false }
    }
    pub fn modified(&self) -> io::Result<SystemTime> { unsupported() }
    pub fn accessed(&self) -> io::Result<SystemTime> { unsupported() }
    pub fn created(&self) -> io::Result<SystemTime> { unsupported() }
}

impl Clone for FileAttr
{
    fn clone(&self) -> FileAttr { FileAttr { size: self.size } }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FilePermissions
{
    readonly: bool,
}

impl FilePermissions
{
    pub fn readonly(&self) -> bool { self.readonly }
    pub fn set_readonly(&mut self, r: bool) { self.readonly = r; }
}

impl fmt::Debug for FilePermissions
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.debug_struct("FilePermissions")
            .field("readonly", &self.readonly)
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileType
{
    is_dir: bool,
    is_file: bool,
    is_symlink: bool,
}

impl FileType
{
    pub fn is_dir(&self) -> bool { self.is_dir }
    pub fn is_file(&self) -> bool { self.is_file }
    pub fn is_symlink(&self) -> bool { self.is_symlink }
}

impl Hash for FileType
{
    fn hash<H: Hasher>(&self, h: &mut H)
    {
        self.is_dir.hash(h);
        self.is_file.hash(h);
        self.is_symlink.hash(h);
    }
}

impl fmt::Debug for FileType
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.debug_struct("FileType")
            .field("is_dir", &self.is_dir)
            .field("is_file", &self.is_file)
            .field("is_symlink", &self.is_symlink)
            .finish()
    }
}

// ReadDir / DirEntry are uninhabited — readdir is Unsupported on v1.
pub struct ReadDir(!);

impl Iterator for ReadDir
{
    type Item = io::Result<DirEntry>;
    fn next(&mut self) -> Option<Self::Item> { self.0 }
}

impl fmt::Debug for ReadDir
{
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result { self.0 }
}

pub struct DirEntry(!);

impl DirEntry
{
    pub fn path(&self) -> PathBuf { self.0 }
    pub fn file_name(&self) -> OsString { self.0 }
    pub fn metadata(&self) -> io::Result<FileAttr> { self.0 }
    pub fn file_type(&self) -> io::Result<FileType> { self.0 }
}

// ── Path walk ─────────────────────────────────────────────────────────────

/// Result of [`walk_path_to_file`].
pub(crate) struct WalkedFile
{
    /// Tokened SEND addressing the resolved file node. Caller owns and
    /// must `cap_delete` when no longer needed.
    pub file_cap: u32,
    /// Size of the file as reported by the final `NS_LOOKUP`'s size hint.
    pub size: u64,
}

/// Result of [`walk_path_to_dir`].
pub(crate) struct WalkedDir
{
    /// Tokened SEND addressing the resolved directory node. Caller owns
    /// and must `cap_delete` when no longer needed.
    pub dir_cap: u32,
}

/// Walk `path_str` from `root_cap` via per-component `NS_LOOKUP`.
///
/// Splits on `/`, drops empty segments, validates component names per
/// the namespace-protocol rules. Every hop (including the final) must
/// resolve to a directory. Returns a freshly derived tokened SEND on
/// the directory. On any error the helper deletes any partial cap it
/// owns before returning.
///
/// Used by `Command::spawn` (path-based cwd resolution) and by
/// `std::env::set_current_dir`.
pub(crate) fn walk_path_to_dir(
    root_cap: u32,
    path_str: &str,
    ipc_buf: *mut u64,
) -> io::Result<WalkedDir>
{
    let walked = walk_components(root_cap, path_str, ipc_buf, ExpectKind::Dir)?;
    Ok(WalkedDir { dir_cap: walked.cap })
}

/// Walk `path_str` from `root_cap` via per-component `NS_LOOKUP`.
///
/// Splits on `/`, drops empty segments, validates component names per
/// the namespace-protocol rules. Each non-final hop must resolve to a
/// directory; the final hop must resolve to a file. Returns a freshly
/// derived tokened SEND on the file plus its size hint. On any error
/// the helper deletes any partial cap it owns before returning.
///
/// Used by `File::open` and by `Command::spawn` (binary lookup); both
/// callers wrap the result with their own per-handle bookkeeping.
pub(crate) fn walk_path_to_file(
    root_cap: u32,
    path_str: &str,
    ipc_buf: *mut u64,
) -> io::Result<WalkedFile>
{
    let walked = walk_components(root_cap, path_str, ipc_buf, ExpectKind::File)?;
    Ok(WalkedFile {
        file_cap: walked.cap,
        size: walked.size,
    })
}

/// Expected kind of the final path component for [`walk_components`].
enum ExpectKind
{
    Dir,
    File,
}

/// Internal: result of a generic component walk.
struct WalkedNode
{
    cap: u32,
    size: u64,
}

/// Internal kind-parameterised walk shared by [`walk_path_to_file`] and
/// [`walk_path_to_dir`].
fn walk_components(
    root_cap: u32,
    path_str: &str,
    ipc_buf: *mut u64,
    expect_kind: ExpectKind,
) -> io::Result<WalkedNode>
{
    let path_bytes = path_str.as_bytes();
    let components: Vec<&[u8]> = path_bytes
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    if components.is_empty()
    {
        return Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "seraph fs: path resolves to no components",
        ));
    }
    for c in &components
    {
        if validate_name(c).is_err()
        {
            return Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "seraph fs: invalid path component",
            ));
        }
    }

    // Walk: hold one cap at a time. `current_cap` starts as the
    // shared root cap (do not delete on advance). After the first hop
    // it points at a freshly-derived child cap that we own and must
    // `cap_delete` when we move past it.
    let mut current_cap = root_cap;
    let mut current_owns = false;
    let mut size_hint: u64 = 0;

    let last_idx = components.len() - 1;
    for (i, &name) in components.iter().enumerate()
    {
        let is_last = i == last_idx;
        // Cap-native rights model: server intersects
        // `parent_rights & entry.max_rights & caller_requested`.
        // Asking for `0xFFFF` (everything I'm allowed) on every hop
        // is the only shape that lets the final cap come back with
        // READ when the chain's parents had READ available.
        let requested_rights: u64 = 0xFFFF;
        let label = ns_labels::NS_LOOKUP | ((name.len() as u64) << 16);
        let msg = IpcMessage::builder(label)
            .word(0, requested_rights)
            .bytes(1, name)
            .build();

        // SAFETY: ipc_buf is the registered IPC buffer for this thread.
        let reply = match unsafe { ipc::ipc_call(current_cap, &msg, ipc_buf) }
        {
            Ok(r) => r,
            Err(_) =>
            {
                if current_owns
                {
                    let _ = syscall::cap_delete(current_cap);
                }
                return Err(io::Error::other("seraph fs: NS_LOOKUP ipc_call failed"));
            }
        };
        if reply.label != 0
        {
            if current_owns
            {
                let _ = syscall::cap_delete(current_cap);
            }
            let base = ns_error_to_io(reply.label);
            let name_str = core::str::from_utf8(name).unwrap_or("<non-utf8>");
            return Err(io::Error::new(
                base.kind(),
                crate::format!("seraph fs: NS_LOOKUP failed at component {name_str:?}"),
            ));
        }
        let kind = reply.word(0);
        let entry_size = reply.word(1);
        let next_cap = match reply.caps().first()
        {
            Some(&c) => c,
            None =>
            {
                if current_owns
                {
                    let _ = syscall::cap_delete(current_cap);
                }
                return Err(io::Error::other(
                    "seraph fs: NS_LOOKUP reply missing child cap",
                ));
            }
        };

        if !is_last && kind != NodeKind::Dir as u64
        {
            let _ = syscall::cap_delete(next_cap);
            if current_owns
            {
                let _ = syscall::cap_delete(current_cap);
            }
            return Err(io::const_error!(
                io::ErrorKind::NotADirectory,
                "seraph fs: non-final path component is not a directory",
            ));
        }
        if is_last
        {
            match expect_kind
            {
                ExpectKind::File if kind == NodeKind::Dir as u64 =>
                {
                    let _ = syscall::cap_delete(next_cap);
                    if current_owns
                    {
                        let _ = syscall::cap_delete(current_cap);
                    }
                    return Err(io::const_error!(
                        io::ErrorKind::IsADirectory,
                        "seraph fs: target path is a directory",
                    ));
                }
                ExpectKind::Dir if kind != NodeKind::Dir as u64 =>
                {
                    let _ = syscall::cap_delete(next_cap);
                    if current_owns
                    {
                        let _ = syscall::cap_delete(current_cap);
                    }
                    return Err(io::const_error!(
                        io::ErrorKind::NotADirectory,
                        "seraph fs: target path is not a directory",
                    ));
                }
                _ => {}
            }
        }

        if current_owns
        {
            let _ = syscall::cap_delete(current_cap);
        }
        current_cap = next_cap;
        current_owns = true;
        size_hint = entry_size;
    }

    Ok(WalkedNode {
        cap: current_cap,
        size: size_hint,
    })
}

// ── File ──────────────────────────────────────────────────────────────────

pub struct File
{
    /// Per-file node capability returned by the final `NS_LOOKUP` of
    /// the open walk. Receives every file-scoped op (FS_READ,
    /// FS_READ_FRAME, FS_CLOSE, synchronous client-initiated
    /// FS_RELEASE_FRAME).
    file_cap: u32,
    /// Token identifying this `File` for the release-handler dispatch.
    /// Carried inside the per-process release endpoint so an inbound
    /// `FS_RELEASE_FRAME` from the driver routes to this `File`'s
    /// outstanding-mappings registry.
    token: u64,
    /// Tokened SEND on the per-process release endpoint. We retain
    /// the parent in our CSpace; on Drop we delete it so any
    /// in-flight forced release fails cleanly at the kernel.
    release_send: u32,
    /// True once the per-process release-endpoint SEND has been
    /// transmitted to the driver via `caps[0]` of an `FS_READ_FRAME`
    /// request. Set on first successful frame-read; subsequent reads
    /// omit the cap so the kernel does not perform a wasted transfer.
    /// `swap` is the only mutator — first reader wins under contention.
    release_delivered: AtomicBool,
    /// Process aspace cap, captured at open for `mem_map` / `mem_unmap`.
    aspace: u32,
    /// Per-file outstanding-mappings registration in the handler.
    entry: Arc<FileEntry>,
    /// Current read offset; advanced by every successful `read`.
    pos: AtomicU64,
    /// File size from the final `NS_LOOKUP`'s `size_hint`. v1 is
    /// read-only so this never changes after open.
    size: u64,
}

impl File
{
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File>
    {
        if !opts.read || opts.write || opts.append || opts.truncate || opts.create || opts.create_new
        {
            // v1: read-only File. Anything else is a usage bug for now;
            // surface as Unsupported rather than silently ignoring the
            // requested mode bits.
            return unsupported();
        }
        let path_str = path
            .to_str()
            .ok_or_else(|| io::const_error!(io::ErrorKind::InvalidInput, "seraph fs: non-UTF-8 path"))?;
        // Anchor the walk: leading `/` → walk from `root_dir_cap()`;
        // anything else → walk from `current_dir_cap()`. The walk
        // helper itself strips empty leading components, so passing
        // the path through as-is is correct in either case.
        let anchor_cap = if path_str.starts_with('/') {
            crate::os::seraph::root_dir_cap()
        } else {
            crate::os::seraph::current_dir_cap()
        };
        if anchor_cap == 0
        {
            return Err(io::const_error!(
                io::ErrorKind::Unsupported,
                "seraph fs: no anchor dir cap for this path \
                 (root_dir_cap zero for absolute paths; current_dir_cap \
                  zero for relative paths)",
            ));
        }
        let info = crate::os::seraph::try_startup_info().ok_or_else(|| {
            io::Error::other("seraph fs: startup info not installed")
        })?;
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            return Err(io::Error::other("seraph fs: IPC buffer not registered"));
        }

        // Allocate the per-`File` release-endpoint plumbing up front.
        // The `release_send` cap is unused on the inline `FS_READ`
        // path; on the first `FS_READ_FRAME` it is transferred to the
        // driver in `caps[0]` so the driver's eviction worker can
        // route cooperative `FS_RELEASE_FRAME` back here. On any
        // walk-failure path below the setup is rolled back
        // (cap_delete + unregister) so a refused open never leaks an
        // entry into the release handler.
        let state = release_handler::ensure_started()?;
        let token = release_handler::allocate_token(state);
        let entry = release_handler::register(state, token);

        let release_ep = release_handler::release_endpoint(state);
        let release_send =
            match syscall::cap_derive_token(release_ep, syscall::RIGHTS_SEND, token)
            {
                Ok(c) => c,
                Err(_) =>
                {
                    let _ = release_handler::unregister(state, token);
                    return Err(io::Error::other(
                        "seraph fs: cap_derive_token (release send) failed",
                    ));
                }
            };

        let walked = match walk_path_to_file(anchor_cap, path_str, ipc_buf)
        {
            Ok(w) => w,
            Err(e) =>
            {
                let _ = syscall::cap_delete(release_send);
                let _ = release_handler::unregister(state, token);
                return Err(e);
            }
        };

        Ok(File {
            file_cap: walked.file_cap,
            token,
            release_send,
            release_delivered: AtomicBool::new(false),
            aspace: info.self_aspace,
            entry,
            pos: AtomicU64::new(0),
            size: walked.size,
        })
    }

    pub fn file_attr(&self) -> io::Result<FileAttr> { Ok(FileAttr { size: self.size }) }
    pub fn fsync(&self) -> io::Result<()> { Ok(()) }
    pub fn datasync(&self) -> io::Result<()> { Ok(()) }
    pub fn lock(&self) -> io::Result<()> { unsupported() }
    pub fn lock_shared(&self) -> io::Result<()> { unsupported() }
    pub fn try_lock(&self) -> Result<(), TryLockError>
    {
        Err(TryLockError::Error(unsupported_err()))
    }
    pub fn try_lock_shared(&self) -> Result<(), TryLockError>
    {
        Err(TryLockError::Error(unsupported_err()))
    }
    pub fn unlock(&self) -> io::Result<()> { unsupported() }
    pub fn truncate(&self, _: u64) -> io::Result<()> { unsupported() }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize>
    {
        if buf.is_empty()
        {
            return Ok(0);
        }
        let pos = self.pos.load(Ordering::Relaxed);
        if pos >= self.size
        {
            return Ok(0);
        }
        let remaining = self.size - pos;
        let want = (buf.len() as u64).min(remaining) as usize;

        // Inline path: small reads or page-tail reads that don't cross a
        // page boundary. Threshold equals the FS_READ IPC payload
        // ceiling: 63 data words × 8 bytes = 504, minus the 8-byte
        // length prefix in word 0. Above this a single inline reply
        // cannot carry the bytes; below this the per-call cost is
        // strictly cheaper than the frame path on both x86_64 and
        // riscv64 (≈ 2× factor; see fsbench numbers recorded in
        // `services/fs/docs/fs-driver-protocol.md`).
        let page_off = (pos % PAGE_SIZE) as usize;
        if want <= READ_INLINE_THRESHOLD && page_off + want <= PAGE_SIZE_USIZE
        {
            return self.read_inline(buf, pos, want);
        }
        self.read_frame(buf, pos)
    }

    fn read_inline(&self, buf: &mut [u8], pos: u64, want: usize) -> io::Result<usize>
    {
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        let msg = IpcMessage::builder(fs_labels::FS_READ)
            .word(0, pos)
            .word(1, want as u64)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(self.file_cap, &msg, ipc_buf) }
            .map_err(|_| io::Error::other("seraph fs: FS_READ ipc_call failed"))?;
        if reply.label != fs_errors::SUCCESS
        {
            return Err(map_fs_error(reply.label));
        }
        let bytes_read = reply.word(0) as usize;
        let payload = reply
            .data_bytes()
            .get(core::mem::size_of::<u64>()..)
            .unwrap_or(&[]);
        let copy_len = bytes_read.min(buf.len()).min(payload.len());
        buf[..copy_len].copy_from_slice(&payload[..copy_len]);
        self.pos.fetch_add(copy_len as u64, Ordering::Relaxed);
        Ok(copy_len)
    }

    fn read_frame(&self, buf: &mut [u8], pos: u64) -> io::Result<usize>
    {
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        let cookie = next_cookie();
        // First FS_READ_FRAME for this File carries the per-process
        // release-endpoint SEND in caps[0]; the driver records it on
        // the OpenFile slot's first allocation so the eviction worker
        // can route cooperative FS_RELEASE_FRAME back to us instead
        // of hard-revoking the page. `swap` ensures only one concurrent
        // reader attempts the transfer — the kernel `transfer_caps`
        // path moves the cap out of our CSpace, leaving the source slot
        // null, so a second concurrent attempt would fail at kernel
        // pre-validation.
        let send_release = !self.release_delivered.swap(true, Ordering::Relaxed);
        let mut builder = IpcMessage::builder(fs_labels::FS_READ_FRAME)
            .word(0, pos)
            .word(1, cookie);
        if send_release
        {
            builder = builder.cap(self.release_send);
        }
        let msg = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(self.file_cap, &msg, ipc_buf) }
            .map_err(|_| io::Error::other("seraph fs: FS_READ_FRAME ipc_call failed"))?;
        if reply.label != fs_errors::SUCCESS
        {
            return Err(map_fs_error(reply.label));
        }
        let bytes_valid = reply.word(0) as usize;
        let frame_data_offset = reply.word(2) as usize;
        let caps = reply.caps();
        if bytes_valid == 0 || caps.is_empty()
        {
            return Ok(0);
        }
        let frame_cap = caps[0];

        let range = match crate::sys::reserve::reserve_pages(1)
        {
            Ok(r) => r,
            Err(_) =>
            {
                let _ = syscall::cap_delete(frame_cap);
                self.release_frame(cookie);
                return Err(io::Error::other("seraph fs: reserve_pages failed"));
            }
        };
        let va = range.va_start();
        if syscall::mem_map(frame_cap, self.aspace, va, 0, 1, syscall::MAP_READONLY).is_err()
        {
            crate::sys::reserve::unreserve_pages(range);
            let _ = syscall::cap_delete(frame_cap);
            self.release_frame(cookie);
            return Err(io::Error::other("seraph fs: mem_map failed"));
        }

        // Register the mapping with the release handler before exposing
        // it to the local copy: a forced release racing in must observe
        // the entry so it can clean up if it wins. Local cleanup below
        // wins via take_mapping if we ack first.
        release_handler::add_mapping(
            self.entry.as_ref(),
            OutstandingMapping {
                cookie,
                range,
                frame_cap,
            },
        );

        let copy_len = bytes_valid.min(buf.len());
        // SAFETY: VA is mapped read-only for one page; the fs invariant
        // is `frame_data_offset + bytes_valid <= PAGE_SIZE`.
        let src = unsafe {
            core::slice::from_raw_parts(
                (va + frame_data_offset as u64) as *const u8,
                bytes_valid,
            )
        };
        buf[..copy_len].copy_from_slice(&src[..copy_len]);
        self.pos.fetch_add(copy_len as u64, Ordering::Relaxed);

        // Proactive release: synchronous FS_RELEASE_FRAME on the file
        // cap clears the fs-side outstanding entry and decrements the
        // cache slot's refcount. After ack we own the local cleanup
        // (take_mapping is no-op if the handler thread already grabbed
        // it via a forced-release race).
        self.release_frame(cookie);
        release_handler::release_one_local(self.entry.as_ref(), self.aspace, cookie);

        Ok(copy_len)
    }

    fn release_frame(&self, cookie: u64)
    {
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        let msg = IpcMessage::builder(fs_labels::FS_RELEASE_FRAME)
            .word(0, cookie)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer. Failure is
        // non-fatal — the fs will reclaim the slot at FS_CLOSE time.
        let _ = unsafe { ipc::ipc_call(self.file_cap, &msg, ipc_buf) };
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize>
    {
        for b in bufs.iter_mut()
        {
            if !b.is_empty()
            {
                return self.read(b);
            }
        }
        Ok(0)
    }
    pub fn is_read_vectored(&self) -> bool { false }
    pub fn read_buf(&self, mut cursor: BorrowedCursor<'_>) -> io::Result<()>
    {
        let mut tmp = [0u8; PAGE_SIZE_USIZE];
        let cap = cursor.capacity().min(tmp.len());
        let n = self.read(&mut tmp[..cap])?;
        cursor.append(&tmp[..n]);
        Ok(())
    }

    pub fn write(&self, _: &[u8]) -> io::Result<usize> { unsupported() }
    pub fn write_vectored(&self, _: &[IoSlice<'_>]) -> io::Result<usize> { unsupported() }
    pub fn is_write_vectored(&self) -> bool { false }
    pub fn flush(&self) -> io::Result<()> { Ok(()) }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64>
    {
        let new = match pos
        {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) => ((self.size as i64).saturating_add(o)).max(0) as u64,
            SeekFrom::Current(o) =>
            {
                let cur = self.pos.load(Ordering::Relaxed) as i64;
                cur.saturating_add(o).max(0) as u64
            }
        };
        self.pos.store(new, Ordering::Relaxed);
        Ok(new)
    }
    pub fn size(&self) -> Option<io::Result<u64>> { Some(Ok(self.size)) }
    pub fn tell(&self) -> io::Result<u64> { Ok(self.pos.load(Ordering::Relaxed)) }
    pub fn duplicate(&self) -> io::Result<File> { unsupported() }
    pub fn set_permissions(&self, _: FilePermissions) -> io::Result<()> { unsupported() }
    pub fn set_times(&self, _: FileTimes) -> io::Result<()> { unsupported() }
}

impl fmt::Debug for File
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.debug_struct("File")
            .field("file_cap", &self.file_cap)
            .field("token", &self.token)
            .field("size", &self.size)
            .finish()
    }
}

impl Drop for File
{
    fn drop(&mut self)
    {
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        // FS_CLOSE: fs walks its outstanding-page table and revokes
        // every per-cookie ancestor cap, decrementing each cache-slot
        // refcount. Any of our locally-mapped pages now point at a cap
        // whose mapping has been torn down by the kernel revocation;
        // we still need to mem_unmap the VA and free the slot.
        if !ipc_buf.is_null()
        {
            let close = IpcMessage::new(fs_labels::FS_CLOSE);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(self.file_cap, &close, ipc_buf) };
        }
        let _ = syscall::cap_delete(self.file_cap);

        // Drain the registry entry. After unregister, the handler
        // thread cannot route any further FS_RELEASE_FRAME to this
        // File — a late forced release on our token finds no entry
        // and no-ops with an ack.
        if let Some(state) = release_handler::state()
        {
            if let Some(entry) = release_handler::unregister(state, self.token)
            {
                for m in release_handler::drain_mappings(entry.as_ref())
                {
                    let _ = syscall::mem_unmap(
                        self.aspace,
                        m.range.va_start(),
                        m.range.page_count(),
                    );
                    let _ = syscall::cap_delete(m.frame_cap);
                    crate::sys::reserve::unreserve_pages(m.range);
                }
            }
        }

        // Drop the per-File tokened SEND. fs's caps[0] copy survives
        // until cap_delete on its slot; revoke would also kill it but
        // we rely on fs's FS_CLOSE handler having already cleared its
        // OpenFile entry, after which fs's slot is a dangling SEND
        // that will be reaped on fs's CSpace cleanup at process death.
        let _ = syscall::cap_delete(self.release_send);
    }
}

fn next_cookie() -> u64
{
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut c = NEXT.fetch_add(1, Ordering::Relaxed);
    while c == 0
    {
        c = NEXT.fetch_add(1, Ordering::Relaxed);
    }
    c
}

/// Map a [`NsError`] reply label to an `io::Error` per the error
/// table in `shared/namespace-protocol/README.md`. Each protocol
/// error maps to a distinct `io::ErrorKind`; unknown labels surface
/// as `Other` so a forward-compatible server adding a new wire code
/// does not silently convert into the wrong kind on older clients.
fn ns_error_to_io(label: u64) -> io::Error
{
    match label
    {
        l if l == NsError::NotFound.as_label() =>
            io::const_error!(io::ErrorKind::NotFound, "ns: name not found"),
        l if l == NsError::PermissionDenied.as_label() =>
            io::const_error!(io::ErrorKind::PermissionDenied, "ns: permission denied"),
        l if l == NsError::NotADirectory.as_label() =>
            io::const_error!(io::ErrorKind::NotADirectory, "ns: not a directory"),
        l if l == NsError::IsADirectory.as_label() =>
            io::const_error!(io::ErrorKind::IsADirectory, "ns: is a directory"),
        l if l == NsError::InvalidName.as_label() =>
            io::const_error!(io::ErrorKind::InvalidInput, "ns: invalid name"),
        l if l == NsError::InvalidOffset.as_label() =>
            io::const_error!(io::ErrorKind::InvalidInput, "ns: invalid offset"),
        l if l == NsError::InvalidFrameCap.as_label() =>
            io::const_error!(io::ErrorKind::InvalidInput, "ns: invalid frame cap"),
        l if l == NsError::InvalidCookie.as_label() =>
            io::const_error!(io::ErrorKind::InvalidInput, "ns: invalid cookie"),
        l if l == NsError::Evicted.as_label() =>
            io::const_error!(io::ErrorKind::UnexpectedEof, "ns: frame evicted"),
        l if l == NsError::IoError.as_label() =>
            io::const_error!(io::ErrorKind::Other, "ns: backend io error"),
        l if l == NsError::NotSupported.as_label() =>
            io::const_error!(io::ErrorKind::Unsupported, "ns: not supported"),
        l if l == NsError::OutOfResources.as_label() =>
            io::const_error!(io::ErrorKind::OutOfMemory, "ns: server out of resources"),
        _ => io::Error::other("ns: unknown error"),
    }
}

fn map_fs_error(label: u64) -> io::Error
{
    match label
    {
        fs_errors::NOT_FOUND =>
            io::const_error!(io::ErrorKind::NotFound, "fs: not found"),
        fs_errors::IO_ERROR =>
            io::const_error!(io::ErrorKind::Other, "fs: io error"),
        fs_errors::INVALID_TOKEN =>
            io::const_error!(io::ErrorKind::Other, "fs: file token invalid"),
        fs_errors::PERMISSION_DENIED =>
            io::const_error!(io::ErrorKind::PermissionDenied, "fs: permission denied"),
        _ => io::Error::other("fs: unknown error"),
    }
}

// ── Free functions: all Unsupported on v1 ─────────────────────────────────

pub fn readdir(_: &Path) -> io::Result<ReadDir> { unsupported() }
pub fn unlink(_: &Path) -> io::Result<()> { unsupported() }
pub fn rename(_: &Path, _: &Path) -> io::Result<()> { unsupported() }
pub fn set_perm(_: &Path, _: FilePermissions) -> io::Result<()> { unsupported() }
pub fn set_times(_: &Path, _: FileTimes) -> io::Result<()> { unsupported() }
pub fn set_times_nofollow(_: &Path, _: FileTimes) -> io::Result<()> { unsupported() }
pub fn rmdir(_: &Path) -> io::Result<()> { unsupported() }
pub fn remove_dir_all(_: &Path) -> io::Result<()> { unsupported() }
pub fn exists(_: &Path) -> io::Result<bool> { unsupported() }
pub fn readlink(_: &Path) -> io::Result<PathBuf> { unsupported() }
pub fn symlink(_: &Path, _: &Path) -> io::Result<()> { unsupported() }
pub fn link(_: &Path, _: &Path) -> io::Result<()> { unsupported() }
pub fn stat(_: &Path) -> io::Result<FileAttr> { unsupported() }
pub fn lstat(_: &Path) -> io::Result<FileAttr> { unsupported() }
pub fn canonicalize(_: &Path) -> io::Result<PathBuf> { unsupported() }
pub fn copy(_: &Path, _: &Path) -> io::Result<u64> { unsupported() }
