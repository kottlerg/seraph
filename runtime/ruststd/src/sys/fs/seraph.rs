// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! seraph-overlay: std::sys::fs (seraph-only)
//!
//! `std::fs::File`, `OpenOptions`, `read_dir`, `metadata`, and the
//! mutating free functions (`write`, `create_dir`, `remove_file`,
//! `remove_dir`, `remove_dir_all`, `rename`) backed by vfsd /
//! fs-driver IPC.
//!
//! ## Read path
//! - Reads ≤ 504 bytes that fit within the current page use the
//!   inline `FS_READ` path; payload bytes ride in the IPC buffer.
//! - Larger reads use `FS_READ_MEMORY`: the driver returns a Memory cap
//!   cap covering one cached page; we reserve VA, `mem_map` it
//!   read-only, memcpy out, then proactively release the cache slot
//!   via `FS_RELEASE_MEMORY` and tear the mapping down locally.
//!
//! ## Write path
//! - Writes ≤ 504 bytes use the inline `FS_WRITE` path with the
//!   payload riding in the IPC buffer.
//! - Larger writes use `FS_WRITE_MEMORY`: one memmgr-allocated page
//!   is mapped MAP_WRITABLE in the caller's address space, filled
//!   chunk-by-chunk, and handed to the driver as a DMA source. The
//!   driver returns the same Memory cap back to us in the reply so
//!   the cap slot id is rebound across iterations.
//!
//! ## Directory mutation
//! `FS_CREATE`, `FS_REMOVE`, `FS_MKDIR`, `FS_RENAME` operate against
//! a parent-directory cap that the PAL obtains by splitting the path
//! into (parent, leaf) and walking to the parent via `NS_LOOKUP`.
//! `remove_dir_all` recursively drains a subtree by enumerating with
//! `NS_READDIR` and issuing per-entry `FS_REMOVE`; after each removal
//! the cursor restarts at index 0 because FAT compacts slot indices.
//!
//! ## Truncate
//! `OpenOptions::truncate(true)` on an existing file and
//! `File::set_len(0)` ride the new `FS_TRUNCATE` label. v1 supports
//! `new_len == 0` only; the corresponding extend-with-zero-fill case
//! is tracked in the `ruststd::fs` completeness-gaps issue.
//!
//! ## Metadata
//! `std::fs::metadata` / `symlink_metadata` / `exists` walk the path
//! (Any-kind leaf) and issue `NS_STAT`. mtime is zero until the FAT
//! timestamp work in issue #85 lands a clock source;
//! `FileAttr::modified()` surfaces `Unsupported` in that case.
//!
//! ## Per-`File` release-endpoint plumbing
//! A badged derivation off the per-process release endpoint owned
//! by [`release_handler`] is allocated on every open and transferred
//! to the driver via `caps[0]` of the first
//! [`fs_labels::FS_READ_MEMORY`] request for that `File`. The driver
//! records it on the file's `OpenFile` slot; its eviction worker
//! uses it to issue cooperative [`fs_labels::FS_RELEASE_MEMORY`] back
//! to us before falling through to hard-revoke. Files that never
//! trigger a frame-read (only inline `FS_READ` / `FS_WRITE`) never
//! deliver the cap and get the hard-revoke fallback; the cap is
//! deleted in `Drop`.
//!
//! ## Path anchoring
//! Absolute paths walk from `root_dir_cap()`; relative paths walk
//! from `current_dir_cap()`. If the relevant anchor cap is unset
//! (e.g. caller has no cwd installed), the PAL returns `Unsupported`.

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
/// zero-copy FS_READ_MEMORY path. A `read()` of at most this many bytes
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

/// Per-call crossover threshold between the inline FS_WRITE path and
/// the zero-copy FS_WRITE_MEMORY path. A `write()` of at most this many
/// bytes goes inline; anything larger takes the frame path. Mirrors
/// `READ_INLINE_THRESHOLD` for symmetry: 504 bytes = 63 data words ×
/// 8 bytes − 8 bytes of length prefix in word 0.
const WRITE_INLINE_THRESHOLD: usize = 504;

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
    pub fn mkdir(&self, path: &Path) -> io::Result<()> { mkdir(path) }
}

// ── FileAttr / FilePermissions / FileType ─────────────────────────────────

pub struct FileAttr
{
    size: u64,
    kind: NodeKind,
    /// Best-effort mtime in microseconds since the UNIX epoch. Zero
    /// when the backend does not track timestamps (current FAT
    /// backend until #85 lands a clock source); `modified()`
    /// surfaces `Unsupported` in that case.
    mtime_us: u64,
}

impl FileAttr
{
    pub fn size(&self) -> u64 { self.size }
    pub fn perm(&self) -> FilePermissions { FilePermissions { readonly: false } }
    pub fn file_type(&self) -> FileType
    {
        let is_dir = matches!(self.kind, NodeKind::Dir);
        FileType { is_dir, is_file: !is_dir, is_symlink: false }
    }
    pub fn modified(&self) -> io::Result<SystemTime>
    {
        // FAT does not surface tracked timestamps yet; the field is
        // carried for forward compatibility with the timestamp work
        // tracked by #85.
        let _ = self.mtime_us;
        unsupported()
    }
    pub fn accessed(&self) -> io::Result<SystemTime> { unsupported() }
    pub fn created(&self) -> io::Result<SystemTime> { unsupported() }
}

impl Clone for FileAttr
{
    fn clone(&self) -> FileAttr
    {
        FileAttr {
            size: self.size,
            kind: self.kind,
            mtime_us: self.mtime_us,
        }
    }
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

/// Directory iterator backed by `NS_READDIR` against an owned
/// directory cap. Each `next()` issues one `NS_READDIR`; the FAT
/// backend's `.` and `..` entries are filtered client-side. The
/// owned `dir_cap` is `cap_delete`d on drop.
pub struct ReadDir
{
    dir_cap: u32,
    next_idx: u64,
    parent_path: PathBuf,
}

impl Iterator for ReadDir
{
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item>
    {
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            return Some(Err(io::Error::other("seraph fs: IPC buffer not registered")));
        }
        loop
        {
            let msg = IpcMessage::builder(ns_labels::NS_READDIR)
                .word(0, self.next_idx)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let reply = match unsafe { ipc::ipc_call(self.dir_cap, &msg, ipc_buf) }
            {
                Ok(r) => r,
                Err(_) =>
                {
                    return Some(Err(io::Error::other(
                        "seraph fs: NS_READDIR ipc_call failed",
                    )));
                }
            };
            if reply.label == fs_labels::END_OF_DIR
            {
                return None;
            }
            if reply.label != 0
            {
                return Some(Err(ns_error_to_io(reply.label)));
            }

            let kind_word = reply.word(0);
            let name_len = reply.word(1) as usize;
            let bytes = reply.data_bytes();
            const NAME_OFF: usize = 16; // words 0,1 = kind + name_len
            let end = NAME_OFF.saturating_add(name_len).min(bytes.len());
            if end < NAME_OFF + name_len
            {
                return Some(Err(io::Error::other(
                    "seraph fs: NS_READDIR truncated name",
                )));
            }
            let name_bytes = &bytes[NAME_OFF..end];

            self.next_idx = self.next_idx.saturating_add(1);

            // Filter the FAT-surfaced `.` / `..` entries. Std iterates
            // children, not the dir-self / dir-parent pseudo-entries.
            if name_bytes == b"." || name_bytes == b".."
            {
                continue;
            }

            let kind = if kind_word == NodeKind::Dir as u64
            {
                NodeKind::Dir
            }
            else
            {
                NodeKind::File
            };
            let name = OsString::from(
                core::str::from_utf8(name_bytes)
                    .unwrap_or("<non-utf8>")
                    .to_owned(),
            );
            return Some(Ok(DirEntry {
                name,
                kind,
                parent_path: self.parent_path.clone(),
            }));
        }
    }
}

impl fmt::Debug for ReadDir
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.debug_struct("ReadDir")
            .field("dir_cap", &self.dir_cap)
            .field("next_idx", &self.next_idx)
            .field("parent_path", &self.parent_path)
            .finish()
    }
}

impl Drop for ReadDir
{
    fn drop(&mut self)
    {
        if self.dir_cap != 0
        {
            let _ = syscall::cap_delete(self.dir_cap);
        }
    }
}

pub struct DirEntry
{
    name: OsString,
    kind: NodeKind,
    parent_path: PathBuf,
}

impl DirEntry
{
    pub fn path(&self) -> PathBuf { self.parent_path.join(&self.name) }
    pub fn file_name(&self) -> OsString { self.name.clone() }
    pub fn metadata(&self) -> io::Result<FileAttr>
    {
        // Refetch live attrs via stat — directory contents may have
        // changed since the enumeration produced this entry.
        stat(&self.path())
    }
    pub fn file_type(&self) -> io::Result<FileType>
    {
        let is_dir = matches!(self.kind, NodeKind::Dir);
        Ok(FileType { is_dir, is_file: !is_dir, is_symlink: false })
    }
}

// ── Path walk ─────────────────────────────────────────────────────────────

/// Result of [`walk_path_to_file`].
pub(crate) struct WalkedFile
{
    /// Badged SEND addressing the resolved file node. Caller owns and
    /// must `cap_delete` when no longer needed.
    pub file_cap: u32,
    /// Size of the file as reported by the final `NS_LOOKUP`'s size hint.
    pub size: u64,
}

/// Result of [`walk_path_to_dir`].
pub(crate) struct WalkedDir
{
    /// Badged SEND addressing the resolved directory node. Caller owns
    /// and must `cap_delete` when no longer needed.
    pub dir_cap: u32,
}

/// Walk `path_str` from `root_cap` via per-component `NS_LOOKUP`.
///
/// Splits on `/`, drops empty segments, validates component names per
/// the namespace-protocol rules. Every hop (including the final) must
/// resolve to a directory. Returns a freshly derived badged SEND on
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
    walk_path_to_dir_with_rights(root_cap, path_str, 0xFFFF, ipc_buf)
}

/// Variant of [`walk_path_to_dir`] that requests `requested_rights`
/// per hop instead of the `0xFFFF` "everything I'm allowed"
/// sentinel. Used by spawners that walk-and-attenuate a subtree cap
/// before installing it on a child via `CONFIGURE_NAMESPACE`.
pub(crate) fn walk_path_to_dir_with_rights(
    root_cap: u32,
    path_str: &str,
    requested_rights: u64,
    ipc_buf: *mut u64,
) -> io::Result<WalkedDir>
{
    let walked = walk_components(
        root_cap,
        path_str,
        requested_rights,
        ipc_buf,
        ExpectKind::Dir,
    )?;
    Ok(WalkedDir { dir_cap: walked.cap })
}

/// Walk `path_str` from `root_cap` via per-component `NS_LOOKUP`.
///
/// Splits on `/`, drops empty segments, validates component names per
/// the namespace-protocol rules. Each non-final hop must resolve to a
/// directory; the final hop must resolve to a file. Returns a freshly
/// derived badged SEND on the file plus its size hint. On any error
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
    let walked = walk_components(root_cap, path_str, 0xFFFF, ipc_buf, ExpectKind::File)?;
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
    /// Accept either kind at the leaf. Used by callers that do not
    /// know upfront whether the target is a file or a directory
    /// (`unlink`, `stat`, `exists`).
    Any,
}

/// Internal: result of a generic component walk.
struct WalkedNode
{
    cap: u32,
    size: u64,
    kind: NodeKind,
}

/// Internal kind-parameterised walk shared by [`walk_path_to_file`] and
/// [`walk_path_to_dir`]. `requested_rights` is the mask sent on every
/// hop; the namespace server intersects it against parent rights and
/// per-entry `max_rights`. Callers wanting "everything I'm allowed"
/// pass `0xFFFF`; callers walking-and-attenuating a subtree pass the
/// target rights mask directly.
fn walk_components(
    root_cap: u32,
    path_str: &str,
    requested_rights: u64,
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
    let mut leaf_kind = NodeKind::Dir;

    let last_idx = components.len() - 1;
    for (i, &name) in components.iter().enumerate()
    {
        let is_last = i == last_idx;
        // Cap-native rights model: server intersects
        // `parent_rights & entry.max_rights & caller_requested`.
        // `requested_rights` is the mask the caller wants on every
        // hop; `0xFFFF` is the "everything I'm allowed" sentinel
        // used by `File::open` and friends, and an explicit narrow
        // mask is used by walk-and-attenuate spawners.
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
            leaf_kind = if kind == NodeKind::Dir as u64
            {
                NodeKind::Dir
            }
            else
            {
                NodeKind::File
            };
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
        kind: leaf_kind,
    })
}

/// Split a path into `(parent_dir_cap, leaf_name)`. The parent walk
/// uses [`walk_path_to_dir`] anchored at `root_dir_cap` for absolute
/// paths and `current_dir_cap` for relative paths. If the parent is
/// the anchor itself (no intermediate components), the anchor cap is
/// returned with `parent_owned == false`; otherwise an owned badged
/// SEND is returned and the caller is responsible for `cap_delete`.
///
/// Used by `unlink`, `rmdir`, `rename`, `DirBuilder::mkdir`, and the
/// `File::open` write/create paths.
pub(crate) struct SplitParent
{
    pub parent_cap: u32,
    pub parent_owned: bool,
    pub leaf: Vec<u8>,
}

pub(crate) fn split_parent_and_leaf(
    path: &Path,
    ipc_buf: *mut u64,
) -> io::Result<SplitParent>
{
    let path_str = path.to_str().ok_or_else(|| {
        io::const_error!(io::ErrorKind::InvalidInput, "seraph fs: non-UTF-8 path")
    })?;

    // Strip a single trailing `/` so `/foo/` and `/foo` are equivalent
    // at the leaf-name level (matches POSIX `rmdir("/foo/")`).
    let trimmed = if path_str.len() > 1 && path_str.ends_with('/')
    {
        &path_str[..path_str.len() - 1]
    }
    else
    {
        path_str
    };
    if trimmed.is_empty() || trimmed == "/"
    {
        return Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "seraph fs: path has no leaf",
        ));
    }

    let (parent_str, leaf_str) = match trimmed.rfind('/')
    {
        Some(idx) => (&trimmed[..idx], &trimmed[idx + 1..]),
        None => ("", trimmed),
    };
    if leaf_str.is_empty()
    {
        return Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "seraph fs: path has empty leaf",
        ));
    }

    let leaf_bytes = leaf_str.as_bytes();
    if validate_name(leaf_bytes).is_err()
    {
        return Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "seraph fs: invalid leaf name",
        ));
    }

    let anchor_cap = if path_str.starts_with('/')
    {
        crate::os::seraph::root_dir_cap()
    }
    else
    {
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

    // `parent_str` is empty when the parent is the anchor (e.g.
    // path = "/foo" → parent_str = "", anchor = root; path = "foo" →
    // parent_str = "", anchor = cwd). Return the anchor cap without
    // claiming ownership so the caller does not cap_delete a borrowed
    // shared cap.
    if parent_str.is_empty() || parent_str == "/"
    {
        return Ok(SplitParent {
            parent_cap: anchor_cap,
            parent_owned: false,
            leaf: leaf_bytes.to_vec(),
        });
    }

    let walked = walk_path_to_dir(anchor_cap, parent_str, ipc_buf)?;
    Ok(SplitParent {
        parent_cap: walked.dir_cap,
        parent_owned: true,
        leaf: leaf_bytes.to_vec(),
    })
}

/// Release the parent cap returned by [`split_parent_and_leaf`] iff
/// it was owned. Helper to keep callers tidy.
fn release_split_parent(split: &SplitParent)
{
    if split.parent_owned
    {
        let _ = syscall::cap_delete(split.parent_cap);
    }
}

// ── Write helpers ─────────────────────────────────────────────────────────

/// Inline `FS_WRITE` of at most `WRITE_INLINE_THRESHOLD` bytes at
/// `offset` against `file_cap`. Returns `bytes_written` reported by
/// the server (may be short; callers iterate).
fn write_inline(
    file_cap: u32,
    offset: u64,
    payload: &[u8],
    ipc_buf: *mut u64,
) -> io::Result<usize>
{
    debug_assert!(payload.len() <= WRITE_INLINE_THRESHOLD);
    let label = fs_labels::FS_WRITE | ((payload.len() as u64) << 16);
    let msg = IpcMessage::builder(label)
        .word(0, offset)
        .bytes(1, payload)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }
        .map_err(|_| io::Error::other("seraph fs: FS_WRITE ipc_call failed"))?;
    if reply.label != fs_errors::SUCCESS
    {
        return Err(map_fs_error(reply.label));
    }
    Ok(reply.word(0) as usize)
}

/// Bulk write via `FS_WRITE_MEMORY`. Acquires one page-sized DMA
/// source frame from memmgr, maps it MAP_WRITABLE, then loops chunks
/// of at most `PAGE_SIZE` bytes through the frame and into the file.
/// The server returns the source frame in the reply caps each
/// round-trip, so the cap slot id is rebound on every iteration.
fn write_memory_chunks(
    file_cap: u32,
    aspace: u32,
    memmgr_ep: u32,
    base_offset: u64,
    payload: &[u8],
    ipc_buf: *mut u64,
) -> io::Result<usize>
{
    use ipc::{memmgr_errors, memmgr_labels};

    // Acquire one single-page frame from memmgr.
    let req = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(memmgr_ep, &req, ipc_buf) }
        .map_err(|_| io::Error::other("seraph fs: memmgr REQUEST_MEMORY_CAPS ipc_call failed"))?;
    if reply.label != memmgr_errors::SUCCESS
    {
        return Err(io::Error::other("seraph fs: memmgr REQUEST_MEMORY_CAPS failed"));
    }
    let mut memory_cap = *reply
        .caps()
        .first()
        .ok_or_else(|| io::Error::other("seraph fs: memmgr returned no frame"))?;

    // Reserve VA and map the frame MAP_WRITABLE.
    let range = crate::sys::reserve::reserve_pages(1).map_err(|_| {
        let _ = syscall::cap_delete(memory_cap);
        io::Error::other("seraph fs: reserve_pages failed for write frame")
    })?;
    let va = range.va_start();
    if syscall::mem_map(memory_cap, aspace, va, 0, 1, syscall::MAP_WRITABLE).is_err()
    {
        crate::sys::reserve::unreserve_pages(range);
        let _ = syscall::cap_delete(memory_cap);
        return Err(io::Error::other("seraph fs: mem_map MAP_WRITABLE failed"));
    }

    let mut total: usize = 0;
    let result: io::Result<()> = (|| {
        while total < payload.len()
        {
            let chunk_len = (payload.len() - total).min(PAGE_SIZE_USIZE);
            // Copy this chunk to the frame.
            // SAFETY: VA is mapped MAP_WRITABLE for exactly one page;
            // chunk_len ≤ PAGE_SIZE.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr().add(total),
                    va as *mut u8,
                    chunk_len,
                );
            }
            let chunk_offset = base_offset.saturating_add(total as u64);
            let msg = IpcMessage::builder(fs_labels::FS_WRITE_MEMORY)
                .word(0, chunk_offset)
                .word(1, chunk_len as u64)
                .word(2, 0)
                .cap(memory_cap)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer.
            let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }
                .map_err(|_| io::Error::other("seraph fs: FS_WRITE_MEMORY ipc_call failed"))?;
            if reply.label != fs_errors::SUCCESS
            {
                return Err(map_fs_error(reply.label));
            }
            // Server moves the source frame back in caps[0]; the slot
            // id may differ from the one we sent.
            memory_cap = *reply.caps().first().ok_or_else(|| {
                io::Error::other("seraph fs: FS_WRITE_MEMORY reply missing memory cap")
            })?;
            let n = reply.word(0) as usize;
            total += n;
            if n < chunk_len
            {
                // Short write — let the caller (`write_all`) iterate.
                break;
            }
        }
        Ok(())
    })();

    // Tear down regardless of result.
    let _ = syscall::mem_unmap(aspace, va, 1);
    let _ = syscall::cap_delete(memory_cap);
    crate::sys::reserve::unreserve_pages(range);

    result.map(|()| total)
}

/// Send `FS_TRUNCATE(0)` against `file_cap`. v1 only supports the
/// truncate-to-zero shrink; the server replies `IO_ERROR` for any
/// non-zero `new_len` and the client pre-rejects with `Unsupported`.
fn file_truncate_zero(file_cap: u32, ipc_buf: *mut u64) -> io::Result<()>
{
    let msg = IpcMessage::builder(fs_labels::FS_TRUNCATE).word(0, 0).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }
        .map_err(|_| io::Error::other("seraph fs: FS_TRUNCATE ipc_call failed"))?;
    if reply.label != fs_errors::SUCCESS
    {
        return Err(map_fs_error(reply.label));
    }
    Ok(())
}

/// Create a new file at `path`. Splits to (parent_dir_cap, leaf),
/// issues `FS_CREATE`, and returns the new file cap and size (0).
///
/// When `allow_existing` is false the helper surfaces `AlreadyExists`
/// on `fs_errors::EXISTS` (this is the `OpenOptions::create_new`
/// path). When true, the helper falls back to walking the existing
/// leaf via `NS_LOOKUP` so the caller can open the existing file
/// (this is the `OpenOptions::create` path).
fn create_file_at(
    path: &Path,
    ipc_buf: *mut u64,
    allow_existing: bool,
) -> io::Result<(u32, u64)>
{
    let split = split_parent_and_leaf(path, ipc_buf)?;

    let label = fs_labels::FS_CREATE | ((split.leaf.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, &split.leaf).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = match unsafe { ipc::ipc_call(split.parent_cap, &msg, ipc_buf) }
    {
        Ok(r) => r,
        Err(_) =>
        {
            release_split_parent(&split);
            return Err(io::Error::other("seraph fs: FS_CREATE ipc_call failed"));
        }
    };

    if reply.label == fs_errors::SUCCESS
    {
        let cap = match reply.caps().first()
        {
            Some(&c) => c,
            None =>
            {
                release_split_parent(&split);
                return Err(io::Error::other("seraph fs: FS_CREATE reply missing cap"));
            }
        };
        release_split_parent(&split);
        return Ok((cap, 0));
    }

    if reply.label == fs_errors::EXISTS && allow_existing
    {
        // Fall through to open-existing via a one-hop NS_LOOKUP on the
        // parent cap.
        let walked = walk_components(
            split.parent_cap,
            core::str::from_utf8(&split.leaf).unwrap_or(""),
            0xFFFF,
            ipc_buf,
            ExpectKind::File,
        );
        release_split_parent(&split);
        let walked = walked?;
        return Ok((walked.cap, walked.size));
    }

    release_split_parent(&split);
    Err(map_fs_error(reply.label))
}

// ── File ──────────────────────────────────────────────────────────────────

pub struct File
{
    /// Per-file node capability returned by the final `NS_LOOKUP` of
    /// the open walk. Receives every file-scoped op (FS_READ,
    /// FS_READ_MEMORY, FS_WRITE, FS_WRITE_MEMORY, FS_TRUNCATE,
    /// FS_CLOSE, synchronous client-initiated FS_RELEASE_MEMORY).
    file_cap: u32,
    /// Badge identifying this `File` for the release-handler dispatch.
    /// Carried inside the per-process release endpoint so an inbound
    /// `FS_RELEASE_MEMORY` from the driver routes to this `File`'s
    /// outstanding-mappings registry.
    badge: u64,
    /// Badged SEND on the per-process release endpoint. We retain
    /// the parent in our CSpace; on Drop we delete it so any
    /// in-flight forced release fails cleanly at the kernel.
    release_send: u32,
    /// True once the per-process release-endpoint SEND has been
    /// transmitted to the driver via `caps[0]` of an `FS_READ_MEMORY`
    /// request. Set on first successful frame-read; subsequent reads
    /// omit the cap so the kernel does not perform a wasted transfer.
    /// `swap` is the only mutator — first reader wins under contention.
    release_delivered: AtomicBool,
    /// Process aspace cap, captured at open for `mem_map` / `mem_unmap`.
    aspace: u32,
    /// memmgr endpoint cap captured at open; used by the write-frame
    /// path to acquire single-page DMA source frames.
    memmgr_ep: u32,
    /// Per-file outstanding-mappings registration in the handler.
    entry: Arc<FileEntry>,
    /// Current read/write offset; advanced by every successful op.
    pos: AtomicU64,
    /// Live file size. Initial value from the open walk's size hint;
    /// mutated on every write that extends past EOF and reset by
    /// `truncate`.
    size: AtomicU64,
    /// `OpenOptions::write || OpenOptions::append`. Drives the write
    /// path's permission check; the server enforces `WRITE` rights
    /// anyway, but the local check returns `Unsupported` faster.
    writable: bool,
    /// `OpenOptions::append`. When set, every write recomputes its
    /// effective offset as `max(pos, size)` so the bytes always land
    /// at EOF even if another writer extended the file since open.
    append: bool,
}

impl File
{
    pub fn open(path: &Path, opts: &OpenOptions) -> io::Result<File>
    {
        // ── Flag-combination validation ──────────────────────────────
        if !opts.read && !opts.write && !opts.append
        {
            return Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "seraph fs: open with no access mode",
            ));
        }
        if opts.append && opts.truncate
        {
            return Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "seraph fs: append and truncate are mutually exclusive",
            ));
        }
        if opts.truncate && !(opts.write || opts.append)
        {
            return Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "seraph fs: truncate requires write",
            ));
        }
        if opts.create && !(opts.write || opts.append)
        {
            return Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "seraph fs: create requires write",
            ));
        }
        if opts.create_new && !(opts.write || opts.append)
        {
            return Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "seraph fs: create_new requires write",
            ));
        }

        let writable = opts.write || opts.append;

        // ── Process-info / IPC buffer plumbing ───────────────────────
        let info = crate::os::seraph::try_startup_info().ok_or_else(|| {
            io::Error::other("seraph fs: startup info not installed")
        })?;
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            return Err(io::Error::other("seraph fs: IPC buffer not registered"));
        }

        // ── Resolve / create the file cap ────────────────────────────
        let (file_cap, mut size) = if opts.create_new
        {
            // Fail if the leaf already exists.
            create_file_at(path, ipc_buf, /*allow_existing=*/ false)?
        }
        else if opts.create
        {
            // Create-or-open. On EXISTS we fall back to the existing
            // file's cap.
            create_file_at(path, ipc_buf, /*allow_existing=*/ true)?
        }
        else
        {
            // Walk-to-existing.
            let path_str = path.to_str().ok_or_else(|| {
                io::const_error!(io::ErrorKind::InvalidInput, "seraph fs: non-UTF-8 path")
            })?;
            let anchor_cap = if path_str.starts_with('/')
            {
                crate::os::seraph::root_dir_cap()
            }
            else
            {
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
            let walked = walk_path_to_file(anchor_cap, path_str, ipc_buf)?;
            (walked.file_cap, walked.size)
        };

        // ── Optional truncate-to-zero on an existing file ────────────
        if opts.truncate && size != 0
        {
            if let Err(e) = file_truncate_zero(file_cap, ipc_buf)
            {
                let _ = syscall::cap_delete(file_cap);
                return Err(e);
            }
            size = 0;
        }

        // ── Release-handler plumbing ─────────────────────────────────
        //
        // The `release_send` cap is unused on the inline `FS_READ`/
        // `FS_WRITE` paths; on the first `FS_READ_MEMORY` it is
        // transferred to the driver in `caps[0]` so the driver's
        // eviction worker can route cooperative `FS_RELEASE_MEMORY`
        // back here. Failure paths below roll the setup back so a
        // refused open never leaks an entry into the release handler.
        let state = match release_handler::ensure_started()
        {
            Ok(s) => s,
            Err(e) =>
            {
                let _ = syscall::cap_delete(file_cap);
                return Err(e);
            }
        };
        let badge = release_handler::allocate_badge(state);
        let entry = release_handler::register(state, badge);

        let release_ep = release_handler::release_endpoint(state);
        let release_send =
            match syscall::cap_derive_badge(release_ep, syscall::RIGHTS_SEND, badge)
            {
                Ok(c) => c,
                Err(_) =>
                {
                    let _ = release_handler::unregister(state, badge);
                    let _ = syscall::cap_delete(file_cap);
                    return Err(io::Error::other(
                        "seraph fs: cap_derive_badge (release send) failed",
                    ));
                }
            };

        // ── Initial position: EOF for append, 0 otherwise ────────────
        let initial_pos = if opts.append { size } else { 0 };

        Ok(File {
            file_cap,
            badge,
            release_send,
            release_delivered: AtomicBool::new(false),
            aspace: info.self_aspace,
            memmgr_ep: info.memmgr_endpoint,
            entry,
            pos: AtomicU64::new(initial_pos),
            size: AtomicU64::new(size),
            writable,
            append: opts.append,
        })
    }

    pub fn file_attr(&self) -> io::Result<FileAttr>
    {
        // File handles are always files (the open walk rejects dir
        // leaves). Carry the live size; mtime is zero until #85.
        Ok(FileAttr {
            size: self.size.load(Ordering::Relaxed),
            kind: NodeKind::File,
            mtime_us: 0,
        })
    }
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

    pub fn truncate(&self, new_len: u64) -> io::Result<()>
    {
        if new_len != 0
        {
            // v1: only shrink-to-zero is implemented. Extend-with-
            // zero-fill is tracked in the `ruststd::fs` completeness-gaps issue.
            return Err(io::const_error!(
                io::ErrorKind::Unsupported,
                "seraph fs: File::set_len(non-zero) not supported in v1",
            ));
        }
        if !self.writable
        {
            return Err(io::const_error!(
                io::ErrorKind::PermissionDenied,
                "seraph fs: truncate on a read-only File",
            ));
        }
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            return Err(io::Error::other("seraph fs: IPC buffer not registered"));
        }
        file_truncate_zero(self.file_cap, ipc_buf)?;
        self.size.store(0, Ordering::Relaxed);
        // Clamp pos to the new (zero) length; subsequent reads/writes
        // start from offset 0.
        self.pos.store(0, Ordering::Relaxed);
        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize>
    {
        if buf.is_empty()
        {
            return Ok(0);
        }
        let pos = self.pos.load(Ordering::Relaxed);
        let cur_size = self.size.load(Ordering::Relaxed);
        if pos >= cur_size
        {
            return Ok(0);
        }
        let remaining = cur_size - pos;
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
        // First FS_READ_MEMORY for this File carries the per-process
        // release-endpoint SEND in caps[0]; the driver records it on
        // the OpenFile slot's first allocation so the eviction worker
        // can route cooperative FS_RELEASE_MEMORY back to us instead
        // of hard-revoking the page. `swap` ensures only one concurrent
        // reader attempts the transfer — the kernel `transfer_caps`
        // path moves the cap out of our CSpace, leaving the source slot
        // null, so a second concurrent attempt would fail at kernel
        // pre-validation.
        let send_release = !self.release_delivered.swap(true, Ordering::Relaxed);
        let mut builder = IpcMessage::builder(fs_labels::FS_READ_MEMORY)
            .word(0, pos)
            .word(1, cookie);
        if send_release
        {
            builder = builder.cap(self.release_send);
        }
        let msg = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(self.file_cap, &msg, ipc_buf) }
            .map_err(|_| io::Error::other("seraph fs: FS_READ_MEMORY ipc_call failed"))?;
        if reply.label != fs_errors::SUCCESS
        {
            return Err(map_fs_error(reply.label));
        }
        let bytes_valid = reply.word(0) as usize;
        let memory_data_offset = reply.word(2) as usize;
        let caps = reply.caps();
        if bytes_valid == 0 || caps.is_empty()
        {
            return Ok(0);
        }
        let memory_cap = caps[0];

        let range = match crate::sys::reserve::reserve_pages(1)
        {
            Ok(r) => r,
            Err(_) =>
            {
                let _ = syscall::cap_delete(memory_cap);
                self.release_frame(cookie);
                return Err(io::Error::other("seraph fs: reserve_pages failed"));
            }
        };
        let va = range.va_start();
        if syscall::mem_map(memory_cap, self.aspace, va, 0, 1, syscall::MAP_READONLY).is_err()
        {
            crate::sys::reserve::unreserve_pages(range);
            let _ = syscall::cap_delete(memory_cap);
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
                memory_cap,
            },
        );

        let copy_len = bytes_valid.min(buf.len());
        // SAFETY: VA is mapped read-only for one page; the fs invariant
        // is `memory_data_offset + bytes_valid <= PAGE_SIZE`.
        let src = unsafe {
            core::slice::from_raw_parts(
                (va + memory_data_offset as u64) as *const u8,
                bytes_valid,
            )
        };
        buf[..copy_len].copy_from_slice(&src[..copy_len]);
        self.pos.fetch_add(copy_len as u64, Ordering::Relaxed);

        // Proactive release: synchronous FS_RELEASE_MEMORY on the file
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
        let msg = IpcMessage::builder(fs_labels::FS_RELEASE_MEMORY)
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

    pub fn write(&self, buf: &[u8]) -> io::Result<usize>
    {
        if !self.writable
        {
            return Err(io::const_error!(
                io::ErrorKind::PermissionDenied,
                "seraph fs: write on a non-writable File",
            ));
        }
        if buf.is_empty()
        {
            return Ok(0);
        }
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            return Err(io::Error::other("seraph fs: IPC buffer not registered"));
        }

        // Compute the effective offset: append always lands at EOF; a
        // racing extender may have moved EOF since the last position
        // update, so we clamp pos up to the live size.
        let offset = if self.append
        {
            let cur_pos = self.pos.load(Ordering::Relaxed);
            let cur_size = self.size.load(Ordering::Relaxed);
            cur_pos.max(cur_size)
        }
        else
        {
            self.pos.load(Ordering::Relaxed)
        };

        // Hybrid: inline ≤ 504 bytes, frame path larger. Threshold is
        // the FS_WRITE IPC payload ceiling — see `WRITE_INLINE_THRESHOLD`.
        let n = if buf.len() <= WRITE_INLINE_THRESHOLD
        {
            write_inline(self.file_cap, offset, buf, ipc_buf)?
        }
        else
        {
            write_memory_chunks(
                self.file_cap,
                self.aspace,
                self.memmgr_ep,
                offset,
                buf,
                ipc_buf,
            )?
        };

        // Advance position and extend live size if needed.
        let new_offset = offset.saturating_add(n as u64);
        self.pos.store(new_offset, Ordering::Relaxed);
        let _ = self.size.fetch_max(new_offset, Ordering::Relaxed);
        Ok(n)
    }
    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize>
    {
        for b in bufs
        {
            if !b.is_empty()
            {
                return self.write(b);
            }
        }
        Ok(0)
    }
    pub fn is_write_vectored(&self) -> bool { false }
    pub fn flush(&self) -> io::Result<()> { Ok(()) }

    pub fn seek(&self, pos: SeekFrom) -> io::Result<u64>
    {
        let new = match pos
        {
            SeekFrom::Start(o) => o,
            SeekFrom::End(o) =>
            {
                let cur_size = self.size.load(Ordering::Relaxed) as i64;
                cur_size.saturating_add(o).max(0) as u64
            }
            SeekFrom::Current(o) =>
            {
                let cur = self.pos.load(Ordering::Relaxed) as i64;
                cur.saturating_add(o).max(0) as u64
            }
        };
        self.pos.store(new, Ordering::Relaxed);
        Ok(new)
    }
    pub fn size(&self) -> Option<io::Result<u64>>
    {
        Some(Ok(self.size.load(Ordering::Relaxed)))
    }
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
            .field("badge", &self.badge)
            .field("size", &self.size.load(Ordering::Relaxed))
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
        // thread cannot route any further FS_RELEASE_MEMORY to this
        // File — a late forced release on our badge finds no entry
        // and no-ops with an ack.
        if let Some(state) = release_handler::state()
        {
            if let Some(entry) = release_handler::unregister(state, self.badge)
            {
                for m in release_handler::drain_mappings(entry.as_ref())
                {
                    let _ = syscall::mem_unmap(
                        self.aspace,
                        m.range.va_start(),
                        m.range.page_count(),
                    );
                    let _ = syscall::cap_delete(m.memory_cap);
                    crate::sys::reserve::unreserve_pages(m.range);
                }
            }
        }

        // Drop the per-File badged SEND. fs's caps[0] copy survives
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
        l if l == NsError::InvalidMemoryCap.as_label() =>
            io::const_error!(io::ErrorKind::InvalidInput, "ns: invalid memory cap"),
        l if l == NsError::InvalidCookie.as_label() =>
            io::const_error!(io::ErrorKind::InvalidInput, "ns: invalid cookie"),
        l if l == NsError::Evicted.as_label() =>
            io::const_error!(io::ErrorKind::UnexpectedEof, "ns: page evicted"),
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
        fs_errors::TOO_MANY_OPEN =>
            io::const_error!(io::ErrorKind::ResourceBusy, "fs: too many open files"),
        fs_errors::INVALID_BADGE =>
            io::const_error!(io::ErrorKind::Other, "fs: file badge invalid"),
        fs_errors::RELEASE_TIMEOUT =>
            io::const_error!(io::ErrorKind::TimedOut, "fs: release timeout"),
        fs_errors::BAD_MEMORY_OFFSET =>
            io::const_error!(io::ErrorKind::InvalidInput, "fs: bad frame offset"),
        fs_errors::PERMISSION_DENIED =>
            io::const_error!(io::ErrorKind::PermissionDenied, "fs: permission denied"),
        fs_errors::LABEL_VERSION_MISMATCH =>
            io::const_error!(io::ErrorKind::Other, "fs: label version mismatch"),
        fs_errors::EXISTS =>
            io::const_error!(io::ErrorKind::AlreadyExists, "fs: already exists"),
        fs_errors::NO_SPACE =>
            io::const_error!(io::ErrorKind::StorageFull, "fs: no space"),
        fs_errors::NOT_EMPTY =>
            io::const_error!(io::ErrorKind::DirectoryNotEmpty, "fs: directory not empty"),
        fs_errors::IS_A_DIRECTORY =>
            io::const_error!(io::ErrorKind::IsADirectory, "fs: is a directory"),
        fs_errors::UNKNOWN_OPCODE =>
            io::const_error!(io::ErrorKind::Unsupported, "fs: unknown opcode"),
        _ => io::Error::other("fs: unknown error"),
    }
}

// ── Free functions ────────────────────────────────────────────────────────

/// `std::fs::read_dir` backend. Walks to the target directory, then
/// returns a `ReadDir` iterator that issues `NS_READDIR` per `next()`
/// and `cap_delete`s the dir cap on drop.
pub fn readdir(path: &Path) -> io::Result<ReadDir>
{
    let path_str = path.to_str().ok_or_else(|| {
        io::const_error!(io::ErrorKind::InvalidInput, "seraph fs: non-UTF-8 path")
    })?;
    let ipc_buf = crate::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return Err(io::Error::other("seraph fs: IPC buffer not registered"));
    }
    let anchor_cap = if path_str.starts_with('/')
    {
        crate::os::seraph::root_dir_cap()
    }
    else
    {
        crate::os::seraph::current_dir_cap()
    };
    if anchor_cap == 0
    {
        return Err(io::const_error!(
            io::ErrorKind::Unsupported,
            "seraph fs: no anchor dir cap for this path",
        ));
    }
    let walked = walk_path_to_dir(anchor_cap, path_str, ipc_buf)?;
    Ok(ReadDir {
        dir_cap: walked.dir_cap,
        next_idx: 0,
        parent_path: PathBuf::from(path_str),
    })
}

/// Unlink a regular file. Returns `IsADirectory` if the leaf resolves
/// to a directory (use `rmdir` / `remove_dir_all` for those).
pub fn unlink(path: &Path) -> io::Result<()>
{
    remove_leaf(path, /*expect_dir=*/ false)
}

/// Remove an empty directory. Returns `NotADirectory` if the leaf
/// resolves to a regular file; returns `DirectoryNotEmpty` if the
/// directory is non-empty.
pub fn rmdir(path: &Path) -> io::Result<()>
{
    remove_leaf(path, /*expect_dir=*/ true)
}

fn remove_leaf(path: &Path, expect_dir: bool) -> io::Result<()>
{
    let ipc_buf = crate::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return Err(io::Error::other("seraph fs: IPC buffer not registered"));
    }
    let split = split_parent_and_leaf(path, ipc_buf)?;

    // Verify the kind before issuing FS_REMOVE so we surface the std
    // ErrorKind for "wrong kind" rather than relying on the server to
    // distinguish (it returns NOT_EMPTY for non-empty dirs but doesn't
    // distinguish file-vs-dir at the wire). One-hop NS_LOOKUP.
    let walked = match walk_components(
        split.parent_cap,
        core::str::from_utf8(&split.leaf).unwrap_or(""),
        0xFFFF,
        ipc_buf,
        ExpectKind::Any,
    )
    {
        Ok(w) => w,
        Err(e) =>
        {
            release_split_parent(&split);
            return Err(e);
        }
    };
    let kind_is_dir = matches!(walked.kind, NodeKind::Dir);
    let _ = syscall::cap_delete(walked.cap);
    if expect_dir && !kind_is_dir
    {
        release_split_parent(&split);
        return Err(io::const_error!(
            io::ErrorKind::NotADirectory,
            "seraph fs: target is not a directory",
        ));
    }
    if !expect_dir && kind_is_dir
    {
        release_split_parent(&split);
        return Err(io::const_error!(
            io::ErrorKind::IsADirectory,
            "seraph fs: target is a directory",
        ));
    }

    let label = fs_labels::FS_REMOVE | ((split.leaf.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, &split.leaf).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(split.parent_cap, &msg, ipc_buf) };
    release_split_parent(&split);
    let reply = reply.map_err(|_| io::Error::other("seraph fs: FS_REMOVE ipc_call failed"))?;
    if reply.label != fs_errors::SUCCESS
    {
        return Err(map_fs_error(reply.label));
    }
    Ok(())
}

/// Create a new (empty) directory at `path`. Drops the returned dir
/// cap — the std contract does not surface it to the caller.
pub fn mkdir(path: &Path) -> io::Result<()>
{
    let ipc_buf = crate::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return Err(io::Error::other("seraph fs: IPC buffer not registered"));
    }
    let split = split_parent_and_leaf(path, ipc_buf)?;
    let label = fs_labels::FS_MKDIR | ((split.leaf.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, &split.leaf).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(split.parent_cap, &msg, ipc_buf) };
    release_split_parent(&split);
    let reply = reply.map_err(|_| io::Error::other("seraph fs: FS_MKDIR ipc_call failed"))?;
    if reply.label != fs_errors::SUCCESS
    {
        return Err(map_fs_error(reply.label));
    }
    if let Some(&cap) = reply.caps().first()
    {
        let _ = syscall::cap_delete(cap);
    }
    Ok(())
}

/// Rename an entry within a single directory. Cross-directory rename
/// is not supported on the wire (see `shared/ipc/src/lib.rs`
/// `FS_RENAME` rustdoc) and is tracked separately; the PAL surfaces
/// it as `InvalidInput`.
pub fn rename(from: &Path, to: &Path) -> io::Result<()>
{
    let ipc_buf = crate::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return Err(io::Error::other("seraph fs: IPC buffer not registered"));
    }
    let src = split_parent_and_leaf(from, ipc_buf)?;
    let dst = match split_parent_and_leaf(to, ipc_buf)
    {
        Ok(s) => s,
        Err(e) =>
        {
            release_split_parent(&src);
            return Err(e);
        }
    };

    // Same-parent enforcement. We compare cap slot ids: if both were
    // walked from the same anchor with no intermediate split (i.e.
    // both `parent_owned=false`) the anchors match by construction;
    // when both are owned they are distinct freshly-derived sub-caps
    // even if the path components are identical, so we cannot
    // syntactically compare them. Instead use the source path strings.
    let src_str = from.to_str().unwrap_or("");
    let dst_str = to.to_str().unwrap_or("");
    let src_parent = src_str.rsplitn(2, '/').nth(1).unwrap_or("");
    let dst_parent = dst_str.rsplitn(2, '/').nth(1).unwrap_or("");
    if src_parent != dst_parent
    {
        release_split_parent(&src);
        release_split_parent(&dst);
        return Err(io::const_error!(
            io::ErrorKind::InvalidInput,
            "seraph fs: cross-directory rename not supported",
        ));
    }

    // Build the FS_RENAME request: word(0)=src_len, word(1)=dst_len,
    // names contiguous from word 2.
    let mut combined = Vec::with_capacity(src.leaf.len() + dst.leaf.len());
    combined.extend_from_slice(&src.leaf);
    combined.extend_from_slice(&dst.leaf);
    let msg = IpcMessage::builder(fs_labels::FS_RENAME)
        .word(0, src.leaf.len() as u64)
        .word(1, dst.leaf.len() as u64)
        .bytes(2, &combined)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(src.parent_cap, &msg, ipc_buf) };
    release_split_parent(&src);
    release_split_parent(&dst);
    let reply = reply.map_err(|_| io::Error::other("seraph fs: FS_RENAME ipc_call failed"))?;
    if reply.label != fs_errors::SUCCESS
    {
        return Err(map_fs_error(reply.label));
    }
    Ok(())
}

pub fn set_perm(_: &Path, _: FilePermissions) -> io::Result<()> { unsupported() }
pub fn set_times(_: &Path, _: FileTimes) -> io::Result<()> { unsupported() }
pub fn set_times_nofollow(_: &Path, _: FileTimes) -> io::Result<()> { unsupported() }

/// Recursive removal of a directory tree. Client-side: enumerate via
/// `NS_READDIR`, recurse into subdirs, `FS_REMOVE` leaves, then
/// `FS_REMOVE` the now-empty target. FAT slot indices shift after
/// every removal, so the iterator restarts at idx=0 after each
/// removal.
pub fn remove_dir_all(path: &Path) -> io::Result<()>
{
    let ipc_buf = crate::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return Err(io::Error::other("seraph fs: IPC buffer not registered"));
    }

    // Resolve the top-level target's parent + leaf. The leaf is the
    // dir to drain; the parent receives the final FS_REMOVE.
    let split = split_parent_and_leaf(path, ipc_buf)?;

    // Look up the target dir cap (must be a Dir).
    let leaf_str = core::str::from_utf8(&split.leaf).unwrap_or("");
    let walked = match walk_components(
        split.parent_cap,
        leaf_str,
        0xFFFF,
        ipc_buf,
        ExpectKind::Any,
    )
    {
        Ok(w) => w,
        Err(e) =>
        {
            release_split_parent(&split);
            return Err(e);
        }
    };
    if !matches!(walked.kind, NodeKind::Dir)
    {
        let _ = syscall::cap_delete(walked.cap);
        release_split_parent(&split);
        return Err(io::const_error!(
            io::ErrorKind::NotADirectory,
            "seraph fs: target is not a directory",
        ));
    }

    let result = drain_dir_recursive(walked.cap, ipc_buf);
    let _ = syscall::cap_delete(walked.cap);
    if let Err(e) = result
    {
        // Release the (possibly-owned) parent cap before propagating;
        // bare `?` would otherwise skip the release_split_parent leg.
        release_split_parent(&split);
        return Err(e);
    }

    // Final FS_REMOVE for the now-empty target.
    let label = fs_labels::FS_REMOVE | ((split.leaf.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, &split.leaf).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(split.parent_cap, &msg, ipc_buf) };
    release_split_parent(&split);
    let reply = reply.map_err(|_| io::Error::other("seraph fs: FS_REMOVE ipc_call failed"))?;
    if reply.label != fs_errors::SUCCESS
    {
        return Err(map_fs_error(reply.label));
    }
    Ok(())
}

/// Drain every entry under `dir_cap`. Iterates `NS_READDIR` forward
/// across `.` / `..`; for every other entry it recurses into the
/// subtree if it is a directory, then `FS_REMOVE`s the entry by name
/// on `dir_cap`. After each removal the cursor restarts at zero
/// because FAT compacts indices when an entry is freed.
fn drain_dir_recursive(dir_cap: u32, ipc_buf: *mut u64) -> io::Result<()>
{
    let mut idx = 0u64;
    loop
    {
        let entry = match ns_readdir_one(dir_cap, idx, ipc_buf)?
        {
            Some(e) => e,
            None => return Ok(()),
        };
        if entry.name == b"." || entry.name == b".."
        {
            idx = idx.saturating_add(1);
            continue;
        }

        if matches!(entry.kind, NodeKind::Dir)
        {
            let leaf_str = core::str::from_utf8(&entry.name).unwrap_or("");
            let walked = walk_components(
                dir_cap,
                leaf_str,
                0xFFFF,
                ipc_buf,
                ExpectKind::Dir,
            )?;
            let drain_res = drain_dir_recursive(walked.cap, ipc_buf);
            let _ = syscall::cap_delete(walked.cap);
            drain_res?;
        }

        let label = fs_labels::FS_REMOVE | ((entry.name.len() as u64) << 16);
        let msg = IpcMessage::builder(label).bytes(0, &entry.name).build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let reply = unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) }
            .map_err(|_| io::Error::other("seraph fs: FS_REMOVE ipc_call failed"))?;
        if reply.label != fs_errors::SUCCESS
        {
            return Err(map_fs_error(reply.label));
        }
        idx = 0;
    }
}

struct ReaddirEntry
{
    name: Vec<u8>,
    kind: NodeKind,
}

/// Issue a single `NS_READDIR(idx)` against `dir_cap`. Returns
/// `Ok(None)` on `END_OF_DIR`.
fn ns_readdir_one(
    dir_cap: u32,
    idx: u64,
    ipc_buf: *mut u64,
) -> io::Result<Option<ReaddirEntry>>
{
    let msg = IpcMessage::builder(ns_labels::NS_READDIR)
        .word(0, idx)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(dir_cap, &msg, ipc_buf) }
        .map_err(|_| io::Error::other("seraph fs: NS_READDIR ipc_call failed"))?;
    if reply.label == fs_labels::END_OF_DIR
    {
        return Ok(None);
    }
    if reply.label != 0
    {
        return Err(ns_error_to_io(reply.label));
    }
    let kind_word = reply.word(0);
    let name_len = reply.word(1) as usize;
    let bytes = reply.data_bytes();
    const NAME_OFF: usize = 16;
    let end = NAME_OFF.saturating_add(name_len).min(bytes.len());
    if end < NAME_OFF + name_len
    {
        return Err(io::Error::other("seraph fs: NS_READDIR truncated name"));
    }
    let kind = if kind_word == NodeKind::Dir as u64
    {
        NodeKind::Dir
    }
    else
    {
        NodeKind::File
    };
    Ok(Some(ReaddirEntry {
        name: bytes[NAME_OFF..end].to_vec(),
        kind,
    }))
}

/// `std::fs::exists`. Returns `Ok(false)` for `NotFound`; surfaces
/// every other walk error (e.g. `PermissionDenied`).
pub fn exists(path: &Path) -> io::Result<bool>
{
    match stat(path)
    {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

pub fn readlink(_: &Path) -> io::Result<PathBuf>
{
    Err(io::const_error!(
        io::ErrorKind::Unsupported,
        "seraph fs: symlinks are not supported on FAT",
    ))
}
pub fn symlink(_: &Path, _: &Path) -> io::Result<()>
{
    Err(io::const_error!(
        io::ErrorKind::Unsupported,
        "seraph fs: symlinks are not supported on FAT",
    ))
}
pub fn link(_: &Path, _: &Path) -> io::Result<()>
{
    Err(io::const_error!(
        io::ErrorKind::Unsupported,
        "seraph fs: hardlinks are not supported on FAT",
    ))
}

/// `std::fs::metadata` backend. Walks the path (Any kind), issues
/// `NS_STAT` against the resulting node cap, and returns a `FileAttr`
/// carrying size + kind. mtime stays zero until #85 lands a clock
/// source; `FileAttr::modified()` surfaces `Unsupported` in that case.
pub fn stat(path: &Path) -> io::Result<FileAttr>
{
    let path_str = path.to_str().ok_or_else(|| {
        io::const_error!(io::ErrorKind::InvalidInput, "seraph fs: non-UTF-8 path")
    })?;
    let ipc_buf = crate::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        return Err(io::Error::other("seraph fs: IPC buffer not registered"));
    }
    let anchor_cap = if path_str.starts_with('/')
    {
        crate::os::seraph::root_dir_cap()
    }
    else
    {
        crate::os::seraph::current_dir_cap()
    };
    if anchor_cap == 0
    {
        return Err(io::const_error!(
            io::ErrorKind::Unsupported,
            "seraph fs: no anchor dir cap for this path",
        ));
    }
    let walked = walk_components(anchor_cap, path_str, 0xFFFF, ipc_buf, ExpectKind::Any)?;
    // NS_STAT against the walked node cap.
    let msg = IpcMessage::new(ns_labels::NS_STAT);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(walked.cap, &msg, ipc_buf) };
    let _ = syscall::cap_delete(walked.cap);
    let reply = reply.map_err(|_| io::Error::other("seraph fs: NS_STAT ipc_call failed"))?;
    if reply.label != 0
    {
        return Err(ns_error_to_io(reply.label));
    }
    let size = reply.word(0);
    let mtime_us = reply.word(1);
    let kind_word = reply.word(2);
    let kind = if kind_word == NodeKind::Dir as u64
    {
        NodeKind::Dir
    }
    else
    {
        NodeKind::File
    };
    Ok(FileAttr { size, kind, mtime_us })
}

/// FAT has no symlinks, so `lstat` and `stat` are equivalent.
pub fn lstat(path: &Path) -> io::Result<FileAttr> { stat(path) }

pub fn canonicalize(_: &Path) -> io::Result<PathBuf> { unsupported() }
pub fn copy(_: &Path, _: &Path) -> io::Result<u64> { unsupported() }
