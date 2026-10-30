// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// runtime/ruststd/src/sys/fs/seraph.rs

//! `std::fs::File`, `OpenOptions`, `read_dir`, `metadata`, and the
//! mutating free functions (`write`, `create_dir`, `remove_file`,
//! `remove_dir`, `remove_dir_all`, `rename`) backed by vfsd /
//! fs-driver IPC.
//!
//! The choice between the inline `FS_READ` / `FS_WRITE` labels and the
//! memory-cap `FS_READ_MEMORY` / `FS_WRITE_MEMORY` labels is the client
//! policy `services/fs/docs/fs-driver-protocol.md` § Inline-vs-memory-cap
//! crossover specifies (with `FS_WRITE_MEMORY` for the write threshold);
//! this file implements it.
//!
//! ## Read path
//! - Inline reads carry the payload in the IPC buffer.
//! - Memory-cap reads: the driver returns a Memory cap covering one cached
//!   page; we reserve VA, `mem_map` it read-only, copy out, then
//!   proactively release the cache slot via `FS_RELEASE_MEMORY` and tear
//!   the mapping down locally.
//!
//! ## Write path
//! - Inline writes carry the payload in the IPC buffer.
//! - Memory-cap writes: one memmgr-allocated page per
//!   write is mapped MAP_WRITABLE in the caller's address space, filled
//!   chunk-by-chunk, and lent to the driver as a DMA source through a
//!   `MAP`-only derivation per chunk; the page's run goes back to memmgr
//!   once the write ends (see `release_write_frame`).
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
//! by [`release_handler`] is allocated on every open and kept by the
//! `File`. Each [`fs_labels::FS_READ_MEMORY`] request carries a fresh
//! copy of it in `caps[0]` until one request that carried a copy the
//! kernel moved gets a `SUCCESS` reply, so a request refused before the
//! driver allocates its `OpenFile` slot, or a concurrent read that
//! reaches the driver first, cannot leave the `File` without a recorded
//! SEND. The driver records the copy on the file's `OpenFile` slot when
//! that request allocates the slot and deletes any other; its eviction
//! worker uses it to issue a cooperative
//! [`fs_labels::FS_RELEASE_MEMORY`] back to us, then revokes the page's
//! caps whether or not the reply is an ack. A slot another opener
//! allocated or freed is outside the `File`'s view (#530). Files that
//! never trigger a frame-read (only inline `FS_READ` / `FS_WRITE`) never
//! deliver a copy and get the revoke without the cooperative step; the
//! kept SEND is deleted in `Drop`.
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
use syscall_abi::{MSG_DATA_WORDS_MAX, PAGE_SIZE};

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
/// 504 is the FS_READ IPC reply ceiling: 64 data words
/// (`abi/syscall/MSG_DATA_WORDS_MAX`) × 8 bytes minus the 8-byte length
/// prefix in word 0.
/// At or below this size, a single FS_READ carries the bytes. The
/// `fsbench` numbers in `services/fs/docs/fs-driver-protocol.md` show
/// inline is roughly 2× cheaper per call on both x86_64 and riscv64,
/// so 504 also happens to be the smallest size at which any larger
/// would force ≥ 2 inline calls and lose to one frame call.
const READ_INLINE_THRESHOLD: usize = 504;

/// Per-call crossover threshold between the inline FS_WRITE path and
/// the zero-copy FS_WRITE_MEMORY path. A `write()` of at most this many
/// bytes goes inline; anything larger takes the frame path. Mirrors
/// `READ_INLINE_THRESHOLD` for symmetry: 504 bytes = 64 data words
/// (`MSG_DATA_WORDS_MAX`) × 8 bytes − the 8-byte file offset in word 0 (the
/// payload length rides in label bits 16-31).
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
    /// Set at `END_OF_DIR` or after an error that would otherwise repeat on
    /// every later call (no registered IPC buffer, an `NS_READDIR`
    /// failure). A rejected entry name is an error for that entry alone;
    /// the iteration continues past it.
    done: bool,
}

impl Iterator for ReadDir
{
    type Item = io::Result<DirEntry>;

    fn next(&mut self) -> Option<Self::Item>
    {
        if self.done
        {
            return None;
        }
        let ipc_buf = crate::os::seraph::current_ipc_buf();
        if ipc_buf.is_null()
        {
            self.done = true;
            return Some(Err(io::Error::other("seraph fs: IPC buffer not registered")));
        }
        loop
        {
            let entry = match ns_readdir_one(self.dir_cap, self.next_idx, ipc_buf)
            {
                Ok(Some(e)) => e,
                Ok(None) =>
                {
                    self.done = true;
                    return None;
                }
                Err(e) =>
                {
                    self.done = true;
                    return Some(Err(e));
                }
            };
            self.next_idx = self.next_idx.saturating_add(1);

            // Filter the FAT-surfaced `.` / `..` entries. Std iterates
            // children, not the dir-self / dir-parent pseudo-entries.
            if entry.name == b"." || entry.name == b".."
            {
                continue;
            }

            // The name is wire input. `DirEntry::path` joins it onto the
            // parent, so only a single valid component names this entry; an
            // empty name or one with a slash would name another node.
            if validate_name(&entry.name).is_err()
            {
                return Some(Err(io::const_error!(
                    io::ErrorKind::InvalidData,
                    "seraph fs: NS_READDIR returned an invalid entry name",
                )));
            }
            // `validate_name` accepts only UTF-8.
            let name = OsString::from(core::str::from_utf8(&entry.name).unwrap_or_default());
            return Some(Ok(DirEntry {
                name,
                kind: entry.kind,
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
            .field("done", &self.done)
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

/// Every namespace right `namespace_protocol::rights` defines. A walk that
/// requests all of them asks for whatever the anchor holds.
const NS_DEFINED_RIGHTS: u64 = {
    use namespace_protocol::rights::{
        ADMIN, EXEC, LOOKUP, MUTATE_DIR, READ, READDIR, STAT, WRITE,
    };
    (LOOKUP | READDIR | STAT | READ | WRITE | EXEC | MUTATE_DIR | ADMIN) as u64
};

/// Internal kind-parameterised walk shared by [`walk_path_to_file`] and
/// [`walk_path_to_dir`]. `requested_rights` is the mask sent on every
/// hop; the namespace server intersects it against parent rights and
/// per-entry `max_rights`. Callers wanting "everything I'm allowed"
/// pass `0xFFFF`; callers walking-and-attenuating a subtree pass the
/// target rights mask directly.
///
/// A path with no components (e.g. `"/"`) denotes the anchor directory
/// itself: directory walks (`Dir`/`Any`) return an owned `SEND` copy of
/// `root_cap` when `requested_rights` includes every right in
/// [`NS_DEFINED_RIGHTS`], and `InvalidInput` otherwise, since no hop
/// narrows the anchor; file walks reject it with `InvalidInput`.
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
        // A path with no components (e.g. "/") denotes the anchor
        // directory itself. Directory walks resolve it to the anchor;
        // file walks have no such target. Return an owned derived copy
        // so the caller's `cap_delete` bookkeeping is uniform with the
        // walked-child case — handing back the borrowed `root_cap`
        // would let a later release delete the anchor cap.
        //
        // The copy keeps the anchor's badge, and with it the anchor's
        // namespace rights, which only the server narrows
        // (docs/namespace-model.md § Namespace Rights). It is returned
        // only to a caller that requests every defined right; a narrower
        // request cannot be honoured without a hop. `cap_derive` takes the
        // kernel's endpoint rights, not namespace rights.
        return match expect_kind
        {
            ExpectKind::File => Err(io::const_error!(
                io::ErrorKind::InvalidInput,
                "seraph fs: path resolves to no components",
            )),
            ExpectKind::Dir | ExpectKind::Any
                if requested_rights & NS_DEFINED_RIGHTS != NS_DEFINED_RIGHTS =>
            {
                Err(io::const_error!(
                    io::ErrorKind::InvalidInput,
                    "seraph fs: the anchor directory cannot be attenuated",
                ))
            }
            ExpectKind::Dir | ExpectKind::Any =>
            {
                let dup = syscall::cap_derive(root_cap, syscall_abi::RIGHTS_EP_SEND)
                    .map_err(|_| {
                        io::Error::other("seraph fs: cap_derive of anchor dir failed")
                    })?;
                Ok(WalkedNode {
                    cap: dup,
                    size: 0,
                    kind: NodeKind::Dir,
                })
            }
        };
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
/// the server (may be short; callers iterate), or `InvalidData` when the
/// server reports more bytes than `payload` holds.
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
    let written = reply.word(0) as usize;
    if written > payload.len()
    {
        return Err(io::const_error!(
            io::ErrorKind::InvalidData,
            "seraph fs: FS_WRITE reported more bytes than were sent",
        ));
    }
    Ok(written)
}

/// One write's source frame: a page from memmgr, mapped writable at a
/// reserved VA for the length of the write.
struct WriteFrame
{
    cap: u32,
    phys: u64,
    range: crate::sys::reserve::ReservedRange,
}

impl WriteFrame
{
    fn va(&self) -> u64
    {
        self.range.va_start()
    }
}

/// Request a source frame from memmgr, fund this address space's page
/// tables for it, and map it. A frame that fails to map was never shown to
/// a driver, so its cap is deleted and its run returned.
fn acquire_write_frame(aspace: u32, memmgr_ep: u32) -> io::Result<WriteFrame>
{
    use crate::sys::alloc::seraph::{
        fund_aspace_pt_budget, slab_release_fresh, slab_request_pages,
    };

    let (cap, _, phys) = slab_request_pages(memmgr_ep, 1)
        .ok_or_else(|| io::Error::other("seraph fs: memmgr REQUEST_MEMORY_CAPS failed"))?;
    let range = crate::sys::reserve::reserve_pages(1).map_err(|_| {
        let _ = syscall::cap_delete(cap);
        slab_release_fresh(phys);
        io::Error::other("seraph fs: reserve_pages failed for write frame")
    })?;
    let failure = if !fund_aspace_pt_budget(aspace, 1)
    {
        Some("seraph fs: page-table funding failed for write frame")
    }
    else
    {
        // SAFETY: `range` is a fresh reservation from the per-process arena,
        // owned here: VA no Rust object or IPC page occupies.
        let mapped =
            unsafe { syscall::mem_map(cap, aspace, range.va_start(), 0, 1, syscall::MAP_WRITABLE) };
        mapped.is_err().then_some("seraph fs: mem_map MAP_WRITABLE failed")
    };
    if let Some(msg) = failure
    {
        crate::sys::reserve::unreserve_pages(range);
        let _ = syscall::cap_delete(cap);
        slab_release_fresh(phys);
        return Err(io::Error::other(msg));
    }
    Ok(WriteFrame { cap, phys, range })
}

/// A cookie's read-in-progress mark in the release registry, from before
/// its `FS_READ_MEMORY` until the local copy from the mapped page is done.
/// A driver release of the cookie waits on the mark, up to the driver's
/// release window, so the page is not unmapped, or acked back to the
/// driver, mid-copy; a copy outlasting the window gets no ack, and the
/// driver may recycle the page (#516). Dropping the mark ends the read on
/// every early return.
struct ReadMark<'a>
{
    entry: &'a FileEntry,
    cookie: u64,
    ended: bool,
}

impl<'a> ReadMark<'a>
{
    fn begin(entry: &'a FileEntry, cookie: u64) -> Self
    {
        release_handler::begin_read(entry, cookie);
        Self {
            entry,
            cookie,
            ended: false,
        }
    }

    /// End the read, registering the page's mapping for release. Returns
    /// whether a driver release's wait for the read ran out during it.
    fn finish(mut self, mapping: OutstandingMapping) -> bool
    {
        self.ended = true;
        release_handler::end_read(self.entry, self.cookie, Some(mapping))
    }
}

impl Drop for ReadMark<'_>
{
    fn drop(&mut self)
    {
        if !self.ended
        {
            release_handler::end_read(self.entry, self.cookie, None);
        }
    }
}

/// Tear a write frame down and return its run to memmgr: unmap it, revoke
/// the derivations lent to the driver, delete the cap, and release the run
/// by its phys base. The release relies on the driver holding no mapping
/// of the frame past the copy, which services/fs/docs/fs-driver-protocol.md
/// § Label 12 requires of it; revocation withdraws a derivation the driver
/// kept but not a mapping it made. A frame whose unmap fails stays mapped,
/// reserved, and accounted to this process until it exits.
fn release_write_frame(frame: WriteFrame, aspace: u32)
{
    // SAFETY: the frame owns its reserved page, which holds no Rust object;
    // the write path reaches it only through raw pointers, and consuming the
    // frame here ends every use of it.
    if unsafe { syscall::mem_unmap(aspace, frame.va(), 1) }.is_err()
    {
        return;
    }
    crate::sys::reserve::unreserve_pages(frame.range);
    let _ = syscall::cap_revoke(frame.cap);
    let _ = syscall::cap_delete(frame.cap);
    crate::sys::alloc::seraph::slab_release_fresh(frame.phys);
}

/// How one `FS_WRITE_MEMORY` chunk failed.
enum ChunkError
{
    /// The call was interrupted after it blocked, possibly after the driver
    /// received it, so the driver may still copy from the frame.
    Call(io::Error),
    /// The frame was not lent, or the driver replied: the frame is idle.
    Settled(io::Error),
}

/// Bulk write via `FS_WRITE_MEMORY`: loop chunks of at most `PAGE_SIZE`
/// bytes through a [`WriteFrame`] acquired for this write and into the
/// file, then release the frame with [`release_write_frame`]. After an
/// interrupted call ([`ChunkError::Call`]) the driver may still be copying
/// from the frame, so it is left mapped and accounted to this process until
/// it exits instead.
///
/// Returns the bytes written. An error after some chunks reached the file
/// returns their count instead, as a short write, so the caller's position
/// stays in step with the file; the error recurs on the next call.
fn write_memory_chunks(
    file_cap: u32,
    aspace: u32,
    memmgr_ep: u32,
    base_offset: u64,
    payload: &[u8],
    ipc_buf: *mut u64,
) -> io::Result<usize>
{
    let frame = acquire_write_frame(aspace, memmgr_ep)?;
    let mut total: usize = 0;
    let mut error = None;
    let mut frame_idle = true;
    while total < payload.len()
    {
        let chunk = &payload[total..(payload.len().min(total + PAGE_SIZE_USIZE))];
        let chunk_offset = base_offset.saturating_add(total as u64);
        match write_frame_chunk(file_cap, &frame, chunk_offset, chunk, ipc_buf)
        {
            Ok(n) =>
            {
                total += n;
                if n < chunk.len()
                {
                    // Short write — let the caller (`write_all`) iterate.
                    break;
                }
            }
            Err(ChunkError::Settled(e)) =>
            {
                error = Some(e);
                break;
            }
            Err(ChunkError::Call(e)) =>
            {
                frame_idle = false;
                error = Some(e);
                break;
            }
        }
    }
    if frame_idle
    {
        release_write_frame(frame, aspace);
    }
    match error
    {
        Some(e) if total == 0 => Err(e),
        _ => Ok(total),
    }
}

/// Copy `chunk` into `frame`, zero the rest of the page, and send one
/// `FS_WRITE_MEMORY` for it.
///
/// The driver receives a `MAP`-only derivation of the frame cap, never the
/// frame cap itself, and returns it as services/fs/docs/fs-driver-protocol.md
/// § Label 12 requires. Every cap the reply carries is deleted, and so is
/// the derivation's handle: a handle the request moved away is stale and its
/// delete fails harmlessly, as docs/capability-model.md § Capability Handle
/// Format defines, while one the kernel left here is freed.
///
/// Returns the bytes written, or `InvalidData` when the driver reports more
/// than `chunk` holds.
fn write_frame_chunk(
    file_cap: u32,
    frame: &WriteFrame,
    offset: u64,
    chunk: &[u8],
    ipc_buf: *mut u64,
) -> Result<usize, ChunkError>
{
    // SAFETY: the frame is mapped writable for one page at `frame.va()` and
    // used by this write alone; `chunk.len() <= PAGE_SIZE`.
    unsafe {
        let va = frame.va() as *mut u8;
        core::ptr::copy_nonoverlapping(chunk.as_ptr(), va, chunk.len());
        core::ptr::write_bytes(va.add(chunk.len()), 0, PAGE_SIZE_USIZE - chunk.len());
    }
    let lent = syscall::cap_derive(frame.cap, syscall_abi::RIGHTS_MEM_MAP).map_err(|_| {
        ChunkError::Settled(io::Error::other("seraph fs: cap_derive of write frame failed"))
    })?;
    let msg = IpcMessage::builder(fs_labels::FS_WRITE_MEMORY)
        .word(0, offset)
        .word(1, chunk.len() as u64)
        .word(2, 0)
        .cap(lent)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) };
    if let Ok(r) = &reply
    {
        for &cap in r.caps()
        {
            let _ = syscall::cap_delete(cap);
        }
    }
    let _ = syscall::cap_delete(lent);
    // `Interrupted` is the one error an `ipc_call` can return after the
    // driver received the message; every other one is a refusal before the
    // call blocked (`ipc::ipc_call` # Errors).
    let reply = reply.map_err(|e| {
        let err = io::Error::other("seraph fs: FS_WRITE_MEMORY ipc_call failed");
        if e == syscall_abi::SyscallError::Interrupted as i64
        {
            ChunkError::Call(err)
        }
        else
        {
            ChunkError::Settled(err)
        }
    })?;
    if reply.label != fs_errors::SUCCESS
    {
        return Err(ChunkError::Settled(map_fs_error(reply.label)));
    }
    let n = reply.word(0) as usize;
    if n > chunk.len()
    {
        return Err(ChunkError::Settled(io::const_error!(
            io::ErrorKind::InvalidData,
            "seraph fs: FS_WRITE_MEMORY reported more bytes than were sent",
        )));
    }
    Ok(n)
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
    /// Badge keying this `File`'s entry in the release-handler registry,
    /// so `Drop` can unregister it; also the badge of `release_send`. A
    /// driver `FS_RELEASE_MEMORY` is matched by cookie across every
    /// registered `File`, not by the badge it arrives on: the driver keeps
    /// one release SEND per node (fs-driver-protocol.md § Label 8).
    badge: u64,
    /// Badged SEND on the per-process release endpoint. It never leaves
    /// this `File`: each delivery attempt moves a `cap_derive`d copy
    /// (which inherits the badge) to the driver, and `Drop` deletes it.
    release_send: u32,
    /// True once an `FS_READ_MEMORY` request whose release-SEND copy the
    /// kernel moved to the driver got a `SUCCESS` reply, which means the
    /// driver's `OpenFile` slot for the node was allocated by then. Until
    /// then every frame read carries a fresh copy, so neither a request
    /// refused before slot allocation nor a concurrent cap-less read can
    /// leave the slot without one; afterwards reads carry none.
    release_confirmed: AtomicBool,
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
        // `FS_WRITE` paths; `FS_READ_MEMORY` transfers copies of it to
        // the driver in `caps[0]` (see `release_copy`) so the driver's
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
        let Some(badge) = release_handler::allocate_badge()
        else
        {
            let _ = syscall::cap_delete(file_cap);
            return Err(io::Error::other("seraph fs: release-badge entropy draw failed"));
        };
        let entry = release_handler::register(state, badge);

        let release_ep = release_handler::release_endpoint(state);
        let release_send =
            match syscall::cap_derive_badge(release_ep, syscall::RIGHTS_EP_SEND, badge)
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
            release_confirmed: AtomicBool::new(false),
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
        // ceiling: 64 data words (`MSG_DATA_WORDS_MAX`) × 8 bytes = 512,
        // minus the 8-byte length prefix in word 0 = 504. Above this a
        // single inline reply cannot carry the bytes; below this the
        // per-call cost is strictly cheaper than the frame path on both
        // x86_64 and riscv64 (≈ 2× factor; see fsbench numbers recorded
        // in `services/fs/docs/fs-driver-protocol.md`).
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
        let Some(cookie) = next_cookie()
        else
        {
            return Err(io::Error::other("seraph fs: read cookie entropy draw failed"));
        };
        let mark = ReadMark::begin(self.entry.as_ref(), cookie);
        // Until the driver's slot is known to hold a release SEND, the
        // request carries a fresh copy of ours in caps[0]: the driver
        // records it if this request allocates the node's OpenFile slot,
        // so its eviction worker can route a cooperative FS_RELEASE_MEMORY
        // back to us, letting us unmap the page, or finish a copy from it,
        // before its revoke, within the driver's cooperative-release window
        // (release_handler); it deletes the copy otherwise.
        let release_copy = self.release_copy();
        let mut builder = IpcMessage::builder(fs_labels::FS_READ_MEMORY)
            .word(0, pos)
            .word(1, cookie);
        if let Some(copy) = release_copy
        {
            builder = builder.cap(copy);
        }
        let msg = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer.
        let result = unsafe { ipc::ipc_call(self.file_cap, &msg, ipc_buf) };
        // A copy the kernel did not move (a refused call, or a delivery
        // degraded to zero caps) is still ours and is deleted here. A moved
        // copy's handle is stale, and the kernel's generation check refuses
        // the delete, so a refusal is what shows the driver received it.
        let copy_moved = release_copy.is_some_and(|copy| syscall::cap_delete(copy).is_err());
        let reply =
            result.map_err(|_| io::Error::other("seraph fs: FS_READ_MEMORY ipc_call failed"))?;
        if reply.label != fs_errors::SUCCESS
        {
            return Err(map_fs_error(reply.label));
        }
        if copy_moved
        {
            // The driver answered a request that carried a SEND, so the
            // node's slot existed by then and later reads need not carry one.
            self.release_confirmed.store(true, Ordering::Relaxed);
        }
        let Some((memory_cap, memory_data_offset, bytes_valid)) =
            self.checked_frame_reply(&reply, cookie)?
        else
        {
            return Ok(0);
        };

        let range = self.map_frame(memory_cap, cookie)?;
        let va = range.va_start();

        let copy_len = bytes_valid.min(buf.len());
        let src = (va + memory_data_offset as u64) as *const u8;
        for (i, byte) in buf[..copy_len].iter_mut().enumerate()
        {
            // SAFETY: VA is mapped read-only for one page and
            // `checked_frame_reply` holds `memory_data_offset + bytes_valid
            // <= PAGE_SIZE`, so `src + i` lies in the mapped page for every
            // `i < copy_len <= bytes_valid`. The page is the driver's and
            // another process may write it: the `ReadMark` holds a driver
            // release off only within the driver's cooperative-release
            // window, and the driver's revoke unmaps nothing, so a copy that
            // outlasts the window can read the page after the driver
            // recycles it. Volatile reads make that a defined read of
            // possibly foreign bytes rather than a data race; the copy is
            // discarded below when it is known to have outlasted the window,
            // and otherwise cannot be told apart (#516).
            *byte = unsafe { core::ptr::read_volatile(src.add(i)) };
        }
        // The copy is done: hand the mapping to the registry, where a driver
        // release that waited on the read can now take it.
        let stalled = mark.finish(OutstandingMapping {
            cookie,
            range,
            memory_cap,
        });

        // Proactive release: synchronous FS_RELEASE_MEMORY on the file
        // cap clears the fs-side outstanding entry and decrements the
        // cache slot's refcount. After ack we own the local cleanup
        // (take_mapping is no-op if the handler thread already grabbed
        // it via a forced-release race).
        self.release_frame(cookie);
        release_handler::release_one_local(self.entry.as_ref(), self.aspace, cookie);

        // A driver release whose wait ran out during the copy means the
        // driver's window had passed, so the page may have been recycled:
        // the bytes are not used, the position stays, and `Interrupted` asks
        // the caller to read again.
        if stalled
        {
            return Err(io::const_error!(
                io::ErrorKind::Interrupted,
                "seraph fs: read page released during the copy",
            ));
        }
        self.pos.fetch_add(copy_len as u64, Ordering::Relaxed);
        Ok(copy_len)
    }

    /// A fresh copy of `release_send` for an `FS_READ_MEMORY` request to
    /// carry, or `None` once a delivery is confirmed or when the derive
    /// fails (the read then goes without one, as an opted-out client's does).
    fn release_copy(&self) -> Option<u32>
    {
        if self.release_confirmed.load(Ordering::Relaxed)
        {
            return None;
        }
        syscall::cap_derive(self.release_send, syscall::RIGHTS_EP_SEND).ok()
    }

    /// Reserve a page, fund this address space's page tables for it, and map
    /// the read frame `memory_cap` read-only there. On failure the frame cap
    /// is deleted and `cookie` released.
    fn map_frame(
        &self,
        memory_cap: u32,
        cookie: u64,
    ) -> io::Result<crate::sys::reserve::ReservedRange>
    {
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
        let failure = if !crate::sys::alloc::seraph::fund_aspace_pt_budget(self.aspace, 1)
        {
            Some("seraph fs: page-table funding failed for read frame")
        }
        else
        {
            // SAFETY: `range` is a fresh reservation from the per-process
            // arena, owned here: VA no Rust object or IPC page occupies.
            let mapped =
                unsafe { syscall::mem_map(memory_cap, self.aspace, va, 0, 1, syscall::MAP_READ) };
            mapped.is_err().then_some("seraph fs: mem_map failed")
        };
        if let Some(msg) = failure
        {
            crate::sys::reserve::unreserve_pages(range);
            let _ = syscall::cap_delete(memory_cap);
            self.release_frame(cookie);
            return Err(io::Error::other(msg));
        }
        Ok(range)
    }

    /// Validate an `FS_READ_MEMORY` success reply as wire input before the
    /// client maps or slices anything. Returns the frame cap, the data offset
    /// in it, and the valid byte count; `None` for end of file (no bytes and
    /// no cap); or `InvalidData` for bytes without a cap, or a span the driver
    /// should have bounded by the page tail (services/fs/docs/fs-driver-protocol.md
    /// § Label 7) that runs past the one page the client maps. Every outcome
    /// but the first deletes the reply's cap and releases `cookie`.
    fn checked_frame_reply(
        &self,
        reply: &IpcMessage,
        cookie: u64,
    ) -> io::Result<Option<(u32, usize, usize)>>
    {
        let bytes_valid = reply.word(0) as usize;
        let memory_data_offset = reply.word(2) as usize;
        let memory_cap = reply.caps().first().copied();
        let in_page = memory_data_offset
            .checked_add(bytes_valid)
            .is_some_and(|end| end <= PAGE_SIZE_USIZE);
        match memory_cap
        {
            Some(cap) if bytes_valid != 0 && in_page =>
            {
                return Ok(Some((cap, memory_data_offset, bytes_valid)));
            }
            Some(cap) =>
            {
                let _ = syscall::cap_delete(cap);
            }
            None =>
            {}
        }
        self.release_frame(cookie);
        if bytes_valid == 0
        {
            return Ok(None);
        }
        Err(io::const_error!(
            io::ErrorKind::InvalidData,
            "seraph fs: FS_READ_MEMORY reply carries no frame or a span past its page",
        ))
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
        // refcount. The revoke invalidates our derived caps but leaves
        // their mappings in place, and fs may recycle the pages (#516),
        // so each VA must still be unmapped, its reservation freed, and
        // its cap deleted.
        if !ipc_buf.is_null()
        {
            let close = IpcMessage::new(fs_labels::FS_CLOSE);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_call(self.file_cap, &close, ipc_buf) };
        }
        let _ = syscall::cap_delete(self.file_cap);

        // Drain the registry entry. A driver release that arrives after
        // unregister, on whichever badge, finds no entry and is acked
        // without action. One already dispatched may take a mapping first
        // and discard it itself; `drain_mappings` and the handler each
        // take a mapping out of `idle` under its lock, so they split the
        // mappings without overlap.
        if let Some(state) = release_handler::state()
        {
            if let Some(entry) = release_handler::unregister(state, self.badge)
            {
                for m in release_handler::drain_mappings(entry.as_ref())
                {
                    release_handler::discard_mapping(m, self.aspace);
                }
            }
        }

        // Drop the per-File badged SEND, which never left this CSpace. The
        // driver's copy of it, if the driver recorded one, is deleted by its
        // FS_CLOSE handler.
        let _ = syscall::cap_delete(self.release_send);
    }
}

/// Per-request correlation cookie for `FS_READ_MEMORY`: a random `u64` from the
/// kernel entropy pool, redrawn off the reserved `0` value (the driver rejects
/// cookie 0 as its outstanding-page `None` sentinel). Random rather than
/// monotonic so the read-memory request count it would otherwise leak to the fs
/// driver stays unguessable; the cookie is opaque and matched by value, never an
/// index. Returns `None` if the entropy draw fails (a kernel-contract violation).
fn next_cookie() -> Option<u64>
{
    loop
    {
        let c = syscall::random_u64().ok()?;
        if c != 0
        {
            return Some(c);
        }
    }
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
        done: false,
    })
}

/// Unlink a regular file. Returns `IsADirectory` if the leaf resolves
/// to a directory (use `rmdir` / `remove_dir_all` for those).
pub fn unlink(path: &Path) -> io::Result<()>
{
    remove_leaf(path, NodeKind::File)
}

/// Remove an empty directory. Returns `NotADirectory` if the leaf
/// resolves to a regular file; returns `DirectoryNotEmpty` if the
/// directory is non-empty.
pub fn rmdir(path: &Path) -> io::Result<()>
{
    remove_leaf(path, NodeKind::Dir)
}

/// Remove the leaf of `path` after confirming it is an `expected` node.
/// `unlink` and `rmdir` differ only in that expectation and in the std
/// `ErrorKind` a mismatch maps to.
fn remove_leaf(path: &Path, expected: NodeKind) -> io::Result<()>
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
    let _ = syscall::cap_delete(walked.cap);
    if walked.kind != expected
    {
        release_split_parent(&split);
        return Err(match expected
        {
            NodeKind::Dir => io::const_error!(
                io::ErrorKind::NotADirectory,
                "seraph fs: target is not a directory",
            ),
            NodeKind::File => io::const_error!(
                io::ErrorKind::IsADirectory,
                "seraph fs: target is a directory",
            ),
        });
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
/// it as `InvalidInput`. The two names share the request's data area
/// after the two length words, so a pair whose combined length does not
/// fit there is refused as `InvalidFilename` even though each name alone
/// passes `validate_name`.
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

    // The names pack contiguously from word 2, so their sum, not each
    // name's own `validate_name` bound, decides whether the request fits
    // the data area; refuse here rather than let the builder assert on
    // caller-supplied lengths.
    if src.leaf.len() + dst.leaf.len() > (MSG_DATA_WORDS_MAX - 2) * 8
    {
        release_split_parent(&src);
        release_split_parent(&dst);
        return Err(io::const_error!(
            io::ErrorKind::InvalidFilename,
            "seraph fs: rename source and target names together exceed the request size",
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
        // The name is wire input. Walked as a path, an empty or slash-only
        // name would name `dir_cap` itself and recurse without end, and a
        // name with a slash would drain another directory; only a single
        // valid component names this entry.
        if validate_name(&entry.name).is_err()
        {
            return Err(io::const_error!(
                io::ErrorKind::InvalidData,
                "seraph fs: NS_READDIR returned an invalid entry name",
            ));
        }

        if matches!(entry.kind, NodeKind::Dir)
        {
            // `validate_name` accepts only UTF-8.
            let leaf_str = core::str::from_utf8(&entry.name).unwrap_or_default();
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
    let Some(end) = NAME_OFF.checked_add(name_len).filter(|&e| e <= bytes.len())
    else
    {
        return Err(io::Error::other("seraph fs: NS_READDIR truncated name"));
    };
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
