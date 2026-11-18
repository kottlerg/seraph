// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/lib.rs

//! Shared IPC helpers for Seraph userspace services.
//!
//! Provides the stack-owned [`IpcMessage`] snapshot type plus thin
//! `ipc_call` / `ipc_recv` / `ipc_reply` wrappers that keep the kernel's
//! per-thread IPC buffer as scratch at the syscall boundary (nested IPC
//! cannot clobber a received/reply message). Also hosts the bootstrap
//! protocol (children receive their initial cap set via IPC from their
//! creator), typed error-code constants, label modules, and the shared
//! policy and code tables listed in `shared/ipc/README.md`.

// When built as a std dep via `rustc-dep-of-std`, we switch to `no_core`
// and rebind `core` to the `rustc_std_workspace_core` facade — same dance
// as abi/syscall and shared/syscall.
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
#![expect(
    clippy::cast_possible_truncation,
    reason = "userspace targets are 64-bit only, so u64 to usize is lossless; u32 capability slot \
              indices are bounded by CSpace capacity"
)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use syscall_abi::{MSG_CAP_HANDLES_WORD, MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

// ── IPC label constants ─────────────────────────────────────────────────────
//
// Per-service IPC operation labels. Namespaced by service because label
// numbers are only meaningful relative to a specific endpoint.
//
// Each `*_LABELS_VERSION` constant declares the wire-protocol version of
// its namespace. When it is bumped, and what each of the four categories
// below means, is specified in shared/ipc/README.md § Wire Stability; this
// block keeps the per-namespace assignment, with the handshake each check
// rides on.
//
//   Handshake-checked at first contact (`data[0]` unless noted):
//     FS_LABELS_VERSION     — fs_labels::FS_MOUNT             (vfsd ↔ fatfs)
//     VFSD_LABELS_VERSION   — vfsd_labels::GET_SYSTEM_ROOT_CAP (init ↔ vfsd),
//                             vfsd_labels::GET_SWAP_PARTITION
//                             (swap service ↔ vfsd), and every
//                             vfsd_labels::UNMOUNT request
//     BLK_LABELS_VERSION    — blk_labels::REGISTER_PARTITION   (vfsd ↔ virtio-blk)
//                             and blk_labels::BLK_GET_GEOMETRY
//                             (vfsd, fatfs ↔ virtio-blk)
//     MEMMGR_LABELS_VERSION — memmgr_labels::REGISTER_PROCESS   (procmgr ↔ memmgr)
//     SVCMGR_LABELS_VERSION — every svcmgr handover endowment `CAPS` round,
//                             in `data[1]` after the round kind (init ↔ svcmgr)
//
//   Checked on every request (`data[0]`):
//     DEVMGR_LABELS_VERSION     — every devmgr_labels request
//     DEVMGR_DMA_LABELS_VERSION — every devmgr_dma_labels request
//     IOMMU_LABELS_VERSION      — every iommu_labels request (devmgr ↔ IOMMU driver)
//     LOG_LABELS_VERSION        — every log_labels::QUERY_SLOTS and QUERY_HISTORY
//                                 request (client ↔ logd)
//     ACPID_LABELS_VERSION      — every acpid_labels request (pwrmgr ↔ acpid)
//
//   Implicitly covered by a parent-channel handshake:
//     NS_LABELS_VERSION     — caps from vfsd_labels / fs_labels handshakes
//
//   Marker-only (no clean parent-channel handshake exists, and per-message
//   inlining would conflict with existing label-bit usage or cost wire bytes
//   on every call; PROCESS_ABI_VERSION at process startup gives
//   coarse-grained coverage in lockstep with workspace-inherited versioning):
//     PROCMGR_LABELS_VERSION
//     STOP_LABELS_VERSION
//     PWRMGR_LABELS_VERSION
//     RTC_LABELS_VERSION
//     TIMED_LABELS_VERSION
//     SERIAL_LABELS_VERSION
//     FB_LABELS_VERSION
//     INPUT_LABELS_VERSION
//     STREAM_LABELS_VERSION — stream caps arrive pre-installed in
//                             ProcessInfo.log_send_cap (init derives its
//                             own), not via a handshake

/// Append a name block to a request whose words before `at` are already
/// set: word `at` holds `name`'s length in bytes, and the bytes follow from
/// word `at + 1`, packed little-endian. `None` when `name` is empty or
/// longer than `max`, which the receiver would refuse.
#[must_use]
pub fn with_name_block(
    builder: IpcMessageBuilder,
    at: usize,
    name: &[u8],
    max: usize,
) -> Option<IpcMessageBuilder>
{
    if name.is_empty() || name.len() > max
    {
        return None;
    }
    Some(
        builder
            .word(at, name.len() as u64)
            .bytes(at.saturating_add(1), name),
    )
}

/// The name in the name block at word `at` of `req` ([`with_name_block`]):
/// `None` when the request delivers no length word, the length is zero or
/// above `max`, or the words delivered do not cover the name's bytes.
#[must_use]
pub fn name_block(req: &IpcMessage, at: usize, max: usize) -> Option<&[u8]>
{
    if at >= req.word_count()
    {
        return None;
    }
    let len = usize::try_from(req.word(at)).ok()?;
    if len == 0 || len > max
    {
        return None;
    }
    let start = at.checked_add(1)?.checked_mul(8)?;
    req.data_bytes().get(start..start.checked_add(len)?)
}

/// Wire-protocol version of [`procmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const PROCMGR_LABELS_VERSION: u32 = 19;
pub mod procmgr_labels;

pub mod sched_policy;

/// Wire-protocol version of [`memmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const MEMMGR_LABELS_VERSION: u32 = 13;
pub mod memmgr_labels;

mod memmgr_grant;

pub use memmgr_grant::memmgr_grant_layout;

pub mod memmgr_errors;

pub mod memmgr_bootstrap;

pub mod procmgr_process_state;

/// Wire-protocol version of [`svcmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const SVCMGR_LABELS_VERSION: u32 = 14;
pub mod svcmgr_labels;

/// Wire-protocol version of [`stop_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const STOP_LABELS_VERSION: u32 = 1;
pub mod stop_labels;

pub mod published_names;

/// Wire-protocol version of [`rtc_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const RTC_LABELS_VERSION: u32 = 1;
pub mod rtc_labels;

pub mod rtc_errors;

/// Wire-protocol version of [`timed_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const TIMED_LABELS_VERSION: u32 = 1;
pub mod timed_labels;

pub mod timed_errors;

/// Wire-protocol version of [`pwrmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const PWRMGR_LABELS_VERSION: u32 = 1;
pub mod pwrmgr_labels;

pub mod pwrmgr_errors;

/// Wire-protocol version of [`acpid_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const ACPID_LABELS_VERSION: u32 = 2;
pub mod acpid_labels;

pub mod acpid_errors;

/// Wire-protocol version of [`vfsd_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const VFSD_LABELS_VERSION: u32 = 4;
pub mod vfsd_labels;

/// Wire-protocol version of [`ns_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const NS_LABELS_VERSION: u32 = 1;
pub mod ns_labels;

/// Wire-protocol version of [`fs_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const FS_LABELS_VERSION: u32 = 6;
pub mod fs_labels;

/// Wire-protocol version of [`devmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const DEVMGR_LABELS_VERSION: u32 = 25;
pub mod devmgr_labels;

pub mod test_fault_labels;

pub mod restart_probe_labels;

pub mod memhog_labels;

pub mod stopsrc_labels;

pub mod test_dma_labels;

mod devmgr_client;

pub use devmgr_client::{
    ClassCallError, ClassWatch, ReadyError, await_device, class_name_of, first_device,
    first_device_from, mint_class_send, query_device, report_driver_ready, watch_class,
};

pub mod device_info_kind;

/// Wire-protocol version of [`devmgr_dma_labels`]; bumped as the block comment
/// above the label modules describes, which also lists its runtime check.
pub const DEVMGR_DMA_LABELS_VERSION: u32 = 3;
pub mod devmgr_dma_labels;

pub mod devmgr_dma_errors;

mod devmgr_dma_client;

pub use devmgr_dma_client::{DmaError, DmaFaults, dma_faults, dma_map, dma_unmap};

/// Wire-protocol version of [`iommu_labels`]; bumped as the block comment
/// above the label modules describes, which also lists its runtime check.
pub const IOMMU_LABELS_VERSION: u32 = 5;
pub mod iommu_labels;

pub mod iommu_errors;

/// Wire-protocol version of [`blk_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const BLK_LABELS_VERSION: u32 = 3;
pub mod blk_labels;

/// Wire-protocol version of [`serial_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const SERIAL_LABELS_VERSION: u32 = 2;
pub mod serial_labels;

pub mod serial_errors;

/// Wire-protocol version of [`fb_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const FB_LABELS_VERSION: u32 = 2;
pub mod fb_labels;

pub mod fb_errors;

/// Wire-protocol version of [`input_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const INPUT_LABELS_VERSION: u32 = 1;
pub mod input_labels;

pub mod input_errors;

pub mod keysym;

/// Wire-protocol version of [`stream_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const STREAM_LABELS_VERSION: u32 = 4;
pub mod stream_labels;

/// Badge bits that endpoints gating a label on a verb-bit use for it: each
/// `*_AUTHORITY` constant in this crate is one of these bits, as are
/// `procmgr_labels::PROCESS_HANDLE_TAG` and `memmgr_labels::NODE_HANDLE_TAG`.
/// A minter whose badges carry other information onto such an endpoint keeps
/// them clear — procmgr's random per-process badge, stamped on the child's
/// svcmgr-registry and procmgr SENDs, and memmgr's per-process badges, which
/// keep bits 58 to 62 clear and use bit 63 for the phys class — so only a
/// server's trusted minters set a verb bit (docs/capability-model.md § Verb-bit
/// authority pattern). Endpoints with no verb gate (bootstrap endpoints,
/// namespace node caps) do not reserve them.
pub const VERB_BIT_MASK: u64 =
    (1u64 << 63) | (1u64 << 62) | (1u64 << 61) | (1u64 << 60) | (1u64 << 59) | (1u64 << 58);
const _: () = core::assert!(
    devmgr_labels::SHUTDOWN_DEVICE_AUTHORITY & VERB_BIT_MASK != 0
        && devmgr_labels::BIND_AUTHORITY & VERB_BIT_MASK != 0
        && devmgr_labels::CLASS_AUTHORITY & VERB_BIT_MASK != 0
        && devmgr_labels::ACPI_AUTHORITY & VERB_BIT_MASK != 0
        && acpid_labels::POWER_AUTHORITY & VERB_BIT_MASK != 0
        && vfsd_labels::MOUNT_AUTHORITY & VERB_BIT_MASK != 0
        && vfsd_labels::SEED_AUTHORITY & VERB_BIT_MASK != 0
        && vfsd_labels::SWAP_AUTHORITY & VERB_BIT_MASK != 0
        && vfsd_labels::DENY_BADGE & VERB_BIT_MASK == 0
        && log_labels::LOG_QUERY_AUTHORITY & VERB_BIT_MASK != 0
        && log_badges::LOG_BADGE_INIT & VERB_BIT_MASK == 0
        && log_badges::LOG_BADGE_PROCMGR & VERB_BIT_MASK == 0
);

pub mod log_badges;

/// Wire-protocol version of [`log_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const LOG_LABELS_VERSION: u32 = 5;
pub mod log_labels;

// ── Bootstrap protocol ──────────────────────────────────────────────────────
//
// Children receive the startup caps their `ProcessInfo` does not carry via IPC
// on their `creator_endpoint` cap. The child issues `bootstrap::REQUEST` in a
// loop; the creator replies with up to
// `MSG_CAP_SLOTS_MAX = 4` caps plus arbitrary payload words per round. The
// reply label's low byte indicates whether more rounds are expected (`MORE`)
// or the bootstrap is complete (`DONE`).
//
// The payload format (which data words mean what, which cap slot goes where)
// is defined per (creator, child-type) pair in each child's crate. No shared
// cap-role enum; no per-service sentinels.

pub mod bootstrap;

pub mod log_query;

pub mod log_record;

pub mod recv_guard;

pub mod bootstrap_errors;

// ── Typed error codes per service ───────────────────────────────────────────
//
// Named constants replace bare numeric reply labels at every `ipc_reply` site.
// `SUCCESS == 0` is an invariant across all services; callers still read
// `label != 0` as a coarse success/failure check.

pub mod procmgr_errors;

pub mod vfsd_errors;

pub mod fs_errors;

pub mod devmgr_errors;

pub mod svcmgr_errors;

pub mod blk_errors;

// ── Protocol constants ─────────────────────────────────────────────────────

/// The one path limit of svcmgr's recipes, in bytes: a `.svc` `binary`
/// path and a `namespace = subtree:<path>` path. It bounds no pool: no
/// message carries a whole path, since svcmgr walks each one a component at
/// a time and stores each at its own length, so the value (the POSIX
/// `PATH_MAX`) only refuses a recipe whose path is longer than any recipe
/// written for this tree, whose paths are tens of bytes.
pub const MAX_PATH_LEN: usize = 4096;

// ── IpcMessage ──────────────────────────────────────────────────────────────

/// Stack-owned snapshot of an IPC message — label, badge, data words, and
/// received capability handles, carried by value across the IPC wrapper
/// boundary.
///
/// `ipc_recv` and the reply path of `ipc_call` return an `IpcMessage`;
/// `ipc_call` and `ipc_reply` consume one built via [`IpcMessageBuilder`].
/// Received data is copied out of the per-thread IPC buffer before the
/// wrapper returns, which leaves the buffer as pure scratch at the syscall
/// boundary — nested IPC (stdio, logging, any IPC-using helper) is safe by
/// construction.
///
/// Fixed-size inline payload (`MSG_DATA_WORDS_MAX` = 64 data words, 512 B)
/// plus `MSG_CAP_SLOTS_MAX` cap handles. No allocation; `no_std`-clean;
/// cheap to return by value.
#[derive(Clone, Copy)]
pub struct IpcMessage
{
    /// Protocol label (opcode / reply code / bit-packed header).
    pub label: u64,
    /// Endpoint badge delivered by `ipc_recv`; zero on send paths
    /// and for unbadged endpoints.
    pub badge: u64,
    data: [u64; MSG_DATA_WORDS_MAX],
    /// Number of valid `u64` words in `data`. `<= MSG_DATA_WORDS_MAX`: every
    /// [`IpcMessageBuilder`] setter panics past the bound in every build (an
    /// empty source at an out-of-range start included), and
    /// [`IpcMessage::from_ipc_buf`] requires it of its caller. That bound
    /// (64) is far below `u8::MAX`, so the width never truncates.
    data_len: u8,
    /// Number of valid slots in `cap_slots`. `<= MSG_CAP_SLOTS_MAX` (4), far
    /// below `u8::MAX`.
    cap_count: u8,
    cap_slots: [u64; MSG_CAP_SLOTS_MAX],
}

impl IpcMessage
{
    /// Zero-length message carrying only a label (no data, no caps, no
    /// badge).
    #[must_use]
    pub const fn new(label: u64) -> Self
    {
        Self {
            label,
            badge: 0,
            data: [0; MSG_DATA_WORDS_MAX],
            data_len: 0,
            cap_count: 0,
            cap_slots: [0; MSG_CAP_SLOTS_MAX],
        }
    }

    /// Start a builder. Equivalent to [`IpcMessageBuilder::new`].
    #[must_use]
    pub const fn builder(label: u64) -> IpcMessageBuilder
    {
        IpcMessageBuilder::new(label)
    }

    /// Read data word `idx`. Reading past the sender's declared
    /// `word_count()` returns zero — the unused array slots are zero-init
    /// and the kernel does not write them past the declared range. This
    /// is a deliberate contract so protocols that carry optional trailing
    /// words at fixed offsets keep working.
    ///
    /// # Panics
    /// Panics in every build if `idx >= MSG_DATA_WORDS_MAX`; the index is a
    /// protocol constant, so an overrun is a programmer error.
    #[must_use]
    pub fn word(&self, idx: usize) -> u64
    {
        assert!(
            idx < MSG_DATA_WORDS_MAX,
            "IpcMessage::word: idx exceeds MSG_DATA_WORDS_MAX"
        );
        // The assertion keeps `idx` inside `data`, so `get` always finds it.
        self.data.get(idx).copied().unwrap_or_default()
    }

    /// Slice view of the populated data words: `&data[..word_count()]`.
    #[must_use]
    pub fn words(&self) -> &[u64]
    {
        // `data_len <= MSG_DATA_WORDS_MAX`, so `get` always finds the range.
        self.data
            .get(..usize::from(self.data_len))
            .unwrap_or_default()
    }

    /// Number of populated data words.
    #[must_use]
    pub fn word_count(&self) -> usize
    {
        self.data_len as usize
    }

    /// Byte-slice view of the populated data words (little-endian).
    ///
    /// Length is `word_count() * 8`. Byte-level protocols (path, blob)
    /// typically carry their byte length separately in the label or a
    /// data word; callers slice this view accordingly.
    #[must_use]
    pub fn data_bytes(&self) -> &[u8]
    {
        let words = self.words();
        // SAFETY: `words` is a bounds-checked sub-slice of `data`, so a byte
        // view of `words.len() * 8` bytes from its start covers only
        // initialised memory of that array; u64 alignment is stricter than
        // u8 alignment, and the shared borrow of `self` keeps the array
        // alive and unmodified for the returned slice's lifetime.
        unsafe {
            core::slice::from_raw_parts(words.as_ptr().cast::<u8>(), core::mem::size_of_val(words))
        }
    }

    /// Slice view of the message's cap handles: on a received message, the
    /// delivered destination handles; on a message being built, the full
    /// handles to transfer (see [`IpcMessageBuilder::cap`]).
    #[must_use]
    pub fn caps(&self) -> &[u64]
    {
        // `cap_count <= MSG_CAP_SLOTS_MAX`, so `get` always finds the range.
        self.cap_slots
            .get(..usize::from(self.cap_count))
            .unwrap_or_default()
    }

    /// Snapshot the IPC buffer into an owned `IpcMessage`.
    ///
    /// Reads `word_count` data words plus cap metadata from the registered
    /// IPC buffer page. Used by the `ipc_recv` / `ipc_call` wrappers after
    /// the kernel returns.
    ///
    /// # Safety
    /// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC
    /// buffer page as registered via `ipc_buffer_set`. `word_count` must
    /// be `<= MSG_DATA_WORDS_MAX`.
    #[must_use]
    pub unsafe fn from_ipc_buf(
        ipc_buf: *const u64,
        label: u64,
        badge: u64,
        word_count: usize,
    ) -> Self
    {
        debug_assert!(word_count <= MSG_DATA_WORDS_MAX);
        let mut data = [0u64; MSG_DATA_WORDS_MAX];
        for (i, slot) in data.iter_mut().take(word_count).enumerate()
        {
            // SAFETY: `i < word_count <= MSG_DATA_WORDS_MAX`, so the offset
            // stays inside the 4 KiB buffer the caller's contract names.
            let word = unsafe { ipc_buf.add(i) };
            // SAFETY: the caller guarantees `ipc_buf` is its mapped,
            // page-aligned IPC buffer, and `word` lies inside it. Volatile
            // because the kernel writes the page.
            *slot = unsafe { core::ptr::read_volatile(word) };
        }
        // Cap metadata: cap_count at word[MSG_DATA_WORDS_MAX], delivered
        // cap handles at word[MSG_CAP_HANDLES_WORD ..].
        // SAFETY: `syscall_abi` asserts that the cap block, which follows
        // word `MSG_DATA_WORDS_MAX`, ends inside the 4 KiB buffer.
        let cap_count_word = unsafe { ipc_buf.add(MSG_DATA_WORDS_MAX) };
        // SAFETY: the caller guarantees `ipc_buf` is its mapped,
        // page-aligned IPC buffer, and `cap_count_word` lies inside it.
        let cap_count_raw = unsafe { core::ptr::read_volatile(cap_count_word) };
        let cap_count = (cap_count_raw as usize).min(MSG_CAP_SLOTS_MAX);
        let mut cap_slots = [0u64; MSG_CAP_SLOTS_MAX];
        // SAFETY: `syscall_abi` asserts that the cap block, which starts at
        // word `MSG_CAP_HANDLES_WORD`, ends inside the 4 KiB buffer.
        let cap_block = unsafe { ipc_buf.add(MSG_CAP_HANDLES_WORD) };
        for (i, slot) in cap_slots.iter_mut().take(cap_count).enumerate()
        {
            // SAFETY: `i < cap_count <= MSG_CAP_SLOTS_MAX`, the cap block's
            // length, so the offset stays inside the block.
            let word = unsafe { cap_block.add(i) };
            // SAFETY: the caller guarantees `ipc_buf` is its mapped,
            // page-aligned IPC buffer, and `word` lies inside it.
            *slot = unsafe { core::ptr::read_volatile(word) };
        }
        Self {
            label,
            badge,
            data,
            data_len: word_count as u8,
            cap_count: cap_count as u8,
            cap_slots,
        }
    }

    /// Write the populated data words and the cap handles to transfer into
    /// the IPC buffer.
    ///
    /// Used by the `ipc_call` / `ipc_reply` wrappers before issuing the
    /// syscall. The handles go to the cap block (word
    /// `MSG_CAP_HANDLES_WORD` on), where the kernel reads the `cap_count`
    /// the syscall names; the count itself travels in a register. The
    /// kernel installs the caps in the receiver and writes the
    /// receiver-side handles into the receiver's buffer.
    ///
    /// # Safety
    /// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC
    /// buffer page as registered via `ipc_buffer_set`.
    pub unsafe fn write_to_ipc_buf(&self, ipc_buf: *mut u64)
    {
        for (i, &val) in self.words().iter().enumerate()
        {
            // SAFETY: `words()` is a bounds-checked sub-slice of the
            // `MSG_DATA_WORDS_MAX`-word `data` array, so
            // `i < MSG_DATA_WORDS_MAX` and the offset is within the
            // 4 KiB buffer.
            let word = unsafe { ipc_buf.add(i) };
            // SAFETY: the caller guarantees `ipc_buf` is its mapped,
            // page-aligned IPC buffer, and `word` lies inside it.
            unsafe { core::ptr::write_volatile(word, val) };
        }
        // SAFETY: `syscall_abi` asserts that the cap block, which starts at
        // word `MSG_CAP_HANDLES_WORD`, ends inside the 4 KiB buffer.
        let cap_block = unsafe { ipc_buf.add(MSG_CAP_HANDLES_WORD) };
        for (i, &handle) in self.caps().iter().enumerate()
        {
            // SAFETY: `caps()` holds at most MSG_CAP_SLOTS_MAX handles, the
            // cap block's length, so the offset stays inside the block.
            let word = unsafe { cap_block.add(i) };
            // SAFETY: the caller guarantees `ipc_buf` is its mapped,
            // page-aligned IPC buffer, and `word` lies inside it.
            unsafe { core::ptr::write_volatile(word, handle) };
        }
    }
}

/// Up to eight bytes of `chunk`, zero-padded to the eight bytes of one data
/// word in little-endian order; bytes past the eighth are not read.
pub(crate) fn padded_word(chunk: &[u8]) -> [u8; 8]
{
    let mut bytes = [0u8; 8];
    for (byte, &src) in bytes.iter_mut().zip(chunk)
    {
        *byte = src;
    }
    bytes
}

// ── IpcMessageBuilder ──────────────────────────────────────────────────────

/// Chainable builder that assembles an [`IpcMessage`] on the caller's
/// stack, without touching the per-thread IPC buffer.
///
/// Typical use at a send site:
/// ```ignore
/// ipc_call(
///     ep,
///     &IpcMessage::builder(label).word(0, value).cap(slot).build(),
///     ipc_buf,
/// )
/// ```
#[derive(Clone, Copy)]
pub struct IpcMessageBuilder
{
    msg: IpcMessage,
}

impl IpcMessageBuilder
{
    /// New builder with the given label and nothing else set.
    #[must_use]
    pub const fn new(label: u64) -> Self
    {
        Self {
            msg: IpcMessage::new(label),
        }
    }

    /// Set data word `idx`; grow `word_count` to cover it if needed.
    ///
    /// # Panics
    /// Panics in every build if `idx >= MSG_DATA_WORDS_MAX`, before
    /// `word_count` can grow past the bound; see
    /// [`IpcMessageBuilder::word_count`] for why an overrun is treated as
    /// a programmer error.
    #[must_use]
    pub fn word(mut self, idx: usize, val: u64) -> Self
    {
        assert!(
            idx < MSG_DATA_WORDS_MAX,
            "IpcMessageBuilder::word: idx exceeds MSG_DATA_WORDS_MAX"
        );
        // The assertion keeps `idx` inside `data`, so `get_mut` always finds it.
        if let Some(slot) = self.msg.data.get_mut(idx)
        {
            *slot = val;
        }
        // `idx < MSG_DATA_WORDS_MAX`, far below `u8::MAX`, so neither the
        // cast nor the addition loses the count.
        let needed = (idx as u8).saturating_add(1);
        if self.msg.data_len < needed
        {
            self.msg.data_len = needed;
        }
        self
    }

    /// Write `src` words contiguously starting at word `start`; grow
    /// `word_count` to cover the range.
    ///
    /// # Panics
    /// Panics in every build if `start + src.len() > MSG_DATA_WORDS_MAX`,
    /// an empty `src` at an out-of-range `start` included, so `word_count`
    /// can never be set past the bound; see
    /// [`IpcMessageBuilder::word_count`] for why the bound is asserted.
    #[must_use]
    pub fn words(mut self, start: usize, src: &[u64]) -> Self
    {
        // A sum past `usize::MAX` saturates, and fails the assertion as well.
        let end = start.saturating_add(src.len());
        assert!(
            end <= MSG_DATA_WORDS_MAX,
            "IpcMessageBuilder::words: range exceeds MSG_DATA_WORDS_MAX"
        );
        // `start <= end <= MSG_DATA_WORDS_MAX`, so `get_mut` always finds the
        // range, which is `src.len()` words long.
        if let Some(dst) = self.msg.data.get_mut(start..end)
        {
            dst.copy_from_slice(src);
        }
        let needed = end as u8;
        if self.msg.data_len < needed
        {
            self.msg.data_len = needed;
        }
        self
    }

    /// Pack `src` bytes into data words (little-endian u64), starting at
    /// word `start_word`. Grows `word_count` to cover the packed bytes.
    ///
    /// # Panics
    /// Panics in every build if the packed range
    /// `start_word + src.len().div_ceil(8)` exceeds `MSG_DATA_WORDS_MAX`, an
    /// empty `src` at an out-of-range `start_word` included, so `word_count`
    /// can never be set past the bound; see
    /// [`IpcMessageBuilder::word_count`] for why the bound is asserted.
    #[must_use]
    pub fn bytes(mut self, start_word: usize, src: &[u8]) -> Self
    {
        let word_count = src.len().div_ceil(8);
        // A sum past `usize::MAX` saturates, and fails the assertion as well.
        let end = start_word.saturating_add(word_count);
        assert!(
            end <= MSG_DATA_WORDS_MAX,
            "IpcMessageBuilder::bytes: range exceeds MSG_DATA_WORDS_MAX"
        );
        // `start_word <= end <= MSG_DATA_WORDS_MAX`, so `get_mut` always finds
        // the range.
        if let Some(dst) = self.msg.data.get_mut(start_word..end)
        {
            for (word, chunk) in dst.iter_mut().zip(src.chunks(8))
            {
                *word = u64::from_le_bytes(padded_word(chunk));
            }
        }
        let needed = end as u8;
        if self.msg.data_len < needed
        {
            self.msg.data_len = needed;
        }
        self
    }

    /// Append one capability to transfer. `handle` must be the full cap
    /// handle as returned by the cap syscalls (index + per-slot generation)
    /// — the kernel generation-validates it and rejects a stale handle with
    /// `InvalidCapability`.
    ///
    /// # Panics
    /// Panics in every build if `MSG_CAP_SLOTS_MAX` caps are already
    /// appended; a message's cap count is a protocol constant, so an overrun
    /// is a programmer error.
    #[must_use]
    pub fn cap(mut self, handle: u64) -> Self
    {
        let idx = usize::from(self.msg.cap_count);
        assert!(
            idx < MSG_CAP_SLOTS_MAX,
            "IpcMessageBuilder::cap: MSG_CAP_SLOTS_MAX caps already appended"
        );
        // The assertion keeps `idx` inside `cap_slots`, so `get_mut` always
        // finds it.
        if let Some(slot) = self.msg.cap_slots.get_mut(idx)
        {
            *slot = handle;
        }
        // The count is below `MSG_CAP_SLOTS_MAX`, so this cannot saturate.
        self.msg.cap_count = self.msg.cap_count.saturating_add(1);
        self
    }

    /// Replace the label set at construction.
    #[must_use]
    pub fn label(mut self, label: u64) -> Self
    {
        self.msg.label = label;
        self
    }

    /// Explicitly set `word_count`. Useful when a protocol wants padding
    /// words counted (`words`/`word`/`bytes` auto-grow only to the
    /// highest touched word).
    ///
    /// # Panics
    /// Panics in every build if `len > MSG_DATA_WORDS_MAX`. The count is a
    /// protocol constant, so an overrun is a programmer error — the same
    /// one `word`/`words`/`bytes` panic on for an out-of-range index — and
    /// it must not reach the `data_len <= MSG_DATA_WORDS_MAX` invariant the
    /// message's views rely on.
    #[must_use]
    pub fn word_count(mut self, len: usize) -> Self
    {
        assert!(
            len <= MSG_DATA_WORDS_MAX,
            "IpcMessageBuilder::word_count: len exceeds MSG_DATA_WORDS_MAX"
        );
        self.msg.data_len = len as u8;
        self
    }

    /// Finalize the message.
    #[must_use]
    pub const fn build(self) -> IpcMessage
    {
        self.msg
    }
}

// ── IPC wrappers (IpcMessage-snapshot) ──────────────────────────────────────

/// Synchronous IPC call on an endpoint, returning a stack-owned reply snapshot.
///
/// Writes `msg`'s payload into the registered IPC buffer, issues
/// `SYS_IPC_CALL`, then copies the reply (label + data words + cap metadata)
/// back out of the buffer into a fresh [`IpcMessage`]. After return the IPC
/// buffer is scratch — nested IPC (stdio, logging, any IPC-using helper)
/// cannot clobber the returned message.
///
/// The endpoint cap must have `EpRights::GRANT` when `msg.caps()` is non-empty.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code if the endpoint cap is invalid, the
/// caller has insufficient rights (`GRANT` missing on a cap-bearing call),
/// a cap slot is stale or Null (`InvalidCapability`), a cap slot is
/// repeated in the message (`InvalidArgument`), a cap slot is pinned by an
/// in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability transfer
/// (`InvalidState`), a cap's object has its reference count at its 2^31
/// ceiling (`QuotaExceeded`), or the call is interrupted. Cap-slot problems are
/// rejected before blocking; a refusal arising only afterwards delivers the
/// message with zero caps (the caller keeps its capabilities).
#[inline]
pub unsafe fn ipc_call(ep: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    // SAFETY: this fn's contract is ipc_call_timeout's.
    unsafe { ipc_call_timeout(ep, msg, ipc_buf, 0) }
}

/// [`ipc_call`] bounded by `timeout_ms` milliseconds over the whole call: the
/// wait for a receiver and the wait for its reply. `0` waits without bound,
/// as [`ipc_call`] does.
///
/// # Safety
/// As [`ipc_call`].
///
/// # Errors
/// As [`ipc_call`], and `WouldBlock` when the timeout expired first. The
/// request may then have been received: a server that replies after the
/// expiry finds no pending caller.
#[inline]
pub unsafe fn ipc_call_timeout(
    ep: u64,
    msg: &IpcMessage,
    ipc_buf: *mut u64,
    timeout_ms: u32,
) -> Result<IpcMessage, i64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        msg.write_to_ipc_buf(ipc_buf);
    }
    let (reply_label, reply_word_count) = syscall::raw_ipc_call_timeout(
        ep,
        msg.label,
        msg.word_count(),
        msg.caps().len(),
        timeout_ms,
    )?;
    // SAFETY: `ipc_buf` is the registered IPC buffer; kernel wrote the
    // reply (data + cap metadata) into it before return. `reply_word_count`
    // is already clamped to MSG_DATA_WORDS_MAX by `raw_ipc_call`.
    Ok(unsafe { IpcMessage::from_ipc_buf(ipc_buf, reply_label, 0, reply_word_count) })
}

/// Receive on an endpoint cap, returning a stack-owned message snapshot.
///
/// Blocks until a caller sends. Copies the message (label, badge, data
/// words, cap metadata) from the registered IPC buffer into a fresh
/// [`IpcMessage`] before returning. After return the IPC buffer is scratch
/// — nested IPC between `ipc_recv` and reading the message is safe.
///
/// A reply still pending from an earlier receive is released once the
/// receive passes its capability check and cap-slot pre-allocation: that
/// caller's `ipc_call` returns `Interrupted`, a fault-blocked caller is
/// killed (one blocked on its restartable syscall's user copy has that syscall
/// fail with `InvalidAddress` instead), and a caller blocked in an upcall
/// delivery has the upcall dropped and resumes. A receive refused before then
/// keeps the pending binding (see
/// `docs/ipc-design.md` § The Call/Reply Model).
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code:
/// - `InvalidCapability` — `ep` is not a live Endpoint cap.
/// - `InsufficientRights` — `ep` lacks Receive rights.
/// - `QuotaExceeded` — the cap-slot pre-allocation for incoming caps was
///   refused because this thread's `CSpace` directory is structurally full.
/// - `OutOfMemory` — the cap-slot pre-allocation was refused because the
///   `CSpace`'s slot-page pool is exhausted.
/// - `Interrupted` — this thread was stopped or interrupted by an upcall, or
///   the endpoint was destroyed, while the receive was blocked.
///
/// The first four refuse the receive before any pending reply is released,
/// so a pending caller stays bound.
#[inline]
pub unsafe fn ipc_recv(ep: u64, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    // SAFETY: this fn's contract is ipc_recv_timeout's.
    unsafe { ipc_recv_timeout(ep, ipc_buf, 0) }
}

/// [`ipc_recv`] under `SYS_IPC_RECV`'s `timeout_ms` policy: `0` waits without
/// bound (as [`ipc_recv`]), `u64::MAX` (`syscall::WAIT_TRY_ONCE`) never
/// waits ([`ipc_try_recv`]), and any other value waits up to `timeout_ms`
/// milliseconds. A try-once that finds no caller keeps a reply still pending
/// from an earlier receive; one that finds a caller releases it as
/// [`ipc_recv`] does.
///
/// # Safety
/// As [`ipc_recv`].
///
/// # Errors
/// As [`ipc_recv`], and `WouldBlock` on an empty try-once or an expiry.
#[inline]
pub unsafe fn ipc_recv_timeout(
    ep: u64,
    ipc_buf: *mut u64,
    timeout_ms: u64,
) -> Result<IpcMessage, i64>
{
    let (label, badge, word_count) = syscall::raw_ipc_recv_timeout(ep, timeout_ms)?;
    // SAFETY: `ipc_buf` is the registered IPC buffer; kernel wrote data +
    // cap metadata there before return. `word_count` is already clamped to
    // MSG_DATA_WORDS_MAX by `raw_ipc_recv_timeout`.
    Ok(unsafe { IpcMessage::from_ipc_buf(ipc_buf, label, badge, word_count) })
}

/// Receive a call already waiting on `ep` without blocking
/// ([`ipc_recv_timeout`] with `syscall::WAIT_TRY_ONCE`).
///
/// # Safety
/// As [`ipc_recv`].
///
/// # Errors
/// As [`ipc_recv`], and `WouldBlock` when no caller is waiting.
#[inline]
pub unsafe fn ipc_try_recv(ep: u64, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    // SAFETY: this fn's contract is ipc_recv_timeout's.
    unsafe { ipc_recv_timeout(ep, ipc_buf, syscall::WAIT_TRY_ONCE) }
}

/// Reply to the current thread's pending caller with `msg`.
///
/// Writes `msg`'s data words into the registered IPC buffer, then issues
/// `SYS_IPC_REPLY` with `msg.word_count()` words and `msg.caps()` cap slots.
/// Cap slots move from the server's `CSpace` to the caller's `CSpace`
/// all-or-nothing with the reply. An `Err` return consumes the pending
/// reply either way: when a caller was claimed it has already been woken
/// with the synthetic `IPC_REPLY_TRANSFER_FAILED` label (a reply cap slot
/// stale, repeated, pinned by an in-flight revoke, move, or IPC capability
/// transfer, naming an object at its reference ceiling, or unacceptable to
/// its `CSpace`), and when none was pending
/// there is nothing to wake — in both cases the reply must not be retried.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's 4 KiB-aligned IPC buffer
/// page as registered via `syscall::ipc_buffer_set`.
///
/// # Errors
/// Returns a negative `i64` error code: `InvalidCapability` (no pending
/// reply target, or a reply cap slot is stale or Null), `InvalidArgument`
/// (a cap slot repeated in the reply), `InvalidState` (a reply cap slot is
/// pinned by an in-flight `SYS_CAP_REVOKE`, `SYS_CAP_MOVE`, or IPC capability
/// transfer), `QuotaExceeded` (the caller's `CSpace` directory cannot accept
/// the reply caps, or a reply cap's object has its reference count at its
/// 2^31 ceiling), or `OutOfMemory` (the caller's `CSpace` slot pool cannot
/// back them). The reply never blocks, so it never returns
/// `Interrupted`; the message's counts are within the kernel's maxima by
/// construction (the kernel clamps larger ones rather than rejecting them).
#[inline]
pub unsafe fn ipc_reply(msg: &IpcMessage, ipc_buf: *mut u64) -> Result<(), i64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        msg.write_to_ipc_buf(ipc_buf);
    }
    syscall::raw_ipc_reply(msg.label, msg.word_count(), msg.caps().len())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_create_name_block_follows_every_other_create_word()
    {
        use procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_FROM_FILE, CREATE_MEMORY_MAX, CREATE_PROCESS, create_name_word,
        };
        assert_eq!(create_name_word(CREATE_PROCESS), 1);
        assert_eq!(create_name_word(CREATE_FROM_FILE | CREATE_MEMORY_MAX), 2);
        assert_eq!(create_name_word(CREATE_PROCESS | CREATE_ARGV_ENV), 5);
        assert_eq!(
            create_name_word(CREATE_FROM_FILE | CREATE_ARGV_ENV | CREATE_MEMORY_MAX),
            6
        );
    }

    #[test]
    fn a_create_name_round_trips_at_every_length()
    {
        use procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_FROM_FILE, CREATE_MEMORY_MAX, CREATE_NAME_MAX, create_name,
            with_create_name,
        };
        let label = CREATE_FROM_FILE | CREATE_ARGV_ENV | CREATE_MEMORY_MAX;
        let mut name = [0u8; CREATE_NAME_MAX];
        for (i, byte) in name.iter_mut().enumerate()
        {
            *byte = b'a' + (i % 26) as u8;
        }
        for len in [1, 7, 8, 9, 16, 17, CREATE_NAME_MAX]
        {
            let builder = IpcMessage::builder(label).word(0, 4096).word(5, 9);
            let msg = with_create_name(builder, label, &name[..len])
                .unwrap()
                .build();
            assert_eq!(create_name(&msg), Some(&name[..len]), "length {len}");
            // The words before the block are untouched.
            assert_eq!((msg.word(0), msg.word(5)), (4096, 9));
        }
    }

    #[test]
    fn a_create_name_block_that_is_missing_empty_long_or_short_is_refused()
    {
        use procmgr_labels::{
            CREATE_FROM_FILE, CREATE_NAME_MAX, CREATE_PROCESS, create_name, with_create_name,
        };
        let long = [b'x'; CREATE_NAME_MAX + 1];
        let builder = || IpcMessage::builder(CREATE_PROCESS).word(0, 4096);
        assert!(with_create_name(builder(), CREATE_PROCESS, b"").is_none());
        assert!(with_create_name(builder(), CREATE_PROCESS, &long).is_none());
        // No length word delivered.
        assert_eq!(create_name(&builder().build()), None);
        // A zero or over-long length word.
        assert_eq!(create_name(&builder().word(1, 0).build()), None);
        let over = builder()
            .word(1, CREATE_NAME_MAX as u64 + 1)
            .bytes(2, &long);
        assert_eq!(create_name(&over.build()), None);
        // A length the delivered words do not cover.
        let short = IpcMessage::builder(CREATE_FROM_FILE)
            .word(0, 1)
            .word(1, 9)
            .bytes(2, b"/abcdefg");
        assert_eq!(create_name(&short.build()), None);
    }

    #[test]
    fn a_class_badge_round_trips_and_carries_no_authority_bit()
    {
        use devmgr_labels::class_badge::{MAX_SLOTS, decode, encode};
        let verbs = serial_labels::WRITE_AUTHORITY | serial_labels::READ_AUTHORITY;
        for slot in [0, 1, 63, MAX_SLOTS - 1]
        {
            let badge = encode(slot, verbs).unwrap();
            assert_eq!(badge & VERB_BIT_MASK, 0, "slot {slot}");
            assert_eq!(decode(badge), Some((slot, verbs)));
        }
        assert_eq!(
            decode(encode(5, VERB_BIT_MASK).unwrap()),
            Some((5, VERB_BIT_MASK))
        );
    }

    #[test]
    fn a_class_badge_refuses_what_it_cannot_name()
    {
        use devmgr_labels::class_badge::{MAX_SLOTS, decode, encode};
        assert_eq!(encode(MAX_SLOTS, blk_labels::MOUNT_AUTHORITY), None);
        assert_eq!(encode(0, 0), None);
        assert_eq!(encode(0, 1), None);
        // No registry SEND of an authority bit reads as a class badge.
        for badge in [
            0,
            devmgr_labels::REGISTRY_QUERY_AUTHORITY,
            devmgr_labels::REGISTRY_QUERY_AUTHORITY | devmgr_labels::BIND_AUTHORITY,
            devmgr_labels::CLASS_AUTHORITY,
            devmgr_labels::DRIVERS_DIR_AUTHORITY,
        ]
        {
            assert_eq!(decode(badge), None, "badge {badge:#x}");
        }
        // A slot without verbs, verbs without a slot, and a class badge with
        // an authority bit added are refused.
        assert_eq!(decode(1), None);
        let good = encode(2, blk_labels::MOUNT_AUTHORITY).unwrap();
        assert_eq!(decode(good & !devmgr_labels::class_badge::SLOT_MASK), None);
        assert_eq!(decode(good | devmgr_labels::REGISTRY_QUERY_AUTHORITY), None);
        assert_eq!(decode(good | (1 << 30)), None);
    }

    #[test]
    fn a_class_name_reads_back_from_its_words()
    {
        let msg = IpcMessage::builder(devmgr_labels::MINT_CLASS_SEND)
            .word(0, 17)
            .word(1, 1 << 63)
            .word(2, 11)
            .bytes(3, b"debug-port!")
            .build();
        assert_eq!(class_name_of(&msg, 2), Some(&b"debug-port!"[..]));
        let short = IpcMessage::builder(0).word(1, 4).bytes(2, b"rtc").build();
        assert_eq!(class_name_of(&short, 1), Some(&b"rtc\0"[..]));
        let long = IpcMessage::builder(0).word(1, 9).bytes(2, b"rtc").build();
        assert_eq!(class_name_of(&long, 1), None);
        let empty = IpcMessage::builder(0).word(1, 0).build();
        assert_eq!(class_name_of(&empty, 1), None);
        let over = IpcMessage::builder(0)
            .word(1, devmgr_labels::MAX_CLASS_NAME_BYTES as u64 + 1)
            .bytes(2, &[b'a'; 40])
            .build();
        assert_eq!(class_name_of(&over, 1), None);
        assert_eq!(class_name_of(&empty, 5), None);
    }

    #[test]
    fn a_stream_label_level_reads_back_and_an_absent_one_reads_as_info()
    {
        use stream_labels::{
            LEVEL_ERROR, LEVEL_INFO, LEVEL_MASK, LEVEL_SHIFT, LEVEL_TRACE, LEVEL_WARN,
            STREAM_BYTES, level_of,
        };
        let label = |level: u64| STREAM_BYTES | (40 << 16) | (level << LEVEL_SHIFT);
        assert_eq!(level_of(label(LEVEL_WARN)), LEVEL_WARN);
        assert_eq!(level_of(label(LEVEL_ERROR)), LEVEL_ERROR);
        assert_eq!(level_of(label(LEVEL_TRACE)), LEVEL_TRACE);
        // A sender that sets no level (the pre-level encoding) logs at info.
        assert_eq!(level_of(STREAM_BYTES | (40 << 16)), LEVEL_INFO);
        // The unassigned codes read as info too.
        assert_eq!(level_of(label(6)), LEVEL_INFO);
        assert_eq!(level_of(label(LEVEL_MASK)), LEVEL_INFO);
        // The level field leaves the id and the length intact.
        assert_eq!(label(LEVEL_TRACE) & 0xFFFF, STREAM_BYTES);
        assert_eq!((label(LEVEL_TRACE) >> 16) & 0xFFFF, 40);
    }

    // Defect caught: a named-sender bit inside the id, length, or level field,
    // which would change a line's label, length, or level, or a full field
    // that reads as the bit.
    #[test]
    fn the_named_sender_bit_lies_outside_every_other_label_field()
    {
        use stream_labels::{
            LEVEL_MASK, LEVEL_SHIFT, LEVEL_WARN, SENDER_NAMED, STREAM_RECORD, level_of,
            sender_named,
        };
        let full = 0xFFFF | (0xFFFF << 16) | (LEVEL_MASK << LEVEL_SHIFT);
        assert!(!sender_named(full));
        assert_eq!(full & SENDER_NAMED, 0);
        let label = STREAM_RECORD | (37 << 16) | (LEVEL_WARN << LEVEL_SHIFT) | SENDER_NAMED;
        assert!(sender_named(label));
        assert_eq!(label & 0xFFFF, STREAM_RECORD);
        assert_eq!((label >> 16) & 0xFFFF, 37);
        assert_eq!(level_of(label), LEVEL_WARN);
    }

    #[test]
    fn a_process_list_page_round_trips_names_of_every_length()
    {
        use procmgr_labels::{LIST_PROCESSES_PAGE, pack_list_entry, unpack_list_entry};
        let long = [b'x'; svcmgr_labels::NAME_MAX];
        let names: [&[u8]; 4] = [b"svctest", &long, b"", b"seven77"];
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        for (i, name) in names.iter().enumerate()
        {
            assert!(pack_list_entry(&mut words, i, 0x100 + i as u64, name));
        }
        words[0] = names.len() as u64;
        for (i, name) in names.iter().enumerate()
        {
            let mut out = [0u8; svcmgr_labels::NAME_MAX];
            let (badge, len) = unpack_list_entry(&words, i, &mut out).unwrap();
            assert_eq!((badge, &out[..len]), (0x100 + i as u64, *name));
        }
        assert!(
            unpack_list_entry(&words, names.len(), &mut [0; svcmgr_labels::NAME_MAX]).is_none()
        );
        // A full page fits the message, and the entry past it does not.
        assert!(pack_list_entry(
            &mut words,
            LIST_PROCESSES_PAGE - 1,
            1,
            b"a"
        ));
        assert!(!pack_list_entry(&mut words, LIST_PROCESSES_PAGE, 1, b"a"));
    }

    #[test]
    fn a_process_list_entry_truncates_a_long_name_and_refuses_a_long_length()
    {
        use procmgr_labels::{pack_list_entry, unpack_list_entry};
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        let long = [b'n'; svcmgr_labels::NAME_MAX + 9];
        assert!(pack_list_entry(&mut words, 0, 7, &long));
        words[0] = 1;
        let mut out = [0u8; svcmgr_labels::NAME_MAX];
        assert_eq!(
            unpack_list_entry(&words, 0, &mut out),
            Some((7, svcmgr_labels::NAME_MAX))
        );
        words[2] = svcmgr_labels::NAME_MAX as u64 + 1;
        assert!(unpack_list_entry(&words, 0, &mut out).is_none());
    }

    // The defect caught: an entry index whose word offset overflows `usize`,
    // which wrapped to a small offset and wrote or read another entry.
    #[test]
    fn a_process_list_index_whose_offset_overflows_is_refused()
    {
        use procmgr_labels::{LIST_PROCESSES_WORDS_PER_ENTRY, pack_list_entry, unpack_list_entry};
        let index = usize::MAX / LIST_PROCESSES_WORDS_PER_ENTRY + 1;
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_list_entry(&mut words, index, 7, b"a"));
        assert_eq!(words, [0; MSG_DATA_WORDS_MAX]);
        words[0] = u64::MAX;
        let mut out = [0u8; svcmgr_labels::NAME_MAX];
        assert!(unpack_list_entry(&words, index, &mut out).is_none());
    }

    #[test]
    fn a_requester_id_packs_segment_bus_device_and_function()
    {
        assert_eq!(iommu_labels::requester_id(0, 0, 3, 0), 0x18);
        assert_eq!(iommu_labels::requester_id(1, 2, 0x1f, 7), 0x1_02ff);
        // Out-of-range device and function bits are masked off.
        assert_eq!(iommu_labels::requester_id(0, 0, 0x20, 8), 0);
    }

    #[test]
    fn a_fault_reply_fits_its_count_and_two_words_per_fault()
    {
        const { assert!(2 * iommu_labels::MAX_FAULTS_PER_REPLY < MSG_DATA_WORDS_MAX) };
    }

    /// A `REQUEST_MEMORY_CAPS` reply with `label`, data `words`, and one
    /// transferred cap per entry of `caps`.
    fn grant_reply(label: u64, words: &[u64], caps: &[u64]) -> IpcMessage
    {
        let mut b = IpcMessage::builder(label).words(0, words);
        for &c in caps
        {
            b = b.cap(c);
        }
        b.build()
    }

    #[test]
    fn grant_layout_splits_page_counts_and_region_ids_per_cap()
    {
        let reply = grant_reply(0, &[2, 3, 5, 7, 8], &[11, 12]);
        let (pages, ids) = memmgr_grant_layout(&reply).expect("well-formed reply");
        assert_eq!(pages, &[3, 5]);
        assert_eq!(ids, &[7, 8]);
    }

    #[test]
    fn grant_layout_refuses_an_error_label()
    {
        let reply = grant_reply(
            memmgr_errors::OUT_OF_MEMORY_CONTIGUOUS,
            &[1, 1, 0x1000],
            &[11],
        );
        assert_eq!(memmgr_grant_layout(&reply), None);
    }

    #[test]
    fn grant_layout_refuses_a_reply_without_data_words()
    {
        assert_eq!(memmgr_grant_layout(&grant_reply(0, &[], &[11])), None);
    }

    #[test]
    fn grant_layout_refuses_a_zero_count()
    {
        assert_eq!(memmgr_grant_layout(&grant_reply(0, &[0], &[])), None);
    }

    #[test]
    fn grant_layout_refuses_a_count_other_than_the_caps_transferred()
    {
        // Declaring more caps than arrived would put the id words at an
        // offset the transferred count does not establish.
        let reply = grant_reply(0, &[2, 1, 1, 0x1000, 0x2000], &[11]);
        assert_eq!(memmgr_grant_layout(&reply), None);
    }

    #[test]
    fn grant_layout_refuses_words_too_few_for_the_count()
    {
        let reply = grant_reply(0, &[2, 1, 1, 0x1000], &[11, 12]);
        assert_eq!(memmgr_grant_layout(&reply), None);
    }

    #[test]
    fn packed_bytes_round_trip_through_data_bytes_with_zero_padding()
    {
        // 13 bytes straddle a word boundary: the tail word must carry the
        // 5 live bytes little-endian and zero padding above them.
        let payload: [u8; 13] = *b"seraph-ipc:13";
        let msg = IpcMessage::builder(7).bytes(1, &payload).build();
        assert_eq!(msg.word_count(), 3);
        let bytes = msg.data_bytes();
        assert_eq!(bytes.len(), 24);
        assert_eq!(&bytes[..8], &[0u8; 8]);
        assert_eq!(&bytes[8..21], &payload);
        assert_eq!(&bytes[21..], &[0u8; 3]);
    }

    #[test]
    fn setters_accept_ranges_ending_exactly_at_the_data_bound()
    {
        let msg = IpcMessage::builder(1)
            .words(MSG_DATA_WORDS_MAX - 2, &[1, 2])
            .bytes(MSG_DATA_WORDS_MAX - 1, &[0xAA; 8])
            .word_count(MSG_DATA_WORDS_MAX)
            .build();
        assert_eq!(msg.word_count(), MSG_DATA_WORDS_MAX);
        assert_eq!(msg.word(MSG_DATA_WORDS_MAX - 2), 1);
        assert_eq!(msg.word(MSG_DATA_WORDS_MAX - 1), 0xAAAA_AAAA_AAAA_AAAA);
    }

    #[test]
    fn reading_past_the_declared_count_yields_zero()
    {
        let msg = IpcMessage::builder(1).word(2, 9).build();
        assert_eq!(msg.word_count(), 3);
        assert_eq!(msg.word(MSG_DATA_WORDS_MAX - 1), 0);
    }

    #[test]
    #[should_panic(expected = "word_count: len exceeds MSG_DATA_WORDS_MAX")]
    fn word_count_past_the_data_bound_panics()
    {
        let _ = IpcMessage::builder(1).word_count(MSG_DATA_WORDS_MAX + 1);
    }

    #[test]
    #[should_panic(expected = "words: range exceeds MSG_DATA_WORDS_MAX")]
    fn empty_words_at_an_out_of_range_start_panics()
    {
        let _ = IpcMessage::builder(1).words(MSG_DATA_WORDS_MAX + 1, &[]);
    }

    #[test]
    #[should_panic(expected = "bytes: range exceeds MSG_DATA_WORDS_MAX")]
    fn empty_bytes_at_an_out_of_range_start_panics()
    {
        let _ = IpcMessage::builder(1).bytes(MSG_DATA_WORDS_MAX + 1, &[]);
    }

    #[test]
    #[should_panic(expected = "words: range exceeds MSG_DATA_WORDS_MAX")]
    fn words_whose_end_overflows_usize_panic()
    {
        let _ = IpcMessage::builder(1).words(usize::MAX, &[1]);
    }

    #[test]
    #[should_panic(expected = "bytes: range exceeds MSG_DATA_WORDS_MAX")]
    fn bytes_whose_end_overflows_usize_panic()
    {
        let _ = IpcMessage::builder(1).bytes(usize::MAX, &[1]);
    }

    #[test]
    #[should_panic(expected = "IpcMessageBuilder::word: idx exceeds MSG_DATA_WORDS_MAX")]
    fn setting_a_word_past_the_data_bound_panics()
    {
        let _ = IpcMessage::builder(1).word(MSG_DATA_WORDS_MAX, 1);
    }

    #[test]
    #[should_panic(expected = "IpcMessage::word: idx exceeds MSG_DATA_WORDS_MAX")]
    fn reading_a_word_past_the_data_bound_panics()
    {
        let _ = IpcMessage::new(1).word(MSG_DATA_WORDS_MAX);
    }

    #[test]
    fn caps_fill_every_slot_in_order()
    {
        let msg = (0..MSG_CAP_SLOTS_MAX as u64)
            .fold(IpcMessage::builder(1), |b, handle| b.cap(handle + 10))
            .build();
        let expected: [u64; MSG_CAP_SLOTS_MAX] = core::array::from_fn(|i| i as u64 + 10);
        assert_eq!(msg.caps(), expected.as_slice());
    }

    #[test]
    #[should_panic(expected = "IpcMessageBuilder::cap: MSG_CAP_SLOTS_MAX caps already appended")]
    fn a_cap_past_the_slot_bound_panics()
    {
        let full =
            (0..MSG_CAP_SLOTS_MAX as u64).fold(IpcMessage::builder(1), IpcMessageBuilder::cap);
        let _ = full.cap(99);
    }

    #[test]
    fn a_candidate_list_page_round_trips_every_field_and_name_length()
    {
        use stop_labels::{LIST_CANDIDATES_PAGE, pack_candidate, unpack_candidate};
        use svcmgr_labels::NAME_MAX;
        let long = [b'x'; NAME_MAX];
        let names: [&[u8]; 3] = [b"memhog", &long, b"a"];
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        for (i, name) in names.iter().enumerate()
        {
            let i64 = i as u64;
            assert!(pack_candidate(
                &mut words,
                i,
                u64::MAX - i64,
                i64,
                0x100 + i64,
                name
            ));
        }
        words[0] = names.len() as u64;
        for (i, name) in names.iter().enumerate()
        {
            let entry = unpack_candidate(&words, i).unwrap();
            let i64 = i as u64;
            assert_eq!(
                (entry.key, entry.rank, entry.pages, &entry.name[..entry.len]),
                (u64::MAX - i64, i64, 0x100 + i64, *name)
            );
            assert!(entry.name[entry.len..].iter().all(|&b| b == 0));
        }
        assert!(unpack_candidate(&words, names.len()).is_none());
        // A full page fits the message, and the entry past it does not.
        assert!(pack_candidate(
            &mut words,
            LIST_CANDIDATES_PAGE - 1,
            1,
            0,
            1,
            b"a"
        ));
        assert!(!pack_candidate(
            &mut words,
            LIST_CANDIDATES_PAGE,
            1,
            0,
            1,
            b"a"
        ));
    }

    #[test]
    fn a_candidate_entry_refuses_names_outside_one_to_name_max()
    {
        use stop_labels::{HEADER_WORDS, pack_candidate, unpack_candidate};
        use svcmgr_labels::NAME_MAX;
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_candidate(&mut words, 0, 1, 0, 7, b""));
        assert!(!pack_candidate(
            &mut words,
            0,
            1,
            0,
            7,
            &[b'n'; NAME_MAX + 1]
        ));
        assert_eq!(words, [0; MSG_DATA_WORDS_MAX]);
        assert!(pack_candidate(&mut words, 0, 1, 0, 7, b"job"));
        words[0] = 1;
        // A length the reply claims past NAME_MAX, or zero, is wire input
        // refused, not read.
        words[HEADER_WORDS + 3] = NAME_MAX as u64 + 1;
        assert!(unpack_candidate(&words, 0).is_none());
        words[HEADER_WORDS + 3] = 0;
        assert!(unpack_candidate(&words, 0).is_none());
    }

    #[test]
    fn a_candidate_index_whose_offset_overflows_is_refused()
    {
        use stop_labels::{CANDIDATE_WORDS, pack_candidate, unpack_candidate};
        let index = usize::MAX / CANDIDATE_WORDS + 1;
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_candidate(&mut words, index, 1, 0, 7, b"a"));
        assert_eq!(words, [0; MSG_DATA_WORDS_MAX]);
        words[0] = u64::MAX;
        assert!(unpack_candidate(&words, index).is_none());
    }

    #[test]
    fn a_stop_source_page_round_trips_and_holds_one_entry_per_cap()
    {
        use svcmgr_labels::{
            LIST_STOP_SOURCES_PAGE, NAME_MAX, STOP_SOURCE_WORDS, pack_stop_source,
            unpack_stop_source,
        };
        assert_eq!(LIST_STOP_SOURCES_PAGE, MSG_CAP_SLOTS_MAX);
        let long = [b'y'; NAME_MAX];
        let names: [&[u8]; 2] = [b"sessiond", &long];
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        for (i, name) in names.iter().enumerate()
        {
            assert!(pack_stop_source(&mut words, i, 1 + i as u64, name));
        }
        words[0] = names.len() as u64;
        for (i, name) in names.iter().enumerate()
        {
            let (class, out, len) = unpack_stop_source(&words, i).unwrap();
            assert_eq!((class, &out[..len]), (1 + i as u64, *name));
        }
        assert!(unpack_stop_source(&words, names.len()).is_none());
        assert!(!pack_stop_source(&mut words, 0, 1, b""));
        assert!(pack_stop_source(
            &mut words,
            LIST_STOP_SOURCES_PAGE - 1,
            1,
            b"a"
        ));
        // A claimed length past NAME_MAX is refused, and an index whose
        // offset overflows writes and reads nothing.
        words[0] = 1;
        words[3] = NAME_MAX as u64 + 1;
        assert!(unpack_stop_source(&words, 0).is_none());
        let index = usize::MAX / STOP_SOURCE_WORDS + 1;
        let mut empty = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_stop_source(&mut empty, index, 1, b"a"));
        assert_eq!(empty, [0; MSG_DATA_WORDS_MAX]);
        empty[0] = u64::MAX;
        assert!(unpack_stop_source(&empty, index).is_none());
    }

    #[test]
    fn svcmgr_name_round_trips_at_every_length_to_name_max()
    {
        use svcmgr_labels::{NAME_MAX, NAME_WORDS, pack_name, unpack_name};
        let source: [u8; NAME_MAX] = core::array::from_fn(|i| b'a' + (i % 26) as u8);
        for len in 1..=NAME_MAX
        {
            let mut words = [u64::MAX; NAME_WORDS];
            assert_eq!(pack_name(&source[..len], &mut words), Some(len.div_ceil(8)));
            let back = unpack_name(&words, len).expect("packed name unpacks");
            assert_eq!(&back[..len], &source[..len]);
            assert!(back[len..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn svcmgr_name_codec_refuses_lengths_outside_one_to_name_max()
    {
        use svcmgr_labels::{NAME_MAX, NAME_WORDS, pack_name, unpack_name};
        let mut words = [u64::MAX; NAME_WORDS];
        assert_eq!(pack_name(&[b'a'; NAME_MAX + 1], &mut words), None);
        assert_eq!(words, [0; NAME_WORDS]);
        assert_eq!(unpack_name(&words, 0), None);
        assert_eq!(unpack_name(&words, NAME_MAX + 1), None);
        // A length whose words the message does not carry.
        assert_eq!(unpack_name(&words[..1], 9), None);
    }
}
