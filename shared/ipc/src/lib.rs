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
//     SESSIOND_LABELS_VERSION — sessiond_labels::REGISTER_INTERFACE, in
//                             `data[1]` (interface ↔ sessiond)
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
pub const PROCMGR_LABELS_VERSION: u32 = 22;
pub mod procmgr_labels;

mod procmgr_debug_client;

pub use procmgr_debug_client::{make_resident, make_resident_step, read_mem_resident};

pub mod sched_policy;

/// Wire-protocol version of [`memmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const MEMMGR_LABELS_VERSION: u32 = 17;
pub mod memmgr_labels;

mod memmgr_grant;

pub use memmgr_grant::memmgr_grant_layout;

pub mod memmgr_errors;

pub mod memmgr_bootstrap;

pub mod procmgr_process_state;

/// Wire-protocol version of [`svcmgr_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const SVCMGR_LABELS_VERSION: u32 = 16;
pub mod svcmgr_labels;

/// Wire-protocol version of [`stop_labels`]; bumped as the block comment above
/// the label modules describes, which also lists its runtime check, if any.
pub const STOP_LABELS_VERSION: u32 = 1;
pub mod stop_labels;

/// Wire-protocol version of [`sessiond_labels`]; bumped as the block comment
/// above the label modules describes, which also lists its runtime check, if any.
pub const SESSIOND_LABELS_VERSION: u32 = 1;
pub mod sessiond_labels;

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
pub const DEVMGR_LABELS_VERSION: u32 = 26;
pub mod devmgr_labels;

pub mod test_fault_labels;

pub mod restart_probe_labels;

pub mod memhog_labels;

pub mod stopsrc_labels;

pub mod test_dma_labels;

mod devmgr_client;

pub use devmgr_client::{
    ClassCallError, ClassWatch, ReadyError, Refresh, await_device, class_name_of, decline_restart,
    first_device, first_device_from, mint_class_send, query_device, refresh_device,
    report_driver_ready, watch_class,
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
}
