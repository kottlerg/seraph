// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/va_layout/src/lib.rs

//! Centralised userspace virtual-address layout.
//!
//! Every hardcoded VA in userspace is defined here. The kernel does not
//! allocate VAs (every mapping syscall takes a caller-supplied VA), so
//! conflict detection must happen at the workspace level. Each constant
//! carries a comment describing the region's owner, lifetime, and size.
//!
//! Zones for *different processes* do not conflict in the kernel — every
//! process has its own page table. The constants below are organised by
//! consuming process so that within a single aspace no two zones overlap.
//! `const_assert!` enforces the critical non-overlaps.
//!
//! Boundaries come from `docs/userspace-memory-model.md`.
//!
//! # Enforcement
//! No new userspace VA constant may be declared outside this crate. Every
//! addition goes here; callers `use va_layout::*`. VA constants follow
//! the workspace convention of a trailing `_VA` segment (e.g.
//! `PROCESS_STACK_GUARD_VA`, `CHILD_IPC_BUF_VA`, `VIRTIO_BLK_BAR_MAP_VA`).
//! Verify with:
//!
//! ```text
//! grep -rnE 'const\s+[A-Z0-9_]+_VA\s*[:=]' . --include='*.rs' \
//!   | grep -v '/shared/va_layout/' \
//!   | grep -v '/target/' \
//!   | grep -v '/abi/' \
//!   | grep -v '/ktest/' \
//!   | grep -v 'SERIAL_VA'
//! ```
//!
//! Expected output: empty. Exclusions:
//! - `abi/init-protocol`, `abi/process-abi`: stable ABI surfaces mirror
//!   their own VA constants independently.
//! - `ktest/`: kernel-only test harness with local test fixtures.
//! - `SERIAL_VA` in `init/src/arch/riscv64/mod.rs`: platform-specific
//!   UART MMIO, single consumer, not cross-component.

// When built as a std dep via `rustc-dep-of-std`, we switch to `no_core`
// and rebind `core` to the `rustc_std_workspace_core` facade — same dance
// as abi/syscall and shared/syscall. This crate has no runtime code, but
// build-std still needs the crate root to resolve against the std-local
// `core`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

// ── Architectural constants ─────────────────────────────────────────────────

/// Userspace page size in bytes. All VAs declared in this module are
/// multiples of this value.
pub const PAGE_SIZE: u64 = 0x1000;

// ── Common: ProcessInfo + main-thread stack (every normal process) ──────────
//
// Normal processes (everything spawned by procmgr) have `ProcessInfo`
// mapped at `PROCESS_INFO_VA` and a main-thread stack of
// `PROCESS_STACK_PAGES` pages whose top (exclusive) is `PROCESS_STACK_TOP`.
//
// Layout (high → low):
//   PROCESS_STACK_TOP              (exclusive upper bound)
//     `PROCESS_STACK_PAGES` pages mapped, stack grows downward
//   PROCESS_STACK_BOTTOM           (first mapped stack page)
//   PROCESS_STACK_GUARD            (unmapped; catches overflow)
//   … gap …
//   PROCESS_INFO_VA                (read-only `ProcessInfo` page)

/// `ProcessInfo` page VA: kernel-populated, read-only, one page.
pub const PROCESS_INFO_VA: u64 = 0x0000_7FFF_FFFF_0000;

/// Main-thread stack top (exclusive upper bound).
pub const PROCESS_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// Main-thread stack size in 4 KiB pages.
pub const PROCESS_STACK_PAGES: u64 = 4;

/// Main-thread stack bottom (inclusive; lowest mapped page).
pub const PROCESS_STACK_BOTTOM: u64 = PROCESS_STACK_TOP - PROCESS_STACK_PAGES * 0x1000;

/// Guard page immediately below the main-thread stack. Unmapped; a stack
/// overflow faults here instead of corrupting heap or adjacent mappings.
pub const PROCESS_STACK_GUARD_VA: u64 = PROCESS_STACK_BOTTOM - 0x1000;

// ── Heap (every std-built service) ──────────────────────────────────────────

/// Heap base (inclusive). std-built services get a `#[global_allocator]`
/// (from `std::sys::seraph`) managing this region.
pub const HEAP_BASE: u64 = 0x0000_0000_4000_0000;

/// Heap zone upper bound (exclusive). Maximum heap size = `HEAP_MAX -
/// HEAP_BASE` = 1 GiB. Growth beyond this bound surfaces OOM.
pub const HEAP_MAX: u64 = 0x0000_0000_8000_0000;

/// Initial heap size at `_start`, in 4 KiB pages. Large enough to cover
/// stdio's lazy 1 KiB line-buffer, two 64 KiB worker-thread stacks plus
/// their per-thread IPC buffer pages (std `thread::spawn` on seraph
/// allocates both from the heap), and typical collection workloads. Cost
/// is a one-off `REQUEST_FRAMES` round-trip at bootstrap, ≈ 512 KiB of
/// physical RAM per process — cheap relative to fragmentation / contended
/// grow-path cost later. Requested in `FRAMES_PER_REQUEST`-sized batches
/// (procmgr's per-call limit).
pub const HEAP_INITIAL_PAGES: u64 = 128;

/// Maximum frames procmgr returns per `REQUEST_FRAMES` call. Fixed by the
/// IPC cap-slot limit on the reply side.
pub const FRAMES_PER_REQUEST: u64 = 4;

// ── init-protocol ABI ───────────────────────────────────────────────────────

/// `InitInfo` page delivered by the kernel to init (init-specific aspace).
pub const INIT_INFO_VA: u64 = 0x0000_7FFF_FFFF_8000;

// ── init process ────────────────────────────────────────────────────────────

/// init main-thread IPC buffer.
pub const INIT_IPC_BUF_VA: u64 = 0x0000_0000_C000_0000;

/// init log-thread IPC buffer (one page above the main IPC buffer).
pub const INIT_LOG_THREAD_IPC_BUF_VA: u64 = 0x0000_0000_C000_1000;

/// init log-thread stack base.
pub const INIT_LOG_THREAD_STACK_VA: u64 = 0x0000_0000_D000_0000;

/// Base for init's scratch mappings (`ProcessInfo` frames, ELF pages).
pub const INIT_TEMP_MAP_BASE: u64 = 0x0000_0001_0000_0000;

/// procmgr's IPC buffer VA as seen from init while bootstrapping procmgr.
pub const PROCMGR_IPC_BUF_VA: u64 = 0x0000_7FFF_FFFE_0000;

/// Per-page ELF write scratch during init's procmgr bootstrap. Sits inside
/// the `INIT_TEMP_MAP_BASE` scratch region, offset 256 MiB.
pub const INIT_ELF_PAGE_TEMP_VA: u64 = INIT_TEMP_MAP_BASE + 0x1000_0000;

// ── procmgr process ─────────────────────────────────────────────────────────

/// IPC buffer VA mapped into every child aspace by procmgr.
pub const CHILD_IPC_BUF_VA: u64 = 0x0000_7FFF_FFFE_0000;

/// Temporary scratch for inspecting a module frame during ELF load.
pub const PROCMGR_TEMP_MODULE_VA: u64 = 0x0000_0000_8000_0000;

/// Temporary scratch for mapping a child frame while populating ELF pages.
pub const PROCMGR_TEMP_FRAME_VA: u64 = 0x0000_0000_9000_0000;

/// Temporary scratch for mapping VFS buffer pages during
/// `CREATE_PROCESS_FROM_VFS`.
pub const PROCMGR_TEMP_VFS_VA: u64 = 0x0000_0000_A000_0000;

// ── devmgr process ──────────────────────────────────────────────────────────

/// Base for devmgr's MMIO mappings (ECAM and per-device BAR windows).
pub const DEVMGR_MMIO_MAP_VA: u64 = 0x0000_0001_0000_0000;

// ── vfsd process ────────────────────────────────────────────────────────────

/// vfsd worker-thread stack base.
pub const VFSD_WORKER_STACK_VA: u64 = 0x0000_0000_D000_0000;

/// vfsd worker-thread stack page count.
pub const VFSD_WORKER_STACK_PAGES: u64 = 2;

/// vfsd worker-thread IPC buffer (one page above the worker stack top).
pub const VFSD_WORKER_IPC_BUF_VA: u64 = 0x0000_0000_D001_0000;

// ── drivers/virtio/blk process ──────────────────────────────────────────────

/// virtio-blk BAR MMIO mapping.
pub const VIRTIO_BLK_BAR_MAP_VA: u64 = 0x0000_0001_0000_0000;

/// virtio-blk virtqueue ring DMA mapping (64 KiB above the BAR).
pub const VIRTIO_BLK_RING_MAP_VA: u64 = 0x0000_0001_0001_0000;

/// virtio-blk data buffer DMA mapping (1 MiB above the BAR).
pub const VIRTIO_BLK_DATA_MAP_VA: u64 = 0x0000_0001_0010_0000;

// ── Compile-time non-overlap assertions ─────────────────────────────────────

// Heap zone is non-empty and sits below service temp zones.
const _: () = assert!(HEAP_MAX > HEAP_BASE);
const _: () = assert!(HEAP_MAX <= PROCMGR_TEMP_MODULE_VA);

// Stack zone is below ProcessInfo-page end-boundary on the high side and
// above its own guard on the low side.
const _: () = assert!(PROCESS_STACK_TOP > PROCESS_INFO_VA);
const _: () = assert!(PROCESS_STACK_BOTTOM < PROCESS_STACK_TOP);
const _: () = assert!(PROCESS_STACK_GUARD_VA + 0x1000 == PROCESS_STACK_BOTTOM);
// Guard above ProcessInfo's end (one page).
const _: () = assert!(PROCESS_STACK_GUARD_VA >= PROCESS_INFO_VA + 0x1000);

// init zones ordered and non-overlapping.
const _: () = assert!(INIT_IPC_BUF_VA + 0x1000 == INIT_LOG_THREAD_IPC_BUF_VA);
const _: () = assert!(INIT_LOG_THREAD_IPC_BUF_VA < INIT_LOG_THREAD_STACK_VA);

// procmgr temp zones in strictly ascending order, 256 MiB apart.
const _: () = assert!(PROCMGR_TEMP_MODULE_VA + 0x1000_0000 == PROCMGR_TEMP_FRAME_VA);
const _: () = assert!(PROCMGR_TEMP_FRAME_VA + 0x1000_0000 == PROCMGR_TEMP_VFS_VA);

// virtio-blk zones ordered within the 4-GiB aperture.
const _: () = assert!(VIRTIO_BLK_BAR_MAP_VA < VIRTIO_BLK_RING_MAP_VA);
const _: () = assert!(VIRTIO_BLK_RING_MAP_VA < VIRTIO_BLK_DATA_MAP_VA);

// All userspace VAs are in the lower canonical half.
const _: () = assert!(PROCESS_INFO_VA < 0x0000_8000_0000_0000);
const _: () = assert!(INIT_INFO_VA < 0x0000_8000_0000_0000);
const _: () = assert!(PROCMGR_TEMP_VFS_VA < 0x0000_8000_0000_0000);
const _: () = assert!(VIRTIO_BLK_DATA_MAP_VA < 0x0000_8000_0000_0000);
