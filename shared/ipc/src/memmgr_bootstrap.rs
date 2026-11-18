// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/memmgr_bootstrap.rs

//! Init → memmgr bootstrap payload layout.
//!
//! memmgr is created directly by init (no procmgr exists yet), so its startup
//! pool bounds arrive over a single bootstrap round on memmgr's creator
//! endpoint plus one auxiliary read-only Memory cap (`caps[1]` of that round) —
//! the "phys-table" page. This module is the single source of truth for the
//! payload layout; init writes it and memmgr reads it. It versions with
//! [`MEMMGR_LABELS_VERSION`](crate::MEMMGR_LABELS_VERSION).
//!
//! Round (`ipc::bootstrap` caps + data words):
//! * `caps[0]` — memmgr's own service endpoint (full rights; its RECV side).
//! * `caps[1]` — read-only Memory cap covering the phys-table page (below).
//! * `data[0]` — `memory_base`: first `CSpace` slot of the free RAM Memory caps
//!   init moved into memmgr's `CSpace`.
//! * `data[1]` — `memory_count`: number of consecutive free RAM Memory caps.
//!   No protocol bound applies: memmgr reads each cap's size and physical base
//!   from the kernel (`cap_info`), so the round carries slot numbers only.
//! * `data[2]` — `procmgr_badge`: badge init burned into procmgr's badged
//!   SEND on memmgr's endpoint; gates the procmgr-only labels.
//!
//! Phys-table page (`u64`-indexed; one 4 KiB page = 512 slots):
//! * `FACTS_*` — the kernel's immutable RAM-accounting facts.
//! * `IN_USE_*` — the in-use bootstrap arenas (memmgr's, procmgr's, and init's
//!   own backing), forwarded so memmgr's `pool_total` spans every page of RAM
//!   it owns, not only the free runs and reap donations.

/// Phys-table `u64` index of the first immutable fact
/// (`system_ram_bytes`).
pub const FACTS_SYSTEM_RAM_IDX: usize = 0;
/// Phys-table `u64` index of `kernel_reserved_bytes`.
pub const FACTS_KERNEL_RESERVED_IDX: usize = 1;

/// Phys-table `u64` index of the in-use arena count.
pub const IN_USE_COUNT_IDX: usize = 2;
/// Phys-table `u64` index of the first in-use arena descriptor.
pub const IN_USE_BASE_IDX: usize = 3;
/// `u64` words per in-use arena descriptor:
/// * word 0 — `cap_slot`, the arena Memory cap's handle in memmgr's
///   `CSpace`.
/// * word 1 — `page_count`.
/// * word 2 — `phys_base`.
/// * word 3 — `kind` (see `IN_USE_KIND_*`).
pub const IN_USE_WORDS: usize = 4;
/// Maximum in-use arenas init forwards (memmgr-self, procmgr, init, slack).
/// `IN_USE_BASE_IDX + MAX_IN_USE * IN_USE_WORDS` must stay within the
/// 512-slot page.
pub const MAX_IN_USE: usize = 4;

// The in-use descriptors end inside the one phys-table page.
const _: () = core::assert!(IN_USE_BASE_IDX + MAX_IN_USE * IN_USE_WORDS <= 512);

/// In-use arena owner kind: memmgr's own bootstrap backing.
pub const IN_USE_KIND_MEMMGR: u64 = 0;
/// In-use arena owner kind: procmgr's bootstrap backing.
pub const IN_USE_KIND_PROCMGR: u64 = 1;
/// In-use arena owner kind: init's own bootstrap backing (endpoint and
/// log-thread retype slabs plus the offset-mapped IPC buffer and
/// log-thread stack/IPC). init exits at reap; the arena's pages stay
/// parked and are accounted against a dedicated memmgr-side record.
pub const IN_USE_KIND_INIT: u64 = 2;
