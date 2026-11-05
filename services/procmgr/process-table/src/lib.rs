// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/lib.rs

//! Pure process-table, badge, recent-exit, request-shape, and init-reap logic
//! for procmgr.
//!
//! Holds the plain-data process record ([`ProcessEntry`]), the heap-backed
//! table ([`ProcessTable`]) with its insert/find/take/query operations, the
//! time-bounded ring of recently reaped or destroyed processes
//! ([`RecentExits`]), the memory reclaims held back for the children created
//! with `CREATE_DMA_HOLD` ([`DmaHolds`]), the pure badge-acceptance predicate
//! ([`badge_is_acceptable`]), the argv/env header decoder and checks for
//! create requests ([`create_blobs`]), which bound client-controlled data
//! words and blob bytes, the create-request cap-layout split
//! ([`split_create_caps`]), the bounds procmgr applies to fs-driver
//! read replies and the `FS_READ_MEMORY` reply-cap split ([`fs_reads`]), the
//! init-reap handoff state machine ([`InitReap`]), and the size of procmgr's
//! first death queue ([`death_queues::FIRST_POOL_OBSERVERS`]). None of these
//! touch a syscall, IPC, or `std::os::seraph` surface — the cap fields are
//! slot *indices* (plain integers), never live capabilities, and the decoder
//! reads a stack [`ipc::IpcMessage`] snapshot — so the whole crate is
//! host-reachable and host-tested. The syscall/IPC-bearing operations
//! (pipe/namespace configuration, the logd death forward, random
//! process-badge minting, ELF load, the init-reap teardown, and process
//! teardown) stay in `procmgr` and drive this logic across the crate
//! boundary; the death-queue binds and creates are made by the `death-set`
//! crate's `DeathSet`, which procmgr calls.
//! See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

pub mod create_blobs;
pub mod death_queues;
pub mod dma_holds;
pub mod fs_reads;
pub mod init_reap;
pub mod request_caps;

pub use create_blobs::{ArgvEnvRefusal, ArgvEnvTally, checked_total, decode_header};
pub use dma_holds::{DmaHolds, HeldReclaim, ReleaseRefusal, release_target, release_token_badge};
pub use init_reap::{CapDisposition, DeathOutcome, InitReap, Refusal, poll_within};
pub use request_caps::{CreateCaps, CreateTailCaps, split_create_caps};

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// How long a reaped or destroyed child stays in [`RecentExits`], in
/// nanoseconds: 30 s.
///
/// A `QUERY_PROCESS` on such a badge answers `EXITED` with its reason for
/// this long, then `UNKNOWN`. The window is a time bound, not a count, so a
/// burst of later deaths cannot rotate a child out early while the heap can
/// hold their records (when it cannot, [`RecentExits::record`] drops the
/// oldest); the ring's size is the death rate times the window, paid for on
/// the heap only while it holds entries.
pub const RECENT_EXIT_RETENTION_NS: u64 = 30_000_000_000;

// ── Process table ───────────────────────────────────────────────────────────

/// Per-process resource record. Fields read when teardown is implemented.
///
/// All fields are non-atomic. Concurrent access is precluded by
/// procmgr's structurally single-threaded dispatch: every mutating
/// path (`configure_namespace`, `start_process`, `teardown_entry`,
/// memmgr reclaim handlers) runs sequentially under the lone
/// `service_ep` recv loop in `main.rs`. If procmgr is ever made
/// multi-threaded — as vfsd was, for spawn-deadlock avoidance — the
/// `started` bool (read by `configure_namespace`, read+written by
/// `start_process`) must become `AtomicBool` with compare-and-swap
/// transitions, and the namespace/cwd-override slots need per-entry
/// serialisation to keep the install-once contract.
pub struct ProcessEntry
{
    /// The child's process badge: the table key, the correlator of its death
    /// observers, the badge of its process handle and of the procmgr,
    /// registry, and log SENDs procmgr mints for it, and the source badge
    /// logd keys its stream by. Minted at random and accepted only by
    /// [`badge_is_acceptable`], so it carries no verb bit.
    pub badge: u64,
    /// Slot in procmgr's `CSpace` of the child's `AddressSpace` cap, the
    /// root its self-cap and memmgr's delegation derive from.
    pub aspace_cap: u64,
    /// Slot in procmgr's `CSpace` of the child's `CSpace` cap, the root its
    /// self-cap derives from.
    pub cspace_cap: u64,
    /// Slot in procmgr's `CSpace` of the child's main-thread cap.
    pub thread_cap: u64,
    /// Slot in procmgr's `CSpace` of the Memory cap behind the child's
    /// `ProcessInfo` page.
    pub pi_memory_cap: u64,
    /// Slot in procmgr's `CSpace` of the Memory cap behind the main thread's
    /// TLS block. Zero when the child's ELF has no TLS segment.
    pub tls_memory_cap: u64,
    /// Slot in procmgr's `CSpace` of the Memory cap behind the child's
    /// argv/env region, the pages mapped after its `ProcessInfo` page. Zero
    /// when the child was created without argv and env.
    pub argv_env_memory_cap: u64,
    /// Slot in procmgr's `CSpace` of the badged SEND cap on memmgr's
    /// endpoint that procmgr minted via `REGISTER_PROCESS` for this child.
    /// Held until `PROCESS_DIED`. Zero when memmgr was unwired at create
    /// time (early-boot regression path).
    pub memmgr_send_cap: u64,
    /// Memmgr-side process badge for this child. Sent in the
    /// `PROCESS_DIED` payload so memmgr can reclaim the right record.
    pub memmgr_badge: u64,
    /// Per-process system-root cap installed by `configure_namespace`.
    /// Zero means the child runs with no namespace authority
    /// (`ProcessInfo.system_root_cap` stays zero; std-side fs ops on
    /// absolute paths return `Unsupported`). Held in procmgr's `CSpace`
    /// from `CONFIGURE_NAMESPACE` until `start_process` consumes it
    /// (`cap_copy` into the child, then `cap_delete` of the procmgr-side
    /// slot) or the entry is torn down (`teardown_entry` deletes the
    /// slot if still present).
    pub namespace_override: u64,
    /// Per-process cwd cap installed by `configure_namespace`. Zero means
    /// the child has no cwd cap (`ProcessInfo.current_dir_cap` stays zero;
    /// relative paths return `Unsupported` until installed). Same lifetime
    /// rules as `namespace_override`.
    pub cwd_override: u64,
    /// Upper bound of the baseline `SchedControl` band minted into this
    /// child (`[1, band_max]`). This is the child's spawn ceiling: when it
    /// calls `CREATE_PROCESS` / `CREATE_FROM_FILE`, procmgr resolves the
    /// request's scheduling fields against this value (see
    /// [`resolve_spawn_sched`]).
    pub band_max: u8,
    /// The child's entry point, its ELF entry relocated by the load bias,
    /// where `start_process` starts the main thread.
    pub entry_point: u64,
    /// The main thread's TLS base (its thread pointer) in the child, passed
    /// to `thread_configure_with_tls` at start; zero without a TLS block.
    pub tls_base_va: u64,
    /// Top of the main-thread stack (SP at entry) the loader chose and mapped
    /// for this child. Passed to `thread_configure_with_tls` at start so the
    /// process is launched at the same VA its stack was mapped to.
    pub stack_top_vaddr: u64,
    /// VA of the read-only `ProcessInfo` page the loader mapped into the child.
    /// Delivered to the child in its entry register at start, so the child reads
    /// its handover struct from the address the loader chose.
    pub process_info_va: u64,
    /// Set by `start_process` once the main thread has started; a held
    /// reclaim is parked only for a started child ([`DmaHolds::park`]).
    pub started: bool,
    /// Set by `CREATE_DMA_HOLD`: once started, the child's teardown holds
    /// its memmgr reclaim back until its creator's `RELEASE_HOLD`
    /// ([`DmaHolds`]).
    pub dma_hold: bool,
}

impl ProcessEntry
{
    /// The child's process badge, the `badge` field.
    #[must_use]
    pub fn badge(&self) -> u64
    {
        self.badge
    }
}

/// Ring of recently reaped or destroyed processes, queried on `QUERY_PROCESS`
/// table miss to distinguish "exited recently" from "never existed".
/// Each record is kept for up to [`RECENT_EXIT_RETENTION_NS`] after its death
/// (best-effort: see [`RecentExits::record`]); a query on an older one, or on
/// one the ring no longer holds, returns `None`.
#[derive(Default)]
pub struct RecentExits
{
    /// Records in death order, oldest first.
    ring: VecDeque<RecentExit>,
}

#[derive(Clone, Copy)]
struct RecentExit
{
    badge: u64,
    exit_reason: u64,
    /// Monotonic time of the death, in nanoseconds.
    at_ns: u64,
}

impl RecentExits
{
    /// An empty ring. It allocates nothing until the first
    /// [`Self::record`], and grows on the heap from there.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            ring: VecDeque::new(),
        }
    }

    /// Drop every record older than the retention window at `now_ns`.
    fn expire(&mut self, now_ns: u64)
    {
        while self
            .ring
            .front()
            .is_some_and(|e| now_ns.saturating_sub(e.at_ns) > RECENT_EXIT_RETENTION_NS)
        {
            self.ring.pop_front();
        }
    }

    /// Record `badge`'s death with `exit_reason` at monotonic time `now_ns`.
    ///
    /// When the heap cannot grow the ring, the oldest record makes room; an
    /// empty ring that cannot grow drops the record, so a query on it answers
    /// `UNKNOWN` rather than procmgr failing.
    pub fn record(&mut self, badge: u64, exit_reason: u64, now_ns: u64)
    {
        self.expire(now_ns);
        if self.ring.try_reserve(1).is_err() && self.ring.pop_front().is_none()
        {
            return;
        }
        self.ring.push_back(RecentExit {
            badge,
            exit_reason,
            at_ns: now_ns,
        });
    }

    /// The exit reason of `badge` if it died within the retention window
    /// before `now_ns`.
    pub fn find(&mut self, badge: u64, now_ns: u64) -> Option<u64>
    {
        self.expire(now_ns);
        self.ring
            .iter()
            .rev()
            .find(|e| e.badge == badge)
            .map(|e| e.exit_reason)
    }
}

/// Why [`ProcessTable::insert`] refused an entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError
{
    /// A live entry already holds the badge.
    BadgeInUse,
    /// The heap could not grow the table.
    OutOfMemory,
}

/// Why [`ProcessTable::arm_dma_hold`] armed nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArmError
{
    /// No live entry holds the badge.
    NotFound,
    /// The heap could not reserve the room the child's held record takes.
    OutOfMemory,
}

/// procmgr's live processes, kept on the heap and sorted by badge, and the
/// memory reclaims held back for the torn-down children created with
/// `CREATE_DMA_HOLD`.
///
/// The table grows with the number of live processes and holds no fixed
/// ceiling of its own; a spawn fails when the heap cannot grow it. Lookups by
/// badge are binary searches. The death correlator procmgr binds is the full
/// `u64` badge, so a death event resolves to its process by the badge lookup.
#[derive(Default)]
pub struct ProcessTable
{
    /// Entries sorted by badge, no two sharing a badge.
    entries: Vec<ProcessEntry>,
    holds: DmaHolds,
}

impl ProcessTable
{
    /// An empty table with no held reclaims. It allocates nothing until the
    /// first [`Self::insert`] or arm, and grows on the heap from there.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: Vec::new(),
            holds: DmaHolds::new(),
        }
    }

    /// Index of the entry whose badge is `badge`, or where one would go.
    fn search(&self, badge: u64) -> Result<usize, usize>
    {
        self.entries.binary_search_by_key(&badge, |e| e.badge)
    }

    /// Index of the live entry whose badge is `badge`.
    fn index_of_badge(&self, badge: u64) -> Option<usize>
    {
        self.search(badge).ok()
    }

    /// Number of live entries.
    #[must_use]
    pub fn len(&self) -> usize
    {
        self.entries.len()
    }

    /// Whether the table holds no live entry.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.entries.is_empty()
    }

    /// Whether a live entry or a held reclaim holds `badge`. Badge minting
    /// redraws such a candidate, so [`Self::insert`] does not refuse it later
    /// and no new child's process handle can release another's held reclaim.
    #[must_use]
    pub fn badge_in_use(&self, badge: u64) -> bool
    {
        self.index_of_badge(badge).is_some() || self.holds.holds(badge)
    }

    /// Arm the live entry `badge` for a held reclaim (`CREATE_DMA_HOLD`),
    /// reserving the room its record takes when it parks. Arming an armed
    /// entry again changes nothing.
    ///
    /// # Errors
    /// [`ArmError::NotFound`] when no live entry holds the badge;
    /// [`ArmError::OutOfMemory`] when the heap cannot reserve the room, the
    /// entry then left unarmed.
    pub fn arm_dma_hold(&mut self, badge: u64) -> Result<(), ArmError>
    {
        let idx = self.index_of_badge(badge).ok_or(ArmError::NotFound)?;
        if self.entries[idx].dma_hold
        {
            return Ok(());
        }
        self.holds.arm().map_err(|_| ArmError::OutOfMemory)?;
        self.entries[idx].dma_hold = true;
        Ok(())
    }

    /// The held reclaims, for the teardown that parks an entry's
    /// ([`DmaHolds::park`]) and the `RELEASE_HOLD` that takes it.
    pub fn holds_mut(&mut self) -> &mut DmaHolds
    {
        &mut self.holds
    }

    /// Insert `entry`, changing nothing on refusal.
    ///
    /// # Errors
    /// [`InsertError::BadgeInUse`] when a live entry already holds the badge;
    /// [`InsertError::OutOfMemory`] when the heap cannot grow the table.
    pub fn insert(&mut self, entry: ProcessEntry) -> Result<(), InsertError>
    {
        let Err(idx) = self.search(entry.badge)
        else
        {
            return Err(InsertError::BadgeInUse);
        };
        self.entries
            .try_reserve(1)
            .map_err(|_| InsertError::OutOfMemory)?;
        self.entries.insert(idx, entry);
        Ok(())
    }

    /// Locate the live entry whose badge matches, for in-place mutation.
    #[must_use]
    pub fn find_mut_by_badge(&mut self, badge: u64) -> Option<&mut ProcessEntry>
    {
        let idx = self.index_of_badge(badge)?;
        Some(&mut self.entries[idx])
    }

    /// Remove and return the entry whose badge matches. The death dispatch
    /// resolves a death event's correlator, the full badge, through it; a
    /// stale correlator (entry already reaped) returns `None`, and the caller
    /// drops that event.
    #[must_use]
    pub fn take_by_badge(&mut self, badge: u64) -> Option<ProcessEntry>
    {
        let idx = self.index_of_badge(badge)?;
        Some(self.entries.remove(idx))
    }

    /// Visit every live entry in badge order. Used by the death resync to
    /// read each child's thread state.
    pub fn for_each<F: FnMut(&ProcessEntry)>(&self, f: F)
    {
        self.entries.iter().for_each(f);
    }

    /// Copy into `out` the badges of the live entries above `after` (every
    /// entry when `after` is `None`), in badge order, and return how many
    /// were copied.
    ///
    /// A pager that passes the last copied badge as the next `after` sees
    /// every entry that stays live across the walk exactly once, whatever is
    /// inserted or removed between pages.
    pub fn live_badges_after(&self, after: Option<u64>, out: &mut [u64]) -> usize
    {
        let start = match after
        {
            None => 0,
            Some(b) => match self.search(b)
            {
                Ok(i) => i + 1,
                Err(i) => i,
            },
        };
        let mut copied = 0;
        for (slot, entry) in out.iter_mut().zip(&self.entries[start..])
        {
            *slot = entry.badge;
            copied += 1;
        }
        copied
    }

    /// Lightweight status lookup for `QUERY_PROCESS`. Returns
    /// `(started, thread_cap)` when an entry is present; `None` if the
    /// badge is unknown (already reaped or never existed).
    ///
    /// `thread_cap` is procmgr's `CSpace` slot for the child's main thread,
    /// suitable for `cap_info`'s `CAP_INFO_THREAD_STATE` selector to
    /// fetch the kernel-authoritative lifecycle snapshot.
    #[must_use]
    pub fn query_by_badge(&self, badge: u64) -> Option<(bool, u64)>
    {
        let idx = self.index_of_badge(badge)?;
        let e = &self.entries[idx];
        Some((e.started, e.thread_cap))
    }

    /// memmgr badge of the live entry whose badge matches, for the
    /// creator-class check of [`child_memmgr_flags`]. `None` if the badge is
    /// unknown.
    #[must_use]
    pub fn memmgr_badge_by_badge(&self, badge: u64) -> Option<u64>
    {
        let idx = self.index_of_badge(badge)?;
        Some(self.entries[idx].memmgr_badge)
    }

    /// Band ceiling of the live entry whose badge matches, for
    /// creator-band resolution on nested spawns. `None` if the badge is
    /// unknown (already reaped, or a badge minted outside the table).
    #[must_use]
    pub fn band_max_by_badge(&self, badge: u64) -> Option<u8>
    {
        let idx = self.index_of_badge(badge)?;
        Some(self.entries[idx].band_max)
    }
}

// ── Spawn physical-address class ─────────────────────────────────────────────

/// The `memmgr_labels::REGISTER_PROCESS` flags of a child a create request
/// labelled `label` makes, for the creator badged `creator_badge` on
/// procmgr, whose memmgr badge is `creator_memmgr_badge` (`None` when the
/// table holds no entry for it).
///
/// `procmgr_labels::CREATE_PHYS_ACCESS` asks for a phys-class child
/// (`memmgr_labels::REGISTER_PHYS_CLASS`). Only a creator that may read
/// physical addresses itself may ask: an un-badged one (badge `0`: init, or
/// svcmgr's mint source) or one memmgr registered phys-class, whose memmgr
/// badge carries `memmgr_labels::PHYS_CLASS_BADGE_BIT`. Returns `None` when
/// any other creator asks, which procmgr refuses with `INVALID_ARGUMENT`.
#[must_use]
pub fn child_memmgr_flags(
    label: u64,
    creator_badge: u64,
    creator_memmgr_badge: Option<u64>,
) -> Option<u64>
{
    if label & ipc::procmgr_labels::CREATE_PHYS_ACCESS == 0
    {
        return Some(0);
    }
    let creator_is_phys = creator_badge == 0
        || creator_memmgr_badge.is_some_and(|b| b & ipc::memmgr_labels::PHYS_CLASS_BADGE_BIT != 0);
    creator_is_phys.then_some(ipc::memmgr_labels::REGISTER_PHYS_CLASS)
}

// ── Spawn scheduling resolution ──────────────────────────────────────────────

/// Resolve the scheduling fields of a `CREATE_PROCESS` /
/// `CREATE_FROM_FILE` request against the creator's band ceiling.
///
/// `requested_priority` and `requested_band_max` are the raw 5-bit label
/// fields (`0` = unspecified). `creator_band_max` is the caller's spawn
/// ceiling (its own minted band; init's is the baseline ceiling) and must
/// be at least 1. `default_priority` is the policy default applied when no
/// priority is requested, clamped to the resolved band.
///
/// Returns the resolved `(priority, band_max)` for the child, or `None`
/// when the request exceeds the creator's authority or is internally
/// inconsistent:
/// - `band_max > creator_band_max` — band escalation.
/// - `priority > band_max` — the child's own band must cover its initial
///   level, so it can always restore its starting priority.
#[must_use]
pub fn resolve_spawn_sched(
    requested_priority: u8,
    requested_band_max: u8,
    creator_band_max: u8,
    default_priority: u8,
) -> Option<(u8, u8)>
{
    if creator_band_max == 0
    {
        return None;
    }
    let band_max = if requested_band_max == 0
    {
        creator_band_max
    }
    else
    {
        requested_band_max
    };
    if band_max > creator_band_max
    {
        return None;
    }
    let priority = if requested_priority == 0
    {
        default_priority.min(band_max)
    }
    else
    {
        requested_priority
    };
    if priority > band_max
    {
        return None;
    }
    Some((priority, band_max))
}

// ── Death resync ────────────────────────────────────────────────────────────

/// The exit reason procmgr's death resync reaps a live entry with, or `None`
/// to leave it live. `main_thread` is the kernel's packed
/// `CAP_INFO_THREAD_STATE` of the entry's main thread (the state above bit
/// 32, the retained exit reason below), `exited` the state value meaning the
/// thread exited, and `terminal_fault` the entry's `AddressSpace`
/// `CAP_INFO_ASPACE_TERMINAL_FAULT` (`0` while no thread of it took a
/// terminal fault, else the first such fault's reason); a read that failed is
/// `None`. An exited main thread reaps with its own reason, as its post would
/// have; otherwise a terminal fault in any thread reaps with the fault's
/// reason, as the address space's post would have.
#[must_use]
pub fn resync_exit_reason(
    main_thread: Option<u64>,
    exited: u32,
    terminal_fault: Option<u64>,
) -> Option<u64>
{
    match (main_thread, terminal_fault)
    {
        (Some(packed), _) if (packed >> 32) as u32 == exited => Some(packed & 0xFFFF_FFFF),
        (_, Some(fault)) if fault != 0 => Some(fault),
        _ => None,
    }
}

// ── Badge acceptance ─────────────────────────────────────────────────────────

/// Whether a candidate badge may be handed out as a process badge.
///
/// A process badge is also the death-EQ correlator procmgr binds and the logd
/// source badge, so it must clear every reserved value:
/// - **below `min`** — the reserved log-badge range. `log_badges` reserves
///   `0..LOG_BADGE_FIRST_CHILD` for system specials: the kernel's `0`
///   "no correlator" death sentinel, init (`1`), procmgr (`2`), and `3..16`.
///   A badge here would bind an unroutable death correlator or alias a
///   reserved logd slot.
/// - **equal to `reserved`** — the init-reap correlator
///   (`INIT_REAP_CORRELATOR`), which `dispatch_death` routes to init teardown.
///
/// and no bit of `verb_bits` may be set: the badge rides every SEND procmgr
/// mints for the child (its procmgr, svcmgr-registry, and log SENDs) and its
/// process handle, where a verb bit (`ipc::VERB_BIT_MASK`) would grant the
/// child an authority its servers reserve to trusted minters.
///
/// All are reachable under random badge minting; the old monotonic counter
/// started at `LOG_BADGE_FIRST_CHILD` and so upheld the floor structurally.
#[must_use]
pub fn badge_is_acceptable(badge: u64, min: u64, reserved: u64, verb_bits: u64) -> bool
{
    badge >= min && badge != reserved && badge & verb_bits == 0
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A thread-state value standing for "exited" in the resync tests; the
    /// function compares against whatever value the caller passes.
    const EXITED: u32 = 3;

    #[test]
    fn the_resync_reaps_an_exited_main_thread_with_its_own_reason()
    {
        let packed = (u64::from(EXITED) << 32) | 0x1007;
        assert_eq!(
            resync_exit_reason(Some(packed), EXITED, Some(0)),
            Some(0x1007)
        );
        // The main thread's reason wins over a fault a worker took first.
        assert_eq!(
            resync_exit_reason(Some(packed), EXITED, Some(0x100E)),
            Some(0x1007)
        );
    }

    #[test]
    fn the_resync_reaps_a_running_process_whose_worker_took_a_terminal_fault()
    {
        let running = u64::from(EXITED - 1) << 32;
        assert_eq!(
            resync_exit_reason(Some(running), EXITED, Some(0x100E)),
            Some(0x100E)
        );
        assert_eq!(resync_exit_reason(None, EXITED, Some(0x100E)), Some(0x100E));
    }

    #[test]
    fn the_resync_leaves_a_process_live_without_an_exit_or_a_fault()
    {
        let running = u64::from(EXITED - 1) << 32;
        assert_eq!(resync_exit_reason(Some(running), EXITED, Some(0)), None);
        assert_eq!(resync_exit_reason(Some(running), EXITED, None), None);
        assert_eq!(resync_exit_reason(None, EXITED, None), None);
    }

    fn entry_with_badge(badge: u64) -> ProcessEntry
    {
        ProcessEntry {
            badge,
            aspace_cap: 0,
            cspace_cap: 0,
            thread_cap: 0,
            pi_memory_cap: 0,
            tls_memory_cap: 0,
            argv_env_memory_cap: 0,
            memmgr_send_cap: 0,
            memmgr_badge: 0,
            namespace_override: 0,
            cwd_override: 0,
            band_max: 0,
            entry_point: 0,
            tls_base_va: 0,
            stack_top_vaddr: 0,
            process_info_va: 0,
            started: false,
            dma_hold: false,
        }
    }

    #[test]
    fn badge_is_rejected_when_equal_to_reserved_correlator()
    {
        // (Floor 16 = LOG_BADGE_FIRST_CHILD; the init-reap sentinel is u64::MAX.)
        assert!(!badge_is_acceptable(u64::MAX, 16, u64::MAX, 0));
        // A badge sharing only the sentinel's low word is a distinct correlator.
        assert!(badge_is_acceptable(0x0000_0005_FFFF_FFFF, 16, u64::MAX, 0));
    }

    #[test]
    fn badge_is_rejected_when_below_floor()
    {
        // The reserved log-badge / no-correlator range (0..16) is refused, so
        // every minted badge carries a routable correlator and never aliases a
        // reserved logd slot.
        assert!(!badge_is_acceptable(0, 16, u64::MAX, 0));
        assert!(!badge_is_acceptable(1, 16, u64::MAX, 0));
        assert!(!badge_is_acceptable(15, 16, u64::MAX, 0));
        assert!(badge_is_acceptable(16, 16, u64::MAX, 0));
        // The floor is on the whole badge: a low word under it with high bits
        // set is above it, and names no reserved slot.
        assert!(badge_is_acceptable(0x0000_0007_0000_000F, 16, u64::MAX, 0));
    }

    #[test]
    fn badge_is_rejected_when_a_verb_bit_is_set()
    {
        // Bits 59..=63 are the verb bits (svcmgr's HANDOVER_AUTHORITY /
        // PUBLISH_AUTHORITY on the child's registry SEND among them); a badge
        // that clears every other check must not carry any of them.
        let verbs = ipc::VERB_BIT_MASK;
        for bit in [63, 62, 61, 60, 59]
        {
            assert!(!badge_is_acceptable(
                (1u64 << bit) | 0x10,
                16,
                u64::MAX,
                verbs
            ));
        }
        assert!(badge_is_acceptable(
            0x07FF_FFFF_0000_0010,
            16,
            u64::MAX,
            verbs
        ));
    }

    #[test]
    fn insert_grows_past_any_fixed_count_and_keeps_every_entry_reachable()
    {
        let mut table = ProcessTable::new();
        // Far past the former 32-entry ceiling, inserted out of order.
        for i in (0..1000u64).rev()
        {
            assert_eq!(table.insert(entry_with_badge((i << 32) | (i + 16))), Ok(()));
        }
        assert_eq!(table.len(), 1000);
        for i in 0..1000u64
        {
            assert!(table.find_mut_by_badge((i << 32) | (i + 16)).is_some());
        }
    }

    #[test]
    fn badges_sharing_low_32_bits_live_together_and_reap_separately()
    {
        // The correlator is the whole badge: two live processes whose badges
        // share the low word are distinct, and reaping one leaves the other.
        let mut table = ProcessTable::new();
        assert_eq!(
            table.insert(entry_with_badge(0x0000_0001_0000_0020)),
            Ok(())
        );
        assert_eq!(
            table.insert(entry_with_badge(0x0000_0002_0000_0020)),
            Ok(())
        );
        assert_eq!(
            table.take_by_badge(0x0000_0002_0000_0020).map(|e| e.badge),
            Some(0x0000_0002_0000_0020)
        );
        assert!(table.badge_in_use(0x0000_0001_0000_0020));
        assert!(!table.badge_in_use(0x0000_0002_0000_0020));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn insert_refuses_a_badge_a_live_entry_holds()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.insert(entry_with_badge(0x20)), Ok(()));
        assert_eq!(
            table.insert(entry_with_badge(0x20)),
            Err(InsertError::BadgeInUse)
        );
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn badge_lookups_miss_a_badge_that_only_shares_a_live_low_word()
    {
        let mut table = ProcessTable::new();
        assert_eq!(
            table.insert(entry_with_badge(0x0000_0001_0000_0020)),
            Ok(())
        );
        let alias = 0x0000_0009_0000_0020;
        assert!(table.find_mut_by_badge(alias).is_none());
        assert!(table.query_by_badge(alias).is_none());
        assert!(table.band_max_by_badge(alias).is_none());
        assert!(table.take_by_badge(alias).is_none());
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn find_mut_by_badge_returns_live_entry_and_none_for_unknown()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.insert(entry_with_badge(16)), Ok(()));
        assert_eq!(table.find_mut_by_badge(16).map(|e| e.badge()), Some(16));
        assert!(table.find_mut_by_badge(99).is_none());
    }

    #[test]
    fn take_by_badge_removes_matching_entry_and_returns_it()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.insert(entry_with_badge(16)), Ok(()));
        assert_eq!(table.take_by_badge(16).map(|e| e.badge), Some(16));
        // The entry is gone: a second take misses and find no longer sees it.
        assert!(table.take_by_badge(16).is_none());
        assert!(table.find_mut_by_badge(16).is_none());
    }

    #[test]
    fn query_by_badge_reports_started_flag_and_absence()
    {
        let mut table = ProcessTable::new();
        let mut entry = entry_with_badge(16);
        entry.thread_cap = 7;
        assert_eq!(table.insert(entry), Ok(()));
        assert_eq!(table.query_by_badge(16), Some((false, 7)));
        table.find_mut_by_badge(16).expect("entry present").started = true;
        assert_eq!(table.query_by_badge(16), Some((true, 7)));
        assert_eq!(table.query_by_badge(99), None);
    }

    #[test]
    fn for_each_visits_exactly_the_live_entries()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.insert(entry_with_badge(30)), Ok(()));
        assert_eq!(table.insert(entry_with_badge(10)), Ok(()));
        assert_eq!(table.insert(entry_with_badge(20)), Ok(()));
        let _ = table.take_by_badge(20);
        let mut seen = Vec::new();
        table.for_each(|e| seen.push(e.badge));
        assert_eq!(seen, [10, 30]);
    }

    #[test]
    fn live_badges_after_pages_every_entry_once_in_badge_order()
    {
        let mut table = ProcessTable::new();
        let b = |n: u64| (n << 32) | (n + 16);
        for n in [4u64, 1, 3, 2, 5]
        {
            assert_eq!(table.insert(entry_with_badge(b(n))), Ok(()));
        }
        let mut page = [0u64; 2];
        assert_eq!(table.live_badges_after(None, &mut page), 2);
        assert_eq!(page, [b(1), b(2)]);
        // An entry removed and one inserted behind the cursor between pages
        // do not disturb the walk over the entries that stay live.
        let _ = table.take_by_badge(b(3));
        assert_eq!(table.insert(entry_with_badge(b(0))), Ok(()));
        assert_eq!(table.live_badges_after(Some(page[1]), &mut page), 2);
        assert_eq!(page, [b(4), b(5)]);
        // A cursor naming a reaped badge resumes after it.
        assert_eq!(table.live_badges_after(Some(b(3)), &mut page), 2);
        assert_eq!(page, [b(4), b(5)]);
        assert_eq!(table.live_badges_after(Some(b(5)), &mut page), 0);
    }

    #[test]
    fn recent_exits_record_then_find_returns_exit_reason()
    {
        let mut recent = RecentExits::new();
        recent.record(16, 42, 1_000);
        assert_eq!(recent.find(16, 2_000), Some(42));
        assert_eq!(recent.find(17, 2_000), None);
    }

    #[test]
    fn a_phys_class_child_needs_an_unbadged_or_phys_class_creator()
    {
        use ipc::memmgr_labels::{PHYS_CLASS_BADGE_BIT, REGISTER_PHYS_CLASS};
        use ipc::procmgr_labels::{CREATE_PHYS_ACCESS, CREATE_PINNED};
        let phys = CREATE_PHYS_ACCESS | CREATE_PINNED;
        // No phys flag: an ordinary child for any creator.
        assert_eq!(child_memmgr_flags(CREATE_PINNED, 16, Some(5)), Some(0));
        // Un-badged creator (init) and a phys-class creator (devmgr).
        assert_eq!(child_memmgr_flags(phys, 0, None), Some(REGISTER_PHYS_CLASS));
        assert_eq!(
            child_memmgr_flags(phys, 16, Some(PHYS_CLASS_BADGE_BIT | 5)),
            Some(REGISTER_PHYS_CLASS)
        );
        // An ordinary creator, and a badge the table does not hold.
        assert_eq!(child_memmgr_flags(phys, 16, Some(5)), None);
        assert_eq!(child_memmgr_flags(phys, 16, None), None);
    }

    #[test]
    fn memmgr_badge_by_badge_reports_the_entry_and_absence()
    {
        let mut table = ProcessTable::new();
        let mut entry = entry_with_badge(16);
        entry.memmgr_badge = 0x77;
        assert_eq!(table.insert(entry), Ok(()));
        assert_eq!(table.memmgr_badge_by_badge(16), Some(0x77));
        assert_eq!(table.memmgr_badge_by_badge(99), None);
    }

    #[test]
    fn band_max_by_badge_reports_ceiling_and_absence()
    {
        let mut table = ProcessTable::new();
        let mut entry = entry_with_badge(16);
        entry.band_max = 21;
        assert_eq!(table.insert(entry), Ok(()));
        assert_eq!(table.band_max_by_badge(16), Some(21));
        assert_eq!(table.band_max_by_badge(99), None);
    }

    #[test]
    fn resolve_spawn_sched_defaults_to_creator_band_and_clamped_priority()
    {
        // Both fields unspecified: band = creator's, priority = policy
        // default clamped to the band.
        assert_eq!(resolve_spawn_sched(0, 0, 28, 10), Some((10, 28)));
        // Narrow creator band clamps the default below it.
        assert_eq!(resolve_spawn_sched(0, 0, 5, 10), Some((5, 5)));
        // Explicit narrow band clamps the default even under a wide creator.
        assert_eq!(resolve_spawn_sched(0, 5, 28, 10), Some((5, 5)));
    }

    #[test]
    fn resolve_spawn_sched_accepts_explicit_fields_within_creator_band()
    {
        // Priority below its own band (devmgr shape: starts at 24, may
        // place children up to 26).
        assert_eq!(resolve_spawn_sched(24, 26, 28, 10), Some((24, 26)));
        // Priority equal to band and creator ceiling.
        assert_eq!(resolve_spawn_sched(28, 28, 28, 10), Some((28, 28)));
        // Explicit priority with unspecified band inherits the creator band.
        assert_eq!(resolve_spawn_sched(18, 0, 21, 10), Some((18, 21)));
    }

    #[test]
    fn resolve_spawn_sched_rejects_escalation_and_inconsistency()
    {
        // Band above the creator's ceiling is an escalation.
        assert_eq!(resolve_spawn_sched(10, 29, 28, 10), None);
        // Priority above the resolved band (explicit band).
        assert_eq!(resolve_spawn_sched(27, 26, 28, 10), None);
        // Priority above the inherited creator band.
        assert_eq!(resolve_spawn_sched(22, 0, 21, 10), None);
        // 5-bit maximum (31) cannot pass any in-tree ceiling.
        assert_eq!(resolve_spawn_sched(31, 31, 28, 10), None);
        // Degenerate zero creator band rejects everything.
        assert_eq!(resolve_spawn_sched(0, 0, 0, 10), None);
    }

    #[test]
    fn recent_exits_keep_a_burst_of_deaths_for_the_whole_window()
    {
        let mut recent = RecentExits::new();
        // Many deaths inside the window: none rotates the first one out.
        for i in 0..10_000u64
        {
            recent.record(100 + i, i, i);
        }
        assert_eq!(recent.find(100, 10_000), Some(0));
        assert_eq!(recent.find(100 + 9_999, 10_000), Some(9_999));
    }

    #[test]
    fn recent_exits_forget_a_record_once_the_window_has_passed()
    {
        let mut recent = RecentExits::new();
        recent.record(16, 1, 0);
        recent.record(17, 2, 5);
        assert_eq!(recent.find(16, RECENT_EXIT_RETENTION_NS), Some(1));
        assert_eq!(recent.find(16, RECENT_EXIT_RETENTION_NS + 1), None);
        assert_eq!(recent.find(17, RECENT_EXIT_RETENTION_NS + 1), Some(2));
    }

    #[test]
    fn arm_dma_hold_refuses_a_badge_no_live_entry_holds()
    {
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(16)).unwrap();
        assert_eq!(table.arm_dma_hold(17), Err(ArmError::NotFound));
        assert!(!table.take_by_badge(16).unwrap().dma_hold);
    }

    #[test]
    fn arm_dma_hold_marks_the_live_entry()
    {
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(16)).unwrap();
        assert_eq!(table.arm_dma_hold(16), Ok(()));
        assert!(table.take_by_badge(16).unwrap().dma_hold);
    }

    #[test]
    fn arming_an_armed_entry_again_reserves_no_second_record()
    {
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(16)).unwrap();
        table.arm_dma_hold(16).unwrap();
        table.arm_dma_hold(16).unwrap();
        let mut taken = table.take_by_badge(16).unwrap();
        taken.started = true;
        // Parking the one entry settles the one reservation it holds; a
        // second arm that reserved again would leave a reservation behind.
        assert!(table.holds_mut().park(&taken));
        assert_eq!(table.holds_mut().armed(), 0);
    }

    #[test]
    fn a_held_reclaim_keeps_its_badge_in_use_until_released()
    {
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(16)).unwrap();
        table.arm_dma_hold(16).unwrap();
        let mut taken = table.take_by_badge(16).unwrap();
        taken.started = true;
        assert!(table.holds_mut().park(&taken));
        assert!(table.badge_in_use(16));
        assert!(table.holds_mut().release(release_token_badge(16)).is_ok());
        assert!(!table.badge_in_use(16));
    }
}
