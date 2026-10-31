// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/lib.rs

//! Pure process-table, badge, recent-exit, request-shape, and init-reap logic
//! for procmgr.
//!
//! Holds the plain-data process record ([`ProcessEntry`]), the heap-backed
//! table ([`ProcessTable`]) with its insert/find/take/query operations, the
//! time-bounded recently-reaped ring ([`RecentExits`]), the pure badge-acceptance
//! predicate ([`badge_is_acceptable`]), the argv/env blob decoder for
//! create requests ([`CreateBlobs`]), which parses client-controlled label
//! fields and data words, the `CREATE_FROM_FILE` cap-layout split
//! ([`split_create_from_file_caps`]), the bounds procmgr applies to fs-driver
//! read replies and the `FS_READ_MEMORY` reply-cap split ([`fs_reads`]), and
//! the init-reap handoff state machine ([`InitReap`]). None of these touch a
//! syscall, IPC, or `std::os::seraph` surface — the cap fields are slot
//! *indices* (plain integers), never live capabilities, and the decoder reads
//! a stack [`ipc::IpcMessage`] snapshot — so the whole crate is
//! host-reachable and host-tested. The syscall/IPC-bearing operations
//! (pipe/namespace configuration, logd death-EQ binding, random process-badge
//! minting, ELF load, the init-reap teardown, and process teardown) stay in
//! `procmgr` and drive this logic across the crate boundary. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

pub mod create_blobs;
pub mod fs_reads;
pub mod init_reap;
pub mod request_caps;

pub use create_blobs::{ChildArgs, ChildEnv, CreateBlobs};
pub use init_reap::{CapDisposition, DeathOutcome, InitReap, Refusal, poll_within};
pub use request_caps::{FileCreateCaps, split_create_from_file_caps};

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// How long a reaped child stays in [`RecentExits`], in nanoseconds: 30 s.
///
/// A `QUERY_PROCESS` on a reaped badge answers `EXITED` with its reason for
/// this long, then `UNKNOWN`. The window is a time bound, not a count, so a
/// burst of later deaths cannot rotate a child out early; the ring's size is
/// the death rate times the window, paid for on the heap only while it holds
/// entries.
pub const RECENT_EXIT_RETENTION_NS: u64 = 30_000_000_000;

/// The death-EQ correlator of a process badge: its low 32 bits.
///
/// The kernel carries a `u64` death correlator, but procmgr still binds each
/// child's observers with the low word of its `u64` badge, and logd keys its
/// eviction on the same word. [`ProcessTable::insert`] refuses a badge whose
/// low word a live entry already holds, so the correlator names exactly one
/// live process.
#[must_use]
pub const fn correlator_of(badge: u64) -> u32
{
    // The low-32 extraction is the point: it is the correlator procmgr binds.
    #[allow(clippy::cast_possible_truncation)]
    let low = badge as u32;
    low
}

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
    pub badge: u64,
    pub aspace_cap: u32,
    pub cspace_cap: u32,
    pub thread_cap: u32,
    pub pi_memory_cap: u32,
    pub tls_memory_cap: u32,
    /// Slot in procmgr's `CSpace` of the badged SEND cap on memmgr's
    /// endpoint that procmgr minted via `REGISTER_PROCESS` for this child.
    /// Held until `PROCESS_DIED`. Zero when memmgr was unwired at create
    /// time (early-boot regression path).
    pub memmgr_send_cap: u32,
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
    pub namespace_override: u32,
    /// Per-process cwd cap installed by `configure_namespace`. Zero means
    /// the child has no cwd cap (`ProcessInfo.current_dir_cap` stays zero;
    /// relative paths return `Unsupported` until installed). Same lifetime
    /// rules as `namespace_override`.
    pub cwd_override: u32,
    /// Upper bound of the baseline `SchedControl` band minted into this
    /// child (`[1, band_max]`). This is the child's spawn ceiling: when it
    /// calls `CREATE_PROCESS` / `CREATE_FROM_FILE`, procmgr resolves the
    /// request's scheduling fields against this value (see
    /// [`resolve_spawn_sched`]).
    pub band_max: u8,
    pub entry_point: u64,
    pub tls_base_va: u64,
    /// Top of the main-thread stack (SP at entry) the loader chose and mapped
    /// for this child. Passed to `thread_configure_with_tls` at start so the
    /// process is launched at the same VA its stack was mapped to.
    pub stack_top_vaddr: u64,
    /// VA of the read-only `ProcessInfo` page the loader mapped into the child.
    /// Delivered to the child in its entry register at start, so the child reads
    /// its handover struct from the address the loader chose.
    pub process_info_va: u64,
    pub started: bool,
}

impl ProcessEntry
{
    #[must_use]
    pub fn badge(&self) -> u64
    {
        self.badge
    }
}

/// Ring of recently auto-reaped processes, queried on `QUERY_PROCESS`
/// table miss to distinguish "exited recently" from "never existed".
/// Each record is kept for [`RECENT_EXIT_RETENTION_NS`] after its death; a
/// query on an older one returns `None`.
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
    /// A live entry already holds the badge's correlator ([`correlator_of`]).
    CorrelatorInUse,
    /// The heap could not grow the table.
    OutOfMemory,
}

/// procmgr's live processes, kept on the heap and sorted by badge.
///
/// The table grows with the number of live processes and holds no fixed
/// ceiling of its own; a spawn fails when the heap cannot grow it, or when
/// procmgr's death queue has no free observer node (`DEATH_EQ_OBSERVERS`,
/// #643). Lookups by badge
/// are binary searches. The death correlator procmgr binds is still the
/// badge's low 32 bits ([`correlator_of`]), and [`Self::insert`] keeps those unique
/// among live entries, so a death event resolves to one process; once the
/// correlator carries the full badge, the correlator lookup becomes the badge
/// lookup and the low-word rule stays as defence in depth.
#[derive(Default)]
pub struct ProcessTable
{
    /// Entries sorted by badge, no two sharing a badge or a correlator.
    entries: Vec<ProcessEntry>,
}

impl ProcessTable
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: Vec::new(),
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

    /// Index of the live entry holding `correlator`.
    fn index_of_correlator(&self, correlator: u32) -> Option<usize>
    {
        self.entries
            .iter()
            .position(|e| correlator_of(e.badge) == correlator)
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

    /// Whether a live entry's badge has `correlator` as its low word. Badge
    /// minting redraws such a candidate, so [`Self::insert`] does not refuse
    /// it later.
    #[must_use]
    pub fn correlator_in_use(&self, correlator: u32) -> bool
    {
        self.index_of_correlator(correlator).is_some()
    }

    /// Insert `entry`, changing nothing on refusal.
    ///
    /// # Errors
    /// [`InsertError::CorrelatorInUse`] when a live entry already holds the
    /// badge's correlator (a live entry with the same badge holds it too);
    /// [`InsertError::OutOfMemory`] when the heap cannot grow the table.
    pub fn insert(&mut self, entry: ProcessEntry) -> Result<(), InsertError>
    {
        if self.correlator_in_use(correlator_of(entry.badge))
        {
            return Err(InsertError::CorrelatorInUse);
        }
        let Err(idx) = self.search(entry.badge)
        else
        {
            return Err(InsertError::CorrelatorInUse);
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

    /// Remove and return the entry whose badge matches.
    #[must_use]
    pub fn take_by_badge(&mut self, badge: u64) -> Option<ProcessEntry>
    {
        let idx = self.index_of_badge(badge)?;
        Some(self.entries.remove(idx))
    }

    /// Remove and return the entry whose badge's low 32 bits are
    /// `correlator`. Used by the death dispatch to resolve a death event back
    /// to its process. Stale correlators (entry already reaped) return
    /// `None`; callers drop such events silently.
    #[must_use]
    pub fn take_by_correlator(&mut self, correlator: u32) -> Option<ProcessEntry>
    {
        let idx = self.index_of_correlator(correlator)?;
        Some(self.entries.remove(idx))
    }

    /// Visit every live entry in badge order. Used by
    /// `install_logd_death_eq` to retroactively bind logd's EQ as a
    /// second death observer on each child's main thread, and by the death
    /// resync to read each child's thread state.
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
    pub fn query_by_badge(&self, badge: u64) -> Option<(bool, u32)>
    {
        let idx = self.index_of_badge(badge)?;
        let e = &self.entries[idx];
        Some((e.started, e.thread_cap))
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

// ── Badge acceptance ─────────────────────────────────────────────────────────

/// Whether a candidate badge may be handed out as a process badge.
///
/// The low 32 bits of a process badge serve double duty — the death-EQ
/// correlator procmgr binds and the logd source badge — so
/// they must clear every reserved low-word value:
/// - **below `min_low`** — the reserved log-badge range. `log_badges` reserves
///   `0..LOG_BADGE_FIRST_CHILD` for system specials: the kernel's `0`
///   "no correlator" death sentinel, init (`1`), procmgr (`2`), and `3..16`.
///   A badge whose low word lands here would bind an unroutable death
///   correlator or evict/contaminate a reserved logd slot — logd evicts every
///   slot whose low word matches a death correlator.
/// - **equal to `reserved_low32`** — the init-reap correlator
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
pub fn badge_is_acceptable(badge: u64, min_low: u64, reserved_low32: u32, verb_bits: u64) -> bool
{
    let low = correlator_of(badge);
    u64::from(low) >= min_low && low != reserved_low32 && badge & verb_bits == 0
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn entry_with_badge(badge: u64) -> ProcessEntry
    {
        ProcessEntry {
            badge,
            aspace_cap: 0,
            cspace_cap: 0,
            thread_cap: 0,
            pi_memory_cap: 0,
            tls_memory_cap: 0,
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
        }
    }

    #[test]
    fn badge_is_rejected_when_low_32_bits_equal_reserved_correlator()
    {
        // A bare match and a high-bits-set u64 whose low word equals the
        // sentinel must both be rejected — proving the `as u32` narrowing
        // rather than a full-u64 compare. (Floor 16 = LOG_BADGE_FIRST_CHILD.)
        assert!(!badge_is_acceptable(u64::from(u32::MAX), 16, u32::MAX, 0));
        assert!(!badge_is_acceptable(0x0000_0005_FFFF_FFFF, 16, u32::MAX, 0));
    }

    #[test]
    fn badge_is_rejected_when_low_word_below_floor()
    {
        // The reserved log-badge / no-correlator range (low word 0..16) is
        // rejected regardless of the high word, so every minted badge carries
        // a routable correlator and never aliases a reserved logd slot.
        assert!(!badge_is_acceptable(0, 16, u32::MAX, 0));
        assert!(!badge_is_acceptable(1, 16, u32::MAX, 0));
        assert!(!badge_is_acceptable(2, 16, u32::MAX, 0));
        assert!(!badge_is_acceptable(15, 16, u32::MAX, 0));
        assert!(!badge_is_acceptable(0x0000_0007_0000_000F, 16, u32::MAX, 0));
    }

    #[test]
    fn badge_is_rejected_when_a_verb_bit_is_set()
    {
        // Bits 59..=63 are the verb bits (svcmgr's HANDOVER_AUTHORITY /
        // PUBLISH_AUTHORITY on the child's registry SEND among them); a low
        // word that clears every other check must not save a badge carrying
        // any of them.
        let verbs = ipc::VERB_BIT_MASK;
        assert!(!badge_is_acceptable(
            0x8000_0000_0000_0010,
            16,
            u32::MAX,
            verbs
        ));
        assert!(!badge_is_acceptable(
            0x4000_0000_0000_0010,
            16,
            u32::MAX,
            verbs
        ));
        for bit in [61, 60, 59]
        {
            assert!(!badge_is_acceptable(
                (1u64 << bit) | 0x10,
                16,
                u32::MAX,
                verbs
            ));
        }
        assert!(badge_is_acceptable(
            0x07FF_FFFF_0000_0010,
            16,
            u32::MAX,
            verbs
        ));
    }

    #[test]
    fn badge_is_accepted_when_low_word_clears_floor_and_correlator()
    {
        assert!(badge_is_acceptable(16, 16, u32::MAX, 0));
        // High bits set, low word clears the floor and the sentinel: accepted.
        assert!(badge_is_acceptable(0x0000_0001_0000_0010, 16, u32::MAX, 0));
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
    fn insert_refuses_a_badge_whose_correlator_a_live_entry_holds()
    {
        let mut table = ProcessTable::new();
        assert_eq!(
            table.insert(entry_with_badge(0x0000_0001_0000_0020)),
            Ok(())
        );
        assert!(table.correlator_in_use(0x20));
        // Same low word, different high word: refused, table unchanged.
        assert_eq!(
            table.insert(entry_with_badge(0x0000_0002_0000_0020)),
            Err(InsertError::CorrelatorInUse)
        );
        assert_eq!(table.len(), 1);
        assert!(table.find_mut_by_badge(0x0000_0002_0000_0020).is_none());
        // Once the holder is reaped, the low word is free again.
        let _ = table.take_by_correlator(0x20);
        assert!(!table.correlator_in_use(0x20));
        assert_eq!(
            table.insert(entry_with_badge(0x0000_0002_0000_0020)),
            Ok(())
        );
    }

    #[test]
    fn badge_lookups_miss_a_badge_that_only_shares_a_live_correlator()
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
    fn take_by_correlator_matches_low_32_bits_of_badge_and_removes_entry()
    {
        let mut table = ProcessTable::new();
        // High bits set; correlator is only the low word. A full-u64 compare
        // would miss this match.
        assert_eq!(
            table.insert(entry_with_badge(0x0000_0001_0000_002A)),
            Ok(())
        );
        assert_eq!(
            table.take_by_correlator(0x2A).map(|e| e.badge),
            Some(0x0000_0001_0000_002A)
        );
        assert!(table.take_by_correlator(0x2A).is_none());
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
}
