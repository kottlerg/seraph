// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/process-table/src/lib.rs

//! Pure process-table, badge, and recent-exit logic for procmgr.
//!
//! Holds the plain-data process record ([`ProcessEntry`]), the fixed-size
//! slot table ([`ProcessTable`]) with its insert/find/take/query operations,
//! the recently-reaped ring ([`RecentExits`]), and the pure badge-acceptance
//! predicate ([`badge_is_acceptable`]). None of these touch a syscall, IPC,
//! or `std::os::seraph` surface — the cap fields are slot *indices* (plain
//! integers), never live capabilities — so the whole crate is host-reachable
//! and host-tested. The syscall/IPC-bearing operations (pipe/namespace
//! configuration, logd death-EQ binding, the atomic badge counter, ELF load,
//! and teardown) stay in `procmgr` and drive these lookups across the crate
//! boundary. See
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants).

#![cfg_attr(not(test), no_std)]

/// Maximum concurrent child processes procmgr tracks.
///
/// Independent of any wait-set capacity — the shared death queue fans in
/// all children's exit events with kernel-side multi-bind, so there is no
/// per-child wait-set slot. Raise this (and the death queue capacity in
/// `main.rs`) as real workloads demand.
pub const MAX_PROCESSES: usize = 32;

/// Slots in the [`RecentExits`] ring.
const RECENT_EXITS_SLOTS: usize = 16;

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
/// Best-effort retention: oldest entries are overwritten as new ones
/// arrive; queries on rotated-out badges return `None`.
#[derive(Clone, Copy)]
pub struct RecentExits
{
    ring: [Option<RecentExit>; RECENT_EXITS_SLOTS],
    head: usize,
}

#[derive(Clone, Copy)]
struct RecentExit
{
    badge: u64,
    exit_reason: u64,
}

impl RecentExits
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            ring: [None; RECENT_EXITS_SLOTS],
            head: 0,
        }
    }

    pub fn record(&mut self, badge: u64, exit_reason: u64)
    {
        self.ring[self.head] = Some(RecentExit { badge, exit_reason });
        self.head = (self.head + 1) % RECENT_EXITS_SLOTS;
    }

    #[must_use]
    pub fn find(&self, badge: u64) -> Option<u64>
    {
        self.ring
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.badge == badge)
            .map(|e| e.exit_reason)
    }
}

impl Default for RecentExits
{
    fn default() -> Self
    {
        Self::new()
    }
}

pub struct ProcessTable
{
    entries: [Option<ProcessEntry>; MAX_PROCESSES],
}

impl ProcessTable
{
    #[must_use]
    pub const fn new() -> Self
    {
        const NONE: Option<ProcessEntry> = None;
        Self {
            entries: [NONE; MAX_PROCESSES],
        }
    }

    /// Place `entry` in the first free slot. Returns `false` (changing
    /// nothing) when all [`MAX_PROCESSES`] slots are occupied.
    #[must_use]
    pub fn insert(&mut self, entry: ProcessEntry) -> bool
    {
        for slot in &mut self.entries
        {
            if slot.is_none()
            {
                *slot = Some(entry);
                return true;
            }
        }
        false
    }

    /// Locate the live entry whose badge matches, for in-place mutation.
    #[must_use]
    pub fn find_mut_by_badge(&mut self, badge: u64) -> Option<&mut ProcessEntry>
    {
        self.entries
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|e| e.badge == badge)
    }

    /// Remove and return the entry whose badge matches, clearing its slot.
    #[must_use]
    pub fn take_by_badge(&mut self, badge: u64) -> Option<ProcessEntry>
    {
        for slot in &mut self.entries
        {
            if let Some(entry) = slot.as_ref()
                && entry.badge == badge
            {
                return slot.take();
            }
        }
        None
    }

    /// Remove and return the entry whose badge matches `correlator` in its
    /// low 32 bits. Used by the auto-reap dispatch to resolve a death event
    /// back to its process. Stale correlators (entry already reaped)
    /// return `None`; callers drop such events silently.
    #[must_use]
    pub fn take_by_correlator(&mut self, correlator: u32) -> Option<ProcessEntry>
    {
        for slot in &mut self.entries
        {
            // The low-32 extraction is intentional: the death-EQ binding
            // API carries a u32 correlator while badges are u64; matching
            // mirrors how the correlator was derived (`badge as u32`).
            #[allow(clippy::cast_possible_truncation)]
            if let Some(entry) = slot.as_ref()
                && (entry.badge as u32) == correlator
            {
                return slot.take();
            }
        }
        None
    }

    /// Visit every live entry in insertion order. Used by
    /// `install_logd_death_eq` to retroactively bind logd's EQ as a
    /// second death observer on each child's main thread.
    pub fn for_each<F: FnMut(&ProcessEntry)>(&self, mut f: F)
    {
        for slot in &self.entries
        {
            if let Some(entry) = slot.as_ref()
            {
                f(entry);
            }
        }
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
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.badge == badge)
            .map(|e| (e.started, e.thread_cap))
    }
}

impl Default for ProcessTable
{
    fn default() -> Self
    {
        Self::new()
    }
}

// ── Badge acceptance ─────────────────────────────────────────────────────────

/// Whether a candidate badge may be handed out as a process badge.
///
/// The low 32 bits of a process badge serve double duty — the death-EQ
/// correlator (the binding API takes a `u32`) and the logd source badge — so
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
/// All are reachable under random badge minting; the old monotonic counter
/// started at `LOG_BADGE_FIRST_CHILD` and so upheld the floor structurally.
#[must_use]
pub fn badge_is_acceptable(badge: u64, min_low: u64, reserved_low32: u32) -> bool
{
    // The low-32 extraction is intentional: only the truncated u32 reaches
    // the correlator-bearing death-EQ API and the logd badge.
    #[allow(clippy::cast_possible_truncation)]
    let low = badge as u32;
    u64::from(low) >= min_low && low != reserved_low32
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
        assert!(!badge_is_acceptable(u64::from(u32::MAX), 16, u32::MAX));
        assert!(!badge_is_acceptable(0x0000_0005_FFFF_FFFF, 16, u32::MAX));
    }

    #[test]
    fn badge_is_rejected_when_low_word_below_floor()
    {
        // The reserved log-badge / no-correlator range (low word 0..16) is
        // rejected regardless of the high word, so every minted badge carries
        // a routable correlator and never aliases a reserved logd slot.
        assert!(!badge_is_acceptable(0, 16, u32::MAX));
        assert!(!badge_is_acceptable(1, 16, u32::MAX));
        assert!(!badge_is_acceptable(2, 16, u32::MAX));
        assert!(!badge_is_acceptable(15, 16, u32::MAX));
        assert!(!badge_is_acceptable(0x0000_0007_0000_000F, 16, u32::MAX));
    }

    #[test]
    fn badge_is_accepted_when_low_word_clears_floor_and_correlator()
    {
        assert!(badge_is_acceptable(16, 16, u32::MAX));
        // High bits set, low word clears the floor and the sentinel: accepted.
        assert!(badge_is_acceptable(0x0000_0001_0000_0010, 16, u32::MAX));
    }

    #[test]
    fn insert_fills_first_empty_slot_and_reports_full_table()
    {
        let mut table = ProcessTable::new();
        for badge in 0..MAX_PROCESSES as u64
        {
            assert!(table.insert(entry_with_badge(badge)));
        }
        // Saturated: the next insert must fail rather than clobber a slot.
        assert!(!table.insert(entry_with_badge(0xDEAD)));
        assert!(table.find_mut_by_badge(0xDEAD).is_none());
    }

    #[test]
    fn find_mut_by_badge_returns_live_entry_and_none_for_unknown()
    {
        let mut table = ProcessTable::new();
        assert!(table.insert(entry_with_badge(16)));
        assert_eq!(table.find_mut_by_badge(16).map(|e| e.badge()), Some(16));
        assert!(table.find_mut_by_badge(99).is_none());
    }

    #[test]
    fn take_by_badge_removes_matching_entry_and_leaves_slot_empty()
    {
        let mut table = ProcessTable::new();
        assert!(table.insert(entry_with_badge(16)));
        assert_eq!(table.take_by_badge(16).map(|e| e.badge), Some(16));
        // Slot is now free: a second take misses and find no longer sees it.
        assert!(table.take_by_badge(16).is_none());
        assert!(table.find_mut_by_badge(16).is_none());
    }

    #[test]
    fn take_by_correlator_matches_low_32_bits_of_badge_and_removes_entry()
    {
        let mut table = ProcessTable::new();
        // High bits set; correlator is only the low word. A full-u64 compare
        // would miss this match.
        assert!(table.insert(entry_with_badge(0x0000_0001_0000_002A)));
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
        assert!(table.insert(entry));
        assert_eq!(table.query_by_badge(16), Some((false, 7)));
        table.find_mut_by_badge(16).expect("entry present").started = true;
        assert_eq!(table.query_by_badge(16), Some((true, 7)));
        assert_eq!(table.query_by_badge(99), None);
    }

    #[test]
    fn for_each_visits_exactly_the_live_entries()
    {
        let mut table = ProcessTable::new();
        assert!(table.insert(entry_with_badge(10)));
        assert!(table.insert(entry_with_badge(20)));
        assert!(table.insert(entry_with_badge(30)));
        let _ = table.take_by_badge(20);
        let mut seen = [0u64; MAX_PROCESSES];
        let mut count = 0usize;
        table.for_each(|e| {
            seen[count] = e.badge;
            count += 1;
        });
        assert_eq!(count, 2);
        assert_eq!(&seen[..2], &[10, 30]);
    }

    #[test]
    fn recent_exits_record_then_find_returns_exit_reason()
    {
        let mut recent = RecentExits::new();
        recent.record(16, 42);
        assert_eq!(recent.find(16), Some(42));
        assert_eq!(recent.find(17), None);
    }

    #[test]
    fn recent_exits_ring_overwrites_oldest_after_capacity()
    {
        let mut recent = RecentExits::new();
        // One more record than the ring holds: the first badge is evicted.
        for i in 0..=RECENT_EXITS_SLOTS as u64
        {
            recent.record(100 + i, 100 + i);
        }
        assert_eq!(recent.find(100), None);
        assert_eq!(
            recent.find(100 + RECENT_EXITS_SLOTS as u64),
            Some(100 + RECENT_EXITS_SLOTS as u64)
        );
    }
}
