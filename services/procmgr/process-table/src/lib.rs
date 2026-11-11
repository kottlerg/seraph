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
//! init-reap handoff state machine ([`InitReap`]), the size of procmgr's
//! first death queue ([`death_queues::FIRST_POOL_OBSERVERS`]), and the
//! registry of the threads a process registers with their crash badges
//! ([`threads`]). None of these
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
pub mod names;
pub mod request_caps;
pub mod threads;

pub use create_blobs::{ArgvEnvRefusal, ArgvEnvTally, checked_total, decode_header};
pub use dma_holds::{DmaHolds, HeldReclaim, ReleaseRefusal, release_target, release_token_badge};
pub use init_reap::{CapDisposition, DeathOutcome, InitReap, Refusal, poll_within};
pub use names::ProcessName;
pub use request_caps::{CreateCaps, CreateTailCaps, split_create_caps};
pub use threads::{
    CrashBadges, Origin, RegisterRefusal, RegisteredThread, ThreadRegistry, is_debugger_badge,
};

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
    /// observers, the badge of its process handle (with
    /// `procmgr_labels::PROCESS_HANDLE_TAG`, [`request_badge`]) and of the
    /// procmgr, registry, and log SENDs procmgr mints for it, and the
    /// source badge logd keys its stream by. Minted at random and accepted
    /// only by [`badge_is_acceptable`], so it carries no verb bit.
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
    /// Set by the child's `DECLARE_NO_DEBUG` ([`ProcessTable::declare_no_debug`]):
    /// procmgr unbound its crash handler and refuses `ATTACH_PROCESS` on it
    /// ([`attach_target`]).
    pub no_debug: bool,
    /// Where the loader placed the child's image, which `ATTACH_PROCESS`
    /// reports.
    pub image: ImageSpan,
    /// The threads the child's runtime registered (`REGISTER_THREAD`), which
    /// `ATTACH_PROCESS` lists after the main thread.
    pub threads: ThreadRegistry,
    /// The child's name, the first string of its argv, which
    /// `LIST_PROCESSES` reports.
    pub name: ProcessName,
    /// Slot in procmgr's `CSpace` of the main-thread cap of the debugger
    /// attached to the child (`ATTACH_PROCESS` `caps[0]`); `0` with none.
    /// Once that thread has exited, procmgr restores the child's crash
    /// bindings, as `DETACH_PROCESS` does. The child's `DECLARE_NO_DEBUG`
    /// takes it ([`ProcessTable::declare_no_debug`]).
    pub debugger: u64,
}

/// Where the loader placed a child's image: the load bias it drew and the
/// biased bounds of the image's executable segments.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ImageSpan
{
    /// The bias added to every ELF address of the image.
    pub load_bias: u64,
    /// Lowest biased address of an executable segment; `0` with none.
    pub text_start: u64,
    /// One past the highest biased address of an executable segment; `0`
    /// with none.
    pub text_end: u64,
}

impl ImageSpan
{
    /// Widen the text bounds to cover the executable segment
    /// `[start, end)` (biased); an empty segment changes nothing.
    pub fn add_text(&mut self, start: u64, end: u64)
    {
        if start >= end
        {
            return;
        }
        if self.text_start == self.text_end
        {
            self.text_start = start;
            self.text_end = end;
            return;
        }
        self.text_start = self.text_start.min(start);
        self.text_end = self.text_end.max(end);
    }
}

impl ProcessEntry
{
    /// The child's process badge, the `badge` field.
    #[must_use]
    pub fn badge(&self) -> u64
    {
        self.badge
    }

    /// Whether a thread of this child bound under `badge` is bound to the
    /// crash endpoint by procmgr: under its process badge, its main thread's,
    /// or under a crash badge, which carries [`threads::CRASH_BADGE_TAG`]
    /// whether or not the thread procmgr bound under it is still registered
    /// (a spawner that exited). A debugger binds under a badge that is
    /// neither (`services/procmgr/docs/ipc-interface.md` § `REGISTER_THREAD`).
    #[must_use]
    pub fn is_crash_binding(&self, badge: u64) -> bool
    {
        badge == self.badge || threads::is_crash_badge(badge)
    }

    /// Whether a `REGISTER_THREAD` binds a thread of this child, whose
    /// exception class is bound under `current` (`None`: unbound), to the
    /// crash endpoint under a fresh crash badge: when procmgr's binding is on
    /// it ([`Self::is_crash_binding`]), which a thread that copied its
    /// spawner's carries, or a debugger's ([`threads::is_debugger_badge`])
    /// while the child has no debugger watched, which a thread that copied a
    /// debugger's binding carries once that debugger has detached or died. A
    /// debugger's binding while one is watched, another handler's, and none
    /// are left.
    #[must_use]
    pub fn rebinds_on_register(&self, current: Option<u64>) -> bool
    {
        current.is_some_and(|b| {
            self.is_crash_binding(b) || (self.debugger == 0 && threads::is_debugger_badge(b))
        })
    }

    /// Whether a restore of this child's crash bindings (`DETACH_PROCESS`,
    /// or its watched debugger's death) binds a listed thread, whose
    /// exception class is bound under `current`, back to the crash endpoint
    /// under `own`, procmgr's badge for it: the process badge for the main
    /// thread, a registered thread's crash badge, or `0` for one that has
    /// none. It does when the class is unbound, bound by a debugger, or bound
    /// by procmgr under another badge; it leaves a thread already under
    /// `own`, and one bound to any other handler: one the child bound
    /// itself, or another process's thread bound under that process's badge.
    #[must_use]
    pub fn restores(&self, current: Option<u64>, own: u64) -> bool
    {
        match current
        {
            None => true,
            Some(b) if own != 0 && b == own => false,
            Some(b) => self.is_crash_binding(b) || threads::is_debugger_badge(b),
        }
    }

    /// Whether `DECLARE_NO_DEBUG` unbinds a thread of this child whose
    /// exception class is bound under `current`: when procmgr or a debugger
    /// bound it, so the declared child is bound to neither the crash
    /// endpoint nor a debugger's. A handler the child bound itself stays.
    #[must_use]
    pub fn declare_unbinds(&self, current: Option<u64>) -> bool
    {
        current.is_some_and(|b| self.is_crash_binding(b) || threads::is_debugger_badge(b))
    }
}

/// What a restore of a process's crash bindings (`DETACH_PROCESS`, or its
/// watched debugger's death) does to the exception class of one of its
/// registered threads ([`ProcessTable::restore_action`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreAction
{
    /// Leave the binding as it is.
    Leave,
    /// Bind the class to the crash endpoint under this badge; `0` asks for a
    /// fresh crash badge, recorded as the thread's.
    Bind(u64),
    /// Unbind the class: a debugger's binding on a thread procmgr does not
    /// bind back.
    Unbind,
}

/// What [`ProcessTable::declare_no_debug`] takes from the entry it marks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Declared
{
    /// The main thread's cap slot, whose bindings procmgr then unbinds.
    pub thread_cap: u64,
    /// The debugger watch the entry held, now cleared, which procmgr
    /// deletes; `0` with none.
    pub debugger: u64,
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
    crash_badges: CrashBadges,
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
            crash_badges: CrashBadges::new(),
        }
    }

    /// A fresh thread crash badge, which no process badge and no other
    /// thread's crash badge equals ([`threads::CrashBadges`]).
    pub fn mint_crash_badge(&mut self) -> u64
    {
        self.crash_badges.mint()
    }

    /// Index of the live entry one of whose registered threads is bound to
    /// the crash endpoint under `crash_badge`.
    fn index_of_crash_badge(&self, crash_badge: u64) -> Option<usize>
    {
        if !threads::is_crash_badge(crash_badge)
        {
            return None;
        }
        self.entries
            .iter()
            .position(|e| e.threads.position_of_crash_badge(crash_badge).is_some())
    }

    /// Whose thread a `REGISTER_THREAD` from the process `sender` takes,
    /// its exception class bound under `current` (`None`: unbound): another
    /// live process's when the binding is that process's badge, or a crash
    /// badge that process's registry lists; unbound when there is no
    /// binding; the sender's own otherwise, as far as procmgr can tell (its
    /// process badge, a crash badge its own registry or no registry lists, a
    /// debugger's badge, or another handler's).
    #[must_use]
    pub fn origin_of(&self, sender: u64, current: Option<u64>) -> Origin
    {
        let Some(bound) = current
        else
        {
            return Origin::Unbound;
        };
        if bound == sender
        {
            return Origin::Own;
        }
        let owner = if threads::is_crash_badge(bound)
        {
            let in_sender = self
                .find_by_badge(sender)
                .is_some_and(|e| e.threads.position_of_crash_badge(bound).is_some());
            if in_sender
            {
                return Origin::Own;
            }
            self.index_of_crash_badge(bound)
                .map(|idx| self.entries[idx].badge)
        }
        else
        {
            self.index_of_badge(bound).map(|idx| self.entries[idx].badge)
        };
        match owner
        {
            Some(badge) if badge != sender => Origin::Foreign(badge),
            _ => Origin::Own,
        }
    }

    /// What a restore of the crash bindings of the process `badge` does to
    /// `thread`, one of its registered threads, whose exception class is
    /// bound under `current` (`None`: unbound). By the thread's origin:
    ///
    /// * the sender's own: bound back under its crash badge, a fresh one when
    ///   it has none, when [`ProcessEntry::restores`] says so (an unbound
    ///   class among them);
    /// * another process's that is live and undeclared: a thread procmgr
    ///   rebound under a crash badge of the sender's is restored as the
    ///   sender's own; one it left is bound back under that process's badge
    ///   from a debugger's binding alone;
    /// * another process's that declared itself undebuggable or is gone, or
    ///   a thread unbound at its registration: never bound to the crash
    ///   endpoint, so no restore makes a declared process debuggable again;
    ///   a debugger's binding on it is unbound.
    ///
    /// A badge that names no live process leaves every thread.
    #[must_use]
    pub fn restore_action(
        &self,
        badge: u64,
        thread: &RegisteredThread,
        current: Option<u64>,
    ) -> RestoreAction
    {
        let Some(entry) = self.find_by_badge(badge)
        else
        {
            return RestoreAction::Leave;
        };
        let own_rule = || {
            if entry.restores(current, thread.crash_badge)
            {
                RestoreAction::Bind(thread.crash_badge)
            }
            else
            {
                RestoreAction::Leave
            }
        };
        let from_debugger = current.is_some_and(threads::is_debugger_badge);
        match thread.origin()
        {
            Origin::Own => own_rule(),
            Origin::Foreign(owner)
                if self.find_by_badge(owner).is_some_and(|e| !e.no_debug) =>
            {
                if thread.crash_badge != 0
                {
                    own_rule()
                }
                else if from_debugger
                {
                    RestoreAction::Bind(owner)
                }
                else
                {
                    RestoreAction::Leave
                }
            }
            Origin::Foreign(_) | Origin::Unbound if from_debugger => RestoreAction::Unbind,
            Origin::Foreign(_) | Origin::Unbound => RestoreAction::Leave,
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

    /// Mark the live entry whose badge matches undebuggable
    /// (`DECLARE_NO_DEBUG`, sent on the child's own procmgr cap), and take
    /// its debugger watch, so no watched debugger's death restores a crash
    /// binding of a declared child. Returns its main-thread cap slot, whose
    /// bindings procmgr then unbinds, and the watch, which procmgr deletes;
    /// `None` when the badge names no live entry.
    #[must_use]
    pub fn declare_no_debug(&mut self, badge: u64) -> Option<Declared>
    {
        let entry = self.find_mut_by_badge(badge)?;
        entry.no_debug = true;
        Some(Declared {
            thread_cap: entry.thread_cap,
            debugger: core::mem::take(&mut entry.debugger),
        })
    }

    /// The live entry whose badge matches.
    #[must_use]
    pub fn find_by_badge(&self, badge: u64) -> Option<&ProcessEntry>
    {
        let idx = self.index_of_badge(badge)?;
        Some(&self.entries[idx])
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
        let mut copied = 0;
        for (slot, entry) in out.iter_mut().zip(self.entries_after(after))
        {
            *slot = entry.badge;
            copied += 1;
        }
        copied
    }

    /// The live entries above `after` (every entry when `after` is `None`),
    /// in badge order: the walk [`Self::live_badges_after`] and
    /// `LIST_PROCESSES` page through.
    pub fn entries_after(&self, after: Option<u64>) -> impl Iterator<Item = &ProcessEntry>
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
        self.entries[start..].iter()
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

// ── Debug authority ─────────────────────────────────────────────────────────

/// Why procmgr refuses an `ATTACH_PROCESS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachRefusal
{
    /// The caller's badge lacks `procmgr_labels::DEBUG_AUTHORITY`
    /// (`UNAUTHORIZED`).
    Unauthorized,
    /// No live process carries the target badge (`INVALID_BADGE`). memmgr
    /// and procmgr, which procmgr did not create, are never in the table.
    Unknown,
    /// The target declared itself undebuggable
    /// (`procmgr_labels::DECLARE_NO_DEBUG`; `NOT_ATTACHABLE`): the log sink,
    /// the serial and framebuffer drivers, the debug port's driver, and every
    /// debug-authority holder, the caller among them.
    NotAttachable,
}

/// The badge procmgr serves a request badged `badge` under, with
/// `procmgr_labels::PROCESS_HANDLE_TAG` cleared, and whether the request
/// came on a process handle, whose badge carries the tag.
#[must_use]
pub fn request_badge(badge: u64) -> (u64, bool)
{
    let tag = ipc::procmgr_labels::PROCESS_HANDLE_TAG;
    (badge & !tag, badge & tag != 0)
}

/// Whether procmgr serves `opcode` (a label's low 16 bits) on a process
/// handle: every label but `DECLARE_NO_DEBUG` and `REGISTER_THREAD`, which
/// name their sender itself and are served on the child's own procmgr cap
/// alone.
#[must_use]
pub fn served_on_handle(opcode: u64) -> bool
{
    !matches!(
        opcode,
        ipc::procmgr_labels::DECLARE_NO_DEBUG | ipc::procmgr_labels::REGISTER_THREAD
    )
}

/// Whether a request on procmgr's endpoint badged `caller_badge` carries
/// `procmgr_labels::DEBUG_AUTHORITY`.
#[must_use]
pub fn debug_authorized(caller_badge: u64) -> bool
{
    caller_badge & ipc::procmgr_labels::DEBUG_AUTHORITY != 0
}

/// The thread the badge of an `ATTACH_PROCESS` request names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NamedThread
{
    /// A process badge: the process's main thread, the thread its crash
    /// binding names.
    Main,
    /// A thread crash badge: the registered thread procmgr bound under it.
    Registered(u64),
}

impl NamedThread
{
    /// The index of the named thread in `entry`'s attach list (the main
    /// thread, then each registered thread), or
    /// `procmgr_labels::ATTACH_NO_THREAD` when it is no longer listed.
    #[must_use]
    pub fn index_in(self, entry: &ProcessEntry) -> u64
    {
        match self
        {
            NamedThread::Main => 0,
            NamedThread::Registered(badge) => entry
                .threads
                .position_of_crash_badge(badge)
                .map_or(ipc::procmgr_labels::ATTACH_NO_THREAD, |i| i as u64 + 1),
        }
    }
}

/// The entry an `ATTACH_PROCESS` from `caller_badge` for `target` reaches,
/// with the thread `target` names, or why it is refused: the caller's
/// authority first, then the target's presence, then its no-debug mark.
/// `target` is a process badge, or the crash badge of one of a process's
/// registered threads, as a fault message on the crash endpoint carries it.
///
/// # Errors
/// The [`AttachRefusal`] that refuses it.
pub fn attach_target(
    table: &mut ProcessTable,
    caller_badge: u64,
    target: u64,
) -> Result<(&mut ProcessEntry, NamedThread), AttachRefusal>
{
    if !debug_authorized(caller_badge)
    {
        return Err(AttachRefusal::Unauthorized);
    }
    let (idx, named) = if threads::is_crash_badge(target)
    {
        let idx = table
            .index_of_crash_badge(target)
            .ok_or(AttachRefusal::Unknown)?;
        (idx, NamedThread::Registered(target))
    }
    else
    {
        let idx = table.index_of_badge(target).ok_or(AttachRefusal::Unknown)?;
        (idx, NamedThread::Main)
    };
    let entry = &mut table.entries[idx];
    if entry.no_debug
    {
        return Err(AttachRefusal::NotAttachable);
    }
    Ok((entry, named))
}

/// The entry a `DETACH_PROCESS` from `caller_badge` for the process badge
/// `target` reaches, or why it is refused, in [`attach_target`]'s order: the
/// caller's authority, the target's presence, its no-debug mark. Unlike an
/// attach, it takes a process badge alone.
///
/// # Errors
/// The [`AttachRefusal`] that refuses it.
pub fn detach_target(
    table: &mut ProcessTable,
    caller_badge: u64,
    target: u64,
) -> Result<&mut ProcessEntry, AttachRefusal>
{
    if !debug_authorized(caller_badge)
    {
        return Err(AttachRefusal::Unauthorized);
    }
    let idx = table.index_of_badge(target).ok_or(AttachRefusal::Unknown)?;
    let entry = &mut table.entries[idx];
    if entry.no_debug
    {
        return Err(AttachRefusal::NotAttachable);
    }
    Ok(entry)
}

/// The entry a `REGISTER_THREAD` sent on a cap badged `sender_badge` registers
/// its thread with, or why it is refused: the sender's presence, then its
/// no-debug mark.
///
/// # Errors
/// [`AttachRefusal::Unknown`] when no live process carries the badge
/// (`INVALID_BADGE`); [`AttachRefusal::NotAttachable`] when it declared
/// itself undebuggable (`NOT_ATTACHABLE`).
pub fn register_target(
    table: &mut ProcessTable,
    sender_badge: u64,
) -> Result<&mut ProcessEntry, AttachRefusal>
{
    let entry = table
        .find_mut_by_badge(sender_badge)
        .ok_or(AttachRefusal::Unknown)?;
    if entry.no_debug
    {
        return Err(AttachRefusal::NotAttachable);
    }
    Ok(entry)
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
/// child an authority its servers reserve to trusted minters. The handle's
/// own verb bit, `procmgr_labels::PROCESS_HANDLE_TAG`, is procmgr's to set,
/// beside the badge ([`request_badge`]).
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
            no_debug: false,
            image: ImageSpan::default(),
            threads: ThreadRegistry::new(),
            name: ProcessName::EMPTY,
            debugger: 0,
        }
    }

    /// The badge and named-thread index an attach reaches, for comparison.
    fn attached(
        table: &mut ProcessTable,
        caller: u64,
        target: u64,
    ) -> Result<(u64, u64), AttachRefusal>
    {
        attach_target(table, caller, target).map(|(e, named)| (e.badge, named.index_in(e)))
    }

    #[test]
    fn an_attach_needs_the_debug_authority_badge()
    {
        use ipc::procmgr_labels::{DEATH_EQ_AUTHORITY, DEBUG_AUTHORITY};
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(0x1234)).unwrap();
        for badge in [0, 0x1234, DEATH_EQ_AUTHORITY]
        {
            assert_eq!(
                attached(&mut table, badge, 0x1234),
                Err(AttachRefusal::Unauthorized)
            );
        }
        assert_eq!(
            attached(&mut table, DEBUG_AUTHORITY, 0x1234),
            Ok((0x1234, 0))
        );
    }

    #[test]
    fn an_attach_to_a_process_procmgr_does_not_hold_is_unknown()
    {
        // memmgr and procmgr are never in the table, and neither is a reaped
        // child, nor a crash badge no registered thread carries.
        let mut table = ProcessTable::new();
        assert_eq!(
            attached(&mut table, ipc::procmgr_labels::DEBUG_AUTHORITY, 0x99),
            Err(AttachRefusal::Unknown)
        );
        let crash_badge = table.mint_crash_badge();
        assert_eq!(
            attached(
                &mut table,
                ipc::procmgr_labels::DEBUG_AUTHORITY,
                crash_badge
            ),
            Err(AttachRefusal::Unknown)
        );
    }

    #[test]
    fn an_attach_by_a_thread_crash_badge_reaches_its_process_and_names_the_thread()
    {
        use ipc::procmgr_labels::DEBUG_AUTHORITY;
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(0x40)).unwrap();
        table.insert(entry_with_badge(0x50)).unwrap();
        let first = table.mint_crash_badge();
        let second = table.mint_crash_badge();
        let entry = register_target(&mut table, 0x50).unwrap();
        for (cap, badge) in [(7, first), (8, 0), (9, second)]
        {
            entry.threads.reserve().unwrap();
            entry
                .threads
                .push(RegisteredThread::new(cap, badge, Origin::Own));
        }
        // The list is the main thread, then the registered ones in order.
        assert_eq!(attached(&mut table, DEBUG_AUTHORITY, first), Ok((0x50, 1)));
        assert_eq!(attached(&mut table, DEBUG_AUTHORITY, second), Ok((0x50, 3)));
        assert_eq!(attached(&mut table, DEBUG_AUTHORITY, 0x50), Ok((0x50, 0)));
        // A crash badge is procmgr's binding whether or not its thread is
        // still registered; another process's badge, or a debugger's, is not.
        let unregistered = table.mint_crash_badge();
        let entry = table.find_by_badge(0x50).unwrap();
        assert!(entry.is_crash_binding(second));
        assert!(entry.is_crash_binding(0x50));
        assert!(entry.is_crash_binding(unregistered));
        assert!(!entry.is_crash_binding(0x40));
        assert!(!entry.is_crash_binding(0x51));
        // A named thread swept out since is no longer listed.
        let (entry, named) = attach_target(&mut table, DEBUG_AUTHORITY, first).unwrap();
        entry.threads.sweep(|t| t.cap != 7, |_| {});
        assert_eq!(named.index_in(entry), ipc::procmgr_labels::ATTACH_NO_THREAD);
    }

    #[test]
    fn a_registration_needs_a_live_process_that_did_not_declare_no_debug()
    {
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(0x60)).unwrap();
        assert_eq!(
            register_target(&mut table, 0x61).map(|e| e.badge),
            Err(AttachRefusal::Unknown)
        );
        assert_eq!(register_target(&mut table, 0x60).map(|e| e.badge), Ok(0x60));
        let _ = table.declare_no_debug(0x60);
        assert_eq!(
            register_target(&mut table, 0x60).map(|e| e.badge),
            Err(AttachRefusal::NotAttachable)
        );
    }

    #[test]
    fn an_attach_to_a_process_that_declared_no_debug_is_refused()
    {
        // The log sink, the serial and framebuffer drivers, and every
        // debug-authority holder, the caller among them, declare themselves
        // undebuggable.
        let mut table = ProcessTable::new();
        let mut marked = entry_with_badge(0x77);
        marked.thread_cap = 41;
        table.insert(marked).unwrap();
        table.insert(entry_with_badge(0x78)).unwrap();
        assert_eq!(table.declare_no_debug(0x77).map(|d| d.thread_cap), Some(41));
        assert_eq!(
            attached(&mut table, ipc::procmgr_labels::DEBUG_AUTHORITY, 0x77),
            Err(AttachRefusal::NotAttachable)
        );
        // The declaration marks its sender alone.
        assert_eq!(
            attached(&mut table, ipc::procmgr_labels::DEBUG_AUTHORITY, 0x78),
            Ok((0x78, 0))
        );
    }

    #[test]
    fn a_detach_is_refused_as_an_attach_is_and_takes_a_process_badge_alone()
    {
        let auth = ipc::procmgr_labels::DEBUG_AUTHORITY;
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(0x77)).unwrap();
        table.insert(entry_with_badge(0x78)).unwrap();
        assert!(table.declare_no_debug(0x78).is_some());
        let detached = |t: &mut ProcessTable, caller, target| {
            detach_target(t, caller, target).map(|e| e.badge)
        };
        assert_eq!(
            detached(&mut table, 0, 0x77),
            Err(AttachRefusal::Unauthorized)
        );
        assert_eq!(
            detached(&mut table, auth, 0x79),
            Err(AttachRefusal::Unknown)
        );
        assert_eq!(
            detached(&mut table, auth, 0x78),
            Err(AttachRefusal::NotAttachable)
        );
        // A thread crash badge names a thread, not the process to detach.
        let crash = table.mint_crash_badge();
        assert_eq!(
            detached(&mut table, auth, crash),
            Err(AttachRefusal::Unknown)
        );
        assert_eq!(detached(&mut table, auth, 0x77), Ok(0x77));
    }

    #[test]
    fn a_name_walk_pages_every_entry_in_badge_order_once()
    {
        let mut table = ProcessTable::new();
        for badge in [0x30, 0x10, 0x20]
        {
            let mut e = entry_with_badge(badge);
            let mut capture = names::NameCapture::default();
            capture.feed(&[b'p', u8::try_from(badge).unwrap(), 0]);
            e.name = capture.name();
            table.insert(e).unwrap();
        }
        let first: Vec<(u64, Vec<u8>)> = table
            .entries_after(None)
            .take(2)
            .map(|e| (e.badge, e.name.as_bytes().to_vec()))
            .collect();
        assert_eq!(
            first,
            [(0x10, b"p\x10".to_vec()), (0x20, b"p\x20".to_vec())]
        );
        let rest: Vec<u64> = table.entries_after(Some(0x20)).map(|e| e.badge).collect();
        assert_eq!(rest, [0x30]);
        // A cursor whose process died resumes at the next badge above it.
        assert_eq!(
            table.entries_after(Some(0x15)).next().map(|e| e.badge),
            Some(0x20)
        );
    }

    #[test]
    fn a_declaration_takes_the_debugger_watch_so_no_restore_follows()
    {
        // A debugger attached with a watch before the child declared: the
        // declaration hands the watch over for deletion and leaves none.
        let mut table = ProcessTable::new();
        let mut watched = entry_with_badge(0x77);
        watched.thread_cap = 41;
        watched.debugger = 93;
        table.insert(watched).unwrap();
        assert_eq!(
            table.declare_no_debug(0x77),
            Some(Declared {
                thread_cap: 41,
                debugger: 93
            })
        );
        let entry = table.find_by_badge(0x77).unwrap();
        assert!(entry.no_debug);
        assert_eq!(entry.debugger, 0);
    }

    #[test]
    fn a_registration_rebinds_procmgrs_binding_and_an_unwatched_debuggers_alone()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let mut table = ProcessTable::new();
        let crash = table.mint_crash_badge();
        let mut entry = entry_with_badge(0x50);
        assert!(entry.rebinds_on_register(Some(0x50)));
        assert!(entry.rebinds_on_register(Some(crash)));
        // A debugger's binding with no debugger watched is a dead or
        // detached debugger's, copied by a thread that registers late.
        assert!(entry.rebinds_on_register(Some(debugger)));
        // Another handler's, another process's, and none stay.
        assert!(!entry.rebinds_on_register(Some(0x51)));
        assert!(!entry.rebinds_on_register(Some(0)));
        assert!(!entry.rebinds_on_register(None));
        // While a debugger is watched, its binding is its own.
        entry.debugger = 93;
        assert!(!entry.rebinds_on_register(Some(debugger)));
        assert!(entry.rebinds_on_register(Some(crash)));
    }

    #[test]
    fn a_restore_binds_back_what_a_debugger_or_nobody_holds_and_leaves_other_handlers()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let mut table = ProcessTable::new();
        let own = table.mint_crash_badge();
        let other = table.mint_crash_badge();
        let entry = entry_with_badge(0x50);
        // The main thread, procmgr's badge for it the process badge.
        assert!(entry.restores(Some(debugger), 0x50));
        assert!(entry.restores(None, 0x50));
        assert!(!entry.restores(Some(0x50), 0x50));
        // A registered thread with a crash badge, and one with none.
        assert!(entry.restores(Some(debugger), own));
        assert!(!entry.restores(Some(own), own));
        assert!(entry.restores(Some(other), own));
        assert!(entry.restores(Some(debugger), 0));
        assert!(entry.restores(Some(0x50), 0));
        // The child's own handler, and another process's thread bound under
        // that process's badge, are not taken into this child's crash binding.
        assert!(!entry.restores(Some(0), 0));
        assert!(!entry.restores(Some(0x51), 0));
        assert!(!entry.restores(Some(0x51), own));
    }

    #[test]
    fn a_declaration_unbinds_procmgrs_and_a_debuggers_bindings_and_no_other()
    {
        let mut table = ProcessTable::new();
        let crash = table.mint_crash_badge();
        let entry = entry_with_badge(0x50);
        assert!(entry.declare_unbinds(Some(0x50)));
        assert!(entry.declare_unbinds(Some(crash)));
        assert!(entry.declare_unbinds(Some(ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3)));
        assert!(!entry.declare_unbinds(Some(0)));
        assert!(!entry.declare_unbinds(Some(0x51)));
        assert!(!entry.declare_unbinds(None));
    }

    #[test]
    fn a_process_handle_names_its_child_and_sends_neither_declaration_nor_registration()
    {
        use ipc::procmgr_labels::{
            DECLARE_NO_DEBUG, DESTROY_PROCESS, PROCESS_HANDLE_TAG, QUERY_PROCESS,
            REGISTER_THREAD, START_PROCESS,
        };
        // A child's own procmgr cap carries its process badge alone; its
        // process handle carries the tag too, which procmgr clears.
        assert_eq!(request_badge(0x50), (0x50, false));
        assert_eq!(request_badge(0x50 | PROCESS_HANDLE_TAG), (0x50, true));
        // The tag is no process badge's: none carries a verb bit.
        assert!(!badge_is_acceptable(
            0x50 | PROCESS_HANDLE_TAG,
            ipc::log_badges::LOG_BADGE_FIRST_CHILD,
            ipc::procmgr_labels::INIT_REAP_CORRELATOR,
            ipc::VERB_BIT_MASK
        ));
        for opcode in [DECLARE_NO_DEBUG, REGISTER_THREAD]
        {
            assert!(!served_on_handle(opcode));
        }
        for opcode in [START_PROCESS, DESTROY_PROCESS, QUERY_PROCESS]
        {
            assert!(served_on_handle(opcode));
        }
    }

    /// A table holding the sender `0x40` and another process `0x50`, each
    /// with one registered thread bound under a crash badge, and those two
    /// badges and one no registry lists.
    fn two_processes() -> (ProcessTable, [u64; 3])
    {
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(0x40)).unwrap();
        table.insert(entry_with_badge(0x50)).unwrap();
        let badges = [
            table.mint_crash_badge(),
            table.mint_crash_badge(),
            table.mint_crash_badge(),
        ];
        for (badge, crash) in [(0x40, badges[0]), (0x50, badges[1])]
        {
            let entry = table.find_mut_by_badge(badge).unwrap();
            entry.threads.reserve().unwrap();
            entry
                .threads
                .push(RegisteredThread::new(7, crash, Origin::Own));
        }
        (table, badges)
    }

    #[test]
    fn a_registration_records_another_live_processs_thread_as_its()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let (table, [own, other, orphan]) = two_processes();
        assert_eq!(table.origin_of(0x40, None), Origin::Unbound);
        assert_eq!(table.origin_of(0x40, Some(0x50)), Origin::Foreign(0x50));
        assert_eq!(table.origin_of(0x40, Some(other)), Origin::Foreign(0x50));
        for own_binding in [0x40, own, orphan, debugger, 0x99]
        {
            assert_eq!(table.origin_of(0x40, Some(own_binding)), Origin::Own);
        }
    }

    #[test]
    fn a_restore_never_binds_a_declared_processs_thread_back()
    {
        // The creator 0x40 registered its child 0x50's main thread, which
        // its binding showed was 0x50's; the child then declared, which
        // unbound that thread.
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let (mut table, _) = two_processes();
        let child_main = RegisteredThread::new(9, 0, table.origin_of(0x40, Some(0x50)));
        // Until the child declares, a debugger's binding goes back to the
        // child's own, and the child's own binding stays.
        assert_eq!(
            table.restore_action(0x40, &child_main, Some(debugger)),
            RestoreAction::Bind(0x50)
        );
        assert_eq!(
            table.restore_action(0x40, &child_main, Some(0x50)),
            RestoreAction::Leave
        );
        let _ = table.declare_no_debug(0x50);
        assert_eq!(
            table.restore_action(0x40, &child_main, None),
            RestoreAction::Leave
        );
        assert_eq!(
            table.restore_action(0x40, &child_main, Some(debugger)),
            RestoreAction::Unbind
        );
        // Nor once the child is gone.
        let _ = table.take_by_badge(0x50);
        assert_eq!(
            table.restore_action(0x40, &child_main, Some(debugger)),
            RestoreAction::Unbind
        );
    }

    #[test]
    fn a_restore_binds_the_senders_own_threads_back_and_never_an_unbound_registration()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let (table, [own, other, _]) = two_processes();
        let badged = RegisteredThread::new(7, own, Origin::Own);
        let unbadged = RegisteredThread::new(8, 0, Origin::Own);
        assert_eq!(
            table.restore_action(0x40, &badged, Some(debugger)),
            RestoreAction::Bind(own)
        );
        assert_eq!(
            table.restore_action(0x40, &badged, Some(own)),
            RestoreAction::Leave
        );
        assert_eq!(
            table.restore_action(0x40, &unbadged, Some(debugger)),
            RestoreAction::Bind(0)
        );
        // An unbound class of the sender's own thread is bound back, as the
        // main thread's is.
        assert_eq!(
            table.restore_action(0x40, &badged, None),
            RestoreAction::Bind(own)
        );
        assert_eq!(
            table.restore_action(0x40, &unbadged, None),
            RestoreAction::Bind(0)
        );
        // Another process's thread procmgr rebound into the sender's crash
        // binding is restored as the sender's own while that process lives
        // undeclared.
        let rebound = RegisteredThread::new(10, own, Origin::Foreign(0x50));
        assert_eq!(
            table.restore_action(0x40, &rebound, Some(debugger)),
            RestoreAction::Bind(own)
        );
        // A thread unbound at its registration is never bound to the crash
        // endpoint; a debugger's binding on it is taken off.
        let unknown = RegisteredThread::new(11, 0, Origin::Unbound);
        assert_eq!(
            table.restore_action(0x40, &unknown, Some(debugger)),
            RestoreAction::Unbind
        );
        assert_eq!(
            table.restore_action(0x40, &unknown, Some(other)),
            RestoreAction::Leave
        );
        assert_eq!(
            table.restore_action(0x40, &unknown, None),
            RestoreAction::Leave
        );
        // A badge naming no live process changes nothing.
        assert_eq!(
            table.restore_action(0x41, &badged, Some(debugger)),
            RestoreAction::Leave
        );
    }

    #[test]
    fn a_declaration_from_a_badge_with_no_live_process_marks_nothing()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.declare_no_debug(0x77), None);
    }

    #[test]
    fn the_text_span_covers_every_executable_segment_and_skips_empty_ones()
    {
        let mut span = ImageSpan::default();
        span.add_text(0x5000, 0x5000);
        assert_eq!((span.text_start, span.text_end), (0, 0));
        span.add_text(0x3000, 0x4000);
        span.add_text(0x8000, 0x9000);
        span.add_text(0x1000, 0x2000);
        assert_eq!((span.text_start, span.text_end), (0x1000, 0x9000));
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
        // Bits 58..=63 are the verb bits (svcmgr's HANDOVER_AUTHORITY /
        // PUBLISH_AUTHORITY on the child's registry SEND among them); a badge
        // that clears every other check must not carry any of them.
        let verbs = ipc::VERB_BIT_MASK;
        for bit in [63, 62, 61, 60, 59, 58]
        {
            assert!(!badge_is_acceptable(
                (1u64 << bit) | 0x10,
                16,
                u64::MAX,
                verbs
            ));
        }
        assert!(badge_is_acceptable(
            0x03FF_FFFF_0000_0010,
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
