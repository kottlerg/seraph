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
//! ([`split_create_caps`]), the bounds procmgr applies to an fs driver's
//! `FS_READ_MEMORY` replies and their cap split ([`fs_reads`]), the
//! init-reap handoff state machine
//! ([`InitReap`]), the size of procmgr's first death queue
//! ([`death_queues::FIRST_POOL_OBSERVERS`]), the registry of the threads a
//! process registers with their crash badges ([`threads`]), and the
//! registered crash service with its registration's generation
//! ([`crash_registrant`]), the signature policy each creator's record
//! carries ([`sign_policy`]), and the process tree: each entry's parent, the
//! marking of a subtree a destroy has begun on, and the re-parenting or
//! containment at a process's end ([`ProcessTable::doom_subtree`],
//! [`ProcessTable::take_ended`]). None of these
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

pub mod crash_registrant;
pub mod create_blobs;
pub mod death_queues;
pub mod dma_holds;
pub mod fs_reads;
pub mod init_reap;
pub mod names;
pub mod request_caps;
pub mod sign_policy;
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
/// All fields are non-atomic. procmgr's request workers and its reaper
/// reach an entry only through the table, which sits behind procmgr's one
/// table lock (`process::Tables`, services/procmgr/README.md
/// § Concurrency): every read and every mutating path
/// (`configure_namespace`, `start_process`, the take that precedes a
/// teardown) holds that lock throughout, so the `started` check and its
/// transition, and the install-once namespace and cwd-override slots, are
/// each one step no other thread interleaves.
#[expect(
    clippy::struct_excessive_bools,
    reason = "`reserve`, `started`, `dma_hold`, `no_debug`, `no_core`, `contained` and \
              `doomed` are independent facts set at different points of the child's life \
              (creation, start, create flags, declarations, a destroy), not states of one machine"
)]
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
    /// Whether the child's memmgr budget node is a system-reserve node, so
    /// the child may ask `CREATE_RESERVE` for its own children
    /// ([`child_budget`]).
    pub reserve: bool,
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
    /// Set by the child's `DECLARE_NO_CORE` ([`ProcessTable::declare_no_core`]):
    /// the child is on the core path, the processes a core dump waits on,
    /// which `ATTACH_PROCESS` reports ([`ProcessEntry::attach_flags`]).
    pub no_core: bool,
    /// Where the loader placed the child's image, which `ATTACH_PROCESS`
    /// reports.
    pub image: ImageSpan,
    /// The threads the child's runtime registered (`REGISTER_THREAD`), which
    /// `ATTACH_PROCESS` lists after the main thread.
    pub threads: ThreadRegistry,
    /// The child's name, the first string of its argv, which
    /// `LIST_PROCESSES` reports.
    pub name: ProcessName,
    /// The roles of object the child's own creates may load: its signature
    /// policy ([`sign_policy`]), its creator's narrowed by the child's own
    /// verified role set ([`sign_policy::child_roles`]).
    pub sign_roles: objsig::RoleSet,
    /// Slot in procmgr's `CSpace` of the main-thread cap of the debugger
    /// attached to the child (`ATTACH_PROCESS` `caps[0]`); `0` with none.
    /// Once that thread has exited, procmgr restores the child's crash
    /// bindings, as `DETACH_PROCESS` does. The child's `DECLARE_NO_DEBUG`
    /// takes it ([`ProcessTable::declare_no_debug`]).
    pub debugger: u64,
    /// The badge of the child's parent: the process whose create request
    /// made it (the badge the request came on, [`ProcessTable::creator_of`]),
    /// or that process's nearest live ancestor once it has ended
    /// ([`ProcessTable::take_ended`]); `0` for none, a child of the
    /// un-badged creator or of a line none of whose processes lives. A nonzero
    /// parent names a live entry. [`ProcessTable::insert`] sets it from the
    /// create's reservation.
    pub parent: u64,
    /// Set by `CREATE_CONTAIN`: the child's end destroys what is left of its
    /// subtree instead of re-parenting its children
    /// ([`ProcessTable::take_ended`]).
    pub contained: bool,
    /// Set once a destroy of a subtree that holds the child has begun
    /// ([`ProcessTable::doom_subtree`]): the entry waits for its teardown,
    /// procmgr refuses a create from it ([`ProcessTable::creator_of`]) and
    /// a start of it, and the child list omits it.
    pub doomed: bool,
    /// Slot in procmgr's `CSpace` of the death relay the create request
    /// carried (`CREATE_DEATH_RELAY`), to which procmgr posts the child's
    /// end once; `0` with none, and once the child is re-parented.
    pub relay: u64,
    /// Set from the insert until procmgr's reply to the create that made the
    /// entry has delivered the child's handle ([`ProcessTable::answer_create`]).
    /// Until then the create owns the entry's teardown, and the death relay
    /// with it: a destroy that marks the entry does not take it
    /// ([`ProcessTable::take_doomed`]), and the create refuses itself instead
    /// and deletes the relay unposted ([`ProcessTable::take_refused`]), so a
    /// failed creation never posts to its relay.
    pub unanswered: bool,
    /// Slot in procmgr's `CSpace` of the end queue the child registered on
    /// itself (`REGISTER_END_QUEUE`, [`ProcessTable::register_end_queue`]),
    /// to which procmgr posts the child's end once; `0` with none.
    pub end_queue: u64,
    /// The correlator posted with the child's end to its end queue, as the
    /// tag word.
    pub end_correlator: u64,
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

    /// The child's declarations and placement, as the `ATTACH_PROCESS`
    /// reply's `procmgr_labels::ATTACH_WORD_FLAGS` carries them: its
    /// `DECLARE_NO_CORE`, and whether its budget node is a reserve node.
    #[must_use]
    pub fn attach_flags(&self) -> u64
    {
        use ipc::procmgr_labels::{ATTACH_FLAG_NO_CORE, ATTACH_FLAG_RESERVE};
        let no_core = if self.no_core { ATTACH_FLAG_NO_CORE } else { 0 };
        let reserve = if self.reserve { ATTACH_FLAG_RESERVE } else { 0 };
        no_core | reserve
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

    /// Keep `watch`, the debugger watch an `ATTACH_PROCESS` of this child
    /// carried (`0`: none), as the child's debugger across `reply`, which
    /// sends the attach's reply and returns whether it was delivered. The
    /// watch is held before `reply` runs: once the caller holds its reply it
    /// can bind the child's threads, and its watch thread can exit at once,
    /// and the check that restores the crash bindings when that thread is
    /// gone must then find the watch. A delivered reply leaves the watch held;
    /// a failed one, which makes no attach, puts back the watch an earlier
    /// attach left. A request with no watch changes none.
    pub fn watch_across_reply(
        &mut self,
        watch: u64,
        reply: impl FnOnce(&Self) -> bool,
    ) -> WatchedReply
    {
        if watch == 0
        {
            return WatchedReply {
                delivered: reply(self),
                stale: 0,
            };
        }
        let earlier = core::mem::replace(&mut self.debugger, watch);
        if reply(self)
        {
            return WatchedReply {
                delivered: true,
                stale: earlier,
            };
        }
        self.debugger = earlier;
        WatchedReply {
            delivered: false,
            stale: watch,
        }
    }
}

/// What [`ProcessEntry::watch_across_reply`] leaves procmgr to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WatchedReply
{
    /// Whether the attach's reply was delivered.
    pub delivered: bool,
    /// The watch slot no entry holds any more, which procmgr deletes: the
    /// earlier watch a delivered reply's replaced, or the new one after a
    /// failed reply; `0` for none.
    pub stale: u64,
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

/// Why [`ProcessTable::insert`] refused an entry, or
/// [`ProcessTable::reserve_badge`] a reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsertError
{
    /// A live entry already holds the badge.
    BadgeInUse,
    /// The heap could not grow the table.
    OutOfMemory,
    /// The creator has ended, or a destroy of a subtree that holds it has
    /// begun: its child would escape that destroy.
    CreatorEnded,
}

/// How [`ProcessTable::answer_create`] ended a create whose child's entry was
/// inserted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateAnswer
{
    /// The reply delivered the child's handle; the child is its creator's.
    Answered,
    /// A destroy marked the entry before the reply, which was not made: the
    /// create is refused, as for a create a destroy marked before its insert.
    Refused,
    /// The reply could not be delivered: the create is refused.
    Undelivered,
}

/// Why [`ProcessTable::register_end_queue`] registered nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndQueueRefusal
{
    /// No live entry holds the badge.
    NotFound,
    /// The process registered an end queue before.
    Present,
}

/// A create in progress ([`ProcessTable::reserve_badge`]).
#[derive(Clone, Copy, Debug)]
struct Pending
{
    /// The badge reserved for the child.
    badge: u64,
    /// The badge of the process the child takes as its parent: its creator,
    /// moved to the creator's nearest live ancestor as an entry's parent is
    /// ([`ProcessTable::take_ended`]); `0` for none.
    creator: u64,
    /// Set once a destroy of a subtree that held the creator has begun: the
    /// insert is refused, so the child does not escape it.
    doomed: bool,
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
    /// The creates in progress ([`Self::reserve_badge`]): few, one per
    /// create a worker is serving.
    pending: Vec<Pending>,
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
            pending: Vec::new(),
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
    /// its exception class bound under `current` (`None`: unbound), which
    /// decides what a restore may bind it back to ([`Self::restore_action`]):
    ///
    /// * [`Origin::Own`] for the sender's process badge, a debugger's badge,
    ///   a crash badge no live registry lists, and a crash badge the sender's
    ///   own registry lists on a thread recorded [`Origin::Own`], so the
    ///   origin carries through a thread's earlier registration;
    /// * [`Origin::Owner`] for another live process's badge, which procmgr
    ///   leaves on the thread, and which no restore binds under;
    /// * [`Origin::Unknown`] otherwise: a crash badge another live registry
    ///   lists, or the sender's lists on a thread not recorded as its own,
    ///   another handler's badge, or no binding.
    #[must_use]
    pub fn origin_of(&self, sender: u64, current: Option<u64>) -> Origin
    {
        let Some(bound) = current
        else
        {
            return Origin::Unknown;
        };
        if bound == sender || threads::is_debugger_badge(bound)
        {
            return Origin::Own;
        }
        if threads::is_crash_badge(bound)
        {
            let Some(entry) = self
                .index_of_crash_badge(bound)
                .and_then(|idx| self.entries.get(idx))
            else
            {
                return Origin::Own;
            };
            let listed_as_own = entry
                .threads
                .position_of_crash_badge(bound)
                .and_then(|i| entry.threads.get(i))
                .is_some_and(|t| t.origin() == Origin::Own);
            return if entry.badge == sender && listed_as_own
            {
                Origin::Own
            }
            else
            {
                Origin::Unknown
            };
        }
        match self.find_by_badge(bound)
        {
            Some(entry) => Origin::Owner(entry.badge),
            None => Origin::Unknown,
        }
    }

    /// What a restore of the crash bindings of the process `badge` does to
    /// `thread`, one of its registered threads, whose exception class is
    /// bound under `current` (`None`: unbound). By the thread's origin
    /// ([`Self::origin_of`]):
    ///
    /// * [`Origin::Own`]: bound back under its crash badge, a fresh one when
    ///   it has none, when [`ProcessEntry::restores`] says so, as the main
    ///   thread is;
    /// * any other, [`Origin::Owner`] included: never bound to the crash
    ///   endpoint. The badge an `Owner` record carries is a value any process
    ///   can bind a thread of its own under, so procmgr binds nothing under
    ///   it.
    ///
    /// A debugger's binding never stays: one the rules above do not bind over
    /// is unbound. No other binding changes. So a restore binds a thread to
    /// the crash endpoint only when the thread is recorded as the sender's
    /// own, and only under a crash badge of the sender's. A badge that names
    /// no live process leaves every thread.
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
        let from_debugger = current.is_some_and(threads::is_debugger_badge);
        match thread.origin()
        {
            Origin::Own if entry.restores(current, thread.crash_badge) =>
            {
                RestoreAction::Bind(thread.crash_badge)
            }
            Origin::Own | Origin::Owner(_) | Origin::Unknown if from_debugger =>
            {
                RestoreAction::Unbind
            }
            Origin::Own | Origin::Owner(_) | Origin::Unknown => RestoreAction::Leave,
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

    /// Whether a live entry, a held reclaim, or a create in progress
    /// ([`Self::reserve_badge`]) holds `badge`. Badge minting redraws such a
    /// candidate, so [`Self::insert`] does not refuse it later, no two
    /// concurrent creates mint one badge, and no new child's process handle
    /// can release another's held reclaim.
    #[must_use]
    pub fn badge_in_use(&self, badge: u64) -> bool
    {
        self.index_of_badge(badge).is_some()
            || self.holds.holds(badge)
            || self.pending.iter().any(|p| p.badge == badge)
    }

    /// Whether `badge` may create: the un-badged creator (`0`), or a live
    /// entry no destroy has begun on.
    fn creates(&self, badge: u64) -> bool
    {
        badge == 0 || self.find_by_badge(badge).is_some_and(|e| !e.doomed)
    }

    /// Reserve `badge` for a create in progress from `creator` (the badge
    /// the request came on, `0` for the un-badged creator), which builds the
    /// child under it with no table lock held and inserts its entry later
    /// ([`Self::insert`] ends the reservation), or ends the reservation on
    /// failure ([`Self::release_badge`]). The reservation keeps the child's
    /// parent current until the insert, as an entry's is
    /// ([`Self::take_ended`]), and a destroy of a subtree that holds it
    /// dooms the create ([`Self::doom_subtree`]).
    ///
    /// # Errors
    /// [`InsertError::BadgeInUse`] when [`Self::badge_in_use`] holds for
    /// `badge`; [`InsertError::CreatorEnded`] when `creator` names no live
    /// entry, or one a destroy has begun on; [`InsertError::OutOfMemory`]
    /// when the heap cannot hold the reservation.
    pub fn reserve_badge(&mut self, badge: u64, creator: u64) -> Result<(), InsertError>
    {
        if self.badge_in_use(badge)
        {
            return Err(InsertError::BadgeInUse);
        }
        if !self.creates(creator)
        {
            return Err(InsertError::CreatorEnded);
        }
        self.pending
            .try_reserve(1)
            .map_err(|_| InsertError::OutOfMemory)?;
        self.pending.push(Pending {
            badge,
            creator,
            doomed: false,
        });
        Ok(())
    }

    /// End the reservation of `badge` a failed create made; a badge not
    /// reserved changes nothing.
    pub fn release_badge(&mut self, badge: u64)
    {
        self.pending.retain(|p| p.badge != badge);
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
        let entry = self
            .index_of_badge(badge)
            .and_then(|idx| self.entries.get_mut(idx))
            .ok_or(ArmError::NotFound)?;
        if entry.dma_hold
        {
            return Ok(());
        }
        self.holds.arm().map_err(|_| ArmError::OutOfMemory)?;
        entry.dma_hold = true;
        Ok(())
    }

    /// The held reclaims, for the teardown that parks an entry's
    /// ([`DmaHolds::park`]) and the `RELEASE_HOLD` that takes it.
    pub fn holds_mut(&mut self) -> &mut DmaHolds
    {
        &mut self.holds
    }

    /// Insert `entry`, ending the reservation of its badge
    /// ([`Self::reserve_badge`]), and changing nothing on refusal. A reserved
    /// badge's entry takes the reservation's creator as its parent; an entry
    /// inserted without one keeps the parent it carries.
    ///
    /// # Errors
    /// [`InsertError::BadgeInUse`] when a live entry already holds the badge;
    /// [`InsertError::CreatorEnded`] when a destroy doomed the reservation, or
    /// the parent names no live entry or one a destroy has begun on;
    /// [`InsertError::OutOfMemory`] when the heap cannot grow the table.
    pub fn insert(&mut self, mut entry: ProcessEntry) -> Result<(), InsertError>
    {
        let Err(idx) = self.search(entry.badge)
        else
        {
            return Err(InsertError::BadgeInUse);
        };
        if let Some(pending) = self.pending.iter().find(|p| p.badge == entry.badge)
        {
            if pending.doomed
            {
                return Err(InsertError::CreatorEnded);
            }
            entry.parent = pending.creator;
        }
        if !self.creates(entry.parent)
        {
            return Err(InsertError::CreatorEnded);
        }
        self.entries
            .try_reserve(1)
            .map_err(|_| InsertError::OutOfMemory)?;
        self.release_badge(entry.badge);
        self.entries.insert(idx, entry);
        Ok(())
    }

    /// Locate the live entry whose badge matches, for in-place mutation.
    #[must_use]
    pub fn find_mut_by_badge(&mut self, badge: u64) -> Option<&mut ProcessEntry>
    {
        let idx = self.index_of_badge(badge)?;
        self.entries.get_mut(idx)
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

    /// Mark the live entry whose badge matches as on the core path, the
    /// processes a core dump waits on (`DECLARE_NO_CORE`, sent on the
    /// child's own procmgr cap). Returns `false` when the badge names no live entry.
    #[must_use]
    pub fn declare_no_core(&mut self, badge: u64) -> bool
    {
        self.find_mut_by_badge(badge)
            .map(|entry| entry.no_core = true)
            .is_some()
    }

    /// The live entry whose badge matches.
    #[must_use]
    pub fn find_by_badge(&self, badge: u64) -> Option<&ProcessEntry>
    {
        let idx = self.index_of_badge(badge)?;
        self.entries.get(idx)
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

    /// Mark the live entry `badge` and every entry below it doomed, and
    /// every create in progress from one of them, at the start of a destroy of
    /// that subtree: from then on procmgr refuses a create from any of them
    /// and an insert of such a create's child, so no process escapes the
    /// destroy by starting a child during the teardown. Returns `false` when
    /// no live entry holds `badge`. The entries stay in the table until
    /// their teardown takes each ([`Self::take_doomed`]), or, for an entry
    /// whose create is unanswered, until that create's refusal takes it
    /// ([`Self::answer_create`], [`Self::take_refused`]).
    pub fn doom_subtree(&mut self, badge: u64) -> bool
    {
        let Some(root) = self.find_mut_by_badge(badge)
        else
        {
            return false;
        };
        root.doomed = true;
        self.doom_descendants();
        true
    }

    /// Mark doomed every entry below a doomed one, and every create in
    /// progress from a doomed one. Each pass marks the entries whose parent
    /// is doomed, so the passes end within the depth of the deepest subtree.
    fn doom_descendants(&mut self)
    {
        loop
        {
            let mut marked = false;
            for idx in 0..self.entries.len()
            {
                let Some(entry) = self.entries.get(idx)
                else
                {
                    break;
                };
                if entry.doomed || entry.parent == 0
                {
                    continue;
                }
                let parent_doomed = self.find_by_badge(entry.parent).is_some_and(|p| p.doomed);
                if let Some(entry) = self.entries.get_mut(idx).filter(|_| parent_doomed)
                {
                    entry.doomed = true;
                    marked = true;
                }
            }
            if !marked
            {
                break;
            }
        }
        for idx in 0..self.pending.len()
        {
            let Some(creator) = self.pending.get(idx).map(|p| p.creator)
            else
            {
                break;
            };
            let creator_doomed = self.find_by_badge(creator).is_some_and(|e| e.doomed);
            if let Some(pending) = self.pending.get_mut(idx)
            {
                pending.doomed |= creator_doomed;
            }
        }
    }

    /// Take the entry `badge` out of the table at its end (an exit, a fault,
    /// or its turn in a destroy), and settle the processes it started: its
    /// children, and the creates it has in progress, take its parent as
    /// theirs, the nearest live ancestor, since a nonzero parent names a live
    /// entry. When the entry was created with `CREATE_CONTAIN`, everything
    /// below it is doomed instead ([`Self::doom_subtree`]), so the caller's
    /// teardowns then take it ([`Self::take_doomed`]). A child that is not
    /// doomed is re-parented: `delete_relay` is called with its death relay's
    /// slot, which no end of the child is then posted to. Returns `None` when
    /// no live entry holds `badge`.
    pub fn take_ended(
        &mut self,
        badge: u64,
        mut delete_relay: impl FnMut(u64),
    ) -> Option<ProcessEntry>
    {
        let idx = self.index_of_badge(badge)?;
        let entry = self.entries.remove(idx);
        let heir = entry.parent;
        let doom =
            entry.contained || entry.doomed || self.find_by_badge(heir).is_some_and(|e| e.doomed);
        for child in self.entries.iter_mut().filter(|e| e.parent == badge)
        {
            child.parent = heir;
            child.doomed |= doom;
            if !child.doomed && child.relay != 0
            {
                delete_relay(core::mem::take(&mut child.relay));
            }
        }
        for pending in self.pending.iter_mut().filter(|p| p.creator == badge)
        {
            pending.creator = heir;
            pending.doomed |= doom;
        }
        if doom
        {
            self.doom_descendants();
        }
        Some(entry)
    }

    /// Answer the create that made the entry `badge`: unless a destroy has
    /// marked the entry, call `reply`, which delivers the child's handle to its
    /// creator and returns whether it did, and on delivery clear
    /// [`ProcessEntry::unanswered`], so a destroy takes the entry from then on.
    /// The reply is made under the caller's hold of the table, so no destroy
    /// marks the entry between the check and the delivery: a destroy that
    /// comes first leaves the create refused, one that comes after finds a
    /// child its creator holds. An unknown badge is refused too.
    pub fn answer_create(&mut self, badge: u64, reply: impl FnOnce() -> bool) -> CreateAnswer
    {
        let Some(entry) = self.find_mut_by_badge(badge).filter(|e| !e.doomed)
        else
        {
            return CreateAnswer::Refused;
        };
        if !reply()
        {
            return CreateAnswer::Undelivered;
        }
        entry.unanswered = false;
        CreateAnswer::Answered
    }

    /// Take the entry `badge` of a child whose create procmgr refuses after it
    /// was inserted (a reply it cannot deliver, a hold it cannot arm), as
    /// [`Self::take_ended`] takes an ended one, and call `delete_relay` with
    /// the entry's own death relay too, which is then zero: the creator was
    /// told the create failed, so no end of the child is posted to it.
    /// Returns `None` when no live entry holds `badge`.
    pub fn take_refused(
        &mut self,
        badge: u64,
        mut delete_relay: impl FnMut(u64),
    ) -> Option<ProcessEntry>
    {
        let mut entry = self.take_ended(badge, &mut delete_relay)?;
        if entry.relay != 0
        {
            delete_relay(core::mem::take(&mut entry.relay));
        }
        Some(entry)
    }

    /// Take a doomed entry out of the table ([`Self::take_ended`]), the
    /// lowest-badged; `None` when none is doomed. A destroy takes the doomed
    /// entries one by one, each teardown in its own hold of the table lock.
    /// An entry whose create is unanswered ([`ProcessEntry::unanswered`]) is
    /// left to that create, which refuses itself once it finds the entry
    /// doomed ([`Self::answer_create`]).
    pub fn take_doomed(&mut self, delete_relay: impl FnMut(u64)) -> Option<ProcessEntry>
    {
        let badge = self
            .entries
            .iter()
            .find(|e| e.doomed && !e.unanswered)?
            .badge;
        self.take_ended(badge, delete_relay)
    }

    /// The children of `parent` above `after` (every child when `after` is
    /// `None`), in badge order, without the doomed: the walk `LIST_CHILDREN`
    /// pages through.
    pub fn children_after(
        &self,
        parent: u64,
        after: Option<u64>,
    ) -> impl Iterator<Item = &ProcessEntry>
    {
        self.entries_after(after)
            .filter(move |e| e.parent == parent && !e.doomed)
    }

    /// Whether the live entry `child` is a child of `parent` that no destroy
    /// has marked, as [`Self::children_after`] lists the children.
    #[must_use]
    pub fn is_child(&self, parent: u64, child: u64) -> bool
    {
        parent != 0
            && self
                .find_by_badge(child)
                .is_some_and(|e| e.parent == parent && !e.doomed)
    }

    /// Record `queue` (a slot in procmgr's `CSpace`) as the end queue of the
    /// live entry `badge`, posted `correlator` with its end
    /// (`REGISTER_END_QUEUE`, sent on the process's own procmgr cap).
    ///
    /// # Errors
    /// [`EndQueueRefusal::NotFound`] when no live entry holds `badge`;
    /// [`EndQueueRefusal::Present`] when the entry registered one before, so
    /// a process cannot replace the queue another holder watches its end
    /// through.
    pub fn register_end_queue(
        &mut self,
        badge: u64,
        queue: u64,
        correlator: u64,
    ) -> Result<(), EndQueueRefusal>
    {
        let entry = self
            .find_mut_by_badge(badge)
            .ok_or(EndQueueRefusal::NotFound)?;
        if entry.end_queue != 0
        {
            return Err(EndQueueRefusal::Present);
        }
        entry.end_queue = queue;
        entry.end_correlator = correlator;
        Ok(())
    }

    /// Visit every live entry in badge order.
    pub fn for_each<F: FnMut(&ProcessEntry)>(&self, f: F)
    {
        self.entries.iter().for_each(f);
    }

    /// The death resync's scan (`resync_deaths` in procmgr's `main.rs`):
    /// push onto `dead` the badge and exit reason of every live entry the
    /// kernel shows dead, in badge order. `read` gives an entry's kernel
    /// records, its main thread's `CAP_INFO_THREAD_STATE` and its address
    /// space's `CAP_INFO_ASPACE_TERMINAL_FAULT` (`None` for a read that
    /// failed), which [`resync_exit_reason`] reads against `exited`, the
    /// state value meaning the thread exited. Returns `false` when `dead`
    /// could not grow to hold every such entry; those left out stay live for
    /// a later resync.
    pub fn resync_dead<R>(&self, exited: u32, mut read: R, dead: &mut Vec<(u64, u64)>) -> bool
    where
        R: FnMut(&ProcessEntry) -> (Option<u64>, Option<u64>),
    {
        let mut listed_all = true;
        for entry in &self.entries
        {
            let (main_thread, terminal_fault) = read(entry);
            let Some(exit_reason) = resync_exit_reason(main_thread, exited, terminal_fault)
            else
            {
                continue;
            };
            if dead.try_reserve(1).is_ok()
            {
                dead.push((entry.badge, exit_reason));
            }
            else
            {
                listed_all = false;
            }
        }
        listed_all
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
        let mut copied = 0usize;
        for (slot, entry) in out.iter_mut().zip(self.entries_after(after))
        {
            *slot = entry.badge;
            // `copied` counts the slots of `out`, so it cannot overflow.
            copied = copied.saturating_add(1);
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
                // `i` indexes an entry, so `i + 1` is at most the length.
                Ok(i) => i.saturating_add(1),
                Err(i) => i,
            },
        };
        self.entries.get(start..).unwrap_or_default().iter()
    }

    /// Lightweight status lookup for `QUERY_PROCESS`: the entry's
    /// [`QueryEntry`] when one is present; `None` if the badge is unknown
    /// (already reaped or never existed).
    #[must_use]
    pub fn query_by_badge(&self, badge: u64) -> Option<QueryEntry>
    {
        self.find_by_badge(badge).map(|e| QueryEntry {
            started: e.started,
            thread_cap: e.thread_cap,
            aspace_cap: e.aspace_cap,
        })
    }

    /// The creator a create request badged `badge` comes from: the
    /// un-badged creator ([`Creator::UNBADGED`]) for badge `0`, else the live
    /// entry whose badge matches. `None` for any other badge: a process
    /// already reaped (its own procmgr cap or its process handle, which a
    /// holder can still send on), a verb-badged cap, or a release token.
    /// procmgr refuses a create from such a badge: its child would have no
    /// creator's node to sit under, and so would escape every memory max.
    /// `None` too for a live entry a destroy has begun on
    /// ([`Self::doom_subtree`]), whose child would escape the destroy.
    #[must_use]
    pub fn creator_of(&self, badge: u64) -> Option<Creator>
    {
        if badge == 0
        {
            return Some(Creator::UNBADGED);
        }
        self.find_by_badge(badge)
            .filter(|e| !e.doomed)
            .map(|e| Creator {
                band_max: e.band_max,
                memmgr_badge: e.memmgr_badge,
                reserve: e.reserve,
                unbadged: false,
                sign_roles: e.sign_roles,
            })
    }
}

// ── Spawn budget and physical-address class ─────────────────────────────────

/// What a create request's child takes from its creator
/// ([`ProcessTable::creator_of`]): its spawn ceiling, its memmgr budget
/// node's parent, whether it may be phys-class or a reserve node, and the
/// roles of object its creates may load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Creator
{
    /// The creator's band ceiling, which bounds the child's band
    /// ([`resolve_spawn_sched`]).
    pub band_max: u8,
    /// The creator's memmgr badge, under whose budget node the child's node
    /// is registered; `0` registers a top-level node.
    pub memmgr_badge: u64,
    /// Whether the creator's budget node is a system-reserve node.
    pub reserve: bool,
    /// Whether the creator is un-badged (badge `0`): init, or svcmgr's mint
    /// source.
    pub unbadged: bool,
    /// The creator's signature policy: the roles of object its creates may
    /// load ([`sign_policy`]).
    pub sign_roles: objsig::RoleSet,
}

impl Creator
{
    /// The un-badged creator (badge `0`): init, which creates devmgr, vfsd
    /// and svcmgr, or a create svcmgr sends on its un-badged mint source.
    /// Its ceiling is the full baseline band, its children not charged to a
    /// node handle are top-level reserve nodes (init's own record parents no
    /// process), a charged child sits under the handle's node outside the
    /// reserve, it may ask for a phys-class child, and its creates may load
    /// every role a process runs in ([`sign_policy::LOADABLE`]).
    pub const UNBADGED: Creator = Creator {
        band_max: ipc::sched_policy::BASELINE_PRIORITY_MAX,
        memmgr_badge: 0,
        reserve: true,
        unbadged: true,
        sign_roles: sign_policy::LOADABLE,
    };

    /// Whether the creator may ask for a phys-class child: an un-badged one,
    /// or one memmgr registered phys-class, whose memmgr badge carries
    /// `memmgr_labels::PHYS_CLASS_BADGE_BIT`.
    #[must_use]
    pub fn phys_class(&self) -> bool
    {
        self.unbadged || self.memmgr_badge & ipc::memmgr_labels::PHYS_CLASS_BADGE_BIT != 0
    }
}

/// How a child registers with memmgr (`memmgr_labels::REGISTER_PROCESS`):
/// its class, its budget node's parent, reserve membership, and max.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildBudget
{
    /// A phys-class child (`REGISTER_PHYS_CLASS`).
    pub phys: bool,
    /// A system-reserve node (`REGISTER_RESERVE`).
    pub reserve: bool,
    /// The memmgr badge of the parent node's process (`data[2]`); `0` for a
    /// top-level node.
    pub parent: u64,
    /// The max in pages the creator asked for (`REGISTER_MAX`, `data[3]`);
    /// `None` for no max.
    pub max: Option<u64>,
    /// The creator asked for the child's node handle
    /// (`procmgr_labels::CREATE_NODE_HANDLE`, `REGISTER_NODE_HANDLE`).
    pub node_handle: bool,
    /// Slot in procmgr's `CSpace` of the node handle a
    /// `procmgr_labels::CREATE_CHARGE_NODE` request carries, under whose node
    /// the child's node goes in place of [`ChildBudget::parent`]'s
    /// (`REGISTER_CHARGE_NODE`); `0` for none. [`child_budget`] leaves it
    /// `0`, and the create handler sets it from the request's caps.
    pub charge: u64,
}

impl ChildBudget
{
    /// The `REGISTER_PROCESS` flags word (`data[1]`).
    #[must_use]
    pub fn register_flags(&self) -> u64
    {
        use ipc::memmgr_labels::{
            REGISTER_CHARGE_NODE, REGISTER_MAX, REGISTER_NODE_HANDLE, REGISTER_PHYS_CLASS,
            REGISTER_RESERVE,
        };
        let mut flags = 0;
        if self.phys
        {
            flags |= REGISTER_PHYS_CLASS;
        }
        if self.reserve
        {
            flags |= REGISTER_RESERVE;
        }
        if self.max.is_some()
        {
            flags |= REGISTER_MAX;
        }
        if self.node_handle
        {
            flags |= REGISTER_NODE_HANDLE;
        }
        if self.charge != 0
        {
            flags |= REGISTER_CHARGE_NODE;
        }
        flags
    }
}

/// Why [`child_budget`] or [`decode_memory_max`] refused a create request,
/// which procmgr answers with `INVALID_ARGUMENT`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetRefusal
{
    /// `CREATE_PHYS_ACCESS` from a creator that is not phys-class.
    PhysAccess,
    /// `CREATE_RESERVE` from a creator whose node is outside the reserve, or
    /// with `CREATE_CHARGE_NODE`.
    Reserve,
    /// `CREATE_MEMORY_MAX` without its data word delivered.
    MissingMax,
}

/// The memmgr registration of the child a create request labelled `label`
/// makes for `creator`, with the max `max` the request carries
/// ([`decode_memory_max`]).
///
/// The child's node sits under the creator's (top-level for the un-badged
/// creator). `procmgr_labels::CREATE_PHYS_ACCESS` asks for a phys-class
/// child, honoured only from a phys-class creator ([`Creator::phys_class`]).
/// `procmgr_labels::CREATE_RESERVE` asks for a reserve node, honoured only
/// from a creator whose own node is a reserve node and never with
/// `procmgr_labels::CREATE_CHARGE_NODE`, whose node may be a sub-node, which
/// is never in the reserve; a child of the un-badged creator not charged to a
/// node handle is a reserve node with or without it.
///
/// # Errors
/// [`BudgetRefusal::PhysAccess`] or [`BudgetRefusal::Reserve`] when the
/// creator may not ask for what the label asks.
pub fn child_budget(
    label: u64,
    max: Option<u64>,
    creator: &Creator,
) -> Result<ChildBudget, BudgetRefusal>
{
    use ipc::procmgr_labels::{
        CREATE_CHARGE_NODE, CREATE_NODE_HANDLE, CREATE_PHYS_ACCESS, CREATE_RESERVE,
    };
    let phys = label & CREATE_PHYS_ACCESS != 0;
    if phys && !creator.phys_class()
    {
        return Err(BudgetRefusal::PhysAccess);
    }
    let asks_reserve = label & CREATE_RESERVE != 0;
    let charged = label & CREATE_CHARGE_NODE != 0;
    if asks_reserve && (!creator.reserve || charged)
    {
        return Err(BudgetRefusal::Reserve);
    }
    Ok(ChildBudget {
        phys,
        reserve: asks_reserve || (creator.unbadged && !charged),
        parent: creator.memmgr_badge,
        max,
        node_handle: label & CREATE_NODE_HANDLE != 0,
        charge: 0,
    })
}

/// The memory max a create request labelled `label` carries, whose data
/// words after the fixed ones start at `first_word` (1 for both
/// `CREATE_PROCESS` and `CREATE_FROM_FILE`, after the object's length): `None` without `procmgr_labels::CREATE_MEMORY_MAX`,
/// else the word after the argv/env header when `CREATE_ARGV_ENV` is set, or
/// at `first_word` without it.
///
/// # Errors
/// [`BudgetRefusal::MissingMax`] when the request did not deliver that word,
/// so no max is read from the zero tail past the delivered words.
pub fn decode_memory_max(
    req: &ipc::IpcMessage,
    first_word: usize,
) -> Result<Option<u64>, BudgetRefusal>
{
    use ipc::procmgr_labels::{ARGV_ENV_HEADER_WORDS, CREATE_ARGV_ENV, CREATE_MEMORY_MAX};
    if req.label & CREATE_MEMORY_MAX == 0
    {
        return Ok(None);
    }
    let word = if req.label & CREATE_ARGV_ENV == 0
    {
        first_word
    }
    else
    {
        first_word.saturating_add(ARGV_ENV_HEADER_WORDS)
    };
    if word >= req.word_count()
    {
        return Err(BudgetRefusal::MissingMax);
    }
    Ok(Some(req.word(word)))
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
    /// (`procmgr_labels::DECLARE_NO_DEBUG`; `NOT_ATTACHABLE`): the debug
    /// port's driver and every debug-authority holder, the caller among them.
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
/// handle: every label but `DECLARE_NO_DEBUG`, `DECLARE_NO_CORE`,
/// `REGISTER_THREAD` and `REGISTER_END_QUEUE`, which name their sender
/// itself and are served on the child's own procmgr cap alone.
#[must_use]
pub fn served_on_handle(opcode: u64) -> bool
{
    !matches!(
        opcode,
        ipc::procmgr_labels::DECLARE_NO_DEBUG
            | ipc::procmgr_labels::DECLARE_NO_CORE
            | ipc::procmgr_labels::REGISTER_THREAD
            | ipc::procmgr_labels::REGISTER_END_QUEUE
    )
}

/// Whether procmgr serves `opcode` on a process handle alone:
/// `BIND_DEATH_OBSERVER`, through which only the child's creator chooses who
/// observes the child's address space, and `LIST_CHILDREN` and
/// `DESTROY_CHILD`, whose authority is the handle's over the process and
/// everything below it.
#[must_use]
pub fn served_on_handle_only(opcode: u64) -> bool
{
    matches!(
        opcode,
        ipc::procmgr_labels::BIND_DEATH_OBSERVER
            | ipc::procmgr_labels::LIST_CHILDREN
            | ipc::procmgr_labels::DESTROY_CHILD
    )
}

/// The error procmgr refuses `opcode` with for the kind of cap it came on,
/// read from the request's `badge` as received ([`request_badge`]: a
/// process handle's carries `PROCESS_HANDLE_TAG`), before it serves it:
/// `INVALID_BADGE` for a label not served on a handle
/// ([`served_on_handle`]), and `UNAUTHORIZED` for a label served on a
/// handle alone ([`served_on_handle_only`]) sent on any other cap; `None`
/// when it serves it.
#[must_use]
pub fn sender_refusal(opcode: u64, badge: u64) -> Option<u64>
{
    let (_, on_handle) = request_badge(badge);
    if on_handle && !served_on_handle(opcode)
    {
        Some(ipc::procmgr_errors::INVALID_BADGE)
    }
    else if !on_handle && served_on_handle_only(opcode)
    {
        Some(ipc::procmgr_errors::UNAUTHORIZED)
    }
    else
    {
        None
    }
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
                .map_or(ipc::procmgr_labels::ATTACH_NO_THREAD, |i| {
                    (i as u64).saturating_add(1)
                }),
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
    let entry = table.entries.get_mut(idx).ok_or(AttachRefusal::Unknown)?;
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
    let entry = table
        .find_mut_by_badge(target)
        .ok_or(AttachRefusal::Unknown)?;
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

// ── Process query ───────────────────────────────────────────────────────────

/// What `QUERY_PROCESS` reads of a live entry ([`ProcessTable::query_by_badge`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryEntry
{
    /// Whether the process was started.
    pub started: bool,
    /// procmgr's slot for the child's main thread, for the kernel's
    /// `CAP_INFO_THREAD_STATE`.
    pub thread_cap: u64,
    /// procmgr's slot for the child's address space, for the kernel's
    /// `CAP_INFO_ASPACE_TERMINAL_FAULT`.
    pub aspace_cap: u64,
}

/// A live entry's state as `QUERY_PROCESS` answers it ([`QueryEntry::state`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryState
{
    /// Dead before procmgr reaped it, with this exit reason.
    Exited(u64),
    /// Started and not dead.
    Alive,
    /// Not yet started.
    Created,
}

impl QueryEntry
{
    /// The entry's state from the kernel's records, read as
    /// [`resync_exit_reason`] reads them (`main_thread`, `exited`,
    /// `terminal_fault`): a process whose main thread exited, or one of
    /// whose threads took a terminal fault, is exited though procmgr has not
    /// reaped it yet, so a caller whose wait returned on its death never sees
    /// it alive.
    #[must_use]
    pub fn state(
        &self,
        main_thread: Option<u64>,
        exited: u32,
        terminal_fault: Option<u64>,
    ) -> QueryState
    {
        if let Some(reason) = resync_exit_reason(main_thread, exited, terminal_fault)
        {
            QueryState::Exited(reason)
        }
        else if self.started
        {
            QueryState::Alive
        }
        else
        {
            QueryState::Created
        }
    }
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
            reserve: false,
            entry_point: 0,
            tls_base_va: 0,
            stack_top_vaddr: 0,
            process_info_va: 0,
            started: false,
            dma_hold: false,
            no_debug: false,
            no_core: false,
            image: ImageSpan::default(),
            threads: ThreadRegistry::new(),
            name: ProcessName::EMPTY,
            sign_roles: objsig::RoleSet::EMPTY,
            debugger: 0,
            parent: 0,
            contained: false,
            doomed: false,
            relay: 0,
            unanswered: false,
            end_queue: 0,
            end_correlator: 0,
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
        // The debug port's driver and every debug-authority holder, the
        // caller among them, declare themselves undebuggable.
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
    fn a_no_core_declaration_marks_its_sender_alone_and_leaves_it_attachable()
    {
        use ipc::procmgr_labels::{ATTACH_FLAG_NO_CORE, DEBUG_AUTHORITY};
        let mut table = ProcessTable::new();
        table.insert(entry_with_badge(0x77)).unwrap();
        table.insert(entry_with_badge(0x78)).unwrap();
        assert!(!table.declare_no_core(0x79));
        assert!(table.declare_no_core(0x77));
        // A repeat is answered as the first.
        assert!(table.declare_no_core(0x77));
        let (entry, _) = attach_target(&mut table, DEBUG_AUTHORITY, 0x77).unwrap();
        assert_eq!(entry.attach_flags(), ATTACH_FLAG_NO_CORE);
        let (entry, _) = attach_target(&mut table, DEBUG_AUTHORITY, 0x78).unwrap();
        assert_eq!(entry.attach_flags(), 0);
    }

    #[test]
    fn the_attach_flags_report_a_reserve_node_beside_the_no_core_declaration()
    {
        use ipc::procmgr_labels::{ATTACH_FLAG_NO_CORE, ATTACH_FLAG_RESERVE, DEBUG_AUTHORITY};
        let mut table = ProcessTable::new();
        table
            .insert(ProcessEntry {
                reserve: true,
                ..entry_with_badge(0x77)
            })
            .unwrap();
        table.insert(entry_with_badge(0x78)).unwrap();
        let (entry, _) = attach_target(&mut table, DEBUG_AUTHORITY, 0x77).unwrap();
        assert_eq!(entry.attach_flags(), ATTACH_FLAG_RESERVE);
        assert!(table.declare_no_core(0x77));
        let (entry, _) = attach_target(&mut table, DEBUG_AUTHORITY, 0x77).unwrap();
        assert_eq!(
            entry.attach_flags(),
            ATTACH_FLAG_NO_CORE | ATTACH_FLAG_RESERVE
        );
        let (entry, _) = attach_target(&mut table, DEBUG_AUTHORITY, 0x78).unwrap();
        assert_eq!(entry.attach_flags(), 0);
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
    fn an_attach_holds_its_watch_while_its_reply_is_sent()
    {
        // A debugger that dies as soon as it has its reply is found gone only
        // if its watch is held by then; the watch it replaced goes.
        let mut entry = entry_with_badge(0x77);
        entry.debugger = 93;
        let outcome = entry.watch_across_reply(94, |e| e.debugger == 94);
        assert_eq!(
            outcome,
            WatchedReply {
                delivered: true,
                stale: 93
            },
            "the watch was not held when the reply was sent"
        );
        assert_eq!(entry.debugger, 94);
    }

    #[test]
    fn an_attach_whose_reply_fails_keeps_the_earlier_watch()
    {
        let mut entry = entry_with_badge(0x77);
        entry.debugger = 93;
        let outcome = entry.watch_across_reply(94, |_| false);
        assert_eq!(
            outcome,
            WatchedReply {
                delivered: false,
                stale: 94
            }
        );
        assert_eq!(entry.debugger, 93);
    }

    #[test]
    fn an_attach_without_a_watch_leaves_the_held_one()
    {
        let mut entry = entry_with_badge(0x77);
        entry.debugger = 93;
        for delivered in [true, false]
        {
            let outcome = entry.watch_across_reply(0, |e| e.debugger == 93 && delivered);
            assert_eq!(
                outcome,
                WatchedReply {
                    delivered,
                    stale: 0
                }
            );
            assert_eq!(entry.debugger, 93);
        }
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
            DECLARE_NO_CORE, DECLARE_NO_DEBUG, DESTROY_PROCESS, PROCESS_HANDLE_TAG, QUERY_PROCESS,
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
        for opcode in [DECLARE_NO_DEBUG, DECLARE_NO_CORE, REGISTER_THREAD]
        {
            assert!(!served_on_handle(opcode));
        }
        for opcode in [START_PROCESS, DESTROY_PROCESS, QUERY_PROCESS]
        {
            assert!(served_on_handle(opcode));
        }
    }

    #[test]
    fn sender_refusal_matches_each_label_to_its_cap()
    {
        use ipc::procmgr_errors::{INVALID_BADGE, UNAUTHORIZED};
        use ipc::procmgr_labels::{
            BIND_DEATH_OBSERVER, DECLARE_NO_CORE, DECLARE_NO_DEBUG, PROCESS_HANDLE_TAG,
            QUERY_PROCESS, REGISTER_THREAD,
        };
        let (own, handle) = (0x50, 0x50 | PROCESS_HANDLE_TAG);
        // Labels naming their sender are refused on a handle.
        for opcode in [DECLARE_NO_DEBUG, DECLARE_NO_CORE, REGISTER_THREAD]
        {
            assert_eq!(sender_refusal(opcode, handle), Some(INVALID_BADGE));
            assert_eq!(sender_refusal(opcode, own), None);
        }
        // The observer bind is the creator's: refused on any other cap.
        assert_eq!(sender_refusal(BIND_DEATH_OBSERVER, handle), None);
        assert_eq!(sender_refusal(BIND_DEATH_OBSERVER, own), Some(UNAUTHORIZED));
        // Every other label is served on both.
        assert_eq!(sender_refusal(QUERY_PROCESS, handle), None);
        assert_eq!(sender_refusal(QUERY_PROCESS, own), None);
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
    fn a_registration_records_whose_thread_its_binding_shows()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let (mut table, [own, other, orphan]) = two_processes();
        // A thread of the sender's registry recorded as not its own, under a
        // crash badge procmgr gave it.
        let taken = table.mint_crash_badge();
        let sender = table.find_mut_by_badge(0x40).unwrap();
        sender.threads.reserve().unwrap();
        sender
            .threads
            .push(RegisteredThread::new(8, taken, Origin::Unknown));
        for own_binding in [0x40, debugger, orphan, own]
        {
            assert_eq!(table.origin_of(0x40, Some(own_binding)), Origin::Own);
        }
        assert_eq!(table.origin_of(0x40, Some(0x50)), Origin::Owner(0x50));
        for unknown_binding in [None, Some(other), Some(taken), Some(0x99)]
        {
            assert_eq!(table.origin_of(0x40, unknown_binding), Origin::Unknown);
        }
    }

    /// Register a thread bound under `bound` from `sender`, rebound under a
    /// fresh crash badge when `rebound`, as `register_thread` does; returns
    /// the record and the binding the thread is left with.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`rebound` is the outcome of the rebind the helper records"
    )]
    fn register(
        table: &mut ProcessTable,
        sender: u64,
        bound: u64,
        rebound: bool,
    ) -> (RegisteredThread, u64)
    {
        let origin = table.origin_of(sender, Some(bound));
        let crash = if rebound { table.mint_crash_badge() } else { 0 };
        let record = RegisteredThread::new(9, crash, origin);
        let entry = table.find_mut_by_badge(sender).unwrap();
        entry.threads.reserve().unwrap();
        entry.threads.push(record);
        (record, if rebound { crash } else { bound })
    }

    /// A thread of a declared process taken through a chain of registries.
    /// The process 0x60's main thread carries a debugger's binding; 0x50
    /// registers it, which procmgr takes as 0x50's own and rebinds; then the
    /// sender 0x40 registers it, once with the rebind failed, and again from
    /// its own crash badge, and 0x60 declares. Every record of the sender's
    /// is unknown, so no restore of the sender's binds that thread to the
    /// crash endpoint.
    #[test]
    fn an_origin_carries_through_a_chain_of_registrations()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let (mut table, _) = two_processes();
        table.insert(entry_with_badge(0x60)).unwrap();
        let (by_other, cx) = register(&mut table, 0x50, debugger, true);
        assert_eq!(by_other.origin(), Origin::Own);
        let (first, cs) = register(&mut table, 0x40, cx, true);
        let (failed, _) = register(&mut table, 0x40, cx, false);
        let (second, _) = register(&mut table, 0x40, cs, true);
        for record in [first, failed, second]
        {
            assert_eq!(record.origin(), Origin::Unknown);
        }
        assert!(table.declare_no_debug(0x60).is_some());
        for record in [first, failed, second]
        {
            for current in [None, Some(debugger), Some(cx), Some(cs), Some(0x60)]
            {
                assert!(
                    !matches!(
                        table.restore_action(0x40, &record, current),
                        RestoreAction::Bind(_)
                    ),
                    "{record:?} {current:?}"
                );
            }
        }
        // The sender's own threads keep their origin through the same chain:
        // a thread that copied a binding procmgr gave the sender's own.
        let (own_thread, own_crash) = register(&mut table, 0x40, 0x40, true);
        let (spawned, _) = register(&mut table, 0x40, own_crash, true);
        assert_eq!(own_thread.origin(), Origin::Own);
        assert_eq!(spawned.origin(), Origin::Own);
    }

    #[test]
    fn a_restore_never_binds_a_thread_under_the_badge_its_registration_showed()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let (mut table, _) = two_processes();
        // The creator 0x40 registered its child 0x50's main thread, left
        // under the child's badge. The sender 0x40 could as well have bound a
        // thread of its own under the badge value 0x50 on an endpoint of its
        // own: procmgr reads the badge alone, so the two registrations make
        // one record.
        let left = RegisteredThread::new(9, 0, table.origin_of(0x40, Some(0x50)));
        assert_eq!(left.origin(), Origin::Owner(0x50));
        // A debugger's binding on it is taken off, never replaced by a
        // binding under 0x50, whatever state 0x50 is in; any other binding
        // stays.
        let check = |table: &ProcessTable| {
            assert_eq!(
                table.restore_action(0x40, &left, Some(debugger)),
                RestoreAction::Unbind
            );
            for current in [None, Some(0x50), Some(0x40), Some(0x99)]
            {
                assert_eq!(
                    table.restore_action(0x40, &left, current),
                    RestoreAction::Leave,
                    "{current:?}"
                );
            }
        };
        check(&table);
        assert!(table.declare_no_debug(0x50).is_some());
        check(&table);
        let _ = table.take_by_badge(0x50);
        check(&table);
    }

    #[test]
    fn a_restore_binds_the_senders_own_threads_back_and_never_an_unknown_one()
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
        // A thread whose binding showed no owner is never bound to the crash
        // endpoint, whatever crash badge procmgr gave it; a debugger's
        // binding on it is taken off.
        for crash in [0, own]
        {
            let unknown = RegisteredThread::new(11, crash, Origin::Unknown);
            assert_eq!(
                table.restore_action(0x40, &unknown, Some(debugger)),
                RestoreAction::Unbind
            );
            for current in [None, Some(own), Some(other), Some(0x50)]
            {
                assert_eq!(
                    table.restore_action(0x40, &unknown, current),
                    RestoreAction::Leave
                );
            }
        }
        // A badge naming no live process changes nothing.
        assert_eq!(
            table.restore_action(0x41, &badged, Some(debugger)),
            RestoreAction::Leave
        );
    }

    /// The restore rule over every origin, with and without a crash badge,
    /// each owner state (live and undeclared, declared, gone), and every
    /// binding a restore can find: the sender's own crash badge, another
    /// live registry's, an orphaned one, each process badge, a gone one, a
    /// debugger's, another handler's, and none. Its invariants: a thread is
    /// bound to the crash endpoint only when recorded as the sender's own, by
    /// the main thread's rule, and only under its own crash badge or a fresh
    /// one; a debugger's binding never stays; and nothing else is touched.
    #[test]
    fn a_restore_binds_back_only_the_senders_own_threads()
    {
        let debugger = ipc::procmgr_labels::DEBUGGER_BADGE_TAG | 3;
        let (mut table, [own, other, orphan]) = two_processes();
        table.insert(entry_with_badge(0x60)).unwrap();
        assert!(table.declare_no_debug(0x60).is_some());
        let gone = 0x70;
        let origins = [
            Origin::Own,
            Origin::Owner(0x50),
            Origin::Owner(0x60),
            Origin::Owner(gone),
            Origin::Unknown,
        ];
        let currents = [
            None,
            Some(debugger),
            Some(own),
            Some(other),
            Some(orphan),
            Some(0x40),
            Some(0x50),
            Some(0x60),
            Some(gone),
            Some(0x99),
        ];
        let sender = table.find_by_badge(0x40).unwrap();
        for origin in origins
        {
            for crash in [0, own]
            {
                for current in currents
                {
                    let thread = RegisteredThread::new(9, crash, origin);
                    let action = table.restore_action(0x40, &thread, current);
                    let from_debugger = current == Some(debugger);
                    let case = (origin, crash, current);
                    let expected = match origin
                    {
                        Origin::Own if sender.restores(current, crash) =>
                        {
                            RestoreAction::Bind(crash)
                        }
                        Origin::Own | Origin::Owner(_) | Origin::Unknown if from_debugger =>
                        {
                            RestoreAction::Unbind
                        }
                        Origin::Own | Origin::Owner(_) | Origin::Unknown => RestoreAction::Leave,
                    };
                    assert_eq!(action, expected, "{case:?}");
                    match action
                    {
                        RestoreAction::Bind(b) =>
                        {
                            assert!(origin == Origin::Own && b == crash, "{case:?}");
                        }
                        RestoreAction::Unbind => assert!(from_debugger, "{case:?}"),
                        RestoreAction::Leave => assert!(!from_debugger, "{case:?}"),
                    }
                    assert_eq!(
                        table.restore_action(0x41, &thread, current),
                        RestoreAction::Leave,
                        "{case:?}"
                    );
                }
            }
        }
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
    fn a_reserved_badge_is_in_use_and_refused_a_second_reservation()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.reserve_badge(0x20, 0), Ok(()));
        assert!(table.badge_in_use(0x20));
        assert_eq!(table.reserve_badge(0x20, 0), Err(InsertError::BadgeInUse));
        // A reservation is no live entry: nothing finds it.
        assert!(table.find_by_badge(0x20).is_none());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn a_badge_a_live_entry_or_a_held_reclaim_holds_is_refused_a_reservation()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.insert(entry_with_badge(0x20)), Ok(()));
        assert_eq!(table.reserve_badge(0x20, 0), Err(InsertError::BadgeInUse));
        assert_eq!(table.arm_dma_hold(0x20), Ok(()));
        let mut entry = table.take_by_badge(0x20).expect("live entry");
        entry.started = true;
        assert!(table.holds_mut().park(&entry));
        assert_eq!(table.reserve_badge(0x20, 0), Err(InsertError::BadgeInUse));
    }

    #[test]
    fn insert_ends_the_reservation_of_its_badge()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.reserve_badge(0x20, 0), Ok(()));
        assert_eq!(table.insert(entry_with_badge(0x20)), Ok(()));
        assert!(table.find_by_badge(0x20).is_some());
        // Taken out again, the badge is free: no reservation outlived it.
        assert!(table.take_by_badge(0x20).is_some());
        assert!(!table.badge_in_use(0x20));
    }

    #[test]
    fn a_released_reservation_frees_its_badge_and_no_other()
    {
        let mut table = ProcessTable::new();
        assert_eq!(table.reserve_badge(0x20, 0), Ok(()));
        assert_eq!(table.reserve_badge(0x40, 0), Ok(()));
        table.release_badge(0x20);
        assert!(!table.badge_in_use(0x20));
        assert!(table.badge_in_use(0x40));
        // Releasing a badge never reserved changes nothing.
        table.release_badge(0x60);
        assert!(table.badge_in_use(0x40));
        assert_eq!(table.reserve_badge(0x20, 0), Ok(()));
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
        assert!(table.creator_of(alias).is_none());
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
        entry.aspace_cap = 8;
        assert_eq!(table.insert(entry), Ok(()));
        let created = QueryEntry {
            started: false,
            thread_cap: 7,
            aspace_cap: 8,
        };
        assert_eq!(table.query_by_badge(16), Some(created));
        table.find_mut_by_badge(16).expect("entry present").started = true;
        assert_eq!(
            table.query_by_badge(16),
            Some(QueryEntry {
                started: true,
                ..created
            })
        );
        assert_eq!(table.query_by_badge(99), None);
    }

    /// Defect caught: a process whose worker thread took a terminal fault
    /// answered ALIVE between its death post and procmgr's reap, because only
    /// the main thread's state was read.
    #[test]
    fn a_query_answers_exited_for_a_main_thread_exit_or_any_terminal_fault()
    {
        const EXITED: u32 = 3;
        let running = 1u64 << 32;
        let started = QueryEntry {
            started: true,
            thread_cap: 7,
            aspace_cap: 8,
        };
        assert_eq!(
            started.state(Some(running), EXITED, Some(0)),
            QueryState::Alive
        );
        assert_eq!(
            started.state(Some(running), EXITED, Some(0x0E)),
            QueryState::Exited(0x0E)
        );
        assert_eq!(
            started.state(Some((u64::from(EXITED) << 32) | 5), EXITED, Some(0)),
            QueryState::Exited(5)
        );
        let created = QueryEntry {
            started: false,
            ..started
        };
        assert_eq!(created.state(None, EXITED, None), QueryState::Created);
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

    // The defect caught: a death whose post procmgr's full death queue
    // dropped that is never reaped, leaving its entry, its kernel objects
    // and its memory held for the life of the system (a scan that skips an
    // entry or misreads the kernel's records, a drain that does not ask for
    // the resync). Run against a model of the kernel's queue
    // (`death_set::model`), drained as procmgr's reaper drains it.
    #[test]
    fn a_resync_reaps_every_death_a_full_death_queue_dropped()
    {
        use death_set::model::KernelQueue;
        use std::collections::HashMap;

        const RING: u32 = 2;
        let running = u64::from(EXITED - 1) << 32;
        let mut table = ProcessTable::new();
        // The kernel's records, by cap: each main thread's state and each
        // address space's retained terminal fault.
        let mut threads = HashMap::new();
        let mut faults = HashMap::new();
        for badge in 1..=6u64
        {
            let mut entry = entry_with_badge(badge);
            entry.thread_cap = 100 + badge;
            entry.aspace_cap = 200 + badge;
            threads.insert(entry.thread_cap, running);
            faults.insert(entry.aspace_cap, 0);
            assert_eq!(table.insert(entry), Ok(()));
        }
        // Five processes die before the reaper drains, more than the ring
        // holds. The kernel records each death before it posts it: 1 to 4
        // exit, posting through their main threads' observers, and a worker
        // thread of 5 faults, posting through its address space's. 6 lives.
        let mut queue = KernelQueue::new(RING);
        let mut dropped = 0;
        for badge in 1..=4u64
        {
            threads.insert(100 + badge, (u64::from(EXITED) << 32) | badge);
            dropped += usize::from(!queue.post((badge, badge)));
        }
        faults.insert(205, 0x100E);
        dropped += usize::from(!queue.post((5, 0x100E)));
        assert_eq!(dropped, 3);

        let mut reaped = Vec::new();
        let full = death_set::drain_queues(
            Some(RING),
            |idx| (idx == 0).then_some(()),
            |()| queue.try_recv(),
            |(badge, exit_reason)| {
                if table.take_by_badge(badge).is_some()
                {
                    reaped.push((badge, exit_reason));
                }
            },
        );
        assert!(
            full,
            "the drain that gave up a full ring asks for the resync"
        );
        let mut dead = Vec::new();
        let listed_all = table.resync_dead(
            EXITED,
            |entry| {
                (
                    threads.get(&entry.thread_cap).copied(),
                    faults.get(&entry.aspace_cap).copied(),
                )
            },
            &mut dead,
        );
        assert!(listed_all);
        for (badge, exit_reason) in dead
        {
            if table.take_by_badge(badge).is_some()
            {
                reaped.push((badge, exit_reason));
            }
        }
        reaped.sort_unstable();
        assert_eq!(reaped, [(1, 1), (2, 2), (3, 3), (4, 4), (5, 0x100E)]);
        let mut live = Vec::new();
        table.for_each(|e| live.push(e.badge));
        assert_eq!(live, [6]);
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

    /// A reserve creator found in the table, whose memmgr badge is `memmgr_badge`.
    fn entry_creator(memmgr_badge: u64) -> Creator
    {
        Creator {
            band_max: 5,
            memmgr_badge,
            reserve: true,
            unbadged: false,
            sign_roles: sign_policy::LOADABLE,
        }
    }

    #[test]
    fn a_phys_class_child_needs_an_unbadged_or_phys_class_creator()
    {
        use ipc::memmgr_labels::PHYS_CLASS_BADGE_BIT;
        use ipc::procmgr_labels::{CREATE_PHYS_ACCESS, CREATE_PINNED};
        let phys = CREATE_PHYS_ACCESS | CREATE_PINNED;
        let ordinary = entry_creator(5);
        // No phys flag: an ordinary child for any creator.
        assert_eq!(
            child_budget(CREATE_PINNED, None, &ordinary).map(|b| b.phys),
            Ok(false)
        );
        // Un-badged creator (init) and a phys-class creator (devmgr).
        assert_eq!(
            child_budget(phys, None, &Creator::UNBADGED).map(|b| b.phys),
            Ok(true)
        );
        let devmgr = entry_creator(PHYS_CLASS_BADGE_BIT | 5);
        assert_eq!(child_budget(phys, None, &devmgr).map(|b| b.phys), Ok(true));
        // An ordinary creator.
        assert_eq!(
            child_budget(phys, None, &ordinary),
            Err(BudgetRefusal::PhysAccess)
        );
    }

    #[test]
    fn a_child_node_sits_under_its_creator_and_reserve_needs_a_reserve_creator()
    {
        use ipc::procmgr_labels::CREATE_RESERVE;
        // init's children: top-level reserve nodes, asked or not.
        for label in [0, CREATE_RESERVE]
        {
            assert_eq!(
                child_budget(label, None, &Creator::UNBADGED),
                Ok(ChildBudget {
                    phys: false,
                    reserve: true,
                    parent: 0,
                    max: None,
                    node_handle: false,
                    charge: 0,
                })
            );
        }
        // A reserve creator's child is outside the reserve unless it asks.
        let svcmgr = entry_creator(0x51);
        assert_eq!(
            child_budget(0, None, &svcmgr).map(|b| (b.reserve, b.parent)),
            Ok((false, 0x51))
        );
        assert_eq!(
            child_budget(CREATE_RESERVE, None, &svcmgr).map(|b| (b.reserve, b.parent)),
            Ok((true, 0x51))
        );
        // A creator outside the reserve may not ask.
        let client = Creator {
            reserve: false,
            ..entry_creator(0x52)
        };
        assert_eq!(
            child_budget(CREATE_RESERVE, None, &client),
            Err(BudgetRefusal::Reserve)
        );
        assert_eq!(
            child_budget(0, Some(9), &client),
            Ok(ChildBudget {
                phys: false,
                reserve: false,
                parent: 0x52,
                max: Some(9),
                node_handle: false,
                charge: 0,
            })
        );
        // Any creator may ask for its child's node handle.
        assert_eq!(
            child_budget(ipc::procmgr_labels::CREATE_NODE_HANDLE, None, &client)
                .map(|b| (b.node_handle, b.charge)),
            Ok((true, 0))
        );
    }

    #[test]
    fn a_child_charged_to_a_node_handle_is_outside_the_reserve()
    {
        use ipc::procmgr_labels::{CREATE_CHARGE_NODE, CREATE_RESERVE};
        // Not even a reserve creator may ask for a reserve child charged to
        // a handle: the handle's node may be a sub-node, never in the reserve.
        let svcmgr = entry_creator(0x51);
        assert_eq!(
            child_budget(CREATE_RESERVE | CREATE_CHARGE_NODE, None, &svcmgr),
            Err(BudgetRefusal::Reserve)
        );
        assert_eq!(
            child_budget(
                CREATE_RESERVE | CREATE_CHARGE_NODE,
                None,
                &Creator::UNBADGED
            ),
            Err(BudgetRefusal::Reserve)
        );
        // A charged child of the un-badged creator is not a reserve node.
        assert_eq!(
            child_budget(CREATE_CHARGE_NODE, None, &Creator::UNBADGED).map(|b| b.reserve),
            Ok(false)
        );
        assert_eq!(
            child_budget(CREATE_CHARGE_NODE, None, &svcmgr).map(|b| b.reserve),
            Ok(false)
        );
    }

    #[test]
    fn register_flags_name_the_class_the_reserve_the_max_and_the_handle()
    {
        use ipc::memmgr_labels::{
            REGISTER_CHARGE_NODE, REGISTER_MAX, REGISTER_NODE_HANDLE, REGISTER_PHYS_CLASS,
            REGISTER_RESERVE,
        };
        let budget = ChildBudget {
            phys: false,
            reserve: false,
            parent: 0,
            max: None,
            node_handle: false,
            charge: 0,
        };
        assert_eq!(budget.register_flags(), 0);
        let full = ChildBudget {
            phys: true,
            reserve: true,
            parent: 7,
            max: Some(0),
            node_handle: true,
            charge: 5,
        };
        assert_eq!(
            full.register_flags(),
            REGISTER_PHYS_CLASS
                | REGISTER_RESERVE
                | REGISTER_MAX
                | REGISTER_NODE_HANDLE
                | REGISTER_CHARGE_NODE
        );
    }

    #[test]
    fn the_memory_max_word_follows_the_fixed_words_and_the_argv_env_header()
    {
        use ipc::IpcMessage;
        use ipc::procmgr_labels::{
            CREATE_ARGV_ENV, CREATE_FROM_FILE, CREATE_MEMORY_MAX, CREATE_PROCESS,
        };
        // No flag: no max, whatever the words.
        let plain = IpcMessage::builder(CREATE_FROM_FILE)
            .word(0, 4096)
            .word(1, 7)
            .build();
        assert_eq!(decode_memory_max(&plain, 1), Ok(None));
        // Either label: word 1, or word 5 after the header.
        let module = IpcMessage::builder(CREATE_PROCESS | CREATE_MEMORY_MAX)
            .words(0, &[8192, 33])
            .build();
        assert_eq!(decode_memory_max(&module, 1), Ok(Some(33)));
        let module_argv = IpcMessage::builder(CREATE_PROCESS | CREATE_MEMORY_MAX | CREATE_ARGV_ENV)
            .words(0, &[8192, 1, 2, 3, 4, 44])
            .build();
        assert_eq!(decode_memory_max(&module_argv, 1), Ok(Some(44)));
        let file = IpcMessage::builder(CREATE_FROM_FILE | CREATE_MEMORY_MAX)
            .words(0, &[4096, 55])
            .build();
        assert_eq!(decode_memory_max(&file, 1), Ok(Some(55)));
        let file_argv = IpcMessage::builder(CREATE_FROM_FILE | CREATE_MEMORY_MAX | CREATE_ARGV_ENV)
            .words(0, &[4096, 1, 2, 3, 4, 66])
            .build();
        assert_eq!(decode_memory_max(&file_argv, 1), Ok(Some(66)));
        // The flag without its word delivered.
        let missing = IpcMessage::builder(CREATE_FROM_FILE | CREATE_MEMORY_MAX | CREATE_ARGV_ENV)
            .words(0, &[4096, 1, 2, 3, 4])
            .build();
        assert_eq!(
            decode_memory_max(&missing, 1),
            Err(BudgetRefusal::MissingMax)
        );
        let none = IpcMessage::builder(CREATE_PROCESS | CREATE_MEMORY_MAX)
            .word(0, 8192)
            .build();
        assert_eq!(decode_memory_max(&none, 1), Err(BudgetRefusal::MissingMax));
    }

    #[test]
    fn creator_of_reports_the_unbadged_creator_an_entry_and_absence()
    {
        let mut table = ProcessTable::new();
        let mut entry = entry_with_badge(16);
        entry.memmgr_badge = 0x77;
        entry.band_max = 9;
        entry.reserve = true;
        entry.sign_roles = objsig::RoleSet::of(&[objsig::Role::Program]);
        assert_eq!(table.insert(entry), Ok(()));
        assert_eq!(table.creator_of(0), Some(Creator::UNBADGED));
        assert_eq!(
            table.creator_of(16),
            Some(Creator {
                band_max: 9,
                memmgr_badge: 0x77,
                reserve: true,
                unbadged: false,
                sign_roles: objsig::RoleSet::of(&[objsig::Role::Program]),
            })
        );
        // A reaped process's badge, and a verb-badged cap's.
        assert_eq!(table.creator_of(99), None);
        assert_eq!(table.creator_of(ipc::procmgr_labels::DEBUG_AUTHORITY), None);
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
        table.holds_mut().release(release_token_badge(16)).unwrap();
        assert!(!table.badge_in_use(16));
    }

    fn child_of(badge: u64, parent: u64) -> ProcessEntry
    {
        let mut entry = entry_with_badge(badge);
        entry.parent = parent;
        entry
    }

    /// A table holding `(badge, parent)` for each pair, inserted in order.
    fn tree(pairs: &[(u64, u64)]) -> ProcessTable
    {
        let mut table = ProcessTable::new();
        for &(badge, parent) in pairs
        {
            assert_eq!(table.insert(child_of(badge, parent)), Ok(()));
        }
        table
    }

    fn parent_of(table: &ProcessTable, badge: u64) -> u64
    {
        table.find_by_badge(badge).expect("entry is live").parent
    }

    fn doomed(table: &ProcessTable, badge: u64) -> bool
    {
        table.find_by_badge(badge).expect("entry is live").doomed
    }

    #[test]
    fn an_insert_takes_its_parent_from_the_reservation()
    {
        let mut table = tree(&[(0x40, 0)]);
        assert_eq!(table.reserve_badge(0x50, 0x40), Ok(()));
        assert_eq!(table.insert(entry_with_badge(0x50)), Ok(()));
        assert_eq!(parent_of(&table, 0x50), 0x40);
        assert!(!table.badge_in_use(0x60));
        assert_eq!(table.reserve_badge(0x60, 0), Ok(()));
        assert_eq!(table.insert(child_of(0x60, 0x40)), Ok(()));
        assert_eq!(parent_of(&table, 0x60), 0);
    }

    #[test]
    fn a_create_from_an_ended_or_doomed_creator_is_refused()
    {
        let mut table = tree(&[(0x40, 0), (0x50, 0x40)]);
        assert_eq!(
            table.reserve_badge(0x60, 0x99),
            Err(InsertError::CreatorEnded)
        );
        assert!(!table.badge_in_use(0x60));
        assert_eq!(table.reserve_badge(0x60, 0x50), Ok(()));
        assert!(table.doom_subtree(0x40));
        assert!(table.creator_of(0x40).is_none());
        assert!(table.creator_of(0x50).is_none());
        assert_eq!(
            table.reserve_badge(0x70, 0x50),
            Err(InsertError::CreatorEnded)
        );
        assert_eq!(
            table.insert(entry_with_badge(0x60)),
            Err(InsertError::CreatorEnded)
        );
        assert_eq!(
            table.insert(child_of(0x80, 0x40)),
            Err(InsertError::CreatorEnded)
        );
        assert!(!table.doom_subtree(0x99));
    }

    #[test]
    fn a_destroy_dooms_the_subtree_and_nothing_else()
    {
        // 0x30 sits below 0x20, which sits below 0x60: badge order is not
        // tree order, so the marking takes more than one pass.
        let mut table = tree(&[
            (0x60, 0),
            (0x20, 0x60),
            (0x30, 0x20),
            (0x10, 0x30),
            (0x40, 0x60),
            (0x50, 0),
        ]);
        assert!(table.doom_subtree(0x20));
        for badge in [0x20, 0x30, 0x10]
        {
            assert!(doomed(&table, badge), "{badge:#x} is below the root");
        }
        for badge in [0x60, 0x40, 0x50]
        {
            assert!(!doomed(&table, badge), "{badge:#x} is outside the subtree");
        }
        let mut taken = Vec::new();
        while let Some(entry) = table.take_doomed(|_| panic!("no doomed child is re-parented"))
        {
            taken.push(entry.badge);
        }
        taken.sort_unstable();
        assert_eq!(taken, [0x10, 0x20, 0x30]);
        assert_eq!(table.len(), 3);
        assert_eq!(parent_of(&table, 0x40), 0x60);
    }

    // Defect guarded: a destroy that marked a child after its insert but
    // before procmgr answered its create tore the child down and posted
    // `EXIT_KILLED` to the creator's death relay, after which procmgr refused
    // the create: a failed creation posted to its relay. The create owns an
    // unanswered entry: the destroy leaves it, and the create refuses itself
    // and drops the relay unposted.
    #[test]
    fn a_destroy_leaves_an_unanswered_create_to_refuse_itself()
    {
        let mut table = tree(&[(0x10, 0)]);
        let mut child = child_of(0x20, 0x10);
        child.unanswered = true;
        child.relay = 44;
        assert_eq!(table.insert(child), Ok(()));
        assert!(table.doom_subtree(0x10));
        let taken = table.take_doomed(|_| panic!("no relay is dropped by the destroy"));
        assert_eq!(taken.map(|e| e.badge), Some(0x10));
        assert!(
            table.take_doomed(|_| ()).is_none(),
            "the destroy took an entry whose create is unanswered"
        );
        let answer = table.answer_create(0x20, || panic!("a marked child's create is answered"));
        assert_eq!(answer, CreateAnswer::Refused);
        let mut dropped = Vec::new();
        let refused = table
            .take_refused(0x20, |relay| dropped.push(relay))
            .expect("the refused child's entry");
        assert_eq!(refused.relay, 0);
        assert_eq!(dropped, [44]);
    }

    #[test]
    fn an_answered_create_is_its_creators_child_for_a_destroy()
    {
        let mut table = tree(&[(0x10, 0)]);
        let mut child = child_of(0x20, 0x10);
        child.unanswered = true;
        child.relay = 44;
        assert_eq!(table.insert(child), Ok(()));
        assert_eq!(table.answer_create(0x20, || true), CreateAnswer::Answered);
        assert!(!table.find_by_badge(0x20).expect("live").unanswered);
        assert!(table.doom_subtree(0x10));
        let mut taken: Vec<u64> = Vec::new();
        while let Some(entry) = table.take_doomed(|_| ())
        {
            taken.push(entry.badge);
            // The answered child keeps its relay for the end post.
            if entry.badge == 0x20
            {
                assert_eq!(entry.relay, 44);
            }
        }
        assert_eq!(taken, [0x10, 0x20]);
    }

    #[test]
    fn an_undelivered_answer_leaves_the_create_unanswered()
    {
        let mut table = tree(&[(0x10, 0)]);
        let mut child = child_of(0x20, 0x10);
        child.unanswered = true;
        assert_eq!(table.insert(child), Ok(()));
        assert_eq!(
            table.answer_create(0x20, || false),
            CreateAnswer::Undelivered
        );
        assert!(table.find_by_badge(0x20).expect("live").unanswered);
        assert_eq!(table.answer_create(0x99, || true), CreateAnswer::Refused);
    }

    // Defect guarded: the teardown of a child whose create procmgr refused
    // after inserting it posted `EXIT_KILLED` to the creator's death relay,
    // which the creator, told the create failed, could read as the end of
    // its next child on the same queue.
    #[test]
    fn a_refused_create_drops_its_own_relay_unposted()
    {
        let mut table = tree(&[(0x10, 0), (0x20, 0x10)]);
        table.find_mut_by_badge(0x20).expect("live").relay = 66;
        let mut dropped = Vec::new();
        let taken = table
            .take_refused(0x20, |relay| dropped.push(relay))
            .expect("the refused child's entry");
        assert_eq!(taken.badge, 0x20);
        assert_eq!(taken.relay, 0);
        assert_eq!(dropped, [66]);
        assert!(table.find_by_badge(0x20).is_none());
        assert!(table.take_refused(0x20, |_| ()).is_none());
    }

    #[test]
    fn an_end_re_parents_to_the_nearest_live_ancestor_and_drops_the_relays()
    {
        let mut table = tree(&[(0x10, 0), (0x20, 0x10), (0x30, 0x20), (0x40, 0x20)]);
        table.find_mut_by_badge(0x30).expect("live").relay = 77;
        assert_eq!(table.reserve_badge(0x50, 0x20), Ok(()));
        let mut dropped = Vec::new();
        let ended = table.take_ended(0x20, |relay| dropped.push(relay));
        assert_eq!(ended.map(|e| e.badge), Some(0x20));
        assert_eq!(dropped, [77]);
        assert_eq!(parent_of(&table, 0x30), 0x10);
        assert_eq!(parent_of(&table, 0x40), 0x10);
        assert_eq!(table.find_by_badge(0x30).expect("live").relay, 0);
        assert_eq!(table.insert(entry_with_badge(0x50)), Ok(()));
        assert_eq!(parent_of(&table, 0x50), 0x10);
        // With no live ancestor left, the children have no parent.
        assert!(table.take_ended(0x10, |_| ()).is_some());
        for badge in [0x30, 0x40, 0x50]
        {
            assert_eq!(parent_of(&table, badge), 0);
            assert!(!doomed(&table, badge));
        }
        assert!(table.take_ended(0x10, |_| ()).is_none());
    }

    #[test]
    fn a_contained_end_dooms_what_is_left_of_its_subtree()
    {
        let mut table = tree(&[
            (0x10, 0),
            (0x20, 0x10),
            (0x30, 0x20),
            (0x40, 0x30),
            (0x50, 0x10),
        ]);
        table.find_mut_by_badge(0x20).expect("live").contained = true;
        table.find_mut_by_badge(0x30).expect("live").relay = 5;
        assert_eq!(table.reserve_badge(0x60, 0x40), Ok(()));
        let ended = table.take_ended(0x20, |_| panic!("a doomed child keeps its relay"));
        assert!(ended.is_some_and(|e| e.contained));
        assert!(doomed(&table, 0x30));
        assert!(doomed(&table, 0x40));
        assert!(!doomed(&table, 0x50));
        assert!(!doomed(&table, 0x10));
        assert_eq!(table.find_by_badge(0x30).expect("live").relay, 5);
        assert_eq!(
            table.insert(entry_with_badge(0x60)),
            Err(InsertError::CreatorEnded)
        );
        // The doomed child lists under no one, and is taken as any doomed.
        assert_eq!(
            table
                .children_after(0x10, None)
                .map(|e| e.badge)
                .collect::<Vec<_>>(),
            [0x50]
        );
        while table
            .take_doomed(|_| panic!("no doomed child is re-parented"))
            .is_some()
        {}
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn a_doomed_create_stays_doomed_when_its_creator_ends_first()
    {
        let mut table = tree(&[(0x10, 0), (0x20, 0x10)]);
        assert_eq!(table.reserve_badge(0x30, 0x20), Ok(()));
        assert!(table.doom_subtree(0x10));
        // The root goes first; the create's creator, then the create, take its
        // parent, none, and stay doomed.
        assert!(table.take_ended(0x10, |_| ()).is_some());
        assert!(table.take_ended(0x20, |_| ()).is_some());
        assert_eq!(
            table.insert(entry_with_badge(0x30)),
            Err(InsertError::CreatorEnded)
        );
    }

    #[test]
    fn the_child_walk_pages_the_live_children_in_badge_order()
    {
        let mut table = tree(&[
            (0x10, 0),
            (0x40, 0x10),
            (0x20, 0x10),
            (0x30, 0x20),
            (0x50, 0x10),
        ]);
        assert!(table.doom_subtree(0x50));
        let all: Vec<u64> = table.children_after(0x10, None).map(|e| e.badge).collect();
        assert_eq!(all, [0x20, 0x40]);
        let rest: Vec<u64> = table
            .children_after(0x10, Some(0x20))
            .map(|e| e.badge)
            .collect();
        assert_eq!(rest, [0x40]);
        assert!(table.is_child(0x10, 0x20));
        // A marked child is no child for `DESTROY_CHILD` either, which
        // refuses it with `INVALID_BADGE` as § Label 28 says.
        assert!(!table.is_child(0x10, 0x50));
        assert!(!table.is_child(0x10, 0x30));
        assert!(!table.is_child(0, 0x10));
        assert!(!table.is_child(0x10, 0x99));
    }

    #[test]
    fn an_end_queue_registers_once()
    {
        let mut table = tree(&[(0x10, 0)]);
        assert_eq!(
            table.register_end_queue(0x20, 9, 1),
            Err(EndQueueRefusal::NotFound)
        );
        assert_eq!(table.register_end_queue(0x10, 9, 1), Ok(()));
        assert_eq!(
            table.register_end_queue(0x10, 10, 2),
            Err(EndQueueRefusal::Present)
        );
        let entry = table.find_by_badge(0x10).expect("live");
        assert_eq!((entry.end_queue, entry.end_correlator), (9, 1));
    }

    #[test]
    fn the_tree_labels_are_served_on_the_cap_their_authority_needs()
    {
        use ipc::procmgr_labels::{
            DESTROY_CHILD, LIST_CHILDREN, PROCESS_HANDLE_TAG, REGISTER_END_QUEUE,
        };
        let own = 0x40;
        let handle = own | PROCESS_HANDLE_TAG;
        assert_eq!(
            sender_refusal(REGISTER_END_QUEUE, handle),
            Some(ipc::procmgr_errors::INVALID_BADGE)
        );
        assert_eq!(sender_refusal(REGISTER_END_QUEUE, own), None);
        for opcode in [LIST_CHILDREN, DESTROY_CHILD]
        {
            assert_eq!(sender_refusal(opcode, handle), None);
            assert_eq!(
                sender_refusal(opcode, own),
                Some(ipc::procmgr_errors::UNAUTHORIZED)
            );
        }
    }
}
