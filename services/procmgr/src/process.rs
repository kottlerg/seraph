// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/src/process.rs

//! Process table, creation, and lifecycle management.
//!
//! Manages the process table and provides functions for creating processes
//! from in-memory ELF images or by streaming from VFS, as well as starting
//! suspended processes.

use crate::loader::{self, ScratchMapping};
use death_set::DeathSet;
use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors};
use process_abi::{PROCESS_ABI_VERSION, PROCESS_MAIN_TLS_MAX_PAGES, resolve_stack_pages};
use process_layout::{ProcessLayout, choose_process_layout};
use std::os::seraph::{ReservedRange, reserve_pages, unreserve_pages};
use std::sync::{Mutex, MutexGuard, PoisonError};
use syscall_abi::{
    EXIT_KILLED, FAULT_CLASS_EXCEPTION, FAULT_CLASS_UPCALL, FAULT_CLASS_VM, PAGE_SIZE, SyscallError,
};

/// How long procmgr waits, at most, on each call it makes on a
/// caller-supplied file cap (`FS_OPEN`, `FS_READ`, `FS_READ_MEMORY`,
/// `FS_RELEASE_MEMORY`, `FS_CLOSE`): 10 s. The cap's server is untrusted, so
/// a server that never answers fails the create with `IO_ERROR` once the
/// bound passes instead of holding the request worker for good
/// (services/procmgr/README.md § Concurrency).
const FILE_CAP_CALL_TIMEOUT_MS: u32 = 10_000;

/// Call the server of a caller-supplied file cap, bounded by
/// [`FILE_CAP_CALL_TIMEOUT_MS`].
///
/// # Safety
/// `ipc_buf` is the calling thread's registered IPC buffer page.
unsafe fn file_call(cap: u64, msg: &IpcMessage, ipc_buf: *mut u64) -> Result<IpcMessage, i64>
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { ipc::ipc_call_timeout(cap, msg, ipc_buf, FILE_CAP_CALL_TIMEOUT_MS) }
}

/// Max file data bytes per VFS read IPC. Word 0 = `bytes_read`, words 1..63 = data.
/// The reply's `MSG_DATA_WORDS_MAX` words less the count word fix it, and
/// `fill_exact` issues as many reads as a file needs.
const VFS_CHUNK_SIZE: u64 = 63 * 8; // 504 bytes

/// Mint a fresh process badge: a random `u64` drawn from the kernel entropy
/// pool ([`syscall::random_u64`]). The same value is procmgr's process-table
/// key, the badged SEND-cap badge on the log endpoint (logd keys slots by the
/// full `u64`), and procmgr's death-EQ correlator. Drawing it at random —
/// rather than the former monotonic counter — keeps the per-process
/// identifier and the spawn rate it would otherwise leak unguessable; the
/// capability is still the sole authority, so this is defense-in-depth. The
/// `u64` width is the kernel badge word, so the space never runs out.
///
/// Single allocation point so the value threads to `populate_child_info`
/// (writes the badged SEND derivation into `pi.log_send_cap`) AND
/// `finalize_creation` (table key, death-EQ correlator, process-handle badge).
/// The badge is reserved in the table from the draw
/// (`ProcessTable::reserve_badge`), so no concurrent create draws it, until
/// `finalize_creation` inserts its entry or the returned reservation drops.
///
/// Redraws until the badge clears `LOG_BADGE_FIRST_CHILD` — keeping it out
/// of the reserved log-badge / no-correlator range that the old monotonic
/// counter held structurally by starting at 16 — and avoids the reserved
/// init-reap correlator, and until no verb bit (`ipc::VERB_BIT_MASK`) is set;
/// see [`badge_is_acceptable`]. It also redraws a badge a live process
/// already holds, or a create in progress reserved, so the death correlator
/// names one live process.
///
/// # Errors
/// `procmgr_errors::OUT_OF_MEMORY`, the code § Label 1 and § Label 13 of
/// `services/procmgr/docs/ipc-interface.md` give a failed badge allocation,
/// when the entropy draw fails (a kernel-contract violation), failing the
/// spawn rather than minting a weak badge, or when the heap cannot hold the
/// reservation.
fn next_process_badge(tables: &Tables) -> Result<BadgeReservation<'_>, u64>
{
    loop
    {
        let t = syscall::random_u64().map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        if !badge_is_acceptable(
            t,
            ipc::log_badges::LOG_BADGE_FIRST_CHILD,
            ipc::procmgr_labels::INIT_REAP_CORRELATOR,
            ipc::VERB_BIT_MASK,
        )
        {
            continue;
        }
        let reserved = tables.lock().table.reserve_badge(t);
        match reserved
        {
            Ok(()) => return Ok(BadgeReservation { tables, badge: t }),
            Err(process_table::InsertError::BadgeInUse) => (),
            Err(process_table::InsertError::OutOfMemory) =>
            {
                return Err(procmgr_errors::OUT_OF_MEMORY);
            }
        }
    }
}

/// A badge [`next_process_badge`] reserved for a create in progress. Its
/// drop ends the reservation, which the entry's insertion has already ended
/// on success. It takes the table lock, so it never drops while its thread
/// holds that lock.
struct BadgeReservation<'a>
{
    tables: &'a Tables,
    badge: u64,
}

impl BadgeReservation<'_>
{
    fn badge(&self) -> u64
    {
        self.badge
    }
}

impl Drop for BadgeReservation<'_>
{
    fn drop(&mut self)
    {
        self.tables.lock().table.release_badge(self.badge);
    }
}

/// procmgr's process table and recent-exits ring, behind the one lock its
/// request workers and its reaper share (`services/procmgr/README.md`
/// § Concurrency). Every holder of the lock makes only syscalls that do not
/// block on another process, and an IPC call is made after the lock is
/// released, with two departures: a growth of procmgr's heap calls memmgr,
/// and a log line calls logd, bounded at `LOG_CALL_TIMEOUT_MS`. Neither
/// memmgr nor logd calls procmgr, so neither call waits on the lock; the
/// checks every worker makes before each request log after the release.
pub struct Tables
{
    state: Mutex<TableState>,
}

/// What [`Tables`] guards.
pub struct TableState
{
    pub table: ProcessTable,
    pub recent: RecentExits,
}

impl Tables
{
    /// An empty table and ring.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            state: Mutex::new(TableState {
                table: ProcessTable::new(),
                recent: RecentExits::new(),
            }),
        }
    }

    /// Lock the table and the ring. procmgr is built with `panic = "abort"`,
    /// so no holder unwinds and a poisoned lock is never seen; it is taken as
    /// it is.
    pub fn lock(&self) -> MutexGuard<'_, TableState>
    {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Draw the entropy one bootstrap-layout choice consumes (ASLR, #39).
///
/// `None` means the draw failed — a kernel-contract violation once the pool
/// is seeded, which it is before any userspace runs.
fn draw_layout_entropy() -> Option<[u8; process_layout::LAYOUT_ENTROPY_BYTES]>
{
    let mut entropy = [0u8; process_layout::LAYOUT_ENTROPY_BYTES];
    let n = syscall::getrandom(&mut entropy).ok()?;
    (n == entropy.len() as u64).then_some(entropy)
}

/// Choose a child's bootstrap layout from fresh entropy, degrading to the
/// deterministic default layout (with a log line) if the draw fails.
fn choose_child_layout() -> ProcessLayout
{
    let entropy = draw_layout_entropy();
    if entropy.is_none()
    {
        std::os::seraph::log!(warn: "layout entropy draw failed; using default layout");
    }
    choose_process_layout(entropy.as_ref())
}

/// Whether a child's `ET_DYN` image with load span `[span_min, span_end)` may
/// load at `bias`: against the image zone sized to the address space, which
/// every process of this boot shares with procmgr (`std::os::seraph::user_va_top`).
fn child_image_fits(bias: u64, span_min: u64, span_end: u64) -> bool
{
    let zones = process_layout::growth_zones(std::os::seraph::user_va_top());
    process_layout::validate_image_placement_below(bias, span_min, span_end, zones.image_zone_end)
}

/// Draw an `ET_DYN` image load bias (ASLR, #39), degrading to the window base
/// (never bias 0 — the image still relocates through the single PIE path)
/// with a log line if the entropy draw fails.
fn choose_image_bias_or_default() -> u64
{
    if let Ok(r) = syscall::random_u64()
    {
        return process_layout::choose_image_bias(r);
    }
    std::os::seraph::log!(warn: "image-bias entropy draw failed; using window base");
    process_layout::IMAGE_WINDOW.base
}

/// Logd's death-notification `EventQueue` cap, registered via
/// `procmgr_labels::REGISTER_DEATH_EQ` once real-logd is up. Zero
/// until then. Every teardown after the registration posts the dead
/// process's death entry to it ([`forward_death_to_logd`]), so the queue
/// carries no death-observer nodes and no pool of its own bounds the
/// processes logd hears of.
///
/// Written once, by the compare-exchange of [`install_logd_death_eq`],
/// whichever request worker serves the first `REGISTER_DEATH_EQ`; readers
/// race only with that write, and the Acquire load pairs with the Release
/// half of the exchange.
pub static LOGD_DEATH_EQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Install logd's death-notification EQ cap. Called by
/// `REGISTER_DEATH_EQ`'s handler.
///
/// First-wins semantics: returns `false` (and changes nothing) if a
/// previous registration already filled the slot. This mitigates the
/// pre-existing `sys_cap_derive_badge` weakness in which any holder of
/// a `SEND_GRANT` cap on procmgr's endpoint can mint
/// `DEATH_EQ_AUTHORITY` and hijack logd's death stream — since logd
/// registers at startup before any other user process is spawned, a
/// later attacker's registration is always second and is rejected
/// here. The caller (`handle_register_death_eq`) is responsible for
/// `cap_delete`ing the just-transferred slot when this returns false.
pub fn install_logd_death_eq(logd_eq: u64) -> bool
{
    if logd_eq == 0
    {
        return false;
    }
    // First-wins: refuse to overwrite. Real logd registers exactly
    // once at startup, so the slot transitions 0 → logd_eq and stays.
    LOGD_DEATH_EQ
        .compare_exchange(
            0,
            logd_eq,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        )
        .is_ok()
}

/// `SYS_EVENT_POST`'s refusal of a post to a full queue.
const QUEUE_FULL: i64 = SyscallError::QueueFull as i64;

/// Post the death entry `(exit_reason, badge)` of a process procmgr tears
/// down to logd's registered death queue, so logd evicts the process's slot.
/// A no-op before logd registers. A post the full queue refuses is dropped,
/// as the kernel drops a post to a full observer queue: logd's drain of the
/// full queue starts its resync, which evicts the slot.
fn forward_death_to_logd(badge: u64, exit_reason: u64)
{
    let logd_eq = LOGD_DEATH_EQ.load(std::sync::atomic::Ordering::Acquire);
    if logd_eq == 0
    {
        return;
    }
    let entry = syscall::EventEntry {
        payload: exit_reason,
        tag: badge,
    };
    match syscall::event_post_entry(logd_eq, entry)
    {
        Ok(()) | Err(QUEUE_FULL) => (),
        Err(e) =>
        {
            std::os::seraph::log!(warn: "death forward to logd failed (badge={badge}, err={e})");
        }
    }
}

// Pure process-table, badge, recent-exit, and create-request argv/env logic
// (`decode_header`, `checked_total`, `ArgvEnvTally`) lives in the
// host-testable `procmgr-process-table` crate; the syscall/IPC-bearing
// operations below stay in the service and drive its lookups. Re-exported so
// the `process::{ProcessTable, ProcessEntry, RecentExits}` paths `main.rs`
// uses, and its `process::split_create_caps` call sites in the create
// handlers, resolve through this module.
pub use process_table::{
    ArgvEnvRefusal, CreateTailCaps, ImageSpan, ProcessEntry, ProcessTable, RecentExits,
    ReleaseRefusal, badge_is_acceptable, release_token_badge, resolve_spawn_sched,
    resync_exit_reason, split_create_caps,
};

// ── Process table (impure operations) ─────────────────────────────────────────

/// Service-private extension trait carrying the syscall/IPC-bearing
/// operations on the (now-foreign) [`ProcessTable`]. Rust forbids inherent
/// `impl` blocks on a type from another crate, so the pipe- and
/// namespace-configuration methods — which `cap_copy`, `cap_delete`, and map
/// the child's `ProcessInfo` page — live here as a trait the service alone
/// sees. Pure slot/badge logic stays on the type itself in the crate.
///
/// `pub(crate)` so the IPC dispatch handlers in `main.rs` can bring it into
/// scope and keep calling `table.configure_pipe(..)` / `configure_namespace(..)`
/// with the original method syntax.
pub(crate) trait TableExt
{
    fn configure_pipe(
        &mut self,
        badge: u64,
        self_aspace: u64,
        direction: u64,
        memory_cap: u64,
        data_notification: u64,
        space_notification: u64,
    ) -> Result<(), u64>;

    fn configure_namespace(&mut self, badge: u64, root_cap: u64, cwd_cap: u64) -> Result<(), u64>;
}

impl TableExt for ProcessTable
{
    /// Install one direction's shmem pipe on a suspended child
    /// identified by `badge`.
    ///
    /// `direction` is one of `ipc::procmgr_labels::PIPE_DIR_STDIN`,
    /// `PIPE_DIR_STDOUT`, `PIPE_DIR_STDERR`. The three caps are
    /// `cap_copy`'d into the child's `CSpace` with `RIGHTS_MEM_MAP_RW` for
    /// the memory cap and `RIGHTS_ALL` for the two notifications. Per pipe,
    /// each end kicks one notification and waits on the other (the writer
    /// kicks `data` and waits on `space`, the reader the reverse; the
    /// parent's death bridge kicks both), and both ends hold both caps with
    /// Notify and Wait rights (`abi/process-abi` `ProcessInfo` pipe fields),
    /// so the child's copies carry Notify and Wait whichever end it holds.
    /// The resulting slot indices are written into the matching
    /// `<dir>_memory_cap` / `<dir>_data_notification_cap` /
    /// `<dir>_space_notification_cap` fields of the child's `ProcessInfo`.
    ///
    /// Each direction is configured at most once before start; different
    /// directions are independent. Every check precedes the copies, and a
    /// copy that fails revokes the copies already made, so a rejected call
    /// installs nothing in the child. (procmgr has no syscall that deletes a
    /// slot in another `CSpace`, so an installed triple cannot be replaced.)
    ///
    /// # Errors
    /// - `procmgr_errors::INVALID_BADGE` — no entry for `badge`.
    /// - `procmgr_errors::ALREADY_STARTED` — target is already running.
    /// - `procmgr_errors::INVALID_ARGUMENT` — bad direction selector, any
    ///   cap is zero, or the direction is already configured.
    /// - `procmgr_errors::OUT_OF_MEMORY` — mapping / `cap_copy` failure.
    fn configure_pipe(
        &mut self,
        badge: u64,
        self_aspace: u64,
        direction: u64,
        memory_cap: u64,
        data_notification: u64,
        space_notification: u64,
    ) -> Result<(), u64>
    {
        if memory_cap == 0 || data_notification == 0 || space_notification == 0
        {
            return Err(procmgr_errors::INVALID_ARGUMENT);
        }
        if !matches!(
            direction,
            ipc::procmgr_labels::PIPE_DIR_STDIN
                | ipc::procmgr_labels::PIPE_DIR_STDOUT
                | ipc::procmgr_labels::PIPE_DIR_STDERR
        )
        {
            return Err(procmgr_errors::INVALID_ARGUMENT);
        }
        let entry = self
            .find_mut_by_badge(badge)
            .ok_or(procmgr_errors::INVALID_BADGE)?;
        if entry.started
        {
            return Err(procmgr_errors::ALREADY_STARTED);
        }
        let pi_memory = entry.pi_memory_cap;
        let child_cspace = entry.cspace_cap;

        let scratch = ScratchMapping::map(self_aspace, pi_memory, 1, syscall::MAP_WRITABLE)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let scratch_va = scratch.va();

        // SAFETY: scratch_va is mapped writable for one page; PI struct
        // lives at offset 0 per the ABI.
        let pi = unsafe { process_abi::process_info_mut(scratch_va) };

        let fields = match direction
        {
            ipc::procmgr_labels::PIPE_DIR_STDIN => (
                &mut pi.stdin_memory_cap,
                &mut pi.stdin_data_notification_cap,
                &mut pi.stdin_space_notification_cap,
            ),
            ipc::procmgr_labels::PIPE_DIR_STDOUT => (
                &mut pi.stdout_memory_cap,
                &mut pi.stdout_data_notification_cap,
                &mut pi.stdout_space_notification_cap,
            ),
            _ => (
                &mut pi.stderr_memory_cap,
                &mut pi.stderr_data_notification_cap,
                &mut pi.stderr_space_notification_cap,
            ),
        };
        if *fields.0 != 0
        {
            return Err(procmgr_errors::INVALID_ARGUMENT);
        }

        let [memory_slot, data_slot, space_slot] = copy_all_into_child(
            child_cspace,
            [
                (memory_cap, syscall::RIGHTS_MEM_MAP_RW),
                (data_notification, syscall::RIGHTS_ALL),
                (space_notification, syscall::RIGHTS_ALL),
            ],
        )
        .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
        *fields.0 = memory_slot;
        *fields.1 = data_slot;
        *fields.2 = space_slot;

        Ok(())
    }

    /// Install per-process root and (optional) cwd caps on a suspended
    /// child. Caps are consumed: ownership transfers to the entry on
    /// success and they are `cap_delete`'d on failure (so the wire-side
    /// caller never has to worry about cleanup after a successful call
    /// returns). Previously-installed caps are `cap_delete`'d procmgr-
    /// side before being replaced.
    ///
    /// # Errors
    /// - `procmgr_errors::INVALID_BADGE` — no entry for `badge` (caps dropped).
    /// - `procmgr_errors::ALREADY_STARTED` — target is already running (caps dropped).
    /// - `procmgr_errors::INVALID_ARGUMENT` — `root_cap` is zero.
    fn configure_namespace(&mut self, badge: u64, root_cap: u64, cwd_cap: u64) -> Result<(), u64>
    {
        if root_cap == 0
        {
            if cwd_cap != 0
            {
                let _ = syscall::cap_delete(cwd_cap);
            }
            return Err(procmgr_errors::INVALID_ARGUMENT);
        }
        let Some(entry) = self.find_mut_by_badge(badge)
        else
        {
            let _ = syscall::cap_delete(root_cap);
            if cwd_cap != 0
            {
                let _ = syscall::cap_delete(cwd_cap);
            }
            return Err(procmgr_errors::INVALID_BADGE);
        };
        if entry.started
        {
            let _ = syscall::cap_delete(root_cap);
            if cwd_cap != 0
            {
                let _ = syscall::cap_delete(cwd_cap);
            }
            return Err(procmgr_errors::ALREADY_STARTED);
        }
        if entry.namespace_override != 0
        {
            let _ = syscall::cap_delete(entry.namespace_override);
        }
        entry.namespace_override = root_cap;
        if entry.cwd_override != 0
        {
            let _ = syscall::cap_delete(entry.cwd_override);
        }
        entry.cwd_override = cwd_cap;
        Ok(())
    }
}

/// Copy each `(cap, rights)` pair into `child_cspace`, all or none.
///
/// Each copy is made from a procmgr-side intermediate derived from the cap,
/// so the child's copy descends from that intermediate alone. If a derive or
/// copy fails, revoking the intermediates removes the copies already made
/// from the child's `CSpace` (a revoke reaches descendants across the
/// boundary, per `docs/capability-model.md` § Revocation) without touching
/// any other descendant of the caller's caps. The intermediates are deleted
/// either way; the child's copies outlive them.
///
/// Returns the child-side slots, or `None` with nothing installed.
fn copy_all_into_child<const N: usize>(child_cspace: u64, caps: [(u64, u64); N])
-> Option<[u64; N]>
{
    let mut intermediates = [0u64; N];
    let mut slots = [0u64; N];
    let mut complete = true;
    for ((&(cap, rights), intermediate_slot), child_slot) in caps
        .iter()
        .zip(intermediates.iter_mut())
        .zip(slots.iter_mut())
    {
        let Ok(intermediate) = syscall::cap_derive(cap, rights)
        else
        {
            complete = false;
            break;
        };
        *intermediate_slot = intermediate;
        let Ok(slot) = syscall::cap_copy(intermediate, child_cspace, rights)
        else
        {
            complete = false;
            break;
        };
        *child_slot = slot;
    }
    for &intermediate in &intermediates
    {
        if intermediate == 0
        {
            continue;
        }
        if !complete
        {
            let _ = syscall::cap_revoke_all(intermediate);
        }
        let _ = syscall::cap_delete(intermediate);
    }
    complete.then_some(slots)
}

// ── Result type ─────────────────────────────────────────────────────────────

/// Result of a successful process creation call.
pub struct CreateResult
{
    /// Badged endpoint cap for the caller to use with `START_PROCESS`.
    pub process_handle: u64,
    /// Derived Thread cap to transfer to caller (CONTROL right).
    pub thread_for_caller: u64,
    /// The child's process badge (its table key), so a create whose reply
    /// cannot be delivered can destroy the child.
    pub badge: u64,
}

/// Resolved scheduling placement for a child, produced by
/// `crate::resolve_create_sched` from the create-label fields and the
/// creator's ceiling. Invariant: `1 <= priority <= band_max <=`
/// [`ipc::sched_policy::BASELINE_PRIORITY_MAX`].
#[derive(Clone, Copy)]
pub struct ChildSched
{
    /// Priority level the child's initial thread is created at.
    pub priority: u8,
    /// Upper bound of the baseline `SchedControl` band minted into the
    /// child (`[1, band_max]`).
    pub band_max: u8,
    /// The `memmgr_labels::REGISTER_PROCESS` flags the child registers with
    /// (`process_table::child_memmgr_flags`): its physical-address class.
    pub memmgr_flags: u64,
}

// ── Child setup helpers ─────────────────────────────────────────────────────

/// Universal bootstrap caps procmgr threads through into every child.
///
/// Procmgr's own service endpoint plus the log-cap derivation source.
///
/// The child receives a badged SEND copy of `procmgr_endpoint` so it
/// can call `REQUEST_MEMORY_CAPS` / `CREATE_PROCESS`, and a
/// freshly-derived badged SEND cap on the log endpoint (badge = the
/// child's process badge) so `seraph::log!` writes go directly to logd
/// with the kernel-attached identity. `log_send_source` is procmgr's
/// un-badged SEND cap on the log endpoint, used as the source for
/// each per-child `cap_derive_badge`.
///
/// Stdio caps (stdin, stdout, stderr) are intentionally NOT part of this
/// struct: they are not a universal property of processes, and each can
/// route to a different endpoint. A spawner that wants the child to have
/// any stdio pipe wiring installs it via separate `CONFIGURE_PIPE`
/// IPCs (one per piped direction) between `CREATE_PROCESS` and
/// `START_PROCESS`.
pub struct UniversalCaps
{
    pub procmgr_endpoint: u64,
    /// Un-badged SEND cap on the system log endpoint, sourced from
    /// the slot procmgr received during init bootstrap. Used as the
    /// `cap_derive_badge` source for minting a badged SEND per child
    /// (badge = child's process badge). Zero when procmgr has no log
    /// endpoint (e.g. a future no-log boot mode); children born in
    /// that case receive zero in `pi.log_send_cap` and silent-drop
    /// `seraph::log!`.
    pub log_send_source: u64,
    /// Badged SEND cap on memmgr's service endpoint, freshly minted by
    /// `memmgr_labels::REGISTER_PROCESS` for this child. The cap lives in
    /// procmgr's `CSpace` on entry; `populate_child_info` copies it into
    /// the child's `CSpace` and records the destination slot in
    /// `ProcessInfo.memmgr_endpoint_cap`. Zero when memmgr is not yet
    /// reachable (procmgr itself, init); the child's heap-bootstrap then
    /// no-ops and the child cannot allocate.
    pub memmgr_endpoint: u64,
    /// Memmgr-side process badge paired with `memmgr_endpoint`. Sent in
    /// `memmgr_labels::PROCESS_DIED` at child teardown so memmgr can
    /// reclaim the right ledger entry. Zero when memmgr is not wired.
    pub memmgr_badge: u64,
    /// Un-badged SEND cap on svcmgr's service endpoint, sourced from
    /// the slot procmgr received during init bootstrap. Used as the
    /// `cap_derive_badge` source for minting a per-child badged SEND
    /// (badge = child's process badge) attenuated to QUERY-only rights.
    /// The minted cap is installed in `ProcessInfo.service_registry_cap`
    /// and is how every child resolves service names via
    /// `svcmgr_labels::QUERY_ENDPOINT`. Zero when svcmgr is not yet
    /// reachable; children born in that case receive zero in
    /// `pi.service_registry_cap` and `registry_client::lookup` no-ops.
    pub registry_send_source: u64,
    /// Baseline `SchedControl` cap in procmgr's `CSpace` (procmgr's own
    /// `ProcessInfo.sched_control_cap`, band
    /// `[1, sched_policy::BASELINE_PRIORITY_MAX]`). Source of every child's
    /// band: copied whole when the child's `band_max` equals the baseline
    /// ceiling, or copy-then-split narrowed to `[1, band_max]` otherwise;
    /// the result is recorded in the child's
    /// `ProcessInfo.sched_control_cap`. Also the authority procmgr invokes
    /// to create child threads at their assigned level. Zero when procmgr
    /// was given no baseline; children then receive zero, are created at
    /// the floor, and cannot set any priority.
    pub sched_baseline: u64,
    /// Whether the child is demand-paged ([`Paging`]).
    pub paging: Paging,
    /// Procmgr's own (procmgr-badged) SEND cap on memmgr's endpoint, used to
    /// issue the procmgr-only `DELEGATE_ASPACE`. Distinct from
    /// [`Self::memmgr_endpoint`] (the child's badged cap). Zero when memmgr is
    /// not reachable.
    pub self_memmgr_ep: u64,
}

/// Whether a child is demand-paged. Demand paging is the default; a child is
/// pinned only when the caller set `procmgr_labels::CREATE_PINNED` (a DMA
/// driver that must be eager-mapped). For a demand-paged child,
/// `finalize_creation` delegates the child `AddressSpace` to memmgr, binds the
/// child's main-thread fault handler to it, and, once both took effect,
/// advertises the pager in `ProcessInfo` (`advertise_pager`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Paging
{
    /// Served by memmgr's default system pager.
    Demand,
    /// Eager-mapped, with no pager.
    Pinned,
}

impl Paging
{
    /// The paging a create request's `label` asks for.
    #[must_use]
    pub const fn of_label(label: u64) -> Self
    {
        if label & ipc::procmgr_labels::CREATE_PINNED == 0
        {
            Self::Demand
        }
        else
        {
            Self::Pinned
        }
    }
}

/// TLS template metadata extracted from a child's `PT_TLS` segment,
/// propagated verbatim into `ProcessInfo` for spawned-thread block
/// population. `memsz == 0` signals "binary has no TLS segment".
#[derive(Clone, Copy, Default)]
pub struct ChildTlsTemplate
{
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// Result of `prepare_main_tls`: the memory cap procmgr retains for teardown
/// plus the `tls_base` VA to pass to `SYS_THREAD_CONFIGURE`.
///
/// Both fields are zero when the child has no `PT_TLS` segment.
#[derive(Clone, Copy, Default)]
pub struct MainTls
{
    pub memory_cap: u64,
    pub base_va: u64,
}

/// Pages procmgr maps at once while it copies a create request's argv and
/// env: the caller's pages and the child's each pass through one window of
/// this many pages, re-mapped for every chunk.
///
/// The window bounds procmgr's own page-table cost per create, which no
/// spawner funds, to the tables two 256 KiB spans need, whatever the blobs'
/// size; a larger window only saves map calls. The blobs themselves are
/// bounded by `process_abi::ARGV_ENV_MAX_PAGES` alone.
const ARGV_ENV_COPY_WINDOW_PAGES: u64 = 64;

/// The argv and env a create request carries: the caller's Memory cap and
/// its header, bounded by the cap and the argv/env region
/// ([`check_argv_env`]). The cap stays the handler's to delete.
pub struct ArgvEnvRequest
{
    cap: u64,
    header: ipc::procmgr_labels::ArgvEnvHeader,
    total: u64,
}

/// Check the argv and env of a create request that sets `CREATE_ARGV_ENV`:
/// decode the header at data word `first_word` and bound the blobs by
/// `argv_env_cap`'s size and by `process_abi::ARGV_ENV_MAX_BYTES`. Maps and
/// acquires nothing, so the handler calls it before any resource and replies
/// `INVALID_ARGUMENT` on `Err`; the strings are checked on the child's copy
/// ([`copy_argv_env`]).
///
/// # Errors
/// The [`ArgvEnvRefusal`] the header earns, and [`ArgvEnvRefusal::NotMemory`]
/// when `argv_env_cap` is not a Memory cap.
pub fn check_argv_env(
    req: &IpcMessage,
    first_word: usize,
    argv_env_cap: u64,
) -> Result<ArgvEnvRequest, ArgvEnvRefusal>
{
    let header = process_table::decode_header(req, first_word)?;
    let cap_bytes = syscall::cap_info(argv_env_cap, syscall_abi::CAP_INFO_MEMORY_SIZE)
        .map_err(|_| ArgvEnvRefusal::NotMemory)?;
    let total = process_table::checked_total(header, cap_bytes, process_abi::ARGV_ENV_MAX_BYTES)?;
    Ok(ArgvEnvRequest {
        cap: argv_env_cap,
        header,
        total,
    })
}

/// A child's argv/env region before it is mapped: the checked copy of the
/// blobs in pages on the child's memmgr account, and the header that locates
/// them. `memory` is zero, and nothing is mapped, for a child without argv
/// or env.
pub struct ChildArgvEnv
{
    memory: CapGuard,
    pages: u64,
    header: ipc::procmgr_labels::ArgvEnvHeader,
    /// The child's name, the first string of its argv (`LIST_PROCESSES`).
    name: process_table::ProcessName,
}

impl ChildArgvEnv
{
    /// The region of a child created without argv and env.
    pub fn empty() -> Self
    {
        Self {
            memory: CapGuard::new(0),
            pages: 0,
            header: ipc::procmgr_labels::ArgvEnvHeader::default(),
            name: process_table::ProcessName::EMPTY,
        }
    }
}

/// Why [`copy_argv_env`] took no copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArgvEnvCopyError
{
    /// The create fails with this `procmgr_errors` code; everything
    /// [`copy_argv_env`] acquired is released.
    Reply(u64),
    /// A copy window's unmap failed, so pages of the child's run (writable)
    /// and of the caller's (read-only) may still be mapped in procmgr. The
    /// window's VA stays reserved; the handler withholds the child's memmgr
    /// record (it sends no `PROCESS_DIED`) and replies
    /// `ARGV_ENV_STILL_MAPPED`, on which the caller withholds its run, so
    /// memmgr re-grants no frame procmgr may still map.
    StillMapped,
}

impl ArgvEnvCopyError
{
    /// The `procmgr_errors` code the create replies.
    pub fn code(self) -> u64
    {
        match self
        {
            Self::Reply(code) => code,
            Self::StillMapped => procmgr_errors::ARGV_ENV_STILL_MAPPED,
        }
    }
}

/// Release the child's memmgr registration `mms` after [`copy_argv_env`]
/// failed with `e`: retire the record (`PROCESS_DIED`, which returns every
/// page billed to the child) for a [`ArgvEnvCopyError::Reply`], and withhold
/// it, slot and record kept, for [`ArgvEnvCopyError::StillMapped`], so
/// memmgr keeps out of its pool the frames procmgr may still map.
pub fn settle_failed_argv_env(mms: MemmgrSendGuard, e: ArgvEnvCopyError)
{
    if e == ArgvEnvCopyError::StillMapped
    {
        std::os::seraph::log!(
            warn: "argv/env copy left pages mapped; the child's memmgr record is withheld"
        );
        let _ = mms.disarm();
    }
}

/// A failed map of [`CopyWindows::map`]: which window, and the kernel's
/// error.
enum WindowMapError
{
    /// The caller's pages (`src`): the error says whose fault it is.
    Src(i64),
    /// The child's pages (`dst`), which procmgr allocated: procmgr's
    /// resources ran out.
    Dst,
}

/// Two VA windows of [`ARGV_ENV_COPY_WINDOW_PAGES`] pages in procmgr's own
/// address space, the caller's and the child's pages mapped through them a
/// chunk at a time. Dropping it unmaps whatever is mapped and releases the
/// VA, unless an unmap failed (`stuck`): the VA then stays reserved, so no
/// later reservation lands on pages still mapped there.
struct CopyWindows
{
    self_aspace: u64,
    src: Option<ReservedRange>,
    dst: Option<ReservedRange>,
    mapped: u64,
    stuck: bool,
}

impl CopyWindows
{
    fn reserve(self_aspace: u64) -> Result<Self, ArgvEnvCopyError>
    {
        let oom = ArgvEnvCopyError::Reply(procmgr_errors::OUT_OF_MEMORY);
        let src = reserve_pages(ARGV_ENV_COPY_WINDOW_PAGES).map_err(|_| oom)?;
        let Ok(dst) = reserve_pages(ARGV_ENV_COPY_WINDOW_PAGES)
        else
        {
            unreserve_pages(src);
            return Err(oom);
        };
        Ok(Self {
            self_aspace,
            src: Some(src),
            dst: Some(dst),
            mapped: 0,
            stuck: false,
        })
    }

    fn src_va(&self) -> u64
    {
        self.src.as_ref().map_or(0, ReservedRange::va_start)
    }

    fn dst_va(&self) -> u64
    {
        self.dst.as_ref().map_or(0, ReservedRange::va_start)
    }

    /// Map `pages` pages, from page `offset` of each cap, at the two windows:
    /// `src` read-only, `dst` writable. The kernel maps page by page and stops
    /// at the first failure, so a failed map unmaps both windows' whole
    /// `pages`-page spans (unmapping a page that was never mapped is
    /// harmless) before it returns; an unmap that fails leaves `stuck` set.
    fn map(&mut self, src: u64, dst: u64, offset: u64, pages: u64) -> Result<(), WindowMapError>
    {
        self.unmap();
        let (aspace, src_va, dst_va) = (self.self_aspace, self.src_va(), self.dst_va());
        self.mapped = pages;
        // SAFETY: the window is a reservation from procmgr's arena that this
        // value owns, `pages` is at most its size, and no Rust object or IPC
        // page lies in it; the only accesses to it are the raw-pointer reads
        // of `copy_argv_chunk`, while it is mapped.
        let src_mapped =
            unsafe { syscall::mem_map(src, aspace, src_va, offset, pages, syscall::MAP_FROM_CAP) };
        let mapped = if let Err(code) = src_mapped
        {
            Err(WindowMapError::Src(code))
        }
        else
        {
            // SAFETY: as for the source window, with the raw-pointer writes
            // of `copy_argv_chunk`.
            let dst_mapped = unsafe {
                syscall::mem_map(dst, aspace, dst_va, offset, pages, syscall::MAP_WRITABLE)
            };
            dst_mapped.map_err(|_| WindowMapError::Dst)
        };
        if mapped.is_err()
        {
            self.unmap();
        }
        mapped
    }

    /// Unmap both windows' last-mapped spans, setting `stuck` when an unmap
    /// fails.
    fn unmap(&mut self)
    {
        if self.mapped == 0
        {
            return;
        }
        // SAFETY: the source window is this value's own reservation, mapped
        // at most `mapped` pages by `map`; nothing references it.
        let src = unsafe { syscall::mem_unmap(self.self_aspace, self.src_va(), self.mapped) };
        // SAFETY: the destination window is this value's own reservation,
        // mapped at most `mapped` pages by `map`; nothing references it.
        let dst = unsafe { syscall::mem_unmap(self.self_aspace, self.dst_va(), self.mapped) };
        self.stuck |= src.is_err() || dst.is_err();
        self.mapped = 0;
    }
}

impl Drop for CopyWindows
{
    fn drop(&mut self)
    {
        self.unmap();
        if self.stuck
        {
            std::os::seraph::log!(warn: "argv/env copy window unmap failed; its VA stays reserved");
            return;
        }
        if let Some(src) = self.src.take()
        {
            unreserve_pages(src);
        }
        if let Some(dst) = self.dst.take()
        {
            unreserve_pages(dst);
        }
    }
}

/// Copy the blobs `request` describes into fresh pages on the child's memmgr
/// account (`child_memmgr_send`), through [`CopyWindows`], and check their
/// strings on the copy ([`process_table::ArgvEnvTally`]).
///
/// The caller's pages are read only by raw-pointer copies into the child's
/// pages, which no one else maps yet, so a caller that rewrites its pages
/// meanwhile changes only what the child receives, and the check covers
/// exactly that.
///
/// # Errors
/// [`ArgvEnvCopyError::Reply`] with `INVALID_ARGUMENT` when the copy fails
/// its string check or the kernel refuses the caller's pages for a reason
/// other than procmgr's memory (no map right, retyped bytes in the range),
/// and with `OUT_OF_MEMORY` when memmgr cannot supply the pages or procmgr
/// cannot derive its caps or reserve or map its windows;
/// [`ArgvEnvCopyError::StillMapped`] when a window's unmap failed.
pub fn copy_argv_env(
    self_aspace: u64,
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    request: &ArgvEnvRequest,
) -> Result<ChildArgvEnv, ArgvEnvCopyError>
{
    use ArgvEnvCopyError::Reply;

    if request.total == 0
    {
        return Ok(ChildArgvEnv::empty());
    }
    let pages = request.total.div_ceil(PAGE_SIZE);
    let (memory, src, dst) = copy_caps(child_memmgr_send, ipc_buf, request.cap, pages)?;
    let mut windows = CopyWindows::reserve(self_aspace)?;
    let mut tally = process_table::ArgvEnvTally::new(request.header);
    let mut offset = 0;
    let mut copied = Ok(());
    while offset < pages && copied.is_ok()
    {
        // The loop condition keeps `offset` below `pages`.
        let chunk_pages = pages.saturating_sub(offset).min(ARGV_ENV_COPY_WINDOW_PAGES);
        copied = copy_argv_chunk(
            &mut windows,
            &src,
            &dst,
            offset,
            chunk_pages,
            request,
            &mut tally,
        );
        // `chunk_pages` is at most `pages - offset`, so the sum is at most `pages`.
        offset = offset.saturating_add(chunk_pages);
    }
    let stuck = windows.stuck;
    drop(windows);
    if stuck
    {
        return Err(ArgvEnvCopyError::StillMapped);
    }
    copied?;
    let name = tally.finish().map_err(|refusal| {
        std::os::seraph::log!(warn: "create argv/env refused: {refusal:?}");
        Reply(procmgr_errors::INVALID_ARGUMENT)
    })?;
    Ok(ChildArgvEnv {
        memory,
        pages,
        header: request.header,
        name,
    })
}

/// The caps [`copy_argv_env`] copies through: the child's fresh run of
/// `pages` pages on its memmgr account, a map-only derivation of the
/// caller's `request_cap`, and a writable derivation of the child's run.
///
/// # Errors
/// [`ArgvEnvCopyError::Reply`] with `OUT_OF_MEMORY` when memmgr cannot
/// supply the run or a derivation fails. A derivation masks rights the
/// source lacks rather than refusing them, so its failure is procmgr's own
/// slot shortfall; a caller's cap without the map right is refused when its
/// window is mapped.
fn copy_caps(
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    request_cap: u64,
    pages: u64,
) -> Result<(CapGuard, CapGuard, CapGuard), ArgvEnvCopyError>
{
    let oom = ArgvEnvCopyError::Reply(procmgr_errors::OUT_OF_MEMORY);
    let memory = CapGuard::new(
        crate::memmgr_alloc_pages_contig(child_memmgr_send, pages, ipc_buf).ok_or(oom)?,
    );
    let src =
        CapGuard::new(syscall::cap_derive(request_cap, syscall::RIGHTS_MEM_MAP).map_err(|_| oom)?);
    let dst = CapGuard::new(
        syscall::cap_derive(memory.cap(), syscall::RIGHTS_MEM_MAP_RW).map_err(|_| oom)?,
    );
    Ok((memory, src, dst))
}

/// Copy the `chunk_pages` pages of the blobs from page `offset` through
/// `windows`, zero the child's page tail past the blobs, and feed the copy to
/// `tally`.
///
/// # Errors
/// [`ArgvEnvCopyError::Reply`] with `OUT_OF_MEMORY` when a window map fails
/// for want of procmgr's resources, and with `INVALID_ARGUMENT` when the
/// kernel refuses the caller's pages for any other reason.
fn copy_argv_chunk(
    windows: &mut CopyWindows,
    src: &CapGuard,
    dst: &CapGuard,
    offset: u64,
    chunk_pages: u64,
    request: &ArgvEnvRequest,
    tally: &mut process_table::ArgvEnvTally,
) -> Result<(), ArgvEnvCopyError>
{
    windows
        .map(src.cap(), dst.cap(), offset, chunk_pages)
        .map_err(|e| match e
        {
            WindowMapError::Src(code) if code != SyscallError::OutOfMemory as i64 =>
            {
                ArgvEnvCopyError::Reply(procmgr_errors::INVALID_ARGUMENT)
            }
            WindowMapError::Src(_) | WindowMapError::Dst =>
            {
                ArgvEnvCopyError::Reply(procmgr_errors::OUT_OF_MEMORY)
            }
        })?;
    // `chunk_pages` is at most the window size, so the product is small.
    let chunk_bytes = chunk_pages.saturating_mul(PAGE_SIZE) as usize;
    // `offset` is below `pages = ceil(total / PAGE_SIZE)`, so `offset * PAGE_SIZE` is below `total`.
    let blob_bytes = request
        .total
        .saturating_sub(offset.saturating_mul(PAGE_SIZE))
        .min(chunk_bytes as u64) as usize;
    // SAFETY: both windows map `chunk_pages` pages just above, `src`
    // read-only and `dst` writable for procmgr alone (the child is not
    // running and maps no page of the child's run yet), and they do not
    // overlap; `blob_bytes` is at most `chunk_bytes`, the windows' length.
    // The caller's bytes are read only by this raw copy, never through a
    // reference, since the caller may write them concurrently.
    unsafe {
        core::ptr::copy_nonoverlapping(
            windows.src_va() as *const u8,
            windows.dst_va() as *mut u8,
            blob_bytes,
        );
    }
    // SAFETY: the destination window maps `chunk_bytes` writable bytes for
    // procmgr alone; the slice covers only the child's window, which nothing
    // else writes while it lives, until the next `map`, and the copy above
    // left no pointer into it in use.
    let dst_bytes =
        unsafe { core::slice::from_raw_parts_mut(windows.dst_va() as *mut u8, chunk_bytes) };
    // The page tail past the blobs carries no earlier owner's bytes.
    // `blob_bytes` is at most `chunk_bytes`, the window length, so the split
    // always succeeds.
    let Some((blob, tail)) = dst_bytes.split_at_mut_checked(blob_bytes)
    else
    {
        return Err(ArgvEnvCopyError::Reply(procmgr_errors::INVALID_ARGUMENT));
    };
    tail.fill(0);
    tally.feed(blob);
    Ok(())
}

/// Pages of argv/env region a child's seed page-table pool covers without
/// funding: one last-level table's span. The region starts on the page after
/// the `ProcessInfo` page, so a region this size needs at most one
/// last-level table beyond the page's own, plus one table for each upper
/// level whose boundary it crosses, which the spare pages of the child's
/// seed pool (`ASPACE_RETYPE_PAGES`) hold; a larger region is funded in full
/// by [`fund_child_page_tables`].
const ARGV_ENV_SEED_COVERED_PAGES: u64 = 512;

/// Add to `child_aspace`'s page-table pool, from pages on the child's memmgr
/// account, the tables a `pages`-page argv/env region needs: one last-level
/// table per 512 pages plus the region's boundary and upper-level tables.
/// The whole need is added, so the region leaves the pool's existing budget
/// to the child's other surfaces. A region of at most
/// [`ARGV_ENV_SEED_COVERED_PAGES`] adds nothing.
///
/// # Errors
/// `OUT_OF_MEMORY` when memmgr cannot supply the pages or the augment fails.
fn fund_child_page_tables(
    child_aspace: u64,
    child_memmgr_send: u64,
    pages: u64,
    ipc_buf: *mut u64,
) -> Result<(), u64>
{
    if pages <= ARGV_ENV_SEED_COVERED_PAGES
    {
        return Ok(());
    }
    // `pages` is a page count of a 64-bit byte total, so the sum cannot overflow.
    let table_pages = pages.div_ceil(512).saturating_add(4);
    let frame = CapGuard::new(
        crate::memmgr_alloc_pages_contig(child_memmgr_send, table_pages, ipc_buf)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?,
    );
    // The address space's donation record holds its own reference on the
    // frames, so procmgr's slot is deleted when `frame` drops.
    syscall::cap_create_aspace(frame.cap(), child_aspace, table_pages)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    Ok(())
}

/// Map `argv_env`'s pages read-only into `child_aspace` directly after the
/// `ProcessInfo` page (`process_abi::ARGV_ENV_REGION_OFFSET`), funding the
/// child's page tables for them first.
///
/// # Errors
/// `OUT_OF_MEMORY` when the funding, the derivation, or the map fails.
///
/// # Safety
/// `child_aspace` must name a child's address space, never procmgr's own:
/// the function maps pages into it, at the VA the child's layout leaves after
/// its `ProcessInfo` page, without checking what procmgr holds there.
unsafe fn map_child_argv_env(
    child_aspace: u64,
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    argv_env: &ChildArgvEnv,
    layout: &ProcessLayout,
) -> Result<(), u64>
{
    fund_child_page_tables(child_aspace, child_memmgr_send, argv_env.pages, ipc_buf)?;
    let ro = CapGuard::new(
        syscall::cap_derive(argv_env.memory.cap(), syscall::RIGHTS_MEM_MAP)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?,
    );
    let Some(region_va) = layout
        .process_info_va
        .checked_add(process_abi::ARGV_ENV_REGION_OFFSET)
    else
    {
        return Err(procmgr_errors::OUT_OF_MEMORY);
    };
    // SAFETY: the caller's contract: `child_aspace` is a child's address
    // space, never procmgr's own, so the map changes nothing procmgr runs on.
    // The region lies inside the tail every layout leaves after the
    // `ProcessInfo` page (`process-layout` pins `1 + ARGV_ENV_MAX_PAGES` to it,
    // and `check_argv_env` bounded the pages by `ARGV_ENV_MAX_BYTES`). A
    // partial map is torn down with the child's address space when the
    // create fails.
    unsafe {
        syscall::mem_map(
            ro.cap(),
            child_aspace,
            region_va,
            0,
            argv_env.pages,
            syscall::MAP_FROM_CAP,
        )
    }
    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)
}

/// The Memory caps [`populate_child_info`] leaves the child's table entry:
/// the `ProcessInfo` page's and the argv/env region's (zero without one).
/// Both guarded, so a later failure of the create releases them.
struct ChildInfoCaps
{
    pi_memory: CapGuard,
    argv_env_memory: CapGuard,
    /// The child's name, carried from its argv to its table entry.
    name: process_table::ProcessName,
}

impl ChildInfoCaps
{
    /// Hand both caps to the child's table entry, which now owns them.
    fn disarm(self)
    {
        let _ = self.pi_memory.disarm();
        let _ = self.argv_env_memory.disarm();
    }
}

/// Populate a `ProcessInfo` page for a child process and map it read-only,
/// with the argv/env region after it when `argv_env` carries any bytes.
///
/// Installs the creator endpoint cap (if any) and the procmgr service
/// endpoint into the child `CSpace` and records their slots in the child's
/// `ProcessInfo`. Stdio pipe slots (memory cap + two notification caps per
/// direction) are left zero here and are populated afterwards by
/// [`ProcessTable::configure_pipe`], which remaps the same `pi_memory`
/// writable, installs caller-supplied caps via `cap_copy` into the
/// child's `CSpace`, and writes the slot indices into the PI page. This
/// split keeps the core `CREATE_PROCESS` path stdio-agnostic and lets
/// spawners pipe each direction independently.
///
/// # Errors
/// `procmgr_errors::OUT_OF_MEMORY` when the page's allocation, its
/// mapping, a capability derivation or copy into the child, or the
/// argv/env region's funding or mapping fails: every create label names
/// that code for these failures
/// (`services/procmgr/docs/ipc-interface.md` § Label 1 and § Label 13).
///
/// # Safety
/// `child_aspace` must name a child's address space, never procmgr's own:
/// the function maps pages into it, at VAs the child's layout chooses,
/// without checking what procmgr holds there.
#[expect(
    clippy::similar_names,
    reason = "child_aspace/child_cspace are intentionally parallel"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "each cluster is a small fixed-size bundle; collapsing them into one struct shifts \
              the verbosity to the call sites without reducing the total parameter count"
)]
#[expect(
    clippy::too_many_lines,
    reason = "this is the single transaction that owns one temporary scratch mapping for the PI \
              page — splitting would require threading the partial state through helpers that all \
              need the same self_aspace + child_cspace + write context"
)]
unsafe fn populate_child_info(
    self_aspace: u64,
    child_aspace: u64,
    child_cspace: u64,
    child_thread: u64,
    creator_endpoint: u64,
    universals: &UniversalCaps,
    tls: &ChildTlsTemplate,
    argv_env: ChildArgvEnv,
    ipc_buf: *mut u64,
    stack_pages: u32,
    process_badge: u64,
    sched: ChildSched,
    layout: &ProcessLayout,
) -> Result<ChildInfoCaps, u64>
{
    // Guarded from allocation: every early `Err` below deletes the slot.
    let pi_memory = CapGuard::new(
        crate::memmgr_alloc_page(universals.memmgr_endpoint, ipc_buf)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?,
    );
    let scratch = ScratchMapping::map(self_aspace, pi_memory.cap(), 1, syscall::MAP_WRITABLE)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let scratch_va = scratch.va();
    // SAFETY: scratch_va mapped writable, one page.
    unsafe { core::ptr::write_bytes(scratch_va as *mut u8, 0, PAGE_SIZE as usize) };

    let child_thread_in_child =
        syscall::cap_copy(child_thread, child_cspace, syscall::RIGHTS_THREAD)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let child_aspace_in_child = syscall::cap_copy(child_aspace, child_cspace, syscall::RIGHTS_ALL)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let child_cspace_in_child =
        syscall::cap_copy(child_cspace, child_cspace, syscall::RIGHTS_CS_ALL)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;

    let creator_ep_in_child = if creator_endpoint != 0
    {
        // Preserve source rights: try ALL first (for services where
        // creator_endpoint doubles as a recv endpoint, e.g. fatfs service ep);
        // fall back to SEND for badged send caps used by the bootstrap protocol.
        syscall::cap_copy(creator_endpoint, child_cspace, syscall::RIGHTS_ALL)
            .or_else(|_| syscall::cap_copy(creator_endpoint, child_cspace, syscall::RIGHTS_EP_SEND))
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?
    }
    else
    {
        0
    };

    // procmgr's own service endpoint: install a SEND+GRANT copy
    // badged with the child's `process_badge` alone. The badge gives
    // procmgr's handlers a kernel-delivered identity for every IPC
    // the child makes, on which alone `DECLARE_NO_DEBUG` and
    // `REGISTER_THREAD` are served (the creator's process handle
    // carries `procmgr_labels::PROCESS_HANDLE_TAG` too), and it
    // locks the child OUT of `cap_derive_badge` on this cap —
    // `sys_cap_derive_badge` rejects sources with `src_badge != 0`,
    // so the child cannot mint a parallel cap with a privileged
    // badge value (`procmgr_labels::DEATH_EQ_AUTHORITY`, etc.). The
    // un-badged source cap stays in procmgr's own CSpace; outside it,
    // init holds un-badged copies and hands svcmgr a badge-0 source at
    // the handover, from which svcmgr mints real-logd's
    // `DEATH_EQ_AUTHORITY` cap (`services/init/docs/bootstrap.md`
    // § Per-stage authority transfers). Zero when procmgr has no procmgr
    // above it — e.g. procmgr itself, when init populates its
    // `ProcessInfo`.
    let procmgr_ep_in_child = if universals.procmgr_endpoint != 0
    {
        let badged = CapGuard::new(
            syscall::cap_derive_badge(
                universals.procmgr_endpoint,
                syscall::RIGHTS_EP_SEND_GRANT,
                process_badge,
            )
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?,
        );
        syscall::cap_copy(badged.cap(), child_cspace, syscall::RIGHTS_EP_SEND_GRANT)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?
    }
    else
    {
        0
    };

    // Badged SEND cap on the system log endpoint: derived from the
    // procmgr-held un-badged source cap with badge = child's process
    // badge. Child's std `_start` installs it via
    // `::log::install_badged_cap`; `seraph::log!` writes ride it
    // directly with no discovery roundtrip. Logd attributes the
    // writes by the kernel-delivered badge, which equals procmgr's
    // process badge, which is also the death-EQ correlator —
    // self-reconciliation across the three views.
    let log_send_in_child = if universals.log_send_source != 0
    {
        let proc_side = CapGuard::new(
            syscall::cap_derive_badge(
                universals.log_send_source,
                syscall::RIGHTS_EP_SEND,
                process_badge,
            )
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?,
        );
        syscall::cap_copy(proc_side.cap(), child_cspace, syscall::RIGHTS_EP_SEND)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?
    }
    else
    {
        0
    };

    // Mirror of the log_send derivation, for the system-wide service-
    // discovery handle. The badge carries only the child's process badge
    // — without `svcmgr_labels::PUBLISH_AUTHORITY` — so the cap answers
    // QUERY_ENDPOINT only; svcmgr rejects PUBLISH_ENDPOINT calls whose
    // badge lacks the verb-bit with `UNAUTHORIZED`. See
    // `docs/capability-model.md` "verb-bit authority pattern".
    let registry_send_in_child = if universals.registry_send_source != 0
    {
        let proc_side = CapGuard::new(
            syscall::cap_derive_badge(
                universals.registry_send_source,
                syscall::RIGHTS_EP_SEND,
                process_badge,
            )
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?,
        );
        syscall::cap_copy(proc_side.cap(), child_cspace, syscall::RIGHTS_EP_SEND)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?
    }
    else
    {
        0
    };

    // Stdio pipe caps are not installed here — CONFIGURE_PIPE remaps
    // this same pi_memory writable and fills in one direction's triple
    // (memory cap + data notification + space notification) per call, before the child
    // is started. Children that ship without any CONFIGURE_PIPE call
    // see all-zero stdio memory-cap/notification slots, which std maps to silent
    // println! / EOF on stdin.

    // Baseline SchedControl: the child's band `[1, sched.band_max]`.
    // Full-width bands are a plain copy of procmgr's baseline. Narrower
    // bands are minted copy-then-split: derive a private copy, split it at
    // `band_max + 1` (the split consumes only the invoked copy — procmgr's
    // baseline slot is untouched), hand the low child across, and drop
    // both procmgr-side pieces (the child's `cap_copy` holds its own
    // reference; the discarded high child never leaves procmgr).
    let sched_in_child = if universals.sched_baseline != 0
    {
        if sched.band_max >= ipc::sched_policy::BASELINE_PRIORITY_MAX
        {
            syscall::cap_copy(universals.sched_baseline, child_cspace, syscall::RIGHTS_ALL)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?
        }
        else
        {
            let own_copy = CapGuard::new(
                syscall::cap_derive(universals.sched_baseline, syscall::RIGHTS_ALL)
                    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?,
            );
            let (low, high) =
                syscall::sched_split(own_copy.cap(), sched.band_max.saturating_add(1))
                    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            // The split consumed `own_copy`; its two halves replace it.
            let _ = own_copy.disarm();
            let (low, _high) = (CapGuard::new(low), CapGuard::new(high));
            syscall::cap_copy(low.cap(), child_cspace, syscall::RIGHTS_ALL)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?
        }
    }
    else
    {
        0
    };

    // SAFETY: scratch_va is page-aligned and mapped writable.
    let pi = unsafe { process_abi::process_info_mut(scratch_va) };
    pi.version = PROCESS_ABI_VERSION;
    pi.self_thread_cap = child_thread_in_child;
    pi.self_aspace_cap = child_aspace_in_child;
    pi.self_cspace_cap = child_cspace_in_child;
    pi.sched_control_cap = sched_in_child;
    pi.initial_priority = sched.priority;
    pi.ipc_buffer_vaddr = layout.ipc_buffer_va;
    pi.creator_endpoint_cap = creator_ep_in_child;
    pi.procmgr_endpoint_cap = procmgr_ep_in_child;
    pi.memmgr_endpoint_cap = if universals.memmgr_endpoint != 0
    {
        // Plain `cap_copy` here is structurally safe — and
        // intentionally asymmetric with the
        // `cap_derive_badge(..., process_badge)` shape used for
        // `procmgr_endpoint_cap` just above. The reason:
        // `universals.memmgr_endpoint` is the per-child badged cap
        // memmgr minted in its `REGISTER_PROCESS` handler
        // `handle_register_process` (`services/memmgr/src/main.rs`) via
        // `cap_derive_badge(service_ep, SEND_GRANT, new_badge)`,
        // returned via IPC in `register_with_memmgr`
        // (`services/procmgr/src/main.rs`). The source is
        // already kernel-badged with a memmgr-private per-child
        // value; `cap_copy` propagates the badge to the child slot.
        // Children therefore cannot `sys_cap_derive_badge` to mint a
        // privileged twin on memmgr's endpoint (the `src_badge != 0`
        // rejection applies). SEND_GRANT lets the child grant onward;
        // no current protocol uses that, mirrored shape with
        // `procmgr_endpoint_cap`.
        syscall::cap_copy(
            universals.memmgr_endpoint,
            child_cspace,
            syscall::RIGHTS_EP_SEND_GRANT,
        )
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?
    }
    else
    {
        0
    };
    pi.stdin_memory_cap = 0;
    pi.stdout_memory_cap = 0;
    pi.stderr_memory_cap = 0;
    // System-root cap is installed at start_process time from the
    // per-process cap delivered via CONFIGURE_NAMESPACE. Defer the
    // copy so a child without an installed cap leaves the slot zero
    // and there is no inter-CSpace cap_delete primitive to clean up.
    pi.system_root_cap = 0;
    pi.current_dir_cap = 0;
    pi.log_send_cap = log_send_in_child;
    pi.service_registry_cap = registry_send_in_child;
    pi.stdin_data_notification_cap = 0;
    pi.stdin_space_notification_cap = 0;
    pi.stdout_data_notification_cap = 0;
    pi.stdout_space_notification_cap = 0;
    pi.stderr_data_notification_cap = 0;
    pi.stderr_space_notification_cap = 0;
    pi.tls_template_vaddr = tls.vaddr;
    pi.tls_template_filesz = tls.filesz;
    pi.tls_template_memsz = tls.memsz;
    pi.tls_template_align = tls.align;
    pi.stack_top_vaddr = layout.stack_top;
    pi.stack_pages = stack_pages;
    // TLS block base, or zero when the binary has no PT_TLS (mirrors
    // `tls_template_memsz == 0`); the block is mapped only in the TLS case.
    pi.main_tls_vaddr = if tls.memsz != 0 { layout.tls_base } else { 0 };
    // The pager fields stay zero here: `finalize_creation` writes them only
    // once the pager binding has taken effect (`advertise_pager`).

    // The argv blob, then the env blob, live in the argv/env region directly
    // after this page; the offsets locate them from the page base. An empty
    // blob is recorded as absent (offset, length and count zero).
    if argv_env.pages != 0
    {
        // SAFETY: the caller's contract: `child_aspace` is a child's address
        // space, never procmgr's own.
        unsafe {
            map_child_argv_env(
                child_aspace,
                universals.memmgr_endpoint,
                ipc_buf,
                &argv_env,
                layout,
            )
        }?;
    }
    let h = argv_env.header;
    (pi.args_offset, pi.args_bytes, pi.args_count) = if h.args_bytes == 0
    {
        (0, 0, 0)
    }
    else
    {
        (
            process_abi::ARGV_ENV_REGION_OFFSET,
            h.args_bytes,
            h.args_count,
        )
    };
    (pi.env_offset, pi.env_bytes, pi.env_count) = if h.env_bytes == 0
    {
        (0, 0, 0)
    }
    else
    {
        (
            // `check_argv_env` bounded the header's byte counts by `ARGV_ENV_MAX_BYTES`.
            process_abi::ARGV_ENV_REGION_OFFSET.saturating_add(h.args_bytes),
            h.env_bytes,
            h.env_count,
        )
    };

    drop(scratch);

    let pi_ro = CapGuard::new(
        syscall::cap_derive(pi_memory.cap(), syscall::RIGHTS_MEM_MAP)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?,
    );
    // SAFETY: the caller's contract: `child_aspace` is a child's address
    // space, never procmgr's own, so the map changes nothing procmgr runs on.
    unsafe {
        syscall::mem_map(
            pi_ro.cap(),
            child_aspace,
            layout.process_info_va,
            0,
            1,
            syscall::MAP_FROM_CAP,
        )
    }
    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    // pi_memory and argv_env_memory stay in procmgr's CSpace as the teardown
    // handles (revoke cascades to any descendants); the mappings don't need
    // the map-only derivations to outlive this call, so their guards delete
    // them on return.
    Ok(ChildInfoCaps {
        pi_memory,
        argv_env_memory: argv_env.memory,
        name: argv_env.name,
    })
}

/// Intermediate state returned by [`alloc_main_tls_memory`] — a memory cap
/// mapped writable in procmgr's aspace at `scratch.va()` plus the layout
/// numbers needed to populate it and to finalise the mapping into the
/// child.
///
/// The memory cap is guarded: dropping the struct before
/// [`finalize_main_tls`] succeeds unmaps the scratch view (`scratch` is
/// declared first, so it drops first) and deletes the cap.
struct MainTlsAlloc
{
    scratch: ScratchMapping,
    memory: CapGuard,
    tls_base_offset: u64,
    tls_base_va: u64,
    /// Mapped base VA of the TLS block (the chosen `layout.tls_base`); the block
    /// is mapped here and `tls_base_va = tls_block_base + tls_base_offset`.
    tls_block_base: u64,
    /// Pages the block spans, mapped at the scratch VA and then in the child.
    pages: u64,
}

impl MainTlsAlloc
{
    fn scratch_va(&self) -> u64
    {
        self.scratch.va()
    }

    /// Bytes mapped at the scratch VA: the whole block, page-rounded.
    fn scratch_bytes(&self) -> u64
    {
        // `pages` is at most `PROCESS_MAIN_TLS_MAX_PAGES`, checked at allocation.
        self.pages.saturating_mul(PAGE_SIZE)
    }
}

/// Allocate a memory cap for the main thread's TLS block, map it writable in
/// procmgr's own aspace at a transient scratch VA, and zero it.
///
/// The block spans the pages its `PT_TLS` memsz needs
/// ([`process_abi::tls_block_layout`]), from one contiguous Memory cap.
/// Callers write the `.tdata` template starting at the scratch VA and then
/// call [`finalize_main_tls`] to install the TCB self-pointer and remap the
/// memory cap into the child.
///
/// # Errors
/// `INVALID_ELF` when the binary has no TLS, when the block exceeds
/// `PROCESS_MAIN_TLS_MAX_PAGES` (the region the layout leaves after the TLS
/// draw), or when alignment demands would outrun the page mapping;
/// `OUT_OF_MEMORY` when memmgr cannot supply the pages; and
/// [`ScratchMapping::map`]'s code when the scratch mapping fails.
fn alloc_main_tls_memory(
    self_aspace: u64,
    tls: &ChildTlsTemplate,
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    layout: &ProcessLayout,
) -> Result<MainTlsAlloc, u64>
{
    let (block_size, block_align, tls_base_offset) =
        process_abi::tls_block_layout(tls.memsz, tls.align);

    let pages = block_size.div_ceil(PAGE_SIZE);
    if block_size == 0 || pages > PROCESS_MAIN_TLS_MAX_PAGES || block_align > PAGE_SIZE
    {
        return Err(procmgr_errors::INVALID_ELF);
    }

    let tls_memory = CapGuard::new(
        if pages == 1
        {
            crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)
                .ok_or(procmgr_errors::OUT_OF_MEMORY)?
        }
        else
        {
            crate::memmgr_alloc_pages_contig(child_memmgr_send, pages, ipc_buf)
                .ok_or(procmgr_errors::OUT_OF_MEMORY)?
        },
    );
    let scratch = ScratchMapping::map(self_aspace, tls_memory.cap(), pages, syscall::MAP_WRITABLE)?;
    let scratch_va = scratch.va();

    // SAFETY: scratch_va is mapped writable for `pages` pages.
    unsafe {
        core::ptr::write_bytes(
            scratch_va as *mut u8,
            0,
            // `pages` is at most `PROCESS_MAIN_TLS_MAX_PAGES`, checked above.
            pages.saturating_mul(PAGE_SIZE) as usize,
        );
    }

    // `tls_base_offset` is within the block, which `PROCESS_MAIN_TLS_MAX_PAGES` bounds.
    let Some(tls_base_va) = layout.tls_base.checked_add(tls_base_offset)
    else
    {
        return Err(procmgr_errors::INVALID_ELF);
    };

    Ok(MainTlsAlloc {
        scratch,
        memory: tls_memory,
        tls_base_offset,
        tls_base_va,
        tls_block_base: layout.tls_base,
        pages,
    })
}

/// Install the TCB self-pointer at `scratch_va + tls_base_offset`, drop
/// the scratch mapping from procmgr's aspace, derive an RW cap, and map
/// the block into the child at the chosen TLS block base.
///
/// # Errors
/// `procmgr_errors::INSUFFICIENT_RIGHTS` when the RW cap cannot be derived;
/// `procmgr_errors::MAP_FAILED` when the block cannot be mapped into the
/// child.
///
/// # Safety
/// `child_aspace` must name a child's address space, never procmgr's own:
/// the function maps pages into it, at VAs the child's layout chooses,
/// without checking what procmgr holds there.
unsafe fn finalize_main_tls(
    alloc: MainTlsAlloc,
    _self_aspace: u64,
    child_aspace: u64,
) -> Result<MainTls, u64>
{
    // SAFETY: scratch_va is mapped writable for the whole block, which holds
    // the TCB at `tls_base_offset`.
    unsafe {
        process_abi::tls_install_tcb(
            alloc.scratch_va() as *mut u8,
            alloc.tls_base_offset,
            alloc.tls_base_va,
        );
    }

    drop(alloc.scratch);

    let tls_rw = CapGuard::new(
        syscall::cap_derive(alloc.memory.cap(), syscall::RIGHTS_MEM_MAP_RW)
            .map_err(|_| procmgr_errors::INSUFFICIENT_RIGHTS)?,
    );
    // SAFETY: the caller's contract: `child_aspace` is a child's address
    // space, never procmgr's own, so the map changes nothing procmgr runs on.
    unsafe {
        syscall::mem_map(
            tls_rw.cap(),
            child_aspace,
            alloc.tls_block_base,
            0,
            alloc.pages,
            syscall::MAP_FROM_CAP,
        )
    }
    .map_err(|_| procmgr_errors::MAP_FAILED)?;
    // The memory cap stays as the teardown handle; tls_rw is transient and
    // its guard deletes it on return.
    Ok(MainTls {
        memory_cap: alloc.memory.disarm(),
        base_va: alloc.tls_base_va,
    })
}

/// Allocate, populate from an in-memory `.tdata` slice, and map the main
/// thread's TLS block. Wraps the two-phase helpers above for the
/// create-from-bytes path.
///
/// `relocate` runs over the populated template copy before the block is
/// finalized; PIE spawns re-apply the `.tdata`-targeting `RELATIVE`
/// relocations there (the in-image template copy is relocated separately
/// during segment loading).
///
/// # Errors
/// [`alloc_main_tls_memory`]'s codes; `INVALID_ELF` when the template is
/// larger than the block; [`finalize_main_tls`]'s when the block cannot be
/// mapped into the child.
///
/// # Safety
/// `child_aspace` must name a child's address space, never procmgr's own:
/// the function maps pages into it, at VAs the child's layout chooses,
/// without checking what procmgr holds there.
#[expect(
    clippy::too_many_arguments,
    reason = "each is a distinct creation input; see prepare_main_tls_from_vfs"
)]
unsafe fn prepare_main_tls_from_bytes(
    self_aspace: u64,
    child_aspace: u64,
    tls: &ChildTlsTemplate,
    template_bytes: &[u8],
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    layout: &ProcessLayout,
    relocate: impl FnOnce(&mut [u8]),
) -> Result<MainTls, u64>
{
    if tls.memsz == 0
    {
        return Ok(MainTls::default());
    }
    let alloc = alloc_main_tls_memory(self_aspace, tls, child_memmgr_send, ipc_buf, layout)?;
    if template_bytes.len() as u64 > alloc.scratch_bytes()
    {
        return Err(procmgr_errors::INVALID_ELF);
    }
    let scratch_va = alloc.scratch_va();
    // SAFETY: scratch_va is mapped writable; length was bounded above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            template_bytes.as_ptr(),
            scratch_va as *mut u8,
            template_bytes.len(),
        );
    }
    // SAFETY: the template region [0, len) was just populated and stays
    // mapped writable until finalize drops the scratch mapping.
    let template =
        unsafe { core::slice::from_raw_parts_mut(scratch_va as *mut u8, template_bytes.len()) };
    relocate(template);
    // SAFETY: the caller's contract covers `child_aspace`.
    unsafe { finalize_main_tls(alloc, self_aspace, child_aspace) }
}

/// Allocate, populate by streaming `.tdata` from an open VFS file handle,
/// and map the main thread's TLS block.
///
/// `relocate` runs over the streamed template copy before the block is
/// finalized; see [`prepare_main_tls_from_bytes`].
///
/// # Errors
/// [`alloc_main_tls_memory`]'s codes; `INVALID_ELF` when the template's file
/// size is larger than the block; `IO_ERROR` when the template's bytes do not
/// all arrive; [`finalize_main_tls`]'s when the block cannot be mapped into
/// the child.
///
/// # Safety
/// `child_aspace` must name a child's address space, never procmgr's own:
/// the function maps pages into it, at VAs the child's layout chooses,
/// without checking what procmgr holds there.
#[expect(
    clippy::too_many_arguments,
    reason = "each is a distinct creation input (caps, file handle, IPC scratch, chosen layout); \
              grouping them would not reduce coupling"
)]
unsafe fn prepare_main_tls_from_vfs(
    self_aspace: u64,
    child_aspace: u64,
    tls: &ChildTlsTemplate,
    file_offset: u64,
    file_cap: u64,
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    layout: &ProcessLayout,
    relocate: impl FnOnce(&mut [u8]),
) -> Result<MainTls, u64>
{
    if tls.memsz == 0
    {
        return Ok(MainTls::default());
    }
    let alloc = alloc_main_tls_memory(self_aspace, tls, child_memmgr_send, ipc_buf, layout)?;
    if tls.filesz > alloc.scratch_bytes()
    {
        return Err(procmgr_errors::INVALID_ELF);
    }
    let scratch_va = alloc.scratch_va();

    // SAFETY: scratch_va is mapped writable for the whole block and
    // `tls.filesz` fits it (checked above); the mapping stays until
    // finalize drops it, after the last use of `template`.
    let template =
        unsafe { core::slice::from_raw_parts_mut(scratch_va as *mut u8, tls.filesz as usize) };
    // `vfs_read_exact` clamps every reply to the bytes it asked for, so an
    // fs driver over-reporting `bytes_read` cannot stretch a copy past the
    // template; a short template (end of file) fails the spawn.
    if vfs_read_exact(file_cap, ipc_buf, file_offset, template).ok_or(procmgr_errors::IO_ERROR)?
        != template.len()
    {
        return Err(procmgr_errors::IO_ERROR);
    }
    relocate(template);
    // SAFETY: the caller's contract covers `child_aspace`.
    unsafe { finalize_main_tls(alloc, self_aspace, child_aspace) }
}

/// Map stack and IPC buffer pages into a child address space.
///
/// No explicit guard-page map. The page immediately below the stack
/// (`layout.stack_top - stack_pages * PAGE_SIZE - PAGE_SIZE`) stays unmapped by
/// construction — `process-layout` chooses disjoint VAs for the stack and the
/// other bootstrap surfaces so the gap is always present. Stack overflow faults
/// on the guard VA instead of silently writing into adjacent mappings.
///
/// # Errors
/// [`map_fresh_child_page`]'s, for the first page that fails.
///
/// # Safety
/// `child_aspace` must name a child's address space, never procmgr's own:
/// the function maps pages into it, at VAs the child's layout chooses,
/// without checking what procmgr holds there.
unsafe fn map_child_stack_and_ipc(
    child_aspace: u64,
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    stack_pages: u32,
    layout: &ProcessLayout,
) -> Result<(), u64>
{
    let Some(stack_base) = u64::from(stack_pages)
        .checked_mul(PAGE_SIZE)
        .and_then(|bytes| layout.stack_top.checked_sub(bytes))
    else
    {
        return Err(procmgr_errors::MAP_FAILED);
    };
    for i in 0..stack_pages
    {
        // SAFETY: the caller's contract covers `child_aspace`.
        unsafe {
            map_fresh_child_page(
                child_aspace,
                child_memmgr_send,
                ipc_buf,
                // `i` is below `stack_pages`, so the page lies inside the stack
                // span whose base was checked above.
                stack_base.saturating_add(u64::from(i).saturating_mul(PAGE_SIZE)),
            )
        }?;
    }
    // SAFETY: the caller's contract covers `child_aspace`.
    unsafe {
        map_fresh_child_page(
            child_aspace,
            child_memmgr_send,
            ipc_buf,
            layout.ipc_buffer_va,
        )
    }
}

/// Allocate one child-billed page and map it read-write into the child at
/// `va`. procmgr's transient slots are dropped on every path: the mapping
/// owns no cap reference, and memmgr's record pins the page until
/// `PROCESS_DIED`.
///
/// # Errors
/// `procmgr_errors::OUT_OF_MEMORY` when memmgr grants no page;
/// `procmgr_errors::INSUFFICIENT_RIGHTS` when its RW cap cannot be derived;
/// `procmgr_errors::MAP_FAILED` when it cannot be mapped into the child.
///
/// # Safety
/// `child_aspace` must name a child's address space, never procmgr's own:
/// the function maps pages into it, at VAs the child's layout chooses,
/// without checking what procmgr holds there.
unsafe fn map_fresh_child_page(
    child_aspace: u64,
    child_memmgr_send: u64,
    ipc_buf: *mut u64,
    va: u64,
) -> Result<(), u64>
{
    let memory = CapGuard::new(
        crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?,
    );
    let rw = CapGuard::new(
        syscall::cap_derive(memory.cap(), syscall::RIGHTS_MEM_MAP_RW)
            .map_err(|_| procmgr_errors::INSUFFICIENT_RIGHTS)?,
    );
    // SAFETY: the caller's contract: `child_aspace` is a child's address
    // space, never procmgr's own, so the map changes nothing procmgr runs on.
    unsafe { syscall::mem_map(rw.cap(), child_aspace, va, 0, 1, syscall::MAP_FROM_CAP) }
        .map_err(|_| procmgr_errors::MAP_FAILED)
}

/// Determine protection flags for an ELF segment.
fn segment_prot(seg: &elf::LoadSegment) -> u64
{
    if seg.executable
    {
        syscall::MAP_EXECUTABLE
    }
    else if seg.writable
    {
        syscall::MAP_WRITABLE
    }
    else
    {
        syscall::MAP_READ
    }
}

// ── RELATIVE relocation application (ET_DYN, #39) ────────────────────────────
//
// Span validation and application live in `shared/elf`
// (`validate_relative_relocs` / `apply_relative_relocs` /
// `apply_reloc_in_span`); this section adds only the VFS-streaming walk the
// create-from-file path needs.

/// Number of `Elf64_Rela` records fetched per streaming chunk. A batch size
/// that bounds no table: `walk_relocs_streaming` loops until `DT_RELASZ` is
/// consumed.
const RELA_CHUNK_RECORDS: usize = 128;

/// Stream a rela table in bounded chunks, invoking `f` on every decoded
/// record. Returns the record count; `None` on a failed/short read or a
/// record that is not a well-formed `RELATIVE` relocation.
///
/// Chunks stay record-aligned: the buffer size and `DT_RELASZ` are both
/// multiples of [`elf::RELA_ENTRY_SIZE`].
fn walk_relocs_streaming<R, F>(
    table: &elf::RelaTable,
    machine: u16,
    mut read_at: R,
    mut f: F,
) -> Option<u64>
where
    R: FnMut(u64, &mut [u8]) -> Option<usize>,
    F: FnMut(&elf::Rela),
{
    let mut buf = [0u8; elf::RELA_ENTRY_SIZE * RELA_CHUNK_RECORDS];
    let mut done: u64 = 0;
    let mut count = 0u64;
    while done < table.size
    {
        // The loop condition keeps `done` below `table.size`.
        let chunk = table.size.saturating_sub(done).min(buf.len() as u64) as usize;
        // A file offset past the address space is a failed read.
        let read_offset = table.file_offset.checked_add(done)?;
        // `chunk` is at most `buf.len()`, so the slice is always present.
        let got = read_at(read_offset, buf.get_mut(..chunk)?)?;
        if got < chunk
        {
            return None;
        }
        for record in elf::relative_relocs(buf.get(..chunk)?, machine).ok()?
        {
            f(&record.ok()?);
            // `count` is at most the table's record count.
            count = count.saturating_add(1);
        }
        // `chunk` is at most `table.size - done`.
        done = done.saturating_add(chunk as u64);
    }
    Some(count)
}

/// Fill `dst` from file offset `off` via bounded `FS_READ` chunks. Returns
/// the number of bytes copied (short only at EOF), or `None` when a read
/// fails.
///
/// A single `FS_READ` may return fewer bytes than asked — fatfs stops at
/// sector boundaries — so short reads continue the loop; only a zero read
/// (end of file) stops it. Every reply is clamped to the bytes requested
/// ([`process_table::fs_reads::fill_exact`]), so a driver over-reporting its
/// count cannot make procmgr copy past `dst`.
fn vfs_read_exact(file_cap: u64, ipc_buf: *mut u64, off: u64, dst: &mut [u8]) -> Option<usize>
{
    process_table::fs_reads::fill_exact(dst, off, VFS_CHUNK_SIZE as usize, |at, window| {
        vfs_read(file_cap, ipc_buf, at, window.len() as u64, window)
    })
}

/// Derive caller-facing caps, wire the child's pager and crash binding, and
/// record the process in the table.
///
/// The entry is inserted last, under the table lock, so a request served on
/// another worker never finds a child whose wiring is still in progress; the
/// pager's delegation, an IPC call to memmgr, runs with no lock held. Only
/// the death relay's bind follows the insertion.
///
/// # Errors
/// `procmgr_errors::OUT_OF_MEMORY` when a death observer cannot be bound,
/// a caller-facing cap cannot be derived, or the table cannot grow: each is
/// procmgr's own memory or slots running out.
#[expect(
    clippy::similar_names,
    reason = "child_aspace/child_cspace are intentionally parallel"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "grouping these into a struct would add complexity without reducing call sites — this \
              helper is called from exactly two places"
)]
fn finalize_creation(
    child_aspace: u64,
    child_cspace: u64,
    child_thread: u64,
    info_caps: &ChildInfoCaps,
    entry_point: u64,
    main_tls: MainTls,
    tables: &Tables,
    self_endpoint: u64,
    deaths: &Mutex<DeathSet>,
    memmgr_send_cap: u64,
    memmgr_badge: u64,
    process_badge: u64,
    paging: Paging,
    self_memmgr_ep: u64,
    parent_relay_cap: u64,
    band_max: u8,
    image: ImageSpan,
    ipc_buf: *mut u64,
    layout: &ProcessLayout,
    self_aspace: u64,
) -> Result<CreateResult, u64>
{
    let badge = process_badge;
    let pi_memory_cap = info_caps.pi_memory.cap();

    // Bind a death observer from procmgr's death queues on the child's main
    // thread. Correlator = the table badge; on death, dispatch_death recovers
    // the entry via `take_by_badge`. A pool that runs out is followed by a
    // further queue, so a failure here is procmgr's memory running out.
    let bound = crate::lock(deaths).bind_thread(child_thread, badge);
    if let Err(e) = bound
    {
        std::os::seraph::log!(warn: "main-thread death bind failed (err={e}); spawn refused");
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }

    // Also bind an address-space observer with the SAME correlator, so a
    // terminal fault in a *spawned* (non-main) thread — which the main-thread
    // binding above does not cover — still routes into `dispatch_death` →
    // `take_by_badge` → teardown. On a main-thread fault both observers fire
    // with the same correlator and `take_by_badge` reaps exactly once (the
    // second event is a stale-correlator no-op). Without it a worker
    // thread's fault would never reap the process, so its failure refuses
    // the spawn; the caller's guards destroy the child, which returns the
    // main-thread observer's node.
    let bound = crate::lock(deaths).bind_aspace(child_aspace, badge);
    if let Err(e) = bound
    {
        std::os::seraph::log!(warn: "address-space death bind failed (err={e}); spawn refused");
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }

    // Derive the process handle, a badged endpoint cap for the caller. The
    // badge names this process on its later START_PROCESS, CONFIGURE_*,
    // QUERY_PROCESS, and DESTROY_PROCESS calls; the handle tag tells it from
    // the child's own procmgr cap, so DECLARE_NO_DEBUG and REGISTER_THREAD,
    // which name their sender, are refused on it
    // (`process_table::served_on_handle`).
    let process_handle = syscall::cap_derive_badge(
        self_endpoint,
        syscall::RIGHTS_EP_SEND_GRANT,
        badge | ipc::procmgr_labels::PROCESS_HANDLE_TAG,
    )
    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let Ok(thread_for_caller) = syscall::cap_derive(child_thread, syscall::RIGHTS_THREAD)
    else
    {
        let _ = syscall::cap_delete(process_handle);
        return Err(procmgr_errors::OUT_OF_MEMORY);
    };

    // Demand-paged wiring (best-effort): delegate the child address space to
    // memmgr and bind the main thread's fault handler to it, then advertise
    // the pager in `ProcessInfo`. A failure at any step degrades to "no
    // pager" (the child keeps its memory eager) rather than failing an
    // otherwise-complete creation; the advertisement is written last, so the
    // page never names a pager the child does not have. Which processes are
    // exempt from the default pager is in docs/fault-handling.md § Default
    // System Pager.
    if paging == Paging::Demand
        && memmgr_send_cap != 0
        && self_memmgr_ep != 0
        && bind_pager(
            child_aspace,
            child_thread,
            memmgr_send_cap,
            memmgr_badge,
            self_memmgr_ep,
            ipc_buf,
        )
    {
        advertise_pager(self_aspace, pi_memory_cap, memmgr_badge);
    }
    bind_crash_endpoint(child_thread, badge);

    let inserted = tables.lock().table.insert(ProcessEntry {
        badge,
        aspace_cap: child_aspace,
        cspace_cap: child_cspace,
        thread_cap: child_thread,
        pi_memory_cap,
        tls_memory_cap: main_tls.memory_cap,
        argv_env_memory_cap: info_caps.argv_env_memory.cap(),
        memmgr_send_cap,
        memmgr_badge,
        namespace_override: 0,
        cwd_override: 0,
        band_max,
        entry_point,
        tls_base_va: main_tls.base_va,
        stack_top_vaddr: layout.stack_top,
        process_info_va: layout.process_info_va,
        started: false,
        dma_hold: false,
        no_debug: false,
        image,
        threads: process_table::ThreadRegistry::new(),
        name: info_caps.name,
        debugger: 0,
    });
    if inserted.is_err()
    {
        // Heap exhausted (the badge was reserved when it was minted, so no
        // other entry holds it): drop the caps we minted for the caller; the caller's
        // guards still own the child kernel objects and per-child memory caps
        // and will release them when finalize returns an error.
        let _ = syscall::cap_delete(thread_for_caller);
        let _ = syscall::cap_delete(process_handle);
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }

    // If the spawner supplied a death-relay POST cap, bind it as a second
    // address-space observer (correlator 0) so a terminal fault in any child
    // thread posts the fault class straight to the spawner's death queue and
    // `Child::wait()` returns. The kernel captures the EventQueue state at
    // bind time, so procmgr drops its copy afterwards (mirrors how the
    // main-thread death binding leaves no procmgr-side ownership concern).
    // Consumed only here, after the last failure return, so on every `Err`
    // the caller still owns the cap and releases it.
    if parent_relay_cap != 0
    {
        if let Err(e) = syscall::aspace_bind_notification(child_aspace, parent_relay_cap, 0)
        {
            // The creation is complete; the spawner's own main-thread
            // observer still reports the child's exit.
            std::os::seraph::log!(
                warn: "death-relay bind failed (err={e}); a worker-thread fault will not reach the spawner"
            );
        }
        let _ = syscall::cap_delete(parent_relay_cap);
    }

    Ok(CreateResult {
        process_handle,
        thread_for_caller,
        badge,
    })
}

/// Bind a child's main thread's exception class to the crash endpoint
/// (`crate::crash`), badged with the child's process badge, so its
/// exceptions, and the virtual-memory faults memmgr forwards, reach the crash
/// service, or procmgr's decliner while none is registered. The runtime
/// copies the binding onto every thread the child spawns. Best-effort: a
/// failure, logged, leaves the class unbound, and an exception then takes the
/// outcome it has with no handler.
fn bind_crash_endpoint(child_thread: u64, badge: u64)
{
    if crate::crash::endpoint() != 0 && !bind_exception_class(child_thread, badge)
    {
        std::os::seraph::log!(warn: "crash endpoint not bound; exceptions stay unbound");
    }
}

/// Bind `thread`'s exception class to the crash endpoint under `badge`.
/// Returns whether the binding took effect; with no crash endpoint it never
/// does.
fn bind_exception_class(thread: u64, badge: u64) -> bool
{
    let ep = crate::crash::endpoint();
    if ep == 0
    {
        return false;
    }
    let Ok(badged) = syscall::cap_derive_badge(ep, syscall::RIGHTS_EP_SEND, badge)
    else
    {
        return false;
    };
    let bound = syscall::thread_set_fault_handler(thread, badged, FAULT_CLASS_EXCEPTION).is_ok();
    // The binding holds its own reference on the endpoint; procmgr needs no
    // copy of the badged cap.
    let _ = syscall::cap_delete(badged);
    bound
}

// ── Thread registry ─────────────────────────────────────────────────────────

/// Register the thread `thread_cap` names with the process the request's
/// `badge` names (`REGISTER_THREAD`), consuming the cap on success.
///
/// The cap must be a Thread cap with `RIGHTS_THREAD`. A registry whose sweep
/// is due (`ThreadRegistry::needs_sweep`: its sweep count, or the bound, and
/// enough requests since the last sweep) first drops the threads that are
/// gone ([`thread_is_listed`]). A thread whose exception class is bound under the
/// sender's process badge or a crash badge (`ProcessEntry::is_crash_binding`), as one
/// that copied its spawner's bindings is, or under a debugger's badge while
/// the process has no debugger watched, as one that copied a debugger's
/// binding is once that debugger has gone (`ProcessEntry::rebinds_on_register`),
/// is bound again under a fresh crash badge, so its faults name it, and,
/// with no debugger watched, a debugger's upcall binding on it is unbound; a
/// binding under any other badge, a watched debugger's, or none, is left as
/// it is. The binding is told by its badge alone, which is all
/// `SYS_THREAD_GET_FAULT_HANDLER` returns, so a debugger binds under
/// `procmgr_labels::DEBUGGER_BADGE_TAG`
/// (`services/procmgr/docs/ipc-interface.md` § `REGISTER_THREAD`). The entry
/// records whose thread the binding showed before any rebind, carried
/// through a thread procmgr already lists under that binding
/// (`ProcessTable::origin_of`), which decides what a restore binds back. A
/// thread refused at the bound or for the heap runs unregistered, so a
/// debugger's binding on it is taken back then, under the process badge; one
/// refused because its process declared itself undebuggable is unbound as
/// the declaration unbinds its threads.
///
/// # Errors
/// The reply code: `INVALID_BADGE` when no live process carries `badge`,
/// `NOT_ATTACHABLE` when it declared itself undebuggable,
/// `INVALID_ARGUMENT` when the cap is not a Thread cap with `RIGHTS_THREAD`,
/// `THREAD_LIMIT` at `procmgr_labels::REGISTERED_THREADS_MAX`, and
/// `OUT_OF_MEMORY` when the heap cannot hold the entry. The caller deletes
/// the cap on every error.
pub fn register_thread(badge: u64, thread_cap: u64, table: &mut ProcessTable) -> Result<(), u64>
{
    // A crash badge the thread copied from a spawner that has exited, and
    // that a sweep dropped, is still procmgr's: the tag tells it. A cap that
    // is not a Thread cap reads unbound and is refused below.
    let current = binding(thread_cap, FAULT_CLASS_EXCEPTION);
    // Whose thread it is, as its binding shows now, before procmgr rebinds
    // it: a restore reads it (`ProcessTable::restore_action`).
    let origin = table.origin_of(badge, current);
    let entry = match process_table::register_target(table, badge)
    {
        Ok(entry) => entry,
        Err(process_table::AttachRefusal::NotAttachable) =>
        {
            // A thread spawned before its process declared copied a binding
            // procmgr or a debugger made: unbind it as the declaration did.
            if is_full_thread_cap(thread_cap)
                && let Some(entry) = table.find_by_badge(badge)
            {
                unbind_declared(entry, thread_cap);
            }
            return Err(procmgr_errors::NOT_ATTACHABLE);
        }
        Err(_) => return Err(procmgr_errors::INVALID_BADGE),
    };
    if !is_full_thread_cap(thread_cap)
    {
        return Err(procmgr_errors::INVALID_ARGUMENT);
    }
    let rebind = entry.rebinds_on_register(current);
    // With no debugger watched, a debugger's upcall binding the thread
    // copied is a gone debugger's too.
    let unwatched = entry.debugger == 0;
    if entry.threads.needs_sweep()
    {
        entry
            .threads
            .sweep(|t| thread_is_listed(t.cap), release_registered_thread);
    }
    if let Err(r) = entry.threads.reserve()
    {
        // The thread runs unregistered, so no attach lists it and no restore
        // reaches it later: a debugger's binding it copied, a watched one's
        // too, goes back to the crash endpoint under the process badge,
        // which its faults then carry.
        if current.is_some_and(process_table::is_debugger_badge)
        {
            if !bind_exception_class(thread_cap, badge)
            {
                std::os::seraph::log!(warn: "crash binding of a refused thread not restored");
            }
            release_debugger_upcall(thread_cap);
        }
        return Err(match r
        {
            process_table::RegisterRefusal::Limit => procmgr_errors::THREAD_LIMIT,
            process_table::RegisterRefusal::OutOfMemory => procmgr_errors::OUT_OF_MEMORY,
        });
    }
    let crash_badge = if rebind { table.mint_crash_badge() } else { 0 };
    let bound = crash_badge != 0 && bind_exception_class(thread_cap, crash_badge);
    if bound && unwatched
    {
        release_debugger_upcall(thread_cap);
    }
    let entry = table
        .find_mut_by_badge(badge)
        .ok_or(procmgr_errors::INVALID_BADGE)?;
    entry.threads.push(process_table::RegisteredThread::new(
        thread_cap,
        if bound { crash_badge } else { 0 },
        origin,
    ));
    Ok(())
}

/// Whether `cap` is a Thread cap carrying every right of `RIGHTS_THREAD`:
/// the rights `ATTACH_PROCESS` hands out.
fn is_full_thread_cap(cap: u64) -> bool
{
    if cap == 0 || syscall::cap_info(cap, syscall_abi::CAP_INFO_THREAD_STATE).is_err()
    {
        return false;
    }
    syscall::cap_info(cap, syscall_abi::CAP_INFO_TAG_RIGHTS).is_ok_and(|packed| {
        let rights = packed & 0xFFFF_FFFF;
        rights & syscall_abi::RIGHTS_THREAD == syscall_abi::RIGHTS_THREAD
    })
}

/// Whether a registered thread's cap still names a thread that has not
/// exited: the runtime's revocation at its reclaim (or any other) leaves the
/// slot stale, and an exited thread is no longer listed.
pub fn thread_is_listed(cap: u64) -> bool
{
    syscall::cap_info(cap, syscall_abi::CAP_INFO_THREAD_STATE)
        .is_ok_and(|packed| (packed >> 32) as u32 != syscall_abi::THREAD_STATE_EXITED)
}

/// Release one registered thread: revoke the caps `ATTACH_PROCESS` derived
/// from procmgr's, then delete procmgr's. A slot the runtime already revoked
/// fails both calls harmlessly, its handle's generation being stale.
pub fn release_registered_thread(thread: process_table::RegisteredThread)
{
    let _ = syscall::cap_revoke_all(thread.cap);
    let _ = syscall::cap_delete(thread.cap);
}

/// Bind the process `badge` names back to the crash endpoint after a
/// debugger's attach (`DETACH_PROCESS`, or the attached debugger's death),
/// and release the debugger watch. The main thread is bound again under its
/// process badge when its exception class is unbound, or bound by a debugger
/// or by procmgr under another badge (`ProcessEntry::restores`). Each
/// registered thread takes the action `ProcessTable::restore_action` names
/// by the origin its registration recorded: one recorded as the process's
/// own is bound again under its crash badge, minted for one that has none,
/// when the main thread's rule would bind it; any other, one left under
/// another process's badge included, is never bound to the crash endpoint,
/// a debugger's binding on it unbound. Each upcall class a debugger bound is
/// unbound, so no thread stays bound to a dead debugger's endpoint. A thread
/// whose bind fails keeps the binding it has, as does every thread that
/// needs a fresh crash badge when procmgr's heap cannot hold them. A
/// declared process (`DECLARE_NO_DEBUG`) is never bound back, and a badge
/// naming no live process changes nothing.
pub fn restore_crash_bindings(table: &mut ProcessTable, badge: u64)
{
    let Some(entry) = table.find_mut_by_badge(badge)
    else
    {
        return;
    };
    let watch = core::mem::take(&mut entry.debugger);
    if watch != 0
    {
        let _ = syscall::cap_delete(watch);
    }
    if entry.no_debug
    {
        return;
    }
    // Out of the entry while it is walked: the rule reads the table.
    let mut threads = core::mem::take(&mut entry.threads);
    let action = |table: &ProcessTable, t: &process_table::RegisteredThread| {
        table.restore_action(badge, t, binding(t.cap, FAULT_CLASS_EXCEPTION))
    };
    let unbadged = (0..threads.len())
        .filter_map(|i| threads.get(i))
        .filter(|t| action(table, t) == process_table::RestoreAction::Bind(0))
        .count();
    let mut fresh: Vec<u64> = Vec::new();
    if fresh.try_reserve_exact(unbadged).is_ok()
    {
        for _ in 0..unbadged
        {
            fresh.push(table.mint_crash_badge());
        }
    }
    else
    {
        std::os::seraph::log!(warn: "no heap for crash badges; threads without one keep their binding");
    }
    for t in threads.iter_mut()
    {
        match action(table, &*t)
        {
            process_table::RestoreAction::Bind(under) =>
            {
                let under = match under
                {
                    0 => fresh.pop().unwrap_or(0),
                    b => b,
                };
                if under != 0 && bind_exception_class(t.cap, under)
                {
                    t.crash_badge = under;
                }
            }
            process_table::RestoreAction::Unbind =>
            {
                let _ = syscall::thread_set_fault_handler(t.cap, 0, FAULT_CLASS_EXCEPTION);
            }
            process_table::RestoreAction::Leave => (),
        }
        release_debugger_upcall(t.cap);
    }
    let Some(entry) = table.find_mut_by_badge(badge)
    else
    {
        // Nothing above removes the entry; were it gone, its threads' caps
        // are released as its teardown would have.
        threads
            .take_all()
            .into_iter()
            .for_each(release_registered_thread);
        return;
    };
    entry.threads = threads;
    if entry.restores(
        binding(entry.thread_cap, FAULT_CLASS_EXCEPTION),
        entry.badge,
    ) && !bind_exception_class(entry.thread_cap, entry.badge)
    {
        std::os::seraph::log!(warn: "crash binding of a detached main thread not restored");
    }
    release_debugger_upcall(entry.thread_cap);
}

/// Restore the crash bindings of every process whose attached debugger
/// (`ATTACH_PROCESS` `caps[0]`) is gone: its thread exited, or its cap went
/// with its process's teardown. procmgr's reaper calls it on every pass,
/// which a process's death, the debugger's among them, wakes; a request
/// worker calls it before it serves each request, since a watch thread other
/// than its process's main thread posts no death when it exits; and the
/// worker that serves a `DESTROY_PROCESS` calls it after the teardown. Each
/// caller holds the table lock, and logs a line for each process restored,
/// whose count this returns, once it releases the lock.
#[must_use]
pub fn check_debuggers(table: &mut ProcessTable) -> usize
{
    let mut gone: Vec<u64> = Vec::new();
    table.for_each(|e| {
        if e.debugger != 0 && !thread_is_listed(e.debugger) && gone.try_reserve(1).is_ok()
        {
            gone.push(e.badge);
        }
    });
    for &badge in &gone
    {
        restore_crash_bindings(table, badge);
    }
    gone.len()
}

/// Keep `watch`, the main-thread cap of the debugger an `ATTACH_PROCESS`
/// carried (`0`: none), as the watch of `entry`, the attach's target, across
/// `reply`, which sends the attach's reply and returns whether it was
/// delivered; returns that. The watch is held before the reply is sent
/// (`ProcessEntry::watch_across_reply`): a debugger can bind the target's
/// threads and die as soon as it has its reply, and a watch kept only after
/// the reply could find the debugger's cap already revoked, take it for no
/// Thread cap, and keep none, so no check would restore the bindings. A
/// delivered reply deletes the watch it replaced; a failed one deletes the
/// new watch and keeps the earlier. A cap that is not a Thread cap is deleted
/// before the reply, and no watch is kept. The caller holds the table lock
/// throughout, so no check sees the watch of an attach whose reply then
/// fails.
pub fn watch_debugger(entry: &mut ProcessEntry, watch: u64, reply: impl FnOnce() -> bool) -> bool
{
    let thread = if watch != 0
        && syscall::cap_info(watch, syscall_abi::CAP_INFO_THREAD_STATE).is_err()
    {
        let _ = syscall::cap_delete(watch);
        0
    }
    else
    {
        watch
    };
    let outcome = entry.watch_across_reply(thread, |_| reply());
    if outcome.stale != 0
    {
        let _ = syscall::cap_delete(outcome.stale);
    }
    outcome.delivered
}

/// Unbind `thread`, a thread of the declared process `entry`
/// (`DECLARE_NO_DEBUG`), from procmgr and from any debugger: its exception
/// class when procmgr or a debugger bound it (`ProcessEntry::declare_unbinds`),
/// and its upcall class when a debugger bound it. A handler the process bound
/// itself stays.
pub fn unbind_declared(entry: &ProcessEntry, thread: u64)
{
    if entry.declare_unbinds(binding(thread, FAULT_CLASS_EXCEPTION))
    {
        let _ = syscall::thread_set_fault_handler(thread, 0, FAULT_CLASS_EXCEPTION);
    }
    release_debugger_upcall(thread);
}

/// The badge `thread`'s `class` is bound under; `None` when it is unbound or
/// the binding cannot be read.
fn binding(thread: u64, class: u64) -> Option<u64>
{
    syscall::thread_get_fault_handler(thread, class)
        .ok()
        .flatten()
}

/// Unbind `thread`'s upcall class when a debugger bound it
/// (`process_table::is_debugger_badge`): a debugger that is gone, or whose
/// target procmgr takes back, leaves no thread bound to an endpoint it no
/// longer receives on. A pending upcall is then dropped and the thread
/// resumes (docs/fault-handling.md § Asynchronous Upcalls).
fn release_debugger_upcall(thread: u64)
{
    if binding(thread, FAULT_CLASS_UPCALL).is_some_and(process_table::is_debugger_badge)
    {
        let _ = syscall::thread_set_fault_handler(thread, 0, FAULT_CLASS_UPCALL);
    }
}

/// Delegate a child's address space to memmgr and bind its main thread's
/// fault handler to `memmgr_send_cap`. Returns `true` only when both took
/// effect, so the child's demand faults reach a pager that can map them.
fn bind_pager(
    child_aspace: u64,
    child_thread: u64,
    memmgr_send_cap: u64,
    memmgr_badge: u64,
    self_memmgr_ep: u64,
    ipc_buf: *mut u64,
) -> bool
{
    // Hand memmgr its own copy of the child AS, keyed by the child's memmgr
    // badge, over procmgr's (procmgr-badged) endpoint so it lands on the
    // privileged DELEGATE_ASPACE tier. procmgr keeps `child_aspace`. Mask out
    // CONTROL: memmgr only maps pages into the AS; the authority to register
    // terminal-fault death observers stays with procmgr (the creator), which
    // holds the CONTROL-bearing `child_aspace`.
    let Ok(as_copy) = syscall::cap_derive(
        child_aspace,
        syscall::RIGHTS_ALL & !syscall::RIGHTS_AS_CONTROL,
    )
    else
    {
        return false;
    };
    let msg = IpcMessage::builder(memmgr_labels::DELEGATE_ASPACE)
        .word(0, memmgr_badge)
        .cap(as_copy)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let delegated = unsafe { ipc::ipc_call(self_memmgr_ep, &msg, ipc_buf) }
        .is_ok_and(|r| r.label == memmgr_errors::SUCCESS);
    if !delegated
    {
        // Call failed or memmgr declined: drop the copy if the IPC did not
        // transfer it (deleting an already-moved slot is harmless).
        let _ = syscall::cap_delete(as_copy);
        return false;
    }
    // Bind only after the AS is delegated, so memmgr can service the first
    // fault. The kernel stamps each fault with the derivation badge of
    // memmgr_send_cap, which memmgr minted as the child's memmgr badge. The
    // virtual-memory class alone: memmgr forwards the faults it cannot back
    // to the exception class, which `bind_crash_endpoint` binds, and is no
    // upcall handler, so the upcall class stays unbound and a post to the
    // child's thread is refused.
    syscall::thread_set_fault_handler(child_thread, memmgr_send_cap, FAULT_CLASS_VM).is_ok()
}

/// Advertise the pager in a child's `ProcessInfo` (still writable through
/// `pi_memory_cap` until the child starts), so the runtime knows the process is
/// demand-paged and backs its heap floor on demand; the runtime copies the main
/// thread's binding onto the threads it spawns
/// (`SYS_THREAD_INHERIT_FAULT_HANDLER`). The child's badged memmgr endpoint is
/// the pager endpoint: the kernel stamps each fault with that cap's derivation
/// badge, `memmgr_badge`, so the fault is attributed to the right memmgr
/// record, and `pager_badge` records the same value for the runtime's
/// information. When the page cannot be mapped the fields stay zero and the
/// child runs as if it had no pager, which is safe: its memory stays eager.
fn advertise_pager(self_aspace: u64, pi_memory_cap: u64, memmgr_badge: u64)
{
    let Ok(scratch) = ScratchMapping::map(self_aspace, pi_memory_cap, 1, syscall::MAP_WRITABLE)
    else
    {
        return;
    };
    // SAFETY: the scratch mapping is the child's ProcessInfo page, mapped
    // writable for one page; the struct lives at offset 0 per the ABI.
    let pi = unsafe { process_abi::process_info_mut(scratch.va()) };
    pi.pager_endpoint_cap = pi.memmgr_endpoint_cap;
    pi.pager_badge = memmgr_badge;
}

// ── Process creation (from memory) ──────────────────────────────────────────

/// The `len` bytes of `bytes` at `offset`, or `None` when the range overflows or
/// leaves the slice.
fn file_range(bytes: &[u8], offset: u64, len: u64) -> Option<&[u8]>
{
    let end = offset.checked_add(len)?;
    bytes.get(usize::try_from(offset).ok()?..usize::try_from(end).ok()?)
}

/// The page-rounded `[start, end)` of a `PT_GNU_RELRO` span of `size` bytes at
/// `va`, biased by `bias`; `None` when the arithmetic overflows.
fn relro_page_range(va: u64, size: u64, bias: u64) -> Option<(u64, u64)>
{
    let start = va.checked_add(bias)?;
    let end = start.checked_add(size)?.checked_add(0xFFF)?;
    Some((start & !0xFFF, end & !0xFFF))
}

/// Create a process from an in-memory ELF byte slice (suspended).
///
/// # Errors
/// `INVALID_ELF` when the image fails validation, its relocations do not
/// all land, its stack note is out of range, its `PT_TLS` reaches past the
/// image, or its TLS block is oversized, overaligned, or smaller than its
/// template ([`alloc_main_tls_memory`], [`prepare_main_tls_from_bytes`]);
/// `OUT_OF_MEMORY` when a kernel object, memory cap, badge, page, or the
/// table entry cannot be had; a segment load's `OUT_OF_MEMORY` (its pages),
/// `MAP_FAILED` (a scratch or child mapping), or `INSUFFICIENT_RIGHTS` (a
/// rights derivation) ([`loader::load_elf_segment_into_child`]); and the main
/// TLS block's and [`populate_child_info`]'s other codes.
#[expect(
    clippy::similar_names,
    reason = "aspace/cspace are intentionally parallel kernel object names"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input the caller holds separately: the image, procmgr's \
              own caps and tables, the child's universals, argv and env, death set and scheduling, \
              and the IPC buffer"
)]
#[expect(
    clippy::too_many_lines,
    reason = "in-memory process creation is one transaction that owns the child's kernel objects \
              and its segment loads; splitting it would thread the partial state through helpers"
)]
fn create_process_from_bytes(
    module_bytes: &[u8],
    self_aspace: u64,
    tables: &Tables,
    self_endpoint: u64,
    creator_endpoint: u64,
    universals: &UniversalCaps,
    argv_env: ChildArgvEnv,
    deaths: &Mutex<DeathSet>,
    sched: ChildSched,
    ipc_buf: *mut u64,
) -> Result<CreateResult, u64>
{
    let machine = crate::arch::current::EXPECTED_ELF_MACHINE;
    let (ehdr, kind) =
        elf::validate_executable(module_bytes, machine).map_err(|_| procmgr_errors::INVALID_ELF)?;
    // `validate_executable` returns the header decoded; the parsers borrow it.
    let ehdr = &ehdr;
    let bias = match kind
    {
        elf::ElfKind::Exec => 0,
        elf::ElfKind::Dyn => choose_image_bias_or_default(),
    };
    let (span_min, span_end) =
        elf::load_span(ehdr, module_bytes).map_err(|_| procmgr_errors::INVALID_ELF)?;
    if kind == elf::ElfKind::Dyn
    {
        if !child_image_fits(bias, span_min, span_end)
        {
            return Err(procmgr_errors::INVALID_ELF);
        }
        // Load-bias observability: no ProcessInfo field carries the bias;
        // debugging correlates through this line (in-process code uses
        // __ehdr_start).
        std::os::seraph::log!("spawn image bias=0x{bias:x}");
    }
    let entry = elf::entry_point(ehdr)
        .checked_add(bias)
        .ok_or(procmgr_errors::INVALID_ELF)?;

    // Locate and pre-validate the RELATIVE relocation table (ET_DYN only; an
    // ET_EXEC image is fully linked and any vestigial table is ignored).
    let rela = if kind == elf::ElfKind::Dyn
    {
        elf::rela_table(ehdr, module_bytes).map_err(|_| procmgr_errors::INVALID_ELF)?
    }
    else
    {
        None
    };
    let rela_bytes = match rela
    {
        Some(t) => Some(
            file_range(module_bytes, t.file_offset, t.size).ok_or(procmgr_errors::INVALID_ELF)?,
        ),
        None => None,
    };
    let total_relocs = match rela_bytes
    {
        Some(table) => elf::validate_relative_relocs(table, machine, span_min, span_end)
            .map_err(|_| procmgr_errors::INVALID_ELF)?,
        None => 0,
    };

    // PT_GNU_RELRO (biased, page-rounded): fully-covered pages of writable
    // segments are mapped read-only after relocation.
    let ro_range = elf::relro_span(ehdr, module_bytes)
        .map_err(|_| procmgr_errors::INVALID_ELF)?
        .map(|(va, sz)| relro_page_range(va, sz, bias))
        .map(|range| range.ok_or(procmgr_errors::INVALID_ELF))
        .transpose()?;

    // A note outside `1..=MAX_PROCESS_STACK_PAGES` refuses the binary.
    let stack_pages = resolve_stack_pages(elf::parse_stack_note(ehdr, module_bytes))
        .ok_or(procmgr_errors::INVALID_ELF)?;
    let layout = choose_child_layout();

    // The child's kernel objects and per-child memory caps are guarded from
    // creation: every early return below releases them, and only a successful
    // `finalize_creation` hands them to the table entry.
    let child_objs = create_child_kernel_objects(
        universals.memmgr_endpoint,
        universals.sched_baseline,
        sched.priority,
        ipc_buf,
    )?;
    let (child_aspace, child_cspace, child_thread) = (
        child_objs.aspace(),
        child_objs.cspace(),
        child_objs.thread(),
    );

    let child_memmgr_send = universals.memmgr_endpoint;

    let mut applied_relocs = 0u64;
    let mut image = ImageSpan {
        load_bias: bias,
        ..ImageSpan::default()
    };
    for seg_result in elf::load_segments(ehdr, module_bytes)
    {
        let seg = seg_result.map_err(|_| procmgr_errors::INVALID_ELF)?;
        if seg.memsz == 0
        {
            continue;
        }

        let prot = segment_prot(&seg);
        // The segment's addresses and file range come from the image; any
        // that overflows or leaves the file refuses it.
        let seg_vaddr = seg
            .vaddr
            .checked_add(bias)
            .ok_or(procmgr_errors::INVALID_ELF)?;
        let seg_end = seg_vaddr
            .checked_add(seg.memsz)
            .ok_or(procmgr_errors::INVALID_ELF)?;
        if seg.executable
        {
            image.add_text(seg_vaddr, seg_end);
        }
        let first_page = seg_vaddr & !0xFFF;
        let last_page_end = seg_end
            .checked_add(0xFFF)
            .ok_or(procmgr_errors::INVALID_ELF)?
            & !0xFFF;
        let num_pages = last_page_end.saturating_sub(first_page) / PAGE_SIZE;
        let file_data =
            file_range(module_bytes, seg.offset, seg.filesz).ok_or(procmgr_errors::INVALID_ELF)?;
        // `first_page` is `seg_vaddr` rounded down, so the difference is below a page.
        let dest_offset = seg_vaddr.saturating_sub(first_page) as usize;

        // SAFETY: `child_aspace` is the fresh address space
        // `create_child_kernel_objects` retyped for this child above.
        unsafe {
            loader::load_elf_segment_into_child(
                first_page,
                num_pages,
                prot,
                if seg.writable { ro_range } else { None },
                self_aspace,
                child_aspace,
                child_memmgr_send,
                ipc_buf,
                |buf| {
                    let copy_len = file_data.len().min(seg.memsz as usize);
                    // `buf` spans `num_pages` pages from `first_page`, which
                    // hold `dest_offset + memsz`, and `copy_len` is at most
                    // `memsz` and the file data length: both ranges are present.
                    if let Some(dst) =
                        buf.get_mut(dest_offset..dest_offset.saturating_add(copy_len))
                        && let Some(src) = file_data.get(..copy_len)
                    {
                        dst.copy_from_slice(src);
                    }
                    // Writable segments only, matching the kernel's init
                    // applier: a target in text/rodata goes unapplied and the
                    // applied-count check below rejects the image.
                    // A span the buffer lacks applies nothing, which the
                    // applied-count check rejects.
                    if seg.writable
                        && let Some(table) = rela_bytes
                        && let Some(span) =
                            buf.get_mut(dest_offset..dest_offset.saturating_add(seg.memsz as usize))
                    {
                        // The count is at most the table's record count.
                        applied_relocs = applied_relocs.saturating_add(elf::apply_relative_relocs(
                            table, machine, bias, seg.vaddr, span,
                        ));
                    }
                },
            )
        }?;
    }
    // Every pre-validated record must have landed in exactly one segment;
    // a shortfall means a target in a gap between segments.
    if applied_relocs != total_relocs
    {
        std::os::seraph::log!(
            warn: "reloc application mismatch applied={applied_relocs} expected={total_relocs}"
        );
        return Err(procmgr_errors::INVALID_ELF);
    }

    let tls_seg = elf::tls_segment(ehdr, module_bytes).map_err(|_| procmgr_errors::INVALID_ELF)?;
    let tls_vaddr = match tls_seg
    {
        Some(s) => s
            .vaddr
            .checked_add(bias)
            .ok_or(procmgr_errors::INVALID_ELF)?,
        None => 0,
    };
    let tls_template = tls_seg.map_or_default(|s| ChildTlsTemplate {
        vaddr: tls_vaddr,
        filesz: s.filesz,
        memsz: s.memsz,
        align: s.align,
    });

    let main_tls = if let Some(seg) = tls_seg
        && tls_template.memsz != 0
    {
        let tdata =
            file_range(module_bytes, seg.offset, seg.filesz).ok_or(procmgr_errors::INVALID_ELF)?;
        // SAFETY: `child_aspace` is the fresh address space
        // `create_child_kernel_objects` retyped for this child above.
        unsafe {
            prepare_main_tls_from_bytes(
                self_aspace,
                child_aspace,
                &tls_template,
                tdata,
                child_memmgr_send,
                ipc_buf,
                &layout,
                |template| {
                    // Re-apply the .tdata-targeting relocations to this
                    // independent copy; the image copy was relocated (and
                    // counted) during segment loading.
                    if let Some(table) = rela_bytes
                    {
                        let _ =
                            elf::apply_relative_relocs(table, machine, bias, seg.vaddr, template);
                    }
                },
            )
        }?
    }
    else
    {
        MainTls::default()
    };

    let main_tls_memory = CapGuard::new(main_tls.memory_cap);

    let reservation = next_process_badge(tables)?;
    let process_badge = reservation.badge();
    // SAFETY: `child_aspace` is the fresh address space
    // `create_child_kernel_objects` retyped for this child above.
    let info_caps = unsafe {
        populate_child_info(
            self_aspace,
            child_aspace,
            child_cspace,
            child_thread,
            creator_endpoint,
            universals,
            &tls_template,
            argv_env,
            ipc_buf,
            stack_pages,
            process_badge,
            sched,
            &layout,
        )
    }?;
    // SAFETY: `child_aspace` is the fresh address space
    // `create_child_kernel_objects` retyped for this child above.
    unsafe {
        map_child_stack_and_ipc(
            child_aspace,
            child_memmgr_send,
            ipc_buf,
            stack_pages,
            &layout,
        )
    }
    // § Label 1 and § Label 13 answer a failed stack or IPC-buffer page
    // `OUT_OF_MEMORY`, whatever cause the helper reports.
    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;

    // The guards stay armed across `finalize_creation`, so its failure
    // releases every resource; on success the table entry owns them.
    let result = finalize_creation(
        child_aspace,
        child_cspace,
        child_thread,
        &info_caps,
        entry,
        main_tls,
        tables,
        self_endpoint,
        deaths,
        child_memmgr_send,
        universals.memmgr_badge,
        process_badge,
        universals.paging,
        universals.self_memmgr_ep,
        // Boot-module spawns (CREATE_PROCESS) have no parent death queue to
        // relay terminal faults to; only CREATE_FROM_FILE carries a relay.
        0,
        sched.band_max,
        image,
        ipc_buf,
        &layout,
        self_aspace,
    )?;
    let _ = child_objs.disarm();
    info_caps.disarm();
    let _ = main_tls_memory.disarm();
    Ok(result)
}

/// Create a process from an ELF module memory cap (suspended).
///
/// Maps the memory cap, delegates to `create_process_from_bytes`, then unmaps.
///
/// # Errors
/// A `procmgr_errors` code naming the cause: [`loader::map_module`]'s
/// (`INSUFFICIENT_RIGHTS`, `OUT_OF_MEMORY`, or `MAP_FAILED`) when the module
/// cannot be mapped, else `create_process_from_bytes`'s. The `CREATE_PROCESS`
/// handler answers every one `OUT_OF_MEMORY`, as § Label 1 of
/// `services/procmgr/docs/ipc-interface.md` names it.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct capability, table or child parameter the caller already \
              holds separately; a struct bundling them would serve this one call only"
)]
pub fn create_process(
    module_memory_cap: u64,
    self_aspace: u64,
    _self_memmgr_ep: u64,
    ipc_buf: *mut u64,
    tables: &Tables,
    self_endpoint: u64,
    creator_endpoint: u64,
    universals: &UniversalCaps,
    argv_env: ChildArgvEnv,
    deaths: &Mutex<DeathSet>,
    sched: ChildSched,
) -> Result<CreateResult, u64>
{
    let (module_scratch, module_pages) = loader::map_module(module_memory_cap, self_aspace)?;
    // `map_module` returns at most 128 pages, so the product is small.
    let module_size = module_pages.saturating_mul(PAGE_SIZE);
    let module_va = module_scratch.va();

    // SAFETY: module memory cap mapped read-only at module_va for module_size
    // bytes; `module_scratch` owns that mapping and is dropped below, after
    // `create_process_from_bytes`, the last use of `module_bytes`, returns.
    let module_bytes =
        unsafe { core::slice::from_raw_parts(module_va as *const u8, module_size as usize) };

    let result = create_process_from_bytes(
        module_bytes,
        self_aspace,
        tables,
        self_endpoint,
        creator_endpoint,
        universals,
        argv_env,
        deaths,
        sched,
        ipc_buf,
    );

    drop(module_scratch);

    result
}

/// Per-request correlation cookie for `FS_READ_MEMORY`: a random `u64` from
/// the kernel entropy pool, redrawn off the reserved `0` value (fatfs rejects
/// cookie 0 as the `OutstandingPage::None` sentinel). Random rather than
/// monotonic so the read-memory request count/rate it would otherwise leak to
/// the fs stays unguessable; the cookie is opaque and never indexes a table.
/// Its `u64` is the one request word that carries it, so the space never
/// runs out. Returns `None` if the entropy draw fails (a kernel-contract violation).
fn next_memory_cookie() -> Option<u64>
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

/// Issue `FS_READ_MEMORY` at byte `offset`.
///
/// On success returns `(memory_cap, bytes_valid, memory_data_offset, cookie)`
/// per `fs/docs/fs-driver-protocol.md`: the file's byte at `offset + i` for
/// `i ∈ [0, bytes_valid)` lives in the returned memory cap at byte offset
/// `memory_data_offset + i`, and `cookie` names the request for the
/// `FS_RELEASE_MEMORY` that drops the fs-side cache refcount once the caller
/// has copied the bytes (`stream_segment_bytes` issues it; `FS_CLOSE` drops
/// any the caller missed). The memory cap is a per-call grandchild of the fs
/// cache slot and is owned by the caller; `cap_delete` releases the caller's
/// reference. `bytes_valid` is bounded by file end, cluster boundary, and
/// memory-cap tail — callers must iterate from `offset + bytes_valid` to read
/// past the boundary.
///
/// The file cap is client-supplied, so its server is untrusted: every reply
/// cap other than the returned one is deleted, and on a failed or empty reply
/// every reply cap ([`process_table::fs_reads::read_memory_reply_caps`]).
fn vfs_read_memory(
    file_cap: u64,
    ipc_buf: *mut u64,
    offset: u64,
) -> Option<(u64, usize, usize, u64)>
{
    let cookie = next_memory_cookie()?;
    let msg = IpcMessage::builder(ipc::fs_labels::FS_READ_MEMORY)
        .word(0, offset)
        .word(1, cookie)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { file_call(file_cap, &msg, ipc_buf) }.ok()?;
    let bytes_valid = reply.word(0) as usize;
    let (kept, surplus) =
        process_table::fs_reads::read_memory_reply_caps(reply.label, bytes_valid, reply.caps());
    crate::release_caps(surplus);
    let memory_data_offset = reply.word(2) as usize;
    Some((kept?, bytes_valid, memory_data_offset, cookie))
}

/// Read from an open file via its per-file capability.
///
/// Copies up to `max_len` bytes of file data into `dst`. Returns the number
/// of bytes the server reported reading (which may exceed `dst.len()` if the
/// caller intentionally requested more than it is staging this call; callers
/// clamp as needed).
fn vfs_read(
    file_cap: u64,
    ipc_buf: *mut u64,
    offset: u64,
    max_len: u64,
    dst: &mut [u8],
) -> Option<usize>
{
    let msg = IpcMessage::builder(ipc::fs_labels::FS_READ)
        .word(0, offset)
        .word(1, max_len)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { file_call(file_cap, &msg, ipc_buf) }.ok()?;
    // FS_READ replies carry no caps; the untrusted server's are deleted.
    crate::release_caps(reply.caps());
    if reply.label != 0
    {
        return None;
    }
    let bytes_read = reply.word(0) as usize;
    // Data bytes live in words 1..; the message byte view covers all
    // populated words starting at word 0. Skip the 8-byte header.
    let data_view = reply.data_bytes();
    let payload = data_view.get(core::mem::size_of::<u64>()..).unwrap_or(&[]);
    let copy_len = bytes_read.min(dst.len()).min(payload.len());
    // `copy_len` is at most both lengths, so both ranges are present.
    if let (Some(to), Some(from)) = (dst.get_mut(..copy_len), payload.get(..copy_len))
    {
        to.copy_from_slice(from);
    }
    Some(bytes_read)
}

/// Open the file a caller-transferred file node cap names (`FS_OPEN`, with
/// no release SEND: procmgr releases each page itself right after its copy,
/// so it opts out of cooperative release), and delete the node cap. Returns
/// the open cap every later read and the closing `FS_CLOSE` go to, so
/// procmgr's pages and close touch no other opener's state, and the open's
/// liveness cap, which keeps the driver from releasing the open until
/// [`vfs_close`] deletes it (`fs/docs/fs-driver-protocol.md` § Label 18).
/// `None` when the call fails or the reply carries no open cap and liveness
/// cap; every other reply cap is deleted.
fn vfs_open(node_cap: u64, ipc_buf: *mut u64) -> Option<OpenedFile>
{
    let msg = IpcMessage::new(ipc::fs_labels::FS_OPEN);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { file_call(node_cap, &msg, ipc_buf) };
    let _ = syscall::cap_delete(node_cap);
    let reply = reply.ok()?;
    let (opened, surplus) = match *reply.caps()
    {
        [cap, liveness, ref rest @ ..] if reply.label == 0 =>
        {
            (Some(OpenedFile { cap, liveness }), rest)
        }
        _ => (None, reply.caps()),
    };
    // The file cap is client-supplied, so its server is untrusted.
    crate::release_caps(surplus);
    opened
}

/// An open [`vfs_open`] made: its open cap and its liveness cap.
#[derive(Clone, Copy)]
struct OpenedFile
{
    cap: u64,
    liveness: u64,
}

/// Close an open file via its open cap, then delete the open cap and the
/// liveness cap.
fn vfs_close(file: OpenedFile, ipc_buf: *mut u64)
{
    let file_cap = file.cap;
    let msg = IpcMessage::new(ipc::fs_labels::FS_CLOSE);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Ok(reply) = unsafe { file_call(file_cap, &msg, ipc_buf) }
    {
        // FS_CLOSE replies carry no caps; the untrusted server's are deleted.
        crate::release_caps(reply.caps());
    }
    let _ = syscall::cap_delete(file_cap);
    let _ = syscall::cap_delete(file.liveness);
}

// ── Per-creation resource guards ────────────────────────────────────────────
//
// `create_process_from_file` accumulates resources whose ownership transfers
// step by step: the caller-transferred file cap, a child-billed memmgr send
// cap, the three child kernel-object caps, and the per-child PI/TLS memory caps.
// Each guard's `Drop` releases the resource if it has not been transferred to
// the success path via `disarm()`. Constructed at the point of acquisition;
// disarmed only after the caps have been moved into the final destination.

/// Holds procmgr's open of the caller-transferred file until the success
/// path consumes it.
struct FileCapGuard
{
    file: OpenedFile,
    ipc_buf: *mut u64,
}

impl FileCapGuard
{
    fn new(file: OpenedFile, ipc_buf: *mut u64) -> Self
    {
        Self { file, ipc_buf }
    }

    fn cap(&self) -> u64
    {
        self.file.cap
    }

    fn disarm(mut self) -> OpenedFile
    {
        let f = self.file;
        self.file.cap = 0;
        f
    }
}

impl Drop for FileCapGuard
{
    fn drop(&mut self)
    {
        if self.file.cap != 0
        {
            vfs_close(self.file, self.ipc_buf);
        }
    }
}

/// Holds a child-billed memmgr SEND cap and its memmgr-side badge from
/// `REGISTER_PROCESS` until the child's table entry owns them.
///
/// While armed, dropping the guard retires the child's memmgr record: it
/// sends `PROCESS_DIED` for the badge over procmgr's own memmgr endpoint, so
/// memmgr returns every page already billed to the child (retype slabs,
/// segment pages, the `ProcessInfo` and TLS pages) and frees the record,
/// then deletes the SEND slot. Declare it before the child's other guards so
/// it drops after them: memmgr then reclaims pages no kernel object or
/// procmgr-held cap still uses.
pub(crate) struct MemmgrSendGuard
{
    cap: u64,
    badge: u64,
    memmgr_ep: u64,
    ipc_buf: *mut u64,
}

impl MemmgrSendGuard
{
    /// Guard the `(cap, badge)` pair `register_with_memmgr` returned;
    /// `memmgr_ep` is procmgr's own memmgr endpoint, the one `PROCESS_DIED`
    /// is accepted on.
    pub(crate) fn new(cap: u64, badge: u64, memmgr_ep: u64, ipc_buf: *mut u64) -> Self
    {
        Self {
            cap,
            badge,
            memmgr_ep,
            ipc_buf,
        }
    }

    pub(crate) fn cap(&self) -> u64
    {
        self.cap
    }

    pub(crate) fn badge(&self) -> u64
    {
        self.badge
    }

    pub(crate) fn disarm(mut self) -> (u64, u64)
    {
        let p = (self.cap, self.badge);
        self.cap = 0;
        self.badge = 0;
        p
    }
}

impl Drop for MemmgrSendGuard
{
    fn drop(&mut self)
    {
        notify_memmgr_died(self.memmgr_ep, self.badge, self.ipc_buf);
        if self.cap != 0
        {
            let _ = syscall::cap_delete(self.cap);
        }
    }
}

/// Holds the three child kernel-object caps (aspace, cspace, thread) until
/// `finalize_creation` records them in the process table. Drops in
/// reverse-creation order (thread → cspace → aspace).
struct ChildKernelObjects
{
    aspace: u64,
    cspace: u64,
    thread: u64,
}

impl ChildKernelObjects
{
    fn new(aspace: u64, cspace: u64, thread: u64) -> Self
    {
        Self {
            aspace,
            cspace,
            thread,
        }
    }

    fn aspace(&self) -> u64
    {
        self.aspace
    }

    fn cspace(&self) -> u64
    {
        self.cspace
    }

    fn thread(&self) -> u64
    {
        self.thread
    }

    fn disarm(mut self) -> (u64, u64, u64)
    {
        let t = (self.aspace, self.cspace, self.thread);
        self.aspace = 0;
        self.cspace = 0;
        self.thread = 0;
        t
    }
}

impl Drop for ChildKernelObjects
{
    /// Release the three objects as `teardown_entry` does: revoke each before
    /// deleting it. Once `populate_child_info` has run, the child's `CSpace`
    /// holds copies of all three (its own `CSpace` among them), and those
    /// descendants would keep every object alive after a bare `cap_delete`.
    fn drop(&mut self)
    {
        for cap in [self.thread, self.cspace, self.aspace]
        {
            if cap != 0
            {
                let _ = syscall::cap_revoke_all(cap);
                let _ = syscall::cap_delete(cap);
            }
        }
    }
}

/// Create a child's `AddressSpace`, `CSpace`, and initial `Thread` from
/// child-billed retype slabs, the thread at `priority` under procmgr's
/// baseline `SchedControl` (`sched_baseline`; zero creates it at the floor).
///
/// Every slab and kernel-object cap is guarded from the moment it exists,
/// so a failure at any step leaves nothing in procmgr's `CSpace`; the
/// returned guard owns the three kernel objects until disarmed.
///
/// # Errors
/// `procmgr_errors::OUT_OF_MEMORY` when memmgr grants no retype slab, the
/// address-space slab's derivation without `RIGHTS_MEM_PHYS` fails, the
/// thread-retype size cannot be read, or a retype fails: § Label 1 and
/// § Label 13 of `services/procmgr/docs/ipc-interface.md` name every
/// kernel-object allocation failure so.
fn create_child_kernel_objects(
    memmgr_send: u64,
    sched_baseline: u64,
    priority: u8,
    ipc_buf: *mut u64,
) -> Result<ChildKernelObjects, u64>
{
    let oom = procmgr_errors::OUT_OF_MEMORY;
    let slab = CapGuard::new(
        crate::memmgr_alloc_pages_contig(memmgr_send, crate::ASPACE_RETYPE_PAGES, ipc_buf)
            .ok_or(oom)?,
    );
    // Retype through a derivation without `RIGHTS_MEM_PHYS`, so the address
    // space is minted without `RIGHTS_AS_READ` even for a phys-class child,
    // whose slab carries `PHYS`: procmgr keeps this cap for the child's life,
    // and no process translates a child's pages (`SYS_ASPACE_QUERY`).
    let narrowed = CapGuard::new(
        syscall::cap_derive(slab.cap(), syscall::RIGHTS_ALL & !syscall::RIGHTS_MEM_PHYS)
            .map_err(|_| oom)?,
    );
    let aspace = CapGuard::new(
        syscall::cap_create_aspace(narrowed.cap(), 0, crate::ASPACE_RETYPE_PAGES)
            .map_err(|_| oom)?,
    );
    // The retype keeps its own reference on the region; drop the slab slots.
    drop(narrowed);
    drop(slab);
    let slab = CapGuard::new(
        crate::memmgr_alloc_pages_contig(memmgr_send, crate::CSPACE_RETYPE_PAGES, ipc_buf)
            .ok_or(oom)?,
    );
    let cspace = CapGuard::new(
        syscall::cap_create_cspace(slab.cap(), 0, crate::CSPACE_RETYPE_PAGES).map_err(|_| oom)?,
    );
    drop(slab);
    let slab = CapGuard::new(
        crate::memmgr_alloc_pages_contig(
            memmgr_send,
            crate::thread_retype_pages().ok_or(oom)?,
            ipc_buf,
        )
        .ok_or(oom)?,
    );
    let (sched_cap, create_priority) = if sched_baseline != 0
    {
        (sched_baseline, priority)
    }
    else
    {
        (0, 0)
    };
    let thread = syscall::cap_create_thread(
        slab.cap(),
        aspace.cap(),
        cspace.cap(),
        sched_cap,
        create_priority,
    )
    .map_err(|_| oom)?;
    drop(slab);
    Ok(ChildKernelObjects::new(
        aspace.disarm(),
        cspace.disarm(),
        thread,
    ))
}

/// `cap_delete`s a single cap slot on drop unless disarmed. Zero on
/// construction means "no cap yet"; the guard becomes a no-op.
struct CapGuard
{
    cap: u64,
}

impl CapGuard
{
    fn new(cap: u64) -> Self
    {
        Self { cap }
    }

    fn cap(&self) -> u64
    {
        self.cap
    }

    fn disarm(mut self) -> u64
    {
        let c = self.cap;
        self.cap = 0;
        c
    }
}

impl Drop for CapGuard
{
    fn drop(&mut self)
    {
        if self.cap != 0
        {
            let _ = syscall::cap_delete(self.cap);
        }
    }
}

// ── VFS-based ELF loading ──────────────────────────────────────────────────

/// Everything `stream_segment_bytes` needs beyond the per-segment arguments:
/// the VFS file handle, IPC buffer, and procmgr's own address space (for the
/// transient cache-page scratch mappings).
pub struct ElfLoadCtx
{
    pub file_cap: u64,
    pub ipc_buf: *mut u64,
    pub self_aspace: u64,
}

/// Stream segment file data from VFS into the segment's scratch span.
///
/// `dest_offset` is the segment's byte offset within `buf` (its in-page
/// offset on the first page of the span). Issues `FS_READ_MEMORY` requests
/// at the current file offset, mapping the returned cache-page Memory cap
/// read-only into a scratch VA, then memcpys the valid slice into the span.
/// The memory cap is the caller's grandchild of fs's cache slot —
/// `cap_delete` (via the `ScratchMapping` `owns_cap` slot) drops the
/// caller's reference. After each copy it issues `FS_RELEASE_MEMORY` for the
/// request's cookie, so fs drops its cache-slot refcount; `FS_CLOSE`
/// reclaims any release that is lost.
///
/// # Errors
/// `IO_ERROR` when the segment's file bytes could not all be copied: a
/// failed or zero-byte `FS_READ_MEMORY`, a cache page that cannot be mapped,
/// or a reply whose `memory_data_offset + bytes_valid` runs past the one page
/// mapped. The loader's `fill` cannot fail, so the caller records the result
/// and fails the spawn with it once the segment load returns; the tail left
/// unfilled is never run.
fn stream_segment_bytes(
    buf: &mut [u8],
    dest_offset: usize,
    seg: &elf::LoadSegment,
    ctx: &ElfLoadCtx,
) -> Result<(), u64>
{
    let total = (seg.filesz.min(seg.memsz)) as usize;
    let mut copied = 0usize;
    while copied < total
    {
        // The segment's file offset comes from the image; an offset past the
        // address space is a failed read.
        let Some(cur) = seg.offset.checked_add(copied as u64)
        else
        {
            return Err(procmgr_errors::IO_ERROR);
        };

        let Some((memory_cap, bytes_valid, memory_data_offset, cookie)) =
            vfs_read_memory(ctx.file_cap, ctx.ipc_buf, cur)
        else
        {
            return Err(procmgr_errors::IO_ERROR);
        };

        let Ok(mut mapping) =
            ScratchMapping::map(ctx.self_aspace, memory_cap, 1, syscall::MAP_FROM_CAP)
        else
        {
            let _ = syscall::cap_delete(memory_cap);
            vfs_release_memory(ctx.file_cap, ctx.ipc_buf, cookie);
            return Err(procmgr_errors::IO_ERROR);
        };
        mapping.set_owns_cap(memory_cap);

        // The offset and count come from the fs driver: refuse a range that
        // leaves the single page mapped before building any slice over it.
        let Some(range) = process_table::fs_reads::cache_page_range(
            memory_data_offset,
            bytes_valid,
            PAGE_SIZE as usize,
        )
        else
        {
            drop(mapping);
            vfs_release_memory(ctx.file_cap, ctx.ipc_buf, cookie);
            return Err(procmgr_errors::IO_ERROR);
        };
        // The loop condition keeps `copied` below `total`.
        let chunk_len = range.len().min(total.saturating_sub(copied));

        // `buf` holds the segment's `memsz` bytes from `dest_offset`, and
        // `copied + chunk_len` is at most `total <= memsz`, so the range is
        // present; a buffer that lacks it ends the copy as a failed read.
        let dst_start = dest_offset.saturating_add(copied);
        let Some(dst) = buf.get_mut(dst_start..dst_start.saturating_add(chunk_len))
        else
        {
            drop(mapping);
            vfs_release_memory(ctx.file_cap, ctx.ipc_buf, cookie);
            return Err(procmgr_errors::IO_ERROR);
        };
        // SAFETY: `mapping.va()` covers PAGE_SIZE bytes, and
        // `cache_page_range` checked `range.start + range.len() <= PAGE_SIZE`,
        // so the offset stays inside the mapping.
        let src = unsafe { (mapping.va() as *const u8).add(range.start) };
        // SAFETY: `mapping.va()` covers PAGE_SIZE bytes mapped read-only;
        // `chunk_len <= range.len()`, so the source span from `src` lies in
        // the mapping, which is dropped only after the copy. The page is the
        // fs driver's cache page, which the driver may write while procmgr
        // reads it, so no Rust reference is formed over it: the bytes are
        // copied by raw pointer into procmgr's own `dst`, which does not
        // overlap it.
        unsafe {
            core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), chunk_len);
        }
        drop(mapping);
        vfs_release_memory(ctx.file_cap, ctx.ipc_buf, cookie);
        // `chunk_len` is at most `total - copied`.
        copied = copied.saturating_add(chunk_len);
    }
    Ok(())
}

/// Issue `FS_RELEASE_MEMORY` on the file-cap to drop the fs-side cache
/// refcount and clear the outstanding-page tracking entry for `cookie`.
/// Failure is non-fatal — the slot will be reclaimed at `FS_CLOSE` time
/// even if the proactive release is lost.
fn vfs_release_memory(file_cap: u64, ipc_buf: *mut u64, cookie: u64)
{
    let msg = IpcMessage::builder(ipc::fs_labels::FS_RELEASE_MEMORY)
        .word(0, cookie)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    if let Ok(reply) = unsafe { file_call(file_cap, &msg, ipc_buf) }
    {
        // FS_RELEASE_MEMORY replies carry no caps; the untrusted server's
        // are deleted.
        crate::release_caps(reply.caps());
    }
}

/// Create a process from a caller-supplied file cap.
///
/// Reads only the ELF header page, then loads each segment page-by-page
/// directly from the file cap into target memory caps. No intermediate file
/// buffer. Procmgr opens `file_cap` (`FS_OPEN`) and deletes it, then
/// `FS_CLOSE`s and deletes its open before return regardless of outcome —
/// ownership transfers in. `creator_endpoint`
/// is only copied into the child, so the caller still owns and releases it;
/// `parent_relay_cap` is consumed only on `Ok`, so on `Err` the caller
/// releases it. Every resource acquired for the child, including memmgr's
/// record for it, is released on every `Err`.
///
/// # Errors
/// The `CREATE_FROM_FILE` reply code § Label 13 of
/// `services/procmgr/docs/ipc-interface.md` names for the failure:
/// - `procmgr_errors::IO_ERROR` (10) — the `FS_OPEN` of `file_cap` failed, an
///   `FS_READ` of the file failed (a refused or an unanswered one: the ELF
///   header, the relocation table, the stack-size note, a segment's
///   relocations, or the `.tdata` template and its relocations), or a
///   segment's file bytes did not all arrive;
/// - `procmgr_errors::INVALID_ELF` (1) — `file_size` is zero, or ELF
///   validation or relocation failed with every read answered;
/// - `procmgr_errors::OUT_OF_MEMORY` (2) — a memory-cap, kernel-object, or
///   badge allocation failed, the main thread's TLS block could not be built
///   for a cause other than a failed read, or the stack or IPC-buffer pages
///   could not be mapped;
/// - `procmgr_errors::MAP_FAILED` (11) — mapping failed during segment load;
/// - `procmgr_errors::INSUFFICIENT_RIGHTS` (12) — a rights derivation failed
///   during segment load;
/// - `procmgr_errors::INVALID_ARGUMENT` (7) — the copy of `argv_env` refused
///   it: the caller's cap could not be mapped, or a blob's NULs disagree with
///   its count or a nonempty blob does not end in a NUL ([`copy_argv_env`]);
/// - `procmgr_errors::ARGV_ENV_STILL_MAPPED` (14) — a window the argv and env
///   were copied through would not unmap, so the child's memmgr record is
///   withheld.
#[expect(
    clippy::too_many_lines,
    reason = "file-cap-based process creation is one transaction that owns the lifetime of the \
              ELF-header scratch memory cap, the child's kernel objects, and the per-page \
              streaming loop"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is a distinct input: the request's file, size, argv and env, demand \
              paging, parent relay and scheduling, and procmgr's context, tables, death set and IPC \
              buffer"
)]
pub fn create_process_from_file(
    ctx: &crate::ProcmgrCtx,
    file_cap: u64,
    file_size: u64,
    tables: &Tables,
    ipc_buf: *mut u64,
    creator_endpoint: u64,
    argv_env: Option<&ArgvEnvRequest>,
    deaths: &Mutex<DeathSet>,
    paging: Paging,
    parent_relay_cap: u64,
    sched: ChildSched,
) -> Result<CreateResult, u64>
{
    let self_aspace = ctx.self_aspace;
    let self_endpoint = ctx.self_endpoint;

    // Caller-transferred file node cap: opened at once, and the open
    // wrapped, so every early return between here and the success-path
    // disarm closes the open (FS_CLOSE on the fs driver) and frees
    // procmgr's CSpace slot.
    let file_cap = FileCapGuard::new(
        vfs_open(file_cap, ipc_buf).ok_or(procmgr_errors::IO_ERROR)?,
        ipc_buf,
    );

    if file_size == 0
    {
        return Err(procmgr_errors::INVALID_ELF);
    }

    // Mint a fresh badged SEND on memmgr's endpoint for this child up
    // front; the header scratch memory cap, the per-segment memory caps, and all
    // subsequent allocations route through this cap so memmgr accounts
    // them to the child's record from the moment they leave the pool.
    let (mms_cap, mms_badge) =
        crate::register_with_memmgr(ctx.memmgr_ep, sched.memmgr_flags, ipc_buf);
    let mms = MemmgrSendGuard::new(mms_cap, mms_badge, ctx.memmgr_ep, ipc_buf);
    if mms.cap() == 0
    {
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }

    // The child's checked copy of the request's argv and env, on its account;
    // a malformed blob refuses the create here, before any other resource.
    let argv_env = match argv_env
    {
        Some(request) => match copy_argv_env(self_aspace, mms.cap(), ipc_buf, request)
        {
            Ok(argv_env) => argv_env,
            Err(e) =>
            {
                settle_failed_argv_env(mms, e);
                return Err(e.code());
            }
        },
        None => ChildArgvEnv::empty(),
    };

    // Allocate one memory cap for the ELF header page. `ScratchMapping::map`
    // takes ownership of the memory cap via `set_owns_cap` so the mapping's
    // Drop releases both the VA reservation and the cap slot together.
    let hdr_memory =
        crate::memmgr_alloc_page(mms.cap(), ipc_buf).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    let mut hdr_scratch = ScratchMapping::map(self_aspace, hdr_memory, 1, syscall::MAP_WRITABLE)
        .map_err(|_| {
            let _ = syscall::cap_delete(hdr_memory);
            procmgr_errors::OUT_OF_MEMORY
        })?;
    hdr_scratch.set_owns_cap(hdr_memory);
    let hdr_va = hdr_scratch.va();

    // Read the first page (ELF header + program headers).
    let hdr_size = file_size.min(PAGE_SIZE) as usize;
    // SAFETY: hdr_va is mapped writable for one page and
    // `hdr_size <= PAGE_SIZE`; the mapping outlives every use of the slice
    // (it is dropped only after the last use of `header_data` below).
    let hdr_page = unsafe { core::slice::from_raw_parts_mut(hdr_va as *mut u8, hdr_size) };
    hdr_page.fill(0);
    // `vfs_read_exact` clamps each reply to the bytes it requested, so an fs
    // driver over-reporting `bytes_read` cannot make procmgr write past the
    // header page.
    let header_len =
        vfs_read_exact(file_cap.cap(), ipc_buf, 0, hdr_page).ok_or(procmgr_errors::IO_ERROR)?;
    // Every later read goes through `reads`, which makes none once one has
    // failed, so an unanswering server costs the create one bounded wait.
    // The parsers it feeds report a failed read as a malformed image or as
    // no stack note, and a failed read, an unanswered one included, fails
    // the create with `IO_ERROR`.
    let reads = process_table::fs_reads::ReadFailures::new();

    // Parse ELF headers from the header page.
    // The read is clamped to `hdr_page`, so the range is present.
    let header_data: &[u8] = hdr_page.get(..header_len).ok_or(procmgr_errors::IO_ERROR)?;
    let machine = crate::arch::current::EXPECTED_ELF_MACHINE;
    let (ehdr, kind) =
        elf::validate_executable(header_data, machine).map_err(|_| procmgr_errors::INVALID_ELF)?;
    // `validate_executable` returns the header decoded; the parsers borrow it.
    let ehdr = &ehdr;
    let bias = match kind
    {
        elf::ElfKind::Exec => 0,
        elf::ElfKind::Dyn => choose_image_bias_or_default(),
    };
    let (span_min, span_end) =
        elf::load_span(ehdr, header_data).map_err(|_| procmgr_errors::INVALID_ELF)?;
    if kind == elf::ElfKind::Dyn
    {
        if !child_image_fits(bias, span_min, span_end)
        {
            return Err(procmgr_errors::INVALID_ELF);
        }
        // Load-bias observability: no ProcessInfo field carries the bias;
        // debugging correlates through this line (in-process code uses
        // __ehdr_start).
        std::os::seraph::log!("spawn image bias=0x{bias:x}");
    }
    let entry = elf::entry_point(ehdr)
        .checked_add(bias)
        .ok_or(procmgr_errors::INVALID_ELF)?;

    // Locate and pre-validate the RELATIVE relocation table (ET_DYN only; an
    // ET_EXEC image is fully linked and any vestigial table is ignored).
    let rela = if kind == elf::ElfKind::Dyn
    {
        elf::rela_table_metadata(ehdr, header_data, file_size, |off, dst| {
            reads.read(|| vfs_read_exact(file_cap.cap(), ipc_buf, off, dst))
        })
        .map_err(|_| reads.code(procmgr_errors::INVALID_ELF))?
    }
    else
    {
        None
    };
    let total_relocs = match &rela
    {
        Some(t) =>
        {
            let mut in_span = true;
            let count = walk_relocs_streaming(
                t,
                machine,
                |off, dst| reads.read(|| vfs_read_exact(file_cap.cap(), ipc_buf, off, dst)),
                |r| in_span &= elf::reloc_target_in_span(r, span_min, span_end),
            )
            .ok_or_else(|| reads.code(procmgr_errors::INVALID_ELF))?;
            if !in_span
            {
                return Err(procmgr_errors::INVALID_ELF);
            }
            count
        }
        None => 0,
    };

    // PT_GNU_RELRO (biased, page-rounded): fully-covered pages of writable
    // segments are mapped read-only after relocation.
    let ro_range = elf::relro_span(ehdr, header_data)
        .map_err(|_| procmgr_errors::INVALID_ELF)?
        .map(|(va, sz)| relro_page_range(va, sz, bias))
        .map(|range| range.ok_or(procmgr_errors::INVALID_ELF))
        .transpose()?;

    // Parse the optional stack-size note. Section headers and the note
    // section are fetched on demand via `vfs_read`; the helper hands a
    // closure that drives the same primitive used to stream `PT_LOAD`
    // pages, so no extra IPC machinery is involved.
    // A note outside `1..=MAX_PROCESS_STACK_PAGES` refuses the binary. A
    // failed read reads as no note, so it is checked apart.
    let stack_pages = resolve_stack_pages(elf::parse_stack_note_streaming(
        ehdr,
        file_size,
        |off, dst| reads.read(|| vfs_read_exact(file_cap.cap(), ipc_buf, off, dst)),
    ))
    .ok_or_else(|| reads.code(procmgr_errors::INVALID_ELF))?;
    if reads.failed()
    {
        return Err(procmgr_errors::IO_ERROR);
    }
    let layout = choose_child_layout();

    // The three child kernel-object caps, guarded from creation so
    // subsequent `?` returns release them in the correct order.
    let child_objs =
        create_child_kernel_objects(mms.cap(), ctx.sched_baseline, sched.priority, ipc_buf)?;

    // Stream each LOAD segment from VFS at segment granularity.
    let mut applied_relocs = 0u64;
    let mut image = ImageSpan {
        load_bias: bias,
        ..ImageSpan::default()
    };
    for seg_result in elf::load_segments_metadata(ehdr, header_data, file_size)
    {
        let seg = seg_result.map_err(|_| procmgr_errors::INVALID_ELF)?;
        if seg.memsz == 0
        {
            continue;
        }

        let prot = segment_prot(&seg);
        // The segment's addresses come from the image; any that overflows
        // refuses it.
        let seg_vaddr = seg
            .vaddr
            .checked_add(bias)
            .ok_or(procmgr_errors::INVALID_ELF)?;
        let seg_end = seg_vaddr
            .checked_add(seg.memsz)
            .ok_or(procmgr_errors::INVALID_ELF)?;
        if seg.executable
        {
            image.add_text(seg_vaddr, seg_end);
        }
        let first_page = seg_vaddr & !0xFFF;
        let last_page_end = seg_end
            .checked_add(0xFFF)
            .ok_or(procmgr_errors::INVALID_ELF)?
            & !0xFFF;
        let num_pages = last_page_end.saturating_sub(first_page) / PAGE_SIZE;
        // `first_page` is `seg_vaddr` rounded down, so the difference is below a page.
        let dest_offset = seg_vaddr.saturating_sub(first_page) as usize;
        let load_ctx = ElfLoadCtx {
            file_cap: file_cap.cap(),
            ipc_buf,
            self_aspace,
        };
        let mut streamed = Ok(());

        // SAFETY: `child_objs.aspace()` is the fresh address space
        // `create_child_kernel_objects` retyped for this child above.
        unsafe {
            loader::load_elf_segment_into_child(
                first_page,
                num_pages,
                prot,
                if seg.writable { ro_range } else { None },
                self_aspace,
                child_objs.aspace(),
                mms.cap(),
                ipc_buf,
                |buf| {
                    streamed = stream_segment_bytes(buf, dest_offset, &seg, &load_ctx);
                    // Writable segments only, matching the kernel's init
                    // applier: a target in text/rodata goes unapplied and the
                    // applied-count check below rejects the image. A segment
                    // whose bytes did not all arrive fails the spawn below,
                    // so its walk would only add reads of the file.
                    if seg.writable
                        && streamed.is_ok()
                        && let Some(t) = &rela
                        && let Some(span) =
                            buf.get_mut(dest_offset..dest_offset.saturating_add(seg.memsz as usize))
                    {
                        // A read failure mid-walk leaves records unapplied;
                        // `reads` notes it, and the check after the segment
                        // fails the spawn.
                        let _ = walk_relocs_streaming(
                            t,
                            machine,
                            |off, dst| {
                                reads.read(|| {
                                    vfs_read_exact(load_ctx.file_cap, load_ctx.ipc_buf, off, dst)
                                })
                            },
                            |r| {
                                // The count is at most the table's record count.
                                applied_relocs = applied_relocs.saturating_add(
                                    elf::apply_reloc_in_span(r, bias, seg.vaddr, span),
                                );
                            },
                        );
                    }
                },
            )
        }?;
        // A segment whose file bytes did not all arrive would run with a
        // zeroed tail; the spawn fails instead. So does a failed read in the
        // segment's relocation walk, before the next segment reads the file.
        streamed?;
        if reads.failed()
        {
            return Err(procmgr_errors::IO_ERROR);
        }
    }
    // Every pre-validated record must have landed in exactly one segment;
    // a shortfall means a target in a gap between segments or a lost read.
    if applied_relocs != total_relocs
    {
        std::os::seraph::log!(
            warn: "reloc application mismatch applied={applied_relocs} expected={total_relocs}"
        );
        return Err(procmgr_errors::INVALID_ELF);
    }

    // Extract PT_TLS metadata before closing the file — we may need another
    // VFS read to pull `.tdata` into the main thread's TLS block.
    let tls_seg = elf::tls_segment_metadata(ehdr, header_data, file_size)
        .map_err(|_| procmgr_errors::INVALID_ELF)?;
    let tls_vaddr = match tls_seg
    {
        Some(s) => s
            .vaddr
            .checked_add(bias)
            .ok_or(procmgr_errors::INVALID_ELF)?,
        None => 0,
    };
    let tls_template = tls_seg.map_or_default(|s| ChildTlsTemplate {
        vaddr: tls_vaddr,
        filesz: s.filesz,
        memsz: s.memsz,
        align: s.align,
    });

    // Done with the header page; the scratch mapping owns `hdr_memory` and
    // its Drop releases both the VA reservation and the cap slot.
    drop(hdr_scratch);

    let main_tls = if let Some(seg) = tls_seg
        && tls_template.memsz != 0
    {
        // SAFETY: `child_objs.aspace()` is the fresh address space
        // `create_child_kernel_objects` retyped for this child above.
        unsafe {
            prepare_main_tls_from_vfs(
                self_aspace,
                child_objs.aspace(),
                &tls_template,
                seg.offset,
                file_cap.cap(),
                mms.cap(),
                ipc_buf,
                &layout,
                |template| {
                    // Re-apply the .tdata-targeting relocations to this
                    // independent copy; the image copy was relocated (and
                    // counted) during segment loading.
                    if let Some(t) = &rela
                    {
                        let _ = walk_relocs_streaming(
                            t,
                            machine,
                            |off, dst| {
                                reads.read(|| vfs_read_exact(file_cap.cap(), ipc_buf, off, dst))
                            },
                            |r| {
                                let _ = elf::apply_reloc_in_span(r, bias, seg.vaddr, template);
                            },
                        );
                    }
                },
            )
        }
        // § Label 13 answers a failure of the main thread's TLS block
        // `IO_ERROR` when a read of the file failed, and `OUT_OF_MEMORY`
        // whatever other cause the helper reports.
        .map_err(|e| {
            if e == procmgr_errors::IO_ERROR
            {
                e
            }
            else
            {
                reads.code(procmgr_errors::OUT_OF_MEMORY)
            }
        })?
    }
    else
    {
        MainTls::default()
    };
    let main_tls_memory_guard = CapGuard::new(main_tls.memory_cap);
    // A failed read in the template's relocation walk leaves `.tdata`
    // records unapplied, which the walk does not report.
    if reads.failed()
    {
        return Err(procmgr_errors::IO_ERROR);
    }

    // Disarm and consume the file cap: success-path `vfs_close` issues
    // FS_CLOSE and deletes the slots. From here on `file_cap` is no longer
    // available; any subsequent failure must not depend on it.
    let raw_file = file_cap.disarm();
    vfs_close(raw_file, ipc_buf);

    let universals = UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_send_source: ctx.log_ep,
        memmgr_endpoint: mms.cap(),
        memmgr_badge: mms.badge(),
        registry_send_source: ctx.registry_ep,
        sched_baseline: ctx.sched_baseline,
        paging,
        self_memmgr_ep: ctx.memmgr_ep,
    };
    let reservation = next_process_badge(tables)?;
    let process_badge = reservation.badge();
    // SAFETY: `child_objs.aspace()` is the fresh address space
    // `create_child_kernel_objects` retyped for this child above.
    let info_caps = unsafe {
        populate_child_info(
            self_aspace,
            child_objs.aspace(),
            child_objs.cspace(),
            child_objs.thread(),
            creator_endpoint,
            &universals,
            &tls_template,
            argv_env,
            ipc_buf,
            stack_pages,
            process_badge,
            sched,
            &layout,
        )
    }?;

    // SAFETY: `child_objs.aspace()` is the fresh address space
    // `create_child_kernel_objects` retyped for this child above.
    unsafe {
        map_child_stack_and_ipc(
            child_objs.aspace(),
            mms.cap(),
            ipc_buf,
            stack_pages,
            &layout,
        )
    }
    // § Label 1 and § Label 13 answer a failed stack or IPC-buffer page
    // `OUT_OF_MEMORY`, whatever cause the helper reports.
    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;

    // Commit point: hand the accumulated cap values to `finalize_creation`,
    // which records them in the process table on success. The guards stay
    // armed across the call so a `finalize_creation` failure releases every
    // resource on Drop; only after Ok do we disarm the guards, transferring
    // ownership to the table entry. `finalize_creation` cleans up the
    // caller-facing caps it mints internally (process_handle,
    // thread_for_caller) on any of its own failure arms.
    let main_tls_for_finalize = MainTls {
        memory_cap: main_tls_memory_guard.cap(),
        base_va: main_tls.base_va,
    };
    let result = finalize_creation(
        child_objs.aspace(),
        child_objs.cspace(),
        child_objs.thread(),
        &info_caps,
        entry,
        main_tls_for_finalize,
        tables,
        self_endpoint,
        deaths,
        mms.cap(),
        mms.badge(),
        process_badge,
        universals.paging,
        universals.self_memmgr_ep,
        parent_relay_cap,
        sched.band_max,
        image,
        ipc_buf,
        &layout,
        self_aspace,
    );
    if result.is_ok()
    {
        let _ = child_objs.disarm();
        let _ = mms.disarm();
        info_caps.disarm();
        let _ = main_tls_memory_guard.disarm();
    }
    result
}

// ── Process destruction ─────────────────────────────────────────────────────

/// Destroy a process identified by `badge`.
///
/// For each kernel object procmgr held on behalf of the child
/// (`thread`, `aspace`, `cspace`, `ProcessInfo` memory cap) we first `cap_revoke`
/// to kill every descendant cap anywhere in the system — crucially, the
/// self-ref copies procmgr installed inside the child's `CSpace` during
/// `populate_child_info`. Without the revoke, those descendants keep the
/// object alive: e.g. the child's own `cspace_cap` slot inside its `CSpace`
/// holds a reference to the `CSpace` itself, so `cap_delete` on procmgr's
/// copy alone would leave refcount at 1 and leak the whole aspace +
/// everything the `CSpace` references.
///
/// Once revoked, `cap_delete` on procmgr's remaining root cap drops the
/// final reference. The kernel's `dealloc_object` path then tears down the
/// `CSpace` (dec-refing every slot it contains) and the `AddressSpace`'s
/// page tables. The child's heap / stack / IPC / `ProcessInfo` pages are
/// `owns_memory = false` derivations of memmgr's pool, so dropping them
/// frees nothing to the sealed buddy; memmgr reclaims those pages into its
/// pool via the process-death notification, which a started
/// `CREATE_DMA_HOLD` child's teardown holds back ([`teardown_entry`]).
///
/// Returns the exit reason the process is torn down with, for the caller to
/// record in the recent-exits ring so `QUERY_PROCESS` answers `EXITED` for
/// it: the reason the kernel retained when the main thread had already
/// exited (a death procmgr's drain had not reaped yet), else `EXIT_KILLED`,
/// the reason the kernel records for a thread its teardown stops. The death
/// forwarded to logd carries the same reason.
///
/// With [`ExitRecord::Record`], the exit is recorded in the recent-exits ring
/// under the same lock that takes the entry, so a `QUERY_PROCESS` served on
/// another worker finds the process either live or exited, never unknown.
///
/// Idempotent: returns `None` if the badge is unknown (already destroyed).
pub fn destroy_process(
    badge: u64,
    memmgr_ep: u64,
    ipc_buf: *mut u64,
    tables: &Tables,
    record: ExitRecord,
) -> Option<u64>
{
    let (tail, exit_reason) = {
        let mut state = tables.lock();
        let entry = state.table.take_by_badge(badge)?;
        let exit_reason =
            match syscall::cap_info(entry.thread_cap, syscall_abi::CAP_INFO_THREAD_STATE)
            {
                Ok(packed) if (packed >> 32) as u32 == syscall_abi::THREAD_STATE_EXITED =>
                {
                    packed & 0xFFFF_FFFF
                }
                _ => EXIT_KILLED,
            };
        match record
        {
            ExitRecord::Record => state.recent.record(badge, exit_reason, crate::now_ns()),
            ExitRecord::Omit => (),
        }
        (
            teardown_entry(entry, exit_reason, &mut state.table),
            exit_reason,
        )
    };
    tail.finish(memmgr_ep, ipc_buf);
    Some(exit_reason)
}

/// Whether [`destroy_process`] records the destroyed process's exit in the
/// recent-exits ring, for `QUERY_PROCESS`.
#[derive(Clone, Copy)]
pub enum ExitRecord
{
    /// Recorded: a handle to the process may still query its exit.
    Record,
    /// Not recorded: no handle to the process survives the destroy.
    Omit,
}

/// Reap the process `badge` names after its death, with `exit_reason`, as
/// [`destroy_process`] tears down a destroyed one: take its entry, record
/// the exit in the recent-exits ring, and tear it down, under one hold of the
/// table lock, then tell memmgr after it. Nothing when the badge is unknown
/// (a destroy or an earlier event already reaped it).
pub fn reap_dead(badge: u64, exit_reason: u64, memmgr_ep: u64, ipc_buf: *mut u64, tables: &Tables)
{
    let tail = {
        let mut state = tables.lock();
        let Some(entry) = state.table.take_by_badge(badge)
        else
        {
            return;
        };
        state.recent.record(badge, exit_reason, crate::now_ns());
        teardown_entry(entry, exit_reason, &mut state.table)
    };
    tail.finish(memmgr_ep, ipc_buf);
}

/// Send memmgr the held-back `PROCESS_DIED` of the torn-down
/// `CREATE_DMA_HOLD` child the release token `sender` names (`RELEASE_HOLD`),
/// then drop procmgr's badged memmgr SEND for it.
///
/// # Errors
/// [`ReleaseRefusal::Unauthorized`] when `sender` is not a release token, the
/// hold staying; [`ReleaseRefusal::NotHeld`] when the table keeps no reclaim
/// for the token's child.
pub fn release_hold(
    sender: u64,
    memmgr_ep: u64,
    ipc_buf: *mut u64,
    tables: &Tables,
) -> Result<(), ReleaseRefusal>
{
    // The hold is taken under the table lock; memmgr is told after it.
    let held = tables.lock().table.holds_mut().release(sender)?;
    notify_memmgr_died(memmgr_ep, held.memmgr_badge, ipc_buf);
    if held.memmgr_send_cap != 0
    {
        let _ = syscall::cap_delete(held.memmgr_send_cap);
    }
    Ok(())
}

/// Notify memmgr that a process died. Memmgr returns every memory cap attributed
/// to the process badge to the free pool. Idempotent on memmgr's side.
fn notify_memmgr_died(memmgr_ep: u64, memmgr_badge: u64, ipc_buf: *mut u64)
{
    if memmgr_ep == 0 || memmgr_badge == 0
    {
        return;
    }
    let msg = IpcMessage::builder(memmgr_labels::PROCESS_DIED)
        .word(0, memmgr_badge)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) };
}

/// Shared cleanup for both the explicit-IPC reap path ([`destroy_process`])
/// and the auto-reap path ([`reap_dead`], from `dispatch_death` and
/// `resync_deaths` in `main.rs`). Revokes and deletes every kernel object
/// procmgr held on behalf of the child, and returns the steps left for
/// after the table lock ([`TeardownTail::finish`]): the memmgr reclaim and
/// the death forward, with `exit_reason`, to logd
/// ([`forward_death_to_logd`]).
///
/// The caller holds the table lock from the entry's take to the return, and
/// the steps here are syscalls that wait on no other process. So the
/// teardown is one step to every other thread: a `DESTROY_PROCESS` that
/// finds no entry finds it torn down, and a `RELEASE_HOLD` after it finds
/// its reclaim parked.
///
/// The memmgr reclaim of a started child created with `CREATE_DMA_HOLD` is
/// parked in the table's held reclaims instead of sent: a device the child drove may still be
/// writing its frames, so they return to memmgr only on the creator's
/// `RELEASE_HOLD` on the child's release token ([`release_hold`];
/// docs/process-lifecycle.md § Process Death). Its `CSpace` goes as any
/// child's: a frame a client lent the child for its device stays out of
/// memmgr's pool through devmgr's DMA-mapping capability instead
/// (docs/device-management.md § DMA-Safe Teardown).
///
/// Note: the bound death-notification observers in the child thread's TCB
/// and address space are released automatically when the objects are torn
/// down by the cap-revokes below — no explicit unbind syscall is required.
pub fn teardown_entry(
    mut entry: ProcessEntry,
    exit_reason: u64,
    table: &mut ProcessTable,
) -> TeardownTail
{
    // Order: threads first so the scheduler drops any residual reference to
    // the aspace before we tear down its page tables: the main thread, then
    // the registered ones, whose caps, and every copy `ATTACH_PROCESS` handed
    // out, go with procmgr's. Then cspace (which owns every cap the child
    // held, the runtime's own thread caps among them) before aspace (whose
    // dealloc walks the page tables). pi_memory and the argv/env region
    // last — leaf resources the child used read-only; no other object
    // references them.
    let _ = syscall::cap_revoke_all(entry.thread_cap);
    let _ = syscall::cap_delete(entry.thread_cap);
    entry
        .threads
        .take_all()
        .into_iter()
        .for_each(release_registered_thread);
    let _ = syscall::cap_revoke_all(entry.cspace_cap);
    let _ = syscall::cap_delete(entry.cspace_cap);
    let _ = syscall::cap_revoke_all(entry.aspace_cap);
    let _ = syscall::cap_delete(entry.aspace_cap);
    let _ = syscall::cap_revoke_all(entry.pi_memory_cap);
    let _ = syscall::cap_delete(entry.pi_memory_cap);
    if entry.argv_env_memory_cap != 0
    {
        let _ = syscall::cap_revoke_all(entry.argv_env_memory_cap);
        let _ = syscall::cap_delete(entry.argv_env_memory_cap);
    }
    if entry.debugger != 0
    {
        let _ = syscall::cap_delete(entry.debugger);
    }
    if entry.tls_memory_cap != 0
    {
        let _ = syscall::cap_revoke_all(entry.tls_memory_cap);
        let _ = syscall::cap_delete(entry.tls_memory_cap);
    }

    // Drop per-process root/cwd caps installed via `CONFIGURE_NAMESPACE`
    // but never consumed by `start_process` (child destroyed before
    // start). On the normal path these slots are already zero —
    // `start_process` deletes them after `cap_copy`.
    if entry.namespace_override != 0
    {
        let _ = syscall::cap_delete(entry.namespace_override);
    }
    if entry.cwd_override != 0
    {
        let _ = syscall::cap_delete(entry.cwd_override);
    }

    // memmgr reclaims every memory cap attributed to this child's memmgr
    // badge after the lock, unless the reclaim is held for the creator's
    // `RELEASE_HOLD`.
    let parked = table.holds_mut().park(&entry);
    TeardownTail {
        badge: entry.badge,
        exit_reason,
        reclaim: (!parked).then_some((entry.memmgr_badge, entry.memmgr_send_cap)),
    }
}

/// What a teardown ([`teardown_entry`]) leaves for after the table lock.
#[must_use]
pub struct TeardownTail
{
    badge: u64,
    exit_reason: u64,
    /// The child's memmgr badge and procmgr's badged memmgr SEND for it,
    /// unless its reclaim was parked.
    reclaim: Option<(u64, u64)>,
}

impl TeardownTail
{
    /// Notify memmgr to reclaim the child's memory, then drop procmgr's
    /// badged SEND copy, unless the reclaim was parked; then forward the
    /// death to logd. Called with no lock held.
    pub fn finish(self, memmgr_ep: u64, ipc_buf: *mut u64)
    {
        if let Some((memmgr_badge, memmgr_send_cap)) = self.reclaim
        {
            notify_memmgr_died(memmgr_ep, memmgr_badge, ipc_buf);
            if memmgr_send_cap != 0
            {
                let _ = syscall::cap_delete(memmgr_send_cap);
            }
        }
        forward_death_to_logd(self.badge, self.exit_reason);
    }
}

// ── Process start ───────────────────────────────────────────────────────────

/// Start a previously created (suspended) process.
///
/// Patches the child's `ProcessInfo.system_root_cap` slot from the
/// per-process namespace cap installed via `CONFIGURE_NAMESPACE`. If
/// no cap was installed, the slot stays zero — the child runs without
/// namespace authority. `finalize_creation` already bound the child's
/// main thread to one of procmgr's death queues, so this just configures
/// the thread and kicks it.
///
/// # Errors
/// Returns the `START_PROCESS` reply code (`services/procmgr/docs/ipc-interface.md`
/// § Label 2):
/// - `procmgr_errors::INVALID_BADGE` (4) — no process in `table` carries
///   `badge`.
/// - `procmgr_errors::ALREADY_STARTED` (5) — the process was started before.
/// - `procmgr_errors::OUT_OF_MEMORY` (2) — a namespace or cwd override is
///   pending and either the scratch mapping of the child's `ProcessInfo`
///   page or the `cap_copy` of an override cap into the child's `CSpace`
///   failed.
/// - `procmgr_errors::THREAD_CONFIGURE_FAILED` (3) —
///   `thread_configure_with_tls` of the child's main thread failed.
/// - `procmgr_errors::THREAD_START_FAILED` (6) — `thread_start` of the
///   child's main thread failed with an error other than `Interrupted`,
///   which is retried.
pub fn start_process(badge: u64, table: &mut ProcessTable, self_aspace: u64) -> Result<(), u64>
{
    let entry = table
        .find_mut_by_badge(badge)
        .ok_or(procmgr_errors::INVALID_BADGE)?;

    if entry.started
    {
        return Err(procmgr_errors::ALREADY_STARTED);
    }

    if entry.namespace_override != 0 || entry.cwd_override != 0
    {
        let pi_memory = entry.pi_memory_cap;
        let child_cspace = entry.cspace_cap;
        let scratch = ScratchMapping::map(self_aspace, pi_memory, 1, syscall::MAP_WRITABLE)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let scratch_va = scratch.va();
        // SAFETY: scratch_va is page-aligned and mapped writable; PI struct
        // lives at offset 0 per the ABI.
        let pi = unsafe { process_abi::process_info_mut(scratch_va) };
        if entry.namespace_override != 0
        {
            let slot = syscall::cap_copy(
                entry.namespace_override,
                child_cspace,
                syscall::RIGHTS_EP_SEND,
            )
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            pi.system_root_cap = slot;
            let _ = syscall::cap_delete(entry.namespace_override);
            entry.namespace_override = 0;
        }
        if entry.cwd_override != 0
        {
            let slot = syscall::cap_copy(entry.cwd_override, child_cspace, syscall::RIGHTS_EP_SEND)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            pi.current_dir_cap = slot;
            let _ = syscall::cap_delete(entry.cwd_override);
            entry.cwd_override = 0;
        }
    }

    // SAFETY: the thread is bound to the child's address space, never
    // procmgr's own, so its entry state touches nothing procmgr runs on.
    unsafe {
        syscall::thread_configure_with_tls(
            entry.thread_cap,
            entry.entry_point,
            entry.stack_top_vaddr,
            entry.process_info_va,
            entry.tls_base_va,
        )
    }
    .map_err(|_| procmgr_errors::THREAD_CONFIGURE_FAILED)?;

    // `Interrupted` means procmgr's thread was stopped while the start waited
    // for the child's thread to settle; nothing was started, so the start is
    // retried.
    loop
    {
        match syscall::thread_start(entry.thread_cap)
        {
            Ok(()) => break,
            Err(e) if e == SyscallError::Interrupted as i64 =>
            {}
            Err(_) => return Err(procmgr_errors::THREAD_START_FAILED),
        }
    }

    entry.started = true;
    Ok(())
}
