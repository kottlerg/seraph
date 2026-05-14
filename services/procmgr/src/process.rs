// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/process.rs

//! Process table, creation, and lifecycle management.
//!
//! Manages the process table and provides functions for creating processes
//! from in-memory ELF images or by streaming from VFS, as well as starting
//! suspended processes.

use crate::loader::{self, ScratchMapping};
use ipc::{IpcMessage, memmgr_labels, procmgr_errors};
use process_abi::{
    DEFAULT_PROCESS_STACK_PAGES, MAX_PROCESS_STACK_PAGES, PROCESS_ABI_VERSION, PROCESS_INFO_VADDR,
    PROCESS_MAIN_TLS_MAX_PAGES, PROCESS_MAIN_TLS_VADDR, PROCESS_STACK_TOP,
};
use syscall_abi::PAGE_SIZE;

// Bootstrap-cross-boundary VA: procmgr picks the per-child main-thread
// IPC-buffer VA and writes it into `ProcessInfo.ipc_buffer_vaddr`. The
// child's `_start` reads it back. Disjoint from the page-reservation
// arena (above 0x1_0000_0000) and from the heap zone (0x4000_0000..0x8000_0000).
const CHILD_IPC_BUF_VA: u64 = 0x0000_7FFF_FFFE_0000;

/// Max file data bytes per VFS read IPC. Word 0 = `bytes_read`, words 1..63 = data.
const VFS_CHUNK_SIZE: u64 = 63 * 8; // 504 bytes

/// Next token value (monotonically increasing, never zero).
static NEXT_TOKEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Maximum concurrent child processes procmgr tracks.
///
/// Independent of any wait-set capacity — the shared death queue fans in
/// all children's exit events with kernel-side multi-bind, so there is no
/// per-child wait-set slot. Raise this (and the death queue capacity in
/// `main.rs`) as real workloads demand.
pub const MAX_PROCESSES: usize = 32;

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
#[allow(dead_code)]
pub struct ProcessEntry
{
    token: u64,
    aspace_cap: u32,
    cspace_cap: u32,
    thread_cap: u32,
    pi_frame_cap: u32,
    tls_frame_cap: u32,
    /// Slot in procmgr's `CSpace` of the tokened SEND cap on memmgr's
    /// endpoint that procmgr minted via `REGISTER_PROCESS` for this child.
    /// Held until `PROCESS_DIED`. Zero when memmgr was unwired at create
    /// time (early-boot regression path).
    memmgr_send_cap: u32,
    /// Memmgr-side process token for this child. Sent in the
    /// `PROCESS_DIED` payload so memmgr can reclaim the right record.
    memmgr_token: u64,
    /// Per-process system-root cap installed by
    /// [`ProcessTable::configure_namespace`]. Zero means the child
    /// runs with no namespace authority (`ProcessInfo.system_root_cap`
    /// stays zero; std-side fs ops on absolute paths return
    /// `Unsupported`). Held in procmgr's `CSpace` from
    /// `CONFIGURE_NAMESPACE` until [`start_process`] consumes it
    /// (`cap_copy` into the child, then `cap_delete` of the procmgr-side
    /// slot) or the entry is torn down (`teardown_entry` deletes the
    /// slot if still present).
    namespace_override: u32,
    /// Per-process cwd cap installed by
    /// [`ProcessTable::configure_namespace`]. Zero means the child has
    /// no cwd cap (`ProcessInfo.current_dir_cap` stays zero; relative
    /// paths return `Unsupported` until installed). Same lifetime
    /// rules as `namespace_override`.
    cwd_override: u32,
    entry_point: u64,
    tls_base_va: u64,
    started: bool,
}

impl ProcessEntry
{
    pub fn token(&self) -> u64
    {
        self.token
    }
}

/// Ring of recently auto-reaped processes, queried on `QUERY_PROCESS`
/// table miss to distinguish "exited recently" from "never existed".
/// Best-effort retention: oldest entries are overwritten as new ones
/// arrive; queries on rotated-out tokens return `None`.
#[derive(Clone, Copy)]
pub struct RecentExits
{
    ring: [Option<RecentExit>; RECENT_EXITS_SLOTS],
    head: usize,
}

#[derive(Clone, Copy)]
struct RecentExit
{
    token: u64,
    exit_reason: u64,
}

const RECENT_EXITS_SLOTS: usize = 16;

impl RecentExits
{
    pub const fn new() -> Self
    {
        Self {
            ring: [None; RECENT_EXITS_SLOTS],
            head: 0,
        }
    }

    pub fn record(&mut self, token: u64, exit_reason: u64)
    {
        self.ring[self.head] = Some(RecentExit { token, exit_reason });
        self.head = (self.head + 1) % RECENT_EXITS_SLOTS;
    }

    pub fn find(&self, token: u64) -> Option<u64>
    {
        self.ring
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.token == token)
            .map(|e| e.exit_reason)
    }
}

pub struct ProcessTable
{
    entries: [Option<ProcessEntry>; MAX_PROCESSES],
}

impl ProcessTable
{
    pub const fn new() -> Self
    {
        const NONE: Option<ProcessEntry> = None;
        Self {
            entries: [NONE; MAX_PROCESSES],
        }
    }

    fn insert(&mut self, entry: ProcessEntry) -> bool
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

    fn find_mut_by_token(&mut self, token: u64) -> Option<&mut ProcessEntry>
    {
        self.entries
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|e| e.token == token)
    }

    fn take_by_token(&mut self, token: u64) -> Option<ProcessEntry>
    {
        for slot in &mut self.entries
        {
            if let Some(entry) = slot.as_ref()
                && entry.token == token
            {
                return slot.take();
            }
        }
        None
    }

    /// Remove and return the entry whose token matches `correlator` in its
    /// low 32 bits. Used by the auto-reap dispatch to resolve a death event
    /// back to its process. Stale correlators (entry already reaped)
    /// return `None`; callers drop such events silently.
    pub fn take_by_correlator(&mut self, correlator: u32) -> Option<ProcessEntry>
    {
        for slot in &mut self.entries
        {
            if let Some(entry) = slot.as_ref()
                && (entry.token as u32) == correlator
            {
                return slot.take();
            }
        }
        None
    }

    /// Lightweight status lookup for `QUERY_PROCESS`. Returns
    /// `(started, thread_cap)` when an entry is present; `None` if the
    /// token is unknown (already reaped or never existed).
    ///
    /// `thread_cap` is procmgr's `CSpace` slot for the child's main thread,
    /// suitable for `cap_info`'s `CAP_INFO_THREAD_STATE` selector to
    /// fetch the kernel-authoritative lifecycle snapshot.
    pub fn query_by_token(&self, token: u64) -> Option<(bool, u32)>
    {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.token == token)
            .map(|e| (e.started, e.thread_cap))
    }

    /// Install one direction's shmem pipe on a suspended child
    /// identified by `token`.
    ///
    /// `direction` is one of `ipc::procmgr_labels::PIPE_DIR_STDIN`,
    /// `PIPE_DIR_STDOUT`, `PIPE_DIR_STDERR`. The three caps are
    /// `cap_copy`'d into the child's `CSpace` with `RIGHTS_MAP_RW` for
    /// the frame and `RIGHTS_ALL` for the two signals (signal objects
    /// don't currently distinguish send/wait at the cap-rights level —
    /// each peer holds a full cap and uses send or wait as appropriate).
    /// The resulting slot indices are written into the matching
    /// `<dir>_frame_cap` / `<dir>_data_signal_cap` /
    /// `<dir>_space_signal_cap` fields of the child's `ProcessInfo`.
    ///
    /// Idempotent per direction before start; later calls overwrite the
    /// previous triple for that direction. Different directions are
    /// independent.
    ///
    /// # Errors
    /// - `procmgr_errors::INVALID_TOKEN` — no entry for `token`.
    /// - `procmgr_errors::ALREADY_STARTED` — target is already running.
    /// - `procmgr_errors::INVALID_ARGUMENT` — bad direction selector or
    ///   any cap is zero.
    /// - `procmgr_errors::OUT_OF_MEMORY` — mapping / `cap_copy` failure.
    pub fn configure_pipe(
        &mut self,
        token: u64,
        self_aspace: u32,
        direction: u64,
        frame: u32,
        data_signal: u32,
        space_signal: u32,
    ) -> Result<(), u64>
    {
        if frame == 0 || data_signal == 0 || space_signal == 0
        {
            return Err(procmgr_errors::INVALID_ARGUMENT);
        }
        let entry = self
            .find_mut_by_token(token)
            .ok_or(procmgr_errors::INVALID_TOKEN)?;
        if entry.started
        {
            return Err(procmgr_errors::ALREADY_STARTED);
        }
        let pi_frame = entry.pi_frame_cap;
        let child_cspace = entry.cspace_cap;

        let scratch = ScratchMapping::map(self_aspace, pi_frame, 1, syscall::MAP_WRITABLE)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
        let scratch_va = scratch.va();

        // SAFETY: scratch_va is mapped writable for one page; PI struct
        // lives at offset 0 per the ABI.
        let pi = unsafe { process_abi::process_info_mut(scratch_va) };

        let frame_slot = syscall::cap_copy(frame, child_cspace, syscall::RIGHTS_MAP_RW)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let data_slot = syscall::cap_copy(data_signal, child_cspace, syscall::RIGHTS_ALL)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
        let space_slot = syscall::cap_copy(space_signal, child_cspace, syscall::RIGHTS_ALL)
            .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;

        match direction
        {
            ipc::procmgr_labels::PIPE_DIR_STDIN =>
            {
                pi.stdin_frame_cap = frame_slot;
                pi.stdin_data_signal_cap = data_slot;
                pi.stdin_space_signal_cap = space_slot;
            }
            ipc::procmgr_labels::PIPE_DIR_STDOUT =>
            {
                pi.stdout_frame_cap = frame_slot;
                pi.stdout_data_signal_cap = data_slot;
                pi.stdout_space_signal_cap = space_slot;
            }
            ipc::procmgr_labels::PIPE_DIR_STDERR =>
            {
                pi.stderr_frame_cap = frame_slot;
                pi.stderr_data_signal_cap = data_slot;
                pi.stderr_space_signal_cap = space_slot;
            }
            _ =>
            {
                return Err(procmgr_errors::INVALID_ARGUMENT);
            }
        }

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
    /// - `procmgr_errors::INVALID_TOKEN` — no entry for `token` (caps dropped).
    /// - `procmgr_errors::ALREADY_STARTED` — target is already running (caps dropped).
    /// - `procmgr_errors::INVALID_ARGUMENT` — `root_cap` is zero.
    pub fn configure_namespace(
        &mut self,
        token: u64,
        root_cap: u32,
        cwd_cap: u32,
    ) -> Result<(), u64>
    {
        if root_cap == 0
        {
            if cwd_cap != 0
            {
                let _ = syscall::cap_delete(cwd_cap);
            }
            return Err(procmgr_errors::INVALID_ARGUMENT);
        }
        let Some(entry) = self.find_mut_by_token(token)
        else
        {
            let _ = syscall::cap_delete(root_cap);
            if cwd_cap != 0
            {
                let _ = syscall::cap_delete(cwd_cap);
            }
            return Err(procmgr_errors::INVALID_TOKEN);
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

// ── Result type ─────────────────────────────────────────────────────────────

/// Result of a successful process creation call.
pub struct CreateResult
{
    /// Tokened endpoint cap for the caller to use with `START_PROCESS`.
    pub process_handle: u32,
    /// Derived Thread cap to transfer to caller (CONTROL right).
    pub thread_for_caller: u32,
}

// ── Child setup helpers ─────────────────────────────────────────────────────

/// Universal bootstrap caps procmgr threads through into every child.
///
/// Procmgr's own service endpoint plus the system log discovery cap.
///
/// The child receives a tokened SEND copy of `procmgr_endpoint` so it
/// can call `REQUEST_FRAMES` / `CREATE_PROCESS`, and
/// an un-tokened SEND copy of `log_discovery` so it can `GET_LOG_CAP`
/// against the system log endpoint on first `seraph::log!` call (the
/// discovery cap by itself grants no log identity and no observability;
/// it merely lets the holder request a freshly-minted tokened cap).
///
/// Stdio caps (stdin, stdout, stderr) are intentionally NOT part of this
/// struct: they are not a universal property of processes, and each can
/// route to a different endpoint. A spawner that wants the child to have
/// any stdio pipe wiring installs it via separate `CONFIGURE_PIPE`
/// IPCs (one per piped direction) between `CREATE_PROCESS` and
/// `START_PROCESS`.
pub struct UniversalCaps
{
    pub procmgr_endpoint: u32,
    /// Un-tokened SEND cap on the system log endpoint, sourced from the
    /// `log_ep` slot procmgr received during init bootstrap. Zero when
    /// procmgr has no log endpoint (e.g. a future no-log boot mode).
    pub log_discovery: u32,
    /// Tokened SEND cap on memmgr's service endpoint, freshly minted by
    /// `memmgr_labels::REGISTER_PROCESS` for this child. The cap lives in
    /// procmgr's `CSpace` on entry; `populate_child_info` copies it into
    /// the child's `CSpace` and records the destination slot in
    /// `ProcessInfo.memmgr_endpoint_cap`. Zero when memmgr is not yet
    /// reachable (procmgr itself, init); the child's heap-bootstrap then
    /// no-ops and the child cannot allocate.
    pub memmgr_endpoint: u32,
    /// Memmgr-side process token paired with `memmgr_endpoint`. Sent in
    /// `memmgr_labels::PROCESS_DIED` at child teardown so memmgr can
    /// reclaim the right ledger entry. Zero when memmgr is not wired.
    pub memmgr_token: u64,
}

/// Program arguments delivered to a child process at spawn time.
///
/// `blob` is a concatenation of `count` NUL-terminated UTF-8 strings. Empty
/// slice + zero count means "no argv". See `project_argv_env_invariants.md`:
/// plain data only, no caps, no security-relevant content, capped to what
/// fits in the `ProcessInfo` page after the struct.
#[derive(Clone, Copy, Default)]
pub struct ChildArgs<'a>
{
    pub blob: &'a [u8],
    pub count: u32,
}

/// Environment variables delivered to a child process at spawn time.
///
/// Same shape as [`ChildArgs`] except each entry is `KEY=VALUE`. Empty
/// slice + zero count means "no env". Same page-remainder bound.
#[derive(Clone, Copy, Default)]
pub struct ChildEnv<'a>
{
    pub blob: &'a [u8],
    pub count: u32,
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

/// Result of `prepare_main_tls`: the frame cap procmgr retains for teardown
/// plus the `tls_base` VA to pass to `SYS_THREAD_CONFIGURE`.
///
/// Both fields are zero when the child has no `PT_TLS` segment.
#[derive(Clone, Copy, Default)]
pub struct MainTls
{
    pub frame_cap: u32,
    pub base_va: u64,
}

/// Populate a `ProcessInfo` page for a child process and map it read-only.
///
/// Installs the creator endpoint cap (if any) and the procmgr service
/// endpoint into the child `CSpace` and records their slots in the child's
/// `ProcessInfo`. Stdio pipe slots (frame + two signal caps per
/// direction) are left zero here and are populated afterwards by
/// [`ProcessTable::configure_pipe`], which remaps the same `pi_frame`
/// writable, installs caller-supplied caps via `cap_copy` into the
/// child's `CSpace`, and writes the slot indices into the PI page. This
/// split keeps the core `CREATE_PROCESS` path stdio-agnostic and lets
/// spawners pipe each direction independently.
// similar_names: child_aspace/child_cspace are intentionally parallel.
// too_many_arguments: each cluster is a small fixed-size bundle; collapsing
// them into one struct shifts the verbosity to the call sites without
// reducing the total parameter count. too_many_lines: this is the single
// transaction that owns one temporary scratch mapping for the PI page —
// splitting would require threading the partial state through helpers
// that all need the same self_aspace + child_cspace + write context.
#[allow(
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn populate_child_info(
    self_aspace: u32,
    child_aspace: u32,
    child_cspace: u32,
    child_thread: u32,
    creator_endpoint: u32,
    universals: &UniversalCaps,
    tls: &ChildTlsTemplate,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
    ipc_buf: *mut u64,
    stack_pages: u32,
) -> Option<u32>
{
    let pi_frame = crate::memmgr_alloc_page(universals.memmgr_endpoint, ipc_buf)?;
    let scratch = ScratchMapping::map(self_aspace, pi_frame, 1, syscall::MAP_WRITABLE)?;
    let scratch_va = scratch.va();
    // SAFETY: scratch_va mapped writable, one page.
    unsafe { core::ptr::write_bytes(scratch_va as *mut u8, 0, PAGE_SIZE as usize) };

    let child_thread_in_child =
        syscall::cap_copy(child_thread, child_cspace, syscall::RIGHTS_THREAD).ok()?;
    let child_aspace_in_child =
        syscall::cap_copy(child_aspace, child_cspace, syscall::RIGHTS_ALL).ok()?;
    let child_cspace_in_child =
        syscall::cap_copy(child_cspace, child_cspace, syscall::RIGHTS_CSPACE).ok()?;

    let creator_ep_in_child = if creator_endpoint != 0
    {
        // Preserve source rights: try ALL first (for services where
        // creator_endpoint doubles as a recv endpoint, e.g. fatfs service ep);
        // fall back to SEND for tokened send caps used by the bootstrap protocol.
        syscall::cap_copy(creator_endpoint, child_cspace, syscall::RIGHTS_ALL)
            .or_else(|_| syscall::cap_copy(creator_endpoint, child_cspace, syscall::RIGHTS_SEND))
            .ok()?
    }
    else
    {
        0
    };

    // procmgr's own service endpoint: install a SEND+GRANT copy so the child
    // can use it for `REQUEST_FRAMES` (send-only) and `CREATE_PROCESS` (needs
    // grant to transfer the module frame and creator endpoint in the same
    // call). Zero when procmgr has no procmgr above it — e.g. procmgr itself,
    // when init populates its `ProcessInfo`.
    let procmgr_ep_in_child = if universals.procmgr_endpoint != 0
    {
        syscall::cap_copy(
            universals.procmgr_endpoint,
            child_cspace,
            syscall::RIGHTS_SEND_GRANT,
        )
        .ok()?
    }
    else
    {
        0
    };

    // Discovery cap on the system log endpoint: SEND-only copy of the
    // procmgr-held un-tokened log endpoint cap. Lets the child issue
    // `GET_LOG_CAP` to lazy-acquire its tokened SEND cap on first
    // `seraph::log!` call. Zero when procmgr has no log endpoint, in
    // which case the macro silently drops.
    let log_discovery_in_child = if universals.log_discovery != 0
    {
        syscall::cap_copy(universals.log_discovery, child_cspace, syscall::RIGHTS_SEND).ok()?
    }
    else
    {
        0
    };

    // Stdio pipe caps are not installed here — CONFIGURE_PIPE remaps
    // this same pi_frame writable and fills in one direction's triple
    // (frame + data signal + space signal) per call, before the child
    // is started. Children that ship without any CONFIGURE_PIPE call
    // see all-zero stdio frame/signal slots, which std maps to silent
    // println! / EOF on stdin.

    // SAFETY: scratch_va is page-aligned and mapped writable.
    let pi = unsafe { process_abi::process_info_mut(scratch_va) };
    pi.version = PROCESS_ABI_VERSION;
    pi.self_thread_cap = child_thread_in_child;
    pi.self_aspace_cap = child_aspace_in_child;
    pi.self_cspace_cap = child_cspace_in_child;
    pi.ipc_buffer_vaddr = CHILD_IPC_BUF_VA;
    pi.creator_endpoint_cap = creator_ep_in_child;
    pi.procmgr_endpoint_cap = procmgr_ep_in_child;
    pi.memmgr_endpoint_cap = if universals.memmgr_endpoint != 0
    {
        // SEND_GRANT so the child can attach memmgr's tokened SEND to
        // outgoing messages it makes on the same endpoint (no current
        // protocol exercises that capability, but the rights mirror
        // `procmgr_endpoint_cap`'s shape).
        syscall::cap_copy(
            universals.memmgr_endpoint,
            child_cspace,
            syscall::RIGHTS_SEND_GRANT,
        )
        .ok()?
    }
    else
    {
        0
    };
    pi.stdin_frame_cap = 0;
    pi.stdout_frame_cap = 0;
    pi.stderr_frame_cap = 0;
    // System-root cap is installed at start_process time from the
    // per-process cap delivered via CONFIGURE_NAMESPACE. Defer the
    // copy so a child without an installed cap leaves the slot zero
    // and there is no inter-CSpace cap_delete primitive to clean up.
    pi.system_root_cap = 0;
    pi.current_dir_cap = 0;
    pi.log_discovery_cap = log_discovery_in_child;
    pi.stdin_data_signal_cap = 0;
    pi.stdin_space_signal_cap = 0;
    pi.stdout_data_signal_cap = 0;
    pi.stdout_space_signal_cap = 0;
    pi.stderr_data_signal_cap = 0;
    pi.stderr_space_signal_cap = 0;
    pi.tls_template_vaddr = tls.vaddr;
    pi.tls_template_filesz = tls.filesz;
    pi.tls_template_memsz = tls.memsz;
    pi.tls_template_align = tls.align;
    pi.stack_top_vaddr = PROCESS_STACK_TOP;
    pi.stack_pages = stack_pages;

    // Write the argv blob, then the env blob, into the page region
    // following the struct. Each blob begins at a u64-aligned offset so
    // std can read whole words safely; both must fit inside the remaining
    // page bytes — caller validates size before reaching here.
    let pi_size = core::mem::size_of::<process_abi::ProcessInfo>() as u64;
    let args_offset = (pi_size + 7) & !7;
    let args_end = if args.count > 0 && !args.blob.is_empty()
    {
        let blob_len = args.blob.len() as u64;
        if args_offset + blob_len > PAGE_SIZE
        {
            return None;
        }
        // SAFETY: range within the mapped page; source is plain bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                args.blob.as_ptr(),
                (scratch_va + args_offset) as *mut u8,
                args.blob.len(),
            );
        }
        pi.args_offset = args_offset as u32;
        pi.args_bytes = args.blob.len() as u32;
        pi.args_count = args.count;
        args_offset + blob_len
    }
    else
    {
        pi.args_offset = 0;
        pi.args_bytes = 0;
        pi.args_count = 0;
        args_offset
    };

    let env_offset = (args_end + 7) & !7;
    if env.count > 0 && !env.blob.is_empty()
    {
        let blob_len = env.blob.len() as u64;
        if env_offset + blob_len > PAGE_SIZE
        {
            return None;
        }
        // SAFETY: range within the mapped page; source is plain bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                env.blob.as_ptr(),
                (scratch_va + env_offset) as *mut u8,
                env.blob.len(),
            );
        }
        pi.env_offset = env_offset as u32;
        pi.env_bytes = env.blob.len() as u32;
        pi.env_count = env.count;
    }
    else
    {
        pi.env_offset = 0;
        pi.env_bytes = 0;
        pi.env_count = 0;
    }

    drop(scratch);

    let pi_ro = syscall::cap_derive(pi_frame, syscall::RIGHTS_MAP_READ).ok()?;
    syscall::mem_map(pi_ro, child_aspace, PROCESS_INFO_VADDR, 0, 1, 0).ok()?;
    // pi_frame stays in procmgr's CSpace as the teardown handle (revoke
    // cascades to any descendants); the mapping doesn't need pi_ro to
    // outlive this call.
    let _ = syscall::cap_delete(pi_ro);

    Some(pi_frame)
}

/// Intermediate state returned by [`alloc_main_tls_frame`] — a frame
/// mapped writable in procmgr's aspace at `scratch.va()` plus the layout
/// numbers needed to populate it and to finalise the mapping into the
/// child.
struct MainTlsAlloc
{
    frame_cap: u32,
    tls_base_offset: u64,
    tls_base_va: u64,
    scratch: ScratchMapping,
}

impl MainTlsAlloc
{
    fn scratch_va(&self) -> u64
    {
        self.scratch.va()
    }
}

/// Allocate a frame for the main thread's TLS block, map it writable in
/// procmgr's own aspace at a transient scratch VA, and zero it.
///
/// Returns `None` when the binary has no TLS, when the block exceeds the
/// single-frame budget, or when alignment demands would outrun the page
/// mapping. Callers write the `.tdata` template starting at the scratch
/// VA and then call [`finalize_main_tls`] to install the TCB self-pointer
/// and remap the frame into the child.
fn alloc_main_tls_frame(
    self_aspace: u32,
    tls: &ChildTlsTemplate,
    child_memmgr_send: u32,
    ipc_buf: *mut u64,
) -> Option<MainTlsAlloc>
{
    let (block_size, block_align, tls_base_offset) =
        process_abi::tls_block_layout(tls.memsz, tls.align);

    if block_size == 0
        || block_size > PAGE_SIZE * PROCESS_MAIN_TLS_MAX_PAGES
        || block_size > PAGE_SIZE
        || block_align > PAGE_SIZE
    {
        return None;
    }

    let tls_frame = crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)?;
    let scratch = ScratchMapping::map(self_aspace, tls_frame, 1, syscall::MAP_WRITABLE)?;
    let scratch_va = scratch.va();

    // SAFETY: scratch_va is mapped writable for one page.
    unsafe { core::ptr::write_bytes(scratch_va as *mut u8, 0, PAGE_SIZE as usize) };

    Some(MainTlsAlloc {
        frame_cap: tls_frame,
        tls_base_offset,
        tls_base_va: PROCESS_MAIN_TLS_VADDR + tls_base_offset,
        scratch,
    })
}

/// Install the TCB self-pointer at `scratch_va + tls_base_offset`, drop
/// the scratch mapping from procmgr's aspace, derive an RW cap, and map
/// the block into the child at [`PROCESS_MAIN_TLS_VADDR`].
fn finalize_main_tls(alloc: MainTlsAlloc, _self_aspace: u32, child_aspace: u32) -> Option<MainTls>
{
    // SAFETY: scratch_va is mapped writable for one page; the block fits.
    unsafe {
        process_abi::tls_install_tcb(
            alloc.scratch_va() as *mut u8,
            alloc.tls_base_offset,
            alloc.tls_base_va,
        );
    }

    drop(alloc.scratch);

    let tls_rw = syscall::cap_derive(alloc.frame_cap, syscall::RIGHTS_MAP_RW).ok()?;
    syscall::mem_map(tls_rw, child_aspace, PROCESS_MAIN_TLS_VADDR, 0, 1, 0).ok()?;
    // alloc.frame_cap stays as the teardown handle; tls_rw is transient.
    let _ = syscall::cap_delete(tls_rw);

    Some(MainTls {
        frame_cap: alloc.frame_cap,
        base_va: alloc.tls_base_va,
    })
}

/// Allocate, populate from an in-memory `.tdata` slice, and map the main
/// thread's TLS block. Wraps the two-phase helpers above for the
/// create-from-bytes path.
fn prepare_main_tls_from_bytes(
    self_aspace: u32,
    child_aspace: u32,
    tls: &ChildTlsTemplate,
    template_bytes: &[u8],
    child_memmgr_send: u32,
    ipc_buf: *mut u64,
) -> Option<MainTls>
{
    if tls.memsz == 0
    {
        return Some(MainTls::default());
    }
    if template_bytes.len() > PAGE_SIZE as usize
    {
        return None;
    }
    let alloc = alloc_main_tls_frame(self_aspace, tls, child_memmgr_send, ipc_buf)?;
    let scratch_va = alloc.scratch_va();
    // SAFETY: scratch_va is mapped writable; length was bounded above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            template_bytes.as_ptr(),
            scratch_va as *mut u8,
            template_bytes.len(),
        );
    }
    finalize_main_tls(alloc, self_aspace, child_aspace)
}

/// Allocate, populate by streaming `.tdata` from an open VFS file handle,
/// and map the main thread's TLS block.
fn prepare_main_tls_from_vfs(
    self_aspace: u32,
    child_aspace: u32,
    tls: &ChildTlsTemplate,
    file_offset: u64,
    file_cap: u32,
    child_memmgr_send: u32,
    ipc_buf: *mut u64,
) -> Option<MainTls>
{
    if tls.memsz == 0
    {
        return Some(MainTls::default());
    }
    let alloc = alloc_main_tls_frame(self_aspace, tls, child_memmgr_send, ipc_buf)?;
    let scratch_va = alloc.scratch_va();

    let mut read_pos: u64 = 0;
    while read_pos < tls.filesz
    {
        let chunk = VFS_CHUNK_SIZE.min(tls.filesz - read_pos);
        let mut buf = [0u8; VFS_CHUNK_SIZE as usize];
        let bytes_read = vfs_read(
            file_cap,
            ipc_buf,
            file_offset + read_pos,
            chunk,
            &mut buf[..chunk as usize],
        )?;
        if bytes_read == 0
        {
            return None;
        }
        let safe_len = (bytes_read as u64).min(tls.filesz - read_pos) as usize;
        // SAFETY: scratch_va mapped writable; (read_pos + safe_len) <=
        // tls.filesz <= PAGE_SIZE; `buf` holds `safe_len` bytes of payload.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (scratch_va as *mut u8).add(read_pos as usize),
                safe_len,
            );
        }
        read_pos += safe_len as u64;
    }

    finalize_main_tls(alloc, self_aspace, child_aspace)
}

/// Map stack and IPC buffer pages into a child address space.
///
/// No explicit guard-page map. The page immediately below the stack
/// (`PROCESS_STACK_TOP - PROCESS_STACK_PAGES * PAGE_SIZE - PAGE_SIZE`)
/// stays unmapped by construction — `process-abi` lays out the stack and
/// `ProcessInfo` page so the gap is always present. Stack overflow
/// faults on the guard VA instead of silently writing into adjacent
/// mappings.
fn map_child_stack_and_ipc(
    child_aspace: u32,
    child_memmgr_send: u32,
    ipc_buf: *mut u64,
    stack_pages: u32,
) -> Option<()>
{
    let stack_base = PROCESS_STACK_TOP - u64::from(stack_pages) * PAGE_SIZE;
    for i in 0..stack_pages
    {
        let frame = crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)?;
        let rw = syscall::cap_derive(frame, syscall::RIGHTS_MAP_RW).ok()?;
        syscall::mem_map(
            rw,
            child_aspace,
            stack_base + u64::from(i) * PAGE_SIZE,
            0,
            1,
            0,
        )
        .ok()?;
        // Drop procmgr's transient slots; mapping owns no cap-refcount and
        // memmgr's outer pins the frame until PROCESS_DIED.
        let _ = syscall::cap_delete(rw);
        let _ = syscall::cap_delete(frame);
    }

    let ipc_frame = crate::memmgr_alloc_page(child_memmgr_send, ipc_buf)?;
    let ipc_rw = syscall::cap_derive(ipc_frame, syscall::RIGHTS_MAP_RW).ok()?;
    syscall::mem_map(ipc_rw, child_aspace, CHILD_IPC_BUF_VA, 0, 1, 0).ok()?;
    let _ = syscall::cap_delete(ipc_rw);
    let _ = syscall::cap_delete(ipc_frame);

    Some(())
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
        syscall::MAP_READONLY
    }
}

/// Derive caller-facing caps and record the process in the table.
// similar_names: child_aspace/child_cspace are intentionally parallel.
// too_many_arguments: grouping these into a struct would add complexity without
// reducing call sites — this helper is called from exactly two places.
#[allow(clippy::similar_names, clippy::too_many_arguments)]
fn finalize_creation(
    child_aspace: u32,
    child_cspace: u32,
    child_thread: u32,
    pi_frame_cap: u32,
    entry_point: u64,
    main_tls: MainTls,
    table: &mut ProcessTable,
    self_endpoint: u32,
    death_eq: u32,
    memmgr_send_cap: u32,
    memmgr_token: u64,
) -> Option<CreateResult>
{
    let token = NEXT_TOKEN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // Bind procmgr's shared death queue as an observer on the child's
    // main thread. Correlator = low 32 bits of the table token; on death,
    // dispatch_death recovers the entry via `take_by_correlator`.
    let correlator = token as u32;
    syscall::thread_bind_notification(child_thread, death_eq, correlator).ok()?;

    // Derive a tokened endpoint cap for the caller. The token identifies this
    // process on subsequent START_PROCESS / REQUEST_FRAMES calls.
    let process_handle =
        syscall::cap_derive_token(self_endpoint, syscall::RIGHTS_SEND_GRANT, token).ok()?;
    let Ok(thread_for_caller) = syscall::cap_derive(child_thread, syscall::RIGHTS_THREAD)
    else
    {
        let _ = syscall::cap_delete(process_handle);
        return None;
    };

    if !table.insert(ProcessEntry {
        token,
        aspace_cap: child_aspace,
        cspace_cap: child_cspace,
        thread_cap: child_thread,
        pi_frame_cap,
        tls_frame_cap: main_tls.frame_cap,
        memmgr_send_cap,
        memmgr_token,
        namespace_override: 0,
        cwd_override: 0,
        entry_point,
        tls_base_va: main_tls.base_va,
        started: false,
    })
    {
        // Table full: drop the caps we minted for the caller; the caller's
        // guards still own the child kernel objects and per-child frames
        // and will release them when finalize returns None.
        let _ = syscall::cap_delete(thread_for_caller);
        let _ = syscall::cap_delete(process_handle);
        return None;
    }

    Some(CreateResult {
        process_handle,
        thread_for_caller,
    })
}

// ── Process creation (from memory) ──────────────────────────────────────────

/// Create a process from an in-memory ELF byte slice (suspended).
// similar_names: aspace/cspace are intentionally parallel kernel object names.
#[allow(
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn create_process_from_bytes(
    module_bytes: &[u8],
    self_aspace: u32,
    table: &mut ProcessTable,
    self_endpoint: u32,
    creator_endpoint: u32,
    universals: &UniversalCaps,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
    death_eq: u32,
    ipc_buf: *mut u64,
) -> Option<CreateResult>
{
    let ehdr = elf::validate(module_bytes, crate::arch::current::EXPECTED_ELF_MACHINE).ok()?;
    let entry = elf::entry_point(ehdr);
    let stack_pages = elf::parse_stack_note(ehdr, module_bytes)
        .unwrap_or(DEFAULT_PROCESS_STACK_PAGES)
        .clamp(1, MAX_PROCESS_STACK_PAGES);

    let aspace_slab = crate::memmgr_alloc_pages_contig(
        universals.memmgr_endpoint,
        crate::ASPACE_RETYPE_PAGES,
        ipc_buf,
    )?;
    let child_aspace =
        syscall::cap_create_aspace(aspace_slab, 0, crate::ASPACE_RETYPE_PAGES - 1).ok()?;
    let _ = syscall::cap_delete(aspace_slab);
    let cspace_slab = crate::memmgr_alloc_pages_contig(
        universals.memmgr_endpoint,
        crate::CSPACE_RETYPE_PAGES,
        ipc_buf,
    )?;
    let child_cspace =
        syscall::cap_create_cspace(cspace_slab, 0, crate::CSPACE_RETYPE_PAGES - 1, 256).ok()?;
    let _ = syscall::cap_delete(cspace_slab);
    let thread_slab = crate::memmgr_alloc_pages_contig(
        universals.memmgr_endpoint,
        crate::THREAD_RETYPE_PAGES,
        ipc_buf,
    )?;
    let child_thread = syscall::cap_create_thread(thread_slab, child_aspace, child_cspace).ok()?;
    let _ = syscall::cap_delete(thread_slab);

    let child_memmgr_send = universals.memmgr_endpoint;

    for seg_result in elf::load_segments(ehdr, module_bytes)
    {
        let seg = seg_result.ok()?;
        if seg.memsz == 0
        {
            continue;
        }

        let prot = segment_prot(&seg);
        let first_page = seg.vaddr & !0xFFF;
        let last_page_end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
        let num_pages = ((last_page_end - first_page) / PAGE_SIZE) as usize;
        let file_data = &module_bytes[seg.offset as usize..(seg.offset + seg.filesz) as usize];

        for page_idx in 0..num_pages
        {
            let page_vaddr = first_page + (page_idx as u64) * PAGE_SIZE;
            loader::load_elf_page(
                page_vaddr,
                seg.vaddr,
                file_data,
                prot,
                self_aspace,
                child_aspace,
                child_memmgr_send,
                ipc_buf,
            )?;
        }
    }

    let tls_seg = elf::tls_segment(ehdr, module_bytes).ok()?;
    let tls_template = tls_seg
        .map(|s| ChildTlsTemplate {
            vaddr: s.vaddr,
            filesz: s.filesz,
            memsz: s.memsz,
            align: s.align,
        })
        .unwrap_or_default();

    let main_tls = if let Some(seg) = tls_seg
        && tls_template.memsz != 0
    {
        let start = seg.offset as usize;
        let end = start + seg.filesz as usize;
        if end > module_bytes.len()
        {
            return None;
        }
        prepare_main_tls_from_bytes(
            self_aspace,
            child_aspace,
            &tls_template,
            &module_bytes[start..end],
            child_memmgr_send,
            ipc_buf,
        )?
    }
    else
    {
        MainTls::default()
    };

    let pi_frame_cap = populate_child_info(
        self_aspace,
        child_aspace,
        child_cspace,
        child_thread,
        creator_endpoint,
        universals,
        &tls_template,
        args,
        env,
        ipc_buf,
        stack_pages,
    )?;
    map_child_stack_and_ipc(child_aspace, child_memmgr_send, ipc_buf, stack_pages)?;

    finalize_creation(
        child_aspace,
        child_cspace,
        child_thread,
        pi_frame_cap,
        entry,
        main_tls,
        table,
        self_endpoint,
        death_eq,
        child_memmgr_send,
        universals.memmgr_token,
    )
}

/// Create a process from an ELF module frame cap (suspended).
///
/// Maps the frame, delegates to `create_process_from_bytes`, then unmaps.
#[allow(clippy::too_many_arguments)]
pub fn create_process(
    module_frame_cap: u32,
    self_aspace: u32,
    _self_memmgr_ep: u32,
    ipc_buf: *mut u64,
    table: &mut ProcessTable,
    self_endpoint: u32,
    creator_endpoint: u32,
    universals: &UniversalCaps,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
    death_eq: u32,
) -> Option<CreateResult>
{
    let (module_scratch, module_pages) = loader::map_module(module_frame_cap, self_aspace)?;
    let module_size = module_pages * PAGE_SIZE;
    let module_va = module_scratch.va();

    // SAFETY: module frame mapped read-only at module_va for module_size bytes.
    let module_bytes =
        unsafe { core::slice::from_raw_parts(module_va as *const u8, module_size as usize) };

    let result = create_process_from_bytes(
        module_bytes,
        self_aspace,
        table,
        self_endpoint,
        creator_endpoint,
        universals,
        args,
        env,
        death_eq,
        ipc_buf,
    );

    drop(module_scratch);

    result
}

/// Monotonic cookie counter for `FS_READ_FRAME`. Skips zero — fatfs
/// rejects cookie 0 as the `OutstandingPage::None` sentinel.
static NEXT_FRAME_COOKIE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn next_frame_cookie() -> u64
{
    let mut c = NEXT_FRAME_COOKIE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    while c == 0
    {
        c = NEXT_FRAME_COOKIE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    c
}

/// Issue `FS_READ_FRAME` at byte `offset`.
///
/// On success returns `(frame_cap, bytes_valid, frame_data_offset)` per
/// `fs/docs/fs-driver-protocol.md`: the file's byte at `offset + i` for
/// `i ∈ [0, bytes_valid)` lives in the returned frame at byte offset
/// `frame_data_offset + i`. The frame cap is a per-call grandchild of the
/// fs cache slot and is owned by the caller; `cap_delete` releases the
/// caller's reference. Pre-Phase-9 the fs holds the underlying cache-slot
/// refcount until `FS_CLOSE`; cooperative early release arrives with
/// Phase 9's `FS_RELEASE_FRAME`. `bytes_valid` is bounded by file end,
/// cluster boundary, and frame tail — callers must iterate from
/// `offset + bytes_valid` to read past the boundary.
fn vfs_read_frame(file_cap: u32, ipc_buf: *mut u64, offset: u64)
-> Option<(u32, usize, usize, u64)>
{
    let cookie = next_frame_cookie();
    let msg = IpcMessage::builder(ipc::fs_labels::FS_READ_FRAME)
        .word(0, offset)
        .word(1, cookie)
        .build();

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }.ok()?;
    if reply.label != 0
    {
        return None;
    }
    let bytes_valid = reply.word(0) as usize;
    if bytes_valid == 0
    {
        return None;
    }
    let frame_data_offset = reply.word(2) as usize;
    let caps = reply.caps();
    if caps.is_empty()
    {
        return None;
    }
    Some((caps[0], bytes_valid, frame_data_offset, cookie))
}

/// Read from an open file via its per-file capability.
///
/// Copies up to `max_len` bytes of file data into `dst`. Returns the number
/// of bytes the server reported reading (which may exceed `dst.len()` if the
/// caller intentionally requested more than it is staging this call; callers
/// clamp as needed).
fn vfs_read(
    file_cap: u32,
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
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }.ok()?;
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
    dst[..copy_len].copy_from_slice(&payload[..copy_len]);
    Some(bytes_read)
}

/// Close an open file via its per-file capability and delete the cap.
fn vfs_close(file_cap: u32, ipc_buf: *mut u64)
{
    let msg = IpcMessage::new(ipc::fs_labels::FS_CLOSE);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) };
    let _ = syscall::cap_delete(file_cap);
}

// ── Per-creation resource guards ────────────────────────────────────────────
//
// `create_process_from_file` accumulates resources whose ownership transfers
// step by step: the caller-transferred file cap, a child-billed memmgr send
// cap, the three child kernel-object caps, and the per-child PI/TLS frames.
// Each guard's `Drop` releases the resource if it has not been transferred to
// the success path via `disarm()`. Constructed at the point of acquisition;
// disarmed only after the caps have been moved into the final destination.

/// Holds the caller-transferred file cap until the success path consumes it.
struct FileCapGuard
{
    cap: u32,
    ipc_buf: *mut u64,
}

impl FileCapGuard
{
    fn new(cap: u32, ipc_buf: *mut u64) -> Self
    {
        Self { cap, ipc_buf }
    }

    fn cap(&self) -> u32
    {
        self.cap
    }

    fn disarm(mut self) -> u32
    {
        let c = self.cap;
        self.cap = 0;
        c
    }
}

impl Drop for FileCapGuard
{
    fn drop(&mut self)
    {
        if self.cap != 0
        {
            vfs_close(self.cap, self.ipc_buf);
        }
    }
}

/// Holds a child-billed memmgr SEND cap and its memmgr-side token. The pair
/// is moved into `UniversalCaps` and then into the `ProcessEntry` on success.
struct MemmgrSendGuard
{
    cap: u32,
    token: u64,
}

impl MemmgrSendGuard
{
    fn new(cap: u32, token: u64) -> Self
    {
        Self { cap, token }
    }

    fn cap(&self) -> u32
    {
        self.cap
    }

    fn token(&self) -> u64
    {
        self.token
    }

    fn disarm(mut self) -> (u32, u64)
    {
        let p = (self.cap, self.token);
        self.cap = 0;
        self.token = 0;
        p
    }
}

impl Drop for MemmgrSendGuard
{
    fn drop(&mut self)
    {
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
    aspace: u32,
    cspace: u32,
    thread: u32,
}

impl ChildKernelObjects
{
    fn new(aspace: u32, cspace: u32, thread: u32) -> Self
    {
        Self {
            aspace,
            cspace,
            thread,
        }
    }

    fn aspace(&self) -> u32
    {
        self.aspace
    }

    fn cspace(&self) -> u32
    {
        self.cspace
    }

    fn thread(&self) -> u32
    {
        self.thread
    }

    fn disarm(mut self) -> (u32, u32, u32)
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
    fn drop(&mut self)
    {
        if self.thread != 0
        {
            let _ = syscall::cap_delete(self.thread);
        }
        if self.cspace != 0
        {
            let _ = syscall::cap_delete(self.cspace);
        }
        if self.aspace != 0
        {
            let _ = syscall::cap_delete(self.aspace);
        }
    }
}

/// `cap_delete`s a single cap slot on drop unless disarmed. Zero on
/// construction means "no cap yet"; the guard becomes a no-op.
struct CapGuard
{
    cap: u32,
}

impl CapGuard
{
    fn new(cap: u32) -> Self
    {
        Self { cap }
    }

    fn cap(&self) -> u32
    {
        self.cap
    }

    fn disarm(mut self) -> u32
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

/// Everything `load_elf_page_streaming` needs beyond the per-page arguments:
/// the VFS file handle, IPC buffer, parent/child address spaces, and the
/// child's tokened SEND on memmgr (so frames are billed to the child).
pub struct ElfLoadCtx
{
    pub file_cap: u32,
    pub ipc_buf: *mut u64,
    pub self_aspace: u32,
    pub child_aspace: u32,
    pub child_memmgr_send: u32,
}

/// Load one ELF segment page by streaming file data from VFS.
///
/// On failure returns a `procmgr_errors::*` code distinguishing
/// allocation, mapping, and rights-derivation failures.
fn load_elf_page_streaming(
    page_vaddr: u64,
    seg: &elf::LoadSegment,
    prot: u64,
    ctx: &ElfLoadCtx,
) -> Result<(), u64>
{
    let Some(frame_cap) = crate::memmgr_alloc_page(ctx.child_memmgr_send, ctx.ipc_buf)
    else
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page_streaming: alloc_page None vaddr=0x{:x}",
            page_vaddr
        );
        return Err(procmgr_errors::OUT_OF_MEMORY);
    };

    let Some(scratch) = ScratchMapping::map(ctx.self_aspace, frame_cap, 1, syscall::MAP_WRITABLE)
    else
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page_streaming: ScratchMapping::map None vaddr=0x{:x}",
            page_vaddr
        );
        let _ = syscall::cap_delete(frame_cap);
        return Err(procmgr_errors::MAP_FAILED);
    };
    let scratch_va = scratch.va();
    // SAFETY: scratch_va mapped writable, one page.
    unsafe { core::ptr::write_bytes(scratch_va as *mut u8, 0, PAGE_SIZE as usize) };

    stream_segment_to_frame(scratch_va, page_vaddr, seg, ctx);

    drop(scratch);

    let Some(derived) = loader::derive_frame_for_prot(frame_cap, prot)
    else
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page_streaming: derive_frame_for_prot None vaddr=0x{:x} prot=0x{:x}",
            page_vaddr,
            prot
        );
        let _ = syscall::cap_delete(frame_cap);
        return Err(procmgr_errors::INSUFFICIENT_RIGHTS);
    };
    if let Err(e) = syscall::mem_map(derived, ctx.child_aspace, page_vaddr, 0, 1, 0)
    {
        std::os::seraph::log!(
            "procmgr: load_elf_page_streaming: mem_map err={} vaddr=0x{:x}",
            e,
            page_vaddr
        );
        let _ = syscall::cap_delete(derived);
        let _ = syscall::cap_delete(frame_cap);
        return Err(procmgr_errors::MAP_FAILED);
    }

    // See `loader::load_elf_page` for the cap-refcount story.
    let _ = syscall::cap_delete(derived);
    let _ = syscall::cap_delete(frame_cap);

    Ok(())
}

/// Stream segment file data from VFS into the frame mapped at `scratch_va`.
///
/// Issues `FS_READ_FRAME` requests at the current file offset, mapping
/// the returned cache-page Frame read-only into a scratch VA, then memcpys
/// the requested slice into the child's destination page. The frame cap is
/// the caller's grandchild of fs's cache slot — `cap_delete` (via the
/// `ScratchMapping` `owns_cap` slot) drops the caller's reference. fs
/// holds the underlying cache-slot refcount until `FS_CLOSE` (pre-Phase-9)
/// or until cooperative `FS_RELEASE_FRAME` lands.
fn stream_segment_to_frame(
    scratch_va: u64,
    page_vaddr: u64,
    seg: &elf::LoadSegment,
    ctx: &ElfLoadCtx,
)
{
    let copy_start_va = page_vaddr.max(seg.vaddr);
    let copy_end_va = (page_vaddr + PAGE_SIZE).min(seg.vaddr + seg.filesz);

    if copy_start_va >= copy_end_va
    {
        return;
    }

    let dest_offset = (copy_start_va - page_vaddr) as usize;
    let file_offset = seg.offset + (copy_start_va - seg.vaddr);
    let bytes_to_read = (copy_end_va - copy_start_va) as usize;

    let mut copied = 0usize;
    while copied < bytes_to_read
    {
        let cur = file_offset + copied as u64;

        let Some((frame_cap, bytes_valid, frame_data_offset, cookie)) =
            vfs_read_frame(ctx.file_cap, ctx.ipc_buf, cur)
        else
        {
            return;
        };

        let Some(mut mapping) =
            ScratchMapping::map(ctx.self_aspace, frame_cap, 1, syscall::MAP_READONLY)
        else
        {
            let _ = syscall::cap_delete(frame_cap);
            vfs_release_frame(ctx.file_cap, ctx.ipc_buf, cookie);
            return;
        };
        mapping.set_owns_cap(frame_cap);

        let chunk_len = bytes_valid.min(bytes_to_read - copied);

        // SAFETY:
        // - `mapping.va()` covers PAGE_SIZE bytes mapped read-only.
        // - `frame_data_offset + chunk_len ≤ PAGE_SIZE` because
        //   `frame_data_offset + bytes_valid ≤ PAGE_SIZE` is a fatfs
        //   invariant and `chunk_len ≤ bytes_valid`.
        // - `dest_offset + copied + chunk_len ≤ PAGE_SIZE` because
        //   `dest_offset + bytes_to_read ≤ PAGE_SIZE` is enforced by the
        //   `copy_start_va`/`copy_end_va` clamp to `[page_vaddr, page_vaddr + PAGE_SIZE)`.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (mapping.va() as *const u8).add(frame_data_offset),
                (scratch_va as *mut u8).add(dest_offset + copied),
                chunk_len,
            );
        }
        drop(mapping);
        vfs_release_frame(ctx.file_cap, ctx.ipc_buf, cookie);
        copied += chunk_len;
    }
}

/// Issue `FS_RELEASE_FRAME` on the file-cap to drop the fs-side cache
/// refcount and clear the outstanding-page tracking entry for `cookie`.
/// Failure is non-fatal — the slot will be reclaimed at `FS_CLOSE` time
/// even if the proactive release is lost.
fn vfs_release_frame(file_cap: u32, ipc_buf: *mut u64, cookie: u64)
{
    let msg = IpcMessage::builder(ipc::fs_labels::FS_RELEASE_FRAME)
        .word(0, cookie)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) };
}

/// Create a process from a caller-supplied file cap.
///
/// Reads only the ELF header page, then loads each segment page-by-page
/// directly from the file cap into target frames. No intermediate file
/// buffer. Procmgr `FS_CLOSE`s and `cap_delete`s `file_cap` before
/// return regardless of outcome — ownership transfers in.
// clippy::too_many_lines: file-cap-based process creation is one transaction
// that owns the lifetime of the ELF-header scratch frame, the child's kernel
// objects, and the per-page streaming loop.
#[allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
pub fn create_process_from_file(
    ctx: &crate::ProcmgrCtx,
    file_cap: u32,
    file_size: u64,
    table: &mut ProcessTable,
    ipc_buf: *mut u64,
    creator_endpoint: u32,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
    death_eq: u32,
) -> Result<CreateResult, u64>
{
    let self_aspace = ctx.self_aspace;
    let self_endpoint = ctx.self_endpoint;

    // Caller-transferred file cap: wrapped immediately so every early
    // return between here and the success-path disarm closes the file
    // (FS_CLOSE on the fs driver) and frees procmgr's CSpace slot.
    let file_cap = FileCapGuard::new(file_cap, ipc_buf);

    if file_size == 0
    {
        return Err(procmgr_errors::INVALID_ELF);
    }

    // Mint a fresh tokened SEND on memmgr's endpoint for this child up
    // front; the header scratch frame, the per-segment frames, and all
    // subsequent allocations route through this cap so memmgr accounts
    // them to the child's record from the moment they leave the pool.
    let (mms_cap, mms_token) = crate::register_with_memmgr(ctx.memmgr_ep, ipc_buf);
    let mms = MemmgrSendGuard::new(mms_cap, mms_token);
    if mms.cap() == 0
    {
        return Err(procmgr_errors::OUT_OF_MEMORY);
    }

    // Allocate one frame for the ELF header page. `ScratchMapping::map`
    // takes ownership of the frame cap via `set_owns_cap` so the mapping's
    // Drop releases both the VA reservation and the cap slot together.
    let hdr_frame =
        crate::memmgr_alloc_page(mms.cap(), ipc_buf).ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    let mut hdr_scratch = ScratchMapping::map(self_aspace, hdr_frame, 1, syscall::MAP_WRITABLE)
        .ok_or_else(|| {
            let _ = syscall::cap_delete(hdr_frame);
            procmgr_errors::OUT_OF_MEMORY
        })?;
    hdr_scratch.set_owns_cap(hdr_frame);
    let hdr_va = hdr_scratch.va();
    // SAFETY: hdr_va mapped writable, one page.
    unsafe { core::ptr::write_bytes(hdr_va as *mut u8, 0, PAGE_SIZE as usize) };

    // Read the first page (ELF header + program headers).
    let hdr_size = file_size.min(PAGE_SIZE);
    let mut offset: u64 = 0;
    while offset < hdr_size
    {
        let chunk = VFS_CHUNK_SIZE.min(hdr_size - offset);
        let mut buf = [0u8; VFS_CHUNK_SIZE as usize];
        let bytes_read = vfs_read(
            file_cap.cap(),
            ipc_buf,
            offset,
            chunk,
            &mut buf[..chunk as usize],
        )
        .ok_or(procmgr_errors::IO_ERROR)?;
        if bytes_read == 0
        {
            break;
        }
        let safe_len = bytes_read.min(VFS_CHUNK_SIZE as usize);
        // SAFETY: hdr_va mapped writable; `buf` holds `safe_len` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (hdr_va as *mut u8).add(offset as usize),
                safe_len,
            );
        }
        offset += safe_len as u64;
    }

    // Parse ELF headers from the header page.
    // SAFETY: hdr_va is mapped and contains `offset` bytes of file data.
    let header_data = unsafe { core::slice::from_raw_parts(hdr_va as *const u8, offset as usize) };
    let ehdr = elf::validate(header_data, crate::arch::current::EXPECTED_ELF_MACHINE)
        .map_err(|_| procmgr_errors::INVALID_ELF)?;
    let entry = elf::entry_point(ehdr);

    // Parse the optional stack-size note. Section headers and the note
    // section are fetched on demand via `vfs_read`; the helper hands a
    // closure that drives the same primitive used to stream `PT_LOAD`
    // pages, so no extra IPC machinery is involved.
    let stack_pages = elf::parse_stack_note_streaming(ehdr, file_size, |off, dst| {
        // SAFETY: dst is a caller-supplied mutable byte buffer.
        let mut tmp = [0u8; VFS_CHUNK_SIZE as usize];
        let mut total = 0usize;
        while total < dst.len()
        {
            let want = (dst.len() - total).min(VFS_CHUNK_SIZE as usize);
            let bytes_read = vfs_read(
                file_cap.cap(),
                ipc_buf,
                off + total as u64,
                want as u64,
                &mut tmp[..want],
            )?;
            if bytes_read == 0
            {
                break;
            }
            let copy_len = bytes_read.min(want);
            dst[total..total + copy_len].copy_from_slice(&tmp[..copy_len]);
            total += copy_len;
            if bytes_read < want
            {
                break;
            }
        }
        Some(total)
    })
    .unwrap_or(DEFAULT_PROCESS_STACK_PAGES)
    .clamp(1, MAX_PROCESS_STACK_PAGES);

    let aspace_slab =
        crate::memmgr_alloc_pages_contig(mms.cap(), crate::ASPACE_RETYPE_PAGES, ipc_buf)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    let child_aspace = syscall::cap_create_aspace(aspace_slab, 0, crate::ASPACE_RETYPE_PAGES - 1)
        .map_err(|_| {
        let _ = syscall::cap_delete(aspace_slab);
        procmgr_errors::OUT_OF_MEMORY
    })?;
    let _ = syscall::cap_delete(aspace_slab);
    let cspace_slab =
        crate::memmgr_alloc_pages_contig(mms.cap(), crate::CSPACE_RETYPE_PAGES, ipc_buf)
            .ok_or_else(|| {
                let _ = syscall::cap_delete(child_aspace);
                procmgr_errors::OUT_OF_MEMORY
            })?;
    let child_cspace =
        syscall::cap_create_cspace(cspace_slab, 0, crate::CSPACE_RETYPE_PAGES - 1, 256).map_err(
            |_| {
                let _ = syscall::cap_delete(cspace_slab);
                let _ = syscall::cap_delete(child_aspace);
                procmgr_errors::OUT_OF_MEMORY
            },
        )?;
    let _ = syscall::cap_delete(cspace_slab);
    let thread_slab =
        crate::memmgr_alloc_pages_contig(mms.cap(), crate::THREAD_RETYPE_PAGES, ipc_buf)
            .ok_or_else(|| {
                let _ = syscall::cap_delete(child_cspace);
                let _ = syscall::cap_delete(child_aspace);
                procmgr_errors::OUT_OF_MEMORY
            })?;
    let child_thread = syscall::cap_create_thread(thread_slab, child_aspace, child_cspace)
        .map_err(|_| {
            let _ = syscall::cap_delete(thread_slab);
            let _ = syscall::cap_delete(child_cspace);
            let _ = syscall::cap_delete(child_aspace);
            procmgr_errors::OUT_OF_MEMORY
        })?;
    let _ = syscall::cap_delete(thread_slab);

    // All three child kernel-object caps are live; group them under a
    // single guard so subsequent `?` returns release them in the correct
    // order. Slab caps were consumed by `cap_create_*`; the post-create
    // `cap_delete` of each slab is correct because `cap_create_*` keeps
    // its own refcount on the underlying retyped region.
    let child_objs = ChildKernelObjects::new(child_aspace, child_cspace, child_thread);

    // Stream each LOAD segment page-by-page from VFS.
    for seg_result in elf::load_segments_metadata(ehdr, header_data, file_size)
    {
        let seg = seg_result.map_err(|_| procmgr_errors::INVALID_ELF)?;
        if seg.memsz == 0
        {
            continue;
        }

        let prot = segment_prot(&seg);
        let first_page = seg.vaddr & !0xFFF;
        let last_page_end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
        let num_pages = ((last_page_end - first_page) / PAGE_SIZE) as usize;

        for page_idx in 0..num_pages
        {
            let page_vaddr = first_page + (page_idx as u64) * PAGE_SIZE;
            let load_ctx = ElfLoadCtx {
                file_cap: file_cap.cap(),
                ipc_buf,
                self_aspace,
                child_aspace: child_objs.aspace(),
                child_memmgr_send: mms.cap(),
            };
            load_elf_page_streaming(page_vaddr, &seg, prot, &load_ctx)?;
        }
    }

    // Extract PT_TLS metadata before closing the file — we may need another
    // VFS read to pull `.tdata` into the main thread's TLS block.
    let tls_seg = elf::tls_segment_metadata(ehdr, header_data, file_size)
        .map_err(|_| procmgr_errors::INVALID_ELF)?;
    let tls_template = tls_seg
        .map(|s| ChildTlsTemplate {
            vaddr: s.vaddr,
            filesz: s.filesz,
            memsz: s.memsz,
            align: s.align,
        })
        .unwrap_or_default();

    // Done with the header page; the scratch mapping owns `hdr_frame` and
    // its Drop releases both the VA reservation and the cap slot.
    drop(hdr_scratch);

    let main_tls = if let Some(seg) = tls_seg
        && tls_template.memsz != 0
    {
        prepare_main_tls_from_vfs(
            self_aspace,
            child_objs.aspace(),
            &tls_template,
            seg.offset,
            file_cap.cap(),
            mms.cap(),
            ipc_buf,
        )
        .ok_or(procmgr_errors::OUT_OF_MEMORY)?
    }
    else
    {
        MainTls::default()
    };
    let main_tls_frame_guard = CapGuard::new(main_tls.frame_cap);

    // Disarm and consume the file cap: success-path `vfs_close` issues
    // FS_CLOSE and deletes the slot. From here on `file_cap` is no longer
    // available; any subsequent failure must not depend on it.
    let raw_file_cap = file_cap.disarm();
    vfs_close(raw_file_cap, ipc_buf);

    let universals = UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_discovery: ctx.log_ep,
        memmgr_endpoint: mms.cap(),
        memmgr_token: mms.token(),
    };
    let pi_frame_cap = populate_child_info(
        self_aspace,
        child_objs.aspace(),
        child_objs.cspace(),
        child_objs.thread(),
        creator_endpoint,
        &universals,
        &tls_template,
        args,
        env,
        ipc_buf,
        stack_pages,
    )
    .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    let pi_frame_guard = CapGuard::new(pi_frame_cap);

    map_child_stack_and_ipc(child_objs.aspace(), mms.cap(), ipc_buf, stack_pages)
        .ok_or(procmgr_errors::OUT_OF_MEMORY)?;

    // Commit point: hand the accumulated cap values to `finalize_creation`,
    // which records them in the process table on success. The guards stay
    // armed across the call so a `finalize_creation` failure releases every
    // resource on Drop; only after Ok do we disarm the guards, transferring
    // ownership to the table entry. `finalize_creation` cleans up the
    // caller-facing caps it mints internally (process_handle,
    // thread_for_caller) on any of its own failure arms.
    let main_tls_for_finalize = MainTls {
        frame_cap: main_tls_frame_guard.cap(),
        base_va: main_tls.base_va,
    };
    let result = finalize_creation(
        child_objs.aspace(),
        child_objs.cspace(),
        child_objs.thread(),
        pi_frame_guard.cap(),
        entry,
        main_tls_for_finalize,
        table,
        self_endpoint,
        death_eq,
        mms.cap(),
        mms.token(),
    )
    .ok_or(procmgr_errors::OUT_OF_MEMORY);
    if result.is_ok()
    {
        let _ = child_objs.disarm();
        let _ = mms.disarm();
        let _ = pi_frame_guard.disarm();
        let _ = main_tls_frame_guard.disarm();
    }
    result
}

// ── Process destruction ─────────────────────────────────────────────────────

/// Auto-reap path — called when the shared death queue fires with a
/// correlator matching some entry.
///
/// Idempotent: stale correlators (already reaped via explicit
/// `DESTROY_PROCESS`) drop silently. Takes the same cleanup path as the
/// IPC-driven `destroy_process` — the only difference is the lookup key.
#[allow(dead_code)]
pub fn reap_by_correlator(
    correlator: u32,
    memmgr_ep: u32,
    ipc_buf: *mut u64,
    table: &mut ProcessTable,
)
{
    let Some(entry) = table.take_by_correlator(correlator)
    else
    {
        return;
    };
    teardown_entry(entry, memmgr_ep, ipc_buf);
}

/// Destroy a process identified by `token`.
///
/// For each kernel object procmgr held on behalf of the child
/// (`thread`, `aspace`, `cspace`, `ProcessInfo` frame) we first `cap_revoke`
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
/// `CSpace` (dec-refing every slot it contains), walks the `AddressSpace`'s
/// user page tables to return intermediate frames to the buddy, and — via
/// `FrameObject::owns_memory` — releases heap / stack / IPC / `ProcessInfo`
/// pages to the buddy as their refcounts hit zero.
///
/// Idempotent: returns silently if the token is unknown (already destroyed).
pub fn destroy_process(token: u64, memmgr_ep: u32, ipc_buf: *mut u64, table: &mut ProcessTable)
{
    let Some(entry) = table.take_by_token(token)
    else
    {
        return;
    };
    teardown_entry(entry, memmgr_ep, ipc_buf);
}

/// Notify memmgr that a process died. Memmgr returns every frame attributed
/// to the process token to the free pool. Idempotent on memmgr's side.
fn notify_memmgr_died(memmgr_ep: u32, memmgr_token: u64, ipc_buf: *mut u64)
{
    if memmgr_ep == 0 || memmgr_token == 0
    {
        return;
    }
    let msg = IpcMessage::builder(memmgr_labels::PROCESS_DIED)
        .word(0, memmgr_token)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) };
}

/// Shared cleanup for both the explicit-IPC reap path (`destroy_process`)
/// and the auto-reap path (`reap_by_correlator`). Revokes and deletes
/// every kernel object procmgr held on behalf of the child.
///
/// Note: the bound death-notification observer in the child thread's TCB
/// is released automatically when the thread is torn down by the
/// cap-revoke below — no explicit unbind syscall is required.
// needless_pass_by_value: consumes the entry's cap slots; passing by
// reference would invite accidental double-free on subsequent reuse.
#[allow(clippy::needless_pass_by_value)]
pub fn teardown_entry(entry: ProcessEntry, memmgr_ep: u32, ipc_buf: *mut u64)
{
    // Order: thread first so the scheduler drops any residual reference to
    // the aspace before we tear down its page tables. Then cspace (which
    // owns every cap the child held) before aspace (whose dealloc walks the
    // page tables). pi_frame last — it was a leaf resource the child used
    // read-only; no other object references it.
    let _ = syscall::cap_revoke(entry.thread_cap);
    let _ = syscall::cap_delete(entry.thread_cap);
    let _ = syscall::cap_revoke(entry.cspace_cap);
    let _ = syscall::cap_delete(entry.cspace_cap);
    let _ = syscall::cap_revoke(entry.aspace_cap);
    let _ = syscall::cap_delete(entry.aspace_cap);
    let _ = syscall::cap_revoke(entry.pi_frame_cap);
    let _ = syscall::cap_delete(entry.pi_frame_cap);
    if entry.tls_frame_cap != 0
    {
        let _ = syscall::cap_revoke(entry.tls_frame_cap);
        let _ = syscall::cap_delete(entry.tls_frame_cap);
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

    // Notify memmgr to reclaim every frame attributed to this child's
    // memmgr token, then drop procmgr's tokened SEND copy.
    notify_memmgr_died(memmgr_ep, entry.memmgr_token, ipc_buf);
    if entry.memmgr_send_cap != 0
    {
        let _ = syscall::cap_delete(entry.memmgr_send_cap);
    }
}

// ── Process start ───────────────────────────────────────────────────────────

/// Start a previously created (suspended) process.
///
/// Patches the child's `ProcessInfo.system_root_cap` slot from the
/// per-process namespace cap installed via `CONFIGURE_NAMESPACE`. If
/// no cap was installed, the slot stays zero — the child runs without
/// namespace authority. `finalize_creation` already bound the child's
/// main thread to procmgr's shared death queue, so this just configures
/// the thread and kicks it.
pub fn start_process(token: u64, table: &mut ProcessTable, self_aspace: u32) -> Result<(), u64>
{
    let entry = table
        .find_mut_by_token(token)
        .ok_or(procmgr_errors::INVALID_TOKEN)?;

    if entry.started
    {
        return Err(procmgr_errors::ALREADY_STARTED);
    }

    if entry.namespace_override != 0 || entry.cwd_override != 0
    {
        let pi_frame = entry.pi_frame_cap;
        let child_cspace = entry.cspace_cap;
        let scratch = ScratchMapping::map(self_aspace, pi_frame, 1, syscall::MAP_WRITABLE)
            .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
        let scratch_va = scratch.va();
        // SAFETY: scratch_va is page-aligned and mapped writable; PI struct
        // lives at offset 0 per the ABI.
        let pi = unsafe { process_abi::process_info_mut(scratch_va) };
        if entry.namespace_override != 0
        {
            let slot =
                syscall::cap_copy(entry.namespace_override, child_cspace, syscall::RIGHTS_SEND)
                    .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            pi.system_root_cap = slot;
            let _ = syscall::cap_delete(entry.namespace_override);
            entry.namespace_override = 0;
        }
        if entry.cwd_override != 0
        {
            let slot = syscall::cap_copy(entry.cwd_override, child_cspace, syscall::RIGHTS_SEND)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            pi.current_dir_cap = slot;
            let _ = syscall::cap_delete(entry.cwd_override);
            entry.cwd_override = 0;
        }
    }

    syscall::thread_configure_with_tls(
        entry.thread_cap,
        entry.entry_point,
        PROCESS_STACK_TOP,
        PROCESS_INFO_VADDR,
        entry.tls_base_va,
    )
    .map_err(|_| 3u64)?;

    syscall::thread_start(entry.thread_cap).map_err(|_| 6u64)?;

    entry.started = true;
    Ok(())
}
