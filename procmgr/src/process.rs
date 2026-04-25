// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/process.rs

//! Process table, creation, and lifecycle management.
//!
//! Manages the process table and provides functions for creating processes
//! from in-memory ELF images or by streaming from VFS, as well as starting
//! suspended processes.

use crate::frames::{FramePool, PAGE_SIZE};
use crate::loader::{self, TEMP_FRAME_VA, TEMP_MODULE_VA, TEMP_VFS_VA};
use ipc::{IpcMessage, procmgr_errors};
use process_abi::{
    PROCESS_ABI_VERSION, PROCESS_INFO_VADDR, PROCESS_MAIN_TLS_MAX_PAGES, PROCESS_MAIN_TLS_VADDR,
    PROCESS_STACK_PAGES, PROCESS_STACK_TOP,
};
use va_layout::CHILD_IPC_BUF_VA;

/// Max file data bytes per VFS read IPC. Word 0 = `bytes_read`, words 1..63 = data.
const VFS_CHUNK_SIZE: u64 = 63 * 8; // 504 bytes

/// Next token value (monotonically increasing, never zero).
static NEXT_TOKEN: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Maximum concurrent child processes procmgr tracks.
///
/// Independent of any wait-set capacity — the shared death queue fans in
/// all children's exit events with kernel-side multi-bind, so there is no
/// per-child wait-set slot. Raise this (and the death queue capacity in
/// `main.rs`) as real workloads demand.
pub const MAX_PROCESSES: usize = 32;

// ── Process table ───────────────────────────────────────────────────────────

/// Per-process resource record. Fields read when teardown is implemented.
#[allow(dead_code)]
pub struct ProcessEntry
{
    token: u64,
    aspace_cap: u32,
    cspace_cap: u32,
    thread_cap: u32,
    pi_frame_cap: u32,
    tls_frame_cap: u32,
    entry_point: u64,
    tls_base_va: u64,
    started: bool,
    frames_allocated: u32,
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
    #[allow(dead_code)]
    fn take_by_correlator(&mut self, correlator: u32) -> Option<ProcessEntry>
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

    /// Lightweight status lookup for `QUERY_PROCESS`. Returns `started` as
    /// a bool when an entry is present; `None` if the token is unknown
    /// (already reaped or never existed).
    ///
    /// Exit-reason reporting is deferred until auto-reap lands and stores
    /// it on the entry during the death path.
    pub fn query_by_token(&self, token: u64) -> Option<bool>
    {
        self.entries
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|e| e.token == token)
            .map(|e| e.started)
    }

    /// Install stdio caps on a suspended child identified by `token`.
    ///
    /// Looks up the entry, confirms the child has not yet been started,
    /// remaps its `ProcessInfo` frame writable in procmgr's own aspace,
    /// `cap_copy`s each non-zero stdio cap from procmgr's `CSpace` into
    /// the child's `CSpace` with the appropriate rights (`RIGHTS_SEND` for
    /// stdout/stderr, `RIGHTS_RECEIVE` for stdin), writes the resulting
    /// slot indices into the PI page, and unmaps.
    ///
    /// Idempotent before start — later calls overwrite earlier slots.
    ///
    /// # Errors
    /// - `procmgr_errors::INVALID_TOKEN` — no entry for `token`.
    /// - `procmgr_errors::ALREADY_STARTED` — target is already running.
    /// - `procmgr_errors::OUT_OF_MEMORY` — mapping / `cap_copy` failure.
    pub fn configure_stdio(
        &mut self,
        token: u64,
        self_aspace: u32,
        stdout: u32,
        stderr: u32,
        stdin: u32,
    ) -> Result<(), u64>
    {
        let entry = self
            .find_mut_by_token(token)
            .ok_or(procmgr_errors::INVALID_TOKEN)?;
        if entry.started
        {
            return Err(procmgr_errors::ALREADY_STARTED);
        }
        let pi_frame = entry.pi_frame_cap;
        let child_cspace = entry.cspace_cap;

        // Remap the PI frame writable in procmgr's aspace so we can poke
        // stdio slots. Safe: the child has not started (checked above), so
        // there's no reader of the PI page yet.
        syscall::mem_map(
            pi_frame,
            self_aspace,
            TEMP_FRAME_VA,
            0,
            1,
            syscall::MAP_WRITABLE,
        )
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;

        // SAFETY: TEMP_FRAME_VA is mapped writable for one page; PI struct
        // lives at offset 0 per the ABI.
        let pi = unsafe { process_abi::process_info_mut(TEMP_FRAME_VA) };

        if stdout != 0
        {
            let slot = syscall::cap_copy(stdout, child_cspace, syscall::RIGHTS_SEND)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            pi.stdout_cap = slot;
        }
        if stderr != 0
        {
            let slot = syscall::cap_copy(stderr, child_cspace, syscall::RIGHTS_SEND)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            pi.stderr_cap = slot;
        }
        if stdin != 0
        {
            let slot = syscall::cap_copy(stdin, child_cspace, syscall::RIGHTS_RECEIVE)
                .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
            pi.stdin_cap = slot;
        }

        let _ = syscall::mem_unmap(self_aspace, TEMP_FRAME_VA, 1);
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
/// can call `REQUEST_FRAMES` / `MINT_LOG_CAP` / `CREATE_PROCESS`, and
/// an un-tokened SEND copy of `log_discovery` so it can `GET_LOG_CAP`
/// against the system log endpoint on first `seraph::log!` call (the
/// discovery cap by itself grants no log identity and no observability;
/// it merely lets the holder request a freshly-minted tokened cap).
///
/// Stdio caps (stdin, stdout, stderr) are intentionally NOT part of this
/// struct: they are not a universal property of processes, and each can
/// route to a different endpoint. A spawner that wants the child to have
/// any stdio wiring installs it via the separate `CONFIGURE_STDIO` IPC
/// between `CREATE_PROCESS` and `START_PROCESS`.
pub struct UniversalCaps
{
    pub procmgr_endpoint: u32,
    /// Un-tokened SEND cap on the system log endpoint, sourced from the
    /// `log_ep` slot procmgr received during init bootstrap. Zero when
    /// procmgr has no log endpoint (e.g. a future no-log boot mode).
    pub log_discovery: u32,
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
/// `ProcessInfo`. Stdio slots (`stdin_cap`, `stdout_cap`, `stderr_cap`)
/// are left zero here and are populated afterwards by
/// [`configure_stdio`], which remaps the same `pi_frame` writable, installs
/// caller-supplied caps via `cap_copy` into the child's `CSpace`, and
/// writes the slot indices into the PI page. This split keeps the core
/// `CREATE_PROCESS` path stdio-agnostic and lets spawners route stdout
/// and stderr independently.
// similar_names: child_aspace/child_cspace are intentionally parallel.
// too_many_arguments: each cluster is a small fixed-size bundle; collapsing
// them into one struct shifts the verbosity to the call sites without
// reducing the total parameter count. too_many_lines: this is the single
// transaction that owns the temporary mapping at TEMP_FRAME_VA — splitting
// would require threading the partial state through helpers that all need
// the same self_aspace + child_cspace + write context.
#[allow(
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]
fn populate_child_info(
    pool: &mut FramePool,
    self_aspace: u32,
    child_aspace: u32,
    child_cspace: u32,
    child_thread: u32,
    creator_endpoint: u32,
    universals: &UniversalCaps,
    tls: &ChildTlsTemplate,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
) -> Option<u32>
{
    let pi_frame = pool.alloc_page()?;
    syscall::mem_map(
        pi_frame,
        self_aspace,
        TEMP_FRAME_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .ok()?;
    // SAFETY: TEMP_FRAME_VA mapped writable, one page.
    unsafe { core::ptr::write_bytes(TEMP_FRAME_VA as *mut u8, 0, PAGE_SIZE as usize) };

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

    // Stdio caps are not installed here — CONFIGURE_STDIO remaps this
    // same pi_frame writable and fills them in before the child is
    // started. Leave the PI slots as zero so a child that ships without a
    // CONFIGURE_STDIO call sees "no stream attached" (silent println!,
    // EOF on stdin read).

    // SAFETY: TEMP_FRAME_VA is page-aligned and mapped writable.
    let pi = unsafe { process_abi::process_info_mut(TEMP_FRAME_VA) };
    pi.version = PROCESS_ABI_VERSION;
    pi.self_thread_cap = child_thread_in_child;
    pi.self_aspace_cap = child_aspace_in_child;
    pi.self_cspace_cap = child_cspace_in_child;
    pi.ipc_buffer_vaddr = CHILD_IPC_BUF_VA;
    pi.creator_endpoint_cap = creator_ep_in_child;
    pi.procmgr_endpoint_cap = procmgr_ep_in_child;
    pi.stdin_cap = 0;
    pi.stdout_cap = 0;
    pi.stderr_cap = 0;
    pi.log_discovery_cap = log_discovery_in_child;
    pi.tls_template_vaddr = tls.vaddr;
    pi.tls_template_filesz = tls.filesz;
    pi.tls_template_memsz = tls.memsz;
    pi.tls_template_align = tls.align;

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
            let _ = syscall::mem_unmap(self_aspace, TEMP_FRAME_VA, 1);
            return None;
        }
        // SAFETY: range within the mapped page; source is plain bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                args.blob.as_ptr(),
                (TEMP_FRAME_VA + args_offset) as *mut u8,
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
            let _ = syscall::mem_unmap(self_aspace, TEMP_FRAME_VA, 1);
            return None;
        }
        // SAFETY: range within the mapped page; source is plain bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                env.blob.as_ptr(),
                (TEMP_FRAME_VA + env_offset) as *mut u8,
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

    let _ = syscall::mem_unmap(self_aspace, TEMP_FRAME_VA, 1);

    let pi_ro = syscall::cap_derive(pi_frame, syscall::RIGHTS_MAP_READ).ok()?;
    syscall::mem_map(pi_ro, child_aspace, PROCESS_INFO_VADDR, 0, 1, 0).ok()?;

    Some(pi_frame)
}

/// Intermediate state returned by [`alloc_main_tls_frame`] — a frame mapped
/// writable at [`TEMP_FRAME_VA`] plus the layout numbers needed to populate
/// it and to finalise the mapping into the child.
#[derive(Clone, Copy)]
struct MainTlsAlloc
{
    frame_cap: u32,
    tls_base_offset: u64,
    tls_base_va: u64,
}

/// Allocate a frame for the main thread's TLS block, map it writable in
/// procmgr's own aspace at [`TEMP_FRAME_VA`], and zero it.
///
/// Returns `None` when the binary has no TLS, when the block exceeds the
/// single-frame budget, or when alignment demands would outrun the page
/// mapping. Callers write the `.tdata` template starting at `TEMP_FRAME_VA`
/// and then call [`finalize_main_tls`] to install the TCB self-pointer and
/// remap the frame into the child.
fn alloc_main_tls_frame(
    pool: &mut FramePool,
    self_aspace: u32,
    tls: &ChildTlsTemplate,
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

    let tls_frame = pool.alloc_page()?;
    syscall::mem_map(
        tls_frame,
        self_aspace,
        TEMP_FRAME_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .ok()?;

    // SAFETY: TEMP_FRAME_VA is mapped writable for one page.
    unsafe { core::ptr::write_bytes(TEMP_FRAME_VA as *mut u8, 0, PAGE_SIZE as usize) };

    Some(MainTlsAlloc {
        frame_cap: tls_frame,
        tls_base_offset,
        tls_base_va: PROCESS_MAIN_TLS_VADDR + tls_base_offset,
    })
}

/// Install the TCB self-pointer at `TEMP_FRAME_VA + tls_base_offset`, unmap
/// the scratch mapping from procmgr's aspace, derive an RW cap, and map
/// the block into the child at [`PROCESS_MAIN_TLS_VADDR`].
fn finalize_main_tls(alloc: MainTlsAlloc, self_aspace: u32, child_aspace: u32) -> Option<MainTls>
{
    // SAFETY: TEMP_FRAME_VA is mapped writable for one page; the block fits.
    unsafe {
        process_abi::tls_install_tcb(
            TEMP_FRAME_VA as *mut u8,
            alloc.tls_base_offset,
            alloc.tls_base_va,
        );
    }

    let _ = syscall::mem_unmap(self_aspace, TEMP_FRAME_VA, 1);

    let tls_rw = syscall::cap_derive(alloc.frame_cap, syscall::RIGHTS_MAP_RW).ok()?;
    syscall::mem_map(tls_rw, child_aspace, PROCESS_MAIN_TLS_VADDR, 0, 1, 0).ok()?;

    Some(MainTls {
        frame_cap: alloc.frame_cap,
        base_va: alloc.tls_base_va,
    })
}

/// Allocate, populate from an in-memory `.tdata` slice, and map the main
/// thread's TLS block. Wraps the two-phase helpers above for the
/// create-from-bytes path.
fn prepare_main_tls_from_bytes(
    pool: &mut FramePool,
    self_aspace: u32,
    child_aspace: u32,
    tls: &ChildTlsTemplate,
    template_bytes: &[u8],
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
    let alloc = alloc_main_tls_frame(pool, self_aspace, tls)?;
    // SAFETY: TEMP_FRAME_VA is mapped writable; length was bounded above.
    unsafe {
        core::ptr::copy_nonoverlapping(
            template_bytes.as_ptr(),
            TEMP_FRAME_VA as *mut u8,
            template_bytes.len(),
        );
    }
    finalize_main_tls(alloc, self_aspace, child_aspace)
}

/// Allocate, populate by streaming `.tdata` from an open VFS file handle,
/// and map the main thread's TLS block.
fn prepare_main_tls_from_vfs(
    pool: &mut FramePool,
    self_aspace: u32,
    child_aspace: u32,
    tls: &ChildTlsTemplate,
    file_offset: u64,
    file_cap: u32,
    ipc_buf: *mut u64,
) -> Option<MainTls>
{
    if tls.memsz == 0
    {
        return Some(MainTls::default());
    }
    let alloc = alloc_main_tls_frame(pool, self_aspace, tls)?;

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
            let _ = syscall::mem_unmap(self_aspace, TEMP_FRAME_VA, 1);
            return None;
        }
        let safe_len = (bytes_read as u64).min(tls.filesz - read_pos) as usize;
        // SAFETY: TEMP_FRAME_VA mapped writable; (read_pos + safe_len) <=
        // tls.filesz <= PAGE_SIZE; `buf` holds `safe_len` bytes of payload.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (TEMP_FRAME_VA as *mut u8).add(read_pos as usize),
                safe_len,
            );
        }
        read_pos += safe_len as u64;
    }

    finalize_main_tls(alloc, self_aspace, child_aspace)
}

/// Map stack and IPC buffer pages into a child address space.
///
/// No explicit guard-page map. `va_layout::PROCESS_STACK_GUARD_VA` sits one
/// page below `PROCESS_STACK_BOTTOM` and stays unmapped by construction —
/// compile-time assertions in `shared/va_layout` (ordering vs. stack
/// bottom and `PROCESS_INFO_VA`) guarantee that invariant. Stack overflow
/// faults on the guard VA instead of silently writing into adjacent
/// mappings.
fn map_child_stack_and_ipc(pool: &mut FramePool, child_aspace: u32) -> Option<()>
{
    let stack_base = PROCESS_STACK_TOP - (PROCESS_STACK_PAGES as u64) * PAGE_SIZE;
    for i in 0..PROCESS_STACK_PAGES
    {
        let frame = pool.alloc_page()?;
        let rw = syscall::cap_derive(frame, syscall::RIGHTS_MAP_RW).ok()?;
        syscall::mem_map(
            rw,
            child_aspace,
            stack_base + (i as u64) * PAGE_SIZE,
            0,
            1,
            0,
        )
        .ok()?;
    }

    let ipc_frame = pool.alloc_page()?;
    let ipc_rw = syscall::cap_derive(ipc_frame, syscall::RIGHTS_MAP_RW).ok()?;
    syscall::mem_map(ipc_rw, child_aspace, CHILD_IPC_BUF_VA, 0, 1, 0).ok()?;

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
    pool: &FramePool,
    pages_before: u32,
    child_aspace: u32,
    child_cspace: u32,
    child_thread: u32,
    pi_frame_cap: u32,
    entry_point: u64,
    main_tls: MainTls,
    table: &mut ProcessTable,
    self_endpoint: u32,
    death_eq: u32,
) -> Option<CreateResult>
{
    let token = NEXT_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);

    // Procmgr auto-reap death-notification bind is temporarily disabled —
    // adding procmgr as a second observer on spawn-path threads (where the
    // spawner's ruststd also binds) surfaces a hang that has not yet been
    // root-caused. Kernel multi-bind is proven working via svcmgr (crasher
    // path). Re-enable once the interaction is diagnosed.
    let _ = death_eq;

    // Derive a tokened endpoint cap for the caller. The token identifies this
    // process on subsequent START_PROCESS / REQUEST_FRAMES calls.
    let process_handle =
        syscall::cap_derive_token(self_endpoint, syscall::RIGHTS_SEND_GRANT, token).ok()?;
    let thread_for_caller = syscall::cap_derive(child_thread, syscall::RIGHTS_THREAD).ok()?;

    table.insert(ProcessEntry {
        token,
        aspace_cap: child_aspace,
        cspace_cap: child_cspace,
        thread_cap: child_thread,
        pi_frame_cap,
        tls_frame_cap: main_tls.frame_cap,
        entry_point,
        tls_base_va: main_tls.base_va,
        started: false,
        frames_allocated: pool.allocated_pages - pages_before,
    });

    Some(CreateResult {
        process_handle,
        thread_for_caller,
    })
}

// ── Process creation (from memory) ──────────────────────────────────────────

/// Create a process from an in-memory ELF byte slice (suspended).
// similar_names: aspace/cspace are intentionally parallel kernel object names.
#[allow(clippy::similar_names, clippy::too_many_arguments)]
fn create_process_from_bytes(
    module_bytes: &[u8],
    pool: &mut FramePool,
    self_aspace: u32,
    table: &mut ProcessTable,
    self_endpoint: u32,
    creator_endpoint: u32,
    universals: &UniversalCaps,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
    death_eq: u32,
) -> Option<CreateResult>
{
    let pages_before = pool.allocated_pages;

    let ehdr = elf::validate(module_bytes, crate::arch::current::EXPECTED_ELF_MACHINE).ok()?;
    let entry = elf::entry_point(ehdr);

    let child_aspace = syscall::cap_create_aspace().ok()?;
    let child_cspace = syscall::cap_create_cspace(256).ok()?;
    let child_thread = syscall::cap_create_thread(child_aspace, child_cspace).ok()?;

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
                pool,
                self_aspace,
                child_aspace,
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
            pool,
            self_aspace,
            child_aspace,
            &tls_template,
            &module_bytes[start..end],
        )?
    }
    else
    {
        MainTls::default()
    };

    let pi_frame_cap = populate_child_info(
        pool,
        self_aspace,
        child_aspace,
        child_cspace,
        child_thread,
        creator_endpoint,
        universals,
        &tls_template,
        args,
        env,
    )?;
    map_child_stack_and_ipc(pool, child_aspace)?;

    finalize_creation(
        pool,
        pages_before,
        child_aspace,
        child_cspace,
        child_thread,
        pi_frame_cap,
        entry,
        main_tls,
        table,
        self_endpoint,
        death_eq,
    )
}

/// Create a process from an ELF module frame cap (suspended).
///
/// Maps the frame, delegates to `create_process_from_bytes`, then unmaps.
#[allow(clippy::too_many_arguments)]
pub fn create_process(
    module_frame_cap: u32,
    pool: &mut FramePool,
    self_aspace: u32,
    table: &mut ProcessTable,
    self_endpoint: u32,
    creator_endpoint: u32,
    universals: &UniversalCaps,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
    death_eq: u32,
) -> Option<CreateResult>
{
    let module_pages = loader::map_module(module_frame_cap, self_aspace)?;
    let module_size = module_pages * PAGE_SIZE;

    // SAFETY: module frame mapped read-only at TEMP_MODULE_VA for module_size bytes.
    let module_bytes =
        unsafe { core::slice::from_raw_parts(TEMP_MODULE_VA as *const u8, module_size as usize) };

    let result = create_process_from_bytes(
        module_bytes,
        pool,
        self_aspace,
        table,
        self_endpoint,
        creator_endpoint,
        universals,
        args,
        env,
        death_eq,
    );

    let _ = syscall::mem_unmap(self_aspace, TEMP_MODULE_VA, module_pages);

    result
}

// ── VFS helpers ─────────────────────────────────────────────────────────────

/// Open a file via vfsd namespace resolution. Returns the per-file capability.
fn vfs_open(vfsd_ep: u32, ipc_buf: *mut u64, path: &[u8]) -> Option<u32>
{
    let label = ipc::vfsd_labels::OPEN | ((path.len() as u64) << 16);
    let msg = IpcMessage::builder(label).bytes(0, path).build();

    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(vfsd_ep, &msg, ipc_buf) }.ok()?;
    if reply.label != 0
    {
        return None;
    }
    let reply_caps = reply.caps();
    if reply_caps.is_empty()
    {
        return None;
    }
    Some(reply_caps[0])
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

/// Stat an open file via its per-file capability.
fn vfs_stat(file_cap: u32, ipc_buf: *mut u64) -> Option<u64>
{
    let msg = IpcMessage::new(ipc::fs_labels::FS_STAT);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) }.ok()?;
    if reply.label != 0
    {
        return None;
    }
    Some(reply.word(0))
}

/// Close an open file via its per-file capability and delete the cap.
fn vfs_close(file_cap: u32, ipc_buf: *mut u64)
{
    let msg = IpcMessage::new(ipc::fs_labels::FS_CLOSE);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_call(file_cap, &msg, ipc_buf) };
    let _ = syscall::cap_delete(file_cap);
}

// ── VFS-based ELF loading ──────────────────────────────────────────────────

/// Everything `load_elf_page_streaming` needs beyond the per-page arguments:
/// the VFS file handle, IPC buffer, parent/child address spaces, and the
/// shared frame pool. The borrow on `pool` is mutable for alloc/free; the
/// rest is by value.
pub struct ElfLoadCtx<'a>
{
    pub file_cap: u32,
    pub ipc_buf: *mut u64,
    pub self_aspace: u32,
    pub child_aspace: u32,
    pub pool: &'a mut FramePool,
}

/// Load one ELF segment page by streaming file data from VFS.
fn load_elf_page_streaming(
    page_vaddr: u64,
    seg: &elf::LoadSegment,
    prot: u64,
    ctx: &mut ElfLoadCtx,
) -> Option<()>
{
    let frame_cap = ctx.pool.alloc_page()?;

    syscall::mem_map(
        frame_cap,
        ctx.self_aspace,
        TEMP_FRAME_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .ok()?;
    // SAFETY: TEMP_FRAME_VA mapped writable, one page.
    unsafe { core::ptr::write_bytes(TEMP_FRAME_VA as *mut u8, 0, PAGE_SIZE as usize) };

    stream_segment_to_frame(page_vaddr, seg, ctx.file_cap, ctx.ipc_buf);

    let _ = syscall::mem_unmap(ctx.self_aspace, TEMP_FRAME_VA, 1);

    let derived = loader::derive_frame_for_prot(frame_cap, prot)?;
    syscall::mem_map(derived, ctx.child_aspace, page_vaddr, 0, 1, 0).ok()?;

    Some(())
}

/// Stream segment file data from VFS into the frame mapped at `TEMP_FRAME_VA`.
fn stream_segment_to_frame(
    page_vaddr: u64,
    seg: &elf::LoadSegment,
    file_cap: u32,
    ipc_buf: *mut u64,
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
    let bytes_to_read = copy_end_va - copy_start_va;

    let mut read_pos = 0u64;
    while read_pos < bytes_to_read
    {
        let chunk = VFS_CHUNK_SIZE.min(bytes_to_read - read_pos);
        let mut buf = [0u8; VFS_CHUNK_SIZE as usize];
        let Some(bytes_read) = vfs_read(
            file_cap,
            ipc_buf,
            file_offset + read_pos,
            chunk,
            &mut buf[..chunk as usize],
        )
        else
        {
            break;
        };
        if bytes_read == 0
        {
            break;
        }
        let safe_len = (bytes_read as u64).min(bytes_to_read - read_pos) as usize;

        // SAFETY: TEMP_FRAME_VA is mapped writable; dest_offset + read_pos +
        // safe_len <= PAGE_SIZE; `buf` holds `safe_len` bytes of payload.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (TEMP_FRAME_VA as *mut u8).add(dest_offset + read_pos as usize),
                safe_len,
            );
        }
        read_pos += safe_len as u64;
    }
}

/// Create a process by streaming an ELF binary from the VFS.
///
/// Reads only the ELF header page, then loads each segment page-by-page
/// directly from vfsd into target frames. No intermediate file buffer.
// clippy::too_many_lines: VFS-based process creation is one transaction that
// owns the lifetime of the ELF-header scratch frame, the child's kernel
// objects, and the per-page streaming loop. Splitting scatters the
// error/cleanup paths that must unwind in a fixed order against a single
// `FramePool` borrow, and introduces helpers that each need the full context
// struct anyway. The sub-phases are already factored through named helpers
// (vfs_open/stat/read/close, load_elf_page_streaming, populate_child_info,
// map_child_stack_and_ipc, finalize_creation); what remains is the linear
// orchestration.
#[allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
pub fn create_process_from_vfs(
    ctx: &crate::ProcmgrCtx,
    path: &[u8],
    pool: &mut FramePool,
    table: &mut ProcessTable,
    ipc_buf: *mut u64,
    creator_endpoint: u32,
    args: &ChildArgs<'_>,
    env: &ChildEnv<'_>,
    death_eq: u32,
) -> Result<CreateResult, u64>
{
    let vfsd_ep = ctx.vfsd_ep;
    let self_aspace = ctx.self_aspace;
    let self_endpoint = ctx.self_endpoint;
    let file_cap = vfs_open(vfsd_ep, ipc_buf, path).ok_or(procmgr_errors::FILE_NOT_FOUND)?;
    let file_size = vfs_stat(file_cap, ipc_buf).ok_or(procmgr_errors::IO_ERROR)?;

    if file_size == 0
    {
        vfs_close(file_cap, ipc_buf);
        return Err(procmgr_errors::INVALID_ELF);
    }

    // Allocate one frame for the ELF header page.
    let hdr_frame = pool.alloc_page().ok_or_else(|| {
        vfs_close(file_cap, ipc_buf);
        procmgr_errors::OUT_OF_MEMORY
    })?;
    syscall::mem_map(
        hdr_frame,
        self_aspace,
        TEMP_VFS_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .map_err(|_| {
        vfs_close(file_cap, ipc_buf);
        procmgr_errors::OUT_OF_MEMORY
    })?;
    // SAFETY: TEMP_VFS_VA mapped writable, one page.
    unsafe { core::ptr::write_bytes(TEMP_VFS_VA as *mut u8, 0, PAGE_SIZE as usize) };

    // Read the first page (ELF header + program headers).
    let hdr_size = file_size.min(PAGE_SIZE);
    let mut offset: u64 = 0;
    while offset < hdr_size
    {
        let chunk = VFS_CHUNK_SIZE.min(hdr_size - offset);
        let mut buf = [0u8; VFS_CHUNK_SIZE as usize];
        let bytes_read = vfs_read(file_cap, ipc_buf, offset, chunk, &mut buf[..chunk as usize])
            .ok_or(procmgr_errors::IO_ERROR)?;
        if bytes_read == 0
        {
            break;
        }
        let safe_len = bytes_read.min(VFS_CHUNK_SIZE as usize);
        // SAFETY: TEMP_VFS_VA mapped writable; `buf` holds `safe_len` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(
                buf.as_ptr(),
                (TEMP_VFS_VA as *mut u8).add(offset as usize),
                safe_len,
            );
        }
        offset += safe_len as u64;
    }

    // Parse ELF headers from the header page.
    // SAFETY: TEMP_VFS_VA is mapped and contains `offset` bytes of file data.
    let header_data =
        unsafe { core::slice::from_raw_parts(TEMP_VFS_VA as *const u8, offset as usize) };
    let ehdr = elf::validate(header_data, crate::arch::current::EXPECTED_ELF_MACHINE)
        .map_err(|_| procmgr_errors::INVALID_ELF)?;
    let entry = elf::entry_point(ehdr);

    let pages_before = pool.allocated_pages;

    let child_aspace = syscall::cap_create_aspace().map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let child_cspace =
        syscall::cap_create_cspace(256).map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;
    let child_thread = syscall::cap_create_thread(child_aspace, child_cspace)
        .map_err(|_| procmgr_errors::OUT_OF_MEMORY)?;

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
            let mut load_ctx = ElfLoadCtx {
                file_cap,
                ipc_buf,
                self_aspace,
                child_aspace,
                pool,
            };
            load_elf_page_streaming(page_vaddr, &seg, prot, &mut load_ctx)
                .ok_or(procmgr_errors::INVALID_ELF)?;
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

    // Done with the header page; the next VFS read (if any) overwrites
    // TEMP_FRAME_VA, not TEMP_VFS_VA, so it is safe to release the header
    // mapping now.
    let _ = syscall::mem_unmap(self_aspace, TEMP_VFS_VA, 1);
    pool.free_page(hdr_frame);

    let main_tls = if let Some(seg) = tls_seg
        && tls_template.memsz != 0
    {
        prepare_main_tls_from_vfs(
            pool,
            self_aspace,
            child_aspace,
            &tls_template,
            seg.offset,
            file_cap,
            ipc_buf,
        )
        .ok_or(procmgr_errors::OUT_OF_MEMORY)?
    }
    else
    {
        MainTls::default()
    };

    vfs_close(file_cap, ipc_buf);

    let universals = UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_discovery: ctx.log_ep,
    };
    let pi_frame_cap = populate_child_info(
        pool,
        self_aspace,
        child_aspace,
        child_cspace,
        child_thread,
        creator_endpoint,
        &universals,
        &tls_template,
        args,
        env,
    )
    .ok_or(procmgr_errors::OUT_OF_MEMORY)?;
    map_child_stack_and_ipc(pool, child_aspace).ok_or(procmgr_errors::OUT_OF_MEMORY)?;

    finalize_creation(
        pool,
        pages_before,
        child_aspace,
        child_cspace,
        child_thread,
        pi_frame_cap,
        entry,
        main_tls,
        table,
        self_endpoint,
        death_eq,
    )
    .ok_or(procmgr_errors::OUT_OF_MEMORY)
}

// ── Process destruction ─────────────────────────────────────────────────────

/// Auto-reap path — called when the shared death queue fires with a
/// correlator matching some entry.
///
/// Idempotent: stale correlators (already reaped via explicit
/// `DESTROY_PROCESS`) drop silently. Takes the same cleanup path as the
/// IPC-driven `destroy_process` — the only difference is the lookup key.
#[allow(dead_code)]
pub fn reap_by_correlator(correlator: u32, table: &mut ProcessTable)
{
    let Some(entry) = table.take_by_correlator(correlator)
    else
    {
        return;
    };
    teardown_entry(entry);
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
pub fn destroy_process(token: u64, table: &mut ProcessTable)
{
    let Some(entry) = table.take_by_token(token)
    else
    {
        return;
    };
    teardown_entry(entry);
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
fn teardown_entry(entry: ProcessEntry)
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
}

// ── Process start ───────────────────────────────────────────────────────────

/// Start a previously created (suspended) process.
///
/// Binds the child's main thread to procmgr's shared death queue (for
/// auto-reap on exit or fault), configures the thread, and starts it.
/// The bind happens BEFORE `thread_start` so a short-lived child cannot
/// exit before procmgr installs its observer and leak the child's frames.
///
/// Correlator: `entry.token as u32`. Procmgr's `NEXT_TOKEN` is monotonic
/// u64; truncation is unambiguous in practice (wrap at 4B process spawns).
#[allow(clippy::cast_possible_truncation)]
pub fn start_process(token: u64, table: &mut ProcessTable, death_eq: u32) -> Result<(), u64>
{
    let entry = table
        .find_mut_by_token(token)
        .ok_or(procmgr_errors::INVALID_TOKEN)?;

    if entry.started
    {
        return Err(procmgr_errors::ALREADY_STARTED);
    }

    // Bind happens in finalize_creation — no-op here.
    let _ = death_eq;

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
