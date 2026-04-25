// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/main.rs

//! Seraph process manager — IPC server for process lifecycle management.
//!
//! Receives requests via IPC to create, configure, and start new processes.
//! Supports both in-memory ELF loading from boot module frames and streaming
//! from the VFS. See `procmgr/docs/ipc-interface.md`.
//!
//! `CREATE_PROCESS` and `CREATE_FROM_VFS` accept the child's module source and
//! the caller's bootstrap endpoint (a tokened send cap); the endpoint is
//! installed in the child `CSpace` and recorded in `ProcessInfo` as the
//! `creator_endpoint_cap`. The child requests its initial cap set from the
//! caller over IPC at startup. procmgr itself has no knowledge of the child's
//! service-specific capabilities.

#![no_std]
#![no_main]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;
mod frames;
mod loader;
mod process;

use frames::FramePool;
use ipc::{IpcMessage, procmgr_errors, procmgr_labels};

use process_abi::{
    PROCESS_ABI_VERSION, PROCESS_INFO_VADDR, ProcessInfo, StartupInfo, process_info_ref,
};

// ── Bespoke runtime ─────────────────────────────────────────────────────────
//
// procmgr cannot share the `std::sys::seraph::_start` path used by every
// other service: that `_start` bootstraps its heap by calling
// `REQUEST_FRAMES` against a procmgr endpoint, which has not yet run.
// procmgr therefore ships its own ELF entry symbol and panic handler here
// and runs on `core` + raw syscalls only (no heap, no `alloc` collections).

/// Process entry point. Reads [`ProcessInfo`] from [`PROCESS_INFO_VADDR`],
/// validates the protocol version, constructs [`StartupInfo`], and calls
/// [`main`].
///
/// # Safety
///
/// init's loader must have mapped a valid [`ProcessInfo`] page at
/// [`PROCESS_INFO_VADDR`] before starting this thread. The page must remain
/// mapped for the process's lifetime.
#[unsafe(no_mangle)]
pub extern "C" fn _start(_info_ptr: u64) -> !
{
    // SAFETY: a valid ProcessInfo page is mapped at PROCESS_INFO_VADDR before
    // the thread starts; it is read-only and remains mapped for the process's
    // lifetime.
    let info: &ProcessInfo = unsafe { process_info_ref(PROCESS_INFO_VADDR) };

    if info.version != PROCESS_ABI_VERSION
    {
        // Version mismatch — cannot safely interpret the struct. Exit.
        syscall::thread_exit();
    }

    // procmgr ignores argv/env (it only accepts caps via its bootstrap IPC);
    // build StartupInfo with empty blobs regardless of what init passed.
    let startup = StartupInfo {
        ipc_buffer: info.ipc_buffer_vaddr as *mut u8,
        creator_endpoint: info.creator_endpoint_cap,
        self_thread: info.self_thread_cap,
        self_aspace: info.self_aspace_cap,
        self_cspace: info.self_cspace_cap,
        procmgr_endpoint: info.procmgr_endpoint_cap,
        stdin_cap: info.stdin_cap,
        stdout_cap: info.stdout_cap,
        stderr_cap: info.stderr_cap,
        tls_template_vaddr: info.tls_template_vaddr,
        tls_template_filesz: info.tls_template_filesz,
        tls_template_memsz: info.tls_template_memsz,
        tls_template_align: info.tls_template_align,
        args_blob: &[],
        args_count: 0,
        env_blob: &[],
        env_count: 0,
    };

    main(&startup)
}

/// Panic handler. No recovery path: exit the thread and let the supervisor
/// observe the death.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> !
{
    syscall::thread_exit();
}

/// Init → procmgr bootstrap plan (one round):
///   caps[0]: service endpoint (procmgr receives requests on this)
///   caps[1]: un-tokened SEND copy of the system log endpoint. Procmgr
///            `cap_copy`s this into every child's
///            `ProcessInfo.log_discovery_cap` at `CREATE_PROCESS` time.
///            Zero means no log endpoint is available yet; children
///            born in that window receive zero and silent-drop
///            `seraph::log!`.
///   data word 0: `memory_frame_base`
///   data word 1: `memory_frame_count`
struct InitBootstrap
{
    service_ep: u32,
    log_ep: u32,
    frame_base: u32,
    frame_count: u32,
}

fn bootstrap_from_init(creator_ep: u32, ipc_buf: *mut u64) -> Option<InitBootstrap>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: caller passes the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) }.ok()?;
    if round.data_words < 2 || round.cap_count < 1 || !round.done
    {
        return None;
    }
    Some(InitBootstrap {
        service_ep: round.caps[0],
        log_ep: if round.cap_count >= 2
        {
            round.caps[1]
        }
        else
        {
            0
        },
        frame_base: round.data[0] as u32,
        frame_count: round.data[1] as u32,
    })
}

#[allow(clippy::too_many_lines)]
fn main(startup: &StartupInfo) -> !
{
    if syscall::ipc_buffer_set(startup.ipc_buffer as u64).is_err()
    {
        syscall::thread_exit();
    }

    let self_aspace = startup.self_aspace;
    // IPC buffer page is page-aligned and registered; treat as `*mut u64` for
    // the new IpcMessage-snapshot IPC wrappers.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    // Bootstrap service endpoint + memory pool bounds + log endpoint from init.
    let Some(boot) = bootstrap_from_init(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    let mut pool = FramePool::new(boot.frame_base, boot.frame_count);
    let mut table = process::ProcessTable::new();

    let mut ctx = ProcmgrCtx {
        self_aspace,
        self_endpoint: boot.service_ep,
        vfsd_ep: 0,
        log_ep: boot.log_ep,
        death_eq: 0,
        ws_cap: 0,
    };
    let service_ep = boot.service_ep;

    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(req) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
        else
        {
            continue;
        };
        let label = req.label;
        let token = req.token;

        match label & 0xFFFF
        {
            procmgr_labels::CREATE_PROCESS =>
            {
                handle_create(&req, ipc_buf, &mut pool, &ctx, &mut table);
            }

            procmgr_labels::START_PROCESS =>
            {
                // Token from ipc_recv identifies which process to start.
                let code = match process::start_process(token, &mut table, ctx.death_eq)
                {
                    Ok(()) => procmgr_errors::SUCCESS,
                    Err(code) => code,
                };
                reply_empty(ipc_buf, code);
            }

            procmgr_labels::REQUEST_FRAMES =>
            {
                handle_request_frames(&req, ipc_buf, &mut pool);
            }

            procmgr_labels::DESTROY_PROCESS =>
            {
                // Token from ipc_recv identifies which process to destroy.
                process::destroy_process(token, &mut table);
                reply_empty(ipc_buf, procmgr_errors::SUCCESS);
            }

            procmgr_labels::QUERY_PROCESS =>
            {
                // Token identifies which process to query. Reply data:
                //   word 0 = state code (see `procmgr_process_state`)
                //   word 1 = exit_reason (0 until auto-reap lands)
                use ipc::procmgr_process_state;
                let (state, exit_reason) = match table.query_by_token(token)
                {
                    Some(true) => (procmgr_process_state::ALIVE, 0u64),
                    Some(false) => (procmgr_process_state::CREATED, 0u64),
                    None => (procmgr_process_state::UNKNOWN, 0u64),
                };
                let reply = IpcMessage::builder(procmgr_errors::SUCCESS)
                    .word(0, state)
                    .word(1, exit_reason)
                    .build();
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            }

            procmgr_labels::CREATE_FROM_VFS =>
            {
                handle_create_from_vfs(&req, ipc_buf, &ctx, &mut pool, &mut table);
            }

            procmgr_labels::SET_VFSD_EP =>
            {
                let caps = req.caps();
                if caps.is_empty()
                {
                    reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
                }
                else
                {
                    ctx.vfsd_ep = caps[0];
                    reply_empty(ipc_buf, procmgr_errors::SUCCESS);
                }
            }

            procmgr_labels::CONFIGURE_STDIO =>
            {
                handle_configure_stdio(&req, ipc_buf, ctx.self_aspace, &mut table);
            }

            _ =>
            {
                reply_empty(ipc_buf, procmgr_errors::UNKNOWN_OPCODE);
            }
        }
    }
}

/// Reply with the given label code and no data / no caps.
fn reply_empty(ipc_buf: *mut u64, code: u64)
{
    let msg = IpcMessage::new(code);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&msg, ipc_buf) };
}

/// Handle `CONFIGURE_STDIO` — install stdin/stdout/stderr caps on a
/// suspended child.
///
/// Caller identifies the target via the request's tokened `process_handle`
/// (token delivered by `ipc_recv`). Caps are positional: `[stdout,
/// stderr?, stdin?]`. Trailing zeros are omitted by the sender (the
/// kernel rejects null cap slot indices). procmgr `cap_copy`s each into
/// the child's `CSpace` and writes the slot index into the child's
/// `ProcessInfo`. Rejects if the child has already been started.
fn handle_configure_stdio(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    self_aspace: u32,
    table: &mut process::ProcessTable,
)
{
    let token = req.token;
    let caps = req.caps();
    let stdout = caps.first().copied().unwrap_or(0);
    let stderr = if caps.len() >= 2 { caps[1] } else { 0 };
    let stdin = if caps.len() >= 3 { caps[2] } else { 0 };

    let code = match table.configure_stdio(token, self_aspace, stdout, stderr, stdin)
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) => code,
    };

    // procmgr's copies of the transferred caps have been moved into the
    // child's CSpace by cap_copy above (configure_stdio uses src-slot in
    // procmgr's CSpace → dst-slot in child_cspace). Drop procmgr-side
    // slots so their underlying refcounts don't keep the caller's
    // references alive unnecessarily. Idempotent on zero.
    if stdout != 0
    {
        let _ = syscall::cap_delete(stdout);
    }
    if stderr != 0
    {
        let _ = syscall::cap_delete(stderr);
    }
    if stdin != 0
    {
        let _ = syscall::cap_delete(stdin);
    }

    reply_empty(ipc_buf, code);
}

/// Reply with a successful process creation result.
///
/// Reply caps: `[process_handle, thread]`.
fn reply_create_result(result: &process::CreateResult, ipc_buf: *mut u64)
{
    let msg = IpcMessage::builder(procmgr_errors::SUCCESS)
        .cap(result.process_handle)
        .cap(result.thread_for_caller)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let _ = unsafe { ipc::ipc_reply(&msg, ipc_buf) };
}

/// Handle `CREATE_PROCESS` — create a process from a boot module frame.
///
/// Label layout:
///   bits [0..16]  = opcode (`CREATE_PROCESS`)
///   bits [16..32] = reserved
///   bits [32..48] = `args_bytes` (total byte length of the argv blob; u16)
///   bits [48..56] = `args_count` (number of NUL-terminated strings; u8)
///   bits [56..64] = `env_count` (number of NUL-terminated `KEY=VALUE`
///                    strings; u8). Zero means "no env"; any value >0
///                    requires an env header word + blob after argv.
///
/// IPC data words:
///   word `0..argv_words`         = argv blob, `args_bytes.div_ceil(8)` words
///   word `argv_words`            = `env_bytes` (low 16 bits; only present
///                                  when `env_count > 0`)
///   word `argv_words+1..`        = env blob, `env_bytes.div_ceil(8)` words
///                                  (only present when `env_count > 0`)
///
/// Expects `caps = [module_frame, creator_endpoint?]`. Stdio wiring is
/// configured via a separate `CONFIGURE_STDIO` IPC on the returned
/// tokened `process_handle` before `START_PROCESS`; it is intentionally
/// not part of this protocol so that stdout and stderr can be routed
/// independently and so the core creation path has no logging concept
/// baked in.
#[allow(clippy::cast_possible_truncation)]
fn handle_create(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    pool: &mut FramePool,
    ctx: &ProcmgrCtx,
    table: &mut process::ProcessTable,
)
{
    let label = req.label;
    let caps = req.caps();

    if caps.is_empty()
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ELF);
        return;
    }

    let module_cap = caps[0];
    let creator_ep = if caps.len() >= 2 { caps[1] } else { 0 };

    let args_bytes = ((label >> 32) & 0xFFFF) as usize;
    let args_count = ((label >> 48) & 0xFF) as u32;
    let env_count = ((label >> 56) & 0xFF) as u32;

    let mut args_buf = [0u8; ipc::ARGS_BLOB_MAX];
    let args_blob: &[u8] = if args_bytes > 0 && args_bytes <= ipc::ARGS_BLOB_MAX
    {
        copy_bytes_from_msg(req, 0, args_bytes, &mut args_buf);
        &args_buf[..args_bytes]
    }
    else
    {
        &[]
    };

    // Env blob (when present) sits after the argv words: 1 header word
    // carrying env_bytes, then the blob itself. Bounds: same ARGS_BLOB_MAX
    // as argv — env must also fit in the ProcessInfo page tail.
    let argv_words = args_bytes.div_ceil(8);
    let mut env_buf = [0u8; ipc::ARGS_BLOB_MAX];
    let env_blob: &[u8] = if env_count > 0
    {
        let env_bytes = (req.word(argv_words) & 0xFFFF) as usize;
        if env_bytes > 0 && env_bytes <= ipc::ARGS_BLOB_MAX
        {
            copy_bytes_from_msg(req, argv_words + 1, env_bytes, &mut env_buf);
            &env_buf[..env_bytes]
        }
        else
        {
            &[]
        }
    }
    else
    {
        &[]
    };

    let args = process::ChildArgs {
        blob: args_blob,
        count: args_count,
    };
    let env = process::ChildEnv {
        blob: env_blob,
        count: env_count,
    };

    let universals = process::UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_discovery: ctx.log_ep,
    };

    let result = process::create_process(
        module_cap,
        pool,
        ctx.self_aspace,
        table,
        ctx.self_endpoint,
        creator_ep,
        &universals,
        &args,
        &env,
        ctx.death_eq,
    );

    // Transferred caps (`module_cap`, `creator_ep`) entered procmgr's
    // CSpace via `ipc_recv` and were either cap_copy'd into the child's
    // CSpace or consumed only for the ELF-load scratch map. procmgr has
    // no further use for any of them; drop them so their underlying
    // object refcounts decrement and — once the child dies — the module
    // Frame (cap_copy descendants in the child's CSpace) can free its
    // backing memory. Idempotent on zero slots.
    let _ = syscall::cap_delete(module_cap);
    if creator_ep != 0
    {
        let _ = syscall::cap_delete(creator_ep);
    }

    match result
    {
        Some(result) => reply_create_result(&result, ipc_buf),
        None =>
        {
            reply_empty(ipc_buf, procmgr_errors::OUT_OF_MEMORY);
        }
    }
}

/// Handle `REQUEST_FRAMES` — allocate and return physical memory frames.
fn handle_request_frames(req: &IpcMessage, ipc_buf: *mut u64, pool: &mut FramePool)
{
    let requested = req.word(0);

    if requested == 0 || requested > 4
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }

    let mut caps = [0u32; 4];
    let mut granted: u64 = 0;

    for cap_slot in caps.iter_mut().take(requested as usize)
    {
        if let Some(page_cap) = pool.alloc_page()
        {
            *cap_slot = page_cap;
            granted += 1;
        }
        else
        {
            break;
        }
    }

    if granted == 0
    {
        reply_empty(ipc_buf, procmgr_errors::REQUEST_FRAMES_OOM);
    }
    else
    {
        let mut builder = IpcMessage::builder(procmgr_errors::SUCCESS).word(0, granted);
        for &cap in caps.iter().take(granted as usize)
        {
            builder = builder.cap(cap);
        }
        let reply = builder.build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// Long-lived procmgr state used by all request handlers.
///
/// `vfsd_ep` starts zero and is populated by `SET_VFSD_EP` once init has
/// handed over; the other fields are fixed for the lifetime of the process.
pub struct ProcmgrCtx
{
    pub self_aspace: u32,
    pub self_endpoint: u32,
    pub vfsd_ep: u32,
    /// Log endpoint (SEND) received from init during procmgr's own bootstrap.
    /// Procmgr `cap_copy`s this into every child's
    /// `ProcessInfo.log_discovery_cap` at `CREATE_PROCESS` time. Zero if
    /// init did not provide one (very early boot); children born in that
    /// window receive zero and silent-drop `seraph::log!`.
    pub log_ep: u32,
    /// Single shared death-notification event queue. Every spawned child
    /// binds its thread to this queue (via multi-bind in the kernel) with
    /// `correlator = entry.token as u32`. Auto-reap fan-in: one queue
    /// scales with process count, while procmgr's wait-set stays a
    /// constant two members.
    pub death_eq: u32,
    /// Wait-set cap. Multiplexes procmgr's service endpoint (token 0) and
    /// the shared death event queue (token 1). Fixed two members — does
    /// not grow with `MAX_PROCESSES`.
    pub ws_cap: u32,
}

/// Handle `CREATE_FROM_VFS` — create a process from a VFS path.
///
/// Label layout:
///   bits [0..16]  = opcode (`CREATE_FROM_VFS`)
///   bits [16..32] = `path_len`
///   bits [32..48] = `args_bytes` (total byte length of the argv blob; u16)
///   bits [48..56] = `args_count` (number of NUL-terminated strings; u8)
///   bits [56..64] = `env_count` (number of NUL-terminated `KEY=VALUE`
///                    strings; u8). Zero means "no env"; any value >0
///                    requires an env header word + blob after argv.
///
/// IPC data words:
///   word `0..path_words`             = path bytes (up to `MAX_PATH_LEN` = 48 bytes)
///   word `path_words..+argv_words`   = argv blob, `args_bytes.div_ceil(8)` words
///   word `path_words+argv_words`     = `env_bytes` (low 16 bits; only present
///                                       when `env_count > 0`)
///   word after env header            = env blob, `env_bytes.div_ceil(8)` words
///                                       (only present when `env_count > 0`)
///
/// Expects `caps = [creator_endpoint?, log_output_cap?, stdin_cap?]`. All
/// caps optional; trailing zeros omitted. Module bytes come from the VFS,
/// not the caller's `CSpace`. `log_output_cap` is installed verbatim into
/// the child's stdout/stderr — zero means no log output. Mirrors
/// `CREATE_PROCESS`'s argv/env encoding (see `handle_create`).
#[allow(clippy::cast_possible_truncation)]
fn handle_create_from_vfs(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    ctx: &ProcmgrCtx,
    pool: &mut FramePool,
    table: &mut process::ProcessTable,
)
{
    let label = req.label;

    if ctx.vfsd_ep == 0
    {
        reply_empty(ipc_buf, procmgr_errors::NO_VFSD_ENDPOINT);
        return;
    }

    let path_len = ((label >> 16) & 0xFFFF) as usize;
    if path_len == 0 || path_len > ipc::MAX_PATH_LEN
    {
        reply_empty(ipc_buf, procmgr_errors::FILE_NOT_FOUND);
        return;
    }

    let caps = req.caps();
    let creator_ep = caps.first().copied().unwrap_or(0);

    let mut path_buf = [0u8; ipc::MAX_PATH_LEN];
    // Path begins at word 0 (word 0 is no longer used as stdio_token).
    let effective_path_len = read_path_from_msg(req, 0, path_len, &mut path_buf);
    let path_words = path_len.div_ceil(8);

    let args_bytes = ((label >> 32) & 0xFFFF) as usize;
    let args_count = ((label >> 48) & 0xFF) as u32;
    let env_count = ((label >> 56) & 0xFF) as u32;

    let mut args_buf = [0u8; ipc::ARGS_BLOB_MAX];
    let args_blob: &[u8] = if args_bytes > 0 && args_bytes <= ipc::ARGS_BLOB_MAX
    {
        copy_bytes_from_msg(req, path_words, args_bytes, &mut args_buf);
        &args_buf[..args_bytes]
    }
    else
    {
        &[]
    };

    let argv_words = args_bytes.div_ceil(8);
    let mut env_buf = [0u8; ipc::ARGS_BLOB_MAX];
    let env_blob: &[u8] = if env_count > 0
    {
        let env_bytes = (req.word(path_words + argv_words) & 0xFFFF) as usize;
        if env_bytes > 0 && env_bytes <= ipc::ARGS_BLOB_MAX
        {
            copy_bytes_from_msg(req, path_words + argv_words + 1, env_bytes, &mut env_buf);
            &env_buf[..env_bytes]
        }
        else
        {
            &[]
        }
    }
    else
    {
        &[]
    };

    let args = process::ChildArgs {
        blob: args_blob,
        count: args_count,
    };
    let env = process::ChildEnv {
        blob: env_blob,
        count: env_count,
    };

    let result = process::create_process_from_vfs(
        ctx,
        &path_buf[..effective_path_len],
        pool,
        table,
        ipc_buf,
        creator_ep,
        &args,
        &env,
        ctx.death_eq,
    );

    match result
    {
        Ok(result) => reply_create_result(&result, ipc_buf),
        Err(code) =>
        {
            reply_empty(ipc_buf, code);
        }
    }
}

/// Unpack `path_len` bytes from the IPC message's data bytes starting at
/// word offset `word_offset`. Returns the number of bytes actually written
/// to `buf`, capped at `buf.len()` and `MAX_PATH_LEN`.
fn read_path_from_msg(
    msg: &IpcMessage,
    word_offset: usize,
    path_len: usize,
    buf: &mut [u8],
) -> usize
{
    let effective_len = path_len.min(buf.len()).min(ipc::MAX_PATH_LEN);
    let bytes = msg.data_bytes();
    let src_start = word_offset * 8;
    let avail = bytes.len().saturating_sub(src_start);
    let copy_len = effective_len.min(avail);
    if copy_len > 0
    {
        buf[..copy_len].copy_from_slice(&bytes[src_start..src_start + copy_len]);
    }
    copy_len
}

/// Copy up to `len` bytes from the IPC message's data-byte view into `dst`,
/// starting at word offset `word_offset`. Used to extract argv/env blobs
/// from positions other than the start of the data area.
fn copy_bytes_from_msg(msg: &IpcMessage, word_offset: usize, len: usize, dst: &mut [u8])
{
    let bytes = msg.data_bytes();
    let src_start = word_offset * 8;
    let avail = bytes.len().saturating_sub(src_start);
    let copy_len = len.min(dst.len()).min(avail);
    if copy_len > 0
    {
        dst[..copy_len].copy_from_slice(&bytes[src_start..src_start + copy_len]);
    }
}
