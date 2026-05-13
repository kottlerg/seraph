// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// procmgr/src/main.rs

//! Seraph process manager — IPC server for process lifecycle management.
//!
//! Receives requests via IPC to create, configure, and start new processes.
//! Supports both in-memory ELF loading from boot module frames and streaming
//! from the VFS. See `procmgr/docs/ipc-interface.md`.
//!
//! `CREATE_PROCESS` and `CREATE_FROM_FILE` accept the child's module source and
//! the caller's bootstrap endpoint (a tokened send cap); the endpoint is
//! installed in the child `CSpace` and recorded in `ProcessInfo` as the
//! `creator_endpoint_cap`. The child requests its initial cap set from the
//! caller over IPC at startup. procmgr itself has no knowledge of the child's
//! service-specific capabilities.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins.
#![feature(restricted_std)]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;
mod loader;
mod process;

use ipc::{IpcMessage, memmgr_errors, memmgr_labels, procmgr_errors, procmgr_labels};
use std::os::seraph::startup_info;

/// Init → procmgr bootstrap plan (one round on procmgr's creator endpoint):
///   caps[0]: service endpoint (procmgr receives requests on this)
///   caps[1]: un-tokened SEND copy of the system log endpoint. Procmgr
///            `cap_copy`s this into every child's
///            `ProcessInfo.log_discovery_cap` at `CREATE_PROCESS` time.
///            Zero means no log endpoint is available yet; children
///            born in that window receive zero and silent-drop
///            `std::os::seraph::log!`.
struct InitBootstrap
{
    service_ep: u32,
    log_ep: u32,
}

fn bootstrap_from_init(creator_ep: u32, ipc_buf: *mut u64) -> Option<InitBootstrap>
{
    if creator_ep == 0
    {
        return None;
    }
    // SAFETY: caller passes the registered IPC buffer page.
    let round = unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) }.ok()?;
    if round.cap_count < 1 || !round.done
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
    })
}

fn main() -> !
{
    std::os::seraph::log::register_name(b"procmgr");
    let startup = startup_info();

    // IPC buffer is registered by `_start`; reinterpret as `*mut u64`.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = startup.ipc_buffer.cast::<u64>();

    let self_aspace = startup.self_aspace;

    // Bootstrap service endpoint + log endpoint from init.
    let Some(boot) = bootstrap_from_init(startup.creator_endpoint, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    let mut table = process::ProcessTable::new();
    let mut recent = process::RecentExits::new();

    // Death-EQ inline slot (matches `cap::retype::event_queue_raw_bytes`):
    // 24 wrapper + 56 state + (capacity + 1) * 8 ring bytes. Capacity is
    // `MAX_PROCESSES * 2` to absorb a simultaneous-crash burst without
    // dropping notifications between drain calls.
    let death_eq_slab_bytes: u64 = 24 + 56 + ((process::MAX_PROCESSES as u64 * 2) + 1) * 8;
    let Some(eq_slab) = std::os::seraph::object_slab_acquire(death_eq_slab_bytes)
    else
    {
        syscall::thread_exit();
    };
    let Ok(death_eq) = syscall::event_queue_create(eq_slab, (process::MAX_PROCESSES as u32) * 2)
    else
    {
        syscall::thread_exit();
    };
    let Some(ws_slab) = std::os::seraph::object_slab_acquire(4096)
    else
    {
        syscall::thread_exit();
    };
    let Ok(ws_cap) = syscall::wait_set_create(ws_slab)
    else
    {
        syscall::thread_exit();
    };
    if syscall::wait_set_add(ws_cap, boot.service_ep, WS_TOKEN_SERVICE).is_err()
    {
        syscall::thread_exit();
    }
    if syscall::wait_set_add(ws_cap, death_eq, WS_TOKEN_DEATH).is_err()
    {
        syscall::thread_exit();
    }

    let mut ctx = ProcmgrCtx {
        self_aspace,
        self_endpoint: boot.service_ep,
        log_ep: boot.log_ep,
        memmgr_ep: startup.memmgr_endpoint,
        death_eq,
        ws_cap,
    };
    let service_ep = boot.service_ep;

    loop
    {
        let Ok(token) = syscall::wait_set_wait(ws_cap)
        else
        {
            continue;
        };

        // Drain any pending deaths before servicing a SERVICE request.
        // SERVICE handlers may allocate from memmgr; without this, a child
        // can die in the same wakeup batch as the parent's spawn-causing
        // IPC, and the SERVICE branch wins the wait_set_wait dispatch
        // ordering — leaving the dead child's frames pinned in memmgr's
        // per-process record until the next loop iteration. Under fast
        // spawn-after-wait churn that races allocations against pool
        // reclaim. dispatch_death is a no-op when the EQ is empty.
        dispatch_death(
            ctx.death_eq,
            ctx.memmgr_ep,
            ipc_buf,
            &mut table,
            &mut recent,
        );

        match token
        {
            WS_TOKEN_SERVICE =>
            {
                dispatch_ipc(service_ep, ipc_buf, &mut ctx, &mut table, &recent);
            }
            WS_TOKEN_DEATH =>
            {
                // Already drained above; nothing to do.
            }
            _ => (),
        }
    }
}

/// `WaitSet` token for procmgr's service endpoint.
const WS_TOKEN_SERVICE: u64 = 0;
/// `WaitSet` token for procmgr's shared death event queue.
const WS_TOKEN_DEATH: u64 = 1;

/// Pages requested from memmgr per spawned child for the child's Thread
/// retype slab. The kernel consumes `KERNEL_STACK_PAGES + 1 = 5` pages
/// (4 kstack + 1 wrapper/TCB) plus a small one-time per-`FrameObject`
/// allocator metadata footprint; one extra page is included so the
/// retype's `available_bytes >= raw_bytes` check passes after that
/// metadata debit.
pub(crate) const THREAD_RETYPE_PAGES: u64 = 6;

/// Pages requested from memmgr for the child's `AddressSpace` retype slab.
/// Page 0 becomes the root PT; the remaining pages form the initial PT
/// growth pool. The +1 covers the ~64 B per-Frame allocator metadata
/// footprint debited at the first retype.
///
/// Sized to cover the typical small-process mapping pattern: 3-6 LOAD
/// segments + stack + IPC buffer + TLS + `ProcessInfo` frame. Each
/// distinct user VA region whose PT entry isn't already populated
/// consumes up to 3 intermediate PT pages (PDPT/PD/PT on x86-64).
/// Larger processes refill via augment-mode `cap_create_aspace`.
pub(crate) const ASPACE_RETYPE_PAGES: u64 = 33;

/// Pages requested from memmgr for the child's `CSpace` retype slab.
/// Each slot page holds 64 capability slots (3584 B); the +1 covers the
/// per-Frame allocator metadata footprint. Larger `CSpace`s refill via
/// augment-mode `cap_create_cspace`. Five pages → 4 slot pages → 256
/// slots covers a small driver's lifetime.
pub(crate) const CSPACE_RETYPE_PAGES: u64 = 5;

/// Register a new child with memmgr. On success returns
/// `(memmgr_send_cap_slot, memmgr_token)`. On any failure (memmgr
/// unwired, IPC error, OOM) returns `(0, 0)`.
///
/// The cap slot lands in procmgr's `CSpace`; procmgr both:
///  * uses it for every per-child frame allocation (so memmgr accounts
///    them to the child's record from the moment they leave the pool); and
///  * copies it into the child's `ProcessInfo.memmgr_endpoint_cap` so the
///    child's std heap-bootstrap can call `REQUEST_FRAMES` on it.
///
/// The token is opaque to procmgr but is sent back in the
/// `PROCESS_DIED` payload at child teardown so memmgr can reclaim the
/// right record.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn register_with_memmgr(memmgr_ep: u32, ipc_buf: *mut u64) -> (u32, u64)
{
    if memmgr_ep == 0
    {
        return (0, 0);
    }
    let msg = IpcMessage::new(memmgr_labels::REGISTER_PROCESS);
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) })
    else
    {
        return (0, 0);
    };
    if reply.label != memmgr_errors::SUCCESS
    {
        return (0, 0);
    }
    let cap = reply.caps().first().copied().unwrap_or(0);
    let token = reply.word(0);
    (cap, token)
}

/// Permanently transfer a boot-module Frame cap into memmgr's pool via
/// `DONATE_FRAMES`. Returns true on success (cap left procmgr's `CSpace`),
/// false on any failure (caller should `cap_delete` to drop the slot).
///
/// Used after `CREATE_PROCESS` completes its ELF load: the source pages
/// are no longer referenced by procmgr, and routing them through memmgr
/// (rather than dropping the cap) returns the bytes to userspace.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
fn donate_module_cap(memmgr_ep: u32, module_cap: u32, ipc_buf: *mut u64) -> bool
{
    if memmgr_ep == 0
    {
        return false;
    }
    let msg = IpcMessage::builder(memmgr_labels::DONATE_FRAMES)
        .cap(module_cap)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(reply) = (unsafe { ipc::ipc_call(memmgr_ep, &msg, ipc_buf) })
    else
    {
        return false;
    };
    reply.label == memmgr_errors::SUCCESS && reply.word(0) >= 1
}

/// Allocate exactly one page from memmgr. Returns the cap slot of the
/// (single-page) Frame in procmgr's `CSpace`, or zero on any failure
/// (memmgr not wired, OOM, derive failure). Caller is responsible for
/// `mem_map`-ping it where appropriate.
///
/// Frames allocated against `child_send_cap` are accounted to that child's
/// memmgr record and reclaimed on `PROCESS_DIED`. Frames allocated against
/// procmgr's own `pi.memmgr_endpoint_cap` are accounted to procmgr.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn memmgr_alloc_page(memmgr_send: u32, ipc_buf: *mut u64) -> Option<u32>
{
    if memmgr_send == 0
    {
        std::os::seraph::log!("procmgr: alloc_page: memmgr_send=0");
        return None;
    }
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_FRAMES)
        .word(0, 1)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = match unsafe { ipc::ipc_call(memmgr_send, &msg, ipc_buf) }
    {
        Ok(r) => r,
        Err(e) =>
        {
            std::os::seraph::log!("procmgr: alloc_page: ipc_call err={}", e);
            return None;
        }
    };
    if reply.label != memmgr_errors::SUCCESS
    {
        std::os::seraph::log!(
            "procmgr: alloc_page: memmgr label={} pool: total={} runs={} max={}",
            reply.label,
            reply.word(0),
            reply.word(1),
            reply.word(2)
        );
        return None;
    }
    if reply.word(0) != 1
    {
        std::os::seraph::log!(
            "procmgr: alloc_page: count={} caps={}",
            reply.word(0),
            reply.caps().len()
        );
        for &slot in reply.caps()
        {
            let _ = syscall::cap_delete(slot);
        }
        return None;
    }
    reply.caps().first().copied()
}

/// Allocate exactly `pages` contiguous pages from `memmgr_send` as a
/// single Frame cap. Returns the cap slot in procmgr's `CSpace`, or
/// `None` on any failure (memmgr unwired, OOM, fragmented reply).
///
/// Used to back kernel-object retypes whose source Frame cap must be
/// contiguous (e.g. `Thread`, `AddressSpace`, `CSpace`). Unlike
/// `memmgr_alloc_page`, this rejects multi-cap replies and any cap
/// whose declared `page_count` does not equal `pages` — retypes
/// require one contiguous span and must not silently accept a smaller
/// cap.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn memmgr_alloc_pages_contig(memmgr_send: u32, pages: u64, ipc_buf: *mut u64) -> Option<u32>
{
    if memmgr_send == 0 || pages == 0
    {
        return None;
    }
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_FRAMES)
        .word(0, pages)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr_send, &msg, ipc_buf) }.ok()?;
    if reply.label != memmgr_errors::SUCCESS
    {
        return None;
    }
    let caps = reply.caps();
    if caps.len() != 1
    {
        for &slot in caps
        {
            let _ = syscall::cap_delete(slot);
        }
        return None;
    }
    let cap = caps[0];
    if syscall::cap_info(cap, syscall_abi::CAP_INFO_FRAME_SIZE)
        .is_ok_and(|size| size == pages * 4096)
    {
        Some(cap)
    }
    else
    {
        let _ = syscall::cap_delete(cap);
        None
    }
}

/// Service-endpoint dispatch. Called when the wait-set wakes for the
/// service endpoint; the sender is already queued so `ipc_recv` returns
/// without blocking.
fn dispatch_ipc(
    service_ep: u32,
    ipc_buf: *mut u64,
    ctx: &mut ProcmgrCtx,
    table: &mut process::ProcessTable,
    recent: &process::RecentExits,
)
{
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let Ok(req) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
    else
    {
        return;
    };
    let label = req.label;
    let token = req.token;

    match label & 0xFFFF
    {
        procmgr_labels::CREATE_PROCESS =>
        {
            handle_create(&req, ipc_buf, ctx, table);
        }

        procmgr_labels::START_PROCESS =>
        {
            // Token from ipc_recv identifies which process to start.
            let code = match process::start_process(token, table, ctx.self_aspace)
            {
                Ok(()) => procmgr_errors::SUCCESS,
                Err(code) => code,
            };
            reply_empty(ipc_buf, code);
        }

        procmgr_labels::DESTROY_PROCESS =>
        {
            // Token from ipc_recv identifies which process to destroy.
            process::destroy_process(token, ctx.memmgr_ep, ipc_buf, table);
            reply_empty(ipc_buf, procmgr_errors::SUCCESS);
        }

        procmgr_labels::QUERY_PROCESS =>
        {
            // Token identifies which process to query. Reply data:
            //   word 0 = state code (see `procmgr_process_state`)
            //   word 1 = exit_reason (only meaningful for `EXITED`)
            let (state, exit_reason) = resolve_query_state(token, table, recent);
            let reply = IpcMessage::builder(procmgr_errors::SUCCESS)
                .word(0, state)
                .word(1, exit_reason)
                .build();
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }

        procmgr_labels::CREATE_FROM_FILE =>
        {
            handle_create_from_file(&req, ipc_buf, ctx, table);
        }

        procmgr_labels::CONFIGURE_PIPE =>
        {
            handle_configure_pipe(&req, ipc_buf, ctx.self_aspace, table);
        }

        procmgr_labels::CONFIGURE_NAMESPACE =>
        {
            handle_configure_namespace(&req, ipc_buf, table);
        }

        _ =>
        {
            reply_empty(ipc_buf, procmgr_errors::UNKNOWN_OPCODE);
        }
    }
}

/// Answer `QUERY_PROCESS` for the addressed entry.
///
/// Consults the kernel for the authoritative thread-lifecycle snapshot
/// (`CAP_INFO_THREAD_STATE`) so a freshly-faulted child is reported as
/// EXITED even before procmgr's own death-event drain has reaped the
/// entry. Without this, the userspace death-eq drain races a parent's
/// "wait then `QUERY_PROCESS`" sequence and produces a transient ALIVE
/// answer for an already-dead child.
fn resolve_query_state(
    token: u64,
    table: &process::ProcessTable,
    recent: &process::RecentExits,
) -> (u64, u64)
{
    use ipc::procmgr_process_state;
    if let Some((started, thread_cap)) = table.query_by_token(token)
    {
        // Kernel-authoritative override: if the thread has transitioned to
        // Exited, report EXITED with the kernel-recorded reason regardless
        // of whether `dispatch_death` has reaped the entry yet.
        if let Ok(packed) = syscall::cap_info(thread_cap, syscall_abi::CAP_INFO_THREAD_STATE)
        {
            let state_code = (packed >> 32) as u32;
            let reason = packed & 0xFFFF_FFFF;
            if state_code == syscall_abi::THREAD_STATE_EXITED
            {
                return (procmgr_process_state::EXITED, reason);
            }
        }
        if started
        {
            (procmgr_process_state::ALIVE, 0u64)
        }
        else
        {
            (procmgr_process_state::CREATED, 0u64)
        }
    }
    else if let Some(reason) = recent.find(token)
    {
        (procmgr_process_state::EXITED, reason)
    }
    else
    {
        (procmgr_process_state::UNKNOWN, 0u64)
    }
}

/// Death-queue dispatch. Drains all pending death events on the shared
/// queue, reaps each by correlator, and records the exit reason in the
/// recent-exits ring for `QUERY_PROCESS`.
fn dispatch_death(
    death_eq: u32,
    memmgr_ep: u32,
    ipc_buf: *mut u64,
    table: &mut process::ProcessTable,
    recent: &mut process::RecentExits,
)
{
    loop
    {
        let Ok(payload) = syscall::event_try_recv(death_eq)
        else
        {
            return;
        };
        let correlator = (payload >> 32) as u32;
        let exit_reason = payload & 0xFFFF_FFFF;
        if let Some(entry) = table.take_by_correlator(correlator)
        {
            let entry_token = entry.token();
            recent.record(entry_token, exit_reason);
            process::teardown_entry(entry, memmgr_ep, ipc_buf);
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

/// Handle `CONFIGURE_PIPE` — install one direction's shmem-backed
/// stdio pipe on a suspended child.
///
/// Wire format (see `ipc::procmgr_labels::CONFIGURE_PIPE`):
/// * `data[0]` = direction (`PIPE_DIR_STDIN` / `STDOUT` / `STDERR`)
/// * `data[1]` = ring byte capacity (informational; procmgr does not
///   re-init the header — the spawner already called `SpscHeader::init`)
/// * `caps[0]` = frame cap (one shmem page)
/// * `caps[1]` = data-available signal cap
/// * `caps[2]` = space-available signal cap
fn handle_configure_pipe(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    self_aspace: u32,
    table: &mut process::ProcessTable,
)
{
    let token = req.token;
    let direction = req.word(0);
    let caps = req.caps();
    if caps.len() < 3
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let frame = caps[0];
    let data_signal = caps[1];
    let space_signal = caps[2];

    let code = match table.configure_pipe(
        token,
        self_aspace,
        direction,
        frame,
        data_signal,
        space_signal,
    )
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) => code,
    };

    // configure_pipe cap_copy'd each cap into the child's CSpace; drop
    // procmgr-side slots so refcounts hit zero when both peers later
    // release. Idempotent on zero. On the failure path the cap_copy may
    // not have happened yet — cap_delete on a stale slot is a no-op.
    let _ = syscall::cap_delete(frame);
    let _ = syscall::cap_delete(data_signal);
    let _ = syscall::cap_delete(space_signal);

    reply_empty(ipc_buf, code);
}

/// Handle `CONFIGURE_NAMESPACE` — install per-process root and
/// (optional) cwd caps on a suspended child. Caps are consumed by
/// procmgr on both success and failure paths; the wire-side caller
/// MUST NOT reuse the slots after the call.
///
/// Wire format (see `ipc::procmgr_labels::CONFIGURE_NAMESPACE`):
/// * `caps[0]` — root cap to deliver to the child at start (mandatory).
/// * `caps[1]` — cwd cap to deliver to the child at start (optional;
///   absent leaves `current_dir_cap` zero in the child).
fn handle_configure_namespace(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    table: &mut process::ProcessTable,
)
{
    let token = req.token;
    let caps = req.caps();
    if caps.is_empty()
    {
        reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
        return;
    }
    let root_cap = caps[0];
    let cwd_cap = caps.get(1).copied().unwrap_or(0);
    let code = match table.configure_namespace(token, root_cap, cwd_cap)
    {
        Ok(()) => procmgr_errors::SUCCESS,
        Err(code) => code,
    };
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
/// Expects `caps = [module_frame, creator_endpoint?]`. Stdio pipe
/// wiring is installed via separate `CONFIGURE_PIPE` IPCs (one per
/// piped direction) on the returned tokened `process_handle` between
/// create and `START_PROCESS`; the create path itself stays
/// stdio-agnostic.
fn handle_create(
    req: &IpcMessage,
    ipc_buf: *mut u64,
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

    // Register this child with memmgr. memmgr replies with a tokened SEND
    // cap on its endpoint plus the memmgr-side process token. Procmgr:
    //   - uses the cap for every per-child frame allocation (so memmgr
    //     accounts them to the child's record from the moment they leave
    //     the pool); and
    //   - copies the cap into the child's `ProcessInfo.memmgr_endpoint_cap`
    //     so the child's std heap-bootstrap can call `REQUEST_FRAMES`; and
    //   - sends the token in `PROCESS_DIED` at child teardown.
    let (memmgr_send, memmgr_token) = register_with_memmgr(ctx.memmgr_ep, ipc_buf);

    let universals = process::UniversalCaps {
        procmgr_endpoint: ctx.self_endpoint,
        log_discovery: ctx.log_ep,
        memmgr_endpoint: memmgr_send,
        memmgr_token,
    };

    let result = process::create_process(
        module_cap,
        ctx.self_aspace,
        ctx.memmgr_ep,
        ipc_buf,
        table,
        ctx.self_endpoint,
        creator_ep,
        &universals,
        &args,
        &env,
        ctx.death_eq,
    );

    // Procmgr's parent-side copy of the tokened cap stays in procmgr's
    // CSpace as long as the child is alive: it's the channel procmgr
    // uses to call `PROCESS_DIED` at teardown. The slot is recorded in
    // ProcessEntry.memmgr_send_cap and dropped only after PROCESS_DIED.
    // On create failure (no entry) it must be dropped immediately to
    // avoid leaking the slot.
    if result.is_none() && memmgr_send != 0
    {
        let _ = syscall::cap_delete(memmgr_send);
    }

    // Module cap disposition: donate the source frame to memmgr's pool. The
    // loader has copied the ELF contents into the child's AddressSpace and
    // procmgr has no further use for the source pages, so routing them
    // through memmgr returns the bytes to userspace.
    if module_cap != 0
    {
        let donated = donate_module_cap(ctx.memmgr_ep, module_cap, ipc_buf);
        if !donated
        {
            let _ = syscall::cap_delete(module_cap);
        }
    }
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

/// Long-lived procmgr state used by all request handlers. All fields are
/// fixed for the lifetime of the process.
pub struct ProcmgrCtx
{
    pub self_aspace: u32,
    pub self_endpoint: u32,
    /// Log endpoint (SEND) received from init during procmgr's own bootstrap.
    /// Procmgr `cap_copy`s this into every child's
    /// `ProcessInfo.log_discovery_cap` at `CREATE_PROCESS` time. Zero if
    /// init did not provide one (very early boot); children born in that
    /// window receive zero and silent-drop `std::os::seraph::log!`.
    pub log_ep: u32,
    /// Tokened SEND cap on memmgr's service endpoint, identifying procmgr.
    /// Used to mint per-child memmgr SENDs via `REGISTER_PROCESS`, to
    /// notify `PROCESS_DIED`, and as the destination for procmgr's own
    /// frame allocations (memmgr auto-registers procmgr's token at
    /// bootstrap so `REQUEST_FRAMES` on this cap is allowed).
    pub memmgr_ep: u32,
    /// Single shared death-notification event queue. Every spawned child
    /// binds its thread to this queue (via multi-bind in the kernel) with
    /// `correlator = entry.token as u32`. Multiplexed alongside the
    /// service endpoint via the wait-set in `ws_cap`.
    pub death_eq: u32,
    /// Wait-set cap. Multiplexes procmgr's service endpoint
    /// (`WS_TOKEN_SERVICE`) and the shared death event queue
    /// (`WS_TOKEN_DEATH`). Fixed two members.
    pub ws_cap: u32,
}

/// Handle `CREATE_FROM_FILE` — create a process from a caller-supplied file cap.
///
/// Wire layout: see [`procmgr_labels::CREATE_FROM_FILE`]. The caller has
/// already walked its own namespace cap to the binary node; procmgr never
/// touches the namespace tree on this path.
fn handle_create_from_file(
    req: &IpcMessage,
    ipc_buf: *mut u64,
    ctx: &ProcmgrCtx,
    table: &mut process::ProcessTable,
)
{
    let label = req.label;

    let caps = req.caps();
    let file_cap = match caps.first().copied()
    {
        Some(c) if c != 0 => c,
        _ =>
        {
            reply_empty(ipc_buf, procmgr_errors::INVALID_ARGUMENT);
            return;
        }
    };
    let creator_ep = caps.get(1).copied().unwrap_or(0);

    let file_size = req.word(0);

    let args_bytes = ((label >> 32) & 0xFFFF) as usize;
    let args_count = ((label >> 48) & 0xFF) as u32;
    let env_count = ((label >> 56) & 0xFF) as u32;

    let mut args_buf = [0u8; ipc::ARGS_BLOB_MAX];
    let args_blob: &[u8] = if args_bytes > 0 && args_bytes <= ipc::ARGS_BLOB_MAX
    {
        copy_bytes_from_msg(req, 1, args_bytes, &mut args_buf);
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
        let env_bytes = (req.word(1 + argv_words) & 0xFFFF) as usize;
        if env_bytes > 0 && env_bytes <= ipc::ARGS_BLOB_MAX
        {
            copy_bytes_from_msg(req, 1 + argv_words + 1, env_bytes, &mut env_buf);
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

    let result = process::create_process_from_file(
        ctx,
        file_cap,
        file_size,
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
