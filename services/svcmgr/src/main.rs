// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/main.rs

//! Seraph service manager — monitors services, detects crashes via a
//! single shared death-notification event queue, and restarts them per
//! their restart policy.
//!
//! svcmgr is loaded from the root filesystem by init (via procmgr's
//! `CREATE_PROCESS_FROM_VFS`). Init registers services via IPC, then sends
//! `HANDOVER_COMPLETE` and exits. svcmgr runs for the lifetime of the system.
//!
//! Every supervised service binds death notification onto the same
//! `deaths_eq` with `correlator = service_index`. The wait set has two
//! members: the service endpoint (token 0) and the deaths queue
//! (token 1). On death wakeup svcmgr drains the queue and routes each
//! payload to its `ServiceEntry` via the correlator. Multiplexing
//! avoids consuming a wait-set slot per supervised process and keeps
//! the wait set inside the 16-member retype-bin sizing.
//!
//! See `svcmgr/docs/ipc-interface.md` and `svcmgr/docs/restart-protocol.md`.

// The `seraph` target is not in rustc's recognised-OS list, so `std` is
// `restricted_std`-gated for downstream bins. Every std-built service on
// seraph carries this preamble.
#![feature(restricted_std)]
// cast_possible_truncation: targets 64-bit only; u64/usize conversions lossless.
#![allow(clippy::cast_possible_truncation)]

mod arch;
mod restart;
mod service;

use ipc::{IpcMessage, svcmgr_labels};
use service::{MAX_BUNDLE_CAPS, MAX_SERVICES, ServiceEntry, bootstrap_caps};
use std::os::seraph::{StartupInfo, startup_info};

/// Global discovery registry size. Enough for a handful of top-level named
/// endpoints (vfsd, logd, procmgr, …) plus slack.
const REGISTRY_CAPACITY: usize = 8;

// ── Registration handling ──────────────────────────────────────────────────

/// Handle a `REGISTER_SERVICE` IPC message.
///
/// Reads name, policy, criticality from data words. Reads `thread_cap`,
/// `module_cap`, `log_ep` from transferred caps. Binds the thread's death
/// notification onto the shared `deaths_eq` with the service's table
/// index as the correlator.
///
/// Two restart sources are supported, distinguished by `vfs_path_len` in
/// label bits [32..48]:
///   - module-loaded (`vfs_path_len` == 0): caps = [thread, module, optional bundle]
///   - VFS-loaded    (`vfs_path_len`  > 0): caps = [thread, optional bundle]
fn handle_register(
    msg: &IpcMessage,
    services: &mut [ServiceEntry; MAX_SERVICES],
    service_count: &mut usize,
    deaths_eq: u32,
) -> u64
{
    let label = msg.label;
    let name_len = ((label >> 16) & 0xFFFF) as usize;
    let vfs_path_len = ((label >> 32) & 0xFFFF) as usize;
    if msg.word(0) != u64::from(ipc::SVCMGR_LABELS_VERSION)
    {
        return ipc::svcmgr_errors::LABEL_VERSION_MISMATCH;
    }
    if name_len == 0 || name_len > 32
    {
        return ipc::svcmgr_errors::INVALID_NAME;
    }
    if vfs_path_len > ipc::MAX_PATH_LEN
    {
        return ipc::svcmgr_errors::INVALID_NAME;
    }
    if *service_count >= MAX_SERVICES
    {
        return ipc::svcmgr_errors::TABLE_FULL;
    }

    let restart_policy = msg.word(1) as u8;
    let criticality = msg.word(2) as u8;

    let name = read_name_from_msg(msg, name_len);

    // Optional bundle-cap name, tail-packed after the service name words.
    // word 0 = SVCMGR_LABELS_VERSION; restart_policy/criticality at words
    // 1 and 2; name starts at word 3.
    let name_words = name_len.div_ceil(8);
    let bundle_name_len_word = 3 + name_words;
    let bundle_name_len = msg.word(bundle_name_len_word) as usize;
    let bundle_name_words = bundle_name_len.div_ceil(8);

    // VFS path (when present) is tail-packed after the bundle-name tail.
    let vfs_path_word = bundle_name_len_word + 1 + bundle_name_words;
    let vfs_loaded = vfs_path_len > 0;

    let recv_caps = msg.caps();
    let cap_count = recv_caps.len();

    if cap_count < 1
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }

    let thread_cap = recv_caps[0];
    if thread_cap == 0
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }

    let (module_cap, bundle_cap_idx) = if vfs_loaded
    {
        (0u32, 1usize)
    }
    else
    {
        if cap_count < 2 || recv_caps[1] == 0
        {
            return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
        }
        (recv_caps[1], 2usize)
    };

    let idx = *service_count;
    if bind_thread_to_deaths_eq(thread_cap, deaths_eq, idx as u32).is_err()
    {
        return ipc::svcmgr_errors::EVENT_QUEUE_FAILED;
    }

    let mut vfs_path_buf = [0u8; ipc::MAX_PATH_LEN];
    if vfs_loaded
    {
        read_path_bytes(msg, vfs_path_word, vfs_path_len, &mut vfs_path_buf);
    }

    services[idx] = ServiceEntry {
        name,
        name_len: name_len as u8,
        thread_cap,
        module_cap,
        vfs_path: vfs_path_buf,
        vfs_path_len: vfs_path_len as u8,
        bundle: [registry::Entry {
            name: [0; registry::NAME_MAX],
            name_len: 0,
            cap: 0,
        }; MAX_BUNDLE_CAPS],
        bundle_count: 0,
        restart_policy,
        criticality,
        restart_count: 0,
        active: true,
        bootstrap_token: 0,
        process_handle: 0,
    };

    // If a bundle cap was sent alongside, stash it in the first bundle slot.
    if cap_count > bundle_cap_idx
        && recv_caps[bundle_cap_idx] != 0
        && bundle_name_len > 0
        && bundle_name_len <= registry::NAME_MAX
    {
        let bundle_name = read_tail_name_from_msg(msg, bundle_name_len_word + 1, bundle_name_len);
        let entry = &mut services[idx].bundle[0];
        entry.name[..bundle_name_len].copy_from_slice(&bundle_name[..bundle_name_len]);
        entry.name_len = bundle_name_len as u8;
        entry.cap = recv_caps[bundle_cap_idx];
        services[idx].bundle_count = 1;
    }

    *service_count += 1;

    std::os::seraph::log!(
        "registered service: {} (bundle caps={})",
        services[idx].name_str(),
        u64::from(services[idx].bundle_count)
    );

    ipc::svcmgr_errors::SUCCESS
}

/// Read a short name packed into IPC data words starting at `first_word`.
fn read_tail_name_from_msg(
    msg: &IpcMessage,
    first_word: usize,
    name_len: usize,
) -> [u8; registry::NAME_MAX]
{
    let mut out = [0u8; registry::NAME_MAX];
    let words = name_len.div_ceil(8);
    for w in 0..words
    {
        let word = msg.word(first_word + w);
        for b in 0..8
        {
            let idx = w * 8 + b;
            if idx < name_len && idx < registry::NAME_MAX
            {
                out[idx] = (word >> (b * 8)) as u8;
            }
        }
    }
    out
}

/// Unpack `path_len` bytes from IPC data words starting at `first_word`
/// into `out`. Caller must ensure `path_len <= out.len()`.
fn read_path_bytes(msg: &IpcMessage, first_word: usize, path_len: usize, out: &mut [u8])
{
    let words = path_len.div_ceil(8);
    for w in 0..words
    {
        let word = msg.word(first_word + w);
        for b in 0..8
        {
            let idx = w * 8 + b;
            if idx < path_len && idx < out.len()
            {
                out[idx] = (word >> (b * 8)) as u8;
            }
        }
    }
}

/// Read a service name from message data words starting at offset 2.
fn read_name_from_msg(msg: &IpcMessage, name_len: usize) -> [u8; 32]
{
    let mut name = [0u8; 32];
    let name_words = name_len.div_ceil(8);
    for w in 0..name_words
    {
        let word = msg.word(3 + w);
        for b in 0..8
        {
            let idx = w * 8 + b;
            if idx < name_len
            {
                name[idx] = (word >> (b * 8)) as u8;
            }
        }
    }
    name
}

/// Bind a service's main thread to the shared death-notification queue,
/// using the service's table index as the correlator. The correlator is
/// recovered from the high 32 bits of the death payload to route the
/// event back to its `ServiceEntry`.
fn bind_thread_to_deaths_eq(thread_cap: u32, deaths_eq: u32, correlator: u32) -> Result<(), ()>
{
    syscall::thread_bind_notification(thread_cap, deaths_eq, correlator).map_err(|_| {
        std::os::seraph::log!("failed to bind death notification");
    })
}

// ── Halt ───────────────────────────────────────────────────────────────────

/// Halt the CPU in an infinite loop. Used on unrecoverable failures.
pub fn halt_loop() -> !
{
    loop
    {
        arch::current::halt();
    }
}

// ── Entry point ────────────────────────────────────────────────────────────

fn main() -> !
{
    std::os::seraph::log::register_name(b"svcmgr");
    let info = startup_info();

    // IPC buffer was registered by `std::os::seraph::_start`. The raw
    // pointer is all the new `ipc::ipc_call`/`ipc_recv`/`ipc_reply` and
    // `ipc::bootstrap::*` wrappers need.
    // cast_ptr_alignment: IPC buffer is page-aligned by the boot protocol.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let Some(caps) = bootstrap_caps(info, ipc_buf)
    else
    {
        syscall::thread_exit();
    };

    std::os::seraph::log!("started");

    if caps.service_ep == 0
    {
        std::os::seraph::log!("no service endpoint, halting");
        halt_loop();
    }
    if info.procmgr_endpoint == 0
    {
        std::os::seraph::log!("no procmgr endpoint, halting");
        halt_loop();
    }

    let Some(ws_slab) = std::os::seraph::object_slab_acquire(512)
    else
    {
        std::os::seraph::log!("failed to acquire frame for wait set");
        halt_loop();
    };
    let Ok(ws_cap) = syscall::wait_set_create(ws_slab)
    else
    {
        std::os::seraph::log!("failed to create wait set");
        halt_loop();
    };

    // One shared death-notification queue, capacity sized so a burst of
    // simultaneous service crashes (worst case `MAX_SERVICES`) cannot
    // overflow before svcmgr drains. Inline-slot bytes follow
    // `cap::retype::event_queue_raw_bytes`: 24 wrapper + 56 state +
    // (capacity + 1) * 8 ring.
    let deaths_eq_slab_bytes: u64 = 24 + 56 + ((MAX_SERVICES as u64 * 2) + 1) * 8;
    let Some(eq_slab) = std::os::seraph::object_slab_acquire(deaths_eq_slab_bytes)
    else
    {
        std::os::seraph::log!("failed to acquire frame for deaths event queue");
        halt_loop();
    };
    let Ok(deaths_eq) = syscall::event_queue_create(eq_slab, (MAX_SERVICES as u32) * 2)
    else
    {
        std::os::seraph::log!("failed to create deaths event queue");
        halt_loop();
    };

    if syscall::wait_set_add(ws_cap, caps.service_ep, WS_TOKEN_SERVICE).is_err()
    {
        std::os::seraph::log!("failed to add service endpoint to wait set");
        halt_loop();
    }
    if syscall::wait_set_add(ws_cap, deaths_eq, WS_TOKEN_DEATHS).is_err()
    {
        std::os::seraph::log!("failed to add deaths event queue to wait set");
        halt_loop();
    }

    let mut state = SvcmgrState {
        services: [const { ServiceEntry::empty() }; MAX_SERVICES],
        service_count: 0,
        handover_complete: false,
        registry: registry::Registry::new(),
    };

    std::os::seraph::log!("waiting for registrations");

    event_loop(info, &caps, ws_cap, deaths_eq, ipc_buf, &mut state);
}

/// `WaitSet` token for svcmgr's service endpoint.
const WS_TOKEN_SERVICE: u64 = 0;
/// `WaitSet` token for svcmgr's shared death event queue.
const WS_TOKEN_DEATHS: u64 = 1;

/// Monitored service table, global discovery registry, and handover flag.
/// Held across the event loop for the lifetime of the process.
pub struct SvcmgrState
{
    pub services: [ServiceEntry; MAX_SERVICES],
    pub service_count: usize,
    pub handover_complete: bool,
    pub registry: registry::Registry<REGISTRY_CAPACITY>,
}

/// Main event loop: dispatches IPC registrations and death notifications.
fn event_loop(
    info: &StartupInfo,
    caps: &service::SvcmgrCaps,
    ws_cap: u32,
    deaths_eq: u32,
    ipc_buf: *mut u64,
    state: &mut SvcmgrState,
) -> !
{
    let restart_ctx = restart::RestartCtx {
        procmgr_ep: info.procmgr_endpoint,
        bootstrap_ep: caps.bootstrap_ep,
        ipc_buf,
        deaths_eq,
    };

    loop
    {
        let Ok(token) = syscall::wait_set_wait(ws_cap)
        else
        {
            std::os::seraph::log!("wait_set_wait failed");
            continue;
        };

        match token
        {
            WS_TOKEN_SERVICE => dispatch_ipc(caps.service_ep, ipc_buf, state, deaths_eq),
            WS_TOKEN_DEATHS => dispatch_deaths(deaths_eq, state, &restart_ctx),
            _ => std::os::seraph::log!("unexpected wait-set token"),
        }
    }
}

/// Handle an IPC message on the service endpoint (registration, handover,
/// or discovery-registry publish/query).
fn dispatch_ipc(service_ep: u32, ipc_buf: *mut u64, state: &mut SvcmgrState, deaths_eq: u32)
{
    // SAFETY: ipc_buf is the registered IPC buffer.
    let Ok(msg) = (unsafe { ipc::ipc_recv(service_ep, ipc_buf) })
    else
    {
        return;
    };

    let opcode = msg.label & 0xFFFF;
    match opcode
    {
        svcmgr_labels::REGISTER_SERVICE =>
        {
            let result = handle_register(
                &msg,
                &mut state.services,
                &mut state.service_count,
                deaths_eq,
            );
            let reply = IpcMessage::new(result);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        svcmgr_labels::HANDOVER_COMPLETE =>
        {
            state.handover_complete = true;
            let reply = IpcMessage::new(ipc::svcmgr_errors::SUCCESS);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
            std::os::seraph::log!(
                "handover complete, monitoring services: {:#018x}",
                state.service_count as u64
            );
        }
        svcmgr_labels::PUBLISH_ENDPOINT =>
        {
            let result = handle_publish_endpoint(&msg, &mut state.registry);
            let reply = IpcMessage::new(result);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
        svcmgr_labels::QUERY_ENDPOINT =>
        {
            handle_query_endpoint(&msg, &mut state.registry, ipc_buf);
        }
        _ =>
        {
            let reply = IpcMessage::new(ipc::svcmgr_errors::UNKNOWN_OPCODE);
            // SAFETY: ipc_buf is the registered IPC buffer.
            let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        }
    }
}

/// Handle `PUBLISH_ENDPOINT`: add a `name → cap` mapping to the discovery
/// registry. The name is packed into data words 0.. per
/// [`read_tail_name_from_msg`]; the cap arrives as the first received cap.
fn handle_publish_endpoint(
    msg: &IpcMessage,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
) -> u64
{
    if msg.token & svcmgr_labels::PUBLISH_AUTHORITY == 0
    {
        return ipc::svcmgr_errors::UNAUTHORIZED;
    }
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    if name_len == 0 || name_len > registry::NAME_MAX
    {
        return ipc::svcmgr_errors::INVALID_NAME;
    }
    let recv_caps = msg.caps();
    if recv_caps.is_empty() || recv_caps[0] == 0
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }
    let name = read_tail_name_from_msg(msg, 0, name_len);
    if registry.publish(&name[..name_len], recv_caps[0]).is_err()
    {
        return ipc::svcmgr_errors::REGISTER_REJECTED;
    }
    ipc::svcmgr_errors::SUCCESS
}

/// Handle `QUERY_ENDPOINT`: look up a name in the discovery registry and
/// reply with a derived SEND cap if found.
fn handle_query_endpoint(
    msg: &IpcMessage,
    registry: &mut registry::Registry<REGISTRY_CAPACITY>,
    ipc_buf: *mut u64,
)
{
    let name_len = ((msg.label >> 16) & 0xFFFF) as usize;
    if name_len == 0 || name_len > registry::NAME_MAX
    {
        let reply = IpcMessage::new(ipc::svcmgr_errors::INVALID_NAME);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    }
    let name = read_tail_name_from_msg(msg, 0, name_len);
    let Some(cap) = registry.lookup(&name[..name_len])
    else
    {
        let reply = IpcMessage::new(ipc::svcmgr_errors::UNKNOWN_NAME);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    let Ok(derived) = syscall::cap_derive(cap, syscall::RIGHTS_SEND)
    else
    {
        // cap_derive failures on a stored entry are terminal — the
        // publisher's endpoint object is gone (e.g. service died and
        // procmgr reaped the source). Evict the dead entry so future
        // queries get UNKNOWN_NAME instead of looping on INSUFFICIENT_CAPS.
        let _ = registry.remove(&name[..name_len]);
        let _ = syscall::cap_delete(cap);
        let reply = IpcMessage::new(ipc::svcmgr_errors::INSUFFICIENT_CAPS);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    let reply = IpcMessage::builder(ipc::svcmgr_errors::SUCCESS)
        .cap(derived)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let send_result = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    if send_result.is_err()
    {
        // ipc_reply did not transfer the cap out of svcmgr's CSpace;
        // delete the freshly-derived slot to avoid cumulative leakage
        // over svcmgr's lifetime (one slot per failed reply).
        let _ = syscall::cap_delete(derived);
    }
}

/// Drain all pending death notifications from the shared queue. Each
/// payload encodes the dying service's table index in the high 32 bits
/// (set as the correlator at `thread_bind_notification` time) and the
/// exit reason in the low 32. The wait-set notifies once per
/// not-empty → empty transition, so a single wakeup may cover several
/// deaths; the try-recv loop runs until the queue empties.
fn dispatch_deaths(deaths_eq: u32, state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    loop
    {
        let Ok(payload) = syscall::event_try_recv(deaths_eq)
        else
        {
            return;
        };
        let correlator = (payload >> 32) as u32;
        let exit_reason = payload & 0xFFFF_FFFF;
        let idx = correlator as usize;

        if idx >= state.service_count
        {
            std::os::seraph::log!("death notification with unknown correlator");
            continue;
        }
        if !state.services[idx].active
        {
            continue;
        }

        restart::handle_death(&mut state.services[idx], exit_reason, ctx, correlator);
    }
}
