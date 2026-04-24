// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// svcmgr/src/main.rs

//! Seraph service manager — monitors services, detects crashes via death
//! notification event queues, and restarts them per their restart policy.
//!
//! svcmgr is loaded from the root filesystem by init (via procmgr's
//! `CREATE_PROCESS_FROM_VFS`). Init registers services via IPC, then sends
//! `HANDOVER_COMPLETE` and exits. svcmgr runs for the lifetime of the system.
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
/// `module_cap`, `log_ep` from transferred caps. Creates an event queue, binds
/// it to the thread, adds to the wait set.
fn handle_register(
    msg: &IpcMessage,
    services: &mut [ServiceEntry; MAX_SERVICES],
    service_count: &mut usize,
    ws_cap: u32,
) -> u64
{
    let label = msg.label;
    let name_len = ((label >> 16) & 0xFFFF) as usize;
    if name_len == 0 || name_len > 32
    {
        return ipc::svcmgr_errors::INVALID_NAME;
    }
    if *service_count >= MAX_SERVICES
    {
        return ipc::svcmgr_errors::TABLE_FULL;
    }

    let restart_policy = msg.word(0) as u8;
    let criticality = msg.word(1) as u8;

    let name = read_name_from_msg(msg, name_len);

    // Optional bundle-cap name, tail-packed after the service name words.
    let name_words = name_len.div_ceil(8);
    let bundle_name_len_word = 2 + name_words;
    let bundle_name_len = msg.word(bundle_name_len_word) as usize;

    // Read transferred caps. Layout:
    //   cap[0] = thread
    //   cap[1] = module
    //   cap[2] = optional bundle cap (named by the tail-word `bundle_name_len`)
    // log endpoint is delivered via `ProcessInfo`, not this protocol.
    let recv_caps = msg.caps();
    let cap_count = recv_caps.len();

    if cap_count < 2
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }

    let thread_cap = recv_caps[0];
    let module_cap = recv_caps[1];

    if thread_cap == 0 || module_cap == 0
    {
        return ipc::svcmgr_errors::INSUFFICIENT_CAPS;
    }

    let Some(eq_cap) = create_and_bind_event_queue(thread_cap, ws_cap, *service_count)
    else
    {
        return ipc::svcmgr_errors::EVENT_QUEUE_FAILED;
    };

    let idx = *service_count;
    services[idx] = ServiceEntry {
        name,
        name_len: name_len as u8,
        thread_cap,
        module_cap,
        bundle: [registry::Entry {
            name: [0; registry::NAME_MAX],
            name_len: 0,
            cap: 0,
        }; MAX_BUNDLE_CAPS],
        bundle_count: 0,
        restart_policy,
        criticality,
        event_queue_cap: eq_cap,
        restart_count: 0,
        active: true,
        bootstrap_token: 0,
        process_handle: 0,
    };

    // If a bundle cap was sent alongside, stash it in the first bundle slot.
    if cap_count >= 3
        && recv_caps[2] != 0
        && bundle_name_len > 0
        && bundle_name_len <= registry::NAME_MAX
    {
        let bundle_name = read_tail_name_from_msg(msg, bundle_name_len_word + 1, bundle_name_len);
        let entry = &mut services[idx].bundle[0];
        entry.name[..bundle_name_len].copy_from_slice(&bundle_name[..bundle_name_len]);
        entry.name_len = bundle_name_len as u8;
        entry.cap = recv_caps[2];
        services[idx].bundle_count = 1;
    }

    *service_count += 1;

    println!(
        "svcmgr: registered service: {} (bundle caps={})",
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

/// Read a service name from message data words starting at offset 2.
fn read_name_from_msg(msg: &IpcMessage, name_len: usize) -> [u8; 32]
{
    let mut name = [0u8; 32];
    let name_words = name_len.div_ceil(8);
    for w in 0..name_words
    {
        let word = msg.word(2 + w);
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

/// Create an event queue, bind it to a thread for death notification, and add
/// it to the wait set. Returns the event queue cap on success.
fn create_and_bind_event_queue(thread_cap: u32, ws_cap: u32, service_index: usize) -> Option<u32>
{
    let Ok(eq_cap) = syscall::event_queue_create(4)
    else
    {
        println!("svcmgr: failed to create event queue for service");
        return None;
    };

    // Correlator 0: svcmgr uses a per-service EventQueue plus WaitSet token
    // for routing; the payload is just `exit_reason`. No correlator needed.
    if syscall::thread_bind_notification(thread_cap, eq_cap, 0).is_err()
    {
        println!("svcmgr: failed to bind death notification");
        return None;
    }

    // Token = service_index + 1 (token 0 = service endpoint).
    let token = (service_index as u64) + 1;
    if syscall::wait_set_add(ws_cap, eq_cap, token).is_err()
    {
        println!("svcmgr: failed to add event queue to wait set");
        return None;
    }

    Some(eq_cap)
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

    println!("svcmgr: started");

    if caps.service_ep == 0
    {
        println!("svcmgr: no service endpoint, halting");
        halt_loop();
    }
    if info.procmgr_endpoint == 0
    {
        println!("svcmgr: no procmgr endpoint, halting");
        halt_loop();
    }

    let Ok(ws_cap) = syscall::wait_set_create()
    else
    {
        println!("svcmgr: failed to create wait set");
        halt_loop();
    };

    if syscall::wait_set_add(ws_cap, caps.service_ep, 0).is_err()
    {
        println!("svcmgr: failed to add service endpoint to wait set");
        halt_loop();
    }

    let mut state = SvcmgrState {
        services: [const { ServiceEntry::empty() }; MAX_SERVICES],
        service_count: 0,
        handover_complete: false,
        registry: registry::Registry::new(),
    };

    println!("svcmgr: waiting for registrations");

    event_loop(info, &caps, ws_cap, ipc_buf, &mut state);
}

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
    ipc_buf: *mut u64,
    state: &mut SvcmgrState,
) -> !
{
    let restart_ctx = restart::RestartCtx {
        procmgr_ep: info.procmgr_endpoint,
        bootstrap_ep: caps.bootstrap_ep,
        ipc_buf,
        ws_cap,
    };

    loop
    {
        let Ok(token) = syscall::wait_set_wait(ws_cap)
        else
        {
            println!("svcmgr: wait_set_wait failed");
            continue;
        };

        if token == 0
        {
            dispatch_ipc(caps.service_ep, ipc_buf, state, ws_cap);
        }
        else
        {
            dispatch_death(token, state, &restart_ctx);
        }
    }
}

/// Handle an IPC message on the service endpoint (registration, handover,
/// or discovery-registry publish/query).
fn dispatch_ipc(service_ep: u32, ipc_buf: *mut u64, state: &mut SvcmgrState, ws_cap: u32)
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
            let result =
                handle_register(&msg, &mut state.services, &mut state.service_count, ws_cap);
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
            println!(
                "svcmgr: handover complete, monitoring services: {:#018x}",
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
            handle_query_endpoint(&msg, &state.registry, ipc_buf);
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
    registry: &registry::Registry<REGISTRY_CAPACITY>,
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
        let reply = IpcMessage::new(ipc::svcmgr_errors::INSUFFICIENT_CAPS);
        // SAFETY: ipc_buf is the registered IPC buffer.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
        return;
    };
    let reply = IpcMessage::builder(ipc::svcmgr_errors::SUCCESS)
        .cap(derived)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
}

/// Handle a death notification from a monitored service.
fn dispatch_death(token: u64, state: &mut SvcmgrState, ctx: &restart::RestartCtx)
{
    let idx = (token - 1) as usize;
    if idx >= state.service_count
    {
        println!("svcmgr: invalid death notification token");
        return;
    }

    let Ok(exit_reason) = syscall::event_recv(state.services[idx].event_queue_cap)
    else
    {
        println!("svcmgr: event_recv failed");
        return;
    };

    if !state.services[idx].active
    {
        return;
    }

    restart::handle_death(&mut state.services[idx], exit_reason, ctx);

    // Re-add event queue to wait set with same token (if still active).
    if state.services[idx].active
        && syscall::wait_set_add(ctx.ws_cap, state.services[idx].event_queue_cap, token).is_err()
    {
        println!("svcmgr: failed to re-add event queue to wait set after restart");
        state.services[idx].active = false;
    }
}
