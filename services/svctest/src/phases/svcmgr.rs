// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/svcmgr.rs

//! svcmgr service surface: the authority gates on its service endpoint, as
//! reached through svctest's per-process `service_registry_cap`.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The svcmgr phases, in run order.
pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "svcmgr_handover_refused",
            run: svcmgr_handover_refused_phase,
        },
        Phase {
            name: "svcmgr_publish_gate",
            run: svcmgr_publish_gate_phase,
        },
        Phase {
            name: "svcmgr_published_send_badged",
            run: svcmgr_published_send_badged_phase,
        },
    ]
}

/// The registry SEND procmgr installed in svctest's `ProcessInfo`, and the
/// IPC buffer to call it with.
fn registry_cap_and_buf(phase: &str) -> (u32, *mut u64)
{
    let info = startup_info();
    let registry_cap = info.service_registry_cap;
    assert_ne!(
        registry_cap, 0,
        "{phase}: no service_registry_cap in ProcessInfo"
    );
    // cast_ptr_alignment: the IPC buffer is page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    (registry_cap, ipc_buf)
}

/// End to end: a `HANDOVER_COMPLETE` sent after init's handover through the
/// per-process SEND must be refused. Were it honoured, svcmgr would re-run
/// reconciliation and launch a second instance of every defined service.
/// svctest always runs after the handover, so the badge test and the
/// once-only rule both refuse this call and the phase cannot tell them apart;
/// each is host-tested on its own in `svcmgr-defs`
/// (`handover_needs_the_authority_bit`, `handover_is_honoured_only_once`).
fn svcmgr_handover_refused_phase(_caps: &Caps)
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_handover_refused");
    let msg = ipc::IpcMessage::new(ipc::svcmgr_labels::HANDOVER_COMPLETE);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
        .expect("svcmgr HANDOVER_COMPLETE ipc_call must return a reply");
    assert_eq!(
        reply.label,
        ipc::svcmgr_errors::UNAUTHORIZED,
        "svcmgr HANDOVER_COMPLETE after the handover must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    std::os::seraph::log!("svcmgr handover-refused phase passed (UNAUTHORIZED reply)");
}

/// `PUBLISH_ENDPOINT` through the per-process SEND must fail the
/// `PUBLISH_AUTHORITY` gate. svcmgr checks the badge before the attached
/// cap, so a request with a valid name and no cap replies `UNAUTHORIZED`
/// only when the process badge lacks the verb-bit; a badge carrying it
/// would reach the cap check and reply `INSUFFICIENT_CAPS`.
fn svcmgr_publish_gate_phase(_caps: &Caps)
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_publish_gate");
    let name = b"svctest.forged";
    let label = ipc::svcmgr_labels::PUBLISH_ENDPOINT | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
        .expect("svcmgr PUBLISH_ENDPOINT ipc_call must return a reply");
    assert_eq!(
        reply.label,
        ipc::svcmgr_errors::UNAUTHORIZED,
        "svcmgr PUBLISH_ENDPOINT through the per-process SEND must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    std::os::seraph::log!("svcmgr publish-gate phase passed (UNAUTHORIZED reply)");
}

/// The SEND svcmgr publishes under `svcmgr` must be badged and lack
/// `PUBLISH_AUTHORITY`. Already badged, it cannot be re-badged, so a
/// consumer cannot mint `HANDOVER_AUTHORITY` from it: the kernel refuses a
/// re-badge of a badged source with `InvalidArgument`. Lacking
/// `PUBLISH_AUTHORITY`, it fails the publish gate: a nameful, capless
/// `PUBLISH_ENDPOINT` through it replies `UNAUTHORIZED`, where the bit would
/// reach the cap check. Whether the badge carries `HANDOVER_AUTHORITY` is
/// not observable after the handover; a compile-time assertion beside
/// `ipc::svcmgr_labels::PUBLISHED_SEND_BADGE` keeps every verb-bit out of it.
fn svcmgr_published_send_badged_phase(_caps: &Caps)
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_published_send_badged");
    let name = ipc::published_names::SVCMGR;
    let label = ipc::svcmgr_labels::QUERY_ENDPOINT | ((name.len() as u64) << 16);
    let msg = ipc::IpcMessage::builder(label).bytes(0, name).build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
        .expect("svcmgr QUERY_ENDPOINT ipc_call must return a reply");
    assert_eq!(
        reply.label,
        ipc::svcmgr_errors::SUCCESS,
        "svcmgr QUERY_ENDPOINT(svcmgr) must resolve (got {:#x})",
        reply.label
    );
    let published = reply.caps().first().copied().unwrap_or(0);
    assert_ne!(
        published, 0,
        "svcmgr QUERY_ENDPOINT(svcmgr) returned no cap"
    );

    let rebadged = syscall::cap_derive_badge(
        published,
        syscall::RIGHTS_EP_SEND,
        ipc::svcmgr_labels::HANDOVER_AUTHORITY,
    );
    if let Ok(forged) = rebadged
    {
        let _ = syscall::cap_delete(forged);
    }

    let forged_name = b"svctest.forged";
    let publish_label = ipc::svcmgr_labels::PUBLISH_ENDPOINT | ((forged_name.len() as u64) << 16);
    let publish = ipc::IpcMessage::builder(publish_label)
        .bytes(0, forged_name)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer.
    let publish_reply = unsafe { ipc::ipc_call(published, &publish, ipc_buf) };
    let _ = syscall::cap_delete(published);

    assert_eq!(
        rebadged,
        Err(syscall_abi::SyscallError::InvalidArgument as i64),
        "re-badging the published svcmgr SEND must fail as already badged"
    );
    let publish_label = publish_reply
        .expect("svcmgr PUBLISH_ENDPOINT ipc_call must return a reply")
        .label;
    assert_eq!(
        publish_label,
        ipc::svcmgr_errors::UNAUTHORIZED,
        "PUBLISH_ENDPOINT through the published svcmgr SEND must reply UNAUTHORIZED (got {publish_label:#x})"
    );
    std::os::seraph::log!("svcmgr published-send phase passed (badged, no PUBLISH_AUTHORITY)");
}
