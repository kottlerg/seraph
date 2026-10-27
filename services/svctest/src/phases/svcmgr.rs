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
            name: "svcmgr_handover_repeat",
            run: svcmgr_handover_repeat_phase,
        },
        Phase {
            name: "svcmgr_publish_gate",
            run: svcmgr_publish_gate_phase,
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

/// A `HANDOVER_COMPLETE` after init's handover must be refused. Were it
/// honoured, svcmgr would re-run reconciliation and launch a second instance
/// of every defined service. svctest runs only after the handover, so this
/// exercises the once-only rule; the badge half of the gate is host-tested
/// in `svcmgr-defs` (`handover_permitted`).
fn svcmgr_handover_repeat_phase(_caps: &Caps)
{
    let (registry_cap, ipc_buf) = registry_cap_and_buf("svcmgr_handover_repeat");
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
    std::os::seraph::log!("svcmgr handover-repeat phase passed (UNAUTHORIZED reply)");
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
