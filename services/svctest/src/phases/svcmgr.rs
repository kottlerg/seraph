// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/svcmgr.rs

//! svcmgr service surface: the one-shot `HANDOVER_COMPLETE` gate.

use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// The svcmgr phases, in run order.
pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "svcmgr_handover_gate",
        run: svcmgr_handover_gate_phase,
    }]
}

/// `HANDOVER_COMPLETE` through svctest's per-process registry SEND (its
/// procmgr-minted badge, not init's `HANDOVER_AUTHORITY` one) must be
/// refused. Were it honoured, svcmgr would re-run reconciliation and launch
/// a second instance of every defined service.
fn svcmgr_handover_gate_phase(_caps: &Caps)
{
    let info = startup_info();
    let registry_cap = info.service_registry_cap;
    assert_ne!(
        registry_cap, 0,
        "svcmgr handover gate: no service_registry_cap in ProcessInfo"
    );
    // cast_ptr_alignment: the IPC buffer is page-aligned.
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    let msg = ipc::IpcMessage::new(ipc::svcmgr_labels::HANDOVER_COMPLETE);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(registry_cap, &msg, ipc_buf) }
        .expect("svcmgr HANDOVER_COMPLETE ipc_call must return a reply");
    assert_eq!(
        reply.label,
        ipc::svcmgr_errors::UNAUTHORIZED,
        "svcmgr HANDOVER_COMPLETE from a non-init caller must reply UNAUTHORIZED (got {:#x})",
        reply.label
    );
    std::os::seraph::log!("svcmgr handover-gate phase passed (UNAUTHORIZED reply)");
}
