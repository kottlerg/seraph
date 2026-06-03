// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Demand-paging pager surface: memmgr backs reserved anonymous regions on
//! fault, and declines (kills) faults outside any registered region.
//!
//! Drives `/programs/demandpaged`, spawned demand-paged via
//! `std::os::seraph::CommandExt::demand_paged`:
//!
//!   * **positive** — the child reserves, registers, touches, and reads back a
//!     multi-page region; memmgr backs each first touch on fault. A clean exit
//!     proves the round-trip (touch → fault → map → resume) and that repeat
//!     access does not re-fault (the read-back pass sees the written pattern).
//!   * **negative** — the child touches an *unregistered* reserved page; memmgr
//!     declines and the kernel kills it, proving preserved segfault semantics
//!     under a bound pager.
//!
//! After the spawn/die cycle the all-RAM-accounted identity must still hold,
//! directly guarding against fault-path accounting drift (a stray
//! `pool_total` credit on demand allocation would break it).

use std::os::seraph::process::CommandExt;
use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "demand_paging",
            run: demand_paging_phase,
        },
        Phase {
            name: "demand_paging_segfault",
            run: demand_paging_segfault_phase,
        },
    ]
}

fn demand_paging_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/demandpaged")
        .demand_paged(true)
        .spawn()
        .expect("spawn /programs/demandpaged failed");
    let status = child.wait().expect("demandpaged wait failed");
    std::os::seraph::log!("demandpaged exited: {status}");
    assert!(
        status.success(),
        "demand-paged child must exit cleanly: {status}"
    );

    // The child has exited; procmgr's PROCESS_DIED reclaims its demand frames.
    // memmgr's accounting identity must remain closed across the cycle.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging phase passed");
}

// cast_sign_loss: ExitStatus::code() is i32 but exit reasons are non-negative
// (fault 0x1000+vec, killed 0x2000); the u64 cast is safe.
#[allow(clippy::cast_sign_loss)]
fn demand_paging_segfault_phase(_: &Caps)
{
    use std::process::Command;

    const EXIT_FAULT_BASE: u64 = 0x1000;

    let mut child = Command::new("/programs/demandpaged")
        .arg("oor")
        .demand_paged(true)
        .spawn()
        .expect("spawn /programs/demandpaged oor failed");
    let status = child.wait().expect("demandpaged oor wait failed");
    std::os::seraph::log!("demandpaged oor exited: {status}");
    assert!(
        !status.success(),
        "out-of-region touch must be killed, not exit cleanly: {status}"
    );
    let raw = status.code().expect("oor ExitStatus must carry a code") as u64;
    assert!(
        raw >= EXIT_FAULT_BASE,
        "expected a fault/kill exit_reason >= {EXIT_FAULT_BASE:#x}, got {raw:#x}"
    );
    std::os::seraph::log!("demand_paging_segfault phase passed (exit_reason={raw:#x})");
}

/// Assert `system_ram == kernel_reserved + pool_total` via memmgr
/// `QUERY_POOL_STATUS`.
fn assert_ram_identity()
{
    let info = startup_info();
    #[allow(clippy::cast_ptr_alignment)]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let req = ipc::IpcMessage::builder(ipc::memmgr_labels::QUERY_POOL_STATUS).build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &req, ipc_buf) }
        .expect("QUERY_POOL_STATUS ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "QUERY_POOL_STATUS status"
    );
    let (system_ram, kernel_reserved, pool_total) = (reply.word(0), reply.word(1), reply.word(2));
    assert_eq!(
        system_ram,
        kernel_reserved.saturating_add(pool_total),
        "RAM identity broken after demand paging: \
         system_ram={system_ram} kernel_reserved={kernel_reserved} pool_total={pool_total}"
    );
}
