// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svctest/src/phases/pager.rs

//! Demand-paging pager surface: memmgr backs reserved anonymous regions on
//! fault, and declines (kills) faults outside any registered region.
//!
//! Drives `/programs/demandpaged`. Demand paging is the system-wide default, so
//! the first two phases spawn it with no opt-in; the third opts out via
//! `std::os::seraph::CommandExt::pinned`:
//!
//!   * **positive** — the child reserves, registers, touches, and reads back a
//!     multi-page region; memmgr backs each first touch on fault. A clean exit
//!     proves the round-trip (touch → fault → map → resume) and that repeat
//!     access does not re-fault (the read-back pass sees the written pattern) —
//!     all with no opt-in flag, proving the default binds a pager.
//!   * **negative** — the child touches an *unregistered* reserved page; memmgr
//!     declines and the kernel kills it, proving preserved segfault semantics
//!     under a bound pager.
//!   * **pinned** — the child is spawned `pinned(true)`, so procmgr binds no
//!     pager and delegates no address space. Touching its *registered* region
//!     (which exits cleanly in **positive**) now faults with no handler and the
//!     kernel kills it, proving the opt-out leaves the process eager-mapped with
//!     no pager on the fault path.
//!
//! After each spawn/die cycle the all-RAM-accounted identity must still hold,
//! directly guarding against fault-path accounting drift (a stray
//! `pool_total` credit on demand allocation would break it).
//!
//! A fourth phase, **forged badge**, shows a process cannot make the kernel
//! stamp its faults with a badge other than its own memmgr cap's: binding its
//! own thread to its pager cap with a binder-supplied badge (another
//! process's, as a forger would pass) is refused with `InvalidArgument`, and
//! the same bind with the reserved word 0 succeeds, so the badge word alone
//! is the refusal's cause (docs/fault-handling.md § Security). The fault badge
//! is therefore always the derivation badge of a cap the binder holds, and a
//! process holding only its own memmgr cap cannot back another's region.

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
        Phase {
            name: "demand_paging_pinned",
            run: demand_paging_pinned_phase,
        },
        Phase {
            name: "pager_forged_badge_refused",
            run: pager_forged_badge_phase,
        },
    ]
}

/// Bind this thread to its pager cap with a forged badge word, then with the
/// reserved 0, through the raw syscall the typed wrapper cannot express.
fn pager_forged_badge_phase(_: &Caps)
{
    use syscall_abi::{FAULT_CLASS_ALL, SYS_THREAD_SET_FAULT_HANDLER, SyscallError};

    let info = startup_info();
    assert_ne!(
        info.pager_endpoint_cap, 0,
        "svctest is demand-paged: its pager cap must be advertised"
    );
    // Any other process's badge would do; a value that is not this process's
    // stands in for one.
    let forged = info.pager_badge ^ 0x5A5A;
    let bind = |badge: u64| {
        // SAFETY: raw_syscall4's four conditions hold. SYS_THREAD_SET_FAULT_HANDLER
        // takes no pointer and uses no IPC buffer; it changes no mapping; the
        // only thread it can change is the calling one, whose fault binding it
        // would set to the pager cap that binding already names (procmgr bound
        // the main thread to `pager_endpoint_cap`), leaving its registers alone;
        // and it changes no CSpace slot.
        unsafe {
            syscall::raw_syscall4(
                SYS_THREAD_SET_FAULT_HANDLER,
                u64::from(info.self_thread),
                u64::from(info.pager_endpoint_cap),
                badge,
                FAULT_CLASS_ALL,
            )
        }
    };
    let refused = bind(forged);
    assert_eq!(
        refused,
        SyscallError::InvalidArgument as i64,
        "a fault-handler bind carrying a binder-supplied badge must be refused"
    );
    let plain = bind(0);
    assert_eq!(
        plain, 0,
        "the same bind with the reserved badge word 0 must succeed"
    );
    std::os::seraph::log!("pager_forged_badge_refused phase passed (forged bind -> {refused})");
}

fn demand_paging_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/demandpaged")
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
    use syscall::EXIT_FAULT_BASE;

    let mut child = Command::new("/programs/demandpaged")
        .arg("oor")
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

// cast_sign_loss: ExitStatus::code() is i32 but exit reasons are non-negative
// (fault 0x1000+vec, killed 0x2000); the u64 cast is safe.
#[allow(clippy::cast_sign_loss)]
fn demand_paging_pinned_phase(_: &Caps)
{
    use std::process::Command;
    use syscall::EXIT_FAULT_BASE;

    // Pinned: procmgr binds no fault handler and delegates no address space.
    // The child still registers its region (memmgr records it against the badge
    // minted at REGISTER_PROCESS), but the first touch faults with no handler
    // bound, so the kernel kills the process. The same registered-region touch
    // exits cleanly in `demand_paging` — the kill here is the proof that
    // `pinned(true)` suppressed the default pager.
    let mut child = Command::new("/programs/demandpaged")
        .pinned(true)
        .spawn()
        .expect("spawn /programs/demandpaged pinned failed");
    let status = child.wait().expect("demandpaged pinned wait failed");
    std::os::seraph::log!("demandpaged pinned exited: {status}");
    assert!(
        !status.success(),
        "a pinned child has no pager: touching its registered region must be \
         killed, not backed: {status}"
    );
    let raw = status.code().expect("pinned ExitStatus must carry a code") as u64;
    assert!(
        raw >= EXIT_FAULT_BASE,
        "expected a no-handler fault exit_reason >= {EXIT_FAULT_BASE:#x}, got {raw:#x}"
    );

    // The child died with no demand frames mapped (no handler ever backed a
    // page); memmgr reclaims its record on PROCESS_DIED. The identity must hold.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging_pinned phase passed (exit_reason={raw:#x})");
}

/// Assert `system_ram == kernel_reserved + pool_total` via memmgr
/// `QUERY_POOL_STATUS`.
fn assert_ram_identity()
{
    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
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
