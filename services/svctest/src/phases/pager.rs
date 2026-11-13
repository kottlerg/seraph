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
//!
//! A fifth phase, **refused access**, shows memmgr declines a fault whose
//! access the region's protection refuses, whether or not the page is backed:
//! no backing satisfies such an access, so a resume would fault again forever.
//! Each decline is checked for memmgr's reason code: a refused access, then,
//! once the region is unregistered, no region.
//!
//! A sixth phase, **page-table drain**, shows a demand fault is backed when
//! the faulting address space's page-table pool is empty: the child registers
//! a region, empties its own pool with mappings of its own, then touches a
//! block of the region that needs a fresh page table. memmgr funds the pool
//! itself and resumes rather than declining the fault.
//!
//! A seventh phase, **teardown**, shows `unregister_demand_paged` releases a
//! demand region whole: the child registers and fills a region, tears it
//! down, and registers one of the same size again, which the reservation
//! allocator places on the same VA. memmgr accepts that registration only if
//! the teardown removed the first one.

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
        Phase {
            name: "pager_refused_access_declined",
            run: pager_refused_access_phase,
        },
        Phase {
            name: "demand_paging_pt_drain",
            run: demand_paging_pt_drain_phase,
        },
        Phase {
            name: "demand_paging_teardown",
            run: demand_paging_teardown_phase,
        },
    ]
}

/// Send memmgr, on this process's own memmgr cap, the fault message the
/// kernel would for an access to `va` (memmgr attributes a fault by the
/// cap's badge, docs/fault-handling.md § Security), and return its reply
/// label, `FAULT_REPLY_RESUME` or `FAULT_REPLY_FORWARD`, with the decline
/// code a `FAULT_REPLY_FORWARD` carries in the low half of data word 0 (zero
/// on a resume): services/memmgr/docs/ipc-interface.md § Kernel-origin fault
/// message tables the codes.
fn forged_vm_fault(va: u64, access: u64) -> (u64, u64)
{
    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(syscall_abi::FAULT_LABEL)
        .word(0, syscall_abi::FAULT_KIND_VM)
        .word(1, va)
        .word(2, access)
        .word(3, 0)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &msg, ipc_buf) }
        .expect("refused_access: forged fault ipc_call failed");
    let code = if reply.label == syscall_abi::FAULT_REPLY_FORWARD
    {
        reply.word(0) & 0xFFFF_FFFF
    }
    else
    {
        0
    };
    (reply.label, code)
}

/// memmgr's decline code for a fault whose access the region refuses.
const DECLINE_ACCESS_REFUSED: u64 = 4;
/// memmgr's decline code for a fault outside every registered region.
const DECLINE_NO_REGION: u64 = 3;

/// An instruction fetch from a read-write demand region is declined before
/// the page is backed and after: a read of the same page is backed and
/// resumed between the two. memmgr once resumed a fault on a backed page
/// whatever its access, so a write to a backed read-only page looped. Each
/// decline carries the reason the kernel's kill diagnostic prints: a refused
/// access, then, once the region is unregistered, no region.
fn pager_refused_access_phase(_: &Caps)
{
    use syscall_abi::{
        FAULT_ACCESS_EXEC, FAULT_ACCESS_READ, FAULT_REPLY_FORWARD, FAULT_REPLY_RESUME,
    };

    let range = std::os::seraph::register_demand_paged(1).expect("refused_access: register");
    let va = range.va_start();
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_EXEC),
        (FAULT_REPLY_FORWARD, DECLINE_ACCESS_REFUSED),
        "refused_access: a fetch from an unbacked read-write page was not declined as refused"
    );
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_READ).0,
        FAULT_REPLY_RESUME,
        "refused_access: a read of a read-write page was not backed"
    );
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_EXEC),
        (FAULT_REPLY_FORWARD, DECLINE_ACCESS_REFUSED),
        "refused_access: a fetch from a backed read-write page was not declined as refused"
    );

    // UNREGISTER_REGION unmaps the backed page and returns its frames.
    let info = startup_info();
    let ipc_buf = std::os::seraph::current_ipc_buf();
    let msg = ipc::IpcMessage::builder(ipc::memmgr_labels::UNREGISTER_REGION)
        .word(0, va)
        .word(1, syscall_abi::PAGE_SIZE)
        .build();
    // SAFETY: ipc_buf is the kernel-registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(info.memmgr_endpoint, &msg, ipc_buf) }
        .expect("refused_access: UNREGISTER_REGION ipc_call failed");
    assert_eq!(
        reply.label,
        ipc::memmgr_errors::SUCCESS,
        "refused_access: UNREGISTER_REGION status"
    );
    assert_eq!(
        forged_vm_fault(va, FAULT_ACCESS_READ),
        (FAULT_REPLY_FORWARD, DECLINE_NO_REGION),
        "refused_access: a read of an unregistered page was not declined as outside every region"
    );
    std::os::seraph::unreserve_pages(range);
    assert_ram_identity();
    std::os::seraph::log!("pager_refused_access_declined phase passed");
}

/// Bind this thread to its pager cap with a forged badge word, then with the
/// reserved 0, through the raw syscall the typed wrapper cannot express.
fn pager_forged_badge_phase(_: &Caps)
{
    use syscall_abi::{FAULT_CLASS_VM, SYS_THREAD_SET_FAULT_HANDLER, SyscallError};

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
        // only thread it can change is the calling one, whose virtual-memory
        // class alone it would set to the pager cap that binding already names
        // (procmgr bound that class of the main thread to `pager_endpoint_cap`),
        // leaving its other classes and its registers alone; and it changes no
        // CSpace slot.
        unsafe {
            syscall::raw_syscall4(
                SYS_THREAD_SET_FAULT_HANDLER,
                info.self_thread,
                info.pager_endpoint_cap,
                badge,
                FAULT_CLASS_VM,
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

/// The child empties its address space's page-table pool after registering a
/// region, then touches a block of the region whose leaf table does not exist
/// yet. A clean exit proves memmgr funded the pool and backed the fault; a
/// fault exit is memmgr declining it with code 9 (`mem_map` failed,
/// `OutOfMemory`). The exit codes are the fixture's
/// (programs/demandpaged/README.md).
fn demand_paging_pt_drain_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/demandpaged")
        .arg("ptdrain")
        .spawn()
        .expect("spawn /programs/demandpaged ptdrain failed");
    let status = child.wait().expect("demandpaged ptdrain wait failed");
    std::os::seraph::log!("demandpaged ptdrain exited: {status}");
    assert!(
        status.success(),
        "a demand fault with the page-table pool empty must be backed: {status}"
    );

    // The pages memmgr donated to the child's page-table pool are accounted to
    // its record and reclaimed with it; the identity must hold.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging_pt_drain phase passed");
}

/// The child registers, fills and tears down a demand region twice, the second
/// region on the first one's VA. A clean exit proves the teardown removed
/// memmgr's registration and released the reservation; exit `2` is memmgr
/// refusing the second registration as an overlap, `4` an unanswered
/// teardown, `5` a second reservation at another VA. The exit codes are the
/// fixture's (programs/demandpaged/README.md).
fn demand_paging_teardown_phase(_: &Caps)
{
    use std::process::Command;

    let mut child = Command::new("/programs/demandpaged")
        .arg("teardown")
        .spawn()
        .expect("spawn /programs/demandpaged teardown failed");
    let status = child.wait().expect("demandpaged teardown wait failed");
    std::os::seraph::log!("demandpaged teardown exited: {status}");
    assert!(
        status.success(),
        "a torn-down demand region must leave its VA free to register again: {status}"
    );

    // The frames memmgr reclaimed at the teardown went back to its pool; the
    // identity must hold.
    assert_ram_identity();
    std::os::seraph::log!("demand_paging_teardown phase passed");
}

#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32 but exit reasons are non-negative (fault 0x1000+vec, \
              killed 0x2000); the u64 cast is safe"
)]
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

#[expect(
    clippy::cast_sign_loss,
    reason = "ExitStatus::code() is i32 but exit reasons are non-negative (fault 0x1000+vec, \
              killed 0x2000); the u64 cast is safe"
)]
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
