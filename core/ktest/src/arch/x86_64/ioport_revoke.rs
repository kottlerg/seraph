// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/ioport_revoke.rs

//! Integration (x86-64): revoking an `IoPort` capability withdraws the port
//! access bound through its descendants, from a thread running on another CPU.
//!
//! Carves `held`, an `IoPort` capability for the first ELCR port (0x4D0, the
//! 8259 edge/level control register, which reads without side effect), out of
//! ktest's wide `IoPort` capability, derives `granted` from `held`, and binds
//! `granted` to a child thread. The child, on another CPU when there is one,
//! reads the port in a loop, so that CPU's TSS holds the permitting bitmap.
//! Revoking `held` frees `granted`, whose teardown withdraws the binding and
//! invalidates every CPU's TSS bitmap before the revoke returns
//! ([docs/capability-model.md § `IoPort`](../../../../../docs/capability-model.md#ioport-x86-64-only)):
//! the child's next read raises `#GP` and kills it.

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::{cap_delete, cap_derive, cap_revoke, ioport_bind, system_info};
use syscall_abi::{EXIT_FAULT_BASE, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult};

/// The port the child reads: the 8259 ELCR for IRQs 0-7.
const PORT: u16 = 0x4D0;

/// `#GP`, the vector a denied port access faults with.
const GP_VECTOR: u64 = 13;

/// Poll bound (about 1 ms per poll), scaled by [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Reads the child completed.
static READS: AtomicU64 = AtomicU64::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    let Some(held) = super::ioport::carve_port_range(PORT, 1)
    else
    {
        crate::log("ktest: integration::ioport_revoke SKIP (cannot carve port 0x4D0)");
        return Ok(());
    };
    let result = check(ctx, held);
    cap_delete(held).ok();
    result
}

fn check(ctx: &TestContext, held: u32) -> TestResult
{
    let granted = cap_derive(held, syscall::RIGHTS_ALL)
        .map_err(|_| "integration::ioport_revoke: cap_derive(granted) failed")?;
    let Ok(child) = crate::spawn::new_child(ctx)
    else
    {
        cap_delete(granted).ok();
        return Err("integration::ioport_revoke: spawn::new_child failed");
    };
    let abandon = |why: &'static str| -> TestResult {
        cap_delete(child.cs).ok();
        cap_delete(child.th).ok();
        cap_delete(granted).ok();
        Err(why)
    };
    if ioport_bind(child.th, granted).is_err()
    {
        return abandon("integration::ioport_revoke: ioport_bind failed");
    }

    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    READS.store(0, Ordering::Relaxed);
    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    let started = unsafe {
        if cpus >= 2
        {
            crate::spawn::configure_and_start_pinned(&child, reader, stack_top, 0, 1)
        }
        else
        {
            crate::spawn::configure_and_start(&child, reader, stack_top, 0)
        }
    };
    if started.is_err()
    {
        return abandon("integration::ioport_revoke: starting the reader failed");
    }

    let polls = crate::scaled_polls(MAX_POLLS);
    let mut waited = 0;
    while READS.load(Ordering::Acquire) == 0
    {
        waited += 1;
        if waited >= polls
        {
            return abandon("integration::ioport_revoke: the reader never read the port");
        }
        syscall::thread_sleep(1).ok();
    }

    if cap_revoke(held).is_err()
    {
        return abandon("integration::ioport_revoke: cap_revoke failed");
    }
    let reason = crate::spawn::wait_until_exited(child.th, polls)?;
    cap_delete(child.th).ok();
    cap_delete(child.cs).ok();
    if reason != EXIT_FAULT_BASE + GP_VECTOR
    {
        return Err("integration::ioport_revoke: the reader did not die of #GP");
    }
    Ok(())
}

/// Child entry: read [`PORT`] until the read faults.
extern "C" fn reader(_arg: u64) -> !
{
    loop
    {
        // SAFETY: the parent bound PORT to this thread before starting it; once
        // the parent's revoke withdraws the binding the read raises #GP and
        // the kernel kills this thread.
        let _ = unsafe { inb(PORT) };
        READS.fetch_add(1, Ordering::Release);
    }
}

/// Read a byte from I/O port `port` (`in al, dx`; reads dx, writes al only,
/// touches no memory or flag).
///
/// # Safety
/// The calling thread must hold an `ioport_bind` grant covering `port`, or
/// expect the `#GP` a denied access raises.
#[inline]
unsafe fn inb(port: u16) -> u8
{
    let val: u8;
    // SAFETY: caller contract.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            in("dx") port,
            out("al") val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}
