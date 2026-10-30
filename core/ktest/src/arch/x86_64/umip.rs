// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/umip.rs

//! Integration (x86-64): on a CPU that reports UMIP, a ring-3 `SIDT` or `SGDT`
//! raises `#GP` instead of returning a kernel address.
//!
//! The IDTR and GDTR bases are kernel addresses: the IDT and the BSP's GDT are
//! statics in the kernel image, which disclose the KASLR image slide, and an
//! AP's GDT lies in the direct map, which discloses the direct-map base. The
//! kernel sets `CR4.UMIP` on every CPU whose CPUID reports it
//! (`cpu::enable_smep_smap`; core/kernel/docs/cross-boundary-disclosure.md
//! § Surface inventory, descriptor-table registers). On every CPU in turn, two
//! children pinned there, one at a time on the same stack, each execute one of
//! the reads with no fault handler bound; each must die with
//! `EXIT_FAULT_BASE + 13` (`#GP`), so a CPU that missed the CR4 bit fails it.
//!
//! The children are killed rather than resumed by a bound handler: a CPU that
//! executes the read writes the register to the child's buffer and the child
//! then exits voluntarily, so a missing `CR4.UMIP` shows as a wrong exit
//! reason instead of a handler blocked forever on a fault that never comes.
//!
//! UMIP is opportunistic (docs/platform-requirements.md § x86-64
//! Classification): the case SKIPs, naming the reason, where
//! `CPUID.(EAX=07H,ECX=0):ECX[2]` is clear. CPUID executes at CPL 3, so the
//! check reads the same bit the kernel gates on.

use syscall_abi::{EXIT_FAULT_BASE, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult};

/// `#GP`, the vector a descriptor-table read faults with under UMIP.
const GP_VECTOR: u64 = 13;

/// Poll bound for each child's exit: ~2 s at ~1 ms per poll, through
/// [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Child argument selecting `SIDT`.
const READ_IDTR: u64 = 0;

/// Child argument selecting `SGDT`.
const READ_GDTR: u64 = 1;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    if core::arch::x86_64::__cpuid_count(7, 0).ecx & (1 << 2) == 0
    {
        crate::log("ktest: integration::umip_descriptor_reads_fault SKIP (CPUID reports no UMIP)");
        return Ok(());
    }
    let cpus = syscall::system_info(SystemInfoType::CpuCount as u64)
        .ok()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or("integration::umip_descriptor_reads_fault: system_info(CpuCount) failed")?;
    (0..cpus).try_for_each(|cpu| {
        expect_gp(
            ctx,
            READ_IDTR,
            cpu,
            "integration::umip_descriptor_reads_fault: SIDT did not #GP",
        )?;
        expect_gp(
            ctx,
            READ_GDTR,
            cpu,
            "integration::umip_descriptor_reads_fault: SGDT did not #GP",
        )
    })
}

/// Run one child, pinned to `cpu`, that executes the read `which` selects and
/// check it died of `#GP`; `failure` names the read. The child's caps are
/// deleted on every path (the `SpawnedChild` guard).
fn expect_gp(ctx: &TestContext, which: u64, cpu: u32, failure: &'static str) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "integration::umip_descriptor_reads_fault: spawn::new_child failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on which
    // no other live thread runs (`ChildStack`'s rule): the previous child has
    // exited and its Thread cap has been deleted before the next starts.
    unsafe { crate::spawn::configure_and_start_pinned(&child, reader, stack_top, which, cpu) }
        .map_err(
            |_| "integration::umip_descriptor_reads_fault: configure_and_start_pinned failed",
        )?;
    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if reason != EXIT_FAULT_BASE + GP_VECTOR
    {
        return Err(failure);
    }
    Ok(())
}

/// Child entry: execute `SIDT` (`which == READ_IDTR`) or `SGDT` into a stack
/// buffer, then exit. Under UMIP the read raises `#GP` and the kernel kills
/// this thread before the exit.
extern "C" fn reader(which: u64) -> !
{
    let mut descriptor = [0u8; 10];
    let dst = descriptor.as_mut_ptr();
    if which == READ_IDTR
    {
        // SAFETY: `sidt` stores the 10-byte IDTR to `[dst]`, the stack buffer
        // above, and touches no register or flag; under UMIP it raises #GP and
        // stores nothing.
        unsafe {
            core::arch::asm!("sidt [{dst}]", dst = in(reg) dst, options(nostack, preserves_flags));
        }
    }
    else
    {
        // SAFETY: `sgdt` stores the 10-byte GDTR to `[dst]`, the stack buffer
        // above, and touches no register or flag; under UMIP it raises #GP and
        // stores nothing.
        unsafe {
            core::arch::asm!("sgdt [{dst}]", dst = in(reg) dst, options(nostack, preserves_flags));
        }
    }
    syscall::thread_exit()
}
