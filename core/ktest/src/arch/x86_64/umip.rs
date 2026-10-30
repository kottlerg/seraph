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
//! § Surface inventory, descriptor-table registers). On each checked CPU, two
//! children pinned there, one at a time on the same stack and with this thread
//! as their fault handler, each execute one of the reads; each read must be
//! delivered as a `FAULT_EXC_PROTECTION` exception, so a CPU that missed the CR4
//! bit fails the case.
//!
//! **Checked CPUs.** Every CPU up to [`EVERY_CPU_MAX`]; past it, the first
//! [`LOW_CPUS`] (the BSP and the first APs) and [`SAMPLED_CPUS`] spread evenly
//! over the rest, the last CPU among them. Every AP sets the bit through the
//! same call in `arch::x86_64::interrupts::init_ap`, so a per-CPU miss is a
//! bring-up-path defect the BSP/AP split and the two ends of the index range
//! expose; checking every CPU at the `MAX_CPUS` boundary costs minutes of
//! oversubscribed scheduling for no path the sample misses.
//!
//! **What counts as the fault.** A `FAULT_EXC_PROTECTION` message whose error
//! code is 0 and whose faulting IP is the read itself: the child records the
//! read's address in [`READ_IP`] before executing it, as the UMIP `#GP` is the
//! only protection fault that reports that IP with a zero error code there.
//!
//! **No fault dump.** A fault the kernel kills a thread for prints a register
//! dump to the serial console, which at boundary widths costs over a second
//! per child. The handler instead resumes each faulted child at
//! [`exit_entry`], so it exits voluntarily and nothing is printed. A CPU that
//! executes the read does not fault there: the child reaches the illegal
//! instruction after it, whose `#UD` the handler receives instead, so a
//! missing `CR4.UMIP` fails the case rather than leaving the handler blocked
//! on a fault that never comes.
//!
//! UMIP is opportunistic (docs/platform-requirements.md § x86-64
//! Classification): the case SKIPs, naming the reason, where
//! `CPUID.(EAX=07H,ECX=0):ECX[2]` is clear. CPUID executes at CPL 3, so the
//! check reads the same bit the kernel gates on.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{cap_create_endpoint, cap_delete, thread_read_regs, thread_write_regs};
use syscall_abi::{
    EXIT_VOLUNTARY, FAULT_EXC_ILLEGAL_INSTRUCTION, FAULT_EXC_PROTECTION, FAULT_KIND_EXCEPTION,
    FAULT_LABEL, FAULT_REPLY_RESUME, SystemInfoType,
};

use crate::{ChildStack, TestContext, TestResult};

/// Up to this many CPUs, every CPU is checked. Like [`LOW_CPUS`], a test
/// fixture: it bounds only how many CPUs the check visits on a wide boot.
const EVERY_CPU_MAX: u32 = 16;

/// Past [`EVERY_CPU_MAX`], the lowest CPUs checked: CPU 0 (the BSP) and the
/// first APs.
const LOW_CPUS: u32 = 8;

/// Past [`EVERY_CPU_MAX`], the CPUs checked above [`LOW_CPUS`], spread evenly
/// from CPU `LOW_CPUS` to the last CPU.
const SAMPLED_CPUS: u32 = EVERY_CPU_MAX - LOW_CPUS;

/// Badge bound with the handler and delivered in each fault message.
const FAULT_BADGE: u64 = 0x0D17_0001;

/// Register-file buffer size; holds the x86-64 `TrapFrame`.
const BUF: usize = 256;
const _: () = assert!(BUF as u64 >= super::TRAP_FRAME_BYTES);

/// Poll bound for each child's exit: ~2 s at ~1 ms per poll, through
/// [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Child argument selecting `SIDT`.
const READ_IDTR: u64 = 0;

/// Child argument selecting `SGDT`.
const READ_GDTR: u64 = 1;

/// Address of the read the child is about to execute, written by the child
/// before the read and compared with the fault message's IP by the handler.
static READ_IP: AtomicU64 = AtomicU64::new(0);

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
    let ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "integration::umip_descriptor_reads_fault: cap_create_endpoint failed")?;
    let result = (0..cpus.min(EVERY_CPU_MAX)).try_for_each(|k| {
        let cpu = checked_cpu(k, cpus);
        expect_gp(ctx, ep, READ_IDTR, cpu)?;
        expect_gp(ctx, ep, READ_GDTR, cpu)
    });
    cap_delete(ep).ok();
    result
}

/// The `k`th CPU checked of `cpus` (`k < cpus.min(EVERY_CPU_MAX)`): `k` itself
/// up to [`EVERY_CPU_MAX`] CPUs; past it, CPU `k` for the first [`LOW_CPUS`],
/// then [`SAMPLED_CPUS`] CPUs evenly spaced from `LOW_CPUS` to `cpus - 1`.
fn checked_cpu(k: u32, cpus: u32) -> u32
{
    if cpus <= EVERY_CPU_MAX || k < LOW_CPUS
    {
        return k;
    }
    // `cpus - 1 - LOW_CPUS` >= SAMPLED_CPUS - 1 here, so the samples are
    // distinct; the last is `cpus - 1`.
    let j = u64::from(k - LOW_CPUS);
    let span = u64::from(cpus - 1 - LOW_CPUS);
    let offset = j * span / u64::from(SAMPLED_CPUS - 1);
    LOW_CPUS + u32::try_from(offset).unwrap_or(0)
}

/// Run one child, pinned to `cpu` with this thread as its fault handler on
/// `ep`, that executes the read `which` selects; check the read is delivered
/// as a `#GP` at the read with error code 0, then resume the child at
/// [`exit_entry`] and check it exits
/// voluntarily. The child's caps are deleted on every path (the `SpawnedChild`
/// guard).
fn expect_gp(ctx: &TestContext, ep: u32, which: u64, cpu: u32) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx)
        .map_err(|_| "integration::umip_descriptor_reads_fault: spawn::new_child failed")?;
    crate::bind_fault_handler(child.th, ep, FAULT_BADGE)
        .map_err(|_| "integration::umip_descriptor_reads_fault: thread_set_fault_handler failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(CHILD_STACK));
    // The previous child's read address must not stand in for this one's.
    READ_IP.store(0, Ordering::Release);
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on which
    // no other live thread runs (`ChildStack`'s rule): the previous child has
    // exited and its Thread cap has been deleted before the next starts.
    unsafe { crate::spawn::configure_and_start_pinned(&child, reader, stack_top, which, cpu) }
        .map_err(
            |_| "integration::umip_descriptor_reads_fault: configure_and_start_pinned failed",
        )?;

    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "integration::umip_descriptor_reads_fault: ipc_recv failed")?;
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE || msg.word(0) != FAULT_KIND_EXCEPTION
    {
        return Err("integration::umip_descriptor_reads_fault: unexpected fault message");
    }
    match msg.word(1)
    {
        FAULT_EXC_PROTECTION =>
        {}
        FAULT_EXC_ILLEGAL_INSTRUCTION if which == READ_IDTR =>
        {
            return Err("integration::umip_descriptor_reads_fault: SIDT did not #GP");
        }
        FAULT_EXC_ILLEGAL_INSTRUCTION =>
        {
            return Err("integration::umip_descriptor_reads_fault: SGDT did not #GP");
        }
        _ => return Err("integration::umip_descriptor_reads_fault: unexpected exception class"),
    }
    let read_ip = READ_IP.load(Ordering::Acquire);
    if msg.word(2) != 0 || read_ip == 0 || msg.word(3) != read_ip
    {
        return Err("integration::umip_descriptor_reads_fault: #GP is not the read's (IP or code)");
    }

    let mut regs = [0u8; BUF];
    thread_read_regs(child.th, &mut regs[..BUF])
        .map_err(|_| "integration::umip_descriptor_reads_fault: thread_read_regs failed")?;
    crate::spawn::redirect_to_entry(&mut regs[..], exit_entry as *const () as u64);
    // SAFETY: the frame was read from this fault-blocked child, so its stack
    // pointer lies on the child's own `ChildStack`; `redirect_to_entry` pointed it
    // at `exit_entry`, an `extern "C"` entry that never returns and needs nothing
    // of the abandoned frame, with the stack pointer moved down to the entry
    // ABI's alignment on that same stack.
    unsafe { thread_write_regs(child.th, &regs[..BUF]) }
        .map_err(|_| "integration::umip_descriptor_reads_fault: thread_write_regs failed")?;
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ctx.ipc_buf) }
        .map_err(|_| "integration::umip_descriptor_reads_fault: ipc_reply(RESUME) failed")?;

    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if reason != EXIT_VOLUNTARY
    {
        return Err(
            "integration::umip_descriptor_reads_fault: resumed child did not exit voluntarily",
        );
    }
    Ok(())
}

/// Child entry: execute `SIDT` (`which == READ_IDTR`) or `SGDT` into a stack
/// buffer, then an illegal instruction. Under UMIP the read faults first and
/// the handler resumes this thread at [`exit_entry`]; without it the read
/// completes and the `#UD` reaches the handler instead.
extern "C" fn reader(which: u64) -> !
{
    let mut descriptor = [0u8; 10];
    let dst = descriptor.as_mut_ptr();
    let slot = READ_IP.as_ptr();
    if which == READ_IDTR
    {
        // SAFETY: `lea` and the `READ_IP` store use the scratch register `t`
        // and write only the `READ_IP` atomic; `sidt` then stores the 10-byte
        // IDTR to `[dst]`, the stack buffer above. No other register or flag
        // is touched; under UMIP the `sidt` raises #GP and stores nothing.
        unsafe {
            core::arch::asm!(
                "lea {t}, [rip + 2f]",
                "mov qword ptr [{slot}], {t}",
                "2:",
                "sidt [{dst}]",
                t = out(reg) _,
                slot = in(reg) slot,
                dst = in(reg) dst,
                options(nostack, preserves_flags),
            );
        }
    }
    else
    {
        // SAFETY: as for the `sidt` arm, with `sgdt` storing the 10-byte GDTR.
        unsafe {
            core::arch::asm!(
                "lea {t}, [rip + 2f]",
                "mov qword ptr [{slot}], {t}",
                "2:",
                "sgdt [{dst}]",
                t = out(reg) _,
                slot = in(reg) slot,
                dst = in(reg) dst,
                options(nostack, preserves_flags),
            );
        }
    }
    crate::arch::illegal_instruction()
}

/// Recovery entry the handler resumes a faulted child at: exit voluntarily.
extern "C" fn exit_entry(_arg: u64) -> !
{
    syscall::thread_exit()
}
