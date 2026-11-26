// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/klog.rs

//! Tier 1 tests for the kernel log: `SYS_KERNEL_LOG_READ` (75) and
//! `SYS_KERNEL_LOG_BIND` (76), the records an attached reader gets, the
//! notification the kernel signals on an append, and the fallback to direct
//! lines when the reader stalls (core/kernel/docs/kernel-log.md).
//!
//! ktest is the log's attached reader (`crate::klog`). A test reads the
//! records it caused from a sequence number it took before, which leaves
//! ktest's own acknowledgement as it is, so the drain before ktest's next line
//! still writes them to the console. A line on demand comes from a child
//! thread that stores to an unmapped address with no fault handler bound: the
//! kernel prints the fault's lines (`fault unhandled`, `USERSPACE FAULT` and a
//! line holding the faulting address) and kills it.

use syscall_abi::{
    EXIT_FAULT_BASE, KLOG_READ_MAX, KLOG_RECORD_MAX, KLOG_STALL_MS, RIGHTS_NTF_WAIT, SyscallError,
};

use crate::{ChildStack, Line, TestContext, TestResult};

/// The first of the unmapped user VAs the faulting child stores to, one page
/// per test so each fault's lines name their own address. Canonical in every
/// paging mode (below the 2^38 Sv39 user half), in the region
/// `integration::fault_kills_thread` leaves unmapped.
const FAULT_BASE: u64 = 0x3E_0010_0000;

/// Poll bound for the faulting child's exit, as in
/// `integration::fault_kills_thread`.
const MAX_POLLS: u32 = 2000;

/// How long a test waits for a bound notification, in milliseconds: far past
/// the two timer ticks the signal takes.
const SIGNAL_WAIT_MS: u64 = 2000;

/// A wait of several timer ticks, in milliseconds.
const TICKS_MS: u64 = 100;

/// A kernel-half address no user span may reach.
const KERNEL_VA: u64 = 0xFFFF_FFFF_FFFF_F000;

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// The buffer the tests read records into, reached only by the main thread.
static mut READ_BUF: [u8; 2048] = [0; 2048];

/// ktest's `KernelLog` cap. Phase 7 mints it into init on both architectures,
/// so its absence is a failure, not a skip.
fn klog_cap(ctx: &TestContext) -> Result<u64, &'static str>
{
    match ctx.kernel_log_cap
    {
        0 => Err("klog: no KernelLog descriptor in InitInfo"),
        cap => Ok(cap),
    }
}

/// Run a child that stores to `va`, unmapped, with no fault handler bound,
/// and wait until the kernel has killed it, its fault lines printed.
fn fault_at(ctx: &TestContext, va: u64) -> TestResult
{
    let mut child = crate::spawn::new_child(ctx).map_err(|_| "klog: spawn::new_child failed")?;
    // SAFETY: `CHILD_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(CHILD_STACK)) };
    // SAFETY: the stack is `CHILD_STACK`, this module's own `ChildStack`, on
    // which no other live thread runs: each child exits before the next starts.
    let started = unsafe { crate::spawn::configure_and_start(&child, fault_child, stack_top, va) };
    let reason = started
        .and_then(|()| crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS)));
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if reason? != EXIT_FAULT_BASE + crate::arch::PAGE_FAULT_STORE_VECTOR
    {
        return Err("klog: the faulting child exited for another reason than its fault");
    }
    Ok(())
}

/// Child entry: store to the unmapped `va`, a fault that kills the thread.
extern "C" fn fault_child(va: u64) -> !
{
    // SAFETY: deliberately faulting: `va` is unmapped, so the store raises a
    // page fault the kernel resolves by terminating this thread.
    unsafe { (va as *mut u64).write_volatile(0x6B6C_6F67) };
    loop
    {
        core::hint::spin_loop();
    }
}

/// The faulting address as the kernel's fault lines print it.
fn address_text(va: u64) -> Line
{
    let mut line = Line::new();
    // `Line` cuts rather than fails, so the write cannot fail.
    let _ = core::fmt::Write::write_fmt(&mut line, format_args!("{va:#018x}"));
    line
}

/// Whether a record from sequence number `from` on holds `needle`. Reads
/// acknowledge only what ktest has already written.
fn recorded(cap: u64, from: u64, needle: &str) -> Result<bool, &'static str>
{
    // SAFETY: only the main thread runs the tests, one at a time, and no other
    // code reaches READ_BUF.
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(READ_BUF) };
    let mut next = from.max(1);
    for _ in 0..256
    {
        let n = syscall::kernel_log_read(cap, next, crate::klog::written(), buf)
            .map_err(|_| "klog: a read through the KernelLog cap failed")?;
        if n == 0
        {
            return Ok(false);
        }
        for rec in syscall_abi::kernel_log_records(buf.get(..n).unwrap_or_default())
        {
            if rec
                .text
                .windows(needle.len())
                .any(|w| w == needle.as_bytes())
            {
                return Ok(true);
            }
            next = rec.seq.saturating_add(1);
        }
    }
    Err("klog: the log did not end within 256 reads")
}

/// The sequence number after the last record ktest has written, all the log
/// holds written first.
fn next_seq() -> u64
{
    crate::klog::drain();
    crate::klog::written().saturating_add(1)
}

/// `SYS_KERNEL_LOG_READ` refuses a handle naming no capability or another
/// type's with `InvalidCapability`, a derived `KernelLog` cap without `Read`
/// with `InsufficientRights`, a length outside its bounds with
/// `InvalidArgument` before the buffer is looked at, and a null or
/// kernel-half buffer with `InvalidAddress`; a zero length only acknowledges.
pub fn read_refusals(ctx: &TestContext) -> TestResult
{
    let cap = klog_cap(ctx)?;
    let ack = crate::klog::written();
    // SAFETY: each call below is refused before the kernel writes, or has a
    // zero length; nothing is written through the pointers.
    let read = |c: u64, buf: u64, len: usize| unsafe {
        syscall::kernel_log_read_raw(c, 0, ack, buf as *mut u8, len)
    };
    let err = |e: SyscallError| Err(e as i64);

    if read(0, 0, 0) != err(SyscallError::InvalidCapability)
    {
        return Err("kernel_log_read: a null handle was not InvalidCapability");
    }
    if read(ctx.sched_control_cap, 0, 0) != err(SyscallError::InvalidCapability)
    {
        return Err("kernel_log_read: a SchedControl cap was not InvalidCapability");
    }
    let weak = syscall::cap_derive(cap, 0).map_err(|_| "kernel_log_read: cap_derive failed")?;
    let weak_result = read(weak, 0, 0);
    syscall::cap_delete(weak).ok();
    if weak_result != err(SyscallError::InsufficientRights)
    {
        return Err("kernel_log_read: a cap without Read was not InsufficientRights");
    }
    if read(cap, 0, KLOG_RECORD_MAX - 1) != err(SyscallError::InvalidArgument)
    {
        return Err("kernel_log_read: a length below one record was not InvalidArgument");
    }
    if read(cap, 0, KLOG_READ_MAX + 1) != err(SyscallError::InvalidArgument)
    {
        return Err("kernel_log_read: a length past KLOG_READ_MAX was not InvalidArgument");
    }
    if read(cap, 0, KLOG_RECORD_MAX) != err(SyscallError::InvalidAddress)
    {
        return Err("kernel_log_read: a null buffer was not InvalidAddress");
    }
    if read(cap, KERNEL_VA, KLOG_RECORD_MAX) != err(SyscallError::InvalidAddress)
    {
        return Err("kernel_log_read: a kernel-half buffer was not InvalidAddress");
    }
    if read(cap, 0, 0) != Ok(0)
    {
        return Err("kernel_log_read: an acknowledgement alone did not return 0");
    }
    Ok(())
}

/// `SYS_KERNEL_LOG_BIND` refuses a handle naming no `KernelLog` cap, one
/// without `Read`, a second handle naming no Notification or one without
/// `Notify`, and zero bits; a zero Notification handle unbinds.
pub fn bind_refusals(ctx: &TestContext) -> TestResult
{
    let cap = klog_cap(ctx)?;
    let ntf = syscall::cap_create_notification(ctx.memory_base)
        .map_err(|_| "kernel_log_bind: cap_create_notification failed")?;
    let result = bind_refusals_with(ctx, cap, ntf);
    syscall::kernel_log_bind(cap, 0, 0).ok();
    syscall::cap_delete(ntf).ok();
    result
}

fn bind_refusals_with(ctx: &TestContext, cap: u64, ntf: u64) -> TestResult
{
    let err = |e: SyscallError| Err(e as i64);
    if syscall::kernel_log_bind(0, ntf, 1) != err(SyscallError::InvalidCapability)
    {
        return Err("kernel_log_bind: a null handle was not InvalidCapability");
    }
    let weak = syscall::cap_derive(cap, 0).map_err(|_| "kernel_log_bind: cap_derive failed")?;
    let weak_result = syscall::kernel_log_bind(weak, ntf, 1);
    syscall::cap_delete(weak).ok();
    if weak_result != err(SyscallError::InsufficientRights)
    {
        return Err("kernel_log_bind: a KernelLog cap without Read was not InsufficientRights");
    }
    if syscall::kernel_log_bind(cap, ctx.sched_control_cap, 1)
        != err(SyscallError::InvalidCapability)
    {
        return Err(
            "kernel_log_bind: a SchedControl cap as the Notification was not InvalidCapability",
        );
    }
    let wait_only = syscall::cap_derive(ntf, RIGHTS_NTF_WAIT)
        .map_err(|_| "kernel_log_bind: cap_derive of the Notification failed")?;
    let wait_result = syscall::kernel_log_bind(cap, wait_only, 1);
    syscall::cap_delete(wait_only).ok();
    if wait_result != err(SyscallError::InsufficientRights)
    {
        return Err("kernel_log_bind: a Notification without Notify was not InsufficientRights");
    }
    if syscall::kernel_log_bind(cap, ntf, 0) != err(SyscallError::InvalidArgument)
    {
        return Err("kernel_log_bind: zero bits were not InvalidArgument");
    }
    if syscall::kernel_log_bind(cap, 0, 0).is_err()
    {
        return Err("kernel_log_bind: an unbind failed");
    }
    Ok(())
}

/// While ktest is attached, the kernel's lines for a userspace fault are
/// records, not console output: a read from before the fault finds them.
pub fn fault_lines_are_records(ctx: &TestContext) -> TestResult
{
    let cap = klog_cap(ctx)?;
    let va = FAULT_BASE;
    let from = next_seq();
    fault_at(ctx, va)?;
    if !recorded(cap, from, "USERSPACE FAULT")?
    {
        return Err("klog: no USERSPACE FAULT record followed the fault");
    }
    if !recorded(cap, from, address_text(va).as_str())?
    {
        return Err("klog: no record named the faulting address");
    }
    Ok(())
}

/// Clear the bits pending on `ntf` after a few ticks, so a signal a test
/// waits for is one of its own append.
fn settle(ntf: u64)
{
    let _ = syscall::thread_sleep(TICKS_MS);
    let _ = syscall::notification_try_wait(ntf);
}

/// The kernel signals the bound notification with the bound bits after an
/// append, from a timer tick.
pub fn bound_notification_signalled(ctx: &TestContext) -> TestResult
{
    let cap = klog_cap(ctx)?;
    let ntf = syscall::cap_create_notification(ctx.memory_base)
        .map_err(|_| "klog: cap_create_notification failed")?;
    let result = (|| {
        syscall::kernel_log_bind(cap, ntf, 0x4).map_err(|_| "klog: the bind failed")?;
        settle(ntf);
        fault_at(ctx, FAULT_BASE + 0x1000)?;
        let bits = syscall::notification_wait_timeout(ntf, SIGNAL_WAIT_MS)
            .map_err(|_| "klog: the wait on the bound Notification failed")?;
        if bits & 0x4 == 0
        {
            return Err("klog: the bound Notification was not signalled after an append");
        }
        Ok(())
    })();
    syscall::kernel_log_bind(cap, 0, 0).ok();
    syscall::cap_delete(ntf).ok();
    result
}

/// A bind replaces the one before it, and deleting the bound Notification
/// ends the binding: neither the replaced Notification nor one allocated
/// after the deletion is signalled by a later append.
pub fn bind_replaced_and_cleared(ctx: &TestContext) -> TestResult
{
    let cap = klog_cap(ctx)?;
    let mut ntfs = [0u64; 3];
    for n in &mut ntfs
    {
        *n = syscall::cap_create_notification(ctx.memory_base)
            .map_err(|_| "klog: cap_create_notification failed")?;
    }
    let [a, b, fresh] = ntfs;
    let result = (|| {
        syscall::kernel_log_bind(cap, a, 0x1).map_err(|_| "klog: the bind of A failed")?;
        syscall::kernel_log_bind(cap, b, 0x2).map_err(|_| "klog: the bind of B failed")?;
        settle(a);
        settle(b);
        fault_at(ctx, FAULT_BASE + 0x2000)?;
        let bits = syscall::notification_wait_timeout(b, SIGNAL_WAIT_MS)
            .map_err(|_| "klog: the wait on B failed")?;
        if bits & 0x2 == 0
        {
            return Err("klog: the Notification bound last was not signalled");
        }
        let _ = syscall::thread_sleep(TICKS_MS);
        if syscall::notification_try_wait(a) != Err(SyscallError::WouldBlock as i64)
        {
            return Err("klog: the replaced binding was still signalled");
        }
        syscall::cap_delete(b).map_err(|_| "klog: deleting B failed")?;
        // The fresh Notification is never bound; its object can take the
        // freed one's place.
        syscall::cap_delete(fresh).ok();
        let fresh = syscall::cap_create_notification(ctx.memory_base)
            .map_err(|_| "klog: cap_create_notification after the delete failed")?;
        fault_at(ctx, FAULT_BASE + 0x3000)?;
        let _ = syscall::thread_sleep(TICKS_MS);
        let stray = syscall::notification_try_wait(fresh);
        syscall::cap_delete(fresh).ok();
        if stray != Err(SyscallError::WouldBlock as i64)
        {
            return Err(
                "klog: a Notification allocated after the bound one's deletion was signalled",
            );
        }
        Ok(())
    })();
    syscall::kernel_log_bind(cap, 0, 0).ok();
    // Deleting a handle already deleted inside is refused, harmlessly.
    for n in ntfs
    {
        syscall::cap_delete(n).ok();
    }
    result
}

/// A reader that leaves records unread past `KLOG_STALL_MS` is detached: a
/// line after that reaches the console directly and is not a record. The
/// next read attaches the reader again.
pub fn stalled_reader_falls_back(ctx: &TestContext) -> TestResult
{
    let cap = klog_cap(ctx)?;
    let from = next_seq();
    // No read from here: the first fault's lines are records ktest leaves
    // unread past the bound, measured from their append, so a tick detaches
    // it before the second fault.
    fault_at(ctx, FAULT_BASE + 0x4000)?;
    let _ = syscall::thread_sleep(KLOG_STALL_MS + 300);
    let direct = FAULT_BASE + 0x5000;
    fault_at(ctx, direct)?;
    if recorded(cap, from, address_text(direct).as_str())?
    {
        return Err("klog: a line after the reader stalled was a record, not a direct line");
    }
    // The read above attached ktest again: a fault now is a record.
    let from = next_seq();
    let again = FAULT_BASE + 0x6000;
    fault_at(ctx, again)?;
    if !recorded(cap, from, address_text(again).as_str())?
    {
        return Err("klog: a read after the stall did not attach the reader again");
    }
    Ok(())
}
