// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/arch/x86_64/ioport_switch.rs

//! Integration (x86-64): a thread's I/O port permissions follow the thread
//! across CPUs and context switches.
//!
//! A thread with no port binding runs with the TSS I/O-bitmap offset out of
//! limit, so every port access raises `#GP`; a bound thread's bitmap is copied
//! into a CPU's TSS only when that CPU's TSS does not already hold it at the
//! bitmap's generation, which every bind and withdrawal advances. Two phases
//! check what userspace sees of that, on ports 0x4D1 (the 8259 ELCR for IRQs
//! 8-15, which reads without side effect) and 0x4D2 (bound, never accessed):
//!
//! 1. `remote_bind_switch_and_withdraw`: a bind made while the thread runs on
//!    another CPU, the thread switched out and back, and a withdrawal made
//!    while it is switched out.
//! 2. `threads_after_a_bound_one`: on a CPU whose TSS holds a bound thread's
//!    bitmap, a thread without a binding and a thread with a different binding
//!    each die of `#GP` on the first thread's port.

use core::sync::atomic::{AtomicU64, Ordering};

use syscall::{
    cap_copy, cap_create_notification, cap_delete, cap_derive, ioport_bind, notification_send,
    notification_wait, system_info,
};
use syscall_abi::{EXIT_FAULT_BASE, SystemInfoType};

use crate::spawn::{ArgBlock, SpawnedChild, child_args};
use crate::{ChildStack, TestContext, TestResult};

/// The port the children read: the 8259 ELCR for IRQs 8-15.
const PORT_P: u16 = 0x4D1;

/// The port bound to the third thread of phase 2, never accessed.
const PORT_Q: u16 = 0x4D2;

/// `#GP`, the vector a denied port access faults with.
const GP_VECTOR: u64 = 13;

/// Poll bound (about 1 ms per poll), scaled by [`crate::scaled_polls`].
const MAX_POLLS: u32 = 2000;

/// Set by the phase 2 child once it runs.
static SPINNING: AtomicU64 = AtomicU64::new(0);
/// Set by the parent to release the phase 2 child's spin.
static GO: AtomicU64 = AtomicU64::new(0);
/// Reads the phase 2 child completed.
static READS: AtomicU64 = AtomicU64::new(0);
/// Set by the phase 2 child A once its read succeeded.
static A_READ: AtomicU64 = AtomicU64::new(0);
/// Set by a child just before its notification wait.
static PARKING: AtomicU64 = AtomicU64::new(0);

static mut STACK_A: ChildStack = ChildStack::ZERO;
static mut STACK_B: ChildStack = ChildStack::ZERO;

/// The notification slot of a child, in its own `CSpace`.
#[derive(Clone, Copy)]
struct Args
{
    note: u64,
}

static ARGS: ArgBlock<Args, 2> = ArgBlock::new(Args { note: 0 });

/// Caps deleted when the guard drops, each slot skipped while zero.
struct Caps([u64; 5]);

impl Caps
{
    /// Delete the cap in slot `i` now and clear it.
    fn drop_at(&mut self, i: usize)
    {
        if let Some(cap) = self.0.get_mut(i)
            && *cap != 0
        {
            cap_delete(*cap).ok();
            *cap = 0;
        }
    }

    /// Hold `cap` in slot `i`, deleted when the guard drops.
    fn hold(&mut self, i: usize, cap: u64)
    {
        if let Some(slot) = self.0.get_mut(i)
        {
            *slot = cap;
        }
    }
}

impl Drop for Caps
{
    fn drop(&mut self)
    {
        for i in 0..self.0.len()
        {
            self.drop_at(i);
        }
    }
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let Some(p) = super::ioport::carve_port_range(PORT_P, 1)
    else
    {
        crate::log("ktest: integration::ioport_switch SKIP (cannot carve ports 0x4D1-0x4D2)");
        return Ok(());
    };
    let Some(q) = super::ioport::carve_port_range(PORT_Q, 1)
    else
    {
        cap_delete(p).ok();
        crate::log("ktest: integration::ioport_switch SKIP (cannot carve ports 0x4D1-0x4D2)");
        return Ok(());
    };
    let result =
        remote_bind_switch_and_withdraw(ctx, p).and_then(|()| threads_after_a_bound_one(ctx, p, q));
    cap_delete(p).ok();
    cap_delete(q).ok();
    result
}

/// Start `child` on CPU 1 when there is one, else unpinned.
fn start(
    child: &SpawnedChild,
    entry: extern "C" fn(u64) -> !,
    stack: *const ChildStack,
    arg: u64,
) -> TestResult
{
    // SAFETY: `stack` is one of this test's own statics, reached only through
    // `addr_of!`.
    let top = unsafe { ChildStack::top(stack) };
    let cpus = system_info(SystemInfoType::CpuCount as u64).unwrap_or(1);
    let started = if cpus >= 2
    {
        // SAFETY: the stack is this test's own `ChildStack`, on which no other
        // live thread runs (`ChildStack`'s rule).
        unsafe { crate::spawn::configure_and_start_pinned(child, entry, top, arg, 1) }
    }
    else
    {
        // SAFETY: as above.
        unsafe { crate::spawn::configure_and_start(child, entry, top, arg) }
    };
    started.map_err(|_| "integration::ioport_switch: starting a child failed")
}

/// Poll until `flag` is nonzero, failing with `why` after the bound.
fn wait_flag(flag: &AtomicU64, why: &'static str) -> TestResult
{
    let polls = crate::scaled_polls(MAX_POLLS);
    let mut waited = 0u32;
    while flag.load(Ordering::Acquire) == 0
    {
        waited = waited.saturating_add(1);
        if waited >= polls
        {
            return Err(why);
        }
        syscall::thread_sleep(1).ok();
    }
    Ok(())
}

/// Poll until `READS` reaches `n`.
fn wait_reads(n: u64, why: &'static str) -> TestResult
{
    let polls = crate::scaled_polls(MAX_POLLS);
    let mut waited = 0u32;
    while READS.load(Ordering::Acquire) < n
    {
        waited = waited.saturating_add(1);
        if waited >= polls
        {
            return Err(why);
        }
        syscall::thread_sleep(1).ok();
    }
    Ok(())
}

/// Wait until the child that set `PARKING` is blocked in its notification
/// wait. The thread-state query reports no Blocked state, so this waits for
/// the child's announcement and then a settling interval, long enough for the
/// wait syscall to commit. A wake that still beat the park is latched by the
/// notification, so the settling only strengthens what the cell exercises.
fn wait_parked() -> TestResult
{
    wait_flag(
        &PARKING,
        "integration::ioport_switch: a child never reached its wait",
    )?;
    syscall::thread_sleep(u64::from(crate::scaled_polls(20))).ok();
    Ok(())
}

/// A child whose `CSpace` pool also funds the port-binding table a bind takes
/// from it (`IOPORT_BINDING_TABLE_PAGES`) after the caps this cell copies in:
/// [`crate::spawn::new_child`]'s four pages hold the copies but not the table
/// as well.
fn new_bindable_child(ctx: &TestContext) -> Result<SpawnedChild, &'static str>
{
    let pages = 4 + syscall_abi::IOPORT_BINDING_TABLE_PAGES;
    let cs = syscall::cap_create_cspace(ctx.memory_base, 0, pages)
        .map_err(|_| "integration::ioport_switch: cap_create_cspace failed")?;
    let Ok(th) = syscall::cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, 0, 0)
    else
    {
        cap_delete(cs).ok();
        return Err("integration::ioport_switch: cap_create_thread failed");
    };
    Ok(SpawnedChild { th, cs })
}

/// A notification and its child-side copy.
fn make_note(
    ctx: &TestContext,
    child: &SpawnedChild,
    caps: &mut Caps,
    i: usize,
) -> Result<(u64, u64), &'static str>
{
    let n = cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::ioport_switch: cap_create_notification failed")?;
    caps.hold(i, n);
    let theirs = cap_copy(n, child.cs, syscall_abi::RIGHTS_NTF_WAIT)
        .map_err(|_| "integration::ioport_switch: cap_copy(notification) failed")?;
    Ok((n, theirs))
}

fn exit_is_gp(child: &mut SpawnedChild, why: &'static str) -> TestResult
{
    let reason = crate::spawn::wait_until_exited(child.th, crate::scaled_polls(MAX_POLLS))?;
    child.delete_thread().ok();
    child.delete_cspace().ok();
    if reason != EXIT_FAULT_BASE + GP_VECTOR
    {
        return Err(why);
    }
    Ok(())
}

/// Defect caught: a bind made to a running thread on another CPU not taking
/// effect before its next port access, a binding lost across a context switch
/// (a stale or missing bitmap copy on the switch back), or a withdrawal made
/// while the thread is switched out not reaching the next switch-in (the CPU's
/// TSS taken as current at a stale generation).
fn remote_bind_switch_and_withdraw(ctx: &TestContext, p: u64) -> TestResult
{
    let mut caps = Caps([0; 5]);
    let g = cap_derive(p, syscall::RIGHTS_ALL)
        .map_err(|_| "integration::ioport_switch: cap_derive(grant) failed")?;
    caps.0[0] = g;
    let mut child = new_bindable_child(ctx)?;
    let (n, theirs) = make_note(ctx, &child, &mut caps, 1)?;
    SPINNING.store(0, Ordering::Relaxed);
    GO.store(0, Ordering::Relaxed);
    READS.store(0, Ordering::Relaxed);
    PARKING.store(0, Ordering::Relaxed);
    // SAFETY: the child is not started yet.
    let arg = unsafe { ARGS.publish(0, Args { note: theirs }) };
    start(&child, spinner, core::ptr::addr_of!(STACK_A), arg)?;
    wait_flag(
        &SPINNING,
        "integration::ioport_switch: the child never spun",
    )?;
    ioport_bind(child.th, g).map_err(|_| "integration::ioport_switch: ioport_bind failed")?;
    GO.store(1, Ordering::Release);
    wait_reads(
        1,
        "integration::ioport_switch: the read after the remote bind never happened",
    )?;
    wait_parked()?;
    PARKING.store(0, Ordering::Relaxed);
    notification_send(n, 1).map_err(|_| "integration::ioport_switch: notification_send failed")?;
    wait_reads(
        2,
        "integration::ioport_switch: the read after the switch back never happened",
    )?;
    wait_parked()?;
    caps.drop_at(0);
    notification_send(n, 1).map_err(|_| "integration::ioport_switch: notification_send failed")?;
    exit_is_gp(
        &mut child,
        "integration::ioport_switch: the child did not die of #GP after the withdrawal",
    )?;
    if READS.load(Ordering::Acquire) != 2
    {
        return Err("integration::ioport_switch: the child read after the withdrawal");
    }
    Ok(())
}

/// A, bound to [`PORT_P`], reads it on CPU 1 and parks there, so that CPU's
/// TSS holds A's bitmap (the switch to idle loads nothing); then an unbound
/// thread C and a thread B bound only to [`PORT_Q`] each read [`PORT_P`] on the
/// same CPU and must die of `#GP`.
///
/// Defects caught: a thread without bindings left permitted by an earlier
/// thread's bitmap (the TSS bitmap offset not taken out of limit for it), and a
/// CPU's copy of one thread's bitmap taken as another thread's (the copy
/// skipped for a thread with a different binding).
fn threads_after_a_bound_one(ctx: &TestContext, p: u64, q: u64) -> TestResult
{
    let mut caps = Caps([0; 5]);
    let a_grant = cap_derive(p, syscall::RIGHTS_ALL)
        .map_err(|_| "integration::ioport_switch: cap_derive(A grant) failed")?;
    caps.0[0] = a_grant;
    let b_grant = cap_derive(q, syscall::RIGHTS_ALL)
        .map_err(|_| "integration::ioport_switch: cap_derive(B grant) failed")?;
    caps.0[1] = b_grant;
    let mut a = new_bindable_child(ctx)?;
    let mut b = new_bindable_child(ctx)?;
    let (_n, theirs) = make_note(ctx, &a, &mut caps, 2)?;
    ioport_bind(a.th, a_grant).map_err(|_| "integration::ioport_switch: ioport_bind(A) failed")?;
    ioport_bind(b.th, b_grant).map_err(|_| "integration::ioport_switch: ioport_bind(B) failed")?;
    A_READ.store(0, Ordering::Relaxed);
    PARKING.store(0, Ordering::Relaxed);
    // SAFETY: the child is not started yet.
    let arg = unsafe { ARGS.publish(1, Args { note: theirs }) };
    start(&a, parker, core::ptr::addr_of!(STACK_A), arg)?;
    wait_flag(&A_READ, "integration::ioport_switch: A never read the port")?;
    wait_parked()?;
    let mut unbound = crate::spawn::new_child(ctx)?;
    start(&unbound, reader_once, core::ptr::addr_of!(STACK_B), 0)?;
    exit_is_gp(
        &mut unbound,
        "integration::ioport_switch: an unbound thread did not die of #GP on A's port",
    )?;
    start(&b, reader_once, core::ptr::addr_of!(STACK_B), 0)?;
    exit_is_gp(
        &mut b,
        "integration::ioport_switch: B did not die of #GP on A's port",
    )?;
    a.delete_thread().ok();
    a.delete_cspace().ok();
    Ok(())
}

/// Child entry: read [`PORT_P`] once.
extern "C" fn reader_once(_arg: u64) -> !
{
    // SAFETY: the read either is permitted by the parent's binding or raises
    // the #GP the test expects, which kills this thread.
    let _ = unsafe { inb(PORT_P) };
    syscall::thread_exit()
}

/// Phase 1 child: spin until released, read, then read again after each of
/// two notification waits; the third read is expected to fault.
extern "C" fn spinner(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the parent published for this child.
    let Args { note } = unsafe { child_args(arg) };
    SPINNING.store(1, Ordering::Release);
    while GO.load(Ordering::Acquire) == 0
    {
        core::hint::spin_loop();
    }
    loop
    {
        // SAFETY: the parent bound PORT_P to this thread before releasing
        // it; the read after the withdrawal raises #GP and kills the thread.
        let _ = unsafe { inb(PORT_P) };
        READS.fetch_add(1, Ordering::Release);
        PARKING.store(1, Ordering::Release);
        notification_wait(note).ok();
        PARKING.store(0, Ordering::Release);
    }
}

/// Phase 2 child A: read once, then block forever.
extern "C" fn parker(arg: u64) -> !
{
    // SAFETY: `arg` is the entry the parent published for this child.
    let Args { note } = unsafe { child_args(arg) };
    // SAFETY: the parent bound PORT_P to this thread before starting it.
    let _ = unsafe { inb(PORT_P) };
    A_READ.store(1, Ordering::Release);
    PARKING.store(1, Ordering::Release);
    loop
    {
        notification_wait(note).ok();
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
