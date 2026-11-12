// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/irq_shared_line.rs

//! Integration: several capabilities to one interrupt line, each its own
//! binding.
//!
//! A copy or derivation of an Interrupt capability is a fresh object with a
//! binding of its own, so receivers sharing a wired line each bind, are each
//! signalled, and each acknowledge; the line is unmasked only once none owes an
//! acknowledgement (core/kernel/docs/syscalls.md § `SYS_IRQ_REGISTER` and
//! § `SYS_IRQ_ACK`).
//!
//! The stand-in device is the UART ktest already owns: setting its
//! transmit-empty interrupt enable while the holding register is empty raises
//! its line (`crate::arch::serial::raise_tx_interrupt`), and clearing it lowers
//! the line again before every acknowledgement. Two derivations A and B of the
//! carved line bind notifications N1 and N2, and then:
//!
//! 1. one raise signals both;
//! 2. after A alone acknowledges, the line stays masked: a raise signals
//!    neither, and an acknowledgement through a third derivation that never
//!    registered changes nothing;
//! 3. after B acknowledges, a raise signals both again;
//! 4. with A owing and B acknowledged, deleting A unmasks the line, and a raise
//!    signals N2 alone;
//! 5. rebinding B to N3 keeps one binding: one acknowledgement unmasks the
//!    line, a raise signals N3 alone, and it does so again after the next.
//!
//! A raise can signal a notification twice. The step 2 raise, made while the
//! line is masked, is latched at the controller as pending (QEMU's APLIC and
//! I/O APIC both latch an edge on a disabled source), and B's acknowledgement
//! in step 3 forwards it at once; step 3's own raise can then reach the
//! controller after the target CPU took that interrupt and before its
//! delivery masked the line, so it is forwarded too and delivered after the
//! first, to the same bindings (core/kernel/docs/syscalls.md
//! § `SYS_IRQ_REGISTER`, Deliver). Steps 4 and 5 latch and race the same way.
//! The extra bit can land after the wait that expected the first took it, so
//! the notification a step expects quiet is emptied once its binding is gone
//! (N1 after A's deletion, N2 after B's rebind): those removals wait out every
//! delivery in flight on the line, and any later delivery walks a line without
//! that binding, so a bit the notification takes after it is a defect. Step 1
//! has nothing latched before it, so its one raise is forwarded once, and
//! step 2's quiet check needs no emptying.
//!
//! Then 64 copies of the line, bound to one notification, fill the line's
//! `MAX_IRQ_BINDINGS` (64) bindings: one more copy's registration returns
//! `QuotaExceeded`, and succeeds once a binding goes. Deleting that
//! notification's only capability removes no binding, since each holds a
//! reference on it, so a further copy is still refused; once the 64 are
//! rebound to a fresh notification, which frees the first, and all
//! acknowledge, a raise signals the fresh one.
//!
//! Last, the line's mode (`IRQ_MODE_*` in `abi/syscall`): a first binding
//! records level-triggered, active-high; a second binding passing another mode
//! is refused, as is a rebind of the first, and binds nothing (with the first
//! acknowledged, a raise signals it alone); a second passing the same mode
//! binds, a raise signals both, and, the mode programming the line
//! level-triggered, with the line held asserted across both acknowledgements,
//! it signals both again at the unmask, which an edge-triggered line would not;
//! once both go, a new first binding records
//! edge-triggered again; a mode with a bit outside `IRQ_MODE_MASK` is refused.
//! Every mode used is active-high, the UART line's own polarity, so no binding
//! inverts the line.

use syscall::{
    IRQ_MODE_LEVEL, IRQ_MODE_MASK, RIGHTS_ALL, cap_create_notification, cap_delete, cap_derive,
    irq_ack, irq_register, notification_try_wait, notification_wait_timeout,
};
use syscall_abi::SyscallError;

use crate::arch::serial::{UART_IRQ, quiet_tx_interrupt, raise_tx_interrupt};
use crate::{TestContext, TestResult};

/// The kernel's `MAX_IRQ_BINDINGS`: bindings one line holds.
const MAX_IRQ_BINDINGS: usize = 64;
/// Wait for a delivery that must come, in ms, through [`crate::scaled_bound`].
const DELIVERY_TIMEOUT_MS: u64 = 1000;
/// Wait for a delivery that must not come, in ms.
const QUIET_WAIT_MS: u64 = 20;

/// Capability handles a scenario made, deleted when it ends.
struct Held
{
    handles: [u64; MAX_IRQ_BINDINGS + 4],
    len: usize,
}

impl Held
{
    const fn new() -> Self
    {
        Self {
            handles: [0; MAX_IRQ_BINDINGS + 4],
            len: 0,
        }
    }

    fn push(&mut self, handle: u64) -> u64
    {
        self.handles[self.len] = handle;
        self.len += 1;
        handle
    }

    /// Delete every held handle. A handle a scenario already deleted fails
    /// its generation check here and is skipped.
    fn release(&mut self)
    {
        for &handle in self.handles[..self.len].iter().rev()
        {
            cap_delete(handle).ok();
        }
        self.len = 0;
    }
}

pub fn run(ctx: &TestContext) -> TestResult
{
    if !crate::serial::is_ready()
    {
        return Err("integration::irq_shared_line: UART not initialised");
    }
    let line = crate::unit::hw::isolate_irq_id(ctx, UART_IRQ)
        .ok_or("integration::irq_shared_line: cannot carve the UART line")?;
    let mut held = Held::new();
    let shared = shared_line(ctx, line, &mut held);
    quiet_tx_interrupt();
    held.release();
    let bounded = shared.and_then(|()| binding_bound(ctx, line, &mut held));
    held.release();
    let moded = bounded.and_then(|()| line_mode(ctx, line, &mut held));
    quiet_tx_interrupt();
    held.release();
    cap_delete(line).ok();
    moded
}

/// The five steps of the module doc.
fn shared_line(ctx: &TestContext, line: u64, held: &mut Held) -> TestResult
{
    let a = held.push(derive(line)?);
    let b = held.push(derive(line)?);
    let unbound = held.push(derive(line)?);
    let n1 = held.push(notification(ctx)?);
    let n2 = held.push(notification(ctx)?);
    let n3 = held.push(notification(ctx)?);
    irq_register(a, n1, 0)
        .and_then(|()| irq_register(b, n2, 0))
        .map_err(|_| "integration::irq_shared_line: binding A or B refused")?;
    acknowledge(&[a, b])?;

    raise_expect(&[n1, n2], &[], "one raise did not signal both bindings")?;

    acknowledge(&[a, unbound])?;
    raise_expect(
        &[],
        &[n1, n2],
        "the line was unmasked before B's acknowledgement",
    )?;

    acknowledge(&[b])?;
    raise_expect(
        &[n1, n2],
        &[],
        "B's acknowledgement did not unmask the line",
    )?;

    acknowledge(&[b])?;
    cap_delete(a).map_err(|_| "integration::irq_shared_line: cap_delete(A) failed")?;
    empty(&[n1]);
    raise_expect(&[n2], &[n1], "deleting the owing A did not leave B served")?;

    irq_register(b, n3, 0).map_err(|_| "integration::irq_shared_line: rebinding B refused")?;
    empty(&[n2]);
    acknowledge(&[b])?;
    raise_expect(&[n3], &[n1, n2], "a rebind left more than one binding")?;
    acknowledge(&[b])?;
    raise_expect(&[n3], &[n2], "the rebound B was not served again")
}

/// The line's binding bound: [`MAX_IRQ_BINDINGS`] bindings fit, one more is
/// refused, and a freed binding makes room; then deleting the capability of
/// the one notification every binding names leaves every binding in place,
/// and once they are rebound to a fresh notification and acknowledged, the
/// line delivers to it. Every binding is a copy's, so the scenario's release
/// leaves the line unbound for the next.
fn binding_bound(ctx: &TestContext, line: u64, held: &mut Held) -> TestResult
{
    let ntf = held.push(notification(ctx)?);
    let mut bound = [0; MAX_IRQ_BINDINGS];
    for slot in &mut bound
    {
        *slot = held.push(derive(line)?);
        irq_register(*slot, ntf, 0)
            .map_err(|_| "integration::irq_shared_line: a binding under the bound was refused")?;
    }
    let extra = held.push(derive(line)?);
    if irq_register(extra, ntf, 0) != Err(SyscallError::QuotaExceeded as i64)
    {
        return Err("integration::irq_shared_line: a binding past the bound was not refused");
    }
    cap_delete(bound[1]).map_err(|_| "integration::irq_shared_line: cap_delete(copy) failed")?;
    irq_register(extra, ntf, 0)
        .map_err(|_| "integration::irq_shared_line: a freed binding did not make room")?;
    bound[1] = extra;

    // The bindings hold the notification: deleting its only capability
    // removes none of them, so the line is still full.
    cap_delete(ntf).map_err(|_| "integration::irq_shared_line: cap_delete(notification) failed")?;
    let fresh = held.push(notification(ctx)?);
    let probe = held.push(derive(line)?);
    if irq_register(probe, fresh, 0) != Err(SyscallError::QuotaExceeded as i64)
    {
        return Err(
            "integration::irq_shared_line: deleting the notification's capability removed a binding",
        );
    }
    // Each rebind gives up its reference on the old notification, and the last
    // frees it. Every binding has owed since it was taken and a rebind keeps
    // the debt, so the line is unmasked only once all 64 acknowledge.
    bound
        .iter()
        .try_for_each(|&cap| irq_register(cap, fresh, 0))
        .map_err(|_| "integration::irq_shared_line: rebinding the full line failed")?;
    acknowledge(&bound)?;
    raise_expect(
        &[fresh],
        &[],
        "the bindings rebound from a deleted notification were not served",
    )
}

/// The line's mode: the last scenario of the module doc. Runs once no binding
/// remains on the line, so its first registration records the mode.
fn line_mode(ctx: &TestContext, line: u64, held: &mut Held) -> TestResult
{
    let a = held.push(derive(line)?);
    let b = held.push(derive(line)?);
    let n1 = held.push(notification(ctx)?);
    let n2 = held.push(notification(ctx)?);
    irq_register(a, n1, IRQ_MODE_LEVEL)
        .map_err(|_| "integration::irq_shared_line: a level first binding was refused")?;
    if irq_register(b, n2, 0) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("integration::irq_shared_line: a binding of another mode was not refused");
    }
    if irq_register(a, n2, 0) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("integration::irq_shared_line: a rebind to another mode was not refused");
    }
    // The refusals bound nothing: with A acknowledged, a raise signals N1
    // alone, where a B bound by a refused call would owe an acknowledgement
    // and hold the line masked.
    acknowledge(&[a])?;
    raise_expect(&[n1], &[n2], "a refused registration bound the line")?;
    irq_register(b, n2, IRQ_MODE_LEVEL)
        .map_err(|_| "integration::irq_shared_line: a binding of the line's mode was refused")?;
    // A raise signals both. The mode programs the line level-triggered (the
    // x86-64 I/O APIC entry, the riscv64 APLIC source, which the unmask pends
    // again while it is asserted), so the assertion, held across both
    // acknowledgements, is delivered again at the unmask; an edge-triggered
    // line raises no new edge for it.
    acknowledge(&[a, b])?;
    raise_tx_interrupt();
    let redelivered = expect_signalled(&[n1, n2], &[], "a level line did not signal both bindings")
        .and_then(|()| {
            acknowledge(&[a, b])?;
            expect_signalled(
                &[n1, n2],
                &[],
                "a level line did not deliver an assertion held at the unmask",
            )
        });
    quiet_tx_interrupt();
    redelivered?;
    cap_delete(a).map_err(|_| "integration::irq_shared_line: cap_delete(A) failed")?;
    cap_delete(b).map_err(|_| "integration::irq_shared_line: cap_delete(B) failed")?;

    // The last binding's removal released the line, so a new first binding may
    // record another mode.
    let c = held.push(derive(line)?);
    irq_register(c, n1, 0).map_err(
        |_| "integration::irq_shared_line: a released line kept the mode of its last bindings",
    )?;
    cap_delete(c).map_err(|_| "integration::irq_shared_line: cap_delete(C) failed")?;
    let d = held.push(derive(line)?);
    if irq_register(d, n1, IRQ_MODE_MASK + 1) != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("integration::irq_shared_line: a mode with an unknown bit was not refused");
    }
    Ok(())
}

fn derive(line: u64) -> Result<u64, &'static str>
{
    cap_derive(line, RIGHTS_ALL).map_err(|_| "integration::irq_shared_line: cap_derive failed")
}

fn notification(ctx: &TestContext) -> Result<u64, &'static str>
{
    cap_create_notification(ctx.memory_base)
        .map_err(|_| "integration::irq_shared_line: cap_create_notification failed")
}

fn acknowledge(caps: &[u64]) -> TestResult
{
    caps.iter()
        .try_for_each(|&cap| irq_ack(cap))
        .map_err(|_| "integration::irq_shared_line: irq_ack failed")
}

/// Take the bits a notification holds, so that a quiet check after it sees
/// only what is delivered from here on (module doc on the double delivery).
fn empty(notifications: &[u64])
{
    for &ntf in notifications
    {
        notification_try_wait(ntf).ok();
    }
}

/// Raise the line once and require every notification in `signalled` to see
/// bit 0 and none in `quiet` to see anything, then lower the line.
fn raise_expect(signalled: &[u64], quiet: &[u64], failure: &'static str) -> TestResult
{
    raise_tx_interrupt();
    let result = expect_signalled(signalled, quiet, failure);
    quiet_tx_interrupt();
    result
}

/// Require every notification in `signalled` to see bit 0 and none in `quiet`
/// to see anything, leaving the line as it is.
fn expect_signalled(signalled: &[u64], quiet: &[u64], failure: &'static str) -> TestResult
{
    let mut result = Ok(());
    for &ntf in signalled
    {
        match notification_wait_timeout(ntf, crate::scaled_bound(DELIVERY_TIMEOUT_MS))
        {
            Ok(bits) if bits & 1 != 0 =>
            {}
            _ => result = Err(failure),
        }
    }
    for &ntf in quiet
    {
        if notification_wait_timeout(ntf, QUIET_WAIT_MS) != Ok(0)
        {
            result = Err(failure);
        }
    }
    result
}
