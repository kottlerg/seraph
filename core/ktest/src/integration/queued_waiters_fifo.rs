// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/queued_waiters_fifo.rs

//! Integration: threads waiting on one notification or event queue are woken
//! in arrival order, one per delivery.
//!
//! ruststd's lock primitives block every contender on one notification and
//! depend on each delivery waking one parked contender. For the notification
//! and for the event queue:
//!
//!   1. **FIFO** — A parks, then B; the first delivery must reach A while B
//!      stays parked, and the second must reach B.
//!   2. **Head expires** — A parks with a short timeout, then B untimed; after
//!      A's wait times out, a delivery must reach B. A run in which B may
//!      have queued only after A expired tests nothing and is run again, at
//!      most twice.
//!   3. **Tail expires** — A parks untimed, then B with a short timeout; after
//!      B's wait times out, a delivery must reach A.
//!
//! Every controller wait is bounded, so a wrong order fails instead of
//! hanging; teardown destroys the object first, interrupting any child still
//! parked. Runs on a single CPU (the children are timer-preempted peers).

use syscall::{
    RIGHTS_ALL, cap_copy, cap_create_notification, cap_delete, cap_revoke, event_post,
    event_queue_create, event_recv, event_recv_timeout, notification_send, notification_wait,
    notification_wait_timeout, system_info, thread_exit, thread_sleep,
};
use syscall_abi::{SyscallError, SystemInfoType};

use crate::{ChildStack, TestContext, TestResult, spawn};

/// Notification NOTIFY right — what a child needs to `notification_send`.
const RIGHTS_SIGNAL: u64 = syscall_abi::RIGHTS_NTF_NOTIFY;

/// Per-child `done` bits; child B's are child A's shifted by [`B_SHIFT`].
/// Raised just before the child parks.
const BIT_READY: u64 = 1 << 0;
/// Raised when the wait returned the result the child expects.
const BIT_OK: u64 = 1 << 1;
/// Raised on any other result.
const BIT_BAD: u64 = 1 << 2;
const BITS_RETURNED: u64 = BIT_OK | BIT_BAD;
const B_SHIFT: u32 = 3;

/// The two deliveries, in order.
const FIRST: u64 = 0x0A;
const SECOND: u64 = 0x0B;

/// Wall-clock settle after READY so a child has, in practice, reached its
/// park (a fixed sleep cannot prove it), and how long a parked child is given
/// to (wrongly) return.
const SETTLE_SLEEP_MS: u64 = 20;
/// A timed child's timeout; long enough for the other child to park behind
/// or ahead of it first ([`head_expires`] checks that it did). Applied, like
/// [`REPORT_MS`], through [`crate::scaled_bound`], which stretches it past
/// [`crate::UNSCALED_CPUS`] CPUs, where starting and settling a child takes
/// longer.
const EXPIRE_MS: u64 = 100;
/// Slack [`head_expires`] leaves before waiter A's earliest expiry: the
/// kernel rounds a deadline to its timer tick, so a wait can expire up to a
/// tick before the scaled `EXPIRE_MS` of `ElapsedUs` have passed.
const EXPIRE_SLACK_MS: u64 = 20;
/// Bound on each controller wait for a child's report.
const REPORT_MS: u64 = 1000;
/// Runs of a phase that ended [`INCONCLUSIVE`] before the last, whose
/// result stands.
const RETRIES: u32 = 2;

/// [`head_expires`]'s verdict when waiter B may have queued after waiter A
/// expired: the phase did not test what it exists to test, and is run again.
const INCONCLUSIVE: &str = "integration::queued_waiters_fifo: waiter B may have queued after \
                            waiter A expired (raise EXPIRE_MS)";

static mut CHILD_STACKS: [ChildStack; 2] = [ChildStack::ZERO; 2];

/// Which object a phase's children wait on.
#[derive(Clone, Copy)]
enum Kind
{
    Notification,
    EventQueue,
}

/// The phase's two children, in the order they park.
#[derive(Clone, Copy)]
enum Waiter
{
    A,
    B,
}

impl Waiter
{
    fn index(self) -> usize
    {
        match self
        {
            Waiter::A => 0,
            Waiter::B => 1,
        }
    }

    /// This child's copy of the `done` bits in `bits`.
    fn bits(self, bits: u64) -> u64
    {
        match self
        {
            Waiter::A => bits,
            Waiter::B => bits << B_SHIFT,
        }
    }

    fn pick(self, a: &'static str, b: &'static str) -> &'static str
    {
        match self
        {
            Waiter::A => a,
            Waiter::B => b,
        }
    }
}

/// The result a child's wait must return.
#[derive(Clone, Copy)]
enum Expect
{
    Delivery(u64),
    TimedOut,
}

/// A child's argument; `timeout_ms == 0` waits untimed.
#[derive(Clone, Copy)]
struct ChildArgs
{
    obj_cap: u32,
    done: u32,
    kind: Kind,
    waiter: Waiter,
    timeout_ms: u64,
    expect: Expect,
}

static CHILD_ARGS: spawn::ArgBlock<ChildArgs, 2> = spawn::ArgBlock::new(ChildArgs {
    obj_cap: 0,
    done: 0,
    kind: Kind::Notification,
    waiter: Waiter::A,
    timeout_ms: 0,
    expect: Expect::TimedOut,
});

type Script = fn(&mut Phase, &TestContext) -> TestResult;

pub fn run(ctx: &TestContext) -> TestResult
{
    let phases: [(Kind, Script, &str); 6] = [
        (Kind::Notification, fifo, "notification fifo"),
        (
            Kind::Notification,
            head_expires,
            "notification head expires",
        ),
        (
            Kind::Notification,
            tail_expires,
            "notification tail expires",
        ),
        (Kind::EventQueue, fifo, "event queue fifo"),
        (Kind::EventQueue, head_expires, "event queue head expires"),
        (Kind::EventQueue, tail_expires, "event queue tail expires"),
    ];
    for (kind, script, name) in phases
    {
        run_phase(ctx, kind, script).inspect_err(|_| {
            crate::log("ktest: integration::queued_waiters_fifo failing phase:");
            crate::log(name);
        })?;
    }
    Ok(())
}

/// Run `script` on a fresh object of `kind`, again on a fresh object up to
/// [`RETRIES`] times while it ends [`INCONCLUSIVE`].
fn run_phase(ctx: &TestContext, kind: Kind, script: Script) -> TestResult
{
    for _ in 0..RETRIES
    {
        match run_once(ctx, kind, script)
        {
            Err(e) if e == INCONCLUSIVE =>
            {}
            result => return result,
        }
    }
    run_once(ctx, kind, script)
}

/// Run `script` on a fresh object of `kind`, then tear the phase down
/// whatever the script returned.
fn run_once(ctx: &TestContext, kind: Kind, script: Script) -> TestResult
{
    let mut phase = Phase::new(ctx, kind)?;
    let result = script(&mut phase, ctx);
    let teardown = phase.teardown();
    result.and(teardown)
}

fn fifo(p: &mut Phase, ctx: &TestContext) -> TestResult
{
    p.start(ctx, Waiter::A, 0, Expect::Delivery(FIRST))?;
    p.start(ctx, Waiter::B, 0, Expect::Delivery(SECOND))?;
    p.deliver(FIRST)?;
    p.expect_returned(Waiter::A)?;
    p.expect_parked(Waiter::B)?;
    p.deliver(SECOND)?;
    p.expect_returned(Waiter::B)
}

fn head_expires(p: &mut Phase, ctx: &TestContext) -> TestResult
{
    // A enters its wait after this, so its deadline lies at least the scaled EXPIRE_MS
    // (less a tick) past it.
    let before_a = elapsed_us()?;
    p.start(
        ctx,
        Waiter::A,
        crate::scaled_bound(EXPIRE_MS),
        Expect::TimedOut,
    )?;
    p.start(ctx, Waiter::B, 0, Expect::Delivery(FIRST))?;
    // A must still be queued ahead of B, or its expiry leaves an empty queue.
    // B's start returns once B's settle has passed, by which time B has, in
    // practice, parked (`SETTLE_SLEEP_MS`); A cannot have expired before then
    // if that time lies short of A's earliest deadline. A start too slow for
    // that, or an expiry A already reported, leaves the order unknown.
    let b_settled_ms = elapsed_us()?.saturating_sub(before_a) / 1000;
    if p.returned(Waiter::A) || b_settled_ms + EXPIRE_SLACK_MS >= crate::scaled_bound(EXPIRE_MS)
    {
        return Err(INCONCLUSIVE);
    }
    p.expect_returned(Waiter::A)?;
    p.expect_parked(Waiter::B)?;
    p.deliver(FIRST)?;
    p.expect_returned(Waiter::B)
}

fn tail_expires(p: &mut Phase, ctx: &TestContext) -> TestResult
{
    p.start(ctx, Waiter::A, 0, Expect::Delivery(FIRST))?;
    p.start(
        ctx,
        Waiter::B,
        crate::scaled_bound(EXPIRE_MS),
        Expect::TimedOut,
    )?;
    p.expect_returned(Waiter::B)?;
    p.expect_parked(Waiter::A)?;
    p.deliver(FIRST)?;
    p.expect_returned(Waiter::A)
}

/// One phase's object, `done` notification, children, and the `done` bits
/// accumulated so far.
struct Phase
{
    kind: Kind,
    obj_cap: u32,
    done: u32,
    children: [Option<spawn::SpawnedChild>; 2],
    acc: u64,
}

impl Phase
{
    fn new(ctx: &TestContext, kind: Kind) -> Result<Self, &'static str>
    {
        let done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "integration::queued_waiters_fifo: create done failed")?;
        let obj_cap = match kind
        {
            Kind::Notification => cap_create_notification(ctx.memory_base),
            Kind::EventQueue => event_queue_create(ctx.memory_base, 4),
        };
        let Ok(obj_cap) = obj_cap
        else
        {
            let _ = cap_delete(done);
            return Err("integration::queued_waiters_fifo: create object failed");
        };
        Ok(Self {
            kind,
            obj_cap,
            done,
            children: [None, None],
            acc: 0,
        })
    }

    /// Start `waiter` waiting on a copy of the object, and return once it
    /// has reported READY and the settle has passed.
    fn start(
        &mut self,
        ctx: &TestContext,
        waiter: Waiter,
        timeout_ms: u64,
        expect: Expect,
    ) -> TestResult
    {
        let index = waiter.index();
        // Stored before anything can fail, so teardown reaps it.
        let child = self.children[index].insert(
            spawn::new_child(ctx)
                .map_err(|_| "integration::queued_waiters_fifo: spawn child failed")?,
        );
        let cs = child.cs;
        let c_obj = cap_copy(self.obj_cap, cs, RIGHTS_ALL)
            .map_err(|_| "integration::queued_waiters_fifo: cap_copy object failed")?;
        let c_done = cap_copy(self.done, cs, RIGHTS_SIGNAL)
            .map_err(|_| "integration::queued_waiters_fifo: cap_copy done failed")?;
        // SAFETY: entry `index` belongs to this child alone; phases run
        // sequentially and each phase's children are reaped before the next
        // phase publishes.
        let arg = unsafe {
            CHILD_ARGS.publish(
                index,
                ChildArgs {
                    obj_cap: c_obj,
                    done: c_done,
                    kind: self.kind,
                    waiter,
                    timeout_ms,
                    expect,
                },
            )
        };
        // SAFETY: stack `index` is this child's; reaped before the next phase.
        let stack = ChildStack::top(unsafe { core::ptr::addr_of!(CHILD_STACKS[index]) });
        // SAFETY: the stack is `CHILD_STACKS[index]`, this test's own `ChildStack`,
        // on which no other live thread runs (`ChildStack`'s rule).
        unsafe { spawn::configure_and_start(child, child_entry, stack, arg) }
            .map_err(|_| "integration::queued_waiters_fifo: start child failed")?;
        if !self.collect(waiter.bits(BIT_READY), crate::scaled_bound(REPORT_MS))?
        {
            return Err("integration::queued_waiters_fifo: a child never reported ready");
        }
        thread_sleep(SETTLE_SLEEP_MS)
            .map_err(|_| "integration::queued_waiters_fifo: settle sleep failed")
    }

    /// Deliver once: notification bits or an event payload.
    fn deliver(&self, value: u64) -> TestResult
    {
        match self.kind
        {
            Kind::Notification => notification_send(self.obj_cap, value),
            Kind::EventQueue => event_post(self.obj_cap, value),
        }
        .map_err(|_| "integration::queued_waiters_fifo: delivery failed")
    }

    /// Whether `waiter`'s wait has returned, from the bits collected so far.
    fn returned(&self, waiter: Waiter) -> bool
    {
        self.acc & waiter.bits(BITS_RETURNED) != 0
    }

    /// `waiter`'s wait must return, with the result it expects, within the
    /// report bound.
    fn expect_returned(&mut self, waiter: Waiter) -> TestResult
    {
        if !self.collect(waiter.bits(BITS_RETURNED), crate::scaled_bound(REPORT_MS))?
        {
            return Err(waiter.pick(
                "integration::queued_waiters_fifo: waiter A did not return in time",
                "integration::queued_waiters_fifo: waiter B did not return in time",
            ));
        }
        if self.acc & waiter.bits(BIT_BAD) != 0
        {
            return Err(waiter.pick(
                "integration::queued_waiters_fifo: waiter A's wait returned the wrong result",
                "integration::queued_waiters_fifo: waiter B's wait returned the wrong result",
            ));
        }
        Ok(())
    }

    /// `waiter` must still be parked after the settle.
    fn expect_parked(&mut self, waiter: Waiter) -> TestResult
    {
        if self.collect(waiter.bits(BITS_RETURNED), SETTLE_SLEEP_MS)?
        {
            return Err(waiter.pick(
                "integration::queued_waiters_fifo: waiter A returned on another's wake",
                "integration::queued_waiters_fifo: waiter B returned on another's wake",
            ));
        }
        Ok(())
    }

    /// Accumulate `done` bits until any bit of `mask` is present; `false`
    /// once a wait of `timeout_ms` passes with nothing new. Each child raises
    /// at most two reports, so the loop is bounded.
    fn collect(&mut self, mask: u64, timeout_ms: u64) -> Result<bool, &'static str>
    {
        while self.acc & mask == 0
        {
            let bits = notification_wait_timeout(self.done, timeout_ms).map_err(
                |_| "integration::queued_waiters_fifo: notification_wait_timeout failed",
            )?;
            if bits == 0
            {
                return Ok(false);
            }
            self.acc |= bits;
        }
        Ok(true)
    }

    fn teardown(self) -> TestResult
    {
        // Revoke deletes the children's copies (derivation children of
        // `obj_cap`); the delete then frees the object, interrupting any
        // child still parked on it.
        cap_revoke(self.obj_cap)
            .map_err(|_| "integration::queued_waiters_fifo: revoke object failed")?;
        cap_delete(self.obj_cap)
            .map_err(|_| "integration::queued_waiters_fifo: del object failed")?;
        for child in self.children.iter().flatten()
        {
            cap_delete(child.th)
                .map_err(|_| "integration::queued_waiters_fifo: reap child thread failed")?;
            cap_delete(child.cs)
                .map_err(|_| "integration::queued_waiters_fifo: reap child cspace failed")?;
        }
        cap_delete(self.done).map_err(|_| "integration::queued_waiters_fifo: del done failed")
    }
}

/// Microseconds since boot, the clock [`head_expires`] times waiter B's
/// start on.
fn elapsed_us() -> Result<u64, &'static str>
{
    system_info(SystemInfoType::ElapsedUs as u64)
        .map_err(|_| "integration::queued_waiters_fifo: system_info(ElapsedUs) failed")
}

/// Wait once on the object and report whether the result is the expected one.
extern "C" fn child_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the entry `Phase::start` published for this child.
    let ChildArgs {
        obj_cap,
        done,
        kind,
        waiter,
        timeout_ms,
        expect,
    } = unsafe { spawn::child_args(arg) };
    notification_send(done, waiter.bits(BIT_READY)).ok();
    let result = match (kind, timeout_ms)
    {
        (Kind::Notification, 0) => notification_wait(obj_cap),
        (Kind::Notification, ms) => notification_wait_timeout(obj_cap, ms),
        (Kind::EventQueue, 0) => event_recv(obj_cap),
        (Kind::EventQueue, ms) => event_recv_timeout(obj_cap, ms),
    };
    let ok = match (expect, kind, result)
    {
        (Expect::Delivery(value), _, Ok(got)) => got == value,
        (Expect::TimedOut, Kind::Notification, Ok(bits)) => bits == 0,
        (Expect::TimedOut, Kind::EventQueue, Err(e)) => e == SyscallError::WouldBlock as i64,
        _ => false,
    };
    let bit = if ok { BIT_OK } else { BIT_BAD };
    notification_send(done, waiter.bits(bit)).ok();
    thread_exit()
}
