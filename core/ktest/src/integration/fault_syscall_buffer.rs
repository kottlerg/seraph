// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/fault_syscall_buffer.rs

//! Integration: a kernel copy into or out of an unbacked syscall buffer faults
//! to the caller's fault handler, and the syscall re-executes when the handler
//! resumes it (docs/fault-handling.md § Kernel Copies).
//!
//! A child bound to the harness as its fault handler makes one restartable
//! call per case on a scratch buffer. The harness checks the fault message
//! against the call: the kind, the buffer's first unmapped byte, the copy's
//! direction, the present bit where the architecture reports it, and, as the
//! instruction pointer, the address the fault-blocked child's own frame holds.
//! It then answers as the case says:
//!
//!   - **Resume, copy to the buffer.** `SYS_GETRANDOM` on an unmapped page,
//!     then on a span straddling a mapped and an unmapped page (the fault names
//!     the second page), and `SYS_THREAD_READ_REGS` on an unmapped page: the
//!     harness backs the page and resumes, and the re-executed call succeeds.
//!   - **Resume, copy from the buffer.** `SYS_THREAD_WRITE_REGS` on a stopped
//!     helper from an unmapped page: the harness backs it with the helper's own
//!     registers and resumes.
//!   - **Decline.** `SYS_GETRANDOM` on an unmapped page, then on a read-only one
//!     (a present page, which x86-64 reports): the harness declines, the call
//!     fails with `InvalidAddress`, and the child lives to report it.
//!   - **Redirect.** The harness rewrites the child's instruction pointer to a
//!     landing function and declines, or resumes without backing the page:
//!     either way the child continues at the landing, not after or at the
//!     syscall.
//!
//! The harness waits on a wait set holding both the endpoint and the child's
//! report notification, so a kernel that fails the copy instead of delivering
//! the fault (the child reports first) fails the case rather than hanging it.

use core::sync::atomic::{AtomicU64, Ordering};

use ipc::IpcMessage;
use syscall::{
    MAP_READ, cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, mem_map,
    mem_unmap, notification_send, notification_wait, notification_wait_timeout, thread_exit,
    thread_read_regs, thread_stop, wait_set_add, wait_set_create, wait_set_wait,
};
use syscall_abi::{
    FAULT_ACCESS_PRESENT, FAULT_ACCESS_READ, FAULT_ACCESS_WRITE, FAULT_KIND_VM, FAULT_LABEL,
    FAULT_REPLY_KILL, FAULT_REPLY_RESUME, MAP_WRITABLE, PAGE_SIZE, RIGHTS_ALL, SyscallError,
};

use crate::{ChildStack, TestContext, TestResult};

/// Scratch pages (crate docs § Scratch VAs) the cases' buffers lie on, two
/// pages per case, distinct from other tests' VAs.
const CASE_VA_BASE: u64 = 0x3E_4800_0000;

/// Badge bound with the handler and delivered in the fault message.
const FAULT_BADGE: u64 = 0xC0FF_EE05;

/// Bytes the `SYS_GETRANDOM` cases ask for.
const RANDOM_LEN: usize = 32;

/// Bytes of a register frame, the register syscalls' buffer length.
// cast_possible_truncation: the frame is a few hundred bytes.
#[allow(clippy::cast_possible_truncation)]
const FRAME_BYTES: usize = crate::arch::TRAP_FRAME_BYTES as usize;

/// Bytes of a page, for zeroing a mapped one.
// cast_possible_truncation: a page is 4 KiB.
#[allow(clippy::cast_possible_truncation)]
const PAGE_BYTES: usize = PAGE_SIZE as usize;

/// Wait-set badges of the endpoint and the report notification.
const WS_FAULT: u64 = 1;
const WS_REPORT: u64 = 2;

/// The child's report bits: its call returned what the case expects (or, for
/// a redirect, the landing ran), or anything else.
const BIT_OK: u64 = 1 << 0;
const BIT_BAD: u64 = 1 << 1;

/// Bound on the child's report after the reply. Applied through
/// [`crate::scaled_bound`], which stretches it past [`crate::UNSCALED_CPUS`]
/// CPUs, where the child's CPU waits for a host core.
const REPORT_MS: u64 = 1000;

/// The child's report notification, as a handle in its own `CSpace`, for the
/// landing a redirect sends it to, which receives no arguments it can trust.
static LANDING_DONE: AtomicU64 = AtomicU64::new(0);

/// What the child calls.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Call
{
    /// `SYS_GETRANDOM` of `len` bytes at the buffer.
    Getrandom,
    /// `SYS_THREAD_READ_REGS` of the stopped helper into the buffer.
    ReadRegs,
    /// `SYS_THREAD_WRITE_REGS` of the stopped helper from the buffer.
    WriteRegs,
}

/// How the harness answers the fault.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Answer
{
    /// Back the faulting page (for `WriteRegs`, with the helper's registers)
    /// and resume: the call re-executes and succeeds.
    Resume,
    /// Decline: the call fails with `InvalidAddress`.
    Decline,
    /// Point the child at [`landing`] and decline: the call's failure lands
    /// there, not past the syscall.
    RedirectDecline,
    /// Point the child at [`landing`] and resume, the page left unbacked: the
    /// child runs the landing, not the syscall again.
    RedirectResume,
}

/// One case.
#[derive(Clone, Copy)]
struct Spec
{
    name: &'static str,
    call: Call,
    answer: Answer,
    /// Offset of the buffer from the case's first page.
    offset: u64,
    /// Bytes the call copies.
    len: usize,
    /// How the case maps its first page before the call: `None` leaves it
    /// unmapped, so the fault names it; otherwise the flags it maps with, and
    /// the fault names the second page when the first is writable.
    premap: Option<u64>,
}

const CASES: [Spec; 8] = [
    Spec {
        name: "fault_syscall_buffer: getrandom resumed",
        call: Call::Getrandom,
        answer: Answer::Resume,
        offset: 0,
        len: RANDOM_LEN,
        premap: None,
    },
    Spec {
        name: "fault_syscall_buffer: getrandom straddling a mapped page, resumed",
        call: Call::Getrandom,
        answer: Answer::Resume,
        offset: PAGE_SIZE - (RANDOM_LEN as u64) / 2,
        len: RANDOM_LEN,
        premap: Some(MAP_WRITABLE),
    },
    Spec {
        name: "fault_syscall_buffer: read_regs resumed",
        call: Call::ReadRegs,
        answer: Answer::Resume,
        offset: 0,
        len: FRAME_BYTES,
        premap: None,
    },
    Spec {
        name: "fault_syscall_buffer: write_regs resumed",
        call: Call::WriteRegs,
        answer: Answer::Resume,
        offset: 0,
        len: FRAME_BYTES,
        premap: None,
    },
    Spec {
        name: "fault_syscall_buffer: getrandom declined",
        call: Call::Getrandom,
        answer: Answer::Decline,
        offset: 0,
        len: RANDOM_LEN,
        premap: None,
    },
    Spec {
        name: "fault_syscall_buffer: getrandom into a read-only page, declined",
        call: Call::Getrandom,
        answer: Answer::Decline,
        offset: 0,
        len: RANDOM_LEN,
        premap: Some(MAP_READ),
    },
    Spec {
        name: "fault_syscall_buffer: getrandom redirected and declined",
        call: Call::Getrandom,
        answer: Answer::RedirectDecline,
        offset: 0,
        len: RANDOM_LEN,
        premap: None,
    },
    Spec {
        name: "fault_syscall_buffer: getrandom redirected and resumed",
        call: Call::Getrandom,
        answer: Answer::RedirectResume,
        offset: 0,
        len: RANDOM_LEN,
        premap: None,
    },
];

/// The child's arguments, by address.
#[derive(Clone, Copy)]
struct CallerArgs
{
    call: Call,
    /// Whether the call is to succeed (a resumed case) or fail with
    /// `InvalidAddress` (a declined one); a redirected call reports `BAD` if
    /// it returns at all.
    succeed: bool,
    redirected: bool,
    buf: u64,
    len: usize,
    done: u64,
    helper: u64,
}

static CALLER_ARGS: crate::spawn::ArgBlock<CallerArgs, 1> =
    crate::spawn::ArgBlock::new(CallerArgs {
        call: Call::Getrandom,
        succeed: false,
        redirected: false,
        buf: 0,
        len: 0,
        done: 0,
        helper: 0,
    });

// The child of each case, and its helper; each case deletes both before the
// next starts.
static mut CALLER_STACK: ChildStack = ChildStack::ZERO;
static mut HELPER_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    for (i, spec) in CASES.iter().enumerate()
    {
        let page = CASE_VA_BASE + 2 * PAGE_SIZE * i as u64;
        run_case(ctx, spec, page).inspect_err(|_| crate::log(spec.name))?;
    }
    Ok(())
}

/// The caps, children and mapped pool frames one case holds, released on
/// drop: the children first (a caller's Thread teardown releases its fault
/// binding's reference on the endpoint, and no thread then reaches a page),
/// then the frames, then the caps.
struct Case
{
    aspace: u64,
    /// The handler endpoint, the child's report notification, and the wait
    /// set over both; 0 holds none.
    ep: u64,
    done: u64,
    ws: u64,
    caller: Option<crate::spawn::SpawnedChild>,
    helper: Option<crate::spawn::SpawnedChild>,
    frames: [Option<(u64, u64)>; 2],
}

impl Drop for Case
{
    fn drop(&mut self)
    {
        drop(self.caller.take());
        drop(self.helper.take());
        for (va, mem) in self.frames.iter_mut().filter_map(Option::take)
        {
            // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs) this case
            // mapped, and no thread of the case is left to reach it.
            if unsafe { mem_unmap(self.aspace, va, 1) }.is_ok()
            {
                // SAFETY: mem is from the pool and no longer mapped.
                unsafe { crate::frame_pool::free(mem) };
            }
        }
        for cap in [self.ws, self.done, self.ep]
        {
            if cap != 0
            {
                cap_delete(cap).ok();
            }
        }
    }
}

impl Case
{
    /// Create the endpoint, the report notification, and the wait set over
    /// both.
    fn new(ctx: &TestContext) -> Result<Self, &'static str>
    {
        let mut case = Case {
            aspace: ctx.aspace_cap,
            ep: 0,
            done: 0,
            ws: 0,
            caller: None,
            helper: None,
            frames: [None, None],
        };
        case.ep = cap_create_endpoint(ctx.memory_base)
            .map_err(|_| "fault_syscall_buffer: cap_create_endpoint failed")?;
        case.done = cap_create_notification(ctx.memory_base)
            .map_err(|_| "fault_syscall_buffer: cap_create_notification failed")?;
        case.ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
            .map_err(|_| "fault_syscall_buffer: wait_set_create failed")?;
        wait_set_add(case.ws, case.ep, WS_FAULT)
            .and_then(|()| wait_set_add(case.ws, case.done, WS_REPORT))
            .map_err(|_| "fault_syscall_buffer: wait_set_add failed")?;
        Ok(case)
    }

    /// Map a pool frame at `va` with `flags`, holding it for the drop. A
    /// writable page is zeroed, since pool frames are reused unscrubbed and
    /// [`landed`] reads a call's writes against zeroes.
    fn map(&mut self, slot: usize, va: u64, flags: u64) -> Result<u64, &'static str>
    {
        let mem =
            crate::frame_pool::alloc().ok_or("fault_syscall_buffer: frame_pool::alloc failed")?;
        // SAFETY: `va` is a scratch VA (crate docs § Scratch VAs), so the page
        // holds no Rust object or IPC page of ktest.
        if unsafe { mem_map(mem, self.aspace, va, 0, 1, flags) }.is_err()
        {
            // SAFETY: mem is from the pool and was never mapped.
            unsafe { crate::frame_pool::free(mem) };
            return Err("fault_syscall_buffer: mem_map failed");
        }
        self.frames[slot] = Some((va, mem));
        if flags & MAP_WRITABLE != 0
        {
            // SAFETY: the page at `va` is mapped writable just above and holds
            // no Rust object; no other thread touches it during the write: the
            // case's child is not yet started (a premap) or is fault-blocked
            // until the reply (a Resume).
            unsafe { core::ptr::write_bytes(va as *mut u8, 0, PAGE_BYTES) };
        }
        Ok(mem)
    }
}

/// Run one case on the two pages from `page`: start the child bound to the
/// harness as its fault handler, take the fault of its call's copy, answer it
/// as the case says, and check the child's report.
fn run_case(ctx: &TestContext, spec: &Spec, page: u64) -> TestResult
{
    let mut case = Case::new(ctx)?;
    let (ep, done, ws) = (case.ep, case.done, case.ws);

    // The first unmapped byte the copy reaches, which the fault must name.
    let fault_va = match spec.premap
    {
        Some(flags) =>
        {
            case.map(0, page, flags)?;
            if flags & MAP_WRITABLE != 0
            {
                page + PAGE_SIZE
            }
            else
            {
                page
            }
        }
        None => page + spec.offset,
    };

    let helper = if spec.call == Call::Getrandom
    {
        None
    }
    else
    {
        let helper = case.helper.insert(start_helper(ctx)?);
        thread_stop(helper.th).map_err(|_| "fault_syscall_buffer: stop the helper failed")?;
        Some(helper.th)
    };

    let caller = case.caller.insert(
        crate::spawn::new_child(ctx).map_err(|_| "fault_syscall_buffer: new_child failed")?,
    );
    let c_done = cap_copy(done, caller.cs, RIGHTS_ALL)
        .map_err(|_| "fault_syscall_buffer: cap_copy(done) failed")?;
    let c_helper = match helper
    {
        Some(th) => cap_copy(th, caller.cs, RIGHTS_ALL)
            .map_err(|_| "fault_syscall_buffer: cap_copy(helper) failed")?,
        None => 0,
    };
    crate::bind_fault_handler(caller.th, ep, FAULT_BADGE)
        .map_err(|_| "fault_syscall_buffer: thread_set_fault_handler failed")?;
    LANDING_DONE.store(c_done, Ordering::Release);
    // SAFETY: no caller is live: each case deletes its caller before the next
    // publishes.
    let arg = unsafe {
        CALLER_ARGS.publish(
            0,
            CallerArgs {
                call: spec.call,
                succeed: spec.answer == Answer::Resume,
                redirected: matches!(
                    spec.answer,
                    Answer::RedirectDecline | Answer::RedirectResume
                ),
                buf: page + spec.offset,
                len: spec.len,
                done: c_done,
                helper: c_helper,
            },
        )
    };
    let stack_top = ChildStack::top(core::ptr::addr_of!(CALLER_STACK));
    // SAFETY: the stack is `CALLER_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(caller, caller_entry, stack_top, arg) }
        .map_err(|_| "fault_syscall_buffer: configure_and_start failed")?;
    let caller_th = caller.th;

    let fired = wait_set_wait(ws).map_err(|_| "fault_syscall_buffer: wait_set_wait failed")?;
    if fired != WS_FAULT
    {
        return Err(
            "fault_syscall_buffer: the call returned without its copy's fault reaching \
                    the handler",
        );
    }
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let msg = unsafe { ipc::ipc_recv(ep, ctx.ipc_buf) }
        .map_err(|_| "fault_syscall_buffer: ipc_recv failed")?;
    let mut regs = [0u8; FRAME_BYTES];
    thread_read_regs(caller_th, &mut regs)
        .map_err(|_| "fault_syscall_buffer: read the fault-blocked child failed")?;
    check_fault(&msg, spec, fault_va, &regs)?;
    answer_fault(ctx, &mut case, spec, fault_va, helper, caller_th, &mut regs)?;

    let bits = notification_wait_timeout(done, crate::scaled_bound(REPORT_MS))
        .map_err(|_| "fault_syscall_buffer: waiting for the report failed")?;
    match bits
    {
        0 => Err("fault_syscall_buffer: the child did not report after the reply"),
        BIT_OK => Ok(()),
        _ => Err("fault_syscall_buffer: the child's call did not end as the reply requires"),
    }
}

/// The instruction pointer `regs`, a register file, holds.
fn frame_ip(regs: &[u8]) -> u64
{
    let mut word = [0u8; 8];
    word.copy_from_slice(&regs[crate::arch::IP_OFFSET..crate::arch::IP_OFFSET + 8]);
    u64::from_le_bytes(word)
}

/// Check that `msg` is the kernel's fault message for the copy of `spec` at
/// `fault_va`, raised from the instruction the fault-blocked child's frame
/// `regs` names.
fn check_fault(msg: &IpcMessage, spec: &Spec, fault_va: u64, regs: &[u8]) -> TestResult
{
    if msg.label != FAULT_LABEL || msg.badge != FAULT_BADGE
    {
        return Err("fault_syscall_buffer: the message is not the child's fault");
    }
    if msg.word(0) != FAULT_KIND_VM || msg.word(1) != fault_va
    {
        return Err(
            "fault_syscall_buffer: the fault does not name the buffer's first unmapped \
                    byte",
        );
    }
    let access = if spec.call == Call::WriteRegs
    {
        FAULT_ACCESS_READ
    }
    else
    {
        FAULT_ACCESS_WRITE
    };
    if msg.word(2) & (FAULT_ACCESS_READ | FAULT_ACCESS_WRITE) != access
    {
        return Err("fault_syscall_buffer: the fault's access is not the copy's direction");
    }
    let present = spec.premap.is_some_and(|flags| flags & MAP_WRITABLE == 0);
    let want_present = present && crate::arch::FAULT_REPORTS_PRESENT;
    if (msg.word(2) & FAULT_ACCESS_PRESENT != 0) != want_present
    {
        return Err("fault_syscall_buffer: the fault's present bit is wrong for the page");
    }
    if msg.word(3) != frame_ip(regs)
    {
        return Err("fault_syscall_buffer: the fault's instruction pointer is not the frame's");
    }
    Ok(())
}

/// Answer the fault of `spec` at `fault_va` as the case says. `regs` is the
/// fault-blocked child's register file, which a redirect edits and writes
/// back.
fn answer_fault(
    ctx: &TestContext,
    case: &mut Case,
    spec: &Spec,
    fault_va: u64,
    helper: Option<u64>,
    caller: u64,
    regs: &mut [u8; FRAME_BYTES],
) -> TestResult
{
    let label = match spec.answer
    {
        Answer::Resume =>
        {
            case.map(1, fault_va & !(PAGE_SIZE - 1), MAP_WRITABLE)?;
            if let (Call::WriteRegs, Some(th)) = (spec.call, helper)
            {
                // SAFETY: the page at `fault_va` is mapped writable just above
                // and holds no Rust object; this slice is the only reference
                // to it and ends with the statement, before the child's
                // re-executed call reads the page.
                let page =
                    unsafe { core::slice::from_raw_parts_mut(fault_va as *mut u8, FRAME_BYTES) };
                thread_read_regs(th, page)
                    .map_err(|_| "fault_syscall_buffer: read the helper failed")?;
            }
            FAULT_REPLY_RESUME
        }
        Answer::Decline => FAULT_REPLY_KILL,
        Answer::RedirectDecline | Answer::RedirectResume =>
        {
            crate::spawn::redirect_to_entry(regs, landing as *const () as u64);
            // SAFETY: the frame resumes the fault-blocked child, bound to
            // ktest's address space, at `landing` on its own stack
            // (`redirect_to_entry`), code the child may run there.
            unsafe { syscall::thread_write_regs(caller, regs) }
                .map_err(|_| "fault_syscall_buffer: redirect the child failed")?;
            if spec.answer == Answer::RedirectDecline
            {
                FAULT_REPLY_KILL
            }
            else
            {
                FAULT_REPLY_RESUME
            }
        }
    };
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    unsafe { ipc::ipc_reply(&IpcMessage::new(label), ctx.ipc_buf) }
        .map_err(|_| "fault_syscall_buffer: ipc_reply failed")
}

/// Start the helper, a thread of ktest's address space that parks on a
/// notification nothing signals, for a register case to stop and copy.
fn start_helper(ctx: &TestContext) -> Result<crate::spawn::SpawnedChild, &'static str>
{
    let helper =
        crate::spawn::new_child(ctx).map_err(|_| "fault_syscall_buffer: new_child failed")?;
    let park = cap_create_notification(ctx.memory_base)
        .map_err(|_| "fault_syscall_buffer: cap_create_notification (park) failed")?;
    let c_park = cap_copy(park, helper.cs, RIGHTS_ALL);
    cap_delete(park).ok();
    let c_park = c_park.map_err(|_| "fault_syscall_buffer: cap_copy(park) failed")?;
    let stack_top = ChildStack::top(core::ptr::addr_of!(HELPER_STACK));
    // SAFETY: the stack is `HELPER_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(&helper, helper_entry, stack_top, c_park) }
        .map_err(|_| "fault_syscall_buffer: start the helper failed")?;
    Ok(helper)
}

/// The helper: park on `park` until the case deletes the thread.
extern "C" fn helper_entry(park: u64) -> !
{
    loop
    {
        notification_wait(park).ok();
    }
}

/// The child: make the call its case names and report whether it returned
/// what the case expects.
extern "C" fn caller_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the `CALLER_ARGS` entry `run_case` published.
    let a: CallerArgs = unsafe { crate::spawn::child_args(arg) };
    // A redirected call never returns here; if it does, the redirect failed.
    let returned_ok = match a.call
    {
        Call::Getrandom =>
        {
            // SAFETY: the span lies on the case's scratch pages, which no
            // Rust object occupies; the kernel writes it once the bound
            // handler backs it, or refuses.
            let r = unsafe { syscall::getrandom_raw(a.buf as *mut u8, a.len) };
            if a.succeed
            {
                r == Ok(a.len as u64) && landed(a.buf, a.len)
            }
            else
            {
                r == Err(SyscallError::InvalidAddress as i64)
            }
        }
        Call::ReadRegs =>
        {
            // SAFETY: as for `Getrandom`.
            let r = unsafe { syscall::thread_read_regs_raw(a.helper, a.buf as *mut u8, a.len) };
            r == Ok(FRAME_BYTES as u64)
        }
        Call::WriteRegs =>
        {
            // SAFETY: the span is a scratch page no Rust object occupies,
            // which the handler fills with the stopped helper's own frame
            // before resuming, so the helper is written back where it
            // stopped.
            let r = unsafe { syscall::thread_write_regs_raw(a.helper, a.buf as *const u8, a.len) };
            r.is_ok()
        }
    };
    let ok = returned_ok && !a.redirected;
    notification_send(a.done, if ok { BIT_OK } else { BIT_BAD }).ok();
    thread_exit()
}

/// Where a redirect sends the child: report success and exit. Reached only
/// through the instruction pointer the harness wrote.
extern "C" fn landing(_: u64) -> !
{
    notification_send(LANDING_DONE.load(Ordering::Acquire), BIT_OK).ok();
    thread_exit()
}

/// Whether the `len` bytes at `va` hold something other than the zeroes the
/// case wrote when it mapped the page (all zero has probability 2^-256 for 32
/// random bytes).
fn landed(va: u64, len: usize) -> bool
{
    (0..len).any(|i| {
        // SAFETY: the span is mapped (the call that wrote it returned), and
        // the read is volatile through a raw pointer.
        unsafe { ((va as *const u8).add(i)).read_volatile() != 0 }
    })
}
