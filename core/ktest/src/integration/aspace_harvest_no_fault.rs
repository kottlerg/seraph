// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/aspace_harvest_no_fault.rs

//! Integration: a touch of a page whose accessed bit `SYS_ASPACE_HARVEST`
//! cleared, and a kernel copy into one, deliver no fault and succeed; the next
//! harvest reports exactly the pages touched.
//!
//! A child thread of ktest's address space, bound to the harness as its fault
//! handler, registers the last of eight scratch pages as its IPC buffer and
//! parks on a notification. The harness, which never touches the pages,
//! harvests them (all eight read accessed, the unmapped page after them
//! clear) and releases the child. The child then:
//!
//!   - stores to pages 1 and 3 and loads from page 4;
//!   - calls `SYS_GETRANDOM` into page 5, a kernel copy into a page with A
//!     clear;
//!   - receives the harness's call, whose data words, more than travel in the
//!     message registers, the kernel writes into its IPC buffer on page 7,
//!     another such page, and checks them.
//!
//! On riscv64 under Svade each of those accesses to a page with A clear faults
//! into the kernel, which sets A and retries without delivering the fault to
//! the bound handler. The harness fails the cell on any fault message, any
//! failed call, and any harvest other than exactly pages 1, 3, 4, 5 and 7.
//!
//! The harness bounds its waits with [`crate::scaled_bound`]: a wait set over
//! the fault endpoint and the child's report notification, and an
//! `ipc_call_timeout`, so a kernel that wedges the child fails the cell
//! rather than hanging it.

use ipc::IpcMessage;
use syscall::{
    cap_copy, cap_create_endpoint, cap_create_notification, cap_delete, notification_send,
    notification_wait, notification_wait_timeout, thread_exit, wait_set_add, wait_set_create,
    wait_set_try_wait, wait_set_wait_timeout,
};
use syscall_abi::{MSG_REGS_DATA_MAX, PAGE_SIZE, RIGHTS_ALL};

use crate::{ChildStack, TestContext, TestResult};

/// Scratch VA (crate docs § Scratch VAs) of the cell's pages, distinct from
/// every other test's VA.
const VA: u64 = 0x1_9100_0000;

/// Pages the cell maps from [`VA`]; the page after them stays unmapped.
const PAGES: usize = 8;

/// The page the child registers as its IPC buffer.
const IPC_PAGE: usize = 7;

/// Badge bound with the fault handler.
const FAULT_BADGE: u64 = 0xC0FF_EE06;

/// Wait-set badges of the endpoint and the report notification.
const WS_FAULT: u64 = 1;
const WS_REPORT: u64 = 2;

/// The child's report bits: ready for the harness's harvest, and the final
/// outcome.
const BIT_OK: u64 = 1 << 0;
const BIT_BAD: u64 = 1 << 1;
const BIT_READY: u64 = 1 << 2;

/// Bound on each wait, through [`crate::scaled_bound`].
const WAIT_MS: u64 = 2000;

/// Bytes the child asks `SYS_GETRANDOM` for.
const RANDOM_LEN: usize = 32;

/// The data words the harness sends and the child checks:
/// `MSG_REGS_DATA_MAX + 1` of them, so the message travels in the IPC buffer.
const PATTERN: [u64; MSG_REGS_DATA_MAX + 1] = [
    0x1111_1111_1111_1111,
    0x2222_2222_2222_2222,
    0x3333_3333_3333_3333,
    0x4444_4444_4444_4444,
    0x5555_5555_5555_5555,
    0x6666_6666_6666_6666,
    0x7777_7777_7777_7777,
];

/// The child's arguments, by address.
#[derive(Clone, Copy)]
struct ChildArgs
{
    done: u64,
    go: u64,
    srv: u64,
}

static CHILD_ARGS: crate::spawn::ArgBlock<ChildArgs, 1> = crate::spawn::ArgBlock::new(ChildArgs {
    done: 0,
    go: 0,
    srv: 0,
});

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

/// The address of page `i`; `i` is at most [`PAGES`], so the sum stays in the
/// low scratch band.
fn page_va(i: usize) -> u64
{
    (i as u64).wrapping_mul(PAGE_SIZE).wrapping_add(VA)
}

/// What the cell holds, released on drop: the child first (no thread then
/// reaches a page), then the frames, then the caps.
struct Cell
{
    ep: u64,
    srv: u64,
    done: u64,
    go: u64,
    ws: u64,
    child: Option<crate::spawn::SpawnedChild>,
    frames: [Option<crate::frame_pool::FrameGuard>; PAGES],
}

impl Drop for Cell
{
    fn drop(&mut self)
    {
        drop(self.child.take());
        for frame in &mut self.frames
        {
            drop(frame.take());
        }
        for cap in [self.ws, self.go, self.done, self.srv, self.ep]
        {
            if cap != 0
            {
                cap_delete(cap).ok();
            }
        }
    }
}

/// Harvest the [`PAGES`] pages and the unmapped page after them.
fn harvest(ctx: &TestContext) -> Result<(u64, [u8; 2]), i64>
{
    const SPAN: u64 = PAGES as u64 + 1;
    let mut bitmap = [0u8; 2];
    let count = syscall::aspace_harvest(ctx.aspace_cap, VA, SPAN, &mut bitmap)?;
    Ok((count, bitmap))
}

pub fn run(ctx: &TestContext) -> TestResult
{
    let mut cell = Cell {
        ep: 0,
        srv: 0,
        done: 0,
        go: 0,
        ws: 0,
        child: None,
        frames: Default::default(),
    };
    setup(ctx, &mut cell)?;
    drive(ctx, cell.srv, cell.done, cell.go, cell.ws)
}

/// Map the pages, create the caps, and start the child, recording each in
/// `cell` as soon as it exists.
fn setup(ctx: &TestContext, cell: &mut Cell) -> TestResult
{
    for (i, slot) in cell.frames.iter_mut().enumerate()
    {
        let mut frame = crate::frame_pool::FrameGuard::new(ctx.aspace_cap)
            .ok_or("aspace_harvest_no_fault: frame pool exhausted")?;
        // SAFETY: the page is a scratch VA (crate docs § Scratch VAs), off
        // every Rust object and IPC page of ktest. The harness never reads or
        // writes it.
        unsafe { frame.map(page_va(i)) }.map_err(|_| "aspace_harvest_no_fault: mem_map failed")?;
        *slot = Some(frame);
    }

    cell.ep = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "aspace_harvest_no_fault: cap_create_endpoint (fault) failed")?;
    cell.srv = cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "aspace_harvest_no_fault: cap_create_endpoint (srv) failed")?;
    cell.done = cap_create_notification(ctx.memory_base)
        .map_err(|_| "aspace_harvest_no_fault: cap_create_notification (done) failed")?;
    cell.go = cap_create_notification(ctx.memory_base)
        .map_err(|_| "aspace_harvest_no_fault: cap_create_notification (go) failed")?;
    cell.ws = wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "aspace_harvest_no_fault: wait_set_create failed")?;
    wait_set_add(cell.ws, cell.ep, WS_FAULT)
        .and_then(|()| wait_set_add(cell.ws, cell.done, WS_REPORT))
        .map_err(|_| "aspace_harvest_no_fault: wait_set_add failed")?;
    let (ep, srv, done, go) = (cell.ep, cell.srv, cell.done, cell.go);

    let child = cell.child.insert(
        crate::spawn::new_child(ctx).map_err(|_| "aspace_harvest_no_fault: new_child failed")?,
    );
    crate::bind_fault_handler(child.th, ep, FAULT_BADGE)
        .map_err(|_| "aspace_harvest_no_fault: thread_set_fault_handler failed")?;
    let c_done = cap_copy(done, child.cs, RIGHTS_ALL)
        .map_err(|_| "aspace_harvest_no_fault: cap_copy(done) failed")?;
    let c_go = cap_copy(go, child.cs, RIGHTS_ALL)
        .map_err(|_| "aspace_harvest_no_fault: cap_copy(go) failed")?;
    let c_srv = cap_copy(srv, child.cs, RIGHTS_ALL)
        .map_err(|_| "aspace_harvest_no_fault: cap_copy(srv) failed")?;
    // SAFETY: no child is live: this cell starts the only one.
    let arg = unsafe {
        CHILD_ARGS.publish(
            0,
            ChildArgs {
                done: c_done,
                go: c_go,
                srv: c_srv,
            },
        )
    };
    // SAFETY: `CHILD_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(CHILD_STACK)) };
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    unsafe { crate::spawn::configure_and_start(child, child_entry, stack_top, arg) }
        .map_err(|_| "aspace_harvest_no_fault: configure_and_start failed")?;
    Ok(())
}

/// The harness's side: harvest, release the child, call it, and check the
/// reports and the second harvest.
fn drive(ctx: &TestContext, srv: u64, done: u64, go: u64, ws: u64) -> TestResult
{
    // The child is ready: it registered its IPC buffer and is parked on `go`.
    let bound = crate::scaled_bound(WAIT_MS);
    match wait_set_wait_timeout(ws, bound)
    {
        Ok(WS_REPORT) =>
        {}
        Ok(WS_FAULT) =>
        {
            return Err("aspace_harvest_no_fault: the child faulted before its touches");
        }
        _ => return Err("aspace_harvest_no_fault: the child did not report ready"),
    }
    if notification_wait_timeout(done, bound) != Ok(BIT_READY)
    {
        return Err("aspace_harvest_no_fault: the child's ready report is wrong");
    }
    if harvest(ctx) != Ok((PAGES as u64, [0xFF, 0x00]))
    {
        return Err("aspace_harvest_no_fault: the first harvest should report every page");
    }
    notification_send(go, 1).map_err(|_| "aspace_harvest_no_fault: notification_send failed")?;

    // The child's kernel write of these words lands on page 7, a page whose
    // accessed bit the harvest cleared.
    let msg = IpcMessage::builder(0x5EED).words(0, &PATTERN).build();
    // SAFETY: ctx.ipc_buf is the registered per-thread IPC buffer.
    let reply = unsafe {
        ipc::ipc_call_timeout(
            srv,
            &msg,
            ctx.ipc_buf,
            u32::try_from(bound).unwrap_or(u32::MAX),
        )
    };
    if reply.is_err()
    {
        return Err("aspace_harvest_no_fault: the call to the child failed or timed out");
    }
    match wait_set_wait_timeout(ws, bound)
    {
        Ok(WS_REPORT) =>
        {}
        Ok(WS_FAULT) => return Err("aspace_harvest_no_fault: a touch delivered a fault"),
        _ => return Err("aspace_harvest_no_fault: the child did not report its result"),
    }
    if notification_wait_timeout(done, bound) != Ok(BIT_OK)
    {
        return Err("aspace_harvest_no_fault: the child's calls or words were wrong");
    }
    if wait_set_try_wait(ws) == Ok(WS_FAULT)
    {
        return Err("aspace_harvest_no_fault: a fault message is pending");
    }

    if harvest(ctx) != Ok((5, [0b1011_1010, 0]))
    {
        return Err(
            "aspace_harvest_no_fault: the harvest should report exactly pages 1, 3, 4, 5, 7",
        );
    }
    Ok(())
}

/// Store to each page of `pages`, with no branch on a page's index, so no
/// access to another page is speculated.
fn store(pages: &[usize])
{
    for &page in pages
    {
        let ptr = page_va(page) as *mut u8;
        // SAFETY: the page is mapped writable by `run` and holds no Rust
        // object; any byte is valid there.
        unsafe { ptr.write_volatile(0x5A) };
    }
}

/// Load from each page of `pages`, as [`store`] does.
fn load(pages: &[usize])
{
    for &page in pages
    {
        let ptr = page_va(page) as *const u8;
        // SAFETY: as for `store`; the read is volatile through a raw pointer.
        let _ = unsafe { ptr.read_volatile() };
    }
}

/// Report `bits` on `done` and exit.
fn finish(done: u64, bits: u64) -> !
{
    notification_send(done, bits).ok();
    thread_exit()
}

/// The child: register page 7 as the IPC buffer, report ready, wait for the
/// harvest, touch pages, copy into a page, and receive the harness's call.
extern "C" fn child_entry(arg: u64) -> !
{
    // SAFETY: `arg` is the `CHILD_ARGS` entry `run` published.
    let a: ChildArgs = unsafe { crate::spawn::child_args(arg) };
    let buf = page_va(IPC_PAGE);
    // SAFETY: page 7 is a scratch page `run` mapped, holding no Rust object,
    // and dedicated to this thread as its IPC buffer.
    if unsafe { syscall::ipc_buffer_set(buf) }.is_err()
    {
        finish(a.done, BIT_BAD);
    }
    notification_send(a.done, BIT_READY).ok();
    if notification_wait(a.go).is_err()
    {
        finish(a.done, BIT_BAD);
    }

    store(&[1, 3]);
    load(&[4]);
    let random_dst = page_va(5).wrapping_add(64) as *mut u8;
    // SAFETY: the span lies on page 5, a mapped, writable scratch page that
    // holds no Rust object.
    let random = unsafe { syscall::getrandom_raw(random_dst, RANDOM_LEN) };
    let random_ok = random == Ok(RANDOM_LEN as u64);

    // SAFETY: `buf` is this thread's registered IPC buffer.
    let words_ok = match unsafe { ipc::ipc_recv(a.srv, buf as *mut u64) }
    {
        Ok(msg) =>
        {
            msg.word_count() == PATTERN.len()
                && PATTERN
                    .iter()
                    .enumerate()
                    .all(|(i, &word)| msg.word(i) == word)
        }
        Err(_) => false,
    };
    // SAFETY: `buf` is this thread's registered IPC buffer.
    let replied = unsafe { ipc::ipc_reply(&IpcMessage::new(0), buf as *mut u64) }.is_ok();
    finish(
        a.done,
        if random_ok && words_ok && replied
        {
            BIT_OK
        }
        else
        {
            BIT_BAD
        },
    )
}
