// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/swapd/src/main.rs

//! The swap service: it holds the swap partition and moves memmgr's sealed
//! chunks between it and memmgr (services/swapd/docs/operation.md).
//!
//! swapd takes the partition from vfsd (`GET_SWAP_PARTITION`) and registers
//! its slots with memmgr (`SWAP_REGISTER`), with a SEND on the endpoint
//! svcmgr provides it, which outlives any one instance, and a Notification
//! memmgr sends on when a debugger's read wants a chunk on disk. Three threads
//! each own a buffer, a contiguous grant swapd never maps: memmgr writes a
//! slot's bytes into one and reads them out of another, and the block driver
//! moves them to and from the partition, so swapd sees no byte of them.
//!
//! * The main thread restores: it receives each fault memmgr redirects to the
//!   endpoint, reads the fault's slot, hands memmgr the bytes
//!   (`SWAP_RESTORE`), and resumes the fault or forwards it.
//! * The write-out thread, while memmgr's level reads `CRITICAL`, takes
//!   chunks (`SWAP_TAKE`), writes them to their slots, and ends each write
//!   (`SWAP_DONE`), so their store pages return to the free pool.
//! * The want thread restores the chunks a debugger's `MAKE_RESIDENT` asked
//!   for (`SWAP_WANTED`), ahead of any fault.
//!
//! The decisions are [`layout`]'s, host-tested. The recipe sets
//! `reserve = yes`: swapd acts to end a pressure episode.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use ipc::{IpcMessage, blk_labels, memmgr_errors, memmgr_labels, vfsd_errors, vfsd_labels};
use layout::{AfterFailedCall, AfterTake, Extent, FaultReply, Geometry, Probe, Transfer};
use std::os::seraph::thread::BuilderExt;
use syscall_abi::{
    FAULT_LABEL, FAULT_REDIRECT_WORD, FAULT_REPLY_FORWARD, FAULT_REPLY_RESUME, SyscallError,
};

/// Pages of a buffer: a slot, the most bytes a chunk on disk takes.
const BUF_PAGES: u64 = memmgr_labels::DEMAND_CHUNK_BYTES / syscall_abi::PAGE_SIZE;

/// The badge of the SEND swapd registers with memmgr, which memmgr's redirect
/// of a fault names, so the fault arrives with it. svcmgr's published SEND on
/// the endpoint carries another badge, and swapd serves no message without
/// this one.
const REDIRECT_BADGE: u64 = 1;

/// The bits memmgr sends on the want Notification.
const WANT_BITS: u64 = 1;

/// The level the write-out thread runs at: below the restore and want
/// threads (the recipe's `priority`), so a restore is not delayed behind a
/// write-out on swapd's side.
const WRITE_OUT_PRIORITY: u8 = 12;

/// Bytes of stack swapd touches at start: more than a request's frames take.
const STACK_TOUCH_BYTES: usize = 32 * 1024;

/// Bytes of heap swapd touches at start: what the runtime's first uses of
/// the heap after start can ask for. swapd allocates nothing after.
const HEAP_TOUCH_BYTES: usize = 16 * 1024;

/// What every thread shares: the swap authority on memmgr, the partition cap
/// on the block driver and its geometry, and whether the partition is lost.
struct Swap
{
    memmgr: u64,
    partition: u64,
    geometry: Geometry,
    lost: AtomicBool,
}

impl Swap
{
    /// Whether the partition is lost: the block driver fails every request
    /// (`DEVICE_FAULT`) or is gone, its cap revoked, so no slot is read or
    /// written again.
    fn lost(&self) -> bool
    {
        self.lost.load(Ordering::Acquire)
    }

    /// Mark the partition lost, logging it once.
    fn lose(&self)
    {
        if !self.lost.swap(true, Ordering::AcqRel)
        {
            std::os::seraph::log!(
                error: "swap partition lost: the block driver fails every request or is gone; \
                        faults on chunks on disk are forwarded, and nothing more is written"
            );
        }
    }
}

fn main()
{
    std::os::seraph::log::register_name(b"swapd");
    let info = std::os::seraph::startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();

    // The recipe's `provides` serves the endpoint's RECV in slot 0, then its
    // seeds: `vfsd.swap`, `memmgr.swap`.
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let (recv, vfsd, memmgr) =
        match unsafe { ipc::bootstrap::request_slots::<3>(info.creator_endpoint, ipc_buf) }
        {
            Ok([recv, vfsd, memmgr]) if recv != 0 && vfsd != 0 && memmgr != 0 =>
            {
                (recv, vfsd, memmgr)
            }
            _ =>
            {
                std::os::seraph::log!(error: "bootstrap caps missing; no swap to disk");
                std::process::exit(1);
            }
        };
    let partition = partition(vfsd, ipc_buf);
    let _ = syscall::cap_delete(vfsd);
    let geometry = geometry(partition, ipc_buf);
    let slots = geometry.slots();
    if slots == 0
    {
        std::os::seraph::log!(warn: "the swap partition holds no slot; swap stays in RAM");
        std::process::exit(0);
    }
    let restore_buf = buffer();
    let write_buf = buffer();
    let want_buf = buffer();
    let want = want_notification();
    touch_stack();
    touch_heap();
    let used = register(memmgr, recv, want, slots, ipc_buf);
    std::os::seraph::log!("swap partition: {slots} slots of 64 KiB, memmgr uses {used}");

    let swap = Arc::new(Swap {
        memmgr,
        partition,
        geometry,
        lost: AtomicBool::new(false),
    });
    let Some(pressure) = std::os::seraph::memory_pressure_notification()
    else
    {
        fail(format_args!("no memory-pressure registration"));
    };
    let writer = Arc::clone(&swap);
    std::thread::Builder::new()
        .name("swapd-write".into())
        .spawn_at_priority(WRITE_OUT_PRIORITY, move || {
            write_out(&writer, pressure, write_buf)
        })
        .unwrap_or_else(|e| fail(format_args!("write-out thread not started: {e}")));
    let wanter = Arc::clone(&swap);
    std::thread::Builder::new()
        .name("swapd-want".into())
        .spawn(move || serve_wants(&wanter, want, want_buf))
        .unwrap_or_else(|e| fail(format_args!("want thread not started: {e}")));
    serve_faults(&swap, recv, restore_buf, ipc_buf);
}

/// The swap partition's cap from vfsd. With no swap partition on any disk,
/// swapd exits cleanly, and svcmgr does not restart it: swap stays in RAM.
/// Any other failure ends swapd with a fault, so svcmgr restarts it within
/// its budget.
fn partition(vfsd: u64, ipc_buf: *mut u64) -> u64
{
    let msg = IpcMessage::builder(vfsd_labels::GET_SWAP_PARTITION)
        .word(0, u64::from(ipc::VFSD_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(vfsd, &msg, ipc_buf) }
        .unwrap_or_else(|e| fail(format_args!("GET_SWAP_PARTITION failed (err={e})")));
    match (reply.label, reply.caps().first())
    {
        (vfsd_errors::SUCCESS, Some(&cap)) => cap,
        (vfsd_errors::NO_MOUNT, _) =>
        {
            std::os::seraph::log!("no swap partition; swap stays in RAM");
            std::process::exit(0);
        }
        (label, _) => fail(format_args!("GET_SWAP_PARTITION replied {label:#x}")),
    }
}

/// The partition's geometry from the block driver.
fn geometry(partition: u64, ipc_buf: *mut u64) -> Geometry
{
    let msg = IpcMessage::builder(blk_labels::BLK_GET_GEOMETRY)
        .word(0, u64::from(ipc::BLK_LABELS_VERSION))
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(partition, &msg, ipc_buf) }
        .unwrap_or_else(|e| fail(format_args!("BLK_GET_GEOMETRY failed (err={e})")));
    if reply.label != ipc::blk_errors::SUCCESS
    {
        fail(format_args!("BLK_GET_GEOMETRY replied {:#x}", reply.label));
    }
    Geometry::new(reply.word(0), reply.word(1)).unwrap_or_else(|| {
        fail(format_args!(
            "the swap partition's block size {} divides no slot",
            reply.word(0)
        ))
    })
}

/// A buffer: a contiguous grant of [`BUF_PAGES`] pages, which swapd never
/// maps, and which each request moves to memmgr or the block driver and back.
fn buffer() -> u64
{
    let pages = BUF_PAGES | (u64::from(memmgr_labels::REQUIRE_CONTIGUOUS) << 32);
    let msg = IpcMessage::builder(memmgr_labels::REQUEST_MEMORY_CAPS)
        .word(0, pages)
        .build();
    let reply = call(
        std::os::seraph::startup_info().memmgr_endpoint,
        &msg,
        "a buffer's grant",
    );
    match (reply.label, reply.caps().first())
    {
        (memmgr_errors::SUCCESS, Some(&cap)) => cap,
        (label, _) => fail(format_args!("a buffer's grant replied {label:#x}")),
    }
}

/// The want Notification memmgr sends [`WANT_BITS`] on.
fn want_notification() -> u64
{
    std::os::seraph::object_slab_retype(std::os::seraph::NOTIFICATION_RETYPE_BYTES, |slab| {
        syscall::cap_create_notification(slab).ok()
    })
    .unwrap_or_else(|| fail(format_args!("no want Notification")))
}

/// Register with memmgr: `slots` slots, a SEND on the endpoint whose RECV is
/// `recv`, badged [`REDIRECT_BADGE`], and a Notify derivation of `want`.
/// A registration ends the writes of an earlier instance and keeps its
/// chunks on disk, which this instance restores. The slots memmgr uses.
fn register(memmgr: u64, recv: u64, want: u64, slots: u64, ipc_buf: *mut u64) -> u64
{
    let send = syscall::cap_derive_badge(recv, syscall::RIGHTS_EP_SEND, REDIRECT_BADGE)
        .unwrap_or_else(|e| fail(format_args!("deriving the redirect SEND failed (err={e})")));
    let notify = syscall::cap_derive(want, syscall::RIGHTS_NTF_NOTIFY)
        .unwrap_or_else(|e| fail(format_args!("deriving the want Notify failed (err={e})")));
    let msg = IpcMessage::builder(memmgr_labels::SWAP_REGISTER)
        .word(0, slots)
        .word(1, WANT_BITS)
        .cap(send)
        .cap(notify)
        .build();
    // SAFETY: ipc_buf is the registered IPC buffer page.
    let reply = unsafe { ipc::ipc_call(memmgr, &msg, ipc_buf) }
        .unwrap_or_else(|e| fail(format_args!("SWAP_REGISTER failed (err={e})")));
    if reply.label != memmgr_errors::SUCCESS
    {
        fail(format_args!("SWAP_REGISTER replied {:#x}", reply.label));
    }
    reply.word(0)
}

/// `msg` called on `ep` from the calling thread; a call that fails ends
/// swapd with a fault, `what` naming it.
fn call(ep: u64, msg: &IpcMessage, what: &str) -> IpcMessage
{
    // SAFETY: `current_ipc_buf` is the calling thread's registered IPC buffer.
    unsafe { ipc::ipc_call(ep, msg, std::os::seraph::current_ipc_buf()) }
        .unwrap_or_else(|e| fail(format_args!("{what} failed (err={e})")))
}

/// Move `extent` between the partition and the buffer `buf` with the block
/// label `label`, the reply moving the buffer back into `buf`. Its outcome;
/// `DEVICE_FAULT` loses the partition. A call that failed is decided by a
/// probe ([`failed_call`]); a reply without the buffer ends swapd with a
/// fault, the next instance taking the partition and its buffers again.
fn transfer(swap: &Swap, label: u64, extent: Extent, buf: &mut u64) -> Transfer
{
    let msg = IpcMessage::builder(label)
        .word(0, extent.lba)
        .word(1, extent.count)
        .cap(*buf)
        .build();
    // SAFETY: `current_ipc_buf` is the calling thread's registered IPC buffer.
    let reply =
        match unsafe { ipc::ipc_call(swap.partition, &msg, std::os::seraph::current_ipc_buf()) }
        {
            Ok(reply) => reply,
            Err(e) => return failed_call(swap, e),
        };
    *buf = *reply
        .caps()
        .first()
        .unwrap_or_else(|| fail(format_args!("a block request moved no buffer back")));
    let outcome = layout::transfer(reply.label);
    if outcome == Transfer::Lost
    {
        swap.lose();
    }
    outcome
}

/// After a block request failed with `err`, its buffer perhaps the
/// driver's: probe the partition with a call that lends no buffer
/// (`BLK_GET_GEOMETRY`) until the probe shows whether the driver lives
/// ([`layout::after_probe`]). A driver that died holding the request wakes
/// it before devmgr revokes its endpoint; the probe then waits on the
/// endpoint until the revoke ends it. A live driver ends swapd with a fault,
/// and a gone one loses the partition.
fn failed_call(swap: &Swap, err: i64) -> Transfer
{
    let probe = IpcMessage::builder(blk_labels::BLK_GET_GEOMETRY)
        .word(0, u64::from(ipc::BLK_LABELS_VERSION))
        .build();
    loop
    {
        // SAFETY: `current_ipc_buf` is the calling thread's registered IPC buffer.
        let outcome =
            unsafe { ipc::ipc_call(swap.partition, &probe, std::os::seraph::current_ipc_buf()) };
        let shown = match outcome
        {
            Ok(_) => Probe::Replied,
            Err(_) if syscall::cap_info(swap.partition, syscall::CAP_INFO_TAG_RIGHTS).is_err() =>
            {
                Probe::CapGone
            }
            Err(e) if e == SyscallError::Interrupted as i64 => Probe::Interrupted,
            Err(_) => Probe::Failed,
        };
        match layout::after_probe(shown)
        {
            AfterFailedCall::Restart => fail(format_args!("a block request failed (err={err})")),
            AfterFailedCall::Lose =>
            {
                swap.lose();
                return Transfer::Lost;
            }
            AfterFailedCall::ProbeAgain =>
            {}
        }
    }
}

/// Read the bytes `word` names into `buf`, at most [`layout::READ_TRIES`]
/// times; whether they were read.
fn read_slot(swap: &Swap, word: u64, buf: &mut u64) -> bool
{
    let Some(extent) = swap.geometry.word_extent(word)
    else
    {
        return false;
    };
    for _ in 0..layout::READ_TRIES
    {
        if swap.lost()
        {
            return false;
        }
        match transfer(swap, blk_labels::BLK_READ_INTO_MEMORY, extent, buf)
        {
            Transfer::Done => return true,
            Transfer::Failed =>
            {}
            Transfer::Lost => return false,
        }
    }
    false
}

/// `SWAP_RESTORE` of `word` with the bytes `buf` holds: memmgr's reply
/// label and word 0, the reply moving the buffer back.
fn swap_restore(swap: &Swap, word: u64, buf: &mut u64) -> (u64, u64)
{
    let msg = IpcMessage::builder(memmgr_labels::SWAP_RESTORE)
        .word(0, word)
        .cap(*buf)
        .build();
    let reply = call(swap.memmgr, &msg, "SWAP_RESTORE");
    *buf = *reply
        .caps()
        .first()
        .unwrap_or_else(|| fail(format_args!("SWAP_RESTORE moved no buffer back")));
    (reply.label, reply.word(0))
}

/// Restore the chunk `word` names: read its slot and hand memmgr the bytes.
/// The reply its held fault takes.
fn restore(swap: &Swap, word: u64, buf: &mut u64) -> FaultReply
{
    if !read_slot(swap, word, buf)
    {
        return FaultReply::Forward(layout::UNREADABLE_WORD);
    }
    let (label, decline) = swap_restore(swap, word, buf);
    layout::fault_reply(label, decline)
}

/// The main thread's loop: receive each message on the endpoint `recv`, and
/// restore each fault memmgr redirected ([`REDIRECT_BADGE`]), resuming or
/// forwarding it. Any other message is answered `FAULT_REPLY_FORWARD`, its
/// caps deleted.
fn serve_faults(swap: &Swap, recv: u64, mut buf: u64, ipc_buf: *mut u64) -> !
{
    loop
    {
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let Ok(msg) = (unsafe { ipc::ipc_recv(recv, ipc_buf) })
        else
        {
            continue;
        };
        let reply = if msg.label == FAULT_LABEL && msg.badge == REDIRECT_BADGE
        {
            restore(swap, msg.word(FAULT_REDIRECT_WORD), &mut buf)
        }
        else
        {
            for &cap in msg.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            FaultReply::Forward(0)
        };
        let reply = match reply
        {
            FaultReply::Resume => IpcMessage::new(FAULT_REPLY_RESUME),
            FaultReply::Forward(word) => IpcMessage::builder(FAULT_REPLY_FORWARD)
                .word(0, word)
                .build(),
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let _ = unsafe { ipc::ipc_reply(&reply, ipc_buf) };
    }
}

/// The want thread's loop: on each send on `want`, take the slot words
/// memmgr posted (`SWAP_WANTED`) and restore each chunk, ahead of any fault.
/// A word whose chunk a fault restored meanwhile is `RESTORE_STALE` there and
/// changes nothing.
fn serve_wants(swap: &Swap, want: u64, mut buf: u64) -> !
{
    let take = IpcMessage::new(memmgr_labels::SWAP_WANTED);
    loop
    {
        if syscall::notification_wait(want).is_err()
        {
            continue;
        }
        let reply = call(swap.memmgr, &take, "SWAP_WANTED");
        if reply.label != memmgr_errors::SUCCESS
        {
            continue;
        }
        let count = usize::try_from(reply.word(0)).unwrap_or(0);
        for i in (1..=count).take(usize::try_from(memmgr_labels::SWAP_WANTED_WORDS).unwrap_or(0))
        {
            let _ = restore(swap, reply.word(i), &mut buf);
        }
    }
}

/// The write-out thread's loop: while memmgr's level reads `CRITICAL`, take
/// a chunk into `buf`, write it to its slot, and end the write; else wait on
/// the pressure Notification `pressure` for a change of the level.
fn write_out(swap: &Swap, pressure: u64, mut buf: u64) -> !
{
    let mut empty: u32 = 0;
    let mut unwritten_logged = false;
    loop
    {
        if swap.lost()
        {
            // Nothing is written again; the thread waits for good.
            let _ = syscall::notification_wait_timeout(pressure, 0);
            continue;
        }
        if std::os::seraph::memory_pressure() != Some(std::os::seraph::MemoryPressure::Critical)
        {
            empty = 0;
            let _ = syscall::notification_wait_timeout(pressure, 0);
            continue;
        }
        let msg = IpcMessage::builder(memmgr_labels::SWAP_TAKE)
            .cap(buf)
            .build();
        let reply = call(swap.memmgr, &msg, "SWAP_TAKE");
        buf = *reply
            .caps()
            .first()
            .unwrap_or_else(|| fail(format_args!("SWAP_TAKE moved no buffer back")));
        match layout::after_take(reply.label, empty)
        {
            AfterTake::Write =>
            {
                empty = 0;
                let outcome = write_slot(swap, reply.word(0), reply.word(1), &mut buf);
                if let Some(wait) = layout::after_write(outcome)
                {
                    if !unwritten_logged
                    {
                        unwritten_logged = true;
                        std::os::seraph::log!(
                            warn: "a slot was not written; the write-out waits after each slot it cannot \
                                   write"
                        );
                    }
                    let _ = syscall::notification_wait_timeout(pressure, wait);
                }
            }
            AfterTake::Again => empty = empty.saturating_add(1),
            AfterTake::Backoff =>
            {
                empty = 0;
                let _ = syscall::notification_wait_timeout(pressure, layout::TAKE_BACKOFF_MS);
            }
            AfterTake::Full =>
            {
                empty = 0;
                let _ = syscall::notification_wait_timeout(pressure, layout::FULL_BACKOFF_MS);
            }
            AfterTake::Refused =>
            {
                std::os::seraph::log!(warn: "SWAP_TAKE refused ({:#x})", reply.label);
                empty = 0;
                let _ = syscall::notification_wait_timeout(pressure, layout::FULL_BACKOFF_MS);
            }
        }
    }
}

/// Write the `len` bytes `SWAP_TAKE` put in `buf` to slot `slot`, and end the
/// write: written, or not, which compresses the chunk again on its store runs.
/// The write's outcome, `Failed` for a slot word that names no slot of the
/// partition.
fn write_slot(swap: &Swap, slot: u64, len: u64, buf: &mut u64) -> Transfer
{
    let outcome = u32::try_from(slot)
        .ok()
        .and_then(|slot| swap.geometry.extent(slot, len))
        .map_or(Transfer::Failed, |extent| {
            transfer(swap, blk_labels::BLK_WRITE_FROM_MEMORY, extent, buf)
        });
    let written = outcome == Transfer::Done;
    let msg = IpcMessage::builder(memmgr_labels::SWAP_DONE)
        .word(0, slot)
        .word(1, u64::from(!written))
        .build();
    let reply = call(swap.memmgr, &msg, "SWAP_DONE");
    if reply.label != memmgr_errors::SUCCESS
    {
        std::os::seraph::log!(warn: "SWAP_DONE of slot {slot} replied {:#x}", reply.label);
    }
    outcome
}

/// End swapd with a fault, `why` logged as its panic message: a panic traps,
/// a fault exit, which svcmgr restarts within its budget (`restart =
/// on_failure`), where a clean exit is not restarted.
#[expect(
    clippy::panic,
    reason = "the deliberate fault exit of an instance that cannot serve, so svcmgr restarts it"
)]
fn fail(why: std::fmt::Arguments<'_>) -> !
{
    panic!("{why}")
}

/// Touch [`STACK_TOUCH_BYTES`] of the stack below this frame, so its pages
/// are backed before memory can run out.
#[inline(never)]
#[expect(
    clippy::large_stack_arrays,
    clippy::large_stack_frames,
    reason = "the probe exists to occupy and touch this much of the stack"
)]
fn touch_stack()
{
    let mut probe = [0u8; STACK_TOUCH_BYTES];
    std::hint::black_box(&mut probe);
}

/// Touch [`HEAP_TOUCH_BYTES`] of heap and free them: the allocator keeps
/// the pages.
fn touch_heap()
{
    drop(std::hint::black_box(vec![1u8; HEAP_TOUCH_BYTES]));
}
