// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/klog/mod.rs

//! The kernel log: the kernel's address-free console lines as records a
//! userspace reader drains, so that while a reader is attached the kernel
//! does not write the serial port beside it.
//!
//! Before a reader attaches, and after one stalls, [`print`] writes each line
//! straight to the console as it always did. While one is attached it
//! appends the line to the ring instead, and the next timer tick signals the
//! reader's bound notification. Failure reports ([`print_direct`]) and the
//! panic handler always write directly, after printing the records no reader
//! has acknowledged ([`flush`]). The design, the lock order and the reader
//! protocol are in `core/kernel/docs/kernel-log.md`.

pub mod ring;

use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};

use syscall::KLOG_LINE_MAX;

use crate::console::Sink;
use crate::ipc::notification::NotificationState;
use crate::sync::Spinlock;
use ring::{Cursor, Ring};
use syscall::KLOG_STALL_MS;

/// Bytes of the kernel log ring.
pub const KLOG_RING_BYTES: usize = 16 * 1024;

/// The severity every kernel line takes until the print sites carry their
/// own (RFC 5424 informational).
pub const LEVEL_INFO: u8 = 6;

/// The ring, in words.
const RING_WORDS: usize = KLOG_RING_BYTES / 8;

/// The kernel log ring.
static RING: Ring<RING_WORDS> = Ring::new();

/// Serialises appends, reads and every change to the reader's cursor. Taken
/// with interrupts disabled. The only lock taken under it is the console's
/// (`console::CONSOLE_LOCK`), by a line written while no reader is attached.
static KLOG_LOCK: Spinlock = Spinlock::new();

/// The reader's cursor (`ring::Cursor`), one atomic per field so the
/// lock-free paths can read it. Written under [`KLOG_LOCK`], except that
/// [`flush`] raises `COMMITTED` without it.
static ATTACHED: AtomicBool = AtomicBool::new(false);
static COMMITTED: AtomicU64 = AtomicU64::new(0);
static LAST_READ_SEQ: AtomicU64 = AtomicU64::new(0);
static SINCE_US: AtomicU64 = AtomicU64::new(0);

/// A record was appended since the last timer tick signalled the reader.
static PENDING: AtomicBool = AtomicBool::new(false);

/// Serialises the binding: its change, its clearing when the notification
/// is freed, and the tick's signal through it. The signal's send takes, under
/// it, the notification's lock and, for a notification in a wait set, the
/// wait set's lock, then the woken waiter's `sched_lock` and a CPU's
/// scheduler lock; so it is never taken while any of those is held
/// (core/kernel/docs/kernel-log.md § Lock order).
static BINDING_LOCK: Spinlock = Spinlock::new();

/// The notification the reader bound, null when none is bound. Written only
/// under [`BINDING_LOCK`], with `Release`, so that [`forget_notification`] can
/// read it without the lock (its comment says why that suffices).
static BINDING_SIG: AtomicPtr<NotificationState> = AtomicPtr::new(core::ptr::null_mut());

/// The bits to signal the bound notification with, under [`BINDING_LOCK`].
static BINDING_BITS: AtomicU64 = AtomicU64::new(0);

/// The cursor as the atomics hold it.
fn load_cursor() -> Cursor
{
    Cursor {
        attached: ATTACHED.load(Ordering::Relaxed),
        committed: COMMITTED.load(Ordering::Acquire),
        last_read_seq: LAST_READ_SEQ.load(Ordering::Relaxed),
        since_us: SINCE_US.load(Ordering::Relaxed),
    }
}

/// Print one line: append it as a record while a reader is attached, else
/// write it directly to `sink`. The path of `kprintln!` and
/// `kprintln_fault!`.
///
/// The line is formed under [`KLOG_LOCK`], straight into the ring or onto the
/// console, so a `Display` implementation it formats must not print.
pub fn print(sink: Sink, args: core::fmt::Arguments)
{
    // SAFETY: released below on every path; no lock that is taken under
    // KLOG_LOCK is held here (the console lock is only ever taken after it).
    let saved = unsafe { KLOG_LOCK.lock_raw() };
    let us = crate::console::now_us();
    if ATTACHED.load(Ordering::Relaxed)
    {
        let mut w = RING.begin();
        let _ = core::fmt::Write::write_fmt(&mut w, args);
        let us = us.unwrap_or(0);
        let seq = RING.commit(w, us, LEVEL_INFO);
        let mut c = load_cursor();
        c.on_append(seq, us);
        SINCE_US.store(c.since_us, Ordering::Relaxed);
        PENDING.store(true, Ordering::Release);
    }
    else
    {
        // Written under KLOG_LOCK, so an attach (which takes it) finds no
        // line half written directly and no line both written and appended.
        // SAFETY: the console is initialised before any line is printed.
        unsafe { crate::console::write_line(sink, us, args) };
    }
    // SAFETY: paired with lock_raw above.
    unsafe { KLOG_LOCK.unlock_raw(saved) };
}

/// [`print`] for a userspace fault diagnostic, which written directly goes to
/// the serial port only: the path of `kprintln_fault!`, as a function a
/// register dump shared with kernel traps can take.
pub fn print_fault(args: core::fmt::Arguments)
{
    print(Sink::Serial, args);
}

/// Print one line directly to the console, after the records no reader has
/// acknowledged ([`flush`]). The path of `kprintln_direct!`.
pub fn print_direct(args: core::fmt::Arguments)
{
    flush(FlushOut::Console);
    // SAFETY: the console is initialised before any line is printed.
    unsafe { crate::console::write_line(Sink::Console, crate::console::now_us(), args) };
}

/// Where [`flush`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlushOut
{
    /// The serial port, through the console lock.
    Console,
    /// The serial port, through `console::panic_write_fmt`, which takes no
    /// lock: the panic handler's path.
    Panic,
}

/// Print, oldest first, every record no reader has acknowledged, to the
/// serial port, each as a direct kernel line with its own timestamp, and
/// raise the committed mark past them.
///
/// Takes no lock to read: the ring is read with [`Ring::read_unlocked`], so a
/// CPU that panicked holding [`KLOG_LOCK`], or one wedged holding it, cannot
/// stop the flush. A record that cannot be read whole (the appender is
/// overwriting it) ends the walk with one line saying so. Two CPUs flushing at
/// once can print a record twice.
pub fn flush(out: FlushOut)
{
    let committed = COMMITTED.load(Ordering::Acquire);
    if RING.newest_seq() <= committed
    {
        return;
    }
    let mut text = [0u8; KLOG_LINE_MAX];
    let (mut pos, head) = RING.bounds();
    let mut expect = None;
    let mut last = committed;
    while pos < head
    {
        let Some(m) = RING.read_unlocked(pos, expect, &mut text)
        else
        {
            emit(
                out,
                None,
                format_args!("klog: flush stopped at a record being overwritten"),
            );
            break;
        };
        if m.seq > committed
        {
            let line = text.get(..m.len).unwrap_or_default();
            let line = core::str::from_utf8(line).unwrap_or("<not UTF-8>");
            emit(out, Some(m.us), format_args!("{line}"));
            last = m.seq;
        }
        expect = Some(m.seq.wrapping_add(1));
        pos = pos.wrapping_add(ring::record_bytes(m.len));
    }
    COMMITTED.fetch_max(last, Ordering::AcqRel);
}

/// Write one flushed line to `out`.
fn emit(out: FlushOut, us: Option<u64>, args: core::fmt::Arguments)
{
    match out
    {
        FlushOut::Console =>
        {
            // SAFETY: the console is initialised before any record exists.
            unsafe { crate::console::write_line(Sink::Serial, us, args) };
        }
        FlushOut::Panic =>
        {
            // SAFETY: as above; panic_write_fmt takes no lock.
            unsafe {
                crate::console::panic_write_fmt(format_args!(
                    "{} kernel: {}\n",
                    crate::console::Stamp(us),
                    args
                ));
            }
        }
    }
}

/// Apply a read's acknowledgement `ack_seq` (`ring::Cursor::acknowledge`) and
/// return the sequence number the read starts at (`ring::Cursor::start_seq`):
/// a reader that acknowledges what it has written and asks for `from_seq` 0
/// gets the records after them, and none a flush has already printed.
///
/// The acknowledgement only raises the committed mark, so a read that faults
/// and re-executes applies it again to the same effect.
pub fn read_start(from_seq: u64, ack_seq: u64) -> u64
{
    // SAFETY: released below; nothing here takes a lock.
    let saved = unsafe { KLOG_LOCK.lock_raw() };
    let mut c = load_cursor();
    c.acknowledge(ack_seq, RING.newest_seq());
    COMMITTED.fetch_max(c.committed, Ordering::AcqRel);
    let start = c.start_seq(from_seq);
    // SAFETY: paired with lock_raw above.
    unsafe { KLOG_LOCK.unlock_raw(saved) };
    start
}

/// Copy the records from `from` on into `out` under [`KLOG_LOCK`]
/// (`ring::Ring::copy_out`): the bytes written and the last sequence number.
pub fn copy_out(from: u64, out: &mut [u8]) -> (usize, u64)
{
    // SAFETY: released below; nothing in copy_out takes a lock.
    let saved = unsafe { KLOG_LOCK.lock_raw() };
    let r = RING.copy_out(from, out);
    // SAFETY: paired with lock_raw above.
    unsafe { KLOG_LOCK.unlock_raw(saved) };
    r
}

/// Record a completed read (`ring::Cursor::on_read`): attach the reader,
/// raise the committed mark to `ack_seq`, and note the last record it
/// returned and, when it attached the reader or returned a new record, its
/// time.
pub fn complete_read(ack_seq: u64, returned_last: u64)
{
    // SAFETY: released below; nothing here takes a lock.
    let saved = unsafe { KLOG_LOCK.lock_raw() };
    let mut c = load_cursor();
    c.on_read(
        ack_seq,
        returned_last,
        RING.newest_seq(),
        crate::console::now_us().unwrap_or(0),
    );
    COMMITTED.fetch_max(c.committed, Ordering::AcqRel);
    LAST_READ_SEQ.store(c.last_read_seq, Ordering::Relaxed);
    SINCE_US.store(c.since_us, Ordering::Relaxed);
    ATTACHED.store(true, Ordering::Release);
    // SAFETY: paired with lock_raw above.
    unsafe { KLOG_LOCK.unlock_raw(saved) };
}

/// The timer tick's work, on every CPU: signal the reader once records were
/// appended since the last tick, and, on the BSP, end the attach of a reader
/// that has stalled (`ring::Cursor::stalled`). `cpu` is the ticking CPU's
/// index; the BSP is CPU 0.
///
/// # Safety
/// Interrupt context with interrupts disabled, holding no lock.
#[cfg(not(test))]
pub unsafe fn tick(cpu: usize)
{
    let bsp = cpu == 0;
    if PENDING.load(Ordering::Relaxed) && PENDING.swap(false, Ordering::Acquire)
    {
        // SAFETY: caller contract.
        unsafe { signal_reader() };
    }
    if bsp && ATTACHED.load(Ordering::Relaxed)
    {
        stall_check();
    }
}

/// End the attach of a reader that has stalled, checked first without the
/// lock and again under it.
#[cfg(not(test))]
fn stall_check()
{
    let Some(now) = crate::console::now_us()
    else
    {
        return;
    };
    let stall_us = KLOG_STALL_MS.saturating_mul(1000);
    if !load_cursor().stalled(RING.newest_seq(), now, stall_us)
    {
        return;
    }
    // SAFETY: released below; nothing here takes a lock.
    let saved = unsafe { KLOG_LOCK.lock_raw() };
    let c = load_cursor();
    let stalled = c.stalled(RING.newest_seq(), now, stall_us);
    if stalled
    {
        ATTACHED.store(false, Ordering::Release);
    }
    // SAFETY: paired with lock_raw above.
    unsafe { KLOG_LOCK.unlock_raw(saved) };
    if stalled
    {
        crate::kprintln!(
            "klog: reader stalled at record {} for {} ms",
            c.seen().saturating_add(1),
            now.saturating_sub(c.since_us) / 1000
        );
    }
}

/// Signal the bound notification, if any, and wake the waiter it released.
///
/// # Safety
/// Interrupt context with interrupts disabled.
#[cfg(not(test))]
unsafe fn signal_reader()
{
    // SAFETY: released below. notification_send takes, under it, the
    // notification's lock and, for a notification in a wait set, the wait
    // set's lock and the woken waiter's sched_lock and a CPU's scheduler
    // lock; the caller holds no lock, and no holder of those takes
    // BINDING_LOCK.
    let saved = unsafe { BINDING_LOCK.lock_raw() };
    let sig = BINDING_SIG.load(Ordering::Relaxed);
    let bits = BINDING_BITS.load(Ordering::Relaxed);
    let woken = if sig.is_null()
    {
        None
    }
    else
    {
        // SAFETY: a bound notification is live while BINDING_LOCK is held:
        // its deallocation clears the binding under this lock first
        // (forget_notification).
        unsafe { crate::ipc::notification::notification_send(sig, bits) }
    };
    // SAFETY: paired with lock_raw above.
    unsafe { BINDING_LOCK.unlock_raw(saved) };
    if let Some(tcb) = woken
    {
        // SAFETY: tcb is the waiter notification_send claimed for wake; the
        // waker is the timer tick, not a thread, so the wake takes no hint.
        let target_cpu = unsafe { crate::sched::select_target_cpu(tcb) };
        // SAFETY: tcb and target_cpu are valid; as in irq's signal.
        unsafe { crate::sched::enqueue_and_wake(tcb, target_cpu) };
    }
}

/// Bind `sig` as the reader's notification, signalled with `bits`, replacing
/// any earlier binding; a null `sig` unbinds. The binding holds no reference
/// on the notification: its deallocation clears the binding
/// ([`forget_notification`]).
///
/// # Safety
/// `sig` is null or a live notification the caller holds pinned.
pub unsafe fn bind(sig: *mut NotificationState, bits: u64)
{
    // SAFETY: released below; nothing here takes a lock.
    let saved = unsafe { BINDING_LOCK.lock_raw() };
    BINDING_BITS.store(bits, Ordering::Relaxed);
    BINDING_SIG.store(sig, Ordering::Release);
    // SAFETY: paired with lock_raw above.
    unsafe { BINDING_LOCK.unlock_raw(saved) };
}

/// Clear the binding if it names `sig`, which is being deallocated. Called
/// with no lock held, before the notification's state is freed, on every
/// notification's deallocation, so it takes [`BINDING_LOCK`] only when the
/// binding names `sig`.
///
/// The check without the lock is enough. `sig`'s last reference is gone, and
/// with it every pin, so no bind can store `sig` after this load: a bind that
/// stored it did so before releasing its pin, which happens before the
/// deallocation. A load that finds another value reads a store made, under
/// [`BINDING_LOCK`] and with `Release`, after every critical section that read
/// `sig` from the binding, the tick's signal through `sig` among them; the
/// `Acquire` load orders those sections before the state is freed.
pub fn forget_notification(sig: *mut NotificationState)
{
    if BINDING_SIG.load(Ordering::Acquire) != sig
    {
        return;
    }
    // SAFETY: released below; nothing here takes a lock.
    let saved = unsafe { BINDING_LOCK.lock_raw() };
    if BINDING_SIG.load(Ordering::Relaxed) == sig
    {
        BINDING_BITS.store(0, Ordering::Relaxed);
        BINDING_SIG.store(core::ptr::null_mut(), Ordering::Release);
    }
    // SAFETY: paired with lock_raw above.
    unsafe { BINDING_LOCK.unlock_raw(saved) };
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: the lock-free check in `forget_notification` clearing a
    // binding that names another notification, or leaving the binding of the
    // one being freed, which the tick would then signal after the free.
    #[test]
    fn forget_clears_only_the_binding_of_the_notification_it_names()
    {
        let mut a = core::mem::MaybeUninit::<NotificationState>::uninit();
        let mut b = core::mem::MaybeUninit::<NotificationState>::uninit();
        let (a, b) = (a.as_mut_ptr(), b.as_mut_ptr());
        // SAFETY: neither pointer is dereferenced: bind and forget only store
        // and compare them.
        unsafe { bind(a, 0b10) };
        forget_notification(b);
        assert_eq!(BINDING_SIG.load(Ordering::Relaxed), a);
        assert_eq!(BINDING_BITS.load(Ordering::Relaxed), 0b10);
        forget_notification(a);
        assert!(BINDING_SIG.load(Ordering::Relaxed).is_null());
        assert_eq!(BINDING_BITS.load(Ordering::Relaxed), 0);
    }
}
