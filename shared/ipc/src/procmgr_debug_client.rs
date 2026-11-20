// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/procmgr_debug_client.rs

//! A debug-authority holder's access to another process's memory when a page
//! of it is evicted (`procmgr_labels::MAKE_RESIDENT`), or maps a memory
//! object's frame it is about to patch (`procmgr_labels::MAKE_PRIVATE`),
//! re-exported at the crate root.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use syscall_abi::SyscallError;

use crate::{IpcMessage, ipc_call, memmgr_labels, procmgr_errors, procmgr_labels};

/// How long a reader pauses before it asks again for a range memmgr replied
/// pending on: the swap service is reading a chunk on disk, which takes a slot
/// read (about 0.15 ms under KVM, 1.5 ms under TCG, measured) and a restore.
pub const PENDING_PAUSE_MS: u64 = 2;

/// How many times a reader pauses for chunks memmgr replied pending on, in
/// all, so it waits about a second, [`PENDING_PAUSE_MS`] apart; then it asks
/// on from where memmgr's walk stopped, passing the chunks on disk over, so a
/// swap service that is down, or restarting, or whose disk has failed, leaves
/// their pages not present, which the reader reads as such, while the rest of
/// the range is still made resident ([`resident_range`]).
pub const PENDING_TRIES: u32 = 500;

/// One `MAKE_RESIDENT` reply: where memmgr stopped, whether it stopped at a
/// chunk on disk the swap service was asked to restore, and where its walk
/// stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidentStep
{
    /// The address memmgr stopped at: the range's end when it is all done.
    pub reached: u64,
    /// `reached` is a chunk on disk memmgr posted to the swap service.
    pub pending: bool,
    /// Where memmgr's walk stopped: `reached` when not pending, else past
    /// every chunk it posted.
    pub walked: u64,
}

/// What a reader making `[at, end)` resident does after a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Next
{
    /// The range is done.
    Done,
    /// Ask again from the address: memmgr bounded its work.
    From(u64),
    /// Pause [`PENDING_PAUSE_MS`] and ask again from the address: a chunk on
    /// disk there is being read.
    Pause(u64),
    /// The reader has paused [`PENDING_TRIES`] times: ask again, without a
    /// pause, from where memmgr's walk stopped, past the chunks on disk it
    /// posted, which stay not present.
    PassOver(u64),
    /// Give up: the reply made no progress or was malformed.
    GiveUp,
}

/// The next move of a reader at `at` of a range ending at `end`, after the
/// step `step`, having paused `paused` times in all.
#[must_use]
pub fn next(at: u64, end: u64, step: ResidentStep, paused: u32) -> Next
{
    if step.pending
    {
        if step.reached < at || step.reached >= end
        {
            return Next::GiveUp;
        }
        if paused < PENDING_TRIES
        {
            return Next::Pause(step.reached);
        }
        if step.walked > step.reached
        {
            return Next::PassOver(step.walked);
        }
        return Next::GiveUp;
    }
    if step.reached >= end
    {
        Next::Done
    }
    else if step.reached <= at
    {
        Next::GiveUp
    }
    else
    {
        Next::From(step.reached)
    }
}

/// A reader's bound on its wait for the chunks on disk of the ranges it makes
/// resident: the pauses it has spent against [`PENDING_TRIES`], never reset,
/// so a reader that passes one bound to several ranges, as crashd does to
/// every read of a dump, pauses at most [`PENDING_TRIES`] times over all of
/// them; and the reader's own stop, checked before each request, so a reader
/// whose own bound has passed (crashd's fault or dump bound) sends no further
/// request.
pub struct ResidentBound<'a>
{
    /// The pauses spent.
    pauses: u32,
    /// Whether the reader's own bound has passed.
    stop: &'a dyn Fn() -> bool,
}

impl<'a> ResidentBound<'a>
{
    /// A bound with no pause spent, which stops once `stop` returns `true`.
    #[must_use]
    pub fn new(stop: &'a dyn Fn() -> bool) -> Self
    {
        Self { pauses: 0, stop }
    }

    /// The pauses spent against [`PENDING_TRIES`].
    #[must_use]
    pub const fn pauses(&self) -> u32
    {
        self.pauses
    }

    /// Whether the reader's own bound has passed: no further request is sent
    /// under this bound.
    #[must_use]
    pub fn stopped(&self) -> bool
    {
        (self.stop)()
    }
}

/// Ask procmgr, through the debug-authority cap `authority`, to make the
/// range of `len` bytes at `va` of the process whose process badge (as
/// `procmgr_labels::LIST_PROCESSES` lists it) is `process` resident
/// (`procmgr_labels::MAKE_RESIDENT`), under a bound of its own: at most
/// [`PENDING_TRIES`] pauses, about a second, and no stop. This is
/// [`make_resident_bounded`] for a reader that runs under no bound of its
/// own, as gdbstub does; a reader that does passes its bound to that.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
pub unsafe fn make_resident(
    authority: u64,
    process: u64,
    va: u64,
    len: u64,
    ipc_buf: *mut u64,
) -> bool
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        make_resident_bounded(
            authority,
            process,
            va,
            len,
            ipc_buf,
            &mut ResidentBound::new(&|| false),
        )
    }
}

/// Ask procmgr, through the debug-authority cap `authority`, to make the
/// range of `len` bytes at `va` of the process whose process badge (as
/// `procmgr_labels::LIST_PROCESSES` lists it) is `process` resident
/// (`procmgr_labels::MAKE_RESIDENT`): memmgr restores each chunk of the
/// range it evicted into its compressed store, and maps each page of an
/// attachment with no copy of its own to its origin, read-only, so a
/// `SYS_THREAD_READ_MEM` that failed with `InvalidAddress` on such a page
/// succeeds when retried (`services/memmgr/docs/memory-pool.md` § Eviction,
/// Debugger reads), and asks the swap service to restore each chunk of it on
/// disk. A page of an ordinary region no fault has backed stays not present.
/// memmgr does a bounded part of the range per request and replies where it
/// stopped, so this asks
/// again from there until the whole range is done ([`next`]); where memmgr
/// stopped at a chunk on disk, it pauses [`PENDING_PAUSE_MS`] before it asks
/// again, while `bound` has pauses left, and past them goes on past the
/// chunks on disk; once `bound` has stopped, it sends no further request
/// ([`resident_range`]).
/// Whether every request was served: `false` when a call failed, procmgr
/// refused (`OUT_OF_MEMORY` when memmgr could not restore a chunk of the
/// range), a reply made no progress, a chunk on disk was not restored within
/// the bound's pauses, or the bound stopped.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
pub unsafe fn make_resident_bounded(
    authority: u64,
    process: u64,
    va: u64,
    len: u64,
    ipc_buf: *mut u64,
    bound: &mut ResidentBound<'_>,
) -> bool
{
    let Some(end) = va.checked_add(len)
    else
    {
        return false;
    };
    resident_range(
        va,
        end,
        bound,
        // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
        |at| unsafe { make_resident_step(authority, process, at, end, ipc_buf) },
        // A sleep cut short (crashd's watchdog upcall) only asks again
        // sooner, which the bound's pauses and its stop bound as well.
        || {
            let _ = syscall::thread_sleep(PENDING_PAUSE_MS);
        },
    )
}

/// The loop of [`make_resident_bounded`] over `[va, end)`: `step` makes one
/// request from the address it is given (`None` when the call failed or was
/// refused), and `pause` waits [`PENDING_PAUSE_MS`] after a pending reply.
/// No request is made once `bound` has stopped. `bound` counts the pauses
/// spent against [`PENDING_TRIES`] and is never reset, so a caller that
/// passes one bound to several ranges, as crashd does for a dump's, bounds
/// the wait on the swap service over all of them; once its pauses are spent,
/// a range still goes on past its chunks on disk, so the chunks memmgr
/// restores from its store beyond them are restored. Whether the whole range
/// is done: `false` when the bound stopped, a request failed, a reply made no
/// progress, or a chunk on disk was passed over.
pub fn resident_range(
    va: u64,
    end: u64,
    bound: &mut ResidentBound<'_>,
    mut step: impl FnMut(u64) -> Option<ResidentStep>,
    mut pause: impl FnMut(),
) -> bool
{
    let mut at = va;
    let mut passed = false;
    loop
    {
        if bound.stopped()
        {
            return false;
        }
        let Some(reply) = step(at)
        else
        {
            return false;
        };
        match next(at, end, reply, bound.pauses)
        {
            Next::Done => return !passed,
            Next::GiveUp => return false,
            Next::From(reached) => at = reached,
            Next::PassOver(walked) =>
            {
                passed = true;
                if walked >= end
                {
                    return false;
                }
                at = walked;
            }
            Next::Pause(reached) =>
            {
                at = reached;
                bound.pauses = bound.pauses.saturating_add(1);
                pause();
            }
        }
    }
}

/// One `MAKE_RESIDENT` request for `[at, end)` of `process`, through the
/// debug-authority cap `authority`: where procmgr replied that memmgr
/// stopped, `end` when the range is done, and whether it stopped at a chunk
/// on disk the swap service was asked to restore, or `None` when the call
/// failed or procmgr refused. [`make_resident_bounded`] drives
/// [`resident_range`] with this, one request per step.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, a std service's thread (crashd, gdbstub), 32 KiB at the smallest"
)]
pub unsafe fn make_resident_step(
    authority: u64,
    process: u64,
    at: u64,
    end: u64,
    ipc_buf: *mut u64,
) -> Option<ResidentStep>
{
    let request = IpcMessage::builder(procmgr_labels::MAKE_RESIDENT)
        .word(0, process)
        .word(1, at)
        .word(2, end.saturating_sub(at))
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { ipc_call(authority, &request, ipc_buf) }
        .ok()
        .filter(|reply| reply.label == procmgr_errors::SUCCESS)
        .map(|reply| ResidentStep {
            reached: reply.word(0),
            pending: reply.word(1) == memmgr_labels::RESIDENT_PENDING,
            walked: reply.word(2),
        })
}

/// Ask procmgr, through the debug-authority cap `authority`, to give each
/// page of the range of `len` bytes at `va` of the process whose process
/// badge (as `procmgr_labels::LIST_PROCESSES` lists it) is `process` that
/// maps a memory object's frame a copy of its own
/// (`procmgr_labels::MAKE_PRIVATE`), so a `SYS_THREAD_WRITE_MEM` text write
/// that failed with `InvalidState` there succeeds when retried
/// (`services/memmgr/docs/memory-pool.md` § Memory objects, Make private).
/// memmgr makes a bounded number of copies per request and replies where it
/// stopped, so this asks again from there until the whole range is done
/// ([`private_range`]). Whether every request was served: `false` when a
/// call failed, procmgr refused (`NOT_ATTACHABLE` for a process that
/// declared itself undebuggable, `OUT_OF_MEMORY` when a copy could not be
/// made), or a reply made no progress.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
pub unsafe fn make_private(
    authority: u64,
    process: u64,
    va: u64,
    len: u64,
    ipc_buf: *mut u64,
) -> bool
{
    let Some(end) = va.checked_add(len)
    else
    {
        return false;
    };
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    private_range(va, end, |at| unsafe {
        make_private_step(authority, process, at, end, ipc_buf)
    })
}

/// One `procmgr_labels::MAKE_PRIVATE` request of [`make_private`] over
/// `[at, end)`: where memmgr stopped, or `None` when the call failed or
/// procmgr refused.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 32 KiB at the smallest (a std process's main thread)"
)]
unsafe fn make_private_step(
    authority: u64,
    process: u64,
    at: u64,
    end: u64,
    ipc_buf: *mut u64,
) -> Option<u64>
{
    let request = IpcMessage::builder(procmgr_labels::MAKE_PRIVATE)
        .word(0, process)
        .word(1, at)
        .word(2, end.saturating_sub(at))
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { ipc_call(authority, &request, ipc_buf) }
        .ok()
        .filter(|reply| reply.label == procmgr_errors::SUCCESS)
        .map(|reply| reply.word(0))
}

/// The loop of [`make_private`] over `[va, end)`: `step` makes one request
/// from the address it is given and returns where memmgr stopped (`None`
/// when the call failed or was refused), and the next request starts there.
/// Whether the whole range is done: `false` when a request failed, or a
/// reply stopped at or below the address it was given, or past `end`, which
/// would ask forever or past the range. An empty range asks nothing.
pub fn private_range(va: u64, end: u64, mut step: impl FnMut(u64) -> Option<u64>) -> bool
{
    let mut at = va;
    while at < end
    {
        let Some(reached) = step(at).filter(|&r| r > at && r <= end)
        else
        {
            return false;
        };
        at = reached;
    }
    true
}

/// Read `buf.len()` bytes at `va` of the address space of `thread`, a thread
/// of the process `process` names, as [`read_mem_resident_bounded`] does,
/// under a bound of its own: at most [`PENDING_TRIES`] pauses, about a
/// second, and no stop, for a reader that runs under no bound of its own, as
/// gdbstub does.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// As [`read_mem_resident_bounded`].
pub unsafe fn read_mem_resident(
    authority: u64,
    process: u64,
    thread: u64,
    va: u64,
    buf: &mut [u8],
    ipc_buf: *mut u64,
) -> Result<(), i64>
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe {
        read_mem_resident_bounded(
            authority,
            process,
            thread,
            va,
            buf,
            ipc_buf,
            &mut ResidentBound::new(&|| false),
        )
    }
}

/// Read `buf.len()` bytes at `va` of the address space of `thread`, a thread
/// of the process `process` names, as `SYS_THREAD_READ_MEM` reads them
/// (`syscall::thread_read_mem`). That read fails with `InvalidAddress` on a
/// page that is not present, as a page of a chunk memmgr evicted is until its
/// next fault; on that failure this asks procmgr to make the range resident
/// under `bound` ([`make_resident_bounded`], through `authority`) and, when
/// procmgr did, reads once more.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// The error of the last `SYS_THREAD_READ_MEM`: the first read's when it
/// failed with anything but `InvalidAddress`, or when procmgr did not make
/// the range resident (a chunk on disk the swap service did not restore
/// within the bound's pauses, or a bound that stopped, included); else the
/// second read's.
pub unsafe fn read_mem_resident_bounded(
    authority: u64,
    process: u64,
    thread: u64,
    va: u64,
    buf: &mut [u8],
    ipc_buf: *mut u64,
    bound: &mut ResidentBound<'_>,
) -> Result<(), i64>
{
    let Err(first) = syscall::thread_read_mem(thread, va, buf)
    else
    {
        return Ok(());
    };
    if first != SyscallError::InvalidAddress as i64
    {
        return Err(first);
    }
    let len = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    if !unsafe { make_resident_bounded(authority, process, va, len, ipc_buf, bound) }
    {
        return Err(first);
    }
    syscall::thread_read_mem(thread, va, buf).map(|_| ())
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A reply that stopped at `reached`, not pending.
    const fn stopped(reached: u64) -> ResidentStep
    {
        ResidentStep {
            reached,
            pending: false,
            walked: reached,
        }
    }

    /// A reply pending at `reached`, its walk stopped there too.
    const fn pending(reached: u64) -> ResidentStep
    {
        pending_past(reached, reached)
    }

    /// A reply pending at `reached`, its walk gone on to `walked`.
    const fn pending_past(reached: u64, walked: u64) -> ResidentStep
    {
        ResidentStep {
            reached,
            pending: true,
            walked,
        }
    }

    #[test]
    fn a_reader_asks_again_from_where_memmgr_stopped_until_the_range_is_done()
    {
        assert_eq!(next(0x1000, 0x9000, stopped(0x5000), 0), Next::From(0x5000));
        assert_eq!(next(0x5000, 0x9000, stopped(0x9000), 0), Next::Done);
        // A reply past the range's end is done too.
        assert_eq!(next(0x5000, 0x9000, stopped(0xa000), 0), Next::Done);
        // A reply that made no progress ends the loop.
        assert_eq!(next(0x5000, 0x9000, stopped(0x5000), 0), Next::GiveUp);
        assert_eq!(next(0x5000, 0x9000, stopped(0x4000), 0), Next::GiveUp);
    }

    #[test]
    fn a_reader_pauses_on_a_pending_chunk_until_the_tries_run_out()
    {
        // Pending at the reader's own address, or at a chunk past it.
        assert_eq!(
            next(0x1000, 0x9000, pending(0x1000), 0),
            Next::Pause(0x1000)
        );
        assert_eq!(
            next(0x1000, 0x9000, pending(0x3000), 7),
            Next::Pause(0x3000)
        );
        assert_eq!(
            next(0x1000, 0x9000, pending(0x1000), PENDING_TRIES - 1),
            Next::Pause(0x1000)
        );
        assert_eq!(
            next(0x1000, 0x9000, pending(0x1000), PENDING_TRIES),
            Next::GiveUp
        );
        // A pending reply outside the range is malformed.
        assert_eq!(next(0x1000, 0x9000, pending(0x0800), 0), Next::GiveUp);
        assert_eq!(next(0x1000, 0x9000, pending(0x9000), 0), Next::GiveUp);
        // memmgr replies pending at the reader's own address when it asked
        // from inside the chunk: a start not on a page boundary.
        assert_eq!(
            next(0x1008, 0x9000, pending(0x1008), 0),
            Next::Pause(0x1008)
        );
    }

    /// What [`drive`] saw: whether the range was done, how many requests it
    /// made, the addresses of the first four, and the pauses it made.
    struct Drove
    {
        done: bool,
        asks: usize,
        first: [u64; 4],
        made: u32,
    }

    /// Drive [`resident_range`] over `[va, end)` with the replies `replies`
    /// in turn (`None` past the last), under `bound`.
    fn drive(va: u64, end: u64, bound: &mut ResidentBound<'_>, replies: &[ResidentStep]) -> Drove
    {
        let mut asks = 0;
        let mut first = [0; 4];
        let mut made = 0;
        let done = resident_range(
            va,
            end,
            bound,
            |at| {
                if let Some(slot) = first.get_mut(asks)
                {
                    *slot = at;
                }
                let reply = replies.get(asks).copied();
                asks += 1;
                reply
            },
            || made += 1,
        );
        Drove {
            done,
            asks,
            first,
            made,
        }
    }

    /// A reader's own bound that never stops.
    fn never() -> bool
    {
        false
    }

    #[test]
    fn a_range_pauses_on_pending_chunks_and_asks_again_from_them()
    {
        let mut bound = ResidentBound::new(&never);
        let d = drive(
            0x1008,
            0x9000,
            &mut bound,
            &[
                pending(0x1008),
                stopped(0x5000),
                pending(0x6000),
                stopped(0x9000),
            ],
        );
        assert!(d.done);
        assert_eq!((d.asks, d.first), (4, [0x1008, 0x1008, 0x5000, 0x6000]));
        assert_eq!((d.made, bound.pauses()), (2, 2));
        // A failed request ends the range.
        let d = drive(0x1000, 0x9000, &mut bound, &[stopped(0x5000)]);
        assert!(!d.done);
        assert_eq!((d.asks, d.first[0], d.first[1]), (2, 0x1000, 0x5000));
    }

    #[test]
    fn one_bound_limits_the_pauses_over_every_range_that_shares_it()
    {
        let stuck = [pending(0x1000); PENDING_TRIES as usize + 1];
        let mut bound = ResidentBound::new(&never);
        let d = drive(0x1000, 0x9000, &mut bound, &stuck);
        assert!(!d.done);
        assert_eq!(
            (d.made, d.asks),
            (PENDING_TRIES, PENDING_TRIES as usize + 1)
        );
        // A second range sharing the spent bound pauses no more: it gives up
        // at its first pending reply, and still serves one that is not.
        let d = drive(0x1000, 0x9000, &mut bound, &stuck);
        assert!(!d.done && d.made == 0 && d.asks == 1);
        let d = drive(0x1000, 0x9000, &mut bound, &[stopped(0x9000)]);
        assert!(d.done && d.made == 0);
    }

    #[test]
    fn a_spent_bound_goes_on_past_the_chunks_on_disk()
    {
        let mut bound = ResidentBound::new(&never);
        bound.pauses = PENDING_TRIES;
        assert_eq!(
            next(0x1000, 0x9000, pending_past(0x1000, 0x5000), bound.pauses()),
            Next::PassOver(0x5000)
        );
        // The rest of the range is still asked for, with no pause; the
        // range is not done, a chunk on disk having been passed over.
        let d = drive(
            0x1000,
            0x9000,
            &mut bound,
            &[pending_past(0x1000, 0x5000), stopped(0x9000)],
        );
        assert!(!d.done);
        assert_eq!(
            (d.asks, d.first[0], d.first[1], d.made),
            (2, 0x1000, 0x5000, 0)
        );
        // A walk that reached the range's end ends it.
        let d = drive(0x1000, 0x9000, &mut bound, &[pending_past(0x3000, 0x9000)]);
        assert!(!d.done && d.asks == 1);
    }

    #[test]
    fn a_stopped_bound_sends_no_further_request()
    {
        // The reader's own bound passes during the second pause: the range
        // ends there, its pauses left unspent, with no third request.
        let asked = core::cell::Cell::new(0u32);
        let fired = core::cell::Cell::new(false);
        let stop = || fired.get();
        let mut bound = ResidentBound::new(&stop);
        let done = resident_range(
            0x1000,
            0x9000,
            &mut bound,
            |_| {
                asked.set(asked.get() + 1);
                Some(pending(0x1000))
            },
            || fired.set(asked.get() >= 2),
        );
        assert!(!done);
        assert_eq!((asked.get(), bound.pauses()), (2, 2));
        // Every later range under the stopped bound, one sharing a dump's
        // bound, sends no request at all.
        let d = drive(0x1000, 0x9000, &mut bound, &[stopped(0x9000)]);
        assert!(!d.done && d.asks == 0 && d.made == 0);
    }

    // The defect caught: a make-private loop that stops before the range's
    // end, asks again from a reply that made no progress (forever), or goes
    // on past a refusal or a reply past the range.
    #[test]
    fn a_make_private_range_asks_from_each_reply_until_its_end()
    {
        let mut asked = [0u64; 3];
        let mut asks = 0;
        let replies = [0x3000, 0x7000, 0x9000];
        assert!(private_range(0x1000, 0x9000, |at| {
            asked[asks] = at;
            asks += 1;
            Some(replies[asks - 1])
        }));
        assert_eq!((asks, asked), (3, [0x1000, 0x3000, 0x7000]));
        assert!(private_range(0x1000, 0x1000, |_| unreachable!()));
        for bad in [None, Some(0x1000), Some(0x800), Some(0xA000)]
        {
            let mut asks = 0;
            assert!(!private_range(0x1000, 0x9000, |_| {
                asks += 1;
                bad
            }));
            assert_eq!(asks, 1);
        }
    }
}
