// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/integration/thread_ext_regs.rs

//! Integration: a debugger reads a thread's extended register state (floating
//! point, SIMD, vector) through a Thread capability
//! (`SYS_THREAD_READ_EXT_REGS`; core/kernel/docs/syscalls.md
//! § `SYS_THREAD_READ_EXT_REGS`).
//!
//! A child loads a distinct value into each register of the file
//! (`crate::arch::fpu::load_and_spin`) and spins, counting progress. Once it
//! has progressed:
//! - a read before the child is stopped is refused (`InvalidState`), since
//!   only a thread held still has its registers in its save area;
//! - after `SYS_THREAD_STOP`, the image holds each loaded value at the offset
//!   the abi publishes for it (`crate::arch::fpu::for_each_ext_word`), each
//!   word read by its own call;
//! - the image read in [`WINDOW`]-byte calls equals it read in [`CHUNK`]-byte
//!   calls, the last of each cut short at the image's end;
//! - an offset at or past the end returns no byte, and the image's size;
//! - a length of 0 or past `MAX_THREAD_MEM_COPY` is refused
//!   (`InvalidArgument`), as is a cap without `OBSERVE`
//!   (`InsufficientRights`).

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::{
    cap_delete, cap_derive, raw_syscall4, system_info, thread_read_ext_regs, thread_sleep,
    thread_stop,
};
use syscall_abi::{
    MAX_THREAD_MEM_COPY, RIGHTS_THREAD_CONTROL, SYS_THREAD_READ_EXT_REGS, SyscallError,
    SystemInfoType,
};

use crate::spawn::SpawnedChild;
use crate::{ChildStack, TestContext, TestResult, spawn};

/// The value the child's registers are loaded from.
const PATTERN: u64 = 0x5EAF_00D5_0F7E_C0DE;

/// Bytes of each read of the window comparison: a quarter page, so the whole
/// image takes several reads on every architecture.
const WINDOW: usize = 1024;
/// Bytes of each read the windows are compared against: not a divisor of
/// [`WINDOW`], so the reads cross every window boundary.
const CHUNK: usize = 100;

/// Bound on the wait for the child to progress, in microseconds, applied
/// through [`crate::scaled_bound`]. One dispatch of the child is all it takes.
const WAIT_US: u64 = 1_000_000;

/// Spins the child has counted.
static PROGRESS: AtomicU32 = AtomicU32::new(0);

static mut CHILD_STACK: ChildStack = ChildStack::ZERO;

pub fn run(ctx: &TestContext) -> TestResult
{
    PROGRESS.store(0, Ordering::Release);
    let child = spawn::new_child(ctx)
        .map_err(|_| "integration::thread_ext_regs: spawn::new_child failed")?;
    // SAFETY: `CHILD_STACK` is a static stack, reached only through `addr_of!`.
    let stack_top = unsafe { ChildStack::top(core::ptr::addr_of!(CHILD_STACK)) };
    // SAFETY: the stack is `CHILD_STACK`, this test's own `ChildStack`, on
    // which no other live thread runs (`ChildStack`'s rule).
    let ran = unsafe { spawn::configure_and_start(&child, spin_entry, stack_top, PATTERN) }
        .and_then(|()| reads(&child));
    let released = release(child);
    ran?;
    released
}

/// The reads of the child, running and then stopped.
fn reads(child: &SpawnedChild) -> TestResult
{
    if !await_progress()?
    {
        return Err("integration::thread_ext_regs: the child did not progress");
    }
    let mut word = [0u8; 8];
    if thread_read_ext_regs(child.th, 0, &mut word) != Err(SyscallError::InvalidState as i64)
    {
        return Err("integration::thread_ext_regs: a read of a running thread was not refused");
    }
    thread_stop(child.th)
        .map_err(|_| "integration::thread_ext_regs: thread_stop of the child failed")?;
    let (_, size) = thread_read_ext_regs(child.th, 0, &mut word)
        .map_err(|_| "integration::thread_ext_regs: a read of the stopped child was refused")?;
    loaded_values(child.th, size)?;
    windows_match_chunks(child.th, size)?;
    past_end(child.th, size)?;
    refusals(child.th)
}

/// Every word [`crate::arch::fpu::for_each_ext_word`] names holds the value
/// the child loaded, each read by its own 8-byte call.
fn loaded_values(th: u64, size: u64) -> TestResult
{
    let mut failed = None;
    let held = crate::arch::fpu::for_each_ext_word(PATTERN, size, &mut |offset, mask, want| {
        let mut word = [0u8; 8];
        let got = match thread_read_ext_regs(th, offset, &mut word)
        {
            Ok((8, n)) if n == size => u64::from_le_bytes(word),
            _ =>
            {
                failed = Some(offset);
                return false;
            }
        };
        if got & mask != want
        {
            crate::log_u64("ktest: integration::thread_ext_regs offset=", offset);
            crate::log_u64("ktest: integration::thread_ext_regs got=", got);
            return false;
        }
        true
    });
    if let Some(offset) = failed
    {
        crate::log_u64("ktest: integration::thread_ext_regs offset=", offset);
        return Err("integration::thread_ext_regs: an 8-byte read inside the image was refused");
    }
    if !held
    {
        return Err("integration::thread_ext_regs: the image does not hold a loaded value");
    }
    Ok(())
}

/// The image read [`WINDOW`] bytes a call equals it read [`CHUNK`] bytes a
/// call; each call returns its length, or the bytes left before the end.
fn windows_match_chunks(th: u64, size: u64) -> TestResult
{
    let mut window = [0u8; WINDOW];
    let mut chunk = [0u8; CHUNK];
    for base in (0..size).step_by(WINDOW)
    {
        // Bytes the window read returns, and so the count of its bytes the
        // chunk reads cover.
        let want = usize::try_from(size.saturating_sub(base)).map_or(WINDOW, |n| n.min(WINDOW));
        if thread_read_ext_regs(th, base, &mut window) != Ok((want as u64, size))
        {
            return Err("integration::thread_ext_regs: a window read returned a wrong length");
        }
        for (at, offset) in (0..want).step_by(CHUNK).zip((base..).step_by(CHUNK))
        {
            let left = usize::try_from(size.saturating_sub(offset)).map_or(CHUNK, |n| n.min(CHUNK));
            if thread_read_ext_regs(th, offset, &mut chunk) != Ok((left as u64, size))
            {
                return Err("integration::thread_ext_regs: a chunk read returned a wrong length");
            }
            let n = left.min(want.saturating_sub(at));
            if window.get(at..at.saturating_add(n)) != chunk.get(..n)
            {
                crate::log_u64("ktest: integration::thread_ext_regs offset=", offset);
                return Err("integration::thread_ext_regs: chunked reads differ from window reads");
            }
        }
    }
    Ok(())
}

/// A read from the end of the image, or from the largest offset, returns no
/// byte; one that starts 4 bytes before the end returns those 4.
fn past_end(th: u64, size: u64) -> TestResult
{
    let mut word = [0u8; 8];
    if thread_read_ext_regs(th, size, &mut word) != Ok((0, size))
        || thread_read_ext_regs(th, u64::MAX, &mut word) != Ok((0, size))
    {
        return Err("integration::thread_ext_regs: a read at or past the end returned bytes");
    }
    if thread_read_ext_regs(th, size.saturating_sub(4), &mut word) != Ok((4, size))
    {
        return Err("integration::thread_ext_regs: a read across the end was not cut short");
    }
    Ok(())
}

/// Lengths of 0 and past `MAX_THREAD_MEM_COPY`, and a cap without `OBSERVE`,
/// are refused.
fn refusals(th: u64) -> TestResult
{
    let invalid = Err(SyscallError::InvalidArgument as i64);
    if thread_read_ext_regs(th, 0, &mut []) != invalid
    {
        return Err("integration::thread_ext_regs: a zero-length read was not refused");
    }
    let mut word = [0u8; 8];
    // The kernel refuses the length before it checks the buffer, so the
    // 8-byte buffer is never written past.
    // SAFETY: a refused call writes nothing; one the kernel took would write at
    // most the image's size into `word`, which is why the length is checked
    // first.
    let long = unsafe {
        raw_syscall4(
            SYS_THREAD_READ_EXT_REGS,
            th,
            0,
            word.as_mut_ptr() as u64,
            (MAX_THREAD_MEM_COPY as u64).saturating_add(1),
        )
    };
    if long != SyscallError::InvalidArgument as i64
    {
        return Err(
            "integration::thread_ext_regs: a read past MAX_THREAD_MEM_COPY was not refused",
        );
    }
    let control = cap_derive(th, RIGHTS_THREAD_CONTROL)
        .map_err(|_| "integration::thread_ext_regs: cap_derive of the thread failed")?;
    let refused = thread_read_ext_regs(control, 0, &mut word);
    cap_delete(control).ok();
    if refused != Err(SyscallError::InsufficientRights as i64)
    {
        return Err("integration::thread_ext_regs: a cap without OBSERVE was not refused");
    }
    Ok(())
}

/// Wait, for at most the scaled [`WAIT_US`], for the child to count a spin;
/// polls sleep 1 ms, so on one CPU the child runs between them. Returns
/// whether it did; a clock that cannot be read fails the wait.
fn await_progress() -> Result<bool, &'static str>
{
    let elapsed = || {
        system_info(SystemInfoType::ElapsedUs as u64)
            .map_err(|_| "integration::thread_ext_regs: system_info(ElapsedUs) failed")
    };
    let start = elapsed()?;
    let bound = crate::scaled_bound(WAIT_US);
    while PROGRESS.load(Ordering::Acquire) == 0
    {
        if elapsed()?.saturating_sub(start) > bound
        {
            return Ok(false);
        }
        let _ = thread_sleep(1);
    }
    Ok(true)
}

/// Stop the child (already stopped unless a read failed first, which the
/// `InvalidState` refusal of a second stop says), then delete its Thread
/// and `CSpace` caps.
fn release(mut child: SpawnedChild) -> TestResult
{
    let stopped = match thread_stop(child.th)
    {
        Ok(()) => true,
        Err(e) => e == SyscallError::InvalidState as i64,
    };
    let thread_deleted = child.delete_thread().is_ok();
    let cspace_deleted = child.delete_cspace().is_ok();
    if stopped && thread_deleted && cspace_deleted
    {
        Ok(())
    }
    else
    {
        Err("integration::thread_ext_regs: teardown failed")
    }
}

/// Child entry: load the registers from `pattern` and spin for ever.
extern "C" fn spin_entry(pattern: u64) -> !
{
    crate::arch::fpu::load_and_spin(pattern, &PROGRESS)
}
