// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/spawn.rs

//! Child-thread spawn helper.
//!
//! Most ktest scenarios spawn a child thread in a fresh `CSpace`, copy one
//! or two caps into that `CSpace`, then configure-and-start the thread. The
//! `cap_create_cspace + cap_create_thread + thread_configure + thread_start`
//! plumbing is mechanical and identical across most of those sites. This module
//! wraps it so each test reads as scenario, not boilerplate.
//!
//! Use [`new_child`] to mint the (`CSpace`, Thread) pair, do any `cap_copy`
//! calls into `child.cs`, then call [`configure_and_start`] (or
//! [`configure_and_start_pinned`] for an affinity-bound child) to launch.
//!
//! # Child arguments
//!
//! A child entry receives one `u64` register argument. A capability handle
//! is 32 bits (a 24-bit slot index plus an 8-bit generation, see
//! `syscall_abi::cap_handle_encode`), so at most two fit in that word, as
//! 32-bit halves (`u64::from(a) | (u64::from(b) << 32)`). A child that
//! needs more than two values receives the address of an entry in a
//! per-test [`ArgBlock`] instead, and decodes it with [`child_args`].
//! Narrower packings truncate the generation and alias a recycled slot.

use core::cell::UnsafeCell;

use syscall::{
    cap_create_cspace, cap_create_thread, thread_configure, thread_set_affinity, thread_start,
};

use crate::TestContext;

/// Static argument entries handed to child entries by address.
///
/// Each test that needs one declares its own block (as it does for
/// `ChildStack`), sized to the number of children it runs concurrently,
/// fills an entry with [`publish`](Self::publish) before starting that child,
/// and the child reads it back with [`child_args`]. The block lives in the
/// test's own image, and every ktest child runs in the test's address space,
/// so the address is valid in the child. The write is ordered before the
/// child's first instruction by the start syscall's scheduler locks.
pub struct ArgBlock<T, const N: usize>(UnsafeCell<[T; N]>);

// SAFETY: entries are written only through `publish`, whose contract makes
// each write exclusive with any child reading that entry; `T: Send` because
// the child receives the value on another thread.
unsafe impl<T: Send, const N: usize> Sync for ArgBlock<T, N> {}

impl<T: Copy, const N: usize> ArgBlock<T, N>
{
    /// A block with every entry set to `init`.
    pub const fn new(init: T) -> Self
    {
        Self(UnsafeCell::new([init; N]))
    }

    /// Store `value` in entry `index` and return its address, the value to
    /// pass as the child's argument.
    ///
    /// # Safety
    ///
    /// `index < N`, and no child may be reading entry `index`: publish
    /// before the start, and reuse an entry only after its previous child
    /// has exited.
    pub unsafe fn publish(&self, index: usize, value: T) -> u64
    {
        debug_assert!(index < N, "ArgBlock::publish: index out of range");
        // SAFETY: index < N; exclusive access per the caller contract.
        unsafe {
            let entry = self.0.get().cast::<T>().add(index);
            entry.write(value);
            entry as u64
        }
    }
}

/// Decode a child argument published with [`ArgBlock::publish`].
///
/// # Safety
///
/// `arg` must be the value returned by `publish` on an `ArgBlock<T, _>`,
/// and the parent must not have rewritten that entry since.
pub unsafe fn child_args<T: Copy>(arg: u64) -> T
{
    // SAFETY: caller contract; the entry outlives the child (static).
    unsafe { *(arg as *const T) }
}

/// Child-thread handle returned by [`new_child`].
///
/// Caller is responsible for deleting both caps when the child has exited
/// (typically via `notification_wait`-based handshake). Either order is
/// safe: deleting `cs` first stops a still-live child
/// (`core/kernel/docs/scheduling-internals.md` § Thread Registry); deleting `th`
/// first is the tidy order, since the exited thread's object goes at once.
pub struct SpawnedChild
{
    pub th: u32,
    pub cs: u32,
}

/// Mint a new (`CSpace`, Thread) pair both bound to the test's address
/// space. The thread is created at the floor priority (`PRIORITY_MIN`) and
/// is not configured or started yet — the caller performs any required
/// `cap_copy` into `child.cs` first. Tests that need the child at a
/// specific level use [`new_child_at`].
pub fn new_child(ctx: &TestContext) -> Result<SpawnedChild, &'static str>
{
    new_child_at(ctx, 0, 0)
}

/// Like [`new_child`] but creates the thread at `priority` under
/// `sched_cap`'s band (the `sched_cap`/`priority` rules are in
/// `core/kernel/docs/syscalls.md` § `SYS_CAP_CREATE_THREAD`).
pub fn new_child_at(
    ctx: &TestContext,
    sched_cap: u32,
    priority: u8,
) -> Result<SpawnedChild, &'static str>
{
    // cap_create_cspace(memory, augment_target=0, init_pages=4) — 3 pool
    // pages back 167 usable slots, ample for tests that copy a few caps
    // into the child. Tests needing a specific pool shape (e.g. the
    // exhaustion fixtures in unit/ipc.rs seed a single pool page) bypass
    // this helper and call cap_create_cspace directly.
    let cs = cap_create_cspace(ctx.memory_base, 0, 4)
        .map_err(|_| "spawn::new_child: cap_create_cspace failed")?;
    let th = cap_create_thread(ctx.memory_base, ctx.aspace_cap, cs, sched_cap, priority)
        .map_err(|_| "spawn::new_child: cap_create_thread failed")?;
    Ok(SpawnedChild { th, cs })
}

/// Configure `child` to enter `entry(arg)` on `stack_top` and start it.
///
/// `entry` is an `extern "C" fn(u64) -> !`, whose address is the entry point
/// passed to `thread_configure`: the kernel enters a thread with its argument
/// in the platform C convention's first argument register, so the entry must
/// use that convention, not the unspecified Rust ABI.
///
/// # Safety
/// `stack_top` must top a stack (a `ChildStack`, as `ChildStack::top` gives
/// it) that no other live thread uses and none will until this child exits:
/// every ktest child runs in ktest's own address space, so this is the
/// contract of `syscall::thread_configure` (the entry ABI holds by `entry`'s
/// type).
pub unsafe fn configure_and_start(
    child: &SpawnedChild,
    entry: extern "C" fn(u64) -> !,
    stack_top: u64,
    arg: u64,
) -> Result<(), &'static str>
{
    // SAFETY: `entry` is an `extern "C" fn(u64) -> !` and the caller's
    // contract dedicates `stack_top`'s stack to this child.
    unsafe { thread_configure(child.th, entry as *const () as u64, stack_top, arg) }
        .map_err(|_| "spawn::configure_and_start: thread_configure failed")?;
    thread_start(child.th).map_err(|_| "spawn::configure_and_start: thread_start failed")?;
    Ok(())
}

/// Like [`configure_and_start`] but pins the child to `cpu` via
/// `thread_set_affinity` before starting it.
///
/// # Safety
/// The contract of [`configure_and_start`].
pub unsafe fn configure_and_start_pinned(
    child: &SpawnedChild,
    entry: extern "C" fn(u64) -> !,
    stack_top: u64,
    arg: u64,
    cpu: u32,
) -> Result<(), &'static str>
{
    // SAFETY: `entry` is an `extern "C" fn(u64) -> !` and the caller's
    // contract dedicates `stack_top`'s stack to this child.
    unsafe { thread_configure(child.th, entry as *const () as u64, stack_top, arg) }
        .map_err(|_| "spawn::configure_and_start_pinned: thread_configure failed")?;
    thread_set_affinity(child.th, cpu)
        .map_err(|_| "spawn::configure_and_start_pinned: thread_set_affinity failed")?;
    thread_start(child.th).map_err(|_| "spawn::configure_and_start_pinned: thread_start failed")?;
    Ok(())
}

/// Point the register file `regs`, read from a stopped or fault-blocked
/// child, at the `extern "C"` entry at `entry`: the instruction pointer
/// becomes `entry` and the stack pointer moves down, on the child's own stack,
/// to the alignment the entry ABI expects (`arch::entry_stack_pointer`). A
/// child resumed with the frame then runs `entry` as if called, with the
/// frame's other registers as its arguments.
///
/// Panics if `regs` is shorter than the register file.
pub fn redirect_to_entry(regs: &mut [u8], entry: u64)
{
    use crate::arch::{IP_OFFSET, SP_OFFSET, entry_stack_pointer};
    let sp = u64::from_le_bytes(
        regs[SP_OFFSET..SP_OFFSET + 8]
            .try_into()
            .unwrap_or([0u8; 8]),
    );
    regs[SP_OFFSET..SP_OFFSET + 8].copy_from_slice(&entry_stack_pointer(sp).to_le_bytes());
    regs[IP_OFFSET..IP_OFFSET + 8].copy_from_slice(&entry.to_le_bytes());
}

/// One `cap_info(CAP_INFO_THREAD_STATE)` on `thread`, decoded into its
/// `(state, exit_reason)` pair: the `THREAD_STATE_*` code from the high word
/// and the retained exit reason from the low word, read together under one
/// scheduler-lock snapshot so the pair is coherent.
///
/// `cap_info` checks no right, so the only refusal is a handle that does
/// not name a live Thread cap in the caller's `CSpace`: an empty or stale
/// slot, or a cap of another type.
fn thread_state(thread: u32) -> Result<(u32, u64), &'static str>
{
    let packed = syscall::cap_info(thread, syscall_abi::CAP_INFO_THREAD_STATE)
        .map_err(|_| "spawn::thread_state: cap_info(THREAD_STATE) failed")?;
    let state = (packed >> 32) as u32;
    Ok((state, packed & 0xFFFF_FFFF))
}

/// One-shot probe: whether `thread` reports `Exited` in its
/// `CAP_INFO_THREAD_STATE`. One syscall; a test that must also read the exit
/// reason uses [`wait_until_exited`], which does not re-query.
///
/// # Errors
///
/// `cap_info` refused `thread`: the handle names no live Thread cap in the
/// caller's `CSpace` (an empty or stale slot, or a cap of another type).
/// `cap_info` checks no right, so any Thread cap suffices.
pub fn is_exited(thread: u32) -> Result<bool, &'static str>
{
    let (state, _) = thread_state(thread)?;
    Ok(state == syscall_abi::THREAD_STATE_EXITED)
}

/// Poll `thread` at 1 ms intervals until it reports `Exited`; returns its
/// retained exit reason, the low word of the same `CAP_INFO_THREAD_STATE`
/// snapshot that reported the state, so the exit path makes one syscall.
///
/// # Errors
///
/// - `cap_info` refused `thread`: the handle names no live Thread cap in
///   the caller's `CSpace` (an empty or stale slot, or a cap of another
///   type). `cap_info` checks no right, so any Thread cap suffices.
/// - `thread` was not `Exited` after `max_polls` polls (about `max_polls`
///   ms, one `thread_sleep(1)` between polls); the bound a test relies on to
///   fail instead of hang when its child never dies.
pub fn wait_until_exited(thread: u32, max_polls: u32) -> Result<u64, &'static str>
{
    let mut polls = 0;
    loop
    {
        let (state, reason) = thread_state(thread)?;
        if state == syscall_abi::THREAD_STATE_EXITED
        {
            return Ok(reason);
        }
        polls += 1;
        if polls >= max_polls
        {
            return Err("spawn::wait_until_exited: thread never reached Exited");
        }
        syscall::thread_sleep(1).ok();
    }
}

/// Poll `memory`'s `MEMORY_AVAILABLE` at 1 ms intervals until it returns to
/// `baseline` — for objects whose free is deferred off-CPU (a thread that
/// destroyed its own `CSpace` or `AddressSpace`). Fails after `max_polls`.
pub fn wait_memory_baseline(memory: u32, baseline: u64, max_polls: u32)
-> Result<(), &'static str>
{
    let mut polls = 0;
    loop
    {
        let now = syscall::cap_info(memory, syscall_abi::CAP_INFO_MEMORY_AVAILABLE)
            .map_err(|_| "spawn::wait_memory_baseline: cap_info(MEMORY_AVAILABLE) failed")?;
        if now == baseline
        {
            return Ok(());
        }
        polls += 1;
        if polls >= max_polls
        {
            return Err("spawn::wait_memory_baseline: memory did not return to baseline");
        }
        syscall::thread_sleep(1).ok();
    }
}
