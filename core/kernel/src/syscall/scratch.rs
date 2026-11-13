// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/syscall/scratch.rs

//! The per-CPU syscall scratch buffer.
//!
//! A syscall that holds kilobytes of data at once holds them here, off its
//! kernel stack, so its frame stays within the riscv64 kernel frame bound
//! (docs/coding-standards.md § Kernel Stack Frames). One buffer per CPU
//! serves every such syscall: a CPU runs one syscall at a time, and the
//! syscall runs to its return without a switch to another thread, so each
//! syscall's use of the buffer ends before the next one's begins.
//!
//! Users: `SYS_THREAD_READ_MEM` and `SYS_THREAD_WRITE_MEM` stage the bytes
//! they move ([`thread_mem`]), and `SYS_CAP_REVOKE` snapshots each batch's
//! revoked objects ([`revoke_snapshot`]).

use core::ptr::NonNull;

use crate::cap::derivation::MAX_REVOKE_EDITS;
use crate::cap::object::KernelObjectHeader;

/// One CPU's scratch buffer: the largest of its users' data, each user
/// viewing it as its own type. Every bit pattern is a valid value of every
/// field (bytes, and `Option<NonNull>`, whose all-zero pattern is `None`), so
/// a user may borrow its field whatever the previous user left there.
#[repr(C)]
union SyscallScratch
{
    /// The thread-memory syscalls' staged bytes.
    thread_mem: [u8; syscall::MAX_THREAD_MEM_COPY],
    /// `SYS_CAP_REVOKE`'s copy of one batch's revoked objects.
    revoke: [Option<NonNull<KernelObjectHeader>>; MAX_REVOKE_EDITS],
}

/// The scratch slab: one [`SyscallScratch`] per CPU.
const SCRATCH_SLAB: crate::sched::PerCpuSlab =
    crate::sched::PerCpuSlab::of::<SyscallScratch>("SYSCALL_SCRATCH");
const _: () = assert!(
    SCRATCH_SLAB.sized_at_every_width(),
    "SYSCALL_SCRATCH slab overflows"
);

/// Base of the scratch slab: `CPU_COUNT` buffers, null until [`init_storage`]
/// (Phase 4).
static SCRATCH: core::sync::atomic::AtomicPtr<SyscallScratch> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Allocate the per-CPU scratch slab. Called once, in Phase 4, before any
/// syscall.
pub fn init_storage(cpu_count: u32, allocator: &mut crate::mm::BuddyAllocator)
{
    let base = crate::sched::alloc_per_cpu_slab::<SyscallScratch>(
        SCRATCH_SLAB,
        cpu_count as usize,
        allocator,
    );
    SCRATCH.store(base, core::sync::atomic::Ordering::Release);
}

/// The calling CPU's buffer. Halts when the slab is not published or the CPU
/// index is past it, which the boot order excludes: Phase 4 allocates the
/// slab for every CPU before any syscall.
fn this_cpu() -> *mut SyscallScratch
{
    let base = SCRATCH.load(core::sync::atomic::Ordering::Acquire);
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    // CPU_COUNT is stored before the Release that publishes `base`.
    let count = crate::sched::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed) as usize;
    if base.is_null() || cpu >= count
    {
        crate::fatal("syscall scratch: no buffer for this CPU");
    }
    // In bounds: cpu < CPU_COUNT, and the slab holds CPU_COUNT buffers.
    base.wrapping_add(cpu)
}

/// The calling CPU's buffer as the thread-memory syscalls' staging bytes.
///
/// # Safety
/// The caller is a syscall handler, holds the returned reference only until
/// it returns, and takes no other view of the buffer while it lives. Between
/// taking it and returning, the handler must not park, yield or schedule:
/// then nothing else on this CPU uses the buffer meanwhile, and the CPU stays
/// this one. A syscall runs with interrupts masked, or open only in an
/// interrupt window with preemption disabled, and no interrupt handler uses
/// the buffer.
pub unsafe fn thread_mem() -> &'static mut [u8; syscall::MAX_THREAD_MEM_COPY]
{
    let scratch = this_cpu();
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "the dereference and the union field access name one place, this CPU's \
                  buffer, under the one contract"
    )]
    // SAFETY: `scratch` is this CPU's buffer, never freed; every bit pattern
    // is valid for the field (`SyscallScratch`); the caller's contract makes this the
    // only reference to the buffer while it lives.
    unsafe {
        &mut (*scratch).thread_mem
    }
}

/// The calling CPU's buffer as `SYS_CAP_REVOKE`'s snapshot of one batch's
/// revoked objects.
///
/// # Safety
/// As for [`thread_mem`].
pub unsafe fn revoke_snapshot()
-> &'static mut [Option<NonNull<KernelObjectHeader>>; MAX_REVOKE_EDITS]
{
    let scratch = this_cpu();
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "the dereference and the union field access name one place, this CPU's \
                  buffer, under the one contract"
    )]
    // SAFETY: as in `thread_mem`.
    unsafe {
        &mut (*scratch).revoke
    }
}
