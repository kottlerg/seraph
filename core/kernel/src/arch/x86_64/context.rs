// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/context.rs

//! x86-64 thread context management.
//!
//! `SavedState` holds the kernel-mode callee-saved register set for one thread.
//! `new_state` constructs the initial state for a new thread.
//!
//! `switch` saves the current thread's callee-saved registers to `*current`
//! and restores them from `*next`, then jumps to `next.rip`.
//!
//! `return_to_user` builds an `iretq` frame from a [`TrapFrame`] on the
//! current kernel stack and transitions to ring-3 user mode.

// ── SavedState ────────────────────────────────────────────────────────────────

/// Kernel-mode callee-saved register state for one thread.
///
/// On each context switch only this minimal set is saved/restored (see
/// `docs/scheduler.md` — "What Gets Saved and Restored"). Caller-saved
/// registers are the calling code's responsibility per the System V AMD64 ABI.
///
/// ## Field offsets (used by assembly in `switch`)
///
/// | Offset | Field   |
/// |--------|---------|
/// |  0     | rip     |
/// |  8     | rsp     |
/// | 16     | rbx     |
/// | 24     | rbp     |
/// | 32     | r12     |
/// | 40     | r13     |
/// | 48     | r14     |
/// | 56     | r15     |
/// | 64     | fs_base |
/// | 72     | rflags  |
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct SavedState
{
    /// Instruction pointer — where execution resumes after `switch` returns.
    pub rip: u64,
    /// Stack pointer.
    pub rsp: u64,
    /// Callee-saved general-purpose registers.
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// FS.base MSR — per-thread TLS pointer (0 for kernel threads).
    pub fs_base: u64,
    /// RFLAGS at the moment of the switch.
    pub rflags: u64,
}

impl SavedState
{
    /// Return the thread's resume instruction pointer.
    ///
    /// For a newly created thread this is the entry function address; for a
    /// resumed thread it is the return address from the previous `switch` call.
    pub fn entry_point(&self) -> u64
    {
        self.rip
    }

    /// Return the initial user-mode argument stored at thread creation.
    ///
    /// `new_state` stashes `arg` in `rbx`; `sched::enter` reads it back here
    /// and forwards it to the user-mode `TrapFrame` via `set_arg0`.
    pub fn user_arg(&self) -> u64
    {
        self.rbx
    }
}

/// Seed the initial TLS base for a thread being configured.
///
/// x86-64 carries the canonical per-thread TLS pointer in
/// `SavedState.fs_base`. The first `switch()` into this thread loads the
/// value into `IA32_FS_BASE` via `wrmsr` before jumping to the user-thread
/// trampoline; subsequent switches `rdmsr` the live MSR on save and `wrmsr`
/// on restore.
#[inline]
pub fn seed_tls_base(saved: &mut SavedState, tls_base: u64)
{
    saved.fs_base = tls_base;
}

// ── new_state ─────────────────────────────────────────────────────────────────

/// Construct the initial [`SavedState`] for a new thread.
///
/// `entry`     — virtual address of the thread's entry function.
/// `stack_top` — top of the thread's kernel stack (RSP starts here).
/// `arg`       — first argument; stashed in `rbx` (delivered to entry by
///               the switch stub when the thread first runs).
/// `is_user`   — unused at construction; user-mode entry uses `return_to_user`.
pub fn new_state(entry: u64, stack_top: u64, arg: u64, _is_user: bool) -> SavedState
{
    SavedState {
        rip: entry,
        rsp: stack_top,
        rbx: arg,      // carried to entry via rbx; idle ignores it
        rflags: 0x200, // IF=1 so timer can fire once thread starts
        ..SavedState::default()
    }
}

// ── switch ────────────────────────────────────────────────────────────────────

/// Save the current thread's kernel registers to `*current` and restore
/// the next thread's registers from `*next`, then jump to `next.rip`.
///
/// For a thread's first run, `next.rip` is its entry function; for a resumed
/// thread, `next.rip` is the return address of the previous `switch` call.
///
/// # Safety
/// Both pointers must be valid, aligned `SavedState` values. The caller must
/// hold the scheduler lock and have interrupts disabled. `save_flag` and
/// `lock_ptr` are used on RISC-V to release the lock between save/load;
/// on x86-64 (TSO) the lock is released inline before the call and these
/// parameters are ignored.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn switch(
    current: *mut SavedState,
    next: *const SavedState,
    _save_flag: *const core::sync::atomic::AtomicU32,
    _lock_ptr: *const crate::sync::Spinlock,
)
{
    // rdi = current, rsi = next, rdx = save_flag (unused), rcx = lock_ptr (unused)
    core::arch::naked_asm!(
        // ── Save current thread ───────────────────────────────────────────
        // Pop return address into rax; the caller will "return" to it when this
        // thread is resumed. This is the standard rip-via-ret trick.
        "pop rax",
        "mov [rdi + 0],  rax", // rip  = return address
        "mov [rdi + 8],  rsp", // rsp  (after pop; matches what restore expects)
        "mov [rdi + 16], rbx",
        "mov [rdi + 24], rbp",
        "mov [rdi + 32], r12",
        "mov [rdi + 40], r13",
        "mov [rdi + 48], r14",
        "mov [rdi + 56], r15",
        // rflags
        "pushfq",
        "pop rax",
        "mov [rdi + 72], rax",
        // ── Signal save complete + release lock ───────────────────────────
        // On x86-64 TSO, stores are globally visible in program order and
        // the lock was released by release_lock_only() before the call.
        // Set the context_saved flag for cross-arch consistency. Do this
        // BEFORE the rdmsr below, which clobbers rdx (the save_flag ptr).
        "test rdx, rdx",
        "jz 1f",
        "mov dword ptr [rdx], 1", // *save_flag = 1 (TSO: implicitly ordered)
        "1:",
        // fs_base: read the currently-live user TLS base from IA32_FS_BASE
        // (MSR 0xc0000100). rdmsr returns high 32 bits in edx, low 32 in
        // eax; combine into rax. Clobbers rcx/rdx/rax (all caller-saved,
        // and rdx/save_flag is no longer needed at this point).
        "mov ecx, 0xc0000100",
        "rdmsr",
        "shl rdx, 32",
        "or  rax, rdx",
        "mov [rdi + 64], rax",
        // ── Restore next thread ───────────────────────────────────────────
        // Restore rflags first so the restored flags take effect early.
        "mov rax, [rsi + 72]",
        "push rax",
        "popfq",
        // Restore fs_base into IA32_FS_BASE before any register the wrmsr
        // clobbers (rcx/rdx/rax) is finalised for the jump.
        "mov rax, [rsi + 64]",
        "mov rdx, rax",
        "shr rdx, 32", // edx = high 32 bits
        "mov ecx, 0xc0000100",
        "wrmsr", // IA32_FS_BASE = next.fs_base
        "mov r15, [rsi + 56]",
        "mov r14, [rsi + 48]",
        "mov r13, [rsi + 40]",
        "mov r12, [rsi + 32]",
        "mov rbp, [rsi + 24]",
        "mov rbx, [rsi + 16]",
        "mov rsp, [rsi + 8]", // restore stack pointer
        "mov rax, [rsi + 0]", // rip (jump target)
        "jmp rax",            // jump to next thread's rip
    );
}

// ── return_to_user ────────────────────────────────────────────────────────────

/// Restore full user register state from `tf` and enter ring-3 via `iretq`.
///
/// Builds an iretq frame (SS / RSP / RFLAGS / CS / RIP) on the current
/// kernel stack from the corresponding `tf` fields, restores all GPRs, then
/// executes `iretq`. Never returns.
///
/// Call sequence for first user-mode entry:
/// 1. Set TSS RSP0 to init's `kernel_stack_top` (via `gdt::set_rsp0`).
/// 2. Set `SYSCALL_KERNEL_RSP` to init's `kernel_stack_top`.
/// 3. Build a zeroed [`TrapFrame`] on init's kernel stack with the desired
///    `rip`, `rsp` (user stack top), `cs`, `ss`, and `rflags`.
/// 4. Call `return_to_user(tf_ptr)`.
///
/// # Safety
/// `tf` must point to a valid [`TrapFrame`] on the kernel stack for the
/// thread being activated. TSS RSP0 must already be set correctly.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn return_to_user(tf: *const super::trap_frame::TrapFrame) -> !
{
    // rdi = tf (*const TrapFrame)
    // TrapFrame field offsets (from trap_frame.rs):
    //   rax=0, rbx=8, rcx=16, rdx=24, rsi=32, rdi=40, rbp=48,
    //   r8=56, r9=64, r10=72, r11=80, r12=88, r13=96, r14=104, r15=112,
    //   rip=120, rflags=128, rsp=136, cs=144, ss=152, fs_base=160
    core::arch::naked_asm!(
        // Switch RSP to just below the TrapFrame before building the iretq
        // frame. This is necessary because:
        //
        // 1. The caller's RSP may point to the boot stack (identity-mapped in
        //    the kernel's lower PML4 half, not copied into user address spaces).
        //    After activate() switches CR3, that stack is inaccessible.
        //
        // 2. If RSP were near kernel_stack_top (above the TrapFrame), the five
        //    pushes below would overwrite TrapFrame fields before they are read
        //    (e.g., the CS field at kst-24 gets clobbered by the RSP push).
        //
        // Setting RSP = tf_ptr (= rdi) places the iretq frame at
        // [tf_ptr-40, tf_ptr-1], entirely below the TrapFrame, which is safe
        // because the TrapFrame occupies [tf_ptr, tf_ptr+167].
        // tf_ptr is on init's kernel stack (direct map), accessible after CR3.
        "lea rsp, [rdi]",
        // Build the iretq frame on the current kernel stack.
        // iretq pops (low → high address): RIP, CS, RFLAGS, RSP, SS.
        // We push in reverse order: SS first, RIP last.
        "mov rax, [rdi + 152]", // ss
        "push rax",
        "mov rax, [rdi + 136]", // rsp (user stack)
        "push rax",
        "mov rax, [rdi + 128]", // rflags
        "push rax",
        "mov rax, [rdi + 144]", // cs
        "push rax",
        "mov rax, [rdi + 120]", // rip (user entry point)
        "push rax",
        // Restore GPRs from TrapFrame (rdi restored last).
        "mov rax, [rdi + 0]",
        "mov rbx, [rdi + 8]",
        "mov rcx, [rdi + 16]",
        "mov rdx, [rdi + 24]",
        "mov rsi, [rdi + 32]",
        "mov rbp, [rdi + 48]",
        "mov r8,  [rdi + 56]",
        "mov r9,  [rdi + 64]",
        "mov r10, [rdi + 72]",
        "mov r11, [rdi + 80]",
        "mov r12, [rdi + 88]",
        "mov r13, [rdi + 96]",
        "mov r14, [rdi + 104]",
        "mov r15, [rdi + 112]",
        "mov rdi, [rdi + 40]", // restore rdi last (was TrapFrame pointer)
        "iretq",
    );
}

// ── first_entry_to_user ───────────────────────────────────────────────────────

/// Switch to a new address space and enter user mode for the first time.
///
/// Architecture-neutral entry point for `sched::enter`. On x86-64 this
/// delegates to [`switch_and_enter_user`], which atomically switches CR3 and
/// discards the boot stack before executing `iretq`.
///
/// # Safety
/// Same contract as [`switch_and_enter_user`]: TSS RSP0 and
/// `SYSCALL_KERNEL_RSP` must already be set to init's `kernel_stack_top`.
#[cfg(not(test))]
pub unsafe fn first_entry_to_user(root_phys: u64, tf: *const super::trap_frame::TrapFrame) -> !
{
    // SAFETY: caller guarantees root_phys and tf satisfy switch_and_enter_user contract;
    // TSS RSP0 and SYSCALL_KERNEL_RSP already set.
    unsafe { switch_and_enter_user(root_phys, tf) }
}

// ── switch_and_enter_user ─────────────────────────────────────────────────────

/// Atomically switch page tables and enter user mode for the first time.
///
/// Performs the CR3 write and the boot-stack-to-kernel-stack switch as a
/// single uninterruptible sequence so no Rust call/return occurs on the boot
/// stack after CR3 is written. Doing these as separate Rust calls would cause
/// a page fault when `activate()` tries to `ret` (the boot stack's identity
/// mapping lives in PML4 entry 0–255, which is not copied into user address
/// spaces).
///
/// # Parameters
/// - `root_phys` (rdi): physical address of init's PML4 root.
/// - `tf` (rsi): pointer to the zeroed-and-filled [`TrapFrame`] on init's
///   kernel stack (at `kernel_stack_top - sizeof(TrapFrame)`).
///
/// # Safety
/// - `root_phys` must be the physical address of a valid 4 KiB-aligned PML4
///   that maps the kernel upper half (entries 256–511) and the direct map.
/// - `tf` must point to a `TrapFrame` on the direct-mapped init kernel stack,
///   with `rip`, `rsp`, `cs`, `ss`, and `rflags` set for user-mode entry.
/// - TSS RSP0 and `SYSCALL_KERNEL_RSP` must be set to init's `kernel_stack_top`
///   before this call.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn switch_and_enter_user(
    root_phys: u64,
    tf: *const super::trap_frame::TrapFrame,
) -> !
{
    // rdi = root_phys, rsi = tf (*const TrapFrame)
    // TrapFrame field offsets (from trap_frame.rs):
    //   rax=0, rbx=8, rcx=16, rdx=24, rsi=32, rdi=40, rbp=48,
    //   r8=56, r9=64, r10=72, r11=80, r12=88, r13=96, r14=104, r15=112,
    //   rip=120, rflags=128, rsp=136, cs=144, ss=152, fs_base=160
    core::arch::naked_asm!(
        // 1. Switch RSP to just below the TrapFrame on init's kernel stack.
        //    Must happen BEFORE the CR3 write so the RSP is in the direct map
        //    (accessible from init's page tables) when we next need the stack.
        //    iretq frame (5 × 8 = 40 bytes) will sit at [rsi-40, rsi-1].
        "mov rsp, rsi",
        // 2. Switch page tables.  After this instruction the boot stack's
        //    identity mapping is gone; RSP now points to the direct-mapped init
        //    kernel stack, which is covered by the copied kernel-upper entries.
        "mov cr3, rdi",
        // 3. Build iretq frame below TrapFrame (RSP = tf_ptr = rsi).
        //    iretq pops (low → high address): RIP, CS, RFLAGS, RSP, SS.
        "mov rax, [rsi + 152]",
        "push rax", // ss
        "mov rax, [rsi + 136]",
        "push rax", // rsp (user stack)
        "mov rax, [rsi + 128]",
        "push rax", // rflags
        "mov rax, [rsi + 144]",
        "push rax", // cs
        "mov rax, [rsi + 120]",
        "push rax", // rip (user entry point)
        // 4. Restore GPRs from TrapFrame (rsi and rdi restored last).
        "mov rax, [rsi + 0]",
        "mov rbx, [rsi + 8]",
        "mov rcx, [rsi + 16]",
        "mov rdx, [rsi + 24]",
        "mov rbp, [rsi + 48]",
        "mov r8,  [rsi + 56]",
        "mov r9,  [rsi + 64]",
        "mov r10, [rsi + 72]",
        "mov r11, [rsi + 80]",
        "mov r12, [rsi + 88]",
        "mov r13, [rsi + 96]",
        "mov r14, [rsi + 104]",
        "mov r15, [rsi + 112]",
        "mov rdi, [rsi + 40]", // restore rdi before rsi
        "mov rsi, [rsi + 32]", // restore rsi last (was TrapFrame pointer)
        "iretq",
    );
}
