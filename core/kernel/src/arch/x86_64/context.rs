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

/// Round a user-supplied stack pointer to the ABI alignment expected at an
/// `extern "C"` entry point. On x86-64 `SysV`, `rsp` ≡ 8 (mod 16) at function
/// entry — the 8 accounts for the return address a normal `call` would have
/// pushed — so the first 16-byte-aligned SSE/AVX access in the callee (e.g. a
/// compiler-emitted `vmovaps (%rsp)`) does not `#GP`.
#[inline]
pub fn align_initial_stack(sp: u64) -> u64
{
    (sp & !0xF).wrapping_sub(8)
}

// ── new_state ─────────────────────────────────────────────────────────────────

/// Construct the initial [`SavedState`] for a new thread.
///
/// `entry`     — virtual address of the thread's entry function.
/// `stack_top` — top of the thread's kernel stack (RSP starts here).
/// `arg`       — first argument; stashed in `rbx` (delivered to entry by
///               the switch stub when the thread first runs).
/// `is_user`   — selects the initial RFLAGS (interrupt-enable) for the first
///               dispatch; see below.
pub fn new_state(entry: u64, stack_top: u64, arg: u64, is_user: bool) -> SavedState
{
    // A user thread's first dispatch runs `user_thread_trampoline` →
    // `return_to_user` in ring 0; its `iretq` restores the user RFLAGS (IF=1,
    // set by `init_user` = 0x202) from the TrapFrame. The kernel-side
    // trampoline itself MUST run with IF=0: with IF=1 a timer can preempt the
    // half-built trampoline frame deep on the kstack, and the convoluted
    // resume path corrupts a return address → kernel `#PF` at RIP=0 (#160).
    // RISC-V already runs this trampoline with SIE masked; this matches it.
    // Kernel threads (idle) have no trampoline and need IF=1 to wake from `hlt`.
    let rflags = if is_user { 0x002 } else { 0x200 };
    SavedState {
        rip: entry,
        rsp: stack_top,
        rbx: arg, // carried to entry via rbx; idle ignores it
        rflags,
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
/// Both pointers must be valid, aligned `SavedState` values. The caller
/// must have already released the scheduler lock (`schedule()` calls
/// `sched.lock.release_lock_only()` before invoking `switch()`) and must
/// have interrupts disabled. `save_flag` is written to `1` after every
/// store into `*current` completes — it is the cross-CPU publication
/// barrier for both remote dispatch (which loads `next.saved_state` after
/// observing the flag) and `dealloc_object(Thread)` (which spins on it
/// before `retype_free`). See `core/kernel/docs/scheduling-internals.md`
/// § Cross-CPU TCB Ownership.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn switch(
    current: *mut SavedState,
    next: *const SavedState,
    save_flag: *const core::sync::atomic::AtomicU32,
)
{
    // rdi = current, rsi = next, rdx = save_flag
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
        // ── Save fs_base ──────────────────────────────────────────────────
        // saved_state.fs_base (offset 64) is the last save-side field
        // written. rdmsr clobbers rdx (which carries the save_flag
        // pointer), so we stash it in r11 (caller-saved per System V
        // AMD64; not part of SavedState). The `context_saved = 1`
        // publication and the `popfq` that re-enables interrupts are
        // both delayed until after the rsp swap (see #117 ordering note
        // below in the restore phase).
        "mov r11, rdx", // r11 = save_flag (rdx clobbered by rdmsr)
        // fs_base: read the currently-live user TLS base from IA32_FS_BASE
        // (MSR 0xc0000100). rdmsr returns high 32 bits in edx, low 32 in
        // eax; combine into rax.
        "mov ecx, 0xc0000100",
        "rdmsr",
        "shl rdx, 32",
        "or  rax, rdx",
        "mov [rdi + 64], rax", // saved_state.fs_base
        // ── Restore next thread ───────────────────────────────────────────
        // #117 ordering invariant: `context_saved = 1` AND `popfq` (which
        // restores `next.rflags`, re-enabling IF if the next thread had
        // IF=1) must BOTH happen AFTER `mov rsp, [rsi + 8]`. Doing either
        // earlier opens a fatal window:
        //   (a) `popfq` before the rsp swap re-enables interrupts while
        //       this CPU is still on the OUTGOING thread's kernel stack,
        //       so any trap taken here pushes its iretq frame to the
        //       outgoing kstack.
        //   (b) Publishing `current.context_saved = 1` before the rsp
        //       swap makes the outgoing TCB visible to peer CPUs as
        //       "safe to dispatch" while this CPU is still using its
        //       kstack. A peer that dispatches `current` will execute
        //       its own `mov rsp, [rsi + 8]` onto the same outgoing
        //       kstack — two CPUs sharing a kstack.
        // Together (a) and (b) let a peer overwrite the iretq frame the
        // trap in (a) pushed, so iretq on this CPU returns to a wild RIP
        // — observed in stress::concurrent_ipc as a kernel #PF at RIP=0.
        // Keep the publication and `popfq` below the rsp swap.
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
        "mov rsp, [rsi + 8]", // restore stack pointer — now on next's kstack
        // Publish context_saved = 1 only AFTER the rsp swap (see ordering
        // note above). The null check covers the boot path where
        // save_flag is null (initial entry).
        "test r11, r11",
        "jz 1f",
        "mov dword ptr [r11], 1", // *save_flag = 1
        "1:",
        // Restore rflags (may re-enable IF). Doing this AFTER the rsp
        // swap means an interrupt taken between popfq and `jmp rax`
        // pushes its iretq frame to next's kstack, not the outgoing one.
        "mov rax, [rsi + 72]",
        "push rax",
        "popfq",
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

/// Switch to a new (tagged) address space and enter user mode for the first
/// time.
///
/// Architecture-neutral entry point for `sched::enter`. The CR3 write happens
/// inside the naked [`switch_and_enter_user`] because the boot stack (identity-
/// mapped, PML4 0–255) vanishes after the switch, so `AddressSpace::activate`
/// cannot run between the CR3 write and `iretq` — its `ret` would fault on the
/// gone boot stack. Instead this does the tagged bookkeeping (claim a tag,
/// record the per-CPU sync) in Rust here, on the still-mapped boot stack, then
/// hands the composed CR3 value (root | PCID) to the naked switch. With tagging
/// disabled it passes the bare root (a full-flush CR3 load).
///
/// # Safety
/// `aspace` must be a valid `AddressSpace` already marked active on this CPU.
/// Otherwise the [`switch_and_enter_user`] contract: TSS RSP0 and
/// `SYSCALL_KERNEL_RSP` must already be set to init's `kernel_stack_top`.
///
/// [`AddressSpace::activate`]: crate::mm::address_space::AddressSpace::activate
#[cfg(not(test))]
pub unsafe fn first_entry_to_user(
    aspace: *const crate::mm::address_space::AddressSpace,
    tf: *const super::trap_frame::TrapFrame,
) -> !
{
    use core::sync::atomic::Ordering;

    // SAFETY: aspace is a valid AddressSpace (caller's contract).
    let root = unsafe { (*aspace).root_phys };
    let cr3 = if crate::mm::tag_allocator::tagging_enabled()
    {
        // Claim init's tag and record this CPU's sync for it. The CR3 write in
        // switch_and_enter_user has bit 63 clear, so it flushes PCID `tag`
        // (correct for the first use of the tag), and the recorded sync makes
        // init's next activate elide.
        // SAFETY: tagging enabled; aspace is active on this CPU (the scheduler
        // marked it), so it cannot be its own eviction victim; the per-CPU slab
        // is initialised and cpu/tag are in range.
        let tag = crate::mm::tag_allocator::claim(unsafe { &*aspace });
        let cpu = super::cpu::current_cpu() as usize;
        // SAFETY: see above.
        unsafe {
            let tag_gen = (*aspace).tag_gen.load(Ordering::Acquire);
            let tlb_gen = (*aspace).tlb_gen.load(Ordering::Acquire);
            crate::mm::tag_allocator::set_tag_state(cpu, tag, tag_gen, tlb_gen);
        }
        root | u64::from(tag)
    }
    else
    {
        root
    };

    // SAFETY: cr3 is a valid CR3 value (PML4 root + optional PCID, bit 63 clear);
    // tf satisfies switch_and_enter_user's contract; TSS RSP0 / SYSCALL_KERNEL_RSP set.
    unsafe { switch_and_enter_user(cr3, tf) }
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
/// - `cr3` (rdi): the CR3 value to load — init's PML4 root, optionally OR'd with
///   a PCID in bits \[11:0\] (bit 63 clear, so the load flushes that PCID).
/// - `tf` (rsi): pointer to the zeroed-and-filled [`TrapFrame`] on init's
///   kernel stack (at `kernel_stack_top - sizeof(TrapFrame)`).
///
/// # Safety
/// - `cr3` must encode a valid 4 KiB-aligned PML4 that maps the kernel upper
///   half (entries 256–511) and the direct map; any PCID bits require
///   `CR4.PCIDE` set.
/// - `tf` must point to a `TrapFrame` on the direct-mapped init kernel stack,
///   with `rip`, `rsp`, `cs`, `ss`, and `rflags` set for user-mode entry.
/// - TSS RSP0 and `SYSCALL_KERNEL_RSP` must be set to init's `kernel_stack_top`
///   before this call.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn switch_and_enter_user(
    cr3: u64,
    tf: *const super::trap_frame::TrapFrame,
) -> !
{
    // rdi = cr3 value, rsi = tf (*const TrapFrame)
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
