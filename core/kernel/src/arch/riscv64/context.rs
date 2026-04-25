// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/riscv64/context.rs

//! RISC-V 64-bit thread context management.
//!
//! `SavedState` holds the kernel-mode callee-saved register set for one thread.
//! `new_state` constructs the initial state for a new thread.
//!
//! `switch` saves the current thread's callee-saved registers to `*current`
//! (including `ra` as the resume point) and restores from `*next`, then
//! executes `ret` which jumps to `next.ra`.
//!
//! `return_to_user` sets `sepc` to the user entry point, configures `sstatus`
//! for U-mode return, restores all GPRs from a [`TrapFrame`], and executes `sret`.

// ── SavedState ────────────────────────────────────────────────────────────────

/// Kernel-mode callee-saved register state for one thread.
///
/// `tp` is intentionally absent: on RISC-V, `tp` always points to
/// `PerCpuData` for the current hart and is a kernel-reserved register.
/// It is never thread-private and must not be saved/restored in `switch`.
///
/// ## Field offsets (used by assembly in `switch`)
///
/// | Offset | Field   |
/// |--------|---------|
/// |  0     | sp      |
/// |  8     | ra      |
/// | 16     | s0      |
/// | 24     | s1      |
/// | 32     | s2      |
/// | 40     | s3      |
/// | 48     | s4      |
/// | 56     | s5      |
/// | 64     | s6      |
/// | 72     | s7      |
/// | 80     | s8      |
/// | 88     | s9      |
/// | 96     | s10     |
/// | 104    | s11     |
/// | 112    | a0      |
#[derive(Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct SavedState
{
    /// Stack pointer.
    pub sp: u64,
    /// Return address — where execution resumes after `switch` returns.
    pub ra: u64,
    /// Callee-saved registers s0/fp through s11.
    pub s0: u64,
    pub s1: u64,
    pub s2: u64,
    pub s3: u64,
    pub s4: u64,
    pub s5: u64,
    pub s6: u64,
    pub s7: u64,
    pub s8: u64,
    pub s9: u64,
    pub s10: u64,
    pub s11: u64,
    /// First argument register `a0`, used to deliver the argument on first
    /// entry to a new kernel thread. Caller-saved; only meaningful at thread
    /// creation time.
    pub a0: u64,
}

impl SavedState
{
    /// Return the thread's resume address.
    ///
    /// For a newly created thread this is the entry function address; for a
    /// resumed thread it is the return address from the previous `switch` call.
    pub fn entry_point(&self) -> u64
    {
        self.ra
    }

    /// Return the initial user-mode argument stored at thread creation.
    ///
    /// `new_state` stashes `arg` in `a0`; `sched::enter` reads it back here
    /// and forwards it to the user-mode `TrapFrame` via `set_arg0`.
    pub fn user_arg(&self) -> u64
    {
        self.a0
    }
}

/// Seed the initial TLS base for a thread being configured.
///
/// RISC-V carries the user-mode TLS pointer in `TrapFrame.tp`, which
/// `return_to_user` restores on every U-mode entry (including the first).
/// `SavedState` holds only kernel-mode callee-saved registers; `tp` is a
/// per-hart kernel register here and is never thread-switched. This hook is
/// therefore a no-op on RISC-V — `TrapFrame::set_tls_base` handles it.
#[inline]
pub fn seed_tls_base(_saved: &mut SavedState, _tls_base: u64) {}

// ── new_state ─────────────────────────────────────────────────────────────────

/// Construct the initial [`SavedState`] for a new thread.
///
/// `entry`     — virtual address of the thread's entry function.
/// `stack_top` — top of the thread's kernel stack (sp starts here).
/// `arg`       — first argument delivered in `a0` on first entry.
/// `_is_user`  — unused; user-mode entry uses `return_to_user`.
pub fn new_state(entry: u64, stack_top: u64, arg: u64, _is_user: bool) -> SavedState
{
    // switch() does not save/restore sstatus. SIE is managed by schedule()'s
    // lock_raw (disables) and restore_interrupts_from (re-enables after switch).
    // SPP and SPIE are hardware-managed: set on trap entry, consumed by sret.
    // Interrupts are enabled later:
    //   - User threads: sret in return_to_user sets SIE ← SPIE (=1).
    //   - Idle thread:  explicitly calls interrupts::enable() in its entry.

    SavedState {
        ra: entry,
        sp: stack_top,
        a0: arg,
        ..SavedState::default()
    }
}

// ── switch ────────────────────────────────────────────────────────────────────

/// Save the current thread's kernel registers to `*current` and restore the
/// next thread's registers from `*next`, then execute `ret` (jr ra).
///
/// For a thread's first run, `next.ra` is its entry function. For a resumed
/// thread, `next.ra` is the return address from its previous `switch` call.
///
/// # Safety
/// Both pointers must be valid, aligned `SavedState` values. Caller must hold
/// the scheduler lock. `save_flag` must be a valid `*const AtomicU32` (the
/// current thread's `context_saved` field) or null (initial boot switch).
///
/// The lock (`now_serving` at `lock_ptr + 4`) is released inside this function
/// between the save and load phases, so that another CPU cannot load the
/// current thread's `SavedState` until the save is globally visible.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn switch(
    current: *mut SavedState,
    next: *const SavedState,
    save_flag: *const core::sync::atomic::AtomicU32,
    lock_ptr: *const crate::sync::Spinlock,
)
{
    // a0 = current (*mut SavedState)
    // a1 = next (*const SavedState)
    // a2 = save_flag (*const AtomicU32) — context_saved flag on current TCB
    // a3 = lock_ptr (*const Spinlock) — scheduler lock (now_serving at offset 4)
    // SAFETY: switch_context preserves ABI; both pointers valid; stack/frame pointers valid.
    core::arch::naked_asm!(
        // ── Save current thread to *a0 ────────────────────────────────────
        // `ra` holds the return address from the `call switch` instruction;
        // saving it means the resumed thread will "return" to the call site.
        // `tp` is NOT saved: it is a kernel-reserved per-hart register that
        // always holds &PER_CPU[cpu_id] and must never be thread-switched.
        "sd ra,     8(a0)",
        "sd sp,     0(a0)",
        "sd s0,    16(a0)",
        "sd s1,    24(a0)",
        "sd s2,    32(a0)",
        "sd s3,    40(a0)",
        "sd s4,    48(a0)",
        "sd s5,    56(a0)",
        "sd s6,    64(a0)",
        "sd s7,    72(a0)",
        "sd s8,    80(a0)",
        "sd s9,    88(a0)",
        "sd s10,   96(a0)",
        "sd s11,  104(a0)",
        // ── Signal save complete (Release) ────────────────────────────────
        // Set context_saved = 1 so a remote CPU spinning in schedule() can
        // proceed to load this thread's SavedState. The Release fence
        // ensures all prior stores (the register saves above) are globally
        // visible before the flag write.
        "beqz a2, 1f", // skip if save_flag is null (boot path)
        "li   t0, 1",
        "fence rw, w",    // Release fence: order saves before flag
        "sw   t0, 0(a2)", // *save_flag = 1
        "1:",
        // ── Release scheduler lock ────────────────────────────────────────
        // Advance now_serving (offset 4 in Spinlock) so other CPUs can
        // acquire this CPU's scheduler lock. Uses fence + plain store
        // since we only need Release ordering and the lock protocol
        // guarantees single-writer (only the holder advances now_serving).
        "fence rw, w",    // Release fence: order saves before unlock
        "addi a3, a3, 4", // a3 = &now_serving
        "lw   t0, 0(a3)", // t0 = now_serving
        "addi t0, t0, 1", // t0 += 1
        "sw   t0, 0(a3)", // now_serving = t0 + 1
        // ── Restore next thread from *a1 ──────────────────────────────────
        "ld ra,     8(a1)", // return address (or entry function)
        "ld sp,     0(a1)",
        "ld s0,    16(a1)",
        "ld s1,    24(a1)",
        "ld s2,    32(a1)",
        "ld s3,    40(a1)",
        "ld s4,    48(a1)",
        "ld s5,    56(a1)",
        "ld s6,    64(a1)",
        "ld s7,    72(a1)",
        "ld s8,    80(a1)",
        "ld s9,    88(a1)",
        "ld s10,   96(a1)",
        "ld s11,  104(a1)",
        "ld a0,   112(a1)", // argument for first-entry threads
        "ret",              // jr ra → jumps to next thread's entry or resume point
    );
}

// ── first_entry_to_user ───────────────────────────────────────────────────────

/// Activate a new address space and enter user mode for the first time.
///
/// Architecture-neutral entry point for `sched::enter`. On RISC-V, activating
/// via `satp` + `sfence.vma` is safe to do before `sret` because the boot
/// stack lives in the direct-mapped region (covered by kernel PPN entries),
/// which is present in the new address space.
///
/// `sscratch` must be set to `kernel_stack_top` before this call so that the
/// trap entry can switch stacks on the first U-mode trap.
///
/// # Safety
/// `root_phys` must be a valid page-table root. `tf` must point to a
/// [`TrapFrame`] on the init thread's kernel stack with `sepc` and `sp` set.
#[cfg(not(test))]
pub unsafe fn first_entry_to_user(root_phys: u64, tf: *const super::trap_frame::TrapFrame) -> !
{
    // SAFETY: root_phys is valid page-table root; tf is valid; direct map present in new space.
    unsafe {
        crate::arch::current::paging::activate(root_phys);
        return_to_user(tf)
    }
}

// ── return_to_user ────────────────────────────────────────────────────────────

/// Restore full user register state from `tf` and enter U-mode via `sret`.
///
/// Sets `sepc` to `tf.sepc` (user entry point), configures `sstatus` for
/// U-mode return (SPP=0, SPIE=1 → interrupts enabled after sret), restores
/// all GPRs, then executes `sret`. Never returns.
///
/// # Safety
/// `tf` must point to a valid [`TrapFrame`] with `sepc` set to the user entry
/// point and `sp` (x2) set to the user stack top.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn return_to_user(tf: *const super::trap_frame::TrapFrame) -> !
{
    // a0 = tf (*const TrapFrame)
    // TrapFrame field offsets (trap_frame.rs):
    //   ra(x1)=0, sp(x2)=8, gp(x3)=16, tp(x4)=24,
    //   t0=32, t1=40, t2=48, s0=56, s1=64,
    //   a0=72, a1=80, a2=88, a3=96, a4=104, a5=112, a6=120, a7=128,
    //   s2=136, s3=144, s4=152, s5=160, s6=168, s7=176, s8=184,
    //   s9=192, s10=200, s11=208, t3=216, t4=224, t5=232, t6=240,
    //   sepc=248, scause=256, stval=264, sstatus=272
    core::arch::naked_asm!(
        // Set sepc = user entry point.
        "ld t0, 248(a0)",
        "csrw sepc, t0",
        // Set sstatus for U-mode return:
        //   SPP  = 0 (bit 8): return to U-mode after sret.
        //   SPIE = 1 (bit 5): enable interrupts after sret.
        "li t0, 0x20",
        "csrw sstatus, t0",
        // Arm sscratch with &PER_CPU so that the next U-mode trap entry can
        // detect U-mode (sscratch != 0) and recover the per-CPU pointer.
        // tp still equals &PER_CPU[cpu_id] here (kernel-reserved register).
        // This must be done BEFORE tp is overwritten by the user tp restore below.
        "csrw sscratch, tp",
        // Restore GPRs x1–x31; restore x10 (a0) last since it is our pointer.
        // x4 (tp) is restored from TrapFrame here — after this, tp = user TLS ptr.
        "ld x1,    0(a0)", // ra
        "ld x2,    8(a0)", // sp (user stack)
        "ld x3,   16(a0)", // gp
        "ld x4,   24(a0)", // tp
        "ld x5,   32(a0)", // t0
        "ld x6,   40(a0)", // t1
        "ld x7,   48(a0)", // t2
        "ld x8,   56(a0)", // s0
        "ld x9,   64(a0)", // s1
        // skip x10 (a0) for last
        "ld x11,  80(a0)", // a1
        "ld x12,  88(a0)", // a2
        "ld x13,  96(a0)", // a3
        "ld x14, 104(a0)", // a4
        "ld x15, 112(a0)", // a5
        "ld x16, 120(a0)", // a6
        "ld x17, 128(a0)", // a7
        "ld x18, 136(a0)", // s2
        "ld x19, 144(a0)", // s3
        "ld x20, 152(a0)", // s4
        "ld x21, 160(a0)", // s5
        "ld x22, 168(a0)", // s6
        "ld x23, 176(a0)", // s7
        "ld x24, 184(a0)", // s8
        "ld x25, 192(a0)", // s9
        "ld x26, 200(a0)", // s10
        "ld x27, 208(a0)", // s11
        "ld x28, 216(a0)", // t3
        "ld x29, 224(a0)", // t4
        "ld x30, 232(a0)", // t5
        "ld x31, 240(a0)", // t6
        "ld x10,  72(a0)", // a0 — restore last (was TrapFrame pointer)
        "sret",
    );
}
