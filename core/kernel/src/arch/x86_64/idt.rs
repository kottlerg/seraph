// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/arch/x86_64/idt.rs

//! Interrupt Descriptor Table for x86-64.
//!
//! Provides:
//! - A 256-entry IDT in BSS.
//! - Naked ISR stubs for exception vectors 0–31 (macro-generated).
//! - Stubs for the APIC timer (vector 32) and spurious (vector 255).
//! - A common exception handler that prints diagnostics and halts.
//!
//! Every ring-3 entry at which a thread can be stopped (exception, `#PF`, NMI,
//! and ring-3 IRQ) builds the one canonical [`TrapFrame`] on the kernel stack via
//! [`tf_build_asm`]/[`tf_resume_asm`]; the fault redirect points `tcb->trap_frame`
//! at that live frame with no copy. See the "Unified entry frame" section.
//!
//! # Exception vector groups
//! Vectors with a hardware-pushed error code: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30.
//! All others: a dummy 0 is pushed by the stub to keep the frame layout uniform.
//!
//! # IST assignments
//! - Vector 8  (Double Fault): IST1
//! - Vector 2  (NMI):          IST2
//!
//! # Modification notes
//! - To register a device IRQ: add a new stub (or reuse a range), call
//!   `set_gate` with the target vector, and implement the handler function.
//! - To change IST assignments: update the `IST` argument in the `isr_stub!`
//!   invocation and ensure the matching IST stack is configured in the TSS.

// cast_possible_truncation: usize→u16 IDT descriptor size calculations; bounded by descriptor count.
#![allow(clippy::cast_possible_truncation)]

use super::gdt::KERNEL_CS;
use super::trap_frame::TrapFrame;
#[cfg(not(test))]
use crate::fatal;

// ── IdtEntry ──────────────────────────────────────────────────────────────────

/// A single 128-bit (16-byte) IDT gate descriptor.
///
/// Encodes the handler offset (split into three parts), code segment selector,
/// IST index, gate type, DPL, and present bit.
#[derive(Clone, Copy, Default)]
#[repr(C)]
pub struct IdtEntry
{
    /// Handler offset bits [15:0].
    offset_low: u16,
    /// Code segment selector (must be a 64-bit code segment).
    selector: u16,
    /// IST index (bits [2:0]); 0 = use RSP from TSS, 1–7 = IST stack.
    ist: u8,
    /// Type and attributes: P | DPL | 0 | `gate_type`.
    type_attr: u8,
    /// Handler offset bits [31:16].
    offset_mid: u16,
    /// Handler offset bits [63:32].
    offset_high: u32,
    /// Reserved, must be zero.
    _reserved: u32,
}

impl IdtEntry
{
    /// Construct a present interrupt gate pointing to `handler`.
    ///
    /// - `ist`: 0 = use RSP0 from TSS, 1–7 = use IST[ist] from TSS.
    /// - `dpl`: descriptor privilege level (0 for kernel-only gates).
    /// - Type = 0xE (64-bit interrupt gate, clears IF on entry).
    pub fn new(handler: u64, ist: u8, dpl: u8) -> Self
    {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: KERNEL_CS,
            ist: ist & 0x7,
            // P=1, DPL, 0, type=0xE (64-bit interrupt gate)
            type_attr: 0x80 | ((dpl & 3) << 5) | 0x0E,
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: (handler >> 32) as u32,
            _reserved: 0,
        }
    }
}

// ── IDT storage ───────────────────────────────────────────────────────────────

/// 256-entry IDT in BSS.
///
/// Written only during single-threaded boot init.
#[cfg(not(test))]
static mut IDT: [IdtEntry; 256] = [IdtEntry {
    offset_low: 0,
    selector: 0,
    ist: 0,
    type_attr: 0,
    offset_mid: 0,
    offset_high: 0,
    _reserved: 0,
}; 256];

// ── IDTR ──────────────────────────────────────────────────────────────────────

#[repr(C, packed)]
struct Idtr
{
    limit: u16,
    base: u64,
}

// ── Unified entry frame ─────────────────────────────────────────────────────
//
// Every ring-3 entry at which a thread can be stopped — syscall (syscall.rs),
// exception/#PF/NMI, and ring-3 IRQ — lands on the one canonical `TrapFrame`
// (the userspace register ABI). The fault redirect points `tcb->trap_frame` at
// the live on-stack frame directly (symmetric with
// riscv64/interrupts.rs::redirect_user_fault), so there is no second frame type
// and no copy.
//
// The CPU + each stub leave a uniform stub frame on entry to a trampoline
// (S = rsp at the trampoline label):
//
//   [S+0]   vector       (pushed by the stub)
//   [S+8]   error_code   (hardware where the vector has one, else a stub-pushed 0)
//   [S+16]  rip          (hardware)
//   [S+24]  cs           (hardware)
//   [S+32]  rflags       (hardware)
//   [S+40]  rsp          (hardware — always present in long mode)
//   [S+48]  ss           (hardware — always present in long mode)
//
// `tf_build_asm` reserves the 168-byte TrapFrame below this stub frame (leaving
// it intact for `iretq`) and fills it; `tf_resume_asm` writes any handler-edited
// CPU-state back into the stub frame and `iretq`s. The two-word error_code +
// vector stub prologue is load-bearing for 16-byte `call` alignment — see the
// stub macros.
//
// vector/error_code are passed to handlers as arguments, not stored in the
// frame: they are consumed at fault-classification time only. cr2 is read via
// `mov reg, cr2` in the handler. fs_base is zeroed (the authoritative TLS base
// lives in SavedState.fs_base; see trap_frame.rs).

/// Naked-asm fragment: build the canonical [`TrapFrame`] from the stub frame.
///
/// On entry rsp = `S` (stub-frame layout above). Reserves 168 bytes with
/// `sub rsp` and fills every field with explicit `mov`s (the `syscall_entry`
/// pattern — chosen over `push qword ptr [rsp+disp]` because the
/// effective-address timing of an rsp-relative `push` source is error-prone).
/// `rax` is saved first, then reused as the copy scratch. After the fragment
/// rsp = `S-168` = `TrapFrame` base; the stub frame sits at `[rsp+168 ..=
/// rsp+216]`.
#[cfg(not(test))]
macro_rules! tf_build_asm {
    () => {
        concat!(
            "sub rsp, 168\n",
            "mov [rsp + 0], rax\n",
            "mov [rsp + 8], rbx\n",
            "mov [rsp + 16], rcx\n",
            "mov [rsp + 24], rdx\n",
            "mov [rsp + 32], rsi\n",
            "mov [rsp + 40], rdi\n",
            "mov [rsp + 48], rbp\n",
            "mov [rsp + 56], r8\n",
            "mov [rsp + 64], r9\n",
            "mov [rsp + 72], r10\n",
            "mov [rsp + 80], r11\n",
            "mov [rsp + 88], r12\n",
            "mov [rsp + 96], r13\n",
            "mov [rsp + 104], r14\n",
            "mov [rsp + 112], r15\n",
            "mov rax, [rsp + 184]\n", // stub rip
            "mov [rsp + 120], rax\n",
            "mov rax, [rsp + 200]\n", // stub rflags
            "mov [rsp + 128], rax\n",
            "mov rax, [rsp + 208]\n", // stub rsp
            "mov [rsp + 136], rax\n",
            "mov rax, [rsp + 192]\n", // stub cs
            "mov [rsp + 144], rax\n",
            "mov rax, [rsp + 216]\n", // stub ss
            "mov [rsp + 152], rax\n",
            "mov qword ptr [rsp + 160], 0\n", // fs_base
        )
    };
}

/// Naked-asm fragment: write the (possibly handler-edited) `TrapFrame`
/// CPU-state back into the stub frame, restore all GPRs from the frame, drop the
/// frame + stub prologue, and `iretq`. Inverse of [`tf_build_asm`]; rsp on entry
/// = `TrapFrame` base, on exit (`iretq`) the stub frame's hardware iret words are
/// at the top of stack. `rax` is the copy scratch, then restored from the frame.
#[cfg(not(test))]
macro_rules! tf_resume_asm {
    () => {
        concat!(
            "mov rax, [rsp + 120]\n", // rip
            "mov [rsp + 184], rax\n",
            "mov rax, [rsp + 128]\n", // rflags
            "mov [rsp + 200], rax\n",
            "mov rax, [rsp + 136]\n", // rsp
            "mov [rsp + 208], rax\n",
            "mov rax, [rsp + 144]\n", // cs
            "mov [rsp + 192], rax\n",
            "mov rax, [rsp + 152]\n", // ss
            "mov [rsp + 216], rax\n",
            "mov rax, [rsp + 0]\n",
            "mov rbx, [rsp + 8]\n",
            "mov rcx, [rsp + 16]\n",
            "mov rdx, [rsp + 24]\n",
            "mov rsi, [rsp + 32]\n",
            "mov rdi, [rsp + 40]\n",
            "mov rbp, [rsp + 48]\n",
            "mov r8, [rsp + 56]\n",
            "mov r9, [rsp + 64]\n",
            "mov r10, [rsp + 72]\n",
            "mov r11, [rsp + 80]\n",
            "mov r12, [rsp + 88]\n",
            "mov r13, [rsp + 96]\n",
            "mov r14, [rsp + 104]\n",
            "mov r15, [rsp + 112]\n",
            "add rsp, 184\n", // drop frame (168) + vector + error_code (16)
            "iretq\n",
        )
    };
}

// ── Common exception handler ──────────────────────────────────────────────────

/// The terminal exception path: a fault that no fault handler resolved. Invoked
/// (and never returned from) by [`exception_handler`], [`page_fault_handler`],
/// and the NMI handler once they determine the fault is unrecoverable.
///
/// If the fault originated in userspace (CPL != 0), the faulting thread is
/// terminated and a death notification is posted (if bound). If the fault
/// originated in the kernel, diagnostics are printed and the system halts.
///
/// # Safety
/// `tf` must point to a valid [`TrapFrame`] on the current stack; `vector` and
/// `error_code` are the trap metadata from the stub frame.
#[cfg(not(test))]
unsafe extern "C" fn common_exception_handler(
    tf: *const TrapFrame,
    vector: u64,
    error_code: u64,
) -> !
{
    // SAFETY: tf is valid — constructed by the entry trampoline on this stack.
    let f = unsafe { &*tf };
    // Read CR2 (faulting address) for page faults (vector 14).
    let cr2: u64 = if vector == 14
    {
        let v: u64;
        // SAFETY: CR2 is a valid read-only register at ring 0; page fault context.
        unsafe {
            core::arch::asm!("mov {}, cr2", out(reg) v, options(nostack, nomem));
        }
        v
    }
    else
    {
        0
    };

    // Check if the fault came from userspace (CPL 3) or kernel (CPL 0).
    let is_userspace = (f.cs & 3) != 0;

    // Disable interrupts before printing to prevent serial interleaving.
    // SAFETY: ring 0 context; this is a crash path.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };

    if is_userspace
    {
        // SAFETY: current_tcb() returns this CPU's running thread; valid in
        // exception context because we entered from a running user thread.
        let tcb = unsafe { crate::syscall::current_tcb() };
        let tid = if tcb.is_null()
        {
            0
        }
        else
        {
            // SAFETY: tcb validated non-null.
            unsafe { (*tcb).thread_id }
        };

        let cpu = super::cpu::current_cpu();
        crate::kprintln_serial!(
            "USERSPACE FAULT: tid={} cpu={} cause={} (vec={} err={:#x})",
            tid,
            cpu,
            x86_exception_name(vector),
            vector,
            error_code,
        );
        // Include fs_base (IA32_FS_BASE) to aid TLS-plumbing diagnosis.
        // SAFETY: interrupts are disabled above; rdmsr on IA32_FS_BASE is
        // always legal in ring 0 and has no side effects.
        let fs_base: u64 = unsafe {
            let low: u32;
            let high: u32;
            core::arch::asm!(
                "rdmsr",
                in("ecx") 0xc000_0100u32,
                out("eax") low,
                out("edx") high,
                options(nomem, nostack, preserves_flags),
            );
            (u64::from(high) << 32) | u64::from(low)
        };
        crate::kprintln_serial!(
            "  rip={:#018x}  cr2={:#018x}  fs_base={:#018x}",
            f.rip,
            cr2,
            fs_base
        );
        dump_x86_regs(f);

        if !tcb.is_null()
        {
            // Commit Exited under all-CPU scheduler.locks so a concurrent
            // dealloc observes a coherent state. See
            // docs/thread-lifecycle-and-sleep.md § Lifecycle State Machine.
            // Write exit_reason first so any subsequent sched.lock acquire
            // observes the reason alongside the Exited transition.
            // SAFETY: tcb validated non-null.
            unsafe {
                (*tcb).exit_reason = 0x1000 + vector;
                crate::sched::set_state_under_all_locks(
                    tcb,
                    crate::sched::thread::ThreadState::Exited,
                );
            }

            // Post death notification if bound (exit_reason = EXIT_FAULT_BASE + vector).
            // EXIT_FAULT_BASE = 0x1000 (matches syscall_abi::EXIT_FAULT_BASE).
            // SAFETY: tcb is valid; post_death_notification handles null check.
            unsafe {
                crate::sched::post_death_notification(tcb, 0x1000 + vector);
            }
        }

        // SAFETY: schedule(false) context-switches away; the exited thread
        // is never re-enqueued.
        unsafe {
            crate::sched::schedule(false);
        }
        crate::arch::current::cpu::halt_loop();
    }
    else
    {
        let cpu = super::cpu::current_cpu();
        crate::kprintln!(
            "KERNEL EXCEPTION: cpu={} cause={} (vec={} err={:#x})",
            cpu,
            x86_exception_name(vector),
            vector,
            error_code,
        );
        crate::kprintln!("  rip={:#018x}  cr2={:#018x}", f.rip, cr2);
        crate::kprintln!("  cs={:#x}  rflags={:#018x}", f.cs, f.rflags,);
        dump_x86_regs_console(f);
        fatal("unhandled kernel exception");
    }
}

/// Generic exception dispatch for vectors routed through
/// [`common_exception_trampoline`] (every ring-3-reachable vector except `#PF`,
/// `#NM`, and NMI, which have dedicated stubs).
///
/// A userspace exception whose thread has a bound fault handler is redirected to
/// it ([`redirect_user_exception`]); on a resume reply this returns and the
/// trampoline's `iretq` re-executes the faulting instruction (or continues from a
/// handler-modified PC). Every other case — no/declined handler, the
/// non-restartable abort vectors, or any kernel exception — is handed to the
/// diverging [`common_exception_handler`], so this returns only on a
/// resolved-and-resumed userspace fault.
///
/// Mirrors the call-from-naked-asm pattern of [`page_fault_handler`]: the
/// trampoline upholds the precondition that `tf` is a valid, writable
/// [`TrapFrame`] on the current stack, so this is a safe `extern "C"` fn.
/// `vector`/`error_code` are the trap metadata from the stub frame.
#[cfg(not(test))]
extern "C" fn exception_handler(tf: *mut TrapFrame, vector: u64, error_code: u64)
{
    // SAFETY: tf is constructed by common_exception_trampoline on this stack.
    let f = unsafe { &*tf };
    let from_user = (f.cs & 3) != 0;
    // #DF (8) and #MC (18) are non-restartable aborts; #DF additionally runs on a
    // dedicated IST stack that is not re-entrant across the reschedule a redirect
    // performs. They are never delivered to a resumable handler — always terminal.
    let redirectable = vector != 8 && vector != 18;
    if from_user && redirectable
    {
        // SAFETY: from_user implies a running user thread; current_tcb is valid
        // in exception context (the kill path uses it too).
        let tcb = unsafe { crate::syscall::current_tcb() };
        // SAFETY: tcb is the running user thread; has_handler only reads the
        // atomic fault_handler field.
        let handler_bound = !tcb.is_null() && unsafe { crate::ipc::fault::has_handler(tcb) };
        if handler_bound
        {
            // SAFETY: tf is the live TrapFrame; the redirect points the TCB at it
            // for the block and returns whether to resume.
            if unsafe { redirect_user_exception(tcb, tf, vector, error_code) }
            {
                return;
            }
            // Handler declined (Kill) — fall through to terminate the thread.
        }
    }

    // Not resumed by a handler — kill (userspace) or fatal (kernel).
    // SAFETY: tf valid; common_exception_handler never returns.
    unsafe {
        common_exception_handler(tf.cast_const(), vector, error_code);
    }
}

// ── Fault diagnostics ────────────────────────────────────────────────────────

/// Human-readable name for an x86-64 exception vector.
fn x86_exception_name(vector: u64) -> &'static str
{
    match vector
    {
        0 => "#DE divide error",
        1 => "#DB debug",
        2 => "NMI",
        3 => "#BP breakpoint",
        4 => "#OF overflow",
        5 => "#BR bound range",
        6 => "#UD invalid opcode",
        7 => "#NM device not available",
        8 => "#DF double fault",
        10 => "#TS invalid TSS",
        11 => "#NP segment not present",
        12 => "#SS stack fault",
        13 => "#GP general protection",
        14 => "#PF page fault",
        16 => "#MF x87 FP error",
        17 => "#AC alignment check",
        18 => "#MC machine check",
        19 => "#XM SIMD FP error",
        20 => "#VE virtualization",
        21 => "#CP control protection",
        _ => "unknown",
    }
}

/// Dump all general-purpose registers from an x86-64 trap frame (serial only).
fn dump_x86_regs(f: &TrapFrame)
{
    crate::kprintln_serial!(
        "  rax={:#018x}  rbx={:#018x}  rcx={:#018x}  rdx={:#018x}",
        f.rax,
        f.rbx,
        f.rcx,
        f.rdx
    );
    crate::kprintln_serial!(
        "  rsi={:#018x}  rdi={:#018x}  rbp={:#018x}  rsp={:#018x}",
        f.rsi,
        f.rdi,
        f.rbp,
        f.rsp
    );
    crate::kprintln_serial!(
        "   r8={:#018x}   r9={:#018x}  r10={:#018x}  r11={:#018x}",
        f.r8,
        f.r9,
        f.r10,
        f.r11
    );
    crate::kprintln_serial!(
        "  r12={:#018x}  r13={:#018x}  r14={:#018x}  r15={:#018x}",
        f.r12,
        f.r13,
        f.r14,
        f.r15
    );
}

/// Dump all general-purpose registers to both serial and framebuffer (for kernel faults).
fn dump_x86_regs_console(f: &TrapFrame)
{
    crate::kprintln!(
        "  rax={:#018x}  rbx={:#018x}  rcx={:#018x}  rdx={:#018x}",
        f.rax,
        f.rbx,
        f.rcx,
        f.rdx
    );
    crate::kprintln!(
        "  rsi={:#018x}  rdi={:#018x}  rbp={:#018x}  rsp={:#018x}",
        f.rsi,
        f.rdi,
        f.rbp,
        f.rsp
    );
    crate::kprintln!(
        "   r8={:#018x}   r9={:#018x}  r10={:#018x}  r11={:#018x}",
        f.r8,
        f.r9,
        f.r10,
        f.r11
    );
    crate::kprintln!(
        "  r12={:#018x}  r13={:#018x}  r14={:#018x}  r15={:#018x}",
        f.r12,
        f.r13,
        f.r14,
        f.r15
    );
}

// ── ISR stub macro ────────────────────────────────────────────────────────────

/// Generate a naked ISR stub for `$vector`.
///
/// If `$has_error_code` is `false`, the stub pushes a dummy 0 before the
/// vector so the stack frame is uniform for `common_exception_handler`.
///
/// Stack on entry to the common handler (from RSP downward):
/// ```text
/// [rsp]    vector (u64)
/// [rsp+8]  error_code (u64)   — hardware or dummy
/// [rsp+16] rip / cs / rflags  — hardware
/// ```
macro_rules! isr_stub {
    ($name:ident, $vector:expr, has_error_code = false, ist = $ist:expr) => {
        #[cfg(not(test))]
        #[unsafe(naked)]
        unsafe extern "C" fn $name()
        {
            core::arch::naked_asm!(
                "push 0",                     // dummy error code
                concat!("push ", $vector),    // vector number
                "jmp {handler}",
                handler = sym common_exception_trampoline,
            );
        }
    };
    ($name:ident, $vector:expr, has_error_code = true, ist = $ist:expr) => {
        #[cfg(not(test))]
        #[unsafe(naked)]
        unsafe extern "C" fn $name()
        {
            core::arch::naked_asm!(
                concat!("push ", $vector), // vector number (error code already on stack)
                "jmp {handler}",
                handler = sym common_exception_trampoline,
            );
        }
    };
}

/// Common trampoline: builds the canonical [`TrapFrame`] ([`tf_build_asm`]),
/// calls [`exception_handler`] with the frame pointer + trap metadata, then —
/// reached only when a userspace exception was redirected to a bound fault
/// handler that resolved it — writes back the (possibly handler-edited) register
/// state and `iretq`s ([`tf_resume_asm`]), re-executing the faulting instruction
/// (or continuing from a handler-modified PC). Every terminal fault (no/declined
/// handler, or any kernel exception) diverges inside [`exception_handler`] →
/// `common_exception_handler`, so the resume tail is dead for those.
///
/// At entry the stack holds the stub frame (vector + `error_code` + hardware iret
/// frame); the build reserves the `TrapFrame` below it and the resume tail leaves
/// the hardware iret frame at the top of stack for `iretq`.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn common_exception_trampoline()
{
    core::arch::naked_asm!(
        concat!(
            tf_build_asm!(),
            "mov rdi, rsp\n",          // arg0 = *mut TrapFrame
            "mov rsi, [rsp + 168]\n",  // arg1 = vector
            "mov rdx, [rsp + 176]\n",  // arg2 = error_code
            "call {handler}\n",
            tf_resume_asm!(),
        ),
        handler = sym exception_handler,
    );
}

// ── Exception stubs ───────────────────────────────────────────────────────────
// Vectors with hardware error codes: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30.

isr_stub!(isr0, 0, has_error_code = false, ist = 0);
isr_stub!(isr1, 1, has_error_code = false, ist = 0);
// NMI (vector 2) uses ipi_nmi_backtrace_stub instead of the generic
// isr_stub! — see the dedicated stub above.
isr_stub!(isr3, 3, has_error_code = false, ist = 0);
isr_stub!(isr4, 4, has_error_code = false, ist = 0);
isr_stub!(isr5, 5, has_error_code = false, ist = 0);
isr_stub!(isr6, 6, has_error_code = false, ist = 0);
// Vector 7 (#NM) has a dedicated handler — see `isr_nm` below.
isr_stub!(isr8, 8, has_error_code = true, ist = 1); // Double Fault — IST1
isr_stub!(isr9, 9, has_error_code = false, ist = 0);
isr_stub!(isr10, 10, has_error_code = true, ist = 0);
isr_stub!(isr11, 11, has_error_code = true, ist = 0);
isr_stub!(isr12, 12, has_error_code = true, ist = 0);
isr_stub!(isr13, 13, has_error_code = true, ist = 0);
// Vector 14 (#PF) has a dedicated stub — see `isr_page_fault` below — so a
// spurious stale-TLB fault can be resolved and retried instead of killing.
isr_stub!(isr15, 15, has_error_code = false, ist = 0);
isr_stub!(isr16, 16, has_error_code = false, ist = 0);
isr_stub!(isr17, 17, has_error_code = true, ist = 0);
isr_stub!(isr18, 18, has_error_code = false, ist = 0);
isr_stub!(isr19, 19, has_error_code = false, ist = 0);
isr_stub!(isr20, 20, has_error_code = false, ist = 0);
isr_stub!(isr21, 21, has_error_code = true, ist = 0);
isr_stub!(isr22, 22, has_error_code = false, ist = 0);
isr_stub!(isr23, 23, has_error_code = false, ist = 0);
isr_stub!(isr24, 24, has_error_code = false, ist = 0);
isr_stub!(isr25, 25, has_error_code = false, ist = 0);
isr_stub!(isr26, 26, has_error_code = false, ist = 0);
isr_stub!(isr27, 27, has_error_code = false, ist = 0);
isr_stub!(isr28, 28, has_error_code = false, ist = 0);
isr_stub!(isr29, 29, has_error_code = true, ist = 0);
isr_stub!(isr30, 30, has_error_code = true, ist = 0);
isr_stub!(isr31, 31, has_error_code = false, ist = 0);

// ── Timer and spurious stubs ──────────────────────────────────────────────────

// ── Shared IRQ trampoline ─────────────────────────────────────────────────────

/// Route a device/timer/IPI interrupt by its IDT vector to the existing handler.
///
/// Called from [`common_irq_trampoline`] with the stub-pushed vector. Each
/// handler performs its own EOI; this only dispatches. The device range carries
/// the GSI as `vector - 33` (the GSI indexes `IRQ_TABLE`; see `irq.rs`).
#[cfg(not(test))]
extern "C" fn irq_dispatch(vector: u64)
{
    match vector
    {
        v if v == u64::from(super::timer::TIMER_VECTOR) => super::timer::timer_isr(),
        33..=55 =>
        {
            // SAFETY: IRQ-handler context at ring 0; `dispatch_device_irq` masks
            // and EOIs internally. `vector - 33` is in 0..=22 (one IOAPIC GSI).
            unsafe {
                crate::irq::dispatch_device_irq((vector - 33) as u32);
            }
        }
        v if v == u64::from(super::interrupts::IPI_VECTOR_TLB_SHOOTDOWN) =>
        {
            ipi_tlb_shootdown_handler();
        }
        v if v == u64::from(super::interrupts::IPI_VECTOR_WAKEUP) => ipi_wakeup_handler(),
        // No routed vector falls here; matches the spurious vector's no-EOI policy.
        _ =>
        {}
    }
}

/// Shared trampoline for device/timer/IPI interrupts (vectors routed through
/// [`irq_dispatch`]). Branches on the interrupted privilege level (saved CS RPL):
///
/// - **Ring-3 origin** (a user thread was preempted): builds the canonical
///   [`TrapFrame`] ([`tf_build_asm`]) so a complete, live user register snapshot
///   exists on the kernel stack (the invariant a userspace debugger consumes —
///   see #233), dispatches, then returns frame-authoritatively ([`tf_resume_asm`]) —
///   all GPRs are restored from the frame, not from the implicit call-chain
///   preservation.
/// - **Ring-0 origin** (the kernel/idle was interrupted): the interrupted context
///   carries no user state (any in-flight user state lives in the thread's syscall
///   frame), so only caller-clobbered registers are saved, matching the legacy
///   minimal path.
///
/// Each stub enters via `push 0; push <vector>; jmp` — the two-word prologue keeps
/// the `call` 16-byte aligned (identical parity to the exception stubs).
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn common_irq_trampoline()
{
    core::arch::naked_asm!(
        concat!(
            "test byte ptr [rsp + 24], 0x3\n", // saved CS RPL; 0 => ring 0
            "jz 2f\n",
            // ── ring-3: build TrapFrame, dispatch, frame-authoritative return ──
            tf_build_asm!(),
            "mov rdi, [rsp + 168]\n", // arg0 = vector
            "call {dispatch}\n",
            tf_resume_asm!(),
            // ── ring-0: minimal save (no user state) ──
            "2:\n",
            "push rax\n",
            "push rcx\n",
            "push rdx\n",
            "push rsi\n",
            "push rdi\n",
            "push r8\n",
            "push r9\n",
            "push r10\n",
            "push r11\n",
            "mov rdi, [rsp + 72]\n", // arg0 = vector
            "call {dispatch}\n",
            "pop r11\n",
            "pop r10\n",
            "pop r9\n",
            "pop r8\n",
            "pop rdi\n",
            "pop rsi\n",
            "pop rdx\n",
            "pop rcx\n",
            "pop rax\n",
            "add rsp, 16\n", // drop vector + placeholder
            "iretq\n",
        ),
        dispatch = sym irq_dispatch,
    );
}

// ── Device IRQ stubs ──────────────────────────────────────────────────────────

/// Generate a naked device IRQ stub for IDT vector `$vector`.
///
/// Each stub pushes the two-word `placeholder + vector` prologue and jumps to
/// [`common_irq_trampoline`], which builds the [`TrapFrame`] (ring-3 origin) and
/// routes to `irq::dispatch_device_irq(vector - 33)` via [`irq_dispatch`].
/// `dispatch_device_irq` handles masking, notification delivery, and EOI.
///
/// # Modification notes
/// - To add more GSIs: `device_irq_stub!(isr_devN, 33+N)` then
///   `set(33+N, isr_devN, 0)` in `init()`.
macro_rules! device_irq_stub {
    ($name:ident, $vector:literal) => {
        #[cfg(not(test))]
        #[unsafe(naked)]
        unsafe extern "C" fn $name()
        {
            core::arch::naked_asm!(
                concat!("push 0\n", "push ", $vector, "\n"), // placeholder + vector
                "jmp {tramp}",
                tramp = sym common_irq_trampoline,
            );
        }
    };
}

device_irq_stub!(isr_dev0, 33);
device_irq_stub!(isr_dev1, 34);
device_irq_stub!(isr_dev2, 35);
device_irq_stub!(isr_dev3, 36);
device_irq_stub!(isr_dev4, 37);
device_irq_stub!(isr_dev5, 38);
device_irq_stub!(isr_dev6, 39);
device_irq_stub!(isr_dev7, 40);
device_irq_stub!(isr_dev8, 41);
device_irq_stub!(isr_dev9, 42);
device_irq_stub!(isr_dev10, 43);
device_irq_stub!(isr_dev11, 44);
device_irq_stub!(isr_dev12, 45);
device_irq_stub!(isr_dev13, 46);
device_irq_stub!(isr_dev14, 47);
device_irq_stub!(isr_dev15, 48);
device_irq_stub!(isr_dev16, 49);
device_irq_stub!(isr_dev17, 50);
device_irq_stub!(isr_dev18, 51);
device_irq_stub!(isr_dev19, 52);
device_irq_stub!(isr_dev20, 53);
device_irq_stub!(isr_dev21, 54);
device_irq_stub!(isr_dev22, 55);

// ── Timer and spurious stubs ──────────────────────────────────────────────────

/// APIC timer ISR stub (vector 32).
///
/// Pushes the `placeholder + vector` prologue and jumps to
/// [`common_irq_trampoline`], which (ring-3 origin) builds the [`TrapFrame`] and
/// routes to `timer::timer_isr` via [`irq_dispatch`] — `timer_isr` increments the
/// tick counter, sends EOI, and may preempt.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn isr_timer()
{
    core::arch::naked_asm!(
        "push 0",  // placeholder
        "push 32", // vector
        "jmp {tramp}",
        tramp = sym common_irq_trampoline,
    );
}

/// Spurious interrupt handler (vector 255).
///
/// Spurious interrupts are not acknowledged via EOI — see Intel SDM §10.9.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn isr_spurious()
{
    core::arch::naked_asm!("iretq");
}

/// `#NM` (Device Not Available, vector 7) handler stub.
///
/// `#NM` fires when CR0.TS = 1 and a user thread executes an x87/SSE/AVX
/// instruction — the kernel's lazy-trap notification that this thread is about
/// to touch extended state. The handler clears CR0.TS and returns; the
/// trapping instruction is re-executed by hardware and proceeds normally.
///
/// In a later commit this handler additionally XRSTORs the thread's saved
/// XSAVE area when the TCB's dirty flag is set; for now the area does not
/// exist yet, so the trapping thread sees zeroed/FINIT-equivalent state.
/// Today no kernel or userspace code emits FP/SIMD, so the handler is
/// installed but dormant.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn isr_nm()
{
    core::arch::naked_asm!(
        "push rax",
        "push rcx",
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        "push r11",
        "call {handler}",
        "pop r11",
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop rax",
        "iretq",
        handler = sym nm_handler,
    );
}

/// `#NM` handler body — FPU lazy-restore dispatch.
///
/// Saves the previous owner's live register file into its TCB XSAVE
/// area (if any), clears CR0.TS, XRSTORs the trapping thread's area into
/// the live registers, and installs the trapping thread as this CPU's
/// new `fpu_owner`. The trapping x87/SSE/AVX instruction then proceeds
/// on re-execution. The area is allocated as page N+1 of the Thread
/// retype slot (see `sys_cap_create_thread` layout), so user threads
/// always have a non-null area; the slot zero-init makes the first
/// XRSTOR restore the architected initial state.
///
/// Preemption is disabled across the handler body so a timer tick mid-
/// sequence cannot reschedule between the prev-owner save and the new-
/// owner restore, which would leave the per-CPU `fpu_owner` invariant
/// transiently violated.
#[cfg(not(test))]
extern "C" fn nm_handler()
{
    crate::percpu::preempt_disable();

    let cpu = super::cpu::current_cpu() as usize;
    let owner_slot = crate::percpu::fpu_owner_for(cpu);
    // Read the prior owner (if any) so we can save its live regs
    // before XRSTOR'ing this thread's area. The atomic swap is
    // simpler than load-then-store but is not load-bearing for
    // concurrency: after #108 the only writer is this same handler
    // (and `switch_out_save` on this CPU), and both run with
    // preemption disabled — no cross-CPU race on this slot.
    let prev = owner_slot.swap(core::ptr::null_mut(), core::sync::atomic::Ordering::AcqRel);

    // SAFETY: current_tcb returns this CPU's running thread; valid in
    // exception context because we entered from a user FP instruction
    // (the trap fires only on x87/SSE/AVX in U-mode given the kernel is
    // soft-float).
    let tcb = unsafe { crate::syscall::current_tcb() };
    if tcb.is_null()
    {
        // No current thread — should not happen at #NM but be defensive.
        // Re-establish the (TS=1, owner=null) state.
        // SAFETY: ring 0.
        unsafe {
            super::fpu::cr0_set_ts();
        }
        crate::percpu::preempt_enable();
        return;
    }

    if !prev.is_null() && prev != tcb
    {
        // SAFETY: prev was the live owner; its extended.area is page-
        // resident for the TCB's lifetime when non-null. XSAVE requires
        // TS=0; clear it before the save instruction.
        let prev_area = unsafe { (*prev).extended.area };
        if !prev_area.is_null()
        {
            // SAFETY: ring 0; prev_area satisfies XSAVE alignment and size.
            unsafe {
                super::fpu::cr0_clear_ts();
                super::fpu::save_to(prev_area);
            }
        }
    }

    // SAFETY: tcb validated non-null. extended.area is page-resident in
    // the Thread retype slot and lives for the TCB's lifetime.
    let area = unsafe { (*tcb).extended.area };
    if area.is_null()
    {
        // A user thread without a backing area cannot legitimately take
        // an FP trap, but we observed one. Re-arm TS for safety and bail.
        // SAFETY: ring 0.
        unsafe {
            super::fpu::cr0_set_ts();
        }
        crate::percpu::preempt_enable();
        return;
    }

    // SAFETY: ring 0; area is a valid XSAVE buffer; we hold logical
    // ownership of the live regs (prev was swapped out atomically).
    unsafe {
        super::fpu::cr0_clear_ts();
        super::fpu::restore_from(area);
    }
    // Publish new ownership. Release pairs with the Acquire load in
    // switch_out_save (the only other reader of this slot after eager
    // save eliminated the cross-CPU flush IPI).
    owner_slot.store(tcb, core::sync::atomic::Ordering::Release);

    crate::percpu::preempt_enable();
}

/// Page-fault (`#PF`, vector 14) stub.
///
/// Builds the canonical [`TrapFrame`] ([`tf_build_asm`]; the hardware already
/// pushed the error code, this stub pushes the vector), calls
/// [`page_fault_handler`], then — reached only when the fault was a resolved
/// spurious stale-TLB fault — writes back the unmodified register state and
/// `iretq`s ([`tf_resume_asm`]), re-executing the faulting instruction. For every
/// genuine fault the handler diverges (`common_exception_handler` never returns)
/// and the resume tail is dead.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn isr_page_fault()
{
    core::arch::naked_asm!(
        concat!(
            "push 14\n", // vector (hardware already pushed the error code)
            tf_build_asm!(),
            "mov rdi, rsp\n",          // arg0 = *mut TrapFrame
            "mov rsi, [rsp + 176]\n",  // arg1 = error_code (vector is implicit 14)
            "call {handler}\n",
            tf_resume_asm!(),
        ),
        handler = sym page_fault_handler,
    );
}

/// Page-fault (`#PF`, vector 14) handler body.
///
/// Classifies the fault before the diverging common handler runs: a userspace
/// fault whose faulting address (CR2) is mapped with permissions covering the
/// access is a stale-TLB *spurious* fault — the live page tables already
/// satisfy it (e.g. after a remote map/widen whose shootdown was elided). Such
/// faults are resolved by a local `invlpg` and a return-to-retry; the stub's
/// `iretq` re-executes the faulting instruction. Every other fault (genuine
/// userspace fault, or any kernel fault) is handed to
/// [`common_exception_handler`], which never returns.
#[cfg(not(test))]
extern "C" fn page_fault_handler(tf: *mut TrapFrame, error_code: u64)
{
    /// `#PF` error-code bits (Intel SDM Vol 3 §4.7).
    const ERR_PRESENT: u64 = 1 << 0;
    const ERR_WRITE: u64 = 1 << 1;
    const ERR_RSVD: u64 = 1 << 3;
    const ERR_INSTR: u64 = 1 << 4;

    // SAFETY: tf is constructed by isr_page_fault on this stack.
    let f = unsafe { &*tf };
    let from_user = (f.cs & 3) != 0;
    // A reserved-bit violation is never a stale-TLB fault; only well-formed
    // present/permission faults from userspace are retry candidates.
    if from_user && error_code & ERR_RSVD == 0
    {
        let cr2: u64;
        // SAFETY: CR2 holds the faulting linear address for a #PF; read-only at
        // ring 0.
        unsafe {
            core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nostack, nomem));
        }
        let write = error_code & ERR_WRITE != 0;
        let instr = error_code & ERR_INSTR != 0;
        // SAFETY: ring 0; the faulting thread's CR3 is still active (no context
        // switch since entry — the interrupt gate left IF=0).
        if unsafe { super::paging::user_fault_is_spurious(cr2, write, instr) }
        {
            // SAFETY: ring 0; drops the stale TLB entry so the retried
            // instruction re-walks the now-satisfying mapping.
            unsafe {
                super::paging::flush_page(cr2);
            }
            return;
        }

        // Genuine userspace page fault. If the faulting thread has a fault
        // handler bound, redirect the fault to it; on a resume reply the stub's
        // `iretq` re-executes the faulting instruction (now satisfiable) or
        // continues from a handler-modified PC.
        // SAFETY: from_user implies a running user thread; current_tcb is valid
        // in exception context (the kill path uses it too).
        let tcb = unsafe { crate::syscall::current_tcb() };
        // SAFETY: tcb is the running user thread; has_handler only reads the
        // atomic fault_handler field.
        let handler_bound = !tcb.is_null() && unsafe { crate::ipc::fault::has_handler(tcb) };
        if handler_bound
        {
            let present = error_code & ERR_PRESENT != 0;
            // SAFETY: tf is the live TrapFrame; the redirect points the TCB at it
            // for the block and returns whether to resume.
            if unsafe { redirect_user_page_fault(tcb, tf, cr2, write, instr, present) }
            {
                return;
            }
            // Handler declined (Kill) — fall through to terminate the thread.
        }
    }

    // Not a recoverable spurious fault and not resumed by a handler — kill
    // (userspace) or fatal (kernel).
    // SAFETY: tf is valid; common_exception_handler never returns.
    unsafe {
        common_exception_handler(tf.cast_const(), 14, error_code);
    }
}

/// Redirect a genuine userspace page fault to the faulting thread's bound fault
/// handler. Builds the `FAULT_KIND_VM` message describing the access and delegates
/// the block to [`redirect_user_fault`]. Returns `true` to resume, `false` to
/// terminate (handler declined or binding severed).
///
/// # Safety
/// `tcb` is the current user thread and has a bound handler; `frame` is the live
/// `#PF` [`TrapFrame`] on the current kernel stack; no lock is held.
#[cfg(not(test))]
unsafe fn redirect_user_page_fault(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    frame: *mut TrapFrame,
    cr2: u64,
    write: bool,
    instr: bool,
    present: bool,
) -> bool
{
    let mut access = 0u64;
    if write
    {
        access |= syscall::FAULT_ACCESS_WRITE;
    }
    if instr
    {
        access |= syscall::FAULT_ACCESS_EXEC;
    }
    if !write && !instr
    {
        access |= syscall::FAULT_ACCESS_READ;
    }
    if present
    {
        access |= syscall::FAULT_ACCESS_PRESENT;
    }

    // SAFETY: frame is valid.
    let rip = unsafe { (*frame).rip };
    let info = crate::ipc::fault::FaultInfo {
        kind: syscall::FAULT_KIND_VM,
        d1: cr2,
        d2: access,
        ip: rip,
    };

    // SAFETY: preconditions forwarded — handler bound, live frame, no lock held.
    unsafe { redirect_user_fault(tcb, frame, &info) }
}

/// Redirect a genuine userspace CPU exception (any vector routed through
/// [`exception_handler`]) to the faulting thread's bound fault handler. Builds the
/// `FAULT_KIND_EXCEPTION` message (normalized class + hardware error code +
/// faulting `rip`) and delegates the block to [`redirect_user_fault`]. Returns
/// `true` to resume, `false` to terminate.
///
/// # Safety
/// `tcb` is the current user thread and has a bound handler; `frame` is the live
/// exception [`TrapFrame`] on the current kernel stack; `vector`/`error_code` are
/// the trap metadata from the stub frame; no lock is held.
#[cfg(not(test))]
unsafe fn redirect_user_exception(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    frame: *mut TrapFrame,
    vector: u64,
    error_code: u64,
) -> bool
{
    // SAFETY: frame is valid.
    let ip = unsafe { (*frame).rip };
    let info = crate::ipc::fault::FaultInfo {
        kind: syscall::FAULT_KIND_EXCEPTION,
        d1: normalize_x86_exception(vector),
        d2: error_code,
        ip,
    };

    // SAFETY: preconditions forwarded — handler bound, live frame, no lock held.
    unsafe { redirect_user_fault(tcb, frame, &info) }
}

/// Map an x86-64 exception vector to the architecture-neutral
/// [`syscall::FAULT_EXC_UNKNOWN`]-family normalized code delivered in a
/// `FAULT_KIND_EXCEPTION` message. Vectors with a dedicated path (`#PF` = 14,
/// `#NM` = 7, NMI = 2) never reach here.
#[cfg(not(test))]
fn normalize_x86_exception(vector: u64) -> u64
{
    match vector
    {
        0 => syscall::FAULT_EXC_DIVIDE,              // #DE
        1 => syscall::FAULT_EXC_DEBUG,               // #DB
        3 => syscall::FAULT_EXC_BREAKPOINT,          // #BP
        4 => syscall::FAULT_EXC_OVERFLOW,            // #OF
        5 => syscall::FAULT_EXC_BOUND_RANGE,         // #BR
        6 => syscall::FAULT_EXC_ILLEGAL_INSTRUCTION, // #UD
        10..=13 => syscall::FAULT_EXC_PROTECTION,    // #TS #NP #SS #GP
        16 | 19 => syscall::FAULT_EXC_FP,            // #MF #XM
        17 => syscall::FAULT_EXC_ALIGNMENT,          // #AC
        _ => syscall::FAULT_EXC_UNKNOWN,
    }
}

/// Deliver `info` to `tcb`'s bound handler and block until it resolves the fault
/// or the binding is severed. Returns `true` if the thread should resume
/// (re-execute the faulting instruction, or continue from a handler-modified PC),
/// `false` if the fault is terminal.
///
/// `frame` is the live canonical [`TrapFrame`] the entry trampoline built on the
/// kernel stack — the same layout the register syscalls operate on — so
/// `(*tcb).trap_frame` is pointed at it directly with no copy. The kernel stack
/// (and thus the frame) is preserved across the block: the context switch saves
/// and restores the kernel rsp, so the pointer stays valid while the faulter is
/// descheduled. The handler's `SYS_THREAD_READ_REGS` / `SYS_THREAD_WRITE_REGS`
/// see and edit the live frame; on resume the trampoline's [`tf_resume_asm`]
/// writes any edits back into the iret frame. Symmetric with
/// `riscv64/interrupts.rs::redirect_user_fault`.
///
/// # Safety
/// `tcb` is the current user thread and has a bound handler; `frame` is the live
/// [`TrapFrame`] on the current kernel stack; no lock is held.
#[cfg(not(test))]
unsafe fn redirect_user_fault(
    tcb: *mut crate::sched::thread::ThreadControlBlock,
    frame: *mut TrapFrame,
    info: &crate::ipc::fault::FaultInfo,
) -> bool
{
    // SAFETY: tcb valid; repoint trap_frame at the live frame for the duration of
    // the block, restoring the prior pointer afterward.
    let saved_tf = unsafe { (*tcb).trap_frame };
    // SAFETY: tcb valid; trap_frame is the live-frame pointer read/edited by the
    // register syscalls while this thread is BlockedOnFault.
    unsafe {
        (*tcb).trap_frame = frame;
    }

    // SAFETY: handler bound; trap_frame points at the live frame; no lock held.
    let outcome = unsafe { crate::ipc::fault::fault_dispatch(tcb, info) };

    // SAFETY: restore the prior trap_frame pointer.
    unsafe {
        (*tcb).trap_frame = saved_tf;
    }

    matches!(outcome, crate::ipc::fault::FaultOutcome::Resume)
}

/// TLB shootdown IPI handler stub (vector 250).
///
/// Pushes the `placeholder + vector` prologue and jumps to
/// [`common_irq_trampoline`], which routes to `ipi_tlb_shootdown_handler` via
/// [`irq_dispatch`] — the handler services any shootdown request naming this CPU,
/// clears its acknowledgement bit, and EOIs.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn ipi_tlb_shootdown_stub()
{
    core::arch::naked_asm!(
        "push 0",   // placeholder
        "push 250", // vector
        "jmp {tramp}",
        tramp = sym common_irq_trampoline,
    );
}

/// NMI backtrace stub (vector 2 with IST=2).
///
/// Builds the canonical [`TrapFrame`] ([`tf_build_asm`]) — unconditionally, since
/// an NMI backtraces whatever ran (kernel or user) and the long-mode iret frame is
/// always present — calls the returning [`ipi_nmi_backtrace_handler`], then writes
/// back and `iretq`s ([`tf_resume_asm`]). The handler decides at runtime whether
/// the NMI is a watchdog backtrace request (returns normally → iretq fires) or a
/// real hardware NMI (falls through to `common_exception_handler` which never
/// returns — the resume tail is unreachable in that case). The two-word
/// `placeholder + vector` prologue matches the exception stubs' alignment parity.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn ipi_nmi_backtrace_stub()
{
    core::arch::naked_asm!(
        concat!(
            "push 0\n", // placeholder (NMI has no error code)
            "push 2\n", // vector
            tf_build_asm!(),
            "mov rdi, rsp\n",         // arg0 = *mut TrapFrame
            "mov rsi, [rsp + 168]\n", // arg1 = vector (= 2)
            "mov rdx, [rsp + 176]\n", // arg2 = error_code (= placeholder 0)
            "call {handler}\n",
            tf_resume_asm!(),
        ),
        handler = sym ipi_nmi_backtrace_handler,
    );
}

/// NMI body. Distinguishes a watchdog-requested backtrace from a real
/// hardware NMI via the per-CPU `nmi_backtrace_request` flag; on a watchdog ping it
/// dumps the saved frame to serial and returns (the stub's iretq
/// resumes the interrupted code). On a real NMI it tail-calls
/// `common_exception_handler` which never returns — the iretq tail of
/// the stub is dead code in that case.
///
/// NMI is not APIC-EOI'd, so no `acknowledge()` call.
#[cfg(not(test))]
extern "C" fn ipi_nmi_backtrace_handler(tf: *const TrapFrame, vector: u64, error_code: u64)
{
    let cpu = super::cpu::current_cpu() as usize;
    let requested = super::interrupts::nmi_backtrace_request(cpu)
        .is_some_and(|flag| flag.swap(false, core::sync::atomic::Ordering::AcqRel));
    if !requested
    {
        // Real hardware NMI — defer to the standard fatal path.
        // SAFETY: tf constructed by ipi_nmi_backtrace_stub above.
        unsafe {
            common_exception_handler(tf, vector, error_code);
        }
    }
    // SAFETY: tf constructed by ipi_nmi_backtrace_stub above.
    let f = unsafe { &*tf };
    // Use the NMI-safe console path: `CONSOLE_LOCK` is swap-and-
    // restored rather than spin-acquired, so an NMI that interrupts
    // the lock-holder does not deadlock the dump.
    crate::kprintln_nmi!(
        "NMI BACKTRACE: cpu={} rip={:#018x} rsp={:#018x} rbp={:#018x} cs={:#x} rflags={:#018x}",
        cpu,
        f.rip,
        f.rsp,
        f.rbp,
        f.cs,
        f.rflags
    );
    crate::kprintln_nmi!(
        "  rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
        f.rax,
        f.rbx,
        f.rcx,
        f.rdx
    );
    crate::kprintln_nmi!(
        "  rsi={:#018x} rdi={:#018x} rbp={:#018x} rsp={:#018x}",
        f.rsi,
        f.rdi,
        f.rbp,
        f.rsp
    );
    crate::kprintln_nmi!(
        "   r8={:#018x}  r9={:#018x} r10={:#018x} r11={:#018x}",
        f.r8,
        f.r9,
        f.r10,
        f.r11
    );
    crate::kprintln_nmi!(
        "  r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x}",
        f.r12,
        f.r13,
        f.r14,
        f.r15
    );
}

/// Wakeup IPI handler stub (vector 251).
///
/// Breaks idle CPUs out of `hlt` when work is enqueued. Pushes the
/// `placeholder + vector` prologue and jumps to [`common_irq_trampoline`], which
/// routes to `ipi_wakeup_handler` via [`irq_dispatch`]; the handler just sends EOI
/// (the interrupt itself wakes the CPU).
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn ipi_wakeup_stub()
{
    core::arch::naked_asm!(
        "push 0",   // placeholder
        "push 251", // vector
        "jmp {tramp}",
        tramp = sym common_irq_trampoline,
    );
}

/// TLB shootdown IPI handler.
///
/// Services every per-CPU shootdown request that names this CPU (flush the
/// requested VA, clear this CPU's acknowledgement bit), then sends EOI. The
/// dedicated vector means every delivery is a shootdown; a re-sent or stale IPI
/// that finds no request naming this CPU simply does no flush.
#[cfg(not(test))]
extern "C" fn ipi_tlb_shootdown_handler()
{
    let cpu_id = super::cpu::current_cpu() as usize;
    // SAFETY: IPI-handler context on cpu_id at ring 0; issuing TLB flushes here
    // is valid.
    unsafe {
        crate::mm::tlb_shootdown::service_shootdowns(cpu_id);
    }

    // Send EOI to local APIC.
    // SAFETY: Vector 250 is the TLB shootdown vector.
    super::interrupts::acknowledge(u32::from(super::interrupts::IPI_VECTOR_TLB_SHOOTDOWN));
}

/// Wakeup IPI handler (vector 251).
///
/// The interrupt itself breaks `hlt`, so this handler just sends EOI and returns.
/// No additional work is needed; the idle loop will check for runnable threads
/// immediately after returning from the interrupt.
#[cfg(not(test))]
extern "C" fn ipi_wakeup_handler()
{
    // Send EOI to local APIC. No other work needed; the interrupt wakes the CPU.
    // SAFETY: Vector 251 is the wakeup IPI vector.
    super::interrupts::acknowledge(u32::from(super::interrupts::IPI_VECTOR_WAKEUP));
}

// ── IDT population ────────────────────────────────────────────────────────────

/// Populate the IDT and execute `lidt`.
///
/// Must be called once during boot from a single-threaded context, after
/// the GDT is loaded (since gate descriptors reference `KERNEL_CS`).
///
/// # Safety
/// Must execute at ring 0.
#[cfg(not(test))]
pub unsafe fn init()
{
    // SAFETY: single-threaded boot.
    let idt = unsafe { &mut *core::ptr::addr_of_mut!(IDT) };

    // Helper: set gate for `vec` pointing to `handler` (unsafe extern "C" fn)
    // with IST index `ist`. Casts through `*const ()` to avoid lint.
    let mut set = |vec: usize, handler: unsafe extern "C" fn(), ist: u8| {
        idt[vec] = IdtEntry::new(handler as *const () as u64, ist, 0);
    };

    // Exception gates (vectors 0–31).
    set(0, isr0, 0);
    set(1, isr1, 0);
    // NMI — IST2. Dedicated stub: distinguishes watchdog backtrace
    // requests from real hardware NMIs (see ipi_nmi_backtrace_handler).
    set(2, ipi_nmi_backtrace_stub, 2);
    set(3, isr3, 0);
    set(4, isr4, 0);
    set(5, isr5, 0);
    set(6, isr6, 0);
    set(7, isr_nm, 0); // #NM — lazy FPU enable, not fatal
    set(8, isr8, 1); // Double Fault — IST1
    set(9, isr9, 0);
    set(10, isr10, 0);
    set(11, isr11, 0);
    set(12, isr12, 0);
    set(13, isr13, 0);
    set(14, isr_page_fault, 0); // #PF — spurious stale-TLB faults retry
    set(15, isr15, 0);
    set(16, isr16, 0);
    set(17, isr17, 0);
    set(18, isr18, 0);
    set(19, isr19, 0);
    set(20, isr20, 0);
    set(21, isr21, 0);
    set(22, isr22, 0);
    set(23, isr23, 0);
    set(24, isr24, 0);
    set(25, isr25, 0);
    set(26, isr26, 0);
    set(27, isr27, 0);
    set(28, isr28, 0);
    set(29, isr29, 0);
    set(30, isr30, 0);
    set(31, isr31, 0);

    // APIC timer and spurious.
    set(32, isr_timer, 0);
    set(255, isr_spurious, 0);

    // TLB shootdown IPI.
    set(
        usize::from(super::interrupts::IPI_VECTOR_TLB_SHOOTDOWN),
        ipi_tlb_shootdown_stub,
        0,
    );

    // Wakeup IPI.
    set(
        usize::from(super::interrupts::IPI_VECTOR_WAKEUP),
        ipi_wakeup_stub,
        0,
    );

    // Device IRQ stubs for IOAPIC GSIs 0–22 (vectors 33–55).
    set(33, isr_dev0, 0);
    set(34, isr_dev1, 0);
    set(35, isr_dev2, 0);
    set(36, isr_dev3, 0);
    set(37, isr_dev4, 0);
    set(38, isr_dev5, 0);
    set(39, isr_dev6, 0);
    set(40, isr_dev7, 0);
    set(41, isr_dev8, 0);
    set(42, isr_dev9, 0);
    set(43, isr_dev10, 0);
    set(44, isr_dev11, 0);
    set(45, isr_dev12, 0);
    set(46, isr_dev13, 0);
    set(47, isr_dev14, 0);
    set(48, isr_dev15, 0);
    set(49, isr_dev16, 0);
    set(50, isr_dev17, 0);
    set(51, isr_dev18, 0);
    set(52, isr_dev19, 0);
    set(53, isr_dev20, 0);
    set(54, isr_dev21, 0);
    set(55, isr_dev22, 0);

    // Load IDTR.
    let idtr = Idtr {
        limit: (core::mem::size_of_val(idt) - 1) as u16,
        base: idt.as_ptr() as u64,
    };
    // SAFETY: lidt is a valid ring-0 instruction; idtr is live on stack; IDT in BSS valid forever.
    unsafe {
        core::arch::asm!(
            "lidt [{0}]",
            in(reg) core::ptr::addr_of!(idtr),
            options(readonly, nostack, preserves_flags),
        );
    }
}

/// Load the already-populated IDT on the current CPU (AP startup path).
///
/// Unlike [`init`], this function does not re-populate the IDT — it only
/// executes `lidt` to load the shared BSS IDT on a new CPU. Must be called
/// after the AP has loaded its own GDT (since gate descriptors reference
/// `KERNEL_CS` which must be valid in the loaded GDT).
///
/// # Safety
/// Ring 0. GDT must be loaded before calling. IDT must have been populated by
/// [`init`] on the BSP first.
#[cfg(not(test))]
pub unsafe fn load()
{
    // SAFETY: IDT is in BSS and was populated by init(); valid for kernel lifetime.
    let idt = unsafe { &*core::ptr::addr_of!(IDT) };
    let idtr = Idtr {
        limit: (core::mem::size_of_val(idt) - 1) as u16,
        base: idt.as_ptr() as u64,
    };
    // SAFETY: lidt is valid at ring 0; idtr is live on stack; IDT in BSS is valid forever.
    unsafe {
        core::arch::asm!(
            "lidt [{0}]",
            in(reg) core::ptr::addr_of!(idtr),
            options(readonly, nostack, preserves_flags),
        );
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn idt_entry_new_present_interrupt_gate()
    {
        let e = IdtEntry::new(0xDEAD_BEEF_1234_5678, 0, 0);
        // Present bit (bit 7 of type_attr).
        assert!(e.type_attr & 0x80 != 0, "P not set");
        // Gate type = 0xE in low nibble.
        assert_eq!(e.type_attr & 0x0F, 0xE, "should be interrupt gate");
        // DPL = 0.
        assert_eq!((e.type_attr >> 5) & 3, 0);
    }

    #[test]
    fn idt_entry_offset_split_correctly()
    {
        let handler: u64 = 0x1234_5678_9ABC_DEF0;
        let e = IdtEntry::new(handler, 0, 0);
        assert_eq!(e.offset_low as u64, handler & 0xFFFF);
        assert_eq!(e.offset_mid as u64, (handler >> 16) & 0xFFFF);
        assert_eq!(e.offset_high as u64, (handler >> 32) & 0xFFFF_FFFF);
    }

    #[test]
    fn idt_entry_ist_stored()
    {
        let e = IdtEntry::new(0x1000, 3, 0);
        assert_eq!(e.ist & 0x7, 3);
    }

    #[test]
    fn idt_entry_selector_is_kernel_cs()
    {
        let e = IdtEntry::new(0x1000, 0, 0);
        assert_eq!(e.selector, KERNEL_CS);
    }

    #[test]
    fn idt_entry_reserved_is_zero()
    {
        let e = IdtEntry::new(0x1000, 0, 0);
        assert_eq!(e._reserved, 0);
    }
}
