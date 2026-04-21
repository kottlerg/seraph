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

// ── ExceptionFrame ────────────────────────────────────────────────────────────

/// Full register state saved on the stack by the ISR trampoline.
///
/// The trampoline pushes all GPRs before calling the exception handler, so
/// fault diagnostics can dump the complete register snapshot. Layout:
///
/// ```text
/// [rsp+0..120]  GPRs: rax rbx rcx rdx rsi rdi rbp r8-r15
/// [rsp+120]     vector        (pushed by ISR stub)
/// [rsp+128]     error_code    (hardware or dummy 0)
/// [rsp+136]     rip           (hardware)
/// [rsp+144]     cs            (hardware)
/// [rsp+152]     rflags        (hardware)
/// [rsp+160]     rsp           (hardware; pushed on CPL change only)
/// [rsp+168]     ss            (hardware; pushed on CPL change only)
/// ```
#[repr(C)]
pub struct ExceptionFrame
{
    // GPRs pushed by trampoline (lowest addresses).
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Hardware + stub fields (higher addresses).
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

// ── Common exception handler ──────────────────────────────────────────────────

/// Called from all exception stubs with a pointer to the exception frame.
///
/// If the fault originated in userspace (CPL != 0), the faulting thread is
/// terminated and a death notification is posted (if bound). If the fault
/// originated in the kernel, diagnostics are printed and the system halts.
///
/// # Safety
/// `frame` must point to a valid `ExceptionFrame` on the current stack.
#[cfg(not(test))]
unsafe extern "C" fn common_exception_handler(frame: *const ExceptionFrame) -> !
{
    // SAFETY: frame pointer is valid — constructed by ISR stubs on this stack.
    let f = unsafe { &*frame };
    // Read CR2 (faulting address) for page faults (vector 14).
    let cr2: u64 = if f.vector == 14
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
            x86_exception_name(f.vector),
            f.vector,
            f.error_code,
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
            // SAFETY: tcb validated non-null; state field always valid.
            unsafe {
                (*tcb).state = crate::sched::thread::ThreadState::Exited;
            }

            // Post death notification if bound (exit_reason = EXIT_FAULT_BASE + vector).
            // EXIT_FAULT_BASE = 0x1000 (matches syscall_abi::EXIT_FAULT_BASE).
            // SAFETY: tcb is valid; post_death_notification handles null check.
            unsafe {
                crate::sched::post_death_notification(tcb, 0x1000 + f.vector);
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
            x86_exception_name(f.vector),
            f.vector,
            f.error_code,
        );
        crate::kprintln!("  rip={:#018x}  cr2={:#018x}", f.rip, cr2);
        crate::kprintln!("  cs={:#x}  rflags={:#018x}", f.cs, f.rflags,);
        dump_x86_regs_console(f);
        fatal("unhandled kernel exception");
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

/// Dump all general-purpose registers from an x86-64 exception frame (serial only).
fn dump_x86_regs(f: &ExceptionFrame)
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
fn dump_x86_regs_console(f: &ExceptionFrame)
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

/// Common trampoline: saves GPRs and calls `common_exception_handler`.
///
/// At entry, the stack holds the ISR stub frame (vector + error code) and
/// hardware frame (rip, cs, rflags, rsp, ss). We push all GPRs to create
/// a full [`ExceptionFrame`], then pass a pointer to it.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn common_exception_trampoline()
{
    core::arch::naked_asm!(
        // Save all GPRs (must match ExceptionFrame field order).
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rbp",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        // rsp now points at the full ExceptionFrame.
        "mov rdi, rsp",
        "call {handler}",
        // common_exception_handler never returns; ud2 guards against it.
        "ud2",
        handler = sym common_exception_handler,
    );
}

// ── Exception stubs ───────────────────────────────────────────────────────────
// Vectors with hardware error codes: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30.

isr_stub!(isr0, 0, has_error_code = false, ist = 0);
isr_stub!(isr1, 1, has_error_code = false, ist = 0);
isr_stub!(isr2, 2, has_error_code = false, ist = 2); // NMI — IST2
isr_stub!(isr3, 3, has_error_code = false, ist = 0);
isr_stub!(isr4, 4, has_error_code = false, ist = 0);
isr_stub!(isr5, 5, has_error_code = false, ist = 0);
isr_stub!(isr6, 6, has_error_code = false, ist = 0);
isr_stub!(isr7, 7, has_error_code = false, ist = 0);
isr_stub!(isr8, 8, has_error_code = true, ist = 1); // Double Fault — IST1
isr_stub!(isr9, 9, has_error_code = false, ist = 0);
isr_stub!(isr10, 10, has_error_code = true, ist = 0);
isr_stub!(isr11, 11, has_error_code = true, ist = 0);
isr_stub!(isr12, 12, has_error_code = true, ist = 0);
isr_stub!(isr13, 13, has_error_code = true, ist = 0);
isr_stub!(isr14, 14, has_error_code = true, ist = 0);
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

// ── Device IRQ stubs ──────────────────────────────────────────────────────────

/// Generate a naked device IRQ stub for IDT vector `$vector`.
///
/// Each stub:
/// 1. Saves all caller-saved registers.
/// 2. Calls `irq::dispatch_device_irq(gsi)` where `gsi = vector - 33`.
/// 3. Restores registers and executes `iretq`.
///
/// `dispatch_device_irq` handles masking and EOI internally; the stub itself
/// does not interact with the APIC or IOAPIC.
///
/// # Modification notes
/// - To add more GSIs: invoke `device_irq_stub!(isr_devN, N)` for each
///   new vector N, then add `set(N, isr_devN, 0)` in `init()`.
///
/// Generate a naked device IRQ stub for IDT vector `DEVICE_VECTOR_BASE + $gsi`.
///
/// Each stub:
/// 1. Saves all caller-saved registers.
/// 2. Loads the GSI number into `edi` (first argument register).
/// 3. Calls `irq::dispatch_device_irq(gsi)`.
/// 4. Restores registers and executes `iretq`.
///
/// `dispatch_device_irq` handles masking, signal delivery, and EOI internally.
///
/// # Modification notes
/// - To add more GSIs: `device_irq_stub!(isr_devN, N)` then `set(33+N, isr_devN, 0)`.
macro_rules! device_irq_stub {
    ($name:ident, $gsi:literal) => {
        #[cfg(not(test))]
        #[unsafe(naked)]
        unsafe extern "C" fn $name()
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
                concat!("mov edi, ", $gsi), // GSI as first argument
                "call {dispatch}",
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
                dispatch = sym crate::irq::dispatch_device_irq,
            );
        }
    };
}

device_irq_stub!(isr_dev0, 0);
device_irq_stub!(isr_dev1, 1);
device_irq_stub!(isr_dev2, 2);
device_irq_stub!(isr_dev3, 3);
device_irq_stub!(isr_dev4, 4);
device_irq_stub!(isr_dev5, 5);
device_irq_stub!(isr_dev6, 6);
device_irq_stub!(isr_dev7, 7);
device_irq_stub!(isr_dev8, 8);
device_irq_stub!(isr_dev9, 9);
device_irq_stub!(isr_dev10, 10);
device_irq_stub!(isr_dev11, 11);
device_irq_stub!(isr_dev12, 12);
device_irq_stub!(isr_dev13, 13);
device_irq_stub!(isr_dev14, 14);
device_irq_stub!(isr_dev15, 15);
device_irq_stub!(isr_dev16, 16);
device_irq_stub!(isr_dev17, 17);
device_irq_stub!(isr_dev18, 18);
device_irq_stub!(isr_dev19, 19);
device_irq_stub!(isr_dev20, 20);
device_irq_stub!(isr_dev21, 21);
device_irq_stub!(isr_dev22, 22);

// ── Timer and spurious stubs ──────────────────────────────────────────────────

/// APIC timer ISR stub (vector 32).
///
/// Calls `timer::timer_isr`, which increments the tick counter and sends EOI.
#[cfg(not(test))]
#[unsafe(naked)]
pub unsafe extern "C" fn isr_timer()
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
        handler = sym super::timer::timer_isr,
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

/// TLB shootdown IPI handler stub (vector 250).
///
/// Reads the shootdown request from `TLB_SHOOTDOWN`, flushes the TLB for the
/// target address space, and acknowledges by clearing this CPU's bit.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn ipi_tlb_shootdown_stub()
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
        handler = sym ipi_tlb_shootdown_handler,
    );
}

/// Wakeup IPI handler stub (vector 251).
///
/// Breaks idle CPUs out of `hlt` when work is enqueued. The handler itself
/// just sends EOI; the interrupt is sufficient to wake the CPU.
#[cfg(not(test))]
#[unsafe(naked)]
unsafe extern "C" fn ipi_wakeup_stub()
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
        handler = sym ipi_wakeup_handler,
    );
}

/// TLB shootdown IPI handler.
///
/// Reads the shootdown request, flushes the TLB for the target address space,
/// and acknowledges by clearing this CPU's bit in the pending mask.
#[cfg(not(test))]
extern "C" fn ipi_tlb_shootdown_handler()
{
    // SAFETY: Acquire ordering ensures we see the root_phys stored by initiator
    let root_phys = crate::mm::tlb_shootdown::TLB_SHOOTDOWN
        .root_phys
        .load(core::sync::atomic::Ordering::Acquire);

    // Flush TLB for the target page.
    let va = crate::mm::tlb_shootdown::TLB_SHOOTDOWN
        .flush_va
        .load(core::sync::atomic::Ordering::Acquire);
    if va == u64::MAX || root_phys == 0
    {
        // Full TLB flush.
        // SAFETY: CR3 write invalidates all non-global TLB entries.
        unsafe {
            super::paging::flush_tlb_all();
        }
    }
    else
    {
        // Per-VA flush via invlpg.
        // SAFETY: va is a valid virtual address from the shootdown initiator.
        unsafe {
            super::paging::flush_page(va);
        }
    }

    // Acknowledge by clearing our bit in pending_cpus
    let cpu_id = super::cpu::current_cpu();
    let mask = !(1u64 << cpu_id);

    // SAFETY: Release ordering ensures TLB flush completes before bit clear is visible
    crate::mm::tlb_shootdown::TLB_SHOOTDOWN
        .pending_cpus
        .fetch_and(mask, core::sync::atomic::Ordering::Release);

    // Send EOI to local APIC
    // SAFETY: Vector 250 is the TLB shootdown vector
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
    set(2, isr2, 2); // NMI — IST2
    set(3, isr3, 0);
    set(4, isr4, 0);
    set(5, isr5, 0);
    set(6, isr6, 0);
    set(7, isr7, 0);
    set(8, isr8, 1); // Double Fault — IST1
    set(9, isr9, 0);
    set(10, isr10, 0);
    set(11, isr11, 0);
    set(12, isr12, 0);
    set(13, isr13, 0);
    set(14, isr14, 0);
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
