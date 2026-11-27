// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/cpu.rs

//! x86-64 CPU control primitives: CPUID and the core key it gives, CR4 and MSR
//! access, the fault-recoverable user-copy routine, SMEP/SMAP enablement and
//! the other ring-3 controls of CR4, the ring-3 controls held in MSRs
//! (`set_user_msr_controls`), PCID enablement, the boot-time baseline feature
//! gate, per-CPU GS-base install and lookup, the kernel trap stack, interrupt
//! control and halt, the fence ahead of an x2APIC MSR write, and the
//! debug-build kernel-entry RFLAGS check.
//!
//! `current_stack_pointer`, `load_word_racy`, the CR4/MSR accessors, `x2apic_wrmsr_fence`,
//! `copy_user`, `in_user_copy`, the enable routines, `set_user_msr_controls`,
//! `verify_baseline`, `install_percpu`, the trap-stack and interrupt save/restore
//! primitives, and the kernel-entry flags check are built only under
//! `#[cfg(not(test))]` (`copy_user` and `verify_baseline` have host stubs). `cpuid`, `cpuid_subleaf`, `smt_core_key`, `core_key`,
//! `current_cpu` (which returns 0 under test), `halt_until_interrupt`,
//! `disable_interrupts`, `halt_loop`, and the no-op
//! `disable_unswitched_user_state` are also built for host tests.

// ── CPUID ─────────────────────────────────────────────────────────────────────

/// Execute CPUID with leaf `leaf` (sub-leaf 0). Returns `(eax, ebx, ecx, edx)`.
///
/// `rbx` is callee-saved and reserved by LLVM, so the EBX result must be
/// shuttled out without leaving it in `rbx`. The `core` intrinsic does this
/// correctly; a hand-rolled `push rbx` / `mov out, ebx` / `pop rbx` sequence is
/// fragile because the chosen output register may itself alias `rbx`, in which
/// case the `pop` clobbers the result.
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32)
{
    cpuid_subleaf(leaf, 0)
}

/// Execute CPUID with leaf `leaf` and sub-leaf `subleaf`. Returns
/// `(eax, ebx, ecx, edx)`, through the same intrinsic as [`cpuid`].
pub fn cpuid_subleaf(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32)
{
    let r = core::arch::x86_64::__cpuid_count(leaf, subleaf);
    (r.eax, r.ebx, r.ecx, r.edx)
}

// ── Core topology ─────────────────────────────────────────────────────────────

/// `CPUID` level type of the SMT level in leaves 0BH and 1FH (`ECX[15:8]`).
const TOPOLOGY_LEVEL_SMT: u32 = 1;

/// Sub-leaves of leaf 0BH or 1FH read before the walk gives up on a terminating
/// (type 0) level. Leaf 1FH defines six level types (SMT, core, module, tile,
/// die, die group), so a CPU that reports more is defective; the bound keeps
/// such a CPU from looping the walk.
const TOPOLOGY_MAX_SUBLEAVES: u32 = 16;

/// The core key of the CPU whose `CPUID` reads through `cpuid` (leaf, sub-leaf
/// to EAX, EBX, ECX, EDX): its x2APIC ID shifted right past the SMT level's
/// bits, so the logical CPUs of one core, and only they, share it.
///
/// The topology leaf is 1FH where the CPU enumerates it (a highest basic leaf
/// of at least 1FH and a sub-leaf 0 whose `EBX` is not zero), else 0BH, as the
/// Intel SDM Vol. 2A `CPUID` leaf 1FH directs; AMD reports 0BH. The walk reads
/// sub-leaves up to the first of level type 0 and takes the shift (`EAX[4:0]`)
/// of the SMT level (type 1). A CPU with no SMT level shifts by 0: each of its
/// logical CPUs is a core. `None` when the leaf enumerates no level at all
/// (sub-leaf 0's `EBX` is zero), where `EDX` is not an x2APIC ID.
pub fn smt_core_key(cpuid: impl Fn(u32, u32) -> [u32; 4]) -> Option<u32>
{
    let max_basic = cpuid(0, 0)[0];
    let leaf = if max_basic >= 0x1F && cpuid(0x1F, 0)[1] != 0
    {
        0x1F
    }
    else
    {
        0x0B
    };
    let [_, ebx, _, x2apic_id] = cpuid(leaf, 0);
    if ebx == 0
    {
        return None;
    }
    let mut shift = 0;
    for subleaf in 0..TOPOLOGY_MAX_SUBLEAVES
    {
        let [eax, _, ecx, _] = cpuid(leaf, subleaf);
        let level_type = (ecx >> 8) & 0xFF;
        if level_type == 0
        {
            break;
        }
        if level_type == TOPOLOGY_LEVEL_SMT
        {
            shift = eax & 0x1F;
            break;
        }
    }
    Some(x2apic_id >> shift)
}

/// The key of the core logical CPU `cpu` runs on: equal for exactly the CPUs
/// that share one core. Called on CPU `cpu` itself (`topology::record_this_cpu`),
/// since it reads that CPU's `CPUID` ([`smt_core_key`]). A CPU whose topology
/// leaf enumerates no level keys by `cpu` and counts as a core of its own;
/// every CPU of one machine reports the same leaves, so its keys do not mix
/// with x2APIC-derived ones.
pub fn core_key(cpu: u32) -> u32
{
    smt_core_key(|leaf, subleaf| {
        let (eax, ebx, ecx, edx) = cpuid_subleaf(leaf, subleaf);
        [eax, ebx, ecx, edx]
    })
    .unwrap_or(cpu)
}

// ── Stack pointer ───────────────────────────────────────────────────────────────

/// Read the current stack pointer (`rsp`).
///
/// Used by the panic-path backtrace scanner to bound the kernel-stack walk,
/// and at `kernel_entry`'s first statement to locate the handoff stack
/// (`crate::stack_depth::note_boot_entry`).
#[cfg(not(test))]
pub fn current_stack_pointer() -> u64
{
    let sp: u64;
    // SAFETY: reads the stack pointer register only; no memory access, no clobbers.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags));
    }
    sp
}

/// Store `value` to each of the `words` 8-byte words from `p` up, with one
/// `rep stosq`, which fast-string hardware performs a cache line at a time.
/// Used by the kernel stack paint (`crate::stack_depth::paint`).
///
/// # Safety
/// `[p, p + words * 8)` is writable, 8-byte aligned, and the caller's alone.
pub unsafe fn fill_words(p: *mut u64, words: usize, value: u64)
{
    // SAFETY: the span is writable, aligned and the caller's per the contract.
    // `rep stosq` stores `rax` to `[rdi]` `rcx` times, stepping `rdi` up by 8
    // (the direction flag is clear on entry, as the Rust ABI keeps it); it
    // clobbers `rdi` and `rcx`, and no flag.
    unsafe {
        core::arch::asm!(
            "rep stosq",
            inout("rdi") p => _,
            inout("rcx") words => _,
            in("rax") value,
            options(nostack, preserves_flags)
        );
    }
}

/// Load one word that another CPU may be writing concurrently, as an opaque
/// machine load the compiler neither elides nor reasons about.
///
/// For diagnostics that sample memory a running CPU owns (the idle-stack depth
/// scan, `crate::stack_depth`): a Rust read racing a plain store is undefined
/// behaviour, a `mov` instruction is not, and a stale value only changes the
/// sample.
///
/// # Safety
/// `p` is a mapped, 8-byte aligned kernel address.
#[cfg(not(test))]
pub unsafe fn load_word_racy(p: *const u64) -> u64
{
    let v: u64;
    // SAFETY: p is mapped and aligned per the contract; a load has no side
    // effect.
    unsafe {
        core::arch::asm!(
            "mov {}, [{}]",
            out(reg) v,
            in(reg) p,
            options(nostack, readonly, preserves_flags)
        );
    }
    v
}

// ── CR4 ───────────────────────────────────────────────────────────────────────

/// Read the current value of CR4.
#[cfg(not(test))]
pub fn read_cr4() -> u64
{
    let val: u64;
    // SAFETY: CR4 readable at ring 0.
    unsafe {
        core::arch::asm!("mov {}, cr4", out(reg) val, options(nostack, nomem));
    }
    val
}

/// Write `val` to CR4.
///
/// # Safety
/// Caller must ensure the new CR4 value is valid and will not fault.
#[cfg(not(test))]
pub unsafe fn write_cr4(val: u64)
{
    // SAFETY: caller's responsibility.
    unsafe {
        core::arch::asm!("mov cr4, {}", in(reg) val, options(nostack, nomem));
    }
}

// ── MSR ───────────────────────────────────────────────────────────────────────

/// Read a model-specific register `msr`.
///
/// # Safety
/// Must execute at ring 0. The MSR must exist on this CPU.
#[cfg(not(test))]
pub unsafe fn read_msr(msr: u32) -> u64
{
    let lo: u32;
    let hi: u32;
    // SAFETY: caller guarantees ring 0 and valid MSR.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nostack, nomem),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}

/// Order every earlier memory access ahead of a following x2APIC MSR write.
///
/// A WRMSR to an x2APIC register is not serializing (Intel SDM Vol. 3A
/// § 11.12.3), so an IPI sent through the x2APIC ICR can reach its target
/// before this CPU's earlier stores are visible there; `mfence; lfence`
/// ahead of the write closes that gap.
#[cfg(not(test))]
pub fn x2apic_wrmsr_fence()
{
    // SAFETY: `mfence; lfence` order memory accesses and instruction execution
    // only; they clobber no register or flag and need only SSE2, which every
    // x86-64 CPU has. Without `nomem` the compiler also keeps earlier memory
    // accesses ahead of the block.
    unsafe {
        core::arch::asm!("mfence", "lfence", options(nostack, preserves_flags));
    }
}

/// Write `val` to model-specific register `msr`.
///
/// # Safety
/// Must execute at ring 0. The MSR must exist and the value must be valid.
#[cfg(not(test))]
pub unsafe fn write_msr(msr: u32, val: u64)
{
    let lo = (val & 0xFFFF_FFFF) as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: caller's responsibility.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nostack, nomem),
        );
    }
}

/// This CPU's shadow-stack pointer, or zero where supervisor shadow stacks are
/// off on it: `rdsspq` is a no-op then (it is encoded in the reserved-NOP
/// space, and runs as one without CET), and leaves the zeroed register.
#[cfg(not(test))]
pub fn shadow_stack_pointer() -> u64
{
    let ssp: u64;
    // SAFETY: `rdsspq` reads the shadow-stack pointer into a register, or does
    // nothing; the `xor` clobbers the flags.
    unsafe {
        core::arch::asm!(
            "xor {0:e}, {0:e}",
            "rdsspq {0}",
            out(reg) ssp,
            options(nomem, nostack),
        );
    }
    ssp
}

// ── User-copy primitive (fault-recoverable) ───────────────────────────────────

// `copy_user` is the sole sanctioned path for kernel access to user memory. It
// owns the SMAP access window (`stac`/`clac`) and is covered by the page-fault
// handler's user-copy recovery: a fault on an unmapped or read-only user span
// inside the copy ends the copy where it stands instead of panicking. The
// handler moves `rep movsb`'s count at the fault (the bytes not copied) into
// `rax` and zeroes `rcx`, and returns to the same instruction, which then
// copies nothing, so the routine closes the window and returns that count.
// The return address is left as it was: with shadow
// stacks on, a return to another address raises #CP. See `crate::uaccess` for
// the typed `copy_to_user`/`copy_from_user` wrappers and
// `idt::page_fault_handler` for the hook. Every kernel entry clears DF (SFMASK
// on SYSCALL, `cld` in the IDT stubs), so `rep movsb` copies forward.
#[cfg(not(test))]
core::arch::global_asm!(
    ".section .text.copy_user, \"ax\"",
    ".global __copy_user",
    ".global __copy_user_fault_start",
    ".global __copy_user_fault_end",
    // fn __copy_user(dst: rdi, src: rsi, len: rdx) -> rax (bytes not copied)
    "__copy_user:",
    "    stac",
    "    mov rcx, rdx",
    "    xor eax, eax", // a copy that does not fault leaves no byte behind
    "__copy_user_fault_start:",
    "    rep movsb",
    "__copy_user_fault_end:",
    "    clac",
    "    ret",
);

#[cfg(not(test))]
unsafe extern "C" {
    /// Raw user-copy routine (`dst=rdi, src=rsi, len=rdx`); returns 0 on success
    /// or, if a fault on the user span was recovered, the bytes not copied.
    fn __copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize;
    /// First byte of the faultable copy instruction.
    static __copy_user_fault_start: u8;
    /// First byte past the faultable copy instruction.
    static __copy_user_fault_end: u8;
}

/// Copy `len` bytes from `src` to `dst` across the SMAP window with fault
/// recovery. Returns 0 on success; when a user-span fault was recovered, the
/// bytes not copied (at least 1), so the faulting byte is at offset
/// `len - returned`.
///
/// # Safety
/// Must execute at ring 0 with SMAP enabled. The operands must be arranged so the
/// user pointer is the only one that may fault; the non-user side must be valid
/// for `len` bytes.
#[cfg(not(test))]
#[inline]
pub unsafe fn copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize
{
    // SAFETY: forwarded to the asm routine; a fault on the user span is recovered
    // by the page-fault handler, which ends the copy in place.
    unsafe { __copy_user(dst, src, len) }
}

/// Host-test stub: `stac`/`clac` are privileged and the test pointers never
/// fault, so perform a plain copy and report success.
#[cfg(test)]
pub unsafe fn copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize
{
    // SAFETY: caller guarantees src/dst valid for len bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, len);
    }
    0
}

/// Whether `pc` lies within `copy_user`'s faultable region. Consulted by the
/// page-fault handler on a kernel-mode fault to convert an unmapped or
/// read-only user access into an error return instead of a panic.
#[cfg(not(test))]
pub fn in_user_copy(pc: u64) -> bool
{
    let lo = core::ptr::addr_of!(__copy_user_fault_start) as u64;
    let hi = core::ptr::addr_of!(__copy_user_fault_end) as u64;
    pc >= lo && pc < hi
}

// ── SMEP / SMAP ───────────────────────────────────────────────────────────────

/// `CR4.FSGSBASE` (bit 16): enables the ring-3 `wrgsbase`/`wrfsbase`
/// instructions.
const CR4_FSGSBASE: u64 = 1 << 16;

/// `CR4.UMIP` (bit 11): faults the descriptor-table reads `SGDT`, `SIDT`,
/// `SLDT`, `SMSW`, and `STR` at CPL > 0 with `#GP`.
const CR4_UMIP: u64 = 1 << 11;

/// `CR4.VME` (bit 0): virtual-8086 mode extensions. No effect in 64-bit mode;
/// cleared so no CPU keeps a firmware value.
const CR4_VME: u64 = 1 << 0;

/// `CR4.PVI` (bit 1): protected-mode virtual interrupts. Turns a ring-3 `CLI`
/// or `STI` under `IOPL` 0, which otherwise raises `#GP`, into a write of
/// `RFLAGS.VIF`.
const CR4_PVI: u64 = 1 << 1;

/// `CR4.TSD` (bit 2): faults `RDTSC` and `RDTSCP` at CPL > 0 with `#GP`.
const CR4_TSD: u64 = 1 << 2;

/// `CR4.PCE` (bit 8): lets `RDPMC` execute at CPL > 0.
const CR4_PCE: u64 = 1 << 8;

/// `CR4.KL` (bit 19): enables the Key Locker instructions, which run at
/// CPL 3 and use the per-CPU wrapping key (`IWKey`), which the kernel neither
/// loads nor switches.
const CR4_KL: u64 = 1 << 19;

/// `CR4.PKE` (bit 22): user-mode protection keys. Makes bits \[62:59\] of a
/// user leaf its key and `RDPKRU`/`WRPKRU` executable at CPL 3; `PKRU` is not
/// an XCR0 component the kernel enables, so it would not be switched.
const CR4_PKE: u64 = 1 << 22;

/// `CR4.PKS` (bit 24): supervisor protection keys. Makes bits \[62:59\] of a
/// supervisor leaf its key, checked against `IA32_PKRS`.
const CR4_PKS: u64 = 1 << 24;

/// `CR4.UINTR` (bit 25): user interrupts. Enables `CLUI`, `STUI`, `TESTUI`,
/// `UIRET` and `SENDUIPI` at CPL 3, whose state the kernel does not switch.
const CR4_UINTR: u64 = 1 << 25;

/// The CR4 controls ring 3 reaches that the kernel does not grant, cleared on
/// every CPU by [`enable_smep_smap`]. `FSGSBASE`, `TSD` and `PCE` are
/// documented there; `PKS` is the supervisor half of `PKE` and is cleared
/// with it. `PCE` is the one the kernel grants afterwards: `perfmon` sets it
/// per thread.
const CR4_USER_CONTROLS_DENIED: u64 =
    CR4_VME | CR4_PVI | CR4_TSD | CR4_PCE | CR4_FSGSBASE | CR4_KL | CR4_PKE | CR4_PKS | CR4_UINTR;

/// Enable Supervisor Mode Execution Prevention (SMEP) and Supervisor Mode
/// Access Prevention (SMAP) by setting CR4 bits 20 and 21, set `CR4.UMIP`
/// where the CPU has it, and clear every CR4 control ring 3 reaches that the
/// kernel does not grant ([`CR4_USER_CONTROLS_DENIED`]), which firmware may
/// have left set.
///
/// The BSP runs on the CR4 the firmware left and each AP on the trampoline's,
/// so this step sets or clears each of these bits explicitly, and every CPU
/// ends with the same ones. With TSD and PCE clear, ring 3 reads the timestamp
/// counter (`RDTSC`, `RDTSCP`) and no performance counter (`RDPMC` raises
/// `#GP`), the counter set
/// [capability-model.md](../../../../../docs/capability-model.md)
/// § Microarchitectural Isolation states. The clear PCE is each CPU's starting
/// grant: `perfmon` sets it while a thread bound with `SYS_PMU_BIND` runs and
/// clears it again for any other (core/kernel/docs/perfmon.md). With PVI, KL,
/// PKE and UINTR clear, a ring-3 `CLI` or `STI` raises `#GP`, and the Key Locker, protection-key and
/// user-interrupt instructions raise `#UD`: each reaches per-CPU state the
/// kernel does not switch between threads.
///
/// `PKS` is cleared because a supervisor key is the kernel's to assign: with
/// it set, the firmware's `IA32_PKRS` would govern the kernel's own accesses to
/// its key-0 pages. Supervisor keys could serve the kernel later, to fence
/// regions such as the page tables from its own stray writes. Adopting them
/// means programming `IA32_PKRS` on every CPU and setting `PKS` here, not
/// keeping the firmware's.
///
/// With FSGSBASE off, ring 3 can change its GS base only by loading a GDT
/// selector, whose base is 0, so a user GS base is never a kernel-half address;
/// the paranoid NMI/`#MC`/`#DF`/`#DB` entry (`idt.rs` `paranoid_entry_asm`)
/// relies on that to tell the user GS base from the kernel's.
///
/// With UMIP on, ring 3 cannot read the IDTR or GDTR, whose bases are kernel
/// addresses: the static IDT and the BSP's static GDT disclose the KASLR image
/// slide, and an AP's GDT, in the direct map, the direct-map base. UMIP is opportunistic
/// ([platform-requirements.md](../../../../../docs/platform-requirements.md) § x86-64
/// Classification); without it that read remains, as
/// [cross-boundary-disclosure.md](../../../docs/cross-boundary-disclosure.md) § Surface
/// inventory records.
///
/// Checks CPUID.07H:EBX bit 7 (SMEP) and bit 20 (SMAP), and CPUID.07H:ECX bit 2
/// (UMIP). Halts with a fatal message if SMEP or SMAP is absent, because the
/// security model requires both.
///
/// # Safety
/// Must execute at ring 0. The IDT need not be loaded: CPUID gates every bit
/// this sets and the [`CR4_USER_CONTROLS_DENIED`] bits are only cleared, so
/// the CR4 write cannot fault, and the BSP calls this before `idt::init`.
#[cfg(not(test))]
#[expect(
    clippy::similar_names,
    reason = "smep_present and smap_present are distinct CPU security features"
)]
pub unsafe fn enable_smep_smap()
{
    // CPUID leaf 7, sub-leaf 0.
    let (_eax, ebx, ecx, _edx) = cpuid(7);
    let smep_present = (ebx >> 7) & 1 != 0;
    let smap_present = (ebx >> 20) & 1 != 0;
    let umip_present = (ecx >> 2) & 1 != 0;
    if !smep_present
    {
        crate::fatal("SMEP not supported by CPU — required");
    }
    if !smap_present
    {
        crate::fatal("SMAP not supported by CPU — required");
    }
    // Bit 20 = SMEP, bit 21 = SMAP.
    let mut cr4 = (read_cr4() & !CR4_USER_CONTROLS_DENIED) | (1 << 20) | (1 << 21);
    if umip_present
    {
        cr4 |= CR4_UMIP;
    }
    // SAFETY: CPUID confirmed SMEP and SMAP, and UMIP whenever its bit is set;
    // the new CR4 value is valid.
    unsafe {
        write_cr4(cr4);
    }
}

// ── User-mode MSR controls ────────────────────────────────────────────────────

/// `IA32_TSC_AUX`: the value `RDTSCP` returns in ECX and `RDPID` returns.
const IA32_TSC_AUX: u32 = 0xC000_0103;

/// `MSR_MISC_FEATURES_ENABLES` (Intel): bit 0 turns ring-3 `CPUID` into `#GP`
/// (CPUID faulting); bit 1 lets ring 3 execute `MONITOR`/`MWAIT` (Xeon Phi).
const MSR_MISC_FEATURES_ENABLES: u32 = 0x140;

/// The [`MSR_MISC_FEATURES_ENABLES`] bits cleared: CPUID faulting and ring-3
/// `MONITOR`/`MWAIT`.
const MISC_FEATURES_USER_DENIED: u64 = (1 << 0) | (1 << 1);

/// `IA32_U_CET`: ring 3's CET controls (shadow stack, indirect-branch
/// tracking), in effect while `CR4.CET` is set.
const IA32_U_CET: u32 = 0x6A0;

/// `HWCR` (AMD).
const AMD_HWCR: u32 = 0xC001_0015;

/// `HWCR.CpuidUserDis` (bit 35): turns ring-3 `CPUID` into `#GP`.
const AMD_HWCR_CPUID_USER_DIS: u64 = 1 << 35;

/// Set this CPU's user-visible MSR controls to the kernel's values, replacing
/// what the firmware or reset left, as `enable_smep_smap` does for CR4:
///
/// - `IA32_TSC_AUX` = 0, where the CPU has `RDTSCP` (`CPUID.80000001H:EDX[27]`)
///   or `RDPID` (`CPUID.(EAX=07H,ECX=0):ECX[22]`), the instructions that read it
///   at CPL 3: ring 3 reads 0 as the processor identifier on every CPU, and
///   learns nothing the firmware stored there. A CPU with neither has no
///   instruction that reads it.
/// - CPUID faulting off: Intel's `MSR_MISC_FEATURES_ENABLES` bits 0 and 1
///   (with ring-3 `MONITOR`/`MWAIT`) cleared where the MSR exists, which the
///   write learns from a recovering read ([`super::idt::msr_recovering`]: the
///   MSR has no CPUID enumeration); AMD's `HWCR.CpuidUserDis` cleared where
///   `CPUID.80000021H:EAX[17]` enumerates it. Ring 3 executes `CPUID`, which
///   Rust's runtime feature detection does. A CPU without either control
///   cannot fault ring-3 `CPUID`.
/// - `IA32_U_CET` = 0, where the CPU has CET shadow stacks
///   (`CPUID.(EAX=07H,ECX=0):ECX[7]`) or indirect-branch tracking (`EDX[20]`):
///   ring 3 runs with neither, whatever the firmware left, once the kernel sets
///   `CR4.CET` for its own shadow stacks (`shadow_stack::enable`). A CPU with
///   neither has no user CET control.
///
/// `EFER`'s user-visible bits are set by `syscall::init`, which writes the
/// register. § User-mode hardware controls of
/// [core/kernel/docs/cross-boundary-disclosure.md](../../../docs/cross-boundary-disclosure.md)
/// lists every control.
///
/// # Safety
/// Ring 0 on the kernel's GDT, interrupts off, and no supervisor shadow stack
/// on this CPU ([`super::idt::msr_recovering`]'s contract): `interrupts::init`
/// on the BSP after `idt::init`, and `interrupts::init_ap` on each AP, both
/// before `shadow_stack::enable`.
#[cfg(not(test))]
pub unsafe fn set_user_msr_controls()
{
    let max_extended = cpuid(0x8000_0000).0;
    let rdtscp = max_extended >= 0x8000_0001 && (cpuid(0x8000_0001).3 >> 27) & 1 != 0;
    // Leaf 7 sub-leaf 0: ECX (.2) and EDX (.3) feature flags.
    let leaf7 = cpuid_subleaf(7, 0);
    let rdpid = (leaf7.2 >> 22) & 1 != 0;
    if rdtscp || rdpid
    {
        // SAFETY: ring 0; CPUID enumerates RDTSCP or RDPID, so IA32_TSC_AUX
        // exists, and every value is valid in its low 32 bits.
        unsafe { write_msr(IA32_TSC_AUX, 0) };
    }

    // SAFETY: the caller's contract is `msr_recovering`'s; a read of an MSR
    // the CPU lacks faults and is recovered as `None`.
    let misc = unsafe { super::idt::msr_recovering(MSR_MISC_FEATURES_ENABLES, None) };
    if let Some(misc) = misc.filter(|misc| misc & MISC_FEATURES_USER_DENIED != 0)
    {
        // SAFETY: as for the read. The MSR exists, and clearing its bits
        // writes zero to a bit the CPU does not implement, which it accepts.
        // A refused write is recovered and leaves the MSR as it was.
        unsafe {
            super::idt::msr_recovering(
                MSR_MISC_FEATURES_ENABLES,
                Some(misc & !MISC_FEATURES_USER_DENIED),
            )
        };
    }

    let cet = (leaf7.2 >> 7) & 1 != 0 || (leaf7.3 >> 20) & 1 != 0;
    if cet
    {
        // SAFETY: ring 0; CPUID enumerates a CET feature, so IA32_U_CET exists,
        // and 0 (every control off) is valid.
        unsafe { write_msr(IA32_U_CET, 0) };
    }

    if max_extended >= 0x8000_0021 && (cpuid(0x8000_0021).0 >> 17) & 1 != 0
    {
        // SAFETY: ring 0; CPUID enumerates CpuidUserDis, so HWCR exists.
        let hwcr = unsafe { read_msr(AMD_HWCR) };
        if hwcr & AMD_HWCR_CPUID_USER_DIS != 0
        {
            // SAFETY: as for the read; the bit is writable, and only it
            // changes.
            unsafe { write_msr(AMD_HWCR, hwcr & !AMD_HWCR_CPUID_USER_DIS) };
        }
    }
}

// ── PCID (Process-Context Identifiers) ────────────────────────────────────────

/// Enable PCID-tagged TLBs by setting `CR4.PCIDE` (bit 17).
///
/// Tagged TLBs require both PCID (`CPUID.01H:ECX[17]`) and INVPCID
/// (`CPUID.(EAX=07H,ECX=0):EBX[10]`): the kernel uses `invpcid` for
/// single-address and single-context invalidation. Returns `true` if both
/// features are present and `CR4.PCIDE` was set, `false` otherwise.
///
/// Unlike [`enable_smep_smap`], absence is **not** fatal: PCID/INVPCID are
/// required but deliberately not gated
/// ([platform-requirements.md](../../../../../docs/platform-requirements.md) § Boot-Time
/// Feature Gate); without them the kernel uses full-flush context switches.
///
/// Per Intel SDM Vol. 3A §4.10.1, `CR3[11:0]` must be 0 at the moment
/// `CR4.PCIDE` is set to 1, or the `MOV CR4` `#GP`s. At the call site (Phase 5
/// BSP / AP init) the active CR3 is the kernel root with zero low bits; this is
/// asserted in debug builds.
///
/// # Safety
/// Must execute at ring 0, after the IDT is loaded, with the kernel root in
/// CR3 (low 12 bits zero). Must be called at most once per CPU and before any
/// PCID-tagged CR3 load.
#[cfg(not(test))]
pub unsafe fn enable_pcid() -> bool
{
    // CPUID.01H:ECX[17] = PCID; CPUID.(07H,0):EBX[10] = INVPCID.
    let pcid = cpuid(1).2 & (1 << 17) != 0;
    let invpcid = cpuid(7).1 & (1 << 10) != 0;
    if !pcid || !invpcid
    {
        return false;
    }

    // CR3[11:0] must be zero before setting PCIDE (SDM Vol. 3A §4.10.1).
    let cr3: u64;
    // SAFETY: reading CR3 is a ring-0 primitive.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nostack, nomem));
    }
    debug_assert!(
        cr3.trailing_zeros() >= 12,
        "enable_pcid: CR3[11:0] must be 0 before setting CR4.PCIDE"
    );

    // Bit 17 = PCIDE.
    let cr4 = read_cr4();
    // SAFETY: CPUID confirmed PCID + INVPCID; CR3 low bits are zero (kernel
    // root); long mode and PAE are active (4- or 5-level paging). The new CR4 value
    // is valid.
    unsafe {
        write_cr4(cr4 | (1 << 17));
    }
    true
}

// ── Baseline feature gate ─────────────────────────────────────────────────────

/// Verify the x86-64 platform baseline and refuse unsupported hardware.
///
/// Checks the required CPUID-detectable features that every supported run
/// environment provides (see
/// [platform-requirements.md](../../../../../docs/platform-requirements.md)) and
/// halts via [`crate::fatal`] naming the first missing feature, rather than
/// faulting obscurely later. A few required features are deliberately excluded
/// — see the note on the check table below. Also sets `CR0.WP` (required per
/// [platform-requirements.md](../../../../../docs/platform-requirements.md) § x86-64
/// Classification); UEFI may hand the BSP off with `CR0.WP` clear, and the AP
/// trampoline already sets it.
///
/// # Safety
/// Must execute at ring 0 during early boot, after the console is live so the
/// diagnostic is visible, and before any subsystem that assumes the baseline.
#[cfg(not(test))]
pub unsafe fn verify_baseline()
{
    /// `CR0.WP` (supervisor write-protect).
    const CR0_WP: u64 = 1 << 16;

    let max_leaf = cpuid(0).0;
    let basic = cpuid(1).2; // leaf 1, ECX
    let structured = cpuid(7).1; // leaf 7 sub-leaf 0, EBX
    let ext = cpuid(0x8000_0001); // ext.2 = ECX, ext.3 = EDX

    // (feature present, diagnostic). The kernel halts naming the first absent one.
    // Required features deliberately not gated here, and why, are listed in
    // docs/platform-requirements.md § Boot-Time Feature Gate.
    let checks: [(bool, &str); 19] = [
        // x86-64-v3 instruction baseline.
        (
            basic & (1 << 28) != 0,
            "AVX not supported by CPU — required (x86-64-v3)",
        ),
        (
            structured & (1 << 5) != 0,
            "AVX2 not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 12) != 0,
            "FMA not supported by CPU — required (x86-64-v3)",
        ),
        (
            structured & (1 << 3) != 0,
            "BMI1 not supported by CPU — required (x86-64-v3)",
        ),
        (
            structured & (1 << 8) != 0,
            "BMI2 not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 22) != 0,
            "MOVBE not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 29) != 0,
            "F16C not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 23) != 0,
            "POPCNT not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 13) != 0,
            "CMPXCHG16B not supported by CPU — required (x86-64-v3)",
        ),
        (
            ext.2 & (1 << 5) != 0,
            "LZCNT not supported by CPU — required (x86-64-v3)",
        ),
        (
            basic & (1 << 26) != 0,
            "XSAVE not supported by CPU — required (x86-64-v3)",
        ),
        // Privilege and W^X substrate.
        (
            ext.3 & (1 << 29) != 0,
            "long mode not supported by CPU — required",
        ),
        (
            ext.3 & (1 << 11) != 0,
            "SYSCALL not supported by CPU — required",
        ),
        (ext.3 & (1 << 20) != 0, "NX not supported by CPU — required"),
        // Supervisor isolation.
        (
            structured & (1 << 7) != 0,
            "SMEP not supported by CPU — required",
        ),
        (
            structured & (1 << 20) != 0,
            "SMAP not supported by CPU — required",
        ),
        // Topology enumeration.
        (
            max_leaf >= 0x0B,
            "CPUID topology leaf 0x0B not supported by CPU — required",
        ),
        // Hardware entropy sources.
        (
            basic & (1 << 30) != 0,
            "RDRAND not supported by CPU — required",
        ),
        (
            structured & (1 << 18) != 0,
            "RDSEED not supported by CPU — required",
        ),
    ];
    for (present, feature) in checks
    {
        if !present
        {
            crate::fatal(feature);
        }
    }

    // SAFETY: ring 0 per the caller contract; setting WP only tightens
    // supervisor write checks. Kernel code paths are WP-safe — the APs run with
    // WP set from the trampoline through all of init.
    unsafe {
        super::fpu::write_cr0(super::fpu::read_cr0() | CR0_WP);
    }
}

/// Test-build stub: the baseline gate performs privileged operations and is a
/// no-op in host unit tests.
#[cfg(test)]
pub unsafe fn verify_baseline() {}

/// Make instruction fetch on every CPU see the stores made before the call
/// (`mm::icache::sync_user_code`). Nothing to do on x86-64: instruction fetch
/// is coherent with stores on every CPU, and code another CPU modified needs
/// only a serializing event on the CPU that runs it, which every return to
/// user mode through `iretq` and every context switch supplies.
pub fn sync_instruction_fetch() {}

/// Disable, for ring 3, every state the kernel does not switch. A no-op on
/// x86-64, which has no state-enable registers: the extended state ring 3 can
/// reach is the set of XCR0 components `fpu` enables (x87, SSE, AVX), and the
/// XSAVE switch saves and restores exactly that set.
///
/// # Safety
/// No preconditions; `unsafe` only for signature parity with the riscv64 item.
pub unsafe fn disable_unswitched_user_state() {}

// ── Misc ──────────────────────────────────────────────────────────────────────

/// Atomically enable interrupts and halt until an interrupt is recognised.
///
/// Precondition: interrupts are **disabled** (IF=0) on entry.
/// Postcondition: interrupts are **enabled** (IF=1) on return; any pending
/// interrupt at the halt boundary has been recognised (handler ran during
/// halt).
///
/// Runs `VERW` first where the transient-execution selection asks for it
/// (`mitigation::verw_before_idle`).
///
/// Per Intel SDM Vol. 2B (STI): when `STI` is immediately followed by `HLT`,
/// the processor delays interrupt recognition until after `HLT` begins
/// execution. The pair is therefore atomic: no interrupt is lost between
/// the enable and the halt; the wake protocol this guarantees is specified in
/// [scheduling-internals.md](../../../docs/scheduling-internals.md) § Wake Protocol
/// Invariants.
///
/// `nomem` is intentionally omitted so the compiler may not reorder
/// preceding atomic loads across this call.
pub fn halt_until_interrupt()
{
    // Clear the CPU's buffers before the halt where the selection asks for it
    // (core/kernel/docs/transient-execution.md § Controls).
    #[cfg(not(test))]
    super::mitigation::verw_before_idle();
    // SAFETY: `sti; hlt` is atomic per Intel SDM; correct only when
    // interrupts were disabled on entry (caller contract).
    unsafe {
        core::arch::asm!("sti; hlt", options(nostack, preserves_flags));
    }
}

/// Whether every CPU idles in `MWAIT` on its idle wake word
/// ([`init_idle_wait`]). Written once by the BSP before any AP starts, so a
/// Relaxed load on any CPU reads the boot's value: the AP startup handshake
/// orders the store before the AP's first instruction.
static IDLE_WAIT: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Choose the idle wait: `MONITOR`/`MWAIT` where CPUID.01H:ECX.MONITOR
/// (bit 3) reports it, else `HLT` ([`halt_until_interrupt`]). Returns the
/// name of the wait chosen. The C1 hint `wait_on_word` passes needs no
/// leaf-5 extension, and the parts whose monitor Linux treats as broken
/// (Apollo Lake, Xeon 7400) lack the x86-64-v3 baseline `verify_baseline`
/// requires. Called once, on the BSP, before any AP starts
/// (core/kernel/docs/scheduler.md § Idle Thread).
pub fn init_idle_wait() -> &'static str
{
    /// CPUID.01H:ECX bit 3: `MONITOR`/`MWAIT`.
    const ECX_MONITOR: u32 = 1 << 3;

    let monitor = cpuid(1).2 & ECX_MONITOR != 0;
    IDLE_WAIT.store(monitor, core::sync::atomic::Ordering::Relaxed);
    if monitor { "mwait" } else { "hlt" }
}

/// Whether the idle loop waits on its idle wake word ([`wait_on_word`]); set
/// by [`init_idle_wait`].
#[must_use]
pub fn idle_wait_available() -> bool
{
    IDLE_WAIT.load(core::sync::atomic::Ordering::Relaxed)
}

/// Arm `MONITOR` on `word`, and unless `word` no longer holds `polling`,
/// atomically enable interrupts and `MWAIT` in C1 (hint 0, the state `HLT`
/// enters) until a store to the word's line or an interrupt.
///
/// Precondition: interrupts are **disabled** (IF=0) on entry.
/// Postcondition: interrupts are **enabled** (IF=1) on return; any interrupt
/// pending at the wait has been recognised, as for [`halt_until_interrupt`].
///
/// The re-read follows the arm, so a store between the caller's last check and
/// the arm is seen by the re-read, and one after the arm ends the wait. `STI`
/// delays interrupt recognition until after the next instruction (Intel SDM
/// Vol. 2B, STI), so `sti; mwait` is atomic as `sti; hlt` is. `MWAIT` may
/// return for other reasons; the caller loops. Runs `VERW` first where the
/// transient-execution selection asks for it, as `halt_until_interrupt` does.
///
/// # Safety
/// Ring 0, with interrupts disabled (the precondition); `word` is live
/// kernel memory, and [`idle_wait_available`] holds.
pub unsafe fn wait_on_word(word: &core::sync::atomic::AtomicU32, polling: u32)
{
    #[cfg(not(test))]
    super::mitigation::verw_before_idle();
    // SAFETY: ring 0 with MONITOR present (caller contract); `word` is mapped
    // kernel memory, so the monitored linear address cannot fault. ECX and EDX
    // are zero: no extensions, no hints. `nomem` is omitted so the re-read below
    // stays after the arm.
    unsafe {
        core::arch::asm!(
            "monitor",
            in("rax") word.as_ptr(),
            in("ecx") 0u32,
            in("edx") 0u32,
            options(nostack, preserves_flags),
        );
    }
    if word.load(core::sync::atomic::Ordering::Relaxed) & polling == 0
    {
        // SAFETY: the precondition's IF=0 is lifted here, ending the masked
        // region with no wait, as the postcondition states.
        unsafe { super::interrupts::enable() };
        return;
    }
    // SAFETY: ring 0 with MWAIT present (caller contract) and IF=0 on entry;
    // `sti; mwait` is atomic per the STI shadow, and EAX 0 / ECX 0 ask for C1
    // with no extensions.
    unsafe {
        core::arch::asm!(
            "sti",
            "mwait",
            in("eax") 0u32,
            in("ecx") 0u32,
            options(nostack, preserves_flags),
        );
    }
}

// ── Per-CPU GS-base ───────────────────────────────────────────────────────────

/// MSR address for `IA32_GS_BASE` — the canonical GS segment base.
const IA32_GS_BASE: u32 = 0xC000_0101;

/// MSR address for `IA32_KERNEL_GS_BASE` — the base `swapgs` exchanges with
/// `IA32_GS_BASE`.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

/// Install `addr` as the per-CPU data pointer for the current CPU.
///
/// Writes `addr` to `IA32_GS_BASE` (MSR `0xC000_0101`) so that
/// GS-relative loads (`gs:[offset]`) reach the `PerCpuData` entry for
/// this CPU, and 0 to `IA32_KERNEL_GS_BASE`: the user GS base every ring-3
/// entry and exit exchanges with the kernel's (`swapgs`; see `syscall.rs`
/// § Entry contract). Must be called from Phase 5 (BSP) and `kernel_entry_ap`
/// (each AP) before any GS-relative access occurs.
///
/// # Safety
/// Must execute at ring 0. `addr` must be the virtual address of a valid
/// `PerCpuData` that outlives the CPU's execution.
#[cfg(not(test))]
pub unsafe fn install_percpu(addr: u64)
{
    // SAFETY: IA32_GS_BASE is a valid MSR on all x86-64 CPUs; ring 0; addr
    // names this CPU's PerCpuData (caller's contract).
    unsafe {
        write_msr(IA32_GS_BASE, addr);
    }
    // SAFETY: IA32_KERNEL_GS_BASE is a valid MSR on all x86-64 CPUs; ring 0;
    // 0 is the user GS base before the first ring-3 entry.
    unsafe {
        write_msr(IA32_KERNEL_GS_BASE, 0);
    }
}

/// Return the logical CPU index of the executing CPU.
///
/// Reads `gs:[0]` which holds `PerCpuData::cpu_id` (u32, offset 0).
/// Valid after [`install_percpu`] is called for this CPU.
///
/// # Safety (internal)
/// `gs:[0]` is always a valid u32 read once GS-base is installed.
/// The function is safe to call because the install guarantee is a
/// precondition of the kernel running on this CPU.
pub fn current_cpu() -> u32
{
    #[cfg(not(test))]
    {
        let id: u32;
        // SAFETY: gs:[0] is PerCpuData::cpu_id; GS-base installed by kernel before scheduler runs.
        unsafe {
            core::arch::asm!(
                "mov {:e}, gs:[0]",
                out(reg) id,
                options(nostack, readonly, preserves_flags),
            );
        }
        id
    }
    #[cfg(test)]
    {
        0
    }
}

/// Read the 32-bit word at byte `OFFSET` of this CPU's `PerCpuData` with
/// one GS-relative load. Not `pure`: each call loads again, since other CPUs
/// write the word.
///
/// # Safety
/// GS-base holds this CPU's `PerCpuData` address (`percpu::init_bsp` or
/// `percpu::init_ap`), and `OFFSET` is the offset of an aligned 32-bit field
/// of it.
#[cfg(not(test))]
#[inline]
pub unsafe fn read_percpu_u32<const OFFSET: usize>() -> u32
{
    let word: u32;
    // SAFETY: gs:[OFFSET] is the aligned 32-bit field (caller contract), so
    // the load is one access; it writes no memory and no flag.
    unsafe {
        core::arch::asm!(
            "mov {:e}, dword ptr gs:[{off}]",
            out(reg) word,
            off = const OFFSET,
            options(nostack, readonly, preserves_flags),
        );
    }
    word
}

/// Read the pointer at byte `OFFSET` of this CPU's `PerCpuData` with one
/// GS-relative load.
///
/// # Safety
/// GS-base holds this CPU's `PerCpuData` address (`percpu::init_bsp` or
/// `percpu::init_ap`), and `OFFSET` is the offset of a pointer field of it.
#[cfg(not(test))]
#[inline]
pub unsafe fn read_percpu_ptr<T, const OFFSET: usize>() -> *const T
{
    let ptr: *const T;
    // SAFETY: gs:[OFFSET] is the pointer field (caller contract); the load
    // writes no memory and no flag.
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[{off}]",
            out(reg) ptr,
            off = const OFFSET,
            options(nostack, readonly, preserves_flags),
        );
    }
    ptr
}

// ── Kernel trap stack ─────────────────────────────────────────────────────────

/// Set the kernel stack pointer used when a trap fires from U-mode.
///
/// On x86-64 this requires two writes: TSS RSP0 (for hardware interrupt/
/// exception entry) and `PerCpuData::kernel_rsp` via `syscall::set_kernel_rsp`
/// (for the `SYSCALL` fast path).
/// Must be called on every context switch to a user thread.
///
/// # Safety
/// Must execute at ring 0. Caller must ensure the stack is valid.
#[cfg(not(test))]
#[inline]
pub unsafe fn set_kernel_trap_stack(stack_top: u64)
{
    // SAFETY: ring 0; caller guarantees stack_top is a valid kernel stack pointer.
    unsafe {
        super::gdt::set_rsp0(stack_top);
    }
    // SAFETY: as for set_rsp0: ring 0, stack_top a valid kernel stack pointer.
    unsafe {
        super::syscall::set_kernel_rsp(stack_top);
    }
}

/// Save the current interrupt-enable state and disable hardware interrupts.
/// Returns an opaque value to pass to [`restore_interrupts`].
///
/// # Safety
/// Must execute at ring 0.
#[cfg(not(test))]
#[inline]
pub unsafe fn save_and_disable_interrupts() -> u64
{
    let flags: u64;
    // SAFETY: pushfq/popfq are valid at ring 0; cli is safe here.
    // `nostack` is intentionally absent: `pushfq` writes 8 bytes below RSP
    // and the matching `pop` reads them. Net RSP delta is zero but the body
    // is not red-zone-safe; only the kernel target's `disable-redzone: true`
    // makes this latent today. Be honest about the body.
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {flags}",
            "cli",
            flags = out(reg) flags,
        );
    }
    flags
}

/// Restore the interrupt-enable state saved by [`save_and_disable_interrupts`].
///
/// # Safety
/// Must execute at ring 0. `saved` must be a value returned by
/// `save_and_disable_interrupts` on this CPU.
#[cfg(not(test))]
#[inline]
pub unsafe fn restore_interrupts(saved: u64)
{
    // SAFETY: restoring a previously captured FLAGS value is safe.
    // See save_and_disable_interrupts above for why `nostack` is absent.
    unsafe {
        core::arch::asm!(
            "push {flags}",
            "popfq",
            flags = in(reg) saved,
        );
    }
}

// ── Kernel-entry flags check ──────────────────────────────────────────────────

/// Read RFLAGS.
///
/// Clobbers only the output register; `pushfq` writes 8 bytes below RSP and the
/// `pop` reads them back (net RSP delta zero), so `nostack` is absent for the
/// reason [`save_and_disable_interrupts`] gives. Assumes ring 0 (any ring can
/// read RFLAGS; the kernel calls this only from kernel entry).
#[cfg(not(test))]
#[inline]
fn read_rflags() -> u64
{
    let flags: u64;
    // SAFETY: pushfq/pop reads RFLAGS into a register and changes no state
    // beyond the transient stack slot it pops back.
    unsafe {
        core::arch::asm!("pushfq", "pop {flags}", flags = out(reg) flags);
    }
    flags
}

/// Debug-build check that the user-controlled RFLAGS bits a ring-3 entry must
/// clear are clear while the kernel runs: AC (SMAP override), DF (string
/// direction) and TF (single-step). `IA32_SFMASK` clears them on SYSCALL, and
/// every ring-3-reachable IDT stub runs `cld` and `clac` (TF is cleared by the
/// interrupt or trap gate), so a set bit here is a regression in that entry
/// discipline. Called first in `syscall::dispatch` and in the exception,
/// `#PF`, `#NM`, and IRQ handler bodies (`idt.rs`). A no-op in release builds
/// (the RFLAGS read is not performed).
#[cfg(not(test))]
#[inline]
pub fn debug_assert_kernel_entry_flags()
{
    const MUST_BE_CLEAR: u64 =
        super::syscall::RFLAGS_AC | super::syscall::RFLAGS_DF | super::syscall::RFLAGS_TF;
    debug_assert!(
        read_rflags() & MUST_BE_CLEAR == 0,
        "kernel entry: RFLAGS AC, DF or TF set in ring 0"
    );
}

// ── Interrupts (hardware state) ───────────────────────────────────────────────

/// Disable hardware interrupts.
///
/// # Safety
/// Changes global CPU interrupt state. Caller is responsible for re-enabling
/// interrupts when appropriate (the kernel does not enable them during early boot).
///
/// `nomem` is intentionally omitted: the idle loop relies on no atomic
/// loads being reordered across this call.
pub unsafe fn disable_interrupts()
{
    // SAFETY: caller guarantees this is called in an appropriate context.
    unsafe {
        core::arch::asm!("cli", options(nostack, preserves_flags));
    }
}

/// Disable interrupts and halt the CPU permanently.
///
/// Loops on `hlt` so that any NMI that fires during early boot does not cause
/// an uncontrolled jump; interrupts remain disabled.
///
/// Never inlined, so the kernel image has a `halt_loop` symbol:
/// `cargo xtask test wedge` moves an idle CPU's program counter to it to wedge
/// that CPU with interrupts off, and checks the NMI frame falls inside it.
#[inline(never)]
pub fn halt_loop() -> !
{
    // SAFETY: kernel code runs at ring 0, where cli and hlt are permitted; cli
    // masks interrupts so the hlt loop below halts permanently.
    unsafe {
        disable_interrupts();
    }
    loop
    {
        // SAFETY: hlt puts the CPU into a low-power wait state until the next interrupt.
        // Interrupts are disabled above, so this halts permanently.
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::smt_core_key;

    /// A CPUID stub over `leaves` ((leaf, sub-leaf), [EAX, EBX, ECX, EDX]);
    /// an absent pair reads as zero, as a terminating topology level does.
    fn stub(leaves: &[((u32, u32), [u32; 4])]) -> impl Fn(u32, u32) -> [u32; 4] + '_
    {
        move |leaf, subleaf| {
            leaves
                .iter()
                .find(|(key, _)| *key == (leaf, subleaf))
                .map_or([0; 4], |(_, regs)| *regs)
        }
    }

    /// A topology level: shift `shift`, `count` logical CPUs, level `level`
    /// of type `kind`, on the CPU with x2APIC ID `id`.
    const fn level(shift: u32, count: u32, level: u32, kind: u32, id: u32) -> [u32; 4]
    {
        [shift, count, (kind << 8) | level, id]
    }

    // Defect guarded: the two threads of one core keyed apart (no SMT tie-break
    // anywhere) or two cores keyed together (a busy core read as a sibling).
    #[test]
    fn leaf_0b_smt_level_shifts_the_thread_bits_out()
    {
        for (id, key) in [(0, 0), (1, 0), (2, 1), (3, 1), (9, 4)]
        {
            let leaves = [
                ((0, 0), [0x16, 0, 0, 0]),
                ((0xB, 0), level(1, 2, 0, 1, id)),
                ((0xB, 1), level(4, 8, 1, 2, id)),
            ];
            assert_eq!(smt_core_key(stub(&leaves)), Some(key), "x2APIC ID {id}");
        }
    }

    // Defect guarded: leaf 0BH read where the CPU enumerates 1FH, whose SMT
    // level can differ (a hybrid part's module level sits between them).
    #[test]
    fn leaf_1f_is_preferred_when_enumerated()
    {
        let leaves = [
            ((0, 0), [0x20, 0, 0, 0]),
            ((0x1F, 0), level(2, 4, 0, 1, 0x17)),
            ((0x1F, 1), level(6, 16, 1, 2, 0x17)),
            ((0xB, 0), level(1, 2, 0, 1, 0x17)),
        ];
        assert_eq!(smt_core_key(stub(&leaves)), Some(0x17 >> 2));
    }

    // Defect guarded: a highest leaf of 1FH whose sub-leaf 0 is empty (the leaf
    // not enumerated) taken over 0BH.
    #[test]
    fn empty_leaf_1f_falls_back_to_0b()
    {
        let leaves = [((0, 0), [0x20, 0, 0, 0]), ((0xB, 0), level(1, 2, 0, 1, 5))];
        assert_eq!(smt_core_key(stub(&leaves)), Some(2));
    }

    // Defect guarded: a CPU without SMT whose first level is the core level
    // read as an SMT level, merging cores.
    #[test]
    fn no_smt_level_keys_by_the_whole_id()
    {
        let leaves = [((0, 0), [0x16, 0, 0, 0]), ((0xB, 0), level(3, 8, 0, 2, 6))];
        assert_eq!(smt_core_key(stub(&leaves)), Some(6));
    }

    // Defect guarded: an unenumerated leaf's EDX (not an x2APIC ID, often 0
    // on every CPU) used as the key, merging every CPU into one core.
    #[test]
    fn unenumerated_leaf_gives_no_key()
    {
        let leaves = [((0, 0), [0x16, 0, 0, 0])];
        assert_eq!(smt_core_key(stub(&leaves)), None);
    }

    // Defect guarded: a CPU that never reports a terminating level looping the
    // walk.
    #[test]
    fn walk_is_bounded_without_a_terminating_level()
    {
        let cpuid = |leaf: u32, _subleaf: u32| match leaf
        {
            0 => [0x16, 0, 0, 0],
            _ => level(4, 8, 0, 2, 0x30),
        };
        assert_eq!(smt_core_key(cpuid), Some(0x30));
    }
}
