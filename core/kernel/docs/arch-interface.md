# Architecture Abstraction Layer

How architecture-specific kernel behaviour is isolated under `arch/<target>/` and reached
by architecture-neutral code through a single module-boundary dispatch surface.

---

All architecture-specific behaviour in the Seraph kernel lives under `core/kernel/src/arch/`.
Architecture-neutral code reaches it through the `arch::current` module alias — calling
`arch::current::<module>::<function>`. `arch/mod.rs` selects the active architecture's
module as `current` via `#[cfg(target_arch)]`.

The dispatch surface is **free functions and concrete types grouped into per-concern
submodules**, not cross-architecture traits.
[coding-standards.md](../../../docs/coding-standards.md) §C permits this — the arch-dispatch
surface may be "traits, type aliases, or re-exports", and a module boundary that re-exports
per-architecture free functions satisfies the rule — and requires architecture-neutral code
to route arch divergence through the surface rather than `#[cfg(target_arch)]` blocks. There
are no `trait` definitions or hand-written trait `impl`s under `arch/` (only `#[derive]`d
standard traits); inherent `impl` blocks on concrete types (`SavedState`, `TrapFrame`, …) are
normal.

Every function in the dispatch surface MUST be defined on every supported architecture
([coding-standards.md](../../../docs/coding-standards.md) §C). The per-architecture build
checks completeness for every surface item that architecture-neutral code calls: if one is
missing on the target being compiled, its `arch::current::…` call fails to resolve and the
build breaks. Items with no neutral caller are not checked this way: `MIN_IRQ_ID`,
`MAX_IRQ_ID`, `interrupts::disable`, `timer::delay_us`, `cpu::current_id`,
`cpu::user_copy_fixup`, `paging::user_fault_is_spurious`, and
`TrapFrame::set_ipc_return_with_badge`. Of these, `timer::delay_us`, `cpu::user_copy_fixup`, and
`paging::user_fault_is_spurious` are called only by arch-internal code; the rest have no caller.

---

## Module Structure

```
core/kernel/src/arch/
├── mod.rs          # The only #[cfg(target_arch)] site; aliases the active arch as `current`
├── x86_64/
│   ├── mod.rs      # Module declarations and arch constants (ARCH_NAME, …)
│   ├── paging.rs   ├── context.rs  ├── interrupts.rs ├── timer.rs
│   ├── syscall.rs  ├── cpu.rs      ├── console.rs    ├── trap_frame.rs
│   ├── gdt.rs      ├── idt.rs      ├── ioapic.rs     ├── fpu.rs
│   ├── platform.rs ├── ap_trampoline.rs └── entropy.rs
└── riscv64/
    ├── mod.rs
    ├── paging.rs   ├── context.rs  ├── interrupts.rs ├── timer.rs
    ├── syscall.rs  ├── cpu.rs      ├── console.rs    ├── trap_frame.rs
    ├── gdt.rs      ├── idt.rs      ├── sbi.rs        ├── fpu.rs
    ├── platform.rs ├── ap_trampoline.rs └── entropy.rs
```

`arch/mod.rs` performs the conditional compilation:

```rust
#[cfg(target_arch = "x86_64")]
#[path = "x86_64/mod.rs"]
pub mod current;

#[cfg(target_arch = "riscv64")]
#[path = "riscv64/mod.rs"]
pub mod current;
```

The sections below document the **cross-architecture contract surface** — the functions,
types, and module-level constants architecture-neutral code depends on, plus the items every
architecture defines without a neutral caller (listed above). Some submodules are mostly
arch-private support code (`gdt`, `idt`, `ioapic`/`sbi`, `fpu`, `platform`, `ap_trampoline`)
whose internals are not part of the contract; the items neutral code calls from them are
listed, with their signatures, in § Module-level constants and free functions.

Addresses cross this boundary as raw `u64`. Page-permission and page-table-rewrite types
(`PageFlags`, `MapOutcome`, `PagingError`) are architecture-neutral and defined in
`mm::paging`; the per-architecture mapping code maps them to hardware bits.

---

## `paging` — `arch::current::paging`

Manages hardware page tables. A page table is referenced by its physical root frame
(`root_phys`) and a direct-map virtual alias (`root_virt`) — not an owned table object;
intermediate frames come from the kernel page-table pool on the kernel-direct path and
from the address-space object's own pool on the pooled path, and only the latter takes
them back, through a reclaiming unmap ([memory-internals.md](memory-internals.md) § Page Table
Node Ownership). The direct-map placement and kernel-half floor the functions below publish
are specified in [memory-model.md](../../../docs/memory-model.md) § Virtual Address Space
Layout.

```rust
/// Install `root_phys` as the active page table for the current CPU with a full
/// TLB flush: x86-64 writes CR3 with PCID 0 (flushing PCID 0's entries); RISC-V
/// writes `satp` with ASID 0 and executes `sfence.vma`. It installs the kernel
/// page table during boot setup, before tagging exists. On the
/// `AddressSpace::activate` path it is the untagged fallback, used when hardware
/// tagging is disabled (and on an unreachable defensive branch should
/// `tag_allocator::claim` return tag 0); the tagged context-switch path uses
/// `activate_tagged` (below). See docs/memory-model.md.
///
/// # Safety
/// `root_phys` must be a valid page-table root mapping current code, stack, and
/// the direct map.
pub unsafe fn activate(root_phys: u64);

/// Write the page-table root without an explicit flush (idle / kernel
/// transitions, where the outgoing space's stale user entries are harmless).
/// RISC-V writes `satp` (ASID 0) without `sfence.vma`. On x86-64 this loads the
/// kernel root under PCID 0 with CR3 bit 63 (no invalidation) when `CR4.PCIDE`
/// is set; without PCID a CR3 write necessarily flushes, so it degrades to
/// `activate`.
pub unsafe fn write_satp_no_fence(root_phys: u64);

/// Read the active page-table root physical address (CR3 on x86-64 with the low
/// bits masked; `satp` PPN on RISC-V).
pub unsafe fn read_root_phys() -> u64;

/// Publish the active paging mode and the KASLR-chosen direct-map base at
/// kernel entry, before any consumer of the VA layout runs, from the validated
/// `BootInfo`. RISC-V decodes `satp.MODE` (the bootloader hands over a running
/// translation regime under the negotiated Sv39/Sv48/Sv57 mode); x86-64 is
/// unconditionally 4-level and records only the direct-map base. Halts the CPU
/// on a base outside the active mode's kernel half or not 1 GiB-aligned.
pub fn init_paging_mode(info: &boot_protocol::BootInfo);

/// Base virtual address of the direct physical map: the KASLR-chosen base from
/// `BootInfo` — a 1 GiB-aligned base at or above the kernel-half floor
/// (0xFFFF800000000000 on x86-64 / Sv48; see docs/memory-model.md § Virtual
/// Address Space Layout), published by `init_paging_mode`. A runtime
/// `AtomicU64` on both arches (a single relaxed load); wrapped by
/// `mm::paging::direct_map_base()` for architecture-neutral consumers.
pub fn direct_map_base() -> u64;

/// Exclusive upper bound of user-half virtual addresses: constant `1 << 47` on
/// x86-64; the active mode's half boundary on RISC-V. Wrapped by
/// `mm::user_va_top()` — the single kernel-wide user-VA gate.
pub fn user_va_top() -> u64;

/// Map `phys` at `virt` in the user region of the address space rooted at
/// `root_virt`. Returns how the rewrite changed any prior mapping
/// (`MapOutcome`), which the caller uses to decide whether a remote TLB
/// shootdown is required. The caller must invalidate the local TLB for `virt`.
pub unsafe fn map_user_page(
    root_virt: u64,
    virt: u64,
    phys: u64,
    flags: PageFlags,
) -> Result<MapOutcome, ()>;

/// As `map_user_page`, but draws intermediate page-table frames from the
/// address-space object's own pool rather than the kernel page-table pool.
pub unsafe fn map_user_page_pooled(
    root_virt: u64,
    virt: u64,
    phys: u64,
    flags: PageFlags,
    aso: &AddressSpaceObject,
) -> Result<MapOutcome, ()>;

/// Change permissions on an existing user mapping without changing the frame.
pub unsafe fn protect_user_page(
    root_virt: u64,
    virt: u64,
    flags: PageFlags,
) -> Result<MapOutcome, PagingError>;

/// Remove the user mapping for `virt` and invalidate the local-CPU TLB entry
/// for it (`flush_page`); the caller performs any remote shootdown.
pub unsafe fn unmap_user_page(root_virt: u64, virt: u64);

/// Clear every 4 KiB leaf in `[virt_base, virt_base + page_count * 4 KiB)` and
/// free each intermediate table the span leaves empty back to `aso`'s pool —
/// only a table whose parent entry carries the pooled-table bit the pooled map
/// path set when it installed the table (core/kernel/docs/memory-internals.md
/// § Page Table Node Ownership). Returns the number of tables freed.
/// The caller holds the address space's `pt_lock` and performs the shootdown.
pub unsafe fn unmap_user_region_pooled(
    root_virt: u64,
    virt_base: u64,
    page_count: usize,
    aso: &AddressSpaceObject,
) -> usize;

/// Walk the user tables and return `(phys, flags_word)` mapped at `virt`, or
/// None if unmapped. RISC-V decodes Svnapot 64 KiB group members internally,
/// so `phys` is always the exact per-page frame; the raw flags word may carry
/// the N bit.
pub unsafe fn translate_user_page(root_virt: u64, virt: u64) -> Option<(u64, u64)>;

/// Invalidate the local-CPU TLB entry for a single virtual address
/// (x86-64 `invlpg`; RISC-V `sfence.vma virt`).
pub unsafe fn flush_page(virt: u64);

/// Invalidate the current CPU's TLB for the loaded address space (x86-64 CR3
/// reload: the loaded PCID's non-global entries when `CR4.PCIDE` is set, all
/// non-global entries otherwise; RISC-V `sfence.vma zero, zero`: every entry
/// for every ASID, global ones included).
pub unsafe fn flush_tlb_all();

/// Install `root_phys` as the active page table under hardware address-space
/// tag `tag` (x86-64 PCID / RISC-V ASID) **without** flushing the TLB, so the
/// outgoing space's cached translations survive (x86-64 sets CR3 bit 63 with
/// `CR4.PCIDE`; RISC-V writes `satp` with the ASID and no `sfence.vma`). Only
/// valid when tagging is enabled; the caller performs any required tag
/// invalidation (the generation check in `AddressSpace::activate`).
pub unsafe fn activate_tagged(root_phys: u64, tag: u16);

/// Invalidate the current-CPU TLB entry for `virt` tagged with `tag`,
/// independent of the tag currently loaded (x86-64 INVPCID type 0;
/// RISC-V `sfence.vma virt, asid`).
pub unsafe fn flush_page_tagged(virt: u64, tag: u16);

/// Invalidate all current-CPU entries tagged with `tag` (x86-64 INVPCID type 1;
/// RISC-V `sfence.vma zero, asid`). Used when a tag is reassigned or a
/// switched-away space accrued unmaps.
pub unsafe fn flush_tag(tag: u16);

/// Open a batched-invalidation window (RISC-V `sfence.w.inval`; x86-64 no-op).
/// The single-VA primitives above intentionally remain plain `sfence.vma` —
/// a bracket only pays for itself across multiple addresses.
pub unsafe fn inval_batch_begin();

/// Invalidate `virt` inside an open window (RISC-V `sinval.vma virt, zero`:
/// every ASID; x86-64 `invlpg`: the loaded PCID and global entries).
pub unsafe fn inval_page(virt: u64);

/// Invalidate `virt` within `tag` inside an open window (RISC-V
/// `sinval.vma virt, asid`; x86-64 INVPCID type 0).
pub unsafe fn inval_page_tagged(virt: u64, tag: u16);

/// Close the window (RISC-V `sfence.inval.ir`; x86-64 no-op). The queued
/// invalidations are architecturally complete when this returns.
pub unsafe fn inval_batch_end();

/// Per-CPU enable of tagged TLBs; returns the number of hardware tags available.
/// x86-64 sets `CR4.PCIDE` and returns 4096, or `0` where PCID/INVPCID are absent
/// (the kernel keeps a full-flush fallback). RISC-V
/// probes the `satp` ASID width and returns `1 << width`; a hart with no ASID
/// support is refused, since tagged TLBs are gated as required on RISC-V.
/// Called on the BSP (whose return seeds the tag pool) and on
/// every AP (which must set its own `CR4.PCIDE` before any tagged CR3 load).
pub unsafe fn enable_tagged_tlb() -> usize;

/// BSP-only boot gate for paging extensions the kernel uses unconditionally.
/// RISC-V refuses to boot unless the bootloader confirmed Svpbmt, Svinval, and
/// Svnapot on every enabled hart (`KernelMmio::hart_caps`); x86-64 provides a
/// no-op (its paging baseline is asserted by
/// `cpu::verify_baseline` and `enable_nx`). Runs after `crate::platform::capture_kernel_mmio`,
/// before the first userspace mapping or TLB shootdown.
pub unsafe fn verify_paging_extensions();

/// Classify a user page fault as spurious (the live PTE already permits the
/// access — a stale entry the handler resolves by retrying) versus a real fault.
/// Called only by each architecture's own page-fault handler, not by neutral code.
pub unsafe fn user_fault_is_spurious(va: u64, write: bool, instr: bool) -> bool;

/// Rebase the boot stack from its identity mapping into the direct map during
/// early paging setup, by adding `direct_map_base` to the stack pointer
/// (x86-64 `add rsp`; RISC-V `add sp, sp`). Both architectures rebase; only
/// the host-test build stubs it out.
pub unsafe fn rebase_boot_stack(direct_map_base: u64);

/// Map a 4 KiB page / a large page in a table rooted at `root_va`, drawing
/// intermediate frames from `pool` (boot page-table construction).
pub fn map_page(
    root_va: u64,
    virt: u64,
    phys: u64,
    flags: PageFlags,
    pool: &mut PoolState,
) -> Result<(), PagingError>;
pub fn map_large_page(
    root_va: u64,
    virt: u64,
    phys: u64,
    flags: PageFlags,
    pool: &mut PoolState,
) -> Result<(), PagingError>;

/// Enable no-execute (x86-64 sets `IA32_EFER.NXE`; no-op on RISC-V, where the
/// PTE X bit always applies).
pub unsafe fn enable_nx();

/// Read the current stack pointer (`rsp` / `sp`) before page-table activation.
pub fn read_stack_pointer() -> u64;

/// Clear the kernel identity-map leaf for `pa` and shoot it down on every CPU.
pub unsafe fn unmap_identity_page(pa: u64);
```

Which paging and TLB features each architecture requires, and which it uses opportunistically,
is specified in [platform-requirements.md](../../../docs/platform-requirements.md) § x86-64
Classification and § riscv64 Classification.

`PageFlags` (`mm::paging`) is an architecture-neutral bitfield with fields `readable`,
`writable`, `executable`, and `uncacheable`. `readable` is meaningful only on RISC-V (x86-64
has no read-disable bit); `uncacheable` selects the device memory type explicitly on both
architectures — PCD|PWT (strong UC) on x86-64, Svpbmt PBMT=IO on RISC-V — so MMIO
attributes do not depend on platform PMAs. W^X is enforced at the memory syscall layer
(`syscall::mem` map/protect reject a writable-and-executable request with
`SyscallError::WxViolation`; see [syscalls.md](syscalls.md) § Memory Syscalls); the arch
mapping primitives require the caller to have already validated W^X.

---

## `context` — `arch::current::context`

Defines the saved register state for a thread and the mechanism to switch between threads.
The context switch is the most performance-critical path in the kernel.

```rust
/// Architecture-specific saved register state for one thread, stored in the TCB
/// and swapped on every context switch. Methods: `entry_point(&self) -> u64`,
/// `user_arg(&self) -> u64`.
pub struct SavedState { /* arch-specific */ }

/// Construct a `SavedState` for a freshly created thread. `entry` is the start
/// PC and `stack_top` the initial kernel SP. `arg` is the first argument:
/// x86-64 stashes it in `rbx` (read back by `SavedState::user_arg`), RISC-V
/// delivers it in `a0`. `is_user` selects the first-dispatch interrupt state on
/// x86-64 (IF clear for a user thread's kernel trampoline, set for a kernel
/// thread) and is unused on RISC-V.
pub fn new_state(entry: u64, stack_top: u64, arg: u64, is_user: bool) -> SavedState;

/// Seed the thread-local-storage base in a `SavedState` before first run
/// (x86-64 `fs_base`, loaded into `IA32_FS_BASE` on first switch; a no-op on
/// RISC-V, where `TrapFrame::set_tls_base` carries the user `tp`).
pub fn seed_tls_base(saved: &mut SavedState, tls_base: u64);

/// Round a user-supplied stack pointer to the entry point's `extern "C"` ABI
/// alignment (x86-64 SysV `rsp ≡ 8 (mod 16)`; RISC-V LP64D `sp ≡ 0 (mod 16)`).
pub fn align_initial_stack(sp: u64) -> u64;

/// Switch from `current` to `next`, saving callee-saved registers into `current`
/// and restoring them from `next`. `save_flag` is published once `current`'s
/// state is fully saved, so another CPU may observe the thread as switched-out.
///
/// # Safety
/// `current` and `next` must point to valid `SavedState` for the duration of the
/// switch, invoked from a consistent kernel-stack context.
pub unsafe extern "C" fn switch(
    current: *mut SavedState,
    next: *const SavedState,
    save_flag: *const AtomicU32,
);

/// Activate `aspace` and enter user mode for the first time via the trap frame
/// `tf`. Does not return. Tags the entry when tagging is enabled, so init does
/// not run its first quantum untagged. On both architectures the rebased boot
/// stack lies in the direct map, which every user address space shares. On
/// x86-64 the tag bookkeeping runs in Rust and the composed CR3 (root + PCID) is
/// handed to the naked `switch_and_enter_user`, which moves the stack pointer to
/// init's kernel stack, writes CR3, and builds the `iretq` frame there; on
/// RISC-V this routes through `AddressSpace::activate` (tagged `satp` write +
/// generation check) then `sret`. `aspace` must already be marked active on this
/// CPU, and `set_kernel_trap_stack` must have been called first.
pub unsafe fn first_entry_to_user(aspace: *const AddressSpace, tf: *const TrapFrame) -> !;

/// Return from a trap to userspace, restoring full user register state from `tf`.
/// Does not return.
pub unsafe extern "C" fn return_to_user(tf: *const TrapFrame) -> !;
```

---

## `interrupts` — `arch::current::interrupts`

Controls interrupt delivery, installs exception/external handlers, and provides the
inter-processor interrupt (IPI) primitives used by the TLB-shootdown and wakeup paths.

```rust
/// Disable interrupts on the current CPU; returns whether they were enabled.
pub fn disable() -> bool;
/// Enable interrupts on the current CPU.
pub unsafe fn enable();
/// Whether interrupts are currently enabled on this CPU.
pub fn are_enabled() -> bool;

/// Initialise interrupt-controller hardware and register exception handlers
/// (IDT on x86-64; `stvec` on RISC-V). `init_ap` does the per-AP equivalent.
pub unsafe fn init();
pub unsafe fn init_ap();

/// Acknowledge / mask / unmask an external interrupt line. On x86-64, `mask` and
/// `unmask` take a GSI at the I/O APIC, and `acknowledge` writes the local-APIC
/// EOI and ignores `irq`. On RISC-V, `irq` is a PLIC source.
pub fn acknowledge(irq: u32);
pub fn mask(irq: u32);
pub fn unmask(irq: u32);

/// Route a device IRQ to the BSP and leave it masked at the controller; the
/// driver unmasks via `SYS_IRQ_ACK`. x86-64 installs an IOAPIC redirection
/// entry; RISC-V enables then masks the PLIC source.
pub unsafe fn route_device_irq(irq: u32);

/// Send a TLB-shootdown or wakeup IPI to the CPU with the given hardware id
/// (APIC id on x86-64; hart id on RISC-V).
pub unsafe fn send_tlb_shootdown_ipi(target_hw_id: u32);
pub unsafe fn send_wakeup_ipi(target_hw_id: u32);

/// Spin until `cond` holds, escalating (resend IPIs → NMI backtrace on x86-64,
/// a logged warning on RISC-V → `crate::fatal`) per
/// the timing ladder described by `ctx`. Used by the shootdown initiator's wait.
pub unsafe fn wait_for_ack(cond: impl FnMut() -> bool, ctx: &IpiWaitCtx<'_>);
```

The `wait_for_ack` phases and their windows are specified in
[scheduling-internals.md](scheduling-internals.md) § IPI Watchdog Ladder.

External-IRQ routing is reached through the `route_device_irq` surface function above; the
underlying controller programming (`ioapic::route` on x86-64; the PLIC enable path on
RISC-V) remains arch-private. Per-CPU table allocation that exists only on x86-64 (GDT/TSS,
AP IST stacks, NMI-backtrace storage) is reached through the `init_ap_percpu_storage`
module-level surface function (a no-op on RISC-V), not a `cfg(target_arch)`-gated call.

---

## `timer` — `arch::current::timer`

Periodic preemption timer: each timer interrupt runs `sched::timer_tick`, which decrements the
running thread's `slice_remaining` to enforce time slices; the tick counter below timestamps
sleep and IPC deadlines.

The tick mechanism is arch-internal: x86-64 uses TSC-deadline mode where CPUID advertises
it and falls back to the periodic local-APIC timer; riscv64 arms the Sstc `stimecmp` CSR
using the bootloader-discovered timebase (`init` refuses to boot without Sstc or a
discovered timebase, per
[platform-requirements.md](../../../docs/platform-requirements.md)).

```rust
/// Initialise the per-CPU preemption timer with a `period_us` microsecond
/// period (BSP), or the per-AP equivalent. Call after `interrupts::init`.
pub unsafe fn init(period_us: u64);
pub unsafe fn init_ap(period_us: u64);

/// Monotonic system-wide tick counter (units of timer periods), derived from a
/// globally consistent clock (x86-64 TSC; RISC-V `time` CSR), and its rate.
pub fn current_tick() -> u64;
pub fn ticks_per_second() -> u64;

/// Microseconds elapsed since timer init, if available; busy-wait helper.
pub fn elapsed_us() -> Option<u64>;
pub fn delay_us(us: u64);
```

---

## `syscall` — `arch::current::syscall`

Architecture-specific syscall entry/return glue. Shared code does not call into this beyond
initialisation; the arch entry stub saves user state, calls `crate::syscall::dispatch`,
restores state, and returns to userspace.

```rust
/// Install the syscall entry handler on the current CPU. x86-64 sets `EFER.SCE`
/// and writes STAR / LSTAR / SFMASK. On RISC-V `init` is a no-op, because
/// `ecall` already reaches the dispatch layer through the `stvec` trap vector
/// that `interrupts::init` installs. Call once per CPU before enabling userspace.
pub unsafe fn init();
```

---

## `cpu` — `arch::current::cpu`

CPU identification, per-CPU storage, kernel-stack setup, and interrupt save/restore. Per-CPU
storage is architecture-managed (GS-base on x86-64; the `tp` register on RISC-V, with
`sscratch` holding the per-CPU pointer while in U-mode).

```rust
/// Hardware CPU identity: the initial (8-bit, CPUID leaf 1) APIC id on x86-64,
/// the hart id on RISC-V. No in-tree caller; the RISC-V implementation returns 0
/// on every hart (#443).
pub fn current_id() -> u32;
/// The 0-based logical CPU index used by arch-neutral code (`PerCpuData::cpu_id`).
pub fn current_cpu() -> u32;

/// Read the current stack pointer (`rsp` / `sp`). Used by the panic-path
/// backtrace scanner to bound the kernel-stack walk.
pub fn current_stack_pointer() -> u64;

/// Verify the platform hardware baseline and refuse unsupported hardware with a
/// clear diagnostic. Run once in early boot after the console is live. x86-64
/// checks the CPUID-detectable required features and sets `CR0.WP`; RISC-V probes
/// for the SBI HSM extension.
pub unsafe fn verify_baseline();

/// Install the current CPU's per-CPU data block at `addr`. Call once per CPU
/// before any per-CPU access.
pub unsafe fn install_percpu(addr: u64);

/// Set the kernel stack used by the next privilege transition. x86-64 writes
/// TSS.RSP0 and the SYSCALL kernel-RSP; RISC-V stores it in `PerCpuData::kernel_rsp`
/// through `tp`, from which `trap_entry` loads it. Call on every
/// switch to a user thread.
pub unsafe fn set_kernel_trap_stack(stack_top: u64);

/// Disable interrupts and return the prior state; restore it later. (x86-64
/// saves RFLAGS then `cli`; RISC-V clears `sstatus.SIE` atomically.) The
/// restore writes the saved enable state whatever the current state is, so a
/// window that enabled interrupts after saving (a preempt-disabled wait)
/// returns to the saved state on both arches (x86-64 `popfq`; RISC-V sets or
/// clears `sstatus.SIE`).
pub unsafe fn save_and_disable_interrupts() -> u64;
pub unsafe fn restore_interrupts(saved: u64);
pub unsafe fn disable_interrupts();

/// Atomically enable interrupts and halt until the next one (x86-64 `sti; hlt`;
/// RISC-V `wfi` then set `sstatus.SIE`); enter with interrupts disabled. `halt_loop`
/// disables interrupts and halts forever.
pub fn halt_until_interrupt();
pub fn halt_loop() -> !;

/// Copy `len` bytes between kernel and user memory across the SMAP/SUM access
/// window with in-kernel fault recovery: a fault on an unmapped or read-only
/// user span returns a non-zero sentinel (recovered by the page-fault handler's
/// user-copy fixup) instead of panicking. The sole sanctioned path for kernel
/// access to user pointers; the typed `crate::uaccess::copy_to_user` /
/// `copy_from_user` wrappers turn the sentinel into `SyscallError::InvalidAddress`.
pub unsafe fn copy_user(dst: *mut u8, src: *const u8, len: usize) -> usize;

/// Map a faulting PC to the `copy_user` recovery fixup, or `None`. Consulted by
/// the page-fault handler on a kernel-mode fault to redirect into the fixup.
pub fn user_copy_fixup(pc: u64) -> Option<u64>;
```

The required/opportunistic/unsupported classification and what each arch gates are in
[platform-requirements.md](../../../docs/platform-requirements.md).

Arch-private CPU helpers (CPUID/MSR/CR access and SMEP/SMAP and PCID enablement on x86-64; the
`satp` ASID-width probe on RISC-V) are not part of the cross-architecture contract surface.

---

## `console` — `arch::current::console`

Serial output available before drivers initialise; used for boot diagnostics and fatal
errors. (The framebuffer path is architecture-neutral, in `crate::console` and
`crate::framebuffer`.)

```rust
/// Initialise the serial device (the RISC-V ns16550 at `phys_base`; x86-64 COM1
/// at I/O port 0x3F8, `phys_base` ignored), write one byte, and read the UART
/// physical base (0 on x86-64). `rebase_serial` updates the MMIO base after the
/// direct map is established (a no-op on x86-64).
pub unsafe fn serial_init(phys_base: u64);
pub unsafe fn serial_write_byte(byte: u8);
pub fn uart_phys_base() -> u64;
pub unsafe fn rebase_serial(new_base: u64);
```

---

## `entropy` — `arch::current::entropy`

Hardware entropy primitives consumed by the kernel entropy subsystem
(`crate::entropy`; see [`entropy.md`](entropy.md)). The hardware RNG is optional —
neutral code gates every draw on `hw_rng_available` and always mixes the result
with timing jitter — so an architecture without one (RISC-V under default
firmware) satisfies the contract by reporting no source.

```rust
/// Whether the CPU exposes a hardware RNG instruction. x86-64 reports RDRAND or
/// RDSEED via CPUID; RISC-V returns false (no source under default firmware).
pub fn hw_rng_available() -> bool;

/// Draw one 64-bit hardware-RNG word, or `None` if no source succeeded. x86-64
/// prefers RDSEED (seed-grade) with an RDRAND fallback, each with bounded retry;
/// RISC-V returns `None`.
pub fn hw_rng_u64() -> Option<u64>;

/// Read a free-running cycle counter for jitter sampling; use deltas only
/// (x86-64 TSC via `rdtsc`; RISC-V the `time` CSR).
pub fn read_cycle_counter() -> u64;
```

---

## `trap_frame` — `arch::current::trap_frame`

The full user-mode register snapshot saved on the kernel stack at every privilege transition.
The layout is architecture-specific; these methods let shared `syscall/` and `sched/` code
operate on frames without `#[cfg(target_arch)]`.

```rust
pub struct TrapFrame { /* arch-specific layout */ }

impl TrapFrame {
    /// Syscall number (rax / a7) and primary return value (rax / a0).
    pub fn syscall_nr(&self) -> u64;
    pub fn set_return(&mut self, val: i64);

    /// User-mode instruction pointer (rip / sepc).
    pub fn instruction_pointer(&self) -> u64;

    /// Validate and sanitize a user-supplied register snapshot before resuming
    /// it in user mode. x86-64 rejects a non-user `rip` or `rsp`, forces ring-3
    /// selectors, and clears RFLAGS privilege bits; RISC-V rejects a non-user
    /// `sepc`, clears `scause`/`stval`, and leaves `sp` and `sstatus` as supplied,
    /// so a supplied SPP or SUM bit reaches hardware on resume (#443).
    /// `Err(())` maps to `SyscallError::InvalidArgument`.
    pub fn sanitize_for_user_resume(&mut self) -> Result<(), ()>;

    /// Read syscall argument `n` (rdi/rsi/rdx/r10/r8/r9 or a0..a5); 0 for n >= 6.
    pub fn arg(&self, n: usize) -> u64;

    /// Write IPC return values (primary + label, optionally a badge), and the
    /// call/recv reply variants used by the IPC fast paths.
    pub fn set_ipc_return(&mut self, primary: u64, label: u64);
    pub fn set_ipc_return_with_badge(&mut self, primary: u64, label: u64, badge: u64);
    pub fn set_ipc_call_return(&mut self, primary: u64, reply_label: u64, reply_word_count: u64);
    pub fn set_ipc_recv_return(&mut self, primary: u64, label: u64, badge: u64, word_count: u64);

    /// Initialise the frame for first entry to user mode (entry PC + user SP);
    /// other fields must be zeroed first. Set the first argument or TLS base (RISC-V
    /// restores `tp` from the frame; on x86-64 the frame field is layout-only and the
    /// TLS base goes through `context::seed_tls_base`).
    pub fn init_user(&mut self, entry: u64, stack: u64);
    pub fn set_arg0(&mut self, val: u64);
    pub fn set_tls_base(&mut self, tls_base: u64);
}
```

---

## Module-level constants and free functions — `arch::current::*`

Cross-architecture items that live directly on the arch module rather than in a per-concern
submodule:

```rust
/// Diagnostic architecture name ("x86_64" / "riscv64").
pub const ARCH_NAME: &str;

/// ELF machine type of the userspace images the kernel loads (init/ktest)
/// (`EM_X86_64` / `EM_RISCV`); `mm::init_reloc` checks relocations against it.
pub const EXPECTED_ELF_MACHINE: u16;

/// Valid external-interrupt id range (0..=255 GSIs on x86-64; PLIC sources
/// 1..=127 on RISC-V). No in-tree consumer.
pub const MIN_IRQ_ID: u32;
pub const MAX_IRQ_ID: u32;

/// Width of the root `Interrupt` range capability minted at Phase 7 (256 on
/// x86-64; 1024 on RISC-V, the PLIC id space). On RISC-V the cap admits ids
/// the kernel cannot route: `plic_enable` ignores a source above
/// `PLIC_NUM_SOURCES`, and registering an id of 256 or above panics in
/// `irq::register` (#443).
pub const ROOT_IRQ_COUNT: u32;

/// Whether the architecture has an I/O port space — `IoPort` capabilities and
/// the `sys_ioport_*` syscalls are meaningful. true on x86-64; false on RISC-V.
pub const HAS_IO_PORTS: bool;

/// Whether the architecture exposes SBI firmware — a root `SbiControl`
/// capability is minted and `SYS_SBI_CALL` is forwardable. false on x86-64;
/// true on RISC-V.
pub const HAS_SBI: bool;

/// Size in bytes of the per-thread I/O Permission Bitmap (8192 on x86-64; 0 on
/// RISC-V). Sizes the `iopb` field in `ThreadControlBlock` uniformly.
pub const IOPB_SIZE: usize;

/// Forward a sanctioned SBI call to firmware, mapping SBI errors to `Err(())`
/// (and always `Err(())` on x86-64, which has no SBI).
/// Called only by the neutral `syscall::sbi` handler.
pub fn sbi_forward(extension: u64, function: u64, a0: u64, a1: u64, a2: u64) -> Result<u64, ()>;

/// Allocate architecture-specific per-CPU tables during SMP bring-up: x86-64
/// per-AP GDT/TSS, AP IST stacks, and NMI-backtrace storage; a no-op on RISC-V.
pub fn init_ap_percpu_storage(cpu_count: usize, allocator: &mut mm::BuddyAllocator);
```

The `SYS_SBI_CALL` handler's rights check and `HAS_SBI` gate are specified in
[syscalls.md](syscalls.md) § `SYS_SBI_CALL`.

These items in otherwise arch-private submodules are also contract surface, because
architecture-neutral code calls them:
`gdt::{load_iopb, permit_port_range_u32, init_ap, bsp_tss_ptr, IOPB_SIZE}`,
`platform::{console_mmio, uart_base_for_boot_info, collect_mmio_direct_map_regions}`,
`fpu::{switch_out_save, switch_in_restore}`, `idt::load`, and
`ap_trampoline::{setup_trampoline, start_ap}` (the `gdt` items are stubs on RISC-V); the rest
of those modules is arch-private:

```rust
/// Load a thread's IOPB into the TSS, or clear it (x86-64); no-op on RISC-V.
pub unsafe fn gdt::load_iopb(iopb: Option<&[u8; IOPB_SIZE]>);
/// Permit an I/O port range in a thread's IOPB (x86-64); no-op on RISC-V.
pub fn gdt::permit_port_range_u32(iopb: &mut [u8; IOPB_SIZE], base: u32, count: u32);
/// Load a per-CPU GDT and TSS on an AP (x86-64); no-op on RISC-V.
pub unsafe fn gdt::init_ap(cpu_id: u32, rsp0: u64, ist1_top: u64, ist2_top: u64);
/// Virtual address of the BSP's static TSS (x86-64); 0 on RISC-V.
pub fn gdt::bsp_tss_ptr() -> u64;
/// Per-thread I/O Permission Bitmap size; the same value as the module-level
/// `IOPB_SIZE` (8192 on x86-64; 0 on RISC-V).
pub const gdt::IOPB_SIZE: usize;

/// Install the exception vector on the current AP: x86-64 `lidt` of the shared
/// IDT the BSP populated; RISC-V reinstalls `stvec`.
pub unsafe fn idt::load();

/// Context-switch FPU hooks. `switch_out_save` saves the outgoing thread's live
/// extended state if this CPU holds it (x86-64 XSAVE when it owns the FPU;
/// RISC-V when `sstatus.FS`/`VS` is Dirty) and arms the lazy trap.
/// `switch_in_restore` arms the first-use trap for the incoming thread (x86-64
/// sets `CR0.TS`; a no-op on RISC-V, where the trap path restores lazily).
pub unsafe fn fpu::switch_out_save(tcb: *mut ThreadControlBlock);
pub unsafe fn fpu::switch_in_restore(tcb: *mut ThreadControlBlock);

/// Physical (base, size) of a boot console UART needing a dedicated `Mmio`
/// capability at Phase 7: `Some` on RISC-V (ns16550, outside the aperture list);
/// `None` on x86-64 (legacy I/O-port COM1).
pub fn platform::console_mmio() -> Option<(u64, u64)>;
/// UART physical base for Phase 1 console init: the discovered UART base (or a
/// compiled-in default) on RISC-V; 0 on x86-64 (I/O-port COM1).
pub fn platform::uart_base_for_boot_info(km: &KernelMmio) -> u64;
/// Write the kernel-internal MMIO `(base, size)` regions Phase 3 maps above the
/// RAM ceiling into `out` and return their count: the LAPIC and every I/O APIC
/// on x86-64; 0 on RISC-V (PLIC and UART lie inside the RAM direct map).
pub fn platform::collect_mmio_direct_map_regions(km: &KernelMmio, out: &mut [(u64, u64)]) -> usize;

/// Copy the AP trampoline into the page at `trampoline_pa`; call once before
/// the first `start_ap`.
pub unsafe fn ap_trampoline::setup_trampoline(trampoline_pa: u64);
/// Start one AP (x86-64 INIT+SIPI; RISC-V SBI HSM `hart_start`). Every AP reads
/// its parameters from the one block in the trampoline page, so APs start
/// sequentially: the previous AP must be online (`APS_READY` observed) first.
/// x86-64 always returns `true` (SIPI delivery is unacknowledged); RISC-V
/// returns `false` when SBI rejects the request.
pub unsafe fn ap_trampoline::start_ap(
    trampoline_pa: u64,
    cpu_idx: u32,
    hw_id: u32,
    entry_fn: u64,
    stack_top: u64,
) -> bool;
```

---

## What Is Architecture-Specific vs Architecture-Neutral

**Architecture-specific** (lives in `arch/*/`):

- Page table format and hardware manipulation
- Register file layout and context switch assembly
- Exception/interrupt vector installation
- Interrupt controller interaction (APIC / PLIC)
- Segment descriptors, TSS (x86-64 only)
- SMEP/SMAP enforcement (x86-64); SUM bit management (RISC-V)
- Syscall instruction handling (`SYSCALL`/`SYSRET` vs `ECALL`)
- CPU feature detection (CPUID / ISA extensions)
- Hardware RNG and cycle-counter access (RDSEED/RDRAND/TSC vs the `time` CSR)
- SMP bringup (INIT/SIPI on x86-64; SBI HSM on RISC-V)

**Architecture-neutral** (lives outside `arch/`, for example in `mm/`, `cap/`, `ipc/`, `sched/`,
and `syscall/`):

- Buddy allocator algorithm
- Retype allocator and the page pools behind address spaces and CSpaces
- CSpace slot storage, lookup, and growth
- Capability derivation tree and revocation algorithm
- Endpoint, notification, event queue, and wait set objects
- Thread control block structure (except the arch-typed `saved_state`, `trap_frame`, and `iopb`
  fields)
- Run queue management, priority levels, and time-slice accounting
- Load balancing decisions
- Syscall dispatch table and argument validation
- Init process creation and initial CSpace population

---

## Adding a New Architecture

A new architecture port MUST:

1. Create `core/kernel/src/arch/<arch>/` with the module files listed above
2. Define every function in the dispatch surface — the build catches a missing item only
   where neutral code calls it; check by hand the items the preamble lists as having no
   neutral caller
3. Add a custom target JSON in `xtask/targets/`
4. Add a linker script in `core/kernel/linker/`
5. Add the `#[cfg]` branch in `core/kernel/src/arch/mod.rs`
6. Add the target to the workspace build configuration

Changes to shared kernel code MUST NOT be made to satisfy an architecture port. If
implementing a surface function requires a shared-code change, that change MUST be proposed
as a modification to this document and the surface definition.

The existing x86-64 implementation is the reference. Where RISC-V diverges in the current
implementation, comments explain why. New ports should document deviations from the reference
equally clearly.

---

## Summarized By

[core/kernel/README.md](../README.md), [Kernel Entropy Subsystem](entropy.md),
[Kernel Initialization Sequence](initialization.md), [Scheduler Internals](scheduler.md),
[SMP Scheduling and Locking Invariants](scheduling-internals.md),
[Syscall Interface Specification](syscalls.md)
