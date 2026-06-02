# Architecture Abstraction Layer

How architecture-specific kernel behaviour is isolated under `arch/<target>/` and reached
by architecture-neutral code through a single module-boundary dispatch surface.

---

All architecture-specific behaviour in the Seraph kernel lives under `kernel/src/arch/`.
Architecture-neutral code reaches it through the `arch::current` module alias — calling
`arch::current::<module>::<function>`. `arch/mod.rs` selects the active architecture's
module as `current` via `#[cfg(target_arch)]`.

The dispatch surface is **free functions and concrete types grouped into per-concern
submodules**, not cross-architecture traits. `docs/coding-standards.md` §C permits this —
the arch-dispatch surface may be "traits, type aliases, or re-exports", and a module
boundary that re-exports per-architecture free functions satisfies the rule — and requires
architecture-neutral code to route arch divergence through the surface rather than
`#[cfg(target_arch)]` blocks. There are no `trait` definitions or trait `impl`s under
`arch/`; inherent `impl` blocks on concrete types (`SavedState`, `TrapFrame`, …) are normal.

Every function in the dispatch surface MUST be defined on every supported architecture
(§C). The completeness check is the per-architecture build: if a surface function is
missing on the target being compiled, an `arch::current::…` call fails to resolve and the
build breaks.

---

## Module Structure

```
kernel/src/arch/
├── mod.rs          # The only #[cfg(target_arch)] site; aliases the active arch as `current`
├── x86_64/
│   ├── mod.rs      # Module declarations and arch constants (ARCH_NAME, …)
│   ├── paging.rs   ├── context.rs  ├── interrupts.rs ├── timer.rs
│   ├── syscall.rs  ├── cpu.rs      ├── console.rs    ├── trap_frame.rs
│   ├── gdt.rs      ├── idt.rs      ├── ioapic.rs     ├── fpu.rs
│   ├── platform.rs └── ap_trampoline.rs
└── riscv64/
    ├── mod.rs
    ├── paging.rs   ├── context.rs  ├── interrupts.rs ├── timer.rs
    ├── syscall.rs  ├── cpu.rs      ├── console.rs    ├── trap_frame.rs
    ├── gdt.rs      ├── idt.rs      ├── sbi.rs        ├── fpu.rs
    ├── platform.rs └── ap_trampoline.rs
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

The sections below document the **cross-architecture contract surface** — the functions and
types architecture-neutral code depends on. Some submodules are arch-private support code
(`gdt`, `idt`, `ioapic`/`sbi`, `fpu`, `platform`, `ap_trampoline`) whose internals are not
part of the cross-architecture contract and are not documented here.

Addresses cross this boundary as raw `u64`. Page-permission and page-table-rewrite types
(`PageFlags`, `MapOutcome`, `PagingError`) are architecture-neutral and defined in
`mm::paging`; the per-architecture mapping code maps them to hardware bits.

---

## `paging` — `arch::current::paging`

Manages hardware page tables. A page table is referenced by its physical root frame
(`root_phys`) and a direct-map virtual alias (`root_virt`) — not an owned table object;
intermediate frames are allocated from and returned to the kernel page-table pool.

```rust
/// Install `root_phys` as the active page table for the current CPU with a full
/// TLB flush: x86-64 writes CR3 with PCID 0 (flushing PCID 0's entries); RISC-V
/// writes `satp` with ASID 0 and executes `sfence.vma`. This is the untagged
/// fallback path, used when hardware tagging is unavailable or the tag pool is
/// exhausted; the tagged context-switch path uses `activate_tagged` (below),
/// driven by `AddressSpace::activate`. See docs/memory-model.md.
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
/// address-space object's reserved pool rather than the global allocator.
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

/// Remove the user mapping for `virt`. The caller must invalidate the TLB.
pub unsafe fn unmap_user_page(root_virt: u64, virt: u64);

/// Walk the user tables and return `(phys, flags_word)` mapped at `virt`, or
/// None if unmapped.
pub unsafe fn translate_user_page(root_virt: u64, virt: u64) -> Option<(u64, u64)>;

/// Free all user page-table frames for the address space rooted at `root_virt`.
pub unsafe fn free_user_page_tables(root_virt: u64);

/// Invalidate the local-CPU TLB entry for a single virtual address
/// (x86-64 `invlpg`; RISC-V `sfence.vma virt`).
pub unsafe fn flush_page(virt: u64);

/// Invalidate all non-global TLB entries on the current CPU
/// (x86-64 CR3 reload; RISC-V `sfence.vma zero, zero`).
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

/// Per-CPU enable of tagged TLBs; returns the number of hardware tags available
/// (`0` when unsupported). x86-64 sets `CR4.PCIDE` and returns 4096; RISC-V
/// probes the `satp` ASID width and returns `1 << width`. Called on the BSP
/// (whose return seeds the tag pool) and on every AP (which must set its own
/// `CR4.PCIDE` before any tagged CR3 load).
pub unsafe fn enable_tagged_tlb() -> usize;

/// Classify a user page fault as spurious (the live PTE already permits the
/// access — a stale entry the handler resolves by retrying) versus a real fault.
pub unsafe fn user_fault_is_spurious(va: u64, write: bool, instr: bool) -> bool;

/// Rebase the boot stack into the direct map during early paging setup
/// (RISC-V; x86-64 provides a no-op stub).
pub unsafe fn rebase_boot_stack(direct_map_base: u64);
```

`PageFlags` (`mm::paging`) is an architecture-neutral bitfield with fields `readable`,
`writable`, `executable`, and `uncacheable`. `readable` is meaningful only on RISC-V (x86-64
has no read-disable bit); `uncacheable` sets PCD|PWT on x86-64 and is a documentation marker
under Sv48-without-Svpbmt on RISC-V. W^X is enforced at the memory syscall layer
(`syscall::mem` map/protect reject a writable-and-executable request with
`SyscallError::WxViolation`); the arch mapping primitives require the caller to have already
validated W^X.

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
/// PC, `stack_top` the initial SP, `arg` the first argument register (rdi / a0),
/// and `is_user` selects the starting privilege level.
pub fn new_state(entry: u64, stack_top: u64, arg: u64, is_user: bool) -> SavedState;

/// Seed the thread-local-storage base in a `SavedState` before first run.
pub fn seed_tls_base(saved: &mut SavedState, tls_base: u64);

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
/// not run its first quantum untagged. On x86-64 the CR3 write and stack switch
/// stay atomic with `iretq` (the boot stack is absent from user address spaces),
/// so the tag bookkeeping runs in Rust beforehand and the composed CR3 (root +
/// PCID) is handed to the naked switch; on RISC-V the boot stack lives in the
/// direct map, so this routes through `AddressSpace::activate` (tagged `satp`
/// write + generation check) then `sret`. `aspace` must already be marked active
/// on this CPU, and `set_kernel_trap_stack` must have been called first.
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

/// Acknowledge / mask / unmask an external interrupt line (APIC vector on
/// x86-64; PLIC source on RISC-V).
pub fn acknowledge(irq: u32);
pub fn mask(irq: u32);
pub fn unmask(irq: u32);

/// Send a TLB-shootdown or wakeup IPI to the CPU with the given hardware id
/// (APIC id on x86-64; hart id on RISC-V).
pub unsafe fn send_tlb_shootdown_ipi(target_hw_id: u32);
pub unsafe fn send_wakeup_ipi(target_hw_id: u32);

/// Spin until `cond` holds, escalating (resend IPIs → NMI backtrace → panic) per
/// the timing ladder described by `ctx`. Used by the shootdown initiator's wait.
pub unsafe fn wait_for_ack(cond: impl FnMut() -> bool, ctx: &IpiWaitCtx<'_>);
```

External-IRQ routing is performed through arch-private modules (`ioapic::route` on x86-64;
the PLIC path on RISC-V) and is not part of the cross-architecture contract surface.
NMI-backtrace storage allocation (`init_nmi_backtrace_storage`) is likewise x86-64-private
(no RISC-V counterpart; its caller is `#[cfg(target_arch = "x86_64")]`-gated).

---

## `timer` — `arch::current::timer`

Periodic preemption timer; the scheduler uses its tick counter to enforce time slices.

```rust
/// Initialise the per-CPU preemption timer with a `period_us` microsecond
/// period (BSP), or the per-AP equivalent. Call after `interrupts::init`.
pub unsafe fn init(period_us: u64);
pub unsafe fn init_ap(period_us: u64);

/// Monotonic per-CPU tick counter (units of timer periods) and its rate.
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
/// Install the syscall entry handler on the current CPU. x86-64 writes LSTAR /
/// STAR / SFMASK; RISC-V routes `ecall` through the trap vector to the dispatch
/// layer. Call once per CPU before enabling userspace.
pub unsafe fn init();
```

---

## `cpu` — `arch::current::cpu`

CPU identification, per-CPU storage, kernel-stack setup, and interrupt save/restore. Per-CPU
storage is architecture-managed (GS-base on x86-64; `sscratch` on RISC-V).

```rust
/// Hardware and logical CPU identity (APIC id / hart id, and the 0-based logical
/// index used by arch-neutral code).
pub fn current_id() -> u32;
pub fn current_cpu() -> u32;

/// Install the current CPU's per-CPU data block at `addr`. Call once per CPU
/// before any per-CPU access.
pub unsafe fn install_percpu(addr: u64);

/// Set the kernel stack used by the next privilege transition. x86-64 writes
/// TSS.RSP0 and the SYSCALL kernel-RSP; RISC-V writes `sscratch`. Call on every
/// switch to a user thread.
pub unsafe fn set_kernel_trap_stack(stack_top: u64);

/// Disable interrupts and return the prior state; restore it later. (x86-64
/// saves RFLAGS then `cli`; RISC-V clears `sstatus.SIE` atomically.)
pub unsafe fn save_and_disable_interrupts() -> u64;
pub unsafe fn restore_interrupts(saved: u64);
pub unsafe fn disable_interrupts();

/// Halt until the next interrupt (`hlt` / `wfi`); never-returning halt loop.
pub fn halt_until_interrupt();
pub fn halt_loop() -> !;

/// Bracket a copy to/from user memory (SMAP/SUM toggle).
pub unsafe fn user_access_begin();
pub unsafe fn user_access_end();
```

Arch-private CPU helpers (CPUID/MSR/CR access on x86-64, SMEP/SMAP/SUM enablement) are not
part of the cross-architecture contract surface.

---

## `console` — `arch::current::console`

Serial output available before drivers initialise; used for boot diagnostics and fatal
errors. (The framebuffer/SBI path is arch-private.)

```rust
/// Initialise the serial device at `phys_base`, write one byte, and read the
/// UART physical base. `rebase_serial` updates the MMIO base after the direct
/// map is established.
pub unsafe fn serial_init(phys_base: u64);
pub unsafe fn serial_write_byte(byte: u8);
pub fn uart_phys_base() -> u64;
pub unsafe fn rebase_serial(new_base: u64);
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

    /// Read syscall argument `n` (rdi/rsi/rdx/r10/r8/r9 or a0..a5); 0 for n >= 6.
    pub fn arg(&self, n: usize) -> u64;

    /// Write IPC return values (primary + label, optionally a token), and the
    /// call/recv reply variants used by the IPC fast paths.
    pub fn set_ipc_return(&mut self, primary: u64, label: u64);
    pub fn set_ipc_return_with_token(&mut self, primary: u64, label: u64, token: u64);
    pub fn set_ipc_call_return(&mut self, primary: u64, reply_label: u64, reply_word_count: u64);
    pub fn set_ipc_recv_return(&mut self, primary: u64, label: u64, token: u64, word_count: u64);

    /// Initialise the frame for first entry to user mode (entry PC + user SP);
    /// other fields must be zeroed first. Set the first argument or TLS base.
    pub fn init_user(&mut self, entry: u64, stack: u64);
    pub fn set_arg0(&mut self, val: u64);
    pub fn set_tls_base(&mut self, tls_base: u64);
}
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
- SMP bringup (INIT/SIPI on x86-64; SBI HSM on RISC-V)

**Architecture-neutral** (lives in `mm/`, `cap/`, `ipc/`, `sched/`, `syscall/`):

- Buddy allocator algorithm and zone management
- Slab allocator and size-class allocator
- CSpace slot storage, lookup, and growth
- Capability derivation tree and revocation algorithm
- Endpoint, signal, event queue, and wait set objects
- Thread control block structure (except the `SavedState` field)
- Run queue management, priority levels, and time-slice accounting
- Load balancing decisions
- Syscall dispatch table and argument validation
- Init process creation and initial CSpace population

---

## Adding a New Architecture

A new architecture port MUST:

1. Create `kernel/src/arch/<arch>/` with the module files listed above
2. Define every function in the dispatch surface — a missing surface function fails to
   resolve at its `arch::current::…` call site and breaks the build, which is the
   completeness check
3. Add a custom target JSON in `targets/`
4. Add a linker script in `kernel/linker/`
5. Add the `#[cfg]` branch in `arch/mod.rs`
6. Add the target to the workspace build configuration

Changes to shared kernel code MUST NOT be made to satisfy an architecture port. If
implementing a surface function requires a shared-code change, that change MUST be proposed
as a modification to this document and the surface definition.

The existing x86-64 implementation is the reference. Where RISC-V diverges in the current
implementation, comments explain why. New ports should document deviations from the reference
equally clearly.

---

## Summarized By

None
