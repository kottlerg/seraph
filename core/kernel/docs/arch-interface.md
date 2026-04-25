# Architecture Abstraction Layer

All architecture-specific behaviour in the Seraph kernel is isolated behind Rust traits
defined in this document. Code outside `kernel/src/arch/` MUST interact with hardware
exclusively through these traits. No `#[cfg(target_arch)]` guards appear in
architecture-neutral kernel code.

This boundary contains architecture-specific bugs within `kernel/src/arch/` and MUST
be implemented in full by any architecture port.

---

## Module Structure

```
kernel/src/arch/
├── mod.rs          # Re-exports the active architecture's implementations
├── x86_64/
│   ├── mod.rs      # Implements all arch traits for x86-64
│   ├── paging.rs
│   ├── context.rs
│   ├── interrupts.rs
│   ├── timer.rs
│   ├── syscall.rs
│   ├── cpu.rs
│   └── console.rs
└── riscv64/
    ├── mod.rs      # Implements all arch traits for RISC-V
    ├── paging.rs
    ├── context.rs
    ├── interrupts.rs
    ├── timer.rs
    ├── syscall.rs
    ├── cpu.rs
    └── console.rs
```

`arch/mod.rs` performs the conditional compilation:

```rust
#[cfg(target_arch = "x86_64")]
pub use x86_64 as current;

#[cfg(target_arch = "riscv64")]
pub use riscv64 as current;
```

All shared kernel code uses `arch::current::*` — the only site of `#[cfg(target_arch)]`
in the kernel outside the `arch/` directory itself.

---

## Trait Definitions

### `Paging`

Manages the hardware page tables for a single address space. One implementation exists
per architecture; the kernel allocates and frees `PageTable` objects, then calls into
this trait to manipulate them.

```rust
pub trait Paging: Sized
{
    /// The root-level page table object for this architecture.
    type PageTable: Send;

    /// Allocate a new, empty page table. Returns None on allocation failure.
    fn new_page_table() -> Option<Box<Self::PageTable>>;

    /// Map `phys` at `virt` in `table` with the given flags.
    ///
    /// # Safety
    /// `phys` must be a valid, kernel-owned physical frame. `virt` must be
    /// canonical for this architecture. The caller must invalidate TLB entries
    /// for `virt` after this call.
    unsafe fn map(
        table: &mut Self::PageTable,
        virt: VirtAddr,
        phys: PhysAddr,
        flags: PageFlags,
    ) -> Result<(), MapError>;

    /// Remove the mapping for `virt` from `table`. Returns the physical address
    /// that was mapped, or None if the address was not mapped.
    ///
    /// # Safety
    /// The caller must invalidate TLB entries for `virt` after this call.
    unsafe fn unmap(
        table: &mut Self::PageTable,
        virt: VirtAddr,
    ) -> Option<PhysAddr>;

    /// Change the flags on an existing mapping without altering the physical
    /// address. Returns an error if `virt` is not currently mapped.
    ///
    /// # Safety
    /// The caller must invalidate TLB entries for `virt` after this call.
    unsafe fn protect(
        table: &mut Self::PageTable,
        virt: VirtAddr,
        flags: PageFlags,
    ) -> Result<(), MapError>;

    /// Walk the page table and return the physical address mapped at `virt`,
    /// or None if unmapped.
    fn translate(table: &Self::PageTable, virt: VirtAddr) -> Option<PhysAddr>;

    /// Install `table` as the active page table for the current CPU, using
    /// `pcid` as the hardware address-space tag (PCID on x86-64, ASID on
    /// RISC-V). If the hardware does not support tagging, `pcid` is ignored
    /// and a full TLB flush is performed.
    ///
    /// # Safety
    /// `table` must remain valid and unmodified for the duration it is active.
    /// Caller must ensure no conflicting TLB entries exist for the new mapping.
    unsafe fn activate(table: &Self::PageTable, pcid: u16);

    /// Flush the TLB entry for a single virtual address on the current CPU.
    ///
    /// # Safety
    /// Must be called after any mapping change that could leave stale entries.
    unsafe fn flush_page(virt: VirtAddr);

    /// Flush all TLB entries on the current CPU (excluding global entries).
    ///
    /// # Safety
    /// Expensive; use only when a full flush is necessary (e.g. PCID/ASID
    /// recycling). Prefer `flush_page` for single-address invalidation.
    unsafe fn flush_all();
}
```

`PageFlags` is an architecture-neutral bitfield with fields `readable`, `writable`,
`executable`, `user_accessible`, `global`, and `huge_page`. The implementation maps
these to architecture hardware bits. W^X is enforced at the `map` and `protect` call
sites — `writable && executable` returns `MapError::WxViolation`.

---

### `Context`

Defines the saved register state for a thread and the mechanism to switch between
threads. The context switch is the most performance-critical path in the kernel.

```rust
pub trait Context: Sized + Default
{
    /// Architecture-specific saved register state for one thread.
    /// Stored in the thread's TCB and swapped on every context switch.
    type SavedState: Send + Sized;

    /// Construct a new `SavedState` for a freshly created thread.
    ///
    /// - `entry`: virtual address where the thread begins execution
    /// - `stack_top`: initial stack pointer (top of the allocated stack)
    /// - `arg`: value placed in the first argument register (a0 / rdi)
    /// - `is_user`: if true, the thread begins in userspace privilege level
    fn new_state(
        entry: VirtAddr,
        stack_top: VirtAddr,
        arg: u64,
        is_user: bool,
    ) -> Self::SavedState;

    /// Return the thread's resume instruction pointer from a `SavedState`.
    ///
    /// For a newly created thread this is the entry function address passed to
    /// `new_state`. For a resumed thread it is the return address captured by
    /// the previous `switch` call. On x86-64: `rip`. On RISC-V: `ra`.
    fn entry_point(state: &Self::SavedState) -> VirtAddr;

    /// Switch from `current` to `next`.
    ///
    /// Saves all callee-saved registers into `current`, then restores all
    /// callee-saved registers from `next` and returns into `next`'s saved
    /// program counter.
    ///
    /// # Safety
    /// Both `current` and `next` must be valid, writable pointers to
    /// `SavedState` that remain valid for the duration of the switch. This
    /// function must be called from a consistent kernel-stack context.
    unsafe fn switch(current: *mut Self::SavedState, next: *const Self::SavedState);

    /// Activate a new address space and enter user mode for the first time.
    ///
    /// Called once at the end of kernel boot. Switches to `root_phys` as the
    /// active page-table root and transfers control to the user entry point
    /// encoded in `tf`. Does not return.
    ///
    /// On x86-64: `switch_and_enter_user` atomically writes CR3 and switches
    /// RSP to init's kernel stack before executing `iretq`. This is required
    /// because the boot stack's identity mapping is absent from user address
    /// spaces; any Rust call/return after the CR3 write would fault.
    ///
    /// On RISC-V: writes `satp` (with `sfence.vma` to serialise), then
    /// executes `sret`. The boot stack lives in the direct-mapped region and
    /// remains accessible after the `satp` write, so activation and entry can
    /// be separate steps.
    ///
    /// `set_kernel_trap_stack` must be called before this function so that the
    /// first U-mode trap lands on the correct kernel stack.
    ///
    /// # Safety
    /// `root_phys` must be a valid page-table root. `tf` must point to a
    /// `TrapFrame` on the init thread's kernel stack with entry and user-stack
    /// fields populated via `TrapFrame::init_user`.
    unsafe fn first_entry_to_user(root_phys: u64, tf: *const TrapFrame) -> !;

    /// Return from an exception or syscall to userspace, restoring the full
    /// user register state from `tf`. Does not return.
    ///
    /// # Safety
    /// `tf` must point to a valid `TrapFrame` with correct user-mode register
    /// state. `set_kernel_trap_stack` must already reflect the current thread.
    unsafe fn return_to_user(tf: *const TrapFrame) -> !;
}
```

---

### `Interrupts`

Controls interrupt delivery and installs handlers for hardware exceptions and external
interrupts. Exception handlers are registered at init time; external interrupt lines
are registered dynamically as drivers register.

```rust
pub trait Interrupts
{
    /// Disable interrupts on the current CPU. Returns true if interrupts were
    /// enabled before the call (for save/restore patterns).
    fn disable() -> bool;

    /// Enable interrupts on the current CPU.
    ///
    /// # Safety
    /// Caller must ensure the interrupt handler infrastructure is initialised
    /// and that enabling interrupts is safe at this point in execution.
    unsafe fn enable();

    /// Return true if interrupts are currently enabled on this CPU.
    fn are_enabled() -> bool;

    /// Initialise the interrupt controller hardware (IDT on x86-64, stvec on
    /// RISC-V) and register all architecture-defined exception handlers.
    /// Called once per CPU during initialisation.
    ///
    /// # Safety
    /// Must be called before enabling interrupts. Must be called from the CPU
    /// the state is being initialised for.
    unsafe fn init();

    /// Register `handler` as the callback for external interrupt line `irq`.
    /// The `irq` number is the architecture's native interrupt line identifier
    /// (APIC vector on x86-64; PLIC source ID on RISC-V).
    ///
    /// # Safety
    /// `handler` must remain valid for the lifetime of the interrupt registration.
    unsafe fn register_handler(irq: u32, handler: fn(u32));

    /// Acknowledge interrupt line `irq` at the interrupt controller, allowing
    /// further interrupts on that line. Called by the kernel after delivering
    /// the IRQ notification to the registered driver endpoint.
    fn acknowledge(irq: u32);

    /// Mask (disable) interrupt line `irq` at the interrupt controller.
    fn mask(irq: u32);

    /// Unmask (re-enable) interrupt line `irq` at the interrupt controller.
    fn unmask(irq: u32);
}
```

---

### `Timer`

Periodic preemption timer. The timer fires a per-CPU interrupt at the configured
interval, which the scheduler uses to enforce time slices.

```rust
pub trait Timer
{
    /// Initialise the per-CPU preemption timer with a period of `period_us`
    /// microseconds. Called once per CPU during initialisation, after
    /// `Interrupts::init()`.
    ///
    /// # Safety
    /// `Interrupts::init()` must have been called first. Must be called from
    /// the CPU being initialised.
    unsafe fn init(period_us: u64);

    /// Return the current value of the monotonic per-CPU tick counter.
    /// Ticks are in units of timer periods — not nanoseconds or any wall-clock
    /// unit. Used for relative time comparisons only.
    fn current_tick() -> u64;

    /// Return the number of timer ticks per second, for converting tick deltas
    /// to real time if needed.
    fn ticks_per_second() -> u64;
}
```

---

### `Syscall`

The architecture-specific syscall entry and return glue. This trait is not directly
called by shared kernel code — it defines what the arch module must export so that the
`syscall/mod.rs` dispatch table can be invoked from the arch-specific trap handler.

```rust
pub trait Syscall
{
    /// Install the syscall entry handler on the current CPU.
    ///
    /// On x86-64: writes the kernel's entry point to `LSTAR`, sets up `STAR`
    /// with the kernel/user segment selectors, and configures `SFMASK`.
    ///
    /// On RISC-V: ensures the trap vector (`stvec`) is configured to route
    /// `ecall` exceptions to the shared trap handler, which dispatches to
    /// the syscall layer.
    ///
    /// # Safety
    /// Must be called once per CPU, after segment/privilege infrastructure
    /// is initialised but before interrupts are enabled for userspace.
    unsafe fn init();
}
```

The arch-specific syscall entry stub saves userspace register state, calls
`crate::syscall::dispatch(nr, args)`, restores state, and returns to userspace.

---

### `Cpu`

CPU identification, feature detection, and per-CPU state management. Per-CPU storage
is architecture-specific (GS-base on x86-64; `sscratch` on RISC-V).

```rust
pub trait Cpu: Sized
{
    /// Per-CPU data stored in architecture-managed per-CPU storage.
    /// Accessed without locks since each CPU accesses only its own block.
    type PerCpuData: Sized;

    /// Return the unique ID of the current CPU (0-based).
    /// On x86-64 this is derived from the APIC ID; on RISC-V from the hart ID.
    fn current_id() -> u32;

    /// Return the total number of CPUs (logical processors) in the system.
    fn count() -> u32;

    /// Initialise per-CPU state for the current CPU. Must be called once per
    /// CPU before any code that accesses per-CPU data.
    ///
    /// # Safety
    /// Must be called exactly once per CPU, from that CPU's boot path.
    unsafe fn init_local(data: Box<Self::PerCpuData>);

    /// Return a mutable reference to the current CPU's `PerCpuData`.
    ///
    /// # Safety
    /// Only one reference may exist at a time. The caller must not allow the
    /// reference to escape a non-preemptible section.
    unsafe fn local_data<'a>() -> &'a mut Self::PerCpuData;

    /// Return the number of SMT siblings sharing the same physical core as
    /// the current CPU. Returns 1 if SMT is not present or not detectable.
    fn smt_siblings() -> u32;

    /// Spin-wait for `cycles` cycles. Used during early boot before the timer
    /// is configured. Not a precise delay; calibration is implementation-defined.
    fn spin_delay(cycles: u64);

    /// Halt the current CPU until the next interrupt arrives.
    /// On x86-64: executes `hlt`. On RISC-V: executes `wfi`.
    /// Must be called with interrupts enabled; if interrupts are disabled the
    /// CPU will halt indefinitely.
    fn halt_until_interrupt();

    /// Set the kernel stack pointer for the current CPU so that the next
    /// privilege-level transition (syscall or exception) uses `stack_top`.
    ///
    /// On x86-64: writes `stack_top` to both `TSS.RSP0` (interrupt/exception
    /// entry) and `SYSCALL_KERNEL_RSP` (fast SYSCALL entry). Both must be kept
    /// in sync so that all privilege transitions land on the same kernel stack.
    /// On RISC-V: writes `stack_top` to `sscratch`. The trap entry stub reads
    /// `sscratch` on every trap to detect U-mode entry and switch stacks before
    /// saving registers. The invariant is: `sscratch = kernel_stack_top` while
    /// in U-mode, `sscratch = 0` while in S-mode.
    ///
    /// Must be called on every context switch to a user thread.
    ///
    /// # Safety
    /// `stack_top` must point to the top of a valid, mapped kernel stack that
    /// remains allocated for the lifetime of the thread that will run next.
    unsafe fn set_kernel_trap_stack(stack_top: VirtAddr);

    /// Disable interrupts and return the prior interrupt state as an opaque
    /// value. Pass the returned value to `restore_interrupts` to restore.
    ///
    /// On x86-64: saves RFLAGS (specifically the IF bit) via `pushfq`, then
    /// executes `cli`. On RISC-V: reads `sstatus` atomically while clearing
    /// the SIE bit via `csrrci`.
    ///
    /// # Safety
    /// Must execute at ring 0 / S-mode.
    unsafe fn save_and_disable_interrupts() -> u64;

    /// Restore the interrupt state saved by `save_and_disable_interrupts`.
    ///
    /// On x86-64: restores RFLAGS via `push`/`popfq`. On RISC-V: re-sets
    /// `sstatus.SIE` if it was set in the saved value.
    ///
    /// # Safety
    /// `saved` must be a value returned by `save_and_disable_interrupts` on
    /// this CPU. Must execute at ring 0 / S-mode.
    unsafe fn restore_interrupts(saved: u64);
}
```

---

### `EarlyConsole`

Output mechanism available before the full kernel heap and drivers are initialised.
Used exclusively for boot-time diagnostics and fatal error messages. The implementation
may use the framebuffer from `BootInfo`, a UART, or the SBI console on RISC-V.

```rust
pub trait EarlyConsole
{
    /// Initialise the early console using information from `boot_info`.
    /// If no output device is available, this may be a no-op.
    ///
    /// # Safety
    /// Must be called before any use of `write_byte` or `write_str`.
    /// Physical memory must still be accessible at boot-info addresses.
    unsafe fn init(boot_info: &BootInfo);

    /// Write a single byte. No buffering; output is immediate. Implementations
    /// must handle `\n` (add `\r` if required by the output device).
    fn write_byte(b: u8);

    /// Write a string slice. Default implementation calls `write_byte` per byte.
    fn write_str(s: &str)
    {
        for b in s.bytes()
        {
            Self::write_byte(b);
        }
    }
}
```

---

### `TrapFrame`

The full user-mode register snapshot saved on the kernel stack at every privilege
transition (syscall, exception, or interrupt from user mode). The struct layout is
architecture-specific and defined in each arch's `trap_frame.rs`, but the following
methods are required on every implementation so that shared kernel code (`syscall/`,
`sched/`) can operate on trap frames without `#[cfg(target_arch)]` guards.

```rust
impl TrapFrame
{
    /// Return the syscall number.
    /// On x86-64: `rax`. On RISC-V: `a7`.
    pub fn syscall_nr(&self) -> u64;

    /// Write the primary syscall return value.
    /// On x86-64: `rax`. On RISC-V: `a0`.
    pub fn set_return(&mut self, val: i64);

    /// Read syscall argument `n` (0-indexed).
    /// On x86-64: rdi/rsi/rdx/r10/r8/r9 for n=0..5.
    /// On RISC-V: a0/a1/a2/a3/a4/a5 for n=0..5.
    /// Returns 0 for n >= 6.
    pub fn arg(&self, n: usize) -> u64;

    /// Write IPC return values: primary result and message label.
    /// On x86-64: primary → rax, label → rdx.
    /// On RISC-V:  primary → a0,  label → a1.
    pub fn set_ipc_return(&mut self, primary: u64, label: u64);

    /// Write IPC return values with token: primary, label, and token.
    /// On x86-64: primary → rax, label → rdx, token → rsi.
    /// On RISC-V:  primary → a0,  label → a1,  token → a2.
    pub fn set_ipc_return_with_token(&mut self, primary: u64, label: u64, token: u64);

    /// Initialise the frame for first entry to user mode.
    ///
    /// Sets the user entry point and user stack pointer. All other fields
    /// must be zeroed by the caller before this method is invoked.
    /// On x86-64: populates rip, rsp, cs (USER_CS), ss (USER_DS), rflags (IF=1).
    /// On RISC-V: populates sepc (entry point) and sp (x2, user stack pointer).
    ///            sstatus (SPP=0, SPIE=1) is set by `return_to_user` immediately
    ///            before `sret`.
    pub fn init_user(&mut self, entry: u64, stack: u64);
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
- PCID/ASID hardware management
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
2. Implement every trait in this document — the compiler enforces completeness
3. Add a custom target JSON in `targets/`
4. Add a linker script in `kernel/linker/`
5. Add the `#[cfg]` branch in `arch/mod.rs`
6. Add the target to the workspace build configuration

Changes to shared kernel code MUST NOT be made to satisfy an architecture port. If
implementing a trait requires a shared-code change, that change MUST be proposed as
a modification to this document and the trait definitions.

The existing x86-64 implementation is the reference. Where RISC-V diverges in the
current implementation, comments explain why. New ports should document deviations
from the reference equally clearly.

---

## Summarized By

None
