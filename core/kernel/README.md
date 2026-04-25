# Kernel

This directory contains the Seraph microkernel. It handles four core responsibilities:
IPC, scheduling, memory management, and capabilities — along with the minimal
supporting mechanism they require (traps, timers, syscall entry, platform resource
validation). Everything else runs in userspace. See
[docs/architecture.md](../../docs/architecture.md) for the design philosophy behind
this boundary.

---

## Source Layout

```
kernel/
├── Cargo.toml                  # Workspace member; no_std crate
├── build.rs                    # Linker script selection per target
├── linker/
│   ├── x86_64.ld               # Linker script for x86-64
│   └── riscv64.ld              # Linker script for RISC-V
├── src/
│   ├── main.rs                 # kernel_entry() — arch-neutral init sequence
│   ├── arch/                   # Architecture-specific implementations
│   │   ├── mod.rs              # Re-exports the active arch module
│   │   ├── x86_64/             # x86-64 implementation
│   │   │   ├── mod.rs
│   │   │   ├── paging.rs       # Page table management (PML4/PML3/PML2/PML1)
│   │   │   ├── context.rs      # Thread context save/restore, context switch
│   │   │   ├── interrupts.rs   # IDT, exception handlers, APIC
│   │   │   ├── timer.rs        # APIC timer for preemption
│   │   │   ├── syscall.rs      # SYSCALL/SYSRET entry glue
│   │   │   ├── cpu.rs          # CPUID, topology, per-CPU state (GDT/TSS)
│   │   │   └── console.rs      # Early framebuffer/serial output
│   │   └── riscv64/            # RISC-V implementation
│   │       ├── mod.rs
│   │       ├── paging.rs       # Page table management (Sv48)
│   │       ├── context.rs      # Thread context save/restore, context switch
│   │       ├── interrupts.rs   # stvec, trap handler, PLIC
│   │       ├── timer.rs        # SBI timer for preemption
│   │       ├── syscall.rs      # ECALL entry glue
│   │       ├── cpu.rs          # Hart ID, topology, per-hart state
│   │       └── console.rs      # Early SBI console / framebuffer output
│   ├── mm/                     # Memory management subsystem
│   │   ├── mod.rs
│   │   ├── buddy.rs            # Physical frame allocator (buddy algorithm)
│   │   ├── slab.rs             # Slab allocator for fixed-size kernel objects
│   │   ├── size_class.rs       # General size-class allocator (heap)
│   │   ├── address_space.rs    # Virtual address space objects and lifecycle
│   │   └── tlb.rs              # TLB management, PCID/ASID allocation
│   ├── cap/                    # Capability subsystem
│   │   ├── mod.rs
│   │   ├── cspace.rs           # CSpace: slot storage, lookup, growth
│   │   ├── slot.rs             # Capability slot representation and rights
│   │   └── derivation.rs       # Derivation tree, revocation algorithm
│   ├── ipc/                    # IPC subsystem
│   │   ├── mod.rs
│   │   ├── endpoint.rs         # Endpoint object: wait queues, state machine
│   │   ├── signal.rs           # Signal object: atomic bitmask
│   │   ├── event_queue.rs      # Event queue: ring buffer
│   │   └── wait_set.rs         # Wait set: multi-source aggregation
│   ├── sched/                  # Scheduler
│   │   ├── mod.rs
│   │   ├── thread.rs           # Thread control block (TCB) definition
│   │   ├── run_queue.rs        # Per-CPU run queues and priority levels
│   │   ├── switch.rs           # Context switch coordination
│   │   └── load_balance.rs     # SMP load balancing and migration
│   └── syscall/                # Syscall dispatch
│       ├── mod.rs              # Dispatch table and entry coordination
│       ├── ipc.rs              # IPC syscall implementations
│       ├── cap.rs              # Capability syscall implementations
│       ├── mm.rs               # Memory syscall implementations
│       ├── thread.rs           # Thread syscall implementations
│       └── wait.rs             # Wait set syscall implementations
└── docs/
    ├── arch-interface.md       # Architecture abstraction trait definitions
    ├── initialization.md       # Boot-to-init sequence, phase by phase
    ├── syscalls.md             # Syscall ABI and complete syscall table
    ├── memory-internals.md     # Memory subsystem implementation details
    ├── capability-internals.md # Capability subsystem implementation details
    ├── ipc-internals.md        # IPC subsystem implementation details
    └── scheduler.md            # Scheduler internals and algorithms
```

---

## Module Responsibilities

### `arch/`

All architecture-specific code. Each subdirectory implements the traits defined in
[`docs/arch-interface.md`](docs/arch-interface.md). No code outside `arch/` contains
`#[cfg(target_arch)]` guards. The active architecture module is selected at build time
and re-exported from `arch/mod.rs` as a unified interface.

### `mm/`

Physical frame allocation, virtual address space management, the kernel heap, and TLB
management. The buddy allocator (`buddy.rs`) is the foundation; the slab and size-class
allocators build on top of it. The `address_space` module manages per-process virtual
address space objects. See [`docs/memory-internals.md`](docs/memory-internals.md).

### `cap/`

The capability subsystem. `cspace.rs` implements per-process capability spaces.
`slot.rs` defines the in-memory representation of a capability slot and its rights
bitmask. `derivation.rs` maintains the global derivation tree used for revocation.
See [`docs/capability-internals.md`](docs/capability-internals.md).

### `ipc/`

IPC kernel objects: endpoints for synchronous call/reply, signals for coalescing async
notification, event queues for ordered async notification, and wait sets for
multiplexed waiting. See [`docs/ipc-internals.md`](docs/ipc-internals.md).

### `sched/`

The preemptive, priority-based, SMP-aware scheduler. Per-CPU run queues, thread
control blocks, context switch coordination, and load balancing live here.
See [`docs/scheduler.md`](docs/scheduler.md).

### `syscall/`

The syscall dispatch layer. Architecture-specific entry glue (in `arch/*/syscall.rs`)
calls into this module's dispatch table, which routes to the appropriate subsystem
implementation. See [`docs/syscalls.md`](docs/syscalls.md).

---

## Build Structure

The kernel is a `no_std` Rust crate. It is a member of the Seraph Cargo workspace
and is compiled with a custom target specification for each architecture:

| Architecture | Target triple |
|---|---|
| x86-64 | `x86_64-seraph-none` |
| RISC-V | `riscv64gc-seraph-none` |

Custom target JSON files live in `targets/`. They specify the code model,
relocation model, and disable features the kernel cannot use (SSE/AVX before explicit
initialization, for example).

`build.rs` selects the appropriate linker script from `linker/` based on the active
target. Linker scripts place sections at the intended virtual addresses and establish
the higher-half layout described in [docs/memory-model.md](../../docs/memory-model.md).

---

## Module Initialization Order

Modules have initialization dependencies that must be respected. The sequence is
documented in detail in [`docs/initialization.md`](docs/initialization.md). The
high-level dependency order:

```
boot info validation
    └─► early console (arch)
            └─► buddy allocator (mm)
                    └─► kernel page tables (arch + mm)
                            └─► slab allocator (mm)
                                    └─► arch hardware init (arch)
                                            └─► platform resource validation
                                                    └─► capability system (cap)
                                                    └─► scheduler (sched)
                                                            └─► init thread (cap + mm + sched)
                                                                    └─► SMP bringup (arch + sched)
```

The kernel creates init's AddressSpace, CSpace, and Thread directly from the
`init_image` segments in `BootInfo` — no ELF parsing occurs in the kernel.

Each arrow means "requires the item above to be complete". Nothing in this chain is
reversible — a failure at any phase is a fatal boot error.

---

## Entry Point

The kernel entry point is `kernel_entry()` in `src/main.rs`. Its calling convention
and the CPU state guaranteed at entry are specified in
[`boot/docs/kernel-handoff.md`](../boot/docs/kernel-handoff.md); the
`BootInfo` layout is owned by the
[`abi/boot-protocol/`](../../abi/boot-protocol/) crate.

The entry point is `#[no_mangle] pub extern "C"` and marked `-> !`. It receives a
single argument: a `*const BootInfo` pointer whose physical address is in `rdi`
(x86-64) or `a0` (RISC-V) per the boot protocol.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System-wide design philosophy |
| [docs/memory-model.md](../../docs/memory-model.md) | Virtual address space layout, paging |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics and message format |
| [docs/capability-model.md](../../docs/capability-model.md) | Capability types, rights, revocation |
| [abi/boot-protocol/](../../abi/boot-protocol/) | `BootInfo` structure, `BOOT_PROTOCOL_VERSION` |
| [boot/docs/kernel-handoff.md](../boot/docs/kernel-handoff.md) | CPU state and register contents at kernel entry |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
