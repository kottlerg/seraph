# shared/pmu

Hardware performance counters behind a `PmuControl` capability: the portable events, the
register packing of `SYS_PMU_INFO`, `SYS_PMU_CONFIGURE` and `SYS_PMU_BIND`, the per-vendor decode
and event tables the kernel programs counters from, and, with the `client` feature, the user API
a measuring thread reads its CPU's counters through. The access model is
[docs/capability-model.md](../../docs/capability-model.md) § `PmuControl`, the calls are
[core/kernel/docs/syscalls.md](../../core/kernel/docs/syscalls.md) § Performance Counter Syscalls,
and the kernel's mechanism is [core/kernel/docs/perfmon.md](../../core/kernel/docs/perfmon.md).

---

## Source Layout

```
pmu/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs      # PmuEvent, PmuMode, Info, EventList, the handle packing, delta
    ├── intel.rs    # CPUID 0AH and 1AH decode, Layout, event selects, the TLB model table
    ├── amd.rs      # Core counter extension and PerfMonV2 decode, event selects
    ├── riscv.rs    # SBI PMU function ids and flags, counter descriptions, Layout, event indices
    └── client.rs   # Pmu, Counters, read_counter (feature `client`)
```

`no_std`, no allocation. Everything but `client` is pure logic over `abi/syscall`'s `PMU_*`
constants, shared by the kernel and its callers and host-tested (`cargo xtask test`). The kernel
takes the crate without the `client` feature; a user of the counters takes it with the feature,
which adds the dependency on [`shared/syscall`](../syscall/README.md).

---

## Events and packing

`PmuEvent` names the portable events by their ABI ids: `Cycles` and `Instructions`, counted
wherever a CPU has counters, and `LlcReferences`, `LlcMisses`, `BranchInstructions`,
`BranchMisses`, `DtlbMisses` and `ItlbMisses`, counted only where the CPU counts them, as
`Info::supports` reports. `PmuMode` is `User`, `Kernel` or `All`.

`Info::pack` and `Info::unpack` carry `SYS_PMU_INFO`'s result; `EventList::encode` and
`EventList::decode` carry `SYS_PMU_CONFIGURE`'s event word and count, refusing more than
`PMU_CONFIGURE_MAX` events, an unknown id and a repeated event; `pack_handles` and `entry` carry
its handle word. `delta` is the count between two reads of a counter of a given width, across at
most one wrap.

---

## Per-vendor logic

| Module | Decodes | Kernel's counter | Events |
|---|---|---|---|
| `intel` | CPUID 0AH (version, general-purpose and fixed counters, width, the unavailable-event vector), 1AH (hybrid core type), the family and model | Fixed counter 1, else the highest general-purpose counter (`Layout::of`) | Architectural encodings gated on the unavailable-event vector; the TLB events from a model table (Skylake, Ice Lake and Tiger Lake, Golden Cove and Gracemont by core type) |
| `amd` | CPUID 80000001H `ECX[23]` (core counter extension) and 80000022H (PerfMonV2), family 17h and later | The highest core counter | Every event but the last-level cache ones, which the core counters do not count |
| `riscv` | `sbi_pmu_counter_get_info` results | The programmable counter of the highest CSR (`Layout::of`) | The SBI hardware and cache event indices; which a hart counts is probed at bring-up; offered only where every hart has Sscofpmf |

Each module also encodes an event select (x86-64: event, unit mask, `USR`, `OS`, `EN`) or the SBI
configuration flags (riscv64: `CLEAR_VALUE`, `AUTO_START` and the mode's inhibit bits) for a
mode.

---

## Client

`Pmu::new(cap)` wraps a `PmuControl` capability. `info` describes the calling CPU's counters,
`configure` programs them and returns `Counters`, `release` releases them, and `bind` and
`unbind` grant and revoke a thread's reads. `Counters` holds the read handles; `bind` grants a
thread, normally the caller, their reads, `read` reads them in the order of the events, and
`delta` subtracts two readings at the counters' width. `Counters` is neither `Send` nor `Sync`:
a value is the CPU's that configured it.

A measuring thread pins itself to one CPU and yields once, so that it runs there, then configures
and binds itself:

```rust
syscall::thread_set_affinity(self_thread, cpu)?;
syscall::thread_yield()?;
let pmu = Pmu::new(pmu_cap);
let counters = pmu.configure(&[PmuEvent::Cycles, PmuEvent::Instructions], PmuMode::User)?;
counters.bind(self_thread)?;
let mut start = [0; 2];
counters.read(&mut start);
```

`read_counter` executes `RDPMC` on x86-64 and `csrr hpmcounterN` on riscv64; a read by an
unbound thread, or by a bound one on a CPU with no configuration, takes the CPU's fault.

---

## Summarized By

[shared/README.md](../README.md)
