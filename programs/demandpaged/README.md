# demandpaged

Test fixture for the demand-paging pager surface. The [`svctest`](../../services/svctest/README.md)
pager phases spawn it as `/programs/demandpaged`, one of the harness fixtures installed under
`/programs/` (see [docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout)). It
prints no marker lines and reports through its exit status, which the spawning phase checks; its
`bench` mode also logs the cycles it measures.

---

## Source Layout

```
programs/demandpaged/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Mode selection, the in-region, out-of-region, drain, teardown and
                           # bench modes
```

---

## Modes

Demand paging is the system-wide default: procmgr binds memmgr as the pager of each process it
creates unless the creator opts out with `CREATE_PINNED`
([docs/fault-handling.md](../../docs/fault-handling.md#demand-paging-and-the-default-system-pager)).
memmgr backs faults inside a region the process registered and kills the thread on any other
fault ([memmgr IPC Interface](../../services/memmgr/docs/ipc-interface.md)). The mode is
selected by argv: any argument equal to `oor` selects the out-of-region mode, any equal to
`ptdrain` the page-table drain mode, any equal to `teardown` the teardown mode, and any equal to
`bench` the bench mode, which takes the argument after it as its chunk count.

| Mode | Behaviour | Exit status |
|---|---|---|
| default | `register_demand_paged(4)` reserves four pages and registers them read-write with the pager; the program writes a per-(page, byte) pattern across all four, then reads it back | `0` on a full match; `2` if registration fails; `3` on a mismatch |
| `oor` | `reserve_pages(1)` reserves one page ([page reservations](../../docs/userspace-memory-model.md#page-reservations)) that is never registered; the program writes to it | Expected to be killed; `0` if the write survives, so the harness's must-be-killed assertion fails; `2` if the reservation fails |
| `ptdrain` | `register_demand_paged(1024)` registers a region holding a whole 2 MiB block that nothing has mapped, so its first touch needs a fresh page table. The program then maps one page of a `REQUEST_MEMORY_CAPS` frame in each 2 MiB block of a second reservation, with no funding, until `mem_map` returns `OutOfMemory` and the address space's page-table pool (`CAP_INFO_ASPACE_PT_BUDGET`) is empty. It then writes a pattern to the block's first page and reads it back, so the pager must fund the pool itself ([memmgr Memory Pool § Client page-table funding](../../services/memmgr/docs/memory-pool.md#client-page-table-funding)) | `0` on a full match; `2` if a reservation or the registration fails; `3` on a mismatch; `4` if the frame request or a drain mapping fails for a reason other than an empty pool; `5` if the drain does not empty the pool; killed if the pager declines the fault |
| `bench [CHUNKS]` | Times the first touch of each of `CHUNKS` (64 when omitted) chunks of a demand region and a grant-and-map of each of `CHUNKS` chunks, and logs the result line of each path (§ Bench mode) | `0` when both paths ran; `2` if the registration or the reservation fails, a region too large for the address space included; `4` if a grant or its map fails; `6` if `CHUNKS` is not a positive integer that fits in 64 bits; `7` if the thread cannot be pinned to CPU 0; `8` if the CPU count cannot be read or a result line cannot be written; killed if the pager declines a fault |
| `teardown` | `register_demand_paged(4)` registers a region, and the program fills and reads it back as the default mode does, then tears it down with `unregister_demand_paged`, which unregisters it with the pager and releases the reservation. It then registers four pages again, which the lowest-address first-fit reservation places on the same VA, so the pager accepts the registration only if the teardown removed the first one, and fills, reads back and tears down the second region the same way | `0` when both rounds pass; `2` if a registration fails; `3` on a mismatch; `4` if a teardown gets no answer from the pager; `5` if the second region lands at another VA |

---

## Bench mode

The bench mode measures what a 16-page chunk costs a process on each of memmgr's two paths: a
demand fault, and a grant of Memory caps the process maps itself. A chunk is
`DEMAND_CHUNK_PAGES` (16) pages, the run memmgr backs on a demand fault when a free run covers it
([memmgr Memory Pool § Demand faults](../../services/memmgr/docs/memory-pool.md#demand-faults)).
Each path runs 4 untimed chunks, then the `CHUNKS` timed ones; cycles come from
[shared/bench](../../shared/bench/README.md)'s `Counters`, `rdtsc` on x86_64 and `csrr cycle` on
riscv64, opened once the thread is pinned. Each sample spans a block on memmgr, and riscv64 keeps
no two harts' `cycle` counters in step, so the mode pins its thread to CPU 0 before it times
anything; the warm-up chunks, which block on memmgr too, leave it running there.

| Path | One sample |
|---|---|
| `fault` | The first store into a chunk of a region `register_demand_paged` registered: the fault's delivery to memmgr, memmgr's backing of the chunk (run selection, zeroing, the map), and the resume. The registration funds the region's page tables, so no sample funds any |
| `grant` | `REQUEST_MEMORY_CAPS` for the chunk's pages with `REQUIRE_CONTIGUOUS`, the cap's map into a reservation with `mem_map_funded`, which funds page tables when the map is refused for want of them, and the first store into it |

The mode logs under the name `demandpaged` one result line per path, in the form
[shared/bench/README.md § Result line](../../shared/bench/README.md#result-line) specifies, where
`<path>` is `fault` or `grant`, `pages=16` is the chunk's size, and `n=` is `CHUNKS`:

```text
bench demandpaged.chunk_backing path=<path> pages=16 arch=<arch> cpus=<k> unit=cycles
    n=<n> min=<v> p50=<v> p90=<v> p99=<v> max=<v>
```

The line is one line, wrapped above for width only.

The figures report and gate nothing; the cycle units differ by architecture, so only figures of
one architecture compare.

---

## Harness Phases

| Phase | Spawn | Expected outcome |
|---|---|---|
| `demand_paging` | Default mode | Clean exit; memmgr's all-RAM-accounted identity still holds |
| `demand_paging_segfault` | `oor` argument | Killed with an exit reason at or above `EXIT_FAULT_BASE` |
| `demand_paging_pinned` | Default mode, `pinned(true)` | Killed with an exit reason at or above `EXIT_FAULT_BASE`, since no pager is bound; the RAM identity still holds |
| `demand_paging_pt_drain` | `ptdrain` argument | Clean exit; the RAM identity still holds |
| `demand_paging_teardown` | `teardown` argument | Clean exit; the RAM identity still holds |
| `demand_fault_cost` | `bench` argument | Clean exit; the RAM identity still holds; no bound on the logged cycles |

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Harness model and the sysroot layout of test fixtures |
| [docs/fault-handling.md](../../docs/fault-handling.md) | Default system pager and the pinned opt-out |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | Page-reservation surface |
| [memmgr IPC Interface](../../services/memmgr/docs/ipc-interface.md) | `REGISTER_REGION` and the fault arm |

---

## Summarized By

[memmgr Memory Pool](../../services/memmgr/docs/memory-pool.md)
