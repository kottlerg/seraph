# mem-fill

Fills memmgr's pool down to its growth floor, the system reserve and, while chunks are swapped, the
restore headroom ([memmgr Memory Pool](../../services/memmgr/docs/memory-pool.md#eviction)
§ Eviction), for the test fixtures that drive the out-of-memory paths: the
[`memhog`](../../services/memhog/README.md) fixture, which oomd stops, and the `oom-fill` mode of
[`crashme`](../../programs/crashme/README.md), beside whose `oom-touch` write crashd holds a fault.

---

## Fill

A `Fill` allocates a 2 MiB ballast and room for 256 blocks at its creation, so the fill itself
allocates only the blocks it commits. The ballast holds the heap's floor, an uncommitted demand
region whose untouched pages memmgr backs only while it has pages to spare, so every block the fill
commits lies above it.

`top_up` reads what memmgr can still grant a process outside the reserve, from `QUERY_POOL_STATUS`
(its free pages outside `promised`, `data[17]`, less the growth floor, `data[11]`; [memmgr Memory
Pool](../../services/memmgr/docs/memory-pool.md) § Commit), which a commitment of it does not pass,
and commits that much through the heap, halving an attempt memmgr refuses, until fewer than 16 pages
are left or the block list is full; it takes the rest a page at a time by `REQUEST_MEMORY_CAPS`
grants, whose caps stay in the process's `CSpace` until it dies. A grant is asked only while the
`CSpace` has more than 16 general slots free, which the `Fill`'s creation funds for 1024 grants
while memory is not yet scarce, since a `CSpace` cannot grow at the growth floor: a grant's cap
never lands in the IPC receive reserve, whose loss would fail the process's receives
([docs/ipc-design.md](../../docs/ipc-design.md) § Receive-Failure Policy). `to_critical` tops up
every `TICK_MS` (10 ms) until nothing is left and the pressure level has read `CRITICAL` for
`SETTLE_MS` (500 ms), which lets a file system give back its cache and the fill take that too, and
fails when memmgr does not answer or the level does not settle within `TIMEOUT_MS` (30 s). A caller
holding memory critical calls `top_up` every `TICK_MS` after, taking back what other processes free.
The process's death gives everything back.

The crate calls memmgr through the runtime (`std::os::seraph`), so it builds only for Seraph and
has no host tests; the svctest `oom_policy` phase and the crashme tester exercise it.

---

## Source Layout

```
mem-fill/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs             # Fill: the ballast, the top-up, the fill to CRITICAL
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/memmgr/docs/memory-pool.md](../../services/memmgr/docs/memory-pool.md) | § Commit, § Memory pressure |
| [docs/testing.md](../../docs/testing.md) | How fixtures are staged |

---

## Summarized By

None
