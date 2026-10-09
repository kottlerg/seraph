# threadchurn

Thread-churn reclaim fixture for the CSpace-slot leak regression (#240) and the memmgr-pool
footprint regression (#274). It spawns and joins, then spawns and detaches, batches of `std`
threads, and asserts that neither its populated CSpace-slot count nor memmgr's free pool drifts
across the churn. Its tester, `threadchurn-tester`, is a per-program tester that `usertest`
discovers at `/tests/programs/threadchurn` and runs, per the
[per-program tester protocol](../../docs/testing.md#per-program-tester-protocol). The fixture
itself installs at `/programs/threadchurn`; the threading is plain `std`, and only the sampling
reaches Seraph surfaces.

---

## Source Layout

```
threadchurn/
├── Cargo.toml             # threadchurn; depends on syscall and syscall-abi
├── README.md
├── src/
│   └── main.rs            # Warm-up, join churn, detach churn, slot and pool bounds
└── tester/
    ├── Cargo.toml         # threadchurn-tester
    └── src/
        └── main.rs        # Runs the fixture, checks its marker and exit status
```

---

## Fixture Run

The fixture samples two quantities: its populated slot count, read with
`cap_info(self_cspace, CAP_INFO_CSPACE_USED)`, and memmgr's free-pool size, read with
`std::os::seraph::memmgr_pool_free_bytes()`, which wraps memmgr's
[`QUERY_POOL_STATUS`](../../services/memmgr/docs/ipc-interface.md#label-6-query_pool_status)
free-bytes word and returns `None` when memmgr is unreachable. It runs in three phases:

1. **Warm-up.** Eight spawn-and-join iterations bring the reaper's death `EventQueue`, the
   pooled object slabs, and the page-table budget to steady state, then the baseline slot
   count and free pool are sampled.
2. **Join churn.** `JOIN_CHURN` (600) spawn-and-join iterations, logging a progress line every
   25, then a slot sample.
3. **Detach churn.** `DETACH_BATCH` (48) threads are spawned and their handles dropped at once,
   a 100 ms sleep lets them die, and `REAP_CHURN` (50) spawn-and-join iterations drive the
   reaper sweeps that reclaim them. A 50 ms sleep and 16 more iterations drain stragglers, then
   the slot count and free pool are sampled again.

Flat results depend on ruststd returning each reclaimed thread's slab to memmgr mid-life and
recycling pooled object-slab bytes in place, per the
[memory allocation contract](../../docs/userspace-memory-model.md#memory-allocation-contract).

The fixture then checks two bounds:

| Bound | Constant | Fails when |
|---|---|---|
| Slot growth | `SLACK` (4) | The larger of the two post-churn slot samples exceeds the baseline by more than 4 |
| Pool drop | `POOL_SLACK_BYTES` (1 MiB) | The final free pool is more than 1 MiB below the baseline; skipped when either sample is `None` |

A per-spawn slot leak grows the slot count by a few slots per spawn, and a per-spawn slab leak
drops the free pool by several pages per spawn, so either trips its bound. `JOIN_CHURN` also
runs past the roughly 250 spawns at which an unbounded memmgr tracking-anchor footprint
live-locks memmgr (#274), so that regression shows as a hang; the progress lines keep a hang
distinguishable from slow progress.

---

## Fixture Output

The fixture prints exactly one stdout line on a completed run and exits `0` on pass, `1` on a
failed bound:

| Line | When |
|---|---|
| `threadchurn: PASS slot growth <g> within slack 4` | Both bounds held |
| `threadchurn: FAIL slot growth <g> exceeds slack 4` | The slot bound failed; the pool bound is not checked |
| `threadchurn: FAIL pool free dropped <d> exceeds slack 1048576` | The slot bound held and the pool bound failed |

It also logs through `log!` under the `[threadchurn]` name: the baseline, a
`join-churn progress <n>/600` line every 25 iterations, the post-churn samples, the measured
pool drop when the pool bound is checked, and a `PASS` or `FAIL` line. A failed `cap_info`
call or a panicked worker panics the fixture, so it exits non-zero with no stdout marker.

---

## Tester

The tester spawns `/programs/threadchurn` with a piped stdout, reads stdout to EOF, and waits
for the child. It fails when any line contains `threadchurn: FAIL`, when no line contains
`threadchurn: PASS`, or when the child exits non-zero, checked in that order. It prints
`[threadchurn-tester] PASS` or `[threadchurn-tester] FAIL <reason>` to stdout and exits `0` or
`1`; a failed spawn, read, or wait panics and also exits non-zero. The exit code is the verdict
and the `PASS`/`FAIL` line is advisory, per [docs/testing.md](../../docs/testing.md#contract).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Per-program tester protocol, sysroot layout, and harness gating |
| [docs/userspace-memory-model.md](../../docs/userspace-memory-model.md) | memmgr grants, mid-life release, and ruststd's pooled object-slab recycling |
| [memmgr IPC Interface](../../services/memmgr/docs/ipc-interface.md) | `QUERY_POOL_STATUS` and `RELEASE_MEMORY_CAPS` wire shapes |
| [Syscall Interface Specification](../../core/kernel/docs/syscalls.md) | `SYS_CAP_INFO` field reads |
| [services/usertest/README.md](../../services/usertest/README.md) | The orchestrator that runs the tester |

---

## Summarized By

None
