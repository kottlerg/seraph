# demandpaged

Test fixture for the demand-paging pager surface. The `services/svctest` pager phases spawn it
as `/programs/demandpaged`, one of the harness fixtures installed under `/programs/` (see
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout)). It prints no marker
lines and reports only through its exit status, which the spawning phase checks.

---

## Source Layout

```
programs/demandpaged/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Mode selection, in-region round-trip, out-of-region touch
```

---

## Modes

Demand paging is the system-wide default: procmgr binds memmgr as the pager of each process it
creates unless the creator opts out with `CREATE_PINNED`
([docs/fault-handling.md](../../docs/fault-handling.md#demand-paging-and-the-default-system-pager)).
memmgr backs faults inside a region the process registered and kills the thread on any other
fault ([memmgr IPC Interface](../../services/memmgr/docs/ipc-interface.md)). The mode is
selected by argv: any argument equal to `oor` selects the out-of-region mode.

| Mode | Behaviour | Exit status |
|---|---|---|
| default | `register_demand_paged(4)` reserves four pages and registers them read-write with the pager; the program writes a per-(page, byte) pattern across all four, then reads it back | `0` on a full match; `2` if registration fails; `3` on a mismatch |
| `oor` | `reserve_pages(1)` reserves one page ([page reservations](../../docs/userspace-memory-model.md#page-reservations)) that is never registered; the program writes to it | Expected to be killed; `0` if the write survives, so the harness's must-be-killed assertion fails; `2` if the reservation fails |

---

## Harness Phases

| Phase | Spawn | Expected outcome |
|---|---|---|
| `demand_paging` | Default mode | Clean exit; memmgr's all-RAM-accounted identity still holds |
| `demand_paging_segfault` | `oor` argument | Killed with an exit reason at or above `EXIT_FAULT_BASE` |
| `demand_paging_pinned` | Default mode, `pinned(true)` | Killed with an exit reason at or above `EXIT_FAULT_BASE`, since no pager is bound; the RAM identity still holds |

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

None
