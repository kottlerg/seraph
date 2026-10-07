# capexhaust

Test fixture that exhausts its own `CSpace` and then runs a guarded blocking receive loop. The
`recv_wedge` phase of `svctest` (`services/svctest/src/phases/recv_guard.rs`) spawns it from
`/programs/capexhaust`, waits for it to exit, and checks that it died with `EXIT_RECV_WEDGE`.
It is not a general-purpose program: it installs under `/programs/` with the other fixtures
the harnesses spawn, per [docs/testing.md](../../docs/testing.md#sysroot-layout).

---

## Source Layout

```
capexhaust/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # CSpace exhaustion, failed-grant rollback check, guarded recv loop
```

---

## Behavior

The fixture runs these steps in order:

1. **Endpoint.** It creates a private endpoint from its object slab. If that fails, it logs
   `cap_create_endpoint failed` and exits with code 1.
2. **Exhaustion.** It derives `RIGHTS_EP_SEND` caps from the endpoint until `cap_derive`
   fails. The fixture never augments its `CSpace`'s slot-page pool, so the loop ends at pool
   exhaustion with no free slot left (see
   [docs/capability-model.md](../../docs/capability-model.md#address-space-and-cspace-growth-budgets)).
3. **Failed-grant rollback.** It reads memmgr's pool `free_bytes` with `QUERY_POOL_STATUS`,
   sends eight one-page `REQUEST_MEMORY_CAPS` calls, and reads `free_bytes` again. The
   exhausted `CSpace` cannot take a cap-bearing reply, so any reply that arrives MUST carry
   the `IPC_REPLY_TRANSFER_FAILED` label (see
   [docs/ipc-design.md](../../docs/ipc-design.md#message-format)), and the two readings MUST
   match. `free_bytes` is system-wide, so another process that allocates or dies in the
   window (`crasher` shares the `svctest` boot, per
   [docs/testing.md](../../docs/testing.md#gating)) can move it. The fixture therefore
   retries the window up to `ROLLBACK_WINDOW_TRIES` (8) times and panics if no window
   matches. If a `QUERY_POOL_STATUS` call fails, it exits with code 1.
4. **Wedged receive.** It enters a blocking `ipc_recv` loop on the endpoint, routing every
   outcome through `ipc::recv_guard::RecvGuard` as services do. With no headroom for the
   kernel's `MSG_CAP_SLOTS_MAX` pre-allocate, every receive fails before blocking, so the
   guard escalates and the process exits with `EXIT_RECV_WEDGE`, per
   [docs/ipc-design.md](../../docs/ipc-design.md#receive-failure-policy).

---

## Log Lines

The fixture registers the log name `capexhaust` and logs these lines:

| Line | When |
|---|---|
| `cspace exhausted after <n> derives` | The derive loop has ended |
| `pool churned during rollback window (attempt <i>: <before> -> <after>); retrying` | The `free_bytes` readings of one window differ |
| `failed-grant rollback verified (free_bytes unchanged); entering recv loop` | A window's readings match |
| `ipc_recv failing (err=<e>); backing off` | `RecvGuard` reports the first failure of a streak |
| `ipc_recv wedged (err=<e>); exiting` | `RecvGuard` reports the fatal failure, before the exit |

The `ipc_recv failing` line also shows that logging still works from a fully exhausted
`CSpace`: log messages and their replies carry no caps.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Where test fixtures install and how `svctest` and `crasher` are staged |
| [docs/ipc-design.md](../../docs/ipc-design.md) | Reply-side transfer failure and the receive-failure policy (`RecvGuard`, `EXIT_RECV_WEDGE`) |
| [docs/capability-model.md](../../docs/capability-model.md) | `CSpace` slot-page pool and its exhaustion |
| [memmgr IPC Interface](../../services/memmgr/docs/ipc-interface.md) | `REQUEST_MEMORY_CAPS` and `QUERY_POOL_STATUS` |
| [shared/ipc/README.md](../../shared/ipc/README.md) | The `recv_guard` module the fixture uses |

---

## Summarized By

None
