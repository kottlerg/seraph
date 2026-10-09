# svctest

Services-surface test harness. A std-built binary installed at `/tests/svctest` that exercises
the services tier (procmgr, memmgr, vfsd and fatfs, devmgr, pwrmgr, timed), the kernel objects
those services hand out, and the `ruststd` runtime layer end to end. `svcmgr` spawns it from the
`svctest.svc` recipe, which lives in `/config/svcmgr/tests/` and runs only when staged into
`/config/svcmgr/services/`, per [docs/testing.md § Gating](../../docs/testing.md#gating).

---

## Source Layout

```
services/svctest/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                # Child-mode check, bootstrap, phase run, pass marker, shutdown
    ├── bootstrap.rs           # Decodes the creator-endpoint bootstrap round into `Caps`
    ├── runner.rs              # `Phase` type and the per-phase log envelope
    ├── reentry.rs             # argv-role dispatch into each phase module's child mode
    ├── ipc_util/
    │   ├── mod.rs             # Raw-IPC helpers shared across phase modules
    │   ├── fs.rs              # `FS_*` wire transactions
    │   ├── ns.rs              # `NS_LOOKUP`, `NS_STAT`, `NS_READDIR`
    │   └── time.rs            # Wall-clock conversion helpers
    └── phases/
        ├── mod.rs             # Ordered phase registry; one module per surface under test
        ├── startup.rs         # argv, env, stack envelope, TLS at entry; unset cwd path
        ├── memmgr.rs          # Heap allocator over memmgr; all-RAM-accounted identity
        ├── threading.rs       # Threads, per-thread state, `thread_local!`, `Condvar`
        ├── procmgr.rs         # `std::process::Command` spawn, cwd, and error paths
        ├── process_faults.rs  # Stack-guard and RELRO-seal faults
        ├── exit_code.rs       # Child exit-code propagation to `ExitStatus`
        ├── random.rs          # `SYS_GETRANDOM`, hash seeding, ASLR layout divergence
        ├── recv_guard.rs      # Shared `RecvGuard` recv-loop failure policy
        ├── devmgr.rs          # Driver-spawn orphan teardown via `TEST_SPAWN_ORPHAN`
        ├── pager.rs           # Demand paging: backed, declined, and pinned faults
        ├── shmem.rs           # Kernel shared-memory objects
        ├── pipes.rs           # Kernel pipes: piped stdio, death-bridge EOF
        ├── namespace.rs       # vfsd namespace protocol, sandboxing, startup cwd
        ├── fs_ipc.rs          # Raw `FS_*` IPC against vfsd and fatfs
        ├── fs_std.rs          # `std::fs` over the FS IPC contract
        ├── pwrmgr.rs          # Shutdown cap-deny check and terminal shutdown
        └── timed.rs           # `SystemTime::now()` through svcmgr and timed
```

Each module under `phases/` covers one surface and exports its `Phase` entries;
`phases::all()` composes them in an order that encodes their dependencies (startup first, the
relative-open phase that installs a process-global cwd cap late, the all-RAM-accounted
identity last).

---

## Run Sequence

`main` registers the log name `svctest`, so every line carries the `[svctest]` prefix. It then
requests the bootstrap round, logs `starting`, and runs each registered phase in order inside
the envelope `phase=<name> starting` / `phase=<name> passed`. After the last phase it logs
`ALL TESTS PASSED`, the marker defined in
[docs/testing.md § Reporting marker](../../docs/testing.md#reporting-marker), and sends
`SHUTDOWN` on the authority-badged pwrmgr cap. On success the platform powers off; a reply,
or an IPC error, is logged and svctest exits, leaving the system idle.

A failing phase panics through the std panic handler; svctest then never logs
`ALL TESTS PASSED` and never requests shutdown. The `ns` phase (`caps[0]`), the pwrmgr
cap-deny phase (`caps[2]`), and the pwrmgr shutdown phase (`caps[1]`) log the skip and return
when their slot is zero; the devmgr orphan-teardown phase (`caps[3]`) instead fails its
assertion.

The startup phases assert the recipe's launch surface: argv is exactly `svctest run`, and env
carries `SERAPH_TEST=1` and `SERAPH_MODE=boot`.

---

## Capabilities

The bootstrap round from the creator endpoint delivers the recipe's seeds in this order;
[service-definitions.md § `seed`](../svcmgr/docs/service-definitions.md#seed) defines each
name's cap shape and the zero slot an unresolved name leaves. With no creator endpoint, every
slot stays zero.

| Slot      | Seed              | Use in svctest                         |
|-----------|-------------------|----------------------------------------|
| `caps[0]` | `rootfs.root`     | `ns` phase                             |
| `caps[1]` | `pwrmgr.shutdown` | Authority cap for the final `SHUTDOWN` |
| `caps[2]` | `pwrmgr.deny`     | Cap-deny phase                         |
| `caps[3]` | `devmgr.registry` | devmgr orphan-teardown phase           |

`caps[2]` drives the cap-deny phase, which requires an `UNAUTHORIZED` reply to `SHUTDOWN`.
`caps[3]` exists only for the devmgr orphan-teardown phase's `TEST_SPAWN_ORPHAN` shim
(TODO(#165): retire with that shim).

---

## Child Modes

Several phases respawn `/tests/svctest` with a role token as `argv[1]`. `main` hands the token
to `reentry::dispatch`, which tries each owning module's `reentry_main`; a matching role runs
its child body and exits, and an unmatched token falls through to the normal run.

| Role                        | Owning module  | Spawned by                                  |
|-----------------------------|----------------|---------------------------------------------|
| `sandbox-child`             | `namespace`    | `ns_sandbox` (namespace attenuation)        |
| `programs-child`            | `namespace`    | `ns_programs_subtree` (`/programs` subtree) |
| `cwd-child`                 | `procmgr`      | `command_cwd_inherit` (cwd-cap delivery)    |
| `exit-code-zero`            | `exit_code`    | `exit_code`                                 |
| `exit-code-nonzero`         | `exit_code`    | `exit_code`                                 |
| `random-diverge-child`      | `random`       | `random` (per-process hash seed)            |
| `aslr-layout-diverge-child` | `random`       | `aslr-layout` (per-process layout tuple)    |

---

## Fixtures

Phases spawn these programs from `/programs/`: `hello` (procmgr, pipes), `stdiotest` and
`pipefault` (pipes), `stackoverflow` and `relrofault` (process faults), `capexhaust`
(recv guard), `demandpaged` (pager), and `fsbench` (FS IPC). The devmgr phase has devmgr spawn
the [`test-orphan`](../drivers/test-orphan/README.md) driver. The FS, namespace, and procmgr
phases read `/data/test.txt`; the FS phases also read the build-synthesised
`/data/svctest/large.bin` and write their scratch files under `/data/svctest/`; and `fsbench`,
spawned by the `fs_crossover_bench` phase, reads the build-synthesised
`/data/svctest/bench.bin`. The sysroot placement of all of these is listed in
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Harness model, reporting marker, sysroot layout, gating, cross-harness conventions |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Process startup, `ProcessInfo` handover, process death |
| [Service Definitions](../svcmgr/docs/service-definitions.md) | `.svc` recipe keys, including `seed` resolution |
| [services/pwrmgr/README.md](../pwrmgr/README.md) | pwrmgr `SHUTDOWN` and its authority badge |
| [services/drivers/test-orphan/README.md](../drivers/test-orphan/README.md) | Fault-injection driver behind the orphan-teardown phase |

---

## Summarized By

[Testing](../../docs/testing.md),
[programs/capexhaust/README.md](../../programs/capexhaust/README.md),
[programs/demandpaged/README.md](../../programs/demandpaged/README.md),
[programs/fsbench/README.md](../../programs/fsbench/README.md),
[programs/hello/README.md](../../programs/hello/README.md),
[programs/pipefault/README.md](../../programs/pipefault/README.md),
[programs/relrofault/README.md](../../programs/relrofault/README.md),
[programs/stackoverflow/README.md](../../programs/stackoverflow/README.md),
[programs/stdiotest/README.md](../../programs/stdiotest/README.md),
[services/drivers/test-orphan/README.md](../drivers/test-orphan/README.md),
[services/pwrmgr/README.md](../pwrmgr/README.md),
[`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)
