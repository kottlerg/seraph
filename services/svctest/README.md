# svctest

Services-surface test harness. A std-built binary installed at `/tests/svctest` that exercises
the services tier (procmgr, memmgr, vfsd and fatfs, devmgr and the authority gates of its serial,
input, and framebuffer drivers, svcmgr, pwrmgr, timed), the kernel objects those services hand
out, and the `ruststd` runtime layer end to end. `svcmgr` spawns it
from the `svctest.svc` recipe, which lives in `/config/svcmgr/tests/` and runs only when staged
into `/config/svcmgr/services/`, per [docs/testing.md § Gating](../../docs/testing.md#gating).

---

## Source Layout

```
services/svctest/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                # Child-mode check, bootstrap, phase run, pass marker, shutdown
    ├── bootstrap.rs           # Decodes the creator-endpoint bootstrap round into `Caps`
    ├── runner.rs              # `Phase` type, per-phase log envelope, failure hooks, markers
    ├── reentry.rs             # argv-role dispatch into each phase module's child mode
    ├── ipc_util/
    │   ├── mod.rs             # Raw-IPC helpers shared across phase modules
    │   ├── fs.rs              # `FS_*` wire transactions
    │   ├── ns.rs              # `NS_LOOKUP`, `NS_STAT`, `NS_READDIR`
    │   └── time.rs            # Wall-clock conversion helpers
    └── phases/
        ├── mod.rs             # Ordered phase registry; one module per surface under test
        ├── startup.rs         # argv, env, stack envelope, TLS at entry; unset cwd path
        ├── memmgr.rs          # Heap; donation gate; stray caps; retyped-grant map; RAM identity
        ├── threading.rs       # Threads, per-thread stdio/alloc, TLS, identity, sync primitives
        ├── procmgr.rs         # `std::process::Command` spawn, cwd, error paths; refused requests
        ├── process_faults.rs  # Stack-guard and RELRO-seal faults
        ├── exit_code.rs       # Child exit-code propagation to `ExitStatus`
        ├── random.rs          # `SYS_GETRANDOM`, hash seeding, ASLR layout divergence
        ├── recv_guard.rs      # Shared `RecvGuard` recv-loop failure policy
        ├── devmgr.rs          # Block, shutdown, test-label deny; `TEST_SPAWN_ORPHAN` teardown
        ├── drivers.rs         # Serial, input, and framebuffer verb-bit deny
        ├── pager.rs           # Demand paging: backed, declined, pinned; forged-badge bind
        ├── shmem.rs           # Kernel shared-memory objects
        ├── pipes.rs           # Kernel pipes: piped stdio, death-bridge EOF
        ├── namespace.rs       # vfsd namespace protocol, sandboxing, startup cwd
        ├── fs_ipc.rs          # Raw `FS_*` IPC against vfsd and fatfs
        ├── fs_std.rs          # `std::fs` over the FS IPC contract
        ├── fs_faults/
        │   ├── mod.rs         # Own fatfs under block faults: failed writes, removes, renames
        │   └── ramdisk.rs     # RAM FAT16 volume and block server with armed faults
        ├── pwrmgr.rs          # Shutdown cap-deny check and terminal shutdown
        ├── svcmgr.rs          # Handover refused; publish gate; badged SEND; seed-only; round 2
        ├── timed.rs           # `SystemTime::now()` through svcmgr and timed
        └── vfsd.rs            # `MOUNT` gate: deny, mounted-path and short-path rejections
```

Each module under `phases/` covers one surface and exports its `Phase` entries;
`phases::all()` composes them in an order that encodes their dependencies (startup first, the
relative-open phase that installs a process-global cwd cap late, the all-RAM-accounted
identity last).

---

## Run Sequence

`main` registers the log name `svctest`, so every line carries the `[svctest]` prefix. It then
installs the failure hooks, requests the bootstrap rounds, hands the hooks the
authority-badged pwrmgr cap, logs `starting`, and runs each registered phase in order inside
the envelope `phase=<name> starting` / `phase=<name> passed`. After the last phase it logs
`ALL TESTS PASSED`, the marker defined in
[docs/testing.md § Reporting marker](../../docs/testing.md#reporting-marker), and sends
`SHUTDOWN` on the authority-badged pwrmgr cap. On success the platform powers off; a reply,
or an IPC error, is logged and svctest exits, leaving the system idle.

A failing phase panics. svctest's targets abort on panic, so nothing unwinds to the runner.
Instead, `runner::install_failure_hooks` installs two hooks. The panic hook runs after std's
default hook prints the panic. The allocation-error hook runs when a heap request fails, which
aborts without a panic; it logs the failed size. Each then logs `SOME TESTS FAILED`, the
failure marker of [docs/testing.md § Reporting marker](../../docs/testing.md#reporting-marker),
and sends the same `SHUTDOWN`, so a failed run also ends in a power-off. The hooks cover any
thread of the parent run; child modes keep std's default hooks. Whichever path claims the
marker first logs it, so a run logs exactly one. A failing thread that finds the marker already
claimed yields until the run ends instead of aborting, so its abort cannot cut off the
claimant's marker or `SHUTDOWN`.

Some failures still end the run idle. A panic or allocation failure during the bootstrap rounds
logs `SOME TESTS FAILED` but sends no `SHUTDOWN`, because the hooks get the pwrmgr cap only
after the rounds return. A `SHUTDOWN` that pwrmgr answers, or whose call fails, is logged and
leaves the system idle, as on the pass path. A fault in svctest's own process (a stray access,
a stack overflow) kills it without running either hook, so it logs neither marker.

The `ns` phase (`caps[0]`) and the pwrmgr cap-deny phase (the queried `pwrmgr.deny` cap) log the
skip and return when their cap is zero; the devmgr deny phases (`caps[2]`), the orphan-teardown and
drivers deny phases (`caps[3]`), the svcmgr seed-only phase (every seed-only seed, plus the
public `svcmgr` and `pwrmgr.deny` names it resolves), the svcmgr second-seed-round phase
(`caps[4]` and `caps[5]`), and the vfsd phases (`caps[4]`, `caps[5]`) instead fail their
assertions. The seed-only phase
thus fails the run on a zero `caps[1]` before the terminal pwrmgr shutdown phase, so that phase's
own zero-cap skip is not reached; the panic hook's `SHUTDOWN` is then skipped for the same zero cap,
and the run ends idle.

The startup phases assert the recipe's launch surface: argv is exactly `svctest run`, walked from
the front, from the back, and from both ends at once, and env carries `SERAPH_TEST=1` and
`SERAPH_MODE=boot`.

---

## Capabilities

The bootstrap rounds from the creator endpoint deliver the recipe's seeds in this order, the
fifth in a second round;
[service-definitions.md § `seed`](../svcmgr/docs/service-definitions.md#seed) defines each
name's cap shape and the zero slot an unresolved name leaves. With no creator endpoint, every
slot stays zero.

| Slot      | Seed              | Use in svctest                         |
|-----------|-------------------|----------------------------------------|
| `caps[0]` | `rootfs.root`     | `ns` phase                             |
| `caps[1]` | `pwrmgr.shutdown` | Authority cap for the final `SHUTDOWN` |
| `caps[2]` | `devmgr.registry` | devmgr deny phases                     |
| `caps[3]` | `devmgr.test`     | devmgr orphan-teardown, drivers deny   |
| `caps[4]` | `vfsd.mount`      | vfsd `MOUNT` rejection phases          |
| `caps[5]` | `vfsd.deny`       | vfsd `MOUNT` deny phase                |

The svcmgr seed-only phase also reads every seed-only slot and fails when any is zero, as evidence
that its name is published. `caps[2]` carries `REGISTRY_QUERY_AUTHORITY` alone, so it drives the
devmgr deny phases, which require an `UNAUTHORIZED` reply to `QUERY_BLOCK_DEVICE`,
`QUERY_SHUTDOWN_DEVICE`, `TEST_SPAWN_ORPHAN`, `TEST_ORPHAN_RESULT`, and `TEST_QUERY_DENY_DEVICE`.
`caps[3]` exists for devmgr's test labels (TODO(#165): retire with them): the orphan-teardown
phase's `TEST_SPAWN_ORPHAN` shim, and `TEST_QUERY_DENY_DEVICE`, which hands the drivers deny phase a
SEND on the serial, input, or framebuffer driver's endpoint badged with none of the driver's verb
bits. That phase requires an `UNAUTHORIZED` reply to `SERIAL_WRITE_BYTES`, `SERIAL_READ_BYTES`,
`SERIAL_REGISTER_RX_NOTIFY`, and `INPUT_READ_EVENTS` (at once, without blocking for a key), and to
`FB_WRITE_BYTES` and `FB_SET_ATTRS` when a framebuffer driver runs; on a headless boot, CI's, devmgr
runs none and the framebuffer case logs a skip. The input case also logs a skip when `terminal.svc`
is staged: the input driver serves one request at a time and the terminal keeps a blocking read
pending, so the deny would wait behind it for a keypress. `caps[4]` and `caps[5]` are SENDs on
vfsd's service endpoint, badged `MOUNT_AUTHORITY` and the no-authority `DENY_BADGE`
(services/vfsd/docs/vfs-ipc-interface.md § Endpoint). The vfsd phases require an `UNAUTHORIZED`
reply to `MOUNT` on `caps[5]` with nothing mounted; a `TABLE_FULL` reply on `caps[4]` to `MOUNT` of
the root role at `/` and of the data role at `/esp`, both already mounted, in each of six rounds
(more than vfsd's four per-mount bootstrap slots, so a rejection that spawned a driver or held a
slot would change a later reply); a `NOT_FOUND` reply to a `MOUNT` whose path length exceeds the
path bytes it carries; and that the mounted filesystems still answer afterwards. The two vfsd
seeds ride in a second bootstrap round, so every svctest boot receives a seed list longer than one
round, and the svcmgr second-seed-round phase fails the run when either arrives empty. Every seed
is seed-only in svcmgr's registry. The no-authority `pwrmgr.deny` cap is public, so svctest
resolves it through `QUERY_ENDPOINT` on its per-process `service_registry_cap` and spends no seed
slot on it; it drives the pwrmgr cap-deny phase, which requires an `UNAUTHORIZED` reply to
`SHUTDOWN`.

---

## Child Modes

Several phases respawn `/tests/svctest` with a role token as `argv[1]`. `main` hands the token
to `reentry::dispatch`, which tries each owning module's `reentry_main`; a matching role runs
its child body and exits (`park-child` parks until its spawner tears it down), and an unmatched
token falls through to the normal run.

| Role                        | Owning module  | Spawned by                                  |
|-----------------------------|----------------|---------------------------------------------|
| `sandbox-child`             | `namespace`    | `ns_sandbox` (namespace attenuation)        |
| `programs-child`            | `namespace`    | `ns_programs_subtree` (`/programs` subtree) |
| `cwd-child`                 | `procmgr`      | `command_cwd_inherit` (cwd-cap delivery)    |
| `blobs-fill-child`          | `procmgr`      | `command_blobs_fill_message` (full message) |
| `park-child`                | `procmgr`      | `command_from_spawned_thread` (kill, drop)  |
| `undeliverable-reply-child` | `procmgr`      | `procmgr_refusals` (failed create reply)    |
| `release-child`             | `fs_std`       | `std_release_matched_by_cookie` (fake fs)   |
| `exit-code-zero`            | `exit_code`    | `exit_code`                                 |
| `exit-code-nonzero`         | `exit_code`    | `exit_code`                                 |
| `random-diverge-child`      | `random`       | `random` (per-process hash seed)            |
| `aslr-layout-diverge-child` | `random`       | `aslr-layout` (per-process layout tuple)    |

---

## Fixtures

Phases spawn these programs from `/programs/`: `hello` (procmgr, pipes), `stdiotest` and
`pipefault` (pipes), `stackoverflow` and `relrofault` (process faults), `capexhaust`
(recv guard), `demandpaged` (pager), and `fsbench` (FS IPC). The devmgr orphan-teardown
phase has devmgr spawn the [`test-orphan`](../drivers/test-orphan/README.md) driver. The
`fs_block_faults` phase spawns a fatfs of its own from `/services/fs/fatfs` through procmgr,
delivers it a block endpoint a thread of its own serves from a RAM FAT16 volume, and tears it
down with `DESTROY_PROCESS`. The FS, namespace, and procmgr phases read `/data/test.txt`; the FS
phases also read the build-synthesised `/data/svctest/large.bin` and write their scratch files
under `/data/svctest/`; and `fsbench`, spawned by the `fs_crossover_bench` phase, reads the
build-synthesised `/data/svctest/bench.bin`. The sysroot placement of all of these is listed in
[docs/testing.md § Sysroot layout](../../docs/testing.md#sysroot-layout).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Harness model, reporting marker, sysroot layout, gating, cross-harness conventions |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Process startup, `ProcessInfo` handover, process death |
| [Service Definitions](../svcmgr/docs/service-definitions.md) | `.svc` recipe keys, including `seed` resolution |
| [svcmgr IPC Interface](../svcmgr/docs/ipc-interface.md) | `HANDOVER_COMPLETE` and `PUBLISH_ENDPOINT` and their authority badges; `QUERY_ENDPOINT` and its seed-only refusal |
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
