# svctest

Services-surface test harness. A std-built binary installed at `/tests/svctest` that exercises
the services tier (procmgr, memmgr, vfsd and fatfs, devmgr and the authority gates of its serial,
input, and framebuffer drivers, svcmgr, pwrmgr, timed), the kernel objects those services hand
out, and the `ruststd` runtime layer end to end. `svcmgr` spawns it
from the `svctest.svc` recipe, which lives in `/config/svcmgr/tests/` and runs only when staged
into `/config/svcmgr/services/`, per [docs/testing.md § Gating](../../docs/testing.md#gating). Its
devmgr phases also need the test class files of `/config/devmgr/tests/` staged into
`/config/devmgr/classes/` and a boot with `cargo xtask run --test-devices`; a phase that finds the
devices missing fails, naming the flag.

---

## Source Layout

```
services/svctest/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs                # Child-mode check, no-debug, bootstrap, phases, markers, shutdown
    ├── bootstrap.rs           # Decodes the creator-endpoint bootstrap rounds into `Caps`
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
        ├── memmgr.rs          # Heap; donation; stray caps; retyped grant; CSpace funding;
        │                      # object-slab release; deferred reclaim; identity;
        │                      # physical base withheld; frames zeroed at hand-out
        ├── layout.rs          # Growth zones, one large alloc, reserve holes, wide TLS,
        │                      # spawned IPC buffers in the arena; stack note
        ├── log_client.rs      # Log-call bounds against a log receiver that never answers
        ├── threading.rs       # Threads, per-thread stdio/alloc, TLS, identity, sync primitives;
        │                      # spawn priority; heap lock under cross-class contention
        ├── procmgr.rs         # `Command` spawn, cwd, errors; refusals; DMA hold;
        │                      # death queues; logd death forward; init reap
        ├── process_faults.rs  # Stack-guard and RELRO-seal faults
        ├── crash.rs           # procmgr's crash endpoint: registration, handover, take-back
        ├── exit_code.rs       # Child exit-code propagation to `ExitStatus`
        ├── random.rs          # `SYS_GETRANDOM`, hash seeding, ASLR layout divergence
        ├── recv_guard.rs      # Shared `RecvGuard` recv-loop failure policy
        ├── recv_pool.rs       # Worker-pool receive helper under concurrent nested IPC;
        │                      #   concurrent logging through logd
        ├── devmgr.rs          # Block, shutdown, bind deny; input ordinal; on-demand
        │                      #   driver bind; DMA confinement; MSI delivery, forge,
        │                      #   churn, and release
        ├── drivers.rs         # Serial, input, and framebuffer verb-bit deny; serial and input
        │                      #   stray caps
        ├── pager.rs           # Demand paging: backed, declined, pinned; forged-badge bind;
        │                      #   refused access; page-table drain; teardown; fault cost;
        │                      #   faults on a fragmented pool; a sparse large region
        ├── shmem.rs           # Kernel shared-memory objects
        ├── pipes.rs           # Kernel pipes: piped stdio, death-bridge EOF
        ├── namespace.rs       # vfsd namespace protocol, sandboxing, startup cwd
        ├── fs_ipc.rs          # Raw `FS_*` IPC against vfsd and fatfs
        ├── fs_opens.rs        # Per-open fatfs state: dead-open reclaim, close, eviction routing
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
installs the failure hooks, declares itself undebuggable to procmgr (`DECLARE_NO_DEBUG`, as
a debug-authority holder; it asserts `SUCCESS`), requests the bootstrap rounds, hands the hooks
the authority-badged pwrmgr cap, logs `starting`, and runs each registered phase in order inside
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

Some failures still end the run idle. A panic or allocation failure during the declaration or
the bootstrap rounds (a refused `DECLARE_NO_DEBUG` among them) logs `SOME TESTS FAILED` but sends
no `SHUTDOWN`, because the hooks get the pwrmgr cap only
after the rounds return. A `SHUTDOWN` that pwrmgr answers, or whose call fails, is logged and
leaves the system idle, as on the pass path. A fault in svctest's own process (a stray access,
a stack overflow) kills it without running either hook, so it logs neither marker.

The `ns` phase (`caps[0]`) and the pwrmgr cap-deny phase (the queried `pwrmgr.deny` cap) log the
skip and return when their cap is zero; the devmgr class-deny phase (`caps[2]` and `caps[3]`), the
bind-deny phase (`caps[2]`), the input-ordinal phase (`caps[8]`), the on-demand-bind phase
(`caps[3]`, `caps[8]`, and `caps[10]`), the DMA confinement and MSI delivery, forge, churn, and
release phases (`caps[9]`), the
drivers stray-cap phases (`caps[7]` and `caps[8]`), the drivers deny phase (`caps[11]` to
`caps[13]`), the svcmgr seed-only phase (every seed-only seed, plus the public `svcmgr` and
`pwrmgr.deny` names it resolves), the svcmgr second-seed-round phase (`caps[4]` and `caps[5]`), the
vfsd phases (`caps[4]`, `caps[5]`), the `logd_death_forward` and `logd_concurrent` phases
(`caps[6]`), the vfsd swap-partition phase (`caps[14]`), and the `crash_endpoint` phase
(`caps[15]`) instead fail their assertions. The seed-only phase thus fails the run on a zero
`caps[1]` before the terminal pwrmgr shutdown phase, so that phase's own zero-cap skip is not
reached; the panic hook's `SHUTDOWN` is then skipped for the same zero cap, and the run ends idle.

The startup phases assert the recipe's launch surface: argv is exactly `svctest run`, walked from
the front, from the back, and from both ends at once, and env carries `SERAPH_TEST=1` and
`SERAPH_MODE=boot`.

---

## Capabilities

The bootstrap rounds from the creator endpoint deliver the recipe's seeds in this order, four slots
to a round (`caps[0]` to `caps[3]`, `caps[4]` to `caps[7]`, `caps[8]` to `caps[11]`, and
`caps[12]` to `caps[15]`), the last being the debug-authority cap the recipe's
`debug_authority = yes` grants; [service-definitions.md §
`seed`](../svcmgr/docs/service-definitions.md#seed) defines each name's cap shape and the zero slot
an unresolved name leaves. With no creator endpoint, every slot stays zero.

| Slot      | Seed              | Use in svctest                         |
|-----------|-------------------|----------------------------------------|
| `caps[0]` | `rootfs.root`     | `ns` phase                             |
| `caps[1]` | `pwrmgr.shutdown` | Authority cap for the final `SHUTDOWN` |
| `caps[2]` | `devmgr.registry` | devmgr class-deny and shutdown-deny phases |
| `caps[3]` | `devmgr.bind`     | devmgr class-deny, bind-deny, and on-demand-bind phases: the `SEND\|GRANT` registry cap `BIND_DRIVERS` needs |
| `caps[4]` | `vfsd.mount`      | vfsd `MOUNT` rejection phases          |
| `caps[5]` | `vfsd.deny`       | vfsd `MOUNT` deny phase                |
| `caps[6]` | `logd.query`      | `logd_death_forward`, `logd_concurrent` phases: read logd's slots and history |
| `caps[7]` | `devmgr.class.serial` | drivers stray-cap phase: the `serial` class SEND |
| `caps[8]` | `devmgr.class.input` | input-ordinal and drivers stray-cap phases: the `input` class SEND |
| `caps[9]` | `devmgr.class.test-dma` | DMA confinement and MSI delivery, forge, churn, and release phases: the `test-dma` class SEND |
| `caps[10]` | `devmgr.class.test-fault` | on-demand-bind phase: the `test-fault` class SEND |
| `caps[11]` | `devmgr.class.serial-deny` | drivers deny phase: a `serial` class SEND without the driver's verb bits |
| `caps[12]` | `devmgr.class.input-deny` | drivers deny phase: an `input` class SEND without the driver's verb bits |
| `caps[13]` | `devmgr.class.framebuffer-deny` | drivers deny phase: a `framebuffer` class SEND without the driver's verb bits |
| `caps[14]` | `vfsd.swap`      | vfsd `GET_SWAP_PARTITION` phase        |
| `caps[15]` | (`debug_authority`) | `crash_endpoint` phase; svctest declares itself undebuggable at startup |

The svcmgr seed-only phase also reads every seed-only slot and fails when any is zero, as evidence
that its name is published, the seven `devmgr.class.*` names among them. `caps[2]` carries
`REGISTRY_QUERY_AUTHORITY` alone, so it drives the devmgr deny phases, which require an
`UNAUTHORIZED` reply to `QUERY_DEVICE` and `MINT_CLASS_SEND` (on `caps[2]` and `caps[3]`, neither of
whose badges carries a class slot), `QUERY_SHUTDOWN_DEVICE`, and `BIND_DRIVERS`. `caps[3]` carries
`REGISTRY_QUERY_AUTHORITY | BIND_AUTHORITY` as a `SEND|GRANT`, since `BIND_DRIVERS` moves a cap to
devmgr; it is the one seed that arrives with GRANT, and the on-demand-bind phase sends
`BIND_DRIVERS` on it. `caps[7]` and `caps[8]` are the `serial` and `input` class SENDs. The
input-ordinal phase requires a cap from `QUERY_DEVICE`
on `caps[8]` at instance ordinal 0 (sent and absent) and `NO_DEVICE` past the one keyboard of every
boot's device set. The drivers stray-cap phase takes granted SENDs on the serial and input drivers'
endpoints through `caps[7]` and `caps[8]` (`QUERY_DEVICE`) and floods each driver with calls
carrying `MSG_CAP_SLOTS_MAX` caps: an unknown label, a zero-byte `SERIAL_WRITE_BYTES`,
`SERIAL_READ_BYTES`, a `SERIAL_REGISTER_RX_NOTIFY` whose stray notification `SYS_IRQ_REGISTER`
rejects, and one whose fresh notification each call rebinds the UART line to. It requires each
call's normal reply and each cap to leave svctest's `CSpace`. A driver that keeps a cap it should
delete exhausts its `CSpace` within one case and exits on its failing receive. For the input driver,
devmgr's withdrawal then fails the call in flight, and the phase fails. For the serial driver,
logd's writes stall on it, and the boot ends as a `HANG`. The read and accepted registration cases,
and the input case, log a skip when `terminal.svc` is staged, since they would take the terminal's
input. `caps[11]` to `caps[13]` are the `serial-deny`, `input-deny`, and `framebuffer-deny` class
SENDs, each published from a class file of `/config/devmgr/tests/` that names its class with
`class =` and carries `verbs = 58`, a verb mask none of the drivers checks; a `QUERY_DEVICE` on one
hands the drivers deny phase a SEND on the serial, input, or framebuffer driver's endpoint badged
with none of the driver's verb bits. That phase requires an `UNAUTHORIZED` reply to
`SERIAL_WRITE_BYTES`,
`SERIAL_READ_BYTES`, `SERIAL_REGISTER_RX_NOTIFY`, and `INPUT_READ_EVENTS` (at once, without blocking
for a key), and to `FB_WRITE_BYTES` and `FB_SET_ATTRS` when a framebuffer driver runs; on a headless
boot, CI's, devmgr runs none and the framebuffer case logs a skip, which the framebuffer device cell
([docs/testing.md](../../docs/testing.md#coverage-tiers) § Coverage tiers) fails on. The input case
also logs a skip when `terminal.svc` is staged: the input driver serves one request at a time and
the terminal keeps a blocking read pending, so the deny would wait behind it for a keypress.
`caps[4]` and `caps[5]` are SENDs on vfsd's service endpoint, badged `MOUNT_AUTHORITY` and the
no-authority `DENY_BADGE` (services/vfsd/docs/vfs-ipc-interface.md § Endpoint). The vfsd phases
require an `UNAUTHORIZED` reply to `MOUNT` on `caps[5]` with nothing mounted; a `TABLE_FULL` reply
on `caps[4]` to `MOUNT` of the root role at `/` and of the data role at `/esp`, both already
mounted, in each of six rounds (vfsd checks the mount point before it registers a partition or
spawns a driver, so a rejection that started a spawn first would change a later reply); a
`NOT_FOUND` reply to a `MOUNT` whose path length exceeds the path bytes it carries; and that the
mounted filesystems still answer afterwards. `caps[14]` is a SEND on the same endpoint badged
`SWAP_AUTHORITY`; the `vfsd_swap_partition` phase, which runs after the short-path phase, requires
`UNAUTHORIZED` to `GET_SWAP_PARTITION` on `caps[4]` and `caps[5]`, and on `caps[14]` a hand-out of
a cap that addresses exactly the swap partition, a second hand-out revoking the first. The
`vfsd.mount` and `vfsd.deny` seeds ride in a second bootstrap round, so every svctest boot
receives a seed list longer than one round, and the svcmgr second-seed-round phase fails the run
when either arrives empty.
`caps[6]` is a SEND on the master log endpoint badged `LOG_QUERY_AUTHORITY` ([logd IPC
interface](../logd/docs/ipc-interface.md) § Queries); the `logd_death_forward` phase reads its dead
child's retired slot and history through it, and requires `QUERY_DENIED` for a query on svctest's
own log cap. Every seed is seed-only in svcmgr's registry. The no-authority `pwrmgr.deny` cap is
public, so svctest resolves it through `QUERY_ENDPOINT` on its per-process `service_registry_cap`
and spends no seed slot on it; it drives the pwrmgr cap-deny phase, which requires an `UNAUTHORIZED`
reply to `SHUTDOWN`.

---

## Child Modes

Several phases respawn `/tests/svctest` with a role token as `argv[1]`. `main` hands the token
to `reentry::dispatch`, which tries each owning module's `reentry_main`; a matching role runs
its child body and exits (`park-child`, `reclaim-child`, and `open-reclaim-child` park until their
spawner tears them down), and an unmatched token falls through to the normal run.

| Role                        | Owning module  | Spawned by                                  |
|-----------------------------|----------------|---------------------------------------------|
| `sandbox-child`             | `namespace`    | `ns_sandbox` (namespace attenuation)        |
| `programs-child`            | `namespace`    | `ns_programs_subtree` (`/programs` subtree) |
| `cwd-child`                 | `procmgr`      | `command_cwd_inherit` (cwd-cap delivery)    |
| `blobs-large-child`         | `procmgr`      | `command_blobs_large` (multi-page argv/env) |
| `park-child`                | `procmgr`      | `command_from_spawned_thread` (kill, drop)  |
| `undeliverable-reply-child` | `procmgr`      | `procmgr_refusals` (failed create reply)    |
| `logd-reclaim-child`        | `procmgr`      | `logd_death_forward` (named logd slot)      |
| `release-child`             | `fs_std`       | `std_release_matched_by_open` (fake fs)     |
| `open-reclaim-child`        | `fs_opens`     | `fs_reclaims_dead_opens` (killed client)    |
| `open-undeliverable-child`  | `fs_opens`     | `fs_reclaims_dead_opens` (failed reply)     |
| `reclaim-child`             | `memmgr`       | `frame_reclaim_live_object` (held endpoint) |
| `scrub-child`               | `memmgr`       | `memmgr_frame_scrub` (frames of a death)    |
| `exit-code-zero`            | `exit_code`    | `exit_code`                                 |
| `exit-code-nonzero`         | `exit_code`    | `exit_code`                                 |
| `random-diverge-child`      | `random`       | `random` (per-process hash seed)            |
| `aslr-layout-diverge-child` | `random`       | `aslr-layout` (per-process layout tuple)    |

---

## Fixtures

Phases spawn these programs from `/programs/`: `hello` (procmgr, pipes), `stdiotest` (pipes,
procmgr), `pipefault` (pipes), `stackoverflow` and `relrofault` (process faults), `capexhaust` (recv
guard), `demandpaged` (pager), `fsbench` (FS IPC), and `crashme` (crash endpoint: svctest, its
recipe granting `debug_authority`, registers as the crash service and takes a `crashme` child's
forwarded page fault, and the faults of two `registry-*` children, whose attach lists their live
registered threads and none that exited or was joined, and whose spawned thread's crash badge names
it; on the first of those it acts as a debugger, finding the child with `LIST_PROCESSES` and having
procmgr restore a registered thread it rebound, by `DETACH_PROCESS` and then by an attach's watch
thread exiting; acts as the debugger of a `debugger-tag` child, whose thread registering with a
gone debugger's binding is bound back to the crash endpoint and whose declaration, with svctest
attached and watched, unbinds svctest's bindings and leaves no watch to bind it back; has procmgr
unbind a debugger's binding from a thread of its own whose registration it refuses, svctest having
declared itself undebuggable; then gives the endpoint back and sees a second child declined by
procmgr). The
devmgr on-demand-bind phase sends `BIND_DRIVERS` on `caps[3]` over `/tests/drivers/`, which no
drivers-directory pass at boot reads, so devmgr binds the
[`test-fault`](../drivers/test-fault/README.md) driver to the QEMU `pci-testdev` functions that
`--test-devices` attaches, one instance each. The
phase asks `caps[10]` for the fixtures: the two serving instances hold instance ordinals 0 and 1,
and ordinal 2 answers `NO_DEVICE`; `FAULT_EXIT` on ordinal 0 makes the next query on it answer
`WITHDRAWN`; the free pool then returns to its size before the bind, so the instance that never
reports ready and the instance that fails its bootstrap's terminal round were destroyed; and a
second `BIND_DRIVERS` over the directory binds nothing. The DMA confinement phase polls
`QUERY_DEVICE` on `caps[9]` (10 ms apart, `INPUT_ATTEMPTS` times) until devmgr serves the
[`test-dma`](../drivers/test-dma/README.md) fixture, which devmgr binds to QEMU's `edu` device
(attached by `--test-devices` on both architectures) by its declaration at `SET_DRIVERS_DIR`,
and asserts it is served; it then asks the driver to probe: a copy through a mapped
page must arrive, and where an IOMMU confines the device a copy to the page's device address after
its unmap must not reach the page, and devmgr must have taken an IOMMU fault for the device at that
address. The probe's reply carries, from devmgr's `DMA_FAULTS`, the confinement flag, the count of
faults devmgr took for the device, and the latest faulting address, which must be the page of the
unmapped address. Without an IOMMU it checks the mapped copies only and requires no fault.
The MSI delivery phase queries the same fixture the same way and asks it to have the `edu` device
raise its interrupt (`INTERRUPT_PROBE`): the fixture must hold the device's MSI vector, which devmgr
gives a declaration that asks for MSI and DMA, not its wired line, and the message must reach the
fixture's notification within `INTERRUPT_WAIT_MS`, with or without an IOMMU. The MSI forge phase
(`devmgr_msi_forge`) asks the fixture for `MSI_FORGE`: where an IOMMU confines the device and the
fixture holds an MSI vector, the device's DMA engine writes the fixture's own message (read with
`SYS_CAP_INFO`) to its own address, which must reach the fixture's notification, then to a forged
address, which must not. On riscv64 the forged address is the interrupt file page beside the
target's, which the device's domain does not map, and devmgr must count an IOMMU fault for the
device at that page. On x86_64 the own message is remappable and the forged address is a remappable
message naming handle `0xFFFF`, which no remapping table entry holds; QEMU records no requester id
for a fault the DMA engine's write raises, so devmgr cannot attribute it and the check is
non-delivery, not an attributed fault. An unconfined device makes no forged write. The MSI churn
phase asks the fixture for `INTERRUPT_CHURN`: while a thread of the fixture has the device raise its
MSI in a loop, the fixture deletes the `Interrupt` cap bound to it, and then the bound
notification's last cap and the binding's cap; after each case a spare copy it binds to a new
notification must receive the device's interrupt, the fixture must hold MSI, and the loop must have
raised. The MSI release phase sends `FIXTURE_EXIT`, after which the fixture leaves its interrupt
raised and exits; the phase polls `caps[9]` until devmgr answers `WITHDRAWN` and asserts
`system_ram == kernel_reserved + pool_total`. devmgr releases the device, which frees the
message-signaled target it minted for it, on its control thread right after the class answers
`WITHDRAWN`, and no request svctest makes observes the release end, so the `ram_accounted_identity`
phase that ends the run asserts the identity again after it. The release phase runs last of the
phases that use the fixture, since no fixture serves the class again in that boot.
The `fs_block_faults` phase spawns a fatfs of its own from `/services/fs/fatfs` through procmgr,
delivers it a block endpoint a thread of its own serves from a RAM FAT16 volume, and tears it down
with `DESTROY_PROCESS`. The FS, namespace, and procmgr phases read `/data/test.txt`; the FS phases
also read the build-synthesised `/data/svctest/large.bin` and write their scratch files under
`/data/svctest/`; `fsbench`, spawned by the `fs_crossover_bench` phase, reads the build-synthesised
`/data/svctest/bench.bin`, which the `fs_eviction_routes_release_to_its_open` phase also holds open.
The sysroot placement of all of these is listed in [docs/testing.md § Sysroot
layout](../../docs/testing.md#sysroot-layout).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Harness model, reporting marker, sysroot layout, gating, cross-harness conventions |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Process startup, `ProcessInfo` handover, process death |
| [Service Definitions](../svcmgr/docs/service-definitions.md) | `.svc` recipe keys, including `seed` resolution |
| [svcmgr IPC Interface](../svcmgr/docs/ipc-interface.md) | `HANDOVER_COMPLETE` and `PUBLISH_ENDPOINT` and their authority badges; `QUERY_ENDPOINT` and its seed-only refusal |
| [services/pwrmgr/README.md](../pwrmgr/README.md) | pwrmgr `SHUTDOWN` and its authority badge |
| [services/drivers/test-dma/README.md](../drivers/test-dma/README.md) | `edu` DMA and MSI test driver behind the DMA confinement and MSI delivery, forge, churn, and release phases |
| [services/drivers/test-fault/README.md](../drivers/test-fault/README.md) | Fault-injection driver behind the on-demand-bind phase |

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
[services/drivers/test-dma/README.md](../drivers/test-dma/README.md),
[services/drivers/test-fault/README.md](../drivers/test-fault/README.md),
[services/pwrmgr/README.md](../pwrmgr/README.md),
[`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)
