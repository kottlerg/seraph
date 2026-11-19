# svctest

Services-surface test harness. A std-built binary installed at `/tests/svctest` that exercises
the services tier (procmgr, memmgr, vfsd and fatfs, devmgr and the authority gates of its serial,
input, framebuffer, and hwrng drivers, svcmgr, pwrmgr, timed, entropyd), the kernel objects those
services hand out, and the `ruststd` runtime layer end to end. `svcmgr` spawns it from the
`svctest.svc` recipe, which lives in `/config/svcmgr/tests/` and runs only when staged into
`/config/svcmgr/services/`, per [docs/testing.md § Gating](../../docs/testing.md#gating). Its devmgr
phases also need the test class files of `/config/devmgr/tests/` staged into
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
    ├── arch/
    │   ├── mod.rs             # Arch dispatch: the one file with `cfg(target_arch)`
    │   ├── x86_64/mod.rs      # Register-file size and instruction-pointer offset
    │   └── riscv64/mod.rs     # Register-file size and instruction-pointer offset
    ├── ipc_util/
    │   ├── mod.rs             # Raw-IPC helpers shared across phase modules
    │   ├── fs.rs              # `FS_*` wire transactions
    │   ├── ns.rs              # `NS_LOOKUP`, `NS_STAT`, `NS_READDIR`
    │   └── time.rs            # Wall-clock conversion helpers
    └── phases/
        ├── mod.rs             # Ordered phase registry; one module per surface under test
        ├── startup.rs         # argv, env, stack envelope, TLS at entry; unset cwd path
        ├── memmgr.rs          # Heap; donation; stray caps; retyped grant; CSpace funding;
        │                      # CSpace low-water hold; object-slab release; deferred
        │                      # reclaim; identity; physical base withheld; frames
        │                      # zeroed at hand-out
        ├── layout.rs          # Growth zones, one large alloc, reserve holes, wide TLS,
        │                      # spawned IPC buffers in the arena; stack note parse
        ├── log_client.rs      # Log-call bounds against a log receiver that never answers
        ├── logd_restart.rs    # logd killed through an attach and restarted: svcmgr's lines,
        │                      #   names restored by refusal, a death forward on the new instance;
        │                      #   and restarted while memory is critical (logd in the reserve)
        ├── logd_sinks.rs      # logd's sinks: serial and framebuffer drivers attachable; lines
        │                      #   answered with either stopped, and with the framebuffer killed
        │                      #   and restarted
        ├── threading.rs       # Threads, per-thread stdio/alloc, TLS, identity, sync primitives;
        │                      # spawn priority; heap lock under cross-class contention
        ├── procmgr.rs         # `Command` spawn, cwd, errors; refusals; DMA hold;
        │                      # large-module create; death queues; logd death
        │                      # forward; init reap
        ├── process_faults.rs  # Stack-guard and RELRO-seal faults
        ├── process_tree.rs    # procmgr's process tree: subtree destroy, re-parenting,
        │                      #   destroy after an end, containment, child list and
        │                      #   destroy, end post, end queue
        ├── crash.rs           # procmgr's crash endpoint: registration, handover, take-back
        ├── exit_code.rs       # Child exit-code propagation to `ExitStatus`
        ├── random.rs          # `SYS_GETRANDOM`, hash seeding, ASLR layout divergence
        ├── entropyd.rs        # entropyd's first contribution accepted by the kernel
        ├── recv_guard.rs      # Shared `RecvGuard` recv-loop failure policy
        ├── recv_pool.rs       # Worker-pool receive helper under concurrent nested IPC;
        │                      #   concurrent logging through logd
        ├── devmgr.rs          # Block, shutdown, bind deny; input ordinal; on-demand
        │                      #   driver bind; DMA confinement; MSI delivery, forge,
        │                      #   churn, and release
        ├── acpi.rs            # acpid's results read from devmgr (`acpi_host_bridges`); the
        │                      #   `ACPI_AUTHORITY` gate (`acpi_authority_deny`); the power
        │                      #   deny check (`acpid_power_deny`)
        ├── drivers.rs         # Serial, input, framebuffer, and hwrng verb-bit deny; serial,
        │                      #   input, and hwrng stray caps; hwrng read;
        │                      #   hwrng killed and restarted
        ├── pager.rs           # Demand paging: backed, declined, pinned; forged-badge bind;
        │                      #   refused access; page-table drain; teardown; fault cost;
        │                      #   faults on a fragmented pool; a sparse large region
        ├── budget.rs          # Create-time memory max: clamp, grants to it, LIMIT, decline 10,
        │                      #   pages back after the destroy; reserve and max refusals
        ├── node_handle.rs     # memmgr node handles: class refusals, sub-node clamp, a max set
        │                      #   while the child runs, LIMIT, limit event, lowering reclaims
        │                      #   nothing, released and dead handles refused; two children
        │                      #   charged to one sub-node share its budget
        ├── heap_commit.rs     # Committed heap growth: max refusal as an allocation error, a grant
        │                      #   past the promised bound, no fault declined, committed region
        │                      #   register, extend, shrink; all-RAM-accounted identity
        ├── discard.rs         # DISCARD_RANGE and SHRINK_REGION return frames; discarded pages
        │                      #   refault zero-filled and, committed, cannot be declined;
        │                      #   the std heap's discard and trim; all-RAM-accounted identity
        ├── swap.rs            # memmgr evicts a child's cold chunks into its store under a
        │                      #   held `LOW` level and restores them: debugger reads and
        │                      #   `MAKE_RESIDENT`; at `CRITICAL`, restores from the restore
        │                      #   headroom and by direct reclaim; a no-evict region, logd's
        │                      #   reserve stack; all-RAM-accounted identity
        ├── swap_client.rs     # memmgr's disk tier with svctest as the swap service over a
        │                      #   RAM slot store: register, take, done, stale restores, a
        │                      #   fault redirected and restored, a re-registration, a
        │                      #   tampered slot killing its faulting child;
        │                      #   all-RAM-accounted identity
        ├── shmem.rs           # Kernel shared-memory objects
        ├── pipes.rs           # Kernel pipes: piped stdio, death-bridge EOF
        ├── namespace.rs       # vfsd namespace protocol, sandboxing, startup cwd
        ├── fs_ipc.rs          # Raw `FS_*` IPC against vfsd and fatfs
        ├── fs_opens.rs        # Per-open fatfs state: dead-open reclaim, close, eviction routing
        ├── fs_std.rs          # `std::fs` over the FS IPC contract
        ├── fs_faults/
        │   ├── mod.rs         # Own fatfs under block faults: failed writes, removes, renames
        │   ├── pressure.rs    # Own fatfs gives idle cache pages back at memory pressure Low
        │   ├── ramdisk.rs     # RAM FAT16 volume and block server with armed faults, read log
        │   └── run_fill.rs    # Own fatfs fills sequential reads in runs; chain cursor retired
        ├── verified_read.rs   # procmgr's verified read of a data file: the body returned and
        │                      #   charged while held; another name, a flipped byte, no
        │                      #   signature, past the bound, and no length refused
        ├── pwrmgr.rs          # Shutdown cap-deny check, terminal shutdown, `reboot` role
        ├── svcmgr.rs          # Handover refused; publish gate; badged SEND; seed-only; round 2
        ├── sessiond.rs        # sessiond's operator interface: badge gates, interface registration
        │                      #   refusals, a session's shell, listed jobs, stopped whole
        ├── oom.rs             # Out-of-memory policy: memhog filled until oomd stops it, a
        │                      #   stop source's job stopped first, a held write resumed
        ├── timed.rs           # `SystemTime::now()` through svcmgr and timed
        ├── unmount.rs         # vfsd `UNMOUNT`: refusals, busy then forced, stale handles,
        │                      #   fall-through, remount, a mapped page across the unmount,
        │                      #   a killed fs driver
        └── vfsd.rs            # `MOUNT` gate: deny, mounted-path and short-path rejections
```

Each module under `phases/` covers one surface and exports its `Phase` entries;
`phases::all()` composes them in an order that encodes their dependencies (startup first, the
relative-open phase that installs a process-global cwd cap late, the unmount phases after every
phase that uses `/data` or the cwd, the all-RAM-accounted identity last).

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
release phases (`caps[9]`), the drivers stray-cap phases (`caps[7]`, `caps[8]`, and `caps[16]`), the
drivers hwrng read phase (`caps[16]`), the drivers hwrng restart phase (`caps[16]` and `caps[19]`),
the drivers deny phase (`caps[11]` to `caps[13]` and `caps[17]`), the `logd_sinks` phase's
framebuffer-killed and framebuffer-restarted cases (`caps[13]`), the svcmgr seed-only phase (every
seed-only seed, plus the public `svcmgr`, `pwrmgr.deny` and `acpid.deny` names it resolves), the
svcmgr second-seed-round phase (`caps[4]` and `caps[5]`), the vfsd and vfsd unmount phases
(`caps[4]`, `caps[5]`), the `logd_death_forward`, `logd_concurrent`, `logd_reserve`, `logd_restart`,
`logd_sinks`, and `entropyd_contribution` phases (`caps[6]`), the vfsd swap-partition phase
(`caps[14]`), the `memmgr_swap_client` phase (`caps[18]`), the `sessiond_operator` phase and the
`oom_policy` phase's session case (`caps[15]` and `caps[20]`), the `crash_endpoint`, `logd_reserve`,
`logd_restart`, `logd_sinks`, `memmgr_swap`, `memmgr_swap_client`, and `vfsd_driver_death` phases,
and the drivers hwrng restart phase (`caps[19]`), the `svcmgr_stop_service` phase (`caps[20]`, and
`caps[19]` with `stopsrc` staged), and the no-stop cases of the `oom_policy` and `logd_reserve`
phases (`caps[20]`), instead fail their assertions. The seed-only phase thus fails the run on a zero
`caps[1]` before the terminal pwrmgr shutdown phase, so that phase's own zero-cap skip is not
reached; the panic hook's `SHUTDOWN` is then skipped for the same zero cap, and the run ends idle.

The startup phases assert the recipe's launch surface: argv is exactly `svctest run`, walked from
the front, from the back, and from both ends at once, and env carries `SERAPH_TEST=1` and
`SERAPH_MODE=boot`.

---

## Capabilities

The bootstrap rounds from the creator endpoint deliver the recipe's seeds in this order, four slots
to a round (`caps[0]` to `caps[3]`, `caps[4]` to `caps[7]`, `caps[8]` to `caps[11]`,
`caps[12]` to `caps[15]`, `caps[16]` to `caps[19]`, and `caps[20]`), the last two being the
debug-authority cap the recipe's `debug_authority = yes` grants and the stop-authority cap its
`stop_authority = yes` grants; [service-definitions.md §
`seed`](../svcmgr/docs/service-definitions.md#seed) defines each name's cap shape and the zero slot
an unresolved name leaves. With no creator endpoint, every slot stays zero.

| Slot      | Seed              | Use in svctest                         |
|-----------|-------------------|----------------------------------------|
| `caps[0]` | `rootfs.root`     | `ns` phase                             |
| `caps[1]` | `pwrmgr.shutdown` | Authority cap for the final `SHUTDOWN` |
| `caps[2]` | `devmgr.registry` | devmgr class-deny and shutdown-deny phases |
| `caps[3]` | `devmgr.bind`     | devmgr class-deny, bind-deny, and on-demand-bind phases: the `SEND\|GRANT` registry cap `BIND_DRIVERS` needs |
| `caps[4]` | `vfsd.mount`      | vfsd `MOUNT` rejection phases; vfsd unmount phases: `UNMOUNT`, the remounts, and the fs-driver death phase's remount |
| `caps[5]` | `vfsd.deny`       | vfsd `MOUNT` deny phase; `UNMOUNT` deny case |
| `caps[6]` | `logd.query`      | `logd_death_forward`, `logd_concurrent`, `logd_reserve`, `logd_restart`, `logd_sinks`, `entropyd_contribution` phases: read logd's slots and history |
| `caps[7]` | `devmgr.class.serial` | drivers stray-cap phase: the `serial` class SEND |
| `caps[8]` | `devmgr.class.input` | input-ordinal and drivers stray-cap phases: the `input` class SEND |
| `caps[9]` | `devmgr.class.test-dma` | DMA confinement and MSI delivery, forge, churn, and release phases: the `test-dma` class SEND |
| `caps[10]` | `devmgr.class.test-fault` | on-demand-bind phase: the `test-fault` class SEND |
| `caps[11]` | `devmgr.class.serial-deny` | drivers deny phase: a `serial` class SEND without the driver's verb bits |
| `caps[12]` | `devmgr.class.input-deny` | drivers deny phase: an `input` class SEND without the driver's verb bits |
| `caps[13]` | `devmgr.class.framebuffer-deny` | drivers deny phase: a `framebuffer` class SEND without the driver's verb bits; `logd_sinks` phase: the class it waits on for the killed framebuffer driver's withdrawal and queries for the restarted instance at ordinal 1 |
| `caps[14]` | `vfsd.swap`      | vfsd `GET_SWAP_PARTITION` phase        |
| `caps[15]` | `sessiond.operator` (`SEND\|GRANT`) | `sessiond_operator` phase: `OPEN_SESSION`, `REGISTER_INTERFACE`; `oom_policy` phase: opens the operator session whose shell runs the large job |
| `caps[16]` | `devmgr.class.hwrng` | drivers hwrng read, hwrng restart, and stray-cap phases: the `hwrng` class SEND |
| `caps[17]` | `devmgr.class.hwrng-deny` | drivers deny phase: an `hwrng` class SEND without the driver's verb bits |
| `caps[18]` | `memmgr.swap` (`SEND\|GRANT`) | `memmgr_swap_client` phase: memmgr's swap labels, as the swap service over a RAM slot store |
| `caps[19]` | (`debug_authority`) | `crash_endpoint` phase; `logd_reserve` and `logd_restart` phases: find and attach to logd; `logd_sinks` phase: finds, attaches to, stops, and kills the sink drivers, and finds, attaches to, and stops the restarted framebuffer driver; drivers hwrng restart phase: kills the virtio-rng driver; `vfsd_driver_death` phase: finds and kills the `/data` fatfs driver, `RESTART_BURST` plus one times; `memmgr_swap` phase: finds the fixture child and attaches to it and to logd, reads their memory, and sends `MAKE_RESIDENT` for every process; `memmgr_swap_client` phase: the same for its fixture child, and every other process's ranges; `svcmgr_stop_service` phase: `LIST_PROCESSES` for `stopsrc`'s job; svctest declares itself undebuggable at startup |
| `caps[20]` | (`stop_authority`) | `svcmgr_stop_service` phase: svcmgr's `STOP_CANDIDATE`, `LIST_CANDIDATES` and `LIST_STOP_SOURCES`; `sessiond_operator` and `oom_policy` phases: `LIST_STOP_SOURCES` for sessiond's stop SEND; `oom_policy` and `logd_reserve` phases, no-stop case: `LIST_CANDIDATES` and `STOP_CANDIDATE` of memhog |

The svcmgr seed-only phase also reads every seed-only slot and fails when any is zero, as evidence
that its name is published, the nine `devmgr.class.*` names among them. `caps[2]` carries
`REGISTRY_QUERY_AUTHORITY` alone, so it drives the devmgr deny phases, which require an
`UNAUTHORIZED` reply to `QUERY_DEVICE`, `WATCH_CLASS`, and `MINT_CLASS_SEND` (on `caps[2]` and
`caps[3]`, neither of
whose badges carries a class slot), `QUERY_SHUTDOWN_DEVICE`, and `BIND_DRIVERS`. `caps[3]` carries
`REGISTRY_QUERY_AUTHORITY | BIND_AUTHORITY` as a `SEND|GRANT`, since `BIND_DRIVERS` moves a cap to
devmgr; it is the one devmgr seed that arrives with GRANT, and the on-demand-bind phase sends
`BIND_DRIVERS` on it. `caps[7]` and `caps[8]` are the `serial` and `input` class SENDs. The
input-ordinal phase waits on a `WATCH_CLASS` watch (bounded by `DEVICE_WAIT_MS`) until devmgr
serves an input driver, then requires a cap from `QUERY_DEVICE`
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
input. The same phase floods the virtio-rng driver, through a granted SEND from `caps[16]`, with
two cases: an unknown label (`UNKNOWN_OPCODE`) and `READ` with no data word (`SUCCESS`, zero
bytes); neither skips under a staged terminal. `caps[11]` to `caps[13]` are the `serial-deny`,
`input-deny`, and `framebuffer-deny` class SENDs, and `caps[17]` the `hwrng-deny` class SEND, each
published from a class file of `/config/devmgr/tests/` that names its class with `class =` and
carries `verbs = 58`, a verb mask none of the drivers checks; a `QUERY_DEVICE` on one hands the
drivers deny phase a SEND on the serial, input, framebuffer, or hwrng driver's endpoint badged
with none of the driver's verb bits. That phase requires an `UNAUTHORIZED` reply to
`SERIAL_WRITE_BYTES`, `SERIAL_READ_BYTES`, `SERIAL_REGISTER_RX_NOTIFY`, and `INPUT_READ_EVENTS` (at
once, without blocking for a key), and `READ` on the `hwrng-deny` SEND, and to `FB_WRITE_BYTES` and
`FB_SET_ATTRS` when a framebuffer driver runs; on a headless boot, CI's, devmgr runs none and the
framebuffer case logs a skip, which the framebuffer device cell
([docs/testing.md](../../docs/testing.md#coverage-tiers) § Coverage tiers) fails on. The
`logd_sinks` phase's framebuffer cases log the same skip on such a boot
([`logd_sinks.rs`](src/phases/logd_sinks.rs) states its cases). The input case
also logs a skip when `terminal.svc` is staged: the input driver serves one request at a time and
the terminal keeps a blocking read pending, so the deny would wait behind it for a keypress.
The drivers hwrng read phase waits (bounded by `DEVICE_WAIT_MS`) for a granted SEND from
`caps[16]`, then requires two `READ` calls of `MAX_READ_BYTES` (504) each to answer `SUCCESS` with
at least 16 and at most 504 bytes, the two answers to differ, and `READ(0)` to answer zero bytes.
The drivers hwrng restart phase kills the virtio-rng driver through `caps[19]`, requires its ordinal
on `caps[16]` to answer `WITHDRAWN` and the class's next ordinal to answer with a new instance, and
requires a `READ` through that instance to answer with bytes.

The `logd_sinks` phase's framebuffer-restarted case queries the framebuffer class's ordinal 1
through `caps[13]`, finds, attaches to, and stops the instance devmgr restarted through `caps[19]`,
requires a line to wait out logd's stall bound on it, then the line in logd's history through
`caps[6]`.
`caps[4]` and `caps[5]` are SENDs on vfsd's service endpoint, badged `MOUNT_AUTHORITY` and the
no-authority `DENY_BADGE` (services/vfsd/docs/vfs-ipc-interface.md § Endpoint). The vfsd phases
require an `UNAUTHORIZED` reply to `MOUNT` on `caps[5]` with nothing mounted; a `TABLE_FULL` reply
on `caps[4]` to `MOUNT` of the root role at `/` and of the data role at `/esp`, both already
mounted, in each of six rounds (vfsd checks the mount point before it registers a partition or
spawns a driver, so a rejection that started a spawn first would change a later reply); a
`NOT_FOUND` reply to a `MOUNT` whose path length exceeds the path bytes it carries; and that the
mounted filesystems still answer afterwards. The vfsd unmount phases require an `UNAUTHORIZED`
reply to `UNMOUNT` on `caps[5]`, forced or not, and on `caps[4]` of `/`; `NO_MOUNT` for a path
with no mount; `LABEL_VERSION_MISMATCH` and `NOT_FOUND` for a wrong version and a short path;
then, on `caps[4]`, `BUSY` with svctest's open files counted, a forced unmount of `/data`, and
the mounts and unmounts of the data partition below; services/vfsd/docs/vfs-ipc-interface.md
§ Label 11 owns the wire shape. `caps[14]` is a SEND on the same endpoint badged
`SWAP_AUTHORITY`; the `vfsd_swap_partition` phase, which runs after the short-path phase, requires
`UNAUTHORIZED` to `GET_SWAP_PARTITION` on `caps[4]` and `caps[5]`, and on `caps[14]` a hand-out of
a cap that addresses exactly the swap partition, a second hand-out revoking the first. The
`vfsd.mount` and `vfsd.deny` seeds ride in a second bootstrap round, so every svctest boot
receives a seed list longer than one round, and the svcmgr second-seed-round phase fails the run
when either arrives empty.
`caps[6]` is a SEND on the master log endpoint badged `LOG_QUERY_AUTHORITY` ([logd IPC
interface](../logd/docs/ipc-interface.md) § Queries); the `logd_death_forward` phase reads its dead
child's retired slot and history through it, and requires `QUERY_DENIED` for a query on svctest's
own log cap.
The `logd_restart` phase kills logd through `caps[19]`: it finds logd by name
(`LIST_PROCESSES`), attaches to it, requires the attach to report logd on the core path
(`ATTACH_FLAG_NO_CORE`), stops its main thread, sets the thread's instruction pointer to
0, and starts it, so the thread faults and the fault takes the path any fault of logd takes, to
crashd when the boot stages it, else to procmgr's decliner, and svcmgr restarts logd. It writes no
log line until it finds, through `caps[6]`, svcmgr's `service died: logd` and
`service restarted: logd` lines in the new instance's history, which holds only lines written
after the respawn, and fails when they do not arrive within 30 s. It then logs how long the restart
took, as svctest's first line to the new instance, whose table holds no name for svctest, and
requires that line retained once, in a live slot named `svctest`: the line carried
`SENDER_NAMED`, so the new instance refused it until svctest's log client registered the name
again ([logd IPC interface](../logd/docs/ipc-interface.md)
§ `stream_labels::STREAM_REGISTER_NAME`). A `logd-name-probe-child` then sends the new
instance raw stream messages: it registers an empty name, so its live slot holds none, and requires
a line without `SENDER_NAMED` accepted, a line and a record with it refused `NAME_UNKNOWN`, and,
once it has registered a name, a line with it accepted; the phase requires logd's history of the
child to hold the two accepted lines alone. Last, it runs the `logd_death_forward` check again,
against the new instance's fresh table and the death queue it registered.

The `logd_reserve` phase, just before it, runs when `memhog.svc` is staged and passes otherwise.
It requires logd's budget node to be a system-reserve node, as logd's recipe's `reserve = yes`
makes it ([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md) § `reserve`):
the attach to the running instance and the attach to the next must each report
`ATTACH_FLAG_RESERVE`. Between them it kills logd in the same way while
[memhog](../memhog/README.md) holds memory at the system reserve, and requires the next instance
to run and serve before the level falls. Outside the reserve the create of the next instance and
every first touch of its heap and stacks are refused while memhog holds the pool, except from the
frames the kill frees until memhog's next tick takes them back, so the attach flags, not the
timing, are what fail for a logd outside the reserve. It attaches to logd before the fill, has
memhog fill the pool, faults logd's main thread once the level reads `CRITICAL`, and waits for
the level to fall: oomd's stop of memhog ends the window when oomd is staged in its stop mode, and
svctest's own stop through `caps[20]`, 5 s after the fill, otherwise. It then requires, through
`caps[6]`, svcmgr's `service restarted: logd` line in the new instance's history stamped before
svcmgr's `stop memhog` line, the first of each after the kill, and memhog's next instance to
answer `PROBE` with a new nonce and no pages. svcmgr writes the stop line once procmgr has
destroyed memhog, which frees the memory, and serves a stop and a restart on one event loop
([Restart Protocol](../svcmgr/docs/restart-protocol.md) § Death detection), so a stop asked for
while it restarts logd waits for the restart, and the order of the two lines is the order of the
restart and the stop, however long the restart takes.

Every seed is seed-only in svcmgr's registry. The no-authority `pwrmgr.deny` cap is
public, so svctest resolves it through `QUERY_ENDPOINT` on its per-process `service_registry_cap`
and spends no seed slot on it; it drives the pwrmgr cap-deny phase, which requires an `UNAUTHORIZED`
reply to `SHUTDOWN`. The public `acpid.deny` is resolved the same way and drives the
`acpid_power_deny` phase, which requires an `UNAUTHORIZED` reply to `SLEEP(5)`, to `RESET` and to
`WAIT_EVENT`.

The `svcmgr_worker_fault_restart` phase runs when the `crasher-worker.svc` recipe is staged
beside `svctest.svc` and is skipped otherwise; staged, it fails if `crasher.worker` is not
published within 10 s. It reads the instance's
nonce with `PROBE_INSTANCE`, sends `PROBE_FAULT_WORKER` so a worker thread of the fixture faults,
and requires a different nonce from the instance svcmgr restarts
([crasher](../crasher/README.md)).

The `svcmgr_boot_death` phase runs when the `crasher-boot.svc` recipe is staged beside
`svctest.svc` and is skipped otherwise; staged, it fails if `crasher.boot` is not published
within 10 s. It checks that svcmgr routes the death of a service that dies before its bootstrap
request ([Restart Protocol § Death
detection](../svcmgr/docs/restart-protocol.md#death-detection)). The fixture's instance that finds
the token `/data/crasher-boot/die-early` removes it and faults before its request, and any other
serves `PROBE_INSTANCE` and `PROBE_FAULT_WORKER` on `crasher.boot`. The data partition ships the
token, so the first launch dies so: the phase requires an instance's nonce, which only an instance
svcmgr started after routing that death answers, and the token gone. It then writes the token,
sends `PROBE_FAULT_WORKER`, and requires a different nonce and the token gone: the restart after the
worker's fault took the token and died before its request, and a later restart answered. It
writes the token again at its end, so a later boot of the same image repeats the first-launch case.

The `svcmgr_stop_service` phase checks the stop authority
([svcmgr IPC Interface](../svcmgr/docs/ipc-interface.md) § Stop authority). Through the
per-process `service_registry_cap`, `STOP_CANDIDATE`, `LIST_CANDIDATES` and `LIST_STOP_SOURCES`
must reply `UNAUTHORIZED`. Through `caps[20]`, the whole `LIST_CANDIDATES` walk must list exactly
the staged fixtures whose recipes set `oom_stop = yes` (`crasher-worker` and `memhog`), each with
a non-zero usage and the service rank, and nothing when neither is staged; `STOP_CANDIDATE` must
reply `NO_CANDIDATE` for the first instance's key of every svcmgr table slot below 32 it does not
list, which covers svctest itself (`restart = never`), the services init started, logd (`critical =
yes`), pwrmgr, entropyd and `stopsrc` (core roles), timed (no `oom_stop`) and the slots past the
table. The whole `LIST_STOP_SOURCES` walk must list exactly
[sessiond](../sessiond/README.md) and [stopsrc](../stopsrc/README.md), each when its recipe is
staged, both with the program class, and nothing when neither is staged; through the SEND it
carries, the fixture's `LIST_CANDIDATES` must reply `SUCCESS` and `STOP_CANDIDATE` of a key it never
gave `NO_CANDIDATE`, and through the fixture's `:deny` SEND,
which `QUERY_ENDPOINT` resolves, both must reply `UNAUTHORIZED`. With `stopsrc.svc` staged, the
phase also checks that svcmgr creates the source contained: through `caps[19]`, `LIST_PROCESSES`
must list one new process named `/tests/stopsrc`, the job's first argv word, after `START_JOB`;
once the fixture has exited (`EXIT`, which leaves the job running) and its next instance answers
`PROBE` with a new nonce, the job's badge must leave the list within 2 s. With
`crasher-worker.svc` staged,
`STOP_CANDIDATE` of its listed key must reply `SUCCESS`, the fixture must then answer
`PROBE_INSTANCE` with a new instance's nonce, the restart its `on_failure` policy makes of the
`EXIT_KILLED` death, and the same key must then reply `NO_CANDIDATE`.

The `oom_policy` phase (`phases/oom.rs`, registered after the svcmgr phases) runs when the
`memhog.svc` recipe is staged beside `svctest.svc` and passes otherwise, logging that `memhog.svc`
is not staged. It waits for the pressure level to read `NORMAL`, sends `PROBE` to
[memhog](../memhog/README.md) (a nonce, 0 pages) and then `HOG`, which fills memory until the level
reads `CRITICAL`. With oomd staged and `OOMD_STOP=yes`, it waits for the level to fall to `NORMAL`
and checks that oomd logged exactly one `stopped memhog: ` line after at least its grace critical,
and no advice line. When `sessiond.svc` is staged and `caps[15]` is set, the phase also opens an
operator session whose shell runs `crashme oom-hold 512`, a job larger than `stopsrc`'s; oomd must
log one `stopped /programs/crashme: ` line before its stop of `stopsrc`'s job, then stop the
session, whose relay gives the leader's end, and then memhog. When `stopsrc.svc` is staged, the
phase first sends the fixture `EXIT`, waits for its restarted instance's new nonce, so the source
oomd finds started after oomd, and has it start a job of 64 pages; oomd must then log one `stopped
stopsrc-job: ` line before its stop of memhog, and the fixture must report the job stopped. When
crashd is staged with a stall, a child (`/programs/crashme oom-touch 1024`) writes the pages of a
demand region in turn during the fill, and crashd logs the write memmgr declines held, then resumed;
with sessiond staged, the child's `go` waits until sessiond lists no candidate, so crashd's hold
covers only memhog's stop. The pages oomd's last stop freed lie above the reserve until memhog's
next top-up takes them back, and the child's writes spend them, so one write is always declined.
The phase first checks that crashd's stall outlasts what oomd takes from the write to memhog's
stop: a cooldown with sessiond staged, else the grace and a cooldown for `stopsrc`'s job. With
`OOMD_STOP=no`, or without `oomd.svc` staged, it checks that memhog stays running and the level
stays `CRITICAL` past the grace, the cooldown and 2000 ms, that oomd, if staged, logged at least
one `would stop ` line, which names the operator session while one is open, and no stop, and then
stops memhog itself through `caps[20]`, by the key svcmgr listed it under before the fill. In
every case memhog's next instance answers `PROBE` with a new nonce and 0 pages
([oomd](../oomd/README.md)).

The `sessiond_operator` phase (`phases/sessiond.rs`, right after the svcmgr phases) runs when
`sessiond.svc` is staged and `caps[15]` is set, and passes otherwise. Through the stop SEND svcmgr
hands svctest for sessiond, operator labels must reply `UNAUTHORIZED`, as must stop labels through
the operator SEND. `OPEN_SESSION` under an unregistered nonce replies `UNKNOWN_INTERFACE`,
`REGISTER_INTERFACE` of another version `VERSION_MISMATCH`, and a second one under one nonce
`INVALID_ARGUMENT`. A cap of the wrong type or rights replies `INVALID_ARGUMENT`: a POST cap as
`REGISTER_INTERFACE`'s end queue, a RECV cap as `OPEN_SESSION`'s relay, and a notification as
`SESSION_STDIO`'s memory cap, which also ends the session, whose relay is then posted. A session
runs the shell (`echo`), lists with `RANK_SESSION` under its key and its job (`crashme oom-hold 16`)
with `RANK_JOB` under `/programs/crashme` with at least 16 pages; `STOP_CANDIDATE` of the job leaves
the shell answering. The shell's exit gives status 0 on the relay and its key `NO_CANDIDATE` after;
a second session stopped whole gives `EXIT_KILLED` ([sessiond](../sessiond/README.md)).

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
| `end-queue-child`           | `process_tree` | `process_tree_end_queue` (end queue)       |
| `exit-fault-child`          | `process_tree` | `process_tree_end_posted_once` (one post)  |
| `logd-name-probe-child`     | `logd_restart` | `logd_restart` (named-sender refusals)      |
| `release-child`             | `fs_std`       | `std_release_matched_by_open` (fake fs)     |
| `open-reclaim-child`        | `fs_opens`     | `fs_reclaims_dead_opens` (killed client)    |
| `open-undeliverable-child`  | `fs_opens`     | `fs_reclaims_dead_opens` (failed reply)     |
| `reclaim-child`             | `memmgr`       | `frame_reclaim_live_object` (held endpoint) |
| `scrub-child`               | `memmgr`       | `memmgr_frame_scrub` (frames of a death)    |
| `exit-code-zero`            | `exit_code`    | `exit_code`                                 |
| `exit-code-nonzero`         | `exit_code`    | `exit_code`                                 |
| `random-diverge-child`      | `random`       | `random` (per-process hash seed)            |
| `aslr-layout-diverge-child` | `random`       | `aslr-layout` (per-process layout tuple)    |
| `stale-map-child`           | `unmount`      | `vfsd_unmount_stale_mapping` (mapped page)  |
| `budget-child`              | `budget`       | `procmgr_memory_max` (4096-page max)        |
| `node-handle-child`         | `node_handle`  | `memmgr_node_handles` (max set by handle)   |
| `heap-commit-limited`       | `heap_commit`  | `memmgr_heap_commit` (4096-page max)        |
| `heap-commit-hog`           | `heap_commit`  | `memmgr_heap_commit` (commits to the bound) |
| `discard-hog`               | `discard`      | `memmgr_discard_range` (refault at the bound) |
| `heap-release`              | `discard`      | `memmgr_discard_range` (heap discard, trim) |
| `swap-fixture`              | `swap`         | `memmgr_swap`, `memmgr_swap_client` (evicted regions, threads) |
| `reboot`                    | `pwrmgr`       | the `reboot.svc` test recipe (`test-reboot`) |

---

## Fixtures

Phases spawn these programs from `/programs/`: `hello` (procmgr, pipes), `stdiotest` (pipes,
procmgr), `pipefault` (pipes), `stackoverflow` and `relrofault` (process faults), `capexhaust` (recv
guard), `demandpaged` (pager), `fsbench` (FS IPC), and `crashme` (`oom-hold <pages>`, run through a
session's shell by the `sessiond_operator` and `oom_policy` phases: it touches that many heap pages,
prints `holding <pages>` and waits to be destroyed; and the crash endpoint: svctest, its recipe
granting `debug_authority`, registers as the crash service and takes a `crashme` child's forwarded
page fault, and the faults of two `registry-*` children, whose attach lists their live registered
threads and none that exited or was joined, and whose spawned thread's crash badge names
it; on the first of those it acts as a debugger, finding the child with `LIST_PROCESSES` and having
procmgr restore a registered thread it rebound, by `DETACH_PROCESS` and then by an attach's watch
thread exiting; acts as the debugger of a `debugger-tag` child, whose thread registering with a
gone debugger's binding is bound back to the crash endpoint and whose declaration, with svctest
attached and watched, unbinds svctest's bindings and leaves no watch to bind it back; has procmgr
unbind a debugger's binding from a thread of its own whose registration it refuses, svctest having
declared itself undebuggable; then gives the endpoint back and sees a second child declined by
procmgr; and, for the `oom_policy` phase, an `oom-touch` child whose write crashd holds while
memory is critical). The
devmgr on-demand-bind phase registers a `WATCH_CLASS` watch on `caps[10]`, then sends
`BIND_DRIVERS` on `caps[3]` over `/tests/drivers/`, which no
drivers-directory pass at boot reads, so devmgr binds the
[`test-fault`](../drivers/test-fault/README.md) driver to the QEMU `pci-testdev` functions that
`--test-devices` attaches, one instance each. The
phase asks `caps[10]` for the fixtures: the two serving instances hold instance ordinals 0 and 1,
and ordinal 2 answers `NO_DEVICE`; `FAULT_EXIT` on ordinal 0 makes the next query on it answer
`WITHDRAWN`; `FAULT_WORKER` on ordinal 1, whose worker thread then faults, returns a call
queued on it and makes the next query on it answer `WITHDRAWN`; the free pool then returns to
its size before the bind, so the instance that never reports ready and the instance that fails
its bootstrap's terminal round were destroyed; and a second `BIND_DRIVERS` over the directory
binds nothing. The watch, registered at ordinal count 0, is signalled when the bind serves the
fixtures and again at each withdrawal. With
that watch held, the phase fills the class to `MAX_CLASS_WATCHERS` (8): the next registration is
refused `WATCHERS_FULL`, and once it deletes one watch a new registration is admitted. The DMA
confinement phase waits on a `WATCH_CLASS` watch on `caps[9]` (bounded by `DEVICE_WAIT_MS`) until
devmgr serves the
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
with `DESTROY_PROCESS`. Its last cases end their driver themselves, each observed through an event
queue bound to the driver's main thread: the block server revokes every capability derived from
its endpoint, two more drivers, each on a volume of its own, take `FS_UNMOUNT`, and a fourth loses
its service endpoint as vfsd ends a driver it cannot use and must exit at its next receive. The
`fs_pressure_release` phase before it starts a fatfs the same way, loses one cache page's cap in a
read the block server fails, drives memmgr's level to `Low` and back as `memmgr_pressure` does, and
checks from the block server's log of reads that the driver gave back every idle cache page but the
one svctest still maps and the few it keeps, the lost cap's page among them, with its children's
charge falling to match and memmgr's pool total unchanged. The `fs_run_fill` phase after it starts
fatfs the same way four times on one volume: from the block server's log of reads, a sequential
`FS_READ_MEMORY` scan of a file fills runs of more than a page and at most `fat_parse::RUN_PAGES`
pages, and a read off the sequence fills one page; a scan whose first run read loses its Memory
cap fills one page at a time from there, and a write after it still succeeds; then an open whose
chain cursor stands deep in the file reads the file's new bytes after a truncate and rewrite give
the file the same first cluster and different later links. The FS,
namespace, and procmgr phases read `/data/test.txt`; the FS phases also read the build-synthesised
`/data/svctest/large.bin` and write their scratch files under `/data/svctest/`; `fsbench`, spawned
by the `fs_crossover_bench` phase, reads the build-synthesised `/data/svctest/bench.bin`, which the
`fs_eviction_routes_release_to_its_open` phase also holds open.
The vfsd unmount phases hold `/data/test.txt` and `/data/svctest/large.bin` open across an
unforced and a forced unmount of `/data`, and a `stale-map-child` maps a cache page of
`/data/test.txt`; while `/data` is unmounted they mount the data partition over
`/config/svcmgr/tests`, the root filesystem's directory of svctest's own recipe, read
`test.txt` there, and after unmounting it read `/config/svcmgr/tests/svctest.svc` through the
fall-through again. The `vfsd_driver_death` phase holds a file on `/data` open and kills the data
mount's fs driver (found by its name `fatfs:/data`) through a debug attach `RESTART_BURST` times;
each time vfsd restarts the driver, a new `fatfs:/data` is listed, `/data/test.txt` reads again,
`/data` is never not found, and the open file is stale. One more kill finds the restart budget
spent: vfsd tears the mount down, `/data` falls through and is not found, and a fresh `MOUNT` at
`/data` succeeds on the same disk. They mount `/data` again and set svctest's cwd to it before
they end.
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
