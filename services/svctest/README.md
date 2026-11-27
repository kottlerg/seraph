# svctest

Services-surface test harness. A std-built binary installed at `/tests/svctest` that exercises
the services tier (procmgr, memmgr, vfsd and fatfs, devmgr and the authority gates of its serial,
input, framebuffer, and hwrng drivers, svcmgr, pwrmgr, timed, entropyd), the kernel objects those
services hand out, and the `ruststd` runtime layer end to end. `svcmgr` spawns it from the
`svctest.svc` recipe, which lives in `/config/svcmgr/tests/` and runs only when staged into
`/config/svcmgr/services/` by `cargo xtask mkdisk --svctest <set>`, which co-stages the set's
fixtures, the test class files of `/config/devmgr/tests/` into `/config/devmgr/classes/`, and the
set's `SVCTEST_FIXTURES` record into the recipe's environment, per
[docs/testing.md § Gating](../../docs/testing.md#gating). The `svctest_fixtures` phase fails the run
unless the image stages exactly the fixtures the record declares, and oomd and sessiond; a phase
whose fixture the set does not declare skips and logs `phase=<phase> skipped: <recipe> not staged`.
The same phase fails an image that stages crashd when the record selects phases, and one that does
not when it selects none. Every set stages oomd's test recipe (`/config/svcmgr/tests/oomd.svc`) over
the default one. The `ci`, `burn-in` and `none` sets stage crashd's test recipe
(`/config/svcmgr/tests/crashd.svc`) over the default one; the `crash-endpoint` set stages no fixture
and no crashd and records `SVCTEST_PHASES=crash_endpoint`, and svctest then runs only its startup
phases, `svctest_fixtures` and `crash_endpoint`.
The devmgr phases also need a boot with `cargo xtask run --test-devices`; a phase that finds the
devices missing fails, naming the flag.

---

## Source Layout

```
services/svctest/
├── Cargo.toml
├── fixtures/                  # `svctest-fixtures` crate: the fixtures, the named sets
│                              #   `mkdisk --svctest` stages, and the SVCTEST_FIXTURES record
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
        │                      # CSpace low-water hold; CSpace funded from no free slot;
        │                      # object-slab release; deferred
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
        │                      #   and restarted; a debug line retained and not on serial; and
        │                      #   logd's flush barrier
        ├── logd_flood.rs      # Probe lines logged between `log-flood begin` and `end` while two
        │                      #   processes flood logd, which refuses the flooders
        │                      #   `WINDOW_FULL` and not the probe; `run --whole-lines`
        │                      #   checks the log
        ├── console_whole_lines.rs # Four threads log numbered lines for up to 3 s between
        │                      #   `whole-lines begin` and `whole-lines end senders=4 lines=N` while
        │                      #   `relrofault` faults in a loop and `capexhaust` wedges its CSpace;
        │                      #   `run --whole-lines` checks the log
        ├── serial_transmit.rs # With the serial driver's transmitter stopped: numbered lines
        │                      #   written between `serial-burst begin` and `end` answered from
        │                      #   its ring, a read answered beside a SERIAL_WRITE_SENT write that
        │                      #   waits until the transmitter is started; `run --whole-lines`
        │                      #   checks the log
        ├── thread_exits.rs    # Another process ended through an attach from a worker thread,
        │                      #   then its main thread, each by an exit syscall it is pointed at
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
        ├── crashd.rs          # crashd over `crashme`: fault deaths with a fault-class exit, the
        │                      #   core each leaves, a live core and its refusal, a held fault
        ├── deadline.rs        # The `deadline` fixture: worker cancelled, call deadlines
        ├── debugger.rs        # The `debugger` fixture: breakpoints, memory, single-step, upcall
        ├── threadchurn.rs     # The `threadchurn` fixture: bounded CSpace-slot growth
        ├── threadstack.rs     # The `threadstack` fixture: stack growth, guard, overflow modes
        ├── pipestress.rs      # The `pipestress` fixture: spawn-drain loop, slot-growth bound,
        │                      #   doorbell trial, in a `pipestress-spawner` child
        ├── exit_code.rs       # Child exit-code propagation to `ExitStatus`
        ├── fixtures.rs        # The staged fixture set: the image checked against the record;
        │                      #   the skip line of a phase whose fixture is not declared
        ├── random.rs          # `SYS_GETRANDOM`, hash seeding, ASLR layout divergence
        ├── entropyd.rs        # entropyd's first contribution accepted by the kernel
        ├── recv_guard.rs      # Shared `RecvGuard` recv-loop failure policy
        ├── recv_pool.rs       # Worker-pool receive helper under concurrent nested IPC;
        │                      #   concurrent logging through logd
        ├── no_receiver.rs     # A call queued on an endpoint whose last Receive right dies,
        │                      #   and the call after it, fail with `NoReceiver`
        ├── devmgr.rs          # Block, shutdown, bind deny; input ordinal; on-demand
        │                      #   driver bind; DMA confinement; MSI delivery, forge,
        │                      #   churn, and release
        ├── acpi.rs            # acpid's results read from devmgr (`acpi_host_bridges`); the
        │                      #   `ACPI_AUTHORITY` gate (`acpi_authority_deny`); the power
        │                      #   deny check (`acpid_power_deny`)
        ├── drivers.rs         # Serial, input, framebuffer, and hwrng verb-bit deny; serial,
        │                      #   input, hwrng, RTC, and framebuffer stray caps; hwrng read;
        │                      #   hwrng killed and restarted
        ├── pager.rs           # Demand paging: backed, declined, pinned; forged-badge bind;
        │                      #   refused access; page-table drain; teardown;
        │                      #   faults and a CSpace top-up on a fragmented pool; a
        │                      #   sparse large region
        ├── budget.rs          # Create-time memory max: clamp, grants to it, LIMIT, decline 10,
        │                      #   pages back after the destroy; reserve and max refusals
        ├── node_handle.rs     # memmgr node handles: class refusals, sub-node clamp, a max set
        │                      #   while the child runs, LIMIT, limit event, lowering reclaims
        │                      #   nothing, released and dead handles refused; two children
        │                      #   charged to one sub-node share its budget
        ├── node_reclaim.rs    # memmgr floors and weights: two sub-nodes of differing weight under
        │                      #   a held `LOW` level, the heavier keeps more resident; weight
        │                      #   refusals; all-RAM-accounted identity
        ├── heap_commit.rs     # Committed heap growth: max refusal as an allocation error, a grant
        │                      #   past the promised bound, no fault declined, committed region
        │                      #   register, extend, shrink; all-RAM-accounted identity
        ├── discard.rs         # DISCARD_RANGE and SHRINK_REGION return frames; discarded pages
        │                      #   refault zero-filled and, committed, from the promise they keep;
        │                      #   the std heap's discard and trim; all-RAM-accounted identity
        ├── memory_objects.rs  # memmgr memory objects: seal refusal and charge, attach refusals,
        │                      #   shared and private attachments in svctest and a child, a
        │                      #   private write seen by no other attacher, a shared write kills
        │                      #   its writer, release, the zero object; early in the run, a
        │                      #   32,768-page object sealed, read back and released
        ├── object_io.rs       # OBJECT_READ, FILL_REGION and MARK_CHECKPOINT: an object's pages
        │                      #   read into a grant and filled into a demand region, the
        │                      #   refusals, no mark from svctest
        ├── memory_object_text.rs # executable memory objects: svctest and children call a sealed
        │                      #   function; a text write refused until MAKE_PRIVATE, then
        │                      #   patching one child alone; MAKE_PRIVATE refusals
        ├── image_sharing.rs   # procmgr image sharing: a text write refused on a shared
        │                      #   image and made on a private and a pinned one, untouched
        │                      #   text read through MAKE_RESIDENT, a breakpoint on it after
        │                      #   MAKE_PRIVATE, the free RAM a shared instance saves
        ├── snapshot.rs        # procmgr SNAPSHOT of a live child: one point in time against a
        │                      #   writer thread that never registered, the child resumed, the
        │                      #   object charged to svctest and released; the regions and
        │                      #   every page origin: image, object, zero and demand pages
        │                      #   the child never touched; the refusals
        ├── checkpoint.rs      # procmgr CHECKPOINT of a child at its quiesce point: the
        │                      #   runtime's refusals, the section read back, Captured; the
        │                      #   refusals of a child at no point and of a pinned child
        ├── restore.rs         # Command::restore of a checkpoint: each held value refusing the
        │                      #   quiesce, two restores resumed with their state and every
        │                      #   handle rebound, distinct HashMap keys; the refusals
        ├── swap.rs            # memmgr evicts a child's cold chunks into its store under a
        │                      #   held `LOW` level and restores them: debugger reads and
        │                      #   `MAKE_RESIDENT`; at `CRITICAL`, restores from the restore
        │                      #   headroom and by direct reclaim; a no-evict region, logd's
        │                      #   reserve stack; all-RAM-accounted identity; each swap phase
        │                      #   ends with no page in no account past its start and the
        │                      #   charge below svctest's node back to its start, not judging
        │                      #   svctest's own charge or a process outside that subtree
        ├── swap_client.rs     # memmgr's disk tier with svctest as a second swap client beside
        │                      #   swapd, over a RAM slot store, registering nothing: take, done,
        │                      #   stale restores, a restore ahead, `ipc::make_resident` of a
        │                      #   chunk whose slot holds no seal, so memmgr loses it, and the
        │                      #   fixture killed on a fault in it; all-RAM-accounted identity
        ├── swap_raw.rs        # memmgr's raw chunks, as that second swap client: a chunk of
        │                      #   noise held raw and counted swapped only once written, its
        │                      #   pages sealed alone in a whole slot, restored; one mapped
        │                      #   back by `MAKE_RESIDENT`, the rest and one in flight by faults
        ├── swapd.rs           # swapd's disk tier end to end: memmgr serving with a write and a
        │                      #   restore in flight and swapd's threads stopped, write-out at
        │                      #   `CRITICAL`, the storage path's stacks never evicted, the want
        │                      #   path, swapd killed and restarted, the fault path through the
        │                      #   next instance; all-RAM-accounted identity
        ├── swap_commit.rs     # Commitment backed by swap slots: admitted past the free pages by
        │                      #   the overcommit allowance and refused past it; with crashd's
        │                      #   hold, a child writes a commitment past the draw room, its
        │                      #   commit overruns held until write-out opens the draw room
        ├── shmem.rs           # Kernel shared-memory objects
        ├── pipes.rs           # Kernel pipes: piped stdio, death-bridge EOF; `stdiotest` output
        ├── namespace.rs       # vfsd namespace protocol, sandboxing, startup cwd
        ├── fs_ipc.rs          # Raw `FS_*` IPC against vfsd and fatfs
        ├── fs_opens.rs        # Per-open fatfs state: dead-open reclaim, close, eviction routing
        ├── fs_sessions.rs     # fatfs sessions: charge on the client's node, LIMIT, return
        ├── fs_create_open.rs  # A create that opens its file in one request: no entry left at
        │                      #   the node's max; a create through a grant-less root refused
        ├── fs_std.rs          # `std::fs` over the FS IPC contract
        ├── fs_faults/
        │   ├── mod.rs         # Own fatfs under block faults: failed writes, removes, renames
        │   ├── pressure.rs    # Own fatfs gives idle cache pages back at memory pressure Low
        │   ├── ramdisk.rs     # RAM FAT16 volume and block server with armed faults, read and
        │   │                  #   write logs
        │   ├── run_fill.rs    # Own fatfs fills sequential reads in runs; chain cursor retired
        │   └── run_write.rs   # Own fatfs writes a page as one block request; a dropped run
        │                      #   rolls back
        ├── verified_read.rs   # procmgr's verified read of a data file: the body returned and
        │                      #   charged while held; another name, a flipped byte, no
        │                      #   signature, past the bound, and no length refused
        ├── pwrmgr.rs          # Shutdown cap-deny check, terminal shutdown, `reboot` role
        ├── svcmgr.rs          # Handover refused; publish gate; badged SEND; seed-only; round 2;
        │                      #   stray caps
        ├── sessiond.rs        # sessiond's operator interface: badge gates, interface registration
        │                      #   refusals, a session's leader, listed jobs, stopped whole
        ├── oom.rs             # Out-of-memory policy: memhog filled until oomd stops it, a
        │                      #   stop source's job stopped first, a held write resumed
        ├── timed.rs           # `SystemTime::now()` through svcmgr and timed; a timed started
        │                      #   after the RTC driver's restart serves the wall clock; the
        │                      #   RTC driver's create refused under memory pressure, retried
        ├── unmount.rs         # vfsd `UNMOUNT`: refusals, busy then forced, stale handles,
        │                      #   fall-through, remount, a mapped page across the unmount,
        │                      #   a killed fs driver, its death's reason from a worker's exit
        ├── vfsd.rs            # `MOUNT` gate: deny, mounted-path and short-path rejections
        └── vfsd_caps.rs       # Caps a request on vfsd's namespace endpoint carries, deleted
                               #   whatever its label, through a synthetic intermediate
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
the envelope `phase=<name> starting` / `phase=<name> passed`, except that the phases of the
concurrent group run at once, each on a thread of its own, and are joined before the next phase
([`phases/mod.rs`](src/phases/mod.rs) § Concurrent group). After the last phase it logs
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

Some failures still end the run idle. A panic or allocation failure during the declaration or the
bootstrap rounds (a refused `DECLARE_NO_DEBUG` among them) logs `SOME TESTS FAILED` but sends no
`SHUTDOWN`, because the hooks get the pwrmgr cap only after the rounds return. A `SHUTDOWN` that
pwrmgr answers, or whose call fails, is logged and leaves the system idle, as on the pass path. A
fault in svctest's own process (a stray access, a stack overflow) kills it without running either
hook, so it logs neither marker; svcmgr then logs `service died: svctest`, which `cargo xtask run`
reads, before the pass marker, as a FAIL, and ends the boot at its fail grace window
([xtask/README.md § `cargo xtask run`](../../xtask/README.md#cargo-xtask-run)). The `ns` phase
(`caps[0]`) and the pwrmgr cap-deny phase (the queried `pwrmgr.deny` cap) log the skip and return
when their cap is zero; the devmgr class-deny
phase (`caps[2]` and `caps[3]`), the bind-deny phase (`caps[2]`), the input-ordinal phase
(`caps[8]`), the device-location phase (`caps[7]` and `caps[8]`), the on-demand-bind phase
(`caps[3]`, `caps[8]`, and `caps[10]`), the DMA confinement
and MSI delivery, forge, churn, and release phases (`caps[9]`), the drivers stray-cap phases
(`caps[7]`, `caps[8]`, `caps[13]`, `caps[16]`, and `caps[19]`), the drivers hwrng read phase
(`caps[16]`), the drivers hwrng restart phase (`caps[16]` and `caps[23]`), the drivers deny phase
(`caps[11]` to `caps[13]` and `caps[17]`), the `logd_sinks` phase's framebuffer-killed and
framebuffer-restarted cases (`caps[13]`), the svcmgr seed-only phase (every seed-only seed, plus the
public `svcmgr`, `pwrmgr.deny` and `acpid.deny` names it resolves), the svcmgr second-seed-round
phase (`caps[4]` and `caps[5]`), the svcmgr stray-cap phase (`caps[20]`), the vfsd and vfsd unmount
phases (`caps[4]`, `caps[5]`), the `vfsd_namespace_stray_caps` phase (`caps[4]`), the
`logd_death_forward`, `logd_concurrent`, `logd_reserve`, `logd_restart`, `logd_sinks`,
`entropyd_contribution`, `devmgr_on_demand_bind`, `devmgr_iommu_restart`, `rtc_create_retry`,
`oom_policy`, and `memmgr_swap_commit` phases (`caps[6]`), the `rtc_create_retry` phase
(`caps[19]`), the vfsd swap-partition phase (`caps[14]`), the `memmgr_swap_client`,
`memmgr_swap_raw` and `swapd` phases (`caps[18]`), the `sessiond_operator` phase and the
`oom_policy` phase's session case (`caps[15]` and `caps[24]`), the `crash_endpoint`, `logd_reserve`,
`logd_restart`, `logd_sinks`, `logd_flush`, `memmgr_swap`, `memmgr_node_reclaim`,
`memmgr_swap_client`,
`memmgr_swap_raw`, `swapd`, `vfsd_driver_death`, `rtc_create_retry`, `procmgr_snapshot`, and
`timed_rtc_restart` phases, and the drivers hwrng restart phase (`caps[23]`), the
`svcmgr_stop_service` phase (`caps[24]`, and `caps[23]` with `stopsrc` staged), and the no-stop
cases of the `oom_policy`, `logd_reserve` and `rtc_create_retry` phases (`caps[24]`), instead fail
their assertions. The seed-only phase thus fails the run on a zero `caps[1]` before the terminal
pwrmgr shutdown phase, so that phase's own zero-cap skip is not reached; the panic hook's `SHUTDOWN`
is then skipped for the same zero cap, and the run ends idle.

The startup phases assert the recipe's launch surface: argv is exactly `svctest run`, walked from
the front, from the back, and from both ends at once, and env carries `SERAPH_TEST=1` and
`SERAPH_MODE=boot`.

---

## Capabilities

The bootstrap rounds from the creator endpoint deliver the recipe's seeds in this order, four slots
to a round (`caps[0]` to `caps[3]`, `caps[4]` to `caps[7]`, `caps[8]` to `caps[11]`,
`caps[12]` to `caps[15]`, `caps[16]` to `caps[19]`, `caps[20]` to `caps[23]`, and `caps[24]`), the
last two being the debug-authority cap the recipe's `debug_authority = yes` grants and the
stop-authority cap its `stop_authority = yes` grants; [service-definitions.md §
`seed`](../svcmgr/docs/service-definitions.md#seed) defines each name's cap shape and the zero slot
an unresolved name leaves. With no creator endpoint, every slot stays zero.

| Slot      | Seed              | Use in svctest                         |
|-----------|-------------------|----------------------------------------|
| `caps[0]` | `rootfs.root`     | `ns` phase                             |
| `caps[1]` | `pwrmgr.shutdown` | Authority cap for the final `SHUTDOWN` |
| `caps[2]` | `devmgr.registry` | devmgr class-deny and shutdown-deny phases |
| `caps[3]` | `devmgr.bind`     | devmgr class-deny, bind-deny, and on-demand-bind phases: the `SEND\|GRANT` registry cap `BIND_DRIVERS` needs |
| `caps[4]` | `vfsd.mount`      | vfsd `MOUNT` rejection phases; vfsd unmount phases: `UNMOUNT`, the remounts, and the fs-driver death phase's remount; `vfsd_namespace_stray_caps` phase: its `UNMOUNT` and both its `MOUNT`s |
| `caps[5]` | `vfsd.deny`       | vfsd `MOUNT` deny phase; `UNMOUNT` deny case |
| `caps[6]` | `logd.query`      | `logd_death_forward`, `logd_concurrent`, `logd_reserve`, `logd_restart`, `logd_sinks`, `entropyd_contribution`, `devmgr_on_demand_bind`, `devmgr_iommu_restart`, `rtc_create_retry`, `oom_policy`, `memmgr_swap_commit`, `vfsd_driver_death` phases: read logd's slots and history; `logd_flush` phase: the `logd.query` SEND `LOG_FLUSH` must refuse |
| `caps[7]` | `devmgr.class.serial` | device-location and drivers stray-cap phases, and the `serial_transmit` phase: the `serial` class SEND |
| `caps[8]` | `devmgr.class.input` | input-ordinal, device-location, and drivers stray-cap phases: the `input` class SEND |
| `caps[9]` | `devmgr.class.test-dma` | DMA confinement and MSI delivery, forge, churn, and release phases: the `test-dma` class SEND |
| `caps[10]` | `devmgr.class.test-fault` | on-demand-bind phase: the `test-fault` class SEND |
| `caps[11]` | `devmgr.class.serial-deny` | drivers deny phase: a `serial` class SEND without the driver's verb bits |
| `caps[12]` | `devmgr.class.input-deny` | drivers deny phase: an `input` class SEND without the driver's verb bits |
| `caps[13]` | `devmgr.class.framebuffer-deny` | drivers deny phase: a `framebuffer` class SEND without the driver's verb bits; `logd_sinks` phase: the class it waits on for the killed framebuffer driver's withdrawal and queries for the restarted instance at ordinal 1; drivers stray-cap phase: the SEND its framebuffer case floods |
| `caps[14]` | `vfsd.swap`      | vfsd `GET_SWAP_PARTITION` phase: the stale-version refusal only, swapd holding the partition |
| `caps[15]` | `sessiond.operator` (`SEND\|GRANT`) | `sessiond_operator` phase: `OPEN_SESSION`, `REGISTER_INTERFACE`; `oom_policy` phase: opens the operator session whose leader runs the large job |
| `caps[16]` | `devmgr.class.hwrng` | drivers hwrng read, hwrng restart, and stray-cap phases: the `hwrng` class SEND |
| `caps[17]` | `devmgr.class.hwrng-deny` | drivers deny phase: an `hwrng` class SEND without the driver's verb bits |
| `caps[18]` | `memmgr.swap` (`SEND\|GRANT`) | `memmgr_swap_client`, `memmgr_swap_raw` and `swapd` phases: memmgr's swap labels, as a second swap client beside swapd, registering nothing, over a RAM slot store |
| `caps[19]` | `devmgr.class.rtc` | `rtc_create_retry` phase: the `rtc` class SEND, on which it waits for devmgr to serve the RTC driver its create retry started; drivers stray-cap phase: the SEND its RTC cases flood |
| `caps[20]` | `svcmgr.grant` | svcmgr stray-cap phase: the `SEND\|GRANT` on svcmgr's service endpoint, under the published `svcmgr` SEND's badge, on which it sends requests that carry caps |
| `caps[21]` | `crashd.core` (`SEND\|GRANT`) | `crashd_live_core` phase: `LIVE_CORE` of `crashme live`, `crashme live-no-core` and `crashme live-declare`; zero in a boot that stages no crashd |
| `caps[22]` | `logd.flush`      | `logd_flush` phase: checks logd's flush barrier |
| `caps[23]` | (`debug_authority`) | `crash_endpoint` phase; `logd_reserve` and `logd_restart` phases: find and attach to logd; `logd_flush` phase: finds, attaches to, stops, and starts the serial driver; `logd_sinks` phase: finds, attaches to, stops, and kills the sink drivers, and finds, attaches to, and stops the restarted framebuffer driver; `serial_transmit` phase: finds and attaches to the serial driver, and stops and starts its transmitter thread; drivers hwrng restart phase: kills the virtio-rng driver; `rtc_create_retry` phase: finds devmgr and the RTC driver, attaches to devmgr, stops and starts its main thread, and kills the RTC driver; `timed_rtc_restart` phase: finds and kills the RTC driver and timed; `vfsd_driver_death` phase: finds and kills the `/data` fatfs driver, `RESTART_BURST` plus one times, the first time by pointing two of its threads at exit syscalls; `memmgr_swap` phase: finds the fixture child and attaches to it and to logd, reads their memory, and sends `MAKE_RESIDENT` for every process; `memmgr_node_reclaim` phase: sends `MAKE_RESIDENT` for every process; `memmgr_swap_client` phase: the same for its fixture child, and every other process's ranges; `memmgr_swap_raw` phase: the same, and `MAKE_RESIDENT` of one chunk of its fixture child; `swapd` phase: the same, and attaches to, stops, and reads the stacks of swapd, devmgr, virtio-blk, and the IOMMU driver, and kills swapd; `devmgr_iommu_restart` phase: finds and kills the IOMMU driver; `svcmgr_stop_service` phase: `LIST_PROCESSES` for `stopsrc`'s job; `memmgr_memory_object_text` phase: finds its child and svctest itself, and sends `MAKE_PRIVATE` for each; `procmgr_image_sharing` phase: finds its children, and sends `MAKE_RESIDENT` and `MAKE_PRIVATE` for them; `procmgr_snapshot` phase: finds its child and sends `SNAPSHOT` for it, and for its badge once it has exited; `memmgr_swap` and `swapd` phases: send `SNAPSHOT` for the fixture child; svctest declares itself undebuggable at startup |
| `caps[24]` | (`stop_authority`) | `svcmgr_stop_service` phase: svcmgr's `STOP_CANDIDATE`, `LIST_CANDIDATES` and `LIST_STOP_SOURCES`; `sessiond_operator` and `oom_policy` phases: `LIST_STOP_SOURCES` for sessiond's stop SEND; `oom_policy`, `logd_reserve` and `rtc_create_retry` phases, no-stop case: `LIST_CANDIDATES` and `STOP_CANDIDATE` of memhog |

The svcmgr seed-only phase also reads every seed-only slot and fails when any is zero, as evidence
that its name is published, the ten `devmgr.class.*` names among them. `caps[2]` carries
`REGISTRY_QUERY_AUTHORITY` alone, so it drives the devmgr deny phases, which require an
`UNAUTHORIZED` reply to `QUERY_DEVICE`, `QUERY_DEVICE_LOCATION`, `WATCH_CLASS`, and
`MINT_CLASS_SEND` (on `caps[2]` and `caps[3]`, neither of whose badges carries a class slot),
`QUERY_SHUTDOWN_DEVICE`, and `BIND_DRIVERS`. `caps[3]` carries
`REGISTRY_QUERY_AUTHORITY | BIND_AUTHORITY` as a `SEND|GRANT`, since `BIND_DRIVERS` moves a cap to
devmgr; it is the one devmgr seed that arrives with GRANT, and the on-demand-bind phase sends
`BIND_DRIVERS` on it. `caps[7]` and `caps[8]` are the `serial` and `input` class SENDs. The
input-ordinal phase waits on a `WATCH_CLASS` watch (bounded by `DEVICE_WAIT_MS`) until devmgr serves
an input driver, then requires a cap from `QUERY_DEVICE` on `caps[8]` at instance ordinal 0 (sent
and absent) and `NO_DEVICE` past the one keyboard of every boot's device set. The device-location
phase waits, the same way, until devmgr serves an input and a serial driver, then requires
`QUERY_DEVICE_LOCATION` on `caps[8]` to locate instance ordinal 0, a PCI function, and to answer
`NO_DEVICE` at ordinal 1, and on `caps[7]` to answer `NO_LOCATION` at ordinal 0, the serial driver's
UART being a platform device. The drivers stray-cap phase takes granted SENDs on the serial and
input drivers' endpoints through `caps[7]` and `caps[8]` (`QUERY_DEVICE`) and floods each driver
with calls carrying `MSG_CAP_SLOTS_MAX` caps: an unknown label, a zero-byte `SERIAL_WRITE_BYTES`,
`SERIAL_READ_BYTES`, a `SERIAL_REGISTER_RX_NOTIFY` whose stray notification `SYS_IRQ_REGISTER`
rejects, and one whose fresh notification each call rebinds the UART line to. It requires each
call's normal reply and each cap to leave svctest's `CSpace`. A driver that keeps a cap it should
delete exhausts its `CSpace` within one case and exits on its failing receive. For the input driver,
devmgr's withdrawal then fails the call in flight, and the phase fails. For the serial driver,
logd's writes stall on it, and the boot ends as a `HANG`. The svctest image stages no program, so no
terminal reads the UART or the input driver beside these cases. The same phase floods the virtio-rng
driver, through a granted SEND from `caps[16]`, with two cases: an unknown label (`UNKNOWN_OPCODE`)
and `READ` with no data word (`SUCCESS`, zero bytes). It floods the RTC driver, through a granted
SEND from `caps[19]`, with an unknown label (`UNKNOWN_OPCODE`) and `RTC_GET_EPOCH_TIME` (`SUCCESS`),
and the framebuffer driver, through a SEND from `caps[13]`, with an `FB_WRITE_BYTES` the driver
refuses for its badge (`UNAUTHORIZED`), which stands for every label, since the driver checks the
badge before the label; on a headless boot, with no framebuffer driver, that case logs
`framebuffer case skipped`, and the phase goes on to the serial and input cases. `caps[11]` to
`caps[13]` are the `serial-deny`, `input-deny`, and `framebuffer-deny` class SENDs, and `caps[17]`
the `hwrng-deny` class SEND, each published from a class file of `/config/devmgr/tests/` that names
its class with `class =` and carries `verbs = 58`, a verb mask none of the drivers checks; a
`QUERY_DEVICE` on one hands the drivers deny phase a SEND on the serial, input, framebuffer, or
hwrng driver's endpoint badged with none of the driver's verb bits. That phase requires an
`UNAUTHORIZED` reply to `SERIAL_WRITE_BYTES`, `SERIAL_READ_BYTES`, `SERIAL_REGISTER_RX_NOTIFY`, and
`INPUT_READ_EVENTS` (at once, without blocking for a key), and `READ` on the `hwrng-deny` SEND, and
to `FB_WRITE_BYTES` and `FB_SET_ATTRS` when a framebuffer driver runs; on a headless boot, CI's,
devmgr runs none and the framebuffer case logs a skip, which the framebuffer device cell
([docs/testing.md](../../docs/testing.md#coverage-tiers) § Coverage tiers) fails on. The
`logd_sinks` phase's framebuffer cases log the same skip on such a boot
([`logd_sinks.rs`](src/phases/logd_sinks.rs) states its cases). The drivers hwrng read phase
waits (bounded by `DEVICE_WAIT_MS`) for a granted SEND from `caps[16]`, then requires two `READ`
calls of `MAX_READ_BYTES` (504) each to answer `SUCCESS` with at least 16 and at most 504 bytes, the
two answers to differ, and `READ(0)` to answer zero bytes. The drivers hwrng restart phase kills the
virtio-rng driver through `caps[23]`, requires its ordinal on `caps[16]` to answer `WITHDRAWN` and
the class's next ordinal to answer with a new instance, and requires a `READ` through that instance
to answer with bytes. The `rtc_create_retry` phase runs just before `timed_rtc_restart`; it skips
when the staged fixture set does not declare it, and logs the skip line ([docs/testing.md §
Gating](../../docs/testing.md#gating)). It stops devmgr's main thread, which runs every driver
restart, through `caps[23]`, kills the RTC driver and waits until procmgr no longer lists it, then
has [memhog](../fixtures/service-modes/README.md#memhog) fill the pool down to the growth floor and,
once the level reads `CRITICAL`, starts devmgr's main thread again, so devmgr's restart of the
driver makes its create while no page is left to a driver outside the system reserve, and procmgr
refuses it. It requires devmgr's line for the refusal and its first retry in logd's history through
`caps[6]`, stamped after the kill; once oomd's stop of memhog, or svctest's own through `caps[24]`
when no oomd stops it, has ended the window, devmgr serving the retried driver at the `rtc` class's
next ordinal on `caps[19]` within 90 s, before the next phase kills it, since devmgr restarts no
driver that dies before its batch settles and serves it, and that driver a new process; and devmgr's
line for a retry of its create ([devmgr
responsibilities](../devmgr/docs/responsibilities.md#create-retry)). The `timed_rtc_restart` phase
kills the RTC driver (`cmos-rtc` on x86-64, `goldfish-rtc` on riscv64) through `caps[23]` and waits
for devmgr's restart of it, then kills timed (its recipe's `argv = timed` names it), and requires
`SystemTime::now()` to give a time between 2024 and 2100 again within 30 s: the restarted timed
resolves the RTC past the withdrawn ordinal ([services/timed/README.md](../timed/README.md)).

The `logd_sinks` phase's framebuffer-restarted case queries the framebuffer class's ordinal 1
through `caps[13]`, finds, attaches to, and stops the instance devmgr restarted through `caps[23]`,
sends as many lines at critical as the stopped case, each answered within half logd's stall bound,
starts the instance, and requires logd's notice of the framebuffer's drops after the last of them
through `caps[6]`.

The `logd_flush` phase ([`logd_sinks.rs`](src/phases/logd_sinks.rs) states its cases) checks logd's
flush barrier through `caps[22]`: `LOG_FLUSH` on `caps[6]` and `QUERY_SLOTS` on `caps[22]` are
refused, and a flush is answered `FLUSHED` with the serial driver running. With the serial driver
stopped through `caps[23]`, a flush is answered `FLUSH_PENDING` before the stall bound has passed
and `FLUSHED` within twice it.

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
`UNAUTHORIZED` to `GET_SWAP_PARTITION` on `caps[4]` and `caps[5]`, and
`LABEL_VERSION_MISMATCH` on `caps[14]` for a stale version; no hand-out is made, since a hand-out
would revoke the partition cap swapd holds. The
`vfsd.mount` and `vfsd.deny` seeds ride in a second bootstrap round, so every svctest boot
receives a seed list longer than one round, and the svcmgr second-seed-round phase fails the run
when either arrives empty.
The svcmgr stray-cap phase floods svcmgr, through `caps[20]`, with 512 calls of each of seven
cases, every call carrying `MSG_CAP_SLOTS_MAX` caps: an unknown label (`UNKNOWN_OPCODE`),
`HANDOVER_COMPLETE`, `PUBLISH_ENDPOINT`, `STOP_CANDIDATE`, `LIST_CANDIDATES`, and
`LIST_STOP_SOURCES` (`UNAUTHORIZED`, since the badge carries no verb bit), and `QUERY_ENDPOINT` of
an unpublished name (`UNKNOWN_NAME`). It requires each call's reply, with no cap, and each cap to
leave svctest's `CSpace`. A svcmgr that kept the caps exhausts its `CSpace` within one case, its
failing receive ends it, and its death is a system death, so the boot ends without the pass
marker.
`caps[6]` is a SEND on the master log endpoint badged `LOG_QUERY_AUTHORITY` ([logd IPC
interface](../logd/docs/ipc-interface.md) § Queries); the `logd_death_forward` phase reads its dead
child's retired slot and history through it, and requires `QUERY_DENIED` for a query on svctest's
own log cap.
The `logd_restart` phase kills logd through `caps[23]`: it finds logd by name
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

The `logd_reserve` phase, just before it, skips when the staged fixture set does not declare
`memhog`. It requires logd's budget node to be a system-reserve node, as logd's recipe's
`reserve = yes` makes it ([`.svc` Service Definitions](../svcmgr/docs/service-definitions.md) §
`reserve`): the attach to the running instance and the attach to the next must each report
`ATTACH_FLAG_RESERVE`. Between them it kills logd in the same way while
[memhog](../fixtures/service-modes/README.md#memhog) holds memory at the system reserve, and
requires the next instance to run and serve before the level falls. Outside the reserve the create
of the next instance and every first touch of its heap and stacks are refused while memhog holds the
pool, except from the frames the kill frees until memhog's next tick takes them back, so the attach
flags, not the timing, are what fail for a logd outside the reserve. It attaches to logd before the
fill, has memhog fill the pool, faults logd's main thread as soon as the level reads `CRITICAL`, and
waits for the level to fall: oomd's stop of memhog ends the window when oomd is staged in its stop
mode, and svctest's own stop through `caps[24]`, 5 s after the fill, otherwise. It then requires,
through `caps[6]`, svcmgr's `service restarted: logd` line in the new instance's history stamped
before svcmgr's `stop memhog` line, the first of each after the kill, and memhog's next instance to
answer `PROBE` with a new nonce and no pages. svcmgr writes the stop line once procmgr has destroyed
memhog, which frees the memory, and serves a stop and a restart on one event loop ([Restart
Protocol](../svcmgr/docs/restart-protocol.md) § Death detection), so a stop asked for while it
restarts logd waits for the restart, and the order of the two lines is the order of the restart and
the stop, however long the restart takes. The kill comes first in the window because logd's death
reaches svcmgr only once crashd, which every svctest set but `crash-endpoint` stages, has reported
the fault, and the restart has to come before oomd's stop, its grace after the level reads
`CRITICAL`.

In the same window the `logd_reserve` phase makes three more checks (`critical_creates.rs`), the
second and third skipped, each logging the skip line, when the staged set does not declare their
fixture; they share its window because svcmgr restarts memhog at most three times a window and the
boot's other memhog windows spend them. After the kill, check 1: svctest's own raw
`CREATE_FROM_FILE` of `/tests/fixtures/programs/spawn-target`, outside the reserve, must be refused
with `OUT_OF_MEMORY` and no other label, the one label svcmgr's memory wait for a restart holds; the
phase destroys each child it creates, waits for memhog's next tick to take back what the destroy
freed, and tries up to four times, so a create the killed logd's freed frames serve before that tick
is made again. Check 2 runs when the set declares `reserve-creator`: the fixture, a service in the
system reserve, makes a `CREATE_FROM_FILE | CREATE_RESERVE` of
`/tests/fixtures/programs/spawn-target` inside the window, which must succeed. After the kill, check
3 runs when the set declares `crasher-worker`: the phase has the fixture's worker fault inside the
window and requires the fixture's next instance to answer, after the window, with a new nonce. Check
3 passes whether or not its restart falls in the gap the killed instances' freed frames open before
memhog's next tick, as for logd above, so it shows the restart is held and made, not that the
refusal was `OUT_OF_MEMORY`, which check 1 shows.

Every seed is seed-only in svcmgr's registry. The no-authority `pwrmgr.deny` cap is
public, so svctest resolves it through `QUERY_ENDPOINT` on its per-process `service_registry_cap`
and spends no seed slot on it; it drives the pwrmgr cap-deny phase, which requires an `UNAUTHORIZED`
reply to `SHUTDOWN`. The public `acpid.deny` is resolved the same way and drives the
`acpid_power_deny` phase, which requires an `UNAUTHORIZED` reply carrying no cap to `SLEEP(5)`,
to `QUERY_SLEEP(5)`, to `RESET` and to `WAIT_EVENT`.

The `svcmgr_worker_fault_restart` phase skips when the staged fixture set does not declare
`crasher-worker`; declared, it fails if `crasher.worker` is not published within 10 s. It reads the
instance's nonce with `PROBE_INSTANCE`, sends `PROBE_FAULT_WORKER` so a worker thread of the fixture
faults, and requires a different nonce from the instance svcmgr restarts
([crasher](../fixtures/service-modes/README.md#crasher)).

The `svcmgr_boot_death` phase skips when the staged fixture set does not declare `crasher-boot`;
declared, it fails if `crasher.boot` is not published within 10 s. It checks that svcmgr routes the
death of a service that dies before its bootstrap request ([Restart Protocol § Death
detection](../svcmgr/docs/restart-protocol.md#death-detection)). The fixture's instance that finds
the token `/data/crasher-boot/die-early` removes it and faults before its request, and any other
serves `PROBE_INSTANCE` and `PROBE_FAULT_WORKER` on `crasher.boot`. The data partition ships the
token, so the first launch dies so: the phase requires an instance's nonce, which only an instance
svcmgr started after routing that death answers, and the token gone. It then writes the token, sends
`PROBE_FAULT_WORKER`, and requires a different nonce and the token gone: the restart after the
worker's fault took the token and died before its request, and a later restart answered. It writes
the token again at its end, so a later boot of the same image repeats the first-launch case.

The `svcmgr_one_shot_death` phase, which runs right after it, skips when the staged fixture set does
not declare `crasher-once`; declared, it fails if `crasher.once` is not published within 10 s. It
reads the instance's nonce with `PROBE_INSTANCE`, sends `PROBE_FAULT_WORKER` so a worker thread of
the fixture faults, and requires svcmgr's `service died: crasher-once` line and then its `restart
policy says no restart` line in logd's history ([restart
protocol](../svcmgr/docs/restart-protocol.md)).

The `svcmgr_stop_service` phase checks the stop authority ([svcmgr IPC
Interface](../svcmgr/docs/ipc-interface.md) § Stop authority). Through the per-process
`service_registry_cap`, `STOP_CANDIDATE`, `LIST_CANDIDATES` and `LIST_STOP_SOURCES` must reply
`UNAUTHORIZED`. Through `caps[24]`, the whole `LIST_CANDIDATES` walk must list exactly the staged
fixtures whose recipes set `oom_stop = yes` (`crasher-worker` and `memhog`, each when the staged set
declares it), each with a non-zero usage and the service rank, and nothing when it declares neither;
`STOP_CANDIDATE` must reply `NO_CANDIDATE` for the first instance's key of every svcmgr table slot
below 32 it does not list, which covers svctest itself (`restart = never`), the services init
started, logd (`critical = yes`), pwrmgr, entropyd and `stopsrc` (core roles), timed (no `oom_stop`)
and the slots past the table. The whole `LIST_STOP_SOURCES` walk must list exactly
[sessiond](../sessiond/README.md), and [stopsrc](../fixtures/service-modes/README.md#stopsrc) when
the staged set declares it, both with the program class; through the SEND it carries, the fixture's
`LIST_CANDIDATES` must reply `SUCCESS`, `STOP_CANDIDATE` of a key it never gave `NO_CANDIDATE`, and
stopsrc's `PROBE` `SUCCESS`, and through the fixture's `:deny` SEND, which `QUERY_ENDPOINT`
resolves, both must reply `UNAUTHORIZED`. With `stopsrc` declared, the phase also checks that svcmgr
creates the source contained: through `caps[23]`, `LIST_PROCESSES` must list one new process named
`/tests/fixtures/service-modes`, the job's first argv word, after `START_JOB`; once the fixture has
exited (`EXIT`, which leaves the job running) and its next instance answers `PROBE` with a new
nonce, the job's badge must leave the list within 2 s. With `crasher-worker` declared,
`STOP_CANDIDATE` of its listed key must reply `SUCCESS`, the fixture must then answer
`PROBE_INSTANCE` with a new instance's nonce, the restart its `on_failure` policy makes of the
`EXIT_KILLED` death, and the same key must then reply `NO_CANDIDATE`; without it, the phase logs the
skip line for that part after the checks above.

The `oom_policy` phase (`phases/oom.rs`, registered after the svcmgr phases) skips when the staged
fixture set does not declare `memhog`. It waits for the pressure level to read `NORMAL`, sends
`PROBE` to [memhog](../fixtures/service-modes/README.md#memhog) (a nonce, 0 pages) and then `HOG`,
which fills memory until the level reads `CRITICAL`. With oomd's `OOMD_STOP=yes`, it waits for the
level to fall to `NORMAL` and checks that oomd logged exactly one `stopped memhog: ` line after at
least its grace critical, and no advice line. The phase also opens, through `caps[15]`, an operator
session whose leader runs `/tests/fixtures/programs/crashme oom-hold 512`, a job larger than
`stopsrc`'s; oomd must log one `stopped /tests/fixtures/programs/crashme: ` line before its stop of
`stopsrc`'s job, then stop the session, whose relay gives the leader's end, and then memhog. When
the set declares `stopsrc`, the phase first sends the fixture `EXIT`, waits for its restarted
instance's new nonce, so the source oomd finds started after oomd, and has it start a job of 64
pages; oomd must then log one `stopped stopsrc-job: ` line before its stop of memhog, and the
fixture must report the job stopped. When crashd is staged with a stall, a child
(`/tests/fixtures/programs/crashme oom-touch 1024`) writes the pages of a demand region in turn
during the fill, and crashd logs the write memmgr declines held, then resumed; the child's `go`
waits until sessiond lists no candidate, so crashd's hold covers only memhog's stop. The pages
oomd's last stop freed lie above the reserve until memhog's next top-up takes them back, and the
child's writes spend them, so one write is always declined. The phase first checks that crashd's
stall outlasts what oomd takes from the write to memhog's stop: a cooldown. With `OOMD_STOP=no`, it
checks that memhog stays running and the level stays `CRITICAL` past the grace, the cooldown and
2000 ms, that oomd logged at least one `would stop ` line, which names the operator session while
one is open, and no stop, and then stops memhog itself through `caps[24]`, by the key svcmgr listed
it under before the fill. In every case memhog's next instance answers `PROBE` with a new nonce and
0 pages ([oomd](../oomd/README.md)).

The `sessiond_operator` phase (`phases/sessiond.rs`, right after the svcmgr phases) fails when
`caps[15]` is not set. Through the stop SEND svcmgr hands svctest for sessiond, operator labels must
reply `UNAUTHORIZED`, as must stop labels through the operator SEND. `OPEN_SESSION` under an
unregistered nonce replies `UNKNOWN_INTERFACE`, `REGISTER_INTERFACE` of another version
`VERSION_MISMATCH`, and a second one under one nonce `INVALID_ARGUMENT`. A cap of the wrong type or
rights replies `INVALID_ARGUMENT`: a POST cap as `REGISTER_INTERFACE`'s end queue, a RECV cap as
`OPEN_SESSION`'s relay, and a notification as `SESSION_STDIO`'s memory cap, which also ends the
session, whose relay is then posted. A session runs the [`leader`](../fixtures/leader/README.md)
fixture (`echo`), lists with `RANK_SESSION` under its key and its job
(`/tests/fixtures/programs/crashme oom-hold 16`) with `RANK_JOB` under
`/tests/fixtures/programs/crashme` with at least 16 pages; `STOP_CANDIDATE` of the job leaves the
leader answering. The leader's exit gives status 0 on the relay and its key `NO_CANDIDATE` after; a
second session stopped whole gives `EXIT_KILLED` ([sessiond](../sessiond/README.md)).

---

## Child Modes

Several phases respawn `/tests/svctest` with a role token as `argv[1]`. `main` hands the token
to `reentry::dispatch`, which tries each owning module's `reentry_main`; a matching role runs
its child body and exits (`park-child`, `reclaim-child`, `open-reclaim-child`, `node-reclaim-child`,
and `no-receiver-child` park until their spawner tears them down), and an unmatched token falls
through to the normal run.

| Role                        | Owning module  | Spawned by                                  |
|-----------------------------|----------------|---------------------------------------------|
| `sandbox-child`             | `namespace`    | `ns_sandbox` (namespace attenuation)        |
| `fixtures-child`            | `namespace`    | `ns_fixtures_subtree` (fixtures subtree)    |
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
| `session-undeliverable-child` | `fs_opens` | `fs_reclaims_dead_opens` (failed session reply) |
| `fs-session-client`         | `fs_sessions`  | `fs_sessions` (exits holding a session)     |
| `fs-create-open-full`       | `fs_create_open` | `fs_create_open` (session full at its max) |
| `fs-create-open-cwd`        | `fs_create_open` | `fs_create_open` (create in the cwd at its max) |
| `fs-create-open-send-only`  | `fs_create_open` | `fs_create_open` (grant-less root)       |
| `reclaim-child`             | `memmgr`       | `frame_reclaim_live_object` (held endpoint) |
| `scrub-child`               | `memmgr`       | `memmgr_frame_scrub` (frames of a death)    |
| `exit-code-zero`            | `exit_code`    | `exit_code`                                 |
| `exit-code-nonzero`         | `exit_code`    | `exit_code`                                 |
| `exit-code-thread`          | `exit_code`    | `exit_code_thread` (exit off main)          |
| `exit-code-thread-race`     | `exit_code`    | `exit_code_thread_race` (main exits after)  |
| `recv-wedge-thread`         | `recv_guard`   | `recv_wedge_thread` (wedge off main)        |
| `no-receiver-child`         | `no_receiver`  | `call_no_receiver` (killed, call queued)    |
| `random-diverge-child`      | `random`       | `random` (per-process hash seed)            |
| `aslr-layout-diverge-child` | `random`       | `aslr-layout` (per-process layout tuple)    |
| `stale-map-child`           | `unmount`      | `vfsd_unmount_stale_mapping` (mapped page)  |
| `budget-child`              | `budget`       | `procmgr_memory_max` (4096-page max)        |
| `node-handle-child`         | `node_handle`  | `memmgr_node_handles` (max set by handle)   |
| `node-reclaim-child`        | `node_reclaim` | `memmgr_node_reclaim` (fills a region, parks) |
| `heap-commit-limited`       | `heap_commit`  | `memmgr_heap_commit` (4096-page max)        |
| `heap-commit-hog`           | `heap_commit`  | `memmgr_heap_commit` (commits to the bound) |
| `discard-hog`               | `discard`      | `memmgr_discard_range` (refault at the bound) |
| `heap-release`              | `discard`      | `memmgr_discard_range` (heap discard, trim) |
| `memory-object-child`       | `memory_objects` | `memmgr_memory_objects` (attaches, writes) |
| `memory-object-limited`     | `memory_objects` | `memmgr_memory_objects` (4096-page max)   |
| `memory-object-text`        | `memory_object_text` | `memmgr_memory_object_text` (calls an executable attachment) |
| `image-sharing`             | `image_sharing` | `procmgr_image_sharing` (reports its image base, waits) |
| `snapshot-child`            | `snapshot`     | `procmgr_snapshot` (an unregistered writer thread, an object, a zero and a demand fixture, reports their addresses) |
| `checkpoint-child`          | `checkpoint`   | `procmgr_checkpoint` (quiesces on command, reports each outcome) |
| `checkpoint-pinned`         | `checkpoint`   | `procmgr_checkpoint` (pinned; sends `QUIESCE`, reports the reply) |
| `restore-child`             | `restore`      | `procmgr_restore` (holds each value on command, quiesces, reports its restore) |
| `swap-fixture`              | `swap`         | `memmgr_swap`, `memmgr_swap_client`, `memmgr_swap_raw`, `swapd` (evicted regions, threads) |
| `swap-commit-writer`        | `swap_commit`  | `memmgr_swap_commit` (writes past the draw room) |
| `pipestress-spawner`        | `pipestress`   | `pipestress` (spawn-drain loop, doorbell trial) |
| `reboot`                    | `pwrmgr`       | the `reboot.svc` test recipe (`shutdown` case) |

---

## Fixtures

Phases spawn these fixtures from `/tests/fixtures/programs/`
([services/fixtures/README.md](../fixtures/README.md)): `spawn-target` (procmgr, pipes and the other
spawning phases: whatever its arguments it prints `spawn-target ran` and exits 0), `stdiotest`
(pipes, procmgr), `program-modes`
([services/fixtures/program-modes/README.md](../fixtures/program-modes/README.md)), one image run
in a mode per phase: `narrow` (procmgr: it tries to start `/tests/fixtures/service-modes` and
exits 0 only when refused `PermissionDenied`), `pipefault` (pipes), `stackoverflow` and
`relrofault` (process faults and console whole lines), `capexhaust` (recv guard and console whole
lines), `demandpaged` (pager), `threadchurn`,
`threadstack`, `deadline` and `pipestress` (their own phases), `fsbench` (FS IPC), and `crashme`
(`oom-hold <pages>`, run by its path through a session's leader by the `sessiond_operator` and
`oom_policy` phases: it touches that many heap pages, prints `holding <pages>` and waits to be
destroyed; and the crash endpoint: svctest, its recipe granting `debug_authority`, registers as the
crash service and takes a `crashme` child's forwarded page fault, and the faults of two `registry-*`
children, whose attach lists their live registered threads and none that exited or was joined, and
whose spawned thread's crash badge names it; on the first of those it acts as a debugger, finding
the child with `LIST_PROCESSES` and having procmgr restore a registered thread it rebound, by
`DETACH_PROCESS` and then by an attach's watch thread exiting; acts as the debugger of a
`debugger-tag` child, whose thread registering with a gone debugger's binding is bound back to the
crash endpoint and whose declaration, with svctest attached and watched, unbinds svctest's bindings
and leaves no watch to bind it back; has procmgr unbind a debugger's binding from a thread of its
own whose registration it refuses, svctest having declared itself undebuggable; then gives the
endpoint back and sees a second child declined by procmgr; and, for the `oom_policy` phase, an
`oom-touch` child whose write crashd holds while memory is critical). The devmgr on-demand-bind
phase registers a `WATCH_CLASS` watch on `caps[10]`, then sends `BIND_DRIVERS` on `caps[3]` over
`/tests/drivers/`, which no drivers-directory pass at boot reads, so devmgr binds the
[`test-fault`](../drivers/test-fault/README.md) driver to the QEMU `pci-testdev` functions that
`--test-devices` attaches, one instance each. The phase asks `caps[10]` for the fixtures: the two
serving instances hold instance ordinals 0 and 1, and ordinal 2 answers `NO_DEVICE`;
`QUERY_DEVICE_LOCATION` locates ordinals 0 and 1 at the `pci-testdev` functions `0000:00:15.0` and
`0000:00:16.0` and answers `NO_DEVICE` at ordinal 2; and logd's history (`caps[6]`) holds devmgr's
line for the death of the instance devmgr binds between them, which exits before its next bootstrap
request, so devmgr abandoned that bind and went on binding; `FAULT_EXIT` on ordinal 0 makes the next
`QUERY_DEVICE` and the next `QUERY_DEVICE_LOCATION` on it answer `WITHDRAWN`; `FAULT_WORKER` on
ordinal 1, whose worker thread then faults, returns a call queued on it and makes the next query on
it answer `WITHDRAWN`; the free pool then returns to its size before the bind, so the instance that
never reports ready and the instance that fails its bootstrap's terminal round were destroyed; and a
second `BIND_DRIVERS` over the directory binds nothing. The watch, registered at ordinal count 0, is
signalled when the bind serves the fixtures and again at each withdrawal. With that watch held, the
phase fills the class to `MAX_CLASS_WATCHERS` (8): the next registration is refused `WATCHERS_FULL`,
and once it deletes one watch a new registration is admitted. The DMA confinement phase waits on a
`WATCH_CLASS` watch on `caps[9]` (bounded by `DEVICE_WAIT_MS`) until devmgr serves the
[`test-dma`](../drivers/test-dma/README.md) fixture, which devmgr binds to QEMU's `edu` device
(attached by `--test-devices` on both architectures) by its declaration at `SET_DRIVERS_DIR`, and
asserts it is served; it then asks the driver to probe: a copy through a mapped page must arrive,
and where an IOMMU confines the device a copy to the page's device address after its unmap must not
reach the page, and devmgr must have taken an IOMMU fault for the device at that address. The
probe's reply carries, from devmgr's `DMA_FAULTS`, the confinement flag, the count of faults devmgr
took for the device, and the latest faulting address, which must be the page of the unmapped
address. Without an IOMMU it checks the mapped copies only and requires no fault. The MSI delivery
phase queries the same fixture the same way and asks it to have the `edu` device raise its interrupt
(`INTERRUPT_PROBE`): the fixture must hold the device's MSI vector, which devmgr gives a declaration
that asks for MSI and DMA, not its wired line, and the message must reach the fixture's notification
within `INTERRUPT_WAIT_MS`, with or without an IOMMU. The MSI forge phase (`devmgr_msi_forge`) asks
the fixture for `MSI_FORGE`: where an IOMMU confines the device and the fixture holds an MSI vector,
the device's DMA engine writes the fixture's own message (read with `SYS_CAP_INFO`) to its own
address, which must reach the fixture's notification, then to a forged address, which must not. On
riscv64 the forged address is the interrupt file page beside the target's, which the device's domain
does not map, and devmgr must count an IOMMU fault for the device at that page. On x86_64 the own
message is remappable and the forged address is a remappable message naming handle `0xFFFF`, which
no remapping table entry holds; QEMU records no requester id for a fault the DMA engine's write
raises, so devmgr cannot attribute it and the check is non-delivery, not an attributed fault. An
unconfined device makes no forged write. The MSI churn phase asks the fixture for `INTERRUPT_CHURN`:
while a thread of the fixture has the device raise its MSI in a loop, the fixture deletes the
`Interrupt` cap bound to it, and then the bound notification's last cap and the binding's cap; after
each case a spare copy it binds to a new notification must receive the device's interrupt, the
fixture must hold MSI, and the loop must have raised. The IOMMU driver restart phase
(`devmgr_iommu_restart`) has the fixture start a DMA stream (`DMA_STREAM_START`): a page of its
memory stays mapped for the device while a thread of the fixture copies through it in a loop. Where
an IOMMU confines the device, the phase waits for at least eight rounds, kills the IOMMU driver
through the debug authority, and waits for a new instance of it and for the line devmgr logs when it
restarted the driver, read from logd's history, which must report at least one mapping installed
again and one hold released. The stream must then make further rounds with none failed, at the same
device address, and with the device's fault count unchanged; the fixture's DMA probe and interrupt
probe must pass as in the phases above, and a read of the bootstrap bundle's header from the root
filesystem must succeed. Without an IOMMU confining the device the phase is skipped. The MSI release
phase sends `FIXTURE_EXIT`, after which the fixture leaves its interrupt raised and exits; the phase
polls `caps[9]` until devmgr answers `WITHDRAWN` and asserts
`system_ram == kernel_reserved + pool_total`. devmgr releases the device, which frees the
message-signaled target it minted for it, on its control thread right after the class answers
`WITHDRAWN`, and no request svctest makes observes the release end, so the `ram_accounted_identity`
phase that ends the run asserts the identity again after it. The release phase runs last of the
phases that use the fixture, since no fixture serves the class again in that boot. The
`fs_block_faults` phase spawns a fatfs of its own from `/services/fs/fatfs` through procmgr,
delivers it a block endpoint a thread of its own serves from a RAM FAT16 volume, and tears it down
with `DESTROY_PROCESS`. Its first case checks from the block server's log of writes that a 4 KiB
`FS_WRITE_MEMORY` over consecutive clusters is one `BLK_WRITE_FROM_MEMORY` of its sectors, and that
a run write the server drops fails the write and leaves the run's cached sectors as they were. Its
last cases end their driver themselves, each observed through an event queue bound to the driver's
main thread: the block server revokes every capability derived from its endpoint, two more drivers,
each on a volume of its own, take `FS_UNMOUNT`, and a fourth loses its service endpoint as vfsd ends
a driver it cannot use and must exit at its next receive. The `fs_pressure_release` phase before it
starts a fatfs the same way, loses one cache page's cap in a read the block server fails, drives
memmgr's level to `Low` and back as `memmgr_pressure` does, and checks from the block server's log
of reads that the driver gave back every idle cache page but the one svctest still maps and the few
it keeps, the lost cap's page among them, with its children's charge falling to match and memmgr's
pool total unchanged. The `fs_run_fill` phase after it starts fatfs the same way four times on one
volume: from the block server's log of reads, a sequential `FS_READ_MEMORY` scan of a file fills
runs of more than a page and at most `fat_parse::RUN_PAGES` pages, and a read off the sequence fills
one page; a scan whose first run read loses its Memory cap fills one page at a time from there, and
a write after it still succeeds; then an open whose chain cursor stands deep in the file reads the
file's new bytes after a truncate and rewrite give the file the same first cluster and different
later links. The FS, namespace, and procmgr phases read `/data/test.txt`; the FS phases also read
the build-synthesised `/data/svctest/large.bin` and write their scratch files under
`/data/svctest/`; `fsbench`, spawned by the `fs_crossover_bench` phase, reads the build-synthesised
`/data/svctest/bench.bin`, which the `fs_eviction_routes_release_to_its_open` phase also holds open,
and creates, rewrites and removes the scratch file `/data/svctest/fsbench-write.bin`. The vfsd
unmount phases hold `/data/test.txt` and `/data/svctest/large.bin` open across an unforced and a
forced unmount of `/data`, and a `stale-map-child` maps a cache page of `/data/test.txt`; while
`/data` is unmounted they mount the data partition over `/config/svcmgr/tests`, the root
filesystem's directory of svctest's own recipe, read `test.txt` there, and after unmounting it read
`/config/svcmgr/tests/svctest.svc` through the fall-through again. The `vfsd_driver_death` phase
holds a file on `/data` open and kills the data mount's fs driver (found by its name `fatfs:/data`)
through a debug attach `RESTART_BURST` times; the first time a worker thread ends the driver with
exit code 43 and its main thread then exits with 44 (`phases/thread_exits.rs`), and vfsd's line
about the death must carry the reason of code 43, the process's, which procmgr's relay gives. Each
time vfsd restarts the driver, a new `fatfs:/data` is listed, `/data/test.txt` reads again, `/data`
is never not found, and the open file is stale. One more kill finds the restart budget spent: vfsd
tears the mount down, `/data` falls through and is not found, and a fresh `MOUNT` at `/data`
succeeds on the same disk. They mount `/data` again and set svctest's cwd to it before they end. The
`vfsd_namespace_stray_caps` phase after them mounts the data partition over `/config/svcmgr/tests`
in place of `/data`, sends requests carrying caps through vfsd's synthetic `/config`, and mounts
`/data` again and sets the cwd to it before it ends. When a storage statement is staged
(`mkdisk --split-data`, which names the data partition on the disk at the second disk's slot for
`/data`), the data role at any other path resolves on the boot disk, which carries none: the unmount
phases mount nothing over `/config/svcmgr/tests`, the `vfsd_namespace_stray_caps` phase is skipped,
and the mounted-partition phase expects `NO_MOUNT` where it otherwise expects `TABLE_FULL`. The
sysroot placement of all of these is listed in [docs/testing.md § Sysroot
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
[services/drivers/test-dma/README.md](../drivers/test-dma/README.md),
[services/drivers/test-fault/README.md](../drivers/test-fault/README.md),
[services/fixtures/fsbench/README.md](../fixtures/fsbench/README.md),
[services/fixtures/program-modes/README.md](../fixtures/program-modes/README.md),
[services/fixtures/stdiotest/README.md](../fixtures/stdiotest/README.md),
[services/pwrmgr/README.md](../pwrmgr/README.md),
[`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)

