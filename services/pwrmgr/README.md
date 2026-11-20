# pwrmgr

Userspace power manager. Owns the platform shutdown and reboot path.

---

## Source Layout

```
pwrmgr/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs       # Entry, bootstrap, IPC dispatch loop, cap-gating, the core-death power-off
    ├── lib.rs        # Host-tested library: the modules below
    ├── guard.rs      # The allocation guard the core-death power-off runs under
    ├── core_death.rs # The core-death queue's entries: the member and the exit reason
    ├── power_off.rs  # The register the x86-64 core-death power-off writes, from QUERY_SLEEP
    ├── caps.rs       # svcmgr bootstrap: the service endpoint, the two seeds, the core-death queue
    └── arch/
        ├── mod.rs         # Arch dispatch: `arch::current` (Actuator, resolve,
        │                  # watch_events, shutdown, reboot, PowerOff,
        │                  # resolve_power_off, power_off_now)
        ├── x86_64/mod.rs  # acpid's SLEEP(5) and RESET; the power-button thread on WAIT_EVENT;
        │                  # PM1a_CNT or SLEEP_CONTROL_REG from acpid's QUERY_SLEEP
        │                  # and the S5 write
        └── riscv64/mod.rs # devmgr's SbiControl derivation; SBI SRST shutdown + cold reboot
```

---

## Responsibilities

pwrmgr owns the shutdown *interpretation*. devmgr is the hardware authority, and acpid
([services/acpid/README.md](../acpid/README.md)) holds the ACPI registers and runs the AML;
pwrmgr reads no table. The one hardware cap it holds of its own is for the death of a core service
(below): on x86-64 a derivation of acpid's capability over `PM1a_CNT`, or over
`SLEEP_CONTROL_REG` on a hardware-reduced platform. Each architecture uses one of
its two seeds and deletes the other at startup:

- **x86-64** — pwrmgr powers off with acpid's `SLEEP` of state S5 and reboots with acpid's
  `RESET` (the FADT's `RESET_REG`), through the `acpid.power` seed
  ([acpid § Power requests](../acpid/README.md#power-requests)). Without that seed pwrmgr logs
  `no acpid.power seed: SHUTDOWN and REBOOT cannot run` at error level at startup and serves
  degraded; a harness boot still passes on its marker then, and only stays up until its timeout.
- **RISC-V** — `devmgr_labels::QUERY_SHUTDOWN_DEVICE` on the `devmgr.shutdown` seed serves a
  Reset-only derivation of devmgr's `SbiControl` cap
  ([devmgr](../devmgr/docs/responsibilities.md#responsibilities)), which authorises forwarding
  `system_reset` through the kernel to M-mode firmware.

It exposes a small IPC surface (`shared/ipc/src/pwrmgr_labels.rs`):

- `SHUTDOWN` — power off the platform (ACPI S5 through acpid on x86-64, SBI SRST type 0
  on RISC-V).
- `REBOOT` — cold reboot the platform (the FADT's `RESET_REG` through acpid on x86-64, SBI SRST
  type 1 on RISC-V). `cargo xtask test-reboot` checks it on both
  ([docs/testing.md](../../docs/testing.md#reboot-test-reboot) § Reboot).

On x86-64 pwrmgr also acts on the power button. A thread of its own calls acpid's
`WAIT_EVENT` through `acpid.power` with no bound
([acpid § Events](../acpid/README.md#events)); on a press it logs
`power button: shutting down` and powers off as `SHUTDOWN` does. A call that fails in transit
(acpid died while holding it) is made again after one second, and a superseded one at once; a
`NO_DEVICE` reply (no SCI or no fixed power button) or any other refusal ends the thread, logged,
and pwrmgr goes on serving its labels. `cargo xtask test-powerbutton` checks the press
([docs/testing.md](../../docs/testing.md#power-button-test-powerbutton) § Power button). RISC-V
has no ACPI power button, and no such thread runs.

For both labels, on the success path the platform powers off or resets and
no reply is delivered. A reply only arrives when the request is rejected (see
the authority gate below), when pwrmgr cannot act on it (no actuator was
resolved at startup, so it serves degraded), when acpid refuses it or does not answer it within
30 s (`ACPID_CALL_TIMEOUT_MS`, so an acpid that is down or blocked fails the request instead of
holding pwrmgr and svcmgr's graceful shutdown), or when the platform
fails to act. Both failures reply `pwrmgr_errors::INVALID_REQUEST`, the latter
including a request the platform has not acted on one second (`RESET_GRACE`)
after its actuator returned. On x86-64 acpid answers a power-off only 10 s
after its writes ([acpid § Power requests](../acpid/README.md#power-requests)),
so a power-off the platform does not act on fails about 11 s after it was
issued, and a reboot about one second after.

Both labels are gated by `pwrmgr_labels::SHUTDOWN_AUTHORITY` (badge bit
`1<<63`). Calls without the bit reply `pwrmgr_errors::UNAUTHORIZED`.

pwrmgr owns the death of the core set, svcmgr, memmgr and procmgr
([docs/supervision.md](../../docs/supervision.md#core-set-and-system-death) § Core Set and System
Death). It waits on one wait set over its service endpoint and the receive-only derivation of the
core-death queue that svcmgr serves it (Cap flow below), on which svcmgr has bound the death
observers of all three ([docs/supervision.md](../../docs/supervision.md#observing-the-core-set)
§ Observing the Core Set). An entry on the queue is a core death, and pwrmgr powers the platform
off at once, by a path that needs no other service and none of the dead member's pages:

- svcmgr creates pwrmgr pinned (`CREATE_PINNED`), so none of its pages is demand-paged on memmgr
  or evicted by it.
- At startup pwrmgr resolves its immediate power-off: on RISC-V the same `SbiControl` derivation
  its `SHUTDOWN` uses; on x86-64 acpid's `QUERY_SLEEP` of S5
  ([acpid § Power requests](../acpid/README.md#power-requests)): a derivation of acpid's
  capability over the register its `SLEEP` writes, and the S5 `SLP_TYPa`. The register is
  `PM1a_CNT`, whose port block pwrmgr binds to its main thread, or, on a hardware-reduced
  platform, `SLEEP_CONTROL_REG`, whose port pwrmgr binds or whose page it maps into its own
  address space, the map's page tables funded then (`pwrmgr::power_off` reads the answer). With
  the queue observed, the power-off held and no pager advertised, it logs
  `core-death power-off armed`; otherwise it logs why the power-off is not armed at error level.
  Without a sleep register or a usable `\_S5_`, it is not armed.
- On an entry pwrmgr arms its allocation guard against its main thread, drains the queue, and
  powers off: SBI SRST on RISC-V; on x86-64 it reads `PM1a_CNT` and writes the S5 sleep type to
  it, then with `SLP_EN`, as acpid's `SLEEP` does, or writes the one byte that enters S5 to
  `SLEEP_CONTROL_REG`, a port write or a store to the page mapped at its start, but without the
  `\_PTS(5)`, the event quiescing and the clearing of `WAK_STS` acpid runs first. Nothing on that
  path allocates, frees, logs or calls a service; an allocation there fails, which ends pwrmgr
  without a power-off.
- Only when the platform keeps running, or no immediate power-off is held, does pwrmgr log
  `<member> died (exit reason <reason>); powering off` at error level and power off as `SHUTDOWN`
  does. A power-off that does not take effect, or the absence of an actuator, is logged, and pwrmgr
  serves on.

Without the queue, or when the wait set cannot be made, pwrmgr logs that a core death is
unobserved and receives on its endpoint alone. `cargo xtask test-core-death` kills svcmgr,
memmgr and procmgr, the last two once pwrmgr has logged that its power-off is armed, and checks
the power-off ([docs/testing.md](../../docs/testing.md#core-death-test-core-death) § Core death).
---

## Cap flow

1. svcmgr launches pwrmgr post-handover from its `pwrmgr.svc` recipe. The
   `provides = pwrmgr.shutdown:auth pwrmgr.deny:deny` directive makes svcmgr
   create pwrmgr's service endpoint, serve its RECV as bootstrap `cap[0]`,
   and publish two SENDs into the discovery registry: `pwrmgr.shutdown`
   (`SHUTDOWN_AUTHORITY`-badged) and `pwrmgr.deny` (a no-authority twin).
   The endpoint persists across restarts. Both behaviours are specified in
   [`provides`](../svcmgr/docs/service-definitions.md#provides).
2. `seed = devmgr.shutdown acpid.power` delivers, per
   [`seed`](../svcmgr/docs/service-definitions.md#seed), a `REGISTRY_QUERY_AUTHORITY |
   SHUTDOWN_DEVICE_AUTHORITY`-badged SEND on devmgr's registry as bootstrap `cap[1]`, and the
   `POWER_AUTHORITY`-badged SEND on acpid's endpoint as `cap[2]`; pwrmgr is the only recipe
   seeding either. RISC-V uses the first and x86-64 the second (see Responsibilities). svcmgr
   publishes `acpid.power` once acpid has launched, and launches acpid before pwrmgr because
   pwrmgr seeds it ([Reconciliation](../svcmgr/docs/service-definitions.md#reconciliation)).
3. Consumers permitted to power the platform off seed `pwrmgr.shutdown`
   (e.g. svctest); the badge rides through the registry lookup unchanged,
   and the name is seed-only, so `QUERY_ENDPOINT` does not hand it out
   ([`provides`](../svcmgr/docs/service-definitions.md#provides)). svcmgr's
   own critical-service-death escalation derives an equally badged SEND from
   pwrmgr's endpoint, because `pwrmgr.svc` declares
   `shutdown_actuator = pwrmgr.shutdown`
   ([`shutdown_actuator`](../svcmgr/docs/service-definitions.md#shutdown_actuator)). svctest
   also resolves the public `pwrmgr.deny`, the negative-test twin, to
   assert the gate rejects an unauthorised cap
   ([`provides`](../svcmgr/docs/service-definitions.md#provides);
   [svctest Capabilities](../svctest/README.md#capabilities)).
4. svcmgr creates pwrmgr, the recognised shutdown actuator, pinned, and serves
   it a RECV-only derivation of the core-death queue, which the death
   observers of svcmgr's, memmgr's and procmgr's main threads and address
   spaces post to, as bootstrap `cap[3]`, on its first launch and on every
   restart
   ([`shutdown_actuator`](../svcmgr/docs/service-definitions.md#shutdown_actuator)).
   The queue is svcmgr's, so its death observers outlive every pwrmgr
   instance, and the derivation keeps the queue alive past svcmgr's death.
   On x86-64 pwrmgr's `QUERY_SLEEP` call through `acpid.power` returns a
   derivation of acpid's `IoPort` over `PM1a_CNT`, or of its capability
   over `SLEEP_CONTROL_REG` on a hardware-reduced platform, an object of its
   own that outlives acpid's restarts.
5. svctest, at the end of `main()` after `ALL TESTS PASSED`, or from its
   failure hooks after `SOME TESTS FAILED`, sends
   `pwrmgr_labels::SHUTDOWN` through the authorised cap, per
   [Cross-harness conventions](../../docs/testing.md#cross-harness-conventions)
   and [svctest Run Sequence](../svctest/README.md#run-sequence).
   pwrmgr executes the platform shutdown sequence. QEMU exits cleanly,
   ending the staged `cargo xtask run` without a wall-clock wait.

---

## Restart semantics

pwrmgr is a `restart = on_failure` svcmgr service. Because it holds no
unique source caps, a crashed pwrmgr is recoverable: svcmgr re-creates it
from `/services/pwrmgr` and re-serves a fresh RECV on the persistent
service endpoint, so a `pwrmgr.shutdown` cap cached against the published
name survives the restart (see
[Supervision hierarchy](../svcmgr/docs/restart-protocol.md#supervision-hierarchy)).
The restarted instance is seeded again: `acpid.power` resolves to the same endpoint, which
outlives acpid's restarts too, and on RISC-V `QUERY_SHUTDOWN_DEVICE` re-derives the Reset-only
`SbiControl` derivation on every call from the cap devmgr holds, so nothing is consumed
([devmgr](../devmgr/docs/responsibilities.md#responsibilities)).

`critical = no`: a permanently-dead pwrmgr (restart budget exhausted)
cannot power the platform off, so the graceful-shutdown-via-`pwrmgr.shutdown`
escalation would be circular. The honest terminal state is logged and the
system continues degraded
([`critical`](../svcmgr/docs/service-definitions.md#critical)), matching
`timed`
([Supervision hierarchy](../svcmgr/docs/restart-protocol.md#supervision-hierarchy)).

---

## Future scope

Out of scope for v0.1.0; deferred until concrete consumers exist:

- **Suspend** (ACPI S3) and **hibernate** (ACPI S4) — RAM-image
  persistence, driver quiescence protocol, BSP/AP resume vector. RISC-V
  deep sleep via the SBI System Suspend (SUSP) extension.
- **Runtime power management** — per-device D-states, CPU C-states / idle
  governors, frequency scaling.
- **Battery and thermal monitoring** — ACPI `_BST` / `_TZ`, RISC-V
  platform sensors.
- **Operator UX** — `shutdown` / `reboot` CLI wrappers calling pwrmgr.
- **Cmdline-driven test-vs-shell mode** — naked `cargo xtask run` could
  drop into an interactive userspace shell instead of running
  tests-then-shutdown.

No code paths or labels are reserved for these. Each lands when its
acceptance criteria are written.

---

## Relationship to ktest

`core/ktest/src/arch/x86_64/acpi_shutdown.rs` and
`core/ktest/src/arch/riscv64/sbi_shutdown.rs`
hold ktest's own shutdown: the S5 write from the FADT and the `\_S5_` package on x86-64, which
pwrmgr leaves to acpid but for the write of its core-death power-off, whose port block and sleep
type acpid hands it, and the SBI call on RISC-V, which pwrmgr also makes. They are kept
deliberately separate so the kernel-validation harness, which runs no service, does not depend
on any userspace-service crate. The ktest copies are a frozen, single-purpose `shutdown(info)`.
There is no shared crate and no cross-reference between the two trees.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System-wide service inventory; pwrmgr's role |
| [docs/supervision.md](../../docs/supervision.md) | Supervision hierarchy; pwrmgr as the observer of the core set |
| [docs/testing.md](../../docs/testing.md) | Cross-harness completion convention; harnesses request pwrmgr shutdown when they finish |
| [shared/ipc/src/pwrmgr_labels.rs](../../shared/ipc/src/pwrmgr_labels.rs) | Authoritative IPC label definitions (`pwrmgr_labels`) |
| [shared/ipc/src/pwrmgr_errors.rs](../../shared/ipc/src/pwrmgr_errors.rs) | Authoritative IPC error definitions (`pwrmgr_errors`) |
| [shared/ipc/src/devmgr_labels.rs](../../shared/ipc/src/devmgr_labels.rs) | The `devmgr_labels` pwrmgr calls |
| [services/acpid/README.md](../acpid/README.md) | Evaluates the firmware's AML; serves the x86-64 sleep, sleep-register, reset and power-button requests pwrmgr calls |
| [services/devmgr/README.md](../devmgr/README.md) | Hardware authority; the `QUERY_SHUTDOWN_DEVICE` broker pwrmgr acquires its RISC-V cap through |
| [services/svcmgr/README.md](../svcmgr/README.md) | Launcher + supervisor; the provider path that publishes `pwrmgr.shutdown` / `pwrmgr.deny` |
| [services/svctest/README.md](../svctest/README.md) | Services-tier harness; seeds `pwrmgr.shutdown`, resolves the public `pwrmgr.deny` through `QUERY_ENDPOINT`, asserts the deny path, and requests the terminal shutdown |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md),
[init Bootstrap Stages](../init/docs/bootstrap.md),
[Restart Protocol](../svcmgr/docs/restart-protocol.md),
[`.svc` Service Definitions](../svcmgr/docs/service-definitions.md),
[services/svctest/README.md](../svctest/README.md)
