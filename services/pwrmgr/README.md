# pwrmgr

Userspace power manager. Owns the platform shutdown and reboot path.

---

## Source Layout

```
pwrmgr/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs       # Entry, bootstrap, IPC dispatch loop, cap-gating
    ├── caps.rs       # svcmgr bootstrap + devmgr-query acquisition
    ├── x86_64.rs     # ACPI S5 walk + PM1a write; 8042 KBC reboot
    └── riscv64.rs    # SBI SRST shutdown + cold reboot
```

---

## Responsibilities

pwrmgr owns the shutdown *interpretation* and *actuation* but holds no
hardware caps of its own. devmgr is the hardware and ACPI authority;
pwrmgr acquires only what it needs from devmgr at startup, "as if it were
a device driver":

- **x86-64** — the FADT and DSDT it parses are served read-only by devmgr
  via `devmgr_labels::QUERY_ACPI_TABLE` (devmgr is the sole owner of the
  `AcpiReclaimable` Memory caps and the only service that walks the ACPI
  table tree). pwrmgr extracts `PM1a_CNT_BLK` from the FADT and the `\_S5_`
  sleep type from the DSDT, then requests a narrow `IoPort` over the
  PM1a control port and the 8042 reset port via
  `devmgr_labels::QUERY_SHUTDOWN_DEVICE`.
- **RISC-V** — `QUERY_SHUTDOWN_DEVICE` serves a `cap_derive` copy of
  devmgr's `SbiControl` cap, which authorises forwarding `system_reset`
  through the kernel to M-mode firmware.

It exposes a small IPC surface (`shared/ipc/src/lib.rs::pwrmgr_labels`):

- `SHUTDOWN` — power off the platform (ACPI S5 on x86-64, SBI SRST type 0
  on RISC-V). On the success path the platform powers off and no reply is
  delivered. A reply only arrives on rejection or hardware-failure paths.
- `REBOOT` — cold reboot the platform (8042 KBC reset on x86-64, SBI SRST
  type 2 on RISC-V).

Both labels are gated by `pwrmgr_labels::SHUTDOWN_AUTHORITY` (badge bit
`1<<63`). Calls without the bit reply `pwrmgr_errors::UNAUTHORIZED`.

---

## Cap flow

1. svcmgr launches pwrmgr post-handover from its `pwrmgr.svc` recipe. The
   `provides = pwrmgr.shutdown:auth pwrmgr.deny:deny` directive makes svcmgr
   create pwrmgr's service endpoint, serve its RECV as bootstrap `cap[0]`,
   and publish two SENDs into the discovery registry: `pwrmgr.shutdown`
   (`SHUTDOWN_AUTHORITY`-badged) and `pwrmgr.deny` (a no-authority twin).
   The endpoint persists across restarts.
2. `seed = devmgr.registry` delivers a `REGISTRY_QUERY_AUTHORITY`-badged
   SEND on devmgr's registry as bootstrap `cap[1]`. pwrmgr uses it to
   resolve its actuation state from devmgr (see Responsibilities). pwrmgr
   never holds a platform cap longer than it needs — the served ACPI Memory
   caps are mapped read-only and dropped after parsing.
3. Consumers permitted to power the platform off seed `pwrmgr.shutdown`
   (e.g. svctest, and svcmgr's own critical-service-death escalation); the
   badge rides through the registry lookup unchanged. svctest also seeds
   `pwrmgr.deny` to assert the gate rejects an unauthorised cap.
4. svctest, at the end of `main()` after `ALL TESTS PASSED`, sends
   `pwrmgr_labels::SHUTDOWN` through the authorised cap. pwrmgr executes
   the platform shutdown sequence. QEMU exits cleanly, ending the staged
   `cargo xtask run` without a wall-clock wait.

---

## Restart semantics

pwrmgr is a `restart = on_failure` svcmgr service. Because it holds no
unique source caps, a crashed pwrmgr is recoverable: svcmgr re-creates it
from `/services/pwrmgr` and re-serves a fresh RECV on the persistent
service endpoint, so a `pwrmgr.shutdown` cap cached against the published
name survives the restart. The restarted instance re-acquires its actuator
caps from devmgr on startup — `QUERY_SHUTDOWN_DEVICE` re-carves the I/O
ports from devmgr's root cap on every call, so nothing is consumed.

`critical = no`: a permanently-dead pwrmgr (restart budget exhausted)
cannot power the platform off, so the graceful-shutdown-via-`pwrmgr.shutdown`
escalation would be circular. The honest terminal state is logged and the
system continues degraded, matching `timed`.

---

## Future scope

Out of scope for v0.1.0; deferred until concrete consumers exist:

- **Suspend** (ACPI S3) and **hibernate** (ACPI S4) — RAM-image
  persistence, driver quiescence protocol, BSP/AP resume vector. RISC-V
  deep sleep via the SBI HSM extension.
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

`core/ktest/src/acpi_shutdown.rs` and `core/ktest/src/sbi_shutdown.rs`
hold their own implementations of the same mechanisms. They are kept
deliberately separate so the kernel-validation harness does not depend
on any userspace-service crate. The ktest copies are a frozen,
single-purpose `shutdown(info)`; pwrmgr's copies will evolve with the
future-scope items above. There is no shared crate and no cross-reference
between the two trees.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System-wide service inventory; pwrmgr's role |
| [shared/ipc/src/lib.rs](../../shared/ipc/src/lib.rs) | Authoritative IPC label and error definitions (`pwrmgr_labels`, `pwrmgr_errors`, `devmgr_labels`) |
| [services/devmgr/README.md](../devmgr/README.md) | Hardware + ACPI authority; the `QUERY_ACPI_TABLE` / `QUERY_SHUTDOWN_DEVICE` brokers pwrmgr acquires its caps through |
| [services/svcmgr/README.md](../svcmgr/README.md) | Launcher + supervisor; the provider path that publishes `pwrmgr.shutdown` / `pwrmgr.deny` |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md)
