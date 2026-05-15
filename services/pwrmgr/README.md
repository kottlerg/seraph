# pwrmgr

Userspace power manager. Owns the platform shutdown and reboot path.

---

## Source layout

```
pwrmgr/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs       # Entry, bootstrap, IPC dispatch loop, cap-gating
    ├── caps.rs       # init → pwrmgr bootstrap protocol
    ├── x86_64.rs     # ACPI S5 walk + PM1a write; 8042 KBC reboot
    └── riscv64.rs    # SBI SRST shutdown + cold reboot
```

---

## Responsibilities

pwrmgr is the sole holder, after Phase 3 of init's bootstrap, of the raw
capabilities required to power off or reset the platform:

- **x86-64** — the `IoPortRange` cap, plus the `AcpiReclaimable` Frame caps
  that cover the firmware tables containing FADT and DSDT.
- **RISC-V** — the `SbiControl` cap that authorises forwarding `system_reset`
  through the kernel to M-mode firmware.

It exposes a small IPC surface (`shared/ipc/src/lib.rs::pwrmgr_labels`):

- `SHUTDOWN` — power off the platform (ACPI S5 on x86-64, SBI SRST type 0
  on RISC-V). On the success path the platform powers off and no reply is
  delivered. A reply only arrives on rejection or hardware-failure paths.
- `REBOOT` — cold reboot the platform (8042 KBC reset on x86-64, SBI SRST
  type 2 on RISC-V).

Both labels are gated by `pwrmgr_labels::SHUTDOWN_AUTHORITY` (token bit
`1<<63`). Calls without the bit reply `pwrmgr_errors::UNAUTHORIZED`.

---

## Cap flow

1. Init holds the platform caps at boot (`InitInfo.acpi_region_frame_*`,
   `InitInfo.sbi_control_cap`, plus the `IoPortRange` cap surfaced through
   the descriptor array).
2. During Phase 3, init creates pwrmgr via `procmgr_labels::CREATE_FROM_FILE`
   from `/bin/pwrmgr`, then transfers derived copies of the platform caps
   through the bootstrap-round protocol in `caps.rs`.
3. After pwrmgr is ready, init derives two tokened SEND caps from pwrmgr's
   service endpoint:
   - `pwrmgr_auth_cap` — `cap_derive_token(ep, SEND, SHUTDOWN_AUTHORITY)`.
   - `pwrmgr_noauth_cap` — `cap_derive_token(ep, SEND, 0)`. Used by
     usertest's `pwrmgr_cap_deny_phase` to verify the gate.
4. Init installs both caps in usertest's bootstrap-round payload.
5. usertest, at the end of `main()` after `ALL TESTS PASSED`, sends
   `pwrmgr_labels::SHUTDOWN` through the authorised cap. pwrmgr executes
   the platform shutdown sequence. QEMU exits cleanly, ending naked
   `cargo xtask run` without a wall-clock wait.

---

## Restart semantics

pwrmgr is not registered with svcmgr. The platform caps it owns are
unique resources; after a hypothetical crash there is no way to restart
pwrmgr with the same authority because init has released its copies. The
system idles in that case (the same behaviour as today's userspace when
no caller can reach the platform reset).

A future revision can have init retain the source caps and re-deliver
them to a restarted pwrmgr on svcmgr's policy; the wiring is
straightforward but adds bootstrap state to init that is not exercised in
v0.1.0.

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
- **svcmgr-managed launch of usertest** — usertest is not
  bootstrap-essential. Moving its spawn from init to svcmgr lets init
  fully exit earlier once a real logd lands.
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

## Documentation hierarchy

- [docs/architecture.md](../../docs/architecture.md) — system-wide
  service inventory.
- [shared/ipc/src/lib.rs](../../shared/ipc/src/lib.rs) — authoritative
  IPC label and error definitions (`pwrmgr_labels`, `pwrmgr_errors`).
- [services/init/README.md](../init/README.md) — bootstrap order and
  cap-flow into pwrmgr.
