# test-fault

Test-only fault-injection driver for devmgr's on-demand bind, driver settle, mid-bootstrap
teardown, and withdrawal. Its declaration matches QEMU's `pci-testdev` (PCI `1b36:0005`), which
only the test launches attach (`cargo xtask run --test-devices`), and it is installed in
`/tests/drivers/`, which no drivers-directory pass of the boot lists. devmgr binds it only when
svctest sends `BIND_DRIVERS` with a cap on that directory, through its seed-only `devmgr.bind`
cap, so a boot without svctest never starts it. Each instance takes the resource list of
[`driver_binding::resources`](../../../shared/driver-binding/README.md) and its role from its
device's BAR 2 (`ipc::test_fault_labels`):

- No BAR 2: it reports `DRIVER_READY` and serves `FAULT_PING` (reply `SUCCESS`) and
  `FAULT_EXIT` (reply `SUCCESS`, then exit after `FAULT_EXIT_DELAY_MS` without receiving
  again, so a call queued after the reply reaches a dead driver until devmgr withdraws it).
- A BAR 2 of `HANG_BAR_BYTES` (4 KiB): it takes the whole list, then holds `HOLD_BYTES`
  (4 MiB) of touched memory and neither reports ready nor exits, so the bind's settle ends at
  its bound and devmgr destroys it, returning the memory, which svctest observes.
- A BAR 2 of `ORPHAN_BAR_BYTES` (8 KiB): once that BAR's round arrives it holds `HOLD_BYTES`
  and answers the next round with a request devmgr's bootstrap server refuses, so devmgr
  withdraws the device and destroys the process before its bootstrap ends, returning the
  memory.

[svctest](../../svctest/README.md)'s devmgr on-demand bind phase drives it. See
[devmgr Responsibilities](../../devmgr/docs/responsibilities.md#responsibilities) for the
bind, the settle and the withdrawal.

---

## Source Layout

```
test-fault/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Declaration, round-by-round resource list, the three roles
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/driver-binding.md](../../../docs/driver-binding.md) | Declarations, the on-demand bind, the test fixtures |
| [devmgr Responsibilities](../../devmgr/docs/responsibilities.md) | Driver settle, its bound, withdrawal, tombstones |
| [docs/device-management.md](../../../docs/device-management.md) | Driver lifecycle and devmgr spawn flow |

---

## Summarized By

[Testing](../../../docs/testing.md), [services/drivers/README.md](../README.md),
[services/svctest/README.md](../../svctest/README.md)
