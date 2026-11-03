# test-fault

Test-only fault-injection driver for devmgr's driver settle and withdrawal. devmgr spawns three
of it in one settle batch on demand through its `TEST_SPAWN_FAULT_DRIVERS` shim, gated on
`TEST_LABEL_AUTHORITY`, which only svctest's seed-only `devmgr.test` cap carries, so a boot
without svctest never spawns it. The bootstrap is the simple-device path's two rounds; the
first round's `data[0]` is the mode (`ipc::test_fault_labels`):

- `MODE_READY` reports `DRIVER_READY` and serves `FAULT_PING` (reply `SUCCESS`) and
  `FAULT_EXIT` (reply `SUCCESS`, then exit after `FAULT_EXIT_DELAY_MS` without receiving
  again, so a call queued after the reply reaches a dead driver until devmgr withdraws it).
- `MODE_NEVER_READY` holds `NEVER_READY_RESERVE_BYTES` (4 MiB) of touched memory and neither
  reports ready nor exits, so the batch's settle ends at its bound and devmgr destroys it,
  returning the memory, which svctest observes.

[svctest](../../svctest/README.md)'s devmgr withdrawal phase drives it. Slated for removal with
the devmgr enumeration redesign ([#165](https://github.com/kottlerg/seraph/issues/165)). See
[devmgr Responsibilities](../../devmgr/docs/responsibilities.md#responsibilities) for the
settle and the withdrawal.

---

## Source Layout

```
test-fault/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Two-round bootstrap, mode, 4 MiB never-ready hold, ping/exit loop
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [devmgr Responsibilities](../../devmgr/docs/responsibilities.md) | Driver settle, its bound, withdrawal, tombstones |
| [docs/device-management.md](../../../docs/device-management.md) | Driver lifecycle and devmgr spawn flow |

---

## Summarized By

[Testing](../../../docs/testing.md), [services/drivers/README.md](../README.md),
[services/svctest/README.md](../../svctest/README.md)
