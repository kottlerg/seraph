# test-orphan

Test-only fault-injection driver for devmgr's spawn-orphan unwind (#176). devmgr spawns it on
demand through its `TEST_SPAWN_ORPHAN` shim; it completes bootstrap round 1, reserves 1 MiB of
memory, then sends a malformed round-2 message so devmgr's `serve_round` rejects it and the
orphan teardown runs, and blocks forever so only devmgr's `DESTROY_PROCESS` returns the reserved
pages. svctest exercises this path. Slated for removal with the devmgr enumeration redesign
(#165). See [services/devmgr/README.md](../../devmgr/README.md).

---

## Source Layout

```
test-orphan/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Round-1 bootstrap, memory reservation, forced round-2 failure
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../docs/device-management.md) | Driver lifecycle and devmgr spawn flow |

---

## Summarized By

[services/drivers/README.md](../README.md)
