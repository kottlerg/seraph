# shared/restart-budget

The windowed restart budget a supervisor keeps for each process it restarts.

---

## Source Layout

```
restart-budget/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs              # RestartBudget, RESTART_BURST, RESTART_WINDOW_NS
```

`no_std`, no allocation, no dependency. Host-tested (`cargo xtask test`).

---

## Budget

A supervised process may restart `RESTART_BURST` (3) times within one `RESTART_WINDOW_NS`
(60 s) window of monotonic time. `RestartBudget::try_charge(now_ns)` charges one restart and
returns `false`, charging nothing, once the open window's burst is spent. The window opens at the
first restart after the previous window has passed, so a process that crashes rarely restarts
every time, however long the boot, while one that crash-loops is stopped after a burst.

---

## Consumers

| Consumer | Budget kept per |
|---|---|
| [`services/svcmgr`](../../services/svcmgr/README.md) | Service ([restart protocol](../../services/svcmgr/docs/restart-protocol.md)) |
| [`services/devmgr`](../../services/devmgr/README.md) | Device record whose driver devmgr restarts ([responsibilities](../../services/devmgr/docs/responsibilities.md)) |
| [`xtask`](../../xtask/README.md) | None: `test-core-death` reads `RESTART_BURST` to kill logd once per restart svcmgr's budget allows, and once more |

---

## Summarized By

[Supervision](../../docs/supervision.md),
[devmgr Responsibilities and Capabilities](../../services/devmgr/docs/responsibilities.md),
[services/svcmgr/README.md](../../services/svcmgr/README.md)
