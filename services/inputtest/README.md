# inputtest

Device-input-surface test harness for the virtio-input keyboard driver.
Resolves the input endpoint from devmgr, prints a READY marker, then asserts
that keys injected over QMP decode to the expected keysyms. Driven by
`cargo xtask test-input`, which performs the host-side QMP injection; the
harness carries no in-guest injection path.

---

## Source Layout

```
services/inputtest/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs   # query input cap, READY marker, blocking read + assert, shutdown
```

`inputtest` is staged only for the `test-input` cell — it is not in svcmgr's
default scan set. See [docs/testing.md](../../docs/testing.md) for the
QMP-injection mechanism and gating.

---

## Relevant Design Documents

| Document | Why |
|---|---|
| [docs/testing.md](../../docs/testing.md) | System-wide test conventions: marker format, gating, the QMP interactive-input mechanism. |
| [services/drivers/virtio/input/README.md](../drivers/virtio/input/README.md) | The driver under test: keysym ABI and read protocol. |

---

## Summarized By

[Root README](../../README.md), [docs/testing.md](../../docs/testing.md)
