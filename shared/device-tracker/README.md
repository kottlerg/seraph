# shared/device-tracker

A device class's current driver, followed across devmgr's restart of it, for `std` clients.

---

## Overview

devmgr restarts a served driver that dies and serves the new instance at the class's next ordinal
([services/devmgr/docs/responsibilities.md](../../services/devmgr/docs/responsibilities.md)
§ Driver Restart). A client that holds a class's driver for its run builds a `Device` from the
class SEND: `Device::start` registers the class's `WATCH_CLASS` watch, resolves the first live
driver, and starts a tracker thread that looks at the class again on each signal
(`ipc::refresh_device`). The client reads the current driver, with its generation, before each
call, and re-registers with a new generation whatever it registered with the dead instance. The
contract (the watch before the first resolve, the look, the settle wait on the tracker thread, the
generations, and the tracker's delete of the dead SEND) is stated once, in the crate's
documentation (`src/lib.rs`).

The terminal follows its input, framebuffer and serial classes with it, and gdbstub and the
`debug-echo` fixture the debug port.

The crate spawns a `std` thread and logs through `std::os::seraph`, so its contents compile only
for seraph and no host test reaches them; the decision it applies is `ipc::refresh_device`'s,
host-tested in [shared/ipc](../ipc/README.md). `cargo xtask test terminal` and `test debug-port`
restart a driver under each client. It depends on `shared/ipc`, `shared/syscall` and
`abi/syscall`.

---

## Source Layout

```
shared/device-tracker/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # Device, Driver: watch, tracker thread, generations, waits
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/devmgr/docs/responsibilities.md](../../services/devmgr/docs/responsibilities.md) | Driver restart, and what a client does on it (§ Driver Restart, Clients) |
| [programs/terminal/README.md](../../programs/terminal/README.md) | The terminal's classes |
| [services/gdbstub/README.md](../../services/gdbstub/README.md) | The stub's debug port |
| [services/fixtures/debug-echo/README.md](../../services/fixtures/debug-echo/README.md) | The fixture's debug port and its restart |

---

## Summarized By

None
