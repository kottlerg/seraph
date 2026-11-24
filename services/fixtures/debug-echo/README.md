# debug-echo

Test-tier fixture that proves the debug port's transport: it answers fixed GDB remote serial
protocol packets on the debug port, so the `debug-port` case drives a round trip from
the host to a guest service and back without a debugger stub. It is gated and opt-in: its
recipe lives in `/config/svcmgr/tests/`, and only the `debug-port` case stages it, for its own boot.

---

## Source Layout

```
debug-echo/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Debug-port query, packet loop, fixed answers
```

---

## Behaviour

The fixture follows the debug port through a
[`device_tracker::Device`](../../../shared/device-tracker/README.md) on its recipe's
`devmgr.class.debug-port` seed, waiting without a bound until devmgr serves the class's first live
driver (the virtio-console driver loads with devmgr's on-disk batch), and logs
`READY on the debug port`. It exits, logging why, when the seed is absent; on a boot without
`--debug-port` it waits. The device's tracker keeps the port across devmgr's restart of its driver
(logged `debug port driver at ordinal <n>`), and before each read or write the fixture registers
its RX notification with a driver instance it has not registered with; the `debug-port` case kills
the driver under it and echoes through the restarted one.

It then frames the bytes it reads with `shared/gdb-rsp`
([shared/gdb-rsp/README.md](../../../shared/gdb-rsp/README.md)), acknowledging each packet with `+`
and a bad checksum with `-` until no-ack mode, and answers:

| Received | Answer |
|---|---|
| `qSupported[:...]` | the crate's `qSupported` reply (`PacketSize`, `QStartNoAckMode+`, `qXfer:features:read+`, `vContSupported+`) |
| `QStartNoAckMode` | `OK`, after which it neither sends nor expects acknowledgements; logs `no-ack mode` |
| `qSeraph.Echo:<data>` | `<data>`, its escapes undone and the bytes escaped again |
| `?` | `S05` |
| the interrupt byte `0x03` | `S02` |
| a packet past its buffer | `E02` |
| a malformed packet of the packet set | `E01` |
| any other packet | an empty reply |
| `-` | its last reply again |

It invokes no shutdown: the host test computes the verdict and kills QEMU.

---

## Capabilities

The bootstrap round delivers the recipe's one seed:

| Slot      | Cap                                                                   |
|-----------|-----------------------------------------------------------------------|
| `caps[0]` | `devmgr.class.debug-port`: the `debug-port` class SEND (serial `WRITE` and `READ` verbs) |

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | The debug-port cell this fixture's boot is, and the test-recipe gating |
| [services/drivers/virtio/console/README.md](../../drivers/virtio/console/README.md) | The debug port's driver and the serial protocol it serves |
| [services/devmgr/docs/responsibilities.md](../../devmgr/docs/responsibilities.md) | The driver restart the fixture follows (§ Driver Restart) |

---

## Summarized By

[Testing](../../../docs/testing.md), [xtask/README.md](../../../xtask/README.md)
