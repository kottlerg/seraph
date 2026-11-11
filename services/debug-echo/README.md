# debug-echo

Test-tier fixture that proves the debug port's transport: it answers fixed GDB remote serial
protocol packets on the debug port, so `cargo xtask test-debug-port` drives a round trip from
the host to a guest service and back without a debugger stub. It is gated and opt-in: its
recipe lives in `/config/svcmgr/tests/`, and only `test-debug-port` stages it, for its own boot.

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

The fixture takes the debug port from devmgr with `QUERY_DEVICE`, through its recipe's
`devmgr.class.debug-port` seed, retrying while devmgr replies `NO_DEVICE` (the virtio-console
driver loads with devmgr's on-disk batch), registers an RX notification on it, and logs
`READY on the debug port`. It exits, logging why, when the seed is absent or no debug port is
served (a boot without `--debug-port`).

It then frames the bytes it reads with `shared/gdb-rsp`
([shared/gdb-rsp/README.md](../../shared/gdb-rsp/README.md)), acknowledging each packet with `+`
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
| [docs/testing.md](../../docs/testing.md) | The debug-port cell this fixture's boot is, and the test-recipe gating |
| [services/drivers/virtio/console/README.md](../drivers/virtio/console/README.md) | The debug port's driver and the serial protocol it serves |

---

## Summarized By

[Testing](../../docs/testing.md), [xtask/README.md](../../xtask/README.md)
