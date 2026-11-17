# hotplug-check

Test-tier fixture that proves devmgr's PCI Express native hotplug add path: it waits for devmgr
to serve the `test-dma` fixture on an `edu` device the host hot-adds behind a root port, then
checks that the device's DMA and its MSI work, so `cargo xtask test-hotplug` follows an arrival
from the slot to a bound driver. It is gated and opt-in: its recipe lives in
`/config/svcmgr/tests/`, and only `test-hotplug` stages it, for its own boots.

---

## Source Layout

```
hotplug-check/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Class wait, the ready marker, the DMA and interrupt probes
```

---

## Behaviour

The fixture takes the `test-dma` class from devmgr through its recipe's `devmgr.class.test-dma`
seed and waits for the class's first live driver on a `WATCH_CLASS` watch
(`ipc::await_device`). Before its first wait it logs `READY for the hot-added device`, on which
the host hot-adds the device; the wait is bounded by 120 s. It then checks, logging the first
failure as `FAIL: <reason>`:

1. a driver was served, and only after the ready line: one served before it was bound to a device
   the boot already had, not the hot-added one;
2. `QUERY_DEVICE` of the class's ordinal 0 answers, the launch attaching no other `test-dma`
   device;
3. `DMA_PROBE` (`test_dma_labels`) replies `PROBE_PASSED`: the device copied through a buffer
   devmgr mapped for it;
4. `INTERRUPT_PROBE` replies that the driver holds an MSI vector and that the device's MSI reached
   it.

When every check passes it logs `PASS: ` with the device address of the probe's buffer. It
invokes no shutdown: the host test computes the verdict and kills QEMU.

---

## Capabilities

The bootstrap round delivers the recipe's one seed:

| Slot      | Cap                                                         |
|-----------|-------------------------------------------------------------|
| `caps[0]` | `devmgr.class.test-dma`: the `test-dma` class SEND           |

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | The hotplug cell this fixture's boot is, and the test-recipe gating |
| [services/devmgr/docs/hotplug.md](../devmgr/docs/hotplug.md) | The hotplug add path the fixture checks |
| [services/drivers/test-dma/README.md](../drivers/test-dma/README.md) | The driver the fixture probes, and its probes |

---

## Summarized By

[Testing](../../docs/testing.md), [xtask/README.md](../../xtask/README.md)
