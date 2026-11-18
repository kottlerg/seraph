# hotplug-check

Test-tier fixture with two modes. The device mode proves devmgr's PCI Express hotplug add and
removal paths, native and through acpid: it waits for devmgr to serve the `test-dma` fixture on an
`edu` device the host hot-adds behind a root port and checks that the device's DMA and its MSI
work; then that devmgr withdraws the driver when the host removes the device, and that the device
added again is served anew, works, and is charged none of its predecessor's IOMMU faults. So
`cargo xtask test-hotplug` follows an arrival from the slot to a bound driver, and a removal back to
an empty slot, under each hotplug control. The disk mode (`hotplug-check disk`) proves vfsd's
handling of a disk removed and added again behind a root port, and of the loss of its root
filesystem's driver. It is gated and opt-in: its recipes live in `/config/svcmgr/tests/`, and only
`test-hotplug` stages them, each for its own boots.

---

## Source Layout

```
hotplug-check/
├── Cargo.toml
├── README.md
└── src/
    ├── main.rs            # Mode dispatch; device mode: class waits, markers, probes
    ├── disk.rs            # Disk mode: vfsd's disk removal, re-add and root-driver loss
    └── arch/              # Register-file size and instruction-pointer offset, to kill a thread
        ├── mod.rs
        ├── x86_64/mod.rs
        └── riscv64/mod.rs
```

---

## Behaviour

`hotplug-check` with no argument runs the device mode (recipe `hotplug-check.svc`); `hotplug-check
disk` (argv[1] `disk`) runs the disk mode (recipe `hotplug-check-disk.svc`).

### Device mode

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

It then logs `READY for the removal`, on which the host removes the device (QMP `device_del`,
which presses the slot's attention button), and checks, on a `WATCH_CLASS` watch bounded by
120 s, that:

5. `QUERY_DEVICE` of ordinal 0 answers `WITHDRAWN`: devmgr withdrew the driver at the removal.

It then logs `WITHDRAWN at ordinal 0; READY for the re-added device`, on which the host adds the
device again, waits for the class's first live driver as before, and checks that:

6. the driver is served at ordinal 1, a withdrawn ordinal staying withdrawn;
7. `DMA_PROBE` and `INTERRUPT_PROBE` pass as in checks 3 and 4;
8. the IOMMU faults `DMA_PROBE` reports (`data[4]`) equal those of the first device's probe:
   each probe raises the same faults, so a count carried from the removed device to the new one
   at the same address fails.

When every check passes it logs `PASS: ` with the device address of each probe's buffer and the
fault count. It invokes no shutdown: the host test computes the verdict and kills QEMU.

### Disk mode

The mode runs on the split-data layout with the data disk behind the first root port from boot,
so vfsd mounts `/data` at startup. It finds the root mount's driver by its process name `fatfs:/`
(`LIST_PROCESSES`), writes a file under `/data`, holds it open, and logs `HOLDING a file open on
/data; READY for the removal of its disk`, on which the host removes the disk. It then checks that:

1. vfsd marked the disk removed: `MOUNT` answers `NO_MOUNT` where it answered `TABLE_FULL`;
2. the mount is torn down: `/data` is not found;
3. the open file is stale: it fails with `StaleNetworkFileHandle`.

It logs `TORN DOWN /data, its disk removed; READY for the re-added disk`, on which the host adds the
disk again. It then mounts `/data` through a fresh `MOUNT` and reads the file back. It then stops
the root driver's threads through a debug attach, checks that a lookup falling through at `/`
errors within 30 s while `/data` still reads, logs `PASS`, and kills the root driver; vfsd exits and
svcmgr shuts the system down. In the second storage boot, whose boot disk sits behind the port, the
host removes the boot disk while the fixture waits.

---

## Capabilities

The device mode's recipe delivers one seed:

| Slot      | Cap                                                         |
|-----------|-------------------------------------------------------------|
| `caps[0]` | `devmgr.class.test-dma`: the `test-dma` class SEND           |

The disk mode's recipe (namespace `universal`, `debug_authority = yes`) delivers `vfsd.mount`, the
`MOUNT_AUTHORITY` SEND on vfsd's service endpoint, in `caps[0]`, and the debug authority in the slot
after it.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | The hotplug cell this fixture's boot is, and the test-recipe gating |
| [services/devmgr/docs/hotplug.md](../devmgr/docs/hotplug.md) | The hotplug add and removal paths the fixture checks |
| [services/drivers/test-dma/README.md](../drivers/test-dma/README.md) | The driver the fixture probes, and its probes |

---

## Summarized By

[Testing](../../docs/testing.md), [xtask/README.md](../../xtask/README.md)
