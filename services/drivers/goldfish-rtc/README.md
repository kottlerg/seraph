# drivers/goldfish-rtc

RISC-V Goldfish RTC driver. Serves
[`rtc_labels::RTC_GET_EPOCH_TIME`](../../../shared/ipc/src/lib.rs).

The Goldfish RTC is a single-page MMIO device originally from the
Android emulator, present on QEMU's `virt` RISC-V machine model at
fixed physical address `0x101000`. It returns wall-clock time as a
64-bit nanosecond count since the Unix epoch in two 32-bit MMIO
register reads.

Installed to `/services/drivers/goldfish-rtc` on the rootfs. Spawned
by devmgr on RISC-V QEMU virt via the non-PCI simple-device path,
`procmgr_labels::CREATE_FROM_FILE` against a vfsd file SEND devmgr
walks to from the `/services/drivers/` subtree cap init delivers
post-vfsd-mount via `devmgr_labels::SET_DRIVERS_DIR`. devmgr owns the
driver's service endpoint and mints client SEND caps on
`devmgr_labels::QUERY_RTC_DEVICE`, each badged with
`rtc_labels::READ_AUTHORITY`. The `timed` service resolves the SEND
once at startup to seed its wall-clock offset.

---

## Source Layout

```
goldfish-rtc/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Driver entry, IPC service loop, MMIO read sequence
```

---

## Endpoint

Bootstrap caps from devmgr (one round, two caps, `done=true`):

| Slot      | Cap                                                  |
|-----------|------------------------------------------------------|
| `caps[0]` | Service-endpoint RECV (driver receives on this)      |
| `caps[1]` | `Mmio` covering one page at `0x101000`         |

The driver reserves one page of VA via `reserve_pages`, funds the AS's
page-table growth budget for that page via `fund_aspace_pt_budget`, and maps
the `Mmio` cap into it via `syscall::mmio_map`.

---

## IPC Interface

* **`rtc_labels::RTC_GET_EPOCH_TIME`** — no payload. The driver
  re-reads the device on every request. Caller's badge must carry
  `rtc_labels::READ_AUTHORITY` (devmgr stamps it on every SEND minted
  from `QUERY_RTC_DEVICE`); the driver replies
  `rtc_errors::UNAUTHORIZED` otherwise. Reply label is a
  [`rtc_errors`](../../../shared/ipc/src/lib.rs) status code; on
  `SUCCESS`, `data[0]` is `u64` microseconds since the Unix epoch.

---

## Hardware Notes

Register layout, offsets from the MMIO base:

| Offset | Register     | Purpose                                          |
|--------|--------------|--------------------------------------------------|
| `0x00` | `TIME_LOW`   | Read: low 32 bits of nanoseconds since epoch     |
| `0x04` | `TIME_HIGH`  | Read: high 32 bits, latched at the prior `TIME_LOW` read |

Read order is `TIME_LOW` first, then `TIME_HIGH`. Reading
`TIME_LOW` snapshots the full 64-bit value into a latch from which
`TIME_HIGH` is then served, giving a consistent reading without a
read-twice loop.

The driver converts nanoseconds to microseconds by integer division
by 1000; sub-microsecond resolution is discarded.

---

## Platform Scope and Discovery

On seraph's RISC-V boot path (EDK2 + QEMU `virt`) the Goldfish RTC
is **not discoverable** at runtime:

- EDK2 consumes the DTB and does not re-publish it via a UEFI
  configuration table on the build seraph targets, so the kernel's
  DTB parser sees nothing.
- EDK2 does not emit an ACPI entry for the Goldfish RTC (no
  standard `_HID`).

The driver therefore depends on the kernel boot path unconditionally
seeding `(0x101000, 0x1000)` as a platform aperture (mirroring the
unconditional PCI-ECAM seed that exists for the same firmware-
discovery reason; see `core/boot/src/arch/riscv64/mod.rs`). devmgr
identifies this driver's region by matching the well-known base
address `0x101000`, not by any discovery mechanism.

Real RISC-V boards diverge from QEMU `virt`. Per-board RTC support
(I2C chips, vendor-specific MMIO RTCs, boards with no RTC at all)
requires DT parsing infrastructure and per-board drivers; tracked
as a follow-up. This driver covers the QEMU target seraph currently
ships.
