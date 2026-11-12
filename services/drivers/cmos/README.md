# cmos

x86-64 CMOS / MC146818-compatible RTC driver. Serves
[`rtc_labels::RTC_GET_EPOCH_TIME`](../../../shared/ipc/src/lib.rs).

Installed to `/services/drivers/cmos-rtc` on the rootfs. Bound by
devmgr on x86-64 platforms to the platform device record the ACPI namespace gives `PNP0B00`
([Device Management](../../../docs/device-management.md#driver-binary-sources)),
`procmgr_labels::CREATE_FROM_FILE` against a vfsd file SEND devmgr
walks to from the `LOOKUP | READ | READDIR` `/services/drivers/` subtree cap svcmgr
delivers post-handover via `devmgr_labels::SET_DRIVERS_DIR`. The driver carries a declaration in
the ELF note section `.note.seraph.driver` (ACPI `PNP0B00`), which the drivers-directory pass
matches against that record.
[devmgr](../../devmgr/docs/responsibilities.md#responsibilities) owns
the driver's service endpoint and mints client SEND caps on
`devmgr_labels::QUERY_DEVICE` on the `rtc` class SEND, each badged with
`rtc_labels::READ_AUTHORITY`. The [`timed`](../../timed/README.md) service
resolves the SEND once at startup to seed its wall-clock offset.

---

## Source Layout

```
cmos/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs             # Register snapshot (bounded UIP wait), decode, epoch time; host-tested
    └── main.rs            # Driver entry, IPC service loop, port I/O
```

---

## Endpoint

devmgr delivers the record's resource list, decoded with
`driver_binding::resources::PlatformDelivery`: the `IoPort` resource covering the CMOS
index/data ports (the ACPI `_CRS` of `PNP0B00`, `0x70` for 8 ports on QEMU q35), and in the end
round the service-endpoint RECV and the driver's devmgr query cap, a SEND badged with its device
badge on the private endpoint of its devmgr spawn batch.

The CMOS RAM index of the century register comes from the FADT's `CENTURY` field, which devmgr
attaches to the record as device info (`ipc::device_info_kind::RTC_CENTURY`, a one-byte
payload). The driver reads it with `QUERY_DEVICE_INFO` on the query cap, and with none takes
the century 20. It uses only an index from `0x0E` to `0x7F`: lower ones are the clock and
status registers, and higher ones lie past the bank its ports reach.

The driver binds the `IoPort` cap to its main thread via
`syscall::ioport_bind` and uses `in`/`out` to drive the CMOS access
protocol. Once the ports are bound it reports `devmgr_labels::DRIVER_READY`
on the query cap, immediately before its service loop, and exits when
devmgr refuses it: devmgr serves the driver's endpoint only after the
report, and withdraws it when the driver dies.

---

## IPC Interface

* **`rtc_labels::RTC_GET_EPOCH_TIME`** — no payload. The driver
  re-reads the CMOS hardware on every request (no caching). Caller's
  badge must carry `rtc_labels::READ_AUTHORITY`
  ([devmgr](../../devmgr/docs/responsibilities.md#responsibilities) stamps it
  on every SEND minted from `QUERY_DEVICE` on the `rtc` class); the driver replies
  `rtc_errors::UNAUTHORIZED` otherwise. Reply label is a
  [`rtc_errors`](../../../shared/ipc/src/lib.rs) status code; on
  `SUCCESS`, `data[0]` is `u64` microseconds since the Unix epoch.

The driver does not maintain a wall-clock offset or compute drift;
that is `timed`'s responsibility.

---

## Hardware Notes

CMOS is the legacy IBM-AT real-time clock at ISA I/O ports `0x70`
(index) and `0x71` (data). The driver waits for the
update-in-progress bit (Status A, register `0x0A`, bit 7) to clear,
reads seconds/minutes/hours/day/month/year, then re-reads and
compares to guard against an update tick mid-read. Every wait is
bounded: an attempt whose update-in-progress bit does not clear within
`UIP_POLL_LIMIT` polls fails, and when none of `MAX_ATTEMPTS` attempts
yields a consistent reading the driver replies `READ_FAILED` rather
than spinning on a stuck bit.

Status B (register `0x0B`) reports BCD vs binary mode (bit 2: 1 =
binary, 0 = BCD) and 12-hour vs 24-hour mode (bit 1: 1 = 24-hour);
the driver converts both representations to a canonical 24-hour
binary value.

Year is two-digit. When the FADT names a century register, the driver
reads the century from it and uses a value of 19 to 99, so the year does
not wrap at 2100. With no century register named, or one reading no such
value, the year is interpreted as `2000 + yy`, which holds through the year
2099; a two-digit year carries no more.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/device-management.md](../../../docs/device-management.md) | Driver binary sources; devmgr spawn and RTC query flow |
| [devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md) | Per-driver capability carve and `QUERY_DEVICE` |
| [services/timed/README.md](../../timed/README.md) | The sole client of this driver |

---

## Summarized By

None
