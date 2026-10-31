# cmos

x86-64 CMOS / MC146818-compatible RTC driver. Serves
[`rtc_labels::RTC_GET_EPOCH_TIME`](../../../shared/ipc/src/lib.rs).

Installed to `/services/drivers/cmos-rtc` on the rootfs. Spawned by
devmgr on x86-64 platforms via the non-PCI simple-device path
([Device Management](../../../docs/device-management.md#driver-binary-sources)),
`procmgr_labels::CREATE_FROM_FILE` against a vfsd file SEND devmgr
walks to from the `LOOKUP | READ` `/services/drivers/` subtree cap svcmgr
delivers post-handover via `devmgr_labels::SET_DRIVERS_DIR`.
[devmgr](../../devmgr/docs/responsibilities.md#responsibilities) owns
the driver's service endpoint and mints client SEND caps on
`devmgr_labels::QUERY_RTC_DEVICE`, each badged with
`rtc_labels::READ_AUTHORITY`. The [`timed`](../../timed/README.md) service
resolves the SEND once at startup to seed its wall-clock offset.

---

## Source Layout

```
cmos/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs             # CMOS register snapshot (bounded UIP wait; host-tested)
    └── main.rs            # Driver entry, IPC service loop, port I/O, decode
```

---

## Endpoint

Bootstrap caps from devmgr (one round, two caps and one data word,
`done=true`):

| Slot      | Cap                                                  |
|-----------|------------------------------------------------------|
| `caps[0]` | Service-endpoint RECV (driver receives on this)      |
| `caps[1]` | `IoPort` covering CMOS index/data ports `0x70`–`0x71` |

`data[0]` is the CMOS RAM index of the century register, from the FADT's
`CENTURY` field, or 0 when the FADT names none.

The driver binds the `IoPort` cap to its main thread via
`syscall::ioport_bind` and uses `in`/`out` to drive the CMOS access
protocol.

---

## IPC Interface

* **`rtc_labels::RTC_GET_EPOCH_TIME`** — no payload. The driver
  re-reads the CMOS hardware on every request (no caching). Caller's
  badge must carry `rtc_labels::READ_AUTHORITY`
  ([devmgr](../../devmgr/docs/responsibilities.md#responsibilities) stamps it
  on every SEND minted from `QUERY_RTC_DEVICE`); the driver replies
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
| [devmgr Responsibilities and Capabilities](../../devmgr/docs/responsibilities.md) | Per-driver capability carve and `QUERY_RTC_DEVICE` |
| [services/timed/README.md](../../timed/README.md) | The sole client of this driver |

---

## Summarized By

None
