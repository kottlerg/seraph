# drivers/cmos

x86-64 CMOS / MC146818-compatible RTC driver. Serves
[`rtc_labels::RTC_GET_EPOCH_TIME`](../../../shared/ipc/src/lib.rs).

Spawned by devmgr on x86-64 platforms. Registered with svcmgr under the
well-known name `rtc.primary`; the `timed` service queries this driver
once at startup to seed its wall-clock offset.

---

## Source Layout

```
cmos/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Driver entry, IPC service loop, CMOS read sequence
```

---

## Endpoint

Bootstrap caps from devmgr (one round, two caps, `done=true`):

| Slot      | Cap                                                  |
|-----------|------------------------------------------------------|
| `caps[0]` | Service-endpoint RECV (driver receives on this)      |
| `caps[1]` | `IoPortRange` covering CMOS index/data ports `0x70`–`0x71` |

The driver binds the `IoPortRange` cap to its main thread via
`syscall::ioport_bind` and uses `in`/`out` to drive the CMOS access
protocol.

---

## IPC Interface

* **`rtc_labels::RTC_GET_EPOCH_TIME`** — no payload. The driver
  re-reads the CMOS hardware on every request (no caching). Reply:
  reply label is a [`rtc_errors`](../../../shared/ipc/src/lib.rs)
  status code; on `SUCCESS`, `data[0]` is `u64` microseconds since
  the Unix epoch.

The driver does not maintain a wall-clock offset or compute drift;
that is `timed`'s responsibility.

---

## Hardware Notes

CMOS is the legacy IBM-AT real-time clock at ISA I/O ports `0x70`
(index) and `0x71` (data). The driver waits for the
update-in-progress bit (Status A, register `0x0A`, bit 7) to clear,
reads seconds/minutes/hours/day/month/year, then re-reads and
compares to guard against an update tick mid-read.

Status B (register `0x0B`) reports BCD vs binary mode (bit 2: 1 =
binary, 0 = BCD) and 12-hour vs 24-hour mode (bit 1: 1 = 24-hour);
the driver converts both representations to a canonical 24-hour
binary value.

Year is two-digit. The century register (`0x32`) is read; if it
returns a sensible BCD century (`0x19`, `0x20`, `0x21`) it is used,
otherwise the year is interpreted as `2000 + yy` (so seraph runs
cleanly on QEMU CMOS, which leaves register `0x32` zero, through
the year 2099).
