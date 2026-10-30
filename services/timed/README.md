# timed

Userspace wall-clock service. RTC-source agnostic: resolves the
platform RTC via devmgr's
[`devmgr_labels::QUERY_RTC_DEVICE`](../../shared/ipc/src/lib.rs) once
at startup, computes a fixed offset against the kernel's monotonic
clock, then serves
[`timed_labels::GET_WALL_TIME`](../../shared/ipc/src/lib.rs) from
`offset + kernel_elapsed_us()` on every request.

`std::time::SystemTime::now()` resolves through this service (via
`SystemTime`'s PAL in `runtime/ruststd`, wiring tracked separately).

---

## Source Layout

```
timed/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Service entry, RTC resolve, event loop
```

No `arch/` subdirectory — no hardware code. The same binary builds and
runs on every supported arch.

---

## Endpoint

Bootstrap caps from svcmgr (one round, `done=true`, carrying the two slots below with the
presence word of [service-definitions.md § `seed`](../svcmgr/docs/service-definitions.md#seed);
recipe `provides = timed`, `seed = devmgr.registry`):

| Slot      | Cap                                                          |
|-----------|--------------------------------------------------------------|
| `caps[0]` | Service-endpoint RECV (timed receives on this)               |
| `caps[1]` | SEND on devmgr's registry endpoint, badged with `REGISTRY_QUERY_AUTHORITY` |

No other caps are needed; the registry SEND is used once for the
`QUERY_RTC_DEVICE` resolve.

---

## IPC Interface

* **`timed_labels::GET_WALL_TIME`** — no payload. Reply label is a
  [`timed_errors`](../../shared/ipc/src/lib.rs) status code; on
  `SUCCESS`, `data[0]` is `u64` microseconds since the Unix epoch.

  Resolution is microseconds. Computed as `offset + kernel_elapsed_us`
  where `kernel_elapsed_us` is the value of `SystemInfoType::ElapsedUs`
  at request time. `offset` is fixed at startup; future NTP discipline
  will update it in place without any client-side change.

If `QUERY_RTC_DEVICE` resolution failed at startup (no RTC reachable
through devmgr), timed enters a degraded state and replies
`timed_errors::WALL_CLOCK_UNAVAILABLE` to every `GET_WALL_TIME`.

---

## Startup Sequence

1. Pull the service endpoint and devmgr-registry SEND via the
   spawner's bootstrap round.
2. `devmgr.QUERY_RTC_DEVICE` → `READ_AUTHORITY`-badged SEND on the
   per-board RTC driver bound by devmgr.
3. `rtc_driver.RTC_GET_EPOCH_TIME` → `rtc_us` (Unix-epoch us).
4. Bracket the RTC read with two `system_info(ElapsedUs)` samples; `kernel_us` is their
   midpoint.
5. `offset = rtc_us.wrapping_sub(kernel_us)`.
6. Enter the service loop.

The offset uses wrapping arithmetic so the same `offset + elapsed`
formula serves every request without branching on whether `rtc_us`
exceeds `kernel_us`. `wrapping_add(wrapping_sub(x, y), y) == x`
holds for unsigned, so the reply value equals `rtc_us` at the
midpoint of the RTC read, plus exactly the elapsed
monotonic time since.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | System-wide service inventory; timed's role |
| [docs/device-management.md](../../docs/device-management.md) | devmgr's `QUERY_RTC_DEVICE` broker and RTC driver binding |
| [Restart Protocol](../svcmgr/docs/restart-protocol.md) | timed's `restart = on_failure`, `critical = no` supervision |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md),
[Device Management](../../docs/device-management.md),
[Process Lifecycle](../../docs/process-lifecycle.md),
[services/drivers/cmos/README.md](../drivers/cmos/README.md),
[services/drivers/goldfish-rtc/README.md](../drivers/goldfish-rtc/README.md),
[services/init/README.md](../init/README.md), [init Bootstrap Stages](../init/docs/bootstrap.md),
[Restart Protocol](../svcmgr/docs/restart-protocol.md)
