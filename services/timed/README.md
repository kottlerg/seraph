# timed

Userspace wall-clock service. RTC-source agnostic: looks up
`rtc.primary` in the service registry once at startup, computes a
fixed offset against the kernel's monotonic clock, then serves
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
    └── main.rs            # Service entry, registry lookup, event loop
```

No `arch/` subdirectory — no hardware code. The same binary builds and
runs on every supported arch.

---

## Endpoint

Bootstrap caps from devmgr (one round, one cap, `done=true`):

| Slot      | Cap                                                  |
|-----------|------------------------------------------------------|
| `caps[0]` | Service-endpoint RECV (timed receives on this)       |

`ProcessInfo.service_registry_cap` (delivered to every spawned process
by procmgr) provides the SEND cap on svcmgr's registry endpoint, used
once for the `rtc.primary` lookup. No other caps are needed.

---

## IPC Interface

* **`timed_labels::GET_WALL_TIME`** — no payload. Reply label is a
  [`timed_errors`](../../shared/ipc/src/lib.rs) status code; on
  `SUCCESS`, `data[0]` is `u64` microseconds since the Unix epoch.

  Resolution is microseconds. Computed as `offset + kernel_elapsed_us`
  where `kernel_elapsed_us` is the value of `SystemInfoType::ElapsedUs`
  at request time. `offset` is fixed at startup; future NTP discipline
  will update it in place without any client-side change.

If `rtc.primary` lookup failed at startup (no RTC driver registered),
timed enters a degraded state and replies
`timed_errors::WALL_CLOCK_UNAVAILABLE` to every `GET_WALL_TIME`.

---

## Startup Sequence

1. Pull the service endpoint via the spawner's bootstrap round.
2. `svcmgr.QUERY_ENDPOINT(b"rtc.primary")` → SEND cap on the RTC
   chip driver registered by devmgr.
3. `rtc_driver.RTC_GET_EPOCH_TIME` → `rtc_us` (Unix-epoch us).
4. Snapshot `kernel_us = system_info(ElapsedUs)`.
5. `offset = rtc_us.wrapping_sub(kernel_us)`.
6. Enter the service loop.

The offset uses wrapping arithmetic so the same `offset + elapsed`
formula serves every request without branching on whether `rtc_us`
exceeds `kernel_us`. `wrapping_add(wrapping_sub(x, y), y) == x`
holds for unsigned, so the reply value equals `rtc_us` at the
instant of the original RTC read, plus exactly the elapsed
monotonic time since.
