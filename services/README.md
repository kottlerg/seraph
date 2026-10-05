# services

Userspace OS processes — managers, the crate-collections they bind, and freestanding daemons.

| Crate | Purpose |
|---|---|
| [`init/`](init/README.md) | Bootstrap service — starts early services and exits |
| [`memmgr/`](memmgr/README.md) | Userspace RAM memory-cap pool owner |
| [`procmgr/`](procmgr/README.md) | Process lifecycle manager |
| [`svcmgr/`](svcmgr/README.md) | Service supervisor and discovery registry |
| [`devmgr/`](devmgr/README.md) | Device manager — platform enumeration, driver binding |
| [`drivers/`](drivers/README.md) | Userspace device drivers (bound by `devmgr`) |
| [`vfsd/`](vfsd/README.md) | Virtual filesystem daemon |
| [`fs/`](fs/README.md) | Filesystem driver implementations (mounted by `vfsd`) |
| [`logd/`](logd/README.md) | Logging daemon |
| [`netd/`](netd/README.md) | Network stack daemon (design intent; not yet implemented) |
| [`pwrmgr/`](pwrmgr/README.md) | Power manager — platform shutdown and reboot |
| [`timed/`](timed/README.md) | Wall-clock service over the devmgr-resolved RTC |
| [`usertest/`](usertest/README.md) | Programs-surface test orchestrator |
| `svctest/` | Services-surface test harness |
| [`crasher/`](crasher/README.md) | Test-tier fixture: deliberate-crash canary for svcmgr's restart path (gated, opt-in) |

---

## Summarized By

None
