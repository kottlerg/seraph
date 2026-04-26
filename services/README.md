# services

Userspace OS processes — managers, the crate-collections they bind, and freestanding daemons.

| Crate | Purpose |
|---|---|
| `init/` | Bootstrap service — starts early services and exits |
| `memmgr/` | Userspace RAM frame pool owner |
| `procmgr/` | Process lifecycle manager |
| `svcmgr/` | Service health monitor and restart manager |
| `devmgr/` | Device manager — platform enumeration, driver binding |
| `drivers/` | Userspace device drivers (bound by `devmgr`) |
| `vfsd/` | Virtual filesystem daemon |
| `fs/` | Filesystem driver implementations (mounted by `vfsd`) |
| `logd/` | Logging daemon |
| `netd/` | Network stack daemon |

Manager↔managed pairings are co-located: `devmgr` ↔ `drivers/`, `vfsd` ↔ `fs/`.

---

## Summarized By

None
