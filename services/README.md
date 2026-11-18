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
| [`crashd/`](crashd/README.md) | Crash service — reports each process that dies on a fault to the system log |
| [`gdbstub/`](gdbstub/README.md) | GDB stub — debugs one process from a host GDB over the debug port (staged per boot, opt-in) |
| [`netd/`](netd/README.md) | Network stack daemon (design intent; not yet implemented) |
| [`pwrmgr/`](pwrmgr/README.md) | Power manager — platform shutdown and reboot |
| [`acpid/`](acpid/README.md) | ACPI service — runs the firmware's AML and pushes each PCI host bridge's `_OSC`, windows and routes to devmgr |
| [`timed/`](timed/README.md) | Wall-clock service over the devmgr-resolved RTC |
| [`oomd/`](oomd/README.md) | Out-of-memory policy service — stops a service that opted in to being stopped when memory stays critical |
| [`usertest/`](usertest/README.md) | Programs-surface test orchestrator |
| [`svctest/`](svctest/README.md) | Services-surface test harness |
| [`crasher/`](crasher/README.md) | Test-tier fixture: deliberate-crash canary for svcmgr's restart path (gated, opt-in) |
| [`memhog/`](memhog/README.md) | Test-tier fixture: fills memory until the pressure level reads `CRITICAL`, for oomd to stop (gated, opt-in) |
| [`debug-echo/`](debug-echo/README.md) | Test-tier fixture: answers fixed GDB remote serial protocol packets on the debug port (gated, opt-in) |
| [`hotplug-check/`](hotplug-check/README.md) | Test-tier fixture: checks that devmgr binds a driver to a device hot-added behind a PCI Express root port, and that its DMA and MSI work (gated, opt-in) |

---

## Summarized By

None
