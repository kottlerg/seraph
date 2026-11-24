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
| [`entropyd/`](entropyd/README.md) | Entropy contributor — mixes the `hwrng` class drivers' bytes into the kernel entropy pool, with no credit |
| [`sessiond/`](sessiond/README.md) | Operator-session supervisor — creates each session's leader for the interface that opens it, ends the session with its leader, and offers oomd the stop of its programs |
| [`oomd/`](oomd/README.md) | Out-of-memory policy service — stops a service that opted in to being stopped when memory stays critical |
| [`swapd/`](swapd/README.md) | Swap service — holds the swap partition and moves memmgr's sealed chunks between it and memmgr, writing chunks out while memory is critical and restoring each on a fault or a debugger's read |
| [`svctest/`](svctest/README.md) | Services-surface test harness |
| [`ubench/`](ubench/README.md) | Userspace benchmark suite, installed as `/tests/ubench`: IPC, demand faults, the pipe ring, console output, and fsbench |
| [`fixtures/`](fixtures/README.md) | Test fixtures the harnesses and per-program testers spawn, installed under `/tests/fixtures/` (gated, opt-in) |

---

## Summarized By

None
