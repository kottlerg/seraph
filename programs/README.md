# programs

General-purpose userspace applications, utilities, and the test fixtures the harnesses spawn.

| Crate | Purpose |
|---|---|
| [`capexhaust/`](capexhaust/README.md) | CSpace-exhaustion fixture for the recv-wedge regression test |
| [`demandpaged/`](demandpaged/README.md) | Demand-paging fixture for the svctest pager phase |
| [`fb-charset/`](fb-charset/README.md) | Framebuffer character-set demo program |
| [`fsbench/`](fsbench/README.md) | `FS_READ` vs `FS_READ_MEMORY` crossover benchmark |
| [`hello/`](hello/README.md) | Hello-world program; std-only, no Seraph cap awareness |
| [`pipefault/`](pipefault/README.md) | Piped-stdio fault fixture for the pipe death-bridge regression test |
| [`pipestress/`](pipestress/README.md) | Spawn-exit-drain stress fixture for the pipe EOF-drain regression test |
| [`relrofault/`](relrofault/README.md) | RELRO write fixture for the `PT_GNU_RELRO` enforcement test |
| [`shell/`](shell/README.md) | Minimal interactive shell; the child of `terminal` |
| [`stackoverflow/`](stackoverflow/README.md) | Stack-overflow fixture for the stack guard-page regression test |
| [`stdiotest/`](stdiotest/README.md) | Stdin↔stdout proof |
| [`terminal/`](terminal/README.md) | Terminal: relays a byte stream between hardware drivers and a child's stdio |
| [`threadchurn/`](threadchurn/README.md) | CSpace-slot and memmgr-pool reclaim fixture for the usertest `threadchurn` tester |
| [`threadstack/`](threadstack/README.md) | Guarded demand-stack fixture for the usertest `threadstack` tester |

---

## Summarized By

None
