# programs

General-purpose userspace applications, utilities, and the test fixtures the harnesses spawn.

| Crate | Purpose |
|---|---|
| `capexhaust` | CSpace-exhaustion fixture for the recv-wedge regression test |
| `demandpaged` | Demand-paging fixture for the svctest pager phase |
| [`fb-charset`](fb-charset/README.md) | Framebuffer character-set demo program |
| `fsbench` | `FS_READ` vs `FS_READ_FRAME` crossover benchmark |
| `hello` | Hello-world program; std-only, no Seraph cap awareness |
| `pipefault` | Piped-stdio fault fixture for the pipe death-bridge regression test |
| `pipestress` | Spawn-exit-drain stress fixture for the pipe EOF-drain regression test |
| `relrofault` | RELRO write fixture for the `PT_GNU_RELRO` enforcement test |
| [`shell`](shell/README.md) | Minimal interactive shell; the child of `terminal` |
| `stackoverflow` | Stack-overflow fixture for the `PROCESS_STACK_GUARD_VA` regression test |
| `stdiotest` | Stdin↔stdout proof |
| [`terminal`](terminal/README.md) | Terminal: relays a byte stream between hardware drivers and a child's stdio |
| `threadchurn` | CSpace-slot and memmgr-pool reclaim fixture for the usertest `threadchurn` tester |
| `threadstack` | Guarded demand-stack fixture for the usertest `threadstack` tester |

---

## Summarized By

None
