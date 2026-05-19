# base

General-purpose userspace applications and utilities. These are
applications, not services — they have no special privileges beyond
what their capabilities grant. They interact with the system through
the IPC interfaces exposed by vfs, net, and other services.

---

## Source Layout

| Crate | Purpose |
|---|---|
| `crasher` | Deliberate-crash fixture for svcmgr restart-path validation. |
| `fsbench` | `FS_READ` vs `FS_READ_FRAME` crossover benchmark. |
| `hello` | Tier-2 hello-world; std-only, no Seraph cap awareness. |
| `pipefault` | Piped-stdio fault fixture for the pipe death-bridge regression test. |
| `stackoverflow` | Stack-overflow fixture for the `PROCESS_STACK_GUARD_VA` regression test. |
| `stdiotest` | Tier-2 stdin↔stdout proof. |
| `usertest` | Generic userspace test driver; first std-built consumer of the ruststd overlay. |

---

## Summarized By

None
