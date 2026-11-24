# programs

General-purpose userspace applications and utilities, and `usertest`, the programs-surface test
orchestrator. The test fixtures the harnesses spawn are under
[`services/fixtures/`](../services/fixtures/README.md).

| Crate | Purpose |
|---|---|
| [`fb-charset/`](fb-charset/README.md) | Framebuffer character-set demo program |
| [`hello/`](hello/README.md) | Hello-world program; std-only, no Seraph cap awareness |
| [`shell/`](shell/README.md) | Minimal interactive shell; the child of `terminal` |
| [`terminal/`](terminal/README.md) | Terminal: relays a byte stream between hardware drivers and a child's stdio |
| [`usertest/`](usertest/README.md) | Programs-surface test orchestrator, installed as `/tests/usertest` |

---

## Summarized By

None
