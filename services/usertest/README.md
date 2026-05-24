# usertest

Programs-surface test orchestrator. Discovers per-program tester binaries
under `/programs/tests/`, spawns each, and reports a pass/fail verdict
from the child's exit status.

---

## Source Layout

```
services/usertest/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs   # discovery + spawn loop + summary marker
```

`usertest` ships no per-program testers itself. Each program under
`programs/<name>/` may ship a tester at `programs/<name>/tester/`; the
tester binary lands at `/programs/tests/<name>` and is discovered at
runtime.

---

## Relevant Design Documents

| Document | Why |
|---|---|
| [docs/testing.md](../../docs/testing.md) | System-wide test conventions: marker format, tester protocol, sysroot layout, gating. |

---

## Summarized By

[Root README](../../README.md), [docs/testing.md](../../docs/testing.md)
