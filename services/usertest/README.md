# usertest

Programs-surface test orchestrator. Discovers per-program tester binaries
under `/tests/programs/`, spawns each, and reports a pass/fail verdict
from the child's exit status, per the harness model in
[docs/testing.md](../../docs/testing.md).

Each tester runs with its stdout and stderr piped. `usertest` forwards every line of both to the
boot log as `[<tester>:out]` or `[<tester>:err]`, and drains the two streams at once, stderr on a
thread of its own, so a tester may write any amount to either while the other is open. It then
waits for the tester's exit status.

---

## Seeds

usertest takes its recipe's seeds over the bootstrap protocol, up to eight slots. Slot 0 is its
own, `pwrmgr.shutdown`, with which it powers off at the end of the run. The later seeds are
authorities testers take: the recipe's env entry `TESTER_SEEDS` declares, per tester, the slots
usertest hands it (`<tester>:<slot>[,<slot>...]`, entries joined by `;`), and usertest gives that
tester a copy of each as its bootstrap caps
([runtime/ruststd/README.md](../../runtime/ruststd/README.md) § Bootstrap caps), the tester's slot
`k` being the `k`-th slot its entry names. A tester with no entry gets no creator endpoint. A
declaration that names slot 0, a slot past the eight, or a tester twice, or that does not parse,
fails the run before any tester starts. The recipe declares `hello:1;crashme:2`: the hello tester
takes `pwrmgr.deny` and checks that pwrmgr refuses it
([programs/hello/README.md](../../programs/hello/README.md) § Tester), and the crashme tester takes
`crashd.core` and asks the crash service for live cores
([programs/crashme/README.md](../../programs/crashme/README.md)).

---

## Source Layout

```
services/usertest/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs    # TESTER_SEEDS declaration parser (host-tested)
    └── main.rs   # seed bootstrap + discovery + spawn loop + summary marker
```

`usertest` ships no per-program testers itself. Each program under
`programs/<name>/` may ship a tester at `programs/<name>/tester/`; the
tester binary lands at `/tests/programs/<name>` and is discovered at
runtime, per
[docs/testing.md § Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).

---

## Relevant Design Documents

| Document | Why |
|---|---|
| [docs/testing.md](../../docs/testing.md) | System-wide test conventions: marker format, tester protocol, sysroot layout, gating. |

---

## Summarized By

[Testing](../../docs/testing.md)
