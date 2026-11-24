# usertest

Programs-surface test orchestrator. Checks the per-program tester binaries
under `/tests/programs/` against the testers its recipe names, spawns each,
and reports a pass/fail verdict from the child's exit status, per the
harness model in [docs/testing.md](../../docs/testing.md).

Each tester runs with its stdout and stderr piped. `usertest` forwards every line of both to the
boot log as `[<tester>:out]` or `[<tester>:err]`, and drains the two streams at once, each on a
thread of its own, so a tester may write any amount to either while the other is open. It waits
for the tester's exit status and the end of both streams within the run's bound (§ Testers).

---

## Testers

The recipe's env entry `TESTERS` names the testers the image holds, entries joined by `;`
(`rootfs/config/svcmgr/tests/usertest.svc`); a new tester is added to it. The list is written by
hand rather than derived from the build, so a build or a staging that drops or renames a tester
fails the run instead of shrinking it. Before any tester starts, `usertest` compares the files
under `/tests/programs/` with the list: each tester named and absent, and each present and
unnamed, is a FAIL line of its own (`<tester>: FAIL (named in TESTERS, absent from
/tests/programs)`, `<tester>: FAIL (in /tests/programs, not named in TESTERS)`), and an unnamed
one is not run. An empty or missing list, a tester named twice, and a `TESTER_SEEDS` entry for a
tester the list does not name fail the run before any tester starts.

The env entry `TESTER_BOUND_MS` bounds each tester's run, from its spawn to its exit and the end
of both its output streams. A tester still running at the bound is killed and reported as
`<tester>: FAIL (no exit within <ms> ms)`, and the testers after it run. A tester that exits
while a process it started holds its output open fails at the bound too, with nothing to kill.
After a kill, the run waits five seconds more for the tester's end and its streams' close, and
goes on without them, the reason naming what stayed open. The bound is 4000 ms, 2.6 times the
slowest tester's worst CI pass (shell, 1.46 s on riscv64 debug, over 97 runs), rounded up to a
second. With the drain it holds a boot 9 s, below the 100 s added bound the CI cells' budgets are
derived with ([docs/build-system.md](../../docs/build-system.md) § Continuous Integration), so a
hung tester's FAIL line and the testers after it reach the log before the cell's budget ends the
boot; a change to the bound or the drain that takes it past 100 s re-derives those budgets. A
missing, zero or non-numeric bound fails the run before any tester starts.

---

## Seeds

usertest takes its recipe's seeds over the bootstrap protocol, up to eight slots. Slot 0 is its
own, `pwrmgr.shutdown`, with which it powers off at the end of the run. The later seeds are
authorities testers take: the recipe's env entry `TESTER_SEEDS` declares, per tester, the slots
usertest hands it (`<tester>:<slot>[,<slot>...]`, entries joined by `;`), and usertest gives that
tester a copy of each as its bootstrap caps
([runtime/ruststd/README.md](../../runtime/ruststd/README.md) § Bootstrap caps), the tester's slot
`k` being the `k`-th slot its entry names. A tester with no entry gets no creator endpoint. A
declaration that names slot 0, a slot past the eight, a tester twice, or a tester `TESTERS` does not
name, or that does not parse, fails the run before any tester starts. The recipe declares
`hello:1`: the hello tester takes `pwrmgr.deny` and checks that pwrmgr refuses it
([programs/hello/README.md](../hello/README.md) § Tester).

---

## Source Layout

```
programs/usertest/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs    # recipe env parsers, tester reconciliation, run bound (host-tested)
    └── main.rs   # seed bootstrap + discovery + spawn loop + summary marker
```

`usertest` ships no per-program testers itself. Each program under `programs/<name>/` may ship a
tester at `programs/<name>/tester/`; the tester binary lands at `/tests/programs/<name>`, is named
in the recipe's `TESTERS` (§ Testers), and is discovered at runtime, per [docs/testing.md §
Per-program tester protocol](../../docs/testing.md#per-program-tester-protocol).

---

## Relevant Design Documents

| Document | Why |
|---|---|
| [docs/testing.md](../../docs/testing.md) | System-wide test conventions: marker format, tester protocol, sysroot layout, gating. |

---

## Summarized By

[Testing](../../docs/testing.md)
