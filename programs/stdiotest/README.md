# stdiotest

Test fixture that proves a line written to a child's piped stdin comes back on its piped stdout. It
uses only `std::io` and has no Seraph capability awareness. Its per-program tester, which `usertest`
discovers at `/tests/programs/stdiotest`, drives it; the
[`svctest`](../../services/svctest/README.md) `pipes` phase
([pipes.rs](../../services/svctest/src/phases/pipes.rs)) spawns it directly; and the
[shell](../shell/README.md) per-program tester runs it through `/programs/shell` to prove stdin
forwarding. Nothing starts it automatically on a normal boot.

---

## Source Layout

```
programs/stdiotest/
├── Cargo.toml
├── README.md
├── src/
│   └── main.rs            # Read one stdin line, print the byte count, echo, and PASS
└── tester/
    ├── Cargo.toml         # stdiotest-tester crate
    └── src/
        └── main.rs        # Per-program tester: pipes a probe line, checks PASS and exit
```

`xtask` installs `stdiotest` at `/programs/stdiotest` and `stdiotest-tester` at
`/tests/programs/stdiotest`, as the
[per-program tester protocol](../../docs/testing.md#per-program-tester-protocol) requires.

---

## Output

`stdiotest` reads one line from stdin, strips the trailing newline, and prints three lines to
stdout before exiting with status `0`:

```
got <n> bytes: "<line>"
shouted: <LINE>
PASS
```

`<n>` is the byte count `read_line` returned, newline included; `<line>` is printed in Rust
`Debug` form, and `<LINE>` is its uppercase form. If the read fails, it writes
`read stdin failed: <error>` to stderr and exits `0` without printing `PASS`.

---

## Tester

`stdiotest-tester` spawns `/programs/stdiotest` with piped stdin and stdout, writes the probe
line `hello-stdio`, closes stdin, and reads stdout to EOF. Its verdict follows the
[tester contract](../../docs/testing.md#contract):

| Condition | Stdout | Exit code |
|---|---|---|
| Spawn, stdin write, stdout read, or wait fails | No verdict line; the tester panics through `expect` | Non-zero (panic) |
| No stdout line is `PASS` | `[stdiotest-tester] FAIL PASS marker missing from stdout`, then `[stdiotest-tester] captured stdout: <out>` | `1` |
| `stdiotest` exited non-zero | `[stdiotest-tester] FAIL non-zero exit: <code>`, with `<code>` the `Debug` form of `ExitStatus::code()` | `2` |
| Otherwise | `[stdiotest-tester] PASS` | `0` |

`<out>` is the `Debug` form of the captured stdout. The tester checks only the `PASS` line and
the exit status. The `svctest` `pipes` phase also checks the byte-count and uppercase lines for
its probe `hello`, and the shell per-program tester checks the `shouted: HELLO-STDIO` line for
its probe `hello-stdio` and the `PASS` line.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../docs/testing.md) | Harnesses, per-program tester protocol, sysroot layout |
| [services/usertest/README.md](../../services/usertest/README.md) | Orchestrator that runs the tester |
| [runtime/ruststd/README.md](../../runtime/ruststd/README.md) | `std` platform layer that backs piped stdio |

---

## Summarized By

None
