# stdiotest

Test fixture that proves a line written to a child's piped stdin comes back on its piped stdout. It
uses only `std::io` and has no Seraph capability awareness. The [`svctest`](../../svctest/README.md)
`pipes` phase ([pipes.rs](../../svctest/src/phases/pipes.rs)) and `death_queue_growth` phase
([procmgr.rs](../../svctest/src/phases/procmgr.rs)) spawn it directly; and the
[shell](../../../programs/shell/README.md) per-program tester runs it through `/programs/shell` to
prove stdin forwarding. Nothing starts it automatically on a normal boot.

---

## Source Layout

```
services/fixtures/stdiotest/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Read one stdin line, print the byte count, echo, and PASS
```

`xtask` installs `stdiotest` at `/tests/fixtures/programs/stdiotest`.

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

## Driven By

Section 2 of the `pipes` phase of svctest (`services/svctest/src/phases/pipes.rs`) spawns
`/tests/fixtures/programs/stdiotest` with piped stdin, stdout, and stderr and asserts:

- before the probe is written, `try_wait` on the child returns no exit status, since the child
  blocks on stdin (`stdiotest try_wait reported an exit before its stdin was written`);
- after writing the probe `hello` and a newline and closing stdin, the trimmed stdout lines, read
  to EOF, are exactly `got 6 bytes: "hello"`, `shouted: HELLO`, and `PASS`, in that order
  (`stdiotest stdout is not the expected three-line reply`);
- stderr reads to EOF, and each line it holds is logged;
- polling `try_wait` every millisecond, up to `TRY_WAIT_POLLS` (5000) times, reports the exit
  (`stdiotest try_wait never reported the exit`), and the status is a success (`stdiotest did not
  exit cleanly`).

The `death_queue_growth` phase of `procmgr.rs` spawns it as well.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/testing.md](../../../docs/testing.md) | Harnesses and sysroot layout |
| [services/svctest/README.md](../../svctest/README.md) | The service that runs the phases |
| [runtime/ruststd/README.md](../../../runtime/ruststd/README.md) | `std` platform layer that backs piped stdio |

---

## Summarized By

None