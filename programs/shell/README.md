# shell

Minimal interactive shell: the child of [`programs/terminal`](../terminal/README.md).
It reads `\n`-terminated lines from stdin, runs a small set of built-ins, and
otherwise spawns `/programs/<name>` as an external command. Pure `std` — no
Seraph cap awareness; stdin/stdout/stderr are the terminal's stdio pipes and
children are spawned via `std::process::Command`. This is v0.0.1 (#112),
replacing the `echosh` placeholder; the feature surface grows in later releases.

The terminal renders no prompt, so the shell owns the `$ ` prompt.

---

## v0.0.1 scope

- **Prompt**: `$ ` written (and flushed) before each line is read.
- **Built-ins**:
  - `help` — list the built-ins.
  - `exit` — exit the shell (the terminal respawns it).
  - `echo <args...>` — print the arguments separated by single spaces.
  - `pwd` — print the working directory.
  - `cd <path>` — change directory.
  - `ls [path]` — list a directory; with no argument, the working directory.
  - `cat <path>` — print a file's bytes.
- **Paths**: absolute and cwd-relative paths both work, including `.` and `..`.
  The shell owns an absolute working directory and resolves every path argument
  against it lexically (collapsing `.`/`..`) into an absolute path before calling
  `std` — so `cd`, `pwd`, `ls`, and `cat` are consistent. `cd` also keeps the
  process cwd cap (which external children inherit) in lockstep.
- **External commands**: a bare name `<cmd>` resolves to `/programs/<cmd>`,
  spawned with piped stdin/stdout/stderr. The child's stdout/stderr are relayed
  to the shell's, and subsequent input lines are forwarded to the child's stdin
  until it exits. An unknown command reports `command not found`.
- **Working directory**: starts at the namespace root (`/`).

## Architecture

A dedicated reader thread owns the process stdin lock and feeds lines to the
main loop over an `mpsc` channel; the main loop never reads stdin directly. When
an external command runs, a per-child waiter thread posts the child's exit onto
the same channel and two pump threads relay the child's stdout/stderr to the
shell's own stdout/stderr. The main loop then forwards subsequent input lines to
the child's stdin until the exit edge arrives.

The reader/waiter split is what lets the shell forward stdin without wedging: a
blocked stdin read cannot be cancelled, so a child that never reads stdin (e.g.
`/programs/hello`) would otherwise hang the shell until the next input line.

### Placement relative to a real shell

The shell occupies bash's *role* — the interactive REPL child of the terminal
that spawns and reaps its own children — but over a different I/O substrate. A
Unix shell does **not** relay stdin: the shell and its children share one kernel
TTY, and the kernel routes input to the foreground process group (job control).
Seraph has no shared tty and no job control yet ([#29]); the terminal relays to
exactly one pipe (the shell's stdin) and is oblivious to grandchildren. So the
shell forwarding stdin to its child is the *interim* substitute for the
shared-tty / foreground-group model — not a bash-faithful mechanism. The
Unix-faithful design (the terminal re-pointing input at the foreground
grandchild) is [#29] job control, deliberately deferred. Layering
(shell → `ruststd` → IPC) mirrors shell → libc → syscalls; the shell holds no
capabilities of its own.

## Known limitations

- **Lexical path resolution only.** `.`/`..` and relative paths are resolved
  by the shell as text against its cwd; there are no symlinks to follow, and a
  resolved path is validated only when used (`cd` validates the target exists;
  `ls`/`cat` surface the namespace error otherwise).
- **stdin-handoff race.** A line typed in the instant between an external
  child's last read and its exit may be delivered to the child rather than the
  shell. A kernel tty would avoid this via atomic foreground-group switching;
  here it is a consequence of the relay stand-in.
- **No pipes/redirection** (`|`, `>`, `<`, `>>`), **no job control**
  (`&`, `fg`, `bg`, `^Z`), **no history or line editing**, **no scripting**
  (`if`, `for`, functions, `source`), **no globbing**, and **no quoting or
  variable expansion** beyond what `std::env` already provides. Line-discipline
  maturity (signals, cooked/raw, job control) is tracked under [#29].

## Testing

Tier-3 per-program tester at `tester/` (crate `shell-tester`), installed to
`/tests/programs/shell` and run by the `usertest` orchestrator. It drives the
shell over piped stdio across two invocations — built-ins plus an external
`/programs/hello` spawn, and an `/programs/stdiotest` run fed one line to prove
stdin forwarding — and exits non-zero on any mismatch. The terminal interactive
path (the `$ ` prompt rendered via the terminal) is covered by
`cargo xtask test-terminal`. See [docs/testing.md](../../docs/testing.md).

## References

- System: [docs/console-model.md](../../docs/console-model.md),
  [docs/process-lifecycle.md](../../docs/process-lifecycle.md),
  [docs/testing.md](../../docs/testing.md).
- Parent: [`programs/terminal`](../terminal/README.md) ([#111]).

[#29]: https://github.com/kottlerg/seraph/issues/29
[#111]: https://github.com/kottlerg/seraph/issues/111
[#112]: https://github.com/kottlerg/seraph/issues/112
