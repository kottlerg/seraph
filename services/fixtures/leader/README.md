# leader

Session leader of svctest's operator sessions: a line-oriented command loop that stands in for the
shell on a services-layer image.

---

## Role

sessiond starts a session's leader from the recipe's `argv[1]` and passes it no argument. A
services-layer image holds no program, so its sessiond recipe,
`rootfs/config/svcmgr/tests/sessiond.svc`, names this fixture, which speaks the protocol svctest's
`sessiond_operator` and `oom_policy` phases drive. It is its own binary because the recipe names an
image and the services layer has no `/programs/shell`. It installs at
`/tests/fixtures/programs/leader`.

---

## Source Layout

```
leader/
├── Cargo.toml
├── README.md
└── src/
    └── main.rs            # Reader thread, command loop, job runner, output pumps
```

---

## Behaviour

The leader prints the prompt `$ ` before each command and reads one line from stdin.

| Command | Effect |
|---|---|
| `echo <args>` | Prints the arguments, separated by single spaces, and a newline to stdout |
| `exit` | Ends the leader with status `0` |
| a word containing `/` | Starts the image at that path as a job, with the rest of the line as its arguments; its stdout and stderr are copied to the leader's, and each later line is forwarded to its stdin until it ends, after which the leader prompts again. A failed start prints `leader: <path>: <error>` to stderr |
| anything else | Prints `leader: command not found: <cmd>` to stderr |

End of input ends the leader; when it comes while a job runs, the job's stdin closes and the leader
ends after the job. A reader thread owns the stdin lock and feeds the main loop over a channel, and
a waiter thread posts a job's end onto the same channel, so a job that never reads its stdin does
not leave the leader blocked in a read when the job ends.

---

## Driven By

The `sessiond_operator` phase of svctest (`services/svctest/src/phases/sessiond.rs`) opens
sessions through sessiond's operator interface and drives their leader. It asserts that:

- the leader echoes `sessiond-echo-ok` for `echo sessiond-echo-ok`;
- a job started by path (`/tests/fixtures/programs/crashme oom-hold 16`) prints `holding 16`, and
  the session is listed as a stop candidate, and so is the job, named by that path and with at least
  16 pages;
- after the job is stopped, the leader prompts `$ `, echoes again, and exits with status `0` on
  `exit`, which ends the session.

The `oom_policy` phase (`oom.rs`) opens a session whose leader runs a job that oomd stops, and
asserts that the leader does not exit cleanly while oomd stops programs. The `namespace` phase
asserts that `NS_READDIR` of `/tests/fixtures/programs` surfaces `leader` verbatim.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/sessiond/README.md](../../sessiond/README.md) | The session service that starts the leader |
| [services/svctest/README.md](../../svctest/README.md) | The harness that drives the sessions |
| [docs/session-supervision.md](../../../docs/session-supervision.md) | Sessions, jobs, and oomd's stop order |

---

## Summarized By

[services/fixtures/README.md](../README.md)