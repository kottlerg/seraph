# logd

Owner of the master system log endpoint.

svcmgr launches and supervises logd post-handover, minting its bootstrap
round from the reserved log-sink sources init endows (see
[`services/svcmgr/docs/service-definitions.md`](../svcmgr/docs/service-definitions.md)).
logd assumes the receive side of the kernel endpoint that init-logd has
been draining since boot, ingests init-logd's captured history (see
[`docs/handover-protocol.md`](docs/handover-protocol.md)), subscribes to
procmgr's death-notification cascade, and from then on is the single owner
of every log line emitted by every userspace process.
It is restartable (`restart = on_failure`; see
[`services/svcmgr/docs/restart-protocol.md`](../svcmgr/docs/restart-protocol.md)):
svcmgr holds the master-log endpoint source for the system's life, so a
restarted logd re-attaches a fresh RECV to the same endpoint object every sender already
targets; only the one-time init-logd history pull
([`docs/handover-protocol.md`](docs/handover-protocol.md)) is skipped on a restart once an
instance has taken its bootstrap rounds, and such a restarted logd serves a fresh table. That
table holds no sender's display name, so logd refuses a sender's first message that says the
sender registered one (`SENDER_NAMED`), and the sender registers it again and resends the
message: every line renders under its sender's name, the first after the restart included
(see [`docs/ipc-interface.md`](docs/ipc-interface.md) § `stream_labels::STREAM_REGISTER_NAME`).

## Role

* **Receiver of the master log endpoint.** Every userspace process
  holds a pre-installed badged SEND cap on the same kernel endpoint
  (seeded into `ProcessInfo.log_send_cap` by procmgr at spawn time;
  see [docs/process-lifecycle.md](../../docs/process-lifecycle.md) and
  [`services/procmgr/src/process.rs`](../procmgr/src/process.rs)).
  Across the init-logd → real-logd handover the kernel endpoint
  object is unchanged — only the holder of the RECV cap changes —
  so every pre-existing badged SEND cap continues to work without
  re-derivation or re-registration (see
  [`docs/handover-protocol.md`](docs/handover-protocol.md)). logd
  receives on it from a pool of worker threads, each on its own IPC
  buffer page, spawned before the handover pull and receiving after it
  (see [`docs/ipc-interface.md`](docs/ipc-interface.md) § Receive pool).

* **Driver-mediated serial writer.** logd emits received log lines
  and its own diagnostics through the userspace serial driver
  (`services/drivers/serial/`), resolved via devmgr's
  `QUERY_DEVICE` on the `serial` class SEND and written with `SERIAL_WRITE_BYTES`. logd registers a
  `WATCH_CLASS` watch on the class at start and resolves the driver then, on its main thread; it
  resolves again, from that thread's wait-set loop, only when devmgr signals the watch: when
  devmgr answers that the held driver's ordinal is withdrawn, logd resolves from the next ordinal
  and deletes the replaced SEND, and it keeps a driver devmgr still serves. logd
  holds no UART hardware authority. It cannot route its own
  diagnostics through `seraph::log!` because it IS the log receiver;
  the macro would self-IPC into the endpoint logd serves and
  deadlock. For the same reason its panic / alloc-error / precondition
  output routes to the serial driver through a
  `std::os::seraph::set_panic_sink` sink rather than the log endpoint,
  and logd deletes its procmgr-seeded `ProcessInfo.log_send_cap` at
  startup so no path can self-IPC. Each line reaches the driver through the serial sink, a bounded
  queue drained by one writer thread, the only logd thread that waits on the driver: a line's
  producer waits for its write for at most `SINK_STALL_MS`, and past that the sink is stalled and
  its lines queued, then dropped and counted, until the driver writes again, so a driver that is
  stopped by a debugger or dead does not hold the log stream; a sink whose writer could not be
  spawned is written by each line's producer, and a stopped driver then costs every line up to that
  bound (see [`docs/ipc-interface.md`](docs/ipc-interface.md) § Output sinks). The panic sink calls
  the driver directly, each call bounded by the same bound. The emit path never calls devmgr: while
  no driver is resolved, serial output is dropped while history still accrues; early-boot output is
  covered by init-logd's direct-UART fallback. logd holds its own diagnostics until init-logd, which
  writes the UART directly, has acknowledged the handover release, so the two never write a line at
  once (see [`docs/handover-protocol.md`](docs/handover-protocol.md) § Startup ordering). See
  [docs/console-model.md](../../docs/console-model.md).

* **Driver-mediated framebuffer mirror.** logd also mirrors each line
  it writes to serial onto the framebuffer, resolved via
  devmgr's `QUERY_DEVICE` on the `framebuffer` class SEND, under a `WATCH_CLASS` watch handled as
  the serial driver's, and written with `FB_WRITE_BYTES`,
  so the steady-state userspace log stream reaches the screen as well as
  the UART (matching the early-kernel console). The mirror is a sink of its own, with its own
  queue and writer, so a framebuffer driver that does not answer holds neither the log stream nor
  the serial output beyond `SINK_STALL_MS`. The mirror soft-degrades
  to a no-op when no framebuffer driver is present (headless boot),
  leaving serial the authoritative channel; the emit path never queries devmgr.
  See [docs/console-model.md](../../docs/console-model.md).

* **Log records.** Beside the text stream, a sender can send a log record,
  a message and fields whose keys and values arrive length-delimited
  (`STREAM_RECORD`; `seraph::log!` with a `; key = value` list). logd
  renders each as one line, quoting and escaping a value that could
  otherwise read as further fields, and retains it with its field table
  (see [`docs/ipc-interface.md`](docs/ipc-interface.md)
  § `stream_labels::STREAM_RECORD`).

* **History buffer.** logd keeps a history of completed entries, text lines and records,
  appended on every `STREAM_BYTES` line flush and every `STREAM_RECORD` (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § History, which states the stored form) and
  seeded at startup from init-logd's handover `LINE` and `RECORD` chunks (see
  [`docs/handover-protocol.md`](docs/handover-protocol.md) § `LINE`). The history of every
  sender together is bounded by `HISTORY_BYTES` (256 KiB): an entry retained past it drops the
  oldest entries logd-wide. A sender keeps at most its last `PER_SLOT_HISTORY` (16) entries. An
  evicted slot is retired with its name and entries, a bounded number of them kept (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Retired slots).

* **Query API.** `QUERY_SLOTS` reads the sender slots, live and retired,
  with each one's name and how it was evicted, and `QUERY_HISTORY` reads the
  history of every slot or of one badge, newest first, a reply's worth per
  call. Both are served only on a SEND badged `LOG_QUERY_AUTHORITY`, which
  svcmgr mints from its master-log source and publishes seed-only as
  `logd.query`. A receive worker answers them from the state logd owns and
  calls no other service to do so (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Queries).

* **Per-sender slot reclamation.** logd creates an `EventQueue` and
  registers it with procmgr via `procmgr_labels::REGISTER_DEATH_EQ`
  (authorised by the `DEATH_EQ_AUTHORITY` badged `SEND|GRANT` cap svcmgr mints
  into logd's bootstrap round). Nothing binds that EQ as a death observer:
  procmgr posts to it the death entry `(exit_reason, process badge)` of
  every process it tears down after the registration, so procmgr, not the
  kernel, is the source of logd's death events, and the EQ needs no
  death-observer nodes (see
  [`services/procmgr/docs/ipc-interface.md`](../procmgr/docs/ipc-interface.md)
  § `REGISTER_DEATH_EQ`). logd evicts the slot of exactly that badge from
  its hash-keyed badge table and logs a `reclaim:` line, a record, naming
  the badge, the exit reason, and the slot's registered name (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Death-notification
  cascade). The EQ has a fixed
  tuning capacity. A death posted to a full EQ is dropped, so a drain that
  took a full queue's worth starts a resync: a helper thread walks procmgr's
  live badges (`QUERY_LIVE_PROCESSES`) and logd evicts the slots it snapshotted
  before the walk that the walk did not list. The walk runs on its own thread:
  no receive worker calls procmgr after startup, since procmgr's own synchronous
  log calls would deadlock against it (see [`docs/ipc-interface.md`](docs/ipc-interface.md)
  § Death-queue resync).

* **Debuggable.** The maintainer decided that logd does not declare itself
  undebuggable to procmgr (`procmgr_labels::DECLARE_NO_DEBUG`): every
  process's log output, a debug-authority holder's own included, waits on
  logd, but every log call is bounded (`LOG_CALL_TIMEOUT_MS`, then `LOG_CALL_UNANSWERED_TIMEOUT_MS`,
  [shared/log](../../shared/log/README.md)), so a holder that stops logd
  waits on its own lines for at most that bound and drops them. A fault of
  logd therefore reaches the crash service, whose report the receive workers
  logd has left serve, and svcmgr restarts logd once the fault is declined
  ([docs/supervision.md](../../docs/supervision.md)); a debug-authority
  holder can attach to it.

* **Reserve service.** logd's recipe sets `reserve = yes`, so its budget node is a
  system-reserve node: oomd, crashd and sessiond, which end a memory-pressure episode, write
  their lines through logd with a synchronous call, and a fault of logd's heap or stacks while
  the free pool is at the reserve is backed from the reserve, as is the create of its next
  instance after a crash (see
  [`services/svcmgr/docs/service-definitions.md`](../svcmgr/docs/service-definitions.md)
  § `reserve`). What logd takes from the reserve is what it grows by while memory is critical:
  its history, which `HISTORY_BYTES` (256 KiB) bounds whatever the number of senders, each live
  sender's partial line filling to `LINE_BUF_SIZE`, and a slot of about 0.5 KiB for each sender
  that sends its first line meanwhile. After a restart while memory is critical that is every live
  sender, since the new instance's table is empty, and the new instance's whole startup footprint
  is taken from the reserve as well; its history is bounded the same way
  ([docs/limits.md](../../docs/limits.md) § init and logd).

* **No core.** logd declares itself on the core path to procmgr
  (`procmgr_labels::DECLARE_NO_CORE`) at startup, before it spawns a
  thread: a core dump stops every thread of its process but the faulting
  one, and every process's log output, the crash service's line of the
  dump's outcome included, waits on logd's receive workers. The crash
  service reports a fault of logd and writes no core of it, whatever its
  `CORE_DUMP` setting names
  ([services/crashd/docs/operation.md](../crashd/docs/operation.md)
  § Core Dump).

## Out of scope (follow-up issues)

* Log rotation, durable-disk persistence.
* Network-syslog sink.

## Source Layout

```
logd/
├── Cargo.toml                  # std-built workspace member
├── README.md
├── codec/                      # logd-codec, its own component shared
│                               # with init-logd: handover wire contract,
│                               # init-logd's history ring, the resync
│                               # decisions, the reclaim line, query
│                               # paging, record
│                               # rendering, the shared line and name
│                               # widths, and BoundedStr
│                               # (see codec/README.md)
├── docs/
│   ├── handover-protocol.md    # init-logd → logd wire format
│   └── ipc-interface.md        # IPC labels logd handles
├── slot-table/                 # logd-slot-table: SlotTable, the sender
│                               # slots, their history under
│                               # HISTORY_BYTES, and the retired slots
│                               # (host-tested)
└── src/
    ├── main.rs                 # entry, bootstrap, receive-pool
    │                           # handler, control loop, serial and
    │                           # framebuffer sinks and their writers,
    │                           # self_log
    └── handover.rs             # HANDOVER_PULL / HANDOVER_RELEASE caller
```

## Bootstrap caps

svcmgr's bootstrap rounds (four slots fit a round, the last marked `done`) fill five positional
slots, carrying only the present caps and a presence word naming the slot each fills (an absent slot
reads as `0`), minted from the reserved log-sink sources svcmgr holds (master-log endpoint, procmgr
`SEND|GRANT`, `devmgr.class.serial` and `devmgr.class.framebuffer` publications; see
[`services/svcmgr/docs/service-definitions.md`](../svcmgr/docs/service-definitions.md) and
[`docs/ipc-interface.md`](docs/ipc-interface.md)):

| Index | Cap |
|---|---|
| 0 | RECV on the master log endpoint |
| 1 | SEND on the master log endpoint (single-use; carries the `HANDOVER_PULL` history drain, then the terminal `HANDOVER_RELEASE`, repeated after a further drain while init-logd defers it, then deleted; see [`docs/handover-protocol.md`](docs/handover-protocol.md)). Absent on a restart once an instance has taken all its bootstrap rounds — there is no init-logd left to pull from, so logd skips the handover; present on a restart before that, which runs the handover |
| 2 | Badged `SEND\|GRANT` on procmgr's service endpoint carrying `DEATH_EQ_AUTHORITY` |
| 3 | The `serial` class SEND, derived from the `devmgr.class.serial` publication (to resolve the serial driver via `QUERY_DEVICE`) |
| 4 | The `framebuffer` class SEND, derived from the `devmgr.class.framebuffer` publication (to resolve the framebuffer driver via `QUERY_DEVICE`) |

logd registers its death-EQ with procmgr before the handover pull and keeps
the two class SENDs for its lifetime (see
[`docs/handover-protocol.md`](docs/handover-protocol.md) § Startup ordering and
[`docs/ipc-interface.md`](docs/ipc-interface.md) § Bootstrap caps).

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | logd's role in the userspace component map |
| [docs/bootstrap.md](../../docs/bootstrap.md) | init-logd's boot role and the init → svcmgr handover that precedes logd's launch |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Death-notification cascade logd subscribes to |
| [docs/ipc-design.md](../../docs/ipc-design.md) | Endpoint identity, cap transfer semantics that make the init-logd handover possible, and the rules of multi-threaded servers |
| [shared/recv-pool/README.md](../../shared/recv-pool/README.md) | The worker pool logd receives on the master log endpoint with |
| [docs/console-model.md](../../docs/console-model.md) | Console output ownership; logd as the serial driver's primary client and a framebuffer-driver consumer |
| [services/init/README.md](../init/README.md) | init-logd's role + termination, and the reserved log-sink sources init endows svcmgr |
| [services/svcmgr/README.md](../svcmgr/README.md) | svcmgr's launch + supervision of logd from the `log_sink` recipe |
| [services/procmgr/README.md](../procmgr/README.md) | `REGISTER_DEATH_EQ` handler and the per-teardown death forward, and the `QUERY_LIVE_PROCESSES` walk logd resyncs from |
| [services/logd/docs/handover-protocol.md](docs/handover-protocol.md) | init-logd → logd wire format |
| [services/logd/docs/ipc-interface.md](docs/ipc-interface.md) | IPC labels logd accepts, the query API (`QUERY_SLOTS`, `QUERY_HISTORY`) and its `LOG_QUERY_AUTHORITY`, the history's stored form and the retired slots, and the `reclaim:` line logd logs when it evicts a slot |
| [services/crashd/docs/operation.md](../crashd/docs/operation.md) | The core dump, whose outcome line waits on logd, and so writes no core of logd, which declares itself on the core path |
| [services/logd/codec/README.md](codec/README.md) | `logd-codec`: the handover wire contract logd decodes with, the `reclaim:` line, log record rendering, and the `BoundedStr` diagnostic formatter |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md),
[Console Model](../../docs/console-model.md),
[`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)
