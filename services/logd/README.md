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
([`docs/handover-protocol.md`](docs/handover-protocol.md)) is skipped on a restart once procmgr
reports init reaped, and such a restarted logd serves a fresh table. That table holds no sender's
display name, so logd refuses a sender's first message that says the sender registered one
(`SENDER_NAMED`), and the sender registers it again and resends the message: every line renders
under its sender's name, the first after the restart included
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
  startup so no path can self-IPC. Each line reaches the driver through the serial sink, a cursor
  into the history and one writer thread that writes from it, the only logd thread that waits on
  the driver: no producer waits on a sink, and a log call returns once its line is retained, so a
  driver that is stopped by a debugger or dead costs logd its writer and the entries the history
  drops before the writer reaches them; a sink whose writer could not be spawned is written by the
  thread that retains each line, and a stopped driver then costs every line up to `SINK_STALL_MS`
  (see [`docs/ipc-interface.md`](docs/ipc-interface.md) § Output sinks). The panic sink calls the
  driver directly, each call bounded by the same bound, and drops its output while no driver is
  resolved. The emit path never calls devmgr: while devmgr serves no driver of a sink's class, the
  history keeps the lines, and the sink writes them to the driver its class watch resolves next;
  early-boot output is covered by init-logd's direct-UART fallback. logd retains its own
  diagnostics in the history until init-logd, which writes the UART directly, has acknowledged the
  handover release, so the two never write a line at
  once (see [`docs/handover-protocol.md`](docs/handover-protocol.md) § Startup ordering). See
  [docs/console-model.md](../../docs/console-model.md).

* **Driver-mediated framebuffer sink.** logd also writes the lines at or above the framebuffer
  sink's level to the framebuffer, resolved via
  devmgr's `QUERY_DEVICE` on the `framebuffer` class SEND, under a `WATCH_CLASS` watch handled as
  the serial driver's, and written with `FB_WRITE_BYTES`, the level tag drawn in its level's colour
  (`FB_SET_ATTRS`). Its level is critical by default, so a healthy boot shows no log line on the
  screen, and before an emergency line it writes the lines at info or more severe it did not show,
  at most its `backlog` (64 by default). The sink has its own
  cursor and writer, so a framebuffer driver that does not answer holds neither the log stream nor
  the serial output, and it never holds a sender. When no framebuffer driver is present
  (headless boot) the sink writes nothing; a driver that comes up later starts at the newest
  `backlog` entries and counts the ones before them that it shows as dropped, leaving serial the
  authoritative channel; the emit path never queries devmgr.

* **Sink settings.** Each sink's level, format (the console format with a field list, or
  rfc5424), pace, backlog, `relayed` and colour come from the `LOGD_SINK_SERIAL` and
  `LOGD_SINK_FRAMEBUFFER` `env` entries of logd's recipe over built-in defaults, serial at info
  and the framebuffer at critical; an entry that does not parse keeps the defaults and is logged at
  warning. A `SINK_SET` on `logd.control` changes them while logd runs
  ([`docs/ipc-interface.md`](docs/ipc-interface.md) § Sink control). The history keeps every entry
  whatever the sinks show (see [`docs/sinks.md`](docs/sinks.md) § Settings).
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
  [`docs/handover-protocol.md`](docs/handover-protocol.md) § `LINE`). The history of every sender
  together is bounded by a byte bound fixed at start, the machine's RAM over 2048 within
  `HISTORY_BYTES_MIN` (256 KiB) and `HISTORY_BYTES_MAX` (2 MiB): an entry retained past it drops the
  oldest entry no `hold` sink (serial by default) shows and has not written, else the oldest entry
  of the slot with the most entries. A sender keeps at most its last `PER_SLOT_HISTORY_MIN` (32)
  entries, scaled by the byte bound's ratio to the floor, a further one dropping its oldest entry no
  `hold` sink shows and has not written, else its oldest; the kernel's slot and logd's own, which no
  window paces, also keep past it the entries a `hold` sink shows and has not written, within the
  byte bound. The history is also the journal the sinks write from. An evicted slot is retired with
  its name and entries, a bounded number of them kept (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Retired slots).
* **Kernel log reader.** From the handover's release on, and at each restart, a thread of logd reads
  the kernel's console records and writes each as a `[<t>] LEVEL  [kernel] <text>` line through the
  sinks. The lines are kept in the kernel's slot, badge `LOG_BADGE_KERNEL` (3), named `kernel`,
  which `QUERY_SLOTS` and `QUERY_HISTORY` return like any sender's slot and which no eviction takes.
  A sender that registers the name `kernel` is stored as `kernel_`
  (`logd_codec::kernel::stored_name`). A gap in the record sequence is named in a warning line of
  logd's (see [`docs/handover-protocol.md`](docs/handover-protocol.md) § Kernel log and
  [docs/console-model.md](../../docs/console-model.md) item 4).

* **Query API.** `QUERY_SLOTS` reads the sender slots, live and retired,
  with each one's name and how it was evicted, and `QUERY_HISTORY` reads the
  history of every slot or of one badge, newest first, or oldest first from a
  given `seq`, filtered by badge and least level, a reply's worth per call.
  `LOG_SUBSCRIBE` signals a subscriber's Notification on each retained entry
  until it deletes the token the reply moved it. Those three are served on a SEND badged
  `LOG_QUERY_AUTHORITY` or `LOG_FOLLOW_AUTHORITY` (`QUERY_SLOTS` and `QUERY_HISTORY` on either),
  which svcmgr mints from its master-log source and publishes seed-only as `logd.query` and
  `logd.follow`. `SINK_LIST` and `SINK_SET` read and set the sinks' settings, and are served only
  on a SEND badged `LOG_CONTROL_AUTHORITY`, published seed-only as `logd.control`. A receive worker
  answers them from the state logd owns and calls no other service to do so (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Queries, § Subscriptions and § Sink control).
* **Flush barrier.** `LOG_FLUSH` answers whether the sink that holds the log (serial) has written
  the lines logd had taken when the barrier was first asked, `FLUSHED` at once when no sink holds it
  or that sink is stalled, unserved or off, and `FLUSH_PENDING` with a retry hint otherwise. It is
  served only on a SEND badged `LOG_FLUSH_AUTHORITY`, which svcmgr mints from its master-log source
  and publishes seed-only as `logd.flush`; pwrmgr and acpid wait on it before every power-off and
  reset, and crashd before it declines a fault (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § Flush barrier).

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
  its history, which its byte bound (256 KiB to 2 MiB) holds whatever the number of senders,
  each live sender's partial line filling to `LINE_BUF_SIZE`, and a slot of about 0.5 KiB for each
  sender that sends its first line meanwhile. After a restart while memory is critical that is
  every live sender, since the new instance's table is empty, and the new instance's whole startup
  footprint is taken from the reserve as well; its history is bounded the same way
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

## Out of scope

Disk persistence with rotation and a network syslog sink are external sinks, processes that follow
logd's history; logd itself holds no file system and no network stack. Their interface, with
the per-sink settings and the record's RFC 5424 mapping, is designed in
[`docs/sinks.md`](docs/sinks.md): logd's side of it, the query, follow and control interface, is
built (#1494), and the external sinks themselves are design intent (#1496, #1499).

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
│   ├── ipc-interface.md        # IPC labels logd handles
│   └── sinks.md                # sink contract, record, formats, settings
├── slot-table/                 # logd-slot-table: SlotTable, the sender
│                               # slots, their history under
│                               # the history's byte bound, and the retired slots
│                               # (host-tested)
└── src/
    ├── main.rs                 # entry, bootstrap, receive-pool
    │                           # handler, control loop, serial and
    │                           # framebuffer sinks and their writers,
    │                           # self_log
    └── handover.rs             # HANDOVER_PULL / HANDOVER_RELEASE caller
```

## Bootstrap caps

svcmgr's bootstrap rounds (four slots fit a round, the last marked `done`) fill seven positional
slots, carrying only the present caps and a presence word naming the slot each fills (an absent slot
reads as `0`), minted from the reserved log-sink sources svcmgr holds (master-log endpoint, procmgr
`SEND|GRANT`, `KernelLog`) and from the `devmgr.class.serial`, `devmgr.class.framebuffer` and
`timed` publications; see
[`services/svcmgr/docs/service-definitions.md`](../svcmgr/docs/service-definitions.md) and
[`docs/ipc-interface.md`](docs/ipc-interface.md)):

| Index | Cap |
|---|---|
| 0 | RECV on the master log endpoint |
| 1 | SEND on the master log endpoint (single-use; carries the `HANDOVER_PULL` history drain, then the terminal `HANDOVER_RELEASE`, repeated after a further drain while init-logd defers it, then deleted; see [`docs/handover-protocol.md`](docs/handover-protocol.md)). Absent on a restart once procmgr reports init reaped — there is no init-logd left to pull from, so logd skips the handover; present on a restart before that (or when the query fails), which runs the handover |
| 2 | Badged `SEND\|GRANT` on procmgr's service endpoint carrying `DEATH_EQ_AUTHORITY` |
| 3 | The `serial` class SEND, derived from the `devmgr.class.serial` publication (to resolve the serial driver via `QUERY_DEVICE`) |
| 4 | The `framebuffer` class SEND, derived from the `devmgr.class.framebuffer` publication (to resolve the framebuffer driver via `QUERY_DEVICE`) |
| 5 | A `KernelLog` cap carrying `Read`, derived with `RIGHTS_KLOG_READ` from the `KernelLog` source svcmgr holds (to read the kernel's console lines; see [`docs/handover-protocol.md`](docs/handover-protocol.md) § Kernel log). Absent when svcmgr holds none |
| 6 | The `timed` SEND, derived from the `timed` publication (to read the wall clock once; see [`docs/sinks.md`](docs/sinks.md) § Wall time). Absent when no recipe provides `timed` |

logd registers its death-EQ with procmgr before the handover pull and keeps the two class SENDs for
its lifetime, and deletes the `timed` SEND once it has read the wall clock (see
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
| [services/logd/docs/sinks.md](docs/sinks.md) | The sink contract (device and external sinks), the record and its RFC 5424 mapping, the per-sink settings, the console format, and the query, follow and control interface; the external sinks are design intent |
| [services/logd/docs/ipc-interface.md](docs/ipc-interface.md) | IPC labels logd accepts, the query API (`QUERY_SLOTS`, `QUERY_HISTORY`, `LOG_SUBSCRIBE`) and its `LOG_QUERY_AUTHORITY` and `LOG_FOLLOW_AUTHORITY`, the sink control (`SINK_LIST`, `SINK_SET`) and its `LOG_CONTROL_AUTHORITY`, the history's stored form and the retired slots, and the `reclaim:` line logd logs when it evicts a slot |
| [services/crashd/docs/operation.md](../crashd/docs/operation.md) | The core dump, whose outcome line waits on logd, and so writes no core of logd, which declares itself on the core path |
| [services/logd/codec/README.md](codec/README.md) | `logd-codec`: the handover wire contract logd decodes with, the `reclaim:` line, log record rendering, and the `BoundedStr` diagnostic formatter |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md),
[Console Model](../../docs/console-model.md),
[`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)
