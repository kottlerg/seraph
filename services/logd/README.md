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
It is declared restartable (`restart = on_failure`); a working restart is design
intent; not yet implemented ([#262](https://github.com/kottlerg/seraph/issues/262); see
[`services/svcmgr/docs/restart-protocol.md`](../svcmgr/docs/restart-protocol.md)). In the
intended model, svcmgr holds the master-log endpoint source for the system's life, so a
restarted logd re-attaches a fresh RECV to the same endpoint object every sender already
targets; only the one-time init-logd history pull
([`docs/handover-protocol.md`](docs/handover-protocol.md)) is skipped on restart.

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
  [`docs/handover-protocol.md`](docs/handover-protocol.md)).

* **Driver-mediated serial writer.** logd emits received log lines
  and its own diagnostics through the userspace serial driver
  (`services/drivers/serial/`), resolved once via devmgr's
  `QUERY_SERIAL_DEVICE` and written with `SERIAL_WRITE_BYTES`. logd
  holds no UART hardware authority. It cannot route its own
  diagnostics through `seraph::log!` because it IS the log receiver;
  the macro would self-IPC into the endpoint logd serves and
  deadlock. For the same reason its panic / alloc-error / precondition
  output routes to the serial driver through a
  `std::os::seraph::set_panic_sink` sink rather than the log endpoint,
  and logd deletes its procmgr-seeded `ProcessInfo.log_send_cap` at
  startup so no path can self-IPC. Until the driver is resolvable,
  serial output is dropped while history still accrues; early-boot
  output is covered by init-logd's direct-UART fallback. See
  [docs/console-model.md](../../docs/console-model.md).

* **Driver-mediated framebuffer mirror.** logd also mirrors each line
  it writes to serial onto the framebuffer, resolved at most once via
  devmgr's `QUERY_FRAMEBUFFER_DEVICE` and written with `FB_WRITE_BYTES`,
  so the steady-state userspace log stream reaches the screen as well as
  the UART (matching the early-kernel console). The mirror soft-degrades
  to a no-op when no framebuffer driver is present (headless boot),
  leaving serial the authoritative channel; the resolution is attempted
  exactly once so a headless boot does not re-query devmgr per line.
  See [docs/console-model.md](../../docs/console-model.md).

* **History buffer.** logd keeps a bounded per-sender ring of completed
  log lines (oldest line dropped when full), appended on every
  `STREAM_BYTES` line flush (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md) § `stream_labels::STREAM_BYTES`)
  and seeded at startup from init-logd's handover `LINE` chunks (see
  [`docs/handover-protocol.md`](docs/handover-protocol.md) § `LINE`). The
  ring has no read surface. TODO: a query IPC that reads the history ring.

* **Per-sender slot reclamation.** logd creates an `EventQueue` and
  registers it with procmgr via `procmgr_labels::REGISTER_DEATH_EQ`
  (authorised by the `DEATH_EQ_AUTHORITY` badged SEND cap svcmgr mints
  into logd's bootstrap round). Procmgr binds that EQ as an
  additional death observer on every existing thread and on every
  future spawn (see
  [`services/procmgr/docs/ipc-interface.md`](../procmgr/docs/ipc-interface.md)).
  When a process exits, logd's EQ receives
  `(process_badge << 32) | exit_reason`; logd evicts the matching
  slot from its hash-keyed badge table (see
  [`docs/ipc-interface.md`](docs/ipc-interface.md)).

## Out of scope (follow-up issues)

* Log rotation, durable-disk persistence, query API.
* Network-syslog sink.

## Source Layout

```
logd/
├── Cargo.toml                  # std-built workspace member
├── README.md
├── docs/
│   ├── handover-protocol.md    # init-logd → logd wire format
│   └── ipc-interface.md        # IPC labels logd handles
└── src/
    ├── main.rs                 # entry, bootstrap, event loop,
    │                           # driver-mediated serial + framebuffer
    │                           # emit, self_log
    ├── handover.rs             # HANDOVER_PULL caller
    └── slot.rs                 # SlotTable: HashMap<badge, Slot>
                                # with per-sender history ring
```

## Bootstrap caps

svcmgr's bootstrap round (one round, `done = true`) delivers four caps,
minted from the reserved log-sink sources svcmgr holds (master-log
endpoint, procmgr `SEND|GRANT`, devmgr registry; see
[`services/svcmgr/docs/service-definitions.md`](../svcmgr/docs/service-definitions.md)
and [`docs/ipc-interface.md`](docs/ipc-interface.md)):

| Index | Cap |
|---|---|
| 0 | RECV on the master log endpoint |
| 1 | SEND on the master log endpoint (single-use; carries the `HANDOVER_PULL` history drain, then the terminal `HANDOVER_RELEASE`, then deleted; see [`docs/handover-protocol.md`](docs/handover-protocol.md)). `0` on a restart — there is no init-logd left to pull from, so logd skips the handover |
| 2 | Badged SEND on procmgr's service endpoint carrying `DEATH_EQ_AUTHORITY` |
| 3 | Badged SEND on devmgr's registry endpoint carrying `REGISTRY_QUERY_AUTHORITY` (to resolve the serial driver via `QUERY_SERIAL_DEVICE` and the framebuffer driver via `QUERY_FRAMEBUFFER_DEVICE`) |

logd registers its death-EQ with procmgr before the handover pull and keeps
the devmgr-registry cap for its lifetime (see
[`docs/handover-protocol.md`](docs/handover-protocol.md) § Startup ordering and
[`docs/ipc-interface.md`](docs/ipc-interface.md) § Bootstrap caps).

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | logd's role in the userspace component map |
| [docs/bootstrap.md](../../docs/bootstrap.md) | init-logd's boot role and the init → svcmgr handover that precedes logd's launch |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Death-notification cascade logd subscribes to |
| [docs/ipc-design.md](../../docs/ipc-design.md) | Endpoint identity, cap transfer semantics that make the init-logd handover possible |
| [docs/console-model.md](../../docs/console-model.md) | Console output ownership; logd as the serial driver's primary client and a framebuffer-driver consumer |
| [services/init/README.md](../init/README.md) | init-logd's role + termination, and the reserved log-sink sources init endows svcmgr |
| [services/svcmgr/README.md](../svcmgr/README.md) | svcmgr's launch + supervision of logd from the `log_sink` recipe |
| [services/procmgr/README.md](../procmgr/README.md) | `REGISTER_DEATH_EQ` handler + retroactive bind |
| [services/logd/docs/handover-protocol.md](docs/handover-protocol.md) | init-logd → logd wire format |
| [services/logd/docs/ipc-interface.md](docs/ipc-interface.md) | IPC labels logd accepts |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md),
[Console Model](../../docs/console-model.md),
[`.svc` Service Definitions](../svcmgr/docs/service-definitions.md)
