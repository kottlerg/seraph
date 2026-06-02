# logd

Owner of the master system log endpoint.

svcmgr launches and supervises logd post-handover, minting its bootstrap
round from the reserved log-sink sources init endows (see
[`services/svcmgr/docs/service-definitions.md`](../svcmgr/docs/service-definitions.md)).
logd assumes the receive side of the kernel endpoint that init-logd has
been draining since boot, ingests init-logd's captured history,
subscribes to procmgr's death-notification cascade, and from then on is
the single owner of every log line emitted by every userspace process.
It is restartable (`restart = on_failure`): svcmgr holds the master-log
endpoint source for the system's life, so a restarted logd re-attaches a
fresh RECV to the same endpoint object every sender already targets; only
the one-time init-logd history pull is skipped on restart.

## Role

* **Receiver of the master log endpoint.** Every userspace process
  holds a pre-installed tokened SEND cap on the same kernel endpoint
  (seeded into `ProcessInfo.log_send_cap` by procmgr at spawn time;
  see [`services/procmgr/src/process.rs`](../procmgr/src/process.rs)).
  Across the init-logd → real-logd handover the kernel endpoint
  object is unchanged — only the holder of the RECV cap changes —
  so every pre-existing tokened SEND cap continues to work without
  re-derivation or re-registration.

* **Driver-mediated serial writer.** logd emits received log lines
  and its own diagnostics through the userspace serial driver
  (`services/drivers/serial/`), resolved once via devmgr's
  `QUERY_SERIAL_DEVICE` and written with `SERIAL_WRITE_BYTES`. logd
  holds no UART hardware authority. It cannot route its own
  diagnostics through `seraph::log!` because it IS the log receiver;
  the macro would self-IPC into the endpoint logd serves and
  deadlock. Until the driver is resolvable, serial output is dropped
  while history still accrues; early-boot output is covered by
  init-logd's direct-UART fallback. See
  [docs/console-model.md](../../docs/console-model.md).

* **History buffer.** logd maintains a per-sender ring of completed
  log lines, populated by every `STREAM_BYTES`-derived flush and
  seeded at startup from init-logd's handover payload. Lines stay in
  memory until per-slot bounds are reached (FIFO drop). A future PR
  exposes this buffer through a query IPC and/or durable sinks
  (disk file, network syslog). For now the buffer is write-only;
  the deliverable here is the retention contract, not yet the read
  surface.

* **Per-sender slot reclamation.** logd creates an `EventQueue` and
  registers it with procmgr via `procmgr_labels::REGISTER_DEATH_EQ`
  (authorised by the `DEATH_EQ_AUTHORITY` tokened SEND cap svcmgr mints
  into logd's bootstrap round). Procmgr binds that EQ as an
  additional death observer on every existing thread and on every
  future spawn. When a process exits, logd's EQ receives
  `(process_token << 32) | exit_reason`; logd evicts the matching
  slot from its hash-keyed token table. This is the slot-table
  scale + reclamation work folded into the same service per issue
  [#1](https://github.com/kottlerg/seraph/issues/1).

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
    │                           # driver-mediated serial emit, self_log
    ├── handover.rs             # HANDOVER_PULL caller
    └── slot.rs                 # SlotTable: HashMap<token, Slot>
                                # with per-sender history ring
```

## Bootstrap caps

svcmgr's bootstrap round (one round, `done = true`) delivers four caps,
minted from the reserved log-sink sources svcmgr holds (master-log
endpoint, procmgr `SEND|GRANT`, devmgr registry):

| Index | Cap |
|---|---|
| 0 | RECV on the master log endpoint |
| 1 | SEND on the master log endpoint (single-use; carries `HANDOVER_PULL` for the history drain then the terminal `HANDOVER_RELEASE`, then deleted). `0` on a restart — there is no init-logd left to pull from, so logd skips the handover |
| 2 | Tokened SEND on procmgr's service endpoint carrying `DEATH_EQ_AUTHORITY` |
| 3 | Tokened SEND on devmgr's registry endpoint carrying `REGISTRY_QUERY_AUTHORITY` (to resolve the serial driver via `QUERY_SERIAL_DEVICE`) |

logd registers its death-EQ with procmgr before the handover pull (while
init-logd still drains the endpoint and procmgr is not yet reaping init),
then pulls cap[1] and deletes it (no other use for a SEND cap on its own
endpoint). The devmgr-registry cap is kept for the lifetime of the
process; logd uses it once to resolve and cache the serial driver's write
endpoint.

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/architecture.md](../../docs/architecture.md) | logd's role in the userspace component map |
| [docs/bootstrap.md](../../docs/bootstrap.md) | init-logd's boot role and the init → svcmgr handover that precedes logd's launch |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Death-notification cascade logd subscribes to |
| [docs/ipc-design.md](../../docs/ipc-design.md) | Endpoint identity, cap transfer semantics that make the init-logd handover possible |
| [docs/console-model.md](../../docs/console-model.md) | Console output ownership; logd as the serial driver's primary client |
| [services/init/README.md](../init/README.md) | init-logd's role + termination, and the reserved log-sink sources init endows svcmgr |
| [services/svcmgr/README.md](../svcmgr/README.md) | svcmgr's launch + supervision of logd from the `log_sink` recipe |
| [services/procmgr/README.md](../procmgr/README.md) | `REGISTER_DEATH_EQ` handler + retroactive bind |
| [services/logd/docs/handover-protocol.md](docs/handover-protocol.md) | init-logd → logd wire format |
| [services/logd/docs/ipc-interface.md](docs/ipc-interface.md) | IPC labels logd accepts |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md), [System Bootstrap](../../docs/bootstrap.md), [Console Model](../../docs/console-model.md)
