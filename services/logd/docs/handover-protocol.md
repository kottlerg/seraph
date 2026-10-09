# logd handover protocol

Wire format for the one-shot init-logd → real-logd state transfer.

svcmgr launches and supervises real-logd, minting its bootstrap caps
from the reserved log-sink sources init endows (see
[`services/svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md)).
On its **first launch**, real-logd holds a single-use SEND cap on the
master log endpoint (bootstrap `cap[1]`) and calls
`log_labels::HANDOVER_PULL` repeatedly on it. Init-logd's receive loop,
on seeing the label, replies one chunk at a time until its captured
state is drained (`DONE`). Real-logd then issues a single
`log_labels::HANDOVER_RELEASE`; init-logd breaks its loop and calls
`sys_thread_exit` on that release — **not** on the drain's `DONE`.
Real-logd's existing badged SEND caps held by every other sender remain
valid because the kernel endpoint object is unchanged across the
transition.

Termination is deliberately decoupled from the data drain. The drain is a
multi-chunk lockstep over a shared, multi-sender endpoint; a kernel IPC
rendezvous race can drop one chunk under SMP. If `DONE` were the exit
trigger, such a drop would leave init-logd running forever, which blocks
procmgr's reap of init's memory caps and breaks the all-RAM-accounted identity.
Gating exit on the single, retried `HANDOVER_RELEASE` instead means a
dropped data chunk costs at most some unrecovered history.

A working logd **restart** is design intent; not yet implemented (#262):
svcmgr's death handler blocks on `log!` calls to the unread master-log
endpoint before it respawns logd, and procmgr's first-wins
`REGISTER_DEATH_EQ` rejects a restarted logd's registration (per
[Restart Protocol](../../svcmgr/docs/restart-protocol.md)). In the restart
code path (unreached today), svcmgr mints `cap[1] = 0`: init-logd exited after
the first launch, so there is no handover source. The restarted logd skips
the pull entirely (guarded on a non-zero `cap[1]`) and serves a fresh
table on the same endpoint object — svcmgr holds the master-log source
for the system's life, so the restarted logd's RECV re-attaches to the
object every sender already targets (see
[`service-definitions.md` § `log_sink`](../../svcmgr/docs/service-definitions.md#log_sink)).
In-flight history from the prior instance is not recoverable.

## Startup ordering

logd creates its death-notification `EventQueue` and registers it with procmgr
(`REGISTER_DEATH_EQ`) before it issues the first `HANDOVER_PULL`. The handover ends with
init-logd exiting, which lets procmgr reap init; that reap logs, and until logd enters its
receive loop the master log endpoint has no reader. Registering first, while init-logd still
serves the endpoint and procmgr is not yet reaping init, keeps logd from blocking on procmgr in
that window, which would deadlock against procmgr blocking on the unread log endpoint. After the
release, logd has no further procmgr dependency before its receive loop, so it drains the reap's
log line itself (see [`main.rs`](../src/main.rs)).

## Call shape

* Request: `IpcMessage::new(HANDOVER_PULL)`. Empty payload, no caps.
* Reply: `label = MORE (0)` for every intermediate chunk;
  `label = DONE (1)` on the terminal data chunk. `DONE` means only
  "no more data" — it does **not** terminate init-logd.
* Release: `IpcMessage::new(HANDOVER_RELEASE)`. Empty payload, no caps.
  Init-logd acks (empty reply), sets its internal `HANDOVER_COMPLETE`
  flag, and self-terminates on its next receive-loop iteration. Real-logd
  retries the release until the call is acknowledged.

The reply label's upper 16 bits (`(byte_len << 16)`) carry the
inline byte length on `SLOT` and `LINE` chunk kinds, matching the
stream-protocol convention. Real-logd masks the bottom 16 bits to
extract the status code.

## Chunk kinds

`word(0)` of each reply identifies the chunk kind. Three kinds:

### `HEADER` (1)

Always the first reply chunk. Lets real-logd size its receiving
state up front.

| Word | Meaning |
|---|---|
| 0 | `HEADER` |
| 1 | total history-line count ever pushed (monotonic; may exceed ring size if wrapped) |
| 2 | active sender-slot count (non-zero badges in init-logd's slot table) |

No inline bytes. No transferred caps.

### `SLOT` (2)

One entry from init-logd's per-sender slot table. Sent once per
non-zero slot, in slot-index order.

| Word | Meaning |
|---|---|
| 0 | `SLOT` |
| 1 | sender badge (kernel-delivered identity on every IPC) |
| 2 | display-name length in bytes |
| 3..  | name bytes (packed via `IpcMessage::builder.bytes(3, ...)`, offset 24 in `data_bytes`) |

The reply label's upper 16 bits carry the name length again (stream-
protocol convention). Real-logd installs each slot into its own
hash-keyed badge table via
[`SlotTable::install_from_handover`](../src/slot.rs).

### `LINE` (3)

One completed log line from init-logd's bounded history ring. Sent
in FIFO order: oldest entry first when the ring has wrapped; index
0 first when it has not.

| Word | Meaning |
|---|---|
| 0 | `LINE` |
| 1 | sender badge at receipt time |
| 2 | receipt timestamp in microseconds since boot |
| 3 | line byte length |
| 4..  | line bytes (packed via `.bytes(4, ...)`, offset 32 in `data_bytes`) |

No trailing `\n`. The line is the buffered content between two
`\n`-terminated `STREAM_BYTES` flushes, unmodified. Real-logd stores
it via
[`SlotTable::install_history_line`](../src/slot.rs); the slot is
created lazily if no `SLOT` entry preceded it (a history line may
outlive its registering sender's slot in init-logd's small
`MAX_SENDERS` table).

## Termination

After the last `LINE` (or the last `SLOT` if no history), init-logd
replies `DONE` with `word(0) = LINE` and zero inline bytes. `DONE`
transfers no exit semantics; init-logd keeps serving. Real-logd, on
seeing `DONE`, returns from [`handover::pull_all`](../src/handover.rs)
and calls [`handover::send_release`](../src/handover.rs), which issues
`HANDOVER_RELEASE` (retried up to `MAX_RETRIES` (64) times until acked).
Init-logd acks, sets `HANDOVER_COMPLETE`, and its next loop iteration
calls `sys_thread_exit`.

In-flight `STREAM_BYTES` sends from other processes queue at the kernel
endpoint and are drained by real-logd once it enters its main receive
loop.

## Failure modes

| Symptom | Cause | Recovery |
|---|---|---|
| `HANDOVER_PULL` IPC returns error mid-drain | A kernel IPC rendezvous race on the shared endpoint, or an invalid `log_ep_handover_send` | `pull_all` returns; logd still issues `HANDOVER_RELEASE`, so init-logd is released. At most some pre-handover history is lost. |
| `HANDOVER_RELEASE` never delivered (cap is `0`, e.g. a logd restart; or logd never launches) | No init-logd→logd channel exists | init-logd keeps serving and procmgr never reaps init; init's memory caps stay held until shutdown — a benign hold, not a wedge. procmgr does not force-stop init-logd (see `services/procmgr/src/init_reap.rs`). |
| `HANDOVER_RELEASE` retries exhausted (`send_release` makes `MAX_RETRIES` (64) attempts, none acknowledged) | init-logd unreachable on the handover SEND for every attempt | `send_release` returns without an ack and logd deletes `cap[1]` regardless; init-logd keeps serving and procmgr never reaps init, so init's memory caps stay held until shutdown (the same benign hold as the row above). |
| Reply with unknown `word(0)` kind | Wire-format drift; one side built against an out-of-sync `shared/ipc` revision | Real-logd skips the chunk and continues. A bounded iteration cap (`MAX_ITERS`) in `pull_all` guarantees termination on a malformed reply stream. |

## Reference

Wire-format constants are defined in
[`services/init/src/logging.rs`](../../init/src/logging.rs) (sender
side) and [`services/logd/src/handover.rs`](../src/handover.rs)
(receiver side). Both files cross-reference each other.

---

## Summarized By

[System Bootstrap](../../../docs/bootstrap.md), [Console Model](../../../docs/console-model.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md), [services/logd/README.md](../README.md),
[logd IPC interface](ipc-interface.md), [services/procmgr/README.md](../../procmgr/README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md),
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
