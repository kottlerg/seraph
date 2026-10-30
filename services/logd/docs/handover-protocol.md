# logd handover protocol

Wire format for the one-shot init-logd → real-logd state transfer.

svcmgr launches and supervises real-logd, minting its bootstrap caps
from the reserved log-sink sources init endows (see
[`services/svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md)).
On its **first launch**, real-logd holds a single-use SEND cap on the
master log endpoint (bootstrap `cap[1]`) and calls
`log_labels::HANDOVER_PULL` repeatedly on it. Init-logd's receive loop,
on seeing the label, replies one chunk at a time until its captured
state is drained (`DONE`). Real-logd then issues
`log_labels::HANDOVER_RELEASE`; init-logd breaks its loop and calls
`sys_thread_exit` on an acknowledged release — **not** on the drain's
`DONE`. Real-logd's existing badged SEND caps held by every other sender
remain valid because the kernel endpoint object is unchanged across the
transition.

Termination is deliberately decoupled from the data drain. The drain is a
multi-chunk lockstep over a shared, multi-sender endpoint; a kernel IPC
rendezvous race can drop one chunk under SMP. If `DONE` were the exit
trigger, such a drop would leave init-logd running forever, which blocks
procmgr's reap of init's memory caps and breaks the all-RAM-accounted identity.
Gating exit on the retried `HANDOVER_RELEASE` instead means a dropped data
chunk costs at most some unrecovered history.

Init-logd keeps serving every other sender while the drain runs, so a
sender can register or change its display name after init-logd has sent
that sender's slot. Each sender registers its name once, at startup, so a
name lost there would leave the sender's lines rendering as `[?]` for the
rest of the boot. Init-logd therefore sends such a slot again (see
[Name changes during the drain](#name-changes-during-the-drain)).

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
  Reply: `label = RELEASE_ACK (0)` — init-logd sets its internal
  `HANDOVER_COMPLETE` flag and self-terminates on its next receive-loop
  iteration — or `label = RELEASE_PENDING (1)`, by which init-logd defers
  the release and keeps serving (see
  [Name changes during the drain](#name-changes-during-the-drain)).
  Real-logd retries a release whose call fails, for up to
  `RELEASE_RETRY_BUDGET_US` (1 s) of wall-clock time, until one is delivered
  (see [Termination](#termination)).

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
non-zero slot, in slot-index order, and again for each slot whose name
changed after the slot pass began (see
[Name changes during the drain](#name-changes-during-the-drain)).

| Word | Meaning |
|---|---|
| 0 | `SLOT` |
| 1 | sender badge (kernel-delivered identity on every IPC) |
| 2 | display-name length in bytes |
| 3..  | name bytes (packed via `IpcMessage::builder.bytes(3, ...)`, offset 24 in `data_bytes`) |

The reply label's upper 16 bits carry the name length again (stream-
protocol convention). Real-logd installs each slot into its own
hash-keyed badge table via
[`SlotTable::install_from_handover`](../src/slot.rs); installing a
badge again replaces its name. Word 2 is the peer's claim: real-logd
takes at most the bytes the message carries, whatever length it
declares, and skips a `SLOT` chunk that carries no name word (an empty
name).

### `LINE` (3)

One completed log line from init-logd's bounded history ring, a byte
ring that packs lines by length and drops the oldest when full. Sent
in FIFO order, by absolute push sequence: oldest live line first. A
line the ring drops before it is sent is skipped, and lines
pushed while the drain runs are sent after the ones before them,
including by a further drain after a deferred release.

| Word | Meaning |
|---|---|
| 0 | `LINE` |
| 1 | sender badge at receipt time |
| 2 | receipt timestamp in microseconds since boot |
| 3 | line byte length |
| 4..  | line bytes (packed via `.bytes(4, ...)`, offset 32 in `data_bytes`) |

No trailing `\n`. The line is the buffered content between two
`\n`-terminated `STREAM_BYTES` flushes, unmodified. As for `SLOT`,
real-logd takes at most the bytes the message carries, whatever length
word 3 declares. Real-logd stores it via
[`SlotTable::install_history_line`](../src/slot.rs); the slot is
created lazily if no `SLOT` entry preceded it (a history line may
outlive its registering sender's slot in init-logd's small
`MAX_SENDERS` table).

## Name changes during the drain

Init-logd sends the header, then every occupied slot, then the history
lines. A `STREAM_REGISTER_NAME` that changes a slot's stored name after
the header was sent may land behind the slot pass, so init-logd records
the slot and sends it again as a further `SLOT` chunk ahead of the
remaining history lines and before `DONE`. A name change that arrives
after `DONE` and before `HANDOVER_RELEASE` is caught at the release:
init-logd answers `RELEASE_PENDING`, keeps serving, and real-logd pulls
again (receiving the recorded `SLOT` chunks, any history lines pushed
since, and `DONE`) before it repeats the release. Init-logd defers at most
`MAX_RELEASE_DEFERRALS` (8) releases and acknowledges the next one
whatever is pending, so a sender that keeps renaming itself cannot hold
the handover open; real-logd makes at most `MAX_RELEASE_DEFERRALS + 1`
pull-and-release rounds.

## Termination

After the last `LINE` (or the last `SLOT` if no history), init-logd
replies `DONE` with no data words. `DONE` transfers no exit semantics;
init-logd keeps serving. Real-logd, on seeing `DONE`, returns from its
drain and issues `HANDOVER_RELEASE`, retrying a call that fails for up to
`RELEASE_RETRY_BUDGET_US` (1 s) of wall-clock time until one is delivered (both
steps run in [`handover::transfer`](../src/handover.rs)). The budget is time, not
an attempt count, so load that slows each attempt does not shorten the window.
On `RELEASE_ACK` init-logd sets `HANDOVER_COMPLETE` and its next loop iteration
calls `sys_thread_exit`; on `RELEASE_PENDING` real-logd drains again and repeats
the release, as the previous section describes.

In-flight `STREAM_BYTES` sends from other processes queue at the kernel
endpoint and are drained by real-logd once it enters its main receive
loop.

## Failure modes

| Symptom | Cause | Recovery |
|---|---|---|
| `HANDOVER_PULL` IPC returns error mid-drain | A kernel IPC rendezvous race on the shared endpoint, or an invalid `log_ep_handover_send` | The drain returns; logd still issues `HANDOVER_RELEASE`, so init-logd is released. At most some pre-handover history, and the names of slots not yet sent, are lost. |
| `HANDOVER_RELEASE` never delivered (cap is `0`, e.g. a logd restart; or logd never launches) | No init-logd→logd channel exists | init-logd keeps serving and procmgr never reaps init; init's memory caps stay held until shutdown — a benign hold, not a wedge. procmgr does not force-stop init-logd (see [procmgr IPC interface](../../procmgr/docs/ipc-interface.md) § `INIT_TEARDOWN_DONE`). |
| `HANDOVER_RELEASE` retries exhausted (`send_release` retries for `RELEASE_RETRY_BUDGET_US` (1 s), no attempt delivered) | init-logd unreachable on the handover SEND for every attempt | `send_release` returns without an ack and logd deletes `cap[1]` regardless; init-logd keeps serving and procmgr never reaps init, so init's memory caps stay held until shutdown (the same benign hold as the row above). |
| `HANDOVER_RELEASE` deferred `MAX_RELEASE_DEFERRALS` (8) times | Senders kept registering or changing names through every round | Init-logd acknowledges the next release whatever is pending and exits; a name changed in that last window reaches real-logd only if its sender registers again. |
| Reply with unknown `word(0)` kind | Wire-format drift; one side built against an out-of-sync `logd-codec` or `shared/ipc` revision | Real-logd skips the chunk and continues. A bounded iteration cap (`MAX_ITERS`) in `pull_all` guarantees termination on a malformed reply stream. |
| `SLOT` or `LINE` length word larger than the carried payload | A malformed or hostile reply | Real-logd takes the bytes the message carries and ignores the excess; the declared length cannot overflow its bounds arithmetic. |

## Reference

The wire contract — the reply, chunk-kind, and release-status codes,
`MAX_RELEASE_DEFERRALS`, `RELEASE_RETRY_BUDGET_US`, the sender's chunk
encoders, history ring, and record of names to send again, and the
receiver's chunk decoder — is defined once, in
[`services/logd/codec/src/handover.rs`](../codec/src/handover.rs), with the
history ring in [`history.rs`](../codec/src/history.rs) beside it
([`logd-codec`](../codec/README.md), host-tested). Both ends build against it:
[`services/init/src/logging.rs`](../../init/src/logging.rs) (sender
side) and [`services/logd/src/handover.rs`](../src/handover.rs)
(receiver side).

---

## Summarized By

[System Bootstrap](../../../docs/bootstrap.md), [Console Model](../../../docs/console-model.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md), [services/logd/README.md](../README.md),
[services/logd/codec/README.md](../codec/README.md), [logd IPC interface](ipc-interface.md),
[services/procmgr/README.md](../../procmgr/README.md),
[procmgr IPC Interface](../../procmgr/docs/ipc-interface.md),
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
