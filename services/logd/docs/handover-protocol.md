# logd handover protocol

Wire format for the one-shot init-logd → real-logd state transfer.

svcmgr launches and supervises real-logd, minting its bootstrap caps
from the reserved log-sink sources init endows (see
[`services/svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md)).
On its **first launch**, real-logd holds a single-use SEND cap on the
master log endpoint (bootstrap `cap[1]`, unbadged) and calls
`log_labels::HANDOVER_PULL` repeatedly on it. Init-logd serves the two
handover labels only on that unbadged SEND
(`logd_codec::handover::drives_handover`); from a log sender's badged SEND
it answers them as an unknown label, with an empty reply, so no sender can
pull the drain or end init-logd. Init-logd's receive loop,
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
that sender's slot. Each sender registers its name once, at startup; a name
lost there would reach real-logd only when real-logd refuses the sender's next
line for it and the sender registers again
([`ipc-interface.md`](ipc-interface.md) § `stream_labels::STREAM_REGISTER_NAME`),
which costs that sender two calls. Init-logd therefore sends such a slot again (see
[Name changes during the drain](#name-changes-during-the-drain)).

On a logd **restart** (per
[Restart Protocol](../../svcmgr/docs/restart-protocol.md#supervision-hierarchy))
svcmgr asks procmgr `QUERY_INIT_REAP`. While procmgr does not report init reaped (which
follows init-logd's exit), or the query fails, the restart's round is the first launch's,
`cap[1]` included, and the restarted logd pulls init-logd's history and releases it as the first
launch would have; the pull continues init-logd's drain where a dead instance left it, so history
that instance already pulled is not resent. Once procmgr reports init reaped, svcmgr mints
`cap[1] = 0`: there is no handover source. A restarted logd
minted `cap[1] = 0` skips the pull entirely (guarded on a non-zero
`cap[1]`) and serves a fresh table on the same endpoint object — svcmgr holds the master-log source
for the system's life, so the restarted logd's RECV re-attaches to the
object every sender already targets (see
[`service-definitions.md` § `log_sink`](../../svcmgr/docs/service-definitions.md#log_sink)).
In-flight history from the prior instance is not recoverable. The senders'
display names are not carried over either, but each sender keeps its own: the
restarted logd refuses a sender's first message that says the sender has a name
(`SENDER_NAMED`) with `NAME_UNKNOWN`, the sender registers the name again and
resends the message, so every line, the first after the restart included, renders
under the sender's name ([`ipc-interface.md`](ipc-interface.md)
§ `stream_labels::STREAM_REGISTER_NAME`).

## Startup ordering

logd creates its death-notification `EventQueue` and registers it with procmgr
(`REGISTER_DEATH_EQ`) before it issues the first `HANDOVER_PULL`. The handover ends with
init-logd exiting, which lets procmgr reap init; that reap logs, and until logd's receive workers
start receiving the master log endpoint has no reader. Registering first, while init-logd still
serves the endpoint and procmgr is not yet reaping init, keeps logd from blocking on procmgr in
that window, which would deadlock against procmgr blocking on the unread log endpoint. For the same
reason logd spawns its receive workers before the pull, behind the receive pool's gate: each
worker's start waits on procmgr's thread registration, and the spawn returns once every worker
has started ([`ipc-interface.md`](ipc-interface.md) § Receive pool). After the release, logd has
no further procmgr dependency before it opens the gate, so its workers drain the reap's log line
(see [`main.rs`](../src/main.rs)).

Until init-logd acknowledges the release, it writes each line it forwards to the UART directly, byte
by byte, and logd's serial writes go through the serial driver to the same UART; the two share no
lock, so a line of each written at once interleaves byte by byte, and a reader of the serial stream
sees neither line whole. logd therefore writes nothing to the serial driver of its own before the
release. It resolves the serial and framebuffer drivers through devmgr first, before it creates
its death queue, writing nothing: a halt on a later start step writes its `FATAL` line, and the
panic sink its output, only to a resolved serial driver, and its first write after the release
then does not call devmgr while the log endpoint has no reader. A driver devmgr does not serve by
then is resolved later on its class watch, and its sink queues the lines meanwhile
([`ipc-interface.md`](ipc-interface.md) § Output sinks). It also holds each line it self-logs, at
most `SELF_LOG_HELD_MAX` (12) of them, and writes them in order, with the time each was logged, once
`handover::transfer` returns. A line past that bound is dropped and counted, and logd writes the
count in one line after the held ones. Init-logd writes its last line,
`handover complete; init-logd thread exiting`, before it acknowledges the release, and nothing
after it. Two writes are not held: logd's panic sink, and a `FATAL` line on the way to a halt,
which writes the held lines first. A restarted logd with no handover source (`cap[1] = 0`, minted
once init is reaped) holds nothing.
When no release reaches init-logd (§ Failure modes), logd writes the held lines when the attempts
end, and its serial writes can then interleave with init-logd's.

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
* Every handover call, pull and release, is bounded by `HANDOVER_CALL_TIMEOUT_MS` (1000 ms),
  the wait for a receiver and for the reply together.

Bits 16-31 of the reply label (`(byte_len << 16)`) carry the
inline byte length on `SLOT`, `LINE`, and `RECORD` chunk kinds, and bits
32-35 the entry's level on `LINE` and `RECORD`, matching the stream-protocol
convention
([`ipc-interface.md`](ipc-interface.md) § Levels). Real-logd masks the
bottom 16 bits to extract the status code.

## Chunk kinds

`word(0)` of each reply identifies the chunk kind. Four kinds:

### `HEADER` (1)

Always the first reply chunk. Lets real-logd size its receiving
state up front.

| Word | Meaning |
|---|---|
| 0 | `HEADER` |
| 1 | total history-entry count ever pushed, text lines and records (monotonic; exceeds the entries the ring still holds once it has dropped its oldest) |
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
[`SlotTable::install_from_handover`](../slot-table/src/lib.rs); installing a
badge again replaces its name. Word 2 is the peer's claim: real-logd
takes at most the bytes the message carries, whatever length it
declares, and skips a `SLOT` chunk that carries no name word (an empty
name).

### `LINE` (3)

One completed log line from init-logd's bounded history ring, a byte
ring that packs its entries, text lines and records, by length and drops
the oldest when full. Entries are sent in FIFO order, by absolute push
sequence: oldest live entry first, each a `LINE` or a `RECORD` chunk as its
kind says. An entry the ring drops before it is sent is skipped, and
entries pushed while the drain runs are sent after the ones before them,
including by a further drain after a deferred release.

| Word | Meaning |
|---|---|
| 0 | `LINE` |
| 1 | sender badge at receipt time |
| 2 | receipt timestamp in microseconds since boot |
| 3 | line byte length |
| 4..  | line bytes (packed via `.bytes(4, ...)`, offset 32 in `data_bytes`) |

No trailing `\n`. The line is the buffered content between two
`\n`-terminated `STREAM_BYTES` flushes, unmodified. The line's level
rides the reply label's level field (bits 32-35, a
`ipc::stream_labels::LEVEL_*` code plus one; a label without one reads as info).
As for `SLOT`, real-logd takes at most the bytes the message carries,
whatever length word 3 declares. Real-logd stores it, with its level, via
[`SlotTable::install_history_line`](../slot-table/src/lib.rs); the slot is
created lazily if no `SLOT` entry preceded it (a history entry may
outlive its registering sender's slot in init-logd's small
`MAX_SENDERS` table).

### `RECORD` (4)

One log record from the same history ring
([`ipc-interface.md`](ipc-interface.md) § `stream_labels::STREAM_RECORD`),
in the ring's push order with the `LINE` chunks.

| Word | Meaning |
|---|---|
| 0 | `RECORD` |
| 1 | sender badge at receipt time |
| 2 | receipt timestamp in microseconds since boot |
| 3 | record byte length |
| 4..  | the record's payload as it arrived (packed via `.bytes(4, ...)`, offset 32 in `data_bytes`) |

A record is at most `RECORD_MAX_BYTES` (480) bytes, which the 60 data words
after word 3 hold whole. The level rides the reply label as on `LINE`, and
real-logd takes at most the bytes the message carries, as for `LINE`. It
stores a record that `ipc::log_record` decodes, with its level and field
table, via [`SlotTable::install_history_record`](../slot-table/src/lib.rs), creating
the slot as for `LINE`, and skips one that does not decode.

## Name changes during the drain

Init-logd sends the header, then every occupied slot, then the history
lines. A `STREAM_REGISTER_NAME` that changes a slot's stored name after
the header was sent may land behind the slot pass, so init-logd records
the slot and sends it again as a further `SLOT` chunk ahead of the
remaining history entries and before `DONE`. A name change that arrives
after `DONE` and before `HANDOVER_RELEASE` is caught at the release:
init-logd answers `RELEASE_PENDING`, keeps serving, and real-logd pulls
again (receiving the recorded `SLOT` chunks, any history entries pushed
since, and `DONE`) before it repeats the release. Init-logd defers at most
`MAX_RELEASE_DEFERRALS` (8) releases and acknowledges the next one
whatever is pending, so a sender that keeps renaming itself cannot hold
the handover open; real-logd makes at most `MAX_RELEASE_DEFERRALS + 1`
pull-and-release rounds.

## Termination

After the last `LINE` or `RECORD` (or the last `SLOT` if no history), init-logd
replies `DONE` with no data words. `DONE` transfers no exit semantics;
init-logd keeps serving. Real-logd, on seeing `DONE`, returns from its
drain and issues `HANDOVER_RELEASE`, retrying a call that fails for up to
`RELEASE_RETRY_BUDGET_US` (1 s) of wall-clock time until one is delivered (both
steps run in [`handover::transfer`](../src/handover.rs)). The budget is time, not
an attempt count, so load that slows each attempt does not shorten the window.
On `RELEASE_ACK` init-logd writes its last line, replies, sets `HANDOVER_COMPLETE`, and its
next loop iteration calls `sys_thread_exit`; on `RELEASE_PENDING` real-logd drains again and repeats
the release, as the previous section describes. A call that runs out of
`HANDOVER_CALL_TIMEOUT_MS` ends the drain as a failed call does; a restarted logd minted the SEND
after init-logd exited but before procmgr's reap (its receive workers wait behind the receive
pool's gate, so no thread receives) ends its transfer with nothing pulled, after at most one bound
on the pull and one on the release. A release that runs out may have been taken, and init-logd
may have answered it, acknowledged or deferred, after the expiry, so real-logd does not take it as
unreached: it drains again, and releases again if init-logd answers any call of that drain. An
init-logd that exited on the release answers none, which ends the transfer after one bound more
([`run_rounds`](../codec/src/handover.rs)).

In-flight `STREAM_BYTES` and `STREAM_RECORD` sends from other processes queue at the kernel
endpoint and are drained by real-logd once it enters its main receive
loop.

## Kernel log

init-logd is the kernel log's first reader
([docs/console-model.md](../../../docs/console-model.md) item 3), and its history holds the
kernel's lines under `LOG_BADGE_KERNEL` (3), which the drain sends as any slot's lines. The first
`HANDOVER_PULL` ends that reading: before init-logd builds the first chunk it reads what the
kernel holds, writes and records it, acknowledges it with an empty read, and unbinds its
notification; it reads no more. An acknowledged release with no pull before it (a pull the
kernel dropped) ends the reading the same way before init-logd's last line. The history the
drain sends therefore holds every kernel line init-logd wrote, and no line is written twice.

The records the kernel appends from then on wait in its ring. Once it holds the drained table,
real-logd names the kernel's slot `kernel` and, through the `KernelLog` cap in its bootstrap slot
5 ([README](../README.md) § Bootstrap caps), binds a notification of its own and reads from the
record after the last one acknowledged (`from_seq` 0), so it writes exactly the records
init-logd left. When the release takes longer than `KLOG_STALL_MS` after the first of them was
appended, the kernel detaches the reader and writes its lines directly until real-logd's first
read attaches it again; the records of that wait are written then, each stamped with its own
time. A restarted logd reads the same way with no handover: the dead instance's binding was
cleared when its notification was freed, and the new one's bind replaces any binding left.

## Failure modes

| Symptom | Cause | Recovery |
|---|---|---|
| `HANDOVER_PULL` IPC returns error mid-drain | A kernel IPC rendezvous race on the shared endpoint, or an invalid `log_ep_handover_send` | The drain returns; logd still issues `HANDOVER_RELEASE`, so init-logd is released. At most some pre-handover history is lost. The names of slots not yet sent reach real-logd when each sender's next message is refused for its name and the sender registers again ([`ipc-interface.md`](ipc-interface.md) § `stream_labels::STREAM_REGISTER_NAME`). |
| `HANDOVER_RELEASE` never delivered (logd never launches, or every instance dies before its release and svcmgr restarts none after the last) | No init-logd→logd channel exists | init-logd keeps serving and procmgr never reaps init; init's memory caps stay held until shutdown — a benign hold, not a wedge. procmgr does not force-stop init-logd (see [procmgr IPC interface](../../procmgr/docs/ipc-interface.md) § `INIT_TEARDOWN_DONE`). |
| `HANDOVER_RELEASE` retries exhausted (`send_release` retries for `RELEASE_RETRY_BUDGET_US` (1 s), no attempt delivered, the last failing other than by running out) | init-logd unreachable on the handover SEND for every attempt | `send_release` returns without an ack and logd deletes `cap[1]` regardless; init-logd keeps serving and procmgr never reaps init, so init's memory caps stay held until shutdown (the same benign hold as the row above, unless a restart of logd releases it). |
| Handover call runs out (`HANDOVER_CALL_TIMEOUT_MS`) | No init-logd receives (it exited after svcmgr minted the SEND, before procmgr's reap), or init-logd did not answer within the bound | The drain ends as on a failed call, and logd still issues the release, whose attempts are bounded the same way. A release that runs out (the first attempt's bound spends `RELEASE_RETRY_BUDGET_US`) may have been taken and answered after the expiry, so logd drains again and, when init-logd answers that drain, releases again, within the `MAX_RELEASE_DEFERRALS + 1` rounds. With no init-logd receiving, the transfer ends after one bound on the pull and one on the release, and an init-logd that exited on a release it answered late costs one bound more, on the next pull; logd then serves what it pulled. |
| `HANDOVER_RELEASE` deferred `MAX_RELEASE_DEFERRALS` (8) times | Senders kept registering or changing names through every round | Init-logd acknowledges the next release whatever is pending and exits; a name first registered in that last window reaches real-logd when the sender's next message is refused for it and the sender registers again, and a name changed there reaches it only if its sender registers again. |
| Reply with unknown `word(0)` kind | Wire-format drift; one side built against an out-of-sync `logd-codec` or `shared/ipc` revision | Real-logd skips the chunk and continues. A bounded iteration cap (`MAX_ITERS`) in `pull_all` guarantees termination on a malformed reply stream. |
| `SLOT`, `LINE`, or `RECORD` length word larger than the carried payload | A malformed or hostile reply | Real-logd takes the bytes the message carries and ignores the excess; the declared length cannot overflow its bounds arithmetic. |
| `RECORD` payload that does not decode as a record | A malformed or hostile reply | Real-logd skips the chunk and continues. |
| real-logd does not read the kernel log (no `KernelLog` cap in slot 5, or its notification, binding, or reader thread could not be had) | svcmgr held no `KernelLog` source, or logd ran out of a resource | logd logs one line saying so. The records init-logd left stall after `KLOG_STALL_MS`, the kernel writes its lines directly from then on, as with no reader, and a restarted logd that reads attaches again. |

## Reference

The wire contract — the reply, chunk-kind, and release-status codes,
`MAX_RELEASE_DEFERRALS`, `RELEASE_RETRY_BUDGET_US`, `HANDOVER_CALL_TIMEOUT_MS`, the sender's chunk
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
