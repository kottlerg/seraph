# logd handover protocol

Wire format for the one-shot init-logd → real-logd state transfer.

Real-logd, on bootstrap, calls `log_labels::HANDOVER_PULL` repeatedly
on its single-use SEND cap to the master log endpoint. Init-logd's
receive loop, on seeing the label, replies one chunk at a time until
its captured state is drained, then breaks its loop and calls
`sys_thread_exit`. Real-logd's existing tokened SEND caps held by
every other sender remain valid because the kernel endpoint object
is unchanged across the transition.

## Call shape

* Request: `IpcMessage::new(HANDOVER_PULL)`. Empty payload, no caps.
* Reply: `label = MORE (0)` for every intermediate chunk;
  `label = DONE (1)` on the terminal chunk. Init-logd sets its
  internal `HANDOVER_COMPLETE` flag immediately after replying
  `DONE`; the next iteration of its receive loop self-terminates the
  init-logd thread.

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
| 2 | active sender-slot count (non-zero tokens in init-logd's slot table) |

No inline bytes. No transferred caps.

### `SLOT` (2)

One entry from init-logd's per-sender slot table. Sent once per
non-zero slot, in slot-index order.

| Word | Meaning |
|---|---|
| 0 | `SLOT` |
| 1 | sender token (kernel-delivered identity on every IPC) |
| 2 | display-name length in bytes |
| 3..  | name bytes (packed via `IpcMessage::builder.bytes(3, ...)`, offset 24 in `data_bytes`) |

The reply label's upper 16 bits carry the name length again (stream-
protocol convention). Real-logd installs each slot into its own
hash-keyed token table via
[`SlotTable::install_from_handover`](../src/slot.rs).

### `LINE` (3)

One completed log line from init-logd's bounded history ring. Sent
in FIFO order: oldest entry first when the ring has wrapped; index
0 first when it has not.

| Word | Meaning |
|---|---|
| 0 | `LINE` |
| 1 | sender token at receipt time |
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
replies `DONE` with `word(0) = LINE` and zero inline bytes, then
sets `HANDOVER_COMPLETE`. Real-logd, on seeing `DONE`, returns from
[`handover::pull_all`](../src/handover.rs). Init-logd's next loop
iteration sees the flag and calls `sys_thread_exit`.

Between the `DONE` reply and init-logd's thread exit, no further log
messages are processed by init-logd — any in-flight `STREAM_BYTES`
sends from other processes queue at the kernel endpoint and are
drained by real-logd once it enters its main receive loop.

## Failure modes

| Symptom | Cause | Recovery |
|---|---|---|
| `HANDOVER_PULL` IPC returns error | `log_ep_handover_send` cap is invalid or init-logd already exited | Real-logd's `pull_all` returns silently; logd boots with an empty `SlotTable`. Pre-handover history is lost. |
| Reply with unknown `word(0)` kind | Wire-format drift; one side built against an out-of-sync `shared/ipc` revision | Real-logd skips the chunk and continues. A bounded iteration cap (`MAX_ITERS`) in `pull_all` guarantees termination on a malformed reply stream. |

## Reference

Wire-format constants are defined in
[`services/init/src/logging.rs`](../../init/src/logging.rs) (sender
side) and [`services/logd/src/handover.rs`](../src/handover.rs)
(receiver side). Both files cross-reference each other.
