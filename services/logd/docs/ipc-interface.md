# logd IPC interface

logd is the receive-side of the master log endpoint. It does not
publish a separate service endpoint; every userspace sender already
holds a badged SEND cap on the log endpoint (seeded by procmgr at
spawn time, per [`docs/process-lifecycle.md`](../../../docs/process-lifecycle.md)
§ ProcessInfo / InitInfo Handover Discipline, or installed by init for
itself / procmgr-self, per
[`services/init/docs/bootstrap.md`](../../init/docs/bootstrap.md) § Raw
bootstrap). The labels documented below are the ones logd's receive
loop dispatches on.

logd additionally calls procmgr's
[`procmgr_labels::REGISTER_DEATH_EQ`](../../procmgr/docs/ipc-interface.md)
once during its own startup; see that document for the wire format.

## Bootstrap caps

svcmgr launches and supervises real-logd, minting its bootstrap round —
one round for its four positional slots, `done = true`, of which only the present
caps ride, named by a presence word (an absent slot reads as `0`) — from the reserved
log-sink sources init endows it (see
[`services/svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md)).
The shape mirrors the README's "Bootstrap caps" table:

| Index | Cap |
|---|---|
| 0 | `RECV` on the master log endpoint |
| 1 | `SEND` on the master log endpoint (single-use; carries the `HANDOVER_PULL` history drain, then the terminal `HANDOVER_RELEASE` (a failed call retried for up to `RELEASE_RETRY_BUDGET_US` (1 s); a release init-logd defers is repeated after a further drain; if no attempt is delivered init-logd keeps serving), then `cap_delete` whatever the outcome; see [`handover-protocol.md`](handover-protocol.md)). Absent on a restart — no init-logd remains to pull from, so logd skips the history pull (restart: design intent; not yet implemented (#262)) |
| 2 | badged `SEND\|GRANT` on procmgr's service endpoint carrying `DEATH_EQ_AUTHORITY` |
| 3 | badged `SEND` on devmgr's registry endpoint carrying `REGISTRY_QUERY_AUTHORITY` (resolves the serial driver via `QUERY_SERIAL_DEVICE` and the framebuffer driver via `QUERY_FRAMEBUFFER_DEVICE`) |

Every (re)launch mints `cap[0]` fresh from svcmgr's persistent master-log
source, so a restarted logd re-attaches its RECV to the same endpoint
object every sender already targets. Only `cap[1]` differs across the two
paths: present on the first launch (one-shot history pull from init-logd),
absent on a restart (history pull skipped, fresh table served). A working
logd restart is design intent; not yet implemented (#262), per svcmgr's
[`restart-protocol.md`](../../svcmgr/docs/restart-protocol.md#supervision-hierarchy)
§ Supervision hierarchy.

logd keeps `cap[0]`, the procmgr `cap[2]` (retained after `REGISTER_DEATH_EQ`), and the
devmgr-registry `cap[3]` for its lifetime, using `cap[3]` to resolve and cache the serial
driver's write endpoint and, when a framebuffer driver is present, the framebuffer driver's;
`cap[1]` is deleted after the handover release.

## Endpoint

| Cap holder | Right | Purpose |
|---|---|---|
| logd's main thread | `RECV` | drains the endpoint via `ipc_recv` inside the wait-set loop |
| every userspace sender | `SEND` (badged) | `STREAM_BYTES`, `STREAM_REGISTER_NAME` |
| real-logd on its first launch | `SEND` (un-badged) | single-use `HANDOVER_PULL` drain to init-logd, then `HANDOVER_RELEASE` (a failed call retried for up to `RELEASE_RETRY_BUDGET_US` (1 s); repeated after a further drain while init-logd defers it), then deleted via `cap_delete` whether or not it was acked. Absent (`cap[1]` reads as `0`) on a restart (design intent; not yet implemented (#262)) |

## Labels accepted

### `stream_labels::STREAM_BYTES` (10)

Per-line byte stream. Sender packs the chunk byte length into the
label's upper 16 bits (`label | ((len << 16))`). Inline bytes
arrive in the IPC message's data words, packed at word 0. logd
appends the bytes to the slot keyed by the kernel-delivered
`msg.badge`; every `\n` flushes the slot's partial buffer as one
line, emitted as `[sec.usfrac] [name] <line>\r\n` to the serial
driver (`SERIAL_WRITE_BYTES`) and mirrored to the framebuffer driver
(`FB_WRITE_BYTES`) when one is present, then appended to the slot's
history ring.

The history ring holds `PER_SLOT_HISTORY` (16) completed lines per slot (see
[`slot.rs`](../src/slot.rs)); appending to a full ring drops its oldest line (FIFO). The ring
has no read surface. TODO: a query IPC that reads the history ring.

Lines exceeding `LINE_BUF_SIZE` (256 bytes) flush without a
trailing `\n` to keep the per-line attribution visible. Senders
that have not yet called `STREAM_REGISTER_NAME` render as `[?]`.

Reply: `label = 0` (success), empty payload. Sender unblocks.

### `stream_labels::STREAM_REGISTER_NAME` (11)

Register or update the display name for the sender identified by
`msg.badge`. Inline bytes carry the name; the label's upper 16
bits carry the name length. Long names truncate at `MAX_NAME_LEN`
(48 bytes).

No collision-suffix policy: procmgr's per-child process badge is
unique within the system, so display-name collisions only occur if
two processes intentionally pick the same string. logd allows
that.

Reply: `label = 0`. Sender unblocks.

### `log_labels::HANDOVER_PULL` (13)

One-shot init-logd → real-logd state transfer. Documented in
[`handover-protocol.md`](handover-protocol.md). real-logd is the caller,
not a handler: its receive loop dispatches only `STREAM_BYTES` and
`STREAM_REGISTER_NAME`, and any other label, this one included, gets an
empty reply. init-logd is the only receiver of the label.

### `log_labels::GET_LOG_CAP` (12) — legacy

Legacy discovery label. Reserved in the label table for backward
compatibility but no caller in the current codebase issues it
(every spawn receives a pre-installed badged SEND cap in
`ProcessInfo.log_send_cap`, per
[`docs/process-lifecycle.md`](../../../docs/process-lifecycle.md) § ProcessInfo / InitInfo
Handover Discipline). logd replies empty if it ever
arrives, so an out-of-tree v0 caller fails closed without crashing
logd.

## Wait-set

logd's main loop waits on a 3-member `WaitSet`:

| Badge | Source | Purpose |
|---|---|---|
| `WS_BADGE_LOG` (0) | RECV on the master log endpoint | `STREAM_BYTES` / `STREAM_REGISTER_NAME` arrivals |
| `WS_BADGE_DEATH` (1) | RECV on logd's death-notification `EventQueue` | drained per loop iteration before service dispatch |
| `WS_BADGE_RESYNC` (2) | logd's resync `Notification` | the resync helper thread's walk has ended (§ Death-queue resync) |

Death events are drained inside every loop iteration (before
servicing the log endpoint) so a recently-died sender's slot is
evicted before logd processes any of its still-queued
`STREAM_BYTES`. Mirrors procmgr's drain-deaths-first pattern.

## Death-notification cascade

Every process spawned by procmgr is bound to two death observers
at creation:

1. Procmgr's own death `EventQueue` (correlator = process badge,
   for procmgr's auto-reap path).
2. logd's death `EventQueue` (correlator = process badge, for
   logd's slot eviction).

Procmgr installs the second binding inside
[`finalize_creation`](../../procmgr/src/process.rs) when its
`LOGD_DEATH_EQ` static is non-zero, AND retroactively across every
existing process table entry when logd's
[`REGISTER_DEATH_EQ`](../../procmgr/docs/ipc-interface.md) IPC arrives. Children spawned before logd
registers see only the first binding until the retroactive bind
catches them up.

logd's drain consumes each event as the death entry
`(exit_reason, process_badge as u32)` (`syscall::DeathEvent`) and evicts the
matching slot from the hash-keyed badge table. Idempotent on
already-evicted badges. procmgr keeps the low 32 bits unique among live
processes, so a death evicts only the dead sender's slot.

## Death-queue resync

logd's death `EventQueue` has a fixed tuning capacity (`DEATH_EQ_CAPACITY`,
128), not one sized from any process count. The kernel drops a post to a full
queue, which would leave that sender's slot unevicted. A drain that takes a full
queue's worth of events or more may have followed such a drop (a dropped post
leaves a full queue of events behind it for that drain or the next), so it starts
a resync:

1. logd snapshots the badges of its child slots: every badge at or above
   `log_badges::LOG_BADGE_FIRST_CHILD`, which only procmgr-spawned children
   carry.
2. A helper thread walks procmgr's live badges with
   [`QUERY_LIVE_PROCESSES`](../../procmgr/docs/ipc-interface.md) through the
   `DEATH_EQ_AUTHORITY` cap, page by page, checking that each page ascends past
   the cursor, sends the list back over a channel, and signals the resync
   notification.
3. On that wake the main thread evicts every snapshot badge the walk did not
   list. A slot created after the snapshot is no candidate, so a sender that
   starts during the walk keeps its slot. A failed walk evicts nothing.

One walk runs at a time. A drain that crosses the capacity while one is in
flight marks another due, and it starts as soon as the current walk ends, so the
deaths dropped during a walk are covered by the next one.

logd's main thread never calls procmgr after startup. `seraph::log!` is a
synchronous `ipc_call` on the master log endpoint, so while procmgr logs it is
blocked until logd's main thread receives; a call from that thread to procmgr at
the same moment would leave each blocked on the other, with no receiver on
either endpoint. The walk therefore runs on the helper thread, and the main
thread keeps receiving procmgr's log calls throughout; procmgr answers the walk
whether or not it logs meanwhile. The one call the main thread makes,
`REGISTER_DEATH_EQ`, precedes the handover pull, before procmgr has a reason to
log to real-logd (see [handover-protocol.md](handover-protocol.md) § Startup
ordering).

---

## Summarized By

[services/logd/README.md](../README.md)
