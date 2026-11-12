# logd IPC interface

logd is the receive-side of the master log endpoint. It does not
publish a separate service endpoint; every userspace sender already
holds a badged SEND cap on the log endpoint (seeded by procmgr at
spawn time, per [`docs/process-lifecycle.md`](../../../docs/process-lifecycle.md)
§ ProcessInfo / InitInfo Handover Discipline, or installed by init for
itself / procmgr-self, per
[`services/init/docs/bootstrap.md`](../../init/docs/bootstrap.md) § Raw
bootstrap). The labels documented below are the ones logd's receive
workers dispatch on (§ Receive pool).

logd additionally calls procmgr's
[`procmgr_labels::REGISTER_DEATH_EQ`](../../procmgr/docs/ipc-interface.md)
once during its own startup; see that document for the wire format.

## Bootstrap caps

svcmgr launches and supervises real-logd, minting its bootstrap round —
rounds for its five positional slots, the last `done = true`, of which only the present
caps ride, named by a presence word (an absent slot reads as `0`) — from the reserved
log-sink sources init endows it and the `devmgr.class.*` publications (see
[`services/svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md)).
The shape mirrors the README's "Bootstrap caps" table:

| Index | Cap |
|---|---|
| 0 | `RECV` on the master log endpoint |
| 1 | `SEND` on the master log endpoint (single-use; carries the `HANDOVER_PULL` history drain, then the terminal `HANDOVER_RELEASE` (a failed call retried for up to `RELEASE_RETRY_BUDGET_US` (1 s); a release init-logd defers is repeated after a further drain; if no attempt is delivered init-logd keeps serving), then `cap_delete` whatever the outcome; see [`handover-protocol.md`](handover-protocol.md)). Absent on a restart — no init-logd remains to pull from, so logd skips the history pull (restart: design intent; not yet implemented (#262)) |
| 2 | badged `SEND\|GRANT` on procmgr's service endpoint carrying `DEATH_EQ_AUTHORITY` |
| 3 | the `serial` class `SEND`, derived from the `devmgr.class.serial` publication (resolves the serial driver via `QUERY_DEVICE`) |
| 4 | the `framebuffer` class `SEND`, derived from the `devmgr.class.framebuffer` publication (resolves the framebuffer driver via `QUERY_DEVICE`) |

Every (re)launch mints `cap[0]` fresh from svcmgr's persistent master-log
source, so a restarted logd re-attaches its RECV to the same endpoint
object every sender already targets. Only `cap[1]` differs across the two
paths: present on the first launch (one-shot history pull from init-logd),
absent on a restart (history pull skipped, fresh table served). A working
logd restart is design intent; not yet implemented (#262), per svcmgr's
[`restart-protocol.md`](../../svcmgr/docs/restart-protocol.md#supervision-hierarchy)
§ Supervision hierarchy.

logd keeps `cap[0]`, the procmgr `cap[2]` (retained after `REGISTER_DEATH_EQ`), and the class SENDs
`cap[3]` and `cap[4]` for its lifetime, using `cap[3]` to resolve and cache the serial driver's
write endpoint and, when a framebuffer driver is present, `cap[4]` the framebuffer driver's;
`cap[1]` is deleted after the handover release.

## Endpoint

| Cap holder | Right | Purpose |
|---|---|---|
| logd's receive workers | `RECV` | each receives on the endpoint with `ipc_recv` (§ Receive pool) |
| every userspace sender | `SEND` (badged) | `STREAM_BYTES`, `STREAM_RECORD`, `STREAM_REGISTER_NAME` |
| a service that seeds `logd.query` | `SEND` badged `LOG_QUERY_AUTHORITY` | `QUERY_SLOTS`, `QUERY_HISTORY` (§ Queries) |
| real-logd on its first launch | `SEND` (un-badged) | single-use `HANDOVER_PULL` drain to init-logd, then `HANDOVER_RELEASE` (a failed call retried for up to `RELEASE_RETRY_BUDGET_US` (1 s); repeated after a further drain while init-logd defers it), then deleted via `cap_delete` whether or not it was acked. Absent (`cap[1]` reads as `0`) on a restart (design intent; not yet implemented (#262)) |

## Labels accepted

### `stream_labels::STREAM_BYTES` (10)

Per-line byte stream. Sender packs the chunk byte length into bits
16-31 of the label (`label | (len << 16)`) and the chunk's log level into
bits 32-34 (§ Levels). Inline bytes
arrive in the IPC message's data words, packed at word 0. logd
appends the bytes to the slot keyed by the kernel-delivered
`msg.badge`; every `\n` flushes the slot's partial buffer as one
line: under the state lock the line is rendered as
`[sec.usfrac] [name] <line>\r\n` and appended to the slot's history
ring with its level, and once the lock is released the rendered line
is emitted to the serial driver
(`SERIAL_WRITE_BYTES`) and mirrored to the framebuffer driver
(`FB_WRITE_BYTES`) when one is present.

The history ring holds `PER_SLOT_HISTORY` (16) completed entries per slot, text lines and
records (§ History; [`slot.rs`](../src/slot.rs)); appending to a full ring drops its oldest
entry (FIFO). `log_labels::QUERY_HISTORY` reads it (§ Queries).

Lines exceeding `LINE_BUF_SIZE` (256 bytes) flush without a
trailing `\n` to keep the per-line attribution visible. Senders
that have not yet called `STREAM_REGISTER_NAME` render as `[?]`.

Reply: `label = 0` (success), empty payload. Sender unblocks.

#### Levels

A log line carries one of five levels, from least to most verbose: error,
warn, info, debug, trace. The level code rides bits 32-34 of every
`STREAM_BYTES` and `STREAM_RECORD` label (`ipc::stream_labels::LEVEL_SHIFT`, `LEVEL_MASK`, and the
`LEVEL_*` codes 1 to 5). Code 0 means no level was given and, like the
unassigned codes 6 and 7, reads as info (`ipc::stream_labels::level_of`), so
a sender that sets no level logs at info.

- **Sender.** `seraph::log!("fmt", args…)` logs at info; a leading `error:`,
  `warn:`, `info:`, `debug:`, or `trace:` sets the level
  (`seraph::log!(warn: "fmt", args…)`). Each call site states the level
  the rule below gives its line. std's panic, allocation-error,
  and precondition output, sent through the same cap, is at error. Bytes a
  sender writes with `log::write_bytes` carry the level it passes. A record
  (§ `stream_labels::STREAM_RECORD`) carries its level the same way.
- **Choosing a level.** A call site states the level its line deserves, so
  a default boot shows lifecycle and failures and `SERAPH_LOG=debug` adds
  the detail a developer needs:
  - error: a failure the component does not recover from, or a request it
    fails that an operator must see (a service that cannot start, a driver
    that cannot bring its device up, a lost invariant before a panic);
  - warn: an anomaly the component recovers from or degrades around (a
    retry, a fallback, a dropped or malformed request it rejects, a
    resource limit reached);
  - info: lifecycle a default boot shows once per event (start, ready, a
    device or mount found, shutdown), and every line of a test harness
    (svctest, usertest, and the programs and fixtures they run: phase
    results and the terminal `ALL TESTS PASSED` / `SOME TESTS FAILED`
    markers);
  - debug: per-request, per-device-probe, or per-step detail useful while
    developing the component;
  - trace: per-message or hot-path lines (per IPC, per block, per packet).

  A line that an xtask check or a CI `run-parallel` pattern matches stays
  at info, whatever the list above gives it, unless the check changes with
  it: a line below info is not sent in a default boot, and a tag after
  `[name] ` breaks a match anchored there. A line whose text contains
  `FATAL:`, which CI's fail pattern matches, keeps its text at any level.
  A line given error or warn drops a leading `error:`, `warning:`, or
  `FAILED` from its text, since the tag replaces it, unless a check
  matches the word.
- **Filter.** A std process sends only lines at or less verbose than its
  level, which std's `_start` reads once from the process's `SERAPH_LOG`
  environment entry (`error`, `warn`, `info`, `debug`, or `trace`; absent
  or any other value: info). A line above that level is neither formatted
  nor sent, so it costs no IPC; a record is filtered as a line is. A
  service sets the entry with the `.svc`
  `env` key ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
  § `argv` / `env`), a spawner with `Command::env`. Neither receiver
  filters: each renders every line it receives. An error line is sent at
  every level.
- **Line level.** The stream carries bytes, not lines, so a receiver gives a
  line the level of the message that carried its first byte; later chunks
  of the same line do not change it. A line split at `LINE_BUF_SIZE` keeps
  that level for each part. Two threads of one process share the process's
  badge and slot, so lines they interleave mix as their bytes do.
- **Rendering.** Both init-logd and logd render an info line as
  `[sec.usfrac] [name] <line>`, as every line rendered before levels
  existed, so each line a harness matches (`[svctest] ALL TESTS PASSED`,
  the `reclaim:` line below) is unchanged. A line of any other level carries
  its tag and a space after `[name] `: `ERROR`, `WARN`, `DEBUG`, or `TRACE`
  (`logd_codec::level::tag`): `[sec.usfrac] [name] WARN <line>`.
- **History.** Each history entry keeps its level, init-logd's across the
  handover ([`handover-protocol.md`](handover-protocol.md) § `LINE`,
  § `RECORD`).

### `stream_labels::STREAM_RECORD` (15)

One log record per message: a message text and a list of fields, each a key
and a value, delimited by lengths rather than by text, so no value or
message byte can read as a key. Bits 16-31 of the label carry the record's
byte length and bits 32-34 its level (§ Levels); the record's bytes are
packed into the data words from word 0. `ipc::log_record` defines the
layout and its encoder and decoder:

| Part | Bytes |
|---|---|
| message length | 2, little-endian |
| message | as many as its length |
| each field: key length | 1 |
| key | as many as its length, `[a-z0-9_]`, 1 to `KEY_MAX_LEN` (32) |
| value length | 2, little-endian |
| value | as many as its length, any bytes |

A record is at most `RECORD_MAX_BYTES` (480) bytes, and its parts fill it
exactly. A key may repeat; a reader sees each occurrence, in order.

- **Sender.** `seraph::log!(warn: "fmt", args…; key = value, …)` sends one
  record (the macro's documentation in `runtime/ruststd/src/os/seraph.rs`,
  through `log::emit_record`): the format string and
  its positional arguments make the message, and each value is formatted with
  `Display`. Keys are checked against the alphabet at compile time. A record
  that would be longer than the limit is cut at the sender: a message or
  value that does not fit is cut on a character boundary, a field that has
  no room for its key and lengths is dropped, and once anything is cut or
  dropped every later field is dropped too, so the fields that arrive are a
  prefix of those the sender wrote.
- **Receivers.** Both init-logd and logd accept the label. A record is
  complete in its message: the receiver renders it as one line at once and
  leaves the slot's partial text line (§ `stream_labels::STREAM_BYTES`)
  pending, then retains it in the history (§ History).
- **Rendering.** `[sec.usfrac] [name] [TAG ]<message> key=value …`, the
  prefix and tag as for a text line (§ Levels). The message is written as a
  text line's bytes are, except that a newline is written `\n`, so a record
  stays on one line. A value is written bare when it is a non-empty run of
  UTF-8 characters, none of them whitespace, a control character, `=`, or
  `"`; any other value is written in double quotes, with `\"`, `\\`, `\n`,
  `\r`, and `\t` escaped, and `\xNN` for each byte of any other control
  character and each byte of an invalid UTF-8 sequence. An info record with
  no fields renders as the text line of its message does. A rendered body is
  at most `RENDERED_MAX_BYTES` (1920) bytes. `logd_codec::record` renders a
  record, and its `fields` reads the text after the message back to the same
  keys and value bytes. The message is the sender's own text, as a text line
  is, so a reader that needs the fields takes them from after the message
  it expects.
- **Reply.** `label = RECORD_ACCEPTED` (0) for a record rendered and
  retained, `RECORD_REJECTED` (1) for a payload that is longer than a record
  or than the message, or that `ipc::log_record` does not decode (a length
  that overruns the payload, a key outside the alphabet, bytes left over):
  such a payload is neither rendered nor retained. The payload is empty.
  Sender unblocks.

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
not a handler: its receive workers dispatch only `STREAM_BYTES`,
`STREAM_RECORD`, `STREAM_REGISTER_NAME`, `QUERY_SLOTS`, and `QUERY_HISTORY`,
and any other label, this one included, gets an empty reply. init-logd is the
only receiver of the label.

### `log_labels::GET_LOG_CAP` (12) — legacy

Legacy discovery label. Reserved in the label table for backward
compatibility but no caller in the current codebase issues it
(every spawn receives a pre-installed badged SEND cap in
`ProcessInfo.log_send_cap`, per
[`docs/process-lifecycle.md`](../../../docs/process-lifecycle.md) § ProcessInfo / InitInfo
Handover Discipline). logd replies empty if it ever
arrives, so an out-of-tree v0 caller fails closed without crashing
logd.

## History

The stored form `log_labels::QUERY_HISTORY` reads (§ Queries). Each of logd's
per-slot entries ([`slot.rs`](../src/slot.rs) `HistoryEntry`) holds:

| Field | Content |
|---|---|
| `seq` | logd-wide arrival sequence: one counter across every slot, taken when the entry is retained, so a larger `seq` is a later entry whatever its sender; entries installed from the handover take theirs in install order, oldest first |
| `us` | receipt time, microseconds since boot |
| `level` | an `ipc::stream_labels::LEVEL_*` code (§ Levels) |
| `kind` | `Text`, a `STREAM_BYTES` line, or `Record`, a `STREAM_RECORD` record with its field table |
| `bytes` | a text line's bytes without its newline (at most `LINE_BUF_SIZE`, 256), or a record's payload as it arrived (at most `RECORD_MAX_BYTES`, 480) |

A `Record` entry's field table is a span (start and length into `bytes`) for
its message and a key span and a value span for each field, in the sender's
order, so a reader selects by a key's value without parsing text. init-logd's
ring (`logd_codec::history`) stores the same level, kind, and bytes per entry,
with the sender's badge, and the handover carries each entry in a `LINE` or
`RECORD` chunk ([`handover-protocol.md`](handover-protocol.md)); logd builds
a record's field table again when it installs the chunk.

### Retired slots

An evicted slot (§ Death-notification cascade, § Death-queue resync) leaves the
badge table and joins logd's retired slots, a FIFO of at most `RETIRED_SLOTS`
(64) entries ([`slot.rs`](../src/slot.rs)); retiring one into a full FIFO drops
its oldest. A retired slot keeps its badge, its display name, its history ring,
and how it was evicted: by a death, with the death entry's exit reason, or by a
resync. A badge retired again replaces its older retired slot, so a badge
appears at most once among them. procmgr may hand a dead process's badge to a
new one, so a live slot and a retired slot can share a badge, unless the badge
is among logd's most recent evictions (§ Wait-set).

## Queries

Two labels read the badge table, the retired slots, and the history. They are
served only on a badge carrying `log_labels::LOG_QUERY_AUTHORITY` (`1 << 63`,
a [verb bit](../../../docs/capability-model.md#verb-bit-authority-pattern)):
svcmgr mints a SEND on the master log endpoint with that badge from its
master-log source and publishes it seed-only as `logd.query`
([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `seed`),
so only a recipe that seeds the name holds it. No sender's badge carries a verb
bit: procmgr redraws a process badge that does
([`log_badges`](../../../shared/ipc/src/lib.rs)), and `LOG_BADGE_INIT` and
`LOG_BADGE_PROCMGR` carry none. A query on any other badge is refused with
`QUERY_DENIED`.

A receive worker answers a query from the table and the rings logd owns, as it
serves the stream labels (§ Receive pool), and calls no other service to answer
it, so a query never waits on another service (§ Death-queue resync gives the
deadlock a call to procmgr would risk). The wire format is defined in
`ipc::log_query`. Every request carries `ipc::LOG_LABELS_VERSION` (5) in
`data[0]`, which logd checks on every query. The reply's label carries the
status in bits 0-15, the reply's entry count in bits 16-31, and in bit 32 whether
more entries follow this page:

| Status | Value | Meaning |
|---|---|---|
| `QUERY_OK` | 0 | the page follows |
| `QUERY_DENIED` | 1 | the badge carries no `LOG_QUERY_AUTHORITY` |
| `QUERY_VERSION_MISMATCH` | 2 | `data[0]` is not logd's `LOG_LABELS_VERSION` |
| `QUERY_INVALID` | 3 | a request word holds a value the label does not define |

A refused query's reply carries no entries. A page is a snapshot of the moment
logd answers it; a caller walks the pages by resuming after the last entry it
read, so an entry added or dropped between two pages shifts no other entry's
place. A walk of several pages is not a snapshot, and a client assumes only
this across its pages:

- `QUERY_SLOTS` reads each (badge, state) pair at most once, each page above
  the last pair read. A slot retired between two pages is read twice, live and
  then retired, only when the earlier page ended at its badge below its new
  retired entry: on its live entry, or, when a resync retires it, on the
  death-retired entry of an earlier holder of the badge, which the retire
  replaces, so the walk reads two retired entries for that badge. Otherwise a
  slot retired after the walk has passed its badge is read once, as live, and
  one retired before the walk reaches its badge once, as retired. A slot
  created below the walk's cursor, or a retired slot dropped before the walk
  reaches it, is missed.
- `QUERY_HISTORY` reads each entry at most once, since `seq` is unique and the
  walk moves to older `seq` only; a retire keeps an entry's `seq`. An entry
  retained after the walk began is newer than every entry it read and is
  missed, as is one a full ring drops before the walk reaches it.

A client that needs one consistent view walks again once the state it waits
for is reached.

init-logd, which holds the endpoint's RECV until the handover, answers every
label it does not serve with an empty `label = 0` reply, which reads as an empty
last page. A caller that runs before logd has taken the endpoint sees no slots
and no history.

### `log_labels::QUERY_SLOTS` (16)

The badge table and the retired slots, in ascending order of badge and then
state, so a live slot comes before a retired one with the same badge.

| Request word | Content |
|---|---|
| `data[0]` | `LOG_LABELS_VERSION` |
| `data[1]` | 0 to start the walk, 1 to resume after the entry in `data[2]` and `data[3]`; any other value: `QUERY_INVALID` |
| `data[2]` | the badge of the last entry read |
| `data[3]` | the state of the last entry read |

The reply carries up to `SLOTS_PAGE` (7) entries of `SLOT_ENTRY_WORDS` (9) data
words each, from `data[0]`:

| Word | Content |
|---|---|
| 0 | badge |
| 1 | state in bits 0-7 (`SLOT_LIVE` 0, `SLOT_EVICTED_DEATH` 1, `SLOT_EVICTED_RESYNC` 2), the name's length in bits 8-15 |
| 2 | exit reason of the death that evicted the slot; 0 for any other state |
| 3-8 | the display name, `MAX_NAME_LEN` (48) bytes little-endian, zero-padded; empty for a slot that registered none |

### `log_labels::QUERY_HISTORY` (17)

History entries, newest first: those of every live and retired slot, or of one
badge (its live slot and its retired slot).

| Request word | Content |
|---|---|
| `data[0]` | `LOG_LABELS_VERSION` |
| `data[1]` | bit 0: one badge's entries only; bit 1: resume before the `seq` in `data[3]`; any other bit set: `QUERY_INVALID` |
| `data[2]` | the badge, with bit 0 of `data[1]` |
| `data[3]` | the `seq` of the last entry read, with bit 1 of `data[1]` |

The reply carries as many whole entries as fit its 64 data words, from
`data[0]`, each word-aligned:

| Words | Content |
|---|---|
| 0 | `seq` (§ History) |
| 1 | `us` |
| 2 | the sender's badge |
| 3 | level in bits 0-7 (`ipc::stream_labels::LEVEL_*`), kind in bits 8-15 (`ENTRY_TEXT` 0, `ENTRY_RECORD` 1), the byte length in bits 16-31 |
| 4 on | the entry's bytes (§ History), zero-padded to a word |

Every entry fits one reply: the longest, a `RECORD_MAX_BYTES` (480) record,
takes 4 + 60 words. A record's bytes are its `STREAM_RECORD` payload, which
`ipc::log_record::Record::decode` reads back to its message and fields.

## Receive pool

logd serves the master log endpoint from `RECV_WORKERS` (4) receive workers, a `shared/recv-pool`
pool ([shared/recv-pool/README.md](../../../shared/recv-pool/README.md)). The count is a
concurrency setting, not a capacity: senders beyond it queue on the endpoint. Each worker receives
on its own IPC buffer page and keeps [IPC Design](../../../docs/ipc-design.md) § Multi-threaded
servers: it drains the death queue (§ Wait-set), serves the request, and replies before it receives
again.

- **Start.** logd spawns the workers before the handover pull, while init-logd still serves the
  endpoint, and they receive once logd opens the pool's gate after the release
  ([handover-protocol.md](handover-protocol.md) § Startup ordering). A spawned thread's start waits
  on procmgr's thread registration
  ([runtime/ruststd/README.md](../../../runtime/ruststd/README.md) § Thread registration): spawned
  after the pull, every worker could be waiting on procmgr while procmgr waits on the unread log
  endpoint to log its reap of init.
- **State.** The badge table, the retired slots, the recently evicted badges (§ Wait-set), the
  history rings, and the death drain's count are under one lock. A worker takes it to complete,
  render, and retain a line or a record, to record a name, or to answer a query, and releases it
  before it writes the line to the drivers. No thread holds it across an IPC call.
- **Output.** A rendered line is written whole: the serial driver's calls for one line are made
  under one output lock and the framebuffer driver's under another, so a line longer than one call
  (a record) is not split by another worker's. Each output lock is held across its driver's calls,
  which is safe because neither driver calls logd; resolving a driver through devmgr, which logs,
  happens before either lock is taken, by one thread at a time. The panic sink takes no lock.
- **Order.** A line is retained, and its `seq` taken (§ History), under the state lock, and is
  written after it, so the lines of different workers reach the serial driver in the order the
  workers take the output lock, which can differ from their `seq` order. A worker replies only once
  the line a message completed is retained and written, so the lines of one sender thread whose
  calls are answered keep their order, in `seq` and on the drivers. A log call is bounded
  ([shared/log/README.md](../../../shared/log/README.md)), and one that times out after a worker
  received it ends that worker's binding, not its service of the message: the sender's next call,
  served by another worker, can be retained and written first, so it takes the smaller `seq` and
  reaches the drivers first, and the bytes of a timed-out `STREAM_BYTES` chunk can join the slot's
  partial line after those of a later chunk. Two threads of one process share a slot (§ Levels).

## Wait-set

logd's main thread waits on a 2-member `WaitSet`:

| Badge | Source | Purpose |
|---|---|---|
| `WS_BADGE_DEATH` (1) | RECV on logd's death-notification `EventQueue` | drained on the wake |
| `WS_BADGE_RESYNC` (2) | logd's resync `Notification` | bit `RESYNC_WALK_DONE` (1): the resync helper thread's walk has ended; bit `RESYNC_REQUESTED` (2): a drain asks for a resync (§ Death-queue resync) |

Each receive worker drains the death queue before it serves a request. The main thread drains the
queue when it is ready, so deaths no request follows are drained too. Each take from the queue is
made, with its eviction, under the state lock (§ Receive pool).

A worker can still serve a request after its sender's eviction: the request was received before
the sender's death, and the death was taken, by this worker or another thread, before the worker
took the state lock; a resync's eviction can fall in the same place. logd keeps the badges of its
last `EVICTED_BADGES` (128) evictions, by a death or a resync, whether or not the badge had a slot
([`slot.rs`](../src/slot.rs)). A `STREAM_BYTES`, `STREAM_RECORD` or `STREAM_REGISTER_NAME` whose
badge has no live slot and is among them is the evicted sender's, and logd drops it and replies as
for one it consumed, rather than give the badge a live slot again. procmgr draws process badges at
random, so a new process takes one of those badges only by chance.

## Death-notification cascade

procmgr, not the kernel, is the source of logd's death events. Every
process spawned by procmgr is bound to death observers on procmgr's own
death queues only (correlator = the full process badge, for procmgr's
auto-reap path). logd's death `EventQueue` has no death-observer nodes and
nothing binds it: once logd's
[`REGISTER_DEATH_EQ`](../../procmgr/docs/ipc-interface.md) has stored it in
procmgr's `LOGD_DEATH_EQ` static, every teardown procmgr runs (the reap of
a death event, its death resync, and `DESTROY_PROCESS`) posts the death
entry `(exit_reason, process badge)` to it. A process torn down before the
registration posts nothing.

logd's drain consumes each event as that death entry (`syscall::DeathEvent`,
the full `u64` badge in the correlator word) and evicts the slot of exactly
that badge from the hash-keyed badge table, so a death evicts only the dead
sender's slot. Idempotent on already-evicted badges.

When a death event evicts a slot, logd logs one line on the serial console,
tagged `[logd]`:

```
reclaim: badge=<badge> exit_reason=0x<reason> name=<name>
```

The line is a record (§ `stream_labels::STREAM_RECORD`) with the message
`reclaim:` and the fields `badge`, `exit_reason`, and `name`, which logd
renders on its own line as a received record is rendered. The badge is
decimal, the exit reason lower-case hex (the death entry's `exit_reason`),
and the name is the slot's registered display name (`STREAM_REGISTER_NAME`),
`?` for a slot that registered none. A name the renderer does not write bare,
one holding a space or `=` among them, is quoted and escaped, so a name such
as `x exit_reason=0x0` stays inside its value and cannot add a field:
`name="x exit_reason=0x0"`. A reader takes the fields with
`logd_codec::record::fields`. A badge with no slot logs nothing. The evicted slot
is retired (§ Retired slots), so `QUERY_SLOTS` reports it evicted with the same
exit reason, and svctest's `logd_death_forward` phase checks the forward that
way. The line names a crashed process: a crash report block carries the process
badge, and a reader finds the process's log name in this line for that badge
([services/crashd/docs/block-format.md](../../crashd/docs/block-format.md)
§ Symbolizing), as `cargo xtask test-crash-report` does.
`logd_codec::reclaim` formats it.

## Death-queue resync

logd's death `EventQueue` has a fixed tuning capacity (`DEATH_EQ_CAPACITY`,
128), not one sized from any process count. procmgr drops a post the full
queue refuses, which would leave that sender's slot unevicted. The takes since one
last found the queue empty, by any thread, are counted; when they reach a full
queue's worth, as one drain from a full queue would take, the drain may have
followed such a drop (a dropped post leaves a full queue of events behind it for
that drain or the next), so it asks the main thread for a resync
(`RESYNC_REQUESTED`), counts again from zero, and the main thread starts it:

1. logd snapshots the badges of its child slots: every badge at or above
   `log_badges::LOG_BADGE_FIRST_CHILD` with no `ipc::VERB_BIT_MASK` bit, which
   only procmgr-spawned children carry. A `LOG_QUERY_AUTHORITY` badge (§ Queries)
   that sent a stream label has a slot but is no candidate.
2. A helper thread walks procmgr's live badges with
   [`QUERY_LIVE_PROCESSES`](../../procmgr/docs/ipc-interface.md) through the
   `DEATH_EQ_AUTHORITY` cap, page by page, checking that each page ascends past
   the cursor, sends the list back over a channel, and signals the resync
   notification.
3. On that wake the main thread evicts every snapshot badge the walk did not
   list, logging `reclaim (resync): badge=<badge> name=<name>` for each (a
   record with the message `reclaim (resync):` and the death drain's fields
   but `exit_reason`). A slot created after the
   snapshot is no candidate, so a sender that starts during the walk keeps its
   slot. A failed walk evicts nothing.

One walk runs at a time. A request for a resync while one is in flight marks
another due, and it starts as soon as the current walk ends, so the deaths
dropped during a walk are covered by the next one.

No receive worker and not the main thread calls procmgr after startup.
`seraph::log!` is a synchronous `ipc_call` on the master log endpoint, so while
procmgr logs it is blocked until a worker receives; a worker's call to procmgr
at the same moment would leave each blocked on the other, and the main thread,
which drains deaths and runs the resync, waits on no other service. The walk
therefore runs on the helper thread, and the workers keep receiving procmgr's
log calls throughout; procmgr answers the walk whether or not it logs meanwhile.
The one call the main thread makes, `REGISTER_DEATH_EQ`, and the workers'
thread registrations precede the handover pull, before procmgr has a reason to
log to real-logd (see [handover-protocol.md](handover-protocol.md) § Startup
ordering).

---

## Summarized By

[runtime/ruststd/README.md](../../../runtime/ruststd/README.md),
[Crash Block Format](../../crashd/docs/block-format.md),
[services/logd/README.md](../README.md),
[services/logd/codec/README.md](../codec/README.md),
[`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md),
[services/svctest/README.md](../../svctest/README.md),
[shared/log/README.md](../../../shared/log/README.md)
