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
rounds for its seven positional slots, the last `done = true`, of which only the present
caps ride, named by a presence word (an absent slot reads as `0`) — from the reserved
log-sink sources init endows it, the `devmgr.class.*` publications and the `timed` publication (see
[`services/svcmgr/docs/service-definitions.md`](../../svcmgr/docs/service-definitions.md)).
The shape mirrors the README's "Bootstrap caps" table:

| Index | Cap |
|---|---|
| 0 | `RECV` on the master log endpoint |
| 1 | `SEND` on the master log endpoint (single-use; carries the `HANDOVER_PULL` history drain, then the terminal `HANDOVER_RELEASE` (a failed call retried for up to `RELEASE_RETRY_BUDGET_US` (1 s); a release init-logd defers is repeated after a further drain; if no attempt is delivered init-logd keeps serving), then `cap_delete` whatever the outcome; see [`handover-protocol.md`](handover-protocol.md)). Absent on a restart once procmgr reports init reaped — no init-logd remains to pull from, so logd skips the history pull; present on a restart before that (or when svcmgr's query fails) |
| 2 | badged `SEND\|GRANT` on procmgr's service endpoint carrying `DEATH_EQ_AUTHORITY` |
| 3 | the `serial` class `SEND`, derived from the `devmgr.class.serial` publication (resolves the serial driver via `QUERY_DEVICE`) |
| 4 | the `framebuffer` class `SEND`, derived from the `devmgr.class.framebuffer` publication (resolves the framebuffer driver via `QUERY_DEVICE`) |
| 5 | a `KernelLog` cap carrying `Read`, derived with `RIGHTS_KLOG_READ` from the `KernelLog` source svcmgr holds (reads the kernel's console lines; [`handover-protocol.md`](handover-protocol.md) § Kernel log); absent when svcmgr holds none |
| 6 | the `timed` `SEND`, derived from the `timed` publication (reads the wall clock once; [`sinks.md`](sinks.md) § Wall time); absent when no recipe provides `timed` |

Every (re)launch mints `cap[0]` fresh from svcmgr's persistent master-log
source, so a restarted logd re-attaches its RECV to the same endpoint
object every sender already targets. Only `cap[1]` differs across the two
paths: present on the first launch, and on a restart while procmgr does not report init reaped
(one-shot history pull from init-logd);
absent on a later restart (history pull skipped, fresh table served), per svcmgr's
[`restart-protocol.md`](../../svcmgr/docs/restart-protocol.md#supervision-hierarchy)
§ Supervision hierarchy.

logd keeps `cap[0]`, the procmgr `cap[2]` (retained after `REGISTER_DEATH_EQ`), and the class SENDs
`cap[3]` and `cap[4]` for its lifetime, using `cap[3]` to register a `WATCH_CLASS` watch and resolve
the serial driver's write endpoint and, when a framebuffer driver is present, `cap[4]` the
framebuffer driver's, on its main thread, which resolves a driver again only when devmgr signals
that class's watch; `cap[1]` is deleted after the handover release. logd keeps `cap[5]` for its
lifetime and reads the kernel log through it. A helper thread calls `timed_labels::GET_WALL_TIME`
once through `cap[6]`, then deletes it.

## Endpoint

| Cap holder | Right | Purpose |
|---|---|---|
| logd's receive workers | `RECV` | each receives on the endpoint with `ipc_recv` (§ Receive pool) |
| every userspace sender | `SEND` (badged) | `STREAM_BYTES`, `STREAM_RECORD`, `STREAM_REGISTER_NAME` |
| a service that seeds `logd.query` | `SEND|GRANT` badged `LOG_QUERY_AUTHORITY` | `QUERY_SLOTS`, `QUERY_HISTORY` (§ Queries), `LOG_SUBSCRIBE` from the `SUBSCRIBERS_MAX` pool (§ Subscriptions) |
| a service that seeds `logd.follow` (an external sink) | `SEND|GRANT` badged `LOG_FOLLOW_AUTHORITY` | `QUERY_SLOTS`, `QUERY_HISTORY`, `LOG_SUBSCRIBE` from the `SINK_SUBSCRIBERS_MAX` pool |
| a service that seeds `logd.control` | `SEND` badged `LOG_CONTROL_AUTHORITY` | `SINK_LIST`, `SINK_SET` (§ Sink control) |
| a service that seeds `logd.flush` | `SEND` badged `LOG_FLUSH_AUTHORITY` | `LOG_FLUSH` (§ Flush barrier) |
| real-logd on its first launch, or on a restart before procmgr reports init reaped | `SEND` (un-badged) | single-use `HANDOVER_PULL` drain to init-logd, then `HANDOVER_RELEASE` (a failed call retried for up to `RELEASE_RETRY_BUDGET_US` (1 s); repeated after a further drain while init-logd defers it), then deleted via `cap_delete` whether or not it was acked. Absent (`cap[1]` reads as `0`) on a later restart. Each call is bounded by `HANDOVER_CALL_TIMEOUT_MS` (1 s) |

## Labels accepted

### `stream_labels::STREAM_BYTES` (10)

Per-line byte stream. Sender packs the chunk byte length into bits
16-31 of the label (`label | (len << 16)`), the chunk's log level into
bits 32-35 (§ Levels), and, once it has registered a display name, bit 36
(`SENDER_NAMED`, § `stream_labels::STREAM_REGISTER_NAME`). Inline bytes
arrive in the IPC message's data words, packed at word 0. logd
appends the bytes to the slot keyed by the kernel-delivered
`msg.badge`; every `\n` flushes the slot's partial buffer as one
line, retained under the state lock in logd's history as the slot's entry with
its level and time. Each sink whose level shows the entry renders it in the sink's own format,
by default the console format `[sec.usfrac] LEVEL  [name] <line>\r\n` (§ Levels;
[sinks.md](sinks.md) § Settings), when its writer reaches it, and writes it to its driver: the
serial driver (`SERIAL_WRITE_BYTES`), and the framebuffer driver (`FB_WRITE_BYTES`) when one is
present (§ Output sinks).

logd's history holds the completed entries of every slot, text lines and records, within
the history's byte bound (256 KiB to 2 MiB with the machine's RAM) together, and at most the
per-slot bound (32 entries at 256 KiB, in proportion above) of one slot
(§ History; [`lib.rs`](../slot-table/src/lib.rs)). `log_labels::QUERY_HISTORY` reads it (§ Queries).

Lines exceeding `LINE_BUF_SIZE` (256 bytes) flush without a
trailing `\n` to keep the per-line attribution visible. Senders
that have not yet called `STREAM_REGISTER_NAME` render as `[?]`.

Reply: `label = 0` (success), empty payload, or `NAME_UNKNOWN` (2) for a
message carrying `SENDER_NAMED` from a sender whose name logd does not hold, of
which nothing is consumed (§ `stream_labels::STREAM_REGISTER_NAME`), or
`WINDOW_FULL` (3) with a retry hint in `data[0]` for a message past the
sender's window, of which nothing is consumed either (§ Hold window). Sender
unblocks.

#### Levels

A log line carries one of the eight RFC 5424 severities, from least to most
verbose: emergency, alert, critical, error, warn (RFC 5424's warning), notice,
info (informational), debug. The `ipc::stream_labels::LEVEL_*` codes are the
severities, 0 (`LEVEL_EMERGENCY`) to 7 (`LEVEL_DEBUG`). The level rides bits
32-35 of every `STREAM_BYTES` and `STREAM_RECORD` label
(`ipc::stream_labels::LEVEL_SHIFT`, `LEVEL_MASK`) as the severity plus one
(`level_bits`). A field of 0 means no level was given and, like the unassigned
fields 9 to 15, reads as info (`ipc::stream_labels::level_of`), so a sender
that sets no level logs at info.

- **Sender.** `seraph::log!("fmt", args…)` logs at info; a leading
  `emergency:`, `alert:`, `critical:`, `error:`, `warn:`, `notice:`,
  `info:`, or `debug:` sets the level (`seraph::log!(warn: "fmt", args…)`).
  Each call site states the level the rule below gives its line, in a message worded as
  [coding-standards.md](../../../docs/coding-standards.md#log-messages)
  § Log Messages requires. std's panic, allocation-error,
  and precondition output, sent through the same cap, is at error. Bytes a
  sender writes with `log::write_bytes` carry the level it passes. A record
  (§ `stream_labels::STREAM_RECORD`) carries its level the same way.
- **Choosing a level.** A call site states the level its line deserves, so
  a default boot shows lifecycle and failures and `SERAPH_LOG=debug` adds
  the detail a developer needs:
  - emergency: the system cannot go on;
  - alert: an operator must act now (the memory reserve reached, a critical
    service out of its restart budget);
  - critical: a component lost, with the system degrading around it;
  - error: a failure the component does not recover from, or a request it
    fails that an operator must see (a service that cannot start, a driver
    that cannot bring its device up, a lost invariant before a panic);
  - warn: an anomaly the component recovers from or degrades around (a
    retry, a fallback, a dropped or malformed request it rejects, a
    resource limit reached);
  - notice: a significant normal event, shown once (a service restarted, an
    oomd kill, a crash report written);
  - info: lifecycle a default boot shows once per event (start, ready, a
    device or mount found, shutdown), and every line of a test harness
    (svctest, usertest, and the programs and fixtures they run: phase
    results and the terminal `ALL TESTS PASSED` / `SOME TESTS FAILED`
    markers);
  - debug: per-request, per-device-probe, per-step, or per-message detail
    useful while developing the component.

  A line that an xtask check or a CI `run --runs` pattern matches stays
  at info, whatever the list above gives it, unless the check changes with
  it: a line below info is not sent in a default boot, and the tag of
  another level, ahead of `[name] `, breaks a match anchored before the
  name. A line a document says a
  component logs, or tells its reader to read, stays at info too unless
  the document changes with it: procmgr's `spawn image bias=0x… (<argv0>)` line,
  from which `run --gdb` and `symbolize --bias` take a process's load bias
  ([xtask/README.md](../../../xtask/README.md#cargo-xtask-symbolize)), is
  one. A line whose text contains
  `FATAL:`, which CI's fail pattern matches, keeps its text at any level.
  A line given a level from emergency to warn drops a leading `error:`,
  `warning:`, or `FAILED` from its text, since the tag replaces it, unless a
  check matches the word.
- **Filter.** A std process sends only lines at or less verbose than its
  level, which std's `_start` reads once from the process's `SERAPH_LOG`
  environment entry (one of the eight keywords `emergency`, `alert`,
  `critical`, `error`, `warn`, `notice`, `info`, or `debug`; absent or any
  other value: info). A line above that level is neither formatted
  nor sent, so it costs no IPC; a record is filtered as a line is. A
  service svcmgr launches sets the entry with the `.svc`
  `env` key ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md)
  § `argv` / `env`), a spawner with `Command::env`. The services init
  spawns (procmgr, devmgr, vfsd, and svcmgr) take their level from the
  boot bundle's log-level configuration, `/config/init/log-levels.conf` (installed from
  `services/init/log-levels.conf`), which init reads at boot and passes to each as its `SERAPH_LOG`
  entry ([init bootstrap](../../init/docs/bootstrap.md) § Log levels); svcmgr only binds the
  services init spawns, so an `env` key in their `.svc` recipes reaches nothing. A driver devmgr
  spawns and a fatfs instance vfsd spawns inherit their spawner's level. init-logd does not
  filter: it writes every line it receives. logd retains every line it receives, and each of its
  sinks shows those at or above the sink's own level, serial's info by default (§ Output sinks;
  [sinks.md](sinks.md) § Settings). An error line is sent at every level.
- **Line level.** The stream carries bytes, not lines, so a receiver gives a
  line the level of the message that carried its first byte; later chunks
  of the same line do not change it. A line split at `LINE_BUF_SIZE` keeps
  that level for each part. Two threads of one process share the process's
  badge and slot, so lines they interleave mix as their bytes do.
- **Rendering.** Both init-logd and logd render a line as
  `[sec.usfrac] LEVEL  [name] <line>`, logd in a sink's default console fields
  ([sinks.md](sinks.md) § The console format), each writing the prefix's fields with the
  functions of `logd_codec::prefix`: the stamp, its seconds right-aligned to five columns, a space,
  the level's tag padded with spaces to six columns and a space, then `[name] `. The tags are
  `EMERG`, `ALERT`, `CRIT`, `ERROR`, `WARN`, `NOTICE`, `INFO`, and `DEBUG`
  (`logd_codec::level::tag`), so the names of lines at different levels and times line
  up: `[    6.000457] WARN   [svcmgr] <line>`. A line's name and text stay
  together, so a pattern that starts at `[name] ` (`[svctest] ALL TESTS
  PASSED`, the `reclaim:` line below) matches at every level.
- **History.** Each history entry keeps its level, init-logd's across the
  handover ([`handover-protocol.md`](handover-protocol.md) § `LINE`,
  § `RECORD`).

### `stream_labels::STREAM_RECORD` (15)

One log record per message: a message text and a list of fields, each a key
and a value, delimited by lengths rather than by text, so no value or
message byte can read as a key. Bits 16-31 of the label carry the record's
byte length and bits 32-35 its level (§ Levels); the record's bytes are
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
- **Rendering.** `[sec.usfrac] LEVEL  [name] <message> key=value …`, the
  prefix and tag as for a text line (§ Levels). The message is written as a
  text line's bytes are, except that a newline is written `\n`, so a record
  stays on one line. A value is written bare when it is a non-empty run of
  UTF-8 characters, none of them whitespace, a control character, `=`, or
  `"`; any other value is written in double quotes, with `\"`, `\\`, `\n`,
  `\r`, and `\t` escaped, and `\xNN` for each byte of any other control
  character and each byte of an invalid UTF-8 sequence. A record with no
  fields renders as a text line of its message at its level does. A rendered body is
  at most `RENDERED_MAX_BYTES` (1920) bytes. `logd_codec::record` renders a
  record, and its `fields` reads the text after the message back to the same
  keys and value bytes. The message is the sender's own text, as a text line
  is, so a reader that needs the fields takes them from after the message
  it expects.
- **Reply.** `label = RECORD_ACCEPTED` (0) for a record rendered and
  retained, `RECORD_REJECTED` (1) for a payload that is longer than a record
  or than the message, or that `ipc::log_record` does not decode (a length
  that overruns the payload, a key outside the alphabet, bytes left over):
  such a payload is neither rendered nor retained. logd answers
  `NAME_UNKNOWN` (2) to a record that decodes and carries `SENDER_NAMED`
  (bit 36) from a sender whose name it does not hold, and neither renders nor
  retains it (§ `stream_labels::STREAM_REGISTER_NAME`), and `WINDOW_FULL` (3),
  with a retry hint in `data[0]`, to a record past the sender's window, which it
  neither renders nor retains (§ Hold window). Otherwise the payload is empty.
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

The name `kernel` belongs to the kernel's slot (`LOG_BADGE_KERNEL`, 3;
[`handover-protocol.md`](handover-protocol.md) § Kernel log): a sender that registers it is stored
as `kernel_` (`logd_codec::kernel::stored_name`), as init-logd stores it. `QUERY_SLOTS` and
`QUERY_HISTORY` return the kernel's slot like any sender's, and no eviction takes it.

A sender registers its name once, at startup, but logd's table can lose it: a
restarted logd serves a fresh table ([`handover-protocol.md`](handover-protocol.md),
the restart paragraph), and a name the handover does not deliver never reaches it
([`handover-protocol.md`](handover-protocol.md) § Failure modes). The sender
therefore keeps its name and states that it has one, and logd asks for it again:

- **Sender.** `shared/log` keeps the first `SLOT_NAME_MAX` (48) bytes of the name
  a process registers on its own log cap (`std::os::seraph::log::register_name`)
  and sets `SENDER_NAMED` (bit 36 of the label) on every `STREAM_BYTES` and
  `STREAM_RECORD` it sends on that cap from then on.
- **logd.** A `STREAM_BYTES` or `STREAM_RECORD` that carries `SENDER_NAMED`, from a
  badge whose live slot holds no name, or that has no live slot and is not among the
  recent evictions (§ Wait-set), is answered `NAME_UNKNOWN` (2), and logd consumes
  none of it: no byte joins the partial line, nothing is rendered or retained. A
  record that does not decode is answered `RECORD_REJECTED` first, and an evicted
  sender's message is dropped and answered as consumed, as without the bit. logd
  never answers `NAME_UNKNOWN` to a message without the bit.
- **Recovery.** On `NAME_UNKNOWN` the sender sends `STREAM_REGISTER_NAME` with its
  kept name, then the refused message once more with the bit clear, which logd
  accepts whatever its table holds. The message is refused at most once, so it costs
  at most three calls, the two after the first only when logd answered, each under
  the sender's log-call bound ([shared/log](../../../shared/log/README.md)), and it
  is rendered under the name the registration restored. A registration that fails
  leaves that one message rendered as `[?]`; the sender's next message is refused
  and tries again.

Every line of a named sender, its first after a logd restart included, is thus
rendered under its name. A sender that sends nothing after the restart has no slot
in the new table until it does, so its death writes no `reclaim:` line
(§ Death-notification cascade); a sender whose registration after a refusal failed
has a slot without a name until its next message, and a `reclaim:` line for it
reads `name=?`. A name init-logd stored with a collision suffix
(`.2`, `.3`, …) is registered again as the sender gave it. init-logd, the first receiver, ignores
the bit and answers no message `NAME_UNKNOWN`.
A sender that registered no name, or that calls the wire helpers with another
cap, sends no bit and is never refused.

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

The stored form `log_labels::QUERY_HISTORY` reads (§ Queries). Each entry of logd's history
([`lib.rs`](../slot-table/src/lib.rs) `HistoryEntry`, kept by its `seq` in `History`) holds:

| Field | Content |
|---|---|
| `seq` | logd-wide arrival sequence: one counter across every slot, taken when the entry is retained, so a larger `seq` is a later entry whatever its sender; entries installed from the handover take theirs in install order, oldest first |
| `badge` | the sender's badge |
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

The history is also the journal the sinks write from (§ Output sinks). It holds every live and
retired slot's entries within a byte bound fixed when logd starts: the machine's RAM over 2048
(`RAM_PER_HISTORY_BYTE`), within `HISTORY_BYTES_MIN` (256 KiB) and `HISTORY_BYTES_MAX` (2 MiB), the
RAM read from memmgr's `QUERY_POOL_STATUS` and the floor when memmgr does not answer
(`Bounds::for_ram`). Each entry is charged its bytes, its field table, and its key and value in the
history map. Retaining an entry past the bound drops the oldest entry no `hold` sink (serial by
default) shows and has not written, or, when a `hold` sink keeps every entry, the oldest entry of
the slot with the most entries, until the new one fits. A slot keeps at most its last
`PER_SLOT_HISTORY_MIN` (32) entries, scaled by the byte bound's ratio to the floor, a further entry
dropping its own oldest entry no `hold` sink shows and has not written, else its oldest, so one
sender logging without pause does not push a quieter or a dead sender's last lines out alone, and a
sender's lines below every `hold` sink's level, which no window paces, do not push out its own lines
a sink has still to write. The kernel's slot and logd's own are the exception: no window paces them
(§ Hold window), so a further entry of theirs drops their oldest entry no `hold` sink shows and has
not written, and keeps the others, which the byte bound alone then limits. An entry dropped before a
sink reached it is counted as that sink's drop. The bound holds whatever the number of senders, so a
logd restarted while memory is critical, to which every live sender is new, holds no more history
than any other ([README](../README.md) § Role, Reserve service).

### Retired slots

An evicted slot (§ Death-notification cascade, § Death-queue resync) leaves the
badge table and joins logd's retired slots, a FIFO of at most `RETIRED_SLOTS`
(64) entries ([`lib.rs`](../slot-table/src/lib.rs)); retiring one into a full FIFO drops
its oldest, with its entries. A retired slot keeps its badge, its display name, its entries,
and how it was evicted: by a death, with the death entry's exit reason, or by a
resync. A badge retired again replaces its older retired slot and its entries, so a badge
appears at most once among them. procmgr may hand a dead process's badge to a
new one, so a live slot and a retired slot can share a badge, unless the badge
is among logd's most recent evictions (§ Wait-set).

## Queries

Two labels read the badge table, the retired slots, and the history. They are
served only on a badge carrying `log_labels::LOG_QUERY_AUTHORITY` (`1 << 63`)
or `log_labels::LOG_FOLLOW_AUTHORITY` (`1 << 60`), each a
[verb bit](../../../docs/capability-model.md#verb-bit-authority-pattern):
svcmgr mints a `SEND|GRANT` on the master log endpoint with each badge from its
master-log source and publishes them seed-only as `logd.query` and
`logd.follow`
([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `seed`),
so only a recipe that seeds a name holds it. The two differ only in the pool a
subscription on them draws from (§ Subscriptions). No sender's badge carries a
verb bit: procmgr redraws a process badge that does
([`log_badges`](../../../shared/ipc/src/log_badges.rs)), and `LOG_BADGE_INIT` and
`LOG_BADGE_PROCMGR` carry none. A query on any other badge is refused with
`QUERY_DENIED`.

A receive worker answers a query, a subscription (§ Subscriptions) and a sink
control request (§ Sink control) from the table, the history and the sinks' state
logd owns, as it serves the stream labels (§ Receive pool), and calls no other
service to answer it, so none of them waits on another service (§ Death-queue
resync gives the deadlock a call to procmgr would risk). The wire format is
defined in `ipc::log_query` and `ipc::log_control`. Every request carries
`ipc::LOG_LABELS_VERSION` (8) in `data[0]`, which logd checks on every request.
The reply's label carries the status in bits 0-15, the reply's entry count in
bits 16-31, and in bit 32 whether more entries follow this page:

| Status | Value | Meaning |
|---|---|---|
| `QUERY_OK` | 0 | the page follows |
| `QUERY_DENIED` | 1 | the badge carries no authority the label is served on |
| `QUERY_VERSION_MISMATCH` | 2 | `data[0]` is not logd's `LOG_LABELS_VERSION` |
| `QUERY_INVALID` | 3 | a request word holds a value the label does not define, or a capability the label does not take |
| `QUERY_STALE` | 4 | an ascending walk names another logd instance's epoch (§ Subscriptions) |
| `QUERY_FULL` | 5 | the subscription pool the badge draws from is full |
| `QUERY_NO_SINK` | 6 | `SINK_SET` names no sink logd has |

`logd.query` and `logd.follow` carry `GRANT`, so any holder can move logd any
capability with any label. A receive worker deletes every capability that
arrives with a request, whatever its label, but the two a `LOG_SUBSCRIBE` it
accepts keeps, so no sender can fill logd's capability space.

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
  walk moves one way only; a retire keeps an entry's `seq`. Newest first, an
  entry retained after the walk began is newer than every entry it read and is
  missed, as is one the history drops before the walk reaches it. Oldest first,
  an entry retained after the walk began is read when the walk reaches it, and
  one the history drops before the walk reaches it is missed, which an
  unfiltered walk sees as a gap in `seq`, since `seq` is dense.

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

The reply carries up to `SLOTS_PAGE` (5) entries of `SLOT_ENTRY_WORDS` (11) data
words each, from `data[0]`:

| Word | Content |
|---|---|
| 0 | badge |
| 1 | state in bits 0-7 (`SLOT_LIVE` 0, `SLOT_EVICTED_DEATH` 1, `SLOT_EVICTED_RESYNC` 2), the name's length in bits 8-15; bits 16-63 0 |
| 2 | exit reason of the death that evicted the slot; 0 for any other state |
| 3-8 | the display name, `MAX_NAME_LEN` (48) bytes little-endian, zero-padded; empty for a slot that registered none |
| 9 | the slot serial: logd numbers each slot it creates from 1, never reusing a number within an instance, and a history entry names its slot by it |
| 10 | the name generation: the slot's name registrations, a count from 0 that stops at `u32::MAX`, where the slot keeps its last name |

### `log_labels::QUERY_HISTORY` (17)

History entries, newest first or oldest first: those of every live and retired
slot, or of one badge (its live slot and its retired slot), at every level or at
a level and the more severe.

| Request word | Content |
|---|---|
| `data[0]` | `LOG_LABELS_VERSION` |
| `data[1]` | bit 0: one badge's entries only; bit 1: newest first, resume before the `seq` in `data[3]`; bit 2: oldest first, from the `seq` in `data[3]`, that entry included; bit 3: only entries at the level in `data[4]` or more severe; bits 1 and 2 both set, or any other bit set: `QUERY_INVALID` |
| `data[2]` | the badge, with bit 0 of `data[1]` |
| `data[3]` | with bit 1, the `seq` of the last entry read; with bit 2, the first `seq` to read (0: from the oldest), which a reader sets to the `seq` after the last one it read |
| `data[4]` | with bit 3, the least severe level returned, an `ipc::stream_labels::LEVEL_*` code; past 7: `QUERY_INVALID` |
| `data[5]` | with bit 2, the instance epoch the reader follows (§ Subscriptions): another instance's is refused `QUERY_STALE`, and 0 asks no check |

With neither bit 1 nor bit 2 the walk starts at the newest entry. A filtered walk
serves an interactive reader, which counts no gap; a reader that counts the
entries it missed walks unfiltered.

The reply carries as many whole entries as fit its 64 data words, from
`data[0]`, each word-aligned:

| Words | Content |
|---|---|
| 0 | `seq` (§ History) |
| 1 | `us` |
| 2 | the slot serial of the sender's slot (§ `log_labels::QUERY_SLOTS` (16)), whose row carries its badge |
| 3 | level in bits 0-7 (`ipc::stream_labels::LEVEL_*`), kind in bits 8-11 (`ENTRY_TEXT` 0, `ENTRY_RECORD` 1), origin in bits 12-15 (`ORIGIN_LIVE` 0, retained by this logd instance; `ORIGIN_RELAYED` 1, installed from init-logd's handover), the byte length in bits 16-31, the slot's name generation when the entry was retained in bits 32-63 |
| 4 on | the entry's bytes (§ History), zero-padded to a word |

Every entry fits one reply: the longest, a `RECORD_MAX_BYTES` (480) record,
takes 4 + 60 words. A record's bytes are its `STREAM_RECORD` payload, which
`ipc::log_record::Record::decode` reads back to its message and fields.

## Subscriptions

### `log_labels::LOG_SUBSCRIBE` (19)

A subscriber is signalled each time logd retains an entry, and reads the new
entries itself with an oldest-first `QUERY_HISTORY` walk from the `seq` after
the last one it read. The request moves two capabilities to logd, in this order:

| Request | Content |
|---|---|
| `data[0]` | `LOG_LABELS_VERSION` |
| capability 0 | the signal: a capability, with the notify right, to a Notification of the subscriber's |
| capability 1 | the token: a capability to a Notification of the subscriber's that nobody waits on, whose sole reference ends the subscription (below) |

The subscriber moves copies and keeps its own capability to each object. Every
holder of a name shares its one badge, so a subscriber is not told apart by its
badge, and the death cascade cannot end its subscription; the token ends it.

logd answers `QUERY_DENIED` on a badge with neither `LOG_QUERY_AUTHORITY` nor
`LOG_FOLLOW_AUTHORITY`, `QUERY_INVALID` for a request with other than two
capabilities, a signal that is not a Notification or lacks the notify right, or
a token that is not a Notification, and `QUERY_FULL` when the badge's pool has
no free subscription. A refused request leaves logd holding none of its
capabilities. Subscriptions come from two pools, kept apart by the verb bit of
the SEND the request arrives on, each a [docs/limits.md](../../../docs/limits.md)
row:

| Pool | Badge | Subscriptions |
|---|---|---|
| interactive followers | `LOG_QUERY_AUTHORITY` (`logd.query`) | `SUBSCRIBERS_MAX` (8), indices 0 to 7 |
| external sinks | `LOG_FOLLOW_AUTHORITY` (`logd.follow`), which only a recipe seeds | `SINK_SUBSCRIBERS_MAX` (4), indices 8 to 11 |

so interactive followers cannot take an external sink's place. The `QUERY_OK`
reply carries no entries:

| Reply word | Content |
|---|---|
| `data[0]` | the subscription's index |
| `data[1]` | the instance epoch: the monotonic time, in microseconds since boot, this logd started; never 0, and no other instance shares it |
| `data[2]` | the `seq` of the oldest entry the history holds, or `data[3]` when it holds none |
| `data[3]` | the `seq` the next entry retained takes |

logd signals every subscriber's Notification, bit 0, after it retains an entry,
from the thread that retained it. The signals coalesce: a subscriber reads
everything after its cursor on each wake. A `STREAM_BYTES` message that
completes no line retains no entry and signals no one.

**The subscriber's end.** logd binds a sole-reference observer
(`SYS_CAP_BIND_SOLE_REFERENCE`,
[core/kernel/docs/capability-internals.md](../../../core/kernel/docs/capability-internals.md)
§ Sole-Reference Observers) on the token, posting to an event queue of logd's
that its main thread's wait set holds (§ Wait-set), the correlator naming the
subscription's index and a generation the index counts. When the subscriber
deletes its token, or dies and its capabilities go, the token falls to logd's
one reference: the kernel posts on the deleting CPU's next drain, at the latest
after its next timer tick, and logd's main thread wakes, ends the subscription,
deletes both of its capabilities and frees the index. A subscriber ends its
subscription by deleting its token. A token moved with no capability kept
ends its subscription as soon as it is made. The token, not the signal's
Notification, is observed because a wait on the Notification and its wait-set
membership are references the kernel counts, so the Notification does not fall
to one reference while its subscriber waits on it.

**logd's end.** The subscriber can bind a sole-reference observer of its own on
the token: when logd dies, or ends the subscription, the token falls to the
subscriber's reference, and the post tells the subscriber to subscribe again.
The epoch then tells it whether the instance changed, and the `seq` numbering
with it. An oldest-first `QUERY_HISTORY` walk carrying the epoch it subscribed
on is refused `QUERY_STALE` by another instance, so a reader that follows by
`seq` cannot read a new instance's entries as the old one's.

A follower thus wakes only for entries and for those two ends: idle, it makes
no call and takes no wake-up, and neither side polls.

## Sink control

Two labels read and change logd's device sinks (§ Output sinks) and their
settings ([sinks.md](sinks.md) § Settings). They are served only on a badge
carrying `log_labels::LOG_CONTROL_AUTHORITY` (`1 << 61`), a verb bit svcmgr
mints on a SEND, without `GRANT`, from its master-log source and publishes
seed-only as `logd.control`; any other badge is refused `QUERY_DENIED`. The
wire format is defined in `ipc::log_control`.

### `log_labels::SINK_LIST` (20)

One sink per request, by its index from 0: `data[0]` `LOG_LABELS_VERSION`,
`data[1]` the index. The reply carries one entry, with bit 32 of its label set
when another sink follows, or none past the last sink:

| Reply word | Content |
|---|---|
| 0 | the state in bits 0-7 (`SINK_SERVED` 0, its driver resolved and answering; `SINK_UNSERVED` 1, no driver of its class resolved; `SINK_STALLED` 2, its current write older than the stall bound), the name's length in bits 8-15, the settings' length in bits 16-31 |
| 1 | the cursor: the `seq` of the next entry the sink considers |
| 2 | the entries the sink owed and dropped since logd started |
| 3 on | the name (`serial`, `framebuffer`), at most `SINK_NAME_MAX` (16) bytes, zero-padded to a word, then the settings in the recipe's syntax, every key with its value, at most `SETTINGS_TEXT_MAX` (256) bytes |

### `log_labels::SINK_SET` (21)

| Request word | Content |
|---|---|
| `data[0]` | `LOG_LABELS_VERSION` |
| `data[1]` | the name's length in bits 0-15, the settings string's length in bits 16-31; bits 32-63 0 |
| `data[2]` on | the sink's name, zero-padded to a word, then the settings string |

The string is a list of `key=value` items in the recipe's syntax, applied over
the sink's current settings by the parser that reads the recipe, so a key it
does not name keeps its value. A name no sink has is refused `QUERY_NO_SINK`; a
string that is not UTF-8 or does not parse is refused `QUERY_INVALID` and
changes nothing. A string that parses becomes the sink's settings at once, under
the state lock: the writers and the kernel log reader are woken, since the sink
may now show or hold differently, and logd records the change in its own
notice line, `<sink>: settings set to <string>`, which the sinks show as any
other entry.

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
  history, each sink's cursor, and the death drain's count are under one lock. A worker takes it
  to complete and retain a line or a record, to record a name, or to answer a query; no thread
  holds it across an IPC call, and no worker renders or writes a line.
- **Output.** A worker retains the lines a message completes in the history (§ History), wakes the
  sink writers, and replies. It waits on no sink: a log call returns once its lines are retained,
  whatever the drivers do (§ Output sinks). A message the sender's window does not admit is
  refused `WINDOW_FULL` before anything of it is consumed (§ Hold window).
- **Order.** A line takes its `seq` (§ History) under the state lock as it is retained, and each
  sink writes the history in `seq` order (§ Output sinks), so the lines of different workers reach
  every driver in `seq` order. A worker replies only once the lines a message completed are
  retained, so the lines of one sender thread whose calls are answered keep their order. A log
  call is bounded ([shared/log/README.md](../../../shared/log/README.md)), and one that times out
  after a worker received it ends that worker's binding, not its service of the message: the
  sender's next call, served by another worker, can be retained first, so it takes the smaller
  `seq`, and the bytes of a timed-out `STREAM_BYTES` chunk can join the slot's partial line after
  those of a later chunk. Two threads of one process share a slot (§ Levels).

## Output sinks

logd writes the history to two output drivers, the serial driver and, when one is resolved, the
framebuffer driver. Each is a sink with a cursor, the `seq` of the next entry it writes, and a
writer thread that writes from the history at its own pace (`services/logd/src/main.rs` `Sink`;
the contract is [sinks.md](sinks.md) § Sinks). Each sink's settings, its level, format, pace,
backlog, `relayed` and colour, come from logd's recipe over the defaults of
[sinks.md](sinks.md) § Device sinks, and live in logd's state (`LogdState::settings`,
[sinks.md](sinks.md) § Settings); a sink writes the entries at or above its level and passes the
others. No receive worker, and no other thread of logd's,
waits on a driver: a driver that is slow, stopped by a debugger, or dead costs logd its own
writer, and the entries the history drops before the writer reaches them.

- **Writer.** The writer takes the state lock, copies the entry at its cursor, releases the lock,
  renders and writes the entry, then moves the cursor past it under the lock. It sleeps on a
  condition variable of the state lock, signalled on each retention. The history counts, for each
  sink, the entries the sink shows that it evicted before the writer reached them, and the writer
  reports them as dropped. The writers are spawned
  beside the receive workers, before the handover pull, and write once init-logd has acknowledged
  the release (at once on a restart).
- **Serial: `hold` by default, at info.** The serial sink writes an entry's chunks as plain writes,
  then one zero-length write with `serial_labels::SERIAL_WRITE_SENT`, a barrier the driver answers
  once every byte before it has left the UART ([serial
  driver](../../drivers/serial/README.md#label-1-serial_write_bytes) § Label 1), and moves its
  cursor only then, so an entry counts as written when it is on the wire. A step the driver answers
  `STALLED` (its `TX_STALL_MS`, 1000 ms, without progress) is made again and the cursor does not
  move; a call that fails, as every call to a driver devmgr has withdrawn does, writes the entry
  again from its first chunk to the next driver resolved. Any other refusal gives the entry up,
  counted. A `hold` sink, serial by default, holds senders (§ Hold window), a flush (§ Flush
  barrier) and the kernel reader while it is *holding*: its level is not `off`, its class SEND was
  delivered, its writer runs, devmgr serves a driver of its class, and its current write is not
  older than `SINK_STALL_MS` (1000 ms, [docs/limits.md](../../../docs/limits.md) § init and logd).
  It holds them only for the entries it shows. A sink that is stalled, unserved, absent or `off`
  holds nobody, so no driver is required: a stopped driver holds senders for `SINK_STALL_MS` once.
- **Framebuffer: `skip` by default, at critical.** The framebuffer sink holds nobody. When its
  driver comes up behind, its cursor starts `backlog` (64 by default) entries before the newest,
  and the entries it passes that it shows are counted as dropped. Before an emergency entry it
  writes the entries at info or more severe before it that it did not show, at most `backlog` of
  them ([sinks.md](sinks.md) § Device sinks), and it draws its level tag in the level's colour
  (`FB_SET_ATTRS`, [sinks.md](sinks.md) § Colour).
- **Drops.** The serial sink writes the count of a gap as one notice-level logd line,
  `serial: <n> lines dropped`, ahead of the next entry. The framebuffer sink retains its count as
  a notice line of logd's in the history, `framebuffer: <n> lines dropped`, so the serial console
  and the history carry it too; while that notice is still ahead of its cursor, a further count is
  added to it ([sinks.md](sinks.md) § Drops).
- **Relayed entries.** The entries of init-logd's handover table (§ History) were written to the
  serial console by init-logd already: the serial sink passes them (`relayed=no`), its cursor
  starting at the table's next `seq`, and the framebuffer (`relayed=yes`) writes those it shows.
- **Inline.** A sink whose writer cannot be spawned is written by the thread that retains an entry,
  one thread at a time, each write bounded by `SINK_STALL_MS` from its start; such a sink holds
  nobody.
- **Kernel reader.** The thread that reads the kernel's log ring retains each record, and before
  it acknowledges a read waits until every holding `hold` sink's cursor, serial's by default, has
  passed the read's last entry, so the kernel's ring does not run ahead of the serial console.
- **Panic sink.** logd's own panic and allocation-failure output goes to the serial driver
  directly, outside the history and with no lock taken, each call bounded by `SINK_STALL_MS`.

## Hold window

A sender may hold at most `HOLD_WINDOW` (16) entries that a `hold` sink, serial by default, shows
and has not written, twice that for a message at `error` or more severe; with two `hold` sinks, the
larger of the two counts. While a `hold` sink is holding (§ Output sinks), a `STREAM_BYTES` or
`STREAM_RECORD` message whose completed lines would take its sender past its window is refused
`stream_labels::WINDOW_FULL` (3), with `data[0]` a retry hint in milliseconds: the entries past the
window times the slowest holding writer's last time per entry, clamped to 1 ms and `SINK_STALL_MS`.
Nothing of a refused message is consumed. A sender whose window is empty is never refused, and
neither are the kernel's records nor logd's own lines. The refusal allocates nothing, logs nothing
and calls nothing, so a sender that resends at once costs logd a receive and a reply. The log
library sleeps the hint and sends the message again while its call bound has room, and
drops it, counted, past that; a process that has set `set_no_wait` (procmgr) drops it at once
([shared/log/README.md](../../../shared/log/README.md)). The window is a pace, not a capacity: the
history's bounds (§ History) do not depend on it.

## Flush barrier

A log call returns once logd has retained its line, before any sink writes it (§ Hold window). So
a process whose next act makes the log unwritable, by stopping or resetting the machine or by
ending logd, first waits on `log_labels::LOG_FLUSH` (18) until the lines logd has taken are on
the console, for at most a bound of its own, and goes on with the act when the wait ends, however
it ends: flushed, timed out, refused or failed. The flush only orders the act after the console;
it never keeps the act from happening. `ipc::log_flush::wait` holds a client's steps, and every
holder calls it. A flush waits on the `hold` sinks that are holding, the serial sink by default
([sinks.md](sinks.md) § Device sinks), and on no `skip` sink, the framebuffer's default.

Each holder of the barrier's authority holds it for one such act:

| Holder | The act it waits before | The lines the wait keeps |
|---|---|---|
| pwrmgr | every power-off and reset it acts on, and its power-off on a core service's death ([pwrmgr](../../pwrmgr/README.md)) | the lines logged before the request or the death, a test's pass marker and crash reports among them |
| acpid | on x86-64, its write of the sleep or reset register (`SLEEP`, `RESET`; [acpid](../../acpid/README.md) § Power requests) | its own line naming the write, which it logs after pwrmgr's flush and right before the write |
| crashd | its decline of a fault ([crashd operation](../../crashd/docs/operation.md) § Per Fault) | the fault's report, since the decline can end logd itself |
| svctest | none: its `logd_flush` phase tests the barrier | none |

The label is served only on a badge carrying `log_labels::LOG_FLUSH_AUTHORITY` (`1 << 62`, a
[verb bit](../../../docs/capability-model.md#verb-bit-authority-pattern)). svcmgr mints a SEND on
the master log endpoint with that badge from its master-log source and publishes it seed-only as
`logd.flush` ([`.svc` Service Definitions](../../svcmgr/docs/service-definitions.md) § `seed`).
The recipes of the holders above seed it, and no other. A request on any other badge, `logd.query`'s
included, is refused `FLUSH_DENIED`, and a query on `logd.flush` is refused `QUERY_DENIED`
(§ Queries).

A receive worker answers at once and waits on nothing. It reads the `hold` sinks' cursors and the
history's next `seq` under the state lock, and the writers' state, and calls no service. A flush
does not wait inside logd: the caller asks again. The wire format is defined in `ipc::log_flush`.

| Request word | Content |
|---|---|
| `data[0]` | `LOG_LABELS_VERSION` (8), checked on every request |
| `data[1]` | 0 for a new flush, 1 to ask again for the token in `data[2]`; any other value: `FLUSH_INVALID` |
| `data[2]` | the token of an earlier answer, with `data[1]` = 1 |

The reply's label is its status:

| Status | Value | Reply words |
|---|---|---|
| `FLUSHED` | 0 | `data[0]`: the token |
| `FLUSH_PENDING` | 1 | `data[0]`: the token; `data[1]`: the retry hint, in milliseconds |
| `FLUSH_DENIED` | 2 | none: the badge carries no `LOG_FLUSH_AUTHORITY` |
| `FLUSH_VERSION_MISMATCH` | 3 | none: `data[0]` is not logd's `LOG_LABELS_VERSION` |
| `FLUSH_INVALID` | 4 | none: `data[1]` is neither 0 nor 1 |

- **Token.** A new flush's token marks the end of the log as logd holds it when it answers: the
  `seq` the next retained entry takes (§ History). A client never reads the token. It hands it
  back unchanged when it asks again. A token holds only for the logd instance that issued it,
  since the lines it marked went with the instance that held them. An instance reads every token
  as a number of its own: one above the next `seq` it would issue (from before logd restarted,
  while the new instance has retained fewer entries) answers `FLUSHED`, and a lower one waits on
  the new instance's entries up to it, within the same bounds. `FLUSHED` is 0, so the empty reply
  that init-logd gives a label it does not serve reads as flushed.
- **Flushed.** The log is flushed for a token once the cursor of every holding `hold` sink, serial's
  by default, is at or past it: every entry before it that the sink shows written, or given up
  (§ Output sinks). A sink that holds nobody (stalled, unserved, absent, `off`, or written inline)
  is not waited for, so with none holding the log is flushed at once. So no driver is required,
  and one that does not answer holds a flush for `SINK_STALL_MS` at most. Written means sent: the
  serial writer ends each entry with its `SERIAL_WRITE_SENT` barrier. A sink whose driver has just
  resumed after a stall holds nobody until its write in flight returns, so a flush in that moment
  is answered `FLUSHED` at once.
- **Retry hint.** A pending answer's hint is the expected time of the unwritten entries up to the
  token: their count times the slowest holding writer's last time per entry, rounded up to whole
  milliseconds, clamped to 1 ms and `SINK_STALL_MS`. A client sleeps it, then asks again with the
  token. Its own bound on the whole wait is its own. pwrmgr uses a log call's bound
  (`log::LOG_CALL_TIMEOUT_MS`) before a requested power-off or reset, and `SINK_STALL_MS` before
  its core-death power-off; acpid a log call's bound before its register write; crashd what is
  left of a fault's 2 s bound.
- **Coverage.** A flush covers every entry retained before it: senders' lines, logd's own lines and
  the kernel's. A line whose message is still being served when the flush is answered is not
  covered, nor is one refused `WINDOW_FULL` and not yet sent again, nor one sent after. Such a
  line races the power-off however the barrier is built.

### Lines lost by decision

A log call returns once its line is retained, before any sink writes it. Two losses follow, and
both are decisions, not defects:

- **Kernel panic.** A kernel panic stops every CPU with logd's unwritten entries in its memory. The
  kernel's own panic output goes to the console directly, but the senders' last lines are lost: at
  worst every sender's window, `HOLD_WINDOW` (16) entries each, twice that for those at `error`
  or more severe, and all the entries the serial sink was behind when it last stalled. pstore,
  which keeps the history across a reset, is #1498 ([sinks.md](sinks.md) § pstore).
- **logd's own death.** The entries logd holds unwritten die with it; a restarted logd starts with
  a history of its own. The processes that end logd, or the machine, wait on the flush barrier first
  (§ Flush barrier): pwrmgr before a power-off or reset, acpid before the register write that enacts
  one, crashd before it declines a fault, a fault of logd's own included. A fault in a thread of
  logd that holds its state lock leaves logd unable to answer the flush: crashd's wait ends at its
  bound, and the report's unwritten lines are lost with logd.

## Wait-set

logd's main thread waits on a `WaitSet` of up to 5 members:

| Badge | Source | Purpose |
|---|---|---|
| `WS_BADGE_DEATH` (1) | RECV on logd's death-notification `EventQueue` | drained on the wake |
| `WS_BADGE_RESYNC` (2) | logd's resync `Notification` | bit `RESYNC_WALK_DONE` (1): the resync helper thread's walk has ended; bit `RESYNC_REQUESTED` (2): a drain asks for a resync (§ Death-queue resync) |
| `WS_BADGE_WATCHES` (3, 4) | the serial and the framebuffer class watch `Notification`s, each when devmgr registered it | the class's driver changed; the sink's driver is resolved again (§ Output sinks) |
| `WS_BADGE_SUBSCRIPTIONS` (5) | RECV on the subscriptions' `EventQueue`, of `SUBSCRIBERS_MAX + SINK_SUBSCRIBERS_MAX` (12) entries and observer nodes, when logd could make it | drained on the wake: each post whose correlator names a subscription's index and current generation ends it (§ Subscriptions) |

logd serves on without the subscriptions' queue, and then refuses every
`LOG_SUBSCRIBE` `QUERY_FULL`.

Each receive worker drains the death queue before it serves a request. The main thread drains the
queue when it is ready, so deaths no request follows are drained too. Each take from the queue is
made, with its eviction, under the state lock (§ Receive pool).

A worker can still serve a request after its sender's eviction: the request was received before
the sender's death, and the death was taken, by this worker or another thread, before the worker
took the state lock; a resync's eviction can fall in the same place. logd keeps the badges of its
last `EVICTED_BADGES` (128) evictions, by a death or a resync, whether or not the badge had a slot
([`lib.rs`](../slot-table/src/lib.rs)). A `STREAM_BYTES`, `STREAM_RECORD` or
`STREAM_REGISTER_NAME` whose badge has no live slot and is among them is the evicted sender's, and
logd drops it and replies as for one it consumed, rather than give the badge a live slot again.
procmgr draws process badges at random, so a new process takes one of those badges only by chance.

## Death-notification cascade

procmgr, not the kernel, is the source of logd's death events. Every
process spawned by procmgr is bound to death observers on procmgr's own
death queues only (correlator = the full process badge, for procmgr's
auto-reap path). logd's death `EventQueue` has no death-observer nodes and
nothing binds it: once logd's
[`REGISTER_DEATH_EQ`](../../procmgr/docs/ipc-interface.md) has stored it in
procmgr's `LOGD_DEATH_EQ` static, every teardown procmgr runs (the reap of
a death event, its death resync, and a destroy, `DESTROY_PROCESS` or
`DESTROY_CHILD`, for each process of the subtree it destroys) posts the death
entry `(exit_reason, process badge)` to it. A process torn down before the
registration posts nothing. A restarted logd's registration replaces the dead
instance's queue, so its fresh table hears every death after it.

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
§ Symbolizing), as `cargo xtask run --crash-reports` does.
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
