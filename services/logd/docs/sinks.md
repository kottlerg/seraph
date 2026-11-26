# logd Sinks

Design of logd's sinks: the record logd keeps, the sink contract that every output of the log
follows, the per-sink settings, the console and RFC 5424 formats, and the interface through which
a program reads, follows and steers the log.

---

## Implementation status

Built: the eight severities and their console tags, the console prefix
`[sec.usfrac] LEVEL  [name] ` that both receivers write, the kernel's records read and written as
`[kernel]` lines, the serial and framebuffer outputs as two sinks with a bounded queue and a writer
thread each, and the serial sink's writes of a line as plain chunks and then a zero-length
`SERIAL_WRITE_SENT` barrier ([ipc-interface.md](ipc-interface.md) § Levels, § Output sinks).

Everything else this document states is design intent, not yet implemented, unless a sentence names
it as built. Each section names the Issue that builds it. Until an Issue lands,
[ipc-interface.md](ipc-interface.md) and [handover-protocol.md](handover-protocol.md) describe what
logd does, and where they and this document differ on current behaviour, they hold.

---

## Standards

logd adopts the parts of RFC 5424 (The Syslog Protocol) that fit the system, so that a network sink
sends records in the standard form and external logging tools receive them as they are:

- **Severities.** The level scale is RFC 5424's eight severities, 0 (emergency) to 7 (debug)
  (built; [ipc-interface.md](ipc-interface.md) § Levels).
- **Record.** The record logd keeps carries what RFC 5424's fields need (§ The record), and a sink
  that emits RFC 5424 maps it field by field (§ The rfc5424 format).
- **Not adopted.** The protocol by which a process logs to logd is the project's own
  (`STREAM_BYTES`, `STREAM_RECORD`). The project defines no structured-data element of its own,
  so it needs no IANA enterprise number. The console format is the project's own (§ The console
  format): RFC 5424 is a wire format between a syslog sender and a receiver and says nothing about
  storage or a console, and its priority value, version and structured data serve no reader of a
  console.

These points of RFC 5424 bind a sink that emits it:

- §6: `<PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG`, each header field
  that has no value written as the nil value `-`; APP-NAME is 1 to 48 printable US-ASCII
  characters.
- §6.4: a MSG encoded in UTF-8 MUST start with the byte order mark (`EF BB BF`).
- §6.2.3 and A.6: TIMESTAMP is RFC 3339, nil only when the sender cannot obtain the time.
- §7.1: an originator not synchronised to a reliable external time source SHOULD write the
  registered `timeQuality` element.
- §5.1: every implementation MUST support the TLS transport (RFC 5425); UDP (RFC 5426) is a SHOULD.
- §6.1: a receiver MUST accept 480 octets and SHOULD accept 2048.

---

## The record

*Design intent: the slot serial and the origin are #1492's and #1496's work and #928's; the
history entry's other fields are built.*

logd's history entry is the record. Every sink renders from it, and the query interface returns it
(§ Queries, follow and control).

| Field | Content |
|---|---|
| `seq` | logd-wide sequence, dense: one counter across every slot, taken when the entry is retained |
| `us` | the monotonic time the entry was retained (a kernel record's own time), microseconds since boot |
| `badge` | the sender's badge |
| `slot` | the slot serial of the sender's slot (below) |
| `level` | the severity, 0 to 7 ([ipc-interface.md](ipc-interface.md) § Levels) |
| `kind` | `Text` or `Record`, with a record's field table ([ipc-interface.md](ipc-interface.md) § History) |
| `bytes` | the line's bytes or the record's payload |
| `origin` | `live` (retained by this logd instance), `relayed` (installed from init-logd's handover), or `previous` (installed from the previous boot's pstore ring, § pstore) |

- **Slot serial.** logd gives every slot it creates a 64-bit serial, counting up from 1 over the
  life of the logd instance and never reused within it. An entry names its sender by it, not by its
  badge alone: a live and a retired slot can share a badge
  ([ipc-interface.md](ipc-interface.md) § Retired slots), and a reader that lags behind the history
  must name an entry whose slot has since been retired. A serial names one slot for the life of the
  instance, but the slot's name can change after a reader reads it: a sender can register its name
  after its first lines, or update it.
  A retired slot that is dropped takes its entries with it, so every entry in the history has its
  slot, and its name, at the moment it is read.
- **Name.** An entry carries no name. A device sink renders the name of the entry's slot, with the
  instance number of § Display names, at the moment it renders. An external sink renders a name
  at least as new as the one the slot had when the entry was retained, or the unnamed sender `?`
  when the slot is no longer in the table (§ External sinks).
- **Name generation.** logd counts each slot's name registrations, a 32-bit count from 0 that only
  rises, and an entry carries its slot's count at the moment the entry was retained, so a reader
  that keeps a slot's name knows when the name it keeps is older than the entry it renders. The
  count never wraps: logd answers a registration from a slot whose count is at `u32::MAX` as it
  answers any other, but leaves the slot's name and count as they are, so the slot keeps its last
  name for the rest of its life.
- **Time.** `us` is monotonic. Wall time is `us` plus the boot wall offset (§ Wall time), applied
  when a sink renders, so a record needs no wall clock to be kept.
- **Origin.** A `relayed` entry was written to the console by init-logd before the handover; a
  `previous` entry's `us` is the previous boot's clock and is never read as this boot's.

---

## Severities

*Built ([ipc-interface.md](ipc-interface.md) § Levels), but for the placement of every call site,
which #1491 makes.*

The eight RFC 5424 severities are the level scale; [ipc-interface.md](ipc-interface.md) § Levels
owns the scale, its keywords, its wire encoding and the rule for choosing a level. The project's
earlier five levels map onto them as follows:

| Earlier level | Severity |
|---|---|
| `error` | error (3), or critical, alert or emergency where the placement rule names the event |
| `warn` | warning (4), or the same three where the rule names the event |
| `info` | informational (6), or notice (5) for a significant normal event shown once |
| `debug` | debug (7) |
| `trace` | removed; a line that was `trace` is `debug` or is removed |

The placement rule for the four severities the earlier scale did not have:

- emergency: the system cannot go on;
- alert: an operator must act now (the memory reserve reached, a critical service out of its restart
  budget);
- critical: a component lost, the system degrading around it;
- notice: a significant normal event, shown once (a service restarted, an oomd kill, a crash report
  written).

The kernel's records carry a severity too: informational for an ordinary print, critical or
emergency for a fault or panic print (#1491; today every record is informational,
[core/kernel/docs/kernel-log.md](../../../core/kernel/docs/kernel-log.md)).

---

## Sinks

*Design intent (#928, #1493, #1494): the contract below replaces the per-sink queues and the
producer's wait that [ipc-interface.md](ipc-interface.md) § Output sinks describes.*

A sink is one output of the log. Every sink, inside logd or outside it, follows one contract: it
reads the history in `seq` order through a cursor, shows the entries at or above its level, renders
each in its format, and writes it to its output.

| Property | Meaning |
|---|---|
| name | `serial`, `framebuffer`, `pstore` for the device sinks; an external sink is named by its own recipe |
| output | the driver a device sink writes to, or what an external sink's process writes to |
| `level` | the least severe level the sink shows; an entry more verbose than it is skipped, uncounted |
| `format` | `console` with a field list, or `rfc5424` |
| `pace` | `hold` (the sink's progress holds senders back) or `skip` (it never does, and loses entries when it falls behind) |
| `backlog` | for a `skip` sink: how many entries before the newest its cursor starts at when it attaches or its driver comes up, when it is further behind than that |
| `relayed` | whether the sink shows `relayed` entries |
| cursor | the `seq` of the last entry the sink has written or skipped |
| drop count | the entries the history evicted before the sink reached them |

### Cursor and order

- A receive worker retains an entry under the state lock and replies; it renders, writes and waits
  for nothing. A sink's writer copies the next entry above its cursor out of the history, with its
  slot's name, under the state lock, renders it outside every lock, and writes it.
- Every sink writes in `seq` order. Lines of different senders therefore reach every output in
  one order, the order the history holds them in.
- A sink whose cursor's next `seq` is no longer in the history counts the missing entries as
  dropped and goes on from the oldest entry still held. `seq` is dense, so a missing `seq` is always
  an evicted entry.

### Pace

- A sink is `hold` or `skip`. Serial is `hold`; the framebuffer, pstore by default, and every
  external sink are `skip`.
- Each sender slot counts its entries that a served, unstalled `hold` sink has not written. A
  message that would take the count past `HOLD_WINDOW` (16) is refused with `WINDOW_FULL`, and
  nothing of it is consumed. A slot with nothing unwritten always accepts, so a message that
  completes more lines than the window holds is taken from an empty window. Messages at error or
  more severe have headroom to twice `HOLD_WINDOW`. The reply carries a retry hint, and the sender's
  library sleeps it and sends the message again within its call's bound
  ([#928](https://github.com/kottlerg/seraph/issues/928) owns the sender's side).
- A `hold` sink is stalled while it is unserved (no driver resolved), or while its writer's current
  write is older than `SINK_STALL_MS`; a stalled sink counts toward no window, so a stopped driver
  holds no sender.
- Past `HISTORY_BYTES`, the history evicts an entry a `hold` sink has not written only when no
  written one is left. `PER_SLOT_HISTORY` drops a slot's own oldest entry whatever the sinks have
  written.
- A `skip` sink holds no sender and keeps no entry: what the history evicts before it is read is
  counted as dropped.

### Drops

A sink that dropped entries writes one line of logd's to its own output before the next entry it
writes, at notice:

```
[   12.000031] NOTICE [logd] serial: 37 lines dropped
```

The line is the sink's own output: it is not retained, not written to another sink, and not counted
in any window. `SINK_LIST` reports each device sink's drop count. An external sink writes its own
drop line to its own output in its own format.

### Device sinks

Device sinks run inside logd, each with its own writer thread, the only logd thread that calls its
driver. A device sink whose writer cannot be spawned is written inline by the thread that retains
each entry, each write bounded by `SINK_STALL_MS`, as today.

| Sink | Level | Format | Pace | Backlog | Relayed | Colour |
|---|---|---|---|---|---|---|
| `serial` | info | console | `hold` | none | no | no |
| `framebuffer` | critical | console | `skip` | 64 | yes | yes |
| `pstore` | debug | records | `skip` | 0 | no | no |

- **serial.** The authoritative console and the channel CI reads. As a `hold` sink it has no
  backlog: its cursor starts before logd's oldest entry and moves only as it writes, so a driver
  that comes up late or restarts is written every entry of its absence the history still holds, and
  the evicted ones are counted as dropped. It skips `relayed` entries, which init-logd wrote to the
  UART itself, and shows `previous` entries (§ pstore).
- **serial's "written" means sent** (built, #1497). The serial driver answers a plain
  `SERIAL_WRITE_BYTES` once the bytes are in its transmit ring, and a write with the flag
  `SERIAL_WRITE_SENT` (label bit 32) once they, and every byte written before them, have left the
  UART; a zero-length write with the flag is a barrier for every write before it. logd's serial sink
  writes a line's chunks as plain writes and then that barrier (built, #1703). The virtio-console
  driver answers every write once the device has taken it, and ignores the flag. The `hold` pace,
  the `SINK_STALL_MS` bound on a write, the kernel reader's acknowledgement (§ The kernel's lines)
  and the pass marker and crash reports being on serial before power-off all rest on serial's cursor
  passing an entry only once its bytes are on the wire.
- **A `STALLED` answer.** The driver answers a write that waited on a transmitter making no
  progress `STALLED` after its `TX_STALL_MS` (1000 ms), the same answer whichever wait stalled.
  The writer writes an entry in two steps whose `STALLED` answers each mean one thing (built,
  #1703). Today's writer, which writes from a queue, ends the line on either answer and stalls the
  sink: a chunk answered `STALLED` drops the line, counted, and a barrier answered `STALLED` ends a
  line already in the ring, uncounted ([ipc-interface.md](ipc-interface.md) § Output sinks). In
  this design (#928) a `STALLED` answer does not move serial's cursor: the sink is stalled (§ Pace)
  and the writer repeats the step that stalled until it is answered without `STALLED`, each attempt
  bounded by the driver's stall bound.
  1. Each chunk of the entry as a plain write. `STALLED` here means the chunk was not appended to
     the ring, so the writer writes that chunk again and goes on from it, not from the entry's
     first chunk. Without the transmit interrupt the driver writes a chunk byte by byte and stops
     at the byte the UART did not take, so the chunk's first part shows twice.
  2. A zero-length write with the flag. `STALLED` here means the entry's bytes are in the ring
     and not yet sent, so the writer writes the barrier again.

  A call that fails, the driver's endpoint withdrawn
  ([serial driver](../../drivers/serial/README.md) § Endpoint), is not a `STALLED` answer: the
  bytes the dead driver accepted died with its ring, so the sink is unserved and the writer writes
  the entry again from its first chunk on the next driver it resolves, where today's writer counts
  the line as dropped. The cursor passes the entry
  only once the barrier is answered without `STALLED` by the driver that accepted every chunk of
  it, so it never passes an entry unsent.
- **`LOG_FLUSH`** (#928) waits for serial's cursor, which passes an entry only once it is sent, and
  needs no barrier of its own. It reports the log flushed once serial's cursor has passed the
  newest entry at the call, or serial is stalled or unserved, as the kernel reader's
  acknowledgement does.
- **framebuffer.** For the person at the screen. Its level is critical, so a healthy boot shows no
  log line on it. When an emergency entry reaches it, the sink first writes the last `backlog`
  entries at info or more severe that precede the emergency entry in the history and that it has
  not written, then the emergency entry, so the screen of a dead machine carries its context. The
  backlog is a walk back through the history, not a buffer of the sink's own. On a (re)attach, its
  cursor starts `backlog` entries before the newest, `relayed` ones included, when it is further
  behind than that.
- **pstore.** A RAM ring that survives a warm reset (§ pstore).

The panic sink stays outside this contract: logd's own panic and allocation-failure output goes to
the serial driver directly, outside the history and with no lock taken.

### External sinks

An external sink is a process that follows the history through the query interface
(§ Queries, follow and control) with the `logd.follow` authority its recipe seeds, which also
serves every read of `logd.query`. It is always `skip`.
logd knows nothing of it but its subscription; logd stays without a namespace, a file system, a
network stack or a TLS stack.

An external sink:

1. subscribes (`LOG_SUBSCRIBE`) and records the instance epoch and the oldest `seq` the reply names;
2. reads the history ascending from the `seq` after its cursor, unfiltered, page by page, and
   applies its own level itself: the walk is unfiltered so that every missing `seq` between two
   entries it reads is an evicted entry, which it counts as dropped;
3. names each entry, and learns its badge, from its slot serial, reading `QUERY_SLOTS` for a serial
   it has not seen or whose kept name generation is below the entry's; a serial no longer in the
   table is rendered as the unnamed sender `?`, with no badge;
4. renders each entry in its format and writes it;
5. waits on its Notification and its event queue together (§ Subscriptions), and on a signal goes
   back to 2.

A reply `QUERY_STALE`, or a post on its event queue that says logd's reference has gone, means the
logd instance it followed is gone: it subscribes again, counts the entries it cannot account for as
an unknown gap, and starts from the new instance's oldest entry.

---

## Settings

*Design intent (#1493).*

Each device sink's settings come from one `env` entry of logd's recipe
(`rootfs/config/svcmgr/services/logd.svc`), so they are set per distribution, signed as
configuration, and replayed on every restart. logd reads no file.

```
LOGD_SINK_<NAME>=<key>=<value>,<key>=<value>,...
```

`<NAME>` is the sink's name in upper case: `SERIAL`, `FRAMEBUFFER`, `PSTORE`.

| Key | Values | Meaning |
|---|---|---|
| `level` | one of the eight keywords | least severe level shown |
| `format` | `console`, `rfc5424` | the output format |
| `fields` | a `:`-separated list of `time`, `host`, `level`, `name`, `procid`, `msg` | the console format's fields, in the order given |
| `time` | `uptime`, `wall` | what the console format's `time` field shows |
| `pace` | `hold`, `skip` | § Pace |
| `backlog` | 0 to 256 | § Device sinks |
| `relayed` | `yes`, `no` | whether `relayed` entries are shown |
| `colour` | `yes`, `no` | the level tag's colour (§ Colour); the framebuffer only |
| `facility` | 0 to 23 | the rfc5424 format's facility (default 3, daemon) |

- `,` separates keys, so the field list uses `:`.
- A key absent keeps its default (§ Device sinks). An entry that does not parse, or a key or value
  it does not know, keeps the defaults for that sink and is self-logged at warning.
- `LOGD_HOSTNAME=<name>` sets the host name the `host` field and the rfc5424 HOSTNAME show; absent,
  they show the nil value `-`.
- Quiet mode is a sink's level.
- The sender-side level ([ipc-interface.md](ipc-interface.md) § Levels, Filter) is still the only
  thing that stops a line from being sent. A sink's level only selects among the lines logd
  retains, and the history keeps every retained line whatever the sinks show.
- `SINK_SET` (§ Queries, follow and control) changes a setting for the life of the logd instance; a
  restarted logd starts from its recipe again.
- The parser is one host-tested type in `logd-codec`, which `SINK_SET` uses too.

An external sink's settings are its own recipe's, in the same keys.

---

## The console format

*Built: the prefix with the tag padded to six. Design intent: the seconds' alignment, the
instance numbers, the field list, wall-clock display and the colour (#1492, #1493).*

The default console line, the same on serial and the framebuffer:

```
[    0.259459] INFO   [init] created memmgr kernel objects
[    6.308457] WARN   [svcmgr] crasher-boot died during its bootstrap (exit reason 0x2000)
[    6.401120] ERROR  [vfsd#2] mount of /data failed
[  104.553210] CRIT   [kernel] page fault in kernel mode at 0xffff800000123456
```

- **Fields.** The default is `time:level:name:msg`: `[sec.usfrac]`, the level tag, `[name]`, the
  message. `host` shows the host name and `procid` the sender's badge in hex, `?` when an external
  sink cannot resolve the entry's slot (§ External sinks). The fields are
  separated by one space, and the tag is padded to six columns, so every line's name starts in one
  column while the seconds are below 100000.
- **Time.** Uptime: the seconds right-aligned to five columns, as Linux's `dmesg` writes them, wider
  past 99999 s; six digits of microseconds. With `time=wall`, an RFC 3339 UTC time with microseconds
  once the boot wall offset is known, and uptime before it. A `previous` entry always shows its own
  uptime.
- **Level.** Every line shows its level, informational included: `EMERG`, `ALERT`, `CRIT`, `ERROR`,
  `WARN`, `NOTICE`, `INFO`, `DEBUG` (`logd_codec::level::tag`).
- **Name.** `[name]` for a sender's first instance, `[name#n]` for its n-th, `[?]` for a sender that
  registered none (§ Display names).
- **Message.** A text line's bytes, or a record rendered as `message key=value ...` on one line
  ([ipc-interface.md](ipc-interface.md) § `stream_labels::STREAM_RECORD`). A text line longer than
  `LINE_BUF_SIZE` is retained as several entries, so each part is its own line with the full prefix
  and its level.
- **Kernel lines** take the same shape, with the name `kernel` and the record's severity.
- **Patterns.** Every pattern xtask or CI matches on a console line changes with the format, in the
  same PR as the line it matches.

### Colour

Serial carries no colour: it is captured to files and matched by CI. On the framebuffer, with
`colour=yes`, only the level tag is coloured, in the terminal's 16-colour palette
([shared/ansi](../../../shared/ansi/README.md) `ANSI_RGB`): emergency to error red, warning yellow,
notice bright white, informational the default foreground, debug bright black. The bytes are
otherwise those serial shows.

The framebuffer driver's colour is one global state that the terminal shares
([services/drivers/framebuffer/README.md](../../drivers/framebuffer/README.md) § Label 2:
`FB_SET_ATTRS`). The sink sets the tag's colour, writes the tag, and sets the driver's default
colour back before the rest of the line, so a colour the terminal had set is reset by a log line
until the terminal next sets one. Per-client colour state arrives with the display broker
([#153](https://github.com/kottlerg/seraph/issues/153)). At the framebuffer's default level a log
line reaches the screen rarely. (Pending the maintainer's approval.)

### Display names

*Design intent (#1492).*

- logd numbers each instance of a display name when its slot registers the name, counting up per
  name over the life of the logd instance; the first shows as `[name]`, the n-th as `[name#n]`. A
  `#` in a registered name renders as `_` and is counted under that rendered name, so no label
  equals another's.
- init-logd numbers the same way, in place of its `name.N` suffix, and the handover carries each
  slot's number and the counter table, so logd continues init-logd's count. One host-tested type in
  `logd-codec` holds the rule.
- The counter table holds `NAME_COUNTERS` (256) names; a name first seen once it is full draws from
  one overflow counter shared by every such name, so it is numbered from its first instance and its
  numbers never repeat.
- `QUERY_SLOTS` returns each slot's number, so `log --sender vfsd#2` names one instance.
- A restarted logd numbers afresh; its restart line marks the boundary.

---

## The rfc5424 format

*Design intent (#1493 for a device sink, #1499 for the network sink).*

A sink in the `rfc5424` format writes each entry as one RFC 5424 message:

| Field | Value |
|---|---|
| PRI | facility × 8 + severity; the facility is 0 (kernel) for the kernel's entries, the sink's `facility` for every other |
| VERSION | `1` |
| TIMESTAMP | `us` plus the boot wall offset, RFC 3339 UTC with microseconds; `-` while no offset is known and for a `previous` entry |
| HOSTNAME | `LOGD_HOSTNAME` (or the external sink's own setting), `-` when unset |
| APP-NAME | the slot's display name without the instance number; each byte outside printable US-ASCII (33 to 126) written `_`, at most 48 bytes; `-` for an unnamed sender |
| PROCID | the badge in lower-case hex; it tells instances of one name apart; `-` when the sink cannot resolve the entry's slot (§ External sinks) |
| MSGID | `-` |
| STRUCTURED-DATA | `[timeQuality tzKnown="1" isSynced="0"]` while the offset comes from an unsynchronised clock, `-` once it is synchronised |
| MSG | the byte order mark, then the console format's message field, each byte of an invalid UTF-8 sequence written `\xNN` as the record renderer writes it, so MSG is valid UTF-8 |

timed sets its offset once, from the RTC, and synchronises to no external source
([services/timed/README.md](../../timed/README.md)), so every message carries `timeQuality` today. A
message longer than the transport carries is cut at a character boundary of MSG.

---

## Wall time

*Design intent (#1493). The svcmgr change below is #1493's.*

- svcmgr's `log_sink` round gains a slot 6: the SEND of the `timed` publication, absent when no
  recipe provides `timed` ([service-definitions.md](../../svcmgr/docs/service-definitions.md) §
  `log_sink`).
- A helper thread of logd calls `timed_labels::GET_WALL_TIME` once, with no bound, and stores the
  boot wall offset, the wall time less the uptime of the same instant. timed answers from memory;
  its own log calls are served by logd's receive workers, which wait on no call of logd's, so the
  call cannot deadlock. No receive worker and not the main thread calls timed.
- On the answer, logd logs one notice line giving the wall time and the uptime it corresponds to,
  so every uptime in a capture converts:
  `[    3.201440] NOTICE [logd] wall clock 2026-11-25T09:01:11Z at uptime 3.201440`.
  `WALL_CLOCK_UNAVAILABLE` leaves the offset unknown and logs that at notice.
- Until the offset is known, a sink that shows wall time shows uptime (console) or `-` (rfc5424).
  A restarted logd reads the offset again.
- An external sink reads the offset from timed itself, through a `timed` seed of its own recipe.

---

## The kernel's lines

*Built: the reader and its acknowledgement. Design intent: the acknowledgement by serial's cursor
(#928).*

logd's kernel log reader retains each kernel record as an entry of the kernel's slot
(`LOG_BADGE_KERNEL`), and the sinks write it as any entry
([handover-protocol.md](handover-protocol.md) § Kernel log). It acknowledges a record on its next
read only once serial's cursor has passed the record's entry, or serial is stalled or unserved, so
a record the kernel's flush before a failure report writes is one no sink took
([docs/console-model.md](../../../docs/console-model.md) item 4). The reader is a thread of its own
and waits on serial's progress for no sender.

---

## pstore

*Design intent (#1498).*

- The boot reserves a small RAM region at a fixed place in the memory map, not cleared at boot, and
  devmgr serves it as a `pstore` class device to logd.
- logd's pstore sink writes each entry into a ring there, at memory speed, as a record: a header
  with a magic, a format version and the boot it belongs to, and per entry `seq`, `us`, `level`,
  `kind`, the slot's name with its instance number, the bytes, and a checksum. It stores records,
  not rendered lines, so each sink renders them in its own format on the next boot.
- On the next boot logd reads a ring whose header and checksums are valid, installs its entries as
  `previous` entries ahead of its own, and clears the ring.
- Serial shows `previous` entries, which no console of this boot has shown, between two notice lines
  of logd's (pending the maintainer's approval):

```
[    1.204417] NOTICE [logd] previous boot: 23 lines follow
[  104.553210] CRIT   [kernel] page fault in kernel mode at 0xffff800000123456
[    1.204630] NOTICE [logd] previous boot: end
```

- The pstore sink closes the loss #928 accepts: the entries retained but not yet written to serial
  when the kernel panics are on the next boot's console.

---

## Queries, follow and control

*Design intent (#1494), but for `QUERY_SLOTS` and the descending `QUERY_HISTORY` walk, which are
built ([ipc-interface.md](ipc-interface.md) § Queries). `LOG_LABELS_VERSION` is bumped with the wire
changes.*

All of these are answered by a receive worker from logd's state under the state lock, with no call
out, as the queries are today.

All of these are served on SENDs that may carry `GRANT`, so any holder can move logd any
capability with any label. A receive worker deletes every capability that arrives with a message,
whatever its label, but the two a `LOG_SUBSCRIBE` it accepts keeps, so no sender can fill logd's
capability space.

### Reads

- `QUERY_HISTORY` gains two request flags in `data[1]`: bit 2, an ascending walk from the `seq` in
  `data[3]`, that entry included (0: from the oldest entry), so a reader asks for the `seq` after
  the last one it read; bit 3, a severity filter, `data[4]` the least severe level
  returned. With bit 2, `data[5]` carries the instance epoch the caller follows; logd answers
  `QUERY_STALE` (4) when it is not its own, and 0 asks no check.
- An entry in the reply carries its slot serial in word 2, in place of the badge, which the slot's
  `QUERY_SLOTS` row carries, so an entry keeps its four header words and the longest still fits one
  reply; the origin is in bits 12-15 of its kind field (bits 8-11 the kind), and the name generation
  in bits 32-63 of word 3.
- `QUERY_SLOTS` rows carry the instance number in bits 32-63 of word 1, the slot serial in a tenth
  word and the name generation in an eleventh, so `SLOTS_PAGE` is 5.
- The severity filter serves interactive reads, which count no gap; a reader that counts gaps walks
  unfiltered (§ External sinks).

### Subscriptions

- `LOG_SUBSCRIBE` moves two capabilities to logd over a `logd.query` or `logd.follow` SEND, which
  svcmgr mints with `GRANT` for it: a signal capability of a Notification the subscriber made, and a
  token, a capability to a second object of the subscriber's that nobody waits on. logd checks each
  capability's type and rights and deletes what it does not keep, since any holder of the name can
  move it any capability.
- Subscriptions come from two pools, each a [docs/limits.md](../../../docs/limits.md) row, kept
  apart by the verb bit of the SEND they arrive on: `SUBSCRIBERS_MAX` (8) for `logd.query`, which
  every session program may hold (§ Authority to read and steer), and `SINK_SUBSCRIBERS_MAX` (4) for
  `logd.follow` (`LOG_FOLLOW_AUTHORITY`), which only a recipe seeds, so interactive followers cannot
  take an external sink's place. A full pool refuses one more with `QUERY_FULL`. The reply carries
  the subscription's index, the instance epoch (the monotonic time logd started, which no other
  instance shares), and the oldest and newest `seq` held.
- logd signals every subscriber's Notification when it retains an entry. The signals coalesce: a
  subscriber reads everything after its cursor on each wake.
- **A subscriber's end.** logd binds a sole-reference observer (`SYS_CAP_BIND_SOLE_REFERENCE`,
  [docs/capability-model.md](../../../docs/capability-model.md)) on the token, posting to an event
  queue of logd's that its wait-set holds, the correlator naming the subscription's index and a
  generation. When the subscriber dies its slots go, the token falls to logd's one reference, and
  logd ends the subscription and deletes both capabilities. The token, not the Notification, is
  observed because the subscriber's wait on the Notification, and its wait-set membership, are
  references the kernel counts, so the Notification does not fall to one while the subscriber waits
  on it. Every holder of a name shares that name's one badge (`log_labels::LOG_QUERY_AUTHORITY`,
  `LOG_FOLLOW_AUTHORITY`), so a subscriber cannot be told apart by its badge, and the death cascade
  cannot end it. `LOG_UNSUBSCRIBE` ends a subscription at once.
- **logd's end.** The subscriber binds a sole-reference observer on the same token, posting to its
  own event queue. When logd dies, or ends the subscription, the token falls to the subscriber's
  reference and the post tells the subscriber to subscribe again (§ External sinks). The epoch then
  tells it whether the instance changed and its cursor's `seq` numbering with it.
- A follower therefore wakes only for entries and for those two ends: idle, it makes no call and
  takes no wake-up, 0 a minute, and neither side polls.

### Control

- `SINK_LIST` returns, per device sink, its name, its settings, its cursor, its drop count and its
  state (served, unserved, stalled).
- `SINK_SET` carries a sink's name and a settings string in the recipe's syntax (§ Settings), parsed
  by the same type; a string that does not parse is refused and changes nothing.
- Both are served only on a new verb bit, `LOG_CONTROL_AUTHORITY`, which svcmgr mints and publishes
  seed-only as `logd.control`; any other badge is refused with `QUERY_DENIED`.

---

## Authority to read and steer

*Design intent (#1494, #1495, #1501).*

- `logd.query` (reads and subscriptions), `logd.follow` (the same, from the external sinks' pool of
  subscriptions) and `logd.control` (sink control) are seed-only names svcmgr mints. `logd.follow`
  is seeded only to external sinks' recipes and is never served at `/svc`. Only a recipe that seeds
  a name holds it, and a holder passes it on explicitly.
- `programs/log` is the interactive client, in the manner of `journalctl` or a network device's
  `show logging`: it shows, filters and follows the history in the console format and lists and sets
  the sinks. It takes the two authorities as bootstrap caps from its spawner, slot 0 the query
  authority and slot 1 the control authority, either absent (#1495).
- A program a user runs has no recipe. The authorities reach it the way files do, as entries of the
  namespace: registry-fs (#75) serves `/svc`, including the seed-only authorities its own recipe
  seeds, and a lookup of such an entry returns a copy of the held, verb-badged SEND. The walk needs
  `LOOKUP` on `/svc` and the entry's `visible_requires` (none for `logd.query`, `ADMIN` for
  `logd.control`), and logd then checks the verb bit as today. vfsd mounts `/svc` in the synthetic
  root through a mount of a caller-supplied namespace endpoint (#1501).
- Whoever's namespace includes the entries holds the authorities: every session program in a
  userless system, what each per-user view includes once #152's views exist. The terminal,
  sessiond, the shell and usermgr name neither.

---

## What later sinks need

Each later sink is built against the interface above and changes none of it.

| Sink | Needs | Provided by |
|---|---|---|
| Disk (#1496) | every entry in `seq` order from its start, `relayed` and `previous` included; the gaps it could not read; each entry's sender name after the sender died; to learn of a logd restart; wall time for its timestamps | the ascending unfiltered walk from `seq` 0, the oldest, the dense `seq`, the slot serial and `QUERY_SLOTS`, the token and the epoch, its own `timed` seed |
| Network syslog (#1499, #1500) | the RFC 5424 fields of each entry; the facility, severity and host name; APP-NAME and PROCID per instance; TLS | the record and § The rfc5424 format; its own recipe's settings; the TLS stack in its own process (#1500), none in logd |
| pstore (#1498) | each entry as a record at memory speed; a way to bring the previous boot's entries back | a device sink inside logd; the `previous` origin |
| Serial transmit (#1497, built) | nothing from logd's interface; for the serial sink, a write answered once its bytes have left the UART (§ Device sinks), while a plain write is answered once its bytes are in the transmit ring | the serial driver's `SERIAL_WRITE_SENT` flag (label bit 32) on `SERIAL_WRITE_BYTES`, which logd's serial sink ends each line with as a zero-length barrier (#1703, built), so `LOG_FLUSH` waits for serial's cursor alone |

---

## Summarized By

[services/logd/README.md](../README.md), [logd IPC interface](ipc-interface.md)
