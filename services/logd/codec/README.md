# logd-codec

Pure, host-tested handover-protocol and formatting logic shared by init-logd and real-logd.

The crate is the single definition of the init-logd → real-logd handover wire contract that
[`docs/handover-protocol.md`](../docs/handover-protocol.md) specifies: the reply, chunk-kind, and
release-status codes, `MAX_RELEASE_DEFERRALS`, `RELEASE_RETRY_BUDGET_US`, and
`HANDOVER_CALL_TIMEOUT_MS`; the sender's chunk encoders, its captured-history byte ring
(`HistoryRing`, which packs entries, text lines and log
records, by length and reads them back by absolute push sequence), and record of names to send
again (`NameResend`), which init-logd
(`services/init/src/logging.rs`) drives; and the receiver's chunk decoder, time-bounded release
retry (`retry_within`), release outcome (`release_outcome`) and pull-and-release rounds
(`run_rounds`), which real-logd (`services/logd/src/handover.rs`) drives. It holds
real-logd's death-queue resync decisions (`is_resync_candidate`, `decode_live_page`, `evictable`,
and the `WalkGate` that runs one walk at a time; see
[`docs/ipc-interface.md`](../docs/ipc-interface.md) § Death-queue resync), and the line real-logd
logs when it evicts a slot (`ReclaimLine`, built as a log record; see the same document
§ Death-notification cascade, where the line is a test contract), and which entries a page of
real-logd's `QUERY_SLOTS` and `QUERY_HISTORY` replies carries (`query::slot_page`,
`query::history_page`; see the same document § Queries). It also holds the level tag both
log receivers render between a line's stamp and its `[name]` prefix (`level::tag`; see the same
document § Levels), how both render a log record and the parser that reads its fields back from
the rendered text (`record::render`, `record::fields`, `RENDERED_MAX_BYTES`; see the same document
§ `stream_labels::STREAM_RECORD`), the line and name widths both log
receivers keep per sender (`LINE_BUF_SIZE`, `MAX_NAME_LEN`), `BoundedStr`, the
fixed-capacity, UTF-8-safe formatter logd uses for its own diagnostics. It holds the rules of
real-logd's output sinks that need no clock or lock of their own (`SINK_STALL_MS`, `write_overdue`,
`hint_ms`, `attach_cursor`, `drop_text`: when a sink's write is overdue, the retry hint of a refused
message, where a `skip` sink's cursor starts, and the text of a drop line; see
[`docs/ipc-interface.md`](../docs/ipc-interface.md) § Output sinks, § Hold window), a device sink's
settings and the parser of the recipe syntax that sets them (`settings::SinkSettings`,
`SinkKind::defaults`), and the two formats a sink renders an entry in, the console format with its
field list (`console::write`) and the rfc5424 format (`rfc5424::write`), and the RFC 3339 writer
of an entry's wall time and the text of logd's notice of the wall clock (`wall::write_rfc3339`,
`wall::WALL_MAX_US`, `wall::wall_clock_text`; see [`docs/sinks.md`](../docs/sinks.md) § Settings,
§ The console format, § The rfc5424 format, § Wall time). It
issues no syscall and no IPC, so both ends keep the IPC calls and the logic stays host-reachable,
per [coding-standards.md § D](../../../docs/coding-standards.md#d-testing-invariants).

`no_std`; depends on `shared/ipc` (`IpcMessage`, `log_record`, `log_query`), `shared/log`
(`parse_level`, the level keywords a sink's `level` takes) and `abi/syscall`
(`MSG_DATA_WORDS_MAX`).

---

## Source Layout

```
services/logd/codec/
├── Cargo.toml
├── clippy.toml                 # Clippy settings; frame threshold of init's 16 KiB stack
├── README.md
└── src/
    ├── lib.rs                  # Crate root
    ├── console.rs              # The console format: a line of the fields
    │                           # a sink's settings name
    ├── handover.rs             # Handover wire contract: codes, encoders,
    │                           # decoder, NameResend, release retry
    ├── history.rs              # HistoryRing: init-logd's captured history
    ├── kernel.rs               # Kernel log lines: the record cursor, the
    │                           # [kernel] line parts, the reserved name
    ├── level.rs                # The level tag a rendered line carries
    │                           # and its colour
    ├── prefix.rs               # The default console prefix and its
    │                           # fields' writers
    ├── query.rs                # Query pages: which slots and history
    │                           # entries a reply carries
    ├── reclaim.rs              # ReclaimLine: the slot-eviction log line
    ├── record.rs               # Log record rendering and the rendered-field
    │                           # parser
    ├── resync.rs               # Death-queue resync: candidates, live-page
    │                           # decoder, eviction set, WalkGate
    ├── rfc5424.rs              # The rfc5424 format and its UTF-8 escape
    ├── settings.rs             # A device sink's settings and their parser
    ├── sink.rs                 # Sink rules: stall bound, retry hint,
    │                           # attach cursor, drop-line text
    ├── wall.rs                 # RFC 3339 wall time and the wall clock
    │                           # notice's text
    └── bounded_str.rs          # BoundedStr: UTF-8-safe bounded formatter
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/logd/docs/handover-protocol.md](../docs/handover-protocol.md) | The handover wire format this crate defines |
| [services/logd/README.md](../README.md) | real-logd, the receiving end |
| [services/init/README.md](../../init/README.md) | init-logd, the sending end |

---

## Summarized By

[services/init/README.md](../../init/README.md), [services/logd/README.md](../README.md)
