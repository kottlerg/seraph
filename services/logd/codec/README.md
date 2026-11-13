# logd-codec

Pure, host-tested handover-protocol and formatting logic shared by init-logd and real-logd.

The crate is the single definition of the init-logd → real-logd handover wire contract that
[`docs/handover-protocol.md`](../docs/handover-protocol.md) specifies: the reply, chunk-kind, and
release-status codes, `MAX_RELEASE_DEFERRALS`, and `RELEASE_RETRY_BUDGET_US`; the sender's chunk
encoders, its captured-history byte ring (`HistoryRing`, which packs entries, text lines and log
records, by length and reads them back by absolute push sequence), and record of names to send
again (`NameResend`), which init-logd
(`services/init/src/logging.rs`) drives; and the receiver's chunk decoder and time-bounded release
retry (`retry_within`), which real-logd (`services/logd/src/handover.rs`) drives. It holds
real-logd's death-queue resync decisions (`is_resync_candidate`, `decode_live_page`, `evictable`,
and the `WalkGate` that runs one walk at a time; see
[`docs/ipc-interface.md`](../docs/ipc-interface.md) § Death-queue resync), and the line real-logd
logs when it evicts a slot (`ReclaimLine`, built as a log record; see the same document
§ Death-notification cascade, where the line is a test contract), and which entries a page of
real-logd's `QUERY_SLOTS` and `QUERY_HISTORY` replies carries (`query::slot_page`,
`query::history_page`; see the same document § Queries). It also holds the level tag both
log receivers render after a line's `[name]` prefix (`level::tag`; see the same document § Levels),
how both render a log record and the parser that reads its fields back from the rendered text
(`record::render`, `record::fields`, `RENDERED_MAX_BYTES`; see the same document
§ `stream_labels::STREAM_RECORD`), the line and name widths both log
receivers keep per sender (`LINE_BUF_SIZE`, `MAX_NAME_LEN`), `BoundedStr`, the
fixed-capacity, UTF-8-safe formatter logd uses for its own diagnostics, and `HeldLines`, the
bounded hold on those diagnostics until init-logd acknowledges the handover release (see
[`docs/handover-protocol.md`](../docs/handover-protocol.md) § Startup ordering). It issues no
syscall and no IPC, so both ends keep the IPC calls and the logic stays host-reachable, per
[coding-standards.md § D](../../../docs/coding-standards.md#d-testing-invariants).

`no_std`; depends on `shared/ipc` (`IpcMessage`, `log_record`, `log_query`) and `abi/syscall`
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
    ├── handover.rs             # Handover wire contract: codes, encoders,
    │                           # decoder, NameResend, release retry
    ├── history.rs              # HistoryRing: init-logd's captured history
    ├── hold.rs                 # HeldLines: logd's self-log lines held
    │                           # until the handover release
    ├── level.rs                # The level tag a rendered line carries
    ├── query.rs                # Query pages: which slots and history
    │                           # entries a reply carries
    ├── reclaim.rs              # ReclaimLine: the slot-eviction log line
    ├── record.rs               # Log record rendering and the rendered-field
    │                           # parser
    ├── resync.rs               # Death-queue resync: candidates, live-page
    │                           # decoder, eviction set, WalkGate
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
