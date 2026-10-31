# logd-codec

Pure, host-tested handover-protocol and formatting logic shared by init-logd and real-logd.

The crate is the single definition of the init-logd → real-logd handover wire contract that
[`docs/handover-protocol.md`](../docs/handover-protocol.md) specifies: the reply, chunk-kind, and
release-status codes, `MAX_RELEASE_DEFERRALS`, and `RELEASE_RETRY_BUDGET_US`; the sender's chunk
encoders, its captured-history byte ring (`HistoryRing`, which packs lines by length and reads
them back by absolute push sequence), and record of names to send again (`NameResend`), which
init-logd (`services/init/src/logging.rs`) drives; and the receiver's chunk decoder and
time-bounded release retry (`retry_within`), which real-logd (`services/logd/src/handover.rs`)
drives. It holds real-logd's death-queue resync decisions (`is_resync_candidate`,
`decode_live_page`, `evictable`; see [`docs/ipc-interface.md`](../docs/ipc-interface.md)
§ Death-queue resync). It also holds the line and name widths both log receivers keep per sender
(`LINE_BUF_SIZE`, `MAX_NAME_LEN`), and `BoundedStr`, the fixed-capacity, UTF-8-safe formatter
logd uses for its own diagnostics. It issues no syscall and no IPC, so both ends keep the IPC
calls and the logic stays host-reachable, per
[coding-standards.md § D](../../../docs/coding-standards.md#d-testing-invariants).

`no_std`; depends on `shared/ipc` (`IpcMessage`) and `abi/syscall` (`MSG_DATA_WORDS_MAX`).

---

## Source Layout

```
services/logd/codec/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                  # Crate root
    ├── handover.rs             # Handover wire contract: codes, encoders,
    │                           # decoder, NameResend, release retry
    ├── history.rs              # HistoryRing: init-logd's captured history
    ├── resync.rs               # Death-queue resync: candidates, live-page
    │                           # decoder, eviction set
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
