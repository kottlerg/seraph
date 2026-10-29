# logd-codec

Pure, host-tested handover-protocol and formatting logic shared by init-logd and real-logd.

The crate is the single definition of the init-logd → real-logd handover wire contract that
[`docs/handover-protocol.md`](../docs/handover-protocol.md) specifies: the reply, chunk-kind, and
release-status codes and `MAX_RELEASE_DEFERRALS`; the sender's chunk encoders, history-ring
sequencing (`next_history_seq`), and record of names to send again (`NameResend`), which
init-logd (`services/init/src/logging.rs`) drives; and the receiver's chunk decoder, which
real-logd (`services/logd/src/handover.rs`) drives. It also holds `BoundedStr`, the
fixed-capacity, UTF-8-safe formatter logd uses for its own diagnostics. It issues no syscall and
no IPC, so both ends keep the IPC calls and the logic stays host-reachable, per
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
    │                           # decoder, history sequencing, NameResend
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
