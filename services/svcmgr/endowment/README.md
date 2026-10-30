# svcmgr-endowment

Pure, host-tested wire codec for init's handover endowment of svcmgr.

The crate is the single definition of the endowment's round kinds (`CAPS`, `SUBSTRATE`,
`LOGD_SOURCES`) and of the encoding of the rounds that carry optional source caps. The kernel
refuses a message carrying a null cap slot, so these rounds list only the caps present and name the
slot each fills with a presence word. The `CAPS` slot list spans as many `CAPS` rounds as it needs,
each a window of `shared/ipc`'s slot-round codec with a rounds-left count, as
[`docs/ipc-interface.md`](../docs/ipc-interface.md#handover-endowment-bootstrap-rounds) specifies.
init (`services/init/src/service.rs`, `endow_svcmgr`) drives the encoders and svcmgr
(`services/svcmgr/src/service.rs`, `bootstrap_caps`) drives the decoders. The crate issues no
syscall and no IPC, so both ends keep the IPC calls and the codec stays host-reachable, per
[coding-standards.md § D](../../../docs/coding-standards.md#d-testing-invariants).

`no_std`; depends on `shared/ipc` (`SVCMGR_LABELS_VERSION` and the `bootstrap` slot-round
codec) and `abi/syscall` (`MSG_CAP_SLOTS_MAX`).

---

## Source Layout

```
services/svcmgr/endowment/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # Round kinds, presence bits, encoders and
                                # decoders of the CAPS and LOGD_SOURCES rounds
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [services/svcmgr/docs/ipc-interface.md](../docs/ipc-interface.md) | The endowment wire format this crate defines |
| [services/svcmgr/README.md](../README.md) | svcmgr, the receiving end |
| [services/init/README.md](../../init/README.md) | init, the sending end |

---

## Summarized By

[services/init/README.md](../../init/README.md), [services/svcmgr/README.md](../README.md)
