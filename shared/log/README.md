# shared/log

System log primitives for Seraph userspace. Two halves: no-allocation wire-format helpers
(`write_bytes`, `write_args`, `register_name`) over the labels in `ipc::stream_labels`, with the
caller supplying its badged SEND cap and IPC buffer; and a process-global cache
(`install_badged_cap`, `ensure_badged_cap`) for the pre-installed badged log cap. Std's `_start`
installs the cap procmgr seeds in `ProcessInfo.log_send_cap`; init installs its own badge-1
cap. `no_std` code calls `emit` directly; the user-facing macro lives in the std overlay.

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/log/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # Wire helpers, badged-cap cache, emit
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../docs/console-model.md) | Console and log output ownership across boot |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | `ProcessInfo` handover that seeds the log cap |
| [services/logd/README.md](../../services/logd/README.md) | Log daemon that receives this crate's stream |

---

## Summarized By

None
