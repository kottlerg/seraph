# shared/log

System log primitives for Seraph userspace. Two halves: no-allocation wire-format helpers
(`write_bytes`, `write_args`, `register_name`) over the labels in `ipc::stream_labels`, with the
caller supplying its badged SEND cap and IPC buffer; and a process-global cache
(`install_badged_cap`, `ensure_badged_cap`) for the pre-installed badged log cap. The only
installer is std's `_start`, which installs the cap procmgr seeds in `ProcessInfo.log_send_cap`;
init does not use this crate and logs through its own path in `services/init/src/logging.rs`.
`emit` is the entry point the std overlay's `seraph::log!` macro reaches through
`std::os::seraph::log::__emit`; the crate's only consumer is std.

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
