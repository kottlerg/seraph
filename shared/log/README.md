# shared/log

System log primitives for Seraph userspace. Three parts: no-allocation wire-format helpers
(`write_bytes`, `write_args`, `write_record`, `register_name`) over the labels in
`ipc::stream_labels`, with the caller supplying its badged SEND cap, IPC buffer, and the line's
level, and `build_record`, which stages a log record (`ipc::log_record`); a process-global cache
(`install_badged_cap`, `ensure_badged_cap`) for the pre-installed badged log cap; and the
process-global level filter (`set_max_level`, `enabled`, `parse_level`, `LEVEL_ENV_KEY`). The only
installer of either is std's `_start`, which installs the cap procmgr seeds in
`ProcessInfo.log_send_cap` and the level the process's `SERAPH_LOG` environment entry names; init
does not use this crate and logs through its own path in `services/init/src/logging.rs`. `emit` is
the entry point the std overlay's `seraph::log!` macro reaches through
`std::os::seraph::log::__emit_at`, and drops a line more verbose than the filter's level;
`emit_record` is the entry point of its form with fields, through
`std::os::seraph::log::__emit_record`, and drops a record as `emit` drops a line. The levels, the
filter, and the wire encodings are specified in
[logd IPC interface](../../services/logd/docs/ipc-interface.md) § Levels and
§ `stream_labels::STREAM_RECORD`. Every log call is bounded (`LOG_CALL_TIMEOUT_MS`), and once one
times out the process's later calls take the short `LOG_CALL_UNANSWERED_TIMEOUT_MS` bound until
one is answered, so a log receiver that stops answering costs a sender one long wait and then a
short one per line ([docs/limits.md](../../docs/limits.md) § Shared IPC and protocol crates). The
crate's consumers are std and svctest, whose `log_client` phase drives the wire helpers against an
endpoint of its own that never answers.

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/log/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # Wire helpers, badged-cap cache, level filter, emit, emit_record
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/console-model.md](../../docs/console-model.md) | Console and log output ownership across boot |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | `ProcessInfo` handover that seeds the log cap |
| [services/logd/README.md](../../services/logd/README.md) | Log daemon that receives this crate's stream |
| [services/logd/docs/ipc-interface.md](../../services/logd/docs/ipc-interface.md) | The `STREAM_BYTES` and `STREAM_RECORD` wire formats, levels, and filter |

---

## Summarized By

None
