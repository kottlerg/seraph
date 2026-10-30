# shared/ipc

Shared IPC helpers for Seraph userspace: the stack-owned `IpcMessage` snapshot type, the
`ipc_call` / `ipc_recv` / `ipc_reply` wrappers that keep the kernel's per-thread IPC buffer as
scratch at the syscall boundary, the generic bootstrap protocol, the `RecvGuard`
receive-failure policy for blocking receive loops, the per-service IPC label and
error-code modules, the shared policy tables (`sched_policy`, `published_names`, `log_badges`),
the `keysym` codes and event packing, the `memmgr_bootstrap`, `device_info_kind`, and
`procmgr_process_state` constants, the crate-level limits and masks (`VERB_BIT_MASK`,
`MAX_PATH_LEN`, `ARGS_BLOB_MAX`), and reply-shape decoders (today `memmgr_grant_layout`).

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/ipc/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                  # IpcMessage, call/recv/reply wrappers, labels, errors, decoders
    ├── bootstrap.rs            # Creator-to-child bootstrap rounds; multi-round slot codec
    └── recv_guard.rs           # RecvGuard backoff and EXIT_RECV_WEDGE policy
```

---

## Wire Stability

The per-service label modules (`procmgr_labels`, `vfsd_labels`, `ns_labels`, `fs_labels`, and
the rest) define inter-process wire formats. Each module has a `*_LABELS_VERSION` constant that
is bumped, per the version rule in docs/conventions.md §
[ABI / wire-protocol versions](../../docs/conventions.md#abi--wire-protocol-versions), on any
breaking change: a label added, removed, or repurposed, or a payload shape changed. The
constants fall into four categories. Handshake-checked namespaces carry the version in their
first-contact handshake, and the receiver rejects a mismatch; `devmgr_labels` instead carries it
in `data[0]` of every request, which devmgr checks each time. Only `ns_labels` is implicitly
covered: its caps descend from the `vfsd_labels::GET_SYSTEM_ROOT_CAP` and `fs_labels::FS_MOUNT`
handshakes, so the parent channel stands in for the version check. The remaining constants are
markers that exist for the bump discipline. `STREAM_LABELS_VERSION` and `LOG_LABELS_VERSION` are
in practice marker-only: no caller issues the `log_labels::GET_LOG_CAP` handshake. Every process
that holds a stream cap has it pre-installed instead, in `ProcessInfo.log_send_cap` or, for
init, derived by init itself. The block comment above the label modules in `src/lib.rs` lists
which namespace falls in which category.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | Message format, call/reply model, receive-failure policy |
| [docs/process-lifecycle.md](../../docs/process-lifecycle.md) | Creator-to-child bootstrap and `ProcessInfo` handover |
| [docs/conventions.md](../../docs/conventions.md) | Version-constant rule for wire protocols (§ ABI / wire-protocol versions) |
| [shared/namespace-protocol/README.md](../namespace-protocol/README.md) | `NS_*` wire format carried under `ns_labels` |

---

## Summarized By

None
