# shared/ipc

Shared IPC helpers for Seraph userspace: the stack-owned `IpcMessage` snapshot type, the
`ipc_call` / `ipc_recv` / `ipc_reply` wrappers that keep the kernel's per-thread IPC buffer as
scratch at the syscall boundary, the generic bootstrap protocol, the `RecvGuard`
receive-failure policy for blocking receive loops, and the per-service IPC label and
error-code modules.

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/ipc/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                  # IpcMessage, call/recv/reply wrappers, label and error modules
    ├── bootstrap.rs            # Creator-to-child bootstrap rounds (request/reply/error)
    └── recv_guard.rs           # RecvGuard backoff and EXIT_RECV_WEDGE policy
```

---

## Wire Stability

The per-service label modules (`procmgr_labels`, `vfsd_labels`, `ns_labels`, `fs_labels`, and
the rest) define inter-process wire formats. Each module has a `*_LABELS_VERSION` constant that
is bumped, per the version rule in docs/conventions.md §
[ABI / wire-protocol versions](../../docs/conventions.md#abi--wire-protocol-versions), on any
breaking change: a label added, removed, or repurposed, or a payload shape changed. The
constants fall into three categories. Handshake-checked namespaces carry the version in their
first-contact handshake, and the receiver rejects a mismatch. Implicitly covered namespaces
(`ns_labels`, `stream_labels`) run over a channel opened against a cap badge minted by a
handshake-checked namespace, so the badge stands in for the version check. The remaining
constants are markers that exist for the bump discipline. The block comment above the label
modules in `src/lib.rs` lists which namespace falls in which category.

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
