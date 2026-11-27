# shared/ipc

Shared IPC helpers for Seraph userspace: the stack-owned `IpcMessage` snapshot type, the `ipc_call`
/ `ipc_recv` / `ipc_reply` / `ipc_reply_recv` wrappers, with the bounded and try-once forms
`ipc_call_timeout`, `ipc_recv_timeout`, and `ipc_try_recv`, and `ipc_call_within`, a call bounded by
the time left to a deadline (`call_timeout`; `WouldBlock` without a call once none is left;
[runtime/ruststd/README.md](../../runtime/ruststd/README.md) § Call deadline), that keep the
kernel's per-thread IPC buffer as scratch at the syscall boundary, the generic bootstrap protocol,
the `RecvGuard` receive-failure policy for blocking receive loops, the `serve` reply slot that
sends a server's reply with its next receive (§ Serving), the per-service IPC label and
error-code modules, the shared policy tables (`sched_policy`, `published_names`, `log_badges`), the
`keysym` codes and event packing, the `memmgr_bootstrap`, `device_info_kind`, and
`procmgr_process_state` constants, the `vfsd_bootstrap` layout of init's round 1 to vfsd, the create
requests' argv/env header codec (`procmgr_labels::ArgvEnvHeader`), the crate-level limits and masks
(`VERB_BIT_MASK`, `MAX_PATH_LEN`), the svcmgr name limit and codec (`svcmgr_labels::NAME_MAX`,
`pack_name`, `unpack_name`), reply-shape decoders (today `memmgr_grant_layout`), the driver-side
`DMA_MAP` and `DMA_UNMAP` calls (`dma_map`, `dma_unmap`), and the log record codec (`log_record`:
the `STREAM_RECORD` payload's encoder `RecordWriter`, decoder `Record`, limits, and key alphabet;
[logd IPC interface](../../services/logd/docs/ipc-interface.md) § `stream_labels::STREAM_RECORD`).

`no_std`; builds inside std's dependency graph through the `rustc-dep-of-std` feature.

---

## Source Layout

```
shared/ipc/
├── Cargo.toml
├── README.md
└── src/
    ├── lib.rs                  # IpcMessage, call/recv/reply wrappers, version constants, modules
    ├── bootstrap.rs            # Creator-to-child bootstrap rounds; multi-round slot codec
    ├── log_query.rs            # Wire format of logd's QUERY_SLOTS and QUERY_HISTORY labels
    ├── log_record.rs           # Log record codec: RecordWriter, Record, key alphabet
    ├── recv_guard.rs           # RecvGuard backoff and EXIT_RECV_WEDGE policy
    ├── serve.rs                # Reply slot and next_request: a reply sent with the next receive
    ├── <protocol>_labels.rs    # One file per label module (procmgr_labels.rs, ...)
    ├── <protocol>_errors.rs    # One file per error-code module (procmgr_errors.rs, ...)
    ├── sched_policy.rs ...     # One file per table module: sched_policy, published_names,
    │                           #   log_badges, keysym, memmgr_bootstrap, device_info_kind,
    │                           #   procmgr_process_state
    ├── memmgr_capture.rs       # CAPTURE_CHUNKS wire format: Descriptor, Region, Chunk
    ├── vfsd_bootstrap.rs       # Data-word layout of init's round 1 to vfsd: the boot device record
    ├── procmgr_snapshot.rs     # Layout of the memory object procmgr's SNAPSHOT and
    │                           #   CHECKPOINT reply with
    ├── devmgr_client.rs        # report_driver_ready, query_device, watch_class,
    │                           #   refresh_device, ...
    ├── devmgr_dma_client.rs    # dma_map, dma_unmap, dma_faults
    └── memmgr_grant.rs         # memmgr_grant_layout reply decoder
```

A label, error or table module is declared in `lib.rs` as `pub mod <name>;` and lives in
`src/<name>.rs`; the three client files are private modules whose items `lib.rs` re-exports at
the crate root. A change to one protocol's labels edits its own file (and, for a version bump, its
constant in `lib.rs`).

---

## Serving

A server loop holds one `serve::Reply` per receiving thread and receives with
`serve::next_request(ep, &mut reply, ipc_buf)`. A handler whose turn ends with its reply leaves it
with `Reply::set`, and the next `next_request` sends it with the receive in one `SYS_IPC_REPLY_RECV`
([IPC Design](../../docs/ipc-design.md) § The Call/Reply Model); with the slot empty, `next_request`
is `ipc_recv`. `serve::next_request_timeout` takes the receive's bound in milliseconds as well, for
a loop whose receive waits a bounded time, and reads the request into the loop's own `IpcMessage`
in place (`IpcMessage::read_delivery`), so the loop copies no whole message; `next_request`
waits without a bound and returns the request. A handler with work
after its reply (an IPC call, a syscall) replies at once with `ipc_reply` and leaves the slot empty,
and a loop with work before its next receive sends a set reply first with
`Reply::flush(ep, ipc_buf)`, so no reply waits behind work. `flush` sends it with a receive that
does not wait (`SYS_IPC_REPLY_RECV` at `WAIT_TRY_ONCE`), not alone: a server that outranks its
caller and last received through `SYS_IPC_REPLY_RECV` may run on the caller's CPU, where a plain
reply leaves the caller's wake queued behind it until it parks, while the wake of a reply whose
receive does not park goes to another CPU ([scheduler.md](../../core/kernel/docs/scheduler.md)
§ Thread Assignment). A call that receive binds is held in the `Reply`, and the next
`next_request` or `next_request_timeout` returns it with no syscall, so it is served once the
loop's work is done, as it would have been from the endpoint's queue. A loop that uses the reply's
outcome reads `Reply::undelivered` after the send that carried it, `flush` or the next receive:
it is true when the reply did not reach its caller (the caller is gone, or its `CSpace` could not
take the reply's caps), until the next send, so the loop can undo what the reply reported.

`next_request` returns the receive's errors, those of `ipc_recv`, for the loop's `RecvGuard`
([IPC Design](../../docs/ipc-design.md) § Receive-Failure Policy). The kernel reports the receive's
capability and headroom refusals before the reply, the reply's errors without receiving, and the
wait's after the reply, and the first two share codes, so on one of those `next_request` sends the
reply again alone: a refused receive keeps its caller bound, and that send makes the reply, while a
failed reply consumed the binding, that send fails with nothing to answer, and the receive is made
alone. No reply is lost or sent twice, and a reply's failure is never returned as a receive
failure. The state machine is host-tested over a stand-in for the three syscalls.

---

## Wire Stability

The per-service label modules (`procmgr_labels`, `vfsd_labels`, `ns_labels`, `fs_labels`, and the
rest) define inter-process wire formats. Each module has a `*_LABELS_VERSION` constant that is
bumped, per the version rule in docs/conventions.md § [ABI / wire-protocol
versions](../../docs/conventions.md#abi--wire-protocol-versions), on any breaking change: a label
added, removed, or repurposed, or a payload shape changed. The constants fall into four categories.
Handshake-checked namespaces carry the version in their first-contact handshake, and the receiver
rejects a mismatch; `devmgr_labels` and `devmgr_dma_labels` instead carry it in `data[0]` of every
request, which devmgr checks each time, and `iommu_labels` does the same, checked by the IOMMU
driver, as does `log_labels` for its three labels `QUERY_SLOTS`, `QUERY_HISTORY` and `LOG_FLUSH`,
checked by logd, and `acpid_labels`, checked by acpid. Only `ns_labels` is implicitly covered: its
caps descend from the `vfsd_labels::GET_SYSTEM_ROOT_CAP` and `fs_labels::FS_MOUNT` handshakes, so
the parent channel stands in for the version check. The remaining constants are markers that exist
for the bump discipline. `STREAM_LABELS_VERSION` is in practice marker-only: every process that
holds a stream cap has it pre-installed, in `ProcessInfo.log_send_cap` or, for init, derived by init
itself, and no caller issues the `log_labels::GET_LOG_CAP` handshake. The block comment above the
label modules in `src/lib.rs` lists which namespace falls in which category.

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
