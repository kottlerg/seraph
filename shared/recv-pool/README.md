# shared/recv-pool

Worker-pool receive helper for multi-threaded std services.

---

## Overview

A service that serves one endpoint from several threads builds a `RecvPool` from the endpoint's
RECV capability, a `RecvGuard` diagnostic hook, and a handler. `spawn` starts named worker threads
behind a start gate and returns once each has started running its code, `open` lets them receive,
and `serve_on_current` opens the gate and makes the calling thread one more worker. A worker whose
thread has no IPC buffer page tells the hook (`NO_IPC_BUFFER`) and exits its thread. Each worker
receives on its own IPC buffer page, under a `RecvGuard`
([IPC Design](../../docs/ipc-design.md) § Receive-Failure Policy), and calls the handler with the
received message and its `IpcBuf`.

`IpcBuf` is the calling thread's registered IPC buffer page, obtained only through
`IpcBuf::current()` and neither `Send` nor `Sync`, so a handler can reach no page but its own
thread's. The rules a server's threads follow, whether or not they use this crate, are
[IPC Design](../../docs/ipc-design.md) § Multi-threaded servers.

The gate exists because a spawned thread's start in the runtime can wait on procmgr
([runtime/ruststd/README.md](../../runtime/ruststd/README.md) § Thread registration). A service
procmgr may be waiting on spawns its workers while something else still serves its endpoint, and
opens the gate when it takes the endpoint over, as logd does
([logd IPC Interface](../../services/logd/docs/ipc-interface.md) § Receive pool).

The crate spawns `std` threads and reads each thread's page through `std::os::seraph`, so its
contents compile only for seraph and no host test reaches them; svctest's `recv_pool` phase
exercises it. It depends on `shared/ipc`, `shared/syscall` and `abi/syscall`.

---

## Source Layout

```
shared/recv-pool/
├── Cargo.toml
├── README.md
└── src/
    └── lib.rs                  # IpcBuf, RecvPool: workers, start gate, guarded receive loop
```

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | Multi-threaded servers, the call/reply binding, and the receive-failure policy |
| [services/logd/docs/ipc-interface.md](../../services/logd/docs/ipc-interface.md) | logd's receive pool |

---

## Summarized By

None
