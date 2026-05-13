# vfsd

Virtual filesystem daemon. vfsd is a namespace server with no on-disk
storage: it composes a synthetic system root from per-mount tokened
SEND caps on filesystem drivers, mints the root cap that every
process receives in `ProcessInfo.system_root_cap`, and stays out of
the I/O path after the walk.

---

## Source Layout

```
vfsd/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs              # Entry, service + namespace loops, MOUNT handler
│   ├── driver.rs            # Spawning fatfs driver instances
│   ├── gpt.rs               # GPT partition table parsing
│   ├── mount_conf.rs        # INGEST_CONFIG_MOUNTS reader
│   ├── root_backend.rs      # VfsdRootBackend (NamespaceBackend impl)
│   ├── worker.rs            # Worker thread implementation
│   └── worker_pool.rs       # Bootstrap-endpoint pool for spawned drivers
└── docs/
    ├── namespace-composition.md   # Synthetic root, root-mount delegation
    └── vfs-ipc-interface.md       # MOUNT / INGEST_CONFIG_MOUNTS
```

---

## Responsibilities

- **Namespace composition** — owns `VfsdRootBackend`, the in-process
  [`NamespaceBackend`] that surfaces installed mounts as cross-server
  entries on the synthetic system root, and forwards unmatched
  lookups to the root mount via transparent delegation. See
  [`docs/namespace-composition.md`](docs/namespace-composition.md).
- **Service endpoint** — handles `MOUNT`, `INGEST_CONFIG_MOUNTS`, and
  `GET_SYSTEM_ROOT_CAP` on its un-tokened service endpoint, with
  multi-threaded recv so a worker-driven `CREATE_FROM_FILE` re-entry
  cannot deadlock an in-flight reply. See
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md).
- **System-root cap delivery** — vfsd does not push a system-root
  cap anywhere at boot. Init pulls one via
  `vfsd_labels::GET_SYSTEM_ROOT_CAP` after the cmdline-driven root
  mount completes; init then distributes per-child copies via
  `procmgr_labels::CONFIGURE_NAMESPACE` on every spawn. Procmgr
  itself holds no namespace cap — children spawned without an
  explicit `CONFIGURE_NAMESPACE` cap see
  `ProcessInfo.system_root_cap == 0`.
- **Filesystem driver lifecycle** — vfsd is the dispatcher for fs
  driver processes. The first `MOUNT` (the cmdline-driven root)
  spawns fatfs from a boot module cap; subsequent mounts walk
  vfsd's own held system-root cap to `/bin/fatfs` and pass the
  resulting file cap to procmgr via `CREATE_FROM_FILE`. The
  first-mount path is permanent and structural — `/bin/fatfs` is
  unreachable until root mounts, so spawning the fatfs that brings
  the root online cannot be moved elsewhere. vfsd supplies each
  driver with a partition-scoped block device endpoint and the
  receive side of its own service endpoint.
- **GPT enumeration** — parses the GPT partition table from a single
  scratch frame at startup and retains `(uuid → (lba, length))`
  entries for `MOUNT` lookups.

vfsd does not touch hardware directly. All storage I/O is mediated
through partition-scoped block device IPC endpoints derived from
virtio-blk's whole-disk endpoint.

---

## After the walk

Once a client holds a node cap returned by `NS_LOOKUP` through the
synthetic root or via transparent root delegation, every subsequent
operation (`NS_LOOKUP` on subdirectories, `NS_READ` / `NS_READ_FRAME`,
`FS_CLOSE`) goes directly to the owning filesystem driver. vfsd is
not on the request path.

---

## Relationship to devmgr

devmgr discovers storage hardware, spawns block device drivers, and
publishes their endpoints in the device registry. vfsd queries the
registry at startup to obtain the whole-disk virtio-blk endpoint;
per-mount partition tokens are derived from it. See
[`docs/device-management.md`](../../docs/device-management.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/namespace-model.md](../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing |
| [docs/capability-model.md](../../docs/capability-model.md) | Token semantics, derivation, revocation |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/device-management.md](../../docs/device-management.md) | Device registry, block device endpoints |
| [docs/architecture.md](../../docs/architecture.md) | vfsd role in the boot lifecycle |
| [shared/namespace-protocol/README.md](../../shared/namespace-protocol/README.md) | NS_* wire surface |
| [services/fs/docs/fs-driver-protocol.md](../fs/docs/fs-driver-protocol.md) | Filesystem-driver protocol (FS_MOUNT, FS_READ, FS_READ_FRAME, …) |

---

## Summarized By

None
