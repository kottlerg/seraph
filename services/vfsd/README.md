# vfsd

Virtual filesystem daemon. vfsd is a namespace server with no on-disk
storage: it composes a synthetic system root from per-mount badged
SEND caps on filesystem drivers, mints the root cap that every
process receives in `ProcessInfo.system_root_cap`, and stays out of
the I/O path after the walk. vfsd self-mounts the Seraph root partition
(and the ESP) at startup; init issues no `MOUNT`.

---

## Source Layout

```
vfsd/
├── Cargo.toml
├── README.md
├── gpt/                     # `vfsd-gpt` crate: pure host-tested GPT-format parser
├── src/
│   ├── main.rs              # Entry, root self-mount, service + namespace loops, MOUNT handler
│   ├── driver.rs            # Spawning fatfs driver instances
│   ├── partition.rs         # Boot-disk partition discovery: block I/O over the gpt crate
│   ├── role_guids.rs        # Compile-time arch-conditional root + ESP GUIDs
│   ├── root_backend.rs      # VfsdRootBackend (NamespaceBackend impl)
│   ├── worker.rs            # Worker thread implementation
│   └── worker_pool.rs       # Bootstrap-endpoint pool for spawned drivers
└── docs/
    ├── namespace-composition.md   # Synthetic root, root-mount delegation
    └── vfs-ipc-interface.md       # MOUNT wire shape
```

---

## Responsibilities

- **Namespace composition** — owns `VfsdRootBackend`, the in-process
  [`NamespaceBackend`] that surfaces installed mounts as cross-server
  entries on the synthetic system root, and forwards unmatched
  lookups to the root mount via transparent delegation. See
  [`docs/namespace-composition.md`](docs/namespace-composition.md).
- **Root self-mount** — at startup, after parsing the GPT, vfsd mounts
  the Seraph root partition at `/`, the ESP at `/esp`, and the data
  partition at `/data` on its own initiative, before any service thread
  begins serving. The namespace dispatcher is spawned first because the
  `/esp` and `/data` mounts re-enter vfsd's namespace endpoint to
  resolve `/services/fs/fatfs`; service threads are spawned only after
  the mounts, so `GET_SYSTEM_ROOT_CAP` is never served against an
  unmounted root. The `/esp` and `/data` mounts are best-effort: an
  absent partition is skipped (non-fatal) and the mount point falls
  through to the root partition.
- **Service endpoint** — handles `MOUNT` and `GET_SYSTEM_ROOT_CAP` on
  its un-badged service endpoint, with multi-threaded recv so a
  worker-driven `CREATE_FROM_FILE` re-entry cannot deadlock an in-
  flight reply. `MOUNT` is the runtime explicit-mount surface
  (foreign-GUID disks, user-invoked mounts); no in-tree caller issues
  it, since root, `/esp`, and `/data` are self-mounted. See
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md).
- **System-root cap delivery** — vfsd does not push a system-root
  cap anywhere at boot. Init pulls one via
  `vfsd_labels::GET_SYSTEM_ROOT_CAP`; vfsd replies `NO_MOUNT` until
  root is mounted, so the pull blocks until the root filesystem is up.
  Init then distributes per-child copies via
  `procmgr_labels::CONFIGURE_NAMESPACE` on every spawn. Procmgr
  itself holds no namespace cap — children spawned without an
  explicit `CONFIGURE_NAMESPACE` cap see
  `ProcessInfo.system_root_cap == 0`.
- **Filesystem driver lifecycle** — vfsd is the dispatcher for fs
  driver processes. The root self-mount spawns fatfs from a boot
  module cap; subsequent mounts walk vfsd's own held system-root cap
  to `/services/fs/fatfs` and pass the resulting file cap to procmgr
  via `CREATE_FROM_FILE`. The boot-module path is permanent and
  structural — `/services/fs/fatfs` is unreachable until root mounts,
  so spawning the fatfs that brings the root online cannot be moved
  elsewhere. vfsd supplies each driver with a partition-scoped block
  device endpoint and the receive side of its own service endpoint.
- **GPT enumeration + mount discovery** — parses the GPT partition
  table from a single scratch memory cap at startup, then resolves the
  arch-conditional root GUID in `src/role_guids.rs` via
  `gpt::lookup_partition_by_type_guid` for the self-mount. The EFI
  System Partition (standard type GUID) and the Seraph data partition
  (arch-neutral `SERAPH_DATA` GUID) auto-mount at `/esp` and `/data`
  immediately after root; there is no `mounts.conf` and no
  `INGEST_CONFIG_MOUNTS` IPC. The runtime `MOUNT` handler decodes a
  `MountRole` byte from the wire payload and reuses the same
  resolution path. See
  [`docs/namespace-composition.md`](docs/namespace-composition.md).

vfsd does not touch hardware directly. All storage I/O is mediated
through partition-scoped block device IPC endpoints derived from
virtio-blk's whole-disk endpoint.

---

## After the walk

Once a client holds a node cap returned by `NS_LOOKUP` through the
synthetic root or via transparent root delegation, every subsequent
operation (`NS_LOOKUP` on subdirectories, `NS_READ` / `NS_READ_MEMORY`,
`FS_CLOSE`) goes directly to the owning filesystem driver. vfsd is
not on the request path.

---

## Relationship to devmgr

devmgr discovers storage hardware, spawns block device drivers, and
publishes their endpoints in the device registry. vfsd queries the
registry at startup to obtain the whole-disk virtio-blk endpoint;
per-mount partition badges are derived from it. See
[`docs/device-management.md`](../../docs/device-management.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/namespace-model.md](../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing |
| [docs/capability-model.md](../../docs/capability-model.md) | Badge semantics, derivation, revocation |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/device-management.md](../../docs/device-management.md) | Device registry, block device endpoints |
| [docs/architecture.md](../../docs/architecture.md) | vfsd role in the boot lifecycle |
| [shared/namespace-protocol/README.md](../../shared/namespace-protocol/README.md) | NS_* wire surface |
| [services/fs/docs/fs-driver-protocol.md](../fs/docs/fs-driver-protocol.md) | Filesystem-driver protocol (FS_MOUNT, FS_READ, FS_READ_MEMORY, …) |

---

## Summarized By

[docs/storage.md](../../docs/storage.md)
