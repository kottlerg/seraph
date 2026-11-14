# vfsd

Virtual filesystem daemon. vfsd is a namespace server with no on-disk
storage: it composes a synthetic system root from per-mount badged
SEND caps on filesystem drivers, mints the root cap that every
process receives in `ProcessInfo.system_root_cap`, and stays out of
the I/O path after the walk. vfsd self-mounts the Seraph root partition
(and the ESP) at startup; init issues no `MOUNT`. See
[`docs/namespace-composition.md`](docs/namespace-composition.md) and
[`docs/storage.md`](../../docs/storage.md).

---

## Source Layout

```
vfsd/
├── Cargo.toml
├── README.md
├── gpt/                     # `vfsd-gpt` crate: pure host-tested GPT-format parser
├── root-backend/            # `vfsd-root-backend` crate: VfsdRootBackend (NamespaceBackend impl)
├── swap/                    # `vfsd-swap` crate: pure host-tested swap-partition hand-out
├── src/
│   ├── main.rs              # Entry, root self-mount, service + namespace loops, MOUNT and
│   │                        # GET_SWAP_PARTITION handlers
│   ├── driver.rs            # Spawning fatfs driver instances
│   ├── partition.rs         # Disk and partition discovery: block I/O over the gpt crate
│   ├── role_guids.rs        # Compile-time arch-conditional root, ESP, data and swap GUIDs
│   ├── worker.rs            # Worker thread implementation
│   └── worker_pool.rs       # Bootstrap-endpoint pool for spawned drivers
└── docs/
    ├── namespace-composition.md   # Synthetic root, root-mount delegation
    └── vfs-ipc-interface.md       # Service-endpoint labels and their wire shapes
```

---

## Responsibilities

- **Namespace composition** — owns `VfsdRootBackend`, the in-process
  `NamespaceBackend` that surfaces installed mounts as cross-server
  entries on the synthetic system root, and forwards unmatched
  lookups to the root mount via transparent delegation. See
  [`docs/namespace-composition.md`](docs/namespace-composition.md).
- **Root self-mount** — at startup, after parsing every disk's GPT,
  vfsd mounts the Seraph root partition at `/`, the ESP at `/esp`, and
  the data partition at `/data` on its own initiative, before any
  service thread begins serving. The namespace dispatcher is spawned
  first because the `/esp` and `/data` mounts re-enter vfsd's namespace
  endpoint to resolve `/services/fs/fatfs`; service threads are spawned
  only after the mounts, so `GET_SYSTEM_ROOT_CAP` is never served
  against an unmounted root. The `/esp` and `/data` mounts are
  best-effort: an absent partition is skipped (non-fatal) and the mount
  point falls through to the root partition. See
  [`docs/namespace-composition.md`](docs/namespace-composition.md#two-endpoints-one-process)
  and [`docs/storage.md`](../../docs/storage.md).
- **Service endpoint** — handles `MOUNT`, `GET_SYSTEM_ROOT_CAP` and
  `GET_SWAP_PARTITION` on its un-badged service endpoint, with
  multi-threaded recv so independent requests proceed while one waits on
  a driver spawn; no service-endpoint request waits on another's IPC (a
  `GET_SWAP_PARTITION` waits at most for the swap lock, held across one
  call to the block driver, which never calls vfsd), so the thread count
  is a concurrency knob, not a correctness bound. `MOUNT` is the runtime explicit-mount surface
  (foreign-GUID disks, user-invoked mounts), gated on the
  `MOUNT_AUTHORITY` badge bit; root, `/esp`, and `/data` are
  self-mounted, and svctest is its only in-tree caller. See
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md) and
  [`docs/namespace-composition.md`](docs/namespace-composition.md).
- **Swap-partition hand-out** — `GET_SWAP_PARTITION`, gated on the
  `SWAP_AUTHORITY` badge bit, hands the swap service a raw partition cap
  on the `SERAPH_SWAP` partition, which vfsd never mounts. The first
  request looks the partition up and registers it, so vfsd's startup does
  not depend on one; each later request revokes the cap handed out before,
  so one holder at a time reaches the partition. The hand-out's decisions
  are the host-tested `vfsd-swap` crate. See
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md) and
  [`docs/storage.md`](../../docs/storage.md).
- **System-root cap delivery** — vfsd does not push a system-root
  cap anywhere at boot. Init pulls one via
  `vfsd_labels::GET_SYSTEM_ROOT_CAP`; service threads start only after
  the root self-mount, so the pull blocks until root is up; if the root
  mount failed, vfsd replies `NO_MOUNT` and init aborts. Init then
  distributes per-child copies via
  `procmgr_labels::CONFIGURE_NAMESPACE` on every spawn. Procmgr
  itself holds no namespace cap — children spawned without an
  explicit `CONFIGURE_NAMESPACE` cap see
  `ProcessInfo.system_root_cap == 0`. See
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md) and
  [`docs/storage.md`](../../docs/storage.md).
- **Filesystem driver lifecycle** — vfsd is the dispatcher for fs
  driver processes. The root self-mount spawns fatfs from a boot
  module cap; subsequent mounts walk vfsd's own held system-root cap
  to `/services/fs/fatfs` and pass the resulting file cap to procmgr
  via `CREATE_FROM_FILE`. The boot-module path is permanent and
  structural — `/services/fs/fatfs` is unreachable until root mounts,
  so spawning the fatfs that brings the root online cannot be moved
  elsewhere. vfsd supplies each driver with a partition-scoped block
  device endpoint, derived from the partition cap vfsd keeps, and the
  receive side of its own service endpoint (see
  [`services/fs/docs/fs-driver-protocol.md`](../fs/docs/fs-driver-protocol.md#bootstrap-caps)).
  Each mount keeps a record of its driver: the service endpoint, the
  process handle, a death queue the driver's exit or fault posts to,
  and the partition cap (see
  [`docs/namespace-composition.md`](docs/namespace-composition.md#mount-record)).
  On both paths a vfsd logging at any level but info creates the
  driver with its own level as the driver's `SERAPH_LOG` env entry, so
  a driver logs at vfsd's level
  ([init bootstrap](../init/docs/bootstrap.md) § Log levels).
  See [`docs/namespace-composition.md`](docs/namespace-composition.md)
  and [`docs/storage.md`](../../docs/storage.md).
- **GPT enumeration + mount discovery** — at startup, queries devmgr
  for every block device (`QUERY_DEVICE` on the `block` class SEND at instance ordinals 0,
  1, …, passing a `WITHDRAWN` one, until another reply is not
  `SUCCESS`) and parses each disk's GPT partition table through one
  scratch memory cap reused across the reads (replaced from memmgr
  before the next disk when a failed read left it lost), keeping every
  used entry of each header's `num_parts`-entry array (a disk whose GPT
  cannot be read or validated contributes none). It then resolves the
  arch-conditional root GUID in `src/role_guids.rs` via
  `gpt::lookup_partition_by_type_guid` over the partitions of every disk
  for the self-mount; the DPS priority tie-break runs across disks, and
  a tie at the highest priority is ambiguous whether or not the tied
  partitions share a disk. The EFI System Partition (standard type
  GUID) and the Seraph data partition (arch-neutral `SERAPH_DATA` GUID)
  auto-mount at `/esp` and `/data` immediately after root; there is no
  `mounts.conf` and no `INGEST_CONFIG_MOUNTS` IPC. The runtime `MOUNT`
  handler decodes a `MountRole` byte from the wire payload and reuses
  the same resolution path. See
  [`docs/namespace-composition.md`](docs/namespace-composition.md),
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md), and
  [`docs/storage.md`](../../docs/storage.md).

vfsd does not touch hardware directly. All storage I/O is mediated
through partition-scoped block device IPC endpoints derived from the
whole-disk endpoint of the virtio-blk instance that holds the
partition. See
[`docs/storage.md`](../../docs/storage.md).

---

## After the walk

Once a client holds a node cap returned by `NS_LOOKUP` through the
synthetic root or via transparent root delegation, every subsequent
operation (`NS_LOOKUP` on subdirectories, `FS_OPEN`, `FS_READ` / `FS_READ_MEMORY`,
`FS_CLOSE`) goes directly to the owning filesystem driver. vfsd is
not on the request path. See
[`docs/storage.md`](../../docs/storage.md).

---

## Relationship to devmgr

devmgr discovers storage hardware, spawns block device drivers, and
publishes their endpoints in the device registry. vfsd queries the
registry at startup, once per instance ordinal, to obtain the
`MOUNT_AUTHORITY`-badged whole-disk cap on every virtio-blk instance.
For each mount, and for the swap partition on the first
`GET_SWAP_PARTITION`, vfsd sends `REGISTER_PARTITION` on the cap of the disk
that holds the partition, and that virtio-blk instance mints and returns
a partition-badged cap. See
[`docs/device-management.md`](../../docs/device-management.md) and
[`docs/storage.md`](../../docs/storage.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/namespace-model.md](../../docs/namespace-model.md) | Cap-as-namespace principles, sandboxing |
| [docs/capability-model.md](../../docs/capability-model.md) | Badge semantics, derivation, revocation |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/device-management.md](../../docs/device-management.md) | Device registry, block device endpoints |
| [docs/storage.md](../../docs/storage.md) | Storage-stack composition, GPT role-GUID discovery, mount lifecycle |
| [docs/architecture.md](../../docs/architecture.md) | vfsd role in the boot lifecycle |
| [shared/namespace-protocol/README.md](../../shared/namespace-protocol/README.md) | NS_* wire surface |
| [services/fs/docs/fs-driver-protocol.md](../fs/docs/fs-driver-protocol.md) | Filesystem-driver protocol (FS_MOUNT, FS_READ, FS_READ_MEMORY, …) |

---

## Summarized By

None
