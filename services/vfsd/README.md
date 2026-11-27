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
├── gpt/                     # `vfsd-gpt` crate: pure host-tested GPT-format parser; its
│                            # property (src/property.rs), its proof harnesses (`proofs` in
│                            # src/lib.rs, docs/testing.md § Bounded verification) and fuzz
│                            # inputs (fuzz/gpt/), the fuzz target `gpt` (docs/testing.md
│                            # § Fuzzing)
├── grant/                   # `vfsd-grant` crate: pure host-tested cut-off of a partition grant
├── root-backend/            # `vfsd-root-backend` crate: VfsdRootBackend (NamespaceBackend impl)
├── swap/                    # `vfsd-swap` crate: pure host-tested swap-partition hand-out
├── src/
│   ├── main.rs              # Entry, root self-mount, service + namespace loops, MOUNT,
│   │                        # UNMOUNT and GET_SWAP_PARTITION handlers
│   ├── driver.rs            # Spawning fatfs driver instances
│   ├── partition.rs         # Disk and partition discovery: block I/O over the gpt crate
│   ├── restart.rs           # Restart of a dead fs driver on its own thread
│   ├── role_guids.rs        # Compile-time arch-conditional root, ESP, data and swap GUIDs
│   ├── watch.rs             # The watch thread: fs-driver deaths and disk removals
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
- **Service endpoint** — handles `MOUNT`, `UNMOUNT`, `GET_SYSTEM_ROOT_CAP`
  and `GET_SWAP_PARTITION` on its un-badged service endpoint, with
  multi-threaded recv so independent requests proceed while one waits on
  a driver spawn; no service-endpoint request waits on another's IPC (a
  `GET_SWAP_PARTITION` waits at most for the discovery lock and the swap
  lock, held across a discovery of new disks and one call to the block
  driver; none of devmgr, memmgr and the block drivers calls vfsd), so the thread count
  is a concurrency knob, not a correctness bound. `MOUNT` mounts the root or the data role at a
  path, resolved as the self-mount resolves it, gated on the
  `MOUNT_AUTHORITY` badge bit; root, `/esp`, and the data paths are
  self-mounted, and svctest and the hotplug-check fixture
  (disk mode) are its only in-tree callers. `UNMOUNT`, on
  the same badge bit, removes a mount below `/`: it asks the driver to
  unmount (refused `BUSY` while a file is open, unless forced), tears the
  driver down, and leaves the path falling through to the root
  filesystem. See
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md) and
  [`docs/namespace-composition.md`](docs/namespace-composition.md#unmount).
- **Swap-partition hand-out** — `GET_SWAP_PARTITION`, gated on the
  `SWAP_AUTHORITY` badge bit, hands the swap service a raw partition cap
  on the `SERAPH_SWAP` partition, which vfsd never mounts. The first
  request looks the partition up and registers it, so vfsd's startup does
  not depend on one; each later request cuts off the grant handed out
  before (revoke, retire, delete) and registers the partition again, so one
  holder at a time reaches the partition. The hand-out's decisions are the
  host-tested `vfsd-swap` crate, the cut-off the `vfsd-grant` crate. See
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
  [`docs/namespace-composition.md`](docs/namespace-composition.md#mount-record)),
  from which an unmount tears the driver down. Each driver's `argv[0]`
  is `fatfs:` and its mount path (`fatfs:/`, `fatfs:/data`).
- **Driver death and device loss** — vfsd's main thread, once the
  service threads run, waits on the death queue of every mount and on a
  watch of devmgr's `block` class. A driver's death restarts the driver
  of its mount, revoke and re-resolve: every cap through the dead
  instance fails closed, a new driver from the installed
  `/services/fs/fatfs` serves the same partition at the same path, and
  lookups into the mount are answered `IoError` meanwhile; once the
  mount's restart budget (shared/restart-budget) is spent, a death tears
  the mount down and the path falls through to the root filesystem (see
  [`docs/namespace-composition.md`](docs/namespace-composition.md#driver-restart)).
  A disk devmgr withdrew is marked removed and each mount on it torn down
  as a forced unmount; the loss of the root mount's driver or
  disk ends vfsd, and svcmgr shuts the system down. Once the root is
  mounted, vfsd sends `DECLINE_RESTART` on the `block` class SEND for
  the root disk's ordinal, so devmgr does not restart that disk's driver.
  Fall-through calls to the root filesystem are bounded (10 s, answered
  `IoError`). See
  [`docs/namespace-composition.md`](docs/namespace-composition.md#driver-death-and-device-loss).
  On both paths a vfsd logging at any level but info creates the
  driver with its own level as the driver's `SERAPH_LOG` env entry, so
  a driver logs at vfsd's level
  ([init bootstrap](../init/docs/bootstrap.md) § Log levels).
  See [`docs/namespace-composition.md`](docs/namespace-composition.md)
  and [`docs/storage.md`](../../docs/storage.md).
- **GPT enumeration + mount discovery** — at startup, queries devmgr
  for every block device (`QUERY_DEVICE` on the `block` class SEND at instance ordinals 0,
  1, …, passing a `WITHDRAWN` one, until another reply is not
  `SUCCESS`), and again from the first ordinal not yet queried before
  each runtime role lookup (a `MOUNT`, a `GET_SWAP_PARTITION`),
  asks devmgr where each new disk's device sits (`QUERY_DEVICE_LOCATION`
  on the same SEND: the PCI function devmgr bound its driver to, kept with
  the disk and logged; the boot-disk identification reads it),
  and parses each disk's GPT
  partition table through one scratch memory cap reused across the reads (replaced from memmgr
  before the next disk when a failed read left it lost), keeping every
  used entry of each header's `num_parts`-entry array, from the primary
  GPT or, when the primary fails its CRC32 or `MyLBA` checks, the backup at
  the disk's last LBA (a disk neither of whose GPT copies can be read and
  validated contributes none). It then identifies the boot disk
  (`gpt::find_boot_disk`: the held disk at the PCI location the bootloader
  reported that carries the boot ESP) and resolves the arch-conditional
  root GUID in `src/role_guids.rs` on it via `gpt::lookup_on_disk` for
  the self-mount; the DPS priority tie-break runs on the boot disk alone,
  and a tie at the highest priority is ambiguous. Another disk takes a
  role only where the signed storage statement `/config/vfsd/storage.conf`
  names its partition by unique partition GUID on the disk it binds it
  to, the boot disk or the disk at a PCI location (`gpt::resolve_named`,
  which reads only that disk); a
  disk neither the boot disk nor named takes no role, and with no boot
  disk the root self-mount fails. After root, vfsd reads the statement and
  auto-mounts the boot ESP (the partition the bootloader's descriptor
  names on the boot disk) at `/esp`, each data partition the statement
  names at its path, and, unless it names one for `/data`, the boot
  disk's `SERAPH_DATA` partition at `/data`; there is no
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
For each mount, and for the swap partition on each
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
