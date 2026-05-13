# fs

Filesystem driver implementations, each running as a separate process launched
and managed by vfsd.

---

## Source Layout

```
fs/
├── README.md
├── fat/                            # FAT12/16/32 filesystem driver (binary)
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
└── docs/
    └── fs-driver-protocol.md       # IPC protocol between vfsd and fs drivers
```

---

## Filesystem Driver Model

Each filesystem implementation is a standalone userspace process. A
driver is a namespace server: it serves the cap-native `NS_*`
protocol against per-node tokened SEND caps on its own endpoint, plus
the surviving fs-driver-specific labels (`FS_MOUNT`, `FS_READ`,
`FS_READ_FRAME` family, `FS_CLOSE`). vfsd captures the driver's root
cap at mount time and forwards walks through it; subsequent
operations bypass vfsd entirely. See
[`vfsd/README.md`](../vfsd/README.md) for the composition layer.

Filesystem drivers do not access hardware directly. They receive
partition-scoped block device IPC endpoints from vfsd (originating
from devmgr's device registry) and perform all storage I/O through
those endpoints. See
[`docs/device-management.md`](../../docs/device-management.md) for
how block device endpoints are established.

A filesystem driver crash does not affect other mounted filesystems
or the block device driver — vfsd can respawn a failed driver and
re-install the new root cap.

---

## Existing Filesystem Drivers

| Crate | Filesystem | Status |
|---|---|---|
| `fat/` | Read-only FAT16/FAT32 | Working |

---

## Adding a Filesystem

1. Create a subdirectory under `fs/` named for the filesystem (e.g.
   `ext4/`, `tmpfs/`).
2. Add a `Cargo.toml` for a binary crate that depends on the
   `namespace-protocol` and `ipc` crates from `shared/`.
3. Implement [`namespace_protocol::NamespaceBackend`] for your
   storage layer; route incoming `NS_*` labels through
   [`namespace_protocol::dispatch_request`] and the surviving
   `FS_*` labels through your own dispatcher (see
   [`docs/fs-driver-protocol.md`](docs/fs-driver-protocol.md)).
4. For disk-backed filesystems, read from the partition-scoped block
   device endpoint vfsd delivers at mount time.
5. For in-memory filesystems (e.g. tmpfs), no block device endpoint
   is needed; the storage layer lives in driver-private RAM.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/namespace-model.md](../../docs/namespace-model.md) | Cap-as-namespace principles |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, message format |
| [docs/device-management.md](../../docs/device-management.md) | Block device endpoint origin |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [shared/namespace-protocol/README.md](../../shared/namespace-protocol/README.md) | `NS_*` wire surface and `NamespaceBackend` trait |

---

## Summarized By

None
