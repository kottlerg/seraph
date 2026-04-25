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

Each filesystem implementation is a standalone userspace process. vfsd launches
filesystem drivers and routes namespace operations (open, read, write, stat,
readdir) to the appropriate driver via IPC. See
[vfsd/README.md](../vfsd/README.md) for namespace routing.

Filesystem drivers do not access hardware directly. They receive block device
IPC endpoints from vfsd (originating from devmgr's device registry) and
perform all storage I/O through those endpoints. See
[docs/device-management.md](../docs/device-management.md) for how block device
endpoints are established.

This isolation means a filesystem driver crash does not affect other mounted
filesystems or the block device driver — vfsd can restart a failed driver and
re-mount.

---

## Existing Filesystem Drivers

| Crate | Filesystem | Status |
|---|---|---|
| `fat/` | FAT12/16/32 | Stub |

---

## Adding a Filesystem

1. Create a subdirectory under `fs/` named for the filesystem (e.g. `ext4/`,
   `tmpfs/`).
2. Add a `Cargo.toml` for a `no_std` binary crate targeting the userspace
   Seraph target.
3. Implement the fs driver protocol: receive IPC messages from vfsd conforming
   to the interface defined in [`docs/fs-driver-protocol.md`](docs/fs-driver-protocol.md).
4. For disk-backed filesystems, communicate with the block device driver via
   the IPC endpoint provided by vfsd at mount time.
5. For in-memory filesystems (e.g. tmpfs), no block device endpoint is needed.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../docs/ipc-design.md) | IPC semantics, message format |
| [docs/device-management.md](../docs/device-management.md) | Block device endpoint origin |
| [docs/coding-standards.md](../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
