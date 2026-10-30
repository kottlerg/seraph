# fs

Filesystem driver implementations, each running as a separate process launched
and managed by vfsd.

---

## Source Layout

```
fs/
├── README.md
├── fat/                            # FAT16/FAT32 filesystem driver (binary)
│   └── README.md                   # fat driver scope and layout
└── docs/
    ├── adding-a-filesystem.md      # Procedure for adding a filesystem driver
    └── fs-driver-protocol.md       # IPC protocol between vfsd and fs drivers
```

---

## Filesystem Driver Model

Each filesystem implementation is a standalone userspace process. A
driver is a namespace server: it serves the cap-native `NS_*`
protocol against per-node badged SEND caps on its own endpoint (see
[`shared/namespace-protocol/README.md`](../../shared/namespace-protocol/README.md) § Badge shape),
plus the fs-driver-specific `FS_*` labels (mount, read, write, and
directory mutation) specified in
[`docs/fs-driver-protocol.md`](docs/fs-driver-protocol.md). At mount
time vfsd keeps the driver's unbadged namespace endpoint; each lookup
that crosses the mount mints an attenuated node cap on that endpoint,
and later operations on that cap go to the driver directly, bypassing
vfsd (see
[`vfsd/docs/namespace-composition.md`](../vfsd/docs/namespace-composition.md)
§ Mount-crossing mint). See [`vfsd/README.md`](../vfsd/README.md) for the
composition layer.

Filesystem drivers do not access hardware directly. They receive
partition-scoped block device IPC endpoints from vfsd (originating
from devmgr's device registry) and perform all storage I/O through
those endpoints (delivery in
[`docs/fs-driver-protocol.md`](docs/fs-driver-protocol.md) § Bootstrap caps). See
[`docs/device-management.md`](../../docs/device-management.md) for
how block device endpoints are established.

A filesystem driver crash does not affect other mounted filesystems
or the block device driver; vfsd does not observe the death or
respawn the driver (see
[`docs/storage.md`](../../docs/storage.md) § Failure and Revocation Invariants).

---

## Existing Filesystem Drivers

| Crate | Filesystem | Status |
|---|---|---|
| [`fat/`](fat/README.md) | Read/write FAT16/FAT32 (write-through, no fsync) | Working |

---

## Adding a Filesystem

A new filesystem is a subdirectory of `fs/` holding a binary crate that implements
`namespace_protocol::NamespaceBackend` and the `FS_*` labels; the procedure is in
[docs/adding-a-filesystem.md](docs/adding-a-filesystem.md).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/adding-a-filesystem.md](docs/adding-a-filesystem.md) | Procedure for adding a filesystem driver |
| [docs/namespace-model.md](../../docs/namespace-model.md) | Cap-as-namespace principles |
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC semantics, message format |
| [docs/device-management.md](../../docs/device-management.md) | Block device endpoint origin |
| [docs/storage.md](../../docs/storage.md) | Storage composition, fs↔block contract, failure invariants |
| [docs/coding-standards.md](../../docs/coding-standards.md) | Formatting, naming, safety rules |
| [shared/namespace-protocol/README.md](../../shared/namespace-protocol/README.md) | `NS_*` wire surface and `NamespaceBackend` trait |

---

## Summarized By

[Architecture Overview](../../docs/architecture.md)
