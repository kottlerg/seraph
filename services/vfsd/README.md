# vfsd

Virtual filesystem daemon providing a unified namespace over multiple filesystem
driver processes.

---

## Source Layout

```
vfsd/
├── Cargo.toml
├── README.md
├── src/
│   └── main.rs                     # Entry point (stub)
└── docs/
    ├── namespace.md                # Mount points, path resolution, namespace hierarchy
    └── vfs-ipc-interface.md        # Filesystem IPC interface for applications
```

---

## Responsibilities

- **Launch filesystem drivers** — start filesystem driver processes from
  [`fs/`](../fs/README.md) via procmgr and manage their lifecycle.
- **Route namespace operations** — maintain a mount table mapping path prefixes
  to filesystem driver endpoints. Incoming filesystem requests (open, read,
  write, stat, readdir) are resolved to the correct driver and forwarded via
  IPC.
- **Manage mount table** — handle mount and unmount operations, associating
  filesystem driver instances with namespace locations.
- **Expose filesystem IPC** — provide a single filesystem IPC endpoint to
  applications and other services. Clients interact with vfsd; vfsd handles
  dispatch to the appropriate driver. See
  [`docs/vfs-ipc-interface.md`](docs/vfs-ipc-interface.md).

vfsd does not touch hardware directly. All storage I/O is mediated through
block device driver IPC endpoints.

---

## Filesystem Driver Management

Filesystem implementations (FAT, ext4, tmpfs, etc.) live in
[`fs/`](../fs/README.md) as separate binary crates. Each runs as an isolated
process with its own address space.

At mount time, vfsd:

1. Requests procmgr to create the filesystem driver process.
2. Passes the block device IPC endpoint (for disk-backed filesystems) to the
   driver. In-memory filesystems (e.g. tmpfs) receive no block device endpoint.
3. Registers the driver in the mount table at the specified namespace path.
4. Routes all subsequent operations under that path to the driver.

On unmount or driver crash, vfsd removes the mount table entry. Filesystem
drivers can be restarted and re-mounted independently without affecting other
mount points.

The IPC protocol between vfsd and filesystem drivers is specified in
[`fs/docs/fs-driver-protocol.md`](../fs/docs/fs-driver-protocol.md).

---

## Relationship to devmgr

vfsd receives block device IPC endpoints indirectly: devmgr discovers storage
hardware, spawns block device drivers, and registers their endpoints in the
device registry. vfsd queries the device registry (or receives endpoints via
init's bootstrap sequence) to obtain block device endpoints for mounting. See
[docs/device-management.md](../docs/device-management.md) for the device
registry and endpoint flow.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../docs/ipc-design.md) | IPC semantics, endpoints, message format |
| [docs/architecture.md](../docs/architecture.md) | Bootstrap sequence, vfsd role |
| [docs/device-management.md](../docs/device-management.md) | Device registry, block device endpoints |
| [docs/coding-standards.md](../docs/coding-standards.md) | Formatting, naming, safety rules |

---

## Summarized By

None
