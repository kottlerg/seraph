# VFS IPC Interface

IPC interface exposed by vfsd to applications and services: namespace resolution
(open) and mount management. After opening a file, clients receive a per-file
capability and perform file operations directly on the filesystem driver.

---

## Endpoint

vfsd listens on a single IPC endpoint. Init creates the endpoint during
bootstrap and injects the Receive-side capability into vfsd's CSpace. Send-side
capabilities are delegated to any process that needs filesystem access.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message label
field identifies the operation.

### Label 1: `OPEN`

Open a file or directory by path. vfsd resolves the mount point, forwards
`FS_OPEN` to the filesystem driver, and relays the per-file capability back
to the client. After this call, the client holds a direct tokened capability
to the driver and performs all file operations (read, close, stat, readdir)
without further vfsd involvement.

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (path_len << 16)` — bits 0–15 = opcode, bits 16–31 = path byte count |
| data[0..5] | Path bytes packed into up to 6 data words (48 bytes max) |

Path is an absolute, `/`-separated, null-free byte string. Case-insensitive
matching is performed for FAT mount points. Maximum path length is 48 bytes;
longer paths are not supported in this version.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| cap[0] | Per-file capability (tokened Send endpoint to the filesystem driver) |

The client uses this capability for all subsequent file operations. See
[fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md) for the
file operation protocol (read, close, stat, readdir).

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `NotFound` | Driver could not resolve the path within the filesystem |
| 2 | `NoMount` | No filesystem mounted at the resolved prefix |
| 3 | `TooManyOpen` | Driver's open file table is full |
| 5 | `IoError` | Driver communication failed |

### Label 10: `MOUNT`

Mount a filesystem by partition UUID. vfsd looks up the UUID in the GPT
partition table, spawns a filesystem driver, sends `FS_MOUNT` to initialize
it, and registers the mount in the namespace table.

**Request:**

| Field | Value |
|---|---|
| label | 10 |
| data[0..1] | Partition UUID (16 bytes, mixed-endian GPT format) |
| data[2] | Mount path length |
| data[3..] | Mount path bytes (packed into u64 words) |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `InvalidPath` | Path length is 0 or too long |
| 2 | `UuidNotFound` | Partition UUID not in GPT table |
| 3 | `NoModule` | FAT filesystem driver module not available |
| 4 | `SpawnFailed` | Failed to spawn filesystem driver process |
| 5 | `MountFailed` | Driver's `FS_MOUNT` returned an error |
| 6 | `TableFull` | Mount table is full |

---

## File Operations

After `OPEN`, the client holds a per-file capability — a tokened Send endpoint
to the filesystem driver. The token identifies the open file to the driver.

File operations (read, close, stat, readdir) are sent directly to the driver
using this capability, not through vfsd. The protocol is defined in
[fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md).

vfsd is not involved in any file operation after the initial `OPEN`.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC message format, cap transfer protocol |
| [fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md) | Per-file capability protocol |
| [docs/architecture.md](../../docs/architecture.md) | vfsd role in the system |
| [docs/capability-model.md](../../docs/capability-model.md) | Tokens and capability derivation |

---

## Summarized By

None
