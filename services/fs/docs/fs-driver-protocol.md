# Filesystem Driver Protocol

IPC protocol for filesystem drivers. Two communication channels exist:

1. **Service endpoint** (untokened): vfsd sends `FS_MOUNT` and `FS_OPEN` on
   the driver's service endpoint. The driver holds the Receive-side capability.

2. **Per-file capabilities** (tokened): On `FS_OPEN`, the driver derives a
   tokened Send cap from its service endpoint and returns it. Clients send
   file operations (`FS_READ`, `FS_CLOSE`, `FS_STAT`, `FS_READDIR`) directly
   on this cap. The token delivered by `ipc_recv` identifies the open file.

---

## Endpoint

vfsd creates a dedicated IPC endpoint for each filesystem driver at mount time.
vfsd holds the Send-side capability; the driver holds the Receive-side
capability, injected into the driver's CSpace during two-phase process creation.

---

## Messages

All operations use `SYS_IPC_CALL` (synchronous call/reply). The driver
dispatches based on the token from `ipc_recv`:

- **token == 0**: service-level request from vfsd (`FS_MOUNT`, `FS_OPEN`)
- **token != 0**: per-file request from a client, identified by the token

### Label 10: `FS_MOUNT`

Initialize the filesystem. Sent once after the driver starts, via the
untokened service endpoint. The driver reads superblock/BPB metadata from the
block device and prepares internal state.

The block device endpoint is injected into the driver's CSpace at creation
time (identified by `CapDescriptor` with `CapType::Frame` and
`aux0 = BLOCK_ENDPOINT_SENTINEL`).

**Request:**

| Field | Value |
|---|---|
| label | 10 |
| data[0] | Partition LBA offset |

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
| 1 | `InvalidFilesystem` | Superblock/BPB validation failed |
| 2 | `IoError` | Block device read failed |

### Label 1: `FS_OPEN`

Open a file or directory by path within this filesystem. Sent via the
untokened service endpoint by vfsd.

On success, the driver:
1. Resolves the path to a directory entry
2. Allocates an internal file slot and assigns a monotonic token value
3. Derives a tokened Send cap from its service endpoint via
   `SYS_CAP_DERIVE_TOKEN`
4. Returns the tokened cap in the reply

**Request:**

| Field | Value |
|---|---|
| label | `1 \| (path_len << 16)` — bits 0–15 = opcode, bits 16–31 = path byte count |
| data[0..5] | Path bytes (relative to this mount point, `/`-separated) |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| cap[0] | Per-file capability (tokened Send endpoint) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `NotFound` | Path does not resolve to an existing entry |
| 2 | `OutOfMemory` | Cap derivation failed |
| 3 | `TooManyOpen` | Open file table is full |

### Label 2: `FS_READ`

Read bytes from an open file. Sent by the client directly on the per-file
capability; the token identifies the file.

**Request:**

| Field | Value |
|---|---|
| label | 2 |
| data[0] | Byte offset |
| data[1] | Maximum bytes to read (capped at 512) |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | Bytes actually read |
| data[1..] | File data in IPC buffer (up to 512 bytes, 64 u64 words) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `InvalidToken` | No open file for this token |

### Label 3: `FS_CLOSE`

Close an open file. Sent by the client on the per-file capability; the token
identifies the file. The client should call `SYS_CAP_DELETE` on the per-file
capability after this call.

**Request:**

| Field | Value |
|---|---|
| label | 3 |

No data words required — the file is identified by the token.

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
| 4 | `InvalidToken` | No open file for this token |

### Label 4: `FS_STAT`

Query metadata for an open file. Sent on the per-file capability; the token
identifies the file.

**Request:**

| Field | Value |
|---|---|
| label | 4 |

No data words required — the file is identified by the token.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | File size in bytes |
| data[1] | Flags: bit 0 = directory, bit 1 = read-only |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `InvalidToken` | No open file for this token |

### Label 5: `FS_READDIR`

Read a directory entry by index. Sent on the per-file capability; the token
identifies the directory.

**Request:**

| Field | Value |
|---|---|
| label | 5 |
| data[0] | Entry index (0-based) |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | Entry name length |
| data[1] | File size |
| data[2] | Flags: bit 0 = directory |
| data[3..] | Entry name bytes (8.3 format, up to 12 bytes) |

**Reply (end of directory):**

| Field | Value |
|---|---|
| label | 6 (`EndOfDir`) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 4 | `InvalidToken` | No open file for this token, or not a directory |

---

## Block Device Access

Filesystem drivers perform all storage I/O through a block device endpoint
received at creation time. The block device protocol uses label 1
(`READ_BLOCK`): data[0] = sector number, reply contains 512 bytes (64 u64
words) on success. See `drivers/virtio/blk` for the block device IPC
specification.

---

## Sentinel Values

Capabilities injected into a filesystem driver's CSpace are identified by
sentinel values in the `CapDescriptor.aux0` field:

| Sentinel | Meaning |
|---|---|
| `0xFFFF_FFFF_FFFF_FFFF` | Log endpoint |
| `0xFFFF_FFFF_FFFF_FFFE` | Service endpoint (vfsd-to-driver IPC, Receive-side) |
| `0xFFFF_FFFF_FFFF_FFFD` | Block device endpoint (Send-side) |
| `0x0000_0000_0000_0000` (aux0 and aux1 both 0) | procmgr endpoint |

All sentinels use `CapType::Frame` as the discriminant (the actual kernel
object is an Endpoint, but the CapDescriptor type field is overloaded for
sentinel identification).

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC message format, cap transfer protocol |
| [vfsd/docs/vfs-ipc-interface.md](../../vfsd/docs/vfs-ipc-interface.md) | Client-facing namespace IPC |
| [docs/capability-model.md](../../docs/capability-model.md) | Tokens and capability derivation |
| [docs/device-management.md](../../docs/device-management.md) | Block device endpoint origin |

---

## Summarized By

None
