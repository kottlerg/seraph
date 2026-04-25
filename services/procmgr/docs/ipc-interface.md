# procmgr IPC Interface

IPC interface specification for procmgr: message labels, capability transfer
semantics, and error conditions for process lifecycle operations.

---

## Endpoint

procmgr listens on a single IPC endpoint. Init holds the Send-side capability
and passes it (or a derived copy) to any service that needs to create processes.
procmgr holds the Receive-side capability.

---

## Messages

All requests use `SYS_IPC_CALL` (synchronous call/reply). The message label
field identifies the operation. Data words and capability slots carry arguments;
the reply carries results.

### Label 1: `CREATE_PROCESS`

Create a new process from a raw ELF module. The process is created in a
**suspended** state — the thread is not started. The caller receives the
child's `CSpace` capability and `ProcessInfo` frame capability so it can
inject initial capabilities and write `CapDescriptor` / startup message data
before starting the process via `START_PROCESS`.

**Request:**

| Field | Value |
|---|---|
| label | 1 |
| cap[0] | Frame capability for the ELF module image |

The caller transfers a Frame cap covering the raw ELF bytes. procmgr maps
the frame, parses the ELF, creates an address space, CSpace, and thread,
maps LOAD segments, and populates the `ProcessInfo` handover page with
identity caps. The thread is **not** started.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| cap[0] | Process handle (tokened endpoint identifying this process) |
| cap[1] | Child `CSpace` capability (full rights) |
| cap[2] | `ProcessInfo` frame capability (MAP\|WRITE rights) |
| cap[3] | Child `Thread` capability (Control right) |

The process handle is a tokened endpoint capability. The caller uses it
to send `START_PROCESS` (and future per-process operations) — the token
identifies the process without a forgeable PID. The `CSpace` cap allows
the caller to inject capabilities into the child's capability space via
`cap_copy`. The `ProcessInfo` frame cap allows the caller to map the page
writable and patch `initial_caps_base`, `initial_caps_count`,
`cap_descriptor_count`, `cap_descriptors_offset`, and startup message
fields. The `Thread` cap allows the caller to bind death notifications or
stop/configure the thread.

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |
| data[0] | 0 |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `InvalidElf` | ELF validation failed (bad magic, wrong arch, corrupt headers) |
| 2 | `OutOfMemory` | Insufficient frame caps to allocate stack, ProcessInfo page, or IPC buffer |
| 3 | `CSpaceFull` | Cannot allocate kernel objects (address space, CSpace, thread) |

### Label 2: `START_PROCESS`

Start a previously created (suspended) process. The caller must have
completed any capability injection and `ProcessInfo` patching before
calling this operation.

The call is sent to the **process handle** (tokened endpoint) returned by
`CREATE_PROCESS`, not to the main procmgr endpoint. The token identifies
which process to start.

**Request:**

| Field | Value |
|---|---|
| endpoint | Process handle (tokened endpoint from `CREATE_PROCESS` reply cap[0]) |
| label | 2 |

No data words are required — the process is identified by the token
embedded in the endpoint capability.

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
| 4 | `InvalidToken` | No process with the given token exists |
| 5 | `AlreadyStarted` | Process was already started |

### Label 3: `EXIT_PROCESS`

Deferred. Not implemented.

### Label 4: `QUERY_PROCESS`

Deferred. Not implemented.

### Label 5: `REQUEST_FRAMES`

Allocate page-sized Frame capabilities from the procmgr memory pool and
transfer them to the caller. Intended for drivers that need DMA-capable
memory at runtime (virtqueue structures, data buffers).

**Request:**

| Field | Value |
|---|---|
| label | 5 |
| data[0] | Number of pages to allocate (1–4) |

The caller specifies how many 4 KiB pages to allocate. Maximum 4 pages per
request (limited by the IPC cap slot count). The caller may issue multiple
requests for larger allocations.

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |
| data[0] | Number of pages actually allocated |
| cap[0..N] | Frame capabilities (one per page, MAP\|WRITE rights) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 6 | `OutOfMemory` | Insufficient frame caps in the memory pool |
| 7 | `InvalidArgument` | Requested page count is 0 or exceeds 4 |

### Label 6: `CREATE_PROCESS_FROM_VFS`

Create a new process by loading an ELF binary from the virtual filesystem.
Requires that a vfsd endpoint has been configured via `SET_VFSD_ENDPOINT`.
The process is created in a **suspended** state, identical to `CREATE_PROCESS`.

**Request:**

| Field | Value |
|---|---|
| label | `6 \| (path_len << 16)` |
| data[0..] | File path bytes packed into u64 words (up to 48 bytes) |

procmgr opens the file via vfsd, reads the ELF binary into an internal
buffer, parses and loads it using the same pipeline as `CREATE_PROCESS`,
then returns a suspended process.

**Reply (success):**

Same as `CREATE_PROCESS`:

| Field | Value |
|---|---|
| label | 0 (success) |
| cap[0] | Process handle (tokened endpoint) |
| cap[1] | Child `CSpace` capability (full rights) |
| cap[2] | `ProcessInfo` frame capability (MAP\|WRITE rights) |
| cap[3] | Child `Thread` capability (Control right) |

**Reply (error):**

| Field | Value |
|---|---|
| label | Nonzero error code |

**Error codes:**

| Code | Name | Meaning |
|---|---|---|
| 1 | `InvalidElf` | ELF validation failed |
| 2 | `OutOfMemory` | Insufficient frame caps |
| 3 | `CSpaceFull` | Cannot allocate kernel objects |
| 8 | `NoVfsEndpoint` | No vfsd endpoint configured |
| 9 | `FileNotFound` | vfsd OPEN failed for the given path |
| 10 | `IoError` | vfsd READ or STAT failed |

### Label 7: `SET_VFSD_ENDPOINT`

Configure the vfsd Send endpoint for VFS-based process creation. Init sends
this after vfsd is running and the root filesystem is mounted. One-time
configuration; subsequent calls overwrite the stored endpoint.

**Request:**

| Field | Value |
|---|---|
| label | 7 |
| cap[0] | vfsd Send endpoint capability |

**Reply (success):**

| Field | Value |
|---|---|
| label | 0 (success) |

---

## Capability Transfer

Capability transfer uses the IPC message's cap slot array (up to 4 caps per
message). On `CREATE_PROCESS`, the caller's Frame cap is moved into procmgr's
CSpace atomically with the message delivery. procmgr consumes the cap during
process creation and does not return it.

On reply, procmgr transfers a tokened process handle endpoint (for
subsequent per-process operations) and derived copies of the child's
`CSpace`, `ProcessInfo` frame, and `Thread` capabilities to the caller.
procmgr retains the original caps for process lifecycle management.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [docs/ipc-design.md](../../docs/ipc-design.md) | IPC message format, cap transfer protocol |
| [abi/process-abi](../../abi/process-abi/README.md) | ProcessInfo handover struct |
| [abi/syscall](../../abi/syscall/README.md) | Syscall numbers and register conventions |

---

## Summarized By

[procmgr/README.md](../README.md)
