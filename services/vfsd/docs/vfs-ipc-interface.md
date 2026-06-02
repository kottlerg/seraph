# vfsd Service Interface

IPC interface vfsd exposes on its un-badged **service endpoint**.
Two labels: `MOUNT` and `GET_SYSTEM_ROOT_CAP`. The namespace surface
(`NS_LOOKUP` / `NS_STAT` / `NS_READDIR` against the synthetic system
root) lives on a separate endpoint and is specified in
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md);
the synthetic-root composition that backs it is described in
[`namespace-composition.md`](namespace-composition.md).

The system-root cap is requested by init via
[`vfsd_labels::GET_SYSTEM_ROOT_CAP`]. vfsd self-mounts root before any
service thread starts, and replies `NO_MOUNT` to this request until
root is mounted, so the pull blocks until the root filesystem is up
(and fails fast — letting init FATAL — if the self-mount failed).
Vfsd derives a fresh badged SEND on its own namespace endpoint
addressing `NodeId::ROOT` at full namespace rights and replies with
it. Init holds the cap as the seed for all later tier-3 namespace-cap
distribution; children of init receive a `cap_copy` of it via
`procmgr_labels::CONFIGURE_NAMESPACE`. Clients consume it via
`std::os::seraph::root_dir_cap()`. Vfsd holds no namespace cap on
procmgr's behalf — there is no boot-time push.

vfsd self-mounts the Seraph root partition at `/` and the EFI System
Partition at `/esp` at startup; additional partitions are discovered by
their type GUID, not by a config file. Label `12` on the service endpoint
is reserved and MUST NOT be reused for an unrelated request.

---

## Endpoint

vfsd holds the receive side of one un-badged service endpoint,
created and delivered by init at vfsd's bootstrap (round 1, `caps[0]`).
Init holds a badged `SEED_AUTHORITY` SEND for `GET_SYSTEM_ROOT_CAP`
during boot; it issues no `MOUNT`, since vfsd self-mounts root.

All requests use `SYS_IPC_CALL` (synchronous call/reply). Numeric
labels live in [`ipc::vfsd_labels`] in `shared/ipc`.

---

## Label 10: `MOUNT`

Runtime explicit-mount surface (foreign-GUID disks, user-invoked
mounts). vfsd self-mounts root and `/esp` at startup through the same
resolution path, so no in-tree caller currently issues `MOUNT`; the
label is retained for runtime mounts.

Mount the partition identified by a Seraph-minted GPT type GUID at the
given path. vfsd resolves the role byte to an arch-conditional type
GUID (see [`services/vfsd/src/role_guids.rs`](../src/role_guids.rs)),
looks the partition up in its parsed GPT table via
[`gpt::lookup_partition_by_type_guid`](../src/gpt.rs) (DPS-style
priority tie-break on attribute bits 48-63; tied priorities are
fatal), registers the partition bound with virtio-blk, spawns a fatfs
driver, sends `FS_MOUNT` to validate the BPB, captures the driver's
root cap into [`VfsdRootBackend`], and replies with a badged SEND on
the new filesystem's namespace endpoint addressing its root. A mount
on `/` is rejected (`NO_MOUNT`) once root is already mounted.

When the requested role is the rootfs (`MountRole::Root`, byte `0`),
vfsd additionally auto-mounts the EFI System Partition at `/esp`
inside the same handler before replying — the same logic the startup
self-mount uses. The ESP mount is best-effort: failure logs a
diagnostic but does not propagate into the root mount reply. The ESP
is identified by the standard EFI System Partition type GUID
(`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`).

**Request**

| Field | Value |
|---|---|
| `label` | `10` |
| `data[0]` low byte | `MountRole` discriminant (`0` = `Root`; other roles reserved) |
| `data[1]` | Mount path length (1..=64) |
| `data[2..]` | Mount path bytes packed little-endian |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `vfsd_errors::SUCCESS` (0) |
| `caps[0]` | Badged SEND on the new filesystem's namespace endpoint, addressing its root (omitted if cap derivation failed; the mount itself still landed) |

**Reply (error)**: `label = vfsd_errors::*` (`NOT_FOUND` for an
unknown role byte or invalid path length, `NO_MOUNT` if no partition
matches the role GUID, if duplicate-priority partitions are detected,
or if root is already mounted, `SPAWN_FAILED`, `IO_ERROR`,
`TABLE_FULL`).

Single-component mount paths only (`/`, `/<name>`). Multi-component
paths are not surfaced through `NS_LOOKUP` and remain reachable only
via the root mount's transparent delegation.

---

## Relevant Design Documents

| Document | Content |
|---|---|
| [namespace-composition.md](namespace-composition.md) | Synthetic-root composition, transparent root delegation |
| [shared/namespace-protocol/README.md](../../../shared/namespace-protocol/README.md) | NS_* wire surface |
| [services/fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md) | Filesystem-driver IPC (FS_MOUNT and per-node ops) |
| [docs/ipc-design.md](../../../docs/ipc-design.md) | IPC message format, cap transfer |
| [docs/capability-model.md](../../../docs/capability-model.md) | Badge semantics, derivation tree |

---

## Summarized By

[services/vfsd/README.md](../README.md), [docs/storage.md](../../../docs/storage.md)
