# vfsd Service Interface

IPC interface vfsd exposes on its un-badged **service endpoint**.
Two labels: `MOUNT` and `GET_SYSTEM_ROOT_CAP`. The namespace surface
(`NS_LOOKUP` / `NS_STAT` / `NS_READDIR` against the synthetic system
root) lives on a separate endpoint and is specified in
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md);
the synthetic-root composition that backs it is described in
[`namespace-composition.md`](namespace-composition.md).

The system-root cap is requested by init via
`vfsd_labels::GET_SYSTEM_ROOT_CAP`. vfsd self-mounts root before any
service thread starts receiving, so the pull blocks until the root
filesystem is up; if the self-mount failed, vfsd replies `NO_MOUNT`
and init FATALs. Vfsd derives a fresh badged SEND on its own namespace
endpoint addressing `NodeId::ROOT` at full namespace rights and replies
with it. Init holds the cap as the seed for all later namespace-cap
distribution; children of init receive a `cap_copy` of it via
`procmgr_labels::CONFIGURE_NAMESPACE` (see
[services/init/docs/bootstrap.md](../../init/docs/bootstrap.md#root-acquisition)).
Clients consume it via
`std::os::seraph::root_dir_cap()`. Vfsd holds no namespace cap on
procmgr's behalf — there is no boot-time push.

vfsd self-mounts the Seraph root partition at `/` at startup, then mounts the EFI System
Partition at `/esp` and the data partition at `/data` (both best-effort); additional partitions
are discovered by their type GUID, not by a config file (see
[docs/storage.md](../../../docs/storage.md#gpt-role-guid-discovery)).
Label `12` on the service endpoint is reserved and MUST NOT be reused for an unrelated request.

---

## Endpoint

vfsd holds the receive side of one un-badged service endpoint,
created and delivered by init at vfsd's bootstrap (round 1, `caps[0]`).
Init holds a badged `SEED_AUTHORITY` SEND for `GET_SYSTEM_ROOT_CAP`
during boot; it issues no `MOUNT`, since vfsd self-mounts root (see
[services/init/docs/bootstrap.md](../../init/docs/bootstrap.md#per-stage-authority-transfers)).
At handover init endows svcmgr with two more SENDs on the endpoint, each
badged and so not re-badgeable: one carrying `MOUNT_AUTHORITY` alone,
which svcmgr publishes seed-only as `vfsd.mount`, and one carrying
`DENY_BADGE` (`1`, no verb bit), published seed-only as `vfsd.deny`.
svctest alone seeds both, to drive `MOUNT`'s refusal and rejection
paths.

| Badge bit | Constant | Gates | Holder |
|---|---|---|---|
| 63 | `vfsd_labels::MOUNT_AUTHORITY` | `MOUNT` | svcmgr's `vfsd.mount` |
| 62 | `vfsd_labels::SEED_AUTHORITY` | `GET_SYSTEM_ROOT_CAP` | init only |

All requests use `SYS_IPC_CALL` (synchronous call/reply). Numeric
labels live in `ipc::vfsd_labels` in `shared/ipc`.

---

## Label 10: `MOUNT`

Runtime explicit-mount surface (foreign-GUID disks, user-invoked
mounts). vfsd self-mounts root, `/esp`, and `/data` at startup through
the same resolution path; the only in-tree caller is svctest, whose
cases drive the rejection paths below. The caller's badge MUST carry
`MOUNT_AUTHORITY`: vfsd replies `UNAUTHORIZED` otherwise, before it
reads the request.

Mount the partition identified by a Seraph-minted GPT type GUID at the
given path. vfsd resolves the role byte to a type GUID (arch-conditional
for the root role, arch-neutral for data; see
[`services/vfsd/src/role_guids.rs`](../src/role_guids.rs)),
looks the partition up in its parsed GPT table via
[`gpt::lookup_partition_by_type_guid`](../gpt/src/lib.rs) (DPS-style
priority tie-break on attribute bits 48-63; a tie at the highest
priority is rejected with `NO_MOUNT` (fatal only for the root
self-mount); see [docs/storage.md](../../../docs/storage.md#gpt-role-guid-discovery)),
registers the partition bound with virtio-blk, spawns a fatfs
driver, sends `FS_MOUNT` (see
[services/fs/docs/fs-driver-protocol.md](../../fs/docs/fs-driver-protocol.md))
to validate the BPB, captures the driver's
root cap into `VfsdRootBackend`, and replies with a badged SEND on
the new filesystem's namespace endpoint addressing its root. A mount
on `/` once root is already mounted, or on a path that is already a mount
point, is rejected (`TABLE_FULL`) before any partition is registered or
driver spawned. A mount that fails after the spawn (the `FS_MOUNT` probe,
or an install a concurrent `MOUNT` beat) revokes the new driver's service
endpoint, which stops the driver; the partition bound virtio-blk
registered for it stays in virtio-blk's table, which has no unregister
request.

When the requested role is the rootfs (`MountRole::Root`, byte `0`),
vfsd additionally auto-mounts the EFI System Partition at `/esp` and
the data partition at `/data` inside the same handler before replying —
the same logic the startup self-mount uses. Both auto-mounts are
best-effort: a missing or duplicate-priority partition logs a
diagnostic and is skipped (leaving `/esp` / `/data` to resolve through
the root-fs fall-through) without propagating into the root mount
reply (see [docs/storage.md](../../../docs/storage.md#gpt-role-guid-discovery)).
The ESP is identified by the standard EFI System Partition type
GUID (`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`); the data partition by
the arch-neutral `SERAPH_DATA` GUID.

**Request**

| Field | Value |
|---|---|
| `label` | `10` |
| `data[0]` low byte | `MountRole` discriminant (`0` = `Root`; `1` = `Data`; other roles reserved) |
| `data[1]` | Mount path length (1..=64) |
| `data[2..]` | Mount path bytes packed little-endian |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `vfsd_errors::SUCCESS` (0) |
| `caps[0]` | Badged SEND on the new filesystem's namespace endpoint, addressing its root (omitted if cap derivation failed; the mount itself still landed) |

**Reply (error)**: `label = vfsd_errors::*` (`UNAUTHORIZED` for a
badge without `MOUNT_AUTHORITY`, `NOT_FOUND` for an
unknown role byte or invalid path length, `NO_MOUNT` if no partition
matches the role GUID or if duplicate-priority partitions are detected,
`SPAWN_FAILED`, `IO_ERROR`, `TABLE_FULL` if the synthetic-root install
fails, including when root is already mounted).

Single-component mount paths only (`/`, `/<name>`). Multi-component
paths are not surfaced through `NS_LOOKUP` and remain reachable only
via the root mount's transparent delegation.

---

## Label 13: `GET_SYSTEM_ROOT_CAP`

Seed pull of the system-root cap by init; the delivery chain is in the introduction. The
caller's badge MUST carry `SEED_AUTHORITY`: vfsd replies `UNAUTHORIZED` otherwise, before it
checks the version word.

**Request**

| Field | Value |
|---|---|
| `label` | `13` |
| `data[0]` | Caller's `ipc::VFSD_LABELS_VERSION` |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `vfsd_errors::SUCCESS` (0) |
| `caps[0]` | Fresh badged SEND on vfsd's namespace endpoint addressing `NodeId::ROOT` at full namespace rights |

**Reply (error)**: `label = vfsd_errors::*` (`UNAUTHORIZED` for a badge without
`SEED_AUTHORITY`, `LABEL_VERSION_MISMATCH` when `data[0]` differs from vfsd's
`VFSD_LABELS_VERSION`, `NO_MOUNT` when the root self-mount failed, and `IO_ERROR` if the
cap derivation fails).

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

[Storage](../../../docs/storage.md),
[Filesystem Driver Protocol](../../fs/docs/fs-driver-protocol.md),
[services/init/README.md](../../init/README.md),
[init Bootstrap Stages](../../init/docs/bootstrap.md), [services/vfsd/README.md](../README.md),
[Synthetic Root and Namespace Composition](namespace-composition.md)
