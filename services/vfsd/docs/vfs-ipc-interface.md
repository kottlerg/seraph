# vfsd Service Interface

IPC interface vfsd exposes on its un-tokened **service endpoint**.
Two labels: `MOUNT` and `GET_SYSTEM_ROOT_CAP`. The namespace surface
(`NS_LOOKUP` / `NS_STAT` / `NS_READDIR` against the synthetic system
root) lives on a separate endpoint and is specified in
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md);
the synthetic-root composition that backs it is described in
[`namespace-composition.md`](namespace-composition.md).

The system-root cap is requested by init via
[`vfsd_labels::GET_SYSTEM_ROOT_CAP`] once the role-driven root mount
completes. Vfsd derives a fresh tokened SEND on its own namespace
endpoint addressing `NodeId::ROOT` at full namespace rights and
replies with it. Init holds the cap as the seed for all later tier-3
namespace-cap distribution; children of init receive a `cap_copy` of
it via `procmgr_labels::CONFIGURE_NAMESPACE`. Clients consume it via
`std::os::seraph::root_dir_cap()`. Vfsd holds no namespace cap on
procmgr's behalf — there is no boot-time push.

The historic `INGEST_CONFIG_MOUNTS` IPC and the `/config/mounts.conf`
file it consumed were retired with the GPT-type-GUID redesign (boot
protocol v8). vfsd now auto-mounts the EFI System Partition at `/esp`
after the role-driven root mount succeeds; additional partitions are
discovered by their type GUID, not by a config file. The label number
(`12`) is reserved and MUST NOT be reused for an unrelated request.

---

## Endpoint

vfsd holds the receive side of one un-tokened service endpoint,
created and delivered by init at vfsd's bootstrap (round 1, `caps[0]`).
Init holds a SEND copy for the role-driven root `MOUNT` and a tokened
`SEED_AUTHORITY` SEND for `GET_SYSTEM_ROOT_CAP` during boot.

All requests use `SYS_IPC_CALL` (synchronous call/reply). Numeric
labels live in [`ipc::vfsd_labels`] in `shared/ipc`.

---

## Label 10: `MOUNT`

Mount the partition identified by a Seraph-minted GPT type GUID at the
given path. vfsd resolves the role byte to an arch-conditional type
GUID (see [`services/vfsd/src/role_guids.rs`](../src/role_guids.rs)),
looks the partition up in its parsed GPT table via
[`gpt::lookup_partition_by_type_guid`](../src/gpt.rs) (DPS-style
priority tie-break on attribute bits 48-63; tied priorities are
fatal), registers the partition bound with virtio-blk, spawns a fatfs
driver, sends `FS_MOUNT` to validate the BPB, captures the driver's
root cap into [`VfsdRootBackend`], and replies with a tokened SEND on
the new filesystem's namespace endpoint addressing its root.

When the requested role is the rootfs (`MountRole::Root`, byte `0`),
vfsd additionally auto-mounts the EFI System Partition at `/esp`
inside the same handler before replying. The ESP mount is best-effort:
failure logs a diagnostic but does not propagate into the root mount
reply. The ESP is identified by the standard EFI System Partition
type GUID (`c12a7328-f81f-11d2-ba4b-00a0c93ec93b`); init never has to
issue a separate MOUNT for `/esp`.

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
| `caps[0]` | Tokened SEND on the new filesystem's namespace endpoint, addressing its root (omitted if cap derivation failed; the mount itself still landed) |

**Reply (error)**: `label = vfsd_errors::*` (`NOT_FOUND` for an
unknown role byte or invalid path length, `NO_MOUNT` if no partition
matches the role GUID or if duplicate-priority partitions are
detected, `SPAWN_FAILED`, `IO_ERROR`, `TABLE_FULL`).

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
| [docs/capability-model.md](../../../docs/capability-model.md) | Token semantics, derivation tree |

---

## Summarized By

[services/vfsd/README.md](../README.md)
