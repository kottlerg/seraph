# vfsd Service Interface

IPC interface vfsd exposes on its un-tokened **service endpoint**.
Three labels: `MOUNT`, `INGEST_CONFIG_MOUNTS`, and
`GET_SYSTEM_ROOT_CAP`. The namespace surface (`NS_LOOKUP` /
`NS_STAT` / `NS_READDIR` against the synthetic system root) lives on
a separate endpoint and is specified in
[`shared/namespace-protocol/README.md`](../../../shared/namespace-protocol/README.md);
the synthetic-root composition that backs it is described in
[`namespace-composition.md`](namespace-composition.md).

The system-root cap is requested by init via
[`vfsd_labels::GET_SYSTEM_ROOT_CAP`] once the cmdline-driven root
mount completes. Vfsd derives a fresh tokened SEND on its own
namespace endpoint addressing `NodeId::ROOT` at full namespace
rights and replies with it. Init holds the cap as the seed for all
later tier-3 namespace-cap distribution; children of init receive a
`cap_copy` of it via `procmgr_labels::CONFIGURE_NAMESPACE`. Clients
consume it via `std::os::seraph::root_dir_cap()`. Vfsd holds no
namespace cap on procmgr's behalf — there is no boot-time push.

---

## Endpoint

vfsd holds the receive side of one un-tokened service endpoint,
created and delivered by init at vfsd's bootstrap (round 1, `caps[0]`).
Init holds a SEND copy for `MOUNT` and `INGEST_CONFIG_MOUNTS` calls
during boot.

All requests use `SYS_IPC_CALL` (synchronous call/reply). Numeric
labels live in [`ipc::vfsd_labels`] in `shared/ipc`.

---

## Label 10: `MOUNT`

Mount the partition identified by GPT UUID at the given path. vfsd
looks up the UUID in its parsed GPT table, registers the partition
bound with virtio-blk, spawns a fatfs driver, sends `FS_MOUNT` to
validate the BPB, captures the driver's root cap into
[`VfsdRootBackend`], and replies with a tokened SEND on the new
filesystem's namespace endpoint addressing its root.

**Request**

| Field | Value |
|---|---|
| `label` | `10` |
| `data[0..1]` | Partition UUID (16 bytes, mixed-endian, as stored in GPT) |
| `data[2]` | Mount path length (1..=64) |
| `data[3..]` | Mount path bytes packed little-endian |

**Reply (success)**

| Field | Value |
|---|---|
| `label` | `vfsd_errors::SUCCESS` (0) |
| `caps[0]` | Tokened SEND on the new filesystem's namespace endpoint, addressing its root (omitted if cap derivation failed; the mount itself still landed) |

**Reply (error)**: `label = vfsd_errors::*` (`NOT_FOUND`, `NO_MOUNT`,
`SPAWN_FAILED`, `IO_ERROR`, `TABLE_FULL`).

Single-component mount paths only (`/`, `/<name>`). Multi-component
paths are not surfaced through `NS_LOOKUP` and remain reachable only
via the root mount's transparent delegation.

---

## Label 12: `INGEST_CONFIG_MOUNTS`

Trigger vfsd to read `/config/mounts.conf` from the freshly-mounted
root filesystem (via vfsd's own internal NS walk + read against the
captured root mount cap) and issue the additional `MOUNT`s described
there. Synchronous: vfsd does not reply until every described mount
has been attempted.

**Request**

| Field | Value |
|---|---|
| `label` | `12` |
| body | empty |

**Reply (success)**: `label = vfsd_errors::SUCCESS` (0). A missing or
empty `mounts.conf` is **not** an error — only catastrophic NS-walk
or read failure against the root mount produces a non-zero reply.

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
