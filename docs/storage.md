# Storage

System-scope composition of the Seraph storage stack: how
[`vfsd`](../services/vfsd/README.md),
[filesystem drivers](../services/fs/README.md), and block drivers are linked by capability
delegation and how mounts are established at boot.

---

## Composition Principle

Storage is three layers of independent userspace processes linked
exclusively by capability delegation:

| Layer | Process | Owns |
|---|---|---|
| Block | `virtio-blk` (per disk) | Hardware MMIO, IRQ, descriptor rings |
| Filesystem | one fs driver per mount (e.g. `fatfs`) | On-disk format, BPB, FAT chains |
| Namespace | `vfsd` (single instance) | Synthetic root, GPT discovery, mount tree |

The kernel transports capabilities and bytes; it holds no filesystem
state and contains no filesystem code. All composition is in
userspace.

Four system-scope invariants govern the stack:

- **vfsd holds no on-disk storage and is off the I/O path after the
  walk.** Once a client has walked `NS_LOOKUP` into a mounted
  filesystem, subsequent reads and writes go directly to the owning
  fs driver. vfsd is not a proxy.
- **One fs-driver process per mount.** A crash in one mount cannot
  corrupt another. `vfsd` is the supervisor for the fs-driver
  lifecycle.
- **Block access is partition-scoped at the capability layer.** The
  block driver exposes one unbadged whole-disk endpoint (held by
  vfsd alone) and badged per-partition endpoints (handed to fs
  drivers). Out-of-bounds LBAs are rejected by the block driver on
  every request.
- **System root is delivered, never discovered.** Every process's
  namespace authority arrives as `ProcessInfo.system_root_cap`
  installed by `procmgr_labels::CONFIGURE_NAMESPACE` on spawn.
  There is no ambient mount table and no global lookup.

The cap-as-namespace principles these invariants rest on are
specified in [`namespace-model.md`](namespace-model.md).

---

## Capability Delegation Chain

Storage authority flows from the kernel's initial cap mint outward in
one direction. Each arrow is a single capability transfer; revoking
any link kills the subtree beneath it.

```
kernel (phase 7) mints Mmio + IRQ from BootInfo
  → init delegates Mmio + IRQ caps to devmgr
    → devmgr binds virtio-blk; delegates per-device MMIO + IRQ
      → virtio-blk publishes its whole-disk service endpoint to devmgr
        → vfsd queries devmgr's device registry → whole-disk SEND
          → vfsd issues REGISTER_PARTITION (whole-disk endpoint only)
            → vfsd derives a badged per-partition SEND
              → vfsd spawns fs driver; injects partition-scoped block cap
                → fs driver issues FS_MOUNT, reads BPB, replies OK
                  → vfsd captures fs driver's root namespace cap
                    → init pulls system root via GET_SYSTEM_ROOT_CAP
                      → init distributes copies via CONFIGURE_NAMESPACE
```

The kernel half (BootInfo → Mmio mint → devmgr → driver binding)
is owned by [`device-management.md`](device-management.md). Badge
semantics, derivation, and revocation are owned by
[`capability-model.md`](capability-model.md) §"Badges".

`REGISTER_PARTITION` is rejected over badged callers: only the holder
of the whole-disk endpoint (vfsd) can mint a partition binding. The
block driver enforces the LBA bound on every read and write against
the caller's badge. See
[`services/drivers/virtio/blk/README.md`](../services/drivers/virtio/blk/README.md).

---

## GPT Role-GUID Discovery

Partition identity in Seraph is a GPT type GUID, not a position, label,
or on-disk UUID. The model is:

- **Seraph-minted root GUIDs are arch-distinguished**, following the
  Discoverable Partitions Specification convention. A single disk
  image may carry both an `x86_64` and a `riscv64` root partition;
  the vfsd binary selects by its own compile-time `target_arch`.
  Authoritative GUID values are
  [`SERAPH_ROOT_X86_64`](../abi/boot-protocol/src/role_guids.rs),
  [`SERAPH_ROOT_RISCV64`](../abi/boot-protocol/src/role_guids.rs),
  and the arch-neutral [`SERAPH_DATA`](../abi/boot-protocol/src/role_guids.rs)
  in [`abi/boot-protocol/src/role_guids.rs`](../abi/boot-protocol/src/role_guids.rs).
- **The EFI System Partition is auto-mounted at `/esp`** immediately
  after the root self-mount, using the standard ESP type GUID
  `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`. No caller issues a
  `MOUNT` for `/esp`; vfsd does so internally at startup. ESP mount
  is best-effort and failure is non-fatal.
- **The Seraph data partition is auto-mounted at `/data`** immediately
  after the ESP, using the arch-neutral `SERAPH_DATA` type GUID. vfsd
  mounts it internally at startup, like the ESP. The mount is
  best-effort: when no `SERAPH_DATA` partition is present — or its
  lookup is ambiguous (duplicate tied priority) — vfsd skips the mount
  and `/data` falls through to the root partition, serving any `/data`
  tree present there (or resolving as absent if none). Unlike the root
  self-mount, an absent or ambiguous data partition is never fatal.
  Whether `/data` is a dedicated partition or a root-fs directory is
  therefore a disk-authoring choice, not a vfsd concern; the in-tree
  image (see [build-system.md](build-system.md)) carries the tree on the
  partition only.
- **DPS-style priority tie-break.** Where multiple partitions match
  a role GUID, GPT attribute bits 48–63 are compared as an unsigned
  priority; the highest wins. Tied non-zero priorities are a fatal
  boot error — the configuration is ambiguous and must be repaired.
- **Nothing else binds.** There is no `mounts.conf`, no `/etc/fstab`,
  no kernel command line carrying mount config, no on-disk
  filesystem label or UUID consulted by vfsd. The GUID is the
  binding.

The role-GUID model is the only mount-discovery mechanism. The wire
shape vfsd uses internally (a `MountRole` byte mapped to a type GUID)
is owned by [`services/vfsd/docs/vfs-ipc-interface.md`](../services/vfsd/docs/vfs-ipc-interface.md).

---

## Mount Establishment Lifecycle

Three actors cooperate to bring a filesystem online:

**init** holds one storage-relevant cap after vfsd is spawned: a
`SEED_AUTHORITY`-badged SEND on vfsd's service endpoint (required by
the `GET_SYSTEM_ROOT_CAP` gate). Init issues no `MOUNT` — vfsd
self-mounts root. Init pulls the system root via
`GET_SYSTEM_ROOT_CAP` (which vfsd serves only once root is mounted, so
the call blocks until the root filesystem is up), then distributes
per-child copies on every spawn via
`procmgr_labels::CONFIGURE_NAMESPACE`. Init retains no further
filesystem access of its own.

**vfsd** parses the GPT once at startup, then self-mounts the root
partition: it resolves the arch root GUID, looks the partition up in
its parsed table, registers the partition bound with virtio-blk,
spawns the fs driver, sends `FS_MOUNT` to validate the BPB, and
captures the driver's root cap into the synthetic root (see
[`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md)).
It then auto-mounts the ESP at `/esp` and the data partition at
`/data`. All three run before any service thread serves a request, so
`GET_SYSTEM_ROOT_CAP` never observes an unmounted root. The runtime
`MOUNT` label is retained for explicit / foreign-GUID mounts and shares
this resolution path.

**fs driver** runs as a separate process. After `FS_MOUNT` succeeds,
it serves the cap-native `NS_*` protocol plus the surviving
`FS_*` labels against per-node badged SEND caps on its own
endpoint. The block endpoint it receives is partition-scoped at
delivery time; the fs driver reads and writes by partition-relative
LBA.

### First-mount structural constraint

The first fatfs process is spawned from the boot-module cap, not via
the namespace. `/services/fs/fatfs` is unreachable until root mounts, so the
fatfs that brings root online cannot be spawned from disk —
chicken-and-egg. Subsequent fs-driver respawns walk vfsd's own
held system-root cap to `/services/fs/fatfs` and pass the resulting file cap
to procmgr via `CREATE_FROM_FILE`. The first-mount path is permanent
by structure.

---

## fs ↔ block IPC Contract

The contract between fs drivers and the block driver has three
elements:

- **Two-tier endpoint.** Whole-disk unbadged (vfsd only) versus
  per-partition badged (fs drivers). The block driver distinguishes
  by the kernel-supplied caller badge.
- **Partition-scoped LBA.** Reads and writes carry an LBA relative
  to the caller badge's partition base. The block driver enforces
  the bound on every request.
- **Single-page Frame-cap DMA.** Each read or write transfers one
  Memory cap as the DMA target; the Memory cap is moved back to the caller
  in every reply (success or error). The block driver never retains
  the data Memory cap.

Authoritative wire shapes for `REGISTER_PARTITION`,
`BLK_READ_INTO_MEMORY`, and `BLK_WRITE_FROM_MEMORY` live in
[`services/drivers/virtio/blk/README.md`](../services/drivers/virtio/blk/README.md).
The fs-driver side — `FS_MOUNT`, `FS_READ`, `FS_READ_MEMORY`,
`FS_RELEASE_MEMORY`, `FS_WRITE`, `FS_WRITE_MEMORY`, `FS_CLOSE`, and
the directory-mutation labels — is owned by
[`services/fs/docs/fs-driver-protocol.md`](../services/fs/docs/fs-driver-protocol.md).

DMA safety (IOMMU vs. no-IOMMU policy) is a devmgr concern, not a
storage concern; see [`device-management.md`](device-management.md)
§"DMA Safety Model".

---

## Failure and Revocation Invariants

The supported failure-handling primitives are:

- **fs-driver crash.** vfsd MAY respawn a failed fs driver and
  reinstall the new root cap. Other mounts are unaffected; the
  block driver is unaffected. The respawn path uses
  `CREATE_FROM_FILE` against vfsd's own held system-root cap walked
  to `/services/<driver>`.
- **Mount-tree-wide revocation.** `cap_revoke` on an fs driver's
  namespace endpoint cascades through the kernel derivation graph
  and invalidates every cap ever derived from it: vfsd's retained
  endpoint for the mount, the `MOUNT` caller's copy, and every node
  cap minted for a lookup through that mount. This is the supported
  primitive for "tear down a mount."
- **Per-cap revocation is not supported.** A terminal mount retains
  the driver's unbadged namespace endpoint and mints a fresh
  attenuated cap per lookup; there is no scheme to invalidate one
  issued node cap without cascading to its siblings. See
  [`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md)
  §"Revocation".
- **Unmount is not implemented.** The mount tree is permanent for
  the lifetime of the vfsd process.

---

## What the Storage System Is Not

To prevent inference of behavior that does not exist:

- **No kernel-side filesystem code.** The kernel has no notion of
  files, directories, mounts, or filesystem labels. It transports
  caps and bytes, nothing more.
- **No ambient mount table.** No `/proc/mounts`, no namespace
  inheritance, no kernel mount-table syscall. Mounts are entries in
  vfsd's synthetic root, reachable only via a held cap on vfsd's
  namespace endpoint.
- **No filesystem labels or on-disk UUIDs as identity.** Partition
  identity is the GPT type GUID plus DPS attribute-bit priority.
  Filesystem-level labels (FAT volume label, ext4 superblock UUID,
  etc.) are not consulted by vfsd.
- **No boot-time mount configuration file.** Discovery is GPT-driven
  and arch-conditional; there is no `mounts.conf`, no `/etc/fstab`,
  and no kernel command line carrying mount config.
- **No process-global filesystem authority.** A process delivered no
  namespace cap has no filesystem access; `std::fs` returns
  `Unsupported`. There is no fallback to a system identity.

---

## Summarized By

[README.md](../README.md),
[architecture.md](architecture.md)
