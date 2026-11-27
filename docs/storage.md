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
| Block | `virtio-blk` (one per virtio-blk device devmgr can give an interrupt: an MSI-X vector, else its wired line, a shared `INTx` line included; vfsd binds every instance) | Hardware MMIO, IRQ, descriptor rings |
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
  corrupt another. `vfsd` spawns every fs driver.
- **Block access is partition-scoped at the capability layer.** The
  block driver serves only badged callers: vfsd holds a
  `blk_labels::MOUNT_AUTHORITY`-badged whole-disk cap minted by devmgr for
  each block driver, and fs drivers hold partition-identity-badged caps
  the block driver mints on `REGISTER_PARTITION`; unbadged callers are
  rejected. vfsd is the sole holder of the whole-disk caps while no
  service definition seeds `devmgr.class.block`, and no shipped one
  does: devmgr mints one on `QUERY_DEVICE` only for a caller whose SEND
  is a `block` class SEND, which init requests for vfsd and svcmgr
  publishes seed-only as `devmgr.class.block`. A definition that seeds
  that name gives its service whole-disk authority, `REGISTER_PARTITION`
  included. Out-of-bounds LBAs are rejected by
  the block driver on every request. See
  [`services/drivers/virtio/blk/README.md`](../services/drivers/virtio/blk/README.md).
- **System root is delivered, never discovered.** Every process
  spawned with a namespace receives its authority as
  `ProcessInfo.system_root_cap` installed by
  `procmgr_labels::CONFIGURE_NAMESPACE` on spawn; only init pulls the
  seed, from vfsd via `GET_SYSTEM_ROOT_CAP`.
  There is no ambient mount table and no global lookup.

The cap-as-namespace principles these invariants rest on are
specified in [`namespace-model.md`](namespace-model.md).

---

## Capability Delegation Chain

Storage authority flows from the kernel's initial cap mint outward in
one direction. Each arrow is one capability transfer or request;
revoking a block-layer cap cuts off the partition caps derived
beneath it.

```
kernel (phase 7) mints Mmio caps from BootInfo.mmio_apertures and the root IRQ range cap
  → init delegates Mmio + IRQ caps to devmgr
    → devmgr binds virtio-blk; delegates per-device MMIO + IRQ
      → devmgr creates the block service endpoint and hands it to virtio-blk at spawn
        → vfsd queries devmgr's registry → each disk's blk_labels::MOUNT_AUTHORITY-badged SEND_GRANT
          → vfsd issues REGISTER_PARTITION (whole-disk endpoint of the partition's disk only)
            → virtio-blk mints a partition-badged SEND_GRANT and returns it in the reply
              → vfsd keeps it; spawns fs driver; injects a derivation of it
                → vfsd sends FS_MOUNT; fs driver reads BPB, replies OK
                  → vfsd captures fs driver's root namespace cap
                    → init pulls system root via GET_SYSTEM_ROOT_CAP
                      → init distributes copies via CONFIGURE_NAMESPACE
```

The swap partition takes a shorter branch from the `REGISTER_PARTITION` step: on each
`GET_SWAP_PARTITION` from the holder of the `vfsd.swap` SEND, vfsd cuts off the grant it made
before (revoke its derivations, retire its badge, delete the kept cap), registers the partition
again as a new grant, runs no fs driver on it, and hands the caller a derivation of the new
partition cap
([`services/vfsd/docs/vfs-ipc-interface.md`](../services/vfsd/docs/vfs-ipc-interface.md)
§ Label 14).

The kernel half (BootInfo → Mmio mint → devmgr → driver binding)
is owned by [`device-management.md`](device-management.md). The
phase-7 mint of the root IRQ range cap is owned by
[`capability-model.md`](capability-model.md) §"Initial Capability
Distribution". Badge semantics, derivation, and revocation are owned by
[`capability-model.md`](capability-model.md) §"Badges".

`REGISTER_PARTITION` is rejected unless the caller's badge carries
`blk_labels::MOUNT_AUTHORITY`: only the holder of the devmgr-minted whole-disk cap
can mint a partition binding. vfsd is the only such holder while no
service definition seeds `devmgr.class.block` (§ Invariants): devmgr
mints a whole-disk cap on `QUERY_DEVICE` only for a caller
whose SEND is a `block` class SEND, which init requests for
vfsd and svcmgr publishes seed-only as `devmgr.class.block`. The block driver
enforces the LBA bound on every read and write against the caller's
badge. See
[`services/drivers/virtio/blk/README.md`](../services/drivers/virtio/blk/README.md).

---

## GPT Role-GUID Discovery

Partition identity in Seraph is a GPT type GUID on the boot disk, and a
unique partition GUID a signed statement names on the disk it binds it to,
the boot disk or the disk at a PCI location; never a position on a disk, a
label, or a filesystem UUID. The model is:

- **Seraph-minted root GUIDs are arch-distinguished**, following the
  Discoverable Partitions Specification convention. A single disk
  image may carry both an `x86_64` and a `riscv64` root partition;
  the vfsd binary selects by its own compile-time `target_arch`.
  Authoritative GUID values are
  [`SERAPH_ROOT_X86_64`](../abi/boot-protocol/src/role_guids.rs),
  [`SERAPH_ROOT_RISCV64`](../abi/boot-protocol/src/role_guids.rs),
  and the arch-neutral [`SERAPH_DATA`](../abi/boot-protocol/src/role_guids.rs)
  and [`SERAPH_SWAP`](../abi/boot-protocol/src/role_guids.rs)
  in [`abi/boot-protocol/src/role_guids.rs`](../abi/boot-protocol/src/role_guids.rs).
- **The boot disk is the disk the firmware booted from.** The bootloader
  reports the boot ESP's GPT descriptor (partition number, first LBA,
  size, unique partition GUID) and the PCI location of the controller
  beneath it, which reach vfsd in init's bootstrap round
  ([boot-flow.md](../core/boot/docs/boot-flow.md#step-1-uefi-protocol-discovery),
  [vfs-ipc-interface.md](../services/vfsd/docs/vfs-ipc-interface.md)). After its startup discovery
  (below), vfsd takes as the boot disk the one held disk at that
  location, compared whole, segment included, that carries an
  ESP-type partition matching the descriptor. With no location reported
  (a controller that is no PCI function; the tree has none), the boot disk
  is the one held disk carrying the descriptor. No disk at the location,
  none there carrying the descriptor, or two or more carrying it, and there
  is no boot disk: vfsd logs `no boot disk:` with the reason, the
  reported location and descriptor and each held disk's location, no
  partition takes any role, and the root self-mount fails. The boot disk is
  fixed for the boot.
- **The root and `/esp` resolve on the boot disk alone.** The root is the
  boot disk's partition of the arch root type GUID of the highest
  priority (below); a tie there is a fatal boot error that must be
  repaired, and only the boot disk's own writer can make one. The EFI
  System Partition is the descriptor's partition, auto-mounted at `/esp`
  immediately after the root self-mount and the statement's read; the
  mount is best-effort and its failure non-fatal.
- **Another disk takes a role only by the storage statement.** The
  statement is `/config/vfsd/storage.conf` on the root filesystem
  ([`shared/storage-statement`](../shared/storage-statement/README.md)
  owns its format), signed in the configuration role under its install
  path ([signing.md](signing.md#configuration)). vfsd reads it once per
  boot, through procmgr's verified read, after the root self-mount and
  before the `/esp` and data auto-mounts. Each line names a role's
  partition by the disk it must be on and its unique partition GUID:
  `data <mount path> <disk> <GUID>`, any number at distinct paths, and
  `swap <disk> <GUID>`, at most one. The disk is `boot`, the boot disk
  wherever it is found, or `pci:SSSS:BB:DD.F`, the PCI location devmgr
  reports for a disk, which vfsd logs for each disk it holds after
  `PCI `. A statement that is missing, refused by the verified read, or
  refused whole by the parser is logged and names nothing: every role
  then resolves on the boot disk. A named role takes the named partition
  only, only on the disk the line binds it to (the boot disk, or a held
  disk at the location, compared whole, segment included), and only when
  it carries the role's type GUID. A partition carrying the named GUID on
  any other disk neither takes the role nor denies it. With none on the
  bound disk the role is not taken: vfsd logs that the partition is not
  on its disk, naming the first other disk it saw it on, or that it found
  none; two on the bound disk, or one of another type there, and it is
  not taken either; each is logged and never fatal. A role the statement
  does not name resolves on the boot disk by type GUID and priority.
- **A disk neither the boot disk nor named takes no role**, at any
  priority. vfsd still holds it and parses its GPT, since a partition the
  statement names, or one on a disk added later, may be on it. A copy of
  a named disk at another location takes nothing and denies nothing, and
  a copy of the boot disk is not at the boot controller's location and
  takes nothing. A disk that moves to another location loses the roles
  the statement binds to its old one until the statement names the new
  one.
- **Data partitions are auto-mounted.** After `/esp`, vfsd mounts each data
  partition the statement names at its path, then, unless the statement
  names one for `/data`, the boot disk's `SERAPH_DATA` partition at
  `/data`. Each mount is best-effort: when no partition resolves (none
  present, a tie, or a named partition not on its disk), vfsd skips the mount and
  the path falls through to the root partition, serving any tree present
  there (or resolving as absent if none); never fatal. Whether `/data` is
  a dedicated partition or a root-fs directory is therefore a
  disk-authoring choice, not a vfsd concern; the in-tree image (see
  [build-system.md](build-system.md)) carries the tree on the partition
  only.
- **The swap partition is never mounted.** It carries no filesystem: vfsd
  resolves it, by the statement's `swap` line or else on the boot disk by
  the arch-neutral `SERAPH_SWAP` type GUID, on the first
  `GET_SWAP_PARTITION` request, not at startup, and hands the swap
  service a raw partition cap on it. A boot with no swap partition boots
  as one with: the request then replies `NO_MOUNT`. The in-tree image
  carries one, the last partition of `disk.img`, or of `disk-data.img`
  in the split layout, where the staged statement names it.
- **Every disk is held.** At startup vfsd sends `QUERY_DEVICE` on the block class SEND
  at instance ordinals 0, 1, …, passing a `WITHDRAWN` one (a disk whose
  driver devmgr withdrew when it died), until another reply is not
  `SUCCESS`, holds the whole-disk cap of every block driver devmgr
  serves with the PCI location devmgr reports for its device
  (`QUERY_DEVICE_LOCATION`), and parses each disk's GPT: the primary, or, when the primary's
  header or entry array fails its CRC32 or `MyLBA` check or cannot be read, the backup at the
  disk's last LBA, as UEFI 2.10 § 5.3.2 directs; vfsd writes neither copy. Before a runtime
  `MOUNT` and each `GET_SWAP_PARTITION` resolve their role, vfsd queries again from
  the first ordinal not yet queried and holds each disk devmgr served
  since, a disk added or inserted again after startup among them, so a
  partition the statement names on such a disk is found. A disk neither
  of whose GPT copies can be read and validated contributes no partition.
  The partition's `REGISTER_PARTITION` goes to the block driver of the
  disk that holds it, and each mount and hand-out logs that disk's
  location.
- **DPS-style priority.** Where several of the boot disk's partitions
  carry a role's type GUID, GPT attribute bits 48–63 are compared as an
  unsigned priority; the highest wins. A tie at the highest priority is
  ambiguous: for the root role a fatal boot error that must be repaired;
  the `/data` auto-mount skips the mount, and `GET_SWAP_PARTITION`
  replies `NO_MOUNT`. Priority is read on the boot disk alone: no
  partition of another disk is ranked against the boot disk's.
- **Nothing else binds.** There is no `mounts.conf`, no `/etc/fstab`,
  no kernel command line carrying mount config, no on-disk
  filesystem label or filesystem UUID consulted by vfsd. The boot disk's
  type GUIDs and the signed statement's partition GUIDs are the binding.

**Known limit: the PCI segment.** Bus, device and function agree between
the bootloader's report and devmgr's on every platform: devmgr keeps the
bus numbers the firmware assigned
([pci-enumeration.md](../services/devmgr/docs/pci-enumeration.md)). The
segment is a software number on both sides, the firmware root bridge's
and the one devmgr gives each ECAM range, and the two can differ on a
platform described by a Device Tree alone with more than one ECAM host
bridge whose nodes carry no `linux,pci-domain`. There no disk is at the
reported location, so there is no boot disk and the boot halts. The fix
belongs in how devmgr numbers segments, not in a wider match in vfsd,
which would let a disk at another location stand in for the boot disk.
QEMU `q35` and `virt` under EDK2 describe PCI by MCFG with one segment
and cannot hit it.

The boot disk and the statement are the only mount-discovery mechanism. The
`MOUNT` request's wire shape (a `MountRole` byte and a mount path)
is owned by [`services/vfsd/docs/vfs-ipc-interface.md`](../services/vfsd/docs/vfs-ipc-interface.md).

---

## Mount Establishment Lifecycle

Three actors cooperate to bring a filesystem online:

**init** holds the un-badged vfsd service endpoint it created plus a
`SEED_AUTHORITY`-badged SEND derived from it (required by the
`GET_SYSTEM_ROOT_CAP` gate). Init issues no `MOUNT` — vfsd
self-mounts root; the `vfsd_labels::MOUNT_AUTHORITY`-badged SEND it endows svcmgr
with (published as `vfsd.mount`) reaches only test fixtures, svctest and the
`hotplug-check` disk fixture, each staged by its case. Init pulls the system root via
`GET_SYSTEM_ROOT_CAP` (which vfsd serves only once root is mounted, so
the call blocks until the root filesystem is up, and replies `NO_MOUNT`
if the root self-mount failed), then distributes
per-child copies on every spawn via
`procmgr_labels::CONFIGURE_NAMESPACE`. Init retains no further
filesystem access of its own. The `GET_SYSTEM_ROOT_CAP` contract is
owned by
[`services/vfsd/docs/vfs-ipc-interface.md`](../services/vfsd/docs/vfs-ipc-interface.md).

**vfsd** parses every held disk's GPT once at startup, identifies the
boot disk among them, then self-mounts the root partition: it resolves
the arch root GUID on the boot disk's parsed table, registers the
partition bound with the virtio-blk instance of the boot disk,
spawns the fs driver, sends `FS_MOUNT` to validate the BPB, and
captures the driver's root cap into the synthetic root (see
[`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md)).
It then reads the storage statement and auto-mounts the ESP at `/esp`
and the data partitions (§ GPT Role-GUID Discovery). All of these run
before any service thread serves a request, so `GET_SYSTEM_ROOT_CAP`
never observes an unmounted root. The runtime `MOUNT` label carries a
`MountRole` byte (`Root` or `Data`; any other byte is rejected) and a
mount path, and shares this resolution path.

**fs driver** runs as a separate process. After `FS_MOUNT` succeeds,
it serves the cap-native `NS_*` protocol plus the surviving
`FS_*` labels against per-node badged SEND caps on its own
endpoint, and the labels of an open against the per-open caps its
`FS_OPEN` mints. The block endpoint it receives is partition-scoped at
delivery time; the fs driver reads and writes by partition-relative
LBA. See
[`services/fs/docs/fs-driver-protocol.md`](../services/fs/docs/fs-driver-protocol.md).

### First-mount structural constraint

The first fatfs process is spawned from the boot-module cap, not via
the namespace. `/services/fs/fatfs` is unreachable until root mounts, so the
fatfs that brings root online cannot be spawned from disk —
chicken-and-egg. Every subsequent mount's fs-driver spawn walks vfsd's own
held system-root cap to `/services/fs/fatfs` and passes the resulting file cap
to procmgr via `CREATE_FROM_FILE`. The first-mount path is permanent
by structure. See
[`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md)
§ Two endpoints, one process.

---

## fs ↔ block IPC Contract

The contract between fs drivers and the block driver has four
elements:

- **Two-tier endpoint.** Whole-disk `blk_labels::MOUNT_AUTHORITY`-badged (vfsd;
  § Invariants) versus
  per-partition badged (fs drivers); unbadged callers
  are rejected. The block driver distinguishes by the
  kernel-supplied caller badge.
- **Partition-scoped LBA.** Reads and writes carry an LBA relative
  to the caller badge's partition base. The block driver enforces
  the bound on every request.
- **Caller-supplied Memory-cap DMA.** Each read or write transfers one
  Memory cap of at least `count * block_size` bytes as the DMA target
  (LBAs and counts are in the device's logical blocks); the
  Memory cap is moved back to the caller in every reply (success or
  error). The block driver never retains the data Memory cap. After a
  request the device loses, the driver resets the device before it
  replies and then fails every later read or write with `DeviceFault`;
  if the device does not acknowledge the reset, the driver exits without
  replying and the cap is destroyed with it.
- **Registered DMA regions.** A partition holder may instead register a
  Memory cap as a region (`BLK_REGISTER_REGION`), which the driver keeps,
  mapped for the device, and transfer through the region cap it gets back
  (`BLK_READ_REGION`, `BLK_WRITE_REGION`) with no cap on each request,
  until the region is unregistered (`BLK_UNREGISTER_REGION`, the end of
  the holder's lease, or `BLK_RETIRE_PARTITION`, which whoever revokes a
  partition cap sends on the cap it kept, ending that grant of the
  partition for good).

Authoritative wire shapes for `REGISTER_PARTITION`,
`BLK_READ_INTO_MEMORY`, `BLK_WRITE_FROM_MEMORY`, `BLK_GET_GEOMETRY`, and
the region labels 6 to 10 live in
[`services/drivers/virtio/blk/README.md`](../services/drivers/virtio/blk/README.md).
The fs-driver side — `FS_MOUNT`, `FS_UNMOUNT`, `FS_SESSION`, `FS_OPEN`, `FS_READ`, `FS_READ_MEMORY`,
`FS_RELEASE_MEMORY`, `FS_RELEASE_ACK`, `FS_WRITE`, `FS_WRITE_MEMORY`,
`FS_TRUNCATE`, `FS_CLOSE`, and the directory-mutation labels — is owned by
[`services/fs/docs/fs-driver-protocol.md`](../services/fs/docs/fs-driver-protocol.md).

DMA safety (IOMMU vs. no-IOMMU policy) is a devmgr concern, not a
storage concern; see [`device-management.md`](device-management.md)
§"DMA Safety Model".

---

## Failure and Revocation Invariants

The supported failure-handling primitives are:

- **fs-driver crash.** vfsd observes each driver's death on the
  mount's death queue and restarts the driver of a mount below `/`,
  revoke and re-resolve: it revokes every derivation of the dead
  driver's endpoint, so every cap a client held through the mount
  fails closed, and starts a new driver on the same partition from the
  installed `/services/fs/fatfs`, never from the boot module. Until the
  new driver serves, a lookup into the mount is answered `IoError` and
  its path does not fall through; then clients resolve the path again
  and reach the new driver. Restarts are bounded by a per-mount budget
  (`RESTART_BURST`, 3, per `RESTART_WINDOW_NS`, 60 s;
  [shared/restart-budget](../shared/restart-budget/README.md)); a death
  that finds it spent, or a restart that cannot start the driver, tears
  the mount down: vfsd revokes the partition cap and the driver's
  endpoint, removes the mount, and the path falls through to the root
  filesystem, as after an unmount. The sequence is owned by
  [`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md#driver-restart)
  § Driver restart. Other mounts and the block driver are unaffected.
- **Device loss.** vfsd watches devmgr's `block` class and, on each
  change and each driver death, asks devmgr whether each disk it holds
  is still served. A disk devmgr withdrew is marked removed, its
  partitions leave every role lookup, and each mount on it is torn
  down as a forced unmount, the driver idle or not. A disk inserted
  again is a new device: no mount follows on its own, and the next
  role lookup finds it by asking devmgr first.
- **Loss of the root.** The death of the root filesystem's driver, or
  the loss of its disk, makes vfsd log `FATAL: root filesystem lost`
  and exit; vfsd is critical and never restarted, so svcmgr shuts the
  system down. vfsd's calls that fall through to the root filesystem
  are bounded (10 s each, answered `IoError`), so a root driver that
  stops answering delays a lookup into another mount by that bound for
  each fall-through call queued ahead of it, not indefinitely. The
  sequence is owned by
  [`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md#driver-death-and-device-loss)
  § Driver death and device loss.
- **Block device revocation.** An fs driver learns that its block
  device capability was revoked at its first block request afterwards:
  it answers that request as for any failed block access (`IO_ERROR`,
  or what the label's section names) and exits. Until a request
  reaches the device, an idle driver, or one serving requests from its
  page cache, serves on. A failed block call through a capability
  still live, or an error reply, fails only its request
  ([`services/fs/docs/fs-driver-protocol.md`](../services/fs/docs/fs-driver-protocol.md)
  § Loss of the block device). The driver's exit is then an fs-driver
  crash, as above, unless the request was an `FS_UNMOUNT`, which
  replies success and ends as an unmount (§ Driver exit there).
- **Unmount.** `UNMOUNT`, on the `MOUNT_AUTHORITY` badge, removes a
  mount below `/`. vfsd stops resolving lookups across it and sends the
  driver `FS_UNMOUNT`; the driver refuses an unforced unmount `BUSY`
  while a file is open, and the mount is kept. Otherwise vfsd tears the
  driver down without relying on its answer: it revokes the partition
  cap, revokes the driver's namespace endpoint, waits a bounded time for
  the driver's death and destroys its process. The endpoint's revocation
  cascades through the kernel derivation graph and invalidates every cap
  derived from it: vfsd's caps for the mount, the `MOUNT` caller's copy,
  and every node cap, open file and working directory a client holds
  through the mount. This is the supported primitive for "tear down a
  mount"; the sequence is owned by
  [`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md)
  § Unmount.
- **Fall-through after an unmount.** The unmounted path resolves
  through the root filesystem, as a skipped auto-mount does: lookups
  and listings serve the root partition's directory of the same name,
  or resolve the name as absent when the root partition has none (the
  in-tree image has none for `/data` or `/esp`). Only lookups and
  listings fall through a synthetic node, so nothing is created on the
  root filesystem through one.
- **Stale handles.** A call on a cap that died with its mount fails;
  std reports it as `ErrorKind::StaleNetworkFileHandle`
  ([`runtime/ruststd/README.md`](../runtime/ruststd/README.md)
  § Namespace capabilities). A page-cache page a client mapped stays
  mapped and readable, holding the bytes it held at the unmount, until
  the client unmaps it: memmgr keeps the dead driver's frame while a
  mapping of it remains
  ([`services/memmgr/README.md`](../services/memmgr/README.md)
  § Responsibilities).
- **Per-cap revocation is not supported.** A terminal mount retains
  the driver's unbadged namespace endpoint and mints a fresh
  attenuated cap per lookup; there is no scheme to invalidate one
  issued node cap without cascading to its siblings. See
  [`services/vfsd/docs/namespace-composition.md`](../services/vfsd/docs/namespace-composition.md)
  §"Revocation".

---

## Data at Rest

Pages written to swap are encrypted and authenticated. memmgr seals each chunk it hands the swap
service with ChaCha20-Poly1305 (`shared/crypto`) under a 256-bit key it draws from `SYS_GETRANDOM`
at start, with a nonce it never repeats within a boot, before the bytes leave its own memory, and
checks the tag of every slot handed back before it decrypts it
([`services/memmgr/docs/memory-pool.md`](../services/memmgr/docs/memory-pool.md#disk-tier) § Disk
tier). The key is held by memmgr only: it is never sent, so the swap service, the block driver and
the disk see ciphertext alone. It lives for one boot, so swap holds nothing a later boot can read,
and a slot's bytes open only as the last seal of the chunk that holds it: bytes changed on disk,
another chunk's bytes, or an older seal fail the tag, and the faulting process is killed rather
than handed them.

The rule covers swap alone. Filesystem contents on the root and data partitions are stored as
written; a block-level encrypting service, key derivation and an unlock flow are not part of the
storage system ([#149](https://github.com/kottlerg/seraph/issues/149) D29,
[#152](https://github.com/kottlerg/seraph/issues/152) D32).

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
- **No filesystem labels or filesystem UUIDs as identity.** Partition
  identity is the GPT type GUID plus DPS attribute-bit priority on the
  boot disk, and the GPT unique partition GUID the signed statement names
  on the disk it binds it to. Filesystem-level labels (FAT volume label, ext4
  superblock UUID, etc.) are not consulted by vfsd.
- **No unsigned mount configuration.** The one configuration file is the
  storage statement, signed in the configuration role, which only names
  partitions for roles; there is no `mounts.conf`, no `/etc/fstab`,
  and no kernel command line carrying mount config.
- **No role from a disk's own say-so.** A disk other than the boot disk
  takes no role by its type GUIDs or priority bits, whatever they are;
  only the statement gives it one, and only on the disk it names: a
  partition's unique GUID and type, which any disk can copy, take a named
  role only at the location the statement binds it to. The location is
  where the disk sits, not a property the disk proves: a disk placed at
  that location while the named one is absent takes its roles
  ([threat-model.md](threat-model.md) § Disk Images).
- **No process-global filesystem authority.** A process delivered no
  namespace cap has no filesystem access; `std::fs` returns
  `Unsupported`. There is no fallback to a system identity. See
  [`runtime/ruststd/README.md`](../runtime/ruststd/README.md).

---

## Summarized By

[Architecture Overview](architecture.md), [Boot Media](boot-media.md),
[System Bootstrap](bootstrap.md), [Build System](build-system.md),
[Supervision](supervision.md),
[rootfs/README.md](../rootfs/README.md),
[services/drivers/README.md](../services/drivers/README.md),
[services/drivers/virtio/blk/README.md](../services/drivers/virtio/blk/README.md),
[services/fs/README.md](../services/fs/README.md),
[init Bootstrap Stages](../services/init/docs/bootstrap.md),
[services/vfsd/README.md](../services/vfsd/README.md),
[vfsd Service Interface](../services/vfsd/docs/vfs-ipc-interface.md),
[xtask/README.md](../xtask/README.md)
