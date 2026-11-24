# Boot Media

Where the one real copy of every shipped object lives, what the EFI System Partition (ESP) holds
in relation to it, and for how long an object loaded from the ESP runs.

---

## Scope

This document is authoritative for:

- The installed copy: where the real copy of a shipped object lives, and when it is signed.
- The ESP as derived state: what it holds, and how it is composed from installed files.
- The bootstrap closure: which objects the bootstrap bundle carries.
- The lifetime of a boot copy: what runs from the bundle, and what the loss of the root
  filesystem's support means.
- The constraints this model sets for the root filesystem type, encryption at rest, Secure Boot
  and update, which the work that owns each meets.

The formats and the verification of signed objects are specified in [signing.md](signing.md),
the bundle's wire format in [`abi/boot-protocol::bundle`](../abi/boot-protocol/src/bundle.rs),
the sysroot and the disk images in [build-system.md](build-system.md) § Build Output: the
Sysroot, the userspace boot order in [process-lifecycle.md](process-lifecycle.md), and the root
mount in [storage.md](storage.md).

---

## Implementation Status

Partly implemented. Implemented: every shipped object, the kernel (`/boot/kernel`) and the
bootloader (`/boot/boot.efi`) included, is installed on the root filesystem at its install path,
and every signed one is signed there once, with the set of roles it may be loaded in
([signing.md](signing.md) § Signing); every pack composes the ESP from the installed files, so
each object on it is its installed file byte for byte, and the composition copies files, signs
nothing and reads no key; the bundle's entries are chosen by a list per harness in configuration
(`/config/bundle/`), and every entry other than `init` is named by its install path; every pack
checks, once it has composed the ESP, that each object on it equals its installed file, and
the pack then checks the same of the image it wrote, its ESP against the installed files
(§ The ESP); the
bootloader refuses an entry without the boot-module role, or, under `/config/` (a platform table
excepted), without the configuration role, and a bundle without the boot-time policy
`/config/boot/policy.conf` ([signing.md](signing.md) § Configuration); the default bundle is the
bootstrap closure, the consoles' drivers and the platform description tables loaded from the root
filesystem (§ The Bootstrap Closure); the bundle is used during bootstrap alone, apart from the
IOMMU driver's image, which devmgr keeps for the driver's restart (§ Bootstrap-Only Boot Copies);
the loss of the root filesystem's driver or of its disk is system death; and the ESP holds no
secret.

The policy-bearing configuration files are signed in the configuration role, and each is verified
before its consumer parses it ([signing.md](signing.md) § Configuration).

---

## Installed Copies

Every shipped object has one real copy: a file on the root filesystem at its install path. The
kernel and the bootloader are included. An object that is signed is signed when it is built or
packaged, never on the machine that runs it, so no signing key is ever needed on that machine.
Every other copy of the object (on the ESP, in the bundle, in memory) is a byte copy of the
installed file, made by a step that needs no key.

The signature belongs to the object, not to the place it is copied to: an object has one
identity, signed once, under its install path, with the set of roles it may be loaded in
([signing.md](signing.md) § Signed Attributes). A copy therefore verifies wherever it lies as
the installed file does. The kernel and the object in the bundle's `init` slot are signed under
their slot names, `kernel` and `init`, since the bootloader loads them by slot, not by path.

---

## The ESP

The ESP is derived state. It holds the bootloader (at `\EFI\seraph\boot.efi` and at the UEFI
fallback path), the kernel (`\EFI\seraph\kernel`), and the bootstrap bundle
(`\EFI\seraph\bootstrap.bundle`), whose entries are byte copies of installed files chosen by a
list in configuration. Beside them it holds only the bootloader's presence-only knobs, which
carry no content ([bootstrap.md](bootstrap.md)), and, when one is staged, a trust request
(`\EFI\seraph\trust-request`), which changes the trust store the bootloader keeps in firmware
storage ([signing.md](signing.md) § Trust Store).

Composing the ESP copies files. It never signs, needs no key, and writes nothing secret: every
object on the ESP is signed and public, and the trust stores the bootloader verifies against are
built into it or kept in firmware storage ([signing.md](signing.md) § Trust Store). The build
composes the ESP this way, and so does any later recomposition on a running system. The list names
only objects that carry the boot-module role, or, under `/config/` (a platform table excepted), the
configuration role; the bootloader refuses an entry without it, so writing the list cannot make an
object bootable that its signer did not permit.

An ESP whose objects all equal their installed files verifies as those files do. Composition
checks that equality once it has written the ESP, and refuses an ESP it cannot establish it for:
one whose object is missing, differs from its installed file or copies one that is not installed,
whose bundle holds an entry its list does not name or lacks one it names, or that holds any other
file than an empty presence-only knob in `\EFI\seraph\` or a trust request at
`\EFI\seraph\trust-request`. Once it has written the disk image, the
pack makes the same check of the image, its ESP against the installed files (those of its root
partition, or the sysroot's for the kernel layer's image, whose root and data partitions hold no
file), read back by xtask's FAT reader, after `fsck.fat -n` has checked every FAT volume of
it, so a pack that wrote one side alone, or wrote a volume an independent reader refuses, fails
([xtask/README.md](../xtask/README.md#the-image-check) § The image check).

---

## The Bootstrap Closure

The bundle is the bootstrap closure: what is needed to reach the root filesystem and begin
loading from it, and nothing else. On the default boot that is:

- `init`, which starts the bootstrap services, and the log-level configuration it reads before
  the root is mounted;
- the boot-time policy, `/config/boot/policy.conf`, which every bundle carries: the bootloader
  refuses a bundle without it ([signing.md](signing.md) § Configuration);
- memmgr and procmgr, which init loads itself, and devmgr and vfsd, which it starts through
  procmgr ([process-lifecycle.md](process-lifecycle.md) § Userspace Boot Order);
- the IOMMU driver of the architecture, which devmgr binds before any DMA-capable driver maps a
  ring ([driver-binding.md](driver-binding.md) § Matching);
- the driver of the root filesystem's disk (`virtio-blk`) and the root filesystem's driver
  (`fatfs`).

A test harness in the `init` slot (ktest) is its own closure together with the boot-time policy
every bundle carries. Anything else is loaded from the root filesystem once vfsd has mounted it: by
svcmgr from its recipes, by devmgr from `/services/drivers/`, the serial and framebuffer drivers of
the consoles included, by vfsd from `/services/fs/`. Each is verified before it is used: an image by
procmgr as it creates the process, and a data file by procmgr at its reader's request, the platform
description tables devmgr reads from `/config/devmgr/platform/` among them
([driver-binding.md](driver-binding.md) § Platform Description Tables) and svcmgr's recipes and
class files, in the configuration role ([signing.md](signing.md) § Configuration). An object outside
the closure costs memory on every boot and is a second path by which the same object starts.

Until the root mount, the only console is init-logd's: it writes the UART directly, and the
kernel's console stays on a framebuffer, since no driver has claimed it
([console-model.md](console-model.md)). A boot whose root does not mount therefore reports the same
lines on serial as one with the consoles' drivers in the bundle, and leaves the kernel's console on
the screen of a machine with a framebuffer alone. A table that describes a device the root mount
needs would be a bundle entry ([driver-binding.md](driver-binding.md) § Platform Description
Tables); none in the tree does.

---

## Bootstrap-Only Boot Copies

A bundle copy runs only during bootstrap, the IOMMU driver's aside (below), and its memory is
returned when bootstrap ends: each consumer deletes its copy of a module once it has started the
process (vfsd its `fatfs` copy after the root mount, devmgr each driver module after its IOMMU and
boot passes), and init donates the modules' sources to memmgr at its reap
([process-lifecycle.md](process-lifecycle.md) § Init reap).

Every later start of an object, a restart of the IOMMU driver aside (below), is from its installed
path, a further instance of a driver that also booted included: vfsd starts `fatfs` from the
bundle for the root mount alone and from `/services/fs/fatfs` for every later mount
([storage.md](storage.md) § First-mount structural
constraint), and devmgr starts a driver from its bundle copy in its IOMMU and boot passes alone, and
from the root filesystem in every later pass, a hot-added device's included
([driver-binding.md](driver-binding.md) § Declaration Bounds, Source). A
restart of a driver by devmgr ([devmgr responsibilities § Driver
Restart](../services/devmgr/docs/responsibilities.md#driver-restart)) or of a filesystem driver
([namespace composition § Driver
restart](../services/vfsd/docs/namespace-composition.md#driver-restart)) is a later start.

The IOMMU driver is the one exception. devmgr copies the driver's boot-module image into pages it
allocates before it releases the module, keeps the copy for the boot, and starts every restart of
the driver from it ([device-management.md](device-management.md#iommu-driver-restart) § IOMMU
Driver Restart): a read of the driver's installed file needs a `DMA_MAP` of the block driver's
buffer, which needs the IOMMU driver. The copy is a second real copy, the image rounded up to whole
pages ([limits.md](limits.md)), kept in memory for the life of the system, and an update of the
installed file does not reach a restarted IOMMU driver before the next boot.

Loss of what the root filesystem stands on is fatal: the root filesystem's driver and the driver
of the disk under it are never restarted, and the root is not remounted in a running system. No
other image is kept from boot for a restart, since a copy kept for that purpose would be a second
real copy, kept in memory for the life of the system, that no update of the installed file
reaches. vfsd ends on the death of the root mount's driver or the loss of its disk, and its death is
system death ([storage.md](storage.md) § Failure and Revocation Invariants;
[supervision.md](supervision.md) § Core Set and System Death); devmgr's restart of a driver
(vfsd declines it for the root disk's driver) and vfsd's restart of a mount's driver
(namespace composition § Driver restart) exclude both drivers.

---

## Constraints on Later Work

The model sets these constraints for work it does not design. Each is met by the work named.

- **A root filesystem other than FAT.** The ESP stays FAT, as the firmware requires. The bundle
  list names the root filesystem type's driver in place of `fatfs`, and `fatfs` is then started
  only from the root filesystem, to mount the ESP and any other FAT volume. vfsd selects the
  driver by its declaration and carries no knowledge of `fatfs`
  ([#884](https://github.com/kottlerg/seraph/issues/884)).
- **Encryption at rest.** The ESP holds only signed, public objects. An encrypted root is
  unreadable until it is unlocked, so the unlock stage belongs to the bootstrap closure, and its
  key comes from outside the disk (a TPM against the measured chain, the console, a token), never
  from the ESP. Configuration read before the unlock is on the ESP, a bundle entry the
  bootloader verifies ([signing.md](signing.md) § Configuration).
- **Secure Boot.** Firmware verifies the bootloader, the bootloader verifies the kernel and each
  bundle entry, and procmgr verifies every later file; a copied ESP verifies as the installed
  files do ([signing.md](signing.md) § Secure Boot).
- **Update.** Composition on the machine is the same copy-only step the build runs. Between an
  update of the root filesystem and the recomposition of the ESP the two can disagree, which the
  updater detects ([#683](https://github.com/kottlerg/seraph/issues/683)). The release key never
  needs to be on a machine, since nothing is signed there
  ([#1073](https://github.com/kottlerg/seraph/issues/1073)).
- **Anti-rollback and enrolment.** A composed ESP is as old as the installed files it copies, so
  the floor that refuses an older image is not state composition writes: the bootloader keeps it in
  firmware storage ([signing.md](signing.md) § Rollback Floor). Nor is a root enrolled without
  rebuilding the bootloader ([#1074](https://github.com/kottlerg/seraph/issues/1074)).

---

## Summarized By

[System Bootstrap](bootstrap.md), [Build System](build-system.md),
[Driver Binding](driver-binding.md), [Process Lifecycle](process-lifecycle.md),
[Signing and Chain of Trust](signing.md), [Supervision](supervision.md)
