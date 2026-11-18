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

Partly implemented. Implemented: every service, driver, filesystem driver, program and test image is
installed on the root filesystem at its install path and signed there ([signing.md](signing.md) §
Signing); the bundle's executables are read from those installed images; the bundle is used during
bootstrap alone (§ Bootstrap-Only Boot Copies); the loss of the root filesystem's driver or of its
disk is system death; and the ESP holds no secret.

Design intent, not yet implemented:

- The kernel and the bootloader have no installed copy: they exist only on the ESP
  ([#1264](https://github.com/kottlerg/seraph/issues/1264)).
- A bundle entry is not a copy of its installed file: xtask signs it again as it composes the
  bundle, as a boot module under a short entry name, so the entry and the installed file differ
  in their trailers ([#1263](https://github.com/kottlerg/seraph/issues/1263)).
- The bundle is chosen by lists in xtask (`xtask/src/bundle.rs`), not by a list in
  configuration ([#1264](https://github.com/kottlerg/seraph/issues/1264)).
- The bundle's data entries (the log-level configuration and the platform description tables)
  are read from the repository and have no installed copy
  ([#1263](https://github.com/kottlerg/seraph/issues/1263)).
- No step checks that the ESP's objects equal their installed files
  ([#1265](https://github.com/kottlerg/seraph/issues/1265)).
- The bundle carries more than the bootstrap closure: the serial and framebuffer drivers and,
  on riscv64, the platform description table, none of which the root mount needs
  ([#1267](https://github.com/kottlerg/seraph/issues/1267)). A table leaves the bundle only once
  the tables devmgr reads from the root filesystem are verified, which #1267 builds.

---

## Installed Copies

Every shipped object has one real copy: a file on the root filesystem at its install path. The
kernel and the bootloader are included. An object that is signed is signed when it is built or
packaged, never on the machine that runs it, so no signing key is ever needed on that machine.
Every other copy of the object (on the ESP, in the bundle, in memory) is a byte copy of the
installed file, made by a step that needs no key.

The signature belongs to the object, not to the place it is copied to: an object has one
identity, signed once, under its install path, with the set of roles it may be loaded in
(design intent, [#1263](https://github.com/kottlerg/seraph/issues/1263);
[signing.md](signing.md) § Signed Attributes). A copy therefore verifies wherever it lies as
the installed file does. The kernel and the object in the bundle's `init` slot are signed under
their slot names, `kernel` and `init`, since the bootloader loads them by slot, not by path.

---

## The ESP

The ESP is derived state. It holds the bootloader (at `\EFI\seraph\boot.efi` and at the UEFI
fallback path), the kernel (`\EFI\seraph\kernel`), and the bootstrap bundle
(`\EFI\seraph\bootstrap.bundle`), whose entries are byte copies of installed files chosen by a
list in configuration. Beside them it holds only the bootloader's presence-only knobs, which
carry no content ([bootstrap.md](bootstrap.md)).

Composing the ESP copies files. It never signs, needs no key, and writes nothing secret: every
object on the ESP is signed and public, and the trust store the bootloader verifies against is
built into the bootloader ([signing.md](signing.md) § Trust Store). The build composes the ESP
this way, and so does any later recomposition on a running system. The list names only objects
that carry the boot-module role; the bootloader refuses an entry without it, so writing the list
cannot make an object bootable that its signer did not permit (design intent,
[#1263](https://github.com/kottlerg/seraph/issues/1263)).

An ESP whose objects all equal their installed files verifies as those files do. Composition
checks that equality, and refuses an ESP it cannot establish it for (design intent,
[#1265](https://github.com/kottlerg/seraph/issues/1265)).

---

## The Bootstrap Closure

The bundle is the bootstrap closure: what is needed to reach the root filesystem and begin
loading from it, and nothing else. On the default boot that is:

- `init`, which starts the bootstrap services, and the log-level configuration it reads before
  the root is mounted;
- memmgr and procmgr, which init loads itself, and devmgr and vfsd, which it starts through
  procmgr ([process-lifecycle.md](process-lifecycle.md) § Userspace Boot Order);
- the IOMMU driver of the architecture, which devmgr binds before any DMA-capable driver maps a
  ring ([driver-binding.md](driver-binding.md) § Matching);
- the driver of the root filesystem's disk (`virtio-blk`) and the root filesystem's driver
  (`fatfs`).

A test harness in the `init` slot (ktest) is its own closure. Anything else is loaded from the root
filesystem once vfsd has mounted it: by svcmgr from its recipes, by devmgr from
`/services/drivers/`, by vfsd from `/services/fs/`. Each is verified before it is used: an image by
procmgr as it creates the process, and a data file by procmgr at its reader's request, a platform
description table devmgr reads among them ([driver-binding.md](driver-binding.md) § Platform
Description Tables; design intent: [#1267](https://github.com/kottlerg/seraph/issues/1267) for the
tables, [#1071](https://github.com/kottlerg/seraph/issues/1071) for the other policy-bearing files).
An object outside the closure costs memory on every boot and is a second path by which the same
object starts.

---

## Bootstrap-Only Boot Copies

A bundle copy runs only during bootstrap, and its memory is returned when bootstrap ends: each
consumer deletes its copy of a module once it has started the process (vfsd its `fatfs` copy after
the root mount, devmgr each driver module after its IOMMU and boot passes), and init donates the
modules' sources to memmgr at its reap ([process-lifecycle.md](process-lifecycle.md) § Init reap).

Every later start of an object is from its installed path, a further instance of a driver that also
booted included: vfsd starts `fatfs` from the bundle for the root mount alone and from
`/services/fs/fatfs` for every later mount ([storage.md](storage.md) § First-mount structural
constraint), and devmgr starts a driver from its bundle copy in its IOMMU and boot passes alone, and
from the root filesystem in every later pass, a hot-added device's included
([driver-binding.md](driver-binding.md) § Declaration Bounds, Source). A
restart of a driver or a filesystem driver ([#1077](https://github.com/kottlerg/seraph/issues/1077),
[#1078](https://github.com/kottlerg/seraph/issues/1078)) is a later start.

Loss of what the root filesystem stands on is fatal: the root filesystem's driver and the driver
of the disk under it are never restarted, and the root is not remounted in a running system. No
image is kept from boot for a restart, since a copy kept for that purpose would be a second real
copy, kept in memory for the life of the system, that no update of the installed file reaches.
vfsd ends on the death of the root mount's driver or the loss of its disk, and its death is
system death ([storage.md](storage.md) § Failure and Revocation Invariants;
[supervision.md](supervision.md) § Core Set and System Death); the restarts of
[#1077](https://github.com/kottlerg/seraph/issues/1077) and
[#1078](https://github.com/kottlerg/seraph/issues/1078) exclude both drivers.

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
  from the ESP. Configuration read before the unlock is on the ESP; its signing is
  [#1071](https://github.com/kottlerg/seraph/issues/1071).
- **Secure Boot.** Firmware verifies the bootloader, the bootloader verifies the kernel and each
  bundle entry, and procmgr verifies every later file; a copied ESP verifies as the installed
  files do ([signing.md](signing.md) § Secure Boot;
  [#1075](https://github.com/kottlerg/seraph/issues/1075)).
- **Update.** Composition on the machine is the same copy-only step the build runs. Between an
  update of the root filesystem and the recomposition of the ESP the two can disagree, which the
  updater detects ([#683](https://github.com/kottlerg/seraph/issues/683)). The release key never
  needs to be on a machine, since nothing is signed there
  ([#1073](https://github.com/kottlerg/seraph/issues/1073)).
- **Anti-rollback and enrolment.** A composed ESP is as old as the installed files it copies, so
  the floor that refuses an older image is not state composition writes
  ([#1070](https://github.com/kottlerg/seraph/issues/1070)); nor is a root enrolled without
  rebuilding the bootloader ([#1074](https://github.com/kottlerg/seraph/issues/1074)).

---

## Summarized By

[System Bootstrap](bootstrap.md), [Build System](build-system.md),
[Driver Binding](driver-binding.md), [Process Lifecycle](process-lifecycle.md),
[Signing and Chain of Trust](signing.md), [Supervision](supervision.md)
