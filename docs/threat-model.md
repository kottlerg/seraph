# Threat Model

The system's trust boundaries: for each, the attacker it faces, the assets it protects, what it
assumes, the mitigations in place, the fuzz targets and proof harnesses that cover it, and its gaps.

---

## Scope

This document is authoritative for the list of the system's trust boundaries, the attacker each one
is held against, and the inventory of each boundary's mitigations, coverage and gaps. It specifies
no mechanism: each mitigation is owned by the document it links, which stays authoritative for it,
and by the code it names. The trust boundaries are:

- the syscall interface, between a process and the kernel;
- IPC handlers, between a client and a service;
- disk images, between storage and the services that parse it;
- ELF loading, between an image's bytes and the process that runs it;
- the boot handover, between the bootloader, the kernel and init;
- devices, between a device or its driver and the rest of the machine;
- the boot chain's signatures, between storage and the code that runs.

Each boundary's section names its **Attacker**, its **Assets**, its **Assumptions**, its
**Mitigations** with the files that implement them, its **Fuzz targets and proof harnesses**
(`cargo xtask fuzz` and `cargo xtask kani`, [testing.md](testing.md) § Fuzzing and § Bounded
verification), and its **Gaps**. A gap is a way the attacker can still reach an asset, or a part of
the boundary that no test or proof covers. § Attackers Out of Scope lists the attackers no section
is held against yet. The files a section's Mitigations and Fuzz targets and proof harnesses name
in backticks, and the files under a directory they name, are the scope of the section's threat
audit ([conventions.md](conventions.md) § Threat audit); a mitigation that names no file is a
defect of this document.

Implementation status: every section is provisional until the hardening milestone, v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)), audits the whole attack surface against
this document and removes this note. Until then a section records the boundary as the code on
`master` builds it; a mitigation or a coverage item named as planned, with its Issue, is design
intent, not yet implemented.

### System-wide assumptions

- Firmware, the bootloader once it runs, the kernel, init, memmgr and procmgr execute as built
  ([signing.md](signing.md) § Threat Model). Every other process is verified by procmgr before it
  runs, and runs only with the capabilities it was given.
- No attacker holds a private key the system's trust store trusts.
- The hardware behaves as its specifications state, apart from the microarchitectural channels
  § Syscall Interface lists and the device behaviour § Devices lists.

---

## Syscall Interface

Implementation status: provisional until v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)).

**Attacker.** Any process, running code of its choice, with the capabilities it holds. It chooses
every syscall argument, the contents of its IPC buffer page and of every page it maps, and the
timing of its calls on any number of threads and CPUs.

**Assets.** The kernel's memory and control flow; every kernel object the process holds no
capability to, and every right a capability it holds does not carry; the randomized kernel layout;
the kernel's random state.

**Assumptions.** The CPU enforces privilege levels, page permissions and the supervisor access
controls below as specified.

**Mitigations.**

- Capabilities are the only access control: a process names a kernel object only through a
  capability slot of its own CSpace, a derived capability carries at most its source's rights, and a
  badge is set once and propagates unchanged ([capability-model.md](capability-model.md) § Rights
  and Attenuation, § Badges; `core/kernel/src/cap/`).
- A capability lookup's index bound, occupancy, generation, type and rights are enforced as data as
  well as by branch, so a mispredicted path resolves no object it should not
  ([capability-model.md](capability-model.md) § Capability Spaces, Bounded under speculation;
  `nospec::index_mask` in `core/kernel/src/cap/cspace.rs`, `pin_checked` in
  `core/kernel/src/syscall/mod.rs`, `core/kernel/src/arch/nospec.rs`).
- User memory is reached only through the fault-recovering copies of `core/kernel/src/uaccess.rs`,
  which open the SMAP window on x86-64 and `sstatus.SUM` on riscv64 for the copy alone; outside them
  the kernel can neither execute nor access user pages ([memory-model.md](memory-model.md) § Kernel
  Isolation — SMEP and SMAP; `core/kernel/src/arch/x86_64/cpu.rs`,
  `core/kernel/src/arch/riscv64/cpu.rs`). Each handler checks, in its own code, that the user span
  it copies lies in the user half: against `mm::user_va_top()` before the copy (for example the
  bitmap of `sys_aspace_harvest` in `core/kernel/src/syscall/mem.rs`), or, for the IPC buffer, when
  `SYS_IPC_BUFFER_SET` registers it (`core/kernel/src/syscall/mod.rs`). `mm::user_page_range`
  (`core/kernel/src/mm/mod.rs`) is the matching check of the page range a memory syscall maps,
  unmaps, protects or harvests.
- No page is writable and executable at once, kernel image included, apart from the AP trampoline
  page during bring-up ([memory-model.md](memory-model.md) § W^X Enforcement; `map_permissions` in
  `core/kernel/src/syscall/mem.rs`, `map_kernel_image` and `map_ap_trampoline` in
  `core/kernel/src/mm/paging.rs`).
- The kernel's virtual layout is randomized, and no value the kernel emits carries a kernel virtual
  address; the accepted residual is the descriptor-table registers on an x86-64 CPU without UMIP
  ([Kernel Cross-Boundary Disclosure Inventory](../core/kernel/docs/cross-boundary-disclosure.md);
  the bootloader chooses and applies the layout, `choose_kaslr_layout` and
  `step5d_apply_kaslr_slide` in `core/boot/src/main.rs`).
- On x86-64 the kernel enumerates the running CPU's exposure to each transient-execution class at
  the user-to-kernel boundary and applies the entry and exit controls it selects; a class the
  selection leaves open is logged as vulnerable
  ([core/kernel/docs/transient-execution.md](../core/kernel/docs/transient-execution.md);
  `core/kernel/src/arch/x86_64/vulnerability.rs`, `core/kernel/src/arch/x86_64/mitigation.rs`).
- Kernel stacks have guard pages, and on x86-64 a CET supervisor shadow stack checks every kernel
  return where the CPU reports `CET_SS` and no transient-execution control the kernel selected
  rewrites a return
  ([core/kernel/docs/return-address-integrity.md](../core/kernel/docs/return-address-integrity.md);
  `core/kernel/src/mm/stack_guard.rs`, `core/kernel/src/arch/x86_64/shadow_stack.rs`).
- `SYS_GETRANDOM` is draw-only and forward secret across the boundary, and the one path that adds to
  the entropy pool needs an `EntropyControl` capability carrying `Contribute`
  ([core/kernel/docs/entropy.md](../core/kernel/docs/entropy.md) § Scope and threat model;
  `core/kernel/src/syscall/entropy.rs`).

**Fuzz targets and proof harnesses.** None covers this boundary: no fuzz target drives a syscall,
and no proof harness covers a syscall's argument checks or a capability lookup.

**Gaps.**

- The user-half check of a copied span is made in each handler's own code; no type carries a checked
  span, and the copies themselves do not check it (`core/kernel/src/uaccess.rs`). SMAP and `SUM` do
  not stop a kernel-half address, so a handler that omits the check copies kernel memory.
- On riscv64 the data bounds of the capability lookup are the only transient-execution defence: the
  RVA23 floor defines no speculation control
  ([core/kernel/docs/transient-execution.md](../core/kernel/docs/transient-execution.md) § Scope).
- The x86-64 transient-execution controls are not yet validated on affected hardware
  ([#1123](https://github.com/kottlerg/seraph/issues/1123)), and the CET shadow stack not on AMD
  parts or bare metal ([#1124](https://github.com/kottlerg/seraph/issues/1124),
  [#1160](https://github.com/kottlerg/seraph/issues/1160)). riscv64 kernel shadow stacks are design
  intent, not yet implemented ([#1154](https://github.com/kottlerg/seraph/issues/1154)).
- Cache-based side channels outside the transient-execution classes, frequency-scaling channels and
  Rowhammer are accepted and unmitigated ([capability-model.md](capability-model.md)
  § Microarchitectural Isolation).

---

## IPC Handlers

Implementation status: provisional until v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)).

**Attacker.** A process holding a SEND capability on a service's endpoint, running code of its
choice: a program, or a service compromised through another boundary. It chooses the label, the data
words, the capabilities a message carries and the memory it lends; it cannot choose the badge the
server receives. The same attacker can sit on the server side of a call a trusted process makes (a
file server answering devmgr), and then chooses the reply.

**Assets.** The service's memory, state and availability to its other clients; the capabilities it
holds; the objects and data of its other clients.

**Assumptions.** The kernel delivers messages and badges as § Syscall Interface states. Every
service executes as built, since procmgr verified it.

**Mitigations.**

- A message is a label, at most `MSG_DATA_WORDS_MAX` data words and at most `MSG_CAP_SLOTS_MAX`
  capabilities, copied by the kernel from the sender's registers or IPC buffer page into the
  receiver's: a received message does not change under the server ([ipc-design.md](ipc-design.md)
  § Message Format; `read_data_words`, `deliver_data_words` and `transfer_caps` in
  `core/kernel/src/syscall/ipc.rs`).
- A server identifies a client by the kernel-delivered badge, which only the server and its trusted
  minters choose, and gates its privileged labels on verb bits of that badge; an un-badged source
  stays with the server and its trusted minters ([capability-model.md](capability-model.md)
  § Badges). A partition's block-device badge, for example, bounds every transfer to the partition
  (`resolve_lba` in `services/drivers/virtio/blk/src/main.rs`).
- A service's blocking receive loop routes its failures through `ipc::recv_guard::RecvGuard`, which
  backs off and ends the process when a failure persists, so a wedged receive cannot spin
  ([ipc-design.md](ipc-design.md) § Receive-Failure Policy; `shared/ipc/src/recv_guard.rs`).
- The variable-length wire formats are decoded by code the sender and the receiver share, in
  `shared/ipc` (`log_record.rs`, `log_query.rs`, `procmgr_snapshot.rs`, `memmgr_capture.rs` and the
  label modules), `shared/namespace-protocol` and `shared/hwrng-protocol`.

**Fuzz targets and proof harnesses.** None on `master`. Planned: property functions, fuzz targets
and proof harnesses for the decoders of `shared/ipc`, `shared/namespace-protocol` (`gate_open`,
`compose_forward_lookup_rights`, `validate_name`) and `shared/hwrng-protocol` (`decode_reply`,
`requested_len`), in [#680](https://github.com/kottlerg/seraph/issues/680) and
[#756](https://github.com/kottlerg/seraph/issues/756).

**Gaps.**

- No decoder of this boundary has a property function, a fuzz target or a proof harness yet.
- Each server's dispatcher checks its own labels, word counts, versions and badges; no shared layer
  checks them, and no review has yet covered every label of every service against this attacker. The
  audit of this section ([#680](https://github.com/kottlerg/seraph/issues/680)) is the first.
- gdbstub's fault receiver retries a failed receive every 10 ms without `RecvGuard`
  (`start_receiver` in `services/gdbstub/src/main.rs`), against [ipc-design.md](ipc-design.md)
  § Receive-Failure Policy; only kernel-delivered faults reach its endpoint
  ([#1534](https://github.com/kottlerg/seraph/issues/1534)).
- No standard governs how a server reads a structure from memory a client lent it and can still
  write, so a check and a later read of the same bytes can see different values.

---

## Disk Images

Implementation status: provisional until v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)).

**Attacker.** Anyone who can write a disk the system reads: its partition table, and every block of
a filesystem on it ([signing.md](signing.md) § Threat Model, the same storage writer).

**Assets.** The integrity and availability of vfsd and of each filesystem driver; the blocks of the
other partitions and disks; the boot, which needs the root filesystem mounted.

**Assumptions.** The block driver and its device return the blocks the disk holds (§ Devices covers
a device that does not). Executables and policy files on a filesystem are signed and verified before
use (§ Boot-Chain Signatures), so this boundary is about the parsers, not about what the files say.

**Mitigations.**

- The GUID Partition Table is decoded by a pure crate, `services/vfsd/gpt`: `parse_header` checks a
  header's signature, size, CRC32 and `MyLBA`, and refuses a block size, an entry size, or an entry
  array that neither starts at LBA 2 or later and ends by `first_usable_lba` nor starts after
  `last_usable_lba` and ends by the header's own LBA, for either copy; `parse_entry` refuses an
  inverted or overflowing range; `collect_partitions` checks exactly the header's entry count and
  the array's CRC32, and stops at a failed read; `read_gpt` reads the backup GPT at the disk's last
  LBA only when the primary fails. A CRC32 detects a corrupt table, not this attacker, who
  recomputes it.
- A filesystem driver reaches its disk through a block-device capability badged for its partition:
  the block driver refuses every transfer outside the partition or past the device's capacity, and
  refuses to register a partition past that capacity (`resolve_lba`, `handle_register_partition` in
  `services/drivers/virtio/blk/src/main.rs`).
- The FAT decoders are a pure crate, `services/fs/fat/fat-parse`: `parse_bpb_geometry` refuses a bad
  signature, a zero divisor, a sector size other than the device's, FAT12 and an inconsistent
  geometry; `is_data_cluster` bounds every cluster number read from disk to the data region. fatfs
  bounds a directory's chain walk to the volume's cluster count, and a file's to the clusters before
  the offset it reads, so a cyclic chain ends (`services/fs/fat/src/dir.rs`, `read_file_data` in
  `services/fs/fat/src/fat.rs`).

**Fuzz targets and proof harnesses.**

- `gpt` (`xtask/fuzz/targets/src/bin/gpt.rs`) drives `vfsd_gpt::property::gpt_holds` over a header
  block and a whole disk, from the seeds in `services/vfsd/gpt/fuzz/gpt/seeds/`; CI's gating `fuzz`
  job runs it on every pull request and the weekly campaign for 30 minutes.
- The `proofs` module of `services/vfsd/gpt/src/lib.rs` proves the property's check of a header and
  of an entry over every input, the choice between the two copies, and, by induction, the CRC32, the
  entry-array walk and the lookup ([testing.md](testing.md) § Bounded verification); CI's `kani` job
  runs them.
- Planned: the FAT decoders' property function, fuzz target and proof harness (`parse_bpb_geometry`,
  `read_fat_entry`, `parse_dir_entry`; [#680](https://github.com/kottlerg/seraph/issues/680),
  [#756](https://github.com/kottlerg/seraph/issues/756)).

**Gaps.**

- A header's fields bound one another: `first_usable_lba` bounds the entry array the same header
  places, so an attacker who sets both, and recomputes the CRC32s, lengthens the entry walk to the
  entries `num_parts` declares, which the device's capacity then bounds.
- No check compares one partition entry with another, so two partitions can overlap, and a
  filesystem driver given one reaches the other's blocks in the overlap.
- The FAT decoders have no fuzz target or proof harness yet, and no target drives fatfs's own logic
  over a corrupt volume (its cache, allocation and write paths): the targets drive the parser crates
  only.

---

## ELF Loading

Implementation status: provisional until v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)).

**Attacker.** The storage writer of § Boot-Chain Signatures, who supplies the bytes of any image in
the bootstrap bundle or the root filesystem but holds no trusted key; and a process that asks
procmgr to create a process from a Memory capability it holds.

**Assets.** The integrity of the loading stage (the bootloader, init, procmgr) and of the process it
builds.

**Assumptions.** An image a trusted key signed was built from the project's sources; a defect in a
loader reached only through such an image is a defect, not an attack.

**Mitigations.**

- Every loader verifies an image's signature before it parses any of its ELF bytes, on a copy no
  other process can write: the bootloader the kernel and `init` (`verify_bundle`, `verify_and_load`
  in `core/boot/src/main.rs`), procmgr every image it creates (`services/procmgr/src/image.rs`);
  init loads memmgr and procmgr only from boot modules the bootloader verified
  ([signing.md](signing.md) § Verifier Discipline).
- The ELF parser, `shared/elf`, reads only inside the slice it is given: `validate_executable`
  checks the identification, the type, the machine and the program-header table's bounds;
  `load_segments` refuses a segment whose file bytes lie past the image; `validate_relative_relocs`
  refuses a relocation of another type or one whose target lies outside the image's span. The
  bootloader also refuses kernel segments that overlap or an entry point outside them
  (`validate_kernel_layout` in `core/boot/src/elf.rs`).
- The kernel parses no ELF header: it maps the segments of `init` that the bootloader decoded into
  `BootInfo.init_image` and, for a position-independent `init`, applies the relocation table the
  bootloader located (refusing a record of another type, or a table over 4 MiB) at a randomized bias
  (`pie_rebase_init_image` in `core/kernel/src/main.rs`, `core/kernel/src/mm/init_reloc.rs`).

**Fuzz targets and proof harnesses.** None on `master`. Planned: property functions, fuzz targets
and proof harnesses for `validate`, `validate_executable`, `parse_stack_note`, `decode_rela` and
`validate_relative_relocs` ([#680](https://github.com/kottlerg/seraph/issues/680),
[#756](https://github.com/kottlerg/seraph/issues/756)).

**Gaps.**

- devmgr reads the ELF header, the section headers and the driver-declaration note of every file in
  `/services/drivers/` before any verification, to choose the driver a device binds (`file_decl`,
  `read_decl` in `services/devmgr/src/decls.rs`), so the storage writer reaches
  `elf::validate_executable`, `elf::find_note_streaming` and the declaration decoder with bytes no
  key signed. procmgr still refuses to run such a file
  ([#1533](https://github.com/kottlerg/seraph/issues/1533)).
- No fuzz target or proof harness covers `shared/elf` yet. Those for `find_note_streaming` and the
  declaration decoder are planned ([#1535](https://github.com/kottlerg/seraph/issues/1535)).

---

## Boot Handover

Implementation status: provisional until v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)).

**Attacker.** The storage writer of § Boot-Chain Signatures, acting on the EFI System Partition: it
can edit the bootstrap bundle's header, which is not signed, and replace any of its entries.

**Assets.** The kernel and init images and the boot modules as the bootloader hands them on; the
memory each boot module occupies; the boot's completion.

**Assumptions.** The bootloader, once running, executes as built, so the `BootInfo` it writes and
the kernel's `InitInfo` are trusted. Firmware's ACPI and Device Tree tables are trusted as firmware
is.

**Mitigations.**

- The bundle header is parsed by `abi/boot-protocol`'s `bundle` module, which refuses an entry past
  the end of the file or off a page boundary, and the bootloader verifies every entry under its
  entry name before it uses any, refuses entry bodies out of order or sharing a page, a second or
  missing `init`, a missing boot-time policy, and an entry not named by an install path
  (`verify_bundle` in `core/boot/src/main.rs`; [signing.md](signing.md) § Which Stage Verifies
  What).
- The kernel checks the `BootInfo` it receives before it uses it (`validate_boot_info` in
  `core/kernel/src/validate.rs`); this is a consistency check on a trusted producer, not a defence
  against this attacker.
- The kernel hands init its `InitInfo` in read-only pages, and init refuses one of another protocol
  version (`services/init/src/main.rs`).

**Fuzz targets and proof harnesses.** None on `master`. Planned: property functions, fuzz targets
and proof harnesses for `FramebufferInfo::from_bytes`, the bundle's `parse_header` and `entry_at`,
and `find_module_slot` ([#680](https://github.com/kottlerg/seraph/issues/680),
[#756](https://github.com/kottlerg/seraph/issues/756)).

**Gaps.**

- The bundle header is unsigned, so the attacker can drop an entry, which fails the boot when it is
  needed ([signing.md](signing.md) § Which Stage Verifies What).
- The firmware-table parsers (the bootloader's `core/boot/src/acpi.rs` and `core/boot/src/dtb.rs`,
  and devmgr's `firmware` crate) have no fuzz target or proof harness yet; they are planned
  ([#1535](https://github.com/kottlerg/seraph/issues/1535)).

---

## Devices

Implementation status: provisional until v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)).

**Attacker.** A device that does not behave as its specification states, whether faulty, malicious,
or hot-added; and a driver process compromised through its other inputs, which programs its device's
DMA engine and registers.

**Assets.** The memory of the kernel and of every other process; the frames a client lends a driver;
the other devices; interrupt delivery.

**Assumptions.** An IOMMU confines DMA as its specification states, and firmware's DMAR or RIMT
describes the remapping units truly.

**Mitigations.**

- A driver programs its device only with device addresses devmgr returns for frames it maps, and
  where a remapping unit confines the device, the device reaches exactly those frames and its
  reserved ranges ([device-management.md](device-management.md) § DMA Safety Model, § DMA
  Authorisation; `services/devmgr/src/dma.rs`).
- Under the signed boot-time policy's `dma-confinement = required`, devmgr starts no driver for a
  DMA-capable device no unit confines (`firmware::dma::admits` in
  `services/devmgr/firmware/src/dma.rs`; [device-management.md](device-management.md) § Required DMA
  Confinement).
- When a DMA-capable driver dies or is withdrawn, its frames return to the pool only after the
  device is blocked in the IOMMU, or its bus mastering is off, its BARs revoked and its reset
  confirmed; otherwise they stay quarantined for the boot
  ([device-management.md](device-management.md) § DMA-Safe Teardown; `withdraw_device` in
  `services/devmgr/src/bind.rs`).
- devmgr carves each driver's MMIO, interrupt and DMA capabilities from its device's record
  ([driver-binding.md](driver-binding.md) § Declaration Bounds), and only devmgr writes a function's
  MSI-X table; with VT-d interrupt remapping on, a device's interrupt write is delivered only
  through an entry written for its own requester ID, and on riscv64 a confined device reaches only
  the interrupt files its domain maps ([device-management.md](device-management.md) § IOMMU
  Discovery and Programming, § Interrupt Delivery; `carve_pci_device` and `give_msix` in
  `services/devmgr/src/bind.rs`, `services/devmgr/src/intremap.rs`, `reach_interrupt_file` in
  `services/devmgr/src/dma.rs`).
- A block driver that loses a request resets its device before it gives the client's memory back,
  and exits without replying when the device does not acknowledge the reset (`quiesce_device` in
  `services/drivers/virtio/blk/src/main.rs`).

**Fuzz targets and proof harnesses.** None. The booted `dma-confinement` and `hotplug` cases test
the confinement policy and hot-add ([testing.md](testing.md) § Gating).

**Gaps.**

- With no IOMMU, or none that can be programmed, under the default `opportunistic` policy, every
  DMA-capable driver runs unconfined, and its device can reach any physical address it can address
  ([device-management.md](device-management.md) § DMA Safety Model).
- On x86-64 with interrupt remapping off, a device whose DMA engine writes to the interrupt range
  can raise any vector on any CPU whose APIC id is below `0xFF`, exception vectors included
  ([device-management.md](device-management.md) § Message-Signaled Interrupts). Message-signaled
  interrupts are not yet validated on hardware
  ([#924](https://github.com/kottlerg/seraph/issues/924)).
- The approved DMA mapping strategy of [#772](https://github.com/kottlerg/seraph/issues/772) lets a
  block device reach a registered client region from its registration to its unregistration, not
  only during one request; design intent, not yet implemented.
- No fuzz target or proof harness covers a driver's decoding of what its device writes (VirtIO used
  rings, configuration space) yet; one is planned
  ([#1535](https://github.com/kottlerg/seraph/issues/1535)).

---

## Boot-Chain Signatures

Implementation status: provisional until v0.13.0
([#686](https://github.com/kottlerg/seraph/issues/686)). [signing.md](signing.md) is authoritative
for this boundary; this section summarizes its threat model.

**Attacker.** Anyone who can write the storage the system boots and runs from (the EFI System
Partition, the bootstrap bundle and the root filesystem) and who holds no private key the system
trusts ([signing.md](signing.md) § Threat Model).

**Assets.** The guarantee that only code and policy signed by a trusted key, in the role it runs in,
at a security version the machine admits, boot and run.

**Assumptions.** The system-wide assumptions above. Secure Boot, where the firmware enforces it,
binds the bootloader to the firmware's db ([signing.md](signing.md) § Secure Boot).

**Mitigations.** Every object carries a composite Ed25519 and ML-DSA-65 signature over its hash,
roles, name, architecture and security version; the bootloader verifies the kernel and every bundle
entry, and procmgr every image it creates and every data or configuration file a reader asks it to,
each on a copy no other process can write, with one exit on failure and no fallback
([signing.md](signing.md) § Which Stage Verifies What, § Verification, § Verifier Discipline). The
machine's security floor is kept in firmware storage and raised, and the enrolled trust store
changes only by a request signed in the enrolment role or confirmed at the console
([signing.md](signing.md) § Rollback Floor, § Trust Store). The code is `shared/objsig` (the formats
and the verifier), `shared/crypto` (the primitives), `core/boot/src/main.rs`,
`core/boot/src/rollback.rs`, `core/boot/src/enrolment.rs`, `core/boot/src/secure_boot.rs` and
`services/procmgr/src/image.rs`.

**Fuzz targets and proof harnesses.** None. The primitives are tested against known-answer and
Wycheproof vectors, `shared/objsig` is host-tested, and the booted `signing`, `rollback`,
`enrolment` and `secureboot` cases boot each refusal ([testing.md](testing.md) § Gating).

**Gaps.**

- What [signing.md](signing.md) § Threat Model leaves: without Secure Boot an attacker who writes
  the ESP replaces the bootloader and its roots, and a whole older image boots; an image packed with
  a test harness signed `init` boots that harness on a system that trusts its key; a console user
  who confirms an attacker's trust request enrols its roots; an attacker at the firmware's shell can
  delete the enrolled store; on a platform whose firmware refuses the floor's write, the machine's
  floor never rises, so even under Secure Boot a whole older image boots, its bootloader and older
  floor included ([signing.md](signing.md) § Rollback Floor); and an older signed configuration
  directory at an admitted security version verifies
  ([#1416](https://github.com/kottlerg/seraph/issues/1416)).
- The parsers of the signature trailer, the certificate, the trust store and the trust request,
  which read bytes before any signature over them is checked, have no fuzz target or proof harness
  yet; they are planned ([#1535](https://github.com/kottlerg/seraph/issues/1535)).
- devmgr parses drivers-directory files before procmgr verifies them (§ ELF Loading,
  [#1533](https://github.com/kottlerg/seraph/issues/1533)).
- Secure Boot and a TPM are not required by the platform floor
  ([#1420](https://github.com/kottlerg/seraph/issues/1420)), and no project root key signs releases
  yet ([#1073](https://github.com/kottlerg/seraph/issues/1073)).

---

## Attackers Out of Scope

No section above is held against these attackers yet. Each enters with the milestone named.

| Attacker | Enters with |
|---|---|
| A remote attacker on a network | v0.4.0, networking ([#151](https://github.com/kottlerg/seraph/issues/151)) |
| Another user of the same system | v0.5.0, identity and authority ([#152](https://github.com/kottlerg/seraph/issues/152)) |
| A co-resident process attacking another through shared microarchitectural state; capability isolation does not stop it ([capability-model.md](capability-model.md) § Microarchitectural Isolation) | v0.5.0, security domains ([#1086](https://github.com/kottlerg/seraph/issues/1086)) |
| A supplier of the toolchain, a dependency or the build host | v0.13.0, whose audit covers the build chain ([#686](https://github.com/kottlerg/seraph/issues/686)) |
| An attacker with physical access to memory or buses, or with the storage while the system is off, against confidentiality | No milestone yet; storage encryption is planned in v0.5.0 ([#152](https://github.com/kottlerg/seraph/issues/152)) and v0.13.0 ([#686](https://github.com/kottlerg/seraph/issues/686)) |
| Malicious firmware | None: firmware is in the trusted base |

---

## Summarized By

None
