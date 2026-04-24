# abi/boot-protocol

Binary boot protocol contract between the bootloader and the kernel.

Defines `BootInfo` and all associated types passed from the bootloader to the
kernel entry point. Includes the `BOOT_PROTOCOL_VERSION` constant; the kernel
halts at entry if the bootloader's version does not match.

**Constraints:** `no_std`, `#[repr(C)]` for all types, no dependencies outside
`core`. Changes that alter `BootInfo` layout or the CPU entry contract MUST
increment `BOOT_PROTOCOL_VERSION`.

The crate source itself ([`src/lib.rs`](src/lib.rs)) is the authoritative
layout specification — type fields, discriminants, doc-comment invariants,
and version-history rationale all live there, not duplicated in markdown.
This README covers only what the source cannot: the third-party-bootloader
policy and the high-level responsibilities required of any compliant
bootloader.

The compile-time view of what each phase of boot establishes, and the
sequence of steps the reference bootloader takes, is documented at the
component level in [`boot/docs/`](../../boot/docs/) — particularly
[`boot/docs/kernel-handoff.md`](../../boot/docs/kernel-handoff.md) for the
CPU-state contract at entry, and
[`boot/docs/boot-flow.md`](../../boot/docs/boot-flow.md) for the ten-step
sequence.

---

## Compliant Bootloader

The Seraph bootloader in [`boot/`](../../boot/) is the **reference
implementation**. Any compliant bootloader that satisfies the contract
defined by this crate — the `BootInfo` layout, the
`BOOT_PROTOCOL_VERSION` check, and the CPU/memory state at kernel entry
— MAY be used in its place. The kernel has no knowledge of the specific
bootloader that produced a `BootInfo`; only the contract matters.

### Contract for a compliant bootloader

A compliant bootloader MUST, before jumping to the kernel entry point:

- Verify the kernel ELF is valid and has a recognisable entry point.
- Load all ELF LOAD segments into allocated physical memory.
- Zero BSS segments.
- Respect ELF segment permissions (readable, writable, executable) when
  establishing initial page table entries; never map any region as both
  writable and executable (W^X).
- Obtain the final UEFI memory map after all allocations are complete.
- Call `ExitBootServices` successfully before jumping to the kernel.
- Populate every field of `BootInfo` per the per-field semantics in
  [`src/lib.rs`](src/lib.rs).
- Set `BootInfo.version = BOOT_PROTOCOL_VERSION` at the version defined
  by the crate the kernel was built against.
- Guarantee that the `BootInfo` structure and all referenced data
  remain mapped and readable at kernel entry.
- Establish the CPU state documented in
  [`boot/docs/kernel-handoff.md`](../../boot/docs/kernel-handoff.md)
  for the target architecture.

A compliant bootloader MUST NOT:

- Leave UEFI boot services active at kernel entry.
- Map any region as both writable and executable.
- Assume anything about the kernel's internal layout beyond the ELF
  headers.
- Include in `BootInfo.mmio_apertures` any region that is inaccessible
  or reserved for firmware's exclusive use.

---

## Summarized By

[README.md](../../README.md), [boot/README.md](../../boot/README.md),
[docs/bootstrap.md](../../docs/bootstrap.md),
[docs/build-system.md](../../docs/build-system.md),
[docs/architecture.md](../../docs/architecture.md),
[docs/memory-model.md](../../docs/memory-model.md),
[docs/device-management.md](../../docs/device-management.md),
[kernel/README.md](../../kernel/README.md),
[kernel/docs/initialization.md](../../kernel/docs/initialization.md),
[init/README.md](../../init/README.md),
[procmgr/README.md](../../procmgr/README.md),
[devmgr/README.md](../../devmgr/README.md),
[shared/elf/README.md](../../shared/elf/README.md),
[abi/init-protocol/README.md](../init-protocol/README.md)
