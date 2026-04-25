# Early Console

Invariants for the bootloader's early debug-output path across both serial
and framebuffer backends.

Implementations:
- Dual-backend writer: [`boot/src/console.rs`](../src/console.rs).
- Framebuffer backend: [`boot/src/framebuffer.rs`](../src/framebuffer.rs).
- Serial backend (x86-64): [`boot/src/arch/x86_64/serial.rs`](../src/arch/x86_64/serial.rs).
- Serial backend (RISC-V): [`boot/src/arch/riscv64/serial.rs`](../src/arch/riscv64/serial.rs).
- Bitmap font (framebuffer): [`shared/font/`](../../../shared/font/).

---

## Scope

The early console is a *pre-kernel* debug surface. Both backends exist solely
to surface diagnostics before `ExitBootServices`; neither survives handoff.
The kernel has its own console arrangements and takes nothing from the
bootloader's console state.

The bootloader is single-threaded and never preempts itself, so the shared
console state needs no locking.

---

## Dual-Backend Writer

The `bprint!` / `bprintln!` macros target a dual backend. Each write fans
out to every backend that is live:

- **Serial** — always available on both architectures; initialised before
  any other output path.
- **Framebuffer** — available only when UEFI's Graphics Output Protocol
  (GOP) reported a linear pixel buffer in Step 1 of the boot sequence.

Early messages (protocol lookup, `boot.conf` parse) occur before GOP is
queried and land on serial only; this is the intended fallback on headless
systems.

---

## Serial Backend

Serial is the always-on path. It is initialised during the bootloader's
pre-boot phase (before Step 1 of [boot-flow.md](boot-flow.md)), so every
subsequent step — including UEFI protocol discovery — can emit diagnostics.

### x86-64

The COM1 16550 UART at I/O ports `0x3F8–0x3FF` is used directly. No
discovery is required; COM1 is a fixed platform convention on every UEFI
x86-64 host.

### RISC-V

The UART is an ns16550a-compatible register file reached via MMIO; its
physical base is **not** a platform constant and must be discovered from
firmware. Discovery runs in
[`arch::riscv64::pre_serial_init`](../src/arch/riscv64/mod.rs) before Step
1 of the boot sequence, in the following order:

1. **ACPI SPCR** — scan the UEFI configuration table for
   `EFI_ACPI_20_TABLE_GUID`; if present, walk RSDP → XSDT and match the
   `SPCR` signature. Take the UART base from the SPCR Generic Address
   Structure when its address-space identifier is MMIO.
2. **Device Tree** — if SPCR did not yield an address, scan the
   configuration table for `EFI_DTB_TABLE_GUID`; if present, walk the FDT
   for a node with `compatible = ns16550a` and take the first `reg` entry.
3. **Fallback** — the QEMU virt convention at `0x10000000` is the last
   resort. This keeps the bootloader functional on bare-QEMU-like
   environments that advertise neither table.

SPCR is the one ACPI table consumed outside Step 5's firmware-parsing
path; the pre-Step-1 order is load-bearing because every later step wants
diagnostics and every subsequent ACPI walk would itself want to emit
diagnostics if something went wrong.

---

## Framebuffer Backend

### Best-Effort Discovery

`EFI_GRAPHICS_OUTPUT_PROTOCOL` is optional. Its absence — headless
systems, some virtual-machine configurations, serial-only platforms — is
a valid configuration, not an error. The bootloader's `FramebufferInfo`
field is zeroed in that case (`physical_base == 0`), which is the
boot-protocol contract's signal for "no framebuffer present". Neither
the bootloader nor the kernel treats this as failure.

GOP query runs in Step 1 of the boot sequence; the result feeds both the
on-screen early-boot messages and the `BootInfo.framebuffer` handoff
field.

### Glyph Rendering

The font is the `9×20` bitmap array exposed by
[`shared/font/`](../../../shared/font/): 256 glyphs, each stored as a
flat `[u16; 5120]` with `FONT_9X20[N * 20 + R]` yielding scanline `R`
of glyph `N`. Bits 15–7 of each scanline are the 9 pixels, MSB first.

The writer tracks a character-cell cursor. Its operations:
- Advance on each glyph (wrap on `max_cols`, scroll on `max_rows`).
- Clear screen to black on construction.
- No backspace, tab expansion, or cursor addressing — this is a debug
  surface, not a terminal.

Column and row limits are computed as `fb.width / GLYPH_WIDTH` and
`fb.height / GLYPH_HEIGHT`; fractional remainders at right / bottom
edges are left unused.

### Pixel Formats

Only `PixelFormat::Rgbx8` and `Bgrx8` are supported. Both are 32-bit
per pixel with 8 bits of RGB and an unused alpha/padding byte; they
differ only in channel order. These two cover every UEFI implementation
encountered on target hardware. Unrecognised pixel formats are not
rendered (the writer is constructed but writes to it are no-ops).

`stride` is bytes per row and may exceed `width * 4` on some firmware
implementations; the writer uses `stride` as the row advance, not
`width`.

### Handoff

The framebuffer physical base, width, height, stride, and pixel format
are recorded in `BootInfo.framebuffer`. The bootloader does not
transfer any ownership of the framebuffer — it records what UEFI told
it and stops touching the memory at `ExitBootServices`. Post-handoff,
any userspace service that is granted the framebuffer MMIO capability
is free to take over; whether an early-boot display service exists at
all is a userspace policy decision, not a bootloader concern.

---

## What Lives Elsewhere

- GOP discovery sequencing and `ExitBootServices` handling are owned
  by [uefi-environment.md](uefi-environment.md).
- The `FramebufferInfo` contract (meaning of `physical_base == 0`,
  pixel-format enum values) is owned by the boot-protocol crate
  [`abi/boot-protocol/src/lib.rs`](../../../abi/boot-protocol/src/lib.rs).
- Font data, layout, and lookup formula are owned by
  [`shared/font/README.md`](../../../shared/font/README.md).
- Detailed ACPI SPCR and DTB `ns16550a` walk invariants belong to
  [acpi.md](acpi.md) and [dtb.md](dtb.md); this document names the
  RISC-V discovery *order* and the pre-Step-1 placement, not the
  per-table parse rules.

---

## Summarized By

[boot/README.md](../README.md)
