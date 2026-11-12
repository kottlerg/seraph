// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/pci.rs

//! PCI configuration-space arithmetic for devmgr: ECAM register offsets, the
//! physical page of a function's configuration space, BAR sizes from their
//! sizing read-backs (PCI Local Bus Specification r3.0 § 6.2.5.1), the
//! Command register's Memory Space Enable, Bus Master Enable, and Interrupt
//! Disable (§ 6.2.2), the capability-list walk, the MSI and MSI-X capability
//! fields (§ 6.8) and the interrupt devmgr gives a driver, and the PCI Express
//! Function Level Reset fields. devmgr performs the volatile accesses; these
//! functions only compute.

/// Bytes of one function's configuration space in an ECAM window (PCI
/// Express Base Specification r4.0 § 7.2.2): one page.
pub const FUNCTION_CONFIG_BYTES: u64 = 0x1000;

/// Physical address of the configuration space of function `func` of device
/// `dev` on `bus` in PCI segment `segment`: the page of it the ECAM window
/// among `windows` that decodes that segment and bus holds. Returns `None`
/// when no window decodes them or a field is out of range
/// ([`config_offset`]).
#[must_use]
pub fn function_config_phys(
    windows: &[crate::EcamLocation],
    segment: u16,
    bus: u8,
    dev: u8,
    func: u8,
) -> Option<u64>
{
    let window = windows
        .iter()
        .find(|w| w.segment == segment && w.start_bus <= bus && bus <= w.end_bus)?;
    window
        .phys_base
        .checked_add(config_offset(window.start_bus, bus, dev, func, 0)?)
}

/// Offset of the Command register in a function's configuration header.
pub const COMMAND: u16 = 0x04;

/// Bus Master Enable, bit 2 of the Command register: while it is clear the
/// function issues no memory or I/O request of its own, so it performs no
/// DMA and signals no MSI.
pub const COMMAND_BUS_MASTER: u16 = 1 << 2;

/// Command register: Memory Space Enable, the function decodes its MMIO
/// BARs.
pub const COMMAND_MEMORY: u16 = 1 << 1;

/// Command register: Interrupt Disable, bit 10. While it is set the function
/// does not assert its wired interrupt line (PCI Local Bus Specification
/// r3.0 § 6.2.2).
pub const COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;

/// The Command register value that turns on Memory Space Enable and keeps
/// every other bit of `command`, Bus Master Enable included: the function
/// then decodes its MMIO BARs, so devmgr can write an MSI-X table through
/// one before the bind's Command write ([`command_for_bind`]).
#[must_use]
pub const fn command_with_memory(command: u16) -> u16
{
    command | COMMAND_MEMORY
}

/// The Command register value that turns on Memory Space Enable and Bus
/// Master Enable and keeps every other bit of `command`: the function then
/// decodes its MMIO BARs and issues DMA. devmgr writes it for a device the
/// firmware left off that its driver needs on.
#[must_use]
pub const fn command_with_memory_and_bus_master(command: u16) -> u16
{
    command | COMMAND_MEMORY | COMMAND_BUS_MASTER
}

/// The Command register value devmgr writes when it binds a driver to the
/// function: Memory Space Enable on; Bus Master Enable on for a device that
/// performs DMA (`dma`) and off for one that does not; Interrupt Disable
/// clear when the driver is given the function's wired line (`wired`) and
/// set when it is not, so a function whose driver takes no interrupt never
/// asserts a line it may share. Every other bit of `command` is kept.
#[must_use]
pub const fn command_for_bind(command: u16, dma: bool, wired: bool) -> u16
{
    let mut value = command | COMMAND_MEMORY;
    value = if dma
    {
        value | COMMAND_BUS_MASTER
    }
    else
    {
        value & !COMMAND_BUS_MASTER
    };
    if wired
    {
        value & !COMMAND_INTERRUPT_DISABLE
    }
    else
    {
        value | COMMAND_INTERRUPT_DISABLE
    }
}

/// The Command register value that sets Interrupt Disable and keeps every
/// other bit of `command`: the step of a withdrawal that stops the function
/// asserting its wired line, whoever else shares it.
#[must_use]
pub const fn command_with_interrupt_disable(command: u16) -> u16
{
    command | COMMAND_INTERRUPT_DISABLE
}

/// Whether a Command register read back after setting Interrupt Disable
/// confirms it set. An all-ones read-back is what a function that does not
/// answer returns, so it confirms nothing.
#[must_use]
pub const fn interrupt_disable_confirmed(read_back: u16) -> bool
{
    read_back != u16::MAX && read_back & COMMAND_INTERRUPT_DISABLE != 0
}

/// Offset of the Status register; bit 4 is Capabilities List.
pub const STATUS: u16 = 0x06;
/// Status register: the function has a capability list at
/// [`CAPABILITIES_POINTER`].
pub const STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
/// Offset of the capability list's head pointer in a type-0 header.
pub const CAPABILITIES_POINTER: u16 = 0x34;
/// Capability slots a function's capability list can hold: capabilities are
/// dword-aligned in the 192 bytes above the 64-byte standard header, so a
/// longer list loops, and the walk stops there.
pub const MAX_CAPABILITIES: u32 = 48;
/// Capability ID of the PCI Express capability.
pub const CAP_ID_PCI_EXPRESS: u8 = 0x10;
/// Offset of Device Capabilities in the PCI Express capability; bit 28 is
/// Function Level Reset Capability (PCI Express Base Specification r4.0
/// § 7.5.3.3).
pub const PCIE_DEVICE_CAPABILITIES: u16 = 0x04;
/// Device Capabilities: the function supports Function Level Reset.
pub const PCIE_DEVCAP_FLR: u32 = 1 << 28;
/// Offset of Device Control in the PCI Express capability; bit 15 is
/// Initiate Function Level Reset (§ 7.5.3.4).
pub const PCIE_DEVICE_CONTROL: u16 = 0x08;
/// Device Control: Initiate Function Level Reset.
pub const PCIE_DEVCTL_INITIATE_FLR: u16 = 1 << 15;
/// The wait after initiating a Function Level Reset before software touches
/// the function again (§ 6.6.2): 100 ms.
pub const FLR_COMPLETION_MS: u64 = 100;

/// Offset of the capability with ID `id` in a function's configuration
/// header, which `read8` reads a byte of. Walks the capability list from
/// [`CAPABILITIES_POINTER`] when the Status register's Capabilities List bit
/// is set (`status`), at most [`MAX_CAPABILITIES`] entries, so a cyclic list
/// ends; `None` when the function has no list or none of its entries has
/// that ID.
pub fn find_capability(status: u16, id: u8, read8: impl Fn(u16) -> u8) -> Option<u16>
{
    if status & STATUS_CAPABILITIES_LIST == 0
    {
        return None;
    }
    // The pointer's low 2 bits are reserved.
    let mut ptr = read8(CAPABILITIES_POINTER) & !3;
    let mut walked = 0u32;
    while ptr != 0 && walked < MAX_CAPABILITIES
    {
        walked = walked.saturating_add(1);
        let at = u16::from(ptr);
        if read8(at) == id
        {
            return Some(at);
        }
        ptr = read8(at.saturating_add(1)) & !3;
    }
    None
}

/// Whether a function whose PCI Express Device Capabilities register reads
/// `devcap` supports Function Level Reset. All ones, a function that does not
/// answer, does not.
#[must_use]
pub const fn flr_capable(devcap: u32) -> bool
{
    devcap != u32::MAX && devcap & PCIE_DEVCAP_FLR != 0
}

/// Capability ID of the MSI capability (PCI Local Bus Specification r3.0
/// § 6.8.1).
pub const CAP_ID_MSI: u8 = 0x05;
/// Capability ID of the MSI-X capability (§ 6.8.2).
pub const CAP_ID_MSIX: u8 = 0x11;
/// Offset of Message Control in the MSI and the MSI-X capability.
pub const MESSAGE_CONTROL: u16 = 0x02;

/// MSI Message Control: MSI Enable.
pub const MSI_CONTROL_ENABLE: u16 = 1 << 0;
/// MSI Message Control: Multiple Message Capable, bits 3:1, the log2 of the
/// vectors the function requests.
const MSI_CONTROL_MMC_SHIFT: u16 = 1;
/// MSI Message Control: Multiple Message Enable, bits 6:4, the log2 of the
/// vectors software allocated.
const MSI_CONTROL_MME: u16 = 0x7 << 4;
/// MSI Message Control: 64-bit Address Capable.
const MSI_CONTROL_64BIT: u16 = 1 << 7;
/// MSI Message Control: Per-vector Masking Capable.
const MSI_CONTROL_PER_VECTOR_MASK: u16 = 1 << 8;
/// Offset of Message Address in the MSI capability; for a 64-bit capable
/// function the upper 32 bits follow it.
pub const MSI_ADDRESS: u16 = 0x04;
/// Offset of Message Upper Address in a 64-bit MSI capability.
pub const MSI_ADDRESS_HIGH: u16 = 0x08;

/// A function's MSI capability (PCI Local Bus Specification r3.0 § 6.8.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msi
{
    /// The capability's offset in the configuration header.
    pub offset: u16,
    /// Vectors the function requests, 1 to 32 (Multiple Message Capable).
    pub vectors: u8,
    /// The function takes a 64-bit message address.
    pub address_64: bool,
    /// The function has a Mask Bits register.
    pub per_vector_mask: bool,
}

impl Msi
{
    /// The MSI capability at `offset` whose Message Control reads `control`.
    /// A reserved Multiple Message Capable encoding (above 5) reads as 32
    /// vectors, the most the field states.
    #[must_use]
    pub const fn decode(offset: u16, control: u16) -> Self
    {
        let log2 = (control >> MSI_CONTROL_MMC_SHIFT) & 0x7;
        let log2 = if log2 > 5 { 5 } else { log2 };
        Self {
            offset,
            vectors: 1 << log2,
            address_64: control & MSI_CONTROL_64BIT != 0,
            per_vector_mask: control & MSI_CONTROL_PER_VECTOR_MASK != 0,
        }
    }

    /// Offset of Message Data in the configuration header: after the upper
    /// address of a 64-bit capability, after the address otherwise.
    #[must_use]
    pub const fn data_offset(&self) -> u16
    {
        self.offset
            .saturating_add(if self.address_64 { 0x0C } else { 0x08 })
    }

    /// Offset of Mask Bits in the configuration header, for a function with
    /// per-vector masking; bit 0 masks the first vector.
    #[must_use]
    pub const fn mask_offset(&self) -> Option<u16>
    {
        if self.per_vector_mask
        {
            Some(
                self.offset
                    .saturating_add(if self.address_64 { 0x10 } else { 0x0C }),
            )
        }
        else
        {
            None
        }
    }

    /// Whether the message `address`, `data` fits the capability: a 32-bit
    /// capability takes an address below 4 GiB, and Message Data is 16 bits
    /// wide.
    #[must_use]
    pub const fn fits(&self, address: u64, data: u64) -> bool
    {
        (self.address_64 || address <= u32::MAX as u64) && data <= u16::MAX as u64
    }
}

/// The MSI Message Control value that enables MSI with one vector: Multiple
/// Message Enable 0 (one vector, since each target devmgr is given stands on
/// its own CPU and a function with more would signal consecutive data values
/// on one), MSI Enable set, every other bit of `control` kept.
#[must_use]
pub const fn msi_control_enable_one(control: u16) -> u16
{
    (control & !MSI_CONTROL_MME) | MSI_CONTROL_ENABLE
}

/// The MSI Message Control value with MSI Enable clear, every other bit of
/// `control` kept: the function signals no MSI.
#[must_use]
pub const fn msi_control_disable(control: u16) -> u16
{
    control & !MSI_CONTROL_ENABLE
}

/// MSI-X Message Control: Table Size, bits 10:0, the table's entries less
/// one.
const MSIX_CONTROL_TABLE_SIZE: u16 = 0x7FF;
/// MSI-X Message Control: Function Mask; while set every vector is masked,
/// whatever its own mask bit.
pub const MSIX_CONTROL_FUNCTION_MASK: u16 = 1 << 14;
/// MSI-X Message Control: MSI-X Enable.
pub const MSIX_CONTROL_ENABLE: u16 = 1 << 15;
/// Offset of the Table Offset and BIR register in the MSI-X capability.
pub const MSIX_TABLE: u16 = 0x04;
/// Offset of the PBA Offset and BIR register in the MSI-X capability.
pub const MSIX_PBA: u16 = 0x08;
/// The BAR Indicator Register bits of the Table and PBA registers; the rest
/// is a QWORD-aligned offset into that BAR.
const MSIX_BIR: u32 = 0x7;
/// Bytes of one MSI-X table entry: address, upper address, data, vector
/// control.
pub const MSIX_ENTRY_BYTES: u64 = 16;
/// Offset of Message Address (its low 32 bits) in an MSI-X table entry.
pub const MSIX_ENTRY_ADDRESS: u64 = 0;
/// Offset of Message Upper Address in an MSI-X table entry.
pub const MSIX_ENTRY_ADDRESS_HIGH: u64 = 4;
/// Offset of Message Data in an MSI-X table entry.
pub const MSIX_ENTRY_DATA: u64 = 8;
/// Offset of Vector Control in an MSI-X table entry.
pub const MSIX_ENTRY_VECTOR_CONTROL: u64 = 12;
/// MSI-X Vector Control: Mask Bit.
pub const MSIX_VECTOR_MASKED: u32 = 1;

/// The Message Address, Message Upper Address, and Message Data dwords of an
/// MSI-X table entry carrying the message `address`, `data`, in that order;
/// `None` when `data` is wider than the entry's 32 bits.
#[must_use]
pub fn msix_entry_message(address: u64, data: u64) -> Option<[u32; 3]>
{
    let data = u32::try_from(data).ok()?;
    let [lo0, lo1, lo2, lo3, hi0, hi1, hi2, hi3] = address.to_le_bytes();
    Some([
        u32::from_le_bytes([lo0, lo1, lo2, lo3]),
        u32::from_le_bytes([hi0, hi1, hi2, hi3]),
        data,
    ])
}

/// The Vector Control value with the Mask Bit set (`masked`) or clear, every
/// reserved bit of `control` kept.
#[must_use]
pub const fn msix_vector_control(control: u32, masked: bool) -> u32
{
    if masked
    {
        control | MSIX_VECTOR_MASKED
    }
    else
    {
        control & !MSIX_VECTOR_MASKED
    }
}

/// Bytes of the page granule devmgr withholds an MSI-X structure in: the
/// 4 KiB a function MUST NOT share between an MSI-X structure and other
/// registers (PCI Local Bus Specification r3.0 § 6.8.2), and the page size
/// an `Mmio` cap is carved and mapped in.
pub const MSIX_PAGE_BYTES: u64 = 0x1000;

/// A page-aligned span of one BAR: the byte offset of its first page and the
/// byte past its last page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarSpan
{
    /// The BAR register (0-5).
    pub bar: u8,
    /// Byte offset of the span's first page in the BAR.
    pub start: u64,
    /// Byte offset past the span's last page in the BAR.
    pub end: u64,
}

impl BarSpan
{
    /// Whether the `len` bytes at `offset` of BAR `bar` reach into the span.
    #[must_use]
    pub const fn overlaps(&self, bar: u8, offset: u64, len: u64) -> bool
    {
        bar == self.bar && len > 0 && offset < self.end && offset.saturating_add(len) > self.start
    }

    /// Bytes the span covers.
    #[must_use]
    pub const fn bytes(&self) -> u64
    {
        self.end.saturating_sub(self.start)
    }
}

/// The most ranges [`delivered_ranges`] cuts one BAR into: the two spans of
/// [`Msix::withheld`] split it at most twice.
pub const MAX_BAR_RANGES: usize = 3;

/// A function's MSI-X capability (PCI Local Bus Specification r3.0 § 6.8.2):
/// its table and Pending Bit Array, each a BAR register index and an offset
/// into that BAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix
{
    /// The capability's offset in the configuration header.
    pub offset: u16,
    /// Table entries, 1 to 2048.
    pub table_size: u16,
    /// The BAR register (0-5) holding the table, and its offset there.
    pub table_bar: u8,
    pub table_offset: u32,
    /// The BAR register (0-5) holding the Pending Bit Array, and its offset
    /// there.
    pub pba_bar: u8,
    pub pba_offset: u32,
}

impl Msix
{
    /// The MSI-X capability at `offset` whose Message Control reads
    /// `control`, Table register `table`, and PBA register `pba`; `None` when
    /// either names a reserved BAR register (above 5).
    #[must_use]
    pub const fn decode(offset: u16, control: u16, table: u32, pba: u32) -> Option<Self>
    {
        let table_bar = (table & MSIX_BIR) as u8;
        let pba_bar = (pba & MSIX_BIR) as u8;
        if table_bar > 5 || pba_bar > 5
        {
            return None;
        }
        Some(Self {
            offset,
            table_size: (control & MSIX_CONTROL_TABLE_SIZE).saturating_add(1),
            table_bar,
            table_offset: table & !MSIX_BIR,
            pba_bar,
            pba_offset: pba & !MSIX_BIR,
        })
    }

    /// Bytes of the table.
    #[must_use]
    pub const fn table_bytes(&self) -> u64
    {
        (self.table_size as u64).saturating_mul(MSIX_ENTRY_BYTES)
    }

    /// Bytes of the Pending Bit Array: one bit per entry, in QWORDs.
    #[must_use]
    pub const fn pba_bytes(&self) -> u64
    {
        (self.table_size as u64).div_ceil(64).saturating_mul(8)
    }

    /// The byte past the table's last in its BAR.
    #[must_use]
    pub const fn table_end(&self) -> u64
    {
        (self.table_offset as u64).saturating_add(self.table_bytes())
    }

    /// The byte past the Pending Bit Array's last in its BAR.
    #[must_use]
    pub const fn pba_end(&self) -> u64
    {
        (self.pba_offset as u64).saturating_add(self.pba_bytes())
    }

    /// The pages holding the table, then the pages holding the Pending Bit
    /// Array: each structure's span, its start rounded down and its end up to
    /// [`MSIX_PAGE_BYTES`]. devmgr delivers no driver these pages
    /// (docs/device-management.md § Message-Signaled Interrupts); the two
    /// spans may overlap or coincide.
    #[must_use]
    pub const fn withheld(&self) -> [BarSpan; 2]
    {
        [
            page_span(self.table_bar, self.table_offset as u64, self.table_end()),
            page_span(self.pba_bar, self.pba_offset as u64, self.pba_end()),
        ]
    }

    /// The table's pages ([`Self::withheld`]'s first span) and the table's
    /// byte offset from the span's start.
    #[must_use]
    pub const fn table_span(&self) -> (BarSpan, u64)
    {
        let span = self.withheld()[0];
        (span, (self.table_offset as u64).saturating_sub(span.start))
    }
}

/// The pages of BAR `bar` holding the bytes from `start` to `end`.
const fn page_span(bar: u8, start: u64, end: u64) -> BarSpan
{
    BarSpan {
        bar,
        start: (start / MSIX_PAGE_BYTES).saturating_mul(MSIX_PAGE_BYTES),
        end: end
            .div_ceil(MSIX_PAGE_BYTES)
            .saturating_mul(MSIX_PAGE_BYTES),
    }
}

/// The ranges of BAR `bar`'s first `bytes` bytes that lie outside every span
/// of `withheld` naming that BAR, each as its offset in the BAR and its
/// length, in ascending offset; the first `count` entries of the array are
/// the ranges. A span of another BAR, or one wholly past `bytes`, cuts
/// nothing; overlapping spans cut as their union. Every range but the last
/// ends at a span's start, which is page-aligned, and every range but the
/// first starts at a span's end, also page-aligned.
#[must_use]
pub fn delivered_ranges(
    bar: u8,
    bytes: u64,
    withheld: &[BarSpan],
) -> ([(u64, u64); MAX_BAR_RANGES], usize)
{
    let mut spans: [Option<(u64, u64)>; 2] = [None; 2];
    for (slot, span) in spans
        .iter_mut()
        .zip(withheld.iter().filter(|s| s.bar == bar && s.start < bytes))
    {
        *slot = Some((span.start, span.end));
    }
    if let [Some(a), Some(b)] = spans
        && b.0 < a.0
    {
        spans = [Some(b), Some(a)];
    }
    let mut ranges = [(0, 0); MAX_BAR_RANGES];
    let mut count = 0;
    let mut cursor = 0;
    for (start, end) in spans.into_iter().flatten()
    {
        if start > cursor
            && let Some(slot) = ranges.get_mut(count)
        {
            *slot = (cursor, start.saturating_sub(cursor));
            count = count.saturating_add(1);
        }
        cursor = cursor.max(end);
    }
    if cursor < bytes
        && let Some(slot) = ranges.get_mut(count)
    {
        *slot = (cursor, bytes.saturating_sub(cursor));
        count = count.saturating_add(1);
    }
    (ranges, count)
}

/// Whether every `VirtIO` register region of `info` lies clear of every span
/// of `withheld`: a function whose MSI-X structures share a page with a
/// region its driver needs breaks the PCI rule that keeps them apart
/// ([`MSIX_PAGE_BYTES`]), so devmgr cannot withhold those pages from the
/// driver; it delivers them and gives the function no MSI-X.
#[must_use]
pub fn virtio_regions_clear(info: &virtio_core::VirtioPciStartupInfo, withheld: &[BarSpan])
-> bool
{
    [
        info.common_cfg,
        info.notify_cfg,
        info.isr_cfg,
        info.device_cfg,
    ]
    .iter()
    .all(|r| {
        !withheld
            .iter()
            .any(|s| s.overlaps(r.bar, u64::from(r.offset), u64::from(r.length)))
    })
}

/// The message-signaled capabilities devmgr may give the driver of a
/// function with the MSI capability `msi`, the MSI-X capability `msix`, and
/// the `VirtIO` register regions `info` (all absent for a function that
/// presents no `VirtIO` register layout), as `(msi, msix)`: the MSI-X
/// capability is also the one whose table and Pending Bit Array pages devmgr
/// withholds from the driver ([`Msix::withheld`]).
///
/// A function with no `VirtIO` layout keeps both. A `VirtIO` function keeps no
/// MSI, since `VirtIO` over PCI signals by MSI-X vectors or the wired line
/// alone (`VirtIO` 1.2 § 4.1.4.5, § 4.1.5.1.2), and keeps MSI-X only when
/// every register region lies clear of its structures' pages
/// ([`virtio_regions_clear`]): otherwise the driver needs those pages, they
/// are delivered, and the function falls back to its wired line.
#[must_use]
pub fn deliverable_messages(
    msi: Option<Msi>,
    msix: Option<Msix>,
    info: &virtio_core::VirtioPciStartupInfo,
) -> (Option<Msi>, Option<Msix>)
{
    if info.register_layout().is_none()
    {
        return (msi, msix);
    }
    (
        None,
        msix.filter(|m| virtio_regions_clear(info, &m.withheld())),
    )
}

/// The MSI-X Message Control value that enables MSI-X with every vector
/// masked by Function Mask, every other bit of `control` kept: the function
/// then signals no interrupt, wired or message, until Function Mask clears.
#[must_use]
pub const fn msix_control_enable_masked(control: u16) -> u16
{
    control | MSIX_CONTROL_ENABLE | MSIX_CONTROL_FUNCTION_MASK
}

/// The MSI-X Message Control value with Function Mask clear, every other bit
/// of `control` kept: each vector is then masked by its own Mask Bit alone.
#[must_use]
pub const fn msix_control_unmask_function(control: u16) -> u16
{
    control & !MSIX_CONTROL_FUNCTION_MASK
}

/// The MSI-X Message Control value with MSI-X Enable clear and Function Mask
/// set, every other bit of `control` kept: the function signals no MSI-X
/// message.
#[must_use]
pub const fn msix_control_disable(control: u16) -> u16
{
    (control & !MSIX_CONTROL_ENABLE) | MSIX_CONTROL_FUNCTION_MASK
}

/// How devmgr gives a bound driver its device's interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterruptPlan
{
    /// No interrupt: the driver declares none.
    None,
    /// The function's wired line.
    Wired,
    /// One MSI vector.
    Msi,
    /// This many MSI-X vectors, table entries 0 onwards.
    MsiX(u8),
}

/// The interrupt devmgr first tries to give a driver of a function with the
/// MSI capability `msi` and the MSI-X capability `msix`
/// (docs/device-management.md § Interrupt Delivery): none for a driver whose
/// need is `InterruptNeed::None`; MSI-X, `min(msi_vectors, table size)`
/// vectors, then MSI, one vector, for a driver that requests message-signaled
/// vectors (`msi_vectors` nonzero) and performs DMA (`dma`), since a message
/// is a write the function issues as a bus master and only a DMA declaration
/// is given Bus Master Enable; the wired line otherwise. Each step falls
/// back to the next when it fails at the bind.
#[must_use]
pub fn interrupt_plan(
    interrupt: driver_binding::decl::Interrupt,
    dma: bool,
    msi: Option<Msi>,
    msix: Option<Msix>,
) -> InterruptPlan
{
    use driver_binding::decl::InterruptNeed;
    if interrupt.need == InterruptNeed::None
    {
        return InterruptPlan::None;
    }
    if interrupt.msi_vectors == 0 || !dma
    {
        return InterruptPlan::Wired;
    }
    if let Some(msix) = msix
    {
        let vectors = u16::from(interrupt.msi_vectors).min(msix.table_size);
        return InterruptPlan::MsiX(u8::try_from(vectors).unwrap_or(u8::MAX));
    }
    if msi.is_some()
    {
        return InterruptPlan::Msi;
    }
    InterruptPlan::Wired
}

/// The plan to fall back to when `plan` fails at the bind: MSI-X to MSI when
/// the function has the MSI capability, else to the wired line; MSI to the
/// wired line; nothing past the wired line.
#[must_use]
pub const fn fallback(plan: InterruptPlan, msi: Option<Msi>) -> Option<InterruptPlan>
{
    match plan
    {
        InterruptPlan::MsiX(_) if msi.is_some() => Some(InterruptPlan::Msi),
        InterruptPlan::MsiX(_) | InterruptPlan::Msi => Some(InterruptPlan::Wired),
        InterruptPlan::Wired | InterruptPlan::None => None,
    }
}

/// Why the minted targets of a message-signaled step cannot be given
/// ([`reach_message_files`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessagesRefused
{
    /// The message of the target at this index does not fit the function's
    /// capability. No interrupt file was reached.
    Unfit(usize),
    /// An interrupt file a target sits on could not be made reachable;
    /// `widened` tells whether a file was newly mapped before it.
    Unreachable
    {
        /// Whether an earlier target's file was newly mapped.
        widened: bool,
    },
}

/// Check that every one of the minted targets `messages` fits the function
/// (`fits`), then make the interrupt file each one sits on reachable by the
/// device (`reach`: `Some(true)` when it newly mapped the file, `Some(false)`
/// when nothing was mapped, `None` when the file cannot be reached). No file
/// is reached before every message has been checked, so a message that does
/// not fit leaves the device's IOMMU domain as it found it and its step can
/// fall back (docs/device-management.md § Message-Signaled Interrupts).
/// Returns whether a file was newly mapped.
///
/// # Errors
/// [`MessagesRefused::Unfit`] for the first message that does not fit, with
/// nothing reached; [`MessagesRefused::Unreachable`] when a file cannot be
/// reached, no later file being tried.
pub fn reach_message_files<M>(
    messages: &[M],
    fits: impl Fn(&M) -> bool,
    mut reach: impl FnMut(&M) -> Option<bool>,
) -> Result<bool, MessagesRefused>
{
    if let Some(i) = messages.iter().position(|m| !fits(m))
    {
        return Err(MessagesRefused::Unfit(i));
    }
    let mut widened = false;
    for m in messages
    {
        widened |= reach(m).ok_or(MessagesRefused::Unreachable { widened })?;
    }
    Ok(widened)
}

/// Offset of the Vendor ID register in a function's configuration header.
pub const VENDOR_ID: u16 = 0x00;

/// The Vendor ID a root port returns for a function still completing a
/// reset when Configuration Request Retry Status Software Visibility is on
/// (PCI Express Base Specification r4.0 § 2.3.2).
const VENDOR_ID_RETRY: u16 = 0x0001;

/// Whether a function whose Vendor ID reads `vendor` [`FLR_COMPLETION_MS`]
/// after a Function Level Reset was initiated has completed it: it answers
/// with a Vendor ID, neither all ones (no answer) nor the retry value.
#[must_use]
pub const fn flr_completed(vendor: u16) -> bool
{
    vendor != u16::MAX && vendor != VENDOR_ID_RETRY
}

/// The Command register value that clears Bus Master Enable and keeps every
/// other bit of `command`, so the function still decodes its BARs.
#[must_use]
pub const fn command_without_bus_master(command: u16) -> u16
{
    command & !COMMAND_BUS_MASTER
}

/// Whether a Command register read back after clearing Bus Master Enable
/// confirms it clear. An all-ones read-back is what a function that does
/// not answer returns, so it confirms nothing.
#[must_use]
pub const fn bus_master_confirmed_clear(read_back: u16) -> bool
{
    read_back != u16::MAX && read_back & COMMAND_BUS_MASTER == 0
}

/// Byte offset of a BDF + register within an ECAM window whose first bus is
/// `start_bus` (1 MiB per bus, 32 KiB per device, 4 KiB per function).
/// Returns `None` when `bus` is below `start_bus`, or `dev`, `func`, or
/// `reg` exceeds 31, 7, or 0xFFF.
#[must_use]
pub fn config_offset(start_bus: u8, bus: u8, dev: u8, func: u8, reg: u16) -> Option<u64>
{
    let bus_index = bus.checked_sub(start_bus)?;
    if dev > 31 || func > 7 || reg > 0xFFF
    {
        return None;
    }
    Some(
        (u64::from(bus_index) << 20)
            | (u64::from(dev) << 15)
            | (u64::from(func) << 12)
            | u64::from(reg),
    )
}

/// Lowest set bit of `mask`: a BAR's decode size, whatever number of high
/// address bits the device implements; 0 when `mask` is 0.
fn lowest_set_bit(mask: u64) -> u64
{
    mask.isolate_lowest_one()
}

/// Size of a memory BAR from the all-ones sizing read-back of its low
/// register (`lo_sized`) and, for a 64-bit BAR, of its high register
/// (`hi_sized`). Returns 0 when no address bit reads back as writable.
#[must_use]
pub fn mmio_bar_size(lo_sized: u32, hi_sized: Option<u32>) -> u64
{
    let lo = u64::from(lo_sized & !0xF);
    let hi = hi_sized.map_or(0, |h| u64::from(h) << 32);
    lowest_set_bit(hi | lo)
}

/// Size of an I/O BAR from the all-ones sizing read-back of its register.
/// I/O space is 16 bits wide; returns 0 when no address bit below bit 16
/// reads back as writable.
#[must_use]
pub fn io_bar_size(sized: u32) -> u64
{
    lowest_set_bit(u64::from(sized & 0xFFFC))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn msix(table_bar: u8, table_offset: u32, entries: u16, pba_bar: u8, pba_offset: u32) -> Msix
    {
        Msix {
            offset: 0x40,
            table_size: entries,
            table_bar,
            table_offset,
            pba_bar,
            pba_offset,
        }
    }

    #[test]
    fn msix_entry_message_splits_the_address_and_keeps_the_data()
    {
        assert_eq!(
            msix_entry_message(0x0000_0001_FEE0_1000, 0x4021),
            Some([0xFEE0_1000, 1, 0x4021])
        );
        assert_eq!(
            msix_entry_message(0x2800_0000, 0),
            Some([0x2800_0000, 0, 0])
        );
    }

    #[test]
    fn msix_entry_message_refuses_data_wider_than_32_bits()
    {
        assert_eq!(msix_entry_message(0xFEE0_0000, 1 << 32), None);
        assert_eq!(
            msix_entry_message(0xFEE0_0000, u64::from(u32::MAX)),
            Some([0xFEE0_0000, 0, u32::MAX])
        );
    }

    #[test]
    fn msix_vector_control_sets_and_clears_only_the_mask()
    {
        assert_eq!(msix_vector_control(0xF0, true), 0xF1);
        assert_eq!(msix_vector_control(0xF1, false), 0xF0);
        assert_eq!(msix_vector_control(1, false), 0);
        assert_eq!(msix_vector_control(1, true), 1);
    }

    #[test]
    fn withheld_rounds_each_structure_out_to_its_pages()
    {
        // QEMU virtio-pci: table at 0 and PBA at 0x800 of BAR 1.
        let m = msix(1, 0, 3, 1, 0x800);
        assert_eq!(
            m.withheld(),
            [
                BarSpan {
                    bar: 1,
                    start: 0,
                    end: 0x1000
                },
                BarSpan {
                    bar: 1,
                    start: 0,
                    end: 0x1000
                },
            ]
        );
        // A table crossing a page and a PBA in another BAR.
        let m = msix(2, 0x1F00, 32, 4, 0x3008);
        assert_eq!(
            m.withheld(),
            [
                BarSpan {
                    bar: 2,
                    start: 0x1000,
                    end: 0x3000
                },
                BarSpan {
                    bar: 4,
                    start: 0x3000,
                    end: 0x4000
                },
            ]
        );
        assert_eq!(
            m.table_span(),
            (
                BarSpan {
                    bar: 2,
                    start: 0x1000,
                    end: 0x3000
                },
                0xF00
            )
        );
    }

    fn assert_ranges(bar: u8, bytes: u64, withheld: &[BarSpan], want: &[(u64, u64)])
    {
        let (ranges, count) = delivered_ranges(bar, bytes, withheld);
        assert_eq!(ranges.get(..count), Some(want));
    }

    #[test]
    fn delivered_ranges_cut_the_withheld_pages_out_of_the_bar()
    {
        let span = |bar, start, end| BarSpan { bar, start, end };
        // Nothing withheld in this BAR: the whole BAR.
        assert_ranges(0, 0x4000, &[span(1, 0, 0x1000)], &[(0, 0x4000)]);
        assert_ranges(0, 0x4000, &[], &[(0, 0x4000)]);
        // The table and PBA on the BAR's first page.
        assert_ranges(
            1,
            0x4000,
            &[span(1, 0, 0x1000), span(1, 0, 0x1000)],
            &[(0x1000, 0x3000)],
        );
        // Two spans in the middle, given out of order: three ranges.
        assert_ranges(
            2,
            0x8000,
            &[span(2, 0x5000, 0x6000), span(2, 0x1000, 0x2000)],
            &[(0, 0x1000), (0x2000, 0x3000), (0x6000, 0x2000)],
        );
        // Overlapping spans cut as their union; a span at the end leaves no tail.
        assert_ranges(
            3,
            0x4000,
            &[span(3, 0x1000, 0x3000), span(3, 0x2000, 0x4000)],
            &[(0, 0x1000)],
        );
        // The whole BAR withheld.
        assert_ranges(4, 0x1000, &[span(4, 0, 0x1000)], &[]);
        // A span past the BAR's bytes cuts nothing.
        assert_ranges(5, 0x1000, &[span(5, 0x1000, 0x2000)], &[(0, 0x1000)]);
    }

    fn info(regions: [(u8, u32, u32); 4]) -> virtio_core::VirtioPciStartupInfo
    {
        let loc = |(bar, offset, length): (u8, u32, u32)| virtio_core::VirtioCapLocation {
            bar,
            pad: [0; 3],
            offset,
            length,
        };
        virtio_core::VirtioPciStartupInfo {
            common_cfg: loc(regions[0]),
            notify_cfg: loc(regions[1]),
            isr_cfg: loc(regions[2]),
            device_cfg: loc(regions[3]),
            notify_off_multiplier: 4,
            pad: 0,
        }
    }

    #[test]
    fn virtio_regions_clear_refuses_a_region_on_a_withheld_page()
    {
        // QEMU's layout: registers in BAR 4, MSI-X in BAR 1.
        let qemu = info([
            (4, 0, 0x1000),
            (4, 0x3000, 0x1000),
            (4, 0x1000, 0x1000),
            (4, 0x2000, 0x1000),
        ]);
        let msix_bar1 = msix(1, 0, 3, 1, 0x800).withheld();
        assert!(virtio_regions_clear(&qemu, &msix_bar1));
        // The table on the page of the ISR region.
        let shared = msix(4, 0x1800, 3, 4, 0x1C00).withheld();
        assert!(!virtio_regions_clear(&qemu, &shared));
        // The PBA on the page past the device region's end touches nothing.
        let after = msix(1, 0, 3, 4, 0x4000).withheld();
        assert!(virtio_regions_clear(&qemu, &after));
        // A zero-length region reaches no page.
        let empty = info([
            (4, 0, 0x1000),
            (4, 0x3000, 0x1000),
            (4, 0x1000, 0x1000),
            (4, 0x5000, 0),
        ]);
        assert!(virtio_regions_clear(
            &empty,
            &msix(4, 0x5000, 1, 4, 0x5800).withheld()
        ));
    }

    #[test]
    fn deliverable_messages_keep_both_for_a_function_with_no_virtio_layout()
    {
        let msi = Some(Msi::decode(0x50, 0));
        let msix = Some(msix(0, 0, 4, 0, 0x800));
        // The table on the registers' page means nothing without a layout.
        assert_eq!(
            deliverable_messages(msi, msix, &virtio_core::VirtioPciStartupInfo::default()),
            (msi, msix)
        );
    }

    #[test]
    fn deliverable_messages_give_a_virtio_function_msix_alone_and_only_clear_of_its_regions()
    {
        let qemu = info([
            (4, 0, 0x1000),
            (4, 0x3000, 0x1000),
            (4, 0x1000, 0x1000),
            (4, 0x2000, 0x1000),
        ]);
        let msi = Some(Msi::decode(0x50, 0));
        let clear = Some(msix(1, 0, 3, 1, 0x800));
        assert_eq!(deliverable_messages(msi, clear, &qemu), (None, clear));
        let shared = Some(msix(4, 0x1800, 3, 1, 0x800));
        assert_eq!(deliverable_messages(msi, shared, &qemu), (None, None));
        assert_eq!(deliverable_messages(msi, None, &qemu), (None, None));
    }

    #[test]
    fn config_offset_of_the_first_bus_is_its_bdf_layout()
    {
        assert_eq!(config_offset(0, 0, 0, 0, 0), Some(0));
        assert_eq!(
            config_offset(0, 1, 2, 3, 0x10),
            Some((1 << 20) | (2 << 15) | (3 << 12) | 0x10)
        );
    }

    #[test]
    fn config_offset_is_relative_to_start_bus()
    {
        assert_eq!(config_offset(4, 4, 0, 0, 0), Some(0));
        assert_eq!(
            config_offset(4, 6, 1, 0, 4),
            Some((2 << 20) | (1 << 15) | 4)
        );
    }

    #[test]
    fn config_offset_rejects_a_bus_below_start_and_out_of_range_fields()
    {
        assert_eq!(config_offset(4, 3, 0, 0, 0), None);
        assert_eq!(config_offset(0, 0, 32, 0, 0), None);
        assert_eq!(config_offset(0, 0, 0, 8, 0), None);
        assert_eq!(config_offset(0, 0, 0, 0, 0x1000), None);
    }

    fn window(segment: u16, phys_base: u64, start_bus: u8, end_bus: u8) -> crate::EcamLocation
    {
        crate::EcamLocation {
            phys_base,
            size: (u64::from(end_bus - start_bus) + 1) << 20,
            segment,
            start_bus,
            end_bus,
        }
    }

    #[test]
    fn function_config_phys_is_its_page_in_the_window_decoding_its_bus()
    {
        let windows = [
            window(0, 0xB000_0000, 0, 0x3F),
            window(0, 0xC000_0000, 0x40, 0x7F),
            window(1, 0xD000_0000, 0, 0xFF),
        ];
        assert_eq!(
            function_config_phys(&windows, 0, 0, 3, 1),
            Some(0xB000_0000 | (3 << 15) | (1 << 12))
        );
        assert_eq!(
            function_config_phys(&windows, 0, 0x41, 0, 0),
            Some(0xC000_0000 | (1 << 20))
        );
        assert_eq!(
            function_config_phys(&windows, 1, 2, 0, 0),
            Some(0xD000_0000 | (2 << 20))
        );
    }

    #[test]
    fn function_config_phys_misses_an_undecoded_segment_or_bus_and_bad_fields()
    {
        let windows = [window(0, 0xB000_0000, 1, 0x3F)];
        assert_eq!(function_config_phys(&windows, 1, 1, 0, 0), None);
        assert_eq!(function_config_phys(&windows, 0, 0, 0, 0), None);
        assert_eq!(function_config_phys(&windows, 0, 0x40, 0, 0), None);
        assert_eq!(function_config_phys(&windows, 0, 1, 32, 0), None);
        assert_eq!(function_config_phys(&windows, 0, 1, 0, 8), None);
    }

    #[test]
    fn enabling_memory_and_bus_master_keeps_every_other_command_bit()
    {
        assert_eq!(command_with_memory_and_bus_master(0x0400), 0x0406);
        assert_eq!(command_with_memory_and_bus_master(0x0007), 0x0007);
    }

    #[test]
    fn a_bind_enables_memory_and_sets_bus_master_and_interrupt_disable_by_need()
    {
        // DMA and a wired line: Bus Master on, Interrupt Disable cleared.
        assert_eq!(command_for_bind(0x0400, true, true), 0x0006);
        // No DMA, no line: Bus Master off, Interrupt Disable set.
        assert_eq!(command_for_bind(0x0004, false, false), 0x0402);
        // Other bits (I/O Space, SERR#) are kept.
        assert_eq!(command_for_bind(0x0101, true, false), 0x0507);
    }

    #[test]
    fn interrupt_disable_is_set_keeping_every_other_bit_and_confirmed_only_when_read_set()
    {
        assert_eq!(command_with_interrupt_disable(0x0006), 0x0406);
        assert!(interrupt_disable_confirmed(0x0402));
        assert!(!interrupt_disable_confirmed(0x0002));
        assert!(!interrupt_disable_confirmed(0xFFFF));
    }

    /// A configuration header whose capability list is `caps`, each
    /// `(offset, id, next)`.
    fn header(caps: &[(u8, u8, u8)]) -> [u8; 256]
    {
        let mut cfg = [0u8; 256];
        if let Some(&(first, _, _)) = caps.first()
        {
            cfg[usize::from(CAPABILITIES_POINTER)] = first;
        }
        for &(at, id, next) in caps
        {
            cfg[usize::from(at)] = id;
            cfg[usize::from(at) + 1] = next;
        }
        cfg
    }

    #[test]
    fn the_capability_walk_finds_an_id_down_the_list()
    {
        let cfg = header(&[(0x40, 0x05, 0x60), (0x60, 0x10, 0x00)]);
        let read = |at: u16| cfg[usize::from(at)];
        assert_eq!(
            find_capability(STATUS_CAPABILITIES_LIST, CAP_ID_PCI_EXPRESS, read),
            Some(0x60)
        );
        assert_eq!(find_capability(STATUS_CAPABILITIES_LIST, 0x11, read), None);
    }

    #[test]
    fn the_capability_walk_needs_the_status_bit_and_ends_on_a_cycle()
    {
        let cfg = header(&[(0x40, 0x10, 0x00)]);
        assert_eq!(
            find_capability(0, CAP_ID_PCI_EXPRESS, |at| cfg[usize::from(at)]),
            None
        );
        let cyclic = header(&[(0x40, 0x05, 0x50), (0x50, 0x09, 0x40)]);
        assert_eq!(
            find_capability(STATUS_CAPABILITIES_LIST, CAP_ID_PCI_EXPRESS, |at| {
                cyclic[usize::from(at)]
            }),
            None
        );
    }

    #[test]
    fn msi_decode_reads_the_vector_count_and_the_layout_the_address_width_sets()
    {
        // 64-bit, Multiple Message Capable 3 (8 vectors), no masking.
        let wide = Msi::decode(0x50, 0x0086);
        assert_eq!(
            (wide.vectors, wide.address_64, wide.per_vector_mask),
            (8, true, false)
        );
        assert_eq!((wide.data_offset(), wide.mask_offset()), (0x5C, None));
        // 32-bit, one vector, per-vector masking.
        let narrow = Msi::decode(0x50, 0x0100);
        assert_eq!((narrow.vectors, narrow.address_64), (1, false));
        assert_eq!(
            (narrow.data_offset(), narrow.mask_offset()),
            (0x58, Some(0x5C))
        );
        // 64-bit with masking: data at 0x0C, Mask Bits at 0x10.
        assert_eq!(Msi::decode(0x40, 0x0180).mask_offset(), Some(0x50));
        // A reserved Multiple Message Capable encoding reads as 32 vectors.
        assert_eq!(Msi::decode(0x40, 0x000E).vectors, 32);
    }

    #[test]
    fn an_msi_message_fits_a_32_bit_capability_only_below_4_gib_and_16_bit_data()
    {
        let narrow = Msi::decode(0x50, 0);
        let wide = Msi::decode(0x50, 0x0080);
        assert!(narrow.fits(0xFEE0_0000, 0x41));
        assert!(!narrow.fits(0x1_0000_0000, 0x41));
        assert!(wide.fits(0x1_0000_0000, 0x41));
        assert!(!wide.fits(0xFEE0_0000, 0x1_0000));
    }

    #[test]
    fn msi_is_enabled_with_one_vector_and_disabled_keeping_the_other_bits()
    {
        // Multiple Message Enable 3 is cleared to 0; the capable bits stay.
        assert_eq!(msi_control_enable_one(0x00B6), 0x0087);
        assert_eq!(msi_control_disable(0x0087), 0x0086);
    }

    #[test]
    fn msix_decode_reads_the_table_size_and_the_table_and_pba_locations()
    {
        let msix = Msix::decode(0x60, 0x0007, 0x0000_2001, 0x0000_3801).unwrap();
        assert_eq!(msix.table_size, 8);
        assert_eq!((msix.table_bar, msix.table_offset), (1, 0x2000));
        assert_eq!((msix.pba_bar, msix.pba_offset), (1, 0x3800));
        assert_eq!((msix.table_bytes(), msix.table_end()), (0x80, 0x2080));
        assert_eq!((msix.pba_bytes(), msix.pba_end()), (8, 0x3808));
        // The Enable and Function Mask bits are not part of the size.
        let full = Msix::decode(0x60, 0xC7FF, 0, 0x1000).unwrap();
        assert_eq!((full.table_size, full.pba_bytes()), (2048, 256));
        // A reserved BAR register refuses the capability.
        assert_eq!(Msix::decode(0x60, 0, 0x6, 0), None);
        assert_eq!(Msix::decode(0x60, 0, 0, 0x7), None);
    }

    #[test]
    fn msix_is_enabled_under_function_mask_unmasked_and_disabled_keeping_the_size()
    {
        assert_eq!(msix_control_enable_masked(0x0007), 0xC007);
        assert_eq!(msix_control_unmask_function(0xC007), 0x8007);
        assert_eq!(msix_control_disable(0x8007), 0x4007);
    }

    fn interrupt(
        need: driver_binding::decl::InterruptNeed,
        msi_vectors: u8,
    ) -> driver_binding::decl::Interrupt
    {
        driver_binding::decl::Interrupt { need, msi_vectors }
    }

    #[test]
    fn the_plan_prefers_msix_then_msi_for_a_dma_driver_requesting_vectors()
    {
        use driver_binding::decl::InterruptNeed::{None as NoNeed, Optional, Required};
        let msi = Some(Msi::decode(0x50, 0x0080));
        let msix = Msix::decode(0x60, 0x0003, 0x1, 0x801);
        // Four table entries: a request for 8 gets 4, one for 2 gets 2.
        assert_eq!(
            interrupt_plan(interrupt(Required, 8), true, msi, msix),
            InterruptPlan::MsiX(4)
        );
        assert_eq!(
            interrupt_plan(interrupt(Optional, 2), true, None, msix),
            InterruptPlan::MsiX(2)
        );
        // MSI gives one vector, however many are requested.
        assert_eq!(
            interrupt_plan(interrupt(Optional, 8), true, msi, None),
            InterruptPlan::Msi
        );
        // Neither capability, no vectors requested, or no DMA: the wired line.
        assert_eq!(
            interrupt_plan(interrupt(Optional, 8), true, None, None),
            InterruptPlan::Wired
        );
        assert_eq!(
            interrupt_plan(interrupt(Required, 0), true, msi, msix),
            InterruptPlan::Wired
        );
        assert_eq!(
            interrupt_plan(interrupt(Required, 8), false, msi, msix),
            InterruptPlan::Wired
        );
        // No need, no interrupt.
        assert_eq!(
            interrupt_plan(interrupt(NoNeed, 0), true, msi, msix),
            InterruptPlan::None
        );
    }

    #[test]
    fn a_failed_plan_falls_back_to_msi_then_the_wired_line()
    {
        let msi = Some(Msi::decode(0x50, 0));
        assert_eq!(
            fallback(InterruptPlan::MsiX(4), msi),
            Some(InterruptPlan::Msi)
        );
        assert_eq!(
            fallback(InterruptPlan::MsiX(4), None),
            Some(InterruptPlan::Wired)
        );
        assert_eq!(
            fallback(InterruptPlan::Msi, msi),
            Some(InterruptPlan::Wired)
        );
        assert_eq!(fallback(InterruptPlan::Wired, msi), None);
        assert_eq!(fallback(InterruptPlan::None, msi), None);
    }

    #[test]
    fn a_message_that_does_not_fit_is_refused_before_any_file_is_reached()
    {
        // A 32-bit MSI capability and a target whose interrupt file is above
        // 4 GiB: no file is reached, so the step falls back.
        let narrow = Msi::decode(0x50, 0);
        let mut reached = Vec::new();
        let outcome = reach_message_files(
            &[(0x1_2800_0000_u64, 0x41_u64)],
            |&(address, data)| narrow.fits(address, data),
            |&(address, _)| {
                reached.push(address);
                Some(true)
            },
        );
        assert_eq!(outcome, Err(MessagesRefused::Unfit(0)));
        assert!(reached.is_empty());
        // Every message is checked first: a later one that does not fit
        // stops the earlier one's file from being reached too.
        let outcome = reach_message_files(
            &[(0x2800_0000_u64, 0x41_u64), (0x2800_1000, 0x1_0000)],
            |&(address, data)| narrow.fits(address, data),
            |&(address, _)| {
                reached.push(address);
                Some(true)
            },
        );
        assert_eq!(outcome, Err(MessagesRefused::Unfit(1)));
        assert!(reached.is_empty());
    }

    #[test]
    fn reaching_message_files_reports_whether_one_was_newly_mapped()
    {
        let fits = |_: &u64| true;
        // Every file reached, one of them newly.
        let mut reached = Vec::new();
        let outcome = reach_message_files(&[0x2800_0000_u64, 0x2800_1000], fits, |&a| {
            reached.push(a);
            Some(a == 0x2800_1000)
        });
        assert_eq!(outcome, Ok(true));
        assert_eq!(reached, [0x2800_0000, 0x2800_1000]);
        // Files already mapped: nothing newly mapped.
        assert_eq!(
            reach_message_files(&[0x2800_0000_u64], fits, |_| Some(false)),
            Ok(false)
        );
        // A file that cannot be reached after one newly mapped widened the
        // domain; no later file is tried.
        let mut reached = Vec::new();
        let outcome =
            reach_message_files(&[0x2800_0000_u64, 0x2800_1000, 0x2800_2000], fits, |&a| {
                reached.push(a);
                (a != 0x2800_1000).then_some(true)
            });
        assert_eq!(outcome, Err(MessagesRefused::Unreachable { widened: true }));
        assert_eq!(reached, [0x2800_0000, 0x2800_1000]);
        // The first file unreachable: nothing was widened.
        assert_eq!(
            reach_message_files(&[0x2800_0000_u64], fits, |_| None),
            Err(MessagesRefused::Unreachable { widened: false })
        );
    }

    #[test]
    fn flr_capability_is_bit_28_of_device_capabilities()
    {
        assert!(flr_capable(0x1000_8000));
        assert!(!flr_capable(0x0000_8000));
        assert!(!flr_capable(u32::MAX));
    }

    #[test]
    fn a_reset_completes_when_the_function_answers_with_a_vendor_id()
    {
        assert!(flr_completed(0x1AF4));
        assert!(!flr_completed(u16::MAX));
        assert!(!flr_completed(0x0001));
    }

    #[test]
    fn clearing_bus_master_keeps_every_other_command_bit()
    {
        assert_eq!(command_without_bus_master(0x0007), 0x0003);
        assert_eq!(command_without_bus_master(0x0406), 0x0402);
        assert_eq!(command_without_bus_master(0x0003), 0x0003);
    }

    #[test]
    fn only_a_read_back_with_bus_master_clear_confirms_it()
    {
        assert!(bus_master_confirmed_clear(0x0003));
        assert!(bus_master_confirmed_clear(0x0000));
        assert!(!bus_master_confirmed_clear(0x0007));
        // A function that does not answer reads all ones.
        assert!(!bus_master_confirmed_clear(0xFFFF));
    }

    #[test]
    fn thirty_two_bit_mmio_bar_size_is_its_lowest_writable_bit()
    {
        assert_eq!(mmio_bar_size(0xFFFF_C000, None), 0x4000);
        // Prefetchable / type flag bits are not address bits.
        assert_eq!(mmio_bar_size(0xFFFF_F00C, None), 0x1000);
        assert_eq!(mmio_bar_size(0x0000_000F, None), 0);
    }

    #[test]
    fn sixty_four_bit_mmio_bar_of_4_gib_or_more_is_sized_from_the_high_register()
    {
        assert_eq!(mmio_bar_size(0x0000_000C, Some(0xFFFF_FFFF)), 1 << 32);
        assert_eq!(mmio_bar_size(0x0000_000C, Some(0xFFFF_FFF0)), 1 << 36);
    }

    #[test]
    fn sixty_four_bit_mmio_bar_with_hardwired_high_bits_keeps_its_size()
    {
        // A device implementing only 40 address bits reads 0x0000_00FF back
        // from the high register; the size is still the low register's.
        assert_eq!(mmio_bar_size(0xFFFF_C00C, Some(0x0000_00FF)), 0x4000);
        assert_eq!(mmio_bar_size(0xFFFF_C00C, Some(0)), 0x4000);
    }

    #[test]
    fn io_bar_size_is_its_lowest_writable_bit_below_bit_16()
    {
        assert_eq!(io_bar_size(0xFFFF_FFE1), 0x20);
        assert_eq!(io_bar_size(0x0000_FFE1), 0x20);
        assert_eq!(io_bar_size(0xFFFF_0001), 0);
    }
}
