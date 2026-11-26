// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/acpi.rs

//! The bootloader's reading of the ACPI tables it consumes: the MADT's CPU
//! entries and RISC-V AIA structures, the RHCT's ISA strings, QEMU's VMGENID
//! SSDT, the TPM2 table, the SPCR's UART base, and the register windows the
//! MADT, MCFG, DMAR and TPM2 name for aperture seeding (`crate::seeds`).
//!
//! Every function reads a byte slice the caller bounded: the bootloader makes
//! a table's slice only after its header's length passed the memory-map check
//! of [`crate::region`]. The table formats (SDT header, MADT structure walk,
//! MCFG entries, DMAR structures, SPCR) are `firmware_tables`'; this module
//! holds what the bootloader takes from them. Layouts are the ACPI
//! Specification 6.5's (§ 5.2.12 MADT, § 5.2.12.18 to 5.2.12.20 the RISC-V
//! structures), the RHCT's (ACPI 6.6 § 5.2.37), the TCG ACPI Specification's
//! (TPM2) and QEMU's (VMGENID).

use boot_protocol::{AplicDomain, ImsicLayout};
use firmware_tables::acpi::{SDT_HDR_LEN, madt_structures, sdt_oem_table_id};
use firmware_tables::bytes::{read_u8, read_u16, read_u32, read_u64};

use crate::isa::{hart_caps, isa_string_has_ext};

// ── MADT ─────────────────────────────────────────────────────────────────────

/// MADT structure types the bootloader reads.
pub mod madt_type
{
    /// Processor Local APIC (x86-64), 8 bytes.
    pub const LAPIC: u8 = 0;
    /// I/O APIC (x86-64), 12 bytes.
    pub const IO_APIC: u8 = 1;
    /// Local APIC Address Override (x86-64), 12 bytes.
    pub const LAPIC_OVERRIDE: u8 = 5;
    /// Processor Local x2APIC (x86-64), 16 bytes.
    pub const LOCAL_X2APIC: u8 = 9;
    /// RISC-V Hart Local Interrupt Controller (RINTC), 36 bytes from
    /// version 1.
    pub const RINTC: u8 = 0x18;
    /// RISC-V Incoming MSI Controller (IMSIC), 16 bytes.
    pub const IMSIC: u8 = 0x19;
    /// RISC-V Advanced Platform-Level Interrupt Controller (APLIC), 36 bytes.
    pub const APLIC: u8 = 0x1A;
}

/// Lengths of the MADT structures whose fields the bootloader reads.
pub mod madt_len
{
    /// A Processor Local APIC structure.
    pub const LAPIC: usize = 8;
    /// An I/O APIC or Local APIC Address Override structure.
    pub const IO_APIC: usize = 12;
    /// A Processor Local x2APIC structure.
    pub const LOCAL_X2APIC: usize = 16;
    /// The fields of a RINTC structure through its ACPI processor UID.
    pub const RINTC_ID: usize = 20;
    /// The fields of a RINTC structure through its flags and hart ID, the
    /// least an IMSIC-file reading needs.
    pub const RINTC_HART: usize = 16;
    /// A RINTC structure that carries its hart's IMSIC file (version 1 and
    /// later).
    pub const RINTC_IMSIC: usize = 36;
    /// The IMSIC structure.
    pub const IMSIC: usize = 16;
    /// The APLIC structure.
    pub const APLIC: usize = 36;
}

/// Offset of the MADT's `LocalApicAddress` (u32), after the SDT header.
const MADT_OFF_LAPIC: usize = SDT_HDR_LEN;

/// The structures of the MADT `madt` as `(type, structure)`, in table order,
/// ending where `firmware_tables::acpi::madt_structure` ends the walk: at a
/// length under 2 or one that runs past the table. Empty for a table that is
/// not a MADT or whose length does not reach the first structure.
pub fn madt_entries(madt: &[u8]) -> impl Iterator<Item = (u8, &[u8])> + '_
{
    madt_structures(madt)
        .into_iter()
        .flatten()
        .filter_map(|(kind, at, len)| Some((kind, madt.get(at..at.checked_add(len)?)?)))
}

/// The hardware ID of the MADT structure `entry` of type `kind` when it is an
/// enabled CPU:
/// - Processor Local APIC (x86-64): its 8-bit APIC ID, when `flags` bit 0
///   (enabled) or bit 1 (online-capable) is set.
/// - Processor Local x2APIC (x86-64): its 32-bit x2APIC ID, on the same flags.
/// - RINTC (RISC-V): the low 32 bits of its hart ID, when `flags` bit 0 is set.
///
/// `None` for any other structure or one too short for its fields.
#[must_use]
pub fn madt_cpu_id(kind: u8, entry: &[u8]) -> Option<u32>
{
    match kind
    {
        // +2: ACPI processor ID, +3: APIC ID, +4: flags (u32).
        madt_type::LAPIC if entry.len() >= madt_len::LAPIC =>
        {
            (read_u32(entry, 4) & 0x3 != 0).then(|| u32::from(read_u8(entry, 3)))
        }
        // +4: x2APIC ID (u32), +8: flags (u32), +12: ACPI processor UID.
        madt_type::LOCAL_X2APIC if entry.len() >= madt_len::LOCAL_X2APIC =>
        {
            (read_u32(entry, 8) & 0x3 != 0).then(|| read_u32(entry, 4))
        }
        // +4: flags (u32), +8: hart ID (u64), +16: ACPI processor UID.
        madt_type::RINTC if entry.len() >= madt_len::RINTC_ID && read_u32(entry, 4) & 0x1 != 0 =>
        {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a RINTC's hart ID is a u64, of which the boot protocol's CPU ids carry                           the low 32 bits"
            )]
            let hart_id = read_u64(entry, 8) as u32;
            Some(hart_id)
        }
        _ => None,
    }
}

/// The hardware IDs of the MADT's enabled CPU structures ([`madt_cpu_id`]),
/// in table order; a CPU listed both as a Local APIC and as a Local x2APIC is
/// yielded twice, which [`crate::cpus::place_cpu_ids`] places once.
pub fn madt_cpu_ids(madt: &[u8]) -> impl Iterator<Item = u32> + '_
{
    madt_entries(madt).filter_map(|(kind, entry)| madt_cpu_id(kind, entry))
}

/// The supervisor-level IMSIC file the MADT structure `entry` of type `kind`
/// names, as `(hart_id, file_address, file_size)`, when it is an enabled RINTC
/// of at least [`madt_len::RINTC_HART`] bytes; address and size zero for a
/// RINTC too short to carry them (under [`madt_len::RINTC_IMSIC`]).
///
/// RINTC layout: +4 flags (u32, bit 0 enabled), +8 hart ID (u64), +16 ACPI
/// processor UID (u32), +20 external interrupt controller ID (u32), +24 IMSIC
/// base (u64), +32 IMSIC size (u32).
#[must_use]
pub fn rintc_imsic_file(kind: u8, entry: &[u8]) -> Option<(u64, u64, u64)>
{
    if kind != madt_type::RINTC
        || entry.len() < madt_len::RINTC_HART
        || read_u32(entry, 4) & 0x1 == 0
    {
        return None;
    }
    let (addr, size) = if entry.len() >= madt_len::RINTC_IMSIC
    {
        (read_u64(entry, 24), u64::from(read_u32(entry, 32)))
    }
    else
    {
        (0, 0)
    };
    Some((read_u64(entry, 8), addr, size))
}

/// The IMSIC layout the MADT structure `entry` of type `kind` states, with a
/// zero base, when it is an IMSIC structure of [`madt_len::IMSIC`] bytes or
/// more.
///
/// IMSIC layout: +4 flags (u32), +8 supervisor interrupt identities (u16),
/// +10 guest interrupt identities (u16), +12 guest index bits (u8), +13 hart
/// index bits, +14 group index bits, +15 group index shift.
#[must_use]
pub fn imsic_structure(kind: u8, entry: &[u8]) -> Option<ImsicLayout>
{
    (kind == madt_type::IMSIC && entry.len() >= madt_len::IMSIC).then(|| ImsicLayout {
        base: 0,
        ids: u32::from(read_u16(entry, 8)),
        guest_index_bits: read_u8(entry, 12),
        hart_index_bits: read_u8(entry, 13),
        group_index_bits: read_u8(entry, 14),
        group_index_shift: read_u8(entry, 15),
    })
}

/// The APLIC domain the MADT structure `entry` of type `kind` states, when it
/// is an APLIC structure of [`madt_len::APLIC`] bytes or more with a non-zero
/// base.
///
/// APLIC layout: +3 APLIC ID (u8), +4 flags (u32), +8 hardware ID (8 bytes),
/// +16 IDC count (u16), +18 external interrupt sources (u16), +20 GSI base
/// (u32), +24 base (u64), +32 size (u32).
#[must_use]
pub fn aplic_structure(kind: u8, entry: &[u8]) -> Option<AplicDomain>
{
    if kind != madt_type::APLIC || entry.len() < madt_len::APLIC || read_u64(entry, 24) == 0
    {
        return None;
    }
    Some(AplicDomain {
        base: read_u64(entry, 24),
        size: u64::from(read_u32(entry, 32)),
        sources: u64::from(read_u16(entry, 18)),
    })
}

/// What the MADT reports of the supervisor's AIA interrupt controllers
/// ([`madt_aia`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MadtAia
{
    /// The first APLIC structure with a non-zero base; zero when none.
    pub aplic: AplicDomain,
    /// The IMSIC layout; zero when the MADT has no IMSIC structure, no
    /// enabled RINTC, or [`Self::off_layout_hart`] is set.
    pub imsic: ImsicLayout,
    /// The hart ID of the first enabled RINTC whose IMSIC file address does
    /// not lie at [`ImsicLayout::s_file_address`] of its hart ID under the
    /// layout the first enabled RINTC fixes.
    pub off_layout_hart: Option<u64>,
}

/// The supervisor's APLIC domain and IMSIC layout the MADT `madt` reports.
///
/// The first IMSIC structure ([`imsic_structure`]) gives the index widths and
/// the identity count; the RINTC structures ([`rintc_imsic_file`]) give each
/// hart's file address. The layout's base is the first enabled RINTC's file
/// address less [`ImsicLayout::s_file_offset`] of its hart ID, and the layout
/// is reported only when every enabled RINTC's file lies at
/// [`ImsicLayout::s_file_address`] of its own hart ID.
#[must_use]
pub fn madt_aia(madt: &[u8]) -> MadtAia
{
    let mut found = MadtAia {
        aplic: AplicDomain::zero(),
        imsic: ImsicLayout::zero(),
        off_layout_hart: None,
    };
    let mut layout = None;
    for (kind, entry) in madt_entries(madt)
    {
        if layout.is_none()
        {
            layout = imsic_structure(kind, entry);
        }
        if found.aplic.base == 0
            && let Some(aplic) = aplic_structure(kind, entry)
        {
            found.aplic = aplic;
        }
    }
    let Some(mut layout) = layout
    else
    {
        return found;
    };
    let mut harts = 0usize;
    for (hart_id, addr, _) in madt_entries(madt).filter_map(|(k, e)| rintc_imsic_file(k, e))
    {
        if harts == 0
        {
            layout.base = imsic_base(&layout, hart_id, addr);
        }
        // `harts` counts the structures of one table, far below `usize::MAX`.
        harts = harts.saturating_add(1);
        if !file_on_layout(&layout, hart_id, addr)
        {
            found.off_layout_hart = Some(hart_id);
            return found;
        }
    }
    if harts > 0
    {
        found.imsic = layout;
    }
    found
}

/// The base of `layout` that puts hart `hart_id`'s file at `addr`; zero when
/// the layout has no offset for the hart or the offset exceeds the address.
#[must_use]
pub fn imsic_base(layout: &ImsicLayout, hart_id: u64, addr: u64) -> u64
{
    layout
        .s_file_offset(hart_id)
        .and_then(|offset| addr.checked_sub(offset))
        .unwrap_or(0)
}

/// Whether hart `hart_id`'s file `addr` is non-zero and lies at the address
/// `layout` gives it.
#[must_use]
pub fn file_on_layout(layout: &ImsicLayout, hart_id: u64, addr: u64) -> bool
{
    addr != 0 && layout.s_file_address(hart_id) == Some(addr)
}

/// The Local APIC register base the MADT `madt` gives (x86-64): its
/// `LocalApicAddress` header field, replaced by the 64-bit address of each
/// Local APIC Address Override structure in turn. Zero when the table is too
/// short for the field and names no override.
#[must_use]
pub fn madt_lapic_base(madt: &[u8]) -> u64
{
    madt_entries(madt).fold(
        u64::from(read_u32(madt, MADT_OFF_LAPIC)),
        |lapic, (kind, entry)| lapic_override(kind, entry).unwrap_or(lapic),
    )
}

/// The address a Local APIC Address Override structure `entry` of type
/// `kind` names (+4, u64); `None` for another structure or one shorter than
/// its 12 bytes.
#[must_use]
pub fn lapic_override(kind: u8, entry: &[u8]) -> Option<u64>
{
    (kind == madt_type::LAPIC_OVERRIDE && entry.len() >= madt_len::IO_APIC)
        .then(|| read_u64(entry, 4))
}

/// One I/O APIC a MADT names (x86-64); the bootloader copies it into the boot
/// protocol's `IoApicEntry`, which only the x86-64 build defines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApic
{
    /// The I/O APIC's ID.
    pub id: u32,
    /// Physical base of its register window.
    pub phys_base: u64,
    /// The first global system interrupt it serves.
    pub gsi_base: u32,
}

/// The I/O APIC an I/O APIC structure `entry` of type `kind` describes
/// (x86-64): +2 ID (u8), +4 register base (u32), +8 GSI base (u32). `None`
/// for another structure or one shorter than its 12 bytes.
#[must_use]
pub fn madt_io_apic(kind: u8, entry: &[u8]) -> Option<IoApic>
{
    (kind == madt_type::IO_APIC && entry.len() >= madt_len::IO_APIC).then(|| IoApic {
        id: u32::from(read_u8(entry, 2)),
        phys_base: u64::from(read_u32(entry, 4)),
        gsi_base: read_u32(entry, 8),
    })
}

// ── RHCT (RISC-V Hart Capabilities Table) ────────────────────────────────────

// RHCT layout after the 36-byte SDT header: 36 flags (u32), 40 time base
// frequency (u64), 48 node count (u32), 52 node offset (u32, from the table's
// start). Each node: type (u16), length (u16), revision (u16), payload. Type 0
// (ISA string): ISA length (u16), then the ISA string, NUL-terminated.
const RHCT_OFF_TIMEBASE: usize = 40;
const RHCT_OFF_NODE_COUNT: usize = 48;
const RHCT_OFF_NODE_OFFSET: usize = 52;
const RHCT_NODE_HDR_LEN: usize = 6;
const RHCT_NODE_TYPE_ISA_STRING: u16 = 0;

/// The RHCT node at `off` of `rhct`: the `HART_CAP_*` bits its ISA string
/// names when it is an ISA-string node (`None` for a node of another type),
/// and the offset of the next node. `None` where the walk ends, as for
/// [`rhct_node_isa`].
#[must_use]
pub fn rhct_node(rhct: &[u8], off: usize) -> Option<(Option<u64>, usize)>
{
    let (isa, end) = rhct_node_isa(rhct, off)?;
    Some((
        isa.map(|isa| hart_caps(|ext| isa_string_has_ext(isa, ext))),
        end,
    ))
}

/// The RHCT node at `off` of `rhct`: its ISA string, the bytes its ISA
/// length names cut at the node's end, when it is an ISA-string node (`None`
/// for a node of another type), and the offset of the next node. `None` where
/// the walk ends: a node header that does not fit, or a length under the
/// header's or running past the table.
#[must_use]
pub fn rhct_node_isa(rhct: &[u8], off: usize) -> Option<(Option<&[u8]>, usize)>
{
    let hdr_end = off.checked_add(RHCT_NODE_HDR_LEN)?;
    if hdr_end > rhct.len()
    {
        return None;
    }
    let kind = read_u16(rhct, off);
    // The node header lies inside `rhct`, so `off + 2` cannot overflow.
    let len = usize::from(read_u16(rhct, off.saturating_add(2)));
    let end = off.checked_add(len)?;
    if len < RHCT_NODE_HDR_LEN || end > rhct.len()
    {
        return None;
    }
    if kind != RHCT_NODE_TYPE_ISA_STRING || len < RHCT_NODE_HDR_LEN + 2
    {
        return Some((None, end));
    }
    let isa_len = usize::from(read_u16(rhct, hdr_end));
    // The node holds at least `RHCT_NODE_HDR_LEN + 2` bytes inside `rhct`.
    let isa_off = hdr_end.saturating_add(2);
    let isa_end = isa_off.saturating_add(isa_len).min(end);
    let isa = rhct.get(isa_off.min(isa_end)..isa_end).unwrap_or_default();
    Some((Some(isa), end))
}

/// The RHCT `rhct`'s `(time_base_frequency, hart_caps)`.
///
/// Walks at most the node count the table states, from its node offset, to
/// where [`rhct_node`] ends the walk. Each `HART_CAP_*` bit is set only when
/// at least one ISA-string node was read and every one names the extension: a
/// per-bit AND, the conservative reading of firmware that deduplicates
/// identical ISA strings into shared nodes, which spares the hart-info node
/// indirection.
#[must_use]
pub fn rhct_hart_caps(rhct: &[u8]) -> (u64, u64)
{
    let timebase = read_u64(rhct, RHCT_OFF_TIMEBASE);
    let node_count = read_u32(rhct, RHCT_OFF_NODE_COUNT);
    let mut off = read_u32(rhct, RHCT_OFF_NODE_OFFSET) as usize;
    let mut isa_nodes = 0usize;
    let mut all_caps = u64::MAX;
    for _ in 0..node_count
    {
        let Some((caps, next)) = rhct_node(rhct, off)
        else
        {
            break;
        };
        if let Some(caps) = caps
        {
            // One per node of one table, far below `usize::MAX`.
            isa_nodes = isa_nodes.saturating_add(1);
            all_caps &= caps;
        }
        off = next;
    }
    (timebase, if isa_nodes > 0 { all_caps } else { 0 })
}

// ── VMGENID (QEMU's VM Generation ID SSDT) ──────────────────────────────────
//
// QEMU publishes the VM Generation ID as an ACPI device in an SSDT whose AML
// holds a named DWORD `VGIA`, which the firmware's bios-linker-loader patches
// with the guest address of the `etc/vmgenid_guid` fw_cfg blob (4 KiB-aligned,
// below 4 GiB). The 16-byte GUID lies 40 bytes into that blob; the AML `ADDR`
// method adds the offset when evaluated, so a reader that evaluates no AML adds
// it itself. The bootloader needs the value before acpid, the service that
// evaluates AML, runs (services/acpid/README.md), so this reading is QEMU's.

/// AML of QEMU's VGIA named object: `NameOp`, the bare `NameSeg` `"VGIA"`,
/// `DWordPrefix`. The patched u32 (little-endian) follows.
const VGIA_PATTERN: [u8; 6] = [0x08, b'V', b'G', b'I', b'A', 0x0C];

/// Offset of the GUID within the `etc/vmgenid_guid` blob (QEMU's
/// `VMGENID_GUID_OFFSET`).
pub const VMGENID_GUID_OFFSET: u64 = 40;

/// The blob base the SSDT `table`'s first `VGIA` named DWORD holds, searched
/// in the table's body after its header. `None` when the pattern is absent,
/// the DWORD after it is cut short, or the value is zero or not 4 KiB-aligned
/// (the linker-loader allocates the blob page-aligned).
#[must_use]
pub fn find_vgia(table: &[u8]) -> Option<u32>
{
    let body = table.get(SDT_HDR_LEN..)?;
    let pos = body
        .windows(VGIA_PATTERN.len())
        .position(|w| w == VGIA_PATTERN)?;
    // `pos` starts a match inside `body`, so the sum cannot overflow.
    let val_off = pos.saturating_add(VGIA_PATTERN.len());
    let value = body.get(val_off..val_off.checked_add(4)?)?;
    let base = u32::from_le_bytes(value.try_into().ok()?);
    (base != 0 && base.is_multiple_of(4096)).then_some(base)
}

/// The VMGENID GUID's physical address an SSDT `table` gives (its
/// [`find_vgia`] base plus [`VMGENID_GUID_OFFSET`]), and whether its OEM table
/// ID starts with `VMGENID` (QEMU's marker). `None` for an SSDT without a
/// plausible `VGIA` or one too short for its OEM table ID.
#[must_use]
pub fn ssdt_vmgenid(table: &[u8]) -> Option<(u64, bool)>
{
    let base = find_vgia(table)?;
    let oem_table_id = sdt_oem_table_id(table)?;
    // `base` is a `u32`, so adding the small GUID offset cannot overflow.
    let guid = u64::from(base).saturating_add(VMGENID_GUID_OFFSET);
    Some((guid, oem_table_id.starts_with(b"VMGENID")))
}

/// The VMGENID GUID's physical address over the SSDTs `ssdts`, in XSDT order:
/// the first one whose OEM table ID marks it, else the first one with a
/// plausible `VGIA`; 0 when none has one.
pub fn vmgenid_guid<'a>(ssdts: impl IntoIterator<Item = &'a [u8]>) -> u64
{
    pick_vmgenid(ssdts.into_iter().map(ssdt_vmgenid))
}

/// The choice [`vmgenid_guid`] makes over the SSDTs' readings `readings`, in
/// XSDT order: the GUID of the first marked one, else of the first one with a
/// GUID; 0 when none has one.
pub fn pick_vmgenid(readings: impl IntoIterator<Item = Option<(u64, bool)>>) -> u64
{
    let mut fallback = None;
    for (guid, marked) in readings.into_iter().flatten()
    {
        if marked
        {
            return guid;
        }
        fallback.get_or_insert(guid);
    }
    fallback.unwrap_or(0)
}

// ── TPM2 ─────────────────────────────────────────────────────────────────────

// TPM2 (TCG ACPI Specification, the TPM 2.0 table), after the SDT header:
// 36 platform class (u16), 38 reserved (u16), 40 CRB control area (u64),
// 48 start method (u32), 52 start-method parameters, then the optional log
// fields.
const TPM2_OFF_CONTROL_AREA: usize = SDT_HDR_LEN + 4;
const TPM2_OFF_START_METHOD: usize = SDT_HDR_LEN + 12;
/// The shortest `TPM2` table: through the start method.
const TPM2_MIN_LEN: usize = TPM2_OFF_START_METHOD + 4;
/// Start method 6: the FIFO (TIS) interface, memory-mapped.
pub const TPM2_START_FIFO: u32 = 6;
/// Start method 7: the CRB interface, started through its `CRB_CTRL_START`
/// register.
pub const TPM2_START_CRB: u32 = 7;

/// The TPM register window to seed for the `TPM2` table `table`, given the
/// platform's TPM window `platform` (the bootloader's per-architecture
/// profile): `platform` when the table names the FIFO interface (start
/// method 6), or the CRB interface (start method 7) with its control area
/// inside `platform`. `None` for any other start method, which the TPM
/// driver does not speak (an ACPI-started CRB, a firmware TPM reached by SMC),
/// a table shorter than its start method, a CRB control area elsewhere, or a
/// platform with no TPM window.
///
/// The table gives no range of its own: its one address is the CRB control
/// area's, inside locality 0, and the FIFO interface has none.
#[must_use]
pub fn tpm2_register_window(table: &[u8], platform: Option<(u64, u64)>) -> Option<(u64, u64)>
{
    let (base, size) = platform?;
    if table.len() < TPM2_MIN_LEN
    {
        return None;
    }
    match read_u32(table, TPM2_OFF_START_METHOD)
    {
        TPM2_START_FIFO => Some((base, size)),
        TPM2_START_CRB => read_u64(table, TPM2_OFF_CONTROL_AREA)
            .checked_sub(base)
            .is_some_and(|offset| offset < size)
            .then_some((base, size)),
        _ => None,
    }
}

// ── DMAR and SPCR ────────────────────────────────────────────────────────────

/// The register window `(phys_base, size)` of a VT-d remapping unit:
/// `register_pages` 4 KiB pages from its register base. `None` when the
/// window's end overflows a 64-bit address.
#[must_use]
pub fn drhd_register_window(unit: &firmware_tables::dmar::DrhdUnit) -> Option<(u64, u64)>
{
    let size = unit.register_pages.checked_mul(0x1000)?;
    unit.register_base.checked_add(size)?;
    Some((unit.register_base, size))
}

/// The register windows of the DMAR `dmar`'s remapping units, in table order
/// (`firmware_tables::dmar::drhd_units`, which skips a unit whose base is
/// zero or not page-aligned), less any whose window overflows.
pub fn dmar_register_windows(dmar: &[u8]) -> impl Iterator<Item = (u64, u64)> + '_
{
    firmware_tables::dmar::drhd_units(dmar).filter_map(|unit| drhd_register_window(&unit))
}

/// The UART register base the SPCR `table` names, when it is a memory
/// address (`firmware_tables::spcr::spcr`); `None` for an I/O-port UART,
/// which an architecture that reaches its UART through MMIO cannot use, or a
/// table that function refuses.
#[must_use]
pub fn spcr_mmio_base(table: &[u8]) -> Option<u64>
{
    match firmware_tables::spcr::spcr(table)?.base
    {
        firmware_tables::spcr::SpcrBase::Mmio(base) => Some(base),
        firmware_tables::spcr::SpcrBase::IoPort(_) => None,
    }
}

#[cfg(test)]
mod tests
{
    use boot_protocol::{
        HART_CAP_SSAIA, HART_CAP_SSTC, HART_CAP_SVINVAL, HART_CAP_SVNAPOT, HART_CAP_SVPBMT,
        MAX_CPUS,
    };
    use firmware_tables::acpi::{MADT_ENTRIES_OFF, SDT_OFF_LENGTH};

    use super::*;
    use crate::cpus::{cpu_id_capacity, place_cpu_ids};

    /// Offset of the signature in an SDT header.
    const SDT_OFF_SIGNATURE: usize = 0;
    /// Offset of the OEM table ID in an SDT header.
    const SDT_OFF_OEM_TABLE_ID: usize = 16;

    /// A DRHD of `size` (log2 pages) at register `base`, with no scopes.
    fn drhd(size: u8, base: u64) -> [u8; 16]
    {
        let mut e = [0u8; 16];
        e[2] = 16;
        e[5] = size;
        e[8..16].copy_from_slice(&base.to_le_bytes());
        e
    }

    /// The register windows of a DMAR holding only `entry`.
    fn drhd_windows(entry: &[u8]) -> Vec<(u64, u64)>
    {
        let dmar = sdt(*b"DMAR", &[&[0u8; 12][..], entry].concat());
        dmar_register_windows(&dmar).collect()
    }

    #[test]
    fn a_drhd_seeds_its_register_window()
    {
        assert_eq!(drhd_windows(&drhd(0, 0xfed9_0000)), [(0xfed9_0000, 0x1000)]);
        assert_eq!(drhd_windows(&drhd(2, 0xfed9_0000)), [(0xfed9_0000, 0x4000)]);
    }

    #[test]
    fn a_non_drhd_or_malformed_drhd_seeds_nothing()
    {
        let mut not_drhd = drhd(0, 0xfed9_0000);
        not_drhd[0] = 1;
        assert_eq!(drhd_windows(&not_drhd), []);
        assert_eq!(drhd_windows(&drhd(0, 0xfed9_0000)[..12]), []);
        assert_eq!(drhd_windows(&drhd(0, 0)), []);
        assert_eq!(drhd_windows(&drhd(0, 0xfed9_0010)), []);
        assert_eq!(drhd_windows(&drhd(0, !0xfff)), []);
    }

    /// The PC Client TPM window the tests give [`tpm2_register_window`].
    const TPM_WINDOW: (u64, u64) = (0xFED4_0000, 0x5000);

    /// A synthetic `TPM2` table: `start_method`, the CRB control area at
    /// `control`, and no start-method parameters.
    fn tpm2(start_method: u32, control: u64) -> Vec<u8>
    {
        let mut body = vec![0u8; 4];
        body.extend_from_slice(&control.to_le_bytes());
        body.extend_from_slice(&start_method.to_le_bytes());
        body.extend_from_slice(&[0u8; 12]);
        sdt(*b"TPM2", &body)
    }

    // Defect caught: a TPM the table names left without an aperture, so
    // devmgr refuses to carve its register window and the driver never binds.
    #[test]
    fn a_fifo_or_crb_tpm2_table_seeds_the_platform_window()
    {
        let platform = Some(TPM_WINDOW);
        assert_eq!(tpm2_register_window(&tpm2(6, 0), platform), platform);
        assert_eq!(
            tpm2_register_window(&tpm2(7, 0xFED4_0040), platform),
            platform
        );
    }

    // Defect caught: a seed for a TPM the driver does not speak or the
    // window does not hold, granting devmgr a range no device decodes.
    #[test]
    fn another_start_method_or_a_crb_elsewhere_seeds_nothing()
    {
        let platform = Some(TPM_WINDOW);
        // ACPI start, and the CRB with ACPI start.
        assert_eq!(tpm2_register_window(&tpm2(2, 0xFED4_0040), platform), None);
        assert_eq!(tpm2_register_window(&tpm2(8, 0xFED4_0040), platform), None);
        // A CRB control area below and past the window.
        assert_eq!(tpm2_register_window(&tpm2(7, 0xFED3_F040), platform), None);
        assert_eq!(tpm2_register_window(&tpm2(7, 0xFED4_5040), platform), None);
        // A table cut before its start method.
        assert_eq!(
            tpm2_register_window(&tpm2(6, 0)[..TPM2_MIN_LEN - 1], platform),
            None
        );
        // A platform with no TPM window.
        assert_eq!(tpm2_register_window(&tpm2(6, 0), None), None);
    }

    /// Build a synthetic MADT: SDT header, LAPIC address and flags, then the
    /// given entries as `(type, apic_or_hart_id)` pairs, each enabled.
    fn madt(entries: &[(u8, u32)]) -> Vec<u8>
    {
        let mut t = vec![0u8; MADT_ENTRIES_OFF];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(b"APIC");
        for &(entry_type, id) in entries
        {
            match entry_type
            {
                madt_type::LAPIC =>
                {
                    t.extend_from_slice(&[madt_type::LAPIC, 8, 0, u8::try_from(id).unwrap()]);
                    t.extend_from_slice(&1u32.to_le_bytes());
                }
                madt_type::LOCAL_X2APIC =>
                {
                    t.extend_from_slice(&[madt_type::LOCAL_X2APIC, 16, 0, 0]);
                    t.extend_from_slice(&id.to_le_bytes());
                    t.extend_from_slice(&1u32.to_le_bytes());
                    t.extend_from_slice(&0u32.to_le_bytes());
                }
                madt_type::RINTC =>
                {
                    let mut e = vec![madt_type::RINTC, 36, 1, 0];
                    e.extend_from_slice(&1u32.to_le_bytes());
                    e.extend_from_slice(&u64::from(id).to_le_bytes());
                    e.resize(36, 0);
                    t.extend_from_slice(&e);
                }
                other => panic!("madt(): unsupported entry type {other}"),
            }
        }
        let len = u32::try_from(t.len()).unwrap();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// A synthetic SDT: `signature`, the length field over `body`, then
    /// `body` after the 36-byte header.
    fn sdt(signature: [u8; 4], body: &[u8]) -> Vec<u8>
    {
        let mut t = vec![0u8; SDT_HDR_LEN];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(&signature);
        t.extend_from_slice(body);
        let len = u32::try_from(t.len()).unwrap();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// The MADT QEMU 11.1 `virt` with `aia=aplic-imsic` and 4 harts in one
    /// socket hands EDK2: four RINTC v1 structures (harts 0 to 3, files at
    /// `0x2800_0000 + hart * 0x1000`), one IMSIC, one supervisor-level APLIC.
    const QEMU_VIRT_AIA_MADT: &[u8] = include_bytes!("../testdata/qemu-virt-aia-smp4-madt.bin");
    /// The RHCT of the same machine (`-cpu max` with Ssaia and Smaia).
    const QEMU_VIRT_AIA_RHCT: &[u8] = include_bytes!("../testdata/qemu-virt-aia-smp4-rhct.bin");

    /// Offset of hart `hart`'s RINTC structure in [`QEMU_VIRT_AIA_MADT`].
    fn qemu_rintc_off(hart: usize) -> usize
    {
        MADT_ENTRIES_OFF + hart * madt_len::RINTC_IMSIC
    }

    // Defect caught: an IMSIC or APLIC structure read at the wrong offsets, a
    // layout base not derived from the RINTC file addresses, or the APLIC's
    // source count taken from its IDC count.
    #[test]
    fn madt_aia_reports_the_qemu_virt_aplic_and_imsic()
    {
        let aia = madt_aia(QEMU_VIRT_AIA_MADT);
        assert_eq!(
            aia.aplic,
            AplicDomain {
                base: 0xd00_0000,
                size: 0x8000,
                sources: 96,
            }
        );
        assert_eq!(
            aia.imsic,
            ImsicLayout {
                base: 0x2800_0000,
                ids: 255,
                guest_index_bits: 0,
                hart_index_bits: 2,
                group_index_bits: 0,
                group_index_shift: 24,
            }
        );
        assert_eq!(aia.off_layout_hart, None);
    }

    // Defect caught: an IMSIC reported although a hart's RINTC names a file
    // elsewhere than the layout puts it, so the kernel would deliver that
    // hart's interrupts to another hart's file.
    #[test]
    fn madt_aia_refuses_a_rintc_file_off_the_layout()
    {
        let mut madt = QEMU_VIRT_AIA_MADT.to_vec();
        // Swap the files of harts 1 and 2.
        let one = qemu_rintc_off(1) + 24;
        let two = qemu_rintc_off(2) + 24;
        madt[one..one + 8].copy_from_slice(&0x2800_2000u64.to_le_bytes());
        madt[two..two + 8].copy_from_slice(&0x2800_1000u64.to_le_bytes());
        let aia = madt_aia(&madt);
        assert_eq!(aia.imsic, ImsicLayout::zero());
        assert_eq!(aia.off_layout_hart, Some(1));
        // The APLIC does not depend on the IMSIC layout.
        assert_eq!(aia.aplic.base, 0xd00_0000);
    }

    // Defect caught: a layout reported with no IMSIC structure, or one
    // derived from a disabled hart's RINTC.
    #[test]
    fn madt_aia_needs_an_imsic_structure_and_skips_disabled_harts()
    {
        let mut madt = QEMU_VIRT_AIA_MADT.to_vec();
        // Hart 0 disabled, with a file no layout reaches: the base comes from
        // hart 1.
        let h0 = qemu_rintc_off(0);
        madt[h0 + 4..h0 + 8].copy_from_slice(&0u32.to_le_bytes());
        madt[h0 + 24..h0 + 32].copy_from_slice(&0x1234_5000u64.to_le_bytes());
        assert_eq!(madt_aia(&madt).imsic.base, 0x2800_0000);

        // Retype the IMSIC structure: no IMSIC, so no layout and no refusal.
        let imsic = qemu_rintc_off(4);
        assert_eq!(madt[imsic], madt_type::IMSIC);
        madt[imsic] = 0x7f;
        let aia = madt_aia(&madt);
        assert_eq!(aia.imsic, ImsicLayout::zero());
        assert_eq!(aia.off_layout_hart, None);
    }

    // Defect caught: Ssaia missing from the extensions the RHCT ISA string is
    // read for, so the kernel cannot tell the harts implement it.
    #[test]
    fn the_qemu_virt_aia_rhct_confirms_ssaia()
    {
        let (timebase, caps) = rhct_hart_caps(QEMU_VIRT_AIA_RHCT);
        assert_eq!(timebase, 10_000_000);
        assert_ne!(caps & HART_CAP_SSAIA, 0);
    }

    /// Place the CPUs a synthetic MADT lists; returns the count, the filled
    /// IDs, and the truncation flag.
    fn topology_full(entries: &[(u8, u32)], bsp_id: u32) -> (u32, Vec<u32>, bool)
    {
        let table = madt(entries);
        let mut ids = vec![0u32; cpu_id_capacity(madt_cpu_ids(&table).count())];
        let (count, truncated) = place_cpu_ids(bsp_id, madt_cpu_ids(&table), &mut ids);
        (count, ids[..count as usize].to_vec(), truncated)
    }

    fn topology(entries: &[(u8, u32)], bsp_id: u32) -> (u32, Vec<u32>)
    {
        let (count, ids, truncated) = topology_full(entries, bsp_id);
        assert!(!truncated);
        (count, ids)
    }

    #[test]
    fn madt_bsp_listed_first_places_aps_in_order()
    {
        let entries = [
            (madt_type::LAPIC, 0),
            (madt_type::LAPIC, 1),
            (madt_type::LAPIC, 2),
        ];
        assert_eq!(topology(&entries, 0), (3, vec![0, 1, 2]));
    }

    #[test]
    fn madt_bsp_listed_twice_is_counted_once()
    {
        let entries = [
            (madt_type::LAPIC, 0),
            (madt_type::LOCAL_X2APIC, 0),
            (madt_type::LAPIC, 1),
        ];
        assert_eq!(topology(&entries, 0), (2, vec![0, 1]));
    }

    #[test]
    fn madt_bsp_absent_keeps_every_ap()
    {
        let entries = [(madt_type::LAPIC, 1), (madt_type::LAPIC, 2)];
        assert_eq!(topology(&entries, 0), (3, vec![0, 1, 2]));
    }

    #[test]
    fn madt_duplicated_ap_is_listed_once()
    {
        let entries = [
            (madt_type::LAPIC, 0),
            (madt_type::LAPIC, 1),
            (madt_type::LOCAL_X2APIC, 1),
        ];
        assert_eq!(topology(&entries, 0), (2, vec![0, 1]));
    }

    #[test]
    fn madt_rintc_harts_follow_the_boot_hart()
    {
        let entries = [
            (madt_type::RINTC, 0),
            (madt_type::RINTC, 1),
            (madt_type::RINTC, 2),
        ];
        assert_eq!(topology(&entries, 2), (3, vec![2, 0, 1]));
    }

    #[test]
    fn madt_without_cpu_entries_falls_back_to_the_bsp()
    {
        assert_eq!(topology(&[], 7), (1, vec![7]));
    }

    #[test]
    fn madt_surplus_beyond_max_cpus_is_dropped_and_reported()
    {
        let max = u32::try_from(MAX_CPUS).unwrap();
        let entries: Vec<(u8, u32)> = (0..=max).map(|id| (madt_type::LOCAL_X2APIC, id)).collect();
        let (count, ids, truncated) = topology_full(&entries, 0);
        assert_eq!(count, max);
        assert_eq!(ids, (0..max).collect::<Vec<u32>>());
        assert!(truncated);
    }

    #[test]
    fn madt_full_without_the_bsp_drops_one_ap_and_reports_it()
    {
        let max = u32::try_from(MAX_CPUS).unwrap();
        let entries: Vec<(u8, u32)> = (1..=max).map(|id| (madt_type::LOCAL_X2APIC, id)).collect();
        let (count, ids, truncated) = topology_full(&entries, 0);
        assert_eq!(count, max);
        assert_eq!(ids, (0..max).collect::<Vec<u32>>());
        assert!(truncated);
    }

    #[test]
    fn madt_exactly_max_cpus_with_the_bsp_is_not_truncated()
    {
        let max = u32::try_from(MAX_CPUS).unwrap();
        let entries: Vec<(u8, u32)> = (0..max).map(|id| (madt_type::LOCAL_X2APIC, id)).collect();
        assert_eq!(topology(&entries, 0), (max, (0..max).collect::<Vec<u32>>()));
    }

    /// Build a synthetic RHCT: SDT header + flags/timebase/node-count/offset
    /// header, followed by the given nodes as `(type, payload)` pairs.
    fn rhct(timebase: u64, nodes: &[(u16, &[u8])]) -> Vec<u8>
    {
        let mut t = vec![0u8; 56];
        t[SDT_OFF_SIGNATURE..SDT_OFF_SIGNATURE + 4].copy_from_slice(b"RHCT");
        t[RHCT_OFF_TIMEBASE..RHCT_OFF_TIMEBASE + 8].copy_from_slice(&timebase.to_le_bytes());
        t[RHCT_OFF_NODE_COUNT..RHCT_OFF_NODE_COUNT + 4]
            .copy_from_slice(&u32::try_from(nodes.len()).unwrap().to_le_bytes());
        t[RHCT_OFF_NODE_OFFSET..RHCT_OFF_NODE_OFFSET + 4].copy_from_slice(&56u32.to_le_bytes());

        for &(node_type, payload) in nodes
        {
            let node_len = u16::try_from(RHCT_NODE_HDR_LEN + payload.len()).unwrap();
            t.extend_from_slice(&node_type.to_le_bytes());
            t.extend_from_slice(&node_len.to_le_bytes());
            t.extend_from_slice(&1u16.to_le_bytes()); // revision
            t.extend_from_slice(payload);
        }

        let len = u32::try_from(t.len()).unwrap();
        t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
        t
    }

    /// ISA-string node payload: `{isa_len(u16), isa bytes incl. NUL}`.
    fn isa_payload(isa: &[u8]) -> Vec<u8>
    {
        let mut p = Vec::new();
        p.extend_from_slice(&u16::try_from(isa.len() + 1).unwrap().to_le_bytes());
        p.extend_from_slice(isa);
        p.push(0);
        p
    }

    #[test]
    fn rhct_timebase_and_caps()
    {
        let isa = isa_payload(b"rv64imafdcvh_zicsr_sstc_svpbmt_svinval_svnapot_svadu");
        let table = rhct(10_000_000, &[(RHCT_NODE_TYPE_ISA_STRING, &isa)]);
        assert_eq!(
            rhct_hart_caps(&table),
            (
                10_000_000,
                HART_CAP_SSTC | HART_CAP_SVPBMT | HART_CAP_SVINVAL | HART_CAP_SVNAPOT
            )
        );
    }

    #[test]
    fn rhct_caps_absent_from_isa_string()
    {
        let isa = isa_payload(b"rv64imafdc_zicsr");
        let table = rhct(10_000_000, &[(RHCT_NODE_TYPE_ISA_STRING, &isa)]);
        assert_eq!(rhct_hart_caps(&table), (10_000_000, 0));
    }

    #[test]
    fn rhct_cap_denied_only_for_the_bit_a_node_lacks()
    {
        // Per-bit AND: the second node advertises only svinval.
        let with = isa_payload(b"rv64imafdc_sstc_svinval");
        let without = isa_payload(b"rv64imafdc_svinval");
        let table = rhct(
            10_000_000,
            &[
                (RHCT_NODE_TYPE_ISA_STRING, &with),
                (RHCT_NODE_TYPE_ISA_STRING, &without),
            ],
        );
        assert_eq!(rhct_hart_caps(&table).1, HART_CAP_SVINVAL);
    }

    #[test]
    fn rhct_skips_non_isa_nodes()
    {
        let isa = isa_payload(b"rv64imafdc_sstc");
        // Hart-info node (type 0xFFFF): num_offsets=1, uid=0, one offset.
        let hart_info: &[u8] = &[1, 0, 0, 0, 0, 0, 56, 0, 0, 0];
        let table = rhct(
            10_000_000,
            &[(RHCT_NODE_TYPE_ISA_STRING, &isa), (0xFFFF, hart_info)],
        );
        assert_eq!(rhct_hart_caps(&table), (10_000_000, HART_CAP_SSTC));
    }

    #[test]
    fn rhct_no_isa_nodes_means_no_caps()
    {
        let table = rhct(10_000_000, &[]);
        assert_eq!(rhct_hart_caps(&table), (10_000_000, 0));
    }

    #[test]
    fn rhct_truncated_node_is_rejected_safely()
    {
        let isa = isa_payload(b"rv64imafdc_sstc");
        let mut table = rhct(10_000_000, &[(RHCT_NODE_TYPE_ISA_STRING, &isa)]);
        // Truncate mid-node: the walker must stop without panicking, and
        // without having confirmed any capability from a complete node.
        table.truncate(60);
        let (freq, caps) = rhct_hart_caps(&table);
        assert_eq!(freq, 10_000_000);
        assert_eq!(caps, 0);
    }

    /// Build a synthetic SSDT: SDT header + the given AML body bytes.
    fn ssdt(body: &[u8]) -> Vec<u8>
    {
        sdt(*b"SSDT", body)
    }

    /// `Name(VGIA, DWordConst)` AML fragment with the given patched value.
    fn vgia_fragment(value: u32) -> Vec<u8>
    {
        let mut f = VGIA_PATTERN.to_vec();
        f.extend_from_slice(&value.to_le_bytes());
        f
    }

    #[test]
    fn vgia_found_amid_surrounding_aml()
    {
        let mut body = vec![0x10, 0x2A, 0x5C, 0x00]; // arbitrary leading AML bytes
        body.extend_from_slice(&vgia_fragment(0x7FDE_1000));
        body.extend_from_slice(&[0xA4, 0x00]); // trailing bytes
        assert_eq!(find_vgia(&ssdt(&body)), Some(0x7FDE_1000));
    }

    #[test]
    fn vgia_absent_pattern_yields_none()
    {
        assert_eq!(find_vgia(&ssdt(&[0x10, 0x2A, 0x5C, 0x00])), None);
    }

    #[test]
    fn vgia_truncated_after_prefix_yields_none()
    {
        let mut body = VGIA_PATTERN.to_vec();
        body.extend_from_slice(&[0x00, 0x10]); // only 2 of 4 value bytes
        assert_eq!(find_vgia(&ssdt(&body)), None);
    }

    #[test]
    fn vgia_zero_value_yields_none()
    {
        assert_eq!(find_vgia(&ssdt(&vgia_fragment(0))), None);
    }

    #[test]
    fn vgia_unaligned_value_yields_none()
    {
        assert_eq!(find_vgia(&ssdt(&vgia_fragment(0x7FDE_1004))), None);
    }

    #[test]
    fn vgia_pattern_in_header_is_ignored()
    {
        // The scan starts after the SDT header; a coincidental pattern in the
        // OEM table ID bytes must not match.
        let mut t = ssdt(&[0x00; 16]);
        t[SDT_OFF_OEM_TABLE_ID..SDT_OFF_OEM_TABLE_ID + 6].copy_from_slice(&VGIA_PATTERN);
        assert_eq!(find_vgia(&t), None);
    }

    #[test]
    fn a_cpu_topology_walk_with_no_out_slot_places_nothing()
    {
        let table = madt(&[]);
        assert_eq!(place_cpu_ids(7, madt_cpu_ids(&table), &mut []).0, 0);
        let mut out = [0u32; 2];
        assert_eq!(place_cpu_ids(7, madt_cpu_ids(&table), &mut out).0, 1);
        assert_eq!(out[0], 7);
    }

    #[test]
    fn madt_entries_stop_at_a_length_that_runs_past_the_table()
    {
        // A MADT of the header, then `entries`, its length field covering them.
        let with_entries = |entries: &[u8]| {
            let mut t = madt(&[]);
            t.extend_from_slice(entries);
            let len = u32::try_from(t.len()).unwrap();
            t[SDT_OFF_LENGTH..SDT_OFF_LENGTH + 4].copy_from_slice(&len.to_le_bytes());
            t
        };
        let mut entries = vec![madt_type::IO_APIC, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        entries.extend_from_slice(&[madt_type::IO_APIC, 12, 0, 0]); // truncated entry
        let t = with_entries(&entries);
        assert_eq!(madt_entries(&t).count(), 1);
        let t = with_entries(&[madt_type::IO_APIC, 1]); // length under 2
        assert_eq!(madt_entries(&t).count(), 0);
        assert_eq!(madt_entries(&t[..MADT_ENTRIES_OFF]).count(), 0);
        assert_eq!(madt_entries(&[]).count(), 0);
    }
}

#[cfg(kani)]
mod proofs
{
    use boot_protocol::ImsicLayout;

    use crate::property::acpi as property;

    /// Every MADT structure of at most 40 bytes, of any type, reads as its
    /// layout: 36 bytes hold an APLIC and an RINTC through its IMSIC file,
    /// so every structure the bootloader reads, and each cut short, is
    /// reached. The loops of the MADT walks over the structures are the fuzz
    /// target's, against `madt_holds`. No loop.
    #[kani::proof]
    fn every_madt_structure_reads_as_its_layout()
    {
        let bytes: [u8; 40] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::structure_holds(kani::any(), &bytes[..len]);
    }

    /// Every IMSIC layout, hart and file address give the layout's base and
    /// say whether the file lies on it: the steps of `madt_aia`, whose walk
    /// the fuzz target drives against `madt_holds`. No loop.
    #[kani::proof]
    fn every_imsic_file_places_its_layout()
    {
        let layout = ImsicLayout {
            base: kani::any(),
            ids: kani::any(),
            guest_index_bits: kani::any(),
            hart_index_bits: kani::any(),
            group_index_bits: kani::any(),
            group_index_shift: kani::any(),
        };
        property::layout_step_holds(&layout, kani::any(), kani::any());
    }

    /// Every RHCT node at any offset of a table of at most 18 bytes reads as
    /// its header and the bounds of its ISA string: 18 bytes hold a node's
    /// 6-byte header, its string length and a string of 10 bytes, and a node
    /// cut short. The reading of the string is
    /// `every_isa_string_names_its_whole_segments`'s, and the loop of
    /// `rhct_hart_caps` over the nodes is the fuzz target's, against
    /// `rhct_holds`. No loop.
    #[kani::proof]
    fn every_rhct_node_reads_as_its_header()
    {
        let bytes: [u8; 18] = kani::any();
        let len: usize = kani::any();
        let off: usize = kani::any();
        kani::assume(len <= bytes.len() && off <= len);
        property::rhct_node_isa_holds(&bytes[..len], off);
    }

    /// Every SSDT of at most 47 bytes holds a `VGIA` name exactly where the
    /// search finds it: 47 bytes hold the 36-byte header, the 6-byte pattern
    /// at either of its first two places and its 4-byte value, and a table
    /// cut inside them. The loops are the search's places and the pattern's
    /// bytes.
    #[kani::proof]
    #[kani::unwind(13)]
    fn every_vgia_name_is_found_where_it_lies()
    {
        let bytes: [u8; 47] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::vgia_search_holds(&bytes[..len]);
    }

    /// Every three SSDTs' readings give the GUID of the first marked one,
    /// else of the first one with a GUID: three hold a marked reading after
    /// an unmarked one and an absent one between them. The loop is the
    /// readings.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_vmgenid_choice_takes_the_first_marked()
    {
        property::pick_holds(kani::any());
    }

    /// Every TPM2 table of at most 56 bytes, with or without the platform's
    /// window, gives the window its start method confirms: 52 bytes hold the
    /// control area and the start method. No loop.
    #[kani::proof]
    fn every_tpm2_table_confirms_its_window()
    {
        let bytes: [u8; 56] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let platform = kani::any::<bool>().then(|| (kani::any(), kani::any()));
        property::tpm2_holds(&bytes[..len], platform);
    }

    /// Every SPCR of at most 88 bytes gives its MMIO base: 80 bytes hold the
    /// table through its last field the reading takes. The loop is the
    /// signature's compare.
    #[kani::proof]
    #[kani::unwind(5)]
    fn every_spcr_gives_its_mmio_base()
    {
        let bytes: [u8; 88] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::spcr_holds(&bytes[..len]);
    }
}
