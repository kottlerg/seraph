// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/dtb.rs

//! Minimal Flattened Device Tree (FDT/DTB) parser.
//!
//! Reads in-place from the DTB blob (identity-mapped by UEFI). No allocation.
//! All header fields and tokens are big-endian. Cell-size assumptions, header
//! validation, and error handling are specified in `core/boot/docs/dtb.md`.
//!
//! # Surface
//! - [`parse_cpu_count`]: count the enabled RISC-V harts under `/cpus`,
//!   which sizes the CPU-id pages.
//! - [`place_hart_ids`]: write their hart IDs, the boot hart's first, into
//!   those pages.
//! - [`parse_hart_caps`]: extract the `/cpus` `timebase-frequency` and
//!   the `HART_CAP_*` bits every enabled hart advertises.
//! - [`parse_boot_cpu_mmu_type`]: read the boot hart's `mmu-type` paging
//!   claim for mode negotiation.
//! - [`count_aperture_seed`]: count the seeds [`parse_aperture_seed`]
//!   writes, which sizes the seed buffer.
//! - [`parse_aperture_seed`]: collect MMIO extents (CLINT, UART, PCI
//!   ECAM + ranges, `virtio,mmio` transports, the supervisor-level APLIC and
//!   IMSIC) as seeds for [`super::memory_map::derive_mmio_apertures`].
//! - [`parse_aia`]: find the supervisor-level APLIC domain and IMSIC layout,
//!   resolving the APLIC's `msi-parent` and each hart's `riscv,cpu-intc`
//!   phandle in the IMSIC's `interrupts-extended`.
//! - [`parse_rng_seed`]: extract and scrub the `/chosen/rng-seed` boot-entropy
//!   fallback.
//!
//! The arch-specific `kernel_mmio` extractor for RISC-V (UART from
//! compatible nodes, APLIC + IMSIC from [`parse_aia`]) lives under [`crate::arch::riscv64`] and
//! consumes the [`Fdt`] surface exposed here.

use crate::bprintln;
use boot_protocol::riscv_paging::PagingMode;
use boot_protocol::{
    AplicDomain, HART_CAP_SSAIA, HART_CAP_SSTC, HART_CAP_SVINVAL, HART_CAP_SVNAPOT,
    HART_CAP_SVPBMT, ImsicLayout, MmioAperture,
};
use core::sync::atomic::{AtomicBool, Ordering};

/// ISA-extension names the CPU-node walker recognizes, with the
/// `hart_caps` bit each one confirms. Shared by the DTB stringlist /
/// legacy-ISA branches here and the ACPI RHCT ISA-string parser.
pub(crate) const HART_CAP_NAMES: [(&[u8], u64); 5] = [
    (b"sstc", HART_CAP_SSTC),
    (b"svpbmt", HART_CAP_SVPBMT),
    (b"svinval", HART_CAP_SVINVAL),
    (b"svnapot", HART_CAP_SVNAPOT),
    (b"ssaia", HART_CAP_SSAIA),
];

// ── FDT constants ─────────────────────────────────────────────────────────────

const FDT_MAGIC: u32 = 0xd00d_feed;

/// FDT struct block token types (big-endian u32).
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
// `FDT_END` is named only by the test `FdtBuilder`, so `dead_code` fires only in non-test
// builds; the walkers reach it, like any unknown token, through the `_ => break` arm.
#[cfg_attr(not(test), allow(dead_code))]
const FDT_END: u32 = 9;

/// Maximum FDT node nesting depth the walkers track. Device trees in the wild
/// nest well under it (buses inside buses inside `/soc`); the cost is stack
/// only, one per-depth state per level, about 7 KiB for `walk_compatible`'s,
/// and a deeper node's properties are skipped with a diagnostic.
const MAX_DEPTH: usize = 32;

/// Maximum `reg` entries (address+size pairs) extracted per node. Only the
/// first is consumed (aperture seeds, kernel MMIO bases), apart from a
/// supervisor-level IMSIC's, whose every window holds interrupt files
/// ([`parse_aia`]); surplus entries are dropped with a diagnostic.
const MAX_REG_ENTRIES: usize = 8;
/// Maximum number of `interrupts` values collected per node. No consumer reads
/// them; surplus values are dropped with a diagnostic.
const MAX_IRQ_ENTRIES: usize = 4;
/// Size of one PCI `ranges` entry: `#address-cells` = 3 child cells, 2 parent
/// address cells and 2 size cells, each a big-endian `u32`.
const PCI_RANGES_ENTRY_BYTES: usize = 28;

// ── Public types ──────────────────────────────────────────────────────────────

/// A validated reference to an FDT blob in identity-mapped physical memory.
///
/// Constructed via [`Fdt::from_raw`]. Field offsets are validated against
/// `total_size` at construction time; subsequent reads are bounds-checked.
pub struct Fdt
{
    /// Physical base address of the DTB blob.
    base: u64,
    /// Byte offset of the struct block from blob start.
    off_struct: u32,
    /// Size of the struct block in bytes.
    size_struct: u32,
    /// Byte offset of the strings block from blob start.
    off_strings: u32,
    /// Size of the strings block in bytes.
    size_strings: u32,
}

/// Data extracted from a single FDT node.
///
/// The `irq_*` fields capture the node's `interrupts` property so the
/// walker can expose raw interrupt specifiers to callers that need them;
/// no current consumer does, but the field is part of the node's data
/// shape and the walker would have to be edited either way to remove it.
#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct FdtNode
{
    /// MMIO regions: `(base_address, size)` pairs from the `reg` property.
    pub reg_entries: [(u64, u64); MAX_REG_ENTRIES],
    /// Number of valid entries in [`reg_entries`].
    pub reg_count: usize,
    /// Interrupt specifiers from the `interrupts` property (raw u32 values).
    pub irq_entries: [u32; MAX_IRQ_ENTRIES],
    /// Number of valid entries in [`irq_entries`].
    pub irq_count: usize,
    /// Where the node's `ranges` property data lies in the struct block, as
    /// `(offset, length)`; `(0, 0)` when it has none. [`Fdt::pci_ranges`]
    /// reads its entries in place, so no entry bound applies.
    pub ranges: (u32, u32),
    /// The AIA properties of an APLIC or IMSIC node; all zero or `None` on
    /// any other node.
    pub aia: AiaProps,
}

/// The properties of an APLIC (`riscv,aplic`) or IMSIC (`riscv,imsics`) node
/// the AIA discovery reads ([`parse_aia`]); a property the node lacks reads
/// as zero, or `None` where the binding gives it a default.
#[derive(Clone, Copy)]
pub struct AiaProps
{
    /// The node's `phandle`, or 0 when it has none.
    pub phandle: u32,
    /// The first cell of `msi-parent` (the IMSIC an APLIC forwards to), or 0.
    pub msi_parent: u32,
    /// Where the node's `interrupts-extended` data lies in the struct block,
    /// as `(offset, length)`; `(0, 0)` when it has none. Read in place, so no
    /// entry bound applies.
    pub interrupts_extended: (u32, u32),
    /// `riscv,num-ids`: the identities each IMSIC file implements.
    pub num_ids: u32,
    /// `riscv,num-sources`: the sources an APLIC domain implements.
    pub num_sources: u32,
    /// `riscv,guest-index-bits`.
    pub guest_index_bits: Option<u32>,
    /// `riscv,hart-index-bits`.
    pub hart_index_bits: Option<u32>,
    /// `riscv,group-index-bits`.
    pub group_index_bits: Option<u32>,
    /// `riscv,group-index-shift`.
    pub group_index_shift: Option<u32>,
}

impl AiaProps
{
    const fn new() -> Self
    {
        AiaProps {
            phandle: 0,
            msi_parent: 0,
            interrupts_extended: (0, 0),
            num_ids: 0,
            num_sources: 0,
            guest_index_bits: None,
            hart_index_bits: None,
            group_index_bits: None,
            group_index_shift: None,
        }
    }

    /// Record `name`'s value `data` when it is one of the properties above;
    /// `data_off` and `len` locate it in the struct block for the ones read
    /// in place.
    fn record(&mut self, name: &[u8], data: &[u8], data_off: u32, len: u32)
    {
        let cell = (data.len() >= 4).then(|| read_be32(data));
        match name
        {
            b"phandle" => self.phandle = cell.unwrap_or(0),
            b"msi-parent" => self.msi_parent = cell.unwrap_or(0),
            b"interrupts-extended" => self.interrupts_extended = (data_off, len),
            b"riscv,num-ids" => self.num_ids = cell.unwrap_or(0),
            b"riscv,num-sources" => self.num_sources = cell.unwrap_or(0),
            b"riscv,guest-index-bits" => self.guest_index_bits = cell,
            b"riscv,hart-index-bits" => self.hart_index_bits = cell,
            b"riscv,group-index-bits" => self.group_index_bits = cell,
            b"riscv,group-index-shift" => self.group_index_shift = cell,
            _ =>
            {}
        }
    }
}

// ── Per-depth traversal state (private) ───────────────────────────────────────

/// Property collection state for one open node during tree traversal.
#[derive(Clone, Copy)]
struct NodeState
{
    compatible_matched: bool,
    reg_entries: [(u64, u64); MAX_REG_ENTRIES],
    reg_count: usize,
    irq_entries: [u32; MAX_IRQ_ENTRIES],
    irq_count: usize,
    ranges: (u32, u32),
    aia: AiaProps,
}

impl NodeState
{
    const fn new() -> Self
    {
        NodeState {
            compatible_matched: false,
            reg_entries: [(0, 0); MAX_REG_ENTRIES],
            reg_count: 0,
            irq_entries: [0; MAX_IRQ_ENTRIES],
            irq_count: 0,
            ranges: (0, 0),
            aia: AiaProps::new(),
        }
    }
}

/// Whether a walk has reported nodes past [`MAX_DEPTH`]; a later walk of the
/// same tree would repeat the report, so the boot reports it once.
static REPORTED_TOO_DEEP: AtomicBool = AtomicBool::new(false);
/// Whether a walk has reported a property past its entry bound, once per boot
/// for the reason [`REPORTED_TOO_DEEP`] gives.
static REPORTED_TRUNCATED: AtomicBool = AtomicBool::new(false);

/// Report, after a walk, that it skipped the properties of nodes past
/// [`MAX_DEPTH`] (`too_deep`) or dropped entries past a property's
/// `MAX_*_ENTRIES` bound (`truncated`), each the first time a walk of this
/// boot meets it.
fn report_walk_limits(too_deep: bool, truncated: bool)
{
    if too_deep && !REPORTED_TOO_DEEP.swap(true, Ordering::Relaxed)
    {
        bprintln!("[--------] boot: DTB: nodes nested past MAX_DEPTH; their properties skipped");
    }
    if truncated && !REPORTED_TRUNCATED.swap(true, Ordering::Relaxed)
    {
        bprintln!(
            "[--------] boot: DTB: a reg or interrupts property past its entry bound; surplus \
             entries dropped"
        );
    }
}

// ── Fdt implementation ────────────────────────────────────────────────────────

/// Offset of the token after a property whose data starts at `off` and is
/// `prop_len` bytes long, rounded up to the 4-byte token alignment. `None` when
/// a firmware-supplied length would overflow the offset, which ends the walk
/// like any other unreadable token.
fn advance_prop(off: u32, prop_len: u32) -> Option<u32>
{
    off.checked_add(prop_len.checked_add(3)? & !3)
}

/// Address of byte `off` of the block at `block_off` in the blob at `base`,
/// or `None` when the sum would overflow the address space.
fn block_addr(base: u64, block_off: u32, off: u32) -> Option<u64>
{
    base.checked_add(u64::from(block_off))?
        .checked_add(u64::from(off))
}

impl Fdt
{
    /// Validate and wrap an FDT blob at the given physical address.
    ///
    /// Returns `None` on bad magic or when the struct or strings block falls
    /// outside `totalsize`.
    ///
    /// # Safety
    /// `base` must be the physical address of a valid, identity-mapped FDT
    /// blob of at least 40 bytes.
    pub unsafe fn from_raw(base: u64) -> Option<Self>
    {
        // FDT header: 10 big-endian u32 fields (40 bytes total).
        // Field layout (byte offsets):
        //   0: magic  4: totalsize  8: off_dt_struct  12: off_dt_strings
        //  16: off_mem_rsvmap  20: version  24: last_comp_version
        //  28: boot_cpuid_phys  32: size_dt_strings  36: size_dt_struct
        let hdr = base as *const u32;
        // SAFETY: base is identity-mapped by UEFI; reads within firmware-provided DTB blob.
        let magic = u32::from_be(unsafe { core::ptr::read_unaligned(hdr) });
        if magic != FDT_MAGIC
        {
            return None;
        }
        // SAFETY: magic validated; remaining header fields within blob.
        let total_size = u32::from_be(unsafe { core::ptr::read_unaligned(hdr.add(1)) });
        // SAFETY: header fields within validated blob.
        let off_struct = u32::from_be(unsafe { core::ptr::read_unaligned(hdr.add(2)) });
        // SAFETY: header fields within validated blob.
        let off_strings = u32::from_be(unsafe { core::ptr::read_unaligned(hdr.add(3)) });
        // SAFETY: header fields within validated blob.
        let size_strings = u32::from_be(unsafe { core::ptr::read_unaligned(hdr.add(8)) });
        // SAFETY: header fields within validated blob.
        let size_struct = u32::from_be(unsafe { core::ptr::read_unaligned(hdr.add(9)) });

        // Bounds: struct and strings blocks must fit inside total_size.
        if off_struct.checked_add(size_struct)? > total_size
            || off_strings.checked_add(size_strings)? > total_size
        {
            return None;
        }

        Some(Fdt {
            base,
            off_struct,
            size_struct,
            off_strings,
            size_strings,
        })
    }

    /// Read a big-endian u32 from the struct block at byte offset `off`.
    /// Returns `None` if the read would exceed the struct block bounds.
    fn read_struct_u32(&self, off: u32) -> Option<u32>
    {
        if off.checked_add(4)? > self.size_struct
        {
            return None;
        }
        let addr = block_addr(self.base, self.off_struct, off)?;
        // SAFETY: offset validated above; read within struct block bounds.
        Some(u32::from_be(unsafe {
            core::ptr::read_unaligned(addr as *const u32)
        }))
    }

    /// Return a byte slice covering `len` bytes of the struct block at `off`.
    /// Returns an empty slice if out of bounds.
    fn struct_slice(&self, off: u32, len: u32) -> &[u8]
    {
        if off.checked_add(len).is_none_or(|e| e > self.size_struct)
        {
            return &[];
        }
        let Some(addr) = block_addr(self.base, self.off_struct, off)
        else
        {
            return &[];
        };
        // SAFETY: bounds validated above; slice within struct block.
        unsafe { core::slice::from_raw_parts(addr as *const u8, len as usize) }
    }

    /// Return the null-terminated string at `nameoff` in the strings block.
    /// Returns an empty slice if `nameoff` is out of range.
    fn string_at(&self, nameoff: u32) -> &[u8]
    {
        if nameoff >= self.size_strings
        {
            return &[];
        }
        let Some(addr) = block_addr(self.base, self.off_strings, nameoff)
        else
        {
            return &[];
        };
        // `nameoff` is below `size_strings`, so the subtraction does not underflow.
        let max_len = self.size_strings.saturating_sub(nameoff) as usize;
        let start = addr as *const u8;
        let mut len = 0;
        // SAFETY: nameoff validated above; pointer arithmetic within strings block.
        while len < max_len && unsafe { *start.add(len) } != 0
        {
            // `len` is below `max_len`, so it is far below `usize::MAX`.
            len = len.saturating_add(1);
        }
        // SAFETY: len ≤ max_len; slice within strings block.
        unsafe { core::slice::from_raw_parts(start, len) }
    }

    /// The PCI `ranges` entries of `node`, as `(child_flags, cpu_addr, size)`,
    /// read from the blob in place: `#address-cells` = 3, parent
    /// `#address-cells` = 2, `#size-cells` = 2, so each entry is
    /// [`PCI_RANGES_ENTRY_BYTES`] of `child_hi child_mid child_lo parent_hi
    /// parent_lo size_hi size_lo`. `child_flags` encodes the space type in bits
    /// 25:24 (1 = I/O, 2 = 32-bit MMIO, 3 = 64-bit MMIO); the child bus address
    /// is not returned, since resource extraction uses the parent address. A
    /// trailing partial entry is ignored.
    pub(crate) fn pci_ranges(&self, node: &FdtNode) -> impl Iterator<Item = (u32, u64, u64)> + '_
    {
        let data = self.struct_slice(node.ranges.0, node.ranges.1);
        data.as_chunks::<PCI_RANGES_ENTRY_BYTES>()
            .0
            .iter()
            .map(|e| (read_be32(e), read_be64(&e[12..]), read_be64(&e[20..])))
    }

    /// Walk the struct block, calling `callback` for every node whose
    /// `compatible` property contains `compat` as one of its strings.
    ///
    /// `callback` returns `true` to continue or `false` to stop early.
    // too_many_lines: DTB traversal state machine; splitting would fragment the
    // node-tracking logic across functions without meaningful abstraction.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn walk_compatible<F>(&self, compat: &[u8], mut callback: F)
    where
        F: FnMut(FdtNode) -> bool,
    {
        // Per-depth node state. Index = depth-1 (depth 0 = before root).
        let mut states = [NodeState::new(); MAX_DEPTH];
        let mut depth: usize = 0;
        let mut off: u32 = 0; // byte offset within struct block
        // Whether a node lay past MAX_DEPTH, and whether a property held more
        // entries than its MAX_*_ENTRIES bound; reported once, after the walk.
        let mut too_deep = false;
        let mut truncated = false;

        while let Some(token) = self.read_struct_u32(off)
        {
            // A read at `off` succeeded, so `off + 4` is within the struct block.
            off = off.saturating_add(4);

            match token
            {
                FDT_BEGIN_NODE =>
                {
                    if let Some(slot) = states.get_mut(depth)
                    {
                        *slot = NodeState::new();
                    }
                    else
                    {
                        too_deep = true;
                    }
                    // Each level takes at least a token of the struct block.
                    depth = depth.saturating_add(1);
                    // Skip null-terminated, 4-byte-aligned node name.
                    let Some(next) = skip_node_name(self, off)
                    else
                    {
                        break;
                    };
                    off = next;
                }
                FDT_END_NODE =>
                {
                    if depth == 0
                    {
                        break; // malformed FDT
                    }
                    // `depth` is non-zero here.
                    depth = depth.saturating_sub(1);
                    if let Some(s) = states.get(depth)
                        && s.compatible_matched
                    {
                        let node = FdtNode {
                            reg_entries: s.reg_entries,
                            reg_count: s.reg_count,
                            irq_entries: s.irq_entries,
                            irq_count: s.irq_count,
                            ranges: s.ranges,
                            aia: s.aia,
                        };
                        if !callback(node)
                        {
                            break;
                        }
                    }
                }
                FDT_PROP =>
                {
                    let Some(prop_len) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let Some(nameoff) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let data_off = off;
                    // Advance past prop data (4-byte aligned).
                    let Some(next) = advance_prop(off, prop_len)
                    else
                    {
                        break;
                    };
                    off = next;

                    // Only process properties for nodes within stack depth.
                    let Some(state) = depth.checked_sub(1).and_then(|d| states.get_mut(d))
                    else
                    {
                        continue;
                    };
                    let name = self.string_at(nameoff);

                    if name == b"compatible"
                    {
                        let data = self.struct_slice(data_off, prop_len);
                        if prop_contains(data, compat)
                        {
                            state.compatible_matched = true;
                        }
                    }
                    else if name == b"reg"
                    {
                        // #address-cells=2, #size-cells=2: each entry = 16 bytes.
                        // Each (address, size) is two big-endian u32 pairs.
                        let data = self.struct_slice(data_off, prop_len);
                        for entry in data.as_chunks::<16>().0
                        {
                            let Some(slot) = state.reg_entries.get_mut(state.reg_count)
                            else
                            {
                                truncated = true;
                                break;
                            };
                            let (addr, size) = entry.split_at(8);
                            *slot = (read_be64(addr), read_be64(size));
                            // `reg_count` indexed a slot, so it is below `MAX_REG_ENTRIES`.
                            state.reg_count = state.reg_count.saturating_add(1);
                        }
                    }
                    else if name == b"interrupts"
                    {
                        // Each 4-byte cell is one entry; the parent's
                        // `#interrupt-cells` is not resolved, so a 2-cell APLIC
                        // specifier fills two entries.
                        let data = self.struct_slice(data_off, prop_len);
                        for cell in data.as_chunks::<4>().0
                        {
                            let Some(slot) = state.irq_entries.get_mut(state.irq_count)
                            else
                            {
                                truncated = true;
                                break;
                            };
                            *slot = u32::from_be_bytes(*cell);
                            // `irq_count` indexed a slot, so it is below `MAX_IRQ_ENTRIES`.
                            state.irq_count = state.irq_count.saturating_add(1);
                        }
                    }
                    else if name == b"ranges"
                    {
                        // Recorded in place; `Fdt::pci_ranges` reads the
                        // entries, however many the property holds.
                        state.ranges = (data_off, prop_len);
                    }
                    else
                    {
                        let data = self.struct_slice(data_off, prop_len);
                        state.aia.record(name, data, data_off, prop_len);
                    }
                }
                FDT_NOP =>
                {}
                // FDT_END = end of struct block; any other token = malformed/unknown.
                _ => break,
            }
        }
        report_walk_limits(too_deep, truncated);
    }

    /// Call `f` for each node whose `compatible` property contains `compat`.
    ///
    /// Only called from `core/boot/src/arch/riscv64/serial.rs`; on x86-64 the DTB parser
    /// is still compiled but no caller for this helper exists.
    #[allow(dead_code)]
    pub fn for_each_compatible<F: FnMut(&FdtNode)>(&self, compat: &[u8], mut f: F)
    {
        self.walk_compatible(compat, |node| {
            f(&node);
            true
        });
    }

    /// Walk CPU nodes (compatible = "riscv") and call
    /// `callback(hart_id, caps, mmu)` for each enabled CPU. CPU nodes use
    /// `#address-cells=1, #size-cells=0`, so `reg` is a single big-endian
    /// u32 hart ID. `caps` carries the `HART_CAP_*` bits for every
    /// [`HART_CAP_NAMES`] extension the node advertises via
    /// `riscv,isa-extensions` (stringlist) or the legacy `riscv,isa`
    /// string.
    ///
    /// `callback` returns `true` to continue or `false` to stop early.
    ///
    /// CPU nodes without a `status` property (or with `status = "okay"`) are
    /// counted as enabled. `status = "disabled"` is skipped.
    // too_many_lines: DTB traversal state machine; splitting would fragment the
    // node-tracking logic across functions without meaningful abstraction.
    #[allow(clippy::too_many_lines)]
    pub fn walk_cpu_nodes<F>(&self, mut callback: F)
    where
        F: FnMut(u32, u64, Option<PagingMode>) -> bool,
    {
        // Node state for one open node during traversal. Independent
        // property observations; enum-ifying them would obscure the walk.
        #[derive(Clone, Copy)]
        struct CpuNodeState
        {
            is_riscv_cpu: bool,
            reg_u32: u32,
            has_reg: bool,
            disabled: bool,
            caps: u64,
            mmu: Option<PagingMode>,
        }

        let mut states = [CpuNodeState {
            is_riscv_cpu: false,
            reg_u32: 0,
            has_reg: false,
            disabled: false,
            caps: 0,
            mmu: None,
        }; MAX_DEPTH];

        let mut depth: usize = 0;
        let mut off: u32 = 0;
        // Whether a node lay past MAX_DEPTH; reported once, after the walk.
        let mut too_deep = false;

        while let Some(token) = self.read_struct_u32(off)
        {
            // A read at `off` succeeded, so `off + 4` is within the struct block.
            off = off.saturating_add(4);

            match token
            {
                FDT_BEGIN_NODE =>
                {
                    if let Some(slot) = states.get_mut(depth)
                    {
                        *slot = CpuNodeState {
                            is_riscv_cpu: false,
                            reg_u32: 0,
                            has_reg: false,
                            disabled: false,
                            caps: 0,
                            mmu: None,
                        };
                    }
                    else
                    {
                        too_deep = true;
                    }
                    // Each level takes at least a token of the struct block.
                    depth = depth.saturating_add(1);
                    let Some(next) = skip_node_name(self, off)
                    else
                    {
                        break;
                    };
                    off = next;
                }
                FDT_END_NODE =>
                {
                    if depth == 0
                    {
                        break;
                    }
                    // `depth` is non-zero here.
                    depth = depth.saturating_sub(1);
                    if let Some(s) = states.get(depth)
                        && s.is_riscv_cpu
                        && s.has_reg
                        && !s.disabled
                        && !callback(s.reg_u32, s.caps, s.mmu)
                    {
                        break;
                    }
                }
                FDT_PROP =>
                {
                    let Some(prop_len) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let Some(nameoff) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let data_off = off;
                    let Some(next) = advance_prop(off, prop_len)
                    else
                    {
                        break;
                    };
                    off = next;

                    let Some(state) = depth.checked_sub(1).and_then(|d| states.get_mut(d))
                    else
                    {
                        continue;
                    };
                    let name = self.string_at(nameoff);

                    if name == b"compatible"
                    {
                        let data = self.struct_slice(data_off, prop_len);
                        // CPU nodes carry "riscv" as one exact entry of their compatible
                        // list; prop_contains matches whole entries only.
                        if prop_contains(data, b"riscv")
                        {
                            state.is_riscv_cpu = true;
                        }
                    }
                    else if name == b"reg" && prop_len >= 4
                    {
                        // #address-cells=1 under /cpus: reg is a single BE u32.
                        let data = self.struct_slice(data_off, 4);
                        if let Some(cell) = data.first_chunk::<4>()
                        {
                            state.reg_u32 = u32::from_be_bytes(*cell);
                            state.has_reg = true;
                        }
                    }
                    else if name == b"status"
                    {
                        let data = self.struct_slice(data_off, prop_len);
                        // "disabled\0" means skip this CPU.
                        if data.starts_with(b"disabled")
                        {
                            state.disabled = true;
                        }
                    }
                    else if name == b"riscv,isa-extensions"
                    {
                        // Null-separated stringlist of extension names.
                        let data = self.struct_slice(data_off, prop_len);
                        for (ext, bit) in HART_CAP_NAMES
                        {
                            if prop_contains(data, ext)
                            {
                                state.caps |= bit;
                            }
                        }
                    }
                    else if name == b"riscv,isa"
                    {
                        // Legacy single ISA string: "rv64imafdc_…_sstc_…\0".
                        let data = self.struct_slice(data_off, prop_len);
                        for (ext, bit) in HART_CAP_NAMES
                        {
                            if isa_string_has_ext(data, ext)
                            {
                                state.caps |= bit;
                            }
                        }
                    }
                    else if name == b"mmu-type"
                    {
                        // Per the devicetree binding, the value names the
                        // widest translation mode the hart implements
                        // ("riscv,sv39" / "riscv,sv48" / "riscv,sv57");
                        // "riscv,none" and the hypervisor "riscv,svNNx4"
                        // forms carry no S-mode paging claim.
                        let data = self.struct_slice(data_off, prop_len);
                        state.mmu = if data.starts_with(b"riscv,sv39x")
                            || data.starts_with(b"riscv,sv48x")
                            || data.starts_with(b"riscv,sv57x")
                        {
                            None
                        }
                        else if data.starts_with(b"riscv,sv57")
                        {
                            Some(PagingMode::Sv57)
                        }
                        else if data.starts_with(b"riscv,sv48")
                        {
                            Some(PagingMode::Sv48)
                        }
                        else if data.starts_with(b"riscv,sv39")
                        {
                            Some(PagingMode::Sv39)
                        }
                        else
                        {
                            None
                        };
                    }
                }
                FDT_NOP =>
                {}
                // FDT_END = end of struct block; any other token = malformed/unknown.
                _ => break,
            }
        }
        report_walk_limits(too_deep, false);
    }

    /// Call `callback(phandle, hart_id)` for each CPU node `walk_cpu_nodes`
    /// reports (`compatible = "riscv"`, a one-cell `reg`, not `status =
    /// "disabled"`), `phandle` being that of its first `riscv,cpu-intc` child
    /// with a `phandle`, or 0 when it has none: dtc gives a node a `phandle`
    /// only when something references it.
    ///
    /// `callback` returns `true` to continue or `false` to stop early.
    // too_many_lines: DTB traversal state machine; splitting would fragment the
    // node-tracking logic across functions without meaningful abstraction.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn walk_cpu_intc<F>(&self, mut callback: F)
    where
        F: FnMut(u32, u32) -> bool,
    {
        #[derive(Clone, Copy)]
        struct IntcState
        {
            is_riscv_cpu: bool,
            disabled: bool,
            hart_id: Option<u32>,
            is_cpu_intc: bool,
            phandle: u32,
            /// Of a CPU node: its first `riscv,cpu-intc` child's `phandle`.
            intc_phandle: u32,
        }
        const EMPTY: IntcState = IntcState {
            is_riscv_cpu: false,
            disabled: false,
            hart_id: None,
            is_cpu_intc: false,
            phandle: 0,
            intc_phandle: 0,
        };

        let mut states = [EMPTY; MAX_DEPTH];
        let mut depth: usize = 0;
        let mut off: u32 = 0;
        let mut too_deep = false;

        while let Some(token) = self.read_struct_u32(off)
        {
            // A read at `off` succeeded, so `off + 4` is within the struct block.
            off = off.saturating_add(4);
            match token
            {
                FDT_BEGIN_NODE =>
                {
                    if let Some(slot) = states.get_mut(depth)
                    {
                        *slot = EMPTY;
                    }
                    else
                    {
                        too_deep = true;
                    }
                    // Each level takes at least a token of the struct block.
                    depth = depth.saturating_add(1);
                    let Some(next) = skip_node_name(self, off)
                    else
                    {
                        break;
                    };
                    off = next;
                }
                FDT_END_NODE =>
                {
                    if depth == 0
                    {
                        break;
                    }
                    // `depth` is non-zero here.
                    depth = depth.saturating_sub(1);
                    let Some(&s) = states.get(depth)
                    else
                    {
                        continue;
                    };
                    if s.is_cpu_intc
                        && s.phandle != 0
                        && let Some(parent) = depth.checked_sub(1).and_then(|d| states.get_mut(d))
                        && parent.intc_phandle == 0
                    {
                        parent.intc_phandle = s.phandle;
                    }
                    if s.is_riscv_cpu
                        && !s.disabled
                        && let Some(hart_id) = s.hart_id
                        && !callback(s.intc_phandle, hart_id)
                    {
                        break;
                    }
                }
                FDT_PROP =>
                {
                    let Some(prop_len) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let Some(nameoff) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let data_off = off;
                    let Some(next) = advance_prop(off, prop_len)
                    else
                    {
                        break;
                    };
                    off = next;

                    let Some(state) = depth.checked_sub(1).and_then(|d| states.get_mut(d))
                    else
                    {
                        continue;
                    };
                    let data = self.struct_slice(data_off, prop_len);
                    match self.string_at(nameoff)
                    {
                        b"compatible" =>
                        {
                            state.is_riscv_cpu |= prop_contains(data, b"riscv");
                            state.is_cpu_intc |= prop_contains(data, b"riscv,cpu-intc");
                        }
                        b"reg" if data.len() >= 4 => state.hart_id = Some(read_be32(data)),
                        b"status" => state.disabled |= data.starts_with(b"disabled"),
                        b"phandle" if data.len() >= 4 => state.phandle = read_be32(data),
                        _ =>
                        {}
                    }
                }
                FDT_NOP =>
                {}
                // FDT_END = end of struct block; any other token = malformed/unknown.
                _ => break,
            }
        }
        report_walk_limits(too_deep, false);
    }

    /// Return the first `timebase-frequency` property value in the tree, or
    /// zero when absent.
    ///
    /// The property lives on the `/cpus` container node (per-cpu duplicates,
    /// where present, carry the same value), so a flat property scan without
    /// node tracking suffices. Accepts the spec's u32 cell and, defensively,
    /// a u64 encoding.
    pub fn timebase_frequency(&self) -> u64
    {
        let mut off: u32 = 0;

        while let Some(token) = self.read_struct_u32(off)
        {
            // A read at `off` succeeded, so `off + 4` is within the struct block.
            off = off.saturating_add(4);

            match token
            {
                FDT_BEGIN_NODE =>
                {
                    let Some(next) = skip_node_name(self, off)
                    else
                    {
                        break;
                    };
                    off = next;
                }
                FDT_END_NODE | FDT_NOP =>
                {}
                FDT_PROP =>
                {
                    let Some(prop_len) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let Some(nameoff) = self.read_struct_u32(off)
                    else
                    {
                        break;
                    };
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let data_off = off;
                    let Some(next) = advance_prop(off, prop_len)
                    else
                    {
                        break;
                    };
                    off = next;

                    if self.string_at(nameoff) == b"timebase-frequency"
                    {
                        let data = self.struct_slice(data_off, prop_len);
                        let value = match prop_len
                        {
                            4 => u64::from(read_be32(data)),
                            8 => read_be64(data),
                            _ => 0,
                        };
                        if value != 0
                        {
                            return value;
                        }
                    }
                }
                // FDT_END = end of struct block; any other token = malformed/unknown.
                _ => break,
            }
        }

        0
    }

    /// Locate a property by name with a flat scan (no node tracking),
    /// returning its `(data_offset, length)` within the struct block, or
    /// `None` when absent. Suitable only for property names that are unique
    /// in the tree — `rng-seed` lives solely under `/chosen`.
    fn find_prop_flat(&self, name: &[u8]) -> Option<(u32, u32)>
    {
        let mut off: u32 = 0;
        while let Some(token) = self.read_struct_u32(off)
        {
            // A read at `off` succeeded, so `off + 4` is within the struct block.
            off = off.saturating_add(4);
            match token
            {
                FDT_BEGIN_NODE => off = skip_node_name(self, off)?,
                FDT_END_NODE | FDT_NOP =>
                {}
                FDT_PROP =>
                {
                    let prop_len = self.read_struct_u32(off)?;
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let nameoff = self.read_struct_u32(off)?;
                    // A read at `off` succeeded, so `off + 4` is within the struct block.
                    off = off.saturating_add(4);
                    let data_off = off;
                    off = advance_prop(off, prop_len)?;
                    if self.string_at(nameoff) == name
                    {
                        return Some((data_off, prop_len));
                    }
                }
                _ => break,
            }
        }
        None
    }

    /// Physical address of `len` bytes of property data at struct-block
    /// offset `data_off`, or `None` if out of bounds.
    fn prop_data_addr(&self, data_off: u32, len: u32) -> Option<u64>
    {
        if data_off.checked_add(len)? > self.size_struct
        {
            return None;
        }
        block_addr(self.base, self.off_struct, data_off)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Skip the null-terminated, 4-byte-aligned node name starting at `off` in
/// the struct block. Returns the offset after the name, or `None` when the
/// 4-byte-aligned offset after it would overflow the u32 struct-block offset
/// (a name ending at the top of a ~4 GiB struct block).
// `len` (usize) is bounded by `max` which equals `size_struct.saturating_sub(start)` (u32),
// so the `len as u32` cast below cannot truncate.
#[allow(clippy::cast_possible_truncation)]
fn skip_node_name(fdt: &Fdt, start: u32) -> Option<u32>
{
    let base_addr = block_addr(fdt.base, fdt.off_struct, start)?;
    let max = fdt.size_struct.saturating_sub(start) as usize;
    let mut len = 0;
    while len < max
    {
        // SAFETY: base_addr + len is within struct block bounds (len < max ≤ size_struct).
        let b = unsafe { core::ptr::read((base_addr as *const u8).add(len)) };
        // `len` is below `max`, so it is far below `usize::MAX`.
        len = len.saturating_add(1);
        if b == 0
        {
            break;
        }
    }
    advance_prop(start, len as u32)
}

/// Check whether `data` (a null-separated compatible string list) contains
/// `target` as one of its entries.
fn prop_contains(data: &[u8], target: &[u8]) -> bool
{
    for s in data.split(|&b| b == 0)
    {
        if s == target
        {
            return true;
        }
    }
    false
}

/// Check whether a RISC-V ISA string (`"rv64imafdc_zicsr_…_sstc_…"`,
/// optionally null-terminated) names `ext` as an underscore-separated
/// multi-letter extension.
///
/// The leading base segment (`rv64imafdc…`) can never equal a multi-letter
/// extension name, so no special-casing is needed. Shared by the DTB
/// `riscv,isa` fallback here and the ACPI RHCT ISA-string node parser in
/// [`crate::arch::riscv64`].
pub(crate) fn isa_string_has_ext(data: &[u8], ext: &[u8]) -> bool
{
    let isa = match data.iter().position(|&b| b == 0)
    {
        Some(nul) => data.get(..nul).unwrap_or(data),
        None => data,
    };
    isa.split(|&b| b == b'_').any(|seg| seg == ext)
}

/// Read a big-endian u32 from the first 4 bytes of `buf`.
/// Returns 0 if `buf` has fewer than 4 bytes.
fn read_be32(buf: &[u8]) -> u32
{
    if buf.len() < 4
    {
        return 0;
    }
    buf.first_chunk::<4>().map_or(0, |c| u32::from_be_bytes(*c))
}

/// Read a big-endian u64 from the first 8 bytes of `buf`.
/// Returns 0 if `buf` has fewer than 8 bytes.
fn read_be64(buf: &[u8]) -> u64
{
    if buf.len() < 8
    {
        return 0;
    }
    buf.first_chunk::<8>().map_or(0, |c| u64::from_be_bytes(*c))
}

// ── CPU topology parsing ──────────────────────────────────────────────────────

/// Count the enabled DTB CPU nodes: the slots [`place_hart_ids`] needs, less
/// one for a boot hart the tree may omit.
///
/// Walks nodes with `compatible = "riscv"`, which is the standard compatible
/// string for RISC-V CPU nodes. Under `/cpus`, `#address-cells=1, #size-cells=0`
/// so the `reg` property is a single big-endian u32 hart ID.
///
/// The generic [`Fdt::walk_compatible`] assumes `#address-cells=2`, so this
/// function uses [`Fdt::walk_cpu_nodes`], which reads the u32 `reg` field.
///
/// Returns 0 if no CPU nodes are found or the DTB is invalid; the caller
/// (consulted only when ACPI is absent) then defaults to a single CPU.
///
/// # Safety
/// `dtb_addr` must be the physical address of a valid, identity-mapped FDT.
pub unsafe fn parse_cpu_count(dtb_addr: u64) -> usize
{
    // SAFETY: caller guarantees dtb_addr is identity-mapped DTB.
    let Some(fdt) = (unsafe { Fdt::from_raw(dtb_addr) })
    else
    {
        return 0;
    };
    let mut count: usize = 0;
    fdt.walk_cpu_nodes(|_reg, _caps, _mmu| {
        // One per CPU node, each at least a token of the struct block.
        count = count.saturating_add(1);
        true
    });
    count
}

/// Place the enabled DTB harts into `out` (`firmware::place_cpu_ids`): the
/// boot hart `bsp_id` at index 0, then each other hart ID once, in tree order.
/// Returns the hart count; harts past `out`, sized from [`parse_cpu_count`]
/// and capped at `boot_protocol::MAX_CPUS`, are dropped with a diagnostic.
///
/// # Safety
/// As [`parse_cpu_count`]. `out` must hold at least one slot.
pub unsafe fn place_hart_ids(dtb_addr: u64, bsp_id: u32, out: &mut [u32]) -> u32
{
    let Some(first) = out.first_mut()
    else
    {
        return 0;
    };
    *first = bsp_id;
    // SAFETY: caller guarantees dtb_addr is identity-mapped DTB.
    let Some(fdt) = (unsafe { Fdt::from_raw(dtb_addr) })
    else
    {
        return 1;
    };
    // walk_cpu_nodes takes a callback, so each hart is placed as it arrives.
    let mut filled: usize = 1;
    let mut truncated = false;
    fdt.walk_cpu_nodes(|reg_u32, _caps, _mmu| {
        crate::firmware::record_cpu_id(reg_u32, out, &mut filled, &mut truncated);
        true
    });
    if truncated
    {
        bprintln!(
            "[--------] boot: DTB: more than MAX_CPUS distinct harts (boot hart included); surplus \
             dropped"
        );
    }
    // filled is at most out.len(), at most MAX_CPUS, which fits in u32.
    #[allow(clippy::cast_possible_truncation)]
    let count = filled as u32;
    count
}

/// Parse the DTB hart capabilities: the `/cpus` `timebase-frequency` and
/// the `HART_CAP_*` bits every enabled hart advertises.
///
/// Returns `(timebase_freq, hart_caps)`. `timebase_freq` is zero when the
/// property is absent. Each `hart_caps` bit is set only when at least one
/// enabled CPU node was seen and all of them advertise the corresponding
/// extension — a conservative per-bit AND, since the kernel relies on each
/// capability on every hart.
///
/// Returns `(0, 0)` if the DTB is invalid.
///
/// # Safety
/// `dtb_addr` must be the physical address of a valid, identity-mapped FDT.
// dead_code: the only caller is core/boot/src/arch/riscv64/dtb_kernel_mmio.rs;
// the module is compiled on every arch.
#[allow(dead_code)]
pub unsafe fn parse_hart_caps(dtb_addr: u64) -> (u64, u64)
{
    // SAFETY: caller guarantees dtb_addr is identity-mapped DTB.
    let Some(fdt) = (unsafe { Fdt::from_raw(dtb_addr) })
    else
    {
        return (0, 0);
    };

    let timebase_freq = fdt.timebase_frequency();

    let mut seen_any = false;
    let mut all_caps = u64::MAX;
    fdt.walk_cpu_nodes(|_hart_id, caps, _mmu| {
        seen_any = true;
        all_caps &= caps;
        true // continue
    });

    (timebase_freq, if seen_any { all_caps } else { 0 })
}

/// Read the paging mode the DTB advertises for the boot hart.
///
/// Returns the boot hart's `mmu-type` when its CPU node carries one;
/// otherwise the widest mode advertised across enabled CPU nodes (the RISC-V
/// Privileged ISA requires an implementation supporting a wider mode to also
/// support every narrower one, so "widest" is safe as a probe candidate).
/// `None` when no CPU node advertises a recognized S-mode translation mode —
/// the caller then probes from its own maximum downward.
///
/// # Safety
/// `dtb_addr` must be the physical address of a valid, identity-mapped FDT.
// dead_code: the only caller is core/boot/src/arch/riscv64/paging.rs;
// the module is compiled on every arch.
#[allow(dead_code)]
pub unsafe fn parse_boot_cpu_mmu_type(dtb_addr: u64, boot_hart_id: u64) -> Option<PagingMode>
{
    // SAFETY: caller guarantees dtb_addr is identity-mapped DTB.
    let fdt = unsafe { Fdt::from_raw(dtb_addr) }?;

    let mut boot_hart_mode: Option<PagingMode> = None;
    let mut widest: Option<PagingMode> = None;
    fdt.walk_cpu_nodes(|reg_u32, _caps, mmu| {
        if u64::from(reg_u32) == boot_hart_id && mmu.is_some()
        {
            boot_hart_mode = mmu;
            return false; // the boot hart's own claim is authoritative
        }
        if let Some(mode) = mmu
            && widest.is_none_or(|w| mode.levels() > w.levels())
        {
            widest = Some(mode);
        }
        true
    });

    boot_hart_mode.or(widest)
}

// ── AIA discovery (APLIC and IMSIC) ──────────────────────────────────────────

/// The supervisor external interrupt (`IRQ_S_EXT`), the hart-local interrupt
/// a supervisor-level IMSIC's `interrupts-extended` entries name.
const IRQ_S_EXT: u32 = 9;

/// Size of one `interrupts-extended` entry of an IMSIC node: a hart's
/// `riscv,cpu-intc` phandle and its one interrupt cell
/// (`#interrupt-cells = <1>`).
const INTERRUPTS_EXTENDED_ENTRY_BYTES: usize = 8;

/// Default `riscv,group-index-shift` of the IMSIC binding.
const IMSIC_DEFAULT_GROUP_SHIFT: u32 = 24;

/// What the DTB reports of the AIA interrupt controllers the supervisor
/// uses ([`parse_aia`]).
#[derive(Clone, Copy)]
pub struct DtbAia
{
    /// The APLIC domain that forwards to the supervisor-level IMSIC; zero
    /// when there is none.
    pub aplic: AplicDomain,
    /// The supervisor-level IMSIC layout; zero when there is none, or when
    /// [`Self::off_layout_hart`] is set.
    pub imsic: ImsicLayout,
    /// The supervisor-level IMSIC node's `reg` windows, and how many are
    /// valid: the aperture seeds of its files.
    pub imsic_regs: ([(u64, u64); MAX_REG_ENTRIES], usize),
    /// The hart ID of the first enabled hart whose supervisor-level file is
    /// missing from the IMSIC, or does not lie at the layout's
    /// [`ImsicLayout::s_file_address`] for that ID.
    pub off_layout_hart: Option<u32>,
}

/// Whether `node`, an IMSIC node, serves supervisor mode: its
/// `interrupts-extended` names at least one hart and only the supervisor
/// external interrupt.
fn is_supervisor_imsic(fdt: &Fdt, node: &FdtNode) -> bool
{
    let (off, len) = node.aia.interrupts_extended;
    let data = fdt.struct_slice(off, len);
    let entries = data.as_chunks::<INTERRUPTS_EXTENDED_ENTRY_BYTES>().0;
    !entries.is_empty() && entries.iter().all(|e| read_be32(&e[4..]) == IRQ_S_EXT)
}

/// The layout the supervisor-level IMSIC `node` states: its first `reg`
/// base, its identity count, and its index widths, a width it does not state
/// taking the binding's default (guest and group bits 0, group shift 24, hart
/// bits the fewest that index every `interrupts-extended` entry). `None`
/// when the node has no `reg` or a width does not fit its field.
fn imsic_layout(fdt: &Fdt, node: &FdtNode) -> Option<ImsicLayout>
{
    if node.reg_count == 0
    {
        return None;
    }
    let (off, len) = node.aia.interrupts_extended;
    let harts = fdt.struct_slice(off, len).len() / INTERRUPTS_EXTENDED_ENTRY_BYTES;
    // The fewest bits that give each hart an index: ceil(log2(harts)).
    let default_hart_bits = harts.saturating_sub(1).bit_width();
    let a = &node.aia;
    Some(ImsicLayout {
        base: node.reg_entries[0].0,
        ids: a.num_ids,
        guest_index_bits: u8::try_from(a.guest_index_bits.unwrap_or(0)).ok()?,
        hart_index_bits: u8::try_from(a.hart_index_bits.unwrap_or(default_hart_bits)).ok()?,
        group_index_bits: u8::try_from(a.group_index_bits.unwrap_or(0)).ok()?,
        group_index_shift: u8::try_from(a.group_index_shift.unwrap_or(IMSIC_DEFAULT_GROUP_SHIFT))
            .ok()?,
    })
}

/// Address of the file of the `index`-th `interrupts-extended` entry of the
/// IMSIC `node`: the files lie `stride` bytes apart, filling its `reg`
/// windows in order. `None` past the last window.
fn imsic_file_in_regs(node: &FdtNode, mut index: u64, stride: u64) -> Option<u64>
{
    for &(base, size) in node.reg_entries.iter().take(node.reg_count)
    {
        let files = size.checked_div(stride)?;
        if index < files
        {
            return base.checked_add(index.checked_mul(stride)?);
        }
        // `index` is at least `files` here.
        index = index.saturating_sub(files);
    }
    None
}

/// The AIA discovery behind [`parse_aia`], over a validated tree.
fn discover_aia(fdt: &Fdt) -> DtbAia
{
    let mut found = DtbAia {
        aplic: AplicDomain::zero(),
        imsic: ImsicLayout::zero(),
        imsic_regs: ([(0, 0); MAX_REG_ENTRIES], 0),
        off_layout_hart: None,
    };

    let mut imsic_node: Option<FdtNode> = None;
    fdt.walk_compatible(b"riscv,imsics", |node| {
        if is_supervisor_imsic(fdt, &node)
        {
            imsic_node = Some(node);
            return false;
        }
        true
    });
    let Some(imsic) = imsic_node
    else
    {
        return found;
    };
    found.imsic_regs = (imsic.reg_entries, imsic.reg_count);

    if imsic.aia.phandle != 0
    {
        fdt.walk_compatible(b"riscv,aplic", |node| {
            if node.aia.msi_parent == imsic.aia.phandle && node.reg_count > 0
            {
                found.aplic = AplicDomain {
                    base: node.reg_entries[0].0,
                    size: node.reg_entries[0].1,
                    sources: u64::from(node.aia.num_sources),
                };
                return false;
            }
            true
        });
    }

    let Some(layout) = imsic_layout(fdt, &imsic)
    else
    {
        return found;
    };
    // s_file_address refuses a layout outside the specification's widths, so
    // the guest bits below are at most 6 once it accepts hart 0.
    if layout.s_file_address(0).is_none()
    {
        return found;
    }
    let stride = 1u64 << (12 + u32::from(layout.guest_index_bits));
    let (ie_off, ie_len) = imsic.aia.interrupts_extended;
    let entries = fdt
        .struct_slice(ie_off, ie_len)
        .as_chunks::<INTERRUPTS_EXTENDED_ENTRY_BYTES>()
        .0;
    let mut off_layout = None;
    fdt.walk_cpu_intc(|phandle, hart_id| {
        // Phandle 0: the hart has no referenced controller, so no entry.
        let file = entries
            .iter()
            .position(|e| phandle != 0 && read_be32(e) == phandle)
            .and_then(|i| imsic_file_in_regs(&imsic, i as u64, stride));
        if file.is_none() || file != layout.s_file_address(u64::from(hart_id))
        {
            off_layout = Some(hart_id);
            return false;
        }
        true
    });
    found.off_layout_hart = off_layout;
    if off_layout.is_none()
    {
        found.imsic = layout;
    }
    found
}

/// Find the supervisor's AIA interrupt controllers in the DTB: the IMSIC
/// node (`riscv,imsics`) whose `interrupts-extended` names only the
/// supervisor external interrupt, and the APLIC node (`riscv,aplic`) whose
/// `msi-parent` is that IMSIC. The machine-level IMSIC and APLIC, which the
/// SBI firmware keeps, are never reported.
///
/// The IMSIC layout is reported only when every enabled hart's
/// `riscv,cpu-intc` appears in the IMSIC's `interrupts-extended` and the file
/// that position names lies at [`ImsicLayout::s_file_address`] of the hart's
/// ID; otherwise it is zero and a diagnostic names the first hart that
/// failed. All zero when the DTB is invalid or names no supervisor IMSIC.
///
/// # Safety
/// `dtb_addr` must be the physical address of a valid, identity-mapped FDT.
#[cfg_attr(
    all(not(target_arch = "riscv64"), not(test)),
    expect(
        dead_code,
        reason = "the only non-test caller is core/boot/src/arch/riscv64/dtb_kernel_mmio.rs; the \
                  module is compiled on every arch"
    )
)]
pub unsafe fn parse_aia(dtb_addr: u64) -> DtbAia
{
    // SAFETY: caller guarantees dtb_addr is identity-mapped DTB.
    let Some(fdt) = (unsafe { Fdt::from_raw(dtb_addr) })
    else
    {
        return DtbAia {
            aplic: AplicDomain::zero(),
            imsic: ImsicLayout::zero(),
            imsic_regs: ([(0, 0); MAX_REG_ENTRIES], 0),
            off_layout_hart: None,
        };
    };
    let found = discover_aia(&fdt);
    if let Some(hart) = found.off_layout_hart
    {
        bprintln!(
            "[--------] boot: DTB: IMSIC file of hart {hart} is not at its layout address; IMSIC \
             not reported"
        );
    }
    found
}

// ── Aperture seeder ──────────────────────────────────────────────────────────

/// Walk the DTB and collect MMIO extents into `out` for aperture seeding.
///
/// Writes up to `out.len()` [`MmioAperture`] entries covering:
/// - CLINT register window (`riscv,clint0` / `sifive,clint0`).
/// - UART register window (`ns16550a`).
/// - PCI host bridge ECAM window (`pci-host-ecam-generic`, from `reg`).
/// - PCI host bridge BAR windows (from the `ranges` property; 32-bit and
///   64-bit MMIO spaces).
/// - Each `virtio,mmio` register window.
/// - The supervisor-level APLIC domain's window and each `reg` window of its
///   IMSIC (the nodes [`parse_aia`] selects); never the machine-level ones.
///
/// Callable unconditionally on every supported architecture; a zero
/// `dtb_addr` (no DTB) is a fast no-op that returns 0. The caller
/// typically also calls [`super::acpi::parse_aperture_seed`] to cover
/// ACPI-only platforms (including QEMU+EDK2 on RISC-V, which hands the
/// bootloader ACPI rather than a DTB); both feeds merge inside
/// [`super::memory_map::derive_mmio_apertures`].
///
/// Returns the number of entries written.
///
/// # Safety
/// `dtb_addr` must be the physical address of a valid, identity-mapped
/// FDT blob. A zero `dtb_addr` returns 0 without reading.
pub unsafe fn parse_aperture_seed(dtb_addr: u64, out: &mut [MmioAperture]) -> usize
{
    // SAFETY: caller contract.
    let (written, found) = unsafe { walk_aperture_seed(dtb_addr, out) };
    if found != written
    {
        bprintln!("[--------] boot: DTB: aperture seeds past the seed buffer dropped");
    }
    written
}

/// The number of seeds [`parse_aperture_seed`] would write into a buffer
/// large enough for every one: the same walk, writing nothing. The bootloader
/// sizes the seed buffer from it before `ExitBootServices`; the blob does not
/// change between the two walks.
///
/// # Safety
/// As [`parse_aperture_seed`].
pub unsafe fn count_aperture_seed(dtb_addr: u64) -> usize
{
    // SAFETY: caller contract.
    unsafe { walk_aperture_seed(dtb_addr, &mut []) }.1
}

/// The walk behind [`parse_aperture_seed`] and [`count_aperture_seed`]:
/// returns the seeds written to `out` and the seeds found, written or not.
///
/// # Safety
/// As [`parse_aperture_seed`].
unsafe fn walk_aperture_seed(dtb_addr: u64, out: &mut [MmioAperture]) -> (usize, usize)
{
    if dtb_addr == 0
    {
        return (0, 0);
    }
    // SAFETY: caller contract.
    let Some(fdt) = (unsafe { Fdt::from_raw(dtb_addr) })
    else
    {
        return (0, 0);
    };

    let mut n: usize = 0;
    let mut found: usize = 0;

    // Push a node's first `reg` entry as an aperture seed when its size is
    // non-zero; shared by every compatible string below.
    let push_first_reg =
        |out: &mut [MmioAperture], n: &mut usize, found: &mut usize, node: &FdtNode| {
            if node.reg_count > 0 && node.reg_entries[0].1 > 0
            {
                push_seed(out, n, found, node.reg_entries[0].0, node.reg_entries[0].1);
            }
        };

    for compat in [
        &b"riscv,clint0"[..],
        &b"sifive,clint0"[..],
        &b"ns16550a"[..],
    ]
    {
        fdt.walk_compatible(compat, |node| {
            push_first_reg(out, &mut n, &mut found, &node);
            true
        });
    }

    // PCI host bridge — reg is the ECAM window; ranges entries with
    // child-space 2 (32-bit MMIO) or 3 (64-bit MMIO) are BAR windows.
    fdt.walk_compatible(b"pci-host-ecam-generic", |node| {
        push_first_reg(out, &mut n, &mut found, &node);
        for (flags, cpu_addr, size) in fdt.pci_ranges(&node)
        {
            let space = (flags >> 24) & 0x3;
            if (space == 2 || space == 3) && size > 0
            {
                push_seed(out, &mut n, &mut found, cpu_addr, size);
            }
        }
        true
    });

    // Each VirtIO MMIO transport advertises its own register window.
    fdt.walk_compatible(b"virtio,mmio", |node| {
        push_first_reg(out, &mut n, &mut found, &node);
        true
    });

    // The supervisor-level AIA controllers: the APLIC domain's window and
    // each window of its IMSIC's files. The machine-level ones belong to the
    // SBI firmware and are not seeded.
    let aia = discover_aia(&fdt);
    if aia.aplic.size > 0
    {
        push_seed(out, &mut n, &mut found, aia.aplic.base, aia.aplic.size);
    }
    for &(base, size) in aia.imsic_regs.0.iter().take(aia.imsic_regs.1)
    {
        if size > 0
        {
            push_seed(out, &mut n, &mut found, base, size);
        }
    }

    (n, found)
}

/// Count the seed `(phys_base, size)` in `found`, and append it to `out[..*n]`
/// when `out` has room.
fn push_seed(out: &mut [MmioAperture], n: &mut usize, found: &mut usize, phys_base: u64, size: u64)
{
    // One per seed found, each from a distinct node window of the blob.
    *found = found.saturating_add(1);
    if let Some(slot) = out.get_mut(*n)
    {
        *slot = MmioAperture { phys_base, size };
        // `*n` indexed a slot of `out`, so it is below `out.len()`.
        *n = n.saturating_add(1);
    }
}

/// Extract the `/chosen/rng-seed` property into `out`, scrub it from the
/// blob, and return the number of bytes copied (0 when absent).
///
/// QEMU's `virt` machine populates `rng-seed` with host-random bytes. This
/// reader is a secondary fallback for firmware that delivers a DTB; which
/// firmware exposes which boot-entropy source is documented in
/// `core/boot/docs/boot-flow.md`. The property bytes are zeroed in place
/// per `core/boot/docs/dtb.md` § Scope.
///
/// # Safety
/// `dtb_addr` must be 0 or the physical address of a valid, identity-mapped
/// (writable, pre-`ExitBootServices`) FDT blob.
pub unsafe fn parse_rng_seed(dtb_addr: u64, out: &mut [u8; 32]) -> usize
{
    if dtb_addr == 0
    {
        return 0;
    }
    // SAFETY: caller contract.
    let Some(fdt) = (unsafe { Fdt::from_raw(dtb_addr) })
    else
    {
        return 0;
    };
    let Some((data_off, prop_len)) = fdt.find_prop_flat(b"rng-seed")
    else
    {
        return 0;
    };
    let Some(addr) = fdt.prop_data_addr(data_off, prop_len)
    else
    {
        return 0;
    };

    // prop_len is a struct-block length (u32), safe as usize on 64-bit.
    let len = (prop_len as usize).min(out.len());
    let src = addr as *const u8;
    for (i, slot) in out.iter_mut().take(len).enumerate()
    {
        // SAFETY: [addr, addr+prop_len) validated within the struct block.
        *slot = unsafe { core::ptr::read(src.add(i)) };
    }
    // Scrub the full property in place (the whole seed, not just the copied
    // prefix), so nothing leaks through the userspace-visible DTB.
    let dst = addr as *mut u8;
    for i in 0..prop_len as usize
    {
        // SAFETY: same validated range; the DTB is writable pre-ExitBootServices.
        unsafe { core::ptr::write_volatile(dst.add(i), 0u8) };
    }
    len
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Minimal FDT blob builder: header + struct block + strings block, all
    /// big-endian, matching the subset of the spec the walkers consume.
    struct FdtBuilder
    {
        structs: Vec<u8>,
        strings: Vec<u8>,
    }

    impl FdtBuilder
    {
        fn new() -> Self
        {
            FdtBuilder {
                structs: Vec::new(),
                strings: Vec::new(),
            }
        }

        fn token(&mut self, t: u32)
        {
            self.structs.extend_from_slice(&t.to_be_bytes());
        }

        fn pad4(&mut self)
        {
            while self.structs.len() % 4 != 0
            {
                self.structs.push(0);
            }
        }

        fn begin_node(&mut self, name: &[u8])
        {
            self.token(FDT_BEGIN_NODE);
            self.structs.extend_from_slice(name);
            self.structs.push(0);
            self.pad4();
        }

        fn end_node(&mut self)
        {
            self.token(FDT_END_NODE);
        }

        fn string_off(&mut self, name: &[u8]) -> u32
        {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(name);
            self.strings.push(0);
            off
        }

        fn prop(&mut self, name: &[u8], data: &[u8])
        {
            let nameoff = self.string_off(name);
            self.token(FDT_PROP);
            self.token(data.len() as u32);
            self.token(nameoff);
            self.structs.extend_from_slice(data);
            self.pad4();
        }

        fn finish(mut self) -> Vec<u8>
        {
            self.token(FDT_END);
            let off_struct: u32 = 40;
            let size_struct = self.structs.len() as u32;
            let off_strings = off_struct + size_struct;
            let size_strings = self.strings.len() as u32;
            let total = off_strings + size_strings;

            let mut blob = Vec::with_capacity(total as usize);
            for field in [
                FDT_MAGIC,
                total,
                off_struct,
                off_strings,
                0, // off_mem_rsvmap (unused by the walkers)
                17,
                16,
                0,
                size_strings,
                size_struct,
            ]
            {
                blob.extend_from_slice(&field.to_be_bytes());
            }
            blob.extend_from_slice(&self.structs);
            blob.extend_from_slice(&self.strings);
            blob
        }
    }

    /// A cpu node: `compatible = "riscv"`, `reg = <hart_id>`, plus the given
    /// extra properties.
    fn cpu_node(b: &mut FdtBuilder, name: &[u8], hart_id: u32, extra: &[(&[u8], &[u8])])
    {
        b.begin_node(name);
        b.prop(b"compatible", b"riscv\0");
        b.prop(b"reg", &hart_id.to_be_bytes());
        for (pname, pdata) in extra
        {
            b.prop(pname, pdata);
        }
        b.end_node();
    }

    fn tree(timebase: Option<&[u8]>, cpus: impl FnOnce(&mut FdtBuilder)) -> Vec<u8>
    {
        let mut b = FdtBuilder::new();
        b.begin_node(b"");
        b.begin_node(b"cpus");
        if let Some(tb) = timebase
        {
            b.prop(b"timebase-frequency", tb);
        }
        cpus(&mut b);
        b.end_node();
        b.end_node();
        b.finish()
    }

    fn hart_caps(blob: &[u8]) -> (u64, u64)
    {
        // SAFETY: blob is a valid in-memory FDT built by FdtBuilder.
        unsafe { parse_hart_caps(blob.as_ptr() as u64) }
    }

    // Defect caught: a depth bound that skips the properties of a node a SoC
    // tree nests deep under buses, losing its aperture seed.
    #[test]
    fn a_node_nested_twenty_deep_is_found()
    {
        let mut b = FdtBuilder::new();
        b.begin_node(b"");
        for _ in 0..19
        {
            b.begin_node(b"bus");
        }
        b.begin_node(b"uart@10000000");
        b.prop(b"compatible", b"ns16550a\0");
        b.prop(
            b"reg",
            &[0, 0, 0, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0],
        );
        b.end_node();
        for _ in 0..19
        {
            b.end_node();
        }
        b.end_node();
        let blob = b.finish();
        // SAFETY: blob is a valid in-memory FDT built by FdtBuilder.
        let fdt = unsafe { Fdt::from_raw(blob.as_ptr() as u64) }.expect("valid FDT");
        let mut reg = None;
        fdt.walk_compatible(b"ns16550a", |node| {
            reg = Some(node.reg_entries[0]);
            false
        });
        assert_eq!(reg, Some((0x1000_0000, 0x1000)));
    }

    // Defect caught: a bound on a host bridge's ranges entries, dropping BAR
    // windows the aperture seeds need.
    #[test]
    fn a_host_bridge_with_forty_ranges_keeps_them_all()
    {
        let mut ranges = Vec::new();
        for i in 0..40u32
        {
            // child_hi (64-bit MMIO), child_mid, child_lo, parent (u64), size (u64)
            ranges.extend_from_slice(&0x0300_0000u32.to_be_bytes());
            ranges.extend_from_slice(&[0; 8]);
            ranges
                .extend_from_slice(&(0x4_0000_0000u64 + u64::from(i) * 0x1000_0000).to_be_bytes());
            ranges.extend_from_slice(&0x1000_0000u64.to_be_bytes());
        }
        let mut b = FdtBuilder::new();
        b.begin_node(b"");
        b.begin_node(b"pcie@30000000");
        b.prop(b"compatible", b"pci-host-ecam-generic\0");
        b.prop(b"ranges", &ranges);
        b.end_node();
        b.end_node();
        let blob = b.finish();
        // SAFETY: blob is a valid in-memory FDT built by FdtBuilder.
        let fdt = unsafe { Fdt::from_raw(blob.as_ptr() as u64) }.expect("valid FDT");
        let mut count = None;
        fdt.walk_compatible(b"pci-host-ecam-generic", |node| {
            count = Some(fdt.pci_ranges(&node).count());
            false
        });
        assert_eq!(count, Some(40));
    }

    // Defect caught: a count pass that finds a different number of seeds
    // than the fill pass writes, so the buffer sized from it drops seeds (or
    // a seed counted twice wastes a slot).
    #[test]
    fn the_seed_count_pass_finds_every_seed_the_fill_pass_writes()
    {
        let mut ranges = Vec::new();
        for i in 0..3u32
        {
            ranges.extend_from_slice(&0x0300_0000u32.to_be_bytes());
            ranges.extend_from_slice(&[0; 8]);
            ranges
                .extend_from_slice(&(0x4_0000_0000u64 + u64::from(i) * 0x1000_0000).to_be_bytes());
            ranges.extend_from_slice(&0x1000_0000u64.to_be_bytes());
        }
        let mut reg = Vec::new();
        reg.extend_from_slice(&0x3000_0000u64.to_be_bytes());
        reg.extend_from_slice(&0x1000_0000u64.to_be_bytes());
        let mut b = FdtBuilder::new();
        b.begin_node(b"");
        b.prop(b"#address-cells", &2u32.to_be_bytes());
        b.prop(b"#size-cells", &2u32.to_be_bytes());
        b.begin_node(b"pcie@30000000");
        b.prop(b"compatible", b"pci-host-ecam-generic\0");
        b.prop(b"reg", &reg);
        b.prop(b"ranges", &ranges);
        b.end_node();
        b.begin_node(b"virtio_mmio@10001000");
        b.prop(b"compatible", b"virtio,mmio\0");
        let mut vreg = Vec::new();
        vreg.extend_from_slice(&0x1000_1000u64.to_be_bytes());
        vreg.extend_from_slice(&0x1000u64.to_be_bytes());
        b.prop(b"reg", &vreg);
        b.end_node();
        b.end_node();
        let blob = b.finish();
        let addr = blob.as_ptr() as u64;
        // SAFETY: blob is a valid in-memory FDT built by FdtBuilder.
        let counted = unsafe { count_aperture_seed(addr) };
        let mut out = vec![
            MmioAperture {
                phys_base: 0,
                size: 0
            };
            counted + 4
        ];
        // SAFETY: as above.
        let written = unsafe { parse_aperture_seed(addr, &mut out) };
        assert_eq!(counted, written);
        assert_eq!(counted, 5, "ECAM, three windows and a virtio transport");
        // A buffer of exactly the counted size drops nothing.
        let mut exact = vec![
            MmioAperture {
                phys_base: 0,
                size: 0
            };
            counted
        ];
        // SAFETY: as above.
        assert_eq!(unsafe { parse_aperture_seed(addr, &mut exact) }, counted);
    }

    #[test]
    fn bad_magic_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        blob[0..4].copy_from_slice(&0xdead_beef_u32.to_be_bytes());
        // SAFETY: blob is a valid in-memory buffer of at least 40 bytes.
        assert!(unsafe { Fdt::from_raw(blob.as_ptr() as u64) }.is_none());
    }

    #[test]
    fn struct_block_past_totalsize_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // Header byte offsets: 4 is `totalsize`, 36 is `size_dt_struct`. A struct
        // block one byte longer than the blob, with no arithmetic overflow, must
        // fail the bounds check itself.
        let total = u32::from_be_bytes(blob[4..8].try_into().unwrap());
        blob[36..40].copy_from_slice(&(total - 40 + 1).to_be_bytes());
        // SAFETY: blob is a valid in-memory buffer of at least 40 bytes.
        assert!(unsafe { Fdt::from_raw(blob.as_ptr() as u64) }.is_none());
    }

    #[test]
    fn struct_block_extent_overflow_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // `off_dt_struct + size_dt_struct` must not overflow before the bounds
        // check; a maximal size with the 40-byte offset exercises that arm.
        blob[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
        // SAFETY: blob is a valid in-memory buffer of at least 40 bytes.
        assert!(unsafe { Fdt::from_raw(blob.as_ptr() as u64) }.is_none());
    }

    #[test]
    fn strings_block_past_totalsize_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // Header byte offset 32 is `size_dt_strings`.
        let total = u32::from_be_bytes(blob[4..8].try_into().unwrap());
        let off_strings = u32::from_be_bytes(blob[12..16].try_into().unwrap());
        blob[32..36].copy_from_slice(&(total - off_strings + 1).to_be_bytes());
        // SAFETY: blob is a valid in-memory buffer of at least 40 bytes.
        assert!(unsafe { Fdt::from_raw(blob.as_ptr() as u64) }.is_none());
    }

    #[test]
    fn strings_block_extent_overflow_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // Header byte offset 32 is `size_dt_strings`; a maximal size with a
        // non-zero offset exercises the overflow arm of the strings bound.
        blob[32..36].copy_from_slice(&u32::MAX.to_be_bytes());
        // SAFETY: blob is a valid in-memory buffer of at least 40 bytes.
        assert!(unsafe { Fdt::from_raw(blob.as_ptr() as u64) }.is_none());
    }

    #[test]
    fn property_length_overflow_ends_the_walk()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // The first FDT_PROP token in the struct block is followed by its
        // length cell; a length that overflows the offset must end the walk
        // with the results collected before it, not panic.
        let structs = 40..blob.len();
        let prop = structs
            .step_by(4)
            .find(|&i| u32::from_be_bytes(blob[i..i + 4].try_into().unwrap()) == FDT_PROP)
            .expect("the tree has a property");
        blob[prop + 4..prop + 8].copy_from_slice(&u32::MAX.to_be_bytes());
        // SAFETY: blob is a valid in-memory FDT built by FdtBuilder.
        let count = unsafe { parse_cpu_count(blob.as_ptr() as u64) };
        assert_eq!(count, 0);
        assert_eq!(hart_caps(&blob), (0, 0));
    }

    #[test]
    fn timebase_frequency_u32_cell()
    {
        let blob = tree(Some(&10_000_000u32.to_be_bytes()), |_| {});
        let (freq, _) = hart_caps(&blob);
        assert_eq!(freq, 10_000_000);
    }

    #[test]
    fn timebase_frequency_u64_cell()
    {
        let blob = tree(Some(&24_000_000u64.to_be_bytes()), |_| {});
        let (freq, _) = hart_caps(&blob);
        assert_eq!(freq, 24_000_000);
    }

    #[test]
    fn timebase_frequency_absent_is_zero()
    {
        let blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        let (freq, _) = hart_caps(&blob);
        assert_eq!(freq, 0);
    }

    #[test]
    fn caps_via_isa_extensions_stringlist()
    {
        let blob = tree(None, |b| {
            let exts: &[(&[u8], &[u8])] = &[(
                b"riscv,isa-extensions",
                b"i\0m\0sstc\0svpbmt\0svinval\0svnapot\0svadu\0",
            )];
            cpu_node(b, b"cpu@0", 0, exts);
            cpu_node(b, b"cpu@1", 1, exts);
        });
        let (_, caps) = hart_caps(&blob);
        assert_eq!(
            caps,
            HART_CAP_SSTC | HART_CAP_SVPBMT | HART_CAP_SVINVAL | HART_CAP_SVNAPOT
        );
    }

    #[test]
    fn caps_via_legacy_isa_string()
    {
        let blob = tree(None, |b| {
            cpu_node(
                b,
                b"cpu@0",
                0,
                &[(
                    b"riscv,isa",
                    b"rv64imafdc_zicsr_sstc_svinval_svnapot_svpbmt\0",
                )],
            );
        });
        let (_, caps) = hart_caps(&blob);
        assert_eq!(
            caps,
            HART_CAP_SSTC | HART_CAP_SVPBMT | HART_CAP_SVINVAL | HART_CAP_SVNAPOT
        );
    }

    #[test]
    fn cap_denied_only_for_the_bit_a_hart_lacks()
    {
        // Per-bit AND: hart 1 advertises svinval but not sstc/svpbmt, so
        // only svinval survives across the pair.
        let blob = tree(None, |b| {
            cpu_node(
                b,
                b"cpu@0",
                0,
                &[(b"riscv,isa-extensions", b"i\0sstc\0svpbmt\0svinval\0")],
            );
            cpu_node(
                b,
                b"cpu@1",
                1,
                &[(b"riscv,isa-extensions", b"i\0svinval\0")],
            );
        });
        let (_, caps) = hart_caps(&blob);
        assert_eq!(caps, HART_CAP_SVINVAL);
    }

    #[test]
    fn caps_ignore_disabled_hart()
    {
        let blob = tree(None, |b| {
            cpu_node(b, b"cpu@0", 0, &[(b"riscv,isa-extensions", b"i\0sstc\0")]);
            let disabled: &[(&[u8], &[u8])] = &[
                (b"riscv,isa-extensions", b"i\0"),
                (b"status", b"disabled\0"),
            ];
            cpu_node(b, b"cpu@1", 1, disabled);
        });
        let (_, caps) = hart_caps(&blob);
        assert_eq!(caps, HART_CAP_SSTC);
    }

    #[test]
    fn caps_zero_without_cpu_nodes()
    {
        let blob = tree(Some(&10_000_000u32.to_be_bytes()), |_| {});
        assert_eq!(hart_caps(&blob).1, 0);
    }

    #[test]
    fn isa_string_matches_whole_segments_only()
    {
        assert!(isa_string_has_ext(b"rv64imafdc_sstc", b"sstc"));
        assert!(isa_string_has_ext(b"rv64imafdc_sstc_svadu\0", b"sstc"));
        assert!(!isa_string_has_ext(b"rv64imafdc", b"sstc"));
        assert!(!isa_string_has_ext(b"rv64imafdc_ssaia", b"sstc"));
        assert!(!isa_string_has_ext(b"rv64imafdc_sstcfoo", b"sstc"));
        assert!(!isa_string_has_ext(b"", b"sstc"));
    }

    #[test]
    fn cpu_walk_still_reports_hart_ids()
    {
        let blob = tree(None, |b| {
            cpu_node(b, b"cpu@0", 7, &[]);
            cpu_node(b, b"cpu@1", 9, &[]);
        });
        // SAFETY: blob is a valid in-memory FDT built by FdtBuilder.
        let base = blob.as_ptr() as u64;
        // SAFETY: as above.
        let entries = unsafe { parse_cpu_count(base) };
        assert_eq!(entries, 2);
        let mut ids = vec![0u32; crate::firmware::cpu_id_capacity(entries)];
        // SAFETY: as above.
        let count = unsafe { place_hart_ids(base, 9, &mut ids) };
        assert_eq!(count, 2);
        assert_eq!(&ids[..2], &[9, 7]);
    }

    /// Build an FDT with a `/chosen` node carrying `rng-seed = seed`.
    fn tree_with_rng_seed(seed: &[u8]) -> Vec<u8>
    {
        let mut b = FdtBuilder::new();
        b.begin_node(b"");
        b.begin_node(b"chosen");
        b.prop(b"rng-seed", seed);
        b.end_node();
        b.end_node();
        b.finish()
    }

    #[test]
    fn rng_seed_extracted_and_scrubbed()
    {
        let seed: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_add(1));
        let mut blob = tree_with_rng_seed(&seed);
        let mut out = [0u8; 32];
        // SAFETY: blob is a valid, writable in-memory FDT.
        let n = unsafe { parse_rng_seed(blob.as_mut_ptr() as u64, &mut out) };
        assert_eq!(n, 32);
        assert_eq!(out, seed);
        // The property bytes must be zeroed in the blob after extraction.
        assert!(blob.windows(32).all(|w| w != seed));
    }

    #[test]
    fn rng_seed_absent_returns_zero()
    {
        let blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        let mut out = [0u8; 32];
        // SAFETY: blob is a valid in-memory FDT with no rng-seed property.
        let n = unsafe { parse_rng_seed(blob.as_ptr() as u64, &mut out) };
        assert_eq!(n, 0);
        assert_eq!(out, [0u8; 32]);
    }

    #[test]
    fn rng_seed_longer_than_out_is_truncated()
    {
        let seed = [0xABu8; 48];
        let mut blob = tree_with_rng_seed(&seed);
        let mut out = [0u8; 32];
        // SAFETY: blob is a valid, writable in-memory FDT.
        let n = unsafe { parse_rng_seed(blob.as_mut_ptr() as u64, &mut out) };
        assert_eq!(n, 32);
        assert_eq!(out, [0xABu8; 32]);
        // The whole 48-byte property is scrubbed, not just the copied prefix.
        assert!(blob.windows(48).all(|w| w != seed));
    }

    /// The DTB QEMU 11.1 `virt` builds with `aia=aplic-imsic` and 4 harts in
    /// one socket (`dumpdtb`, its `rng-seed` zeroed): machine- and
    /// supervisor-level IMSICs at `0x2400_0000` and `0x2800_0000`, and
    /// APLICs at `0xc00_0000` and `0xd00_0000`.
    const QEMU_VIRT_AIA_DTB: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/qemu-virt-aia-smp4.dtb"
    ));

    fn aia(blob: &[u8]) -> DtbAia
    {
        // SAFETY: blob is a valid in-memory FDT.
        unsafe { parse_aia(blob.as_ptr() as u64) }
    }

    fn seeds(blob: &[u8]) -> Vec<(u64, u64)>
    {
        let addr = blob.as_ptr() as u64;
        // SAFETY: blob is a valid in-memory FDT.
        let count = unsafe { count_aperture_seed(addr) };
        let mut out = vec![
            MmioAperture {
                phys_base: 0,
                size: 0
            };
            count
        ];
        // SAFETY: as above.
        let n = unsafe { parse_aperture_seed(addr, &mut out) };
        out[..n].iter().map(|a| (a.phys_base, a.size)).collect()
    }

    // Defect caught: the machine-level IMSIC or APLIC (the SBI firmware's)
    // reported in place of the supervisor-level ones, the IMSIC binding's
    // defaults not applied, or the APLIC's source count not read.
    #[test]
    fn the_qemu_virt_aia_dtb_reports_the_supervisor_aplic_and_imsic()
    {
        let found = aia(QEMU_VIRT_AIA_DTB);
        assert_eq!(
            found.aplic,
            AplicDomain {
                base: 0xd00_0000,
                size: 0x8000,
                sources: 96,
            }
        );
        assert_eq!(
            found.imsic,
            ImsicLayout {
                base: 0x2800_0000,
                ids: 255,
                guest_index_bits: 0,
                hart_index_bits: 2,
                group_index_bits: 0,
                group_index_shift: 24,
            }
        );
        assert_eq!(found.off_layout_hart, None);
    }

    // Defect caught: the supervisor-level APLIC and IMSIC missing from the
    // aperture seeds, or the machine-level ones seeded, which OpenSBI's PMP
    // denies the supervisor.
    #[test]
    fn the_qemu_virt_aia_dtb_seeds_only_the_supervisor_aplic_and_imsic()
    {
        let s = seeds(QEMU_VIRT_AIA_DTB);
        assert!(s.contains(&(0xd00_0000, 0x8000)), "{s:x?}");
        assert!(s.contains(&(0x2800_0000, 0x4000)), "{s:x?}");
        assert!(
            !s.iter().any(|&(b, _)| b == 0xc00_0000 || b == 0x2400_0000),
            "{s:x?}"
        );
    }

    // Defect caught: Ssaia missing from the extensions the CPU nodes are read
    // for, so the kernel cannot tell the harts implement it.
    #[test]
    fn the_qemu_virt_aia_dtb_confirms_ssaia()
    {
        assert_ne!(hart_caps(QEMU_VIRT_AIA_DTB).1 & HART_CAP_SSAIA, 0);
    }

    /// A tree of two harts (IDs 0 and 1, `riscv,cpu-intc` phandles `0x10`
    /// and `0x11`) and, in this order, a machine-level APLIC (`msi-parent`
    /// the machine-level IMSIC), a supervisor-level APLIC whose `msi-parent`
    /// is `aplic_parent`, the machine-level IMSIC (phandle `0x20`) and the
    /// supervisor-level IMSIC (phandle `0x21`, two files at `0x2800_0000`)
    /// whose `interrupts-extended` lists the harts in `ie_harts` order.
    /// `hart1_intc` shapes hart 1's controller: `Some(true)` as above,
    /// `Some(false)` with no `phandle`, `None` absent.
    fn aia_tree(ie_harts: &[u32], aplic_parent: u32, hart1_intc: Option<bool>) -> Vec<u8>
    {
        fn reg(base: u64, size: u64) -> Vec<u8>
        {
            [base.to_be_bytes(), size.to_be_bytes()].concat()
        }
        fn interrupts_extended(harts: &[u32], irq: u32) -> Vec<u8>
        {
            harts
                .iter()
                .flat_map(|&h| [(0x10 + h).to_be_bytes(), irq.to_be_bytes()])
                .flatten()
                .collect()
        }

        let mut b = FdtBuilder::new();
        b.begin_node(b"");
        b.begin_node(b"cpus");
        for hart in 0..2u32
        {
            b.begin_node(b"cpu");
            b.prop(b"compatible", b"riscv\0");
            b.prop(b"reg", &hart.to_be_bytes());
            let intc = if hart == 1 { hart1_intc } else { Some(true) };
            if let Some(phandle) = intc
            {
                b.begin_node(b"interrupt-controller");
                b.prop(b"compatible", b"riscv,cpu-intc\0");
                if phandle
                {
                    b.prop(b"phandle", &(0x10 + hart).to_be_bytes());
                }
                b.end_node();
            }
            b.end_node();
        }
        b.end_node();
        b.begin_node(b"soc");
        for (base, parent) in [(0xc00_0000u64, 0x20u32), (0xd00_0000, aplic_parent)]
        {
            b.begin_node(b"interrupt-controller");
            b.prop(b"compatible", b"riscv,aplic\0");
            b.prop(b"reg", &reg(base, 0x8000));
            b.prop(b"msi-parent", &parent.to_be_bytes());
            b.prop(b"riscv,num-sources", &96u32.to_be_bytes());
            b.end_node();
        }
        for (phandle, base, harts, irq) in [
            (0x20u32, 0x2400_0000u64, &[0u32, 1][..], 11u32),
            (0x21, 0x2800_0000, ie_harts, IRQ_S_EXT),
        ]
        {
            b.begin_node(b"interrupt-controller");
            b.prop(b"compatible", b"riscv,imsics\0");
            b.prop(b"phandle", &phandle.to_be_bytes());
            b.prop(b"reg", &reg(base, 0x2000));
            b.prop(b"interrupts-extended", &interrupts_extended(harts, irq));
            b.prop(b"riscv,num-ids", &255u32.to_be_bytes());
            b.end_node();
        }
        b.end_node();
        b.end_node();
        b.finish()
    }

    // Defect caught: an IMSIC reported although its `interrupts-extended`
    // order puts a hart's file elsewhere than the hart's ID does, so the
    // kernel would deliver each hart's interrupts to another hart's file.
    #[test]
    fn an_imsic_listing_the_harts_out_of_id_order_is_refused()
    {
        let in_order = aia(&aia_tree(&[0, 1], 0x21, Some(true)));
        assert_eq!(in_order.imsic.base, 0x2800_0000);
        assert_eq!(in_order.imsic.hart_index_bits, 1);
        assert_eq!(in_order.off_layout_hart, None);

        let swapped = aia(&aia_tree(&[1, 0], 0x21, Some(true)));
        assert_eq!(swapped.imsic, ImsicLayout::zero());
        assert_eq!(swapped.off_layout_hart, Some(0));
    }

    // Defect caught: an IMSIC reported although an enabled hart has no file
    // in it.
    #[test]
    fn an_imsic_missing_a_hart_is_refused()
    {
        let found = aia(&aia_tree(&[0], 0x21, Some(true)));
        assert_eq!(found.imsic, ImsicLayout::zero());
        assert_eq!(found.off_layout_hart, Some(1));
    }

    // Defect caught: an enabled hart whose `riscv,cpu-intc` has no `phandle`
    // (nothing references it, so dtc emits none), or that has no controller,
    // skipped by the check, so the IMSIC is reported although the hart has no
    // file in it.
    #[test]
    fn an_imsic_is_refused_when_a_hart_has_no_referenced_controller()
    {
        for hart1_intc in [Some(false), None]
        {
            let found = aia(&aia_tree(&[0], 0x21, hart1_intc));
            assert_eq!(found.imsic, ImsicLayout::zero(), "{hart1_intc:?}");
            assert_eq!(found.off_layout_hart, Some(1), "{hart1_intc:?}");
        }
    }

    // Defect caught: the first `riscv,aplic` node in tree order taken as the
    // supervisor's whatever its `msi-parent`, which reports the machine-level
    // APLIC.
    #[test]
    fn the_aplic_is_the_one_whose_msi_parent_is_the_supervisor_imsic()
    {
        assert_eq!(
            aia(&aia_tree(&[0, 1], 0x21, Some(true))).aplic.base,
            0xd00_0000
        );
        assert_eq!(
            aia(&aia_tree(&[0, 1], 0x20, Some(true))).aplic,
            AplicDomain::zero()
        );
    }

    #[test]
    fn block_addr_overflow_reads_nothing()
    {
        // A blob whose struct block would run past the top of the address
        // space reads as empty; no memory is touched.
        let fdt = Fdt {
            base: u64::MAX - 8,
            off_struct: 0,
            size_struct: 16,
            off_strings: 0,
            size_strings: 16,
        };
        assert_eq!(fdt.read_struct_u32(12), None);
        assert!(fdt.struct_slice(12, 4).is_empty());
        assert!(fdt.string_at(12).is_empty());
        assert_eq!(fdt.prop_data_addr(12, 4), None);
    }

    #[test]
    fn place_hart_ids_empty_out_places_nothing()
    {
        let blob = tree(None, |b| cpu_node(b, b"cpu@0", 7, &[]));
        let base = blob.as_ptr() as u64;
        let mut ids: [u32; 0] = [];
        // SAFETY: blob is a valid in-memory FDT built by FdtBuilder.
        assert_eq!(unsafe { place_hart_ids(base, 7, &mut ids) }, 0);
    }

    #[test]
    fn imsic_file_in_regs_rejects_zero_stride()
    {
        let mut node = FdtNode {
            reg_entries: [(0, 0); MAX_REG_ENTRIES],
            reg_count: 1,
            irq_entries: [0; MAX_IRQ_ENTRIES],
            irq_count: 0,
            ranges: (0, 0),
            aia: AiaProps::new(),
        };
        node.reg_entries[0] = (0x1000, 0x4000);
        assert_eq!(imsic_file_in_regs(&node, 0, 0), None);
        assert_eq!(imsic_file_in_regs(&node, 1, 0x1000), Some(0x2000));
        assert_eq!(imsic_file_in_regs(&node, u64::MAX, 0x1000), None);
    }
}
