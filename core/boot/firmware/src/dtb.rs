// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/dtb.rs

//! The bootloader's reading of a flattened device tree: the enabled RISC-V
//! harts, their ISA extensions and paging modes, the `time` CSR frequency,
//! the supervisor-level AIA interrupt controllers, the UART, the MMIO
//! aperture seeds, and where `/chosen/rng-seed` lies.
//!
//! The token stream is `firmware_tables::fdt`'s, over the blob slice the
//! bootloader bounded by the header's `totalsize` and the memory map. Each
//! walk here is a state machine over that stream: a per-depth state array of
//! `D` levels (the bootloader's walks use [`MAX_DEPTH`]) and a `step` that
//! takes one event, which the proofs check from any state
//! (`core/boot/docs/dtb.md` gives the cell-size assumptions and what each
//! walk reads).

use core::cell::Cell;

use boot_protocol::riscv_paging::PagingMode;
use boot_protocol::{AplicDomain, ImsicLayout};
use firmware_tables::bytes::{be_u32, be_u64};
use firmware_tables::fdt::{Fdt, FdtEvent, compatible_contains};

use crate::isa::isa_string_has_ext;
use crate::seeds::Seeds;

/// Deepest node nesting the walks track. Device trees in the wild nest well
/// under it (buses inside buses inside `/soc`); the cost is stack only, one
/// per-depth state per level, and a deeper node's properties are skipped and
/// reported ([`Limits::too_deep`]).
pub const MAX_DEPTH: usize = 32;

/// `reg` entries (address and size pairs, two cells each) a node keeps. Only
/// the first is used (aperture seeds, the UART), apart from a supervisor-level
/// IMSIC's, whose every window holds interrupt files; surplus entries are
/// dropped and reported ([`Limits::truncated`]).
pub const MAX_REG_ENTRIES: usize = 8;

/// Size of one `reg` entry under `#address-cells = <2>`, `#size-cells = <2>`.
const REG_ENTRY_BYTES: usize = 16;

/// Size of one PCI `ranges` entry: three child address cells, two parent
/// address cells and two size cells.
const PCI_RANGES_ENTRY_BYTES: usize = 28;

/// The supervisor external interrupt (`IRQ_S_EXT`), the hart-local interrupt
/// a supervisor-level IMSIC's `interrupts-extended` entries name.
const IRQ_S_EXT: u32 = 9;

/// Size of one `interrupts-extended` entry of an IMSIC node: a hart's
/// `riscv,cpu-intc` phandle and its one interrupt cell.
const INTERRUPTS_EXTENDED_ENTRY_BYTES: usize = 8;

/// Default `riscv,group-index-shift` of the IMSIC binding.
const IMSIC_DEFAULT_GROUP_SHIFT: u32 = 24;

/// What a walk met past its bounds, which the bootloader reports once per
/// boot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Limits
{
    /// A node lay deeper than [`MAX_DEPTH`]; its properties were skipped.
    pub too_deep: bool,
    /// A `reg` property held more than [`MAX_REG_ENTRIES`] entries; the
    /// surplus was dropped.
    pub truncated: bool,
}

/// What one event does to a walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step<T>
{
    /// Nothing to report; the walk goes on.
    Continue,
    /// A node closed that the walk reports.
    Yield(T),
    /// The stream closes more nodes than it opened: the walk ends.
    Stop,
}

// ── Nodes by compatible ──────────────────────────────────────────────────────

/// The properties of an APLIC (`riscv,aplic`) or IMSIC (`riscv,imsics`) node
/// the AIA discovery reads ([`Tree::aia`]); a property the node lacks reads
/// as zero or empty, or `None` where the binding gives it a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AiaProps<'a>
{
    /// The node's `phandle`, or 0 when it has none.
    pub phandle: u32,
    /// The first cell of `msi-parent` (the IMSIC an APLIC forwards to), or 0.
    pub msi_parent: u32,
    /// The `interrupts-extended` property's value.
    pub interrupts_extended: &'a [u8],
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

impl<'a> AiaProps<'a>
{
    /// No property read.
    pub const EMPTY: Self = Self {
        phandle: 0,
        msi_parent: 0,
        interrupts_extended: &[],
        num_ids: 0,
        num_sources: 0,
        guest_index_bits: None,
        hart_index_bits: None,
        group_index_bits: None,
        group_index_shift: None,
    };

    /// Record the property `name` of value `data` when it is one of the
    /// properties above; a one-cell property shorter than its cell reads as
    /// absent.
    pub fn record(&mut self, name: &[u8], data: &'a [u8])
    {
        let cell = (data.len() >= 4).then(|| be_u32(data, 0));
        match name
        {
            b"phandle" => self.phandle = cell.unwrap_or(0),
            b"msi-parent" => self.msi_parent = cell.unwrap_or(0),
            b"interrupts-extended" => self.interrupts_extended = data,
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

/// What a node whose `compatible` names the walk's string holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FdtNode<'a>
{
    /// Whether the node's `compatible` names the walk's string.
    pub matched: bool,
    /// `reg` entries `(address, size)`, two cells each.
    pub reg_entries: [(u64, u64); MAX_REG_ENTRIES],
    /// How many of [`Self::reg_entries`] the node's `reg` filled.
    pub reg_count: usize,
    /// The `ranges` property's value ([`pci_ranges`] reads it).
    pub ranges: &'a [u8],
    /// The AIA properties.
    pub aia: AiaProps<'a>,
}

impl FdtNode<'_>
{
    /// A node with no property read.
    pub const EMPTY: Self = Self {
        matched: false,
        reg_entries: [(0, 0); MAX_REG_ENTRIES],
        reg_count: 0,
        ranges: &[],
        aia: AiaProps::EMPTY,
    };

    /// The node's first `reg` entry, if it has one.
    #[must_use]
    pub fn first_reg(&self) -> Option<(u64, u64)>
    {
        self.regs().first().copied()
    }

    /// The `reg` entries the node's `reg` filled.
    #[must_use]
    pub fn regs(&self) -> &[(u64, u64)]
    {
        self.reg_entries.get(..self.reg_count).unwrap_or_default()
    }
}

/// The PCI `ranges` entries of a node's `ranges` value `ranges`, as
/// `(child_flags, cpu_addr, size)`: three child address cells, two parent
/// address cells and two size cells, so each entry is
/// `child_hi child_mid child_lo parent_hi parent_lo size_hi size_lo`.
/// `child_flags` encodes the space type in bits 25:24 (1 I/O, 2 32-bit MMIO,
/// 3 64-bit MMIO). A trailing partial entry is ignored.
pub fn pci_ranges(ranges: &[u8]) -> impl Iterator<Item = (u32, u64, u64)> + '_
{
    ranges
        .as_chunks::<PCI_RANGES_ENTRY_BYTES>()
        .0
        .iter()
        .map(|e| (be_u32(e, 0), be_u64(e, 12), be_u64(e, 20)))
}

/// The walk that reports every node whose `compatible` names `compat`, with
/// its `reg`, `ranges` and AIA properties ([`Tree::for_each_compatible`]).
pub struct CompatibleWalk<'c, 'a, const D: usize>
{
    /// The `compatible` entry the walk reports.
    pub compat: &'c [u8],
    /// The open nodes' states, the root's at index 0.
    pub states: [FdtNode<'a>; D],
    /// Nodes open.
    pub depth: usize,
    /// What the walk met past its bounds.
    pub limits: Limits,
}

impl<'c, 'a, const D: usize> CompatibleWalk<'c, 'a, D>
{
    /// The walk at the start of the structure block.
    #[must_use]
    pub fn new(compat: &'c [u8]) -> Self
    {
        Self {
            compat,
            states: [FdtNode::EMPTY; D],
            depth: 0,
            limits: Limits::default(),
        }
    }

    /// Take one event: open a node, close one (yielding it when its
    /// `compatible` named the walk's string), or record a property of the
    /// open node when it lies within `D` levels.
    pub fn step(&mut self, event: FdtEvent<'a>) -> Step<FdtNode<'a>>
    {
        match event
        {
            FdtEvent::BeginNode { .. } =>
            {
                open(
                    &mut self.states,
                    &mut self.depth,
                    &mut self.limits,
                    FdtNode::EMPTY,
                );
                Step::Continue
            }
            FdtEvent::EndNode => match close(&self.states, &mut self.depth)
            {
                Closed::Unopened => Step::Stop,
                Closed::Node(node) if node.matched => Step::Yield(node),
                Closed::Node(_) | Closed::Deep => Step::Continue,
            },
            FdtEvent::Prop { name, data, .. } =>
            {
                if let Some(node) = self
                    .depth
                    .checked_sub(1)
                    .and_then(|d| self.states.get_mut(d))
                {
                    record_node_prop(node, self.compat, name, data, &mut self.limits);
                }
                Step::Continue
            }
        }
    }
}

/// Record the property `name` of value `data` into `node`, for a walk that
/// reports nodes whose `compatible` names `compat`.
pub fn record_node_prop<'a>(
    node: &mut FdtNode<'a>,
    compat: &[u8],
    name: &[u8],
    data: &'a [u8],
    limits: &mut Limits,
)
{
    match name
    {
        b"compatible" => node.matched |= compatible_contains(data, compat),
        b"reg" =>
        {
            for entry in data.as_chunks::<REG_ENTRY_BYTES>().0
            {
                let Some(slot) = node.reg_entries.get_mut(node.reg_count)
                else
                {
                    limits.truncated = true;
                    break;
                };
                *slot = (be_u64(entry, 0), be_u64(entry, 8));
                // `reg_count` indexed a slot, so it is below `MAX_REG_ENTRIES`.
                node.reg_count = node.reg_count.saturating_add(1);
            }
        }
        b"ranges" => node.ranges = data,
        _ => node.aia.record(name, data),
    }
}

/// Open a node: reset its state at `depth` when the array has room, else
/// note the overflow; then count it open.
fn open<S: Copy, const D: usize>(
    states: &mut [S; D],
    depth: &mut usize,
    limits: &mut Limits,
    empty: S,
)
{
    if let Some(slot) = states.get_mut(*depth)
    {
        *slot = empty;
    }
    else
    {
        limits.too_deep = true;
    }
    // Each open node takes at least a token of the bounded blob.
    *depth = depth.saturating_add(1);
}

/// What closing the open node gives.
enum Closed<S>
{
    /// No node was open: the end of the tree.
    Unopened,
    /// A node past the walk's `D` levels, whose state was not kept.
    Deep,
    /// A node at a kept level, with the state it held.
    Node(S),
}

/// Close the open node.
fn close<S: Copy, const D: usize>(states: &[S; D], depth: &mut usize) -> Closed<S>
{
    let Some(d) = depth.checked_sub(1)
    else
    {
        return Closed::Unopened;
    };
    *depth = d;
    states.get(d).copied().map_or(Closed::Deep, Closed::Node)
}

// ── CPU nodes ────────────────────────────────────────────────────────────────

/// One enabled CPU node: `compatible` names `riscv`, it has a one-cell
/// `reg` (`#address-cells = <1>` under `/cpus`), and its `status` does not
/// start with `disabled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cpu
{
    /// The hart ID, its `reg`.
    pub hart_id: u32,
    /// The `HART_CAP_*` bits of the [`HART_CAP_NAMES`](crate::isa::HART_CAP_NAMES) extensions its
    /// `riscv,isa-extensions` list or legacy `riscv,isa` string names.
    pub caps: u64,
    /// The S-mode paging mode its `mmu-type` claims ([`mmu_type`]).
    pub mmu: Option<PagingMode>,
}

/// The state of one open node for [`CpuWalk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuState
{
    /// `compatible` names `riscv`.
    pub is_riscv_cpu: bool,
    /// The first cell of `reg`, when it has one.
    pub hart_id: Option<u32>,
    /// `status` starts with `disabled`.
    pub disabled: bool,
    /// The `HART_CAP_*` bits named so far.
    pub caps: u64,
    /// The `mmu-type` claim.
    pub mmu: Option<PagingMode>,
}

impl CpuState
{
    /// A node with no property read.
    pub const EMPTY: Self = Self {
        is_riscv_cpu: false,
        hart_id: None,
        disabled: false,
        caps: 0,
        mmu: None,
    };
}

/// The walk that reports every enabled CPU node ([`Cpu`]).
pub struct CpuWalk<const D: usize>
{
    /// The open nodes' states.
    pub states: [CpuState; D],
    /// Nodes open.
    pub depth: usize,
    /// What the walk met past its bounds.
    pub limits: Limits,
}

impl<const D: usize> Default for CpuWalk<D>
{
    fn default() -> Self
    {
        Self {
            states: [CpuState::EMPTY; D],
            depth: 0,
            limits: Limits::default(),
        }
    }
}

impl<const D: usize> CpuWalk<D>
{
    /// Take one event, yielding a closing node that is an enabled CPU.
    pub fn step(&mut self, event: FdtEvent<'_>) -> Step<Cpu>
    {
        match event
        {
            FdtEvent::BeginNode { .. } =>
            {
                open(
                    &mut self.states,
                    &mut self.depth,
                    &mut self.limits,
                    CpuState::EMPTY,
                );
                Step::Continue
            }
            FdtEvent::EndNode => match close(&self.states, &mut self.depth)
            {
                Closed::Unopened => Step::Stop,
                Closed::Node(s) => match (s.is_riscv_cpu && !s.disabled, s.hart_id)
                {
                    (true, Some(hart_id)) => Step::Yield(Cpu {
                        hart_id,
                        caps: s.caps,
                        mmu: s.mmu,
                    }),
                    _ => Step::Continue,
                },
                Closed::Deep => Step::Continue,
            },
            FdtEvent::Prop { name, data, .. } =>
            {
                if let Some(s) = self
                    .depth
                    .checked_sub(1)
                    .and_then(|d| self.states.get_mut(d))
                {
                    record_cpu_prop(s, name, data);
                }
                Step::Continue
            }
        }
    }
}

/// Record the property `name` of value `data` into the CPU-node state `s`.
pub fn record_cpu_prop(s: &mut CpuState, name: &[u8], data: &[u8])
{
    match name
    {
        // A CPU node carries `riscv` as one whole entry of its list.
        b"compatible" => s.is_riscv_cpu |= compatible_contains(data, b"riscv"),
        b"reg" if data.len() >= 4 => s.hart_id = Some(be_u32(data, 0)),
        b"status" => s.disabled |= data.starts_with(b"disabled"),
        b"riscv,isa-extensions" =>
        {
            s.caps |= crate::isa::hart_caps(|ext| compatible_contains(data, ext));
        }
        b"riscv,isa" => s.caps |= crate::isa::hart_caps(|ext| isa_string_has_ext(data, ext)),
        b"mmu-type" => s.mmu = mmu_type(data),
        _ =>
        {}
    }
}

/// The S-mode paging mode an `mmu-type` value claims: per the devicetree
/// binding, the widest translation mode the hart implements (`riscv,sv39`,
/// `riscv,sv48`, `riscv,sv57`). `riscv,none` and the hypervisor
/// `riscv,svNNx4` forms claim none.
#[must_use]
pub fn mmu_type(data: &[u8]) -> Option<PagingMode>
{
    if [b"riscv,sv39x", b"riscv,sv48x", b"riscv,sv57x"]
        .iter()
        .any(|x| data.starts_with(*x))
    {
        return None;
    }
    [
        (b"riscv,sv57", PagingMode::Sv57),
        (b"riscv,sv48", PagingMode::Sv48),
        (b"riscv,sv39", PagingMode::Sv39),
    ]
    .iter()
    .find(|(name, _)| data.starts_with(*name))
    .map(|&(_, mode)| mode)
}

// ── CPU interrupt controllers ────────────────────────────────────────────────

/// The state of one open node for [`CpuIntcWalk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntcState
{
    /// `compatible` names `riscv`.
    pub is_riscv_cpu: bool,
    /// `status` starts with `disabled`.
    pub disabled: bool,
    /// The first cell of `reg`, when it has one.
    pub hart_id: Option<u32>,
    /// `compatible` names `riscv,cpu-intc`.
    pub is_cpu_intc: bool,
    /// The node's `phandle`, or 0.
    pub phandle: u32,
    /// Of a CPU node: its first `riscv,cpu-intc` child's `phandle`, or 0.
    pub intc_phandle: u32,
}

impl IntcState
{
    /// A node with no property read.
    pub const EMPTY: Self = Self {
        is_riscv_cpu: false,
        disabled: false,
        hart_id: None,
        is_cpu_intc: false,
        phandle: 0,
        intc_phandle: 0,
    };
}

/// The walk that reports each enabled CPU node (as [`CpuWalk`] selects them)
/// as `(intc_phandle, hart_id)`, `intc_phandle` being the `phandle` of its
/// first `riscv,cpu-intc` child that has one, or 0: dtc gives a node a
/// `phandle` only when something references it.
pub struct CpuIntcWalk<const D: usize>
{
    /// The open nodes' states.
    pub states: [IntcState; D],
    /// Nodes open.
    pub depth: usize,
    /// What the walk met past its bounds.
    pub limits: Limits,
}

impl<const D: usize> Default for CpuIntcWalk<D>
{
    fn default() -> Self
    {
        Self {
            states: [IntcState::EMPTY; D],
            depth: 0,
            limits: Limits::default(),
        }
    }
}

impl<const D: usize> CpuIntcWalk<D>
{
    /// Take one event, yielding a closing enabled CPU node.
    pub fn step(&mut self, event: FdtEvent<'_>) -> Step<(u32, u32)>
    {
        match event
        {
            FdtEvent::BeginNode { .. } =>
            {
                open(
                    &mut self.states,
                    &mut self.depth,
                    &mut self.limits,
                    IntcState::EMPTY,
                );
                Step::Continue
            }
            FdtEvent::EndNode =>
            {
                let s = match close(&self.states, &mut self.depth)
                {
                    Closed::Unopened => return Step::Stop,
                    Closed::Deep => return Step::Continue,
                    Closed::Node(s) => s,
                };
                if s.is_cpu_intc
                    && s.phandle != 0
                    && let Some(parent) = self
                        .depth
                        .checked_sub(1)
                        .and_then(|d| self.states.get_mut(d))
                    && parent.intc_phandle == 0
                {
                    parent.intc_phandle = s.phandle;
                }
                match s.hart_id
                {
                    Some(hart_id) if s.is_riscv_cpu && !s.disabled =>
                    {
                        Step::Yield((s.intc_phandle, hart_id))
                    }
                    _ => Step::Continue,
                }
            }
            FdtEvent::Prop { name, data, .. } =>
            {
                if let Some(s) = self
                    .depth
                    .checked_sub(1)
                    .and_then(|d| self.states.get_mut(d))
                {
                    match name
                    {
                        b"compatible" =>
                        {
                            s.is_riscv_cpu |= compatible_contains(data, b"riscv");
                            s.is_cpu_intc |= compatible_contains(data, b"riscv,cpu-intc");
                        }
                        b"reg" if data.len() >= 4 => s.hart_id = Some(be_u32(data, 0)),
                        b"status" => s.disabled |= data.starts_with(b"disabled"),
                        b"phandle" if data.len() >= 4 => s.phandle = be_u32(data, 0),
                        _ =>
                        {}
                    }
                }
                Step::Continue
            }
        }
    }
}

// ── Flat scans ───────────────────────────────────────────────────────────────

/// The `time` CSR frequency a `timebase-frequency` property of value `data`
/// gives: the specification's one cell or, defensively, two; `None` for any
/// other length or a zero value.
#[must_use]
pub fn timebase_value(data: &[u8]) -> Option<u64>
{
    let value = match data.len()
    {
        4 => u64::from(be_u32(data, 0)),
        8 => be_u64(data, 0),
        _ => 0,
    };
    (value != 0).then_some(value)
}

// ── AIA ──────────────────────────────────────────────────────────────────────

/// What the device tree reports of the AIA interrupt controllers the
/// supervisor uses ([`Tree::aia`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

impl DtbAia
{
    /// Nothing found.
    pub const NONE: Self = Self {
        aplic: AplicDomain::zero(),
        imsic: ImsicLayout::zero(),
        imsic_regs: ([(0, 0); MAX_REG_ENTRIES], 0),
        off_layout_hart: None,
    };
}

/// The `interrupts-extended` entries of an IMSIC node.
fn imsic_entries<'a>(node: &FdtNode<'a>) -> &'a [[u8; INTERRUPTS_EXTENDED_ENTRY_BYTES]]
{
    node.aia.interrupts_extended.as_chunks().0
}

/// Whether `node`, an IMSIC node, serves supervisor mode: its
/// `interrupts-extended` names at least one hart and only the supervisor
/// external interrupt.
#[must_use]
pub fn is_supervisor_imsic(node: &FdtNode<'_>) -> bool
{
    let entries = imsic_entries(node);
    !entries.is_empty() && entries.iter().all(|e| be_u32(e, 4) == IRQ_S_EXT)
}

/// The layout the supervisor-level IMSIC `node` states: its first `reg`
/// base, its identity count, and its index widths, a width it does not state
/// taking the binding's default (guest and group bits 0, group shift 24, hart
/// bits the fewest that index every `interrupts-extended` entry). `None`
/// when the node has no `reg` or a width does not fit its field.
#[must_use]
pub fn imsic_layout(node: &FdtNode<'_>) -> Option<ImsicLayout>
{
    let (base, _) = node.first_reg()?;
    let harts = imsic_entries(node).len();
    // The fewest bits that give each hart an index: ceil(log2(harts)).
    let default_hart_bits = harts.saturating_sub(1).bit_width();
    let a = &node.aia;
    Some(ImsicLayout {
        base,
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
/// windows in order. `None` past the last window, for a zero `stride`, or
/// when the file's offset overflows.
#[must_use]
pub fn imsic_file_in_regs(node: &FdtNode<'_>, mut index: u64, stride: u64) -> Option<u64>
{
    for &(base, size) in node.regs()
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

/// The file the hart whose `riscv,cpu-intc` has phandle `phandle` has in the
/// supervisor-level IMSIC `imsic`, files `stride` bytes apart: the file of
/// the first `interrupts-extended` entry naming the phandle. `None` for
/// phandle 0 (the hart's controller is unreferenced, so no entry names it),
/// no such entry, or no such file ([`imsic_file_in_regs`]).
#[must_use]
pub fn hart_imsic_file(imsic: &FdtNode<'_>, phandle: u32, stride: u64) -> Option<u64>
{
    if phandle == 0
    {
        return None;
    }
    let index = imsic_entries(imsic)
        .iter()
        .position(|e| be_u32(e, 0) == phandle)?;
    imsic_file_in_regs(imsic, u64::try_from(index).ok()?, stride)
}

// ── The tree ─────────────────────────────────────────────────────────────────

/// A validated device tree and what its walks met past their bounds.
pub struct Tree<'a>
{
    fdt: Fdt<'a>,
    limits: Cell<Limits>,
}

impl<'a> Tree<'a>
{
    /// The tree in `blob`: `None` where `Fdt::new` refuses the header.
    #[must_use]
    pub fn new(blob: &'a [u8]) -> Option<Self>
    {
        Some(Self {
            fdt: Fdt::new(blob)?,
            limits: Cell::new(Limits::default()),
        })
    }

    /// What the walks so far met past their bounds.
    #[must_use]
    pub fn limits(&self) -> Limits
    {
        self.limits.get()
    }

    /// Note a walk's limits.
    fn note(&self, met: Limits)
    {
        let mut all = self.limits.get();
        all.too_deep |= met.too_deep;
        all.truncated |= met.truncated;
        self.limits.set(all);
    }

    /// Call `f` on each node whose `compatible` names `compat`, in tree
    /// order, until it returns `false`.
    pub fn for_each_compatible(&self, compat: &[u8], mut f: impl FnMut(FdtNode<'a>) -> bool)
    {
        let mut walk = CompatibleWalk::<MAX_DEPTH>::new(compat);
        for event in self.fdt.events()
        {
            match walk.step(event)
            {
                Step::Continue =>
                {}
                Step::Yield(node) =>
                {
                    if !f(node)
                    {
                        break;
                    }
                }
                Step::Stop => break,
            }
        }
        self.note(walk.limits);
    }

    /// Call `f` on each enabled CPU node, in tree order, until it returns
    /// `false`.
    pub fn for_each_cpu(&self, mut f: impl FnMut(Cpu) -> bool)
    {
        let mut walk = CpuWalk::<MAX_DEPTH>::default();
        for event in self.fdt.events()
        {
            match walk.step(event)
            {
                Step::Continue =>
                {}
                Step::Yield(cpu) =>
                {
                    if !f(cpu)
                    {
                        break;
                    }
                }
                Step::Stop => break,
            }
        }
        self.note(walk.limits);
    }

    /// Call `f(intc_phandle, hart_id)` on each enabled CPU node
    /// ([`CpuIntcWalk`]), in tree order, until it returns `false`.
    pub fn for_each_cpu_intc(&self, mut f: impl FnMut(u32, u32) -> bool)
    {
        let mut walk = CpuIntcWalk::<MAX_DEPTH>::default();
        for event in self.fdt.events()
        {
            match walk.step(event)
            {
                Step::Continue =>
                {}
                Step::Yield((phandle, hart_id)) =>
                {
                    if !f(phandle, hart_id)
                    {
                        break;
                    }
                }
                Step::Stop => break,
            }
        }
        self.note(walk.limits);
    }

    /// The first property named `name` in the tree, as its value's offset
    /// in the blob and the value. Only for a name the tree holds once
    /// (`rng-seed` lies only under `/chosen`).
    #[must_use]
    pub fn find_prop(&self, name: &[u8]) -> Option<(usize, &'a [u8])>
    {
        self.fdt.events().find_map(|event| match event
        {
            FdtEvent::Prop { name: n, data, at } if n == name => Some((at, data)),
            FdtEvent::BeginNode { .. } | FdtEvent::EndNode | FdtEvent::Prop { .. } => None,
        })
    }

    /// The first non-zero `timebase-frequency` in the tree ([`timebase_value`]),
    /// or 0. The property lies on `/cpus` (a CPU node's copy carries the same
    /// value), so a flat scan finds it.
    #[must_use]
    pub fn timebase_frequency(&self) -> u64
    {
        self.fdt
            .events()
            .find_map(|event| match event
            {
                FdtEvent::Prop {
                    name: b"timebase-frequency",
                    data,
                    ..
                } => timebase_value(data),
                FdtEvent::BeginNode { .. } | FdtEvent::EndNode | FdtEvent::Prop { .. } => None,
            })
            .unwrap_or(0)
    }

    /// The enabled CPU nodes.
    #[must_use]
    pub fn cpu_count(&self) -> usize
    {
        let mut count = 0usize;
        self.for_each_cpu(|_| {
            // One per CPU node of a bounded blob.
            count = count.saturating_add(1);
            true
        });
        count
    }

    /// Place the enabled harts into `out` ([`crate::cpus::place_cpu_ids`]):
    /// `bsp_id` at index 0, then each other hart ID once, in tree order.
    /// Returns `(count, truncated)`.
    pub fn place_hart_ids(&self, bsp_id: u32, out: &mut [u32]) -> (u32, bool)
    {
        let mut filled = 0usize;
        let mut truncated = false;
        crate::cpus::record_cpu_id(bsp_id, out, &mut filled, &mut truncated);
        self.for_each_cpu(|cpu| {
            crate::cpus::record_cpu_id(cpu.hart_id, out, &mut filled, &mut truncated);
            true
        });
        // `filled` is at most `out.len()`, which the caller caps at `MAX_CPUS`.
        (u32::try_from(filled).unwrap_or(u32::MAX), truncated)
    }

    /// The `time` CSR frequency ([`Self::timebase_frequency`]) and the
    /// `HART_CAP_*` bits every enabled hart names: each bit only when at
    /// least one enabled CPU node was read and all of them name it, since the
    /// kernel relies on each capability on every hart.
    #[must_use]
    pub fn hart_caps(&self) -> (u64, u64)
    {
        let mut seen = false;
        let mut all = u64::MAX;
        self.for_each_cpu(|cpu| {
            seen = true;
            all &= cpu.caps;
            true
        });
        (self.timebase_frequency(), if seen { all } else { 0 })
    }

    /// The paging mode the tree claims for the boot hart: its CPU node's
    /// `mmu-type` when it has one, else the widest any enabled CPU node
    /// claims (the RISC-V Privileged ISA requires a hart implementing a wider
    /// mode to implement every narrower one, so the widest is a safe probe
    /// candidate), else `None`.
    #[must_use]
    pub fn boot_cpu_mmu_type(&self, boot_hart_id: u64) -> Option<PagingMode>
    {
        let mut boot = None;
        let mut widest: Option<PagingMode> = None;
        self.for_each_cpu(|cpu| {
            if u64::from(cpu.hart_id) == boot_hart_id && cpu.mmu.is_some()
            {
                boot = cpu.mmu;
                return false;
            }
            if let Some(mode) = cpu.mmu
                && widest.is_none_or(|w| mode.levels() > w.levels())
            {
                widest = Some(mode);
            }
            true
        });
        boot.or(widest)
    }

    /// The first `ns16550a` node's first `reg` window with a non-zero base.
    #[must_use]
    pub fn uart(&self) -> Option<(u64, u64)>
    {
        let mut found = None;
        self.for_each_compatible(b"ns16550a", |node| {
            found = node.first_reg().filter(|&(base, _)| base != 0);
            found.is_none()
        });
        found
    }

    /// The supervisor's AIA interrupt controllers: the first IMSIC node
    /// (`riscv,imsics`) whose `interrupts-extended` names only the supervisor
    /// external interrupt ([`is_supervisor_imsic`]), and the first APLIC node
    /// (`riscv,aplic`) with a `reg` whose `msi-parent` is that IMSIC. The
    /// machine-level IMSIC and APLIC, which the SBI firmware keeps, are never
    /// reported.
    ///
    /// The IMSIC layout ([`imsic_layout`]) is reported only when every
    /// enabled hart's `riscv,cpu-intc` appears in the IMSIC's
    /// `interrupts-extended` and the file that position names
    /// ([`hart_imsic_file`]) lies at [`ImsicLayout::s_file_address`] of the
    /// hart's ID; otherwise it is zero and [`DtbAia::off_layout_hart`] names
    /// the first hart that failed.
    #[must_use]
    pub fn aia(&self) -> DtbAia
    {
        let mut found = DtbAia::NONE;
        let mut imsic = None;
        self.for_each_compatible(b"riscv,imsics", |node| {
            if is_supervisor_imsic(&node)
            {
                imsic = Some(node);
                return false;
            }
            true
        });
        let Some(imsic) = imsic
        else
        {
            return found;
        };
        found.imsic_regs = (imsic.reg_entries, imsic.reg_count);
        if imsic.aia.phandle != 0
        {
            self.for_each_compatible(b"riscv,aplic", |node| match node.first_reg()
            {
                Some((base, size)) if node.aia.msi_parent == imsic.aia.phandle =>
                {
                    found.aplic = AplicDomain {
                        base,
                        size,
                        sources: u64::from(node.aia.num_sources),
                    };
                    false
                }
                _ => true,
            });
        }
        let Some(layout) = imsic_layout(&imsic)
        else
        {
            return found;
        };
        // `s_file_address` refuses a layout outside the specification's
        // widths, so the guest bits are at most 6 once it accepts hart 0.
        if layout.s_file_address(0).is_none()
        {
            return found;
        }
        let stride = 1u64 << (12 + u32::from(layout.guest_index_bits));
        let mut off_layout = None;
        self.for_each_cpu_intc(|phandle, hart_id| {
            let file = hart_imsic_file(&imsic, phandle, stride);
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

    /// Add the tree's aperture seeds to `seeds` (named seeds only): the first
    /// `reg` window of each `riscv,clint0`, `sifive,clint0` and `ns16550a`
    /// node; of each `pci-host-ecam-generic` node its ECAM window (first
    /// `reg`) and each 32-bit and 64-bit MMIO `ranges` window; of each
    /// `virtio,mmio` node its first `reg`; and the supervisor-level APLIC's
    /// window and its IMSIC's `reg` windows ([`Self::aia`]), never the
    /// machine-level ones.
    pub fn seeds(&self, seeds: &mut Seeds<'_>)
    {
        let first_reg = |seeds: &mut Seeds<'_>, node: &FdtNode<'_>| {
            if let Some((base, size)) = node.first_reg()
            {
                seeds.named(base, size);
            }
        };
        for compat in [
            &b"riscv,clint0"[..],
            &b"sifive,clint0"[..],
            &b"ns16550a"[..],
        ]
        {
            self.for_each_compatible(compat, |node| {
                first_reg(seeds, &node);
                true
            });
        }
        self.for_each_compatible(b"pci-host-ecam-generic", |node| {
            first_reg(seeds, &node);
            for (flags, cpu_addr, size) in pci_ranges(node.ranges)
            {
                let space = (flags >> 24) & 0x3;
                if space == 2 || space == 3
                {
                    seeds.named(cpu_addr, size);
                }
            }
            true
        });
        self.for_each_compatible(b"virtio,mmio", |node| {
            first_reg(seeds, &node);
            true
        });
        let aia = self.aia();
        seeds.named(aia.aplic.base, aia.aplic.size);
        let (regs, count) = aia.imsic_regs;
        for &(base, size) in regs.get(..count).unwrap_or_default()
        {
            seeds.named(base, size);
        }
    }
}

/// Copy the tree's first `rng-seed` property ([`Tree::find_prop`]) from
/// `blob` into `out`, as many bytes as fit, then zero the whole property in
/// `blob`, which the bootloader hands on to userspace
/// (`core/boot/docs/dtb.md` § Scope). Returns the bytes copied: 0 for a blob
/// [`Tree::new`] refuses or a tree without the property.
///
/// The zeroing writes the caller's memory, which outlives the call, so none
/// of its writes is dead.
pub fn take_rng_seed(blob: &mut [u8], out: &mut [u8; 32]) -> usize
{
    let Some((at, len)) = Tree::new(blob)
        .and_then(|tree| tree.find_prop(b"rng-seed"))
        .map(|(at, data)| (at, data.len()))
    else
    {
        return 0;
    };
    let Some(seed) = at.checked_add(len).and_then(|end| blob.get_mut(at..end))
    else
    {
        return 0;
    };
    let copied = len.min(out.len());
    if let (Some(dst), Some(src)) = (out.get_mut(..copied), seed.get(..copied))
    {
        dst.copy_from_slice(src);
    }
    seed.fill(0);
    copied
}

#[cfg(test)]
mod tests
{
    use boot_protocol::MmioAperture;
    use boot_protocol::{
        HART_CAP_SSAIA, HART_CAP_SSTC, HART_CAP_SVINVAL, HART_CAP_SVNAPOT, HART_CAP_SVPBMT,
    };
    use firmware_tables::fdt::{FDT_BEGIN_NODE, FDT_END_NODE, FDT_MAGIC, FDT_PROP};

    use super::*;
    use crate::cpus::cpu_id_capacity;

    /// The end-of-structure-block token.
    const FDT_END: u32 = 9;

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
            let off = u32::try_from(self.strings.len()).unwrap();
            self.strings.extend_from_slice(name);
            self.strings.push(0);
            off
        }

        fn prop(&mut self, name: &[u8], data: &[u8])
        {
            let nameoff = self.string_off(name);
            self.token(FDT_PROP);
            self.token(u32::try_from(data.len()).unwrap());
            self.token(nameoff);
            self.structs.extend_from_slice(data);
            self.pad4();
        }

        fn finish(mut self) -> Vec<u8>
        {
            self.token(FDT_END);
            let off_struct: u32 = 40;
            let size_struct = u32::try_from(self.structs.len()).unwrap();
            let off_strings = off_struct + size_struct;
            let size_strings = u32::try_from(self.strings.len()).unwrap();
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
        Tree::new(blob).expect("valid FDT").hart_caps()
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
        let fdt = Tree::new(&blob).expect("valid FDT");
        let mut reg = None;
        fdt.for_each_compatible(b"ns16550a", |node| {
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
        let fdt = Tree::new(&blob).expect("valid FDT");
        let mut count = None;
        fdt.for_each_compatible(b"pci-host-ecam-generic", |node| {
            count = Some(pci_ranges(node.ranges).count());
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
        let fdt = Tree::new(&blob).expect("valid FDT");
        let mut counting = Seeds::counting();
        fdt.seeds(&mut counting);
        let counted = counting.found.0;
        let mut out = vec![
            MmioAperture {
                phys_base: 0,
                size: 0
            };
            counted + 4
        ];
        let mut seeds = Seeds::new(&mut out, &mut []);
        fdt.seeds(&mut seeds);
        let written = seeds.written.0;
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
        let mut seeds = Seeds::new(&mut exact, &mut []);
        fdt.seeds(&mut seeds);
        assert_eq!(seeds.written.0, counted);
    }

    #[test]
    fn bad_magic_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        blob[0..4].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        assert!(Tree::new(&blob).is_none());
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
        assert!(Tree::new(&blob).is_none());
    }

    #[test]
    fn struct_block_extent_overflow_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // `off_dt_struct + size_dt_struct` must not overflow before the bounds
        // check; a maximal size with the 40-byte offset exercises that arm.
        blob[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Tree::new(&blob).is_none());
    }

    #[test]
    fn strings_block_past_totalsize_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // Header byte offset 32 is `size_dt_strings`.
        let total = u32::from_be_bytes(blob[4..8].try_into().unwrap());
        let off_strings = u32::from_be_bytes(blob[12..16].try_into().unwrap());
        blob[32..36].copy_from_slice(&(total - off_strings + 1).to_be_bytes());
        assert!(Tree::new(&blob).is_none());
    }

    #[test]
    fn strings_block_extent_overflow_is_rejected()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        // Header byte offset 32 is `size_dt_strings`; a maximal size with a
        // non-zero offset exercises the overflow arm of the strings bound.
        blob[32..36].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Tree::new(&blob).is_none());
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
        let fdt = Tree::new(&blob).expect("valid FDT");
        assert_eq!(fdt.cpu_count(), 0);
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
    fn cpu_walk_still_reports_hart_ids()
    {
        let blob = tree(None, |b| {
            cpu_node(b, b"cpu@0", 7, &[]);
            cpu_node(b, b"cpu@1", 9, &[]);
        });
        let fdt = Tree::new(&blob).expect("valid FDT");
        let entries = fdt.cpu_count();
        assert_eq!(entries, 2);
        let mut ids = vec![0u32; cpu_id_capacity(entries)];
        let (count, _) = fdt.place_hart_ids(9, &mut ids);
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
        let seed: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap().wrapping_add(1));
        let mut blob = tree_with_rng_seed(&seed);
        let (at, data) = Tree::new(&blob)
            .and_then(|t| t.find_prop(b"rng-seed"))
            .map(|(at, data)| (at, data.to_vec()))
            .expect("the tree has a seed");
        assert_eq!(data, seed);
        let mut out = [0u8; 32];
        assert_eq!(take_rng_seed(&mut blob, &mut out), 32);
        assert_eq!(out, seed);
        assert_eq!(blob[at..at + 32], [0u8; 32]);
    }

    #[test]
    fn rng_seed_longer_than_out_is_truncated()
    {
        let seed = [0xABu8; 48];
        let mut blob = tree_with_rng_seed(&seed);
        let mut out = [0u8; 32];
        assert_eq!(take_rng_seed(&mut blob, &mut out), 32);
        assert_eq!(out, [0xABu8; 32]);
        // The whole 48-byte property is scrubbed, not just the copied prefix.
        assert!(blob.windows(48).all(|w| w != seed));
    }

    #[test]
    fn rng_seed_absent_returns_zero()
    {
        let mut blob = tree(None, |b| cpu_node(b, b"cpu@0", 0, &[]));
        let fdt = Tree::new(&blob).expect("valid FDT");
        assert_eq!(fdt.find_prop(b"rng-seed"), None);
        let before = blob.clone();
        let mut out = [0u8; 32];
        assert_eq!(take_rng_seed(&mut blob, &mut out), 0);
        assert_eq!((blob, out), (before, [0u8; 32]));
    }

    /// The DTB QEMU 11.1 `virt` builds with `aia=aplic-imsic` and 4 harts in
    /// one socket (`dumpdtb`, its `rng-seed` zeroed): machine- and
    /// supervisor-level IMSICs at `0x2400_0000` and `0x2800_0000`, and
    /// APLICs at `0xc00_0000` and `0xd00_0000`.
    const QEMU_VIRT_AIA_DTB: &[u8] = include_bytes!("../testdata/qemu-virt-aia-smp4.dtb");

    fn aia(blob: &[u8]) -> DtbAia
    {
        Tree::new(blob).expect("valid FDT").aia()
    }

    fn seeds(blob: &[u8]) -> Vec<(u64, u64)>
    {
        let fdt = Tree::new(blob).expect("valid FDT");
        let mut counting = Seeds::counting();
        fdt.seeds(&mut counting);
        let mut out = vec![
            MmioAperture {
                phys_base: 0,
                size: 0
            };
            counting.found.0
        ];
        let mut seeds = Seeds::new(&mut out, &mut []);
        fdt.seeds(&mut seeds);
        let n = seeds.written.0;
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
    fn place_hart_ids_empty_out_places_nothing()
    {
        let blob = tree(None, |b| cpu_node(b, b"cpu@0", 7, &[]));
        let fdt = Tree::new(&blob).expect("valid FDT");
        let mut ids: [u32; 0] = [];
        // An empty `out` reports truncation: the CPU found no slot.
        assert_eq!(fdt.place_hart_ids(7, &mut ids), (0, true));
    }

    #[test]
    fn imsic_file_in_regs_rejects_zero_stride()
    {
        let mut node = FdtNode::EMPTY;
        node.reg_entries[0] = (0x1000, 0x4000);
        node.reg_count = 1;
        assert_eq!(imsic_file_in_regs(&node, 0, 0), None);
        assert_eq!(imsic_file_in_regs(&node, 1, 0x1000), Some(0x2000));
        assert_eq!(imsic_file_in_regs(&node, u64::MAX, 0x1000), None);
    }
}

#[cfg(kani)]
mod proofs
{
    use boot_protocol::riscv_paging::PagingMode;
    use firmware_tables::fdt::FdtEvent;

    use super::{
        AiaProps, CompatibleWalk, CpuIntcWalk, CpuState, CpuWalk, FdtNode, IntcState, Limits,
        MAX_REG_ENTRIES,
    };
    use crate::property::dtb as property;

    /// A walk of two levels at any depth up to two past them: the step
    /// harnesses' small state. Each step reads only the open node's state
    /// and the depth, so two levels reach a node inside the array, the root,
    /// and a node past it; the property's driver checks the walks over
    /// whole trees of `MAX_DEPTH` levels.
    const D: usize = 2;

    /// Any depth from 0 to two past the walk's levels.
    fn depth() -> usize
    {
        let depth: usize = kani::any();
        kani::assume(depth <= D + 2);
        depth
    }

    /// Any limits.
    fn limits() -> Limits
    {
        Limits {
            too_deep: kani::any(),
            truncated: kani::any(),
        }
    }

    /// Any event but a property.
    fn node_event<'a>() -> FdtEvent<'a>
    {
        if kani::any()
        {
            FdtEvent::BeginNode { start: kani::any() }
        }
        else
        {
            FdtEvent::EndNode
        }
    }

    /// A property named `name` of the first `len` bytes of `data`.
    fn prop<'a>(name: &'a [u8], data: &'a [u8]) -> FdtEvent<'a>
    {
        let len: usize = kani::any();
        kani::assume(len <= data.len());
        FdtEvent::Prop {
            name,
            data: &data[..len],
            at: kani::any(),
        }
    }

    /// Any node state of the compatible walk, its slices `ranges` and
    /// `ie`.
    fn node<'a>(ranges: &'a [u8], ie: &'a [u8]) -> FdtNode<'a>
    {
        let reg_count: usize = kani::any();
        kani::assume(reg_count <= MAX_REG_ENTRIES);
        // Each entry by name: `kani::any` of an array is a loop the step
        // harnesses' bounds would have to cover.
        let reg_entries: [(u64, u64); MAX_REG_ENTRIES] = [
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
            (kani::any(), kani::any()),
        ];
        FdtNode {
            matched: kani::any(),
            reg_entries,
            reg_count,
            ranges,
            aia: AiaProps {
                phandle: kani::any(),
                msi_parent: kani::any(),
                interrupts_extended: ie,
                num_ids: kani::any(),
                num_sources: kani::any(),
                guest_index_bits: kani::any(),
                hart_index_bits: kani::any(),
                group_index_bits: kani::any(),
                group_index_shift: kani::any(),
            },
        }
    }

    /// Any paging-mode claim.
    fn mmu() -> Option<PagingMode>
    {
        match kani::any::<u8>() % 4
        {
            0 => Some(PagingMode::Sv39),
            1 => Some(PagingMode::Sv48),
            2 => Some(PagingMode::Sv57),
            _ => None,
        }
    }

    /// Any CPU-node state.
    fn cpu_state() -> CpuState
    {
        CpuState {
            is_riscv_cpu: kani::any(),
            hart_id: kani::any(),
            disabled: kani::any(),
            caps: kani::any(),
            mmu: mmu(),
        }
    }

    /// Any interrupt-controller walk state.
    fn intc_state() -> IntcState
    {
        IntcState {
            is_riscv_cpu: kani::any(),
            disabled: kani::any(),
            hart_id: kani::any(),
            is_cpu_intc: kani::any(),
            phandle: kani::any(),
            intc_phandle: kani::any(),
        }
    }

    /// Any compatible walk for `compat` over nodes with no slices.
    fn compatible_walk<'c, 'a>(compat: &'c [u8]) -> CompatibleWalk<'c, 'a, D>
    {
        CompatibleWalk {
            compat,
            states: [node(&[], &[]), node(&[], &[])],
            depth: depth(),
            limits: limits(),
        }
    }

    /// Every step of the compatible walk from any state opens and closes a
    /// node as the structure block nests it, yielding a matched node. The
    /// loops are the states' compare and, within it, the compare of a
    /// state's `MAX_REG_ENTRIES` `reg` entries.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_compatible_walk_step_nests_its_nodes()
    {
        let _ = property::compatible_step_holds(&mut compatible_walk(b"ab"), node_event());
    }

    /// Every step of the compatible walk takes a `reg` of up to 33 bytes
    /// into any open node, filling its free slots and noting a surplus: 33
    /// bytes hold two entries and a partial one, and a node with 7 or 8 slots
    /// filled truncates them. The loops are the entries, the states'
    /// compare and the name's bytes.
    #[kani::proof]
    #[kani::unwind(12)]
    fn every_compatible_walk_step_records_its_reg()
    {
        let data: [u8; 33] = kani::any();
        let _ = property::compatible_step_holds(&mut compatible_walk(b"ab"), prop(b"reg", &data));
    }

    /// The compatible walk's property harnesses, one per property it reads,
    /// each a step from any state taking that property's value of up to the
    /// bytes given: a `compatible` of 5, which holds the walk's two-byte entry
    /// at either of a list's first two places (`c\0ab\0`), a longer name it
    /// begins, or neither, and a `ranges` and each AIA property of 5, a cell
    /// and one past it. Whether a list names an entry is the shared
    /// `compatible_contains`'s, proved in `firmware_tables`. The loops are
    /// the list's bytes, the states' compare and the names' bytes, so each
    /// unwinds at least one past the longest of the property's value, its
    /// name and the names of the step's other arms of the same length: 11
    /// for `compatible`, whose arms of ten bytes include `msi-parent`, and 25,
    /// one past `riscv,group-index-shift`, for the others.
    macro_rules! compatible_property_proofs {
        ($($proof:ident: $name:literal, $len:literal, $unwind:literal;)*) => {$(
            #[doc = concat!("Every step of the compatible walk takes a `", $name,
                "` of up to ", stringify!($len), " bytes as its binding says.")]
            #[kani::proof]
            #[kani::unwind($unwind)]
            fn $proof()
            {
                let data: [u8; $len] = kani::any();
                let _ = property::compatible_step_holds(
                    &mut compatible_walk(b"ab"),
                    prop($name.as_bytes(), &data),
                );
            }
        )*};
    }

    compatible_property_proofs! {
        every_compatible_walk_step_records_its_compatible: "compatible", 5, 11;
        every_compatible_walk_step_records_its_ranges: "ranges", 5, 25;
        every_compatible_walk_step_records_its_phandle: "phandle", 5, 25;
        every_compatible_walk_step_records_its_msi_parent: "msi-parent", 5, 25;
        every_compatible_walk_step_records_its_interrupts_extended: "interrupts-extended", 5, 25;
        every_compatible_walk_step_records_its_num_ids: "riscv,num-ids", 5, 25;
        every_compatible_walk_step_records_its_num_sources: "riscv,num-sources", 5, 25;
        every_compatible_walk_step_records_its_guest_index_bits: "riscv,guest-index-bits", 5, 25;
        every_compatible_walk_step_records_its_hart_index_bits: "riscv,hart-index-bits", 5, 25;
        every_compatible_walk_step_records_its_group_index_bits: "riscv,group-index-bits", 5, 25;
        every_compatible_walk_step_records_its_group_index_shift: "riscv,group-index-shift", 5, 25;
    }

    /// Every step of the CPU walk from any state opens and closes a node as
    /// the structure block nests it, yielding an enabled CPU with a hart ID.
    /// The loops are the states' compare.
    #[kani::proof]
    #[kani::unwind(3)]
    fn every_cpu_walk_step_nests_its_nodes()
    {
        let mut walk = CpuWalk::<D> {
            states: [cpu_state(), cpu_state()],
            depth: depth(),
            limits: limits(),
        };
        let _ = property::cpu_step_holds(&mut walk, node_event());
    }

    /// The CPU walk's property harnesses, one per property a CPU node's
    /// binding gives it, each a step from any state taking that property's
    /// value of up to the bytes given: a `compatible` of 8, which holds
    /// `riscv` at a list's second place (`a\0riscv\0`); a `reg` of 5, a cell
    /// and one past it; a `status` of 9, `disabled` and one past it; a
    /// `riscv,isa-extensions` and a `riscv,isa` of 5, which hold `sstc` with
    /// its NUL; and an `mmu-type` of 12, `riscv,sv57x` with its NUL. Whether
    /// a list names an entry is the shared `compatible_contains`'s, proved in
    /// `firmware_tables`, and an ISA string's reading over longer strings is
    /// `every_isa_string_names_its_whole_segments`'s, so these two harnesses
    /// check that the step records the reading in the open node. The
    /// loops are the values' entries, the extension names and the states'
    /// compare, so each unwinds two past its value's bytes; the names are
    /// constants, whose compares need no unwinding.
    macro_rules! cpu_property_proofs {
        ($($proof:ident: $name:literal, $len:literal, $unwind:literal;)*) => {$(
            #[doc = concat!("Every step of the CPU walk takes a `", $name,
                "` of up to ", stringify!($len), " bytes as its binding says.")]
            #[kani::proof]
            #[kani::unwind($unwind)]
            fn $proof()
            {
                let data: [u8; $len] = kani::any();
                let mut walk = CpuWalk::<D> {
                    states: [cpu_state(), cpu_state()],
                    depth: depth(),
                    limits: limits(),
                };
                let _ = property::cpu_step_holds(&mut walk, prop($name.as_bytes(), &data));
            }
        )*};
    }

    cpu_property_proofs! {
        every_cpu_walk_step_records_its_compatible: "compatible", 8, 10;
        every_cpu_walk_step_records_its_reg: "reg", 5, 7;
        every_cpu_walk_step_records_its_status: "status", 9, 11;
        every_cpu_walk_step_records_its_isa_extensions: "riscv,isa-extensions", 5, 7;
        every_cpu_walk_step_records_its_isa: "riscv,isa", 5, 7;
        every_cpu_walk_step_records_its_mmu_type: "mmu-type", 12, 14;
    }

    /// Every step of the interrupt-controller walk from any state opens and
    /// closes a node as the structure block nests it, a closing
    /// `riscv,cpu-intc` giving its parent its phandle once. The loops are
    /// the states' compare.
    #[kani::proof]
    #[kani::unwind(3)]
    fn every_intc_walk_step_nests_its_nodes()
    {
        let mut walk = CpuIntcWalk::<D> {
            states: [intc_state(), intc_state()],
            depth: depth(),
            limits: limits(),
        };
        let _ = property::intc_step_holds(&mut walk, node_event());
    }

    /// The interrupt-controller walk's property harnesses, one per property
    /// it reads, each a step from any state taking that property's value of
    /// up to the bytes given: a `compatible` of 6, `riscv` with its NUL; a
    /// `reg` and a `phandle` of 5, a cell and one past it; and a `status` of
    /// 9, `disabled` and one past it. A `compatible` that names
    /// `riscv,cpu-intc` is `every_intc_walk_step_records_a_cpu_intc`'s.
    /// Which entries a list names is the shared `compatible_contains`'s,
    /// proved in `firmware_tables`. The loops are the list's bytes and the
    /// states'
    /// compare, so each unwinds two past its value's bytes; the names are
    /// constants, whose compares need no unwinding.
    macro_rules! intc_property_proofs {
        ($($proof:ident: $name:literal, $len:literal, $unwind:literal;)*) => {$(
            #[doc = concat!("Every step of the interrupt-controller walk takes a `",
                $name, "` of up to ", stringify!($len), " bytes as its binding says.")]
            #[kani::proof]
            #[kani::unwind($unwind)]
            fn $proof()
            {
                let data: [u8; $len] = kani::any();
                let mut walk = CpuIntcWalk::<D> {
                    states: [intc_state(), intc_state()],
                    depth: depth(),
                    limits: limits(),
                };
                let _ = property::intc_step_holds(&mut walk, prop($name.as_bytes(), &data));
            }
        )*};
    }

    intc_property_proofs! {
        every_intc_walk_step_records_its_compatible: "compatible", 6, 8;
        every_intc_walk_step_records_its_reg: "reg", 5, 7;
        every_intc_walk_step_records_its_status: "status", 9, 11;
        every_intc_walk_step_records_its_phandle: "phandle", 5, 7;
    }

    /// Every step of the interrupt-controller walk takes a `compatible` that
    /// names `riscv,cpu-intc` as its binding says, from any state. The list
    /// is that one whole entry, whose 15 bytes no symbolic list of a size the
    /// memory limit admits reaches.
    #[kani::proof]
    #[kani::unwind(17)]
    fn every_intc_walk_step_records_a_cpu_intc()
    {
        let mut walk = CpuIntcWalk::<D> {
            states: [intc_state(), intc_state()],
            depth: depth(),
            limits: limits(),
        };
        let event = FdtEvent::Prop {
            name: b"compatible",
            data: b"riscv,cpu-intc\0",
            at: kani::any(),
        };
        let _ = property::intc_step_holds(&mut walk, event);
    }

    /// Every `mmu-type` of at most 12 bytes claims the mode it names, and a
    /// hypervisor form none: 12 bytes hold `riscv,sv57x` and one past it.
    /// The loops are the names' compare.
    #[kani::proof]
    #[kani::unwind(13)]
    fn every_mmu_type_claims_its_mode()
    {
        let bytes: [u8; 12] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::mmu_holds(&bytes[..len]);
    }

    /// Every `timebase-frequency` of at most 9 bytes reads as its one or two
    /// cells. No loop.
    #[kani::proof]
    fn every_timebase_reads_as_its_cells()
    {
        let bytes: [u8; 9] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::timebase_holds(&bytes[..len]);
    }

    /// Any matched IMSIC node with up to 2 `reg` windows, its
    /// `interrupts-extended` the first bytes of `ie`, and no `ranges`.
    fn imsic_node(ie: &[u8]) -> FdtNode<'_>
    {
        let ie_len: usize = kani::any();
        kani::assume(ie_len <= ie.len());
        let mut n = node(&[], &ie[..ie_len]);
        kani::assume(n.reg_count <= 2);
        n.matched = true;
        n
    }

    /// Every IMSIC node with up to 2 `reg` windows and an
    /// `interrupts-extended` of up to 17 bytes serves the supervisor and
    /// states its layout as the AIA binding says: 17 bytes hold two entries
    /// and a partial one. The loops are the entries.
    #[kani::proof]
    #[kani::unwind(6)]
    fn every_imsic_node_states_its_layout()
    {
        let ie: [u8; 17] = kani::any();
        property::imsic_layout_holds(&imsic_node(&ie));
    }

    /// The IMSIC file harnesses, one per stride the property tries
    /// (`property::IMSIC_STRIDES`): every IMSIC node with up to 2 `reg`
    /// windows and an `interrupts-extended` of up to 17 bytes places each of
    /// its files, by index and by a hart's phandle, as the AIA binding says:
    /// 2 windows hold a file past the first window's, and 17 bytes two
    /// entries and a partial one. The loops are the indices, the windows and
    /// the entries.
    macro_rules! imsic_files_proofs {
        ($($proof:ident: $stride:literal;)*) => {$(
            #[doc = concat!("Every IMSIC node places its files at the stride `IMSIC_STRIDES[",
                stringify!($stride), "]` as the AIA binding says.")]
            #[kani::proof]
            #[kani::unwind(6)]
            fn $proof()
            {
                let ie: [u8; 17] = kani::any();
                property::imsic_files_hold(&imsic_node(&ie), property::IMSIC_STRIDES[$stride]);
            }
        )*};
    }

    imsic_files_proofs! {
        every_imsic_node_places_no_file_at_no_stride: 0;
        every_imsic_node_places_its_files_a_page_apart: 1;
        every_imsic_node_places_its_files_two_pages_apart: 2;
        every_imsic_node_places_its_files_at_an_overflowing_stride: 3;
    }

    /// Every `ranges` of up to 29 bytes reads as its PCI ranges: 29 bytes
    /// hold one 28-byte range and a partial one. The loop is the ranges.
    #[kani::proof]
    #[kani::unwind(3)]
    fn every_pci_range_reads_as_its_cells()
    {
        let ranges: [u8; 29] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= ranges.len());
        property::pci_ranges_hold(&ranges[..len]);
    }
}
