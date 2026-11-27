// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/property/dtb.rs

//! The device-tree walks' contract: each step of a walk opens, closes or
//! records into the open node as the Devicetree Specification 0.4's
//! structure block nests them and the bindings the walk reads (`reg` of two
//! cells each, `ranges` of a PCI host, the CPU node's `compatible`, `reg`,
//! `status`, `riscv,isa-extensions`, `riscv,isa` and `mmu-type`, the AIA
//! IMSIC's and APLIC's properties) lay them out, and the tree's answers are
//! the walks' reports combined as `crate::dtb::Tree` documents.

use boot_protocol::riscv_paging::PagingMode;
use firmware_tables::fdt::{Fdt, FdtEvent};

use super::acpi::isa_names;
use super::{be32, be64, list_holds};
use crate::dtb::{
    CompatibleWalk, Cpu, CpuIntcWalk, CpuState, CpuWalk, FdtNode, IntcState, Limits, MAX_DEPTH,
    MAX_REG_ENTRIES, Step, Tree, hart_imsic_file, imsic_file_in_regs, imsic_layout,
    is_supervisor_imsic, mmu_type, pci_ranges, timebase_value,
};
use crate::isa::HART_CAP_NAMES;

/// The CPU nodes whose placement the check compares.
const MAX_HARTS: usize = 16;

/// The `compatible` entries the check walks for.
const COMPATS: [&[u8]; 4] = [
    b"ns16550a",
    b"riscv,imsics",
    b"riscv,aplic",
    b"pci-host-ecam-generic",
];

/// Check the device-tree reading of `input`, read as a blob.
///
/// # Panics
///
/// When a walk breaks its contract on `input`.
pub(crate) fn dtb_holds(input: &[u8])
{
    for data in [input, input.get(..input.len().min(16)).unwrap_or_default()]
    {
        mmu_holds(data);
        timebase_holds(data);
    }
    let (Some(fdt), Some(tree)) = (Fdt::new(input), Tree::new(input))
    else
    {
        assert!(Fdt::new(input).is_none() && Tree::new(input).is_none());
        return;
    };
    let uart = compatible_walks_hold(&fdt, &tree);
    cpu_walks_hold(&fdt, &tree);
    if let Some((at, data)) = tree.find_prop(b"rng-seed")
    {
        assert_eq!(input.get(at..at.saturating_add(data.len())), Some(data));
    }
    assert_eq!(tree.uart(), uart);
    let _ = tree.aia();
}

/// Check the compatible walks over `fdt` against `tree`'s, and return the
/// UART the tree reports: the first `ns16550a` node's first `reg` entry
/// with a non-zero base.
fn compatible_walks_hold(fdt: &Fdt<'_>, tree: &Tree<'_>) -> Option<(u64, u64)>
{
    let mut limits = Limits::default();
    let mut uart = None;
    for compat in COMPATS
    {
        let mut walk = CompatibleWalk::<MAX_DEPTH>::new(compat);
        let mut nodes = 0usize;
        for event in fdt.events()
        {
            let step = compatible_step_holds(&mut walk, event);
            if let Step::Yield(node) = step
            {
                imsic_holds(&node);
                nodes = nodes.saturating_add(1);
                if compat == b"ns16550a"
                    && uart.is_none()
                    && node.reg_count > 0
                    && node.reg_entries[0].0 != 0
                {
                    uart = Some(node.reg_entries[0]);
                }
            }
            if step == Step::Stop
            {
                break;
            }
        }
        let mut seen = 0usize;
        tree.for_each_compatible(compat, |_| {
            seen = seen.saturating_add(1);
            true
        });
        assert_eq!(seen, nodes);
        limits.too_deep |= walk.limits.too_deep;
        limits.truncated |= walk.limits.truncated;
    }
    assert_eq!(tree.limits(), limits);
    uart
}

/// Check the CPU and CPU interrupt-controller walks over `fdt` against
/// `tree`'s CPUs, capabilities, timebase and hart placement.
fn cpu_walks_hold(fdt: &Fdt<'_>, tree: &Tree<'_>)
{
    let mut walk = CpuWalk::<MAX_DEPTH>::default();
    let mut cpus = 0usize;
    let mut caps = u64::MAX;
    let mut harts = [0u32; MAX_HARTS];
    for event in fdt.events()
    {
        match cpu_step_holds(&mut walk, event)
        {
            Step::Yield(cpu) =>
            {
                if let Some(slot) = harts.get_mut(cpus)
                {
                    *slot = cpu.hart_id;
                }
                cpus = cpus.saturating_add(1);
                assert_eq!(cpu.caps(), cpu_caps(&cpu));
                caps &= cpu.caps();
            }
            Step::Stop => break,
            Step::Continue =>
            {}
        }
    }
    assert_eq!(tree.cpu_count(), cpus);
    let timebase = fdt
        .events()
        .find_map(|e| match e
        {
            FdtEvent::Prop { name, data, .. } if name == b"timebase-frequency" =>
            {
                timebase_value(data)
            }
            FdtEvent::BeginNode { .. } | FdtEvent::EndNode | FdtEvent::Prop { .. } => None,
        })
        .unwrap_or(0);
    assert_eq!(tree.timebase_frequency(), timebase);
    assert_eq!(
        tree.hart_caps(),
        (timebase, if cpus > 0 { caps } else { 0 })
    );

    let mut walk = CpuIntcWalk::<MAX_DEPTH>::default();
    let mut intcs = 0usize;
    for event in fdt.events()
    {
        match intc_step_holds(&mut walk, event)
        {
            Step::Yield(_) => intcs = intcs.saturating_add(1),
            Step::Stop => break,
            Step::Continue =>
            {}
        }
    }
    assert_eq!(intcs, cpus, "both walks select the same CPU nodes");

    // The placement over the tree's harts is the placement over its CPU
    // nodes' IDs, into an array that holds them all and into one that
    // truncates them.
    if cpus <= MAX_HARTS
    {
        let bsp = harts.get(cpus / 2).copied().unwrap_or(7);
        for slots in [MAX_HARTS + 1, cpus / 2]
        {
            let (mut got, mut want) = ([0u32; MAX_HARTS + 1], [0u32; MAX_HARTS + 1]);
            let placed = tree.place_hart_ids(bsp, got.get_mut(..slots).unwrap_or_default());
            let expected = crate::cpus::place_cpu_ids(
                bsp,
                harts.get(..cpus).unwrap_or_default().iter().copied(),
                want.get_mut(..slots).unwrap_or_default(),
            );
            assert_eq!((placed, got), (expected, want));
        }
    }
    let _ = tree.boot_cpu_mmu_type(0);
    let mut seeds = crate::seeds::Seeds::counting();
    tree.seeds(&mut seeds);
}

/// The node `node` becomes once the property `name` of value `data` is
/// recorded for a walk that reports nodes whose `compatible` names
/// `compat`, with whether a `reg` overflowed it.
fn node_reading<'a>(
    mut node: FdtNode<'a>,
    compat: &[u8],
    name: &[u8],
    data: &'a [u8],
) -> (FdtNode<'a>, bool)
{
    let cell = be32(data, 0);
    let mut truncated = false;
    match name
    {
        b"compatible" => node.matched = node.matched || list_holds(data, compat),
        b"reg" =>
        {
            for i in 0..data.len() / 16
            {
                if node.reg_count == MAX_REG_ENTRIES
                {
                    truncated = true;
                    break;
                }
                if let Some(slot) = node.reg_entries.get_mut(node.reg_count)
                {
                    *slot = (
                        be64(data, 16usize.saturating_mul(i)).unwrap_or(0),
                        be64(data, 16usize.saturating_mul(i).saturating_add(8)).unwrap_or(0),
                    );
                }
                node.reg_count = node.reg_count.saturating_add(1);
            }
        }
        b"ranges" => node.ranges = data,
        b"phandle" => node.aia.phandle = cell.unwrap_or(0),
        b"msi-parent" => node.aia.msi_parent = cell.unwrap_or(0),
        b"interrupts-extended" => node.aia.interrupts_extended = data,
        b"riscv,num-ids" => node.aia.num_ids = cell.unwrap_or(0),
        b"riscv,num-sources" => node.aia.num_sources = cell.unwrap_or(0),
        b"riscv,guest-index-bits" => node.aia.guest_index_bits = cell,
        b"riscv,hart-index-bits" => node.aia.hart_index_bits = cell,
        b"riscv,group-index-bits" => node.aia.group_index_bits = cell,
        b"riscv,group-index-shift" => node.aia.group_index_shift = cell,
        _ =>
        {}
    }
    (node, truncated)
}

/// Check the nesting a step of a walk with `D` levels made: from depth
/// `depth` and states `before`, to `walk_depth` and `after` with result
/// `step`, where `empty` is an opened node's state, `yields` whether a
/// closing node's state is reported, and `recorded` the state a property
/// makes of the open node's.
#[expect(
    clippy::too_many_arguments,
    reason = "the check judges one step of any of three walks, each argument a part of the step               it judges"
)]
fn nesting_holds<
    S: Copy + PartialEq + core::fmt::Debug,
    T: PartialEq + core::fmt::Debug,
    const D: usize,
>(
    event: &FdtEvent<'_>,
    depth: usize,
    before: &[S; D],
    after: &[S; D],
    walk_depth: usize,
    step: &Step<T>,
    empty: S,
    yields: impl Fn(&S) -> Option<T>,
    recorded: impl Fn(&S) -> S,
)
{
    for (i, (b, a)) in before.iter().zip(after.iter()).enumerate()
    {
        let expected = match event
        {
            FdtEvent::BeginNode { .. } if i == depth => empty,
            FdtEvent::Prop { .. } if i.saturating_add(1) == depth => recorded(b),
            FdtEvent::BeginNode { .. } | FdtEvent::EndNode | FdtEvent::Prop { .. } => *b,
        };
        assert_eq!(*a, expected, "the state at depth {i}");
    }
    match event
    {
        FdtEvent::BeginNode { .. } =>
        {
            assert_eq!(walk_depth, depth.saturating_add(1));
            assert_eq!(*step, Step::Continue);
        }
        FdtEvent::EndNode if depth == 0 =>
        {
            assert_eq!(walk_depth, 0);
            assert_eq!(*step, Step::Stop);
        }
        FdtEvent::EndNode =>
        {
            assert_eq!(walk_depth, depth.saturating_sub(1));
            match before.get(depth.saturating_sub(1)).and_then(&yields)
            {
                Some(t) => assert_eq!(*step, Step::Yield(t)),
                None => assert_eq!(*step, Step::Continue),
            }
        }
        FdtEvent::Prop { .. } =>
        {
            assert_eq!(walk_depth, depth);
            assert_eq!(*step, Step::Continue);
        }
    }
}

/// Check one step of a compatible walk from its state.
///
/// # Panics
///
/// When the step breaks its contract.
pub(crate) fn compatible_step_holds<'a, const D: usize>(
    walk: &mut CompatibleWalk<'_, 'a, D>,
    event: FdtEvent<'a>,
) -> Step<FdtNode<'a>>
{
    let (depth, before, limits) = (walk.depth, walk.states, walk.limits);
    let compat = walk.compat;
    let step = walk.step(event);
    nesting_holds(
        &event,
        depth,
        &before,
        &walk.states,
        walk.depth,
        &step,
        FdtNode::EMPTY,
        |s| s.matched.then_some(*s),
        |s| match event
        {
            FdtEvent::Prop { name, data, .. } => node_reading(*s, compat, name, data).0,
            FdtEvent::BeginNode { .. } | FdtEvent::EndNode => *s,
        },
    );
    let opened_past = matches!(event, FdtEvent::BeginNode { .. }) && depth >= D;
    assert_eq!(walk.limits.too_deep, limits.too_deep || opened_past);
    let overflowed = match event
    {
        FdtEvent::Prop { name, data, .. } => depth
            .checked_sub(1)
            .and_then(|d| before.get(d))
            .is_some_and(|s| node_reading(*s, compat, name, data).1),
        FdtEvent::BeginNode { .. } | FdtEvent::EndNode => false,
    };
    assert_eq!(walk.limits.truncated, limits.truncated || overflowed);
    step
}

/// The `HART_CAP_*` bits of the extensions the CPU node `cpu`'s
/// `riscv,isa-extensions` list or `riscv,isa` string names.
fn cpu_caps(cpu: &Cpu<'_>) -> u64
{
    HART_CAP_NAMES
        .iter()
        .filter(|(ext, _)| list_holds(cpu.isa_extensions, ext) || isa_names(cpu.isa, ext))
        .fold(0, |caps, (_, bit)| caps | bit)
}

/// The CPU-node state `s` becomes once the property `name` of value `data`
/// is recorded.
fn cpu_reading<'a>(mut s: CpuState<'a>, name: &[u8], data: &'a [u8]) -> CpuState<'a>
{
    match name
    {
        b"compatible" => s.is_riscv_cpu = s.is_riscv_cpu || list_holds(data, b"riscv"),
        b"reg" if data.len() >= 4 => s.hart_id = be32(data, 0),
        b"status" => s.disabled = s.disabled || data.get(..8) == Some(b"disabled"),
        b"riscv,isa-extensions" => s.isa_extensions = data,
        b"riscv,isa" => s.isa = data,
        b"mmu-type" => s.mmu = mmu_type(data),
        _ =>
        {}
    }
    s
}

/// Check one step of the CPU walk from its state.
///
/// # Panics
///
/// When the step breaks its contract.
pub(crate) fn cpu_step_holds<'a, const D: usize>(
    walk: &mut CpuWalk<'a, D>,
    event: FdtEvent<'a>,
) -> Step<Cpu<'a>>
{
    let (depth, before, limits) = (walk.depth, walk.states, walk.limits);
    let step = walk.step(event);
    nesting_holds(
        &event,
        depth,
        &before,
        &walk.states,
        walk.depth,
        &step,
        CpuState::EMPTY,
        |s| match s.hart_id
        {
            Some(hart_id) if s.is_riscv_cpu && !s.disabled => Some(Cpu {
                hart_id,
                isa_extensions: s.isa_extensions,
                isa: s.isa,
                mmu: s.mmu,
            }),
            _ => None,
        },
        |s| match event
        {
            FdtEvent::Prop { name, data, .. } => cpu_reading(*s, name, data),
            FdtEvent::BeginNode { .. } | FdtEvent::EndNode => *s,
        },
    );
    let opened_past = matches!(event, FdtEvent::BeginNode { .. }) && depth >= D;
    assert_eq!(walk.limits.too_deep, limits.too_deep || opened_past);
    step
}

/// Check one step of the CPU interrupt-controller walk from its state.
///
/// # Panics
///
/// When the step breaks its contract.
pub(crate) fn intc_step_holds<const D: usize>(
    walk: &mut CpuIntcWalk<D>,
    event: FdtEvent<'_>,
) -> Step<(u32, u32)>
{
    let (depth, before) = (walk.depth, walk.states);
    let step = walk.step(event);
    // A closing `riscv,cpu-intc` with a phandle gives it to its parent, once.
    let mut expected_before = before;
    if matches!(event, FdtEvent::EndNode)
        && depth >= 2
        && let Some(&s) = before.get(depth.saturating_sub(1))
        && s.is_cpu_intc
        && s.phandle != 0
        && let Some(parent) = expected_before.get_mut(depth.saturating_sub(2))
        && parent.intc_phandle == 0
    {
        parent.intc_phandle = s.phandle;
    }
    nesting_holds(
        &event,
        depth,
        &expected_before,
        &walk.states,
        walk.depth,
        &step,
        IntcState::EMPTY,
        |s| match s.hart_id
        {
            Some(hart_id) if s.is_riscv_cpu && !s.disabled => Some((s.intc_phandle, hart_id)),
            _ => None,
        },
        |s| match event
        {
            FdtEvent::Prop { name, data, .. } =>
            {
                let mut s = *s;
                match name
                {
                    b"compatible" =>
                    {
                        s.is_riscv_cpu = s.is_riscv_cpu || list_holds(data, b"riscv");
                        s.is_cpu_intc = s.is_cpu_intc || list_holds(data, b"riscv,cpu-intc");
                    }
                    b"reg" if data.len() >= 4 => s.hart_id = be32(data, 0),
                    b"status" => s.disabled = s.disabled || data.get(..8) == Some(b"disabled"),
                    b"phandle" if data.len() >= 4 => s.phandle = be32(data, 0).unwrap_or(0),
                    _ =>
                    {}
                }
                s
            }
            FdtEvent::BeginNode { .. } | FdtEvent::EndNode => *s,
        },
    );
    step
}

/// Check the `mmu-type` reading of `data`.
///
/// # Panics
///
/// When the reading breaks its contract.
pub(crate) fn mmu_holds(data: &[u8])
{
    let name = |n: &[u8]| data.get(..n.len()) == Some(n);
    let expected = if name(b"riscv,sv39x") || name(b"riscv,sv48x") || name(b"riscv,sv57x")
    {
        None
    }
    else if name(b"riscv,sv57")
    {
        Some(PagingMode::Sv57)
    }
    else if name(b"riscv,sv48")
    {
        Some(PagingMode::Sv48)
    }
    else if name(b"riscv,sv39")
    {
        Some(PagingMode::Sv39)
    }
    else
    {
        None
    };
    assert_eq!(mmu_type(data), expected);
}

/// Check the `timebase-frequency` reading of `data`.
///
/// # Panics
///
/// When the reading breaks its contract.
pub(crate) fn timebase_holds(data: &[u8])
{
    let value = match data.len()
    {
        4 => be32(data, 0).map(u64::from),
        8 => be64(data, 0),
        _ => None,
    }
    .filter(|&v| v != 0);
    assert_eq!(timebase_value(data), value);
}

/// The file strides the IMSIC checks try: none, which places no file, one
/// and two 4 KiB pages, and one whose offsets overflow.
pub(crate) const IMSIC_STRIDES: [u64; 4] = [0, 0x1000, 0x2000, u64::MAX];

/// Check the IMSIC readings of `node`: whether it serves supervisor mode,
/// its layout, where its files lie at each of [`IMSIC_STRIDES`], and its
/// PCI ranges.
///
/// # Panics
///
/// When a reading breaks its contract.
pub(crate) fn imsic_holds(node: &FdtNode<'_>)
{
    imsic_layout_holds(node);
    for stride in IMSIC_STRIDES
    {
        imsic_files_hold(node, stride);
    }
    pci_ranges_hold(node.ranges);
}

/// The number of whole `interrupts-extended` entries of `node`.
fn ie_entries(node: &FdtNode<'_>) -> usize
{
    node.aia.interrupts_extended.len() / 8
}

/// Check whether the IMSIC `node` serves supervisor mode, and its layout.
///
/// # Panics
///
/// When a reading breaks its contract.
pub(crate) fn imsic_layout_holds(node: &FdtNode<'_>)
{
    let ie = node.aia.interrupts_extended;
    let entries = ie_entries(node);
    let supervisor = entries > 0
        && (0..entries).all(|i| be32(ie, 8usize.saturating_mul(i).saturating_add(4)) == Some(9));
    assert_eq!(is_supervisor_imsic(node), supervisor);

    let a = &node.aia;
    let hart_bits_default = if entries <= 1
    {
        0
    }
    else
    {
        entries.saturating_sub(1).bit_width()
    };
    let width = |w: Option<u32>, default: u32| u8::try_from(w.unwrap_or(default)).ok();
    let layout = (node.reg_count > 0)
        .then(|| {
            Some(boot_protocol::ImsicLayout {
                base: node.reg_entries[0].0,
                ids: a.num_ids,
                guest_index_bits: width(a.guest_index_bits, 0)?,
                hart_index_bits: width(a.hart_index_bits, hart_bits_default)?,
                group_index_bits: width(a.group_index_bits, 0)?,
                group_index_shift: width(a.group_index_shift, 24)?,
            })
        })
        .flatten();
    assert_eq!(imsic_layout(node), layout);
}

/// Check where the files of the IMSIC `node` lie, by index and by a hart's
/// `interrupts-extended` phandle, when they lie `stride` bytes apart.
///
/// # Panics
///
/// When a reading breaks its contract.
pub(crate) fn imsic_files_hold(node: &FdtNode<'_>, stride: u64)
{
    let ie = node.aia.interrupts_extended;
    let entries = ie_entries(node);
    for index in 0..=(node.reg_count as u64).saturating_add(1)
    {
        files_hold(node, index, stride);
    }
    for i in 0..entries.min(4)
    {
        let phandle = be32(ie, 8usize.saturating_mul(i)).unwrap_or(0);
        let first = (0..entries).find(|&j| be32(ie, 8usize.saturating_mul(j)) == Some(phandle));
        let expected = if phandle == 0
        {
            None
        }
        else
        {
            first.and_then(|j| imsic_file_in_regs(node, j as u64, stride))
        };
        assert_eq!(hart_imsic_file(node, phandle, stride), expected);
    }
    assert_eq!(hart_imsic_file(node, 0, stride), None);
}

/// Check the PCI ranges a node's `ranges` property `r` reads as.
///
/// # Panics
///
/// When a reading breaks its contract.
pub(crate) fn pci_ranges_hold(r: &[u8])
{
    for (i, range) in pci_ranges(r).enumerate()
    {
        let at = 28usize.saturating_mul(i);
        assert_eq!(
            Some(range),
            be32(r, at)
                .zip(be64(r, at.saturating_add(12)))
                .zip(be64(r, at.saturating_add(20)))
                .map(|((f, c), s)| (f, c, s))
        );
    }
    assert_eq!(pci_ranges(r).count(), r.len() / 28);
}

/// Check where the `index`-th file of an IMSIC `node` lies when its files lie
/// `stride` bytes apart.
///
/// # Panics
///
/// When the reading breaks its contract.
pub(crate) fn files_hold(node: &FdtNode<'_>, index: u64, stride: u64)
{
    let mut expected = None;
    let mut left = index;
    for &(base, size) in node.reg_entries.iter().take(node.reg_count)
    {
        // A stride of 0 places no file.
        let Some(files) = size.checked_div(stride)
        else
        {
            break;
        };
        if left < files
        {
            expected = left.checked_mul(stride).and_then(|o| base.checked_add(o));
            break;
        }
        left = left.saturating_sub(files);
    }
    assert_eq!(imsic_file_in_regs(node, index, stride), expected);
}
