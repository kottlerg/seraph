// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/process-layout/src/lib.rs

//! Per-process bootstrap virtual-address layout.
//!
//! A process creator (procmgr for general processes, init for memmgr/procmgr)
//! must place four bootstrap surfaces in a new process's address space before
//! it runs: the `ProcessInfo` handover page, the main-thread stack, the
//! main-thread TLS block, and the main-thread IPC buffer. This crate owns the
//! choice of where those surfaces go, so the decision lives in one place rather
//! than being pinned as ABI constants in `process-abi`.
//!
//! The creator is the chooser: it draws entropy, calls
//! [`choose_process_layout`] once per process, and writes the chosen VAs into
//! the handover surface (`ProcessInfo.stack_top_vaddr`,
//! `ProcessInfo.main_tls_vaddr`, `ProcessInfo.ipc_buffer_vaddr`) and into the
//! entry register that delivers the `ProcessInfo` page address. The created
//! process reads them back from the struct and the register — it does not
//! assume any fixed address.
//!
//! # Randomisation model (ASLR, #39)
//!
//! The draw windows and the per-process zone map are specified in
//! `docs/userspace-memory-model.md` § Bootstrap Cross-Boundary VAs,
//! § Image Placement, and § Growth Zones. Each window's base, slot count,
//! and the disjointness and ordering of every possible draw are
//! const-asserted below.
//!
//! # Two tiers
//!
//! Every surface a creator places (the bootstrap windows, init's windows,
//! the image window, and the degraded-fallback defaults) lies below
//! [`LAYOUT_VA_CEILING`], the smallest user half, because init and the
//! kernel place them without knowing the paging mode. The byte heap and the
//! reservation arena are drawn by the process itself, which knows its
//! address space's size (`SystemInfoType::UserVaTop`), so their zones are
//! sized to it by [`growth_zones`]: under Sv39 they share the space
//! below the bootstrap windows, and in a wider user half they move above
//! the fixed tier and grow with it.
//!
//! When the creator has no entropy (a draw failed), it passes `None` and the
//! layout degrades to the deterministic `DEFAULT_*` addresses. The defaults
//! lie outside the windows above; harness window assertions fail loudly on a
//! degraded boot by design.

// Under `rustc-dep-of-std` (build-std), use the core facade and no_core so
// this crate can sit inside std's dep graph. Mirrors abi/process-abi. Normal
// builds (no feature) retain `#![no_std]`.
#![cfg_attr(feature = "rustc-dep-of-std", feature(no_core))]
#![cfg_attr(feature = "rustc-dep-of-std", allow(internal_features))]
#![cfg_attr(not(feature = "rustc-dep-of-std"), no_std)]
#![cfg_attr(feature = "rustc-dep-of-std", no_core)]

#[cfg(feature = "rustc-dep-of-std")]
extern crate rustc_std_workspace_core as core;

// `no_core` drops the implicit prelude; the glob restores it, and lints as
// unused for whichever prelude items this crate happens not to name.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use process_abi::MAX_PROCESS_STACK_PAGES;

/// Page size shared by every layout computation in this crate.
const PAGE_SIZE: u64 = 4096;

/// Exclusive ceiling of the fixed tier: every surface a creator places lies
/// below it. It is the smallest user half among the supported paging modes
/// (riscv64 Sv39's 2^38), so one static layout of those surfaces is
/// canonical under every mode on both architectures. The process-drawn
/// growth zones ([`growth_zones`]) are sized to the actual user half
/// instead (2^47 on x86-64 and Sv48, 2^56 on Sv57).
pub const LAYOUT_VA_CEILING: u64 = 1 << 38;

/// Default base (region start) of the main-thread TLS block (degraded
/// fallback). The defaults sit in the gap between init's stack-guard zone
/// and the image window, each region with its window's full tail.
pub const DEFAULT_MAIN_TLS_VA: u64 = 0x0000_002E_8000_0000;

/// Default base (region start) of the main-thread IPC buffer (degraded
/// fallback): one region tail above the TLS default.
pub const DEFAULT_IPC_BUFFER_VA: u64 = DEFAULT_MAIN_TLS_VA + MAX_WINDOW_REGION_PAGES * PAGE_SIZE;

/// Default `ProcessInfo` handover-page virtual address (degraded fallback).
pub const DEFAULT_PROCESS_INFO_VA: u64 = DEFAULT_IPC_BUFFER_VA + PAGE_SIZE;

/// Default top of the main-thread user stack (degraded fallback).
/// `stack_pages` pages are mapped immediately below this, with one unmapped
/// guard page beneath them. The top lies a full stack reservation
/// (`1 + MAX_PROCESS_STACK_PAGES` pages) above the page after the
/// `ProcessInfo` default, so no accepted stack reaches the other defaults.
pub const DEFAULT_STACK_TOP: u64 =
    DEFAULT_PROCESS_INFO_VA + PAGE_SIZE + (1 + MAX_PROCESS_STACK_PAGES as u64) * PAGE_SIZE;

/// A fixed randomisation window: `2^slots_log2` page-aligned candidate
/// addresses starting at `base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaWindow
{
    /// Lowest (and first) candidate address; page-aligned.
    pub base: u64,
    /// Log2 of the number of page-granular slots (= bits of entropy per
    /// draw). The windows' values are an ASLR budget, not a capacity: they
    /// are sized so every zone fits its tier, below [`LAYOUT_VA_CEILING`]
    /// for the fixed tier and inside the user half for a [`GrowthZone`],
    /// which the zone-map asserts check.
    pub slots_log2: u32,
}

impl VaWindow
{
    /// Pick the slot selected by raw entropy `r`.
    ///
    /// Masks `r` to the slot count and scales by the page size: page-aligned
    /// and uniform over the window for uniform `r` (no modulo bias).
    #[must_use]
    pub const fn pick(self, r: u64) -> u64
    {
        self.base + ((r & ((1 << self.slots_log2) - 1)) << 12)
    }

    /// Whether `va` is one of the window's `2^slots_log2` candidate slots'
    /// addresses (draw-span membership; used by tests and harness
    /// assertions).
    #[must_use]
    pub const fn contains(self, va: u64) -> bool
    {
        va >= self.base
            && va < self.base + self.span()
            && (va - self.base).is_multiple_of(PAGE_SIZE)
    }

    /// Size in bytes of the draw span (`2^slots_log2` pages).
    #[must_use]
    pub const fn span(self) -> u64
    {
        (1 << self.slots_log2) << 12
    }
}

/// Window for the main-thread TLS block base.
pub const MAIN_TLS_WINDOW: VaWindow = VaWindow {
    base: 0x0000_0021_0000_0000,
    slots_log2: 21,
};

/// Window for the main-thread IPC buffer.
pub const IPC_BUFFER_WINDOW: VaWindow = VaWindow {
    base: 0x0000_0023_4000_0000,
    slots_log2: 21,
};

/// Window for the `ProcessInfo` handover page.
pub const PROCESS_INFO_WINDOW: VaWindow = VaWindow {
    base: 0x0000_0025_8000_0000,
    slots_log2: 21,
};

/// Window for the main-thread stack **guard page**. The drawn address is the
/// unmapped guard; the stack top is
/// `draw + (1 + MAX_PROCESS_STACK_PAGES) * 4096`, so the maximum stack always
/// fits between the guard and the top with the guard page unmapped below the
/// stack base.
pub const STACK_GUARD_WINDOW: VaWindow = VaWindow {
    base: 0x0000_0027_C000_0000,
    slots_log2: 21,
};

/// Window for the `InitInfo` handover page (kernel-chosen, per boot).
pub const INIT_INFO_WINDOW: VaWindow = VaWindow {
    base: 0x0000_002A_0000_0000,
    slots_log2: 21,
};

/// Window for init's stack guard page (kernel-chosen, per boot). Same draw
/// semantics as [`STACK_GUARD_WINDOW`], with `INIT_STACK_PAGES` mapped pages.
pub const INIT_STACK_GUARD_WINDOW: VaWindow = VaWindow {
    base: 0x0000_002C_4000_0000,
    slots_log2: 21,
};

/// Window for the `ET_DYN` image load bias (creator-chosen, per process; kernel
/// for init). `ET_DYN` link-time VAs start near zero, so the bias is the image
/// base.
pub const IMAGE_WINDOW: VaWindow = VaWindow {
    base: 0x0000_0030_0000_0000,
    slots_log2: 23,
};

/// Exclusive end of the image zone in the fixed tier. The band above it, up
/// to [`LAYOUT_VA_CEILING`], holds the kernel's degraded-fallback addresses
/// for init (`mm::address_space`).
pub const FIXED_IMAGE_ZONE_END: u64 = 0x0000_003F_0000_0000;

/// Maximum biased image span (`max_vaddr_end - min_vaddr`) accepted by
/// [`validate_image_placement`]: the room between the image window's last
/// slot and [`FIXED_IMAGE_ZONE_END`] (28 GiB). The kernel (for init) and
/// init (for memmgr and procmgr) place images in the fixed tier; procmgr
/// validates its children's images against the image zone of its own
/// address space's size ([`validate_image_placement_below`]).
pub const IMAGE_MAX_SPAN: u64 = image_max_span(FIXED_IMAGE_ZONE_END);

/// Largest region, in pages, hanging off any window draw: the gap each
/// window's 9 GiB stride leaves after its 8 GiB draw span (1 GiB). It bounds
/// the main-thread stack reservation (`1 + MAX_PROCESS_STACK_PAGES`) and the
/// main-thread TLS block (`PROCESS_MAIN_TLS_MAX_PAGES`), which the asserts
/// below pin to it; both cost VA only, since a loader maps what the binary
/// declares.
pub const MAX_WINDOW_REGION_PAGES: u64 = 1 << 18;

const fn window_zone_end(w: VaWindow) -> u64
{
    w.base + w.span() + MAX_WINDOW_REGION_PAGES * PAGE_SIZE
}

/// Largest biased image span an image zone ending at `image_zone_end`
/// holds: the room between the image window's last slot and that end.
/// `image_zone_end` is at least the window's end (every
/// [`AddressSpaceZones::image_zone_end`] is).
#[must_use]
pub const fn image_max_span(image_zone_end: u64) -> u64
{
    image_zone_end.saturating_sub(IMAGE_WINDOW.base + IMAGE_WINDOW.span())
}

/// One process-drawn zone: a base drawn from `window`, and up to `span`
/// bytes above the drawn base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrowthZone
{
    /// Window the zone's base is drawn from.
    pub window: VaWindow,
    /// Bytes the zone extends above its drawn base.
    pub span: u64,
}

impl GrowthZone
{
    /// The zone's base for raw entropy `r`, or the window base (the
    /// degraded fallback) for `None`.
    #[must_use]
    pub const fn base(self, r: Option<u64>) -> u64
    {
        match r
        {
            Some(r) => self.window.pick(r),
            None => self.window.base,
        }
    }

    /// Exclusive upper bound of the zone over every possible draw.
    #[must_use]
    pub const fn end_bound(self) -> u64
    {
        self.window.base + self.window.span() + self.span
    }
}

/// The zones sized to one address space: the byte heap, the reservation
/// arena, and the end of the image zone procmgr validates its children's
/// images against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddressSpaceZones
{
    /// Byte-heap zone (`runtime/ruststd/src/sys/alloc/seraph.rs`).
    pub heap: GrowthZone,
    /// Page-reservation arena zone (`runtime/ruststd/src/sys/reserve/seraph.rs`).
    pub arena: GrowthZone,
    /// Exclusive end of the image zone above [`IMAGE_WINDOW`].
    pub image_zone_end: u64,
}

/// Zones of an Sv39-sized address space, and of any address space whose
/// size is unknown: both growth zones lie below the bootstrap windows, so
/// they are valid under every paging mode. The heap's base window is
/// `[1 GiB, 3 GiB)` (19 bits) with a 60 GiB span; the arena's is
/// `[64 GiB, 96 GiB)` (23 bits) with a 32 GiB span. The windows' slot counts
/// are an ASLR budget, sized so both zones fit below the bootstrap windows.
pub const SV39_ZONES: AddressSpaceZones = AddressSpaceZones {
    heap: GrowthZone {
        window: VaWindow {
            base: 0x0000_0000_4000_0000,
            slots_log2: 19,
        },
        span: 0x0000_000F_0000_0000,
    },
    arena: GrowthZone {
        window: VaWindow {
            base: 0x0000_0010_0000_0000,
            slots_log2: 23,
        },
        span: 0x0000_0008_0000_0000,
    },
    image_zone_end: FIXED_IMAGE_ZONE_END,
};

/// Smallest user half [`growth_zones`] scales its zones to; a
/// smaller one gets [`SV39_ZONES`]. At this size the scaled image zone
/// (`half / 8`) ends at the fixed tier's ceiling.
const SCALED_MIN_HALF: u64 = LAYOUT_VA_CEILING * 8;

/// Size the growth zones to an address space whose exclusive user top is
/// `user_va_top` (`SystemInfoType::UserVaTop`).
///
/// With `half` the largest power of two at most `user_va_top` plus one
/// page (the x86-64 top user page is unmappable), the image zone ends at
/// `half / 8`, where the heap's base window starts; the arena's starts at
/// `half / 2`; each window spans `half / 64`, and each zone extends
/// `half / 4` above its drawn base: 32 TiB each under a 2^47 half, so the
/// zones end below `25 * half / 64` and `49 * half / 64`. A half below
/// 2^41 gets [`SV39_ZONES`].
#[must_use]
pub const fn growth_zones(user_va_top: u64) -> AddressSpaceZones
{
    let Some(top) = user_va_top.checked_add(PAGE_SIZE)
    else
    {
        return SV39_ZONES;
    };
    let half = 1_u64 << top.ilog2();
    if half < SCALED_MIN_HALF
    {
        return SV39_ZONES;
    }
    // A window of `half / 64` bytes holds `half / 2^18` page slots.
    let slots_log2 = half.ilog2() - 18;
    AddressSpaceZones {
        heap: GrowthZone {
            window: VaWindow {
                base: half / 8,
                slots_log2,
            },
            span: half / 4,
        },
        arena: GrowthZone {
            window: VaWindow {
                base: half / 2,
                slots_log2,
            },
            span: half / 4,
        },
        image_zone_end: half / 8,
    }
}

// Zone-map invariants: every window's worst-case zone (draw span + region
// tail) ends before the next zone begins, and everything stays inside the
// fixed tier. Region ordering and stack-guard gaps then hold for all draws.
const _: () = {
    // Region tails fit the stride gap they hang into: the stack reservation
    // (`1 + MAX_PROCESS_STACK_PAGES`, guard page included) and the TLS block.
    assert!((MAX_PROCESS_STACK_PAGES as u64) < MAX_WINDOW_REGION_PAGES);
    assert!(process_abi::PROCESS_MAIN_TLS_MAX_PAGES <= MAX_WINDOW_REGION_PAGES);
    // Sv39 growth zones: heap below arena, arena below the bootstrap windows.
    assert!(SV39_ZONES.heap.end_bound() <= SV39_ZONES.arena.window.base);
    assert!(SV39_ZONES.arena.end_bound() <= MAIN_TLS_WINDOW.base);
    // Stride chain in address order; `tls < ipc < info < stack_top` for all
    // draws follows from it.
    assert!(window_zone_end(MAIN_TLS_WINDOW) <= IPC_BUFFER_WINDOW.base);
    assert!(window_zone_end(IPC_BUFFER_WINDOW) <= PROCESS_INFO_WINDOW.base);
    assert!(window_zone_end(PROCESS_INFO_WINDOW) <= STACK_GUARD_WINDOW.base);
    assert!(window_zone_end(STACK_GUARD_WINDOW) <= INIT_INFO_WINDOW.base);
    assert!(window_zone_end(INIT_INFO_WINDOW) <= INIT_STACK_GUARD_WINDOW.base);
    // Degraded-fallback defaults: between init's stack-guard zone and the
    // image window, each region with its window's full tail.
    assert!(window_zone_end(INIT_STACK_GUARD_WINDOW) <= DEFAULT_MAIN_TLS_VA);
    assert!(
        DEFAULT_MAIN_TLS_VA + process_abi::PROCESS_MAIN_TLS_MAX_PAGES * PAGE_SIZE
            <= DEFAULT_IPC_BUFFER_VA
    );
    assert!(DEFAULT_STACK_TOP <= IMAGE_WINDOW.base);
    // The fixed image zone stays below the kernel's init fallback band.
    assert!(IMAGE_WINDOW.base + IMAGE_WINDOW.span() + IMAGE_MAX_SPAN <= FIXED_IMAGE_ZONE_END);
    assert!(FIXED_IMAGE_ZONE_END < LAYOUT_VA_CEILING);
    // The scaled zones start at or above the fixed tier's ceiling.
    assert!(growth_zones(SCALED_MIN_HALF).image_zone_end >= LAYOUT_VA_CEILING);
};

/// The user tops of the supported paging modes: riscv64 Sv39, x86-64
/// four-level (its top user page is unmappable), Sv48, and Sv57.
const SUPPORTED_USER_TOPS: [u64; 4] = [1 << 38, (1 << 47) - PAGE_SIZE, 1 << 47, 1 << 56];

// Growth zones under every supported mode: the heap below the arena, the
// arena inside the address space, and both clear of the fixed tier (below
// the bootstrap windows under Sv39, above the image zone otherwise).
const _: () = {
    let mut i = 0;
    while i < SUPPORTED_USER_TOPS.len()
    {
        let top = SUPPORTED_USER_TOPS[i];
        let z = growth_zones(top);
        assert!(z.heap.end_bound() <= z.arena.window.base);
        assert!(z.arena.end_bound() <= top);
        assert!(z.image_zone_end >= IMAGE_WINDOW.base + IMAGE_WINDOW.span());
        if top <= LAYOUT_VA_CEILING
        {
            assert!(z.arena.end_bound() <= MAIN_TLS_WINDOW.base);
        }
        else
        {
            assert!(z.image_zone_end >= LAYOUT_VA_CEILING);
            assert!(z.image_zone_end <= z.heap.window.base);
        }
        i += 1;
    }
};

/// Number of entropy bytes [`choose_process_layout`] consumes: one
/// little-endian `u64` per drawn surface. The layout draws exactly four
/// surfaces, so the count is fixed by the layout, not by any workload.
pub const LAYOUT_ENTROPY_BYTES: usize = 32;

/// The bootstrap virtual addresses for one new process.
///
/// Page counts are not part of the layout: the stack size comes from the
/// binary's `.note.seraph.stack` ELF note and the TLS block size from its
/// `PT_TLS` segment, both resolved by the creator. This struct carries only the
/// base addresses the creator places those regions at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessLayout
{
    /// Virtual address of the read-only `ProcessInfo` handover page. Delivered
    /// to the new process in its entry register (`rdi`/`a0`), not stored in the
    /// struct (which would be circular — the process needs this to find it).
    pub process_info_va: u64,
    /// Top of the main-thread user stack; written to `ProcessInfo.stack_top_vaddr`
    /// and passed as the initial stack pointer.
    pub stack_top: u64,
    /// Base of the main-thread TLS block; written to `ProcessInfo.main_tls_vaddr`
    /// (when the process has a `PT_TLS` segment) and used to derive the thread
    /// pointer.
    pub tls_base: u64,
    /// Base of the main-thread IPC buffer; written to `ProcessInfo.ipc_buffer_vaddr`.
    pub ipc_buffer_va: u64,
}

fn entropy_word(entropy: &[u8; LAYOUT_ENTROPY_BYTES], index: usize) -> u64
{
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&entropy[index * 8..index * 8 + 8]);
    u64::from_le_bytes(bytes)
}

/// Choose the bootstrap VA layout for a new process.
///
/// With `Some(entropy)`, each surface is drawn independently from its window
/// (byte mapping: LE `u64`s at `[0..8]` → `ProcessInfo`, `[8..16]` → stack
/// guard, `[16..24]` → TLS, `[24..32]` → IPC buffer). With `None` (the
/// creator's entropy draw failed), the deterministic `DEFAULT_*` addresses
/// are returned instead.
#[must_use]
pub fn choose_process_layout(entropy: Option<&[u8; LAYOUT_ENTROPY_BYTES]>) -> ProcessLayout
{
    let Some(entropy) = entropy
    else
    {
        return ProcessLayout {
            process_info_va: DEFAULT_PROCESS_INFO_VA,
            stack_top: DEFAULT_STACK_TOP,
            tls_base: DEFAULT_MAIN_TLS_VA,
            ipc_buffer_va: DEFAULT_IPC_BUFFER_VA,
        };
    };
    ProcessLayout {
        process_info_va: PROCESS_INFO_WINDOW.pick(entropy_word(entropy, 0)),
        stack_top: STACK_GUARD_WINDOW.pick(entropy_word(entropy, 1))
            + (1 + u64::from(MAX_PROCESS_STACK_PAGES)) * PAGE_SIZE,
        tls_base: MAIN_TLS_WINDOW.pick(entropy_word(entropy, 2)),
        ipc_buffer_va: IPC_BUFFER_WINDOW.pick(entropy_word(entropy, 3)),
    }
}

/// Pick an `ET_DYN` image load bias from [`IMAGE_WINDOW`].
#[must_use]
pub const fn choose_image_bias(r: u64) -> u64
{
    IMAGE_WINDOW.pick(r)
}

/// Whether an `ET_DYN` image with link-time load span
/// `[min_vaddr, max_vaddr_end)` may be placed at `bias` in the fixed tier:
/// [`validate_image_placement_below`] with [`FIXED_IMAGE_ZONE_END`]. The
/// kernel (for init) and init (for memmgr and procmgr) validate this way.
#[must_use]
pub fn validate_image_placement(bias: u64, min_vaddr: u64, max_vaddr_end: u64) -> bool
{
    validate_image_placement_below(bias, min_vaddr, max_vaddr_end, FIXED_IMAGE_ZONE_END)
}

/// Whether an `ET_DYN` image with link-time load span
/// `[min_vaddr, max_vaddr_end)` may be placed at `bias` in an image zone
/// ending at `image_zone_end` (an [`AddressSpaceZones::image_zone_end`]).
///
/// Requires the bias to be a window slot, the span to be non-empty and at
/// most [`image_max_span`] of the zone, and the biased image to end at or
/// below `image_zone_end` (all arithmetic checked).
#[must_use]
pub fn validate_image_placement_below(
    bias: u64,
    min_vaddr: u64,
    max_vaddr_end: u64,
    image_zone_end: u64,
) -> bool
{
    if !IMAGE_WINDOW.contains(bias) || max_vaddr_end <= min_vaddr
    {
        return false;
    }
    if max_vaddr_end - min_vaddr > image_max_span(image_zone_end)
    {
        return false;
    }
    match bias.checked_add(max_vaddr_end)
    {
        Some(end) => end <= image_zone_end,
        None => false,
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const PATTERNS: [[u8; LAYOUT_ENTROPY_BYTES]; 4] = [
        [0x00; LAYOUT_ENTROPY_BYTES],
        [0xFF; LAYOUT_ENTROPY_BYTES],
        [0xA5; LAYOUT_ENTROPY_BYTES],
        [0x5A; LAYOUT_ENTROPY_BYTES],
    ];

    fn regions(layout: &ProcessLayout) -> [(u64, u64); 4]
    {
        let stack_reserve = (1 + u64::from(MAX_PROCESS_STACK_PAGES)) * PAGE_SIZE;
        [
            (
                layout.tls_base,
                process_abi::PROCESS_MAIN_TLS_MAX_PAGES * PAGE_SIZE,
            ),
            (layout.ipc_buffer_va, PAGE_SIZE),
            (layout.process_info_va, PAGE_SIZE),
            // Includes the guard page below the stack base.
            (layout.stack_top - stack_reserve, stack_reserve),
        ]
    }

    fn assert_ordered_and_disjoint(layout: &ProcessLayout)
    {
        assert!(layout.tls_base < layout.ipc_buffer_va);
        assert!(layout.ipc_buffer_va < layout.process_info_va);
        assert!(layout.process_info_va < layout.stack_top);
        let regions = regions(layout);
        for (i, &(base_a, len_a)) in regions.iter().enumerate()
        {
            for &(base_b, len_b) in &regions[i + 1..]
            {
                assert!(
                    base_a + len_a <= base_b || base_b + len_b <= base_a,
                    "regions [{base_a:#x},+{len_a:#x}) and [{base_b:#x},+{len_b:#x}) overlap"
                );
            }
        }
    }

    // Defect guarded: a degraded-fallback layout whose largest accepted stack
    // or TLS block overlaps another default surface, or whose regions run
    // into the image window.
    #[test]
    fn fallback_regions_hold_their_largest_tails_disjointly()
    {
        let layout = choose_process_layout(None);
        assert_eq!(layout.stack_top, DEFAULT_STACK_TOP);
        assert_ordered_and_disjoint(&layout);
        for (base, len) in regions(&layout)
        {
            assert_eq!(base % PAGE_SIZE, 0, "{base:#x} unaligned");
            assert!(base + len <= IMAGE_WINDOW.base);
        }
    }

    #[test]
    fn draws_are_aligned_in_window_ordered_and_disjoint()
    {
        for pattern in &PATTERNS
        {
            let layout = choose_process_layout(Some(pattern));

            for (base, _) in regions(&layout)
            {
                assert_eq!(base % PAGE_SIZE, 0, "{base:#x} unaligned");
            }
            assert!(PROCESS_INFO_WINDOW.contains(layout.process_info_va));
            assert!(MAIN_TLS_WINDOW.contains(layout.tls_base));
            assert!(IPC_BUFFER_WINDOW.contains(layout.ipc_buffer_va));
            let stack_reserve = (1 + u64::from(MAX_PROCESS_STACK_PAGES)) * PAGE_SIZE;
            assert!(STACK_GUARD_WINDOW.contains(layout.stack_top - stack_reserve));

            assert!(layout.stack_top < LAYOUT_VA_CEILING);
            assert_ordered_and_disjoint(&layout);
        }
    }

    #[test]
    fn max_draw_tail_stays_inside_stride()
    {
        let max = [0xFF_u8; LAYOUT_ENTROPY_BYTES];
        let layout = choose_process_layout(Some(&max));
        assert!(layout.stack_top <= STACK_GUARD_WINDOW.base + 0x0002_4000_0000);
        assert!(
            layout.tls_base + process_abi::PROCESS_MAIN_TLS_MAX_PAGES * PAGE_SIZE
                <= IPC_BUFFER_WINDOW.base
        );
    }

    #[test]
    fn deterministic_for_equal_entropy()
    {
        let pattern = PATTERNS[2];
        assert_eq!(
            choose_process_layout(Some(&pattern)),
            choose_process_layout(Some(&pattern))
        );
    }

    #[test]
    fn image_bias_is_aligned_and_in_window()
    {
        for r in [0_u64, 1, u64::MAX, 0xDEAD_BEEF_DEAD_BEEF]
        {
            let bias = choose_image_bias(r);
            assert!(IMAGE_WINDOW.contains(bias));
            assert_eq!(bias % PAGE_SIZE, 0);
        }
    }

    #[test]
    fn fixed_tier_image_placement_validation()
    {
        let bias = IMAGE_WINDOW.base;
        assert!(validate_image_placement(bias, 0, IMAGE_MAX_SPAN));
        assert!(!validate_image_placement(bias, 0, IMAGE_MAX_SPAN + 1));
        assert!(!validate_image_placement(bias, 0x1000, 0x1000)); // empty span
        assert!(!validate_image_placement(bias + 1, 0, 0x1000)); // unaligned bias
        assert!(!validate_image_placement(0, 0, 0x1000)); // outside window
        assert!(!validate_image_placement(bias, 0, u64::MAX)); // overflow / span
        // The last slot with a full span ends one page below the zone end; a
        // span that starts above zero cannot push the biased end past it.
        let last = IMAGE_WINDOW.base + IMAGE_WINDOW.span() - PAGE_SIZE;
        assert!(validate_image_placement(last, 0, IMAGE_MAX_SPAN));
        assert!(!validate_image_placement(
            last,
            0x2000,
            IMAGE_MAX_SPAN + 0x2000
        ));
    }

    // Defect guarded: an image span bound that does not follow the address
    // space's size, so a wide user half still refuses an image the fixed
    // tier could not hold.
    #[test]
    fn wide_image_zone_accepts_spans_past_the_fixed_tier()
    {
        let zones = growth_zones((1 << 47) - PAGE_SIZE);
        let span = IMAGE_MAX_SPAN + 0x1000;
        assert!(!validate_image_placement(IMAGE_WINDOW.base, 0, span));
        assert!(validate_image_placement_below(
            IMAGE_WINDOW.base,
            0,
            span,
            zones.image_zone_end
        ));
        assert!(!validate_image_placement_below(
            IMAGE_WINDOW.base,
            0,
            image_max_span(zones.image_zone_end) + 0x1000,
            zones.image_zone_end
        ));
    }

    // Defect guarded: growth zones that overlap each other, the image zone,
    // or the bootstrap windows, or that run past the address space's top.
    #[test]
    fn growth_zones_are_disjoint_and_inside_the_address_space()
    {
        for top in SUPPORTED_USER_TOPS
        {
            let z = growth_zones(top);
            assert!(z.heap.end_bound() <= z.arena.window.base, "{top:#x}");
            assert!(z.arena.end_bound() <= top, "{top:#x}");
            assert!(z.image_zone_end >= IMAGE_WINDOW.base + IMAGE_WINDOW.span());
            if z == SV39_ZONES
            {
                assert!(z.arena.end_bound() <= MAIN_TLS_WINDOW.base);
            }
            else
            {
                // Scaled zones lie above every fixed-tier surface.
                assert!(z.image_zone_end >= LAYOUT_VA_CEILING, "{top:#x}");
                assert!(z.image_zone_end <= z.heap.window.base, "{top:#x}");
            }
            for zone in [z.heap, z.arena]
            {
                for r in [Some(0), Some(u64::MAX), None]
                {
                    let base = zone.base(r);
                    assert_eq!(base % PAGE_SIZE, 0);
                    assert!(base + zone.span <= zone.end_bound());
                }
            }
        }
    }

    // Defect guarded: zones that stay at the Sv39 size on a wider address
    // space, which is what capped every process's heap and arena before.
    #[test]
    fn growth_zones_scale_with_the_user_half()
    {
        let sv39 = growth_zones(1 << 38);
        let four_level = growth_zones((1 << 47) - 4096);
        let five_level = growth_zones(1 << 56);
        assert_eq!(sv39, SV39_ZONES);
        assert_eq!(four_level, growth_zones(1 << 47));
        assert_eq!(four_level.heap.span, 1 << 45);
        assert_eq!(four_level.arena.span, 1 << 45);
        assert_eq!(five_level.heap.span, 1 << 54);
        // A top that is no supported mode's, or that overflows, degrades to
        // the zones valid in every mode.
        assert_eq!(growth_zones(0), SV39_ZONES);
        assert_eq!(growth_zones(u64::MAX), SV39_ZONES);
    }
}
