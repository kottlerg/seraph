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
//! Every surface is drawn independently inside a fixed, per-region
//! [`VaWindow`]: a power-of-two count of page-aligned slots starting at a
//! constant base. A draw is `base + ((r & (2^slots_log2 - 1)) << 12)` —
//! page-aligned and free of modulo bias by construction. The windows sit on
//! 64 GiB strides inside the top PML4/Sv48-root slot, so pairwise
//! disjointness, the `tls < ipc < info < stack_top` ordering, and the
//! unmapped guard page below every stack hold for **all** possible draws; no
//! rejection or collision checking is needed (const-asserted below).
//!
//! The per-process VA zone map (creator-chosen and process-private zones):
//!
//! | Zone | Base | Entropy bits | Chooser |
//! |---|---|---|---|
//! | `ET_EXEC` image (bias 0) | ~`0x20_0000` | — | linker |
//! | Byte heap | `0x4000_0000` | 19 | `std::sys` (`alloc/seraph.rs`) |
//! | Reservation arena | `0x10_0000_0000` | 24 | `std::sys` (`reserve/seraph.rs`) |
//! | PIE image bias | `0x30_0000_0000` | 23 | creator ([`IMAGE_WINDOW`]) |
//! | Main TLS | `0x7F80_0000_0000` | 23 | creator ([`MAIN_TLS_WINDOW`]) |
//! | IPC buffer | `0x7F90_0000_0000` | 23 | creator ([`IPC_BUFFER_WINDOW`]) |
//! | `ProcessInfo` | `0x7FA0_0000_0000` | 23 | creator ([`PROCESS_INFO_WINDOW`]) |
//! | Stack guard | `0x7FB0_0000_0000` | 23 | creator ([`STACK_GUARD_WINDOW`]) |
//! | `InitInfo` | `0x7FC0_0000_0000` | 23 | kernel ([`INIT_INFO_WINDOW`]) |
//! | Init stack guard | `0x7FD0_0000_0000` | 23 | kernel ([`INIT_STACK_GUARD_WINDOW`]) |
//!
//! The heap and reservation-arena bases are drawn by the process itself in
//! `runtime/ruststd/src/sys/{alloc,reserve}/seraph.rs`; their zone bounds are
//! mirrored here as constants so the image window can be const-asserted
//! disjoint from them.
//!
//! When the creator has no entropy (a draw failed), it passes `None` and the
//! layout degrades to the deterministic `DEFAULT_*` addresses. The defaults
//! lie outside the windows above; harness window assertions fail loudly on a
//! degraded boot by design.

#![no_std]

use process_abi::MAX_PROCESS_STACK_PAGES;

/// Page size shared by every layout computation in this crate.
const PAGE_SIZE: u64 = 4096;

/// Exclusive top of the canonical user half on both supported architectures
/// (x86-64 4-level paging and riscv64 Sv48 both give userspace a 47-bit low
/// half).
pub const USER_HALF_TOP: u64 = 0x0000_8000_0000_0000;

/// Default `ProcessInfo` handover-page virtual address (degraded fallback).
pub const DEFAULT_PROCESS_INFO_VA: u64 = 0x0000_7FFF_FFFF_0000;

/// Default top of the main-thread user stack (degraded fallback).
/// `stack_pages` pages are mapped immediately below this, with one unmapped
/// guard page beneath them.
pub const DEFAULT_STACK_TOP: u64 = 0x0000_7FFF_FFFF_E000;

/// Default base (region start) of the main-thread IPC buffer (degraded
/// fallback).
pub const DEFAULT_IPC_BUFFER_VA: u64 = 0x0000_7FFF_FFFE_0000;

/// Default base (region start) of the main-thread TLS block (degraded
/// fallback).
pub const DEFAULT_MAIN_TLS_VA: u64 = 0x0000_7FFF_FFFD_0000;

/// A fixed randomisation window: `2^slots_log2` page-aligned candidate
/// addresses starting at `base`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaWindow
{
    /// Lowest (and first) candidate address; page-aligned.
    pub base: u64,
    /// Log2 of the number of page-granular slots (= bits of entropy per
    /// draw).
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
    base: 0x0000_7F80_0000_0000,
    slots_log2: 23,
};

/// Window for the main-thread IPC buffer.
pub const IPC_BUFFER_WINDOW: VaWindow = VaWindow {
    base: 0x0000_7F90_0000_0000,
    slots_log2: 23,
};

/// Window for the `ProcessInfo` handover page.
pub const PROCESS_INFO_WINDOW: VaWindow = VaWindow {
    base: 0x0000_7FA0_0000_0000,
    slots_log2: 23,
};

/// Window for the main-thread stack **guard page**. The drawn address is the
/// unmapped guard; the stack top is
/// `draw + (1 + MAX_PROCESS_STACK_PAGES) * 4096`, so the maximum stack always
/// fits between the guard and the top with the guard page unmapped below the
/// stack base.
pub const STACK_GUARD_WINDOW: VaWindow = VaWindow {
    base: 0x0000_7FB0_0000_0000,
    slots_log2: 23,
};

/// Window for the `InitInfo` handover page (kernel-chosen, per boot).
pub const INIT_INFO_WINDOW: VaWindow = VaWindow {
    base: 0x0000_7FC0_0000_0000,
    slots_log2: 23,
};

/// Window for init's stack guard page (kernel-chosen, per boot). Same draw
/// semantics as [`STACK_GUARD_WINDOW`], with `INIT_STACK_PAGES` mapped pages.
pub const INIT_STACK_GUARD_WINDOW: VaWindow = VaWindow {
    base: 0x0000_7FD0_0000_0000,
    slots_log2: 23,
};

/// Window for the `ET_DYN` image load bias (creator-chosen, per process; kernel
/// for init). `ET_DYN` link-time VAs start near zero, so the bias is the image
/// base.
pub const IMAGE_WINDOW: VaWindow = VaWindow {
    base: 0x0000_0030_0000_0000,
    slots_log2: 23,
};

/// Maximum biased image span (`max_vaddr_end - min_vaddr`) accepted by
/// [`validate_image_placement`].
pub const IMAGE_MAX_SPAN: u64 = 0x4000_0000;

/// Upper bound of the byte-heap zone; mirrors `HEAP` in
/// `runtime/ruststd/src/sys/alloc/seraph.rs` (base window `[1 GiB, 3 GiB)` +
/// 1 GiB span).
const HEAP_ZONE_END: u64 = 0x0000_0001_0000_0000;

/// Upper bound of the reservation-arena zone; mirrors `RESERVE_ARENA` in
/// `runtime/ruststd/src/sys/reserve/seraph.rs` (base window
/// `[64 GiB, 128 GiB)` + 256 MiB arena).
const RESERVE_ARENA_ZONE_END: u64 = 0x0000_0020_1000_0000;

/// Conservative worst-case region tail hanging off any window draw, in pages.
/// The largest real region is the stack reservation
/// (`1 + MAX_PROCESS_STACK_PAGES` = 257 pages); 512 bounds them all.
const MAX_WINDOW_REGION_PAGES: u64 = 512;

const fn window_zone_end(w: VaWindow) -> u64
{
    w.base + w.span() + MAX_WINDOW_REGION_PAGES * PAGE_SIZE
}

// Zone-map invariants: every window's worst-case zone (draw span + region
// tail) ends before the next zone begins, and everything stays inside the
// user half. Region ordering and stack-guard gaps then hold for all draws.
const _: () = {
    assert!(HEAP_ZONE_END <= 0x0000_0010_0000_0000); // heap below arena zone
    assert!(RESERVE_ARENA_ZONE_END <= IMAGE_WINDOW.base);
    assert!(window_zone_end(IMAGE_WINDOW) + IMAGE_MAX_SPAN <= MAIN_TLS_WINDOW.base);
    // Stride chain in address order; `tls < ipc < info < stack_top` for all
    // draws follows from it.
    assert!(window_zone_end(MAIN_TLS_WINDOW) <= IPC_BUFFER_WINDOW.base);
    assert!(window_zone_end(IPC_BUFFER_WINDOW) <= PROCESS_INFO_WINDOW.base);
    assert!(window_zone_end(PROCESS_INFO_WINDOW) <= STACK_GUARD_WINDOW.base);
    assert!(window_zone_end(STACK_GUARD_WINDOW) <= INIT_INFO_WINDOW.base);
    assert!(window_zone_end(INIT_INFO_WINDOW) <= INIT_STACK_GUARD_WINDOW.base);
    assert!(window_zone_end(INIT_STACK_GUARD_WINDOW) <= USER_HALF_TOP);
};

/// Number of entropy bytes [`choose_process_layout`] consumes: one
/// little-endian `u64` per drawn surface.
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
/// `[min_vaddr, max_vaddr_end)` may be placed at `bias`.
///
/// Requires the bias to be a window slot, the span to be non-empty and at
/// most [`IMAGE_MAX_SPAN`], and the biased image to stay below the user half
/// (all arithmetic checked).
#[must_use]
pub fn validate_image_placement(bias: u64, min_vaddr: u64, max_vaddr_end: u64) -> bool
{
    if !IMAGE_WINDOW.contains(bias) || max_vaddr_end <= min_vaddr
    {
        return false;
    }
    if max_vaddr_end - min_vaddr > IMAGE_MAX_SPAN
    {
        return false;
    }
    match bias.checked_add(max_vaddr_end)
    {
        Some(end) => end < USER_HALF_TOP,
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

    #[test]
    fn fallback_returns_defaults()
    {
        let layout = choose_process_layout(None);
        assert_eq!(layout.process_info_va, DEFAULT_PROCESS_INFO_VA);
        assert_eq!(layout.stack_top, DEFAULT_STACK_TOP);
        assert_eq!(layout.tls_base, DEFAULT_MAIN_TLS_VA);
        assert_eq!(layout.ipc_buffer_va, DEFAULT_IPC_BUFFER_VA);
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

            assert!(layout.tls_base < layout.ipc_buffer_va);
            assert!(layout.ipc_buffer_va < layout.process_info_va);
            assert!(layout.process_info_va < layout.stack_top);
            assert!(layout.stack_top < USER_HALF_TOP);

            let regions = regions(&layout);
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
    }

    #[test]
    fn max_draw_tail_stays_inside_stride()
    {
        let max = [0xFF_u8; LAYOUT_ENTROPY_BYTES];
        let layout = choose_process_layout(Some(&max));
        assert!(layout.stack_top <= STACK_GUARD_WINDOW.base + 0x0010_0000_0000);
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
    fn image_placement_validation()
    {
        let bias = IMAGE_WINDOW.base;
        assert!(validate_image_placement(bias, 0, IMAGE_MAX_SPAN));
        assert!(!validate_image_placement(bias, 0, IMAGE_MAX_SPAN + 1));
        assert!(!validate_image_placement(bias, 0x1000, 0x1000)); // empty span
        assert!(!validate_image_placement(bias + 1, 0, 0x1000)); // unaligned bias
        assert!(!validate_image_placement(0, 0, 0x1000)); // outside window
        assert!(!validate_image_placement(bias, 0, u64::MAX)); // overflow / span
    }
}
