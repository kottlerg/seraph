// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/x86_paging.rs

//! x86-64 paging-depth geometry shared by the bootloader and kernel.
//!
//! The bootloader enables 5-level paging (`CR4.LA57`) when CPUID reports LA57
//! and hands the kernel a running translation regime; the kernel recovers the
//! depth from `CR4.LA57` at entry. Both sides derive level counts, the
//! canonical halves, and table indices from this one definition so the
//! handshake cannot skew.
//!
//! The LA57 enumeration bit (`CPUID.(EAX=07H,ECX=0):ECX[16]`), the `CR4.LA57`
//! control bit (bit 12), and the 4- and 5-level linear-address translation are
//! defined by the Intel SDM Vol. 3A § 4.5 ("4-Level Paging and 5-Level
//! Paging"). Every level indexes 512 eight-byte entries with 9 VA bits; the
//! depths differ only in level count.

/// `CPUID.(EAX=07H,ECX=0):ECX` bit that enumerates 5-level paging (LA57).
pub const CPUID_7_ECX_LA57: u32 = 1 << 16;

/// `CR4` bit that selects 5-level paging. Writable only outside IA-32e mode
/// (`IA32_EFER.LMA = 0`).
pub const CR4_LA57: u64 = 1 << 12;

/// An x86-64 paging depth supported by this kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PagingDepth
{
    /// Four translation levels (PML4 root), 48-bit VAs. The platform minimum.
    Four = 4,
    /// Five translation levels (PML5 root), 57-bit VAs. Enabled when the CPU
    /// reports LA57.
    Five = 5,
}

impl PagingDepth
{
    /// The depth the bootloader negotiates from `CPUID.(EAX=07H,ECX=0):ECX`.
    #[must_use]
    pub const fn from_cpuid_7_ecx(ecx: u32) -> Self
    {
        if ecx & CPUID_7_ECX_LA57 != 0
        {
            Self::Five
        }
        else
        {
            Self::Four
        }
    }

    /// The depth a running translation regime uses, read from `CR4`.
    #[must_use]
    pub const fn from_cr4(cr4: u64) -> Self
    {
        if cr4 & CR4_LA57 != 0
        {
            Self::Five
        }
        else
        {
            Self::Four
        }
    }

    /// Decode a depth from its level count. Returns `None` for any count
    /// other than 4 or 5.
    #[must_use]
    pub const fn from_levels(levels: u8) -> Option<Self>
    {
        match levels
        {
            4 => Some(Self::Four),
            5 => Some(Self::Five),
            _ => None,
        }
    }

    /// Number of translation levels (page-table tiers) the depth walks.
    #[must_use]
    pub const fn levels(self) -> usize
    {
        self as usize
    }

    /// Whether this depth sets `CR4.LA57`.
    #[must_use]
    pub const fn la57(self) -> bool
    {
        matches!(self, Self::Five)
    }

    /// Virtual-address width in bits. Addresses must be sign-extended from
    /// bit `va_bits - 1` to be canonical.
    #[must_use]
    pub const fn va_bits(self) -> u32
    {
        match self
        {
            Self::Four => 48,
            Self::Five => 57,
        }
    }

    /// Lowest address of the upper (kernel) canonical half.
    ///
    /// Equal to `!0 << (va_bits - 1)`, and at either depth the base of root
    /// entry 256: the canonical halves split a 512-entry root in half
    /// regardless of level count, so kernel-half sharing that copies root
    /// entries `256..512` between address spaces is depth-invariant.
    #[must_use]
    pub const fn kernel_va_base(self) -> u64
    {
        match self
        {
            Self::Four => 0xFFFF_8000_0000_0000,
            Self::Five => 0xFF00_0000_0000_0000,
        }
    }

    /// Exclusive upper bound of the lower canonical half: `1 << (va_bits - 1)`.
    /// A user RIP or RSP at or above it is non-canonical.
    #[must_use]
    pub const fn canonical_user_limit(self) -> u64
    {
        1 << (self.va_bits() - 1)
    }

    /// Exclusive upper bound of user-mappable virtual addresses: the lower
    /// canonical half less its top 4 KiB page, which stays unmappable so no
    /// user instruction can end at the canonical boundary.
    #[must_use]
    pub const fn user_va_top(self) -> u64
    {
        self.canonical_user_limit() - 4096
    }
}

/// Page-table index of `va` at translation level `level`.
///
/// Level 0 is the leaf (4 KiB) tier; the root of a depth sits at
/// `levels() - 1` (level 3 is the PML4, level 4 the PML5). Every tier
/// consumes 9 VA bits above the 12-bit page offset.
#[must_use]
pub const fn table_index(level: usize, va: u64) -> usize
{
    ((va >> (12 + 9 * level)) & 0x1FF) as usize
}

/// Bytes of VA covered by one entry at translation level `level`
/// (4 KiB at level 0, 2 MiB at level 1, 1 GiB at level 2, ...).
#[must_use]
pub const fn level_stride(level: usize) -> u64
{
    1 << (12 + 9 * level)
}

/// First VA above `va` whose `table_index(level, ..)` differs: the start of
/// the next entry's span at `level`.
#[must_use]
pub const fn next_level_boundary(level: usize, va: u64) -> u64
{
    let shift = 12 + 9 * level;
    ((va >> shift) + 1) << shift
}

#[cfg(test)]
mod tests
{
    use super::*;

    const ALL: [PagingDepth; 2] = [PagingDepth::Four, PagingDepth::Five];

    #[test]
    fn depth_follows_the_la57_bit_in_cpuid_and_cr4()
    {
        assert_eq!(PagingDepth::from_cpuid_7_ecx(0), PagingDepth::Four);
        assert_eq!(
            PagingDepth::from_cpuid_7_ecx(!CPUID_7_ECX_LA57),
            PagingDepth::Four
        );
        assert_eq!(
            PagingDepth::from_cpuid_7_ecx(CPUID_7_ECX_LA57),
            PagingDepth::Five
        );
        // A CR4 with PAE, PGE and PCIDE set but not LA57 is 4-level.
        assert_eq!(PagingDepth::from_cr4(0x0002_00A0), PagingDepth::Four);
        assert_eq!(
            PagingDepth::from_cr4(0x0002_00A0 | CR4_LA57),
            PagingDepth::Five
        );
        for depth in ALL
        {
            let cr4 = if depth.la57() { CR4_LA57 } else { 0 };
            assert_eq!(PagingDepth::from_cr4(cr4), depth);
        }
    }

    #[test]
    fn level_count_roundtrips_and_rejects_other_counts()
    {
        for depth in ALL
        {
            let levels = u8::try_from(depth.levels()).unwrap();
            assert_eq!(PagingDepth::from_levels(levels), Some(depth));
        }
        for levels in [0u8, 3, 6]
        {
            assert_eq!(PagingDepth::from_levels(levels), None);
        }
    }

    #[test]
    fn kernel_va_base_is_the_sign_extended_half()
    {
        for depth in ALL
        {
            assert_eq!(depth.kernel_va_base(), !0u64 << (depth.va_bits() - 1));
            assert_eq!(depth.canonical_user_limit(), !depth.kernel_va_base() + 1);
        }
    }

    #[test]
    fn canonical_split_is_root_entry_256_at_either_depth()
    {
        for depth in ALL
        {
            let root = depth.levels() - 1;
            assert_eq!(table_index(root, depth.kernel_va_base()), 256);
            assert_eq!(table_index(root, depth.canonical_user_limit()), 256);
            assert_eq!(table_index(root, depth.canonical_user_limit() - 1), 255);
        }
    }

    #[test]
    fn user_va_top_keeps_the_top_page_of_the_lower_half_unmappable()
    {
        assert_eq!(PagingDepth::Four.user_va_top(), 0x0000_7FFF_FFFF_F000);
        assert_eq!(PagingDepth::Five.user_va_top(), 0x00FF_FFFF_FFFF_F000);
        for depth in ALL
        {
            let top = depth.user_va_top();
            // The last mappable page and the excluded page share the root
            // entry below the split.
            assert_eq!(table_index(depth.levels() - 1, top), 255);
            assert_eq!(depth.canonical_user_limit() - top, 4096);
        }
    }

    #[test]
    fn kernel_image_base_is_in_the_last_root_entry()
    {
        // The kernel links at the top-2-GiB VA, canonical at either depth.
        let image_base = crate::layout::KERNEL_LINK_BASE;
        for depth in ALL
        {
            assert_eq!(table_index(depth.levels() - 1, image_base), 511);
        }
    }

    #[test]
    fn table_index_reads_nine_bits_per_level()
    {
        // 0x0123_4567_89AB_C000 split into 9-bit fields above the page offset,
        // from the PT (level 0) up to the PML5 (level 4).
        let va = 0x0123_4567_89AB_C000u64;
        let expected = [0x0BC, 0x04D, 0x19E, 0x08A, 0x123];
        for (level, index) in expected.into_iter().enumerate()
        {
            assert_eq!(table_index(level, va), index, "level {level}");
        }
        // Level 4 (the PML5) reads bits 56:48.
        assert_eq!(table_index(4, 0x0100_0000_0000_0000), 256);
        assert_eq!(table_index(4, 0x0001_0000_0000_0000), 1);
    }

    #[test]
    fn next_level_boundary_starts_the_next_entry()
    {
        for level in 0..5
        {
            let va = 0x1234_5678_9000u64;
            let next = next_level_boundary(level, va);
            assert_eq!(next % level_stride(level), 0);
            assert!(next > va);
            assert!(next - va <= level_stride(level));
            assert_ne!(table_index(level, va), table_index(level, next));
        }
    }
}
