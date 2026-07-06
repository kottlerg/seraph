// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/boot-protocol/src/riscv_paging.rs

//! RISC-V paging-mode constants shared by the bootloader and kernel.
//!
//! The bootloader negotiates a paging mode at boot (DTB `mmu-type` plus a
//! `satp` write-probe) and hands the kernel a running translation regime; the
//! kernel recovers the mode from the `satp` CSR at entry. Both sides derive
//! level counts, VA splits, and `satp` encodings from this one definition so
//! the handshake cannot skew.
//!
//! `satp` encoding and the MODE field values are defined by the RISC-V
//! Privileged Architecture (§ "Supervisor Address Translation and Protection
//! Register"): MODE occupies bits [63:60], ASID bits [59:44], and the root
//! page-table PPN bits [43:0]. Every translation level indexes 512 eight-byte
//! entries with 9 VA bits; the modes differ only in level count.

/// A RISC-V address-translation mode supported by this kernel.
///
/// Discriminants are the architectural `satp.MODE` field values, so
/// `mode as u64` is directly usable in `satp` construction. `Bare` (0) and
/// the RV32-only `Sv32` are deliberately unrepresentable: the kernel never
/// runs with translation off, and this port is RV64-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PagingMode
{
    /// Three translation levels, 39-bit VAs. The RVA23 mandatory minimum.
    Sv39 = 8,
    /// Four translation levels, 48-bit VAs. The standing default.
    Sv48 = 9,
    /// Five translation levels, 57-bit VAs.
    Sv57 = 10,
}

impl PagingMode
{
    /// Decode a mode from the `satp.MODE` field value (bits [63:60] shifted
    /// down). Returns `None` for Bare, Sv32, and reserved encodings.
    #[must_use]
    pub const fn from_satp_mode(bits: u64) -> Option<Self>
    {
        match bits
        {
            8 => Some(Self::Sv39),
            9 => Some(Self::Sv48),
            10 => Some(Self::Sv57),
            _ => None,
        }
    }

    /// Number of translation levels (page-table tiers) the mode walks.
    #[must_use]
    pub const fn levels(self) -> usize
    {
        match self
        {
            Self::Sv39 => 3,
            Self::Sv48 => 4,
            Self::Sv57 => 5,
        }
    }

    /// Virtual-address width in bits. Addresses must be sign-extended from
    /// bit `va_bits - 1` to be canonical.
    #[must_use]
    pub const fn va_bits(self) -> u32
    {
        match self
        {
            Self::Sv39 => 39,
            Self::Sv48 => 48,
            Self::Sv57 => 57,
        }
    }

    /// Lowest address of the upper (kernel) canonical half.
    ///
    /// Equal to `!0 << (va_bits - 1)` — and, in every mode, the base of root
    /// page-table entry 256: the canonical halves split a 512-entry root in
    /// half regardless of level count. Kernel-half sharing that copies root
    /// entries `256..512` between address spaces is therefore mode-invariant.
    #[must_use]
    pub const fn kernel_va_base(self) -> u64
    {
        match self
        {
            Self::Sv39 => 0xFFFF_FFC0_0000_0000,
            Self::Sv48 => 0xFFFF_8000_0000_0000,
            Self::Sv57 => 0xFF00_0000_0000_0000,
        }
    }

    /// Exclusive upper bound of the lower (user) canonical half:
    /// `1 << (va_bits - 1)`.
    #[must_use]
    pub const fn user_va_top(self) -> u64
    {
        1 << (self.va_bits() - 1)
    }

    /// Construct a `satp` value activating `root_pa` under this mode.
    ///
    /// `root_pa` must be the 4 KiB-aligned physical address of the root
    /// page-table frame; `asid` fills the address-space-identifier field.
    #[must_use]
    pub const fn make_satp(self, root_pa: u64, asid: u16) -> u64
    {
        ((self as u64) << 60) | ((asid as u64) << 44) | (root_pa >> 12)
    }

    /// The next-narrower supported mode, or `None` below Sv39. Drives the
    /// bootloader's probe-failure fallback chain.
    #[must_use]
    pub const fn next_lower(self) -> Option<Self>
    {
        match self
        {
            Self::Sv39 => None,
            Self::Sv48 => Some(Self::Sv39),
            Self::Sv57 => Some(Self::Sv48),
        }
    }
}

/// Page-table index of `va` at translation level `level`.
///
/// Level 0 is the leaf (4 KiB) tier; the root of a mode sits at
/// `levels() - 1`. Every tier consumes 9 VA bits above the 12-bit page
/// offset.
#[must_use]
pub const fn vpn_index(level: usize, va: u64) -> usize
{
    ((va >> (12 + 9 * level)) & 0x1FF) as usize
}

/// Bytes of VA covered by one entry at translation level `level`
/// (4 KiB at level 0, 2 MiB at level 1, ...).
#[must_use]
pub const fn level_stride(level: usize) -> u64
{
    1 << (12 + 9 * level)
}

/// First VA above `va` whose `vpn_index(level, ..)` differs — the start of
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

    const ALL: [PagingMode; 3] = [PagingMode::Sv39, PagingMode::Sv48, PagingMode::Sv57];

    #[test]
    fn satp_mode_roundtrip_and_rejection()
    {
        for mode in ALL
        {
            assert_eq!(PagingMode::from_satp_mode(mode as u64), Some(mode));
        }
        for bits in [0u64, 1, 7, 11, 15]
        {
            assert_eq!(PagingMode::from_satp_mode(bits), None);
        }
    }

    #[test]
    fn kernel_va_base_is_sign_extended_half()
    {
        for mode in ALL
        {
            assert_eq!(mode.kernel_va_base(), !0u64 << (mode.va_bits() - 1));
            assert_eq!(mode.user_va_top(), !mode.kernel_va_base() + 1);
        }
    }

    #[test]
    fn canonical_split_is_root_entry_256_in_every_mode()
    {
        for mode in ALL
        {
            let root = mode.levels() - 1;
            assert_eq!(vpn_index(root, mode.kernel_va_base()), 256);
            assert_eq!(vpn_index(root, mode.user_va_top()), 256);
            assert_eq!(vpn_index(root, mode.user_va_top() - 1), 255);
        }
    }

    #[test]
    fn kernel_image_base_root_slot()
    {
        // The kernel links at the top-2-GiB VA, canonical in every mode.
        let image_base = 0xFFFF_FFFF_8000_0000u64;
        assert_eq!(vpn_index(PagingMode::Sv39.levels() - 1, image_base), 510);
        assert_eq!(vpn_index(PagingMode::Sv48.levels() - 1, image_base), 511);
        assert_eq!(vpn_index(PagingMode::Sv57.levels() - 1, image_base), 511);
    }

    #[test]
    fn make_satp_field_placement()
    {
        let root_pa = 0x8020_3000u64;
        for mode in ALL
        {
            let satp = mode.make_satp(root_pa, 0);
            assert_eq!(satp >> 60, mode as u64);
            assert_eq!((satp >> 44) & 0xFFFF, 0);
            assert_eq!(satp & ((1 << 44) - 1), root_pa >> 12);
        }
        let tagged = PagingMode::Sv48.make_satp(root_pa, 0xBEEF);
        assert_eq!((tagged >> 44) & 0xFFFF, 0xBEEF);
        assert_eq!(tagged >> 60, 9);
    }

    #[test]
    fn vpn_index_shift_schedule()
    {
        let va = 0x0000_0040_2030_1000u64;
        assert_eq!(vpn_index(0, va), ((va >> 12) & 0x1FF) as usize);
        assert_eq!(vpn_index(1, va), ((va >> 21) & 0x1FF) as usize);
        assert_eq!(vpn_index(2, va), ((va >> 30) & 0x1FF) as usize);
        assert_eq!(vpn_index(3, va), ((va >> 39) & 0x1FF) as usize);
        assert_eq!(vpn_index(4, va), ((va >> 48) & 0x1FF) as usize);
    }

    #[test]
    fn level_stride_and_boundary()
    {
        assert_eq!(level_stride(0), 0x1000);
        assert_eq!(level_stride(1), 0x20_0000);
        assert_eq!(level_stride(2), 0x4000_0000);
        assert_eq!(level_stride(3), 0x80_0000_0000);
        assert_eq!(level_stride(4), 0x1_0000_0000_0000);

        for level in 0..5
        {
            let va = 0x1234_5678_9000u64;
            let next = next_level_boundary(level, va);
            assert_eq!(next % level_stride(level), 0);
            assert!(next > va);
            assert!(next - va <= level_stride(level));
            assert_ne!(vpn_index(level, va), vpn_index(level, next));
        }
    }

    #[test]
    fn probe_fallback_chain_ends_at_sv39()
    {
        assert_eq!(PagingMode::Sv57.next_lower(), Some(PagingMode::Sv48));
        assert_eq!(PagingMode::Sv48.next_lower(), Some(PagingMode::Sv39));
        assert_eq!(PagingMode::Sv39.next_lower(), None);
    }
}
