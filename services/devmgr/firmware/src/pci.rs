// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/pci.rs

//! PCI configuration-space arithmetic for devmgr: ECAM register offsets and
//! BAR sizes from their sizing read-backs (PCI Local Bus Specification r3.0
//! § 6.2.5.1). devmgr performs the volatile accesses; these functions only
//! compute.

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
    mask & mask.wrapping_neg()
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
        assert_eq!(config_offset(4, 6, 1, 0, 4), Some((2 << 20) | (1 << 15) | 4));
    }

    #[test]
    fn config_offset_rejects_a_bus_below_start_and_out_of_range_fields()
    {
        assert_eq!(config_offset(4, 3, 0, 0, 0), None);
        assert_eq!(config_offset(0, 0, 32, 0, 0), None);
        assert_eq!(config_offset(0, 0, 0, 8, 0), None);
        assert_eq!(config_offset(0, 0, 0, 0, 0x1000), None);
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
