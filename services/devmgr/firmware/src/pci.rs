// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/pci.rs

//! PCI configuration-space arithmetic for devmgr: ECAM register offsets, the
//! physical page of a function's configuration space, BAR sizes from their
//! sizing read-backs (PCI Local Bus Specification r3.0 § 6.2.5.1), and the
//! Command register's Bus Master Enable (§ 6.2.2). devmgr performs the
//! volatile accesses; these functions only compute.

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

/// The Command register value that turns on Memory Space Enable and Bus
/// Master Enable and keeps every other bit of `command`: the function then
/// decodes its MMIO BARs and issues DMA. devmgr writes it for a device the
/// firmware left off that its driver needs on.
#[must_use]
pub const fn command_with_memory_and_bus_master(command: u16) -> u16
{
    command | COMMAND_MEMORY | COMMAND_BUS_MASTER
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
