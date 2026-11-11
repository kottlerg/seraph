// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/pci.rs

//! PCI configuration-space arithmetic for devmgr: ECAM register offsets, the
//! physical page of a function's configuration space, BAR sizes from their
//! sizing read-backs (PCI Local Bus Specification r3.0 § 6.2.5.1), the
//! Command register's Memory Space Enable, Bus Master Enable, and Interrupt
//! Disable (§ 6.2.2), the capability-list walk, and the PCI Express Function
//! Level Reset fields. devmgr performs the volatile accesses; these functions
//! only compute.

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

/// Command register: Interrupt Disable, bit 10. While it is set the function
/// does not assert its wired interrupt line (PCI Local Bus Specification
/// r3.0 § 6.2.2).
pub const COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;

/// The Command register value that turns on Memory Space Enable and Bus
/// Master Enable and keeps every other bit of `command`: the function then
/// decodes its MMIO BARs and issues DMA. devmgr writes it for a device the
/// firmware left off that its driver needs on.
#[must_use]
pub const fn command_with_memory_and_bus_master(command: u16) -> u16
{
    command | COMMAND_MEMORY | COMMAND_BUS_MASTER
}

/// The Command register value devmgr writes when it binds a driver to the
/// function: Memory Space Enable on; Bus Master Enable on for a device that
/// performs DMA (`dma`) and off for one that does not; Interrupt Disable
/// clear when the driver is given the function's wired line (`wired`) and
/// set when it is not, so a function whose driver takes no interrupt never
/// asserts a line it may share. Every other bit of `command` is kept.
#[must_use]
pub const fn command_for_bind(command: u16, dma: bool, wired: bool) -> u16
{
    let mut value = command | COMMAND_MEMORY;
    value = if dma
    {
        value | COMMAND_BUS_MASTER
    }
    else
    {
        value & !COMMAND_BUS_MASTER
    };
    if wired
    {
        value & !COMMAND_INTERRUPT_DISABLE
    }
    else
    {
        value | COMMAND_INTERRUPT_DISABLE
    }
}

/// The Command register value that sets Interrupt Disable and keeps every
/// other bit of `command`: the step of a withdrawal that stops the function
/// asserting its wired line, whoever else shares it.
#[must_use]
pub const fn command_with_interrupt_disable(command: u16) -> u16
{
    command | COMMAND_INTERRUPT_DISABLE
}

/// Whether a Command register read back after setting Interrupt Disable
/// confirms it set. An all-ones read-back is what a function that does not
/// answer returns, so it confirms nothing.
#[must_use]
pub const fn interrupt_disable_confirmed(read_back: u16) -> bool
{
    read_back != u16::MAX && read_back & COMMAND_INTERRUPT_DISABLE != 0
}

/// Offset of the Status register; bit 4 is Capabilities List.
pub const STATUS: u16 = 0x06;
/// Status register: the function has a capability list at
/// [`CAPABILITIES_POINTER`].
pub const STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
/// Offset of the capability list's head pointer in a type-0 header.
pub const CAPABILITIES_POINTER: u16 = 0x34;
/// Capability slots a function's capability list can hold: capabilities are
/// dword-aligned in the 192 bytes above the 64-byte standard header, so a
/// longer list loops, and the walk stops there.
pub const MAX_CAPABILITIES: u32 = 48;
/// Capability ID of the PCI Express capability.
pub const CAP_ID_PCI_EXPRESS: u8 = 0x10;
/// Offset of Device Capabilities in the PCI Express capability; bit 28 is
/// Function Level Reset Capability (PCI Express Base Specification r4.0
/// § 7.5.3.3).
pub const PCIE_DEVICE_CAPABILITIES: u16 = 0x04;
/// Device Capabilities: the function supports Function Level Reset.
pub const PCIE_DEVCAP_FLR: u32 = 1 << 28;
/// Offset of Device Control in the PCI Express capability; bit 15 is
/// Initiate Function Level Reset (§ 7.5.3.4).
pub const PCIE_DEVICE_CONTROL: u16 = 0x08;
/// Device Control: Initiate Function Level Reset.
pub const PCIE_DEVCTL_INITIATE_FLR: u16 = 1 << 15;
/// The wait after initiating a Function Level Reset before software touches
/// the function again (§ 6.6.2): 100 ms.
pub const FLR_COMPLETION_MS: u64 = 100;

/// Offset of the capability with ID `id` in a function's configuration
/// header, which `read8` reads a byte of. Walks the capability list from
/// [`CAPABILITIES_POINTER`] when the Status register's Capabilities List bit
/// is set (`status`), at most [`MAX_CAPABILITIES`] entries, so a cyclic list
/// ends; `None` when the function has no list or none of its entries has
/// that ID.
pub fn find_capability(status: u16, id: u8, read8: impl Fn(u16) -> u8) -> Option<u16>
{
    if status & STATUS_CAPABILITIES_LIST == 0
    {
        return None;
    }
    // The pointer's low 2 bits are reserved.
    let mut ptr = read8(CAPABILITIES_POINTER) & !3;
    let mut walked = 0u32;
    while ptr != 0 && walked < MAX_CAPABILITIES
    {
        walked += 1;
        let at = u16::from(ptr);
        if read8(at) == id
        {
            return Some(at);
        }
        ptr = read8(at + 1) & !3;
    }
    None
}

/// Whether a function whose PCI Express Device Capabilities register reads
/// `devcap` supports Function Level Reset. All ones, a function that does not
/// answer, does not.
#[must_use]
pub const fn flr_capable(devcap: u32) -> bool
{
    devcap != u32::MAX && devcap & PCIE_DEVCAP_FLR != 0
}

/// Offset of the Vendor ID register in a function's configuration header.
pub const VENDOR_ID: u16 = 0x00;

/// The Vendor ID a root port returns for a function still completing a
/// reset when Configuration Request Retry Status Software Visibility is on
/// (PCI Express Base Specification r4.0 § 2.3.2).
const VENDOR_ID_RETRY: u16 = 0x0001;

/// Whether a function whose Vendor ID reads `vendor` [`FLR_COMPLETION_MS`]
/// after a Function Level Reset was initiated has completed it: it answers
/// with a Vendor ID, neither all ones (no answer) nor the retry value.
#[must_use]
pub const fn flr_completed(vendor: u16) -> bool
{
    vendor != u16::MAX && vendor != VENDOR_ID_RETRY
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
    mask.isolate_lowest_one()
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
    fn a_bind_enables_memory_and_sets_bus_master_and_interrupt_disable_by_need()
    {
        // DMA and a wired line: Bus Master on, Interrupt Disable cleared.
        assert_eq!(command_for_bind(0x0400, true, true), 0x0006);
        // No DMA, no line: Bus Master off, Interrupt Disable set.
        assert_eq!(command_for_bind(0x0004, false, false), 0x0402);
        // Other bits (I/O Space, SERR#) are kept.
        assert_eq!(command_for_bind(0x0101, true, false), 0x0507);
    }

    #[test]
    fn interrupt_disable_is_set_keeping_every_other_bit_and_confirmed_only_when_read_set()
    {
        assert_eq!(command_with_interrupt_disable(0x0006), 0x0406);
        assert!(interrupt_disable_confirmed(0x0402));
        assert!(!interrupt_disable_confirmed(0x0002));
        assert!(!interrupt_disable_confirmed(0xFFFF));
    }

    /// A configuration header whose capability list is `caps`, each
    /// `(offset, id, next)`.
    fn header(caps: &[(u8, u8, u8)]) -> [u8; 256]
    {
        let mut cfg = [0u8; 256];
        if let Some(&(first, _, _)) = caps.first()
        {
            cfg[usize::from(CAPABILITIES_POINTER)] = first;
        }
        for &(at, id, next) in caps
        {
            cfg[usize::from(at)] = id;
            cfg[usize::from(at) + 1] = next;
        }
        cfg
    }

    #[test]
    fn the_capability_walk_finds_an_id_down_the_list()
    {
        let cfg = header(&[(0x40, 0x05, 0x60), (0x60, 0x10, 0x00)]);
        let read = |at: u16| cfg[usize::from(at)];
        assert_eq!(
            find_capability(STATUS_CAPABILITIES_LIST, CAP_ID_PCI_EXPRESS, read),
            Some(0x60)
        );
        assert_eq!(find_capability(STATUS_CAPABILITIES_LIST, 0x11, read), None);
    }

    #[test]
    fn the_capability_walk_needs_the_status_bit_and_ends_on_a_cycle()
    {
        let cfg = header(&[(0x40, 0x10, 0x00)]);
        assert_eq!(
            find_capability(0, CAP_ID_PCI_EXPRESS, |at| cfg[usize::from(at)]),
            None
        );
        let cyclic = header(&[(0x40, 0x05, 0x50), (0x50, 0x09, 0x40)]);
        assert_eq!(
            find_capability(STATUS_CAPABILITIES_LIST, CAP_ID_PCI_EXPRESS, |at| {
                cyclic[usize::from(at)]
            }),
            None
        );
    }

    #[test]
    fn flr_capability_is_bit_28_of_device_capabilities()
    {
        assert!(flr_capable(0x1000_8000));
        assert!(!flr_capable(0x0000_8000));
        assert!(!flr_capable(u32::MAX));
    }

    #[test]
    fn a_reset_completes_when_the_function_answers_with_a_vendor_id()
    {
        assert!(flr_completed(0x1AF4));
        assert!(!flr_completed(u16::MAX));
        assert!(!flr_completed(0x0001));
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
