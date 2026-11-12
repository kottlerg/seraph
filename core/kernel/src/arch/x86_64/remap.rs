// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/remap.rs

//! x86-64 remappable interrupt formats and the handle of a device vector.
//!
//! With VT-d interrupt remapping on, a device's message and an I/O APIC entry no longer name
//! a CPU and a vector: they name a handle, the index of an entry in the interrupt remapping
//! table, and the IOMMU delivers what that entry holds (Intel VT-d specification, the
//! "Interrupt Remapping" chapter, "Interrupt Requests in Remappable Format").
//!
//! The kernel derives each handle from the target it delivers, so it keeps no table of its
//! own: a device vector `v` on CPU `c` has the handle
//! `c * DEVICE_VECTOR_COUNT + (v - DEVICE_VECTOR_BASE)`, the vector's place among every
//! CPU's device vectors laid end to end. The table's 16-bit index bounds the CPUs that can
//! take a remapped target to [`REMAP_CPU_LIMIT`].
//!
//! - **Message address**: `0xFEE` in bits 31:20, handle bits 14:0 in address bits 19:5, the
//!   remappable format (bit 4), the subhandle-valid bit (bit 3) and handle bit 15 in bit 2.
//! - **Message data**: the subhandle, which is added to the handle; always zero, since every
//!   target is one vector.
//! - **I/O APIC entry**: handle bits 14:0 in entry bits 63:49, the remappable format in bit 48,
//!   handle bit 15 in bit 11, and the vector in bits 7:0, which an I/O APIC matches against the
//!   vector of an EOI to clear a level entry's Remote IRR and so must equal the vector the
//!   remapping entry delivers. Trigger mode, polarity and the mask keep their compatibility
//!   bits.

use super::ioapic::{DEVICE_VECTOR_BASE, DEVICE_VECTOR_COUNT};

/// Entries an interrupt remapping table can index: a handle is 16 bits.
pub const HANDLE_COUNT: usize = 1 << 16;

/// CPUs whose device vectors all have a handle: CPU indices below this take a remapped
/// target, and no others.
pub const REMAP_CPU_LIMIT: usize = HANDLE_COUNT / DEVICE_VECTOR_COUNT;

const _: () = assert!(
    REMAP_CPU_LIMIT > 0,
    "a CPU's device vectors need a handle each"
);
const _: () = assert!(
    REMAP_CPU_LIMIT * DEVICE_VECTOR_COUNT <= HANDLE_COUNT,
    "every handle of the eligible CPUs fits the 16-bit index"
);

/// Bit 4 of a message address and bit 48 of an I/O APIC entry: the remappable format.
const ADDRESS_REMAPPABLE: u64 = 1 << 4;

/// Bit 3 of a message address: the message data carries a subhandle.
const ADDRESS_SUBHANDLE_VALID: u64 = 1 << 3;

/// Bit 2 of a message address: handle bit 15.
const ADDRESS_HANDLE_15_SHIFT: u32 = 2;

/// Shift of handle bits 14:0 in a message address (address bits 19:5).
const ADDRESS_HANDLE_LOW_SHIFT: u32 = 5;

/// Handle bits 14:0.
const HANDLE_LOW_MASK: u32 = 0x7FFF;

/// Bit 16 of an I/O APIC entry's high dword (entry bit 48): the remappable format.
const ENTRY_HIGH_REMAPPABLE: u32 = 1 << 16;

/// Shift of handle bits 14:0 in an I/O APIC entry's high dword (entry bits 63:49).
const ENTRY_HIGH_HANDLE_SHIFT: u32 = 17;

/// Bit 11 of an I/O APIC entry's low dword: handle bit 15.
const ENTRY_LOW_HANDLE_15_SHIFT: u32 = 11;

/// The message data of every remappable message: subhandle 0.
pub const MESSAGE_DATA: u32 = 0;

/// The handle of device vector `vector` on CPU `cpu`, or `None` when `vector` is not a
/// device vector or `cpu` is not below [`REMAP_CPU_LIMIT`].
#[must_use]
pub const fn handle(cpu: usize, vector: u8) -> Option<u16>
{
    let Some(offset) = vector.checked_sub(DEVICE_VECTOR_BASE)
    else
    {
        return None;
    };
    let offset = offset as usize;
    if cpu >= REMAP_CPU_LIMIT || offset >= DEVICE_VECTOR_COUNT
    {
        return None;
    }
    // Below HANDLE_COUNT by the bounds above and the const assertion on REMAP_CPU_LIMIT, so
    // neither operation wraps and the handle fits 16 bits.
    #[allow(clippy::cast_possible_truncation)]
    Some(cpu.wrapping_mul(DEVICE_VECTOR_COUNT).wrapping_add(offset) as u16)
}

/// The number of handles `cpu_count` CPUs use: every device vector of each CPU below
/// [`REMAP_CPU_LIMIT`]. The interrupt remapping table needs this many entries.
#[must_use]
pub const fn handle_count(cpu_count: usize) -> usize
{
    let cpus = if cpu_count < REMAP_CPU_LIMIT
    {
        cpu_count
    }
    else
    {
        REMAP_CPU_LIMIT
    };
    // At most REMAP_CPU_LIMIT * DEVICE_VECTOR_COUNT, which the const assertion keeps
    // within HANDLE_COUNT.
    cpus.saturating_mul(DEVICE_VECTOR_COUNT)
}

/// The remappable message address naming `handle`, with the subhandle valid.
#[must_use]
pub const fn message_address(handle: u16) -> u64
{
    let low = (handle as u32 & HANDLE_LOW_MASK) as u64;
    let high = (handle >> 15) as u64;
    super::msi::MSI_ADDRESS_BASE
        | (low << ADDRESS_HANDLE_LOW_SHIFT)
        | ADDRESS_REMAPPABLE
        | ADDRESS_SUBHANDLE_VALID
        | (high << ADDRESS_HANDLE_15_SHIFT)
}

/// The I/O APIC entry naming `handle` in remappable format, given the low dword the
/// compatibility format would program (the vector, trigger mode, polarity and mask):
/// `(low, high)`, the low dword with handle bit 15 added and the high dword carrying the
/// rest of the handle and the format bit.
#[must_use]
pub const fn redirection(handle: u16, compatibility_low: u32) -> (u32, u32)
{
    let low = compatibility_low | (((handle >> 15) as u32) << ENTRY_LOW_HANDLE_15_SHIFT);
    let high =
        ((handle as u32 & HANDLE_LOW_MASK) << ENTRY_HIGH_HANDLE_SHIFT) | ENTRY_HIGH_REMAPPABLE;
    (low, high)
}

#[cfg(test)]
mod tests
{
    use super::super::ioapic::DEVICE_VECTOR_LAST;
    use super::*;

    #[test]
    fn the_cpu_limit_fills_the_16_bit_index()
    {
        assert_eq!(DEVICE_VECTOR_COUNT, 217);
        assert_eq!(REMAP_CPU_LIMIT, 302);
        assert_eq!(handle_count(REMAP_CPU_LIMIT), 65_534);
    }

    #[test]
    fn handles_lay_every_cpus_device_vectors_end_to_end()
    {
        assert_eq!(handle(0, DEVICE_VECTOR_BASE), Some(0));
        assert_eq!(handle(0, DEVICE_VECTOR_LAST), Some(216));
        assert_eq!(handle(1, DEVICE_VECTOR_BASE), Some(217));
        assert_eq!(handle(3, DEVICE_VECTOR_BASE + 10), Some(3 * 217 + 10));
        assert_eq!(
            handle(REMAP_CPU_LIMIT - 1, DEVICE_VECTOR_LAST),
            Some(65_533)
        );
    }

    #[test]
    fn non_device_vectors_and_cpus_past_the_limit_have_no_handle()
    {
        assert_eq!(handle(0, DEVICE_VECTOR_BASE - 1), None);
        assert_eq!(handle(0, DEVICE_VECTOR_LAST + 1), None);
        assert_eq!(handle(0, 0), None);
        assert_eq!(handle(0, 0xFF), None);
        assert_eq!(handle(REMAP_CPU_LIMIT, DEVICE_VECTOR_BASE), None);
    }

    #[test]
    fn handle_count_stops_at_the_cpu_limit()
    {
        assert_eq!(handle_count(0), 0);
        assert_eq!(handle_count(4), 4 * 217);
        assert_eq!(handle_count(4096), handle_count(REMAP_CPU_LIMIT));
    }

    #[test]
    fn the_message_address_splits_the_handle_around_the_format_bits()
    {
        // Handle 0: base, remappable format, subhandle valid.
        assert_eq!(message_address(0), 0xFEE0_0018);
        // Handle bits 14:0 land in address bits 19:5.
        assert_eq!(message_address(1), 0xFEE0_0038);
        assert_eq!(message_address(0x7FFF), 0xFEE0_0018 | (0x7FFF << 5));
        // Handle bit 15 lands in address bit 2.
        assert_eq!(message_address(0x8000), 0xFEE0_001C);
        assert_eq!(message_address(0xFFFF), 0xFEE0_001C | (0x7FFF << 5));
        assert_eq!(MESSAGE_DATA, 0);
    }

    #[test]
    fn the_entry_carries_the_handle_and_keeps_the_compatibility_low_bits()
    {
        let low = 0x0001_A021; // masked, level, active-low, vector 33
        assert_eq!(redirection(0, low), (low, 1 << 16));
        assert_eq!(redirection(1, low), (low, (1 << 17) | (1 << 16)));
        assert_eq!(redirection(0x7FFF, low), (low, (0x7FFF << 17) | (1 << 16)));
        assert_eq!(redirection(0x8000, low), (low | (1 << 11), 1 << 16));
    }
}
