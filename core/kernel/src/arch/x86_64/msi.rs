// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/msi.rs

//! x86-64 message-signaled interrupt encoding.
//!
//! A device raises a message-signaled interrupt by writing the message data to the message
//! address. With interrupt remapping off, the kernel hands out the compatibility format (Intel
//! SDM Vol. 3, the APIC chapter's "Message Signalled Interrupts" section); with it on
//! (`SYS_IRQ_REMAP`), the remappable format of [`super::remap`]. The compatibility format:
//!
//! - **Address**: `0xFEE` in bits 31:20, the destination APIC id in bits 19:12, redirection
//!   hint (bit 3) and destination mode (bit 2) clear, so the message is delivered to the one
//!   local APIC the id names, in physical mode.
//! - **Data**: the vector in bits 7:0; delivery mode (bits 10:8) fixed and trigger mode
//!   (bit 15) edge, both zero.
//!
//! The 8-bit destination field cannot name an x2APIC id of `0xFF` or more, and `0xFF` itself
//! is the broadcast id, so with remapping off a message target is placed only on a CPU whose
//! APIC id is below [`super::ioapic::BROADCAST_APIC_ID`] (`interrupts::alloc_message_target`).

/// The fixed upper part of every compatibility-format message address (bits 31:20 `0xFEE`).
pub const MSI_ADDRESS_BASE: u64 = 0xFEE0_0000;

/// Shift of the destination APIC id in a message address (bits 19:12).
const DESTINATION_SHIFT: u32 = 12;

/// The message address that delivers to the local APIC with id `apic_id` in physical
/// destination mode, or `None` when the 8-bit destination field cannot name it alone (the
/// id is the broadcast id or wider).
#[must_use]
pub const fn address(apic_id: u32) -> Option<u64>
{
    if apic_id >= super::ioapic::BROADCAST_APIC_ID
    {
        return None;
    }
    Some(MSI_ADDRESS_BASE | ((apic_id as u64) << DESTINATION_SHIFT))
}

/// The message data that raises `vector` with fixed delivery, edge-triggered.
#[must_use]
pub const fn data(vector: u8) -> u32
{
    vector as u32
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn the_address_names_the_apic_id_in_bits_19_to_12()
    {
        assert_eq!(address(0), Some(0xFEE0_0000));
        assert_eq!(address(1), Some(0xFEE0_1000));
        assert_eq!(address(0xFE), Some(0xFEE0_0000 | (0xFE << 12)));
    }

    #[test]
    fn the_broadcast_id_and_wider_ids_have_no_address()
    {
        assert_eq!(address(0xFF), None);
        assert_eq!(address(0x100), None);
        assert_eq!(address(u32::MAX), None);
    }

    #[test]
    fn the_data_is_the_vector_fixed_and_edge()
    {
        assert_eq!(data(33), 33);
        assert_eq!(data(249), 249);
        // Delivery mode (bits 10:8) and trigger mode (bit 15) are zero.
        assert_eq!(data(0xFF) & !0xFF, 0);
    }
}
