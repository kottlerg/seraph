// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/queue.rs

//! Queued invalidation: the 128-bit descriptors the driver places in a unit's
//! invalidation queue and the queue registers' values (Intel VT-d
//! specification rev. 4.1, section 6.5.2, "Queued Invalidation Interface").
//!
//! Every invalidation the driver makes goes through the queue: the interrupt
//! entry cache can be invalidated no other way, and once queued invalidation
//! is on the context-command and IOTLB registers may not be used. The queue
//! is one page of [`QUEUE_ENTRIES`] descriptors; each submission ends with an
//! invalidation wait descriptor whose status write the driver polls, so the
//! queue is empty whenever a submission starts.

/// Descriptors one queue page holds: 4 KiB of 128-bit descriptors, the
/// smallest queue (`IQA.QS` = 0).
pub const QUEUE_ENTRIES: usize = 256;

/// A queue descriptor: its low and high 64-bit words.
pub type Descriptor = [u64; 2];

/// Context-cache invalidate descriptor type.
const TYPE_CONTEXT: u64 = 0x1;
/// IOTLB invalidate descriptor type.
const TYPE_IOTLB: u64 = 0x2;
/// Interrupt entry cache invalidate descriptor type.
const TYPE_IEC: u64 = 0x4;
/// Invalidation wait descriptor type.
const TYPE_WAIT: u64 = 0x5;

/// Context-cache and IOTLB descriptors: global granularity (bits 5:4).
const GRANULARITY_GLOBAL: u64 = 1 << 4;
/// Context-cache and IOTLB descriptors: domain-selective granularity.
const GRANULARITY_DOMAIN: u64 = 2 << 4;
/// IOTLB descriptor: drain writes (bit 6) and reads (bit 7) first.
const IOTLB_DRAIN: u64 = (1 << 6) | (1 << 7);
/// Interrupt entry cache descriptor: index-selective granularity (bit 4).
const IEC_INDEX: u64 = 1 << 4;
/// Wait descriptor: write the status data to the status address (bit 5).
const WAIT_STATUS_WRITE: u64 = 1 << 5;
/// Wait descriptor: fence, so the descriptors after it wait for it (bit 6).
const WAIT_FENCE: u64 = 1 << 6;

/// Invalidate the whole context cache.
#[must_use]
pub const fn context_global() -> Descriptor
{
    [TYPE_CONTEXT | GRANULARITY_GLOBAL, 0]
}

/// Invalidate the whole IOTLB, draining reads and writes first.
#[must_use]
pub const fn iotlb_global() -> Descriptor
{
    [TYPE_IOTLB | GRANULARITY_GLOBAL | IOTLB_DRAIN, 0]
}

/// Invalidate every IOTLB entry of domain `did`, draining reads and writes
/// first.
#[must_use]
pub const fn iotlb_domain(did: u16) -> Descriptor
{
    [
        TYPE_IOTLB | GRANULARITY_DOMAIN | IOTLB_DRAIN | ((did as u64) << 16),
        0,
    ]
}

/// Invalidate the whole interrupt entry cache.
#[must_use]
pub const fn iec_global() -> Descriptor
{
    [TYPE_IEC, 0]
}

/// Invalidate the interrupt entry cache's copy of the remapping table entry
/// `index` (index mask 0: that entry alone).
#[must_use]
pub const fn iec_index(index: u16) -> Descriptor
{
    [TYPE_IEC | IEC_INDEX | ((index as u64) << 32), 0]
}

/// Write `data` to the physical address `status` once every descriptor
/// before this one has completed. `status` is 4-byte aligned.
#[must_use]
pub const fn wait(status: u64, data: u32) -> Descriptor
{
    [
        TYPE_WAIT | WAIT_STATUS_WRITE | WAIT_FENCE | ((data as u64) << 32),
        status & !0x3,
    ]
}

/// The `IQA` value for a one-page queue of 128-bit descriptors at the
/// physical address `base` (`DW` = 0, `QS` = 0).
#[must_use]
pub const fn iqa(base: u64) -> u64
{
    base & !0xfff
}

/// The `IQT` (or `IQH`) value naming descriptor `index` of a queue of
/// 128-bit descriptors: the index in bits 18:4.
#[must_use]
pub const fn tail(index: usize) -> u64
{
    ((index % QUEUE_ENTRIES) as u64) << 4
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn context_and_iotlb_descriptors_carry_type_granularity_and_domain()
    {
        assert_eq!(context_global(), [0x11, 0]);
        assert_eq!(iotlb_global(), [0xd2, 0]);
        let d = iotlb_domain(5);
        assert_eq!(d[0] & 0xf, 2);
        assert_eq!((d[0] >> 4) & 0x3, 2);
        assert_eq!((d[0] >> 16) & 0xffff, 5);
        assert_eq!(d[0] & 0xc0, 0xc0);
    }

    #[test]
    fn interrupt_entry_cache_descriptors_select_global_or_one_index()
    {
        assert_eq!(iec_global(), [0x4, 0]);
        let d = iec_index(0x1234);
        assert_eq!(d[0] & 0xf, 4);
        assert_eq!(d[0] & (1 << 4), 1 << 4);
        // Index mask (bits 31:27) zero: one entry.
        assert_eq!((d[0] >> 27) & 0x1f, 0);
        assert_eq!((d[0] >> 32) & 0xffff, 0x1234);
    }

    #[test]
    fn a_wait_descriptor_writes_its_data_to_its_status_address()
    {
        let d = wait(0x1234_5678_9000, 7);
        assert_eq!(d[0] & 0xf, 5);
        assert_eq!(d[0] & (1 << 5), 1 << 5);
        assert_eq!(d[0] >> 32, 7);
        assert_eq!(d[1], 0x1234_5678_9000);
        assert_eq!(wait(0x1003, 1)[1], 0x1000);
    }

    #[test]
    fn the_queue_registers_take_a_page_base_and_a_wrapping_index()
    {
        assert_eq!(iqa(0x7f00_0000), 0x7f00_0000);
        assert_eq!(tail(1), 0x10);
        assert_eq!(tail(QUEUE_ENTRIES - 1), 0xff0);
        assert_eq!(tail(QUEUE_ENTRIES), 0);
    }
}
