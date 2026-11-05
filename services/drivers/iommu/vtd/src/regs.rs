// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/vtd/src/regs.rs

//! VT-d remapping-unit register offsets and the fields the driver reads and
//! writes (Intel VT-d specification rev. 4.1, chapter 11, "Register
//! Descriptions").

/// Capability register (64-bit).
pub const CAP: usize = 0x08;
/// Extended capability register (64-bit).
pub const ECAP: usize = 0x10;
/// Global command register (32-bit).
pub const GCMD: usize = 0x18;
/// Global status register (32-bit).
pub const GSTS: usize = 0x1c;
/// Root table address register (64-bit).
pub const RTADDR: usize = 0x20;
/// Context command register (64-bit).
pub const CCMD: usize = 0x28;
/// Fault status register (32-bit).
pub const FSTS: usize = 0x34;
/// Fault event control register (32-bit).
pub const FECTL: usize = 0x38;

/// `FECTL`: interrupt mask. The driver keeps fault events masked and polls
/// the fault recording registers instead.
pub const FECTL_IM: u32 = 1 << 31;

/// `GCMD` / `GSTS`: translation enable / status.
pub const G_TE: u32 = 1 << 31;
/// `GCMD` / `GSTS`: set root table pointer / its status.
pub const G_SRTP: u32 = 1 << 30;
/// `GCMD` / `GSTS`: write buffer flush / its status (set while the flush is
/// in progress).
pub const G_WBF: u32 = 1 << 27;
/// `GCMD` / `GSTS`: queued invalidation enable; the driver never sets it,
/// since it invalidates through the registers.
pub const G_QIE: u32 = 1 << 26;
/// `GSTS` bits that are one-shot operations rather than persistent states:
/// a write of `GCMD` carries the persistent states of `GSTS` with these
/// masked off (section 11.4.4).
pub const G_ONE_SHOT: u32 = G_SRTP | (1 << 29) | (1 << 27) | (1 << 24);

/// `CCMD`: invalidate context cache.
pub const CCMD_ICC: u64 = 1 << 63;
/// `CCMD`: global invalidation request.
pub const CCMD_GLOBAL: u64 = 1 << 61;

/// `IOTLB` (at `ECAP.IRO * 16 + 8`): invalidate IOTLB.
pub const IOTLB_IVT: u64 = 1 << 63;
/// `IOTLB`: global invalidation request.
pub const IOTLB_GLOBAL: u64 = 1 << 60;
/// `IOTLB`: domain-selective invalidation request.
pub const IOTLB_DOMAIN: u64 = 2 << 60;
/// `IOTLB`: drain reads and writes before completing.
pub const IOTLB_DRAIN: u64 = (1 << 49) | (1 << 48);

/// `FSTS`: primary pending fault (a fault recording register holds one).
pub const FSTS_PPF: u32 = 1 << 1;
/// `FSTS`: primary fault overflow, cleared by writing 1.
pub const FSTS_PFO: u32 = 1 << 0;

/// The index of the first fault recording register holding a fault, from
/// `FSTS`'s `FRI` field (bits 15:8); meaningful while [`FSTS_PPF`] is set.
#[must_use]
pub const fn fault_record_index(fsts: u32) -> usize
{
    ((fsts >> 8) & 0xff) as usize
}

/// The value written to `GCMD` to set `bit` while keeping every persistent
/// state `gsts` reports.
#[must_use]
pub const fn gcmd_set(gsts: u32, bit: u32) -> u32
{
    (gsts & !G_ONE_SHOT) | bit
}

/// The value written to `GCMD` to clear `bit` while keeping every other
/// persistent state `gsts` reports.
#[must_use]
pub const fn gcmd_clear(gsts: u32, bit: u32) -> u32
{
    gsts & !G_ONE_SHOT & !bit
}

/// The `CCMD` value that invalidates the whole context cache.
#[must_use]
pub const fn ccmd_global() -> u64
{
    CCMD_ICC | CCMD_GLOBAL
}

/// The `IOTLB` value that invalidates every IOTLB entry of domain `did`,
/// draining reads and writes first.
#[must_use]
pub const fn iotlb_domain(did: u16) -> u64
{
    IOTLB_IVT | IOTLB_DOMAIN | IOTLB_DRAIN | ((did as u64) << 32)
}

/// The `IOTLB` value that invalidates the whole IOTLB.
#[must_use]
pub const fn iotlb_global() -> u64
{
    IOTLB_IVT | IOTLB_GLOBAL | IOTLB_DRAIN
}

/// The fields of `CAP` the driver uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capability
{
    /// Domain IDs the unit supports: `2^(4 + 2 * ND)`.
    pub domains: u32,
    /// Supported second-level page-table depths (`SAGAW`): bit 1 for
    /// 3-level (39-bit), bit 2 for 4-level (48-bit), bit 3 for 5-level.
    pub sagaw: u8,
    /// Maximum guest address width, in bits.
    pub mgaw: u8,
    /// Byte offset of the first fault recording register.
    pub fault_offset: usize,
    /// Fault recording registers.
    pub fault_count: usize,
    /// Caching mode: the unit may cache not-present entries, so making an
    /// entry present needs an invalidation too.
    pub caching_mode: bool,
    /// Required write-buffer flushing: the unit may buffer writes to the
    /// translation structures until software flushes them (`GCMD.WBF`).
    pub write_buffer_flush: bool,
}

impl Capability
{
    /// Decode a `CAP` value.
    // cast_possible_truncation: every field is masked to at most 10 bits
    // before its cast, so each value fits its target type (and `usize` is
    // 64-bit on every target the driver builds for).
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn decode(cap: u64) -> Self
    {
        let nd = (cap & 0x7) as u32;
        Self {
            domains: 1 << (4 + 2 * nd),
            sagaw: ((cap >> 8) & 0x1f) as u8,
            mgaw: (((cap >> 16) & 0x3f) + 1) as u8,
            fault_offset: (((cap >> 24) & 0x3ff) * 16) as usize,
            fault_count: (((cap >> 40) & 0xff) + 1) as usize,
            caching_mode: (cap >> 7) & 1 != 0,
            write_buffer_flush: (cap >> 4) & 1 != 0,
        }
    }

    /// The deepest page-table depth the unit supports and the driver
    /// builds, with its address width: 4-level (48-bit) when offered, else
    /// 3-level (39-bit). `None` when the unit offers neither.
    #[must_use]
    pub const fn table_depth(&self) -> Option<(u32, u8)>
    {
        if self.sagaw & (1 << 2) != 0
        {
            Some((4, 48))
        }
        else if self.sagaw & (1 << 1) != 0
        {
            Some((3, 39))
        }
        else
        {
            None
        }
    }
}

/// The byte offset of the `IOTLB` register for an `ECAP` value: its
/// `IRO` field (bits 17:8) counts 16-byte units, and the register sits 8
/// bytes past them.
// cast_possible_truncation: the field is masked to 10 bits, so the offset is
// below 2^15 and fits `usize` on every target.
#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub const fn iotlb_offset(ecap: u64) -> usize
{
    (((ecap >> 8) & 0x3ff) * 16 + 8) as usize
}

/// Whether the unit's page walks snoop the processor caches (`ECAP.C`, bit
/// 0). A unit that does not reads the translation structures from memory,
/// so every write to them is flushed from the caches before it is used.
#[must_use]
pub const fn coherent(ecap: u64) -> bool
{
    ecap & 1 != 0
}

/// One fault recording register's two words, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault
{
    /// The requester's source ID (bus, device, function).
    pub source_id: u16,
    /// The fault reason code (section 7.1.3).
    pub reason: u8,
    /// The faulting address, page-aligned.
    pub address: u64,
}

/// Decode a fault recording register from its low word (`lo`, the fault
/// information) and high word (`hi`); `None` when its `F` bit (63 of the
/// high word) is clear, so it records no fault.
#[must_use]
pub const fn decode_fault(lo: u64, hi: u64) -> Option<Fault>
{
    if hi >> 63 == 0
    {
        return None;
    }
    Some(Fault {
        source_id: (hi & 0xffff) as u16,
        reason: ((hi >> 32) & 0xff) as u8,
        address: lo & !0xfff,
    })
}

/// The high word written back to clear a fault recording register: its `F`
/// bit, which is write-1-to-clear.
pub const FAULT_CLEAR: u64 = 1 << 63;

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_q35_default_capability_decodes()
    {
        // QEMU intel-iommu, aw-bits=39: ND=6 (2^16 domains), SAGAW 39-bit,
        // MGAW 39, FRO at 0x220 (34 units), 16 fault registers.
        let cap: u64 = 6 | (0b10 << 8) | (38 << 16) | (0x22 << 24) | (15 << 40);
        let c = Capability::decode(cap);
        assert_eq!(c.domains, 1 << 16);
        assert_eq!(c.sagaw, 0b10);
        assert_eq!(c.mgaw, 39);
        assert_eq!(c.fault_offset, 0x220);
        assert_eq!(c.fault_count, 16);
        assert!(!c.caching_mode);
        assert!(!c.write_buffer_flush);
        assert_eq!(c.table_depth(), Some((3, 39)));
    }

    #[test]
    fn caching_mode_and_write_buffer_flushing_decode_from_their_bits()
    {
        let c = Capability::decode((1 << 7) | (1 << 4));
        assert!(c.caching_mode);
        assert!(c.write_buffer_flush);
        assert!(coherent(1));
        assert!(!coherent(0x10 << 8));
    }

    #[test]
    fn the_first_pending_fault_record_index_decodes_from_fsts()
    {
        assert_eq!(fault_record_index((5 << 8) | FSTS_PPF), 5);
        assert_eq!(fault_record_index(0xff00), 0xff);
    }

    #[test]
    fn the_deepest_offered_depth_is_chosen()
    {
        assert_eq!(Capability::decode(0b110 << 8).table_depth(), Some((4, 48)));
        assert_eq!(Capability::decode(0b1000 << 8).table_depth(), None);
    }

    #[test]
    fn gcmd_keeps_persistent_states_and_drops_one_shot_bits()
    {
        let gsts = G_TE | G_SRTP;
        assert_eq!(gcmd_set(gsts, G_SRTP), G_TE | G_SRTP);
        assert_eq!(gcmd_set(G_SRTP, G_TE), G_TE);
        assert_eq!(gcmd_clear(G_TE | G_QIE | G_SRTP, G_QIE), G_TE);
    }

    #[test]
    fn invalidation_commands_carry_their_granularity_and_domain()
    {
        assert_eq!(ccmd_global(), (1 << 63) | (1 << 61));
        assert_eq!(iotlb_domain(5) >> 32 & 0xffff, 5);
        assert_eq!(iotlb_domain(5) >> 60 & 0x3, 2);
        assert_eq!(iotlb_global() >> 60 & 0x3, 1);
    }

    #[test]
    fn the_iotlb_register_sits_eight_bytes_past_its_offset()
    {
        assert_eq!(iotlb_offset(0x10 << 8), 0x108);
    }

    #[test]
    fn a_recorded_fault_decodes_and_an_empty_one_does_not()
    {
        let f = decode_fault(0xdead_b123, (1 << 63) | (6 << 32) | 0x0018).unwrap();
        assert_eq!(f.source_id, 0x18);
        assert_eq!(f.reason, 6);
        assert_eq!(f.address, 0xdead_b000);
        assert!(decode_fault(0xdead_b000, 0x18).is_none());
    }
}
