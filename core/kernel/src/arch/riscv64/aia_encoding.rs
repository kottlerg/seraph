// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/riscv64/aia_encoding.rs

//! RISC-V Advanced Interrupt Architecture register-map arithmetic: the APLIC
//! and IMSIC bounds the specification sets, the APLIC source modes and MSI
//! targets, the IMSIC register count and EID rows, and the routed-source word
//! (`aia` drives the controllers with them).
//!
//! Pure functions of their arguments with no dependency on the rest of the
//! arch module. `arch/mod.rs` also compiles this file into host test builds
//! of the other architectures, so `cargo xtask test` (run on an `x86_64`
//! host) runs its tests.

/// Largest APLIC interrupt source the RISC-V Advanced Interrupt Architecture
/// allows (sources 1..=1023; source 0 is reserved).
pub(super) const APLIC_MAX_SOURCES: u32 = 1023;

/// Smallest APLIC domain register window: the 16 KiB that hold `domaincfg`,
/// every `sourcecfg`, the enable and pending registers, and every `target`
/// (`target[1023]` ends at 0x4000). A reported window below it is refused.
pub(super) const APLIC_MIN_WINDOW: u64 = 0x4000;

/// Fewest interrupt identities an IMSIC interrupt file implements (AIA
/// specification: identities `1..=ids`, `ids` from 63 to 2047).
pub(super) const IMSIC_MIN_IDS: u32 = 63;

/// Most interrupt identities an IMSIC interrupt file implements.
pub(super) const IMSIC_MAX_IDS: u32 = 2047;

/// Largest hart index an APLIC `target` register holds in MSI delivery mode:
/// its Hart Index field is bits 31:18, 14 bits wide.
pub(super) const APLIC_MAX_HART_INDEX: u32 = (1 << 14) - 1;

/// The source count of an APLIC domain reporting `reported` sources: the report
/// when it lies in `1..=APLIC_MAX_SOURCES`, else `None` (no domain, or a count
/// the specification does not admit; the boot refuses either).
pub(super) fn aplic_sources_for(reported: u64) -> Option<u32>
{
    match u32::try_from(reported)
    {
        Ok(n) if (1..=APLIC_MAX_SOURCES).contains(&n) => Some(n),
        _ => None,
    }
}

/// Whether an IMSIC file of `ids` interrupt identities lies in the range the
/// AIA specification admits.
pub(super) const fn imsic_ids_valid(ids: u32) -> bool
{
    ids >= IMSIC_MIN_IDS && ids <= IMSIC_MAX_IDS
}

/// APLIC `sourcecfg` source mode for a `SYS_IRQ_REGISTER` trigger and polarity
/// word (`IRQ_MODE_LEVEL`, `IRQ_MODE_ACTIVE_LOW` in `abi/syscall`; a word with
/// other bits is refused before this is reached): Edge1 (4) for a rising edge,
/// Edge0 (5) for a falling edge, Level1 (6) for active-high, Level0 (7) for
/// active-low.
pub(super) fn aplic_source_mode(mode: u32) -> u32
{
    let level = u64::from(mode) & syscall::IRQ_MODE_LEVEL != 0;
    let low = u64::from(mode) & syscall::IRQ_MODE_ACTIVE_LOW != 0;
    match (level, low)
    {
        (false, false) => 4,
        (false, true) => 5,
        (true, false) => 6,
        (true, true) => 7,
    }
}

/// Whether an APLIC source mode is level-sensitive (Level1 or Level0).
pub(super) const fn aplic_mode_is_level(source_mode: u32) -> bool
{
    source_mode == 6 || source_mode == 7
}

/// The APLIC `target` register value, in MSI delivery mode, that forwards a
/// source as identity `eid` to the supervisor-level file at hart index
/// `hart_index`, guest index 0: `hart_index << 18 | eid`. `None` when the hart
/// index exceeds [`APLIC_MAX_HART_INDEX`], or `eid` is 0 or past
/// [`IMSIC_MAX_IDS`] (the 11-bit EIID field).
pub(super) const fn aplic_msi_target(hart_index: u32, eid: u32) -> Option<u32>
{
    if hart_index > APLIC_MAX_HART_INDEX || eid == 0 || eid > IMSIC_MAX_IDS
    {
        return None;
    }
    Some((hart_index << 18) | eid)
}

/// Number of 64-bit `eip`/`eie` registers covering identities `0..=ids` of an
/// IMSIC file: each holds 64 identities.
pub(super) const fn imsic_reg_words(ids: u32) -> u32
{
    (ids + 1).div_ceil(64)
}

/// The lowest free identity in an EID row (`row[eid]` is free when identity
/// `eid` is; entry 0, the reserved identity 0, is never taken), or `None` when
/// every identity is taken.
pub(super) fn lowest_free_eid(row: &[crate::irq::SlotEntry]) -> Option<u32>
{
    let (index, _) = row
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, entry)| entry.is_free())?;
    u32::try_from(index).ok()
}

/// A routed APLIC source: the logical CPU whose IMSIC file it is delivered to,
/// the identity it takes there, and whether it is level-sensitive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SourceRoute
{
    /// Logical index of the target CPU.
    pub cpu: u32,
    /// The identity the source takes in the target CPU's file.
    pub eid: u32,
    /// Whether the source is level-sensitive, so its unmask re-pends it.
    pub level: bool,
}

/// Bit marking a packed [`SourceRoute`] as routed, so a zero word is unrouted.
const SOURCE_ROUTED: u64 = 1 << 63;

/// Bit holding a packed [`SourceRoute`]'s `level`.
const SOURCE_LEVEL: u64 = 1 << 62;

impl SourceRoute
{
    /// The route packed into one word: the identity in bits 0..=31, the CPU
    /// in bits 32..=61, `level` and the routed mark above them. A CPU index
    /// is below `MAX_CPUS`, which 30 bits hold.
    pub(super) const fn pack(self) -> u64
    {
        let level = if self.level { SOURCE_LEVEL } else { 0 };
        SOURCE_ROUTED | level | ((self.cpu as u64) << 32) | self.eid as u64
    }

    /// The route a word [`Self::pack`] wrote, or `None` for an unrouted (zero)
    /// word.
    pub(super) const fn unpack(word: u64) -> Option<Self>
    {
        if word & SOURCE_ROUTED == 0
        {
            return None;
        }
        // Each field is a u32 `pack` placed in its own bit range.
        #[allow(clippy::cast_possible_truncation)]
        Some(Self {
            cpu: ((word >> 32) & 0x3FFF_FFFF) as u32,
            eid: word as u32,
            level: word & SOURCE_LEVEL != 0,
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a trigger or polarity bit read wrongly, so a level line
    // is programmed as an edge (never re-pended at unmask) or a polarity
    // inverted (a line that interrupts forever, or never).
    #[test]
    fn source_mode_follows_trigger_and_polarity()
    {
        let level = syscall::IRQ_MODE_LEVEL as u32;
        let low = syscall::IRQ_MODE_ACTIVE_LOW as u32;
        assert_eq!(aplic_source_mode(0), 4);
        assert_eq!(aplic_source_mode(low), 5);
        assert_eq!(aplic_source_mode(level), 6);
        assert_eq!(aplic_source_mode(level | low), 7);
        assert!(!aplic_mode_is_level(aplic_source_mode(low)));
        assert!(aplic_mode_is_level(aplic_source_mode(level | low)));
    }

    // Defect caught: a hart index or identity past the target register's
    // fields written into it, which would deliver to another hart or identity.
    #[test]
    fn msi_target_refuses_what_its_fields_cannot_hold()
    {
        assert_eq!(aplic_msi_target(3, 5), Some((3 << 18) | 5));
        assert_eq!(
            aplic_msi_target(APLIC_MAX_HART_INDEX, IMSIC_MAX_IDS),
            Some((APLIC_MAX_HART_INDEX << 18) | IMSIC_MAX_IDS)
        );
        assert_eq!(aplic_msi_target(APLIC_MAX_HART_INDEX + 1, 1), None);
        assert_eq!(aplic_msi_target(0, 0), None);
        assert_eq!(aplic_msi_target(0, IMSIC_MAX_IDS + 1), None);
    }

    // Defect caught: an APLIC source count or IMSIC identity count outside the
    // specification accepted, which would size the routing table or the EID
    // rows past the registers the controllers implement.
    #[test]
    fn controller_counts_outside_the_specification_are_refused()
    {
        assert_eq!(aplic_sources_for(96), Some(96));
        assert_eq!(aplic_sources_for(1023), Some(1023));
        assert_eq!(aplic_sources_for(0), None);
        assert_eq!(aplic_sources_for(1024), None);
        assert!(imsic_ids_valid(63) && imsic_ids_valid(255) && imsic_ids_valid(2047));
        assert!(!imsic_ids_valid(62) && !imsic_ids_valid(2048) && !imsic_ids_valid(0));
    }

    // Defect caught: a register count that misses the file's last identities
    // (left disabled or pending) or writes past its last register.
    #[test]
    fn imsic_registers_cover_every_identity()
    {
        assert_eq!(imsic_reg_words(63), 1);
        assert_eq!(imsic_reg_words(255), 4);
        assert_eq!(imsic_reg_words(2047), 32);
    }

    // Defect caught: identity 0 handed out (the IMSIC reserves it, so the
    // source would never be claimed), a taken identity handed out twice, or
    // a full row not reported.
    #[test]
    fn lowest_free_eid_skips_identity_zero_and_taken_ones()
    {
        use crate::irq::{Slot, SlotEntry};
        let row: [SlotEntry; 4] = [const { SlotEntry::free() }; 4];
        assert_eq!(lowest_free_eid(&row), Some(1));
        row[1].store(Slot::Line(10));
        row[3].store(Slot::Unbound);
        assert_eq!(lowest_free_eid(&row), Some(2));
        row[2].store(Slot::Line(0));
        assert_eq!(lowest_free_eid(&row), None);
        row[3].store(Slot::Free);
        assert_eq!(lowest_free_eid(&row), Some(3));
    }

    // Defect caught: a field lost or bled into another in the packed word, so
    // an unroute frees the wrong identity or CPU, or an unmask misses the
    // level re-pend; or a zero word read as routed.
    #[test]
    fn source_route_round_trips_and_zero_is_unrouted()
    {
        let route = SourceRoute {
            cpu: 8191,
            eid: IMSIC_MAX_IDS,
            level: true,
        };
        assert_eq!(SourceRoute::unpack(route.pack()), Some(route));
        let edge = SourceRoute {
            cpu: 0,
            eid: 1,
            level: false,
        };
        assert_eq!(SourceRoute::unpack(edge.pack()), Some(edge));
        assert_eq!(SourceRoute::unpack(0), None);
    }
}
