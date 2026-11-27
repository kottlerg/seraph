// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/pmu/src/amd.rs

//! AMD core performance counters, family 17h and later: the decode of the
//! core counter extension (CPUID `8000_0001H` `ECX[23]`) and of `PerfMonV2`
//! (CPUID `8000_0022H`), the counters' event selects and the events'
//! encodings (AMD64 APM Vol. 2, Performance Monitor Counters; the Processor
//! Programming Reference of each family for the events).
//!
//! The highest core counter is the kernel's; a configuration takes the
//! others. The core counters count no L3 event, so the last-level cache
//! events are not supported.

use crate::{PmuEvent, PmuMode};

/// CPUID leaf whose `ECX[23]` (`PerfCtrExtCore`) reports the six core
/// counters at [`MSR_PERF_CTL0`].
pub const LEAF_EXT_FEATURES: u32 = 0x8000_0001;
/// CPUID leaf of `PerfMonV2`: `EAX[0]` the version 2 global controls,
/// `EBX[3:0]` the core counter count.
pub const LEAF_PERFMON_V2: u32 = 0x8000_0022;

/// `PerfCtrExtCore`: CPUID `8000_0001H` `ECX` bit 23.
pub const ECX_PERF_CTR_EXT_CORE: u32 = 1 << 23;

/// `PERF_CTL0` of the core counter extension; counter `i`'s select is at
/// `+ 2 * i`, its count at `+ 2 * i + 1`.
pub const MSR_PERF_CTL0: u32 = 0xC001_0200;
/// `PerfCntrGlobalCtl` (`PerfMonV2`): bit `i` enables core counter `i`.
pub const MSR_GLOBAL_CTL: u32 = 0xC000_0301;

/// The core counters `RDPMC` reads by their own index (`ECX` 0 to 5); a
/// higher `ECX` selects another unit's counters.
pub const RDPMC_CORE: u8 = 6;
/// The core counters' width in bits.
pub const WIDTH: u8 = 48;
/// The core counters without `PerfMonV2`.
const EXT_CORE_COUNTERS: u8 = 6;
/// The most core counters the kernel uses: a configuration takes at most
/// eight events.
pub const MAX_COUNTERS: u8 = 9;

/// Event select `USR` (bit 16): count at CPL > 0.
pub const SEL_USR: u64 = 1 << 16;
/// Event select `OS` (bit 17): count at CPL 0.
pub const SEL_OS: u64 = 1 << 17;
/// Event select `EN` (bit 22): the counter counts.
pub const SEL_EN: u64 = 1 << 22;

/// A CPU's core counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perfmon
{
    /// Core counters, the kernel's included.
    pub counters: u8,
    /// Whether `PerfCntrGlobalCtl` gates them (`PerfMonV2`).
    pub global_ctl: bool,
}

impl Perfmon
{
    /// The core counters of a CPU of display `family`, whose CPUID
    /// `8000_0001H` `ECX` is `ext_ecx` and `8000_0022H` `(EAX, EBX)` is
    /// `v2` (`None` past the CPU's maximum extended leaf). `None` before
    /// family 17h, without the core counter extension, or with fewer than
    /// two counters.
    #[must_use]
    pub fn decode(family: u32, ext_ecx: u32, v2: Option<(u32, u32)>) -> Option<Perfmon>
    {
        if family < 0x17 || ext_ecx & ECX_PERF_CTR_EXT_CORE == 0
        {
            return None;
        }
        let perfmon = match v2
        {
            Some((eax, ebx)) if eax & 1 != 0 => Perfmon {
                counters: ((ebx & 0xF) as u8).min(MAX_COUNTERS),
                global_ctl: true,
            },
            _ => Perfmon {
                counters: EXT_CORE_COUNTERS,
                global_ctl: false,
            },
        };
        (perfmon.counters >= 2).then_some(perfmon)
    }

    /// The core counters a configuration takes: `0..user()`, those below the
    /// kernel's that `RDPMC` reads by their own index.
    #[must_use]
    pub const fn user(&self) -> u8
    {
        let below = self.counters.saturating_sub(1);
        if below < RDPMC_CORE
        {
            below
        }
        else
        {
            RDPMC_CORE
        }
    }

    /// The kernel's core counter: the highest.
    #[must_use]
    pub const fn reserved(&self) -> u8
    {
        self.counters.saturating_sub(1)
    }
}

/// An event's encoding in a core counter's select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoding
{
    /// The 12-bit event select (bits 7:0 and 35:32).
    pub event: u16,
    /// The unit mask (bits 15:8).
    pub umask: u8,
}

/// The encoding of `event`, or `None` for an event the core counters do not
/// count.
#[must_use]
pub const fn encoding(event: PmuEvent) -> Option<Encoding>
{
    let (event, umask) = match event
    {
        // PMCx076 cycles not in halt.
        PmuEvent::Cycles => (0x076, 0x00),
        // PMCx0C0 retired instructions.
        PmuEvent::Instructions => (0x0C0, 0x00),
        // PMCx0C2 retired branch instructions.
        PmuEvent::BranchInstructions => (0x0C2, 0x00),
        // PMCx0C3 retired branch instructions mispredicted.
        PmuEvent::BranchMisses => (0x0C3, 0x00),
        // PMCx045 L1 DTLB misses, the L2 DTLB miss (page walk) unit masks.
        PmuEvent::DtlbMisses => (0x045, 0xF0),
        // PMCx085 L1 ITLB misses that also missed the L2 ITLB.
        PmuEvent::ItlbMisses => (0x085, 0x07),
        PmuEvent::LlcReferences | PmuEvent::LlcMisses => return None,
    };
    Some(Encoding { event, umask })
}

/// The events the core counters count, as a mask of [`PmuEvent::bit`]s.
#[must_use]
pub fn events() -> u16
{
    PmuEvent::ALL
        .iter()
        .filter(|&&e| encoding(e).is_some())
        .fold(0, |m, e| m | e.bit())
}

/// The core counter select that counts `enc` in `mode`: the event's two
/// fields, the unit mask, `USR` and `OS` by the mode, and `EN`. It never
/// sets `INT`, `INV`, `E`, a counter mask or the host/guest bits.
#[must_use]
pub fn event_select(enc: Encoding, mode: PmuMode) -> u64
{
    let event = u64::from(enc.event);
    let mut sel = (event & 0xFF) | ((event >> 8) << 32) | (u64::from(enc.umask) << 8) | SEL_EN;
    if mode.counts_user()
    {
        sel |= SEL_USR;
    }
    if mode.counts_kernel()
    {
        sel |= SEL_OS;
    }
    sel
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect guarded: a pre-Zen part, or one without the core counter
    // extension, programmed at MSRs it does not have; PerfMonV2's count
    // ignored.
    #[test]
    fn decode_requires_family_17h_and_the_core_extension()
    {
        let ext = ECX_PERF_CTR_EXT_CORE;
        assert_eq!(Perfmon::decode(0x16, ext, None), None);
        assert_eq!(Perfmon::decode(0x17, 0, None), None);
        assert_eq!(
            Perfmon::decode(0x17, ext, None),
            Some(Perfmon {
                counters: 6,
                global_ctl: false
            })
        );
        assert_eq!(
            Perfmon::decode(0x19, ext, Some((1, 6))),
            Some(Perfmon {
                counters: 6,
                global_ctl: true
            })
        );
        // Version 2 not reported: the leaf's count is not read.
        assert_eq!(
            Perfmon::decode(0x19, ext, Some((0, 2))).unwrap().counters,
            6
        );
        assert_eq!(Perfmon::decode(0x19, ext, Some((1, 1))), None);
    }

    // Defect guarded: a configuration given the kernel's counter.
    #[test]
    fn the_kernel_keeps_the_highest_core_counter()
    {
        let p = Perfmon::decode(0x17, ECX_PERF_CTR_EXT_CORE, None).unwrap();
        assert_eq!((p.user(), p.reserved()), (5, 5));
        // Past six core counters, a configuration still takes only those
        // RDPMC reads by their own index.
        let wide = Perfmon::decode(0x1A, ECX_PERF_CTR_EXT_CORE, Some((1, 8))).unwrap();
        assert_eq!((wide.user(), wide.reserved()), (6, 7));
    }

    // Defect guarded: an L3 event offered on a core counter, which counts
    // none, or a select that loses the event's high nibble.
    #[test]
    fn events_and_selects()
    {
        assert_eq!(encoding(PmuEvent::LlcMisses), None);
        assert_eq!(events(), 0b1111_0011);
        let sel = event_select(
            Encoding {
                event: 0x1C0,
                umask: 0x07,
            },
            PmuMode::User,
        );
        assert_eq!(sel, 0xC0 | (1 << 32) | 0x700 | SEL_USR | SEL_EN);
        let cycles = event_select(encoding(PmuEvent::Cycles).unwrap(), PmuMode::All);
        assert_eq!(cycles, 0x76 | SEL_USR | SEL_OS | SEL_EN);
    }
}
