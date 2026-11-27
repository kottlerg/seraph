// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/pmu/src/intel.rs

//! Intel architectural performance monitoring: the decode of CPUID leaf 0AH,
//! the general-purpose counters' event selects, the architectural events'
//! encodings and the model table of the TLB events (Intel SDM Vol. 3B
//! ch. 20, Performance Monitoring; Vol. 4, the per-model event lists).
//!
//! A configuration takes general-purpose counters only. Fixed counter 1
//! (unhalted core cycles) is the kernel's; where the CPU has no second fixed
//! counter, the highest general-purpose counter is the kernel's instead
//! ([`Layout::of`]).

use crate::{PmuEvent, PmuMode};

/// CPUID leaf of architectural performance monitoring.
pub const LEAF_PERFMON: u32 = 0x0A;
/// CPUID leaf of the hybrid core type (`EAX[31:24]`).
pub const LEAF_HYBRID: u32 = 0x1A;

/// `IA32_PERFEVTSEL0`; general-purpose counter `i`'s select is at `+ i`.
pub const MSR_PERFEVTSEL0: u32 = 0x186;
/// `IA32_PMC0`; general-purpose counter `i` is at `+ i`.
pub const MSR_PMC0: u32 = 0xC1;
/// `IA32_PERF_GLOBAL_CTRL` (version 2 and later): bit `i` enables
/// general-purpose counter `i`, bit `32 + j` fixed counter `j`.
pub const MSR_PERF_GLOBAL_CTRL: u32 = 0x38F;

/// Event select `USR` (bit 16): count at CPL > 0.
pub const SEL_USR: u64 = 1 << 16;
/// Event select `OS` (bit 17): count at CPL 0.
pub const SEL_OS: u64 = 1 << 17;
/// Event select `EN` (bit 22): the counter counts.
pub const SEL_EN: u64 = 1 << 22;

/// The most general-purpose counters the kernel uses: `IA32_PERFEVTSEL0..7`
/// are contiguous, and a configuration takes at most eight events.
pub const MAX_GENERAL: u8 = 8;

/// The bits of CPUID 0AH `EBX` that mark an architectural event
/// unavailable, by event.
const EBX_CYCLES: u32 = 1 << 0;
const EBX_INSTRUCTIONS: u32 = 1 << 1;
const EBX_LLC_REFERENCES: u32 = 1 << 3;
const EBX_LLC_MISSES: u32 = 1 << 4;
const EBX_BRANCH_INSTRUCTIONS: u32 = 1 << 5;
const EBX_BRANCH_MISSES: u32 = 1 << 6;

/// What CPUID leaf 0AH reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Perfmon
{
    /// The architectural performance monitoring version (`EAX[7:0]`).
    pub version: u8,
    /// General-purpose counters per logical CPU (`EAX[15:8]`).
    pub general: u8,
    /// Their width in bits (`EAX[23:16]`).
    pub width: u8,
    /// `EBX`, with every bit at or past the vector's length (`EAX[31:24]`)
    /// set: a set bit marks an architectural event unavailable.
    pub unavailable: u32,
    /// Fixed-function counters (`EDX[4:0]`, version 2 and later).
    pub fixed: u8,
}

impl Perfmon
{
    /// Decode CPUID 0AH's `EAX`, `EBX` and `EDX`, or `None` for a CPU
    /// with no architectural performance monitoring (version 0, or no
    /// general-purpose counter), as QEMU's TCG reports.
    #[must_use]
    pub const fn decode(eax: u32, ebx: u32, edx: u32) -> Option<Perfmon>
    {
        let version = (eax & 0xFF) as u8;
        let general = ((eax >> 8) & 0xFF) as u8;
        if version == 0 || general == 0
        {
            return None;
        }
        let length = (eax >> 24) & 0xFF;
        let past = if length >= 32 { 0 } else { u32::MAX << length };
        Some(Perfmon {
            version,
            general,
            width: ((eax >> 16) & 0xFF) as u8,
            unavailable: ebx | past,
            fixed: if version >= 2 { (edx & 0x1F) as u8 } else { 0 },
        })
    }

    /// Whether the architectural event whose `EBX` bit is `bit` is
    /// available.
    const fn has(self, bit: u32) -> bool
    {
        self.unavailable & bit == 0
    }
}

/// The counter the kernel keeps, out of every configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reserved
{
    /// A fixed-function counter.
    Fixed(u8),
    /// A general-purpose counter.
    General(u8),
}

/// How a CPU's counters divide between configurations and the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout
{
    /// The general-purpose counters a configuration takes: `0..user`.
    pub user: u8,
    /// The kernel's counter.
    pub reserved: Reserved,
}

impl Layout
{
    /// The layout of `perfmon`: fixed counter 1 is the kernel's where it
    /// exists, and every general-purpose counter, up to [`MAX_GENERAL`], a
    /// configuration's; otherwise the highest general-purpose counter is the
    /// kernel's. `None` when no counter is left for a configuration.
    #[must_use]
    pub fn of(perfmon: &Perfmon) -> Option<Layout>
    {
        let general = perfmon.general.min(MAX_GENERAL);
        let layout = if perfmon.fixed >= 2
        {
            Layout {
                user: general,
                reserved: Reserved::Fixed(1),
            }
        }
        else
        {
            let top = perfmon.general.saturating_sub(1);
            Layout {
                user: general.min(top),
                reserved: Reserved::General(top),
            }
        };
        (layout.user != 0).then_some(layout)
    }
}

/// The core type of a hybrid part (CPUID 1AH `EAX[31:24]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreType
{
    /// An Atom-class (efficiency) core.
    Atom,
    /// A Core-class (performance) core.
    Core,
    /// Not a hybrid part, or a type this table does not know.
    Other,
}

impl CoreType
{
    /// The core type CPUID 1AH's `EAX` reports; `Other` where the leaf is
    /// past the CPU's maximum leaf, which the caller passes as 0.
    #[must_use]
    pub const fn decode(eax: u32) -> CoreType
    {
        match eax >> 24
        {
            0x20 => CoreType::Atom,
            0x40 => CoreType::Core,
            _ => CoreType::Other,
        }
    }
}

/// A CPU's display family and model, from CPUID 01H's `EAX`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Model
{
    /// The display family.
    pub family: u32,
    /// The display model.
    pub model: u32,
}

impl Model
{
    /// Decode CPUID 01H's `EAX` (Intel SDM Vol. 2A, CPUID, the display family
    /// and model).
    #[must_use]
    pub const fn decode(eax: u32) -> Model
    {
        let base_family = (eax >> 8) & 0xF;
        let family = if base_family == 0xF
        {
            base_family.saturating_add((eax >> 20) & 0xFF)
        }
        else
        {
            base_family
        };
        let mut model = (eax >> 4) & 0xF;
        if base_family == 0x6 || base_family == 0xF
        {
            model |= ((eax >> 16) & 0xF) << 4;
        }
        Model { family, model }
    }
}

/// An event's encoding in a general-purpose counter's select.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Encoding
{
    /// The event select (bits 7:0).
    pub event: u8,
    /// The unit mask (bits 15:8).
    pub umask: u8,
}

const fn enc(event: u8, umask: u8) -> Encoding
{
    Encoding { event, umask }
}

/// The TLB events' microarchitecture families, by display model of family 6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlbFamily
{
    /// Skylake and its derivatives: `DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK`
    /// (08H/01H), `ITLB_MISSES.MISS_CAUSES_A_WALK` (85H/01H).
    Skylake,
    /// Sunny Cove and Willow Cove (Ice Lake, Tiger Lake, Rocket Lake), and
    /// Gracemont (the Atom cores of Alder Lake and Raptor Lake):
    /// `DTLB_LOAD_MISSES.WALK_COMPLETED` (08H/0EH),
    /// `ITLB_MISSES.WALK_COMPLETED` (85H/0EH).
    SunnyCove,
    /// Golden Cove and Raptor Cove: `DTLB_LOAD_MISSES.WALK_COMPLETED`
    /// (12H/0EH), `ITLB_MISSES.WALK_COMPLETED` (11H/0EH).
    GoldenCove,
}

/// The TLB family of `model` on a core of type `core`, or `None` for a
/// model the table does not list.
const fn tlb_family(model: Model, core: CoreType) -> Option<TlbFamily>
{
    if model.family != 6
    {
        return None;
    }
    match model.model
    {
        // Skylake, Skylake-X, Kaby Lake, Coffee Lake, Comet Lake.
        0x4E | 0x5E | 0x55 | 0x8E | 0x9E | 0xA5 | 0xA6 => Some(TlbFamily::Skylake),
        // Ice Lake, Ice Lake-SP, Tiger Lake, Rocket Lake.
        0x7D | 0x7E | 0x6A | 0x6C | 0x8C | 0x8D | 0xA7 => Some(TlbFamily::SunnyCove),
        // Sapphire Rapids and Emerald Rapids: Golden Cove and Raptor Cove
        // cores alone.
        0x8F | 0xCF => Some(TlbFamily::GoldenCove),
        // Alder Lake and Raptor Lake: hybrid, the event by the core's type.
        0x97 | 0x9A | 0xB7 | 0xBA | 0xBF => match core
        {
            CoreType::Core => Some(TlbFamily::GoldenCove),
            CoreType::Atom => Some(TlbFamily::SunnyCove),
            CoreType::Other => None,
        },
        _ => None,
    }
}

/// The encoding of `event` on a CPU with `perfmon`, of `model`, on a core
/// of type `core`, or `None` where the CPU does not count it: an
/// architectural event `EBX` marks unavailable, or a TLB event of a model the
/// table does not list.
#[must_use]
pub fn encoding(
    perfmon: &Perfmon,
    model: Model,
    core: CoreType,
    event: PmuEvent,
) -> Option<Encoding>
{
    let arch = |bit: u32, e: u8, u: u8| {
        if perfmon.has(bit)
        {
            Some(enc(e, u))
        }
        else
        {
            None
        }
    };
    match event
    {
        PmuEvent::Cycles => arch(EBX_CYCLES, 0x3C, 0x00),
        PmuEvent::Instructions => arch(EBX_INSTRUCTIONS, 0xC0, 0x00),
        PmuEvent::LlcReferences => arch(EBX_LLC_REFERENCES, 0x2E, 0x4F),
        PmuEvent::LlcMisses => arch(EBX_LLC_MISSES, 0x2E, 0x41),
        PmuEvent::BranchInstructions => arch(EBX_BRANCH_INSTRUCTIONS, 0xC4, 0x00),
        PmuEvent::BranchMisses => arch(EBX_BRANCH_MISSES, 0xC5, 0x00),
        PmuEvent::DtlbMisses => match tlb_family(model, core)
        {
            Some(TlbFamily::Skylake) => Some(enc(0x08, 0x01)),
            Some(TlbFamily::SunnyCove) => Some(enc(0x08, 0x0E)),
            Some(TlbFamily::GoldenCove) => Some(enc(0x12, 0x0E)),
            None => None,
        },
        PmuEvent::ItlbMisses => match tlb_family(model, core)
        {
            Some(TlbFamily::Skylake) => Some(enc(0x85, 0x01)),
            Some(TlbFamily::SunnyCove) => Some(enc(0x85, 0x0E)),
            Some(TlbFamily::GoldenCove) => Some(enc(0x11, 0x0E)),
            None => None,
        },
    }
}

/// The events a CPU counts, as a mask of [`PmuEvent::bit`]s.
#[must_use]
pub fn events(perfmon: &Perfmon, model: Model, core: CoreType) -> u16
{
    PmuEvent::ALL
        .iter()
        .filter(|&&e| encoding(perfmon, model, core, e).is_some())
        .fold(0, |m, e| m | e.bit())
}

/// The general-purpose event select that counts `enc` in `mode`: the
/// event, the unit mask, `USR` and `OS` by the mode, and `EN`. It never
/// sets `INT`, `AnyThread`, `INV`, `E` or a counter mask.
#[must_use]
pub fn event_select(enc: Encoding, mode: PmuMode) -> u64
{
    let mut sel = u64::from(enc.event) | (u64::from(enc.umask) << 8) | SEL_EN;
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

    /// CPUID 0AH of a Skylake client: version 4, four 48-bit general
    /// counters, a 7-bit vector with every event available, three fixed
    /// counters.
    const SKL: (u32, u32, u32) = (0x0730_0404, 0, 0x0000_0603);

    fn skl() -> Perfmon
    {
        Perfmon::decode(SKL.0, SKL.1, SKL.2).unwrap()
    }

    // Defect guarded: a field read from the wrong bits of EAX or EDX, or a
    // TCG CPU (all zero) taken for one with a PMU.
    #[test]
    fn leaf_0ah_decodes_each_field()
    {
        let p = skl();
        assert_eq!((p.version, p.general, p.width, p.fixed), (4, 4, 48, 3));
        assert_eq!(p.unavailable, u32::MAX << 7);
        assert_eq!(Perfmon::decode(0, 0, 0), None);
        assert_eq!(Perfmon::decode(0x0730_0001, 0, 0), None);
        // Version 1 reports no fixed counters, whatever EDX holds.
        assert_eq!(Perfmon::decode(0x0728_0201, 0, 0x603).unwrap().fixed, 0);
    }

    // Defect guarded: an event the EBX vector marks unavailable, or one past
    // the vector's length, given an encoding.
    #[test]
    fn architectural_events_follow_the_ebx_vector()
    {
        let m = Model::decode(0x0005_06E3);
        let p = skl();
        assert_eq!(
            encoding(&p, m, CoreType::Other, PmuEvent::Cycles),
            Some(Encoding {
                event: 0x3C,
                umask: 0
            })
        );
        assert_eq!(
            encoding(&p, m, CoreType::Other, PmuEvent::LlcMisses),
            Some(Encoding {
                event: 0x2E,
                umask: 0x41
            })
        );
        // EBX bit 6: branch misses unavailable.
        let p6 = Perfmon::decode(SKL.0, 1 << 6, SKL.2).unwrap();
        assert_eq!(
            encoding(&p6, m, CoreType::Other, PmuEvent::BranchMisses),
            None
        );
        // A vector of length 2 covers cycles and instructions alone.
        let short = Perfmon::decode(0x0230_0404, 0, SKL.2).unwrap();
        assert!(encoding(&short, m, CoreType::Other, PmuEvent::Instructions).is_some());
        assert_eq!(
            encoding(&short, m, CoreType::Other, PmuEvent::LlcReferences),
            None
        );
    }

    // Defect guarded: a TLB event programmed from another
    // microarchitecture's encoding, or on an unknown model or core type.
    #[test]
    fn tlb_events_come_from_the_model_table()
    {
        let p = skl();
        let at = |eax, core, e| encoding(&p, Model::decode(eax), core, e);
        // Skylake client, family 6 model 5EH.
        assert_eq!(
            at(0x0005_06E3, CoreType::Other, PmuEvent::DtlbMisses),
            Some(Encoding {
                event: 0x08,
                umask: 0x01
            })
        );
        // Tiger Lake, model 8CH.
        assert_eq!(
            at(0x0008_06C1, CoreType::Other, PmuEvent::ItlbMisses),
            Some(Encoding {
                event: 0x85,
                umask: 0x0E
            })
        );
        // Alder Lake, model 97H: by core type.
        assert_eq!(
            at(0x0009_0672, CoreType::Core, PmuEvent::DtlbMisses),
            Some(Encoding {
                event: 0x12,
                umask: 0x0E
            })
        );
        assert_eq!(
            at(0x0009_0672, CoreType::Atom, PmuEvent::DtlbMisses),
            Some(Encoding {
                event: 0x08,
                umask: 0x0E
            })
        );
        assert_eq!(at(0x0009_0672, CoreType::Other, PmuEvent::DtlbMisses), None);
        // An unlisted model (Haswell, 3CH).
        assert_eq!(at(0x0003_06C3, CoreType::Other, PmuEvent::ItlbMisses), None);
        assert_eq!(
            events(&p, Model::decode(0x0003_06C3), CoreType::Other),
            0b0011_1111
        );
        assert_eq!(
            events(&p, Model::decode(0x0005_06E3), CoreType::Other),
            0xFF
        );
    }

    // Defect guarded: the display model losing its extended bits, so every
    // model past 0FH misses the table.
    #[test]
    fn display_model_includes_the_extended_model()
    {
        assert_eq!(
            Model::decode(0x0009_0672),
            Model {
                family: 6,
                model: 0x97
            }
        );
        assert_eq!(Model::decode(0x00A2_0F12).family, 0x19);
        assert_eq!(CoreType::decode(0x2000_0000), CoreType::Atom);
        assert_eq!(CoreType::decode(0x4000_0001), CoreType::Core);
        assert_eq!(CoreType::decode(0), CoreType::Other);
    }

    // Defect guarded: a configuration given the kernel's counter, or more
    // general counters than the select MSRs the kernel writes.
    #[test]
    fn the_kernel_keeps_fixed_counter_1_or_the_top_general_counter()
    {
        assert_eq!(
            Layout::of(&skl()),
            Some(Layout {
                user: 4,
                reserved: Reserved::Fixed(1)
            })
        );
        let one_fixed = Perfmon::decode(0x0730_0402, 0, 0x0000_0601).unwrap();
        assert_eq!(
            Layout::of(&one_fixed),
            Some(Layout {
                user: 3,
                reserved: Reserved::General(3)
            })
        );
        let lone = Perfmon::decode(0x0730_0102, 0, 0).unwrap();
        assert_eq!(Layout::of(&lone), None);
        let wide = Perfmon::decode(0x0730_0A05, 0, 0x0000_0603).unwrap();
        assert_eq!(Layout::of(&wide).unwrap().user, MAX_GENERAL);
    }

    // Defect guarded: a select that sets INT, AnyThread, INV, E or a counter
    // mask, or that counts the mode it was not asked to.
    #[test]
    fn event_select_sets_only_event_umask_mode_and_enable()
    {
        let e = Encoding {
            event: 0x2E,
            umask: 0x4F,
        };
        assert_eq!(
            event_select(e, PmuMode::User),
            0x2E | 0x4F00 | SEL_USR | SEL_EN
        );
        assert_eq!(
            event_select(e, PmuMode::Kernel),
            0x2E | 0x4F00 | SEL_OS | SEL_EN
        );
        assert_eq!(
            event_select(e, PmuMode::All),
            0x2E | 0x4F00 | SEL_USR | SEL_OS | SEL_EN
        );
        assert_eq!(event_select(e, PmuMode::All) & 0xFFFF_FFFF_FFBC_0000, 0);
    }
}
