// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/arch/x86_64/timer_rate.rs

//! x86-64 timer rates: which source gives the TSC rate, and the arithmetic of
//! each source, as pure functions of the values the boot CPU probed.
//!
//! [`select`] takes the TSC rate from the first of three sources, ordered by
//! accuracy:
//!
//! 1. CPUID leaf 0x15 where it enumerates the core crystal's frequency (ECX)
//!    and the TSC-to-crystal ratio (EBX / EAX): exact, and no device is
//!    involved.
//! 2. The 8254 PIT, measured over one channel-2 window, where leaf 0x15 gives
//!    no crystal frequency.
//! 3. Only where the 8254 window gives no plausible rate (an absent or
//!    gated-off 8254): the processor base frequency of CPUID leaf 0x16, where
//!    leaf 0x15 enumerates the ratio. Linux derives the crystal from it
//!    (`base * EAX / EBX`) and the TSC rate from the crystal (`* EBX / EAX`),
//!    so the rate is the base frequency itself; the enumerated ratio is what
//!    marks a TSC that runs at that nominal frequency. Leaf 0x16 is in whole
//!    MHz, so this rate is approximate.
//!
//! Every source's rate must lie in [`TSC_RATE_MIN_HZ`]..=[`TSC_RATE_MAX_HZ`]
//! to be taken. The 8254 is measured only when source 1 gives nothing, through
//! the closure [`select`] is handed, so the probes stay in
//! [`super::timer`] and the order is tested here.
//!
//! [`apic_ticks_per_sec`] scales a local-APIC timer count measured over a TSC
//! window to a rate, the one path every TSC source shares.

/// 8254 PIT input clock (Hz).
pub const PIT_HZ: u64 = 1_193_182;

/// Lowest TSC rate taken from any source: 100 MHz. Every CPU with an invariant
/// TSC that meets the platform floor runs it at its nominal frequency, several
/// hundred MHz at the least, so a lower reading is a fault of the source: an
/// 8254 window that ended at once (an undecoded port 0x61 reads all ones) gives
/// a rate near zero.
pub const TSC_RATE_MIN_HZ: u64 = 100_000_000;

/// Highest TSC rate taken from any source: 10 GHz, the fastest plausible rate
/// the 8254 poll budget is set against. A higher reading is a fault of the
/// source: an 8254 window that ran long because the PIT counted slow.
pub const TSC_RATE_MAX_HZ: u64 = 10_000_000_000;

/// CPUID leaf 0x15 (Time Stamp Counter and Nominal Core Crystal Clock
/// Information), as read on the boot CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf15
{
    /// EAX: the denominator of the TSC-to-crystal ratio.
    pub denominator: u32,
    /// EBX: the numerator of the TSC-to-crystal ratio; 0 when the ratio is not
    /// enumerated.
    pub numerator: u32,
    /// ECX: the core crystal's nominal frequency in Hz; 0 when not enumerated.
    pub crystal_hz: u32,
}

impl Leaf15
{
    /// Whether the leaf enumerates the TSC-to-crystal ratio.
    fn has_ratio(self) -> bool
    {
        self.denominator != 0 && self.numerator != 0
    }
}

/// What one 8254 channel-2 window measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PitWindow
{
    /// The channel-2 output rose after this many TSC ticks.
    Expired
    {
        /// TSC ticks from the gate-enable to the output rising.
        tsc_ticks: u64,
    },
    /// The output never rose within the poll budget.
    NeverExpired,
}

/// Why the 8254 gave no TSC rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PitFault
{
    /// The channel-2 output never rose within the poll budget.
    NeverExpired,
    /// The window gave a TSC rate outside the plausible range (Hz).
    Implausible
    {
        /// The rate the window gave.
        hz: u64,
    },
}

/// The source a TSC rate was taken from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source
{
    /// Source 1: leaf 0x15's crystal frequency and ratio.
    Crystal(Leaf15),
    /// Source 2: an 8254 channel-2 window.
    Pit,
    /// Source 3: leaf 0x16's base frequency, approximate; taken because the
    /// 8254 gave no rate.
    BaseFrequency
    {
        /// Leaf 0x16 EAX[15:0], the processor base frequency in MHz.
        base_mhz: u32,
        /// Why the 8254 gave no rate.
        pit: PitFault,
    },
}

/// A TSC rate and the source it was taken from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TscRate
{
    /// TSC ticks per second.
    pub hz: u64,
    /// The source the rate was taken from.
    pub source: Source,
}

/// No source gave a TSC rate. Leaf 0x15 gave no crystal rate and leaf 0x16 no
/// base frequency (the caller holds both leaves); `pit` says why the 8254 gave
/// none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NoSource
{
    /// Why the 8254 gave no rate.
    pub pit: PitFault,
}

/// Whether `hz` is a TSC rate any source may give.
pub fn plausible(hz: u64) -> bool
{
    (TSC_RATE_MIN_HZ..=TSC_RATE_MAX_HZ).contains(&hz)
}

/// Source 1: the TSC rate leaf 0x15 enumerates (crystal x EBX / EAX), or
/// `None` when the leaf leaves the crystal frequency or the ratio unenumerated
/// or the product is implausible.
pub fn crystal_rate(leaf: Leaf15) -> Option<u64>
{
    if leaf.crystal_hz == 0 || !leaf.has_ratio()
    {
        return None;
    }
    // Two u32 factors: the product fits u64, and the denominator is non-zero.
    let hz = u64::from(leaf.crystal_hz)
        .checked_mul(u64::from(leaf.numerator))?
        .checked_div(u64::from(leaf.denominator))?;
    plausible(hz).then_some(hz)
}

/// Source 2: the TSC rate one 8254 window gives, `tsc_ticks` over `pit_counts`
/// PIT counts, or the fault that makes the 8254 count as not working.
pub fn pit_rate(window: PitWindow, pit_counts: u16) -> Result<u64, PitFault>
{
    let PitWindow::Expired { tsc_ticks } = window
    else
    {
        return Err(PitFault::NeverExpired);
    };
    // In u128, ticks x PIT_HZ cannot overflow; a zero count gives no rate.
    let hz = u128::from(tsc_ticks)
        .saturating_mul(u128::from(PIT_HZ))
        .checked_div(u128::from(pit_counts))
        .map_or(0, |hz| u64::try_from(hz).unwrap_or(u64::MAX));
    if plausible(hz)
    {
        Ok(hz)
    }
    else
    {
        Err(PitFault::Implausible { hz })
    }
}

/// Source 3: the base frequency of leaf 0x16 as the TSC rate, where leaf 0x15
/// enumerates the ratio and the rate is plausible.
pub fn base_frequency_rate(leaf15: Option<Leaf15>, base_mhz: Option<u32>) -> Option<u64>
{
    let base_mhz = base_mhz.filter(|&mhz| mhz != 0)?;
    if !leaf15.is_some_and(Leaf15::has_ratio)
    {
        return None;
    }
    // A u32 of MHz fits u64 in Hz.
    let hz = u64::from(base_mhz).saturating_mul(1_000_000);
    plausible(hz).then_some(hz)
}

/// Take the TSC rate from the first source that gives one, in the order the
/// module documentation sets.
///
/// `leaf15` is `None` where the CPU's maximum basic leaf is below 0x15;
/// `base_mhz` is leaf 0x16 EAX[15:0], `None` where the maximum leaf is below
/// 0x16. `measure_pit` runs one 8254 window of `pit_counts` counts; it is
/// called only when leaf 0x15 gives no rate.
pub fn select(
    leaf15: Option<Leaf15>,
    base_mhz: Option<u32>,
    pit_counts: u16,
    measure_pit: impl FnOnce() -> PitWindow,
) -> Result<TscRate, NoSource>
{
    if let Some(leaf) = leaf15
        && let Some(hz) = crystal_rate(leaf)
    {
        return Ok(TscRate {
            hz,
            source: Source::Crystal(leaf),
        });
    }
    let pit = match pit_rate(measure_pit(), pit_counts)
    {
        Ok(hz) =>
        {
            return Ok(TscRate {
                hz,
                source: Source::Pit,
            });
        }
        Err(fault) => fault,
    };
    match (base_frequency_rate(leaf15, base_mhz), base_mhz)
    {
        (Some(hz), Some(base_mhz)) => Ok(TscRate {
            hz,
            source: Source::BaseFrequency { base_mhz, pit },
        }),
        _ => Err(NoSource { pit }),
    }
}

/// Local-APIC timer ticks per second from `apic_ticks` counted over a window of
/// `tsc_ticks` TSC ticks at `tsc_hz`, or `None` when the window is empty or the
/// timer did not count.
pub fn apic_ticks_per_sec(apic_ticks: u64, tsc_ticks: u64, tsc_hz: u64) -> Option<u64>
{
    // In u128: a 32-bit count times a rate up to TSC_RATE_MAX_HZ exceeds u64.
    let tps = u128::from(apic_ticks)
        .saturating_mul(u128::from(tsc_hz))
        .checked_div(u128::from(tsc_ticks))?;
    let tps = u64::try_from(tps).ok()?;
    (tps != 0).then_some(tps)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// A leaf 0x15 that enumerates the ratio but no crystal frequency, as on
    /// parts whose firmware leaves ECX zero.
    const RATIO_ONLY: Leaf15 = Leaf15 {
        denominator: 2,
        numerator: 216,
        crystal_hz: 0,
    };

    /// The window length the tests measure over, in PIT counts.
    const PIT_COUNTS: u16 = 2;

    #[test]
    fn crystal_rate_is_crystal_times_ratio()
    {
        let leaf = Leaf15 {
            denominator: 2,
            numerator: 216,
            crystal_hz: 24_000_000,
        };
        assert_eq!(crystal_rate(leaf), Some(2_592_000_000));
    }

    #[test]
    fn leaf_15_with_a_zero_field_gives_no_crystal_rate()
    {
        let full = Leaf15 {
            denominator: 2,
            numerator: 166,
            crystal_hz: 38_400_000,
        };
        assert_eq!(crystal_rate(full), Some(3_187_200_000));
        for leaf in [
            Leaf15 {
                denominator: 0,
                ..full
            },
            Leaf15 {
                numerator: 0,
                ..full
            },
            Leaf15 {
                crystal_hz: 0,
                ..full
            },
        ]
        {
            assert_eq!(crystal_rate(leaf), None, "{leaf:?}");
        }
    }

    #[test]
    fn implausible_crystal_rate_is_refused()
    {
        let slow = Leaf15 {
            denominator: 1,
            numerator: 1,
            crystal_hz: 24_000_000,
        };
        let fast = Leaf15 {
            denominator: 1,
            numerator: u32::MAX,
            crystal_hz: u32::MAX,
        };
        assert_eq!(crystal_rate(slow), None);
        assert_eq!(crystal_rate(fast), None);
    }

    #[test]
    fn plausible_range_includes_both_bounds()
    {
        assert!(plausible(TSC_RATE_MIN_HZ));
        assert!(plausible(TSC_RATE_MAX_HZ));
        assert!(!plausible(TSC_RATE_MIN_HZ - 1));
        assert!(!plausible(TSC_RATE_MAX_HZ + 1));
    }

    #[test]
    fn pit_rate_scales_window_ticks_by_the_pit_clock()
    {
        // 5000 TSC ticks over 2 PIT counts: 5000 x 1 193 182 / 2 Hz.
        let window = PitWindow::Expired { tsc_ticks: 5000 };
        assert_eq!(pit_rate(window, PIT_COUNTS), Ok(2_982_955_000));
    }

    #[test]
    fn pit_window_outside_the_plausible_range_counts_as_no_working_8254()
    {
        // An undecoded port 0x61 reads all ones: the window ends at once.
        assert_eq!(
            pit_rate(PitWindow::Expired { tsc_ticks: 0 }, PIT_COUNTS),
            Err(PitFault::Implausible { hz: 0 })
        );
        // About the microvm reading of 14 MHz: 23 ticks over 2 PIT counts.
        assert_eq!(
            pit_rate(PitWindow::Expired { tsc_ticks: 23 }, PIT_COUNTS),
            Err(PitFault::Implausible { hz: 13_721_593 })
        );
        // A window that ran long, up to the poll budget's end and past u64 on scaling.
        assert_eq!(
            pit_rate(
                PitWindow::Expired {
                    tsc_ticks: u64::MAX
                },
                PIT_COUNTS
            ),
            Err(PitFault::Implausible { hz: u64::MAX })
        );
        assert_eq!(
            pit_rate(PitWindow::Expired { tsc_ticks: 5000 }, 0),
            Err(PitFault::Implausible { hz: 0 })
        );
        assert_eq!(
            pit_rate(PitWindow::NeverExpired, PIT_COUNTS),
            Err(PitFault::NeverExpired)
        );
    }

    #[test]
    fn select_takes_leaf_15_without_measuring_the_8254()
    {
        let leaf = Leaf15 {
            crystal_hz: 25_000_000,
            ..RATIO_ONLY
        };
        let rate = select(Some(leaf), Some(2_700), PIT_COUNTS, || {
            panic!("the 8254 is measured only when leaf 0x15 gives no rate")
        });
        assert_eq!(
            rate,
            Ok(TscRate {
                hz: 2_700_000_000,
                source: Source::Crystal(leaf),
            })
        );
    }

    #[test]
    fn select_measures_the_8254_where_leaf_15_gives_no_crystal_rate()
    {
        for leaf15 in [None, Some(RATIO_ONLY)]
        {
            let rate = select(leaf15, Some(2_700), PIT_COUNTS, || PitWindow::Expired {
                tsc_ticks: 5000,
            });
            assert_eq!(
                rate,
                Ok(TscRate {
                    hz: 2_982_955_000,
                    source: Source::Pit,
                }),
                "{leaf15:?}"
            );
        }
    }

    #[test]
    fn select_takes_the_base_frequency_only_where_the_8254_fails()
    {
        let never = select(Some(RATIO_ONLY), Some(2_700), PIT_COUNTS, || {
            PitWindow::NeverExpired
        });
        assert_eq!(
            never,
            Ok(TscRate {
                hz: 2_700_000_000,
                source: Source::BaseFrequency {
                    base_mhz: 2_700,
                    pit: PitFault::NeverExpired,
                },
            })
        );
        let at_once = select(Some(RATIO_ONLY), Some(2_700), PIT_COUNTS, || {
            PitWindow::Expired { tsc_ticks: 0 }
        });
        assert_eq!(
            at_once.map(|rate| rate.source),
            Ok(Source::BaseFrequency {
                base_mhz: 2_700,
                pit: PitFault::Implausible { hz: 0 },
            })
        );
    }

    #[test]
    fn base_frequency_needs_the_leaf_15_ratio_and_a_base()
    {
        let no_ratio = Leaf15 {
            numerator: 0,
            ..RATIO_ONLY
        };
        for (leaf15, base_mhz) in [
            (None, Some(2_700)),
            (Some(no_ratio), Some(2_700)),
            (Some(RATIO_ONLY), Some(0)),
            (Some(RATIO_ONLY), None),
            // 50 MHz: below the plausible range.
            (Some(RATIO_ONLY), Some(50)),
        ]
        {
            let rate = select(leaf15, base_mhz, PIT_COUNTS, || PitWindow::NeverExpired);
            assert_eq!(
                rate,
                Err(NoSource {
                    pit: PitFault::NeverExpired,
                }),
                "{leaf15:?} {base_mhz:?}"
            );
        }
    }

    #[test]
    fn apic_rate_scales_the_count_by_the_tsc_window()
    {
        // 10 ms at 3 GHz, 625 000 APIC ticks: 62.5 MHz.
        assert_eq!(
            apic_ticks_per_sec(625_000, 30_000_000, 3_000_000_000),
            Some(62_500_000)
        );
        // A full 32-bit count at the fastest TSC overflows u64 before the division.
        assert_eq!(
            apic_ticks_per_sec(u64::from(u32::MAX), 100_000_000, TSC_RATE_MAX_HZ),
            Some(u64::from(u32::MAX) * 100)
        );
    }

    #[test]
    fn apic_rate_refuses_an_empty_window_or_a_stopped_timer()
    {
        assert_eq!(apic_ticks_per_sec(625_000, 0, 3_000_000_000), None);
        assert_eq!(apic_ticks_per_sec(0, 30_000_000, 3_000_000_000), None);
    }
}
