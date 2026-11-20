// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/memmgr/free-pool/src/pressure.rs

//! Memory-pressure levels: how close the free pool's pages outside `promised`
//! (`services/memmgr/docs/memory-pool.md` § Commit) are to the floor growth
//! outside the system reserve must leave ([`growth_floor`]), with hysteresis so a pool that hovers at a threshold does not flip the
//! level on every turn of memmgr's receive loop. memmgr signals every
//! registered process when the level changes
//! (`services/memmgr/docs/memory-pool.md` § Memory pressure).

use crate::budget::growth_floor;

/// The level is `Low` while the free pool holds fewer than
/// `pool_total / PRESSURE_LOW_DIVISOR` pages. A tuning value proportional to
/// RAM (docs/limits.md § memmgr): an early warning well above the reserve.
pub const PRESSURE_LOW_DIVISOR: u64 = 16;

/// The hysteresis band is `pool_total / PRESSURE_BAND_DIVISOR` pages, and at
/// least one: a level is left for a better one only once the free pool clears
/// that level's threshold by the band. A tuning value proportional to RAM
/// (docs/limits.md § memmgr).
pub const PRESSURE_BAND_DIVISOR: u64 = 128;

/// The hysteresis band of a pool of `pool_total` pages:
/// `pool_total / PRESSURE_BAND_DIVISOR` pages, and at least one.
#[must_use]
pub const fn band(pool_total: u64) -> u64
{
    let band = pool_total / PRESSURE_BAND_DIVISOR;
    if band == 0 { 1 } else { band }
}

/// A memory-pressure level, ordered from the least pressure to the most.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PressureLevel
{
    /// The free pool is at or above the low threshold.
    Normal,
    /// The free pool is below `pool_total / PRESSURE_LOW_DIVISOR` pages.
    Low,
    /// The free pool is at or below the growth floor, the system reserve and
    /// the restore headroom ([`growth_floor`]): a charge to a node outside
    /// the reserve that would take a page is refused.
    Critical,
}

/// The bits a `REGISTER_PRESSURE` registrant asked memmgr to send
/// (`services/memmgr/docs/ipc-interface.md` § Label 11): `level` on a change
/// of the level, `draw_room` on an opening of the draw room, `0` for none.
/// Each mask lies in the low 32 bits of the Notification word, so the pair
/// fits the process's caps slot beside its other caps.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PressureBits
{
    pub level: u32,
    pub draw_room: u32,
}

/// What one turn of memmgr's receive loop signals to the registrants: a
/// change of the level, an opening of the draw room, or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PressureSignal
{
    pub level: bool,
    pub draw_room: bool,
}

impl PressureBits
{
    /// The registration `REGISTER_PRESSURE`'s `data[0]` and `data[1]` ask
    /// for, the level bits and the draw-room bits; `None`, refused, when the
    /// level bits are `0` or either mask has a bit above the low 32.
    #[must_use]
    pub fn from_words(level: u64, draw_room: u64) -> Option<Self>
    {
        let level = u32::try_from(level).ok().filter(|&bits| bits != 0)?;
        let draw_room = u32::try_from(draw_room).ok()?;
        Some(Self { level, draw_room })
    }

    /// The bits to send for `signal`: the level bits on a change of level and
    /// the draw-room bits on an opening of the draw room, so a registrant
    /// whose two masks differ tells from a wake which happened; `0` sends
    /// nothing.
    #[must_use]
    pub fn for_signal(self, signal: PressureSignal) -> u64
    {
        let level = if signal.level { self.level } else { 0 };
        let draw_room = if signal.draw_room { self.draw_room } else { 0 };
        u64::from(level) | u64::from(draw_room)
    }
}

/// The level `free` pages give against `pool_total`, `swapped` of whose
/// pages are swapped chunks of uncommitted regions, which the restore headroom
/// counts ([`growth_floor`]), with no hysteresis.
fn classify(free: u64, pool_total: u64, swapped: u64) -> PressureLevel
{
    if free <= growth_floor(pool_total, swapped)
    {
        PressureLevel::Critical
    }
    else if free < pool_total / PRESSURE_LOW_DIVISOR
    {
        PressureLevel::Low
    }
    else
    {
        PressureLevel::Normal
    }
}

/// The level after `prev`, for `free` pages of the free pool outside
/// `promised` (deferred pages excluded) out of `pool_total`, with `swapped`
/// pages of uncommitted regions swapped (`Ledger::uncommitted_swapped`).
///
/// A worse level applies at once. A better one applies only once the free
/// pool clears its threshold by the hysteresis band: the result is the level
/// `free` less the band gives, held at `prev` at most. So `Critical` is left
/// once `free` exceeds the growth floor plus the band, and `Low` once `free`
/// reaches the low threshold plus the band, while a pool that moves inside a
/// band keeps its level.
#[must_use]
pub fn pressure_level(
    prev: PressureLevel,
    free: u64,
    pool_total: u64,
    swapped: u64,
) -> PressureLevel
{
    let raw = classify(free, pool_total, swapped);
    if raw >= prev
    {
        return raw;
    }
    classify(free.saturating_sub(band(pool_total)), pool_total, swapped).min(prev)
}

#[cfg(test)]
mod tests
{
    use super::PressureLevel::{Critical, Low, Normal};
    use super::*;
    use crate::budget::reserve_pages;

    /// A pool of 128 Ki pages (512 MiB): reserve 2048, low threshold 8192,
    /// band 1024.
    const TOTAL: u64 = 128 * 1024;
    const RESERVE: u64 = TOTAL / 64;
    const LOW: u64 = TOTAL / PRESSURE_LOW_DIVISOR;
    const BAND: u64 = TOTAL / PRESSURE_BAND_DIVISOR;

    #[test]
    fn thresholds_sit_where_the_constants_put_them()
    {
        assert_eq!(reserve_pages(TOTAL), RESERVE);
        assert_eq!(pressure_level(Normal, LOW, TOTAL, 0), Normal);
        assert_eq!(pressure_level(Normal, LOW - 1, TOTAL, 0), Low);
        assert_eq!(pressure_level(Normal, RESERVE + 1, TOTAL, 0), Low);
        assert_eq!(pressure_level(Normal, RESERVE, TOTAL, 0), Critical);
        assert_eq!(pressure_level(Normal, 0, TOTAL, 0), Critical);
    }

    #[test]
    fn worsening_applies_at_once()
    {
        assert_eq!(pressure_level(Normal, LOW - 1, TOTAL, 0), Low);
        assert_eq!(pressure_level(Low, RESERVE, TOTAL, 0), Critical);
        assert_eq!(pressure_level(Normal, RESERVE, TOTAL, 0), Critical);
    }

    #[test]
    fn critical_is_left_only_past_the_reserve_and_the_band()
    {
        assert_eq!(pressure_level(Critical, RESERVE + 1, TOTAL, 0), Critical);
        assert_eq!(pressure_level(Critical, RESERVE + BAND, TOTAL, 0), Critical);
        assert_eq!(pressure_level(Critical, RESERVE + BAND + 1, TOTAL, 0), Low);
    }

    #[test]
    fn low_is_left_only_at_the_threshold_plus_the_band()
    {
        assert_eq!(pressure_level(Low, LOW, TOTAL, 0), Low);
        assert_eq!(pressure_level(Low, LOW + BAND - 1, TOTAL, 0), Low);
        assert_eq!(pressure_level(Low, LOW + BAND, TOTAL, 0), Normal);
    }

    #[test]
    fn critical_goes_straight_to_normal_on_a_large_release()
    {
        assert_eq!(pressure_level(Critical, LOW + BAND, TOTAL, 0), Normal);
        assert_eq!(pressure_level(Critical, LOW + BAND - 1, TOTAL, 0), Low);
        assert_eq!(pressure_level(Critical, TOTAL, TOTAL, 0), Normal);
    }

    #[test]
    fn a_pool_moving_inside_a_band_keeps_its_level()
    {
        let mut level = pressure_level(Normal, LOW - 1, TOTAL, 0);
        for free in (LOW - 1..LOW + BAND).chain((LOW..LOW + BAND).rev())
        {
            level = pressure_level(level, free, TOTAL, 0);
            assert_eq!(level, Low, "free {free}");
        }
        let mut level = pressure_level(Low, RESERVE, TOTAL, 0);
        for free in (RESERVE..=RESERVE + BAND).chain((RESERVE..=RESERVE + BAND).rev())
        {
            level = pressure_level(level, free, TOTAL, 0);
            assert_eq!(level, Critical, "free {free}");
        }
    }

    #[test]
    fn a_tiny_pool_keeps_a_band_of_one_page()
    {
        // 64 pages: reserve 1, low threshold 4, band 1.
        assert_eq!(pressure_level(Normal, 1, 64, 0), Critical);
        assert_eq!(pressure_level(Critical, 2, 64, 0), Critical);
        assert_eq!(pressure_level(Critical, 3, 64, 0), Low);
        assert_eq!(pressure_level(Low, 4, 64, 0), Low);
        assert_eq!(pressure_level(Low, 5, 64, 0), Normal);
        assert_eq!(pressure_level(Normal, 0, 0, 0), Critical);
    }

    #[test]
    fn critical_moves_with_the_restore_headroom()
    {
        // 300 pages swapped: CRITICAL up to the reserve and 300 pages, left
        // past that and the band; with nothing swapped, at the reserve.
        assert_eq!(pressure_level(Normal, RESERVE + 300, TOTAL, 300), Critical);
        assert_eq!(pressure_level(Normal, RESERVE + 301, TOTAL, 300), Low);
        assert_eq!(pressure_level(Normal, RESERVE, TOTAL, 0), Critical);
        assert_eq!(pressure_level(Normal, RESERVE + 1, TOTAL, 0), Low);
        assert_eq!(
            pressure_level(Critical, RESERVE + 300 + BAND, TOTAL, 300),
            Critical
        );
        assert_eq!(
            pressure_level(Critical, RESERVE + 300 + BAND + 1, TOTAL, 300),
            Low
        );
        // The headroom is at most the reserve, so LOW's threshold stays above
        // CRITICAL's.
        assert_eq!(pressure_level(Normal, 2 * RESERVE, TOTAL, TOTAL), Critical);
        assert_eq!(pressure_level(Normal, 2 * RESERVE + 1, TOTAL, TOTAL), Low);
        assert_eq!(pressure_level(Normal, LOW, TOTAL, TOTAL), Normal);
    }

    #[test]
    fn a_registration_takes_nonzero_level_bits_and_two_32_bit_masks()
    {
        assert_eq!(
            PressureBits::from_words(1, 2),
            Some(PressureBits {
                level: 1,
                draw_room: 2
            })
        );
        // No draw-room bits: openings are not signalled.
        assert_eq!(
            PressureBits::from_words(1 << 31, 0),
            Some(PressureBits {
                level: 1 << 31,
                draw_room: 0
            })
        );
        assert_eq!(PressureBits::from_words(0, 2), None);
        assert_eq!(PressureBits::from_words(1 << 32, 0), None);
        assert_eq!(PressureBits::from_words(1, 1 << 32), None);
    }

    #[test]
    fn a_level_wake_carries_the_level_bits_and_an_opening_the_draw_room_bits()
    {
        let bits = PressureBits {
            level: 0b01,
            draw_room: 0b10,
        };
        let signal = |level, draw_room| PressureSignal { level, draw_room };
        assert_eq!(bits.for_signal(signal(true, false)), 0b01);
        assert_eq!(bits.for_signal(signal(false, true)), 0b10);
        assert_eq!(bits.for_signal(signal(true, true)), 0b11);
        assert_eq!(bits.for_signal(signal(false, false)), 0);
        // A registrant with no draw-room bits is sent nothing on an opening.
        let level_only = PressureBits {
            level: 0b100,
            draw_room: 0,
        };
        assert_eq!(level_only.for_signal(signal(false, true)), 0);
        assert_eq!(level_only.for_signal(signal(true, true)), 0b100);
    }
}
