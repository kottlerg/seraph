// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/lines.rs

//! The interrupt lines devmgr holds, one single-line cap per GSI.
//!
//! devmgr splits a line's single-line `Interrupt` cap off its range cap the
//! first time a device on that line asks for it, and keeps it for the boot.
//! Every device on the line, the first included, is given a derivation of
//! that held cap, never the held cap itself: each derivation is an Interrupt
//! object of its own, so each driver binds and acknowledges its own binding
//! on the line (docs/device-management.md § Interrupt Delivery), and
//! releasing one device's derivation leaves the line held for the others.
//! [`HeldLines`] decides when a line is split and remembers the held cap; the
//! split and the derivation are the caller's closures, so the policy is
//! host-tested here.

extern crate alloc;

use alloc::vec::Vec;

use crate::resource::CarveError;

/// Why [`HeldLines::hold`] holds no cap for a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HoldError
{
    /// The line could not be split off the range: `NotCovered` when no held
    /// range contains it, any other carve error otherwise. Nothing is held,
    /// so a later request tries the split again.
    Split(CarveError),
    /// The table could not grow to record a newly split line; nothing was
    /// split.
    NoMemory,
}

/// Why [`HeldLines::derive`] gave no cap for a line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineError<E>
{
    /// The line is not held ([`HoldError`]).
    Hold(HoldError),
    /// The line is held, but deriving a cap from it failed with this error.
    Derive(E),
}

/// The lines devmgr holds: GSI and the single-line cap split for it.
pub struct HeldLines<C>
{
    lines: Vec<(u32, C)>,
}

impl<C: Copy> Default for HeldLines<C>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<C: Copy> HeldLines<C>
{
    /// A table holding no line.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { lines: Vec::new() }
    }

    /// The held cap for `gsi`, splitting it off the range through `split`
    /// the first time the line is asked for. A line is split at most once:
    /// later requests for it reuse the held cap.
    ///
    /// # Errors
    /// [`HoldError::NoMemory`] when the table cannot grow to hold a new line,
    /// before anything is split; [`HoldError::Split`] with `split`'s error,
    /// nothing held.
    pub fn hold<S>(&mut self, gsi: u32, split: S) -> Result<C, HoldError>
    where
        S: FnOnce(u32) -> Result<C, CarveError>,
    {
        if let Some(cap) = self.held(gsi)
        {
            return Ok(cap);
        }
        self.lines.try_reserve(1).map_err(|_| HoldError::NoMemory)?;
        let cap = split(gsi).map_err(HoldError::Split)?;
        self.lines.push((gsi, cap));
        Ok(cap)
    }

    /// A device's own cap on line `gsi`: a derivation, through `derive`, of
    /// the held cap [`hold`](Self::hold) returns.
    ///
    /// # Errors
    /// [`LineError::Hold`] with [`hold`](Self::hold)'s error, and
    /// [`LineError::Derive`] with `derive`'s error, the line staying held.
    pub fn derive<S, D, E>(&mut self, gsi: u32, split: S, derive: D) -> Result<C, LineError<E>>
    where
        S: FnOnce(u32) -> Result<C, CarveError>,
        D: FnOnce(C) -> Result<C, E>,
    {
        let held = self.hold(gsi, split).map_err(LineError::Hold)?;
        derive(held).map_err(LineError::Derive)
    }

    /// The held cap for `gsi`, if the line is held.
    #[must_use]
    pub fn held(&self, gsi: u32) -> Option<C>
    {
        self.lines
            .iter()
            .find(|(g, _)| *g == gsi)
            .map(|&(_, cap)| cap)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use core::cell::Cell;

    /// A split that hands out caps `100 + gsi` and counts its calls.
    fn counting_split(calls: &Cell<u32>) -> impl Fn(u32) -> Result<u32, CarveError> + '_
    {
        move |gsi| {
            calls.set(calls.get() + 1);
            Ok(100 + gsi)
        }
    }

    #[test]
    fn devices_on_one_line_split_it_once_and_each_get_a_derivation()
    {
        let mut lines = HeldLines::new();
        let splits = Cell::new(0);
        let derived = Cell::new(0u32);
        let derive = |held: u32| -> Result<u32, ()> {
            derived.set(derived.get() + 1);
            Ok(held * 10 + derived.get())
        };
        let first = lines.derive(33, counting_split(&splits), derive);
        let second = lines.derive(33, counting_split(&splits), derive);
        assert_eq!(splits.get(), 1);
        // Both derive from the one held cap (133), and they are distinct.
        assert_eq!(first, Ok(1331));
        assert_eq!(second, Ok(1332));
        assert_eq!(lines.held(33), Some(133));
    }

    #[test]
    fn distinct_lines_are_split_separately()
    {
        let mut lines = HeldLines::new();
        let splits = Cell::new(0);
        assert_eq!(lines.hold(32, counting_split(&splits)), Ok(132));
        assert_eq!(lines.hold(34, counting_split(&splits)), Ok(134));
        assert_eq!(lines.hold(32, counting_split(&splits)), Ok(132));
        assert_eq!(splits.get(), 2);
    }

    #[test]
    fn a_failed_split_holds_nothing_and_is_tried_again()
    {
        let mut lines: HeldLines<u32> = HeldLines::new();
        assert_eq!(
            lines.hold(40, |_| Err(CarveError::NotCovered)),
            Err(HoldError::Split(CarveError::NotCovered))
        );
        assert_eq!(lines.held(40), None);
        // A later request splits again; once it succeeds the line is held.
        assert_eq!(lines.hold(40, |g| Ok(g + 1)), Ok(41));
        assert_eq!(lines.held(40), Some(41));
    }

    #[test]
    fn a_failed_derivation_keeps_the_line_held()
    {
        let mut lines = HeldLines::new();
        let result = lines.derive(35, Ok, |_held| Err::<u32, &str>("no slot"));
        assert_eq!(result, Err(LineError::Derive("no slot")));
        assert_eq!(lines.held(35), Some(35));
        // The next device on the line derives from the same held cap.
        assert_eq!(
            lines.derive(
                35,
                |_| panic!("held; no second split"),
                |held| Ok::<_, &str>(held + 1)
            ),
            Ok(36)
        );
    }
}
