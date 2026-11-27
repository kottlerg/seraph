// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/bench/src/window.rs

//! Window-mean measurements: a benchmark whose thread may run on another CPU
//! between its two counter reads times windows of several operations, each
//! sample the mean per operation of one window
//! (`shared/bench/README.md` § Window-mean rows).
//!
//! The thread reads the counters on the CPU it measures on, at the opening and
//! at the closing of each window. A window counts only when both reads ran on
//! that CPU and the CPU did not halt between them: the idle-halt span the
//! thread opens and closes around the window says both, since its close fails
//! on another CPU than its open's and otherwise returns the halts between them.
//! The rest are left out and counted. A row whose counted windows fall below
//! [`WindowShape::floor`] reports no sample.

/// Operations per window when the benchmark runs at least this many.
pub const WINDOW_OPS: u32 = 16;

/// The extra naming the operations each sample is the mean of.
pub const WINDOW_OPS_KEY: &str = "window_ops";

/// The extra counting the windows left out because a read ran on another CPU
/// than the one measured on.
pub const MOVED: &str = "moved";

/// The extra counting the windows left out because the measuring CPU halted
/// inside them.
pub const HALTED: &str = "halted";

/// How a benchmark's operations split into windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowShape
{
    /// Operations in each window.
    pub ops: u32,
    /// Windows timed.
    pub windows: u32,
}

impl WindowShape
{
    /// Split `total` operations into windows of [`WINDOW_OPS`], or one window
    /// of all of them when there are fewer; operations past the last whole
    /// window are not run. `None` for no operation.
    #[must_use]
    pub fn for_ops(total: u32) -> Option<Self>
    {
        let ops = total.min(WINDOW_OPS);
        let windows = total.checked_div(ops)?;
        Some(Self { ops, windows })
    }

    /// The fewest counted windows a row reports a sample from: half the
    /// windows, rounded up. Fewer leave the row the mean of the windows the
    /// pair happened to stay together in, not of the case.
    #[must_use]
    pub const fn floor(self) -> u32
    {
        self.windows.div_ceil(2)
    }
}

/// How one window ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowEnd
{
    /// Both reads on the measuring CPU, which did not halt between them.
    Counted,
    /// The idle-halt span did not close on the CPU it opened on, so a read
    /// may have run on another CPU.
    Moved,
    /// The measuring CPU halted inside the window.
    Halted,
}

impl WindowEnd
{
    /// Classify a window by its idle-halt span's close: `None` when the close
    /// failed, otherwise the halts since the open.
    #[must_use]
    pub const fn from_close(halts: Option<u64>) -> Self
    {
        match halts
        {
            None => Self::Moved,
            Some(0) => Self::Counted,
            Some(_) => Self::Halted,
        }
    }
}

/// The windows of one row by how they ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WindowTally
{
    /// Windows that gave a sample.
    pub counted: u32,
    /// Windows left out as [`WindowEnd::Moved`].
    pub moved: u32,
    /// Windows left out as [`WindowEnd::Halted`].
    pub halted: u32,
}

impl WindowTally
{
    /// Count one window's end.
    pub fn record(&mut self, end: WindowEnd)
    {
        let slot = match end
        {
            WindowEnd::Counted => &mut self.counted,
            WindowEnd::Moved => &mut self.moved,
            WindowEnd::Halted => &mut self.halted,
        };
        *slot = slot.saturating_add(1);
    }

    /// Whether the counted windows reach `shape`'s floor, so the row reports
    /// its samples.
    #[must_use]
    pub const fn reaches_floor(&self, shape: WindowShape) -> bool
    {
        self.counted >= shape.floor()
    }
}

/// The mean per operation of a window whose two reads differ by `elapsed`
/// over `ops` operations, rounded down; `elapsed` itself for no operation.
#[must_use]
pub fn window_mean(elapsed: u64, ops: u32) -> u64
{
    elapsed.checked_div(u64::from(ops)).unwrap_or(elapsed)
}

#[cfg(test)]
mod tests
{
    use super::{WINDOW_OPS, WindowEnd, WindowShape, WindowTally, window_mean};

    #[test]
    fn operations_split_into_whole_windows_of_at_most_the_window_size()
    {
        assert_eq!(WindowShape::for_ops(0), None);
        assert_eq!(
            WindowShape::for_ops(8),
            Some(WindowShape { ops: 8, windows: 1 })
        );
        assert_eq!(
            WindowShape::for_ops(256),
            Some(WindowShape {
                ops: WINDOW_OPS,
                windows: 16
            })
        );
        // 40 = 2 whole windows of 16; the 8 past them are not run.
        assert_eq!(
            WindowShape::for_ops(40),
            Some(WindowShape {
                ops: 16,
                windows: 2
            })
        );
    }

    #[test]
    fn the_floor_is_half_the_windows_rounded_up()
    {
        let shape = |windows| WindowShape { ops: 16, windows };
        assert_eq!(shape(16).floor(), 8);
        assert_eq!(shape(3).floor(), 2);
        assert_eq!(shape(1).floor(), 1);
    }

    #[test]
    fn a_window_counts_only_when_its_span_closed_with_no_halt()
    {
        assert_eq!(WindowEnd::from_close(Some(0)), WindowEnd::Counted);
        assert_eq!(WindowEnd::from_close(Some(3)), WindowEnd::Halted);
        assert_eq!(WindowEnd::from_close(None), WindowEnd::Moved);
    }

    #[test]
    fn a_row_reports_once_its_counted_windows_reach_the_floor()
    {
        let shape = WindowShape {
            ops: 16,
            windows: 16,
        };
        let mut tally = WindowTally::default();
        for _ in 0..7
        {
            tally.record(WindowEnd::Counted);
        }
        tally.record(WindowEnd::Moved);
        tally.record(WindowEnd::Halted);
        assert_eq!(
            tally,
            WindowTally {
                counted: 7,
                moved: 1,
                halted: 1
            }
        );
        assert!(!tally.reaches_floor(shape));
        tally.record(WindowEnd::Counted);
        assert!(tally.reaches_floor(shape));
    }

    #[test]
    fn a_window_mean_divides_by_its_operations_rounding_down()
    {
        assert_eq!(window_mean(1607, 16), 100);
        assert_eq!(window_mean(42, 0), 42);
    }
}
