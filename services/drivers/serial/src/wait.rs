// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/serial/src/wait.rs

//! The bound on a wait for the transmitter.
//!
//! A write waits on the transmitter twice: for room in the transmit ring,
//! and, when the write asks for it, for its bytes to leave the UART. Either
//! wait ends once the transmitter has made no progress for [`TX_STALL_MS`]:
//! a UART that takes no byte (a wedged device, or a transmitter thread a
//! debugger stopped) holds a writer for that long at most, and a transmitter
//! that is merely slow (a long queue at a low baud) holds it as long as it
//! keeps taking bytes.

/// Milliseconds a write waits on a transmitter that makes no progress
/// before it is refused (`serial_errors::STALLED`): logd's sink stall bound
/// (`SINK_STALL_MS`), so a stalled UART is reported by the driver no later
/// than logd would give up on it (`docs/limits.md`).
pub const TX_STALL_MS: u64 = 1000;

/// A wait that ends once the progress count it watches has not moved for its
/// bound. Times are milliseconds on any monotonic clock.
pub struct StallWatch
{
    bound_ms: u64,
    seen: u64,
    since_ms: u64,
}

impl StallWatch
{
    /// A watch over a count that reads `progress` at `now_ms`.
    #[must_use]
    pub const fn new(bound_ms: u64, progress: u64, now_ms: u64) -> Self
    {
        Self {
            bound_ms,
            seen: progress,
            since_ms: now_ms,
        }
    }

    /// The milliseconds the wait may still sleep, given the count reads
    /// `progress` at `now_ms`; `None` once the count has not moved for
    /// the bound. A count that moved restarts the bound.
    pub const fn remaining(&mut self, progress: u64, now_ms: u64) -> Option<u64>
    {
        if progress != self.seen
        {
            self.seen = progress;
            self.since_ms = now_ms;
        }
        let left = self
            .bound_ms
            .saturating_sub(now_ms.saturating_sub(self.since_ms));
        if left == 0 { None } else { Some(left) }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a wait that never ends on a transmitter that takes no
    // byte, which would hold a writer, and logd's power-off barrier, for good.
    #[test]
    fn a_wait_without_progress_ends_at_the_bound()
    {
        let mut watch = StallWatch::new(1000, 7, 100);
        assert_eq!(watch.remaining(7, 100), Some(1000));
        assert_eq!(watch.remaining(7, 600), Some(500));
        assert_eq!(watch.remaining(7, 1099), Some(1));
        assert_eq!(watch.remaining(7, 1100), None);
    }

    // Defect caught: a slow transmitter refused while it still takes bytes,
    // which would drop output a long queue holds.
    #[test]
    fn progress_restarts_the_bound()
    {
        let mut watch = StallWatch::new(1000, 0, 0);
        assert_eq!(watch.remaining(0, 900), Some(100));
        assert_eq!(watch.remaining(16, 950), Some(1000));
        assert_eq!(watch.remaining(16, 1949), Some(1));
        assert_eq!(watch.remaining(16, 1950), None);
    }

    // Defect caught: a clock read earlier than the watch's start read as a
    // huge elapsed time, ending the wait at once.
    #[test]
    fn an_earlier_clock_reading_does_not_end_the_wait()
    {
        let mut watch = StallWatch::new(1000, 0, 500);
        assert_eq!(watch.remaining(0, 400), Some(1000));
    }
}
