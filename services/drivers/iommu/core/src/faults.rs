// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/faults.rs

//! The faults an IOMMU driver has polled from its units and not yet handed
//! to devmgr (`ipc::iommu_labels::TAKE_FAULTS`).
//!
//! The driver's poll thread reads each unit's fault records into the queue
//! and clears them, so the unit's few records do not overflow while devmgr
//! has not asked; devmgr takes them, oldest first, and logs them per device.

use alloc::collections::VecDeque;

/// Faults the queue holds. Past it a newly polled fault is counted as
/// dropped and not kept; `docs/limits.md` classifies the bound.
pub const FAULT_QUEUE_CAPACITY: usize = 64;

/// One translation fault a unit recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fault
{
    /// The unit that recorded it.
    pub unit: usize,
    /// The requester's bus, device, and function (bus in bits 8..16).
    pub bdf: u16,
    /// The unit's fault reason code: VT-d's 8-bit fault reason, or the
    /// RISC-V IOMMU's 12-bit `CAUSE`.
    pub reason: u16,
    /// The faulting IOVA, page-aligned; for a VT-d interrupt-remapping fault
    /// (reason `0x20` and above), the remapping table handle the blocked
    /// interrupt named instead (`iommu_labels::TAKE_FAULTS`).
    pub iova: u64,
}

/// A bounded queue of polled faults.
pub struct FaultQueue
{
    faults: VecDeque<Fault>,
    dropped: u64,
}

impl FaultQueue
{
    /// An empty queue with its room reserved; `None` when the reservation
    /// fails.
    #[must_use]
    pub fn new() -> Option<Self>
    {
        let mut faults = VecDeque::new();
        faults.try_reserve_exact(FAULT_QUEUE_CAPACITY).ok()?;
        Some(Self { faults, dropped: 0 })
    }

    /// Queue `fault`, or count it dropped when the queue is full.
    pub fn push(&mut self, fault: Fault)
    {
        if self.faults.len() < FAULT_QUEUE_CAPACITY
        {
            self.faults.push_back(fault);
        }
        else
        {
            // The count is reset at every poll, so it cannot near `u64::MAX`.
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    /// Take up to `max` faults, oldest first, passing each to `take`.
    /// Returns how many were taken.
    pub fn take(&mut self, max: usize, take: impl FnMut(Fault)) -> usize
    {
        let n = max.min(self.faults.len());
        self.faults.drain(..n).for_each(take);
        n
    }

    /// Faults dropped since the last call, resetting the count.
    pub fn take_dropped(&mut self) -> u64
    {
        core::mem::take(&mut self.dropped)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn fault(iova: u64) -> Fault
    {
        Fault {
            unit: 0,
            bdf: 0x18,
            reason: 6,
            iova,
        }
    }

    #[test]
    fn faults_are_taken_oldest_first_and_at_most_the_bound_per_take()
    {
        let mut q = FaultQueue::new().unwrap();
        for i in 0..5
        {
            q.push(fault(i << 12));
        }
        let mut got = Vec::new();
        assert_eq!(q.take(3, |f| got.push(f.iova)), 3);
        assert_eq!(got, [0, 0x1000, 0x2000]);
        got.clear();
        assert_eq!(q.take(3, |f| got.push(f.iova)), 2);
        assert_eq!(got, [0x3000, 0x4000]);
    }

    #[test]
    fn a_fault_past_the_capacity_is_counted_dropped_once()
    {
        let mut q = FaultQueue::new().unwrap();
        for i in 0..=FAULT_QUEUE_CAPACITY as u64
        {
            q.push(fault(i << 12));
        }
        assert_eq!(q.take_dropped(), 1);
        assert_eq!(q.take_dropped(), 0);
        let mut n = 0;
        q.take(usize::MAX, |_| n += 1);
        assert_eq!(n, FAULT_QUEUE_CAPACITY);
    }
}
