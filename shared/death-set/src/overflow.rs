// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/death-set/src/overflow.rs

//! How a drain of a death queue of a fixed ring finds that the queue may
//! have dropped a post.
//!
//! The kernel drops a death post to a full queue. A dropped post leaves the
//! ring full behind it: its capacity of events, each taken after the drop,
//! oldest first, with the queue holding at least one of them until the last
//! is taken, so no take finds the queue empty in between. A count of the
//! takes since one last found the queue empty ([`OverflowWatch`]), started
//! again from zero each time it reaches the ring's capacity, therefore reaches
//! the capacity at one of those takes: after the drop. A resync from the
//! kernel's records that starts after that take finds the death the post
//! carried, since the kernel records a death before it posts it. The count
//! also reaches the capacity when no post was dropped (a ring's worth taken
//! with the queue never found empty), which costs only a resync that finds
//! nothing.
//!
//! The takes must be counted wherever they are made: every take from the
//! queue passes through one watch, and every take that finds it empty resets
//! it. A service with one drainer counts each drain from zero
//! ([`drain_queues`]), since each drain ends on a take that finds the queue
//! empty; logd, whose threads take from its one queue in turn, keeps one
//! watch under the lock its takes are made under.

/// The count of takes from one death queue of a fixed ring since one last
/// found it empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverflowWatch
{
    /// The ring's capacity, the entries the queue was created with.
    ring: u32,
    /// The takes since the queue was last found empty, or since the count
    /// last reached `ring`.
    run: u32,
}

impl OverflowWatch
{
    /// The watch on a queue of `ring` entries that no take has been made
    /// from.
    #[must_use]
    pub const fn new(ring: u32) -> Self
    {
        Self { ring, run: 0 }
    }

    /// Count one event taken from the queue. Returns `true` when the takes
    /// since the queue was last found empty reach the ring's capacity: the
    /// queue may have been full and dropped a post, so the caller resyncs
    /// once this take is handled. The count then starts again from zero, so
    /// a drop after this take is reported by a later one.
    #[must_use = "a `true` return asks for a resync"]
    pub fn took(&mut self) -> bool
    {
        // `run` is below `ring` here, so the sum cannot saturate.
        self.run = self.run.saturating_add(1);
        if self.run >= self.ring
        {
            self.run = 0;
            return true;
        }
        false
    }

    /// A take found the queue empty: every event a dropped post left behind
    /// it has been taken and counted.
    pub fn found_empty(&mut self)
    {
        self.run = 0;
    }
}

/// Drain a set of death queues, oldest first: `queue_at` names the queue at
/// each index, read anew for each, and `None` past the last; `try_recv`
/// takes one event from a queue without blocking, `None` when it is empty;
/// each event is handed to `f`. Each queue is drained until a take finds it
/// empty, its takes counted from zero by an [`OverflowWatch`] when `ring` is
/// `Some` (the capacity of every queue's fixed ring); `None` is a set whose
/// queues cannot drop a post, which counts nothing.
///
/// Returns whether any queue's count reached its ring: the caller resyncs.
/// This holds for a queue only while every take from it is made through
/// this drain, by one thread at a time.
pub fn drain_queues<Q, E, A, R, F>(
    ring: Option<u32>,
    mut queue_at: A,
    mut try_recv: R,
    mut f: F,
) -> bool
where
    Q: Copy,
    A: FnMut(usize) -> Option<Q>,
    R: FnMut(Q) -> Option<E>,
    F: FnMut(E),
{
    let mut full = false;
    let mut idx: usize = 0;
    while let Some(queue) = queue_at(idx)
    {
        let mut watch = ring.map(OverflowWatch::new);
        while let Some(event) = try_recv(queue)
        {
            if let Some(watch) = watch.as_mut()
            {
                full |= watch.took();
            }
            f(event);
        }
        // `idx` indexes the queue list, so it cannot saturate.
        idx = idx.saturating_add(1);
    }
    full
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::model::KernelQueue;

    /// One step of a run against modelled queues: the kernel posts a death
    /// to queue `n`, or the service makes one take.
    #[derive(Clone, Copy, Debug)]
    enum Op
    {
        Post(usize),
        Take,
    }

    /// Every sequence of `len` steps or fewer over `queues` queues.
    fn scripts(queues: usize, len: usize) -> Vec<Vec<Op>>
    {
        let ops: Vec<Op> = (0..queues).map(Op::Post).chain([Op::Take]).collect();
        let mut all = vec![Vec::new()];
        let mut last: Vec<Vec<Op>> = vec![Vec::new()];
        for _ in 0..len
        {
            let mut next = Vec::new();
            for script in &last
            {
                for &op in &ops
                {
                    let mut longer = script.clone();
                    longer.push(op);
                    next.push(longer);
                }
            }
            all.extend(next.iter().cloned());
            last = next;
        }
        all
    }

    /// Whether every drop at a step of `drops` is followed by a report at a
    /// later step of `reports`.
    fn each_drop_reported(drops: &[usize], reports: &[usize]) -> bool
    {
        drops
            .iter()
            .all(|&drop| reports.iter().any(|&report| report > drop))
    }

    /// Run `script` against `queues` modelled queues of `ring` entries,
    /// drained by one thread through [`drain_queues`], the kernel's posts
    /// landing between any two of its takes; once the script ends, drain
    /// until every queue is empty. Returns the steps at which a post was
    /// dropped and the steps at which a drain that reported a full queue
    /// ended, where its caller's resync starts.
    fn run_drains(script: &[Op], queues: usize, ring: u32) -> (Vec<usize>, Vec<usize>)
    {
        let mut model = vec![KernelQueue::new(ring); queues];
        let mut drops = Vec::new();
        let mut resyncs = Vec::new();
        let mut at = 0;
        let mut step = 0;
        // The kernel's posts from `at` up to the next take.
        let mut posts = |model: &mut [KernelQueue<usize>], at: &mut usize, step: &mut usize| {
            while let Some(&Op::Post(n)) = script.get(*at)
            {
                if !model[n].post(*step)
                {
                    drops.push(*step);
                }
                *at += 1;
                *step += 1;
            }
        };
        loop
        {
            posts(&mut model, &mut at, &mut step);
            if at == script.len() && model.iter().all(KernelQueue::is_empty)
            {
                return (drops, resyncs);
            }
            let full = drain_queues(
                Some(ring),
                |idx| (idx < queues).then_some(idx),
                |n| {
                    posts(&mut model, &mut at, &mut step);
                    // This take is the script's next step, or, once the
                    // script has ended, one of the final drain's.
                    at = (at + 1).min(script.len());
                    step += 1;
                    model[n].try_recv()
                },
                |_| {},
            );
            if full
            {
                resyncs.push(step);
            }
        }
    }

    // The defect caught: a drain that misses a dropped post, so no resync
    // follows it (a count compared past the ring, a count kept across the
    // queues of a set, a report of one queue overwritten by the next
    // queue's).
    #[test]
    fn every_dropped_post_is_followed_by_a_drain_that_reports_it()
    {
        for (queues, len, rings) in [(1, 12, 1..=3), (2, 9, 1..=2)]
        {
            for ring in rings
            {
                for script in scripts(queues, len)
                {
                    let (drops, resyncs) = run_drains(&script, queues, ring);
                    assert!(
                        each_drop_reported(&drops, &resyncs),
                        "ring {ring}, {queues} queues, script {script:?}: drops at {drops:?}, \
                         resyncs at {resyncs:?}"
                    );
                }
            }
        }
    }

    // The defect caught: a watch shared by several takers that misses a
    // dropped post (a count not started again after it reports, so the takes
    // after a drop never reach the ring again; a count compared past the
    // ring). Takes are serialised, as logd's are under its state lock.
    #[test]
    fn every_dropped_post_is_followed_by_a_take_the_watch_reports()
    {
        for ring in 1..=3
        {
            for script in scripts(1, 12)
            {
                let mut queue = KernelQueue::new(ring);
                let mut watch = OverflowWatch::new(ring);
                let (mut drops, mut reports) = (Vec::new(), Vec::new());
                let mut step = 0;
                // One take, by whichever thread: whether it found an event.
                let mut take = |queue: &mut KernelQueue<usize>, step: usize| {
                    if queue.try_recv().is_some()
                    {
                        if watch.took()
                        {
                            reports.push(step);
                        }
                        return true;
                    }
                    watch.found_empty();
                    false
                };
                for op in &script
                {
                    match op
                    {
                        Op::Post(_) =>
                        {
                            if !queue.post(step)
                            {
                                drops.push(step);
                            }
                        }
                        Op::Take =>
                        {
                            take(&mut queue, step);
                        }
                    }
                    step += 1;
                }
                while take(&mut queue, step)
                {
                    step += 1;
                }
                assert!(
                    each_drop_reported(&drops, &reports),
                    "ring {ring}, script {script:?}: drops at {drops:?}, reports at {reports:?}"
                );
            }
        }
    }

    // The defect caught: a watch that reports with fewer than a ring's worth
    // of takes since the queue was last found empty, or that keeps counting
    // across an empty queue, so a service resyncs on every busy drain.
    #[test]
    fn the_watch_reports_a_ring_taken_with_the_queue_never_empty()
    {
        let mut watch = OverflowWatch::new(3);
        assert!(!watch.took());
        assert!(!watch.took());
        watch.found_empty();
        assert!(!watch.took());
        assert!(!watch.took());
        assert!(watch.took());
        // Counted again from zero after the report.
        assert!(!watch.took());
        assert!(!watch.took());
        assert!(watch.took());
    }

    // The defect caught: a drain that stops before a queue is empty, hands
    // events out of order, or skips a later queue of the set.
    #[test]
    fn a_drain_hands_every_event_over_oldest_queue_first()
    {
        let mut model = [KernelQueue::new(4), KernelQueue::new(4)];
        for event in [1, 2, 3]
        {
            assert!(model[0].post(event));
        }
        for event in [4, 5]
        {
            assert!(model[1].post(event));
        }
        let mut seen = Vec::new();
        let full = drain_queues(
            Some(4),
            |idx| (idx < 2).then_some(idx),
            |n| model[n].try_recv(),
            |event| seen.push(event),
        );
        assert_eq!(seen, [1, 2, 3, 4, 5]);
        assert!(!full, "no queue gave up its ring");
        assert!(model.iter().all(KernelQueue::is_empty));
    }

    // The defect caught: a set whose queues cannot drop a post (devmgr's
    // counted set) asking for a resync it has no use for.
    #[test]
    fn a_set_without_fixed_rings_never_reports()
    {
        let mut queue = KernelQueue::new(2);
        assert!(queue.post(1u32) && queue.post(2));
        let mut seen = 0;
        let full = drain_queues(
            None,
            |idx| (idx == 0).then_some(0),
            |_| queue.try_recv(),
            |_| seen += 1,
        );
        assert_eq!(seen, 2);
        assert!(!full);
    }
}
