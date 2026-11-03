// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/death_queues.rs

//! Bind order and growth of svcmgr's death queues.
//!
//! Each death-observer bind takes one node from the pool of the queue it
//! names, and a queue's pool is fixed when the queue is created
//! (`SYS_CAP_CREATE_EVENT_Q`). [`DeathQueues`] keeps the queues svcmgr has
//! created and decides where a bind goes: the newest queue first, then the
//! older ones, whose nodes return as their observed threads and address
//! spaces are destroyed, and, only when every queue refuses for want of a
//! node, a further queue with twice the last pool. The syscalls themselves
//! (the bind, and the create that funds a queue and adds it to the wait set)
//! are the caller's closures, so the policy is host-tested here. procmgr
//! keeps a copy of this policy (`procmgr-process-table`'s `death_queues`).

use syscall_abi::{EVENT_QUEUE_MAX_CAPACITY, SyscallError};

/// The error a bind or a create returns when no node or no memory is left.
const OUT_OF_MEMORY: i64 = SyscallError::OutOfMemory as i64;

/// The death queues svcmgr binds its observers on, in creation order.
pub struct DeathQueues
{
    /// Queue caps, oldest first.
    queues: Vec<u32>,
    /// Observer nodes the next created queue is funded with.
    next_observers: u32,
    /// Most queues the set may hold (the wait set's room for them).
    max_queues: usize,
}

impl DeathQueues
{
    /// An empty set whose first queue will hold `first_observers` nodes and
    /// which holds at most `max_queues` queues.
    #[must_use]
    pub const fn new(first_observers: u32, max_queues: usize) -> Self
    {
        Self {
            queues: Vec::new(),
            next_observers: first_observers,
            max_queues,
        }
    }

    /// The queue caps, oldest first.
    #[must_use]
    pub fn queues(&self) -> &[u32]
    {
        &self.queues
    }

    /// Create a further queue through `create`, which is handed the node
    /// count to fund, and keep it. The next queue's pool doubles, up to
    /// `EVENT_QUEUE_MAX_CAPACITY`.
    ///
    /// # Errors
    /// `OutOfMemory` when the set already holds `max_queues` queues or its
    /// list cannot grow, or the error `create` returns; the set is unchanged
    /// on every error.
    pub fn grow<C>(&mut self, create: C) -> Result<u32, i64>
    where
        C: FnOnce(u32) -> Result<u32, i64>,
    {
        if self.queues.len() >= self.max_queues
        {
            return Err(OUT_OF_MEMORY);
        }
        self.queues.try_reserve(1).map_err(|_| OUT_OF_MEMORY)?;
        let queue = create(self.next_observers)?;
        self.queues.push(queue);
        self.next_observers = self
            .next_observers
            .saturating_mul(2)
            .min(EVENT_QUEUE_MAX_CAPACITY);
        Ok(queue)
    }

    /// Bind one observer through `bind`, which is handed a queue cap.
    ///
    /// The queues are tried newest first; a refusal for want of a node
    /// (`OutOfMemory`) moves to the next older one. When every queue refuses
    /// so, one further queue is created through `create` ([`Self::grow`]) and
    /// the bind is tried on it once, its result returned as it is.
    ///
    /// # Errors
    /// The first error `bind` returns other than `OutOfMemory`, at once and
    /// without trying another queue; the error [`Self::grow`] returns; or the
    /// error of the bind on the new queue.
    pub fn bind<B, C>(&mut self, mut bind: B, create: C) -> Result<(), i64>
    where
        B: FnMut(u32) -> Result<(), i64>,
        C: FnOnce(u32) -> Result<u32, i64>,
    {
        for &queue in self.queues.iter().rev()
        {
            match bind(queue)
            {
                Err(OUT_OF_MEMORY) =>
                {}
                result => return result,
            }
        }
        let queue = self.grow(create)?;
        bind(queue)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const INVALID: i64 = SyscallError::InvalidCapability as i64;

    /// A set holding queues `10, 20, ...`, as many as `count`.
    fn set_with(count: u32) -> DeathQueues
    {
        let mut set = DeathQueues::new(4, 8);
        for i in 1..=count
        {
            assert_eq!(set.grow(|_| Ok(i * 10)), Ok(i * 10));
        }
        set
    }

    #[test]
    fn bind_takes_the_newest_queue_that_has_a_node()
    {
        let mut set = set_with(3);
        let mut tried = Vec::new();
        let result = set.bind(
            |q| {
                tried.push(q);
                if q == 20 { Ok(()) } else { Err(OUT_OF_MEMORY) }
            },
            |_| panic!("a queue had a node; nothing to create"),
        );
        assert_eq!(result, Ok(()));
        assert_eq!(tried, [30, 20]);
        assert_eq!(set.queues(), [10, 20, 30]);
    }

    #[test]
    fn bind_grows_only_when_every_queue_is_out_of_nodes()
    {
        let mut set = set_with(2);
        let mut tried = Vec::new();
        let mut funded = None;
        let result = set.bind(
            |q| {
                tried.push(q);
                if q == 99 { Ok(()) } else { Err(OUT_OF_MEMORY) }
            },
            |observers| {
                funded = Some(observers);
                Ok(99)
            },
        );
        assert_eq!(result, Ok(()));
        assert_eq!(tried, [20, 10, 99]);
        // Two queues of 4 and 8 came first, so the third is funded with 16.
        assert_eq!(funded, Some(16));
        assert_eq!(set.queues(), [10, 20, 99]);
    }

    #[test]
    fn bind_surfaces_another_error_without_trying_older_queues()
    {
        let mut set = set_with(2);
        let mut tried = Vec::new();
        let result = set.bind(
            |q| {
                tried.push(q);
                Err(INVALID)
            },
            |_| panic!("a non-OutOfMemory refusal must not grow the set"),
        );
        assert_eq!(result, Err(INVALID));
        assert_eq!(tried, [20]);
    }

    #[test]
    fn bind_on_a_new_queue_returns_its_failure_without_growing_again()
    {
        for error in [OUT_OF_MEMORY, INVALID]
        {
            let mut set = set_with(1);
            let creates = core::cell::Cell::new(0);
            let result = set.bind(
                |_| {
                    Err(
                        if creates.get() == 0
                        {
                            OUT_OF_MEMORY
                        }
                        else
                        {
                            error
                        },
                    )
                },
                |_| {
                    creates.set(creates.get() + 1);
                    Ok(50)
                },
            );
            assert_eq!(result, Err(error));
            assert_eq!(creates.get(), 1);
            // The new queue is kept: its nodes serve later binds.
            assert_eq!(set.queues(), [10, 50]);
        }
    }

    #[test]
    fn bind_with_no_queue_creates_the_first()
    {
        let mut set = DeathQueues::new(4, 8);
        let mut funded = None;
        let result = set.bind(
            |q| if q == 7 { Ok(()) } else { Err(INVALID) },
            |observers| {
                funded = Some(observers);
                Ok(7)
            },
        );
        assert_eq!(result, Ok(()));
        assert_eq!(funded, Some(4));
    }

    #[test]
    fn grow_refuses_past_the_queue_limit_and_keeps_the_set()
    {
        let mut set = DeathQueues::new(4, 2);
        assert_eq!(set.grow(|_| Ok(1)), Ok(1));
        assert_eq!(set.grow(|_| Ok(2)), Ok(2));
        assert_eq!(
            set.grow(|_| panic!("no room for a third queue")),
            Err(OUT_OF_MEMORY)
        );
        assert_eq!(set.queues(), [1, 2]);
    }

    #[test]
    fn grow_keeps_the_set_when_the_create_fails()
    {
        let mut set = set_with(1);
        assert_eq!(set.grow(|_| Err(OUT_OF_MEMORY)), Err(OUT_OF_MEMORY));
        assert_eq!(set.queues(), [10]);
        // The failed create did not advance the pool size.
        let mut funded = None;
        let _ = set.grow(|observers| {
            funded = Some(observers);
            Ok(20)
        });
        assert_eq!(funded, Some(8));
    }

    #[test]
    fn pools_double_up_to_the_kernel_maximum()
    {
        let mut set = DeathQueues::new(EVENT_QUEUE_MAX_CAPACITY / 2, 4);
        let mut funded = Vec::new();
        for q in 0..3
        {
            let _ = set.grow(|observers| {
                funded.push(observers);
                Ok(q)
            });
        }
        assert_eq!(
            funded,
            [
                EVENT_QUEUE_MAX_CAPACITY / 2,
                EVENT_QUEUE_MAX_CAPACITY,
                EVENT_QUEUE_MAX_CAPACITY
            ]
        );
    }
}
