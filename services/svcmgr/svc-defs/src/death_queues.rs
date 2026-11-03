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
//! node, a further queue with twice the last pool. A further queue is one
//! contiguous grant, so a refused one is retried at half the pool, down to
//! the first pool's size. Every queue is a member of the service's main wait
//! set, beside its service endpoint; when the queues fill it, the set is
//! replaced by one with twice the members, up to `WAIT_SET_MAX_MEMBERS`. The
//! syscalls themselves (the bind, the create that funds a queue and adds it
//! to the wait set, and the wait-set replacement) are the caller's closures,
//! so the policy is host-tested here. procmgr keeps a copy of this policy
//! (`procmgr-process-table`'s `death_queues`).

use syscall_abi::{EVENT_QUEUE_MAX_CAPACITY, SyscallError, WAIT_SET_MAX_MEMBERS};

/// Members of the service's first main wait set: its service endpoint and
/// the first death queue. Each replacement doubles it.
pub const FIRST_WAIT_SET_MEMBERS: u32 = 2;

/// The error a bind or a create returns when no node or no memory is left.
const OUT_OF_MEMORY: i64 = SyscallError::OutOfMemory as i64;

/// The death queues svcmgr binds its observers on, in creation order, and
/// the size of the wait set they are members of.
pub struct DeathQueues
{
    /// Queue caps, oldest first.
    queues: Vec<u32>,
    /// Observer nodes in the first queue: the smallest pool a refused grant
    /// falls back to.
    first_observers: u32,
    /// Observer nodes the next created queue is funded with first.
    next_observers: u32,
    /// Members the main wait set has room for: the service endpoint and every
    /// queue.
    ws_members: u32,
}

impl DeathQueues
{
    /// An empty set whose first queue will hold `first_observers` nodes,
    /// in a wait set with room for `ws_members` members.
    #[must_use]
    pub const fn new(first_observers: u32, ws_members: u32) -> Self
    {
        Self {
            queues: Vec::new(),
            first_observers,
            next_observers: first_observers,
            ws_members,
        }
    }

    /// The queue caps, oldest first.
    #[must_use]
    pub fn queues(&self) -> &[u32]
    {
        &self.queues
    }

    /// Members the main wait set has room for.
    #[must_use]
    pub const fn ws_members(&self) -> u32
    {
        self.ws_members
    }

    /// Create a further queue and keep it.
    ///
    /// When the service endpoint and the queues already fill the wait set,
    /// `grow_ws` is first handed the queues and twice the members (up to
    /// `WAIT_SET_MAX_MEMBERS`) to replace the wait set with. Then `create` is
    /// handed the node count to fund: the next pool size, and on an
    /// `OutOfMemory` refusal (no contiguous grant that large) half that,
    /// down to the first pool's size. The next queue's pool doubles from the
    /// size that succeeded, up to `EVENT_QUEUE_MAX_CAPACITY`.
    ///
    /// # Errors
    /// `OutOfMemory` when the wait set is already `WAIT_SET_MAX_MEMBERS`
    /// wide and full, when the queue list cannot grow, or when `create`
    /// refuses even the first pool's size; the error `grow_ws` returns; or
    /// the first error `create` returns other than `OutOfMemory`. The set is
    /// unchanged on every error, except that a wait set `grow_ws` replaced
    /// stays replaced.
    pub fn grow<C, W>(&mut self, mut create: C, grow_ws: W) -> Result<u32, i64>
    where
        C: FnMut(u32) -> Result<u32, i64>,
        W: FnOnce(&[u32], u32) -> Result<(), i64>,
    {
        // The service endpoint holds one member.
        let members_used = u32::try_from(self.queues.len())
            .map_err(|_| OUT_OF_MEMORY)?
            .saturating_add(1);
        if members_used >= self.ws_members
        {
            let wider = self.ws_members.saturating_mul(2).min(WAIT_SET_MAX_MEMBERS);
            if wider <= self.ws_members
            {
                return Err(OUT_OF_MEMORY);
            }
            grow_ws(&self.queues, wider)?;
            self.ws_members = wider;
        }
        self.queues.try_reserve(1).map_err(|_| OUT_OF_MEMORY)?;
        let mut observers = self.next_observers;
        loop
        {
            match create(observers)
            {
                Ok(queue) =>
                {
                    self.queues.push(queue);
                    self.next_observers = observers.saturating_mul(2).min(EVENT_QUEUE_MAX_CAPACITY);
                    return Ok(queue);
                }
                Err(OUT_OF_MEMORY) if observers > self.first_observers =>
                {
                    observers = (observers / 2).max(self.first_observers);
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Bind one observer through `bind`, which is handed a queue cap.
    ///
    /// The queues are tried newest first; a refusal for want of a node
    /// (`OutOfMemory`) moves to the next older one. When every queue refuses
    /// so, one further queue is created ([`Self::grow`], through `create`
    /// and `grow_ws`) and the bind is tried on it once, its result returned
    /// as it is.
    ///
    /// # Errors
    /// The first error `bind` returns other than `OutOfMemory`, at once and
    /// without trying another queue; the error [`Self::grow`] returns; or the
    /// error of the bind on the new queue.
    pub fn bind<B, C, W>(&mut self, mut bind: B, create: C, grow_ws: W) -> Result<(), i64>
    where
        B: FnMut(u32) -> Result<(), i64>,
        C: FnMut(u32) -> Result<u32, i64>,
        W: FnOnce(&[u32], u32) -> Result<(), i64>,
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
        let queue = self.grow(create, grow_ws)?;
        bind(queue)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    const INVALID: i64 = SyscallError::InvalidCapability as i64;

    /// A `grow_ws` a test does not expect to be called.
    fn no_ws(_: &[u32], _: u32) -> Result<(), i64>
    {
        panic!("the wait set had room; it must not grow")
    }

    /// A set holding queues `10, 20, ...`, as many as `count`, in a wait set
    /// with room for all of them.
    fn set_with(count: u32) -> DeathQueues
    {
        let mut set = DeathQueues::new(4, 64);
        for i in 1..=count
        {
            assert_eq!(set.grow(|_| Ok(i * 10), no_ws), Ok(i * 10));
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
            no_ws,
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
            no_ws,
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
            no_ws,
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
                no_ws,
            );
            assert_eq!(result, Err(error));
            assert_eq!(creates.get(), 1);
            // The new queue is kept: its nodes serve later binds.
            assert_eq!(set.queues(), [10, 50]);
        }
    }

    #[test]
    fn a_refused_grant_is_retried_at_half_the_pool()
    {
        let mut set = set_with(3);
        let mut asked = Vec::new();
        // Pools of 4, 8 and 16 came first, so the next asks for 32; grants
        // above 8 nodes are refused.
        let result = set.grow(
            |observers| {
                asked.push(observers);
                if observers > 8
                {
                    Err(OUT_OF_MEMORY)
                }
                else
                {
                    Ok(77)
                }
            },
            no_ws,
        );
        assert_eq!(result, Ok(77));
        assert_eq!(asked, [32, 16, 8]);
        // The next pool doubles from the size that succeeded.
        let mut next = None;
        let _ = set.grow(
            |observers| {
                next = Some(observers);
                Ok(78)
            },
            no_ws,
        );
        assert_eq!(next, Some(16));
    }

    #[test]
    fn a_grant_refused_down_to_the_first_pool_is_out_of_memory()
    {
        let mut set = set_with(3);
        let mut asked = Vec::new();
        let result = set.grow(
            |observers| {
                asked.push(observers);
                Err(OUT_OF_MEMORY)
            },
            no_ws,
        );
        assert_eq!(result, Err(OUT_OF_MEMORY));
        assert_eq!(asked, [32, 16, 8, 4]);
        assert_eq!(set.queues(), [10, 20, 30]);
    }

    #[test]
    fn a_create_error_other_than_out_of_memory_is_not_retried()
    {
        let mut set = set_with(3);
        let mut asked = Vec::new();
        let result = set.grow(
            |observers| {
                asked.push(observers);
                Err(INVALID)
            },
            no_ws,
        );
        assert_eq!(result, Err(INVALID));
        assert_eq!(asked, [32]);
    }

    #[test]
    fn a_full_wait_set_doubles_before_the_queue_is_created()
    {
        // Room for the service endpoint and one queue.
        let mut set = DeathQueues::new(4, 2);
        assert_eq!(set.grow(|_| Ok(1), no_ws), Ok(1));
        let order = core::cell::RefCell::new(Vec::new());
        let result = set.grow(
            |_| {
                order.borrow_mut().push("create");
                Ok(2)
            },
            |queues, members| {
                assert_eq!(queues, [1]);
                assert_eq!(members, 4);
                order.borrow_mut().push("grow_ws");
                Ok(())
            },
        );
        assert_eq!(result, Ok(2));
        assert_eq!(*order.borrow(), ["grow_ws", "create"]);
        assert_eq!(set.ws_members(), 4);
    }

    #[test]
    fn a_failed_wait_set_growth_leaves_the_set_unchanged()
    {
        let mut set = DeathQueues::new(4, 2);
        assert_eq!(set.grow(|_| Ok(1), no_ws), Ok(1));
        let result = set.grow(
            |_| panic!("no queue is created when the wait set cannot grow"),
            |_, _| Err(OUT_OF_MEMORY),
        );
        assert_eq!(result, Err(OUT_OF_MEMORY));
        assert_eq!(set.queues(), [1]);
        assert_eq!(set.ws_members(), 2);
    }

    #[test]
    fn a_wait_set_grown_before_a_refused_queue_stays_grown()
    {
        // The caller's wider set is already live when the create fails, so
        // the policy must keep counting it.
        let mut set = DeathQueues::new(4, 2);
        assert_eq!(set.grow(|_| Ok(1), no_ws), Ok(1));
        let result = set.grow(|_| Err(OUT_OF_MEMORY), |_, _| Ok(()));
        assert_eq!(result, Err(OUT_OF_MEMORY));
        assert_eq!(set.ws_members(), 4);
        assert_eq!(set.queues(), [1]);
    }

    #[test]
    fn the_wait_set_grows_no_wider_than_the_kernel_maximum()
    {
        let mut set = DeathQueues::new(4, WAIT_SET_MAX_MEMBERS / 2);
        // Fill the half-width set: the service endpoint and its queues.
        for q in 1..WAIT_SET_MAX_MEMBERS / 2
        {
            assert_eq!(set.grow(|_| Ok(q), no_ws), Ok(q));
        }
        let mut widths = Vec::new();
        let _ = set.grow(
            |_| Ok(0),
            |_, members| {
                widths.push(members);
                Ok(())
            },
        );
        assert_eq!(widths, [WAIT_SET_MAX_MEMBERS]);
        // Fill the full-width set; a further queue has no room.
        for q in WAIT_SET_MAX_MEMBERS / 2 + 1..WAIT_SET_MAX_MEMBERS
        {
            assert_eq!(set.grow(|_| Ok(q), no_ws), Ok(q));
        }
        assert_eq!(
            set.grow(|_| panic!("no room for another queue"), no_ws),
            Err(OUT_OF_MEMORY)
        );
    }

    #[test]
    fn pools_double_up_to_the_kernel_maximum()
    {
        let mut set = DeathQueues::new(EVENT_QUEUE_MAX_CAPACITY / 2, 64);
        let mut funded = Vec::new();
        for q in 0..3
        {
            let _ = set.grow(
                |observers| {
                    funded.push(observers);
                    Ok(q)
                },
                no_ws,
            );
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
