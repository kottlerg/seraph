// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/death_caps.rs

//! A service's death as the caps svcmgr holds on it show it: its main thread's
//! state and, for a service whose address space svcmgr holds (memmgr and
//! procmgr), the space's retained terminal end. svcmgr reads both with
//! `cap_info` and decodes them here ([`caps_death`]), for a supervised
//! service's entry and for a substrate registration not yet reconciled alike.
//! The death resync ([`resync`]) reads them for every active service, after a
//! drain that may have followed a full death queue. The specification is
//! `services/svcmgr/docs/restart-protocol.md` § Death detection.

use crate::death_tag::DeathTag;

/// The exit reason of a service its caps show dead, else `None`.
///
/// `thread_state` is the result of `cap_info(CAP_INFO_THREAD_STATE)` on its
/// main-thread cap, and `aspace_end` that of
/// `cap_info(CAP_INFO_ASPACE_END)` on its address-space cap; `None`
/// for a cap svcmgr does not hold. An ended space (`syscall_abi::aspace_end_reason`)
/// gives the reason of its first terminal fault or process exit, `0` for a
/// clean exit, ahead of the thread, in the order procmgr reads a process's
/// end before it has answered one: the space's end is the process's first
/// end by a fault or an exit, whichever thread made it. Otherwise the thread
/// reading decodes as every creator
/// decodes it (`ipc::bootstrap::thread_death`): an exited thread gives the
/// reason the kernel recorded, and a thread cap that no longer resolves gives
/// `EXIT_KILLED`, since procmgr's teardown of the process revokes it. A thread that
/// runs or has not started, a space that has not ended, and a failed read of
/// the space show nothing.
#[must_use]
pub fn caps_death(
    thread_state: Option<Result<u64, i64>>,
    aspace_end: Option<Result<u64, i64>>,
) -> Option<u64>
{
    if let Some(end) = aspace_end
        .and_then(Result::ok)
        .and_then(syscall_abi::aspace_end_reason)
    {
        return Some(end);
    }
    thread_state.and_then(ipc::bootstrap::thread_death)
}

/// One slot of svcmgr's service table, as the death resync reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResyncSlot
{
    /// Whether the slot supervises a service now.
    pub active: bool,
    /// The service's current instance.
    pub instance: u32,
    /// svcmgr's cap on the service's process handle, which procmgr answers
    /// `QUERY_PROCESS` on; `0` for a service procmgr did not create.
    pub process_handle: u64,
}

/// svcmgr's service table and the reads and calls its death resync makes
/// on it ([`resync`]).
pub trait ResyncTable
{
    /// The number of slots in the table.
    fn slots(&self) -> usize;

    /// The slot at `idx`; `None` past the table.
    fn slot(&self, idx: usize) -> Option<ResyncSlot>;

    /// The exit reason of the slot's current instance when the caps svcmgr
    /// holds on it show it dead ([`caps_death`]), else `None`.
    fn caps_death(&self, idx: usize) -> Option<u64>;

    /// Route the death of the instance `tag` names, as a post carrying it
    /// would be: a restart, a permanent end, or the system's shutdown, any of
    /// which may change any slot.
    fn route(&mut self, tag: DeathTag, exit_reason: u64);

    /// Whether every service whose address space svcmgr holds (memmgr and
    /// procmgr) is active and shown alive by its caps, so procmgr answers a
    /// call.
    fn substrate_alive(&self) -> bool;

    /// The exit reason procmgr reports for the process `process_handle`
    /// names when it reports it dead, else `None`. The call blocks until
    /// procmgr answers.
    fn queried_death(&mut self, process_handle: u64) -> Option<u64>;
}

/// svcmgr's death resync: route a death for every active service whose
/// current instance is dead, the recovery for the death posts a full queue
/// dropped. The kernel records a death before it posts it, so a main-thread
/// exit, a revoked thread cap, and a fault or process exit of a service whose
/// address space svcmgr holds show in svcmgr's caps
/// ([`ResyncTable::caps_death`]), and those deaths are routed first. A
/// worker-thread fault or process exit of a service procmgr created shows
/// there only once procmgr's teardown revokes the thread cap,
/// which can follow the resync, so each service the caps showed alive is
/// asked of procmgr ([`ResyncTable::queried_death`]) when one was, and only
/// while the substrate is alive ([`ResyncTable::substrate_alive`]), since
/// the call blocks until procmgr answers. Each slot is read again before it
/// is routed, as an earlier route may have changed it. A post for a service
/// routed here that arrives later names the dead instance, and is not
/// routed ([`crate::death_tag::routes`]).
pub fn resync<T: ResyncTable>(table: &mut T)
{
    // Slots the caps showed alive, which procmgr is asked about.
    let mut alive = Vec::new();
    for idx in 0..table.slots()
    {
        let Some(slot) = table.slot(idx)
        else
        {
            continue;
        };
        if !slot.active
        {
            continue;
        }
        let Some(exit_reason) = table.caps_death(idx)
        else
        {
            // A failed reservation only narrows the query to the slots
            // recorded before it.
            if slot.process_handle != 0 && alive.try_reserve(1).is_ok()
            {
                alive.push(idx);
            }
            continue;
        };
        // A slot index that does not fit a tag has no observer to stand in
        // for.
        let Some(tag) = DeathTag::new(idx, slot.instance)
        else
        {
            continue;
        };
        table.route(tag, exit_reason);
    }
    if alive.is_empty() || !table.substrate_alive()
    {
        return;
    }
    for idx in alive
    {
        let Some(slot) = table.slot(idx)
        else
        {
            continue;
        };
        if !slot.active
        {
            continue;
        }
        let Some(tag) = DeathTag::new(idx, slot.instance)
        else
        {
            continue;
        };
        if let Some(exit_reason) = table.queried_death(slot.process_handle)
        {
            table.route(tag, exit_reason);
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use syscall_abi::{
        ASPACE_ENDED, EXIT_FAULT_BASE, EXIT_KILLED, THREAD_STATE_ALIVE, THREAD_STATE_CREATED,
        THREAD_STATE_EXITED,
    };

    /// A thread cap's `CAP_INFO_THREAD_STATE` reading: the state code in the
    /// high half, the exit reason in the low.
    fn packed(code: u32, reason: u64) -> u64
    {
        (u64::from(code) << 32) | reason
    }

    #[test]
    fn an_exited_thread_gives_its_recorded_reason()
    {
        assert_eq!(
            caps_death(Some(Ok(packed(THREAD_STATE_EXITED, 0))), None),
            Some(0)
        );
        assert_eq!(
            caps_death(
                Some(Ok(packed(THREAD_STATE_EXITED, EXIT_FAULT_BASE + 14))),
                None
            ),
            Some(EXIT_FAULT_BASE + 14)
        );
    }

    #[test]
    fn a_thread_cap_that_no_longer_resolves_is_killed()
    {
        assert_eq!(caps_death(Some(Err(-1)), None), Some(EXIT_KILLED));
        assert_eq!(caps_death(Some(Err(-1)), Some(Ok(0))), Some(EXIT_KILLED));
    }

    // The defect caught: the thread's reading ranked ahead of the space's
    // end, so a worker's process exit (5) followed by the main thread's
    // exit (0) read 0 here while procmgr reports 5.
    #[test]
    fn an_ended_space_gives_its_first_end_over_the_threads_reading()
    {
        assert_eq!(
            caps_death(
                Some(Ok(packed(THREAD_STATE_EXITED, 0))),
                Some(Ok(ASPACE_ENDED | 5))
            ),
            Some(5)
        );
        assert_eq!(
            caps_death(Some(Err(-1)), Some(Ok(ASPACE_ENDED | 7))),
            Some(7)
        );
    }

    #[test]
    fn a_live_thread_and_a_clean_space_show_nothing()
    {
        for code in [THREAD_STATE_CREATED, THREAD_STATE_ALIVE]
        {
            assert_eq!(caps_death(Some(Ok(packed(code, 0))), None), None);
            assert_eq!(caps_death(Some(Ok(packed(code, 0))), Some(Ok(0))), None);
        }
        assert_eq!(caps_death(None, None), None);
    }

    #[test]
    fn a_retained_fault_of_another_thread_is_the_death()
    {
        let fault = EXIT_FAULT_BASE + 13;
        let ended = ASPACE_ENDED | fault;
        assert_eq!(
            caps_death(Some(Ok(packed(THREAD_STATE_ALIVE, 0))), Some(Ok(ended))),
            Some(fault)
        );
        assert_eq!(caps_death(None, Some(Ok(ended))), Some(fault));
    }

    // The defect caught: a clean process exit by another thread (reason
    // `0`) read as a space that has not ended, so the death stays unrouted.
    #[test]
    fn a_clean_process_exit_of_another_thread_is_the_death()
    {
        assert_eq!(
            caps_death(
                Some(Ok(packed(THREAD_STATE_ALIVE, 0))),
                Some(Ok(ASPACE_ENDED))
            ),
            Some(0)
        );
    }

    #[test]
    fn a_failed_read_of_the_space_shows_nothing()
    {
        assert_eq!(
            caps_death(Some(Ok(packed(THREAD_STATE_ALIVE, 0))), Some(Err(-1))),
            None
        );
    }

    /// A modelled service: its slot, and what the kernel's records and
    /// procmgr show of its current instance.
    struct Service
    {
        slot: ResyncSlot,
        /// What its caps show: the exit reason of a dead instance.
        caps_dead: Option<u64>,
        /// What procmgr reports: the exit reason of a dead instance, which a
        /// worker thread's fault shows before the caps do.
        procmgr_dead: Option<u64>,
    }

    /// A modelled service table: each route of a current instance restarts
    /// it, as svcmgr's restart decision does for a `restart = always`
    /// service.
    struct Table
    {
        services: Vec<Service>,
        substrate_alive: bool,
        routed: Vec<(u32, u32, u64)>,
        queries: usize,
    }

    impl Table
    {
        /// `count` live services, each created by procmgr.
        fn new(count: u64) -> Self
        {
            let services = (0..count)
                .map(|n| Service {
                    slot: ResyncSlot {
                        active: true,
                        instance: 0,
                        process_handle: 100 + n,
                    },
                    caps_dead: None,
                    procmgr_dead: None,
                })
                .collect();
            Self {
                services,
                substrate_alive: true,
                routed: Vec::new(),
                queries: 0,
            }
        }

        /// Route a death post's correlator, as svcmgr's drain does.
        fn route_post(&mut self, correlator: u64, exit_reason: u64)
        {
            self.route(DeathTag::from_correlator(correlator), exit_reason);
        }
    }

    impl ResyncTable for Table
    {
        fn slots(&self) -> usize
        {
            self.services.len()
        }

        fn slot(&self, idx: usize) -> Option<ResyncSlot>
        {
            self.services.get(idx).map(|s| s.slot)
        }

        fn caps_death(&self, idx: usize) -> Option<u64>
        {
            self.services.get(idx).and_then(|s| s.caps_dead)
        }

        fn route(&mut self, tag: DeathTag, exit_reason: u64)
        {
            let Some(service) = self.services.get_mut(tag.index())
            else
            {
                return;
            };
            if !crate::death_tag::routes(tag, service.slot.active, service.slot.instance)
            {
                return;
            }
            self.routed.push((tag.slot, tag.instance, exit_reason));
            // The restart: a new instance, alive.
            service.slot.instance += 1;
            service.caps_dead = None;
            service.procmgr_dead = None;
        }

        fn substrate_alive(&self) -> bool
        {
            self.substrate_alive
        }

        fn queried_death(&mut self, process_handle: u64) -> Option<u64>
        {
            self.queries += 1;
            self.services
                .iter()
                .find(|s| s.slot.process_handle == process_handle)
                .and_then(|s| s.procmgr_dead)
        }
    }

    // The defect caught: a service whose death post svcmgr's full death
    // queue dropped that is never restarted, or one restarted twice for one
    // death (a resync that skips a slot, misses a death only procmgr can
    // report, or routes a death the drain already routed). Run against a
    // model of the kernel's queue (`death_set::model`), drained as svcmgr's
    // main loop drains it.
    #[test]
    fn a_resync_routes_every_death_a_full_death_queue_dropped_once()
    {
        use death_set::model::KernelQueue;

        const RING: u32 = 2;
        let mut table = Table::new(6);
        let mut queue = KernelQueue::new(RING);
        let tag = |slot: usize| DeathTag::new(slot, 0).expect("slot fits").correlator();
        // Services 1 to 4 die before svcmgr drains, more than the ring holds.
        // The kernel records each death before it posts it: 1 to 3 exit,
        // posting through their main threads' observers, and 4's main thread
        // faults, which both of its observers post. A worker thread of 5
        // faults: only its address space's observer posts, and only procmgr
        // shows the death until its teardown. 0 lives.
        for (slot, service) in table.services.iter_mut().enumerate().take(5).skip(1)
        {
            service.caps_dead = Some(slot as u64);
            let _ = queue.post((tag(slot), slot as u64));
        }
        let _ = queue.post((tag(4), 4));
        table.services[5].procmgr_dead = Some(0x100E);
        assert!(!queue.post((tag(5), 0x100E)), "the ring is full");

        let full = death_set::drain_queues(
            Some(RING),
            |idx| (idx == 0).then_some(()),
            |()| queue.try_recv(),
            |(correlator, exit_reason)| table.route_post(correlator, exit_reason),
        );
        assert!(
            full,
            "the drain that gave up a full ring asks for the resync"
        );
        resync(&mut table);
        table.routed.sort_unstable();
        assert_eq!(
            table.routed,
            [(1, 0, 1), (2, 0, 2), (3, 0, 3), (4, 0, 4), (5, 0, 0x100E)]
        );
        // A dropped post's twin that the kernel delivers later names the
        // instance already routed.
        table.route_post(tag(4), 4);
        assert_eq!(table.routed.len(), 5);
    }

    // The defect caught: a resync that calls procmgr while memmgr or
    // procmgr is dead, which blocks svcmgr for good, since no thread answers
    // the call.
    #[test]
    fn a_resync_asks_procmgr_nothing_while_the_substrate_is_dead()
    {
        let mut table = Table::new(3);
        table.substrate_alive = false;
        table.services[1].caps_dead = Some(7);
        table.services[2].procmgr_dead = Some(0x100E);
        resync(&mut table);
        assert_eq!(table.routed, [(1, 0, 7)]);
        assert_eq!(table.queries, 0);
    }
}
