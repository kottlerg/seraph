// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/src/hold.rs

//! The hold of faults memmgr declined for want of memory
//! (services/crashd/docs/operation.md § Hold).
//!
//! With a stall set (`CRASHD_OOM_STALL_MS`), crashd's thread waits on a wait
//! set of procmgr's crash endpoint and the runtime's memory-pressure
//! Notification, with a timeout of the earliest hold's deadline. A fault that
//! memmgr declined with code 6, 7, 8 or 11 while the level is `CRITICAL` is
//! redirected (`FAULT_REPLY_REDIRECT`) to one of [`SLOTS`] endpoints crashd
//! made at start, where it waits queued, its thread fault-blocked, and no
//! thread of crashd's waits on it. The fault reaches that endpoint only when
//! its thread next runs, so the endpoint is in the wait set from the redirect
//! until the fault arrives, and out of it while the fault waits there. When
//! the level falls below `CRITICAL`, crashd receives each held fault that
//! has arrived from its endpoint and resumes it; when a hold's deadline
//! passes first, it receives that fault and reports and declines it as any
//! other, or, when it has not arrived, replaces the slot's endpoint, so a
//! slot's endpoint only ever queues the one fault crashd holds there. The
//! decisions are [`oom_hold`]'s, host-tested.

use core_file::policy::Policy;
use ipc::IpcMessage;
use oom_hold::{Admit, Ended, Found, Held, Holds, Key, Level, Refusal, SLOTS, Why};
use syscall_abi::{
    FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL, FAULT_REPLY_REDIRECT,
    FAULT_REPLY_RESUME, PAGE_SIZE, SyscallError,
};

use crate::{BOUND, Dump, FAULT_BOUND_MS, await_settled, delete_caps, handle_fault, now_ms};

/// The wait-set badge of procmgr's crash endpoint.
const WAKE_FAULT: u64 = 0;

/// The wait-set badge of the memory-pressure Notification.
const WAKE_PRESSURE: u64 = 1;

/// The wait-set badge of slot 0's endpoint; slot `n`'s is this plus `n`.
const WAKE_SLOT: u64 = 2;

/// One past the wait-set badge of the last slot's endpoint.
const WAKE_SLOT_END: u64 = WAKE_SLOT + SLOTS as u64;

/// Members of the wait set: the crash endpoint, the Notification, and each
/// slot's endpoint.
#[expect(
    clippy::cast_possible_truncation,
    reason = "SLOTS is 16; the sum fits a u32 at compile time"
)]
const WAIT_SET_MEMBERS: u32 = 2 + SLOTS as u32;

/// How long crashd waits before it waits on its wait set again after the
/// wait failed with an error a retry does not clear at once.
const WAIT_RETRY_MS: u64 = 100;

/// A held fault's message as it reached crashd. A redirect delivers the fault
/// again with the slot endpoint's badge and the slot in its reason word, so
/// the report of a fault declined at its deadline is made from this.
#[derive(Clone, Copy)]
struct Message
{
    badge: u64,
    /// The fault's kind, address, access and instruction pointer, and
    /// memmgr's reason word.
    words: [u64; 5],
}

impl Message
{
    fn of(msg: &IpcMessage) -> Self
    {
        let mut words = [0u64; 5];
        for (at, word) in words.iter_mut().enumerate()
        {
            *word = msg.word(at);
        }
        Self {
            badge: msg.badge,
            words,
        }
    }

    fn rebuilt(&self) -> IpcMessage
    {
        let mut msg = IpcMessage::builder(FAULT_LABEL)
            .words(0, &self.words)
            .build();
        msg.badge = self.badge;
        msg
    }

    fn addr(&self) -> u64
    {
        let [_, addr, ..] = self.words;
        addr
    }

    /// memmgr's decline code: the reason word's low 32 bits.
    fn code(&self) -> u64
    {
        let [.., reason] = self.words;
        reason & 0xffff_ffff
    }
}

/// crashd's side of the hold: the slots' state, their endpoints and
/// messages, and the wait set the thread waits on.
struct Hold
{
    holds: Holds,
    /// The endpoint each slot's fault is redirected to; crashd alone holds a
    /// cap to it.
    endpoints: [u64; SLOTS],
    messages: [Option<Message>; SLOTS],
    wait_set: u64,
    /// The runtime's memory-pressure Notification, in the wait set.
    pressure: u64,
    /// The level the last read gave; memmgr signals `pressure` on every
    /// change, so it holds until the Notification carries a bit.
    level: Level,
}

/// Serve the crash endpoint `endpoint` with the hold of faults for at most
/// `stall_ms` each, as crashd's main loop, after touching the thread's stack
/// and the heap a report under `CRITICAL` uses; return, with nothing made,
/// when the hold cannot start, logged, for the loop without it.
pub fn serve(stall_ms: u64, endpoint: u64, policy: &Policy, authority: u64, ipc_buf: *mut u64)
{
    let Some(hold) = Hold::start(stall_ms, endpoint)
    else
    {
        return;
    };
    crate::touch_stack();
    crate::touch_heap();
    std::os::seraph::log!("holding faults declined for want of memory up to {stall_ms} ms");
    std::os::seraph::log!("reporting crashes");
    hold.serve(endpoint, policy, authority, ipc_buf);
}

impl Hold
{
    /// Make the slots' endpoints and the wait set of the crash endpoint
    /// `endpoint` and the pressure Notification, and read the level; `None`,
    /// logged, with nothing left made, when the process has no pressure
    /// registration or an object cannot be made.
    fn start(stall_ms: u64, endpoint: u64) -> Option<Self>
    {
        let Some(pressure) = std::os::seraph::memory_pressure_notification()
        else
        {
            std::os::seraph::log!(warn: "no memory-pressure registration; no fault held");
            return None;
        };
        let mut endpoints = [0u64; SLOTS];
        for slot in &mut endpoints
        {
            let Some(cap) =
                std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |s| {
                    syscall::cap_create_endpoint(s).ok()
                })
            else
            {
                delete_caps(&endpoints);
                std::os::seraph::log!(warn: "hold endpoints not made; no fault held");
                return None;
            };
            *slot = cap;
        }
        let capacity = WAIT_SET_MEMBERS;
        let wait_set = std::os::seraph::object_slab_retype(
            std::os::seraph::wait_set_retype_bytes(u64::from(capacity)),
            |s| syscall::wait_set_create(s, capacity).ok(),
        )
        .unwrap_or(0);
        let joined = wait_set != 0
            && syscall::wait_set_add(wait_set, endpoint, WAKE_FAULT).is_ok()
            && syscall::wait_set_add(wait_set, pressure, WAKE_PRESSURE).is_ok();
        if !joined
        {
            // Deleting the set removes the members it took.
            delete_caps(&[wait_set]);
            delete_caps(&endpoints);
            std::os::seraph::log!(warn: "hold wait set not made; no fault held");
            return None;
        }
        // A change signalled before now is in the level read here.
        let _ = syscall::notification_try_wait(pressure);
        Some(Self {
            holds: Holds::new(stall_ms),
            endpoints,
            messages: [None; SLOTS],
            wait_set,
            pressure,
            level: read_level(),
        })
    }

    /// Serve the crash endpoint `endpoint` with the hold: end each hold whose
    /// level fell or whose deadline passed, then wait for a fault, a change of
    /// the level, or the next deadline.
    fn serve(mut self, endpoint: u64, policy: &Policy, authority: u64, ipc_buf: *mut u64) -> !
    {
        loop
        {
            self.refresh_level();
            if self.level == Level::BelowCritical
            {
                self.end_all(policy, authority, ipc_buf);
            }
            while let Some(slot) = self.holds.due(now_ms())
            {
                self.end(slot, Why::Due, policy, authority, ipc_buf);
            }
            // 0 waits without bound; a deadline due within the millisecond
            // waits one.
            let timeout = self
                .holds
                .next_deadline()
                .map_or(0, |at| at.saturating_sub(now_ms()).max(1));
            match syscall::wait_set_wait_timeout(self.wait_set, timeout)
            {
                Ok(WAKE_FAULT) =>
                {
                    // SAFETY: ipc_buf is the registered IPC buffer page.
                    if let Ok(msg) = unsafe { ipc::ipc_try_recv(endpoint, ipc_buf) }
                    {
                        self.dispatch(&msg, policy, authority, ipc_buf);
                    }
                }
                // A held fault reached its slot's endpoint; a fall of the
                // level is acted on at the loop's top.
                Ok(badge) if (WAKE_SLOT..WAKE_SLOT_END).contains(&badge) =>
                {
                    let slot =
                        usize::try_from(badge.saturating_sub(WAKE_SLOT)).unwrap_or(usize::MAX);
                    self.arrived(slot);
                }
                // A change of the level, read at the loop's top; then a
                // deadline, or a late upcall of the watchdog's.
                Ok(_) =>
                {}
                Err(e)
                    if e == SyscallError::WouldBlock as i64
                        || e == SyscallError::Interrupted as i64 =>
                {}
                Err(e) =>
                {
                    bounded(|| std::os::seraph::log!(warn: "hold wait failed (err={e})"));
                    std::thread::sleep(std::time::Duration::from_millis(WAIT_RETRY_MS));
                }
            }
        }
    }

    /// Take a signalled change of the level and read the level.
    fn refresh_level(&mut self)
    {
        if syscall::notification_try_wait(self.pressure).is_ok()
        {
            self.level = read_level();
        }
    }

    /// Whether a report made now may write a core: not while the level is
    /// `CRITICAL`.
    fn dump(&self) -> Dump
    {
        match self.level
        {
            Level::Critical => Dump::MemoryCritical,
            Level::BelowCritical => Dump::Allowed,
        }
    }

    /// Answer the fault `msg` from the crash endpoint: hold a holdable one,
    /// or resume it at once when the level has fallen since memmgr declined
    /// it; report and decline every other.
    fn dispatch(&mut self, msg: &IpcMessage, policy: &Policy, authority: u64, ipc_buf: *mut u64)
    {
        if msg.label != FAULT_LABEL
        {
            // Only procmgr holds a SEND on the endpoint, and it sends crashd
            // none; answer anything else without acting on it.
            // SAFETY: ipc_buf is the registered IPC buffer page.
            let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_KILL), ipc_buf) };
            return;
        }
        self.refresh_level();
        let Some(key) = holdable(msg)
        else
        {
            handle_fault(msg, policy, authority, ipc_buf, self.dump());
            return;
        };
        let now = now_ms();
        let fault = Message::of(msg);
        match self.holds.admit(now, key, self.level)
        {
            Admit::Hold { slot, deadline } =>
            {
                self.redirect(slot, fault, deadline.saturating_sub(now), ipc_buf);
            }
            Admit::Resume =>
            {
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ipc_buf) };
                bounded(|| {
                    std::os::seraph::log!(
                        "fault badge={} addr={:#x} resumed at once: memory no longer critical",
                        fault.badge,
                        fault.addr()
                    );
                });
            }
            Admit::Decline(why) =>
            {
                let line = match why
                {
                    Refusal::SlotsFull => "no free hold slot",
                    Refusal::Repeat => "repeats a resumed fault",
                    Refusal::NoStall => "no stall",
                };
                bounded(|| {
                    std::os::seraph::log!(
                        warn: "fault badge={} addr={:#x} not held: {line}",
                        fault.badge,
                        fault.addr()
                    );
                });
                handle_fault(msg, policy, authority, ipc_buf, self.dump());
            }
        }
    }

    /// Redirect the fault whose reply crashd holds to `slot`'s endpoint, which
    /// [`Holds::admit`] gave it for `stall_ms`.
    fn redirect(&mut self, slot: usize, fault: Message, stall_ms: u64, ipc_buf: *mut u64)
    {
        let Some(&target) = self.endpoints.get(slot)
        else
        {
            return;
        };
        // The slot reaches the endpoint as the delivery's word 4.
        let redirect = IpcMessage::builder(FAULT_REPLY_REDIRECT)
            .word(0, u64::try_from(slot).unwrap_or(u64::MAX))
            .cap(target)
            .build();
        // SAFETY: ipc_buf is the registered IPC buffer page.
        if let Err(e) = unsafe { ipc::ipc_reply(&redirect, ipc_buf) }
        {
            // The reply claimed the fault: it is unhandled, its thread killed.
            let _ = self.holds.cancel(slot);
            bounded(|| {
                std::os::seraph::log!(
                    warn: "fault badge={} addr={:#x} not held: redirect failed (err={e})",
                    fault.badge,
                    fault.addr()
                );
            });
            return;
        }
        if let Some(cell) = self.messages.get_mut(slot)
        {
            *cell = Some(fault);
        }
        // Until the fault arrives, a fall of the level does not end the hold;
        // without the membership its arrival goes unseen, and the hold ends
        // at its deadline.
        let badge = WAKE_SLOT.saturating_add(u64::try_from(slot).unwrap_or(u64::MAX));
        if let Err(e) = syscall::wait_set_add(self.wait_set, target, badge)
        {
            bounded(|| {
                std::os::seraph::log!(warn: "hold slot {slot} not watched (err={e})");
            });
        }
        bounded(|| {
            std::os::seraph::log!(
                "fault badge={} addr={:#x} held: memory critical (reason={}), up to {stall_ms} ms",
                fault.badge,
                fault.addr(),
                fault.code()
            );
        });
    }

    /// End every hold whose fault has arrived: the level fell below
    /// `CRITICAL`.
    fn end_all(&mut self, policy: &Policy, authority: u64, ipc_buf: *mut u64)
    {
        for slot in 0..SLOTS
        {
            self.end(slot, Why::LevelFell, policy, authority, ipc_buf);
        }
    }

    /// End the hold in `slot` because `why`: receive its fault from the slot's
    /// endpoint, and resume it, or report and decline it, or, when it is no
    /// longer queued there, free the slot, or, when it has not arrived by its
    /// deadline, replace the slot's endpoint. A fall of the level before the
    /// fault arrived leaves the hold as it is.
    fn end(&mut self, slot: usize, why: Why, policy: &Policy, authority: u64, ipc_buf: *mut u64)
    {
        let Some(&target) = self.endpoints.get(slot)
        else
        {
            return;
        };
        let Some(fault) = self.messages.get(slot).copied().flatten()
        else
        {
            return;
        };
        // SAFETY: ipc_buf is the registered IPC buffer page.
        let found = match unsafe { ipc::ipc_try_recv(target, ipc_buf) }
        {
            Ok(_) => Found::Fault,
            Err(_) => Found::Nothing,
        };
        let Some(ended) = self.holds.end(slot, why, found)
        else
        {
            return;
        };
        if let Some(cell) = self.messages.get_mut(slot)
        {
            *cell = None;
        }
        // Not a member once its fault arrived; the error is then ignored.
        let _ = syscall::wait_set_remove(self.wait_set, target);
        match ended
        {
            Ended::Resume(held) =>
            {
                // SAFETY: ipc_buf is the registered IPC buffer page.
                let _ = unsafe { ipc::ipc_reply(&IpcMessage::new(FAULT_REPLY_RESUME), ipc_buf) };
                bounded(|| {
                    std::os::seraph::log!(
                        "fault badge={} addr={:#x} resumed after {} ms: memory no longer critical",
                        fault.badge,
                        fault.addr(),
                        held_ms(&held)
                    );
                });
            }
            Ended::Decline(held) =>
            {
                bounded(|| {
                    std::os::seraph::log!(
                        warn: "fault badge={} addr={:#x} hold timed out after {} ms",
                        fault.badge,
                        fault.addr(),
                        held_ms(&held)
                    );
                });
                handle_fault(&fault.rebuilt(), policy, authority, ipc_buf, self.dump());
            }
            Ended::Withdrawn(held) =>
            {
                bounded(|| {
                    std::os::seraph::log!(
                        "fault badge={} addr={:#x} withdrawn after {} ms held",
                        fault.badge,
                        fault.addr(),
                        held_ms(&held)
                    );
                });
            }
            Ended::Undelivered(held) =>
            {
                bounded(|| {
                    std::os::seraph::log!(
                        warn: "fault badge={} addr={:#x} not delivered to its hold in {} ms; \
                               slot {slot} endpoint replaced",
                        fault.badge,
                        fault.addr(),
                        held_ms(&held)
                    );
                });
                self.replace(slot);
            }
        }
    }

    /// Record that `slot`'s fault reached its endpoint, and take the endpoint
    /// out of the wait set, which would otherwise return it on every wait
    /// while the fault waits there.
    fn arrived(&mut self, slot: usize)
    {
        let Some(&target) = self.endpoints.get(slot)
        else
        {
            return;
        };
        let _ = syscall::wait_set_remove(self.wait_set, target);
        self.holds.arrived(slot);
    }

    /// Give `slot` a new endpoint in place of the one its undelivered fault
    /// was redirected to. crashd's cap and the wait set's membership go, so
    /// a late delivery's own reference is that endpoint's last, and the fault
    /// is released unhandled when it parks there
    /// (docs/fault-handling.md § Liveness, rule 1). With no new endpoint the
    /// slot is retired.
    fn replace(&mut self, slot: usize)
    {
        let Some(cell) = self.endpoints.get_mut(slot)
        else
        {
            return;
        };
        let _ = syscall::wait_set_remove(self.wait_set, *cell);
        delete_caps(&[*cell]);
        *cell = std::os::seraph::object_slab_retype(std::os::seraph::ENDPOINT_RETYPE_BYTES, |s| {
            syscall::cap_create_endpoint(s).ok()
        })
        .unwrap_or(0);
        if *cell == 0
        {
            self.holds.retire(slot);
            bounded(|| {
                std::os::seraph::log!(warn: "hold slot {slot} retired: no endpoint made");
            });
        }
    }
}

/// The thread and page of a fault crashd may hold: a page fault memmgr
/// declined for want of memory ([`oom_hold::holdable`]); `None` for every
/// other fault.
fn holdable(msg: &IpcMessage) -> Option<Key>
{
    (msg.word(0) == FAULT_KIND_VM
        && msg.word_count() > FAULT_FORWARD_REASON_WORD
        && oom_hold::holdable(msg.word(FAULT_FORWARD_REASON_WORD)))
    .then(|| Key {
        badge: msg.badge,
        page: msg.word(1) & !(PAGE_SIZE - 1),
    })
}

/// memmgr's level; `CRITICAL` when it cannot be read, so a held fault is
/// declined at its deadline rather than resumed into another decline.
fn read_level() -> Level
{
    match std::os::seraph::memory_pressure()
    {
        Some(std::os::seraph::MemoryPressure::Critical) | None => Level::Critical,
        Some(_) => Level::BelowCritical,
    }
}

/// Milliseconds `held` has been held.
fn held_ms(held: &Held) -> u64
{
    now_ms().saturating_sub(held.since)
}

/// Run `log`, a log write outside a fault's report, under the watchdog's
/// bound, so a log write that waits on a stuck driver does not stop crashd
/// serving faults and ending holds.
fn bounded(log: impl FnOnce())
{
    let generation = BOUND.arm(now_ms(), FAULT_BOUND_MS);
    log();
    if BOUND.end(generation)
    {
        await_settled(generation);
    }
}
