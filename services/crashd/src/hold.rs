// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/crashd/src/hold.rs

//! The hold of faults memmgr declined for want of memory
//! (services/crashd/docs/operation.md § Hold).
//!
//! With a stall set (`CRASHD_OOM_STALL_MS`), crashd's thread waits on a wait
//! set of procmgr's crash endpoint, the live-core endpoint and the runtime's
//! memory-pressure Notification, with a timeout of the earliest hold's
//! deadline. A fault that
//! memmgr declined with code 6 or 8 while the level is `CRITICAL`, with code
//! 11 while memmgr's draw room is short of a demand chunk, or with code 7 while
//! both are short, is redirected
//! (`FAULT_REPLY_REDIRECT`) to one of [`SLOTS`] endpoints crashd made at
//! start, where it waits queued, its thread fault-blocked, and no thread of
//! crashd's waits on it. The fault reaches that endpoint only when its thread
//! next runs, so the endpoint is in the wait set from the redirect until the
//! fault arrives, and out of it while the fault waits there. When the memory a
//! held fault waits for is there (the level below `CRITICAL`, for code 11 the
//! draw room open, at a demand chunk's bytes or more, and for code 7 either,
//! each of which memmgr signals on the Notification), crashd receives each such held fault
//! that has arrived from its endpoint and resumes it; when a hold's deadline
//! passes first, it receives that fault and reports and declines it as any
//! other, or, when it has not arrived, replaces the slot's endpoint, so a
//! slot's endpoint only ever queues the one fault crashd holds there. memmgr
//! signals the draw room's opening and not its closing, so crashd reads the
//! draw room again for each code-7 or code-11 fault that reaches it. No core
//! is written while a fault is held or memmgr's memory is short
//! ([`Hold::dump`]). Every receive crashd makes from the crash and live-core
//! endpoints and the slots' endpoints goes through one receive guard, so a
//! receive that keeps failing ends crashd for its restart rather than spinning
//! on a source the wait set keeps returning
//! (`docs/ipc-design.md` § Receive-Failure Policy). The decisions are
//! [`oom_hold`]'s, host-tested.

use core_file::policy::Policy;
use ipc::IpcMessage;
use ipc::recv_guard::RecvGuard;
use oom_hold::{Admit, Ended, Found, Held, Holds, Key, Refusal, Room, Rooms, SLOTS, Waits, Why};
use syscall_abi::{
    FAULT_FORWARD_REASON_WORD, FAULT_KIND_VM, FAULT_LABEL, FAULT_REPLY_KILL, FAULT_REPLY_REDIRECT,
    FAULT_REPLY_RESUME, PAGE_SIZE, SyscallError,
};

use crate::{
    Dump, WAIT_RETRY_MS, WAKE_FAULT, WAKE_LIVE, bounded, delete_caps, guarded, handle_fault,
    now_ms, recv_diag,
};

/// The wait-set badge of the memory-pressure Notification.
const WAKE_PRESSURE: u64 = 2;

/// The wait-set badge of slot 0's endpoint; slot `n`'s is this plus `n`.
const WAKE_SLOT: u64 = 3;

/// One past the wait-set badge of the last slot's endpoint.
const WAKE_SLOT_END: u64 = WAKE_SLOT + SLOTS as u64;

/// Members of the wait set: the crash endpoint, the live-core endpoint, the
/// Notification, and each slot's endpoint.
#[expect(
    clippy::cast_possible_truncation,
    reason = "SLOTS is 16; the sum fits a u32 at compile time"
)]
const WAIT_SET_MEMBERS: u32 = 3 + SLOTS as u32;

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
    /// memmgr's level and draw room as the last read gave them; memmgr
    /// signals `pressure` on every change of the level and every opening of
    /// the draw room, so the level holds until the Notification carries a
    /// bit, and the draw room only while it reads short: a commit overrun
    /// that arrives reads it again ([`Hold::dispatch`]).
    rooms: Rooms,
    /// The guard of every receive crashd's thread makes.
    guard: RecvGuard,
}

/// Serve the crash endpoint `endpoint` with the hold of faults for at most
/// `stall_ms` each, and the live-core endpoint `live` when it is nonzero,
/// as crashd's main loop, after touching the thread's stack and the heap a
/// report under `CRITICAL` uses; return, with nothing made, when the hold
/// cannot start, logged, for the loop without it.
pub fn serve(
    stall_ms: u64,
    endpoint: u64,
    live: u64,
    policy: &Policy,
    authority: u64,
    ipc_buf: *mut u64,
)
{
    let Some(hold) = Hold::start(stall_ms, endpoint, live)
    else
    {
        return;
    };
    crate::touch_stack();
    crate::touch_heap();
    std::os::seraph::log!("holding faults declined for want of memory up to {stall_ms} ms");
    std::os::seraph::log!("reporting crashes");
    hold.serve(endpoint, live, policy, authority, ipc_buf);
}

impl Hold
{
    /// Make the slots' endpoints and the wait set of the crash endpoint
    /// `endpoint`, the live-core endpoint `live` when it is nonzero, and the
    /// pressure Notification, and read memmgr's memory; `None`, logged, with
    /// nothing left made, when the process has no pressure registration or an
    /// object cannot be made.
    fn start(stall_ms: u64, endpoint: u64, live: u64) -> Option<Self>
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
            let Some(cap) = std::os::seraph::create_endpoint()
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
            && syscall::wait_set_add(wait_set, pressure, WAKE_PRESSURE).is_ok()
            && (live == 0 || syscall::wait_set_add(wait_set, live, WAKE_LIVE).is_ok());
        if !joined
        {
            // Deleting the set removes the members it took.
            delete_caps(&[wait_set]);
            delete_caps(&endpoints);
            std::os::seraph::log!(warn: "hold wait set not made; no fault held");
            return None;
        }
        // A change signalled before now is in the read made here.
        let _ = syscall::notification_try_wait(pressure);
        Some(Self {
            holds: Holds::new(stall_ms),
            endpoints,
            messages: [None; SLOTS],
            wait_set,
            pressure,
            rooms: read_rooms(),
            guard: RecvGuard::new(recv_diag),
        })
    }

    /// Serve the crash endpoint `endpoint` with the hold, and the live-core
    /// endpoint `live`: end each hold whose memory is there or whose
    /// deadline passed, then wait for a fault, a live-core request, a signal
    /// from memmgr, or the next deadline. A live core delays the holds' ends
    /// and the faults that arrive meanwhile by at most the dump's bound, as a
    /// crash core does.
    fn serve(
        mut self,
        endpoint: u64,
        live: u64,
        policy: &Policy,
        authority: u64,
        ipc_buf: *mut u64,
    ) -> !
    {
        loop
        {
            self.refresh_rooms();
            self.end_opened(policy, authority, ipc_buf);
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
                    let received = unsafe { ipc::ipc_try_recv(endpoint, ipc_buf) };
                    if let Some(msg) = guarded(&mut self.guard, &received)
                    {
                        self.dispatch(msg, policy, authority, ipc_buf);
                    }
                }
                Ok(WAKE_LIVE) =>
                {
                    // SAFETY: ipc_buf is the registered IPC buffer page.
                    let received = unsafe { ipc::ipc_try_recv(live, ipc_buf) };
                    if let Some(msg) = guarded(&mut self.guard, &received)
                    {
                        let dump = self.dump();
                        crate::live::serve(msg, authority, ipc_buf, dump);
                    }
                }
                // A held fault reached its slot's endpoint; memory that came
                // back for it is acted on at the loop's top.
                Ok(badge) if (WAKE_SLOT..WAKE_SLOT_END).contains(&badge) =>
                {
                    let slot =
                        usize::try_from(badge.saturating_sub(WAKE_SLOT)).unwrap_or(usize::MAX);
                    self.arrived(slot);
                }
                // A signal from memmgr, read at the loop's top; then a
                // deadline.
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

    /// Take a signal from memmgr and read its level and draw room.
    fn refresh_rooms(&mut self)
    {
        if syscall::notification_try_wait(self.pressure).is_ok()
        {
            self.rooms = read_rooms();
        }
    }

    /// Whether a report or a live core made now may write a core: not while
    /// crashd holds a fault, nor while memmgr's level reads `CRITICAL` or its
    /// draw room is short, read now, since memmgr does not signal the draw
    /// room's closing. A dump's buffers and the file system's writes need
    /// pages, and a fault of the file system's threads memmgr declines for
    /// want of them comes to crashd, which serves nothing until the dump ends,
    /// so a held fault would outlast its stall and the dump would wait on it.
    fn dump(&mut self) -> Dump
    {
        let _ = syscall::notification_try_wait(self.pressure);
        self.rooms = read_rooms();
        let short = self.rooms.level == Room::Short || self.rooms.draw == Room::Short;
        if short || self.holds.held_slots().next().is_some()
        {
            Dump::MemoryShort
        }
        else
        {
            Dump::Allowed
        }
    }

    /// Answer the fault `msg` from the crash endpoint: hold a holdable one,
    /// or resume it at once when the memory it waits for came back since
    /// memmgr declined it; report and decline every other.
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
        self.refresh_rooms();
        let Some(key) = holdable(msg)
        else
        {
            let dump = self.dump();
            handle_fault(msg, policy, authority, ipc_buf, dump);
            return;
        };
        let now = now_ms();
        let fault = Message::of(msg);
        let waits = oom_hold::waits_on(fault.code());
        if waits != Waits::Level
        {
            // memmgr does not signal the draw room's closing, and its decline
            // of this fault may have closed it since the last read; a stale
            // open would resume the fault into the same decline, which then
            // repeats it.
            self.rooms = read_rooms();
        }
        match self.holds.admit(now, key, waits, self.rooms)
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
                        "fault badge={} addr={:#x} resumed at once: {}",
                        fault.badge,
                        fault.addr(),
                        came_back(waits)
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
                let dump = self.dump();
                handle_fault(msg, policy, authority, ipc_buf, dump);
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
        // Until the fault arrives, memory coming back does not end the hold;
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
                "fault badge={} addr={:#x} held: {} (reason={}), up to {stall_ms} ms",
                fault.badge,
                fault.addr(),
                short_of(oom_hold::waits_on(fault.code())),
                fault.code()
            );
        });
    }

    /// End every hold whose memory is there and whose fault has arrived.
    fn end_opened(&mut self, policy: &Policy, authority: u64, ipc_buf: *mut u64)
    {
        let mut opened = [false; SLOTS];
        for slot in self.holds.opened(self.rooms)
        {
            if let Some(cell) = opened.get_mut(slot)
            {
                *cell = true;
            }
        }
        for (slot, _) in opened.iter().enumerate().filter(|(_, open)| **open)
        {
            self.end(slot, Why::RoomOpened, policy, authority, ipc_buf);
        }
    }

    /// End the hold in `slot` because `why`: receive its fault from the slot's
    /// endpoint, and resume it, or report and decline it, or, when it is no
    /// longer queued there, free the slot, or, when it has not arrived by its
    /// deadline, replace the slot's endpoint. Memory that came back before the
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
            Ok(_) =>
            {
                self.guard.on_success();
                Found::Fault
            }
            Err(e) if e == SyscallError::WouldBlock as i64 => Found::Nothing,
            // A receive that failed says nothing of the fault, which may
            // still be queued: the hold stays, and a failure that keeps
            // repeating ends crashd.
            Err(e) =>
            {
                self.guard.on_failure(e);
                return;
            }
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
                        "fault badge={} addr={:#x} resumed after {} ms: {}",
                        fault.badge,
                        fault.addr(),
                        held_ms(&held),
                        came_back(held.waits)
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
                let dump = self.dump();
                handle_fault(&fault.rebuilt(), policy, authority, ipc_buf, dump);
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
        *cell = std::os::seraph::create_endpoint().unwrap_or(0);
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

/// memmgr's memory: the level, short at `CRITICAL`, and the draw room, short
/// below a demand chunk's bytes (`ipc::memmgr_labels::DEMAND_CHUNK_BYTES`),
/// the most one committed draw takes; each short when it cannot be read, so a
/// held fault is declined at its deadline rather than resumed into another
/// decline.
fn read_rooms() -> Rooms
{
    let level = match std::os::seraph::memory_pressure()
    {
        Some(std::os::seraph::MemoryPressure::Critical) | None => Room::Short,
        Some(_) => Room::Open,
    };
    let draw = match std::os::seraph::commit_draw_room_bytes()
    {
        Some(bytes) if bytes >= ipc::memmgr_labels::DEMAND_CHUNK_BYTES => Room::Open,
        Some(_) | None => Room::Short,
    };
    Rooms { level, draw }
}

/// What a held fault that waits for `waits` is short of, as its hold's line
/// names it.
const fn short_of(waits: Waits) -> &'static str
{
    match waits
    {
        Waits::Level => "memory critical",
        Waits::DrawRoom => "no commit draw room",
        Waits::LevelOrDrawRoom => "memory critical and no commit draw room",
    }
}

/// What came back for a fault that waits for `waits`, as its resume's line
/// names it.
const fn came_back(waits: Waits) -> &'static str
{
    match waits
    {
        Waits::Level => "memory no longer critical",
        Waits::DrawRoom => "commit draw room open",
        Waits::LevelOrDrawRoom => "memory no longer critical or commit draw room open",
    }
}

/// Milliseconds `held` has been held.
fn held_ms(held: &Held) -> u64
{
    now_ms().saturating_sub(held.since)
}
