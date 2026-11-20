// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/session.rs

//! The stop state machine of one attached session, apart from the syscalls
//! that carry it out (`services/gdbstub/README.md` § Stop Model).
//!
//! The machine holds the target's thread table, the breakpoints, and the
//! step in flight, and drives the [`Kernel`] the service implements with
//! syscalls and the host tests with a simulated kernel. It keeps these
//! invariants:
//!
//! 1. Every stop a receiver passes on is answered exactly once: a held one,
//!    or one kept beside it, by a resume, a step, a detach, or the drop of
//!    the session; any other at once.
//! 2. Between two resumes GDB is told of, every live bound thread is held,
//!    or was posted an upcall that has not arrived within [`STOP_WAIT`] of
//!    the all-stop's start, or of the post when its creator started it
//!    during the all-stop, or is not yet started, read again meanwhile; an all-stop
//!    that ends with one unstarted at its last read records it
//!    ([`Session::awaits_start`]), and the attach then detaches. A
//!    held stop GDB has been told of is never restarted: it is answered by
//!    a resume, a step, a detach, or the drop, or replaced by an upcall or
//!    `#DB` under its badge, which a thread held on its own stop cannot
//!    make, so the held stop was not its thread's. A repeat of it under its
//!    badge, which can be the kernel's second delivery of it, is kept beside
//!    it and answered with it.
//! 3. A stop is resumed only as its thread's own, or as the restart of a
//!    breakpoint hit or a fault that GDB has not been told of, its pointer
//!    set back to a breakpoint first, which the thread then takes again; a
//!    stop no thread claims is answered [`control::decline_label`].
//! 4. A step is undone (its text through any live thread, its registers on
//!    the held stepped thread) at the end of every all-stop that holds its
//!    thread, before its thread's slot is taken again, and at the detach.
//! 5. Every exit, a detach or the drop when every thread has exited, answers
//!    every held stop; the detach also undoes the step, writes every
//!    breakpoint back through a live thread when one is left, answers the
//!    stops that arrive before procmgr's rebind, and has procmgr restore the
//!    crash bindings.

extern crate alloc;

use alloc::vec::Vec;

use gdb_rsp::command::ThreadId;

use crate::breakpoints::{Breakpoint, Breakpoints};
use crate::control::{self, Credit, Named, Origin, Plan, Repeat, Unclaimed};

/// The most threads one session holds at once: each takes a receiver
/// thread of the service while it is stopped ([`MAX_RECEIVERS`]). An exited
/// thread's slot is taken again.
pub const MAX_THREADS: usize = 32;

/// The most receivers the session asks for: one per held stop and kept
/// delivery, each holding its thread blocked, and one free to take the next
/// stop. Past it, a stop waits on the endpoint until a held one is answered.
pub const MAX_RECEIVERS: usize = 2 * MAX_THREADS;

/// How long an all-stop waits for every thread's upcall to arrive, in
/// milliseconds.
pub const STOP_WAIT: u64 = 2000;

/// How often, in milliseconds, an all-stop posts again to a thread its
/// creator has not started, which takes no upcall until it is.
pub const START_POLL: u64 = 10;

/// How long a detach keeps answering the stops that arrive after its
/// resume, in milliseconds, ended early once none has come for
/// [`DRAIN_QUIET`].
pub const DRAIN_WAIT: u64 = 500;

/// How long, in milliseconds, a detach's drain waits for one more stop
/// before it ends, within [`DRAIN_WAIT`].
pub const DRAIN_QUIET: u64 = 50;

/// How many times a refresh, or the attach, takes procmgr's thread list
/// when a thread it lists exits during the walk of its pages.
pub const REFRESH_TRIES: u32 = 3;

/// A fault or upcall message one receiver took off the endpoint, which that
/// receiver holds, its thread blocked, until the stub answers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stop
{
    /// The receiver holding the message.
    pub receiver: usize,
    /// The badge of the binding it came under.
    pub badge: u64,
    /// Data word 0: the fault kind.
    pub kind: u64,
    /// Data word 1: the exception class, or the upcall's cookie.
    pub detail: u64,
    /// Data word 3: the thread's instruction pointer.
    pub ip: u64,
}

/// A page of procmgr's thread list for the target (`ATTACH_PROCESS`).
#[derive(Debug, Default)]
pub struct Page
{
    /// The length of the list.
    pub count: u64,
    /// The caps of the threads from the first index asked for.
    pub caps: Vec<u64>,
    /// The caps reach the end of the list.
    pub complete: bool,
}

/// What the machine asks of the kernel and of the service around it.
pub trait Kernel
{
    /// A clock, in milliseconds.
    fn now(&mut self) -> u64;
    /// The next stop a receiver passes on, waiting until `until` at most.
    fn next_stop(&mut self, until: u64) -> Option<Stop>;
    /// Have at least `count` receivers on the stub's endpoint, each holding
    /// the stop it takes until it is answered. The service logs a receiver
    /// it cannot start; the session acts on none, since a stop then waits on
    /// the endpoint until a held one is answered, as at [`MAX_RECEIVERS`].
    fn receivers(&mut self, count: usize);
    /// Answer the stop `receiver` holds with `label`.
    fn reply(&mut self, receiver: usize, label: u64);
    /// The pointer of a thread that is stopped or fault-blocked; `None` for
    /// one that runs or has exited.
    fn pc(&mut self, cap: u64) -> Option<u64>;
    /// Set the pointer of a stopped or fault-blocked thread; `false` when
    /// the kernel refuses (the thread runs or has exited).
    fn set_pc(&mut self, cap: u64, pc: u64) -> bool;
    /// Whether the thread has not exited.
    fn alive(&mut self, cap: u64) -> bool;
    /// Whether the thread's creator has started it: a thread procmgr lists
    /// between its process's creation and its start has not been.
    fn started(&mut self, cap: u64) -> bool;
    /// Post the thread an `UPCALL_ANY_INSTRUCTION` upcall; `false` when the
    /// kernel refuses it (the thread has exited or has not been started, or
    /// has an upcall pending).
    fn post_upcall(&mut self, cap: u64) -> bool;
    /// Bind the thread's exception and upcall classes to the stub's
    /// endpoint under the badge of table slot `slot`, with a receiver for it;
    /// `false` when the bind or the receiver fails, which leaves the thread's
    /// bindings as they were.
    fn bind(&mut self, slot: usize, cap: u64) -> bool;
    /// Unbind the thread's upcall class.
    fn unbind_upcall(&mut self, cap: u64);
    /// Delete the cap.
    fn delete(&mut self, cap: u64);
    /// The page of procmgr's thread list from `first`, at most `room` caps,
    /// walked in procmgr's replies of `ATTACH_THREADS_PAGE` caps from the
    /// index past the last reply's, until one reaches the end of the list
    /// or the room.
    fn list(&mut self, first: u64, room: usize) -> Option<Page>;
    /// Arm one instruction's step on the held thread, keeping its undo;
    /// `false` when the step cannot be armed, which leaves the thread as it
    /// was.
    fn prepare_step(&mut self, cap: u64) -> bool;
    /// Undo the step's text through the thread, any live one of the target.
    fn undo_step_text(&mut self, cap: u64);
    /// Undo the step's registers on the held stepped thread.
    fn undo_step_regs(&mut self, cap: u64);
    /// The stepped thread is alive and never stopped: its registers keep
    /// what the step set.
    fn step_abandoned(&mut self, cap: u64);
    /// Write `bytes` into the target's text through the thread; `false`
    /// when the kernel refuses the write.
    fn write_text(&mut self, cap: u64, addr: u64, bytes: &[u8]) -> bool;
    /// Whether the target's text holds the architecture's breakpoint
    /// instruction at `addr`, read through the thread: one the stub planted,
    /// or one the target was built with. Asked only where the architecture
    /// reports the pointer past a breakpoint ([`control::rewound_pc`]).
    fn breakpoint_at(&mut self, cap: u64, addr: u64) -> bool;
    /// Have procmgr restore the target's crash bindings (`DETACH_PROCESS`);
    /// returns whether procmgr answered success.
    fn detach_process(&mut self) -> bool;
}

/// What a table slot holds, as [`Session::slot_state`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState
{
    /// A thread bound under the slot's badge: GDB can select it.
    Live,
    /// No slot: the id is past the table, or names none.
    Absent,
    /// A thread whose bind failed, kept while it lives and hidden from GDB.
    Unbound,
    /// A thread that has exited.
    Gone,
}

impl SlotState
{
    /// The error number a refused `Hg` of a slot in this state answers:
    /// `E04` unbound, `E05` gone, `E01` otherwise. The number names the
    /// cause where the stub's log line cannot reach the host, as when the
    /// target it holds is logd.
    #[must_use]
    pub fn refusal_code(self) -> u8
    {
        match self
        {
            Self::Unbound => 4,
            Self::Gone => 5,
            Self::Live | Self::Absent => 1,
        }
    }
}

/// One stop the session holds.
#[derive(Clone, Copy, Debug)]
struct Held
{
    stop: Stop,
    /// The all-stop that took it has ended, so GDB knows of it.
    reported: bool,
}

/// One thread of the target, in the table slot it was stored in.
#[derive(Debug)]
struct Slot
{
    cap: u64,
    /// Bound under its slot's badge; an unbound thread keeps its slot while
    /// it lives and is not shown to GDB.
    bound: bool,
    held: Option<Held>,
    /// The target's main thread: procmgr's index 0, which procmgr lists
    /// there whether or not it has exited.
    main: bool,
    /// Repeats of the held stop, kept beside it once GDB has been told of
    /// it ([`Unclaimed::Keep`]), and answered with it.
    beside: Vec<Stop>,
    /// Where this all-stop's upcall to it stands.
    upcall: Upcall,
    gone: bool,
}

impl Slot
{
    fn live(&self) -> bool
    {
        self.bound && !self.gone
    }
}

/// What an undo of the step does when the stepped thread is alive and not
/// held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unheld
{
    /// Keep the step pending, for the thread's next stop.
    Pending,
    /// Undo the step's text anyway, and leave its registers (a detach).
    Abandon,
}

/// Where an all-stop's upcall to a thread stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Upcall
{
    /// Not posted yet.
    Unposted,
    /// Not posted: a read found its creator had not started it.
    Unstarted,
    /// Posted, and not arrived.
    Posted,
}

/// What one read of an all-stop's posts found.
#[derive(Clone, Copy, Debug)]
struct Posted
{
    /// A live thread its creator has not started stays unposted.
    unstarted: bool,
    /// A thread an earlier read of the all-stop found unstarted was posted.
    started: bool,
}

/// How a resume packet ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resumed
{
    /// The target runs; a stop is reported when one comes.
    Running,
    /// Nothing ran: no live thread named, or the step could not be armed.
    Refused,
    /// Every thread has exited; the session is over.
    Exited,
}

/// One attached session.
#[derive(Debug)]
pub struct Session
{
    threads: Vec<Slot>,
    /// The table holds every thread procmgr listed, so a refresh can page
    /// on from the first index the table does not hold.
    complete: bool,
    /// How far past a software breakpoint the architecture reports the
    /// pointer.
    advance: u64,
    stepping: Option<usize>,
    /// The target was resumed and no stop has been reported since.
    running: bool,
    /// The last all-stop ended with a live thread its creator had not
    /// started at its last read, so neither held nor posted.
    unstarted: bool,
    /// The thread register and memory commands act on, by slot.
    pub current: usize,
    /// The breakpoints planted in the target's text.
    pub breakpoints: Breakpoints,
}

impl Session
{
    /// Attach to the threads of `page`, procmgr's list from its start, and
    /// stop them all. A list whose walk a thread's exit can have torn
    /// ([`walk_torn`]) is taken again, [`REFRESH_TRIES`] times in all;
    /// one still torn then is attached as incomplete, so no refresh pages
    /// on from it.
    pub fn attach(k: &mut impl Kernel, advance: u64, page: Page) -> Self
    {
        let mut page = page;
        let mut tries = 1;
        while walk_torn(k, 0, &page.caps)
        {
            let again = if tries < REFRESH_TRIES
            {
                k.list(0, MAX_THREADS)
            }
            else
            {
                None
            };
            let Some(again) = again
            else
            {
                page.complete = false;
                break;
            };
            tries = tries.saturating_add(1);
            for &cap in &page.caps
            {
                k.delete(cap);
            }
            page = again;
        }
        let mut s = Self {
            threads: Vec::new(),
            complete: page.complete,
            advance,
            stepping: None,
            running: true,
            unstarted: false,
            current: 0,
            breakpoints: Breakpoints::new(),
        };
        for (index, cap) in page.caps.into_iter().enumerate()
        {
            let slot = s.add_thread(k, cap);
            if index == 0
                && let Some(t) = s.threads.get_mut(slot)
            {
                t.main = true;
            }
        }
        s.stop_all(k);
        s
    }

    // ── The table ────────────────────────────────────────────────────────

    /// Store `cap` in the slot of an exited thread with no stop held, or
    /// after the last, and bind it under that slot's badge; returns the
    /// slot.
    fn add_thread(&mut self, k: &mut impl Kernel, cap: u64) -> usize
    {
        let free = control::free_slot(self.threads.iter().map(|t| (t.gone, t.held.is_some())));
        let index = free.unwrap_or(self.threads.len());
        if free.is_some() && self.stepping == Some(index)
        {
            self.undo_step(k, Unheld::Pending);
        }
        let bound = k.bind(index, cap);
        let slot = Slot {
            cap,
            bound,
            held: None,
            main: false,
            beside: Vec::new(),
            upcall: Upcall::Unposted,
            gone: !bound && !k.alive(cap),
        };
        if let Some(entry) = self.threads.get_mut(index)
        {
            let old = core::mem::replace(entry, slot);
            k.delete(old.cap);
        }
        else
        {
            self.threads.push(slot);
        }
        index
    }

    /// Mark the exited threads gone; returns how many are alive.
    fn alive_count(&mut self, k: &mut impl Kernel) -> usize
    {
        for t in &mut self.threads
        {
            if !t.gone && !k.alive(t.cap)
            {
                t.gone = true;
            }
        }
        self.threads.iter().filter(|t| !t.gone).count()
    }

    /// Take the threads the target registered since the attach from
    /// procmgr's list and bind them; returns whether one was added.
    /// procmgr lists the main thread at index 0 whether or not it has
    /// exited, then each registered thread still alive in registration
    /// order, so the new ones start after the main thread and the table's
    /// live registered threads. The list is taken again when a thread of
    /// the table, or one the list took, exits during its walk
    /// ([`walk_torn`]).
    fn refresh(&mut self, k: &mut impl Kernel) -> bool
    {
        if !self.complete
        {
            return false;
        }
        for _ in 0..REFRESH_TRIES
        {
            let alive = self.alive_count(k);
            let first = self.unlisted_index();
            let Some(page) = k.list(first, MAX_THREADS.saturating_sub(alive))
            else
            {
                return false;
            };
            if self.alive_count(k) != alive
                || page.count < first
                || walk_torn(k, first, &page.caps)
            {
                for cap in page.caps
                {
                    k.delete(cap);
                }
                continue;
            }
            self.complete = page.complete;
            let added = !page.caps.is_empty();
            for cap in page.caps
            {
                let _ = self.add_thread(k, cap);
            }
            return added;
        }
        false
    }

    /// The index in procmgr's list of the first thread the table does not
    /// hold: one for the main thread, held or exited, and one for each live
    /// registered thread of the table. Read after [`Self::alive_count`].
    fn unlisted_index(&self) -> u64
    {
        let registered = self.threads.iter().filter(|t| !t.gone && !t.main).count();
        (registered as u64).saturating_add(1)
    }

    // ── Stops ────────────────────────────────────────────────────────────

    /// Stop every running thread with an upcall and wait, bounded by
    /// [`STOP_WAIT`], for each stop. A thread its creator has not started
    /// yet is read again every [`START_POLL`] and posted once started, with
    /// a whole [`STOP_WAIT`] from that post. A breakpoint another thread
    /// hits meanwhile is held unreported and set back ([`Self::cancel_hit`]).
    /// Once every thread is held the table is refreshed: a thread the
    /// target spawned since the last refresh, under its spawner's badge,
    /// can have had its stop taken for its spawner's, so every unreported
    /// hold of a breakpoint hit or fault is restarted
    /// ([`Self::restart_unreported`]) and the new threads are stopped too.
    /// Its end makes every held stop reported and finishes the step when
    /// its thread is held.
    pub fn stop_all(&mut self, k: &mut impl Kernel)
    {
        let mut deadline = k.now().saturating_add(STOP_WAIT);
        let mut refreshed = false;
        loop
        {
            let Posted { unstarted, started } = self.post_upcalls(k);
            // A thread its creator started since an earlier read was posted
            // just now: its upcall gets a whole wait from the post, not what
            // is left of the all-stop's.
            if started
            {
                deadline = deadline.max(k.now().saturating_add(STOP_WAIT));
            }
            self.unstarted = unstarted;
            let waiting = self
                .threads
                .iter()
                .any(|t| t.live() && t.held.is_none() && t.upcall == Upcall::Posted);
            if !waiting && !unstarted
            {
                if refreshed || !self.refresh(k)
                {
                    break;
                }
                refreshed = true;
                self.restart_unreported(k, None);
                continue;
            }
            // A thread not started yet is read again once this wait ends.
            let until = if unstarted
            {
                k.now().saturating_add(START_POLL).min(deadline)
            }
            else
            {
                deadline
            };
            let Some(stop) = self.next_stop(k, until)
            else
            {
                if unstarted && k.now() < deadline
                {
                    continue;
                }
                break;
            };
            if let Some(index) = self.hold(k, stop)
            {
                self.cancel_hit(k, index);
            }
        }
        for t in &mut self.threads
        {
            t.upcall = Upcall::Unposted;
            if let Some(h) = &mut t.held
            {
                h.reported = true;
            }
        }
        self.undo_step(k, Unheld::Pending);
        self.running = false;
    }

    /// The next stop a receiver passes on, waiting until `until` at most,
    /// once a receiver is free to take it: the session asks for one per
    /// held stop and kept delivery, each holding its thread, and one more
    /// ([`MAX_RECEIVERS`] at most).
    fn next_stop(&self, k: &mut impl Kernel, until: u64) -> Option<Stop>
    {
        let holding: usize = self
            .threads
            .iter()
            .map(|t| usize::from(t.held.is_some()).saturating_add(t.beside.len()))
            .sum();
        k.receivers(holding.saturating_add(1).min(MAX_RECEIVERS));
        k.next_stop(until)
    }

    /// Post an upcall to every live thread not held and not yet posted,
    /// except one its creator has not started, which the kernel posts
    /// nothing to until it is, so it stays unposted.
    fn post_upcalls(&mut self, k: &mut impl Kernel) -> Posted
    {
        let mut posted = Posted {
            unstarted: false,
            started: false,
        };
        for t in self
            .threads
            .iter_mut()
            .filter(|t| t.live() && t.held.is_none() && t.upcall != Upcall::Posted)
        {
            // Read before the post, since a thread its creator starts
            // between a refused post and a later read would be taken for
            // one with an upcall pending.
            if !k.started(t.cap) && k.alive(t.cap)
            {
                t.upcall = Upcall::Unstarted;
                posted.unstarted = true;
            }
            else if !k.post_upcall(t.cap) && !k.alive(t.cap)
            {
                t.gone = true;
            }
            else
            {
                // A refused post to a started live thread finds an upcall
                // pending, which arrives as well.
                posted.started |= t.upcall == Upcall::Unstarted;
                t.upcall = Upcall::Posted;
            }
        }
        posted
    }

    /// Take `stop` as its thread's held stop and return the thread's slot,
    /// or settle it ([`control::settle`]) and return `None`.
    fn hold(&mut self, k: &mut impl Kernel, stop: Stop) -> Option<usize>
    {
        let Some((i, cap, held)) = control::thread_index(stop.badge)
            .and_then(|i| self.threads.get(i).map(|t| (i, t.cap, t.held)))
        else
        {
            k.reply(
                stop.receiver,
                control::decline_label(stop.kind, stop.detail),
            );
            return None;
        };
        if self.credit_to(k, i, stop)
        {
            return Some(i);
        }
        let added = self.refresh(k);
        if added
            && control::credit_again(cap, self.threads.get(i).map(|t| t.cap))
            && self.credit_to(k, i, stop)
        {
            return Some(i);
        }
        if added
        {
            self.restart_unreported(k, Some(i));
        }
        self.settle_unclaimed(k, i, held, stop)
    }

    /// Carry out what [`control::settle`] says of `stop`, a delivery under
    /// slot `i`'s badge that the slot's thread, holding `held`, was not
    /// credited. Returns the slot when it now holds `stop` unreported.
    fn settle_unclaimed(
        &mut self,
        k: &mut impl Kernel,
        i: usize,
        held: Option<Held>,
        stop: Stop,
    ) -> Option<usize>
    {
        let decline = |s: &Stop| control::decline_label(s.kind, s.detail);
        let Some(h) = held
        else
        {
            k.reply(stop.receiver, decline(&stop));
            return None;
        };
        match settle_beside(&h, &stop)
        {
            Unclaimed::Restart =>
            {
                self.restart(k, i, h.stop, stop);
                None
            }
            Unclaimed::Adopt =>
            {
                // An adopted stop's predecessors were not the thread's: a new
                // thread's its bind cancelled, or a live one of a thread the
                // stub cannot bind.
                for old in self.replace_held(i, h, stop)
                {
                    k.reply(old.receiver, decline(&old));
                }
                (!h.reported).then_some(i)
            }
            Unclaimed::Redelivered =>
            {
                // A redelivered stop's predecessors the kernel cancelled.
                for old in self.replace_held(i, h, stop)
                {
                    k.reply(old.receiver, syscall_abi::FAULT_REPLY_RESUME);
                }
                (!h.reported).then_some(i)
            }
            Unclaimed::Keep =>
            {
                if let Some(t) = self.threads.get_mut(i)
                {
                    t.beside.push(stop);
                }
                else
                {
                    k.reply(stop.receiver, decline(&stop));
                }
                None
            }
            Unclaimed::Decline =>
            {
                k.reply(stop.receiver, decline(&stop));
                None
            }
        }
    }

    /// Hold `stop` in slot `i` in place of `held`, keeping whether GDB has
    /// been told of the stop; returns the deliveries it replaced, the held
    /// one and those kept beside it, for the caller to answer.
    fn replace_held(&mut self, i: usize, held: Held, stop: Stop) -> Vec<Stop>
    {
        let Some(t) = self.threads.get_mut(i)
        else
        {
            return Vec::from([held.stop, stop]);
        };
        t.held = Some(Held {
            stop,
            reported: held.reported,
        });
        let mut old = core::mem::take(&mut t.beside);
        old.insert(0, held.stop);
        old
    }

    /// Hold `stop` as slot `index`'s own when [`control::credit`] gives it
    /// to the thread: free, and blocked at the stop's pointer.
    fn credit_to(&mut self, k: &mut impl Kernel, index: usize, stop: Stop) -> bool
    {
        let Some((cap, holds)) = self.threads.get(index).map(|t| (t.cap, t.held.is_some()))
        else
        {
            return false;
        };
        let regs_pc = if holds { None } else { k.pc(cap) };
        let set_back = self.rewound(k, cap, &stop, stop.ip);
        if control::credit(holds, regs_pc, stop.ip, set_back) != Credit::Own
        {
            return false;
        }
        let Some(t) = self.threads.get_mut(index)
        else
        {
            return false;
        };
        t.held = Some(Held {
            stop,
            reported: false,
        });
        t.upcall = Upcall::Unposted;
        true
    }

    /// Resume both `held`, slot `index`'s unreported stop, and `stop`, a
    /// second delivery under its badge, both breakpoint hits or faults,
    /// after setting the thread's pointer back to a breakpoint it took:
    /// whichever delivery is live runs the breakpoint or the faulting
    /// instruction again, and the thread stops anew under its own badge.
    fn restart(&mut self, k: &mut impl Kernel, index: usize, held: Stop, stop: Stop)
    {
        let cap = self.threads.get_mut(index).map(|t| {
            t.held = None;
            t.upcall = Upcall::Unposted;
            t.cap
        });
        if let Some(cap) = cap
        {
            self.rewind_hit(k, cap, &[held, stop]);
        }
        k.reply(held.receiver, syscall_abi::FAULT_REPLY_RESUME);
        k.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
    }

    /// Restart every held breakpoint hit or fault GDB has not been told of,
    /// but slot `except`'s: after a refresh bound new threads, any of them
    /// can have been a new thread's stop taken for its spawner's. A restart
    /// is idempotent: a live delivery runs the thread's breakpoint, set back
    /// to, or its faulting instruction again, and the thread stops anew; a
    /// delivery the bind cancelled ignores the answer.
    fn restart_unreported(&mut self, k: &mut impl Kernel, except: Option<usize>)
    {
        for i in 0..self.threads.len()
        {
            let Some(h) = self.threads.get(i).and_then(|t| t.held)
            else
            {
                continue;
            };
            if Some(i) == except
                || h.reported
                || control::origin(h.stop.kind, h.stop.detail) == Origin::Own
            {
                continue;
            }
            let Some(t) = self.threads.get_mut(i)
            else
            {
                continue;
            };
            t.held = None;
            t.upcall = Upcall::Unposted;
            let cap = t.cap;
            self.rewind_hit(k, cap, &[h.stop]);
            k.reply(h.stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
        }
    }

    /// Set the held slot `index`'s pointer back to a breakpoint hit the stub
    /// does not report ([`Self::rewind_hit`]).
    fn cancel_hit(&mut self, k: &mut impl Kernel, index: usize)
    {
        if let Some((cap, h)) = self.threads.get(index).and_then(|t| Some((t.cap, t.held?)))
        {
            self.rewind_hit(k, cap, &[h.stop]);
        }
    }

    /// Set the fault-blocked thread `cap`'s pointer back to the breakpoint
    /// it took, when one of `stops` is a breakpoint hit and the architecture
    /// reports the pointer past it ([`Self::rewound`]).
    fn rewind_hit(&self, k: &mut impl Kernel, cap: u64, stops: &[Stop])
    {
        let Some(pc) = k.pc(cap)
        else
        {
            return;
        };
        if let Some(at) = stops.iter().find_map(|s| self.rewound(k, cap, s, pc))
        {
            // The pointer was just read, so the thread is blocked; a refusal
            // means it exited meanwhile, and its stop goes with it.
            let _ = k.set_pc(cap, at);
        }
    }

    /// The breakpoint address `pc` is past after `stop`
    /// ([`control::rewound_pc`]): one the stub planted, or one built into the
    /// target, which the thread `cap` reads in the text, so that a restart
    /// runs either again rather than past it.
    fn rewound(&self, k: &mut impl Kernel, cap: u64, stop: &Stop, pc: u64) -> Option<u64>
    {
        control::rewound_pc(self.advance, stop.kind, stop.detail, pc, |a| {
            self.breakpoints.contains(a) || k.breakpoint_at(cap, a)
        })
    }

    /// Take the stops that arrive while the target runs: an upcall then was
    /// posted to a thread that stopped on a fault first, and is resumed;
    /// the first other stop held stops the target. Returns the slot and
    /// stop to report: the stopping thread's, or another held one's when a
    /// restart released it during the all-stop.
    pub fn poll(&mut self, k: &mut impl Kernel) -> Option<(usize, Stop)>
    {
        if !self.running
        {
            return None;
        }
        let now = k.now();
        let stop = self.next_stop(k, now)?;
        if stop.kind == syscall_abi::FAULT_KIND_UPCALL
        {
            k.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
            return None;
        }
        let index = self.hold(k, stop)?;
        self.stop_all(k);
        let held = |i: usize| {
            let t = self.threads.get(i)?;
            Some((i, t.cap, t.held?.stop))
        };
        let Some((index, cap, stop)) =
            held(index).or_else(|| (0..self.threads.len()).find_map(held))
        else
        {
            self.running = true;
            return None;
        };
        // The stop reported is its thread's last: one the all-stop took
        // after a restart was set back as unreported, and GDB, told of it,
        // reads the pointer the stop carries.
        if k.pc(cap).is_some_and(|pc| pc != stop.ip)
        {
            // A refusal means the thread exited after its stop, which GDB
            // then finds gone.
            let _ = k.set_pc(cap, stop.ip);
        }
        self.current = index;
        Some((index, stop))
    }

    /// GDB's interrupt: stop the target when it runs. Returns whether it
    /// ran, so a stop is to be reported; `false` leaves the session as it
    /// is.
    pub fn interrupt(&mut self, k: &mut impl Kernel) -> bool
    {
        if !self.running
        {
            return false;
        }
        self.stop_all(k);
        true
    }

    // ── Resumes ──────────────────────────────────────────────────────────

    /// Answer every held stop: `FAULT_REPLY_RESUME`, or, for slot
    /// `signalled` stopped on a fault when GDB passes it a nonzero
    /// `signal`, `FAULT_REPLY_KILL`, so the fault takes the outcome it has
    /// with no handler.
    fn resume_all(&mut self, k: &mut impl Kernel, signal: Option<u8>, signalled: usize)
    {
        for (i, t) in self.threads.iter_mut().enumerate()
        {
            if let Some(h) = t.held.take()
            {
                let pass = i == signalled && signal.is_some_and(|s| s != 0);
                let label = if pass && h.stop.kind != syscall_abi::FAULT_KIND_UPCALL
                {
                    syscall_abi::FAULT_REPLY_KILL
                }
                else
                {
                    syscall_abi::FAULT_REPLY_RESUME
                };
                k.reply(h.stop.receiver, label);
                // A delivery kept beside it takes the same answer: whichever
                // is live is the thread's.
                for b in t.beside.drain(..)
                {
                    k.reply(b.receiver, label);
                }
            }
        }
        self.running = true;
    }

    /// Carry out a resume packet's `plan`, after moving the planned
    /// thread's pointer to `addr` when the packet gives one.
    pub fn resume(&mut self, k: &mut impl Kernel, plan: Plan, addr: Option<u64>) -> Resumed
    {
        let thread = match plan
        {
            Plan::Step { thread } | Plan::Continue { thread, .. } => thread,
            Plan::Nothing => return Resumed::Refused,
        };
        if let Some(addr) = addr
            && !self
                .threads
                .get(thread)
                .is_some_and(|t| k.set_pc(t.cap, addr))
        {
            return Resumed::Refused;
        }
        match plan
        {
            Plan::Step { thread } =>
            {
                self.current = thread;
                if self.step(k, thread)
                {
                    Resumed::Running
                }
                else
                {
                    Resumed::Refused
                }
            }
            Plan::Continue { thread, signal } =>
            {
                self.resume_all(k, signal, thread);
                if self.alive_count(k) == 0
                {
                    Resumed::Exited
                }
                else
                {
                    Resumed::Running
                }
            }
            Plan::Nothing => Resumed::Refused,
        }
    }

    /// Step slot `index` one instruction, the others held.
    fn step(&mut self, k: &mut impl Kernel, index: usize) -> bool
    {
        let Some(t) = self.threads.get_mut(index)
        else
        {
            return false;
        };
        let Some(h) = t.held
        else
        {
            return false;
        };
        if !k.prepare_step(t.cap)
        {
            return false;
        }
        t.held = None;
        let beside = core::mem::take(&mut t.beside);
        self.stepping = Some(index);
        k.reply(h.stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
        for b in beside
        {
            k.reply(b.receiver, syscall_abi::FAULT_REPLY_RESUME);
        }
        self.running = true;
        true
    }

    /// Undo the step in flight: its text through any live thread, its
    /// registers when its thread is held. A stepped thread that is alive and
    /// not held keeps the step pending, or has it abandoned, as `unheld`
    /// says.
    fn undo_step(&mut self, k: &mut impl Kernel, unheld: Unheld)
    {
        let Some(s) = self.stepping
        else
        {
            return;
        };
        let stepped = self
            .threads
            .get(s)
            .map(|t| (t.cap, t.held.is_some(), t.gone));
        if let Some((_, false, false)) = stepped
            && unheld == Unheld::Pending
        {
            return;
        }
        let text = match stepped
        {
            Some((cap, _, false)) => Some(cap),
            _ => self.any_cap(),
        };
        if let Some(cap) = text
        {
            k.undo_step_text(cap);
        }
        match stepped
        {
            Some((cap, true, _)) => k.undo_step_regs(cap),
            Some((cap, false, false)) => k.step_abandoned(cap),
            _ =>
            {}
        }
        self.stepping = None;
    }

    // ── Exits ────────────────────────────────────────────────────────────

    /// Detach: undo the step, write every breakpoint back, resume every
    /// thread, answer the stops that arrive before procmgr's rebind
    /// ([`DRAIN_WAIT`]), have procmgr restore the crash bindings, unbind
    /// the upcall class, and drop the caps. Returns procmgr's answer.
    pub fn detach(mut self, k: &mut impl Kernel) -> bool
    {
        if self.stepping.is_some()
        {
            self.undo_step(k, Unheld::Pending);
        }
        if self.stepping.is_some()
        {
            // The stepped thread runs on: one more all-stop for its stop.
            self.running = true;
            self.stop_all(k);
        }
        // A thread registered since the last all-stop is bound, so a stop
        // it has in flight comes again under its own badge, which the drain
        // below finds it by.
        self.refresh(k);
        self.alive_count(k);
        self.undo_step(k, Unheld::Abandon);
        let taken: Vec<Breakpoint> = self.breakpoints.take_all();
        if let Some(cap) = self.any_cap()
        {
            for bp in &taken
            {
                let _ = k.write_text(cap, bp.addr, bp.original());
            }
        }
        let current = self.current;
        self.resume_all(k, None, current);
        self.drain(k, &taken);
        let detached = k.detach_process();
        for t in &self.threads
        {
            k.unbind_upcall(t.cap);
            k.delete(t.cap);
        }
        detached
    }

    /// Answer the stops that arrive within [`DRAIN_WAIT`], until none has
    /// come for [`DRAIN_QUIET`]: each resumed, a hit of one of the `taken`
    /// breakpoints set back to it first, since its bytes are written back.
    fn drain(&mut self, k: &mut impl Kernel, taken: &[Breakpoint])
    {
        let deadline = k.now().saturating_add(DRAIN_WAIT);
        loop
        {
            let until = deadline.min(k.now().saturating_add(DRAIN_QUIET));
            let Some(stop) = self.next_stop(k, until)
            else
            {
                return;
            };
            if let Some(cap) = control::thread_index(stop.badge)
                .and_then(|i| self.threads.get(i))
                .map(|t| t.cap)
                && let Some(pc) = k.pc(cap).filter(|&pc| pc == stop.ip)
                && let Some(at) =
                    control::rewound_pc(self.advance, stop.kind, stop.detail, pc, |a| {
                        taken.iter().any(|b| b.addr == a)
                    })
            {
                // A refusal means the thread exited after its stop, which the
                // resume below then finds cancelled.
                let _ = k.set_pc(cap, at);
            }
            k.reply(stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
        }
    }

    /// End a session whose threads have all exited: answer what is held,
    /// whose deliveries their exit cancelled, and drop the caps.
    pub fn drop_all(self, k: &mut impl Kernel)
    {
        for t in &self.threads
        {
            if let Some(h) = t.held
            {
                k.reply(h.stop.receiver, syscall_abi::FAULT_REPLY_RESUME);
            }
            for b in &t.beside
            {
                k.reply(b.receiver, syscall_abi::FAULT_REPLY_RESUME);
            }
            k.delete(t.cap);
        }
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// The cap of slot `index`'s thread.
    #[must_use]
    pub fn cap(&self, index: usize) -> Option<u64>
    {
        self.threads.get(index).map(|t| t.cap)
    }

    /// The cap of a live thread, the current one first, for memory access.
    #[must_use]
    pub fn any_cap(&self) -> Option<u64>
    {
        self.threads
            .get(self.current)
            .filter(|t| !t.gone)
            .or_else(|| self.threads.iter().find(|t| !t.gone))
            .map(|t| t.cap)
    }

    /// GDB's ids of the live threads: slots plus one.
    #[must_use]
    pub fn live_ids(&self) -> Vec<u64>
    {
        self.threads
            .iter()
            .enumerate()
            .filter(|(_, t)| t.live())
            .map(|(i, _)| (i as u64).saturating_add(1))
            .collect()
    }

    /// The slot of the live thread `thread` names; the current one for
    /// "any" and "all".
    #[must_use]
    pub fn select(&self, thread: ThreadId) -> Option<usize>
    {
        let index = match thread
        {
            ThreadId::Id(id) => usize::try_from(id).ok()?.checked_sub(1)?,
            ThreadId::Any | ThreadId::All => self.current,
        };
        self.threads.get(index).filter(|t| t.live()).map(|_| index)
    }

    /// What the slot `thread` names holds, the reason [`Self::select`]
    /// refuses it when it is not [`SlotState::Live`]; with the table's size.
    #[must_use]
    pub fn slot_state(&self, thread: ThreadId) -> (SlotState, usize)
    {
        let index = match thread
        {
            ThreadId::Id(id) => usize::try_from(id).ok().and_then(|id| id.checked_sub(1)),
            ThreadId::Any | ThreadId::All => Some(self.current),
        };
        let state = match index.and_then(|i| self.threads.get(i))
        {
            None => SlotState::Absent,
            Some(t) if t.gone => SlotState::Gone,
            Some(t) if !t.bound => SlotState::Unbound,
            Some(_) => SlotState::Live,
        };
        (state, self.threads.len())
    }

    /// Whether slot `index` holds a stop.
    #[must_use]
    pub fn is_held(&self, index: usize) -> bool
    {
        self.threads.get(index).is_some_and(|t| t.held.is_some())
    }

    /// Whether the last all-stop ended with a live thread its creator had
    /// not started at the all-stop's last read of it: that thread is neither
    /// held nor posted and, once started, runs on, so the session has no
    /// stop of it to report. The record is the all-stop's, not a new read: a
    /// thread started after that read is unposted all the same.
    #[must_use]
    pub fn awaits_start(&self) -> bool
    {
        self.unstarted
    }
}

/// Whether a walk of procmgr's list that took `caps` from index `first`
/// ([`Kernel::list`]) can have skipped a thread: one taken from a reply
/// before the last, past the main thread at index 0, has exited. procmgr
/// drops an exited thread from the list before each reply, so an exit
/// between two replies moves every later thread one index down, past the
/// next reply's first index. The main thread stays listed after its exit,
/// and an exit of a thread of the last reply moves none the walk takes.
fn walk_torn(k: &mut impl Kernel, first: u64, caps: &[u64]) -> bool
{
    const REPLY: usize = ipc::procmgr_labels::ATTACH_THREADS_PAGE;
    // Every reply but the last is full, so the last starts at the last
    // multiple of a reply below the count.
    let last = (caps.len().saturating_sub(1) / REPLY).saturating_mul(REPLY);
    caps.iter()
        .take(last)
        .zip(first..)
        .any(|(&cap, index)| index != 0 && !k.alive(cap))
}

/// [`control::settle`] of `stop`, a delivery under the badge of a thread
/// holding `held` that was not credited to it.
fn settle_beside(held: &Held, stop: &Stop) -> Unclaimed
{
    let named = if held.reported
    {
        Named::Reported
    }
    else
    {
        Named::Unreported
    };
    let h = &held.stop;
    let repeat = if (h.kind, h.detail, h.ip) == (stop.kind, stop.detail, stop.ip)
    {
        Repeat::Same
    }
    else
    {
        Repeat::Other
    };
    control::settle(
        named,
        control::origin(h.kind, h.detail),
        control::origin(stop.kind, stop.detail),
        repeat,
    )
}

/// Answer a stop that arrives while no session is attached: one of a thread
/// procmgr did not rebind at the detach (it never registered) and that
/// kept the stub's binding, or a late one of the last session. It is
/// declined as no thread's ([`control::decline_label`]). Waits until
/// `until` at most; returns whether a stop came.
pub fn decline_detached(k: &mut impl Kernel, until: u64) -> bool
{
    match k.next_stop(until)
    {
        Some(stop) =>
        {
            k.reply(
                stop.receiver,
                control::decline_label(stop.kind, stop.detail),
            );
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests
{
    //! The machine against a simulated kernel: threads that run, hit
    //! breakpoints, fault, spawn copies of their binding, and exit; an
    //! endpoint whose deliveries a rebind to another binding cancels and
    //! makes again; replies that resume or kill. The simulation records
    //! every invariant it can see broken.

    extern crate std;

    use alloc::collections::VecDeque;
    use std::format;
    use std::string::String;

    use super::*;

    const ADVANCE: u64 = 1;
    const EXC: u64 = syscall_abi::FAULT_KIND_EXCEPTION;
    const BP: u64 = syscall_abi::FAULT_EXC_BREAKPOINT;
    const ILL: u64 = syscall_abi::FAULT_EXC_ILLEGAL_INSTRUCTION;
    const DBG: u64 = syscall_abi::FAULT_EXC_DEBUG;
    const UPCALL: u64 = syscall_abi::FAULT_KIND_UPCALL;
    const RESUME: u64 = syscall_abi::FAULT_REPLY_RESUME;
    const KILL: u64 = syscall_abi::FAULT_REPLY_KILL;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Run
    {
        Running,
        Blocked(usize),
        Exited,
    }

    #[expect(
        clippy::struct_excessive_bools,
        reason = "a simulated thread's flags are independent kernel states the session \
                  reads one by one; they form no state machine"
    )]
    struct Thread
    {
        run: Run,
        pc: u64,
        /// The badge its exception and upcall classes are bound under; `None`
        /// once procmgr took the exception class back.
        badge: Option<u64>,
        upcall_pending: bool,
        registered: bool,
        stepping: bool,
        killed: bool,
    }

    struct Delivery
    {
        thread: usize,
        badge: u64,
        kind: u64,
        detail: u64,
        ip: u64,
        live: bool,
        answers: u32,
        /// A receiver took it, and holds it until it is answered.
        taken: bool,
    }

    struct Sim
    {
        threads: Vec<Thread>,
        ds: Vec<Delivery>,
        queue: VecDeque<usize>,
        time: u64,
        planted: Vec<u64>,
        /// Breakpoints written back: a thread past one resumes mid-instruction.
        restored: Vec<u64>,
        broken: Vec<String>,
        detached: bool,
        crash_endpoint: Vec<usize>,
        /// A step's text is planted and not yet undone.
        step_text: bool,
        /// Breakpoint instructions the target was built with.
        compiled: Vec<u64>,
        /// Threads that exit when next resumed.
        exit_on_resume: Vec<usize>,
        /// Threads whose upcall never arrives.
        deaf: Vec<usize>,
        /// The receivers on the endpoint, and how many hold a delivery.
        receivers: usize,
        busy: usize,
        /// Threads whose bind the kernel refuses.
        refuse_bind: Vec<usize>,
        /// Threads their creator starts only at the given time, before which
        /// the kernel refuses them an upcall.
        unstarted: Vec<(usize, u64)>,
        /// Threads whose upcall arrives the given time after its post.
        late: Vec<(usize, u64)>,
        /// The late upcalls posted, by thread and time due.
        due: Vec<(usize, u64)>,
        /// At the given time the given thread registers a thread its creator
        /// never starts, and a thread it spawned stops under its badge.
        spawn_at: Vec<(u64, usize)>,
        /// Threads that exit between the first two replies of the next walk
        /// of procmgr's list.
        exit_mid_list: Vec<usize>,
    }

    fn cap_of(t: usize) -> u64
    {
        1000 + t as u64
    }

    fn thread_of(cap: u64) -> usize
    {
        usize::try_from(cap - 1000).unwrap()
    }

    impl Sim
    {
        fn new() -> Self
        {
            let mut sim = Self {
                threads: Vec::new(),
                ds: Vec::new(),
                queue: VecDeque::new(),
                time: 0,
                planted: Vec::new(),
                restored: Vec::new(),
                broken: Vec::new(),
                detached: false,
                crash_endpoint: Vec::new(),
                step_text: false,
                compiled: Vec::new(),
                exit_on_resume: Vec::new(),
                deaf: Vec::new(),
                receivers: 0,
                busy: 0,
                refuse_bind: Vec::new(),
                unstarted: Vec::new(),
                late: Vec::new(),
                due: Vec::new(),
                spawn_at: Vec::new(),
                exit_mid_list: Vec::new(),
            };
            sim.spawn(None, true);
            sim
        }

        /// A thread spawned by `parent`, whose binding it copies.
        #[expect(
            clippy::fn_params_excessive_bools,
            reason = "`registered` is the field of the simulated thread it records"
        )]
        fn spawn(&mut self, parent: Option<usize>, registered: bool) -> usize
        {
            let badge = parent.and_then(|p| self.threads[p].badge);
            self.threads.push(Thread {
                run: Run::Running,
                pc: 0x40,
                badge,
                upcall_pending: false,
                registered,
                stepping: false,
                killed: false,
            });
            self.threads.len() - 1
        }

        fn deliver(&mut self, t: usize, kind: u64, detail: u64)
        {
            let Some(badge) = self.threads[t].badge
            else
            {
                return;
            };
            self.ds.push(Delivery {
                thread: t,
                badge,
                kind,
                detail,
                ip: self.threads[t].pc,
                live: true,
                answers: 0,
                taken: false,
            });
            let d = self.ds.len() - 1;
            self.threads[t].run = Run::Blocked(d);
            self.queue.push_back(d);
        }

        /// Thread `t` runs into the planted or built-in breakpoint at `addr`.
        fn hit(&mut self, t: usize, addr: u64)
        {
            assert!(self.planted.contains(&addr) || self.compiled.contains(&addr));
            self.threads[t].pc = addr + ADVANCE;
            self.deliver(t, EXC, BP);
        }

        fn fault(&mut self, t: usize)
        {
            self.deliver(t, EXC, ILL);
        }

        /// The kernel's second delivery of thread `t`'s fault under the same
        /// binding, which cancels the first.
        fn redeliver(&mut self, t: usize)
        {
            let Run::Blocked(d) = self.threads[t].run
            else
            {
                panic!("thread {t} is not blocked");
            };
            self.ds[d].live = false;
            self.queue.retain(|&q| q != d);
            let (badge, kind, detail, ip) = {
                let x = &self.ds[d];
                (x.badge, x.kind, x.detail, x.ip)
            };
            self.ds.push(Delivery {
                thread: t,
                badge,
                kind,
                detail,
                ip,
                live: true,
                answers: 0,
                taken: false,
            });
            let d = self.ds.len() - 1;
            self.threads[t].run = Run::Blocked(d);
            self.queue.push_back(d);
        }

        fn exit(&mut self, t: usize)
        {
            if let Run::Blocked(d) = self.threads[t].run
            {
                self.ds[d].live = false;
                self.queue.retain(|&q| q != d);
            }
            self.threads[t].run = Run::Exited;
        }

        /// Take thread `t`'s queued delivery off the endpoint for a while, as
        /// a receiver slow to pass it on, or a thread blocked elsewhere, makes
        /// it late; returns it for [`Self::release`].
        fn withhold(&mut self, t: usize) -> usize
        {
            let Run::Blocked(d) = self.threads[t].run
            else
            {
                panic!("thread {t} is not blocked");
            };
            self.queue.retain(|&q| q != d);
            d
        }

        fn release(&mut self, d: usize)
        {
            if self.ds[d].live
            {
                self.queue.push_back(d);
            }
        }

        fn plant(&mut self, s: &mut Session, addr: u64)
        {
            self.planted.push(addr);
            s.breakpoints.insert(addr, &[0xcc]);
        }

        fn page(&mut self) -> Page
        {
            self.list(0, MAX_THREADS).unwrap()
        }

        fn held_live(&self, s: &Session) -> bool
        {
            s.threads
                .iter()
                .all(|slot| slot.held.is_none_or(|h| self.ds[h.stop.receiver].live))
        }

        fn assert_sound(&self)
        {
            assert!(self.broken.is_empty(), "{:?}", self.broken);
        }
    }

    impl Kernel for Sim
    {
        fn now(&mut self) -> u64
        {
            self.time
        }

        fn next_stop(&mut self, until: u64) -> Option<Stop>
        {
            // A late upcall arrives at its time, within the wait.
            if self.queue.is_empty()
                && let Some(i) = (0..self.due.len())
                    .filter(|&i| self.due[i].1 <= until)
                    .min_by_key(|&i| self.due[i].1)
            {
                let (t, at) = self.due.remove(i);
                self.time = self.time.max(at);
                if self.threads[t].run == Run::Running
                {
                    self.deliver(t, UPCALL, 0);
                }
            }
            if self.queue.is_empty()
                && let Some(i) = self.spawn_at.iter().position(|&(at, _)| at <= until)
            {
                let (at, parent) = self.spawn_at.remove(i);
                self.time = self.time.max(at);
                let u = self.spawn(Some(parent), true);
                self.unstarted.push((u, u64::MAX));
                let n = self.spawn(Some(parent), true);
                self.deliver(n, UPCALL, 0);
            }
            // A delivery waits on the endpoint while every receiver holds one.
            let taken = if self.busy < self.receivers
            {
                self.queue.pop_front()
            }
            else
            {
                None
            };
            if let Some(d) = taken
            {
                self.busy += 1;
                self.ds[d].taken = true;
                let x = &self.ds[d];
                Some(Stop {
                    receiver: d,
                    badge: x.badge,
                    kind: x.kind,
                    detail: x.detail,
                    ip: x.ip,
                })
            }
            else
            {
                self.time = self.time.max(until);
                None
            }
        }

        fn receivers(&mut self, count: usize)
        {
            self.receivers = self.receivers.max(count);
        }

        fn reply(&mut self, receiver: usize, label: u64)
        {
            self.ds[receiver].answers += 1;
            if self.ds[receiver].answers > 1
            {
                self.broken
                    .push(format!("delivery {receiver} answered twice"));
            }
            else if self.ds[receiver].taken
            {
                self.busy -= 1;
            }
            if !self.ds[receiver].live
            {
                return;
            }
            self.ds[receiver].live = false;
            let (t, kind, detail) = {
                let d = &self.ds[receiver];
                (d.thread, d.kind, d.detail)
            };
            if label == KILL
            {
                self.threads[t].killed = true;
                self.exit(t);
                return;
            }
            if self.exit_on_resume.contains(&t)
            {
                self.exit(t);
                return;
            }
            let pc = self.threads[t].pc;
            let past = pc - ADVANCE;
            if kind == EXC
                && detail == BP
                && (self.planted.contains(&past)
                    || self.restored.contains(&past)
                    || self.compiled.contains(&past))
            {
                self.broken.push(format!(
                    "thread {t} resumed past the breakpoint at {:#x}",
                    pc - ADVANCE
                ));
            }
            self.threads[t].run = Run::Running;
            if self.planted.contains(&pc) || self.compiled.contains(&pc)
            {
                self.hit(t, pc);
            }
            else if kind == EXC && detail != BP && detail != DBG
            {
                self.deliver(t, kind, detail);
            }
            else if self.threads[t].stepping
            {
                self.threads[t].pc += 4;
                self.deliver(t, EXC, DBG);
            }
            else if self.threads[t].upcall_pending
            {
                self.threads[t].upcall_pending = false;
                self.deliver(t, UPCALL, 0);
            }
        }

        fn pc(&mut self, cap: u64) -> Option<u64>
        {
            let t = &self.threads[thread_of(cap)];
            matches!(t.run, Run::Blocked(_)).then_some(t.pc)
        }

        fn set_pc(&mut self, cap: u64, pc: u64) -> bool
        {
            let t = &mut self.threads[thread_of(cap)];
            if !matches!(t.run, Run::Blocked(_))
            {
                return false;
            }
            t.pc = pc;
            true
        }

        fn alive(&mut self, cap: u64) -> bool
        {
            self.threads[thread_of(cap)].run != Run::Exited
        }

        fn started(&mut self, cap: u64) -> bool
        {
            let t = thread_of(cap);
            !self
                .unstarted
                .iter()
                .any(|&(u, at)| u == t && self.time < at)
        }

        fn post_upcall(&mut self, cap: u64) -> bool
        {
            let t = thread_of(cap);
            if !self.started(cap)
            {
                return false;
            }
            if self.deaf.contains(&t)
            {
                return self.threads[t].run != Run::Exited;
            }
            if let Some(&(_, after)) = self.late.iter().find(|&&(u, _)| u == t)
                && self.threads[t].run == Run::Running
            {
                self.due.push((t, self.time + after));
                return true;
            }
            match self.threads[t].run
            {
                Run::Exited => false,
                Run::Running =>
                {
                    self.deliver(t, UPCALL, 0);
                    true
                }
                Run::Blocked(_) =>
                {
                    self.threads[t].upcall_pending = true;
                    true
                }
            }
        }

        fn bind(&mut self, slot: usize, cap: u64) -> bool
        {
            let t = thread_of(cap);
            if self.refuse_bind.contains(&t)
            {
                return false;
            }
            // The service starts a receiver per slot as it binds.
            self.receivers = self.receivers.max(slot + 1);
            let badge = control::thread_badge(slot);
            if self.threads[t].badge == Some(badge)
            {
                return true;
            }
            self.threads[t].badge = Some(badge);
            if let Run::Blocked(d) = self.threads[t].run
                && self.ds[d].live
            {
                // A rebind cancels the delivery in flight and makes it again.
                self.ds[d].live = false;
                self.queue.retain(|&q| q != d);
                let (kind, detail) = (self.ds[d].kind, self.ds[d].detail);
                self.deliver(t, kind, detail);
            }
            true
        }

        fn unbind_upcall(&mut self, _cap: u64) {}

        fn delete(&mut self, _cap: u64) {}

        fn list(&mut self, first: u64, room: usize) -> Option<Page>
        {
            // As the service walks procmgr's list: a reply of at most
            // `ATTACH_THREADS_PAGE` caps from the next index, each reply's
            // list the main thread, thread 0, at index 0 whether or not it
            // has exited, then each registered thread still alive.
            let first = usize::try_from(first).unwrap();
            let mut caps = Vec::new();
            let mut next = first;
            loop
            {
                let listed: Vec<u64> = (0..self.threads.len())
                    .filter(|&t| {
                        t == 0
                            || (self.threads[t].registered && self.threads[t].run != Run::Exited)
                    })
                    .map(cap_of)
                    .collect();
                let reply: Vec<u64> = listed
                    .iter()
                    .skip(next)
                    .take(ipc::procmgr_labels::ATTACH_THREADS_PAGE)
                    .copied()
                    .collect();
                caps.extend(reply.iter().take(room.saturating_sub(caps.len())));
                next += reply.len();
                if reply.is_empty() || next >= listed.len() || caps.len() >= room
                {
                    return Some(Page {
                        count: listed.len() as u64,
                        complete: first + caps.len() >= listed.len(),
                        caps,
                    });
                }
                for t in core::mem::take(&mut self.exit_mid_list)
                {
                    self.exit(t);
                }
            }
        }

        fn prepare_step(&mut self, cap: u64) -> bool
        {
            self.threads[thread_of(cap)].stepping = true;
            self.step_text = true;
            true
        }

        fn undo_step_text(&mut self, cap: u64)
        {
            if self.threads[thread_of(cap)].run == Run::Exited
            {
                self.broken
                    .push(String::from("step text written through an exited thread"));
            }
            self.step_text = false;
        }

        fn undo_step_regs(&mut self, cap: u64)
        {
            self.threads[thread_of(cap)].stepping = false;
        }

        fn step_abandoned(&mut self, _cap: u64) {}

        fn write_text(&mut self, cap: u64, addr: u64, _bytes: &[u8]) -> bool
        {
            if self.threads[thread_of(cap)].run == Run::Exited
            {
                return false;
            }
            self.planted.retain(|&a| a != addr);
            self.restored.push(addr);
            true
        }

        fn breakpoint_at(&mut self, _cap: u64, addr: u64) -> bool
        {
            self.planted.contains(&addr) || self.compiled.contains(&addr)
        }

        fn detach_process(&mut self) -> bool
        {
            self.detached = true;
            // procmgr takes the exception class of every registered thread
            // back; a delivery in flight on the stub's endpoint goes to the
            // crash endpoint.
            for t in 0..self.threads.len()
            {
                if !self.threads[t].registered
                {
                    continue;
                }
                self.threads[t].badge = None;
                if let Run::Blocked(d) = self.threads[t].run
                    && self.ds[d].live
                {
                    self.ds[d].live = false;
                    self.queue.retain(|&q| q != d);
                    self.crash_endpoint.push(t);
                }
            }
            true
        }
    }

    fn attached() -> (Sim, Session)
    {
        let mut sim = Sim::new();
        let page = sim.page();
        let s = Session::attach(&mut sim, ADVANCE, page);
        (sim, s)
    }

    fn resume(sim: &mut Sim, s: &mut Session)
    {
        let r = s.resume(
            sim,
            Plan::Continue {
                thread: s.current,
                signal: None,
            },
            None,
        );
        assert_eq!(r, Resumed::Running);
    }

    // Defect caught: a spawner and a thread it spawned after the attach
    // that hit one breakpoint together: the spawner resumed past its int3,
    // or a held stop whose delivery a bind cancelled kept.
    #[test]
    fn a_spawner_and_its_new_thread_at_one_breakpoint_are_each_held_there()
    {
        for new_first in [true, false]
        {
            let (mut sim, mut s) = attached();
            sim.plant(&mut s, 0x100);
            resume(&mut sim, &mut s);
            let n = sim.spawn(Some(0), true);
            if new_first
            {
                sim.hit(n, 0x100);
                sim.hit(0, 0x100);
            }
            else
            {
                sim.hit(0, 0x100);
                sim.hit(n, 0x100);
            }
            let (index, stop) = s.poll(&mut sim).expect("a stop is reported");
            assert_eq!(stop.kind, EXC);
            assert_eq!(sim.pc(s.cap(index).unwrap()), Some(stop.ip));
            assert!(s.is_held(0) && s.is_held(1), "both threads held");
            assert!(sim.held_live(&s));
            sim.assert_sound();
            // GDB sets the reported thread back to the breakpoint; each
            // thread resumes into it and takes it again, none past it.
            sim.threads[0].pc = 0x100;
            sim.threads[n].pc = 0x100;
            resume(&mut sim, &mut s);
            sim.assert_sound();
        }
    }

    // Defect caught: a spawner's slot reported holding its new thread's
    // stop, which the new thread's bind cancelled, when the spawner's own
    // stop at the same breakpoint came late.
    #[test]
    fn a_spawner_whose_own_stop_is_late_holds_no_cancelled_stop()
    {
        let (mut sim, mut s) = attached();
        sim.plant(&mut s, 0x100);
        resume(&mut sim, &mut s);
        let n = sim.spawn(Some(0), true);
        sim.hit(n, 0x100);
        sim.hit(0, 0x100);
        let late = sim.withhold(0);
        let (index, _) = s.poll(&mut sim).expect("the new thread's stop");
        assert_eq!(
            index, 1,
            "reported as the new thread's, the spawner not held"
        );
        assert!(sim.held_live(&s), "every held stop is live");
        sim.release(late);
        sim.threads[n].pc = 0x100;
        resume(&mut sim, &mut s);
        let _ = s.poll(&mut sim);
        assert!(sim.held_live(&s));
        sim.assert_sound();
    }

    // Defect caught: a stop of a thread the stub cannot bind resumed, past
    // a breakpoint or into the same fault for ever.
    #[test]
    fn a_fault_of_a_thread_the_stub_cannot_bind_is_declined_once()
    {
        let (mut sim, mut s) = attached();
        resume(&mut sim, &mut s);
        let n = sim.spawn(Some(0), false);
        sim.fault(n);
        assert_eq!(s.poll(&mut sim), None);
        assert!(sim.threads[n].killed);
        assert_eq!(sim.ds.iter().filter(|d| d.thread == n).count(), 1);
        sim.assert_sound();
    }

    // Defect caught: a new thread stored in the slot of the exited spawner
    // whose badge it copied, rebound to that same binding, had its live
    // stop declined.
    #[test]
    fn a_new_thread_in_its_exited_spawner_s_slot_is_credited_its_stop()
    {
        let mut sim = Sim::new();
        let worker = sim.spawn(Some(0), true);
        let page = sim.page();
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        sim.plant(&mut s, 0x100);
        resume(&mut sim, &mut s);
        let successor = sim.spawn(Some(worker), true);
        sim.exit(worker);
        sim.hit(successor, 0x100);
        let (index, _) = s.poll(&mut sim).expect("the successor's stop");
        assert_eq!(s.cap(index), Some(cap_of(successor)));
        assert!(!sim.threads[successor].killed);
        assert!(sim.held_live(&s));
        sim.assert_sound();
    }

    // Defect caught: during a step, a new thread's stop under a reported
    // held thread's badge restarted that thread, which then ran.
    #[test]
    fn a_new_thread_s_stop_during_a_step_leaves_the_held_threads_held()
    {
        let mut sim = Sim::new();
        let other = sim.spawn(Some(0), true);
        let page = sim.page();
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        sim.plant(&mut s, 0x100);
        let held = s.threads[1].held.unwrap().stop.receiver;
        let n = sim.spawn(Some(other), true);
        sim.hit(n, 0x100);
        let r = s.resume(&mut sim, Plan::Step { thread: 0 }, None);
        assert_eq!(r, Resumed::Running);
        let _ = s.poll(&mut sim);
        let _ = s.poll(&mut sim);
        assert!(sim.ds[held].live, "the reported thread is still held");
        assert_eq!(sim.ds[held].answers, 0);
        assert!(!sim.threads[other].stepping);
        sim.assert_sound();
    }

    // Defect caught: an x86-64 step's held #DB restarted beside another
    // delivery, running one instruction too many.
    #[test]
    fn a_held_step_trap_is_never_restarted()
    {
        let (mut sim, mut s) = attached();
        let r = s.resume(&mut sim, Plan::Step { thread: 0 }, None);
        assert_eq!(r, Resumed::Running);
        let trap = s.next_stop(&mut sim, 0).expect("the step's #DB");
        assert_eq!((trap.kind, trap.detail), (EXC, DBG));
        assert_eq!(s.hold(&mut sim, trap), Some(0));
        let pc = sim.threads[0].pc;
        // A thread the stub cannot bind faults under its badge meanwhile.
        let n = sim.spawn(Some(0), false);
        sim.fault(n);
        let other = s.next_stop(&mut sim, 0).unwrap();
        assert_eq!(s.hold(&mut sim, other), None);
        assert_eq!(sim.threads[0].pc, pc, "the stepped thread ran no further");
        assert!(sim.ds[trap.receiver].live && sim.ds[trap.receiver].answers == 0);
        sim.assert_sound();
    }

    // Defect caught: a repeat of a reported held stop, from a thread the
    // stub cannot bind, answered the held thread's live delivery with a
    // kill.
    #[test]
    fn a_repeat_of_a_reported_stop_never_kills_the_held_thread()
    {
        let (mut sim, mut s) = attached();
        sim.plant(&mut s, 0x100);
        resume(&mut sim, &mut s);
        sim.hit(0, 0x100);
        let (_, _) = s.poll(&mut sim).expect("the hit");
        let n = sim.spawn(Some(0), false);
        sim.hit(n, 0x100);
        let repeat = s.next_stop(&mut sim, 0).unwrap();
        assert_eq!(s.hold(&mut sim, repeat), None);
        assert!(!sim.threads[0].killed);
        assert!(sim.held_live(&s));
        sim.assert_sound();
    }

    // Defect caught: a detach after every thread exited answered no held
    // stop and sent no DETACH_PROCESS, leaving receivers blocked.
    #[test]
    fn a_detach_answers_every_held_stop_and_restores_the_bindings()
    {
        let (mut sim, s) = attached();
        let held = s.threads[0].held.unwrap().stop.receiver;
        sim.exit(0);
        assert!(s.detach(&mut sim));
        assert!(sim.detached);
        assert_eq!(sim.ds[held].answers, 1);
        sim.assert_sound();
    }

    // Defect caught: a stop pending at the detach was left to the crash
    // endpoint, or a breakpoint hit in it resumed past the restored bytes.
    #[test]
    fn a_detach_answers_a_pending_breakpoint_hit_set_back_to_its_address()
    {
        let mut sim = Sim::new();
        let other = sim.spawn(Some(0), true);
        let page = sim.page();
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        sim.plant(&mut s, 0x100);
        resume(&mut sim, &mut s);
        sim.hit(other, 0x100);
        let (index, _) = s.poll(&mut sim).expect("the hit");
        assert_eq!(index, 1);
        // GDB sets the reported thread back to the breakpoint.
        sim.threads[other].pc = 0x100;
        // A thread spawned after the attach hits it as GDB detaches.
        let late = sim.spawn(Some(0), true);
        sim.hit(late, 0x100);
        assert!(s.detach(&mut sim));
        assert!(
            sim.crash_endpoint.is_empty(),
            "no stop left to the crash endpoint"
        );
        assert_eq!(
            sim.threads[late].pc, 0x100,
            "set back to the restored bytes"
        );
        assert!(sim.threads.iter().all(|t| t.run == Run::Running));
        sim.assert_sound();
    }

    // Defect caught: a stop arriving during a resume, or a fault taken in
    // place of an all-stop's upcall, lost or answered twice.
    #[test]
    fn stops_racing_a_resume_or_an_all_stop_are_each_held_once()
    {
        let mut sim = Sim::new();
        let other = sim.spawn(Some(0), true);
        let third = sim.spawn(Some(0), true);
        let page = sim.page();
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        sim.plant(&mut s, 0x100);
        resume(&mut sim, &mut s);
        // Thread 0 hits the breakpoint at once; the others fault, or hit it
        // too, before their upcalls reach them.
        sim.hit(0, 0x100);
        sim.fault(other);
        sim.hit(third, 0x100);
        let (index, stop) = s.poll(&mut sim).expect("the hit");
        assert_eq!((index, stop.detail), (0, BP));
        assert!(s.is_held(1) && s.is_held(2));
        assert!(sim.held_live(&s));
        // The host goes away mid-session: nothing more is asked, and the
        // target stays held with every delivery answered at most once.
        sim.assert_sound();
        assert!(sim.threads.iter().all(|t| matches!(t.run, Run::Blocked(_))));
        // Or GDB resumes: the unreported hit takes its breakpoint again.
        sim.threads[0].pc = 0x100;
        resume(&mut sim, &mut s);
        sim.assert_sound();
    }

    // Defect caught: a step's planted text left behind when its thread
    // exited before the detach.
    #[test]
    fn a_detach_undoes_a_step_whose_thread_exited_through_a_live_one()
    {
        let mut sim = Sim::new();
        let _other = sim.spawn(Some(0), true);
        let page = sim.page();
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        let r = s.resume(&mut sim, Plan::Step { thread: 0 }, None);
        assert_eq!(r, Resumed::Running);
        // The step's trap is still queued when the stepped thread exits.
        sim.exit(0);
        assert!(s.detach(&mut sim));
        assert!(s_has_no_step(&sim));
        sim.assert_sound();
    }

    // Defect caught: a detach whose extra all-stop missed the stepped
    // thread's trap left the step's text planted.
    #[test]
    fn a_detach_undoes_a_step_whose_trap_never_came()
    {
        let (mut sim, mut s) = attached();
        let r = s.resume(&mut sim, Plan::Step { thread: 0 }, None);
        assert_eq!(r, Resumed::Running);
        // The trap is late past the all-stop's wait.
        let _late = sim.withhold(0);
        assert!(s.detach(&mut sim));
        // Its text is undone; a trap flag on a thread that never stopped
        // cannot be, and stays set.
        assert!(!sim.step_text);
        sim.assert_sound();
    }

    fn s_has_no_step(sim: &Sim) -> bool
    {
        !sim.step_text
            && !sim
                .threads
                .iter()
                .any(|t| t.stepping && t.run != Run::Exited)
    }

    // Defect caught: the kernel's second delivery of a reported breakpoint
    // hit, made during a step of another thread, answered with a kill.
    #[test]
    fn a_redelivery_of_a_reported_stop_is_answered_with_it()
    {
        let mut sim = Sim::new();
        let other = sim.spawn(Some(0), true);
        let page = sim.page();
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        sim.plant(&mut s, 0x100);
        resume(&mut sim, &mut s);
        sim.hit(other, 0x100);
        let (index, _) = s.poll(&mut sim).expect("the hit");
        assert_eq!(index, 1);
        sim.redeliver(other);
        let second = sim.ds.len() - 1;
        let r = s.resume(&mut sim, Plan::Step { thread: 0 }, None);
        assert_eq!(r, Resumed::Running);
        assert_eq!(s.poll(&mut sim), None, "the second delivery is kept");
        let (index, stop) = s.poll(&mut sim).expect("the step's stop");
        assert_eq!((index, stop.detail), (0, DBG));
        assert!(!sim.threads[other].killed);
        // GDB sets the hit back to the breakpoint and continues: the live
        // delivery resumes the thread into it again.
        sim.threads[other].pc = 0x100;
        resume(&mut sim, &mut s);
        assert_eq!(sim.ds[second].answers, 1, "the kept delivery is answered");
        assert!(!sim.threads[other].killed);
        sim.assert_sound();
    }

    // Defect caught: on x86-64, a restart of a hit of a breakpoint the target
    // was built with resumed past it, and the stop was lost.
    #[test]
    fn a_restarted_hit_of_a_built_in_breakpoint_stops_again()
    {
        let (mut sim, mut s) = attached();
        resume(&mut sim, &mut s);
        let _new = sim.spawn(Some(0), true);
        sim.compiled.push(0x200);
        sim.hit(0, 0x200);
        let (index, stop) = s.poll(&mut sim).expect("the breakpoint's stop");
        assert_eq!((index, stop.detail, stop.ip), (0, BP, 0x200 + ADVANCE));
        sim.assert_sound();
    }

    // Defect caught: a thread's own upcall beside a held stop that was not
    // its own left the held one unanswered, or answered the upcall.
    #[test]
    fn a_thread_s_own_upcall_replaces_a_held_stop_of_another_thread()
    {
        let (mut sim, mut s) = attached();
        resume(&mut sim, &mut s);
        let n = sim.spawn(Some(0), false);
        sim.fault(n);
        let theirs = s.next_stop(&mut sim, 0).unwrap();
        // Taken for thread 0's, as a credit at a shared pointer takes it.
        s.threads[0].held = Some(Held {
            stop: theirs,
            reported: false,
        });
        sim.deliver(0, UPCALL, 0);
        let own = s.next_stop(&mut sim, 0).unwrap();
        assert_eq!(s.hold(&mut sim, own), Some(0));
        assert_eq!(
            s.threads[0].held.map(|h| h.stop.receiver),
            Some(own.receiver)
        );
        assert!(sim.threads[n].killed, "the other stop declined");
        assert!(sim.held_live(&s));
        sim.assert_sound();
    }

    // Defect caught: the kernel's second delivery of a held upcall declined,
    // or the first kept, leaving the thread's live delivery unanswered.
    #[test]
    fn a_redelivered_upcall_takes_the_place_of_the_first()
    {
        let (mut sim, mut s) = attached();
        let first = s.threads[0].held.unwrap().stop.receiver;
        sim.redeliver(0);
        let again = s.next_stop(&mut sim, 0).unwrap();
        assert_eq!(s.hold(&mut sim, again), None, "GDB already knows of it");
        assert_eq!(
            s.threads[0].held.map(|h| h.stop.receiver),
            Some(again.receiver)
        );
        assert_eq!(sim.ds[first].answers, 1);
        assert!(sim.held_live(&s));
        resume(&mut sim, &mut s);
        assert_eq!(sim.threads[0].run, Run::Running);
        sim.assert_sound();
    }

    // Defect caught: an all-stop that ended with no thread held reported a
    // stop of none, or left the target taken for stopped.
    #[test]
    fn an_all_stop_that_holds_no_thread_leaves_the_target_running()
    {
        let (mut sim, mut s) = attached();
        resume(&mut sim, &mut s);
        let n = sim.spawn(Some(0), true);
        sim.deaf.push(n);
        sim.exit_on_resume.push(0);
        // Thread 0 faults; the refresh that binds the new thread restarts
        // it, and it exits; the new thread's upcall never arrives.
        sim.fault(0);
        assert_eq!(s.poll(&mut sim), None);
        assert!(s.running);
        sim.assert_sound();
    }

    // Defect caught: a continue after which every thread had exited
    // reported the target running.
    #[test]
    fn a_continue_that_ends_every_thread_reports_the_target_exited()
    {
        let (mut sim, mut s) = attached();
        sim.exit_on_resume.push(0);
        let r = s.resume(
            &mut sim,
            Plan::Continue {
                thread: 0,
                signal: None,
            },
            None,
        );
        assert_eq!(r, Resumed::Exited);
        s.drop_all(&mut sim);
        sim.assert_sound();
    }

    // Defect caught: receivers asked for past MAX_RECEIVERS, one thread each
    // without bound, or one short of it, a stop left with none below it.
    #[test]
    fn the_session_asks_for_one_receiver_more_than_it_holds_up_to_the_bound()
    {
        let (mut sim, mut s) = attached();
        let held = s.threads[0].held.unwrap();
        // Slots of exited threads, each still holding a stop.
        let hold_more = |s: &mut Session, n: usize| {
            for _ in 0..n
            {
                s.threads.push(Slot {
                    cap: cap_of(0),
                    bound: false,
                    held: Some(held),
                    main: false,
                    beside: Vec::new(),
                    upcall: Upcall::Unposted,
                    gone: true,
                });
            }
        };
        hold_more(&mut s, MAX_RECEIVERS - 3);
        let _ = s.next_stop(&mut sim, 0);
        assert_eq!(
            sim.receivers,
            MAX_RECEIVERS - 1,
            "one free beyond those held"
        );
        hold_more(&mut s, 1);
        let _ = s.next_stop(&mut sim, 0);
        assert_eq!(sim.receivers, MAX_RECEIVERS);
        hold_more(&mut s, 1);
        let _ = s.next_stop(&mut sim, 0);
        assert_eq!(sim.receivers, MAX_RECEIVERS, "no more past the bound");
    }

    // Defect caught: a refresh after the main thread's exit paged procmgr's
    // list from the count of the table's live threads, which procmgr's
    // index 0, the exited main thread, put one short: it added a held
    // thread a second time, rebinding it under the new slot's badge.
    #[test]
    fn a_refresh_after_the_main_thread_s_exit_adds_each_thread_once()
    {
        let mut sim = Sim::new();
        let worker = sim.spawn(Some(0), true);
        let page = sim.page();
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        resume(&mut sim, &mut s);
        sim.exit(0);
        let n = sim.spawn(Some(worker), true);
        assert!(s.interrupt(&mut sim));
        assert_eq!(slots_of(&s, worker), 1, "the worker takes one slot");
        assert_eq!(slots_of(&s, n), 1, "the new thread is added once");
        assert_eq!(s.live_ids().len(), 2);
        assert_eq!(
            sim.threads[worker].badge,
            Some(control::thread_badge(1)),
            "the worker stays bound under its own slot's badge"
        );
        assert!(s.is_held(1), "the worker is held");
        assert!(sim.held_live(&s));
        sim.assert_sound();
    }

    /// How many live slots of the table hold simulated thread `t`.
    fn slots_of(s: &Session, t: usize) -> usize
    {
        s.threads
            .iter()
            .filter(|slot| slot.cap == cap_of(t) && !slot.gone)
            .count()
    }

    // Defect caught: a thread that exited between two replies of a
    // refresh's walk of procmgr's list moved the later ones an index down,
    // so the walk skipped one and, taken for complete, the next refresh
    // added a thread the table held.
    #[test]
    fn a_refresh_whose_walk_a_thread_s_exit_tore_takes_the_list_again()
    {
        let (mut sim, mut s) = attached();
        resume(&mut sim, &mut s);
        let new: Vec<usize> = (0..6).map(|_| sim.spawn(Some(0), true)).collect();
        sim.exit_mid_list.push(new[1]);
        assert!(s.interrupt(&mut sim));
        for &t in new.iter().filter(|&&t| t != new[1])
        {
            assert_eq!(slots_of(&s, t), 1, "thread {t} is in one slot");
        }
        resume(&mut sim, &mut s);
        assert!(s.interrupt(&mut sim));
        for &t in new.iter().filter(|&&t| t != new[1])
        {
            assert_eq!(slots_of(&s, t), 1, "thread {t} is in one slot");
        }
        assert!(sim.held_live(&s));
        sim.assert_sound();
    }

    // Defect caught: a thread that exited between two replies of the
    // attach's walk of procmgr's list left a later thread out of the table,
    // never stopped, which a refresh then took for one the table held.
    #[test]
    fn an_attach_whose_walk_a_thread_s_exit_tore_takes_the_list_again()
    {
        let mut sim = Sim::new();
        let workers: Vec<usize> = (0..5).map(|_| sim.spawn(Some(0), true)).collect();
        sim.exit_mid_list.push(workers[0]);
        let page = sim.page();
        let s = Session::attach(&mut sim, ADVANCE, page);
        assert!(s.complete);
        for &t in [0].iter().chain(&workers[1..])
        {
            assert_eq!(slots_of(&s, t), 1, "thread {t} is in one slot");
            assert!(matches!(sim.threads[t].run, Run::Blocked(_)), "thread {t} is held");
        }
        assert!(sim.held_live(&s));
        sim.assert_sound();
    }

    // Defect caught: a simulation that misses a resume past a breakpoint,
    // so every test above passes whatever the machine does.
    #[test]
    fn the_simulation_reports_a_resume_past_a_breakpoint()
    {
        let mut sim = Sim::new();
        sim.planted.push(0x100);
        sim.threads[0].badge = Some(control::thread_badge(0));
        sim.hit(0, 0x100);
        let d = sim.queue.pop_front().unwrap();
        sim.reply(d, RESUME);
        assert_ne!(sim.broken, [] as [String; 0]);
    }

    // Defect caught: a refused `Hg` whose log cannot tell a slot past the
    // table from a thread whose bind failed or one that has exited, the three
    // causes of the E01 a `Hg` answers (#1339).
    #[test]
    fn slot_state_tells_each_reason_a_selection_is_refused()
    {
        let mut sim = Sim::new();
        let refused = sim.spawn(Some(0), true);
        let worker = sim.spawn(Some(0), true);
        // Last, so no later thread of the attach takes its gone slot.
        let exited_unbound = sim.spawn(Some(0), true);
        sim.refuse_bind.extend([refused, exited_unbound]);
        // One thread exits between procmgr's list and its bind.
        let page = sim.page();
        sim.exit(exited_unbound);
        let mut s = Session::attach(&mut sim, ADVANCE, page);
        sim.exit(worker);
        s.alive_count(&mut sim);
        let id = |slot: usize| ThreadId::Id(slot as u64 + 1);
        assert_eq!(s.slot_state(id(0)), (SlotState::Live, 4));
        assert_eq!(s.slot_state(id(refused)), (SlotState::Unbound, 4));
        assert_eq!(s.slot_state(id(exited_unbound)), (SlotState::Gone, 4));
        assert_eq!(s.slot_state(id(worker)), (SlotState::Gone, 4));
        assert_eq!(s.slot_state(id(4)), (SlotState::Absent, 4));
        assert_eq!(s.slot_state(ThreadId::Id(0)), (SlotState::Absent, 4));
        for slot in [refused, exited_unbound, worker, 4]
        {
            assert_eq!(s.select(id(slot)), None);
        }
        assert_eq!(s.select(id(0)), Some(0));
        assert_eq!(SlotState::Absent.refusal_code(), 1);
        assert_eq!(SlotState::Unbound.refusal_code(), 4);
        assert_eq!(SlotState::Gone.refusal_code(), 5);
    }

    // Defect caught: an attach between the target's creation and its start
    // took the kernel's refusal of an upcall to the unstarted main thread
    // for one pending, never posted again, and left the thread to run on
    // once started, while GDB took it for stopped.
    #[test]
    fn an_attach_before_the_targets_start_holds_its_main_thread_once_started()
    {
        let mut sim = Sim::new();
        sim.unstarted.push((0, STOP_WAIT / 4));
        let page = sim.page();
        let s = Session::attach(&mut sim, ADVANCE, page);
        assert!(s.is_held(0), "the main thread runs unheld");
        assert!(!s.awaits_start());
        assert!(sim.time < STOP_WAIT, "the all-stop waited out its bound");
        assert!(s.detach(&mut sim));
        sim.assert_sound();
    }

    // Defect caught: a target its creator had not started by the end of the
    // attach's all-stop was attached holding nothing, so GDB would take a
    // target that then runs for stopped.
    #[test]
    fn a_target_unstarted_past_the_all_stop_awaits_its_start_and_detaches()
    {
        let mut sim = Sim::new();
        sim.unstarted.push((0, STOP_WAIT + START_POLL));
        let page = sim.page();
        let s = Session::attach(&mut sim, ADVANCE, page);
        assert_eq!(sim.time, STOP_WAIT, "the all-stop ends at its bound");
        assert!(!s.is_held(0));
        assert_eq!(s.slot_state(ThreadId::Id(1)).0, SlotState::Live);
        assert!(s.awaits_start());
        assert!(s.detach(&mut sim));
        assert!(sim.detached);
        sim.assert_sound();
    }

    // Defect caught: a target its creator started in the all-stop's last
    // `START_POLL` before its bound, before its last read, was posted with
    // what was left of the wait, and attached holding nothing when its
    // upcall came later, while it ran.
    #[test]
    fn a_target_started_late_in_the_all_stop_gets_a_whole_wait()
    {
        let mut sim = Sim::new();
        sim.unstarted.push((0, STOP_WAIT - START_POLL));
        sim.late.push((0, 2 * START_POLL));
        let page = sim.page();
        let s = Session::attach(&mut sim, ADVANCE, page);
        assert!(s.is_held(0), "the main thread runs unheld");
        assert!(!s.awaits_start());
        assert_eq!(sim.time, STOP_WAIT + START_POLL, "the upcall came at once");
        assert!(s.detach(&mut sim));
        sim.assert_sound();
    }

    // Defect caught: a start read beside a thread a refresh had just added
    // unstarted left the count of unstarted threads as it was, so the
    // started thread was posted with what was left of the wait, and was
    // neither held nor recorded when its upcall came later.
    #[test]
    fn a_start_beside_a_new_unstarted_thread_gets_a_whole_wait()
    {
        let mut sim = Sim::new();
        let a = sim.spawn(Some(0), true);
        sim.unstarted.push((a, STOP_WAIT - 2 * START_POLL + 3));
        sim.late.push((a, 2 * START_POLL));
        sim.spawn_at.push((STOP_WAIT - 2 * START_POLL + 5, 0));
        let page = sim.page();
        let s = Session::attach(&mut sim, ADVANCE, page);
        assert!(s.is_held(1), "the started thread runs unheld");
        assert!(s.awaits_start(), "the thread never started is not recorded");
        assert!(s.detach(&mut sim));
        sim.assert_sound();
    }

    // Defect caught: a target its creator started after the all-stop's last
    // read, in its last `START_POLL`, was read again as started once the
    // all-stop had ended, and attached holding nothing while it ran.
    #[test]
    fn a_target_started_after_the_all_stops_last_read_detaches()
    {
        let mut sim = Sim::new();
        sim.unstarted.push((0, STOP_WAIT - START_POLL / 2));
        let page = sim.page();
        let s = Session::attach(&mut sim, ADVANCE, page);
        assert_eq!(sim.time, STOP_WAIT, "the all-stop ends at its bound");
        assert!(!s.is_held(0));
        assert!(s.awaits_start(), "a target running unheld is attached");
        assert!(s.detach(&mut sim));
        assert!(sim.detached);
        sim.assert_sound();
    }
}
