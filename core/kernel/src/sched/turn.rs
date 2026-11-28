// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/turn.rs

//! Turn lending: a fair caller's turn goes with its call to a fair server and
//! comes back with the reply (core/kernel/docs/scheduler.md § Time Slice
//! Policy, "Lent turns"; § Service Call Latency).
//!
//! A thread's [`lent_turn`](ThreadControlBlock::lent_turn) word holds the
//! ticks of a turn the thread runs on before its own slice: the low
//! [`TURN_TICKS`] bits count the ticks, and the rest is the tag of whose turn
//! it is. A zero tag is the thread's own turn, moved out of its slice at its
//! call ([`lend_turn_out`]); a caller's tag ([`lender_tag`]) marks a turn
//! the thread took from that caller with the call it serves ([`take_turn`]).
//! A turn is moved, never copied: the call moves the caller's remainder out
//! of its slice, the bind moves it to the server, the reply or a claimant that
//! ends the call unanswered moves what is left back ([`return_turn`],
//! [`reclaim_turn`]), and the tick charges it ([`charge_tick`]). Each move
//! of ticks out of a server's word is a compare-and-swap that holds only while
//! the word carries the caller's tag, so a claimant on another CPU that wins
//! the binding and a late one that lost it to a later bind never move a turn
//! twice.

use core::sync::atomic::Ordering;

use super::thread::ThreadControlBlock;

/// The tick count of a [`lent_turn`](ThreadControlBlock::lent_turn) word: its
/// low 31 bits. A turn is at most one slice, far below the field's range.
pub const TURN_TICKS: u64 = 0x7FFF_FFFF;

/// The bit of a tag that marks a caller's turn, set in every
/// [`lender_tag`]; a word without it holds the thread's own turn.
const LENT: u64 = 1 << 31;

/// The tag a turn taken from the caller of thread id `tid` carries in its
/// server's word: the id in the high half and [`LENT`].
pub fn lender_tag(tid: u32) -> u64
{
    (u64::from(tid) << 32) | LENT
}

/// The ticks of `word`.
pub const fn ticks(word: u64) -> u64
{
    word & TURN_TICKS
}

/// The tag of `word`: zero for the thread's own turn, a [`lender_tag`] for a
/// caller's.
pub const fn tag(word: u64) -> u64
{
    word & !TURN_TICKS
}

/// `word` with `more` ticks added, its tag kept.
pub const fn with_more_ticks(word: u64, more: u64) -> u64
{
    let sum = ticks(word).saturating_add(more);
    let capped = if sum > TURN_TICKS { TURN_TICKS } else { sum };
    tag(word) | capped
}

/// What the tick does with a thread's turn ([`charge_tick`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TickCharge
{
    /// A tick of a lent turn was charged, or a caller's turn the thread serves
    /// on has just run out: the slice is not charged and the thread runs on.
    /// The thread then goes on on its own slice, and the reply sends the
    /// caller to the tail ([`Returned::RanOut`]).
    Lent,
    /// The last tick of the thread's own turn, which its call moved out of its
    /// slice, was charged: the slice expires now.
    OwnTurnEnds,
    /// No lent tick is left: the tick is the slice's.
    Slice,
}

/// The tick's charge of `word`: the word after it, `None` when the word
/// holds no tick, and what it means for the slice.
pub const fn charged(word: u64) -> (Option<u64>, TickCharge)
{
    let left = ticks(word);
    if left == 0
    {
        return (None, TickCharge::Slice);
    }
    let after = tag(word) | left.saturating_sub(1);
    if left == 1 && tag(word) == 0
    {
        (Some(after), TickCharge::OwnTurnEnds)
    }
    else
    {
        (Some(after), TickCharge::Lent)
    }
}

/// How a reply finds the caller's turn ([`return_turn`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Returned
{
    /// The server held no turn of this caller: the call was not both fair, or
    /// a claimant already took the turn back.
    NotHeld,
    /// What was left of the turn went back to the caller.
    InTime,
    /// The turn ran out during the request: the caller goes to the tail of its
    /// queue with a fresh turn, as at a slice expiry.
    RanOut,
}

/// The tag of `caller`'s turn in a server's word.
///
/// # Safety
/// `caller` is a valid TCB.
unsafe fn caller_tag(caller: *mut ThreadControlBlock) -> u64
{
    // SAFETY: caller is valid (contract); thread_id is fixed at creation.
    lender_tag(unsafe { (*caller).thread_id })
}

/// Add `more` ticks to `tcb`'s word, keeping its tag.
///
/// # Safety
/// `tcb` is a valid TCB.
unsafe fn give_ticks(tcb: *mut ThreadControlBlock, more: u64)
{
    if more == 0
    {
        return;
    }
    // SAFETY: tcb is valid (contract); lent_turn is atomic.
    let word = unsafe { &(*tcb).lent_turn };
    // The closure never refuses, so the update cannot fail.
    let _ = word.try_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
        Some(with_more_ticks(w, more))
    });
}

/// Move what is left of the running fair `caller`'s slice into its word as it
/// calls, leaving its slice one tick, which the word's ticks stand in for: the
/// tick charges the word first and expires the slice when the word's last
/// tick goes ([`TickCharge::OwnTurnEnds`]). A caller whose word already holds
/// a turn (one it serves on, or its own, given back by an earlier reply) keeps
/// it, and the bind moves that.
///
/// # Safety
/// `caller` is the thread running on this CPU, with interrupts masked, so no
/// tick of this CPU, the slice's only other writer, runs meanwhile.
pub unsafe fn lend_turn_out(caller: *mut ThreadControlBlock)
{
    // SAFETY: caller is the running thread (contract), whose fields this CPU
    // alone writes while interrupts are masked.
    let tcb = unsafe { &mut *caller };
    if !super::is_fair_level(tcb.priority) || tcb.lent_turn.load(Ordering::Relaxed) != 0
    {
        return;
    }
    let own = tcb.slice_remaining;
    if own > 0
    {
        tcb.lent_turn.store(u64::from(own), Ordering::Relaxed);
        tcb.slice_remaining = 1;
    }
}

/// The fair `server` takes the turn of the fair `caller` whose call it binds,
/// before the binding publishes, so a claimant that wins the binding later
/// finds the turn under the caller's tag. The caller keeps its own word's tag,
/// so a turn it serves on that is given back to it goes on to its own caller.
/// Returns the server's word before the take, for [`untake_turn`] and
/// [`give_displaced_turn`], or `None` when the pair is not both fair and
/// nothing moved. A turn of the server's own that the word held is dropped:
/// a turn is never gained.
///
/// # Safety
/// Both are valid TCBs and `caller` is pinned; the binding endpoint's lock is
/// held with interrupts masked, so this CPU's tick does not charge `server`
/// before the bind commits or is undone.
pub unsafe fn take_turn(
    server: *mut ThreadControlBlock,
    caller: *mut ThreadControlBlock,
) -> Option<u64>
{
    // SAFETY: both valid (contract); the levels are read as hints, as the
    // placement reads them.
    let server_fair = super::is_fair_level(unsafe { (*server).priority });
    // SAFETY: as above.
    let caller_fair = super::is_fair_level(unsafe { (*caller).priority });
    if !(server_fair && caller_fair)
    {
        return None;
    }
    // SAFETY: caller valid (contract); lent_turn is atomic.
    let turn = ticks(unsafe {
        (*caller)
            .lent_turn
            .fetch_and(!TURN_TICKS, Ordering::Relaxed)
    });
    // SAFETY: as above.
    let tag = unsafe { caller_tag(caller) };
    // SAFETY: server valid (contract); lent_turn is atomic.
    Some(unsafe { (*server).lent_turn.swap(tag | turn, Ordering::Relaxed) })
}

/// Undo [`take_turn`] for a bind that did not commit: `server` gets back the
/// word `prior` and `caller` what is left of its turn, unless a claimant
/// already took the turn back.
///
/// # Safety
/// As for [`take_turn`]; `prior` is what it returned for this pair.
pub unsafe fn untake_turn(
    server: *mut ThreadControlBlock,
    caller: *mut ThreadControlBlock,
    prior: Option<u64>,
)
{
    let Some(prior) = prior
    else
    {
        return;
    };
    // SAFETY: caller valid (contract).
    let held = unsafe { caller_tag(caller) };
    // SAFETY: server valid (contract); lent_turn is atomic.
    let took = unsafe {
        (*server)
            .lent_turn
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                (tag(w) == held).then_some(prior)
            })
    };
    if let Ok(word) = took
    {
        // SAFETY: caller valid and pinned (contract).
        unsafe { give_ticks(caller, ticks(word)) };
    }
}

/// A rebind displaced `displaced`, the caller the server's word `prior`
/// held a turn of before [`take_turn`] replaced it: give it back what is
/// left.
///
/// # Safety
/// `displaced` is null or a valid TCB, pinned by the rebind's swap; `prior`
/// is what `take_turn` returned for the rebind.
pub unsafe fn give_displaced_turn(displaced: *mut ThreadControlBlock, prior: Option<u64>)
{
    let Some(prior) = prior
    else
    {
        return;
    };
    // SAFETY: displaced is valid when non-null (contract).
    if displaced.is_null() || tag(prior) != unsafe { caller_tag(displaced) }
    {
        return;
    }
    // SAFETY: displaced valid and pinned (contract).
    unsafe { give_ticks(displaced, ticks(prior)) };
}

/// The reply of `server` to `caller` gives the caller back what is left of
/// the turn the server took from it, and a fresh turn of its own when that
/// turn ran out during the request, for the tail link the reply then makes.
///
/// # Safety
/// Both are valid TCBs; `caller` is pinned by the won reply claim, or by the
/// claimant's won claim for [`reclaim_turn`].
pub unsafe fn return_turn(
    server: *mut ThreadControlBlock,
    caller: *mut ThreadControlBlock,
) -> Returned
{
    // SAFETY: caller valid (contract).
    let held = unsafe { caller_tag(caller) };
    // SAFETY: server valid (contract); lent_turn is atomic.
    let took = unsafe {
        (*server)
            .lent_turn
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                (tag(w) == held).then_some(0)
            })
    };
    let Ok(word) = took
    else
    {
        return Returned::NotHeld;
    };
    let left = ticks(word);
    if left > 0
    {
        // SAFETY: caller valid and pinned (contract).
        unsafe { give_ticks(caller, left) };
        return Returned::InTime;
    }
    // A caller on its own turn starts its next one; one that serves a call
    // on its own caller's turn keeps that word, now spent, and goes on on its
    // own slice.
    // SAFETY: caller valid and pinned (contract); the level is read as a hint.
    let quantum = u64::from(super::quantum_ticks(unsafe { (*caller).priority }));
    // SAFETY: caller valid (contract); lent_turn is atomic.
    let _ = unsafe {
        (*caller)
            .lent_turn
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                (w == 0).then_some(quantum)
            })
    };
    Returned::RanOut
}

/// A claimant that ends `caller`'s call to `server` unanswered (the server's
/// next receive, a cancel, a timed call's expiry, a dealloc, a fault
/// redelivery) gives the caller back what is left of its turn.
///
/// # Safety
/// Both are valid TCBs; the claimant won `server`'s binding of `caller`,
/// which pins `caller`.
pub unsafe fn reclaim_turn(server: *mut ThreadControlBlock, caller: *mut ThreadControlBlock)
{
    // SAFETY: the contract, which is return_turn's.
    let _ = unsafe { return_turn(server, caller) };
}

/// Charge this CPU's tick to the turn `current`, the thread running here,
/// holds in its word, if any ([`charged`]). A claimant on another CPU may
/// take the turn back at any moment, so the charge is a compare-and-swap.
///
/// # Safety
/// `current` is the thread running on this CPU, a valid TCB.
pub unsafe fn charge_tick(current: *mut ThreadControlBlock) -> TickCharge
{
    // SAFETY: current valid (contract); lent_turn is atomic.
    let word = unsafe { &(*current).lent_turn };
    let mut charge = TickCharge::Slice;
    let _ = word.try_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
        let (after, what) = charged(w);
        charge = what;
        after
    });
    charge
}

#[cfg(test)]
mod tests
{
    use super::*;

    const CALLER: u32 = 7;
    const SERVER: u32 = 9;

    #[test]
    fn a_tag_names_its_lender_and_keeps_clear_of_the_ticks()
    {
        assert_eq!(tag(lender_tag(0)), lender_tag(0));
        assert_ne!(lender_tag(0), 0);
        assert_eq!(ticks(lender_tag(u32::MAX)), 0);
        assert_ne!(lender_tag(CALLER), lender_tag(SERVER));
        assert_eq!(ticks(lender_tag(CALLER) | 5), 5);
        assert_eq!(tag(lender_tag(CALLER) | 5), lender_tag(CALLER));
    }

    #[test]
    fn added_ticks_keep_the_tag_and_saturate_the_field()
    {
        let word = lender_tag(CALLER) | 3;
        assert_eq!(with_more_ticks(word, 4), lender_tag(CALLER) | 7);
        assert_eq!(
            with_more_ticks(word, u64::MAX),
            lender_tag(CALLER) | TURN_TICKS
        );
        assert_eq!(with_more_ticks(0, 2), 2);
    }

    #[test]
    fn the_tick_charges_a_lent_turn_before_the_slice()
    {
        // A caller's turn: every tick is the turn's, its last included, after
        // which the slice is charged again.
        let mut word = lender_tag(CALLER) | 2;
        let (after, what) = charged(word);
        assert_eq!(what, TickCharge::Lent);
        word = after.unwrap();
        let (after, what) = charged(word);
        assert_eq!(what, TickCharge::Lent);
        word = after.unwrap();
        assert_eq!(word, lender_tag(CALLER));
        assert_eq!(charged(word), (None, TickCharge::Slice));

        // The thread's own turn: its last tick expires the slice.
        assert_eq!(charged(2), (Some(1), TickCharge::Lent));
        assert_eq!(charged(1), (Some(0), TickCharge::OwnTurnEnds));
        assert_eq!(charged(0), (None, TickCharge::Slice));
    }
    /// A zeroed TCB with `tid` at `level` and `slice` ticks of slice. Only
    /// the fields the turn functions touch are set; the rest stay zero, as for
    /// the run-queue tests' TCBs. Leaked: a test reaches it through the raw
    /// pointer alone.
    fn tcb(tid: u32, level: u8, slice: u32) -> *mut ThreadControlBlock
    {
        // SAFETY: the turn functions read only thread_id, priority,
        // slice_remaining and lent_turn, each valid at any bit pattern set
        // below; the other fields are never read.
        let mut tcb: ThreadControlBlock = unsafe { core::mem::zeroed() };
        tcb.thread_id = tid;
        tcb.priority = level;
        tcb.slice_remaining = slice;
        Box::into_raw(Box::new(tcb))
    }

    // Host tests are single-threaded and every TCB is a live leaked box, so
    // the contracts of the turn functions hold; these wrappers state that
    // once.

    fn word(t: *mut ThreadControlBlock) -> u64
    {
        // SAFETY: t is a live TCB (above).
        unsafe { (*t).lent_turn.load(Ordering::Relaxed) }
    }

    fn slice(t: *mut ThreadControlBlock) -> u32
    {
        // SAFETY: as above.
        unsafe { (*t).slice_remaining }
    }

    fn lend(t: *mut ThreadControlBlock)
    {
        // SAFETY: as above.
        unsafe { lend_turn_out(t) }
    }

    fn take(s: *mut ThreadControlBlock, c: *mut ThreadControlBlock) -> Option<u64>
    {
        // SAFETY: as above.
        unsafe { take_turn(s, c) }
    }

    fn untake(s: *mut ThreadControlBlock, c: *mut ThreadControlBlock, prior: Option<u64>)
    {
        // SAFETY: as above.
        unsafe { untake_turn(s, c, prior) }
    }

    fn displaced(d: *mut ThreadControlBlock, prior: Option<u64>)
    {
        // SAFETY: as above.
        unsafe { give_displaced_turn(d, prior) }
    }

    fn back(s: *mut ThreadControlBlock, c: *mut ThreadControlBlock) -> Returned
    {
        // SAFETY: as above.
        unsafe { return_turn(s, c) }
    }

    fn reclaim(s: *mut ThreadControlBlock, c: *mut ThreadControlBlock)
    {
        // SAFETY: as above.
        unsafe { reclaim_turn(s, c) }
    }

    fn tick(t: *mut ThreadControlBlock) -> TickCharge
    {
        // SAFETY: as above.
        unsafe { charge_tick(t) }
    }

    const LEVEL: u8 = 10;

    // Defect caught (#1732): a turn copied rather than moved (the caller keeps
    // its remainder while the server spends it, so a call gains the pair a
    // turn), the slice charged while a lent turn lasts, or the reply giving
    // back more or less than the server left.
    #[test]
    fn a_call_moves_the_callers_turn_to_the_server_and_the_reply_moves_it_back()
    {
        let caller = tcb(CALLER, LEVEL, 7);
        let server = tcb(SERVER, LEVEL, 4);
        lend(caller);
        assert_eq!((word(caller), slice(caller)), (7, 1));
        assert_eq!(take(server, caller), Some(0));
        assert_eq!(word(caller), 0);
        assert_eq!(word(server), lender_tag(CALLER) | 7);
        assert_eq!(tick(server), TickCharge::Lent);
        assert_eq!(tick(server), TickCharge::Lent);
        assert_eq!(slice(server), 4);
        assert_eq!(back(server, caller), Returned::InTime);
        assert_eq!((word(caller), word(server)), (5, 0));
        // The caller spends what came back, then its slice expires.
        for _ in 0..4
        {
            assert_eq!(tick(caller), TickCharge::Lent);
        }
        assert_eq!(tick(caller), TickCharge::OwnTurnEnds);
        assert_eq!(tick(caller), TickCharge::Slice);
    }

    // Defect caught (#1732): a caller whose turn ran out during the request
    // passed again on a spent turn, which lets a caller that keeps calling
    // run ahead of the tail for good; or one sent back with no fresh turn,
    // so its slice expires a tick after it reaches the head.
    #[test]
    fn a_turn_that_runs_out_mid_request_sends_the_caller_round_with_a_fresh_one()
    {
        let caller = tcb(CALLER, LEVEL, 1);
        let server = tcb(SERVER, LEVEL, 4);
        lend(caller);
        assert_eq!(take(server, caller), Some(0));
        assert_eq!(tick(server), TickCharge::Lent);
        assert_eq!(tick(server), TickCharge::Slice);
        assert_eq!(back(server, caller), Returned::RanOut);
        assert_eq!(word(caller), u64::from(super::super::quantum_ticks(LEVEL)));
        assert_eq!(word(server), 0);
    }

    // Defect caught (#1732): a server that calls on while it serves lending
    // its own slice instead of its caller's turn, or a turn given back to it
    // that loses its caller's tag, so the server's reply finds nothing to
    // give back.
    #[test]
    fn a_nested_call_lends_the_callers_turn_on_and_back()
    {
        let caller = tcb(CALLER, LEVEL, 6);
        let first = tcb(SERVER, LEVEL, 4);
        let second = tcb(SERVER + 1, LEVEL, 4);
        lend(caller);
        assert_eq!(take(first, caller), Some(0));
        lend(first);
        assert_eq!(slice(first), 4);
        assert_eq!(take(second, first), Some(0));
        assert_eq!(word(first), lender_tag(CALLER));
        assert_eq!(tick(second), TickCharge::Lent);
        assert_eq!(back(second, first), Returned::InTime);
        assert_eq!(word(first), lender_tag(CALLER) | 5);
        assert_eq!(back(first, caller), Returned::InTime);
        assert_eq!(word(caller), 5);
    }

    // Defect caught (#1732): a claimant that lost the binding to a later bind
    // moving the later caller's turn; a refused bind keeping the turn it took;
    // a rebind's displaced caller losing what was left of its turn; or a pair
    // not both fair moving a turn at all.
    #[test]
    fn only_the_holder_of_the_callers_tag_moves_its_turn()
    {
        let early = tcb(CALLER, LEVEL, 5);
        let late = tcb(CALLER + 1, LEVEL, 3);
        let server = tcb(SERVER, LEVEL, 4);
        lend(early);
        lend(late);
        assert_eq!(take(server, early), Some(0));
        let rebind = take(server, late);
        reclaim(server, early);
        assert_eq!(word(server), lender_tag(CALLER + 1) | 3);
        displaced(early, rebind);
        assert_eq!(word(early), 5);
        untake(server, late, rebind);
        assert_eq!(word(late), 3);
        assert_eq!(word(server), lender_tag(CALLER) | 5);

        let rt = tcb(CALLER + 2, super::super::RT_PRIORITY_MIN, 10);
        lend(rt);
        assert_eq!((word(rt), slice(rt)), (0, 10));
        assert_eq!(take(server, rt), None);
        assert_eq!(back(server, rt), Returned::NotHeld);
    }
}
