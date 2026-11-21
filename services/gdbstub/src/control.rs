// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/control.rs

//! The stub's run-control decisions, apart from the syscalls that carry them
//! out: which thread a binding's badge names, whether a stop is that
//! thread's own and what becomes of one that is not, which slot a new
//! thread takes, how a breakpoint hit the stub does not report is undone,
//! and what a resume packet asks of which thread
//! (`services/gdbstub/README.md` § Stop Model).

extern crate alloc;

use alloc::vec::Vec;

use gdb_rsp::command::{Resume, ThreadId, VContAction};

/// The tag of a target thread's binding badge: procmgr's debugger tag
/// (`ipc::procmgr_labels::DEBUGGER_BADGE_TAG`), with bit 63 clear, so procmgr
/// tells the binding as a debugger's and neither the target's process badge
/// nor a crash badge (`services/procmgr/docs/ipc-interface.md`
/// § `ATTACH_PROCESS`).
pub const THREAD_BADGE_TAG: u64 = ipc::procmgr_labels::DEBUGGER_BADGE_TAG;

/// The badge thread `index` of the stub's table is bound under: the tag with
/// the index plus one. Each thread is bound under the index it is stored at,
/// so the badge of a stop names the table entry that holds the thread.
#[must_use]
pub fn thread_badge(index: usize) -> u64
{
    THREAD_BADGE_TAG | (index as u64).saturating_add(1)
}

/// The table index a binding's badge names; `None` for a badge the stub
/// did not mint.
#[must_use]
pub fn thread_index(badge: u64) -> Option<usize>
{
    if badge & THREAD_BADGE_TAG == 0 || badge & (1 << 63) != 0
    {
        return None;
    }
    usize::try_from(badge & !THREAD_BADGE_TAG)
        .ok()?
        .checked_sub(1)
}

/// Whose stop a fault or upcall message is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Credit
{
    /// The thread its badge names: not already held, and blocked at the
    /// message's instruction pointer.
    Own,
    /// Another thread bound under the same badge: one the target spawned
    /// after the attach, which copied its spawner's binding.
    Unknown,
}

/// Credit a stop whose badge names a thread that is already `held` or not,
/// whose register file reads `regs_pc` (`None` when the read is refused, as
/// it is for a running thread, or finds the thread blocked in a syscall),
/// carrying the instruction pointer `stop_ip` (data word 3 of the message).
/// The thread is blocked at the stop's pointer, or at `set_back`, the
/// breakpoint the stop reports a hit of ([`rewound_pc`]), where a restart
/// set the thread's pointer while this delivery waited.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`held` is whether the thread is already held, which the credit compares"
)]
pub fn credit(held: bool, regs_pc: Option<u64>, stop_ip: u64, set_back: Option<u64>) -> Credit
{
    let at_stop = regs_pc.is_some_and(|pc| pc == stop_ip || Some(pc) == set_back);
    if !held && at_stop
    {
        Credit::Own
    }
    else
    {
        Credit::Unknown
    }
}

/// Which threads can make a stop: only the thread an upcall was posted to,
/// or the thread whose step's trap flag took `#DB`; or any thread bound
/// under the badge, as a breakpoint hit or a fault of a thread spawned after
/// the attach, which copied its spawner's binding, is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin
{
    /// Only the thread the badge names: an upcall, or a step's `#DB`.
    Own,
    /// Any thread bound under the badge: a breakpoint hit or a fault.
    Any,
}

/// The [`Origin`] of a stop of kind `kind` and, for an exception, class
/// `detail`.
#[must_use]
pub fn origin(kind: u64, detail: u64) -> Origin
{
    let debug_trap =
        kind == syscall_abi::FAULT_KIND_EXCEPTION && detail == syscall_abi::FAULT_EXC_DEBUG;
    if kind == syscall_abi::FAULT_KIND_UPCALL || debug_trap
    {
        Origin::Own
    }
    else
    {
        Origin::Any
    }
}

/// What the stub does with a stop [`credit`] did not give to the thread its
/// badge names, once a refresh has bound the threads the target spawned
/// since the attach (each bind to a new endpoint or badge cancels the
/// delivery in flight and makes it again under the new binding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unclaimed
{
    /// The named thread is held, GDB has not been told of that stop, and
    /// both stops are breakpoint hits or faults: one delivery is the
    /// thread's own and the other a new thread's or one the kernel made
    /// again, and which is live is unknown. Both are resumed, the thread's
    /// breakpoint hit rewound first ([`rewound_pc`]); a breakpoint or a
    /// fault, run again, stops the thread anew under its own badge.
    Restart,
    /// The new stop is the named thread's own and the held one is not: the
    /// held one, a new thread's credited to it, gives way, and is answered
    /// with [`decline_label`]; the new one is held in its place.
    Adopt,
    /// Both stops are the named thread's own: the new one is the kernel's
    /// second delivery of the held one, which cancelled the first
    /// (docs/fault-handling.md § Delivery, Resume, and Kill, Rebind). The
    /// new one is held in its place, and the first answered with
    /// `FAULT_REPLY_RESUME`, which its cancellation ignores.
    Redelivered,
    /// The named thread holds a breakpoint hit or fault GDB has been told
    /// of, and the new stop repeats it (the same kind, class, and pointer):
    /// the kernel's second delivery of it, which a rebind's race can make
    /// (docs/fault-handling.md § Delivery, Resume, and Kill, Rebind), or a
    /// stop of a thread the stub cannot bind at the same instruction, and
    /// which is live is unknown. Neither is answered now: the new one is
    /// kept beside the held one, and both take the answer the held one
    /// takes, so the live one is the thread's.
    Keep,
    /// Any other stop: a new thread's, cancelled by the refresh's bind, or
    /// one of a thread the stub cannot bind. It is answered with
    /// [`decline_label`]; the held stop stays as it is. A held breakpoint
    /// hit or fault GDB has been told of is never answered here.
    Decline,
}

/// The state of the thread an unclaimed stop's badge names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Named
{
    /// Not held.
    Free,
    /// Held, and GDB has not been told of the stop: the all-stop that took
    /// it has not ended.
    Unreported,
    /// Held, and the all-stop that took it has ended, so GDB knows the
    /// thread stopped there.
    Reported,
}

/// Whether an unclaimed stop repeats the stop its named thread holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Repeat
{
    /// The same kind, class, and pointer as the held stop.
    Same,
    /// Any other stop.
    Other,
}

/// Settle an unclaimed stop of origin `stop`, whose badge names a thread in
/// state `named` holding a stop of origin `held` (any, for a free thread),
/// which the new stop does or does not `repeat`.
#[must_use]
pub fn settle(named: Named, held: Origin, stop: Origin, repeat: Repeat) -> Unclaimed
{
    match (named, held, stop)
    {
        (Named::Reported, Origin::Any, Origin::Any) if repeat == Repeat::Same => Unclaimed::Keep,
        (Named::Free, ..)
        | (_, Origin::Own, Origin::Any)
        | (Named::Reported, Origin::Any, Origin::Any) => Unclaimed::Decline,
        (_, Origin::Any, Origin::Own) => Unclaimed::Adopt,
        (_, Origin::Own, Origin::Own) => Unclaimed::Redelivered,
        (Named::Unreported, Origin::Any, Origin::Any) => Unclaimed::Restart,
    }
}

/// Whether a stop the refresh did not settle is credited again, to the
/// thread now in its slot: when the refresh stored a new thread there (the
/// slot's cap `before` the refresh differs from `after`), that thread copied
/// the slot's badge from the exited spawner it replaces, so its bind, to
/// the binding it already had, cancelled nothing, and its stop is live.
#[must_use]
pub fn credit_again(before: u64, after: Option<u64>) -> bool
{
    after.is_some_and(|cap| cap != before)
}

/// The reply to a stop no thread of the stub's table claims: an upcall or a
/// step's `#DB`, which no thread but the one it names makes, resumes; a
/// breakpoint hit or a fault is declined (`FAULT_REPLY_KILL`), so it takes
/// the outcome it has with no handler bound, rather than resuming past a
/// breakpoint or faulting again for ever. A delivery a bind cancelled
/// ignores the reply.
#[must_use]
pub fn decline_label(kind: u64, detail: u64) -> u64
{
    match origin(kind, detail)
    {
        Origin::Own => syscall_abi::FAULT_REPLY_RESUME,
        Origin::Any => syscall_abi::FAULT_REPLY_KILL,
    }
}

/// The slot of the stub's table a new thread takes: the first of an exited
/// thread with no stop held, so the table stays within the session's
/// [`MAX_THREADS`](crate::session::MAX_THREADS) of live threads however
/// many the target spawns and joins; `None` to append. `slots` gives each
/// slot's (exited, holds a stop).
#[must_use]
pub fn free_slot(slots: impl Iterator<Item = (bool, bool)>) -> Option<usize>
{
    slots
        .enumerate()
        .find_map(|(i, (gone, held))| (gone && !held).then_some(i))
}

/// The pointer to set on a thread held at a breakpoint hit the stub does not
/// report, so that its resume runs the breakpoint again rather than resuming
/// past it: `pc - advance` when the stop is a breakpoint exception, the
/// architecture reports the pointer `advance` bytes past the breakpoint (one
/// on x86-64, none on RISC-V), and `breakpoint_at` says a breakpoint
/// instruction is there (one the stub planted, or one the target was built
/// with). `None` leaves the pointer as it is.
#[must_use]
pub fn rewound_pc(
    advance: u64,
    kind: u64,
    exception: u64,
    pc: u64,
    breakpoint_at: impl FnOnce(u64) -> bool,
) -> Option<u64>
{
    if advance == 0
        || kind != syscall_abi::FAULT_KIND_EXCEPTION
        || exception != syscall_abi::FAULT_EXC_BREAKPOINT
    {
        return None;
    }
    let at = pc.checked_sub(advance)?;
    breakpoint_at(at).then_some(at)
}

/// One held thread a continue resumes, and the signal passed to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Release
{
    /// The thread, by table index.
    pub thread: usize,
    /// The signal, when one is passed (nonzero).
    pub signal: Option<u8>,
}

/// What a resume packet asks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan
{
    /// Run thread `thread` one instruction, the others held.
    Step
    {
        /// The thread to step, by table index.
        thread: usize,
    },
    /// Resume the threads `releases` names, each passed its signal; every
    /// other thread stays held.
    Continue
    {
        /// The thread the packet's first action names, whose pointer the
        /// address of a `c` or `C` packet sets.
        thread: usize,
        /// The threads to resume, in table order; never empty.
        releases: Vec<Release>,
    },
    /// Nothing to run: no action names a live thread.
    Nothing,
}

/// The `vCont` actions a `c`, `C`, `s` or `S` packet stands for:
/// `resume`, passing `signal`, on `selected`, the thread `Hc` selected
/// by table index, alone; or, when `Hc` selected every thread (`None`), on
/// the current thread, with a continue of every other thread. GDB selects a
/// thread with `Hc` before such a packet to resume it alone.
#[must_use]
pub fn packet_actions(
    resume: Resume,
    signal: Option<u8>,
    selected: Option<usize>,
) -> Vec<VContAction>
{
    let thread = selected.map_or(ThreadId::Any, |i| {
        ThreadId::Id((i as u64).saturating_add(1))
    });
    let own = VContAction {
        resume,
        signal,
        thread: Some(thread),
    };
    match selected
    {
        Some(_) => Vec::from([own]),
        None => Vec::from([
            own,
            VContAction {
                resume: Resume::Continue,
                signal: None,
                thread: None,
            },
        ]),
    }
}

/// The plan of a `vCont` packet's `actions` over the live threads `live`,
/// by table index, with `select` mapping a thread id to a live thread's
/// index and `current` the thread "any" names.
///
/// Each thread takes the leftmost action that names it, an action with no
/// thread id or with "all" naming every thread, and a thread no action
/// names stays held, as the remote protocol has it. When a thread's action
/// is a step, that thread alone is stepped, the current one when its action
/// is a step, and every other thread stays held, those a continue action
/// names among them: the riscv64 step plants a breakpoint any thread could
/// take (`services/gdbstub/README.md` § Stop Model, Single-step), and GDB's
/// own software step resumes only the stepped thread for the same reason.
/// Otherwise every thread whose action is a continue is resumed with the
/// action's signal. A step action that passes a signal is a continue
/// passing it: delivering the signal declines the thread's fault, which
/// then takes its outcome with no handler bound, so the thread runs no
/// single instruction to stop after. A stop action asks nothing.
#[must_use]
pub fn plan_vcont(
    mut actions: impl Iterator<Item = VContAction> + Clone,
    current: usize,
    live: impl Iterator<Item = usize>,
    select: impl Fn(ThreadId) -> Option<usize>,
) -> Plan
{
    let names = |a: &VContAction, i: usize| match a.thread
    {
        None | Some(ThreadId::All) => true,
        Some(ThreadId::Any) => i == current,
        Some(t @ ThreadId::Id(_)) => select(t) == Some(i),
    };
    let mut step = None;
    let mut releases = Vec::new();
    for i in live
    {
        let Some(a) = actions.clone().find(|a| names(a, i))
        else
        {
            continue;
        };
        let signal = a.signal.filter(|&s| s != 0);
        match (a.resume, signal)
        {
            (Resume::Step, None) =>
            {
                if step.is_none() || i == current
                {
                    step = Some(i);
                }
            }
            (Resume::Step | Resume::Continue, _) => releases.push(Release { thread: i, signal }),
            (Resume::Stop, _) =>
            {}
        }
    }
    if let Some(thread) = step
    {
        return Plan::Step { thread };
    }
    let Some(first) = releases.first().map(|r| r.thread)
    else
    {
        return Plan::Nothing;
    };
    let thread = actions
        .next()
        .and_then(|a| releases.iter().map(|r| r.thread).find(|&i| names(&a, i)))
        .unwrap_or(first);
    Plan::Continue { thread, releases }
}

#[cfg(test)]
mod tests
{
    use super::*;

    // Defect caught: a thread bound under one index and stored at another,
    // so its stops name the wrong table entry.
    #[test]
    fn a_thread_badge_names_the_index_it_was_minted_for()
    {
        for index in [0, 1, 7, 31]
        {
            assert_eq!(thread_index(thread_badge(index)), Some(index));
        }
        assert_eq!(thread_index(0x1234), None);
        assert_eq!(thread_index(THREAD_BADGE_TAG), None);
        // A crash badge (bit 63) is procmgr's, never the stub's.
        assert_eq!(thread_index((1 << 63) | THREAD_BADGE_TAG | 1), None);
    }

    // Defect caught: a stop of a thread spawned after the attach, under its
    // spawner's badge, credited to the spawner.
    #[test]
    fn a_stop_is_credited_only_to_a_free_thread_blocked_at_its_pointer()
    {
        assert_eq!(credit(false, Some(0x40), 0x40, None), Credit::Own);
        assert_eq!(credit(true, Some(0x40), 0x40, None), Credit::Unknown);
        assert_eq!(credit(false, None, 0x40, None), Credit::Unknown);
        assert_eq!(credit(false, Some(0x44), 0x40, None), Credit::Unknown);
        // A restart set the thread back to the breakpoint the stop reports.
        assert_eq!(credit(false, Some(0x3f), 0x40, Some(0x3f)), Credit::Own);
    }

    // Defect caught: an x86-64 thread held at a breakpoint the stub does not
    // report resumed past its `int3`.
    #[test]
    fn an_unreported_breakpoint_hit_is_rewound_where_the_pointer_is_past_it()
    {
        let exc = syscall_abi::FAULT_KIND_EXCEPTION;
        let bp = syscall_abi::FAULT_EXC_BREAKPOINT;
        let planted = |a| a == 0x100;
        assert_eq!(rewound_pc(1, exc, bp, 0x101, planted), Some(0x100));
        // RISC-V reports the ebreak itself.
        assert_eq!(rewound_pc(0, exc, bp, 0x100, planted), None);
        // An int3 of the target's own, not the stub's.
        assert_eq!(rewound_pc(1, exc, bp, 0x201, planted), None);
        // A step's #DB, or an upcall, is no breakpoint hit.
        assert_eq!(
            rewound_pc(1, exc, syscall_abi::FAULT_EXC_DEBUG, 0x101, planted),
            None
        );
        assert_eq!(
            rewound_pc(1, syscall_abi::FAULT_KIND_UPCALL, 0, 0x101, planted),
            None
        );
    }

    // Defect caught: a spawner's own stop resumed past its breakpoint, and a
    // held stop whose reply a refresh's bind cancelled kept for ever, when a
    // thread spawned after the attach stopped beside it under its badge; a
    // step's held #DB restarted, running one instruction too many; a
    // reported thread restarted during a step, or killed by a repeat of its
    // stop from a thread the stub cannot bind, or by the kernel's second
    // delivery of its own.
    #[test]
    fn an_unclaimed_stop_restarts_only_an_unreported_repeatable_stop()
    {
        use Origin::{Any, Own};
        for repeat in [Repeat::Same, Repeat::Other]
        {
            assert_eq!(
                settle(Named::Unreported, Any, Any, repeat),
                Unclaimed::Restart
            );
            // A step's #DB, or an upcall, held: the new stop is another
            // thread's.
            assert_eq!(
                settle(Named::Unreported, Own, Any, repeat),
                Unclaimed::Decline
            );
            assert_eq!(
                settle(Named::Reported, Own, Any, repeat),
                Unclaimed::Decline
            );
            // The thread's own #DB or upcall arrives: the held stop was not
            // its.
            assert_eq!(
                settle(Named::Unreported, Any, Own, repeat),
                Unclaimed::Adopt
            );
            assert_eq!(settle(Named::Reported, Any, Own, repeat), Unclaimed::Adopt);
            // Two of its own: the kernel delivered the held one again.
            assert_eq!(
                settle(Named::Reported, Own, Own, repeat),
                Unclaimed::Redelivered
            );
            assert_eq!(settle(Named::Free, Any, Any, repeat), Unclaimed::Decline);
        }
        // Beside a reported breakpoint hit or fault: kept when it repeats
        // it, since it can be the kernel's second delivery of it; declined
        // otherwise, never answered in its place.
        assert_eq!(
            settle(Named::Reported, Any, Any, Repeat::Same),
            Unclaimed::Keep
        );
        assert_eq!(
            settle(Named::Reported, Any, Any, Repeat::Other),
            Unclaimed::Decline
        );
    }

    // Defect caught: a new thread stored in the slot of the exited spawner
    // whose badge it copied, rebound to the same binding, had its live stop
    // declined.
    #[test]
    fn a_stop_is_credited_again_only_to_a_new_occupant_of_its_slot()
    {
        assert!(credit_again(0x10, Some(0x20)));
        assert!(!credit_again(0x10, Some(0x10)));
        assert!(!credit_again(0x10, None));
    }

    // Defect caught: a fault no thread claims resumed, so it ran past a
    // breakpoint on x86-64 or faulted again for ever.
    #[test]
    fn an_unclaimed_fault_is_declined_and_an_upcall_or_step_trap_resumed()
    {
        let exc = syscall_abi::FAULT_KIND_EXCEPTION;
        assert_eq!(origin(syscall_abi::FAULT_KIND_UPCALL, 0), Origin::Own);
        assert_eq!(origin(exc, syscall_abi::FAULT_EXC_DEBUG), Origin::Own);
        assert_eq!(origin(exc, syscall_abi::FAULT_EXC_BREAKPOINT), Origin::Any);
        assert_eq!(
            decline_label(syscall_abi::FAULT_KIND_UPCALL, 0),
            syscall_abi::FAULT_REPLY_RESUME
        );
        assert_eq!(
            decline_label(exc, syscall_abi::FAULT_EXC_DEBUG),
            syscall_abi::FAULT_REPLY_RESUME
        );
        assert_eq!(
            decline_label(exc, syscall_abi::FAULT_EXC_BREAKPOINT),
            syscall_abi::FAULT_REPLY_KILL
        );
        assert_eq!(
            decline_label(syscall_abi::FAULT_KIND_VM, 0),
            syscall_abi::FAULT_REPLY_KILL
        );
    }

    // Defect caught: exited threads counted toward the table's bound, so a
    // target that spawned and joined enough threads lost every new one.
    #[test]
    fn a_new_thread_takes_the_first_slot_of_an_exited_one_with_no_stop()
    {
        let slots = [(false, false), (true, true), (true, false), (true, false)];
        assert_eq!(free_slot(slots.into_iter()), Some(2));
        assert_eq!(free_slot([(false, false), (true, true)].into_iter()), None);
    }

    fn action(resume: Resume, signal: Option<u8>, thread: Option<ThreadId>) -> VContAction
    {
        VContAction {
            resume,
            signal,
            thread,
        }
    }

    /// Thread ids 1 to 3 name the live slots 0 to 2; "any" and "all" name
    /// the current slot, 0.
    fn select(t: ThreadId) -> Option<usize>
    {
        match t
        {
            ThreadId::Id(id) if (1..=3).contains(&id) => usize::try_from(id - 1).ok(),
            ThreadId::Id(_) => None,
            ThreadId::Any | ThreadId::All => Some(0),
        }
    }

    fn plan(actions: &[VContAction]) -> Plan
    {
        plan_vcont(actions.iter().copied(), 0, 0..3, select)
    }

    fn releases(threads: &[(usize, Option<u8>)]) -> Vec<Release>
    {
        threads
            .iter()
            .map(|&(thread, signal)| Release { thread, signal })
            .collect()
    }

    // Defect caught: a vCont signal passed to the current thread whatever
    // thread the action names, and a step's signal dropped.
    #[test]
    fn a_resume_plan_follows_the_action_s_thread_and_signal()
    {
        let one = |a: VContAction| plan(&[a]);
        assert_eq!(
            one(action(Resume::Step, None, Some(ThreadId::Id(2)))),
            Plan::Step { thread: 1 }
        );
        assert_eq!(
            one(action(Resume::Continue, Some(11), Some(ThreadId::Id(3)))),
            Plan::Continue {
                thread: 2,
                releases: releases(&[(2, Some(11))])
            }
        );
        assert_eq!(
            one(action(Resume::Step, Some(11), Some(ThreadId::Id(2)))),
            Plan::Continue {
                thread: 1,
                releases: releases(&[(1, Some(11))])
            }
        );
        assert_eq!(
            one(action(Resume::Continue, None, Some(ThreadId::Id(9)))),
            Plan::Nothing
        );
        assert_eq!(
            one(action(Resume::Stop, None, Some(ThreadId::Id(2)))),
            Plan::Nothing
        );
        assert_eq!(
            plan(&[
                action(Resume::Continue, Some(0), Some(ThreadId::Id(2))),
                action(Resume::Continue, None, None)
            ]),
            Plan::Continue {
                thread: 1,
                releases: releases(&[(0, None), (1, None), (2, None)])
            },
            "a zero signal passes none"
        );
    }

    // Defect caught: a continue of one thread resumed every held thread, so
    // GDB, which had resumed one thread to step it over a breakpoint in
    // software, was told of another thread's stop (#1426).
    #[test]
    fn a_continue_resumes_only_the_threads_its_actions_name()
    {
        assert_eq!(
            plan(&[action(Resume::Continue, None, Some(ThreadId::Id(2)))]),
            Plan::Continue {
                thread: 1,
                releases: releases(&[(1, None)])
            }
        );
        assert_eq!(
            plan(&[
                action(Resume::Continue, None, Some(ThreadId::Id(1))),
                action(Resume::Continue, Some(9), Some(ThreadId::Id(3)))
            ]),
            Plan::Continue {
                thread: 0,
                releases: releases(&[(0, None), (2, Some(9))])
            }
        );
        // A default action covers the threads no earlier action names.
        assert_eq!(
            plan(&[
                action(Resume::Continue, Some(11), Some(ThreadId::Id(2))),
                action(Resume::Continue, None, None)
            ]),
            Plan::Continue {
                thread: 1,
                releases: releases(&[(0, None), (1, Some(11)), (2, None)])
            }
        );
        // "all" names every thread; "any" the current one.
        assert_eq!(
            plan(&[action(Resume::Continue, None, Some(ThreadId::All))]),
            Plan::Continue {
                thread: 0,
                releases: releases(&[(0, None), (1, None), (2, None)])
            }
        );
        assert_eq!(
            plan(&[action(Resume::Continue, None, Some(ThreadId::Any))]),
            Plan::Continue {
                thread: 0,
                releases: releases(&[(0, None)])
            }
        );
        // A stop action leaves its thread held beside a default continue.
        assert_eq!(
            plan(&[
                action(Resume::Stop, None, Some(ThreadId::Id(1))),
                action(Resume::Continue, None, None)
            ]),
            Plan::Continue {
                thread: 1,
                releases: releases(&[(1, None), (2, None)])
            }
        );
    }

    // Defect caught: a step action after a default continue stepped its
    // thread, though the leftmost action naming a thread is the one it
    // takes; and a step beside a default continue resumed the others, which
    // can take the riscv64 step's planted breakpoint.
    #[test]
    fn each_thread_takes_its_leftmost_action_and_a_step_runs_alone()
    {
        assert_eq!(
            plan(&[
                action(Resume::Continue, None, None),
                action(Resume::Step, None, Some(ThreadId::Id(3)))
            ]),
            Plan::Continue {
                thread: 0,
                releases: releases(&[(0, None), (1, None), (2, None)])
            }
        );
        assert_eq!(
            plan(&[
                action(Resume::Step, None, Some(ThreadId::Id(3))),
                action(Resume::Continue, None, None)
            ]),
            Plan::Step { thread: 2 }
        );
        // Several threads to step: the current one is.
        assert_eq!(
            plan(&[action(Resume::Step, None, None)]),
            Plan::Step { thread: 0 }
        );
    }

    // Defect caught: a `c` or `s` packet resumed every thread after GDB
    // selected one with `Hc` to resume it alone, or acted on the thread
    // `Hg` selected in its place.
    #[test]
    fn a_c_or_s_packet_resumes_the_thread_hc_selected_alone()
    {
        let packet = |resume, signal, selected| {
            let actions = packet_actions(resume, signal, selected);
            plan_vcont(actions.iter().copied(), 0, 0..3, select)
        };
        assert_eq!(
            packet(Resume::Continue, None, Some(1)),
            Plan::Continue {
                thread: 1,
                releases: releases(&[(1, None)])
            }
        );
        assert_eq!(
            packet(Resume::Step, None, Some(2)),
            Plan::Step { thread: 2 }
        );
        assert_eq!(
            packet(Resume::Continue, Some(11), None),
            Plan::Continue {
                thread: 0,
                releases: releases(&[(0, Some(11)), (1, None), (2, None)])
            }
        );
        assert_eq!(packet(Resume::Step, None, None), Plan::Step { thread: 0 });
        assert_eq!(
            packet(Resume::Step, Some(5), None),
            Plan::Continue {
                thread: 0,
                releases: releases(&[(0, Some(5)), (1, None), (2, None)])
            }
        );
    }
}
