// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/gdbstub/src/control.rs

//! The stub's run-control decisions, apart from the syscalls that carry them
//! out: which thread a binding's badge names, whether a stop is that
//! thread's own, how a breakpoint hit the stub does not report is undone,
//! and what a resume packet asks of which thread
//! (`services/gdbstub/README.md` § Stop Model).

use gdb_rsp::command::{Resume, ThreadId, VContAction};

/// The tag of a target thread's binding badge: a verb bit (bit 62, which no
/// process badge carries), with bit 63 clear, so the badge is neither the
/// target's process badge nor a crash badge, as procmgr requires of a
/// debugger's binding (`services/procmgr/docs/ipc-interface.md`
/// § `REGISTER_THREAD`).
pub const THREAD_BADGE_TAG: u64 = 1 << 62;

/// The badge thread `index` of the stub's table is bound under: the tag with
/// the index plus one. Each thread is bound under the index it is stored at,
/// so the badge of a stop names the table entry that holds the thread.
#[must_use]
pub fn thread_badge(index: usize) -> u64
{
    THREAD_BADGE_TAG | (index as u64 + 1)
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
/// it is for a thread that is neither stopped nor fault-blocked), carrying
/// the instruction pointer `stop_ip` (data word 3 of the message).
#[must_use]
pub fn credit(held: bool, regs_pc: Option<u64>, stop_ip: u64) -> Credit
{
    if !held && regs_pc == Some(stop_ip)
    {
        Credit::Own
    }
    else
    {
        Credit::Unknown
    }
}

/// The pointer to set on a thread held at a breakpoint hit the stub does not
/// report, so that its resume runs the breakpoint again rather than resuming
/// past it: `pc - advance` when the stop is a breakpoint exception, the
/// architecture reports the pointer `advance` bytes past the breakpoint (one
/// on x86-64, none on RISC-V), and a breakpoint of the stub's is `planted`
/// there. `None` leaves the pointer as it is.
#[must_use]
pub fn rewound_pc(
    advance: u64,
    kind: u64,
    exception: u64,
    pc: u64,
    planted: impl Fn(u64) -> bool,
) -> Option<u64>
{
    if advance == 0
        || kind != syscall_abi::FAULT_KIND_EXCEPTION
        || exception != syscall_abi::FAULT_EXC_BREAKPOINT
    {
        return None;
    }
    let at = pc.checked_sub(advance)?;
    planted(at).then_some(at)
}

/// What a resume packet asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan
{
    /// Run thread `thread` one instruction, the others held.
    Step
    {
        /// The thread to step, by table index.
        thread: usize,
    },
    /// Resume every held thread, passing `signal` to thread `thread`.
    Continue
    {
        /// The thread the signal is for, by table index.
        thread: usize,
        /// The signal, when one is passed (nonzero).
        signal: Option<u8>,
    },
    /// Nothing to run: no action names a live thread.
    Nothing,
}

/// The plan of a `c`, `C`, `s`, or `S` packet on the current thread
/// `current`, passing `signal`. A step that passes a signal is a continue
/// passing it: delivering the signal declines the thread's fault, which then
/// takes its outcome with no handler bound, so the thread runs no single
/// instruction to stop after.
#[must_use]
pub fn plan_resume(step: bool, signal: Option<u8>, current: usize) -> Plan
{
    let signal = signal.filter(|&s| s != 0);
    if step && signal.is_none()
    {
        Plan::Step { thread: current }
    }
    else
    {
        Plan::Continue {
            thread: current,
            signal,
        }
    }
}

/// The plan of a `vCont` packet's `actions`, with `select` mapping a thread
/// id to a live thread's table index and `current` the thread "any" and
/// "all" name. The first step action plans a step of its thread, the others
/// held; otherwise the first continue action resumes every held thread,
/// passing its signal to the thread it names. A step action that passes a
/// signal is a continue, as in [`plan_resume`]; a stop action asks nothing.
#[must_use]
pub fn plan_vcont(
    actions: impl Iterator<Item = VContAction> + Clone,
    current: usize,
    select: impl Fn(ThreadId) -> Option<usize>,
) -> Plan
{
    let index = |a: &VContAction| a.thread.map_or(Some(current), &select);
    let step = actions
        .clone()
        .filter(|a| a.resume == Resume::Step)
        .find_map(|a| index(&a).map(|i| (i, a.signal)));
    if let Some((thread, signal)) = step
    {
        return plan_resume(true, signal, thread);
    }
    actions
        .filter(|a| a.resume == Resume::Continue)
        .find_map(|a| index(&a).map(|i| (i, a.signal)))
        .map_or(Plan::Nothing, |(thread, signal)| {
            plan_resume(false, signal, thread)
        })
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
        assert_eq!(credit(false, Some(0x40), 0x40), Credit::Own);
        assert_eq!(credit(true, Some(0x40), 0x40), Credit::Unknown);
        assert_eq!(credit(false, None, 0x40), Credit::Unknown);
        assert_eq!(credit(false, Some(0x44), 0x40), Credit::Unknown);
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

    fn action(resume: Resume, signal: Option<u8>, thread: Option<ThreadId>) -> VContAction
    {
        VContAction {
            resume,
            signal,
            thread,
        }
    }

    // Defect caught: a vCont signal passed to the current thread whatever
    // thread the action names, and a step's signal dropped.
    #[test]
    fn a_resume_plan_follows_the_action_s_thread_and_signal()
    {
        let select = |t| match t
        {
            ThreadId::Id(id) if (1..=3).contains(&id) => usize::try_from(id - 1).ok(),
            ThreadId::Id(_) => None,
            ThreadId::Any | ThreadId::All => Some(0),
        };
        let one = |a: VContAction| plan_vcont([a].into_iter(), 0, select);
        assert_eq!(
            one(action(Resume::Step, None, Some(ThreadId::Id(2)))),
            Plan::Step { thread: 1 }
        );
        assert_eq!(
            one(action(Resume::Continue, Some(11), Some(ThreadId::Id(3)))),
            Plan::Continue {
                thread: 2,
                signal: Some(11)
            }
        );
        assert_eq!(
            one(action(Resume::Step, Some(11), Some(ThreadId::Id(2)))),
            Plan::Continue {
                thread: 1,
                signal: Some(11)
            }
        );
        assert_eq!(
            one(action(Resume::Continue, None, Some(ThreadId::Id(9)))),
            Plan::Nothing
        );
        // A step action outranks a continue action before it.
        let both = [
            action(Resume::Continue, None, None),
            action(Resume::Step, None, Some(ThreadId::Id(3))),
        ];
        assert_eq!(
            plan_vcont(both.into_iter(), 0, select),
            Plan::Step { thread: 2 }
        );
        assert_eq!(plan_resume(true, Some(0), 4), Plan::Step { thread: 4 });
        assert_eq!(
            plan_resume(true, Some(5), 4),
            Plan::Continue {
                thread: 4,
                signal: Some(5)
            }
        );
    }
}
