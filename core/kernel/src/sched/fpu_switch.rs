// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/fpu_switch.rs

//! The switch-in decision of the extended-state (FPU, SIMD, vector) discipline.
//!
//! A user thread's extended state is live in the registers whenever it runs in
//! user mode, and no other thread's is. Each CPU's `fpu_owner`
//! (`percpu::PerCpuData`) names the thread whose state its registers hold, and
//! each thread's `ExtendedState::fpu_cpu` names the CPU that last loaded its
//! area. Switch-out saves the outgoing thread's state into its area and leaves
//! both as they are; switch-in loads the incoming thread's area unless the two
//! still name each other ([`in_use_action`]). A riscv64 thread that has not yet
//! used F/D or V runs with the units Off, and its registers are cleared when they
//! hold another thread's state ([`never_used_action`]). The arch code
//! (`arch::*::fpu::switch_in_restore`) applies the decision; this module holds
//! it as pure functions so the host can test it.
//!
//! Why a skip is safe: `fpu_cpu` is written only together with a load of the
//! area into that CPU's registers, the area only by the thread's own switch-out
//! save and by thread creation (which also starts `fpu_cpu` at [`NO_CPU`]), and
//! a CPU's `fpu_owner` only by that CPU. A thread that ran on another CPU since
//! carries that CPU in `fpu_cpu`. The design and its ordering are in
//! core/kernel/docs/scheduler.md § What Gets Saved and Restored.

/// The `fpu_cpu` of a thread whose area no CPU has loaded since it was created.
pub const NO_CPU: u32 = u32::MAX;

/// Whom a CPU's `fpu_owner` names, seen from the thread switching in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Owner
{
    /// The incoming thread, or a thread that lived at its address before it.
    Next,
    /// Another thread.
    Other,
    /// No thread: the registers hold no thread's state.
    None,
}

impl Owner
{
    /// Classify the owner pointer `owner` against the incoming thread `next`.
    /// The pointers are compared, never dereferenced: `owner` may name a
    /// thread that has since been destroyed.
    pub fn of<T>(owner: *const T, next: *const T) -> Self
    {
        if owner.is_null()
        {
            Self::None
        }
        else if core::ptr::eq(owner, next)
        {
            Self::Next
        }
        else
        {
            Self::Other
        }
    }
}

/// What the switch-in of a thread that uses its extended state does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InUseAction
{
    /// The registers hold the thread's state: load nothing.
    Keep,
    /// Load the thread's area, then name the thread this CPU's owner and this
    /// CPU the thread's `fpu_cpu`.
    Load,
}

/// The switch-in decision for a thread that uses its extended state (every user
/// thread on x86_64; on riscv64 one that has taken its first-use trap):
/// [`InUseAction::Keep`] when this CPU's owner is the thread and the thread's
/// `fpu_cpu` (`loaded_on`) is this CPU, else [`InUseAction::Load`].
pub const fn in_use_action(owner: Owner, loaded_on: u32, this_cpu: u32) -> InUseAction
{
    match owner
    {
        Owner::Next if loaded_on == this_cpu => InUseAction::Keep,
        Owner::Next | Owner::Other | Owner::None => InUseAction::Load,
    }
}

/// What the switch-in of a riscv64 thread that has not yet used F/D or V does.
/// It runs with the units Off, so it cannot read the registers until its
/// first-use trap loads its own area; the registers are cleared before it runs
/// so that no other thread's values are present even then, against a speculative
/// read (core/kernel/docs/transient-execution.md § Excluded classes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NeverUsedAction
{
    /// The registers hold a thread's state (an owner is named, the incoming
    /// thread's address included, which can only be a destroyed predecessor's):
    /// clear them and name no owner.
    Scrub,
    /// No owner is named: the registers hold no thread's state.
    Nothing,
}

/// The switch-in decision for a riscv64 thread that has not yet used F/D or V.
#[cfg_attr(
    all(target_arch = "x86_64", not(test)),
    expect(
        dead_code,
        reason = "riscv64 only: an x86_64 user thread loads its area at every switch-in that \
                  needs it, its first included, so no thread runs without its own state loaded"
    )
)]
pub const fn never_used_action(owner: Owner) -> NeverUsedAction
{
    match owner
    {
        Owner::None => NeverUsedAction::Nothing,
        Owner::Next | Owner::Other => NeverUsedAction::Scrub,
    }
}

#[cfg(test)]
mod tests
{
    use super::{InUseAction, NO_CPU, NeverUsedAction, Owner, in_use_action, never_used_action};

    // The defect caught: a skip on the owner alone, which restores nothing for a
    // thread that ran on another CPU since this one loaded it.
    #[test]
    fn keep_only_when_the_owner_and_fpu_cpu_both_name_the_thread_and_this_cpu()
    {
        assert_eq!(in_use_action(Owner::Next, 2, 2), InUseAction::Keep);
        assert_eq!(in_use_action(Owner::Next, 1, 2), InUseAction::Load);
        assert_eq!(in_use_action(Owner::Next, NO_CPU, 2), InUseAction::Load);
        assert_eq!(in_use_action(Owner::Other, 2, 2), InUseAction::Load);
        assert_eq!(in_use_action(Owner::None, 2, 2), InUseAction::Load);
    }

    // The defect caught: a thread that has not used its registers left running
    // beside another thread's values, including a destroyed predecessor's at its
    // own address.
    #[test]
    fn a_never_used_thread_scrubs_whenever_an_owner_is_named()
    {
        assert_eq!(never_used_action(Owner::Next), NeverUsedAction::Scrub);
        assert_eq!(never_used_action(Owner::Other), NeverUsedAction::Scrub);
        assert_eq!(never_used_action(Owner::None), NeverUsedAction::Nothing);
    }

    #[test]
    fn owner_compares_pointers_only()
    {
        let a = 1u8;
        let b = 2u8;
        assert_eq!(Owner::of(core::ptr::null(), &raw const a), Owner::None);
        assert_eq!(Owner::of(&raw const a, &raw const a), Owner::Next);
        assert_eq!(Owner::of(&raw const b, &raw const a), Owner::Other);
    }

    /// A register-file value: the thread it belongs to (a fresh id per
    /// creation, so a thread built at a destroyed one's address differs) and
    /// how many writes that thread has made. Thread 0 is what boot left.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    struct Val
    {
        thread: u32,
        version: u32,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Arch
    {
        X86_64,
        Riscv64,
    }

    /// One thread slot: an address a TCB lives at, and the thread now there.
    struct Slot
    {
        id: u32,
        area: Val,
        fpu_cpu: u32,
        /// riscv64: the first-use trap has run. x86_64 threads are in use
        /// from creation.
        in_use: bool,
        /// The CPU it runs on, if any.
        on: Option<usize>,
    }

    struct Cpu
    {
        /// `None`: zeroed by a scrub.
        regs: Option<Val>,
        /// The slot (address) `fpu_owner` names.
        owner: Option<usize>,
        /// The running user thread's slot; `None` runs a kernel thread or idle.
        current: Option<usize>,
        /// The running thread wrote its registers since its switch-in.
        dirty: bool,
    }

    struct Model
    {
        arch: Arch,
        cpus: Vec<Cpu>,
        slots: Vec<Slot>,
        next_id: u32,
    }

    impl Model
    {
        fn new(arch: Arch, cpus: usize, slots: usize) -> Self
        {
            let mut m = Self {
                arch,
                cpus: (0..cpus)
                    .map(|_| Cpu {
                        regs: Some(Val {
                            thread: 0,
                            version: 0,
                        }),
                        owner: None,
                        current: None,
                        dirty: false,
                    })
                    .collect(),
                slots: Vec::new(),
                next_id: 1,
            };
            for _ in 0..slots
            {
                let s = m.fresh();
                m.slots.push(s);
            }
            m
        }

        fn fresh(&mut self) -> Slot
        {
            let id = self.next_id;
            self.next_id += 1;
            Slot {
                id,
                area: Val {
                    thread: id,
                    version: 0,
                },
                fpu_cpu: NO_CPU,
                in_use: self.arch == Arch::X86_64,
                on: None,
            }
        }

        /// Switch-out of CPU `c`'s current thread: x86_64 saves when this
        /// CPU's owner names it, riscv64 when the thread wrote (Dirty).
        fn switch_out(&mut self, c: usize)
        {
            let cpu = &mut self.cpus[c];
            if let Some(s) = cpu.current.take()
            {
                let save = match self.arch
                {
                    Arch::X86_64 => cpu.owner == Some(s),
                    Arch::Riscv64 => cpu.dirty,
                };
                if save
                {
                    self.slots[s].area = cpu.regs.expect("a saved register file is a thread's");
                }
                self.slots[s].on = None;
            }
            cpu.dirty = false;
        }

        /// Switch-in of slot `s` (or a kernel thread) on CPU `c`, then the
        /// check that the thread now runs with only its own state.
        fn switch_in(&mut self, c: usize, s: Option<usize>)
        {
            self.switch_out(c);
            let Some(s) = s
            else
            {
                return;
            };
            assert!(self.slots[s].on.is_none());
            let owner = owner_of(self.cpus[c].owner, s);
            if self.slots[s].in_use
            {
                self.make_live(c, s, owner);
            }
            else
            {
                match never_used_action(owner)
                {
                    NeverUsedAction::Scrub =>
                    {
                        self.cpus[c].regs = None;
                        self.cpus[c].owner = None;
                    }
                    NeverUsedAction::Nothing =>
                    {}
                }
            }
            self.slots[s].on = Some(c);
            self.cpus[c].current = Some(s);
            self.check_user_mode(c);
        }

        fn make_live(&mut self, c: usize, s: usize, owner: Owner)
        {
            match in_use_action(owner, self.slots[s].fpu_cpu, c as u32)
            {
                // Invariant 1: a skipped load finds the thread's current state.
                InUseAction::Keep => assert_eq!(
                    self.cpus[c].regs,
                    Some(self.slots[s].area),
                    "stale registers kept for slot {s} on cpu {c}"
                ),
                InUseAction::Load =>
                {
                    self.cpus[c].regs = Some(self.slots[s].area);
                    self.cpus[c].owner = Some(s);
                    self.slots[s].fpu_cpu = c as u32;
                }
            }
        }

        /// Invariant 2: CPU `c`'s user thread runs with its own state live,
        /// or, never having used it, with no other thread's in the registers.
        fn check_user_mode(&self, c: usize)
        {
            let Some(s) = self.cpus[c].current
            else
            {
                return;
            };
            let slot = &self.slots[s];
            if slot.in_use
            {
                assert_eq!(self.cpus[c].regs, Some(slot.area), "slot {s} on cpu {c}");
            }
            else
            {
                assert!(
                    self.cpus[c].regs.is_none_or(|v| v.thread == 0),
                    "foreign state {:?} beside never-used slot {s} on cpu {c}",
                    self.cpus[c].regs
                );
            }
        }

        /// CPU `c`'s user thread writes its registers in user mode, taking the
        /// riscv64 first-use trap first when it has not used them before.
        fn user_write(&mut self, c: usize)
        {
            let Some(s) = self.cpus[c].current
            else
            {
                return;
            };
            if !self.slots[s].in_use
            {
                self.slots[s].in_use = true;
                let owner = owner_of(self.cpus[c].owner, s);
                self.make_live(c, s, owner);
                self.check_user_mode(c);
            }
            let regs = self.cpus[c].regs.expect("a live register file");
            self.cpus[c].regs = Some(Val {
                thread: regs.thread,
                version: regs.version + 1,
            });
            // The area is behind the registers until the switch-out save.
            self.cpus[c].dirty = true;
        }

        /// The thread in slot `s`, not running, is destroyed and a new one is
        /// built at its address; CPU owners still naming the address are left.
        fn recreate(&mut self, s: usize)
        {
            if self.slots[s].on.is_none()
            {
                self.slots[s] = self.fresh();
            }
        }
    }

    fn owner_of(owner: Option<usize>, s: usize) -> Owner
    {
        match owner
        {
            None => Owner::None,
            Some(o) if o == s => Owner::Next,
            Some(_) => Owner::Other,
        }
    }

    // The defect caught: migration A to B and back to A while A's owner still
    // names the thread, with the thread's writes on B lost by a skip on A.
    #[test]
    fn migration_and_back_reloads_the_state_written_elsewhere()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let mut m = Model::new(arch, 2, 1);
            m.switch_in(0, Some(0));
            m.user_write(0);
            m.switch_in(0, None);
            m.switch_in(1, Some(0));
            m.user_write(1);
            m.switch_in(1, None);
            // CPU 0's owner still names slot 0, whose fpu_cpu is 1.
            assert_eq!(m.cpus[0].owner, Some(0));
            m.switch_in(0, Some(0));
            assert_eq!(m.cpus[0].regs.map(|v| v.version), Some(2));
        }
    }

    // The defect caught: a thread built at a destroyed owner's address taken
    // for the owner, so it runs on its predecessor's registers.
    #[test]
    fn a_thread_at_a_destroyed_owners_address_never_gets_its_registers()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let mut m = Model::new(arch, 1, 1);
            m.switch_in(0, Some(0));
            m.user_write(0);
            m.switch_in(0, None);
            m.recreate(0);
            m.switch_in(0, Some(0));
            m.user_write(0);
            assert_eq!(
                m.cpus[0].regs.map(|v| (v.thread, v.version)),
                Some((m.slots[0].id, 1))
            );
        }
    }

    // The defects caught: any interleaving of switches, migrations, kernel
    // threads, writes and thread re-creation across CPUs that keeps stale
    // registers or runs a thread beside another's. A seeded generator drives
    // the model; each step's checks are the two invariants.
    #[test]
    fn random_interleavings_keep_both_invariants()
    {
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let mut m = Model::new(arch, 4, 6);
            let mut seed: u64 = 0x5EED_F00D;
            let mut next = |n: usize| {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (seed >> 33) as usize % n
            };
            for _ in 0..200_000
            {
                let c = next(4);
                match next(4)
                {
                    0 => m.user_write(c),
                    1 => m.switch_in(c, None),
                    2 => m.recreate(next(6)),
                    _ =>
                    {
                        let s = next(6);
                        if m.slots[s].on.is_none()
                        {
                            m.switch_in(c, Some(s));
                        }
                    }
                }
            }
        }
    }
}
