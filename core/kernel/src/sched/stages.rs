// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/sched/stages.rs

//! The stage breakdown of `schedule()`, built with the kernel's
//! `sched-stages` feature: the cycles each stage of a context switch takes on
//! one collecting CPU, summed for `SystemInfoType::SchedStages`
//! (core/kernel/docs/scheduler.md § Stage Breakdown).
//!
//! `schedule()` calls a stamp at each stage's end. Without the feature every
//! stamp is an empty function and the [`Recorder`] is not built, so the
//! kernel's image is the one a tree without this module builds.

#[cfg(any(test, feature = "sched-stages"))]
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// A stage of `schedule()` that ends before its call of `switch()`, timed
/// from the previous stamp to its own; the discriminant is its
/// `syscall::SCHED_STAGE_*` word. A stage a switch's path skips (the
/// dispatch flip and the I/O bitmap of a switch to idle) adds nothing, and
/// its time falls in the next stage stamped.
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum Stage
{
    /// Both of the outgoing side's locks taken.
    Lock = syscall::SCHED_STAGE_LOCK as usize,
    /// The outgoing thread requeued, the next chosen.
    Pick = syscall::SCHED_STAGE_PICK as usize,
    /// The next thread claimed, both locks released.
    Release = syscall::SCHED_STAGE_RELEASE as usize,
    /// The next thread's `sched_lock` taken, the thread marked `Running`.
    Flip = syscall::SCHED_STAGE_FLIP as usize,
    /// The next thread's I/O permission bitmap loaded.
    Iopb = syscall::SCHED_STAGE_IOPB as usize,
    /// The next thread's `sched_lock` released, its trap stack set, its
    /// guard page's stale translation flushed.
    Guard = syscall::SCHED_STAGE_GUARD as usize,
    /// The address-space switch.
    Aspace = syscall::SCHED_STAGE_ASPACE as usize,
    /// The extended-state hooks and the wait for the next thread's saved
    /// registers.
    #[cfg_attr(
        not(any(test, feature = "sched-stages")),
        expect(
            dead_code,
            reason = "ended by `before_switch`, which is empty without the feature"
        )
    )]
    Fpu = syscall::SCHED_STAGE_FPU as usize,
}

/// Number of stages, the register switch included.
#[cfg(any(test, feature = "sched-stages"))]
const STAGES: usize = syscall::SCHED_STAGE_COUNT as usize;

/// The stage after the last [`Stage`]: from the call of `switch()` until
/// the incoming thread resumes in `schedule()`.
#[cfg(any(test, feature = "sched-stages"))]
const SWITCH: usize = syscall::SCHED_STAGE_SWITCH as usize;

/// No CPU collects: the value of [`Recorder::cpu`] before the first arm.
#[cfg(any(test, feature = "sched-stages"))]
const NO_CPU: usize = usize::MAX;

/// The sums of one collecting CPU's switches, and the laps of the switch it
/// is making.
///
/// Only the collecting CPU writes the laps and the sums, from `schedule()`
/// with interrupts disabled, so a load and a store make each update and every
/// access is `Relaxed`; a read from another CPU may see one switch's sums
/// partly added. An arm made while another CPU collects may let that CPU's
/// switch in progress add to the zeroed sums; a benchmark arms on the CPU it
/// is pinned to.
#[cfg(any(test, feature = "sched-stages"))]
pub struct Recorder
{
    /// The collecting CPU, or [`NO_CPU`].
    cpu: AtomicUsize,
    /// The cycle count of the switch's last stamp.
    last: AtomicU64,
    /// The laps of the switch in progress, by stage.
    laps: [AtomicU64; STAGES],
    /// Whether a committed switch has its register switch to close.
    switching: AtomicBool,
    /// The cycles of every committed switch, by stage.
    sums: [AtomicU64; STAGES],
    /// Switches committed: those [`Recorder::sums`] covers up to the register
    /// switch.
    switches: AtomicU64,
    /// Register switches closed: those the register switch's sum covers.
    resumes: AtomicU64,
}

#[cfg(any(test, feature = "sched-stages"))]
impl Default for Recorder
{
    fn default() -> Self
    {
        Self::new()
    }
}

#[cfg(any(test, feature = "sched-stages"))]
impl Recorder
{
    /// A recorder no CPU collects on.
    pub const fn new() -> Self
    {
        Self {
            cpu: AtomicUsize::new(NO_CPU),
            last: AtomicU64::new(0),
            laps: [const { AtomicU64::new(0) }; STAGES],
            switching: AtomicBool::new(false),
            sums: [const { AtomicU64::new(0) }; STAGES],
            switches: AtomicU64::new(0),
            resumes: AtomicU64::new(0),
        }
    }

    /// Whether `cpu` is the collecting CPU.
    fn collects(&self, cpu: usize) -> bool
    {
        self.cpu.load(Ordering::Relaxed) == cpu
    }

    /// Add `cycles` to `slot`.
    fn add(slot: &AtomicU64, cycles: u64)
    {
        slot.store(
            slot.load(Ordering::Relaxed).wrapping_add(cycles),
            Ordering::Relaxed,
        );
    }

    /// Begin a switch on `cpu` at `now`. Drops the laps of a switch that
    /// committed nothing (one that re-selected its outgoing thread) and the
    /// open register switch of one whose incoming thread started elsewhere
    /// than in `schedule()` (its first run).
    pub fn start(&self, cpu: usize, now: u64)
    {
        if !self.collects(cpu)
        {
            return;
        }
        for lap in &self.laps
        {
            lap.store(0, Ordering::Relaxed);
        }
        self.switching.store(false, Ordering::Relaxed);
        self.last.store(now, Ordering::Relaxed);
    }

    /// End `stage` on `cpu` at `now`: the cycles since the last stamp are
    /// its lap.
    pub fn lap(&self, cpu: usize, stage: Stage, now: u64)
    {
        if !self.collects(cpu)
        {
            return;
        }
        let cycles = now.wrapping_sub(self.last.load(Ordering::Relaxed));
        if let Some(lap) = self.laps.get(stage as usize)
        {
            Self::add(lap, cycles);
        }
        self.last.store(now, Ordering::Relaxed);
    }

    /// Add the switch's laps on `cpu` to the sums and count it; its register
    /// switch begins at the next stamp, [`Recorder::open_switch`].
    pub fn commit(&self, cpu: usize)
    {
        if !self.collects(cpu)
        {
            return;
        }
        for (sum, lap) in self.sums.iter().zip(&self.laps)
        {
            Self::add(sum, lap.load(Ordering::Relaxed));
        }
        Self::add(&self.switches, 1);
    }

    /// Begin the register switch on `cpu` at `now`.
    pub fn open_switch(&self, cpu: usize, now: u64)
    {
        if !self.collects(cpu)
        {
            return;
        }
        self.switching.store(true, Ordering::Relaxed);
        self.last.store(now, Ordering::Relaxed);
    }

    /// End the register switch on `cpu` at `now`, where the incoming thread
    /// resumes in `schedule()`; nothing when no committed switch is open.
    pub fn close_switch(&self, cpu: usize, now: u64)
    {
        if !self.collects(cpu) || !self.switching.load(Ordering::Relaxed)
        {
            return;
        }
        self.switching.store(false, Ordering::Relaxed);
        let cycles = now.wrapping_sub(self.last.load(Ordering::Relaxed));
        if let Some(sum) = self.sums.get(SWITCH)
        {
            Self::add(sum, cycles);
        }
        Self::add(&self.resumes, 1);
    }

    /// Zero every sum and count and collect on `cpu` from now on.
    pub fn arm(&self, cpu: usize)
    {
        self.cpu.store(NO_CPU, Ordering::Relaxed);
        for sum in &self.sums
        {
            sum.store(0, Ordering::Relaxed);
        }
        self.switches.store(0, Ordering::Relaxed);
        self.resumes.store(0, Ordering::Relaxed);
        self.switching.store(false, Ordering::Relaxed);
        self.cpu.store(cpu, Ordering::Relaxed);
    }

    /// The `SystemInfoType::SchedStages` word `word` other than the arm: a
    /// stage's sum, or a count. `None` for an unknown word.
    pub fn read(&self, word: u64) -> Option<u64>
    {
        match word
        {
            syscall::SCHED_STAGES_SWITCHES => Some(self.switches.load(Ordering::Relaxed)),
            syscall::SCHED_STAGES_RESUMES => Some(self.resumes.load(Ordering::Relaxed)),
            _ =>
            {
                let stage = usize::try_from(word).ok()?;
                self.sums.get(stage).map(|sum| sum.load(Ordering::Relaxed))
            }
        }
    }
}

/// The kernel's recorder.
#[cfg(all(not(test), feature = "sched-stages"))]
static RECORDER: Recorder = Recorder::new();

/// The cycle counter, read as the benchmarks read it.
#[cfg(all(not(test), feature = "sched-stages"))]
fn now() -> u64
{
    bench::Counters::open().read().cycles
}

/// Begin a switch on `cpu`.
#[cfg(all(not(test), feature = "sched-stages"))]
pub fn start(cpu: usize)
{
    RECORDER.start(cpu, now());
}

/// End `stage` of the switch on `cpu`.
#[cfg(all(not(test), feature = "sched-stages"))]
pub fn lap(cpu: usize, stage: Stage)
{
    RECORDER.lap(cpu, stage, now());
}

/// End [`Stage::Fpu`] on `cpu`, add the switch to the sums, and begin its
/// register switch; called right before `switch()`.
#[cfg(all(not(test), feature = "sched-stages"))]
pub fn before_switch(cpu: usize)
{
    RECORDER.lap(cpu, Stage::Fpu, now());
    RECORDER.commit(cpu);
    RECORDER.open_switch(cpu, now());
}

/// End the register switch, where the incoming thread resumes in
/// `schedule()`; reads the CPU afresh, since the thread may have entered
/// `schedule()` on another.
#[cfg(all(not(test), feature = "sched-stages"))]
pub fn after_switch()
{
    let cpu = crate::arch::current::cpu::current_cpu() as usize;
    RECORDER.close_switch(cpu, now());
}

/// The `SystemInfoType::SchedStages` query: [`Recorder::arm`] on the calling
/// CPU for `syscall::SCHED_STAGES_ARM`, which returns 0, and
/// [`Recorder::read`] otherwise; `None` for an unknown word.
#[cfg(all(not(test), feature = "sched-stages"))]
pub fn query(word: u64) -> Option<u64>
{
    if word == syscall::SCHED_STAGES_ARM
    {
        RECORDER.arm(crate::arch::current::cpu::current_cpu() as usize);
        return Some(0);
    }
    RECORDER.read(word)
}

/// Begin a switch: nothing without the `sched-stages` feature.
#[cfg(all(not(test), not(feature = "sched-stages")))]
#[inline]
pub fn start(_cpu: usize) {}

/// End a stage: nothing without the `sched-stages` feature.
#[cfg(all(not(test), not(feature = "sched-stages")))]
#[inline]
pub fn lap(_cpu: usize, _stage: Stage) {}

/// Commit a switch: nothing without the `sched-stages` feature.
#[cfg(all(not(test), not(feature = "sched-stages")))]
#[inline]
pub fn before_switch(_cpu: usize) {}

/// End a register switch: nothing without the `sched-stages` feature.
#[cfg(all(not(test), not(feature = "sched-stages")))]
#[inline]
pub fn after_switch() {}

#[cfg(test)]
mod tests
{
    use super::{Recorder, Stage};

    /// One switch on CPU `cpu` stamped at the cycle counts `at`: its start,
    /// then the ends of lock, pick, release, flip, iopb, guard, aspace and fpu,
    /// then the register switch's open and close.
    fn switch(recorder: &Recorder, cpu: usize, at: [u64; 11])
    {
        let [
            start,
            lock,
            pick,
            release,
            flip,
            iopb,
            guard,
            aspace,
            fpu,
            open,
            close,
        ] = at;
        recorder.start(cpu, start);
        recorder.lap(cpu, Stage::Lock, lock);
        recorder.lap(cpu, Stage::Pick, pick);
        recorder.lap(cpu, Stage::Release, release);
        recorder.lap(cpu, Stage::Flip, flip);
        recorder.lap(cpu, Stage::Iopb, iopb);
        recorder.lap(cpu, Stage::Guard, guard);
        recorder.lap(cpu, Stage::Aspace, aspace);
        recorder.lap(cpu, Stage::Fpu, fpu);
        recorder.commit(cpu);
        recorder.open_switch(cpu, open);
        recorder.close_switch(cpu, close);
    }

    fn sums(recorder: &Recorder) -> Vec<u64>
    {
        (0..syscall::SCHED_STAGE_COUNT)
            .map(|word| recorder.read(word).unwrap())
            .collect()
    }

    // Defect caught: a lap credited to the wrong stage, or measured from the
    // wrong stamp, so a stage's mean carries its neighbour's cycles.
    #[test]
    fn each_stage_sums_the_cycles_since_the_previous_stamp()
    {
        let recorder = Recorder::new();
        recorder.arm(0);
        switch(
            &recorder,
            0,
            [100, 110, 130, 160, 200, 250, 310, 380, 460, 470, 560],
        );
        switch(
            &recorder,
            0,
            [
                1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010,
            ],
        );
        assert_eq!(sums(&recorder), [11, 21, 31, 41, 51, 61, 71, 81, 91]);
        assert_eq!(recorder.read(syscall::SCHED_STAGES_SWITCHES), Some(2));
        assert_eq!(recorder.read(syscall::SCHED_STAGES_RESUMES), Some(2));
    }

    // Defect caught: a skipped stage's time lost, or the laps of a switch
    // that re-selected its outgoing thread (no commit) added to the next.
    #[test]
    fn a_skipped_stage_falls_in_the_next_and_an_uncommitted_switch_adds_nothing()
    {
        let recorder = Recorder::new();
        recorder.arm(3);
        recorder.start(3, 0);
        recorder.lap(3, Stage::Lock, 500);
        recorder.start(3, 1000);
        recorder.lap(3, Stage::Lock, 1010);
        recorder.lap(3, Stage::Pick, 1020);
        recorder.lap(3, Stage::Release, 1030);
        recorder.lap(3, Stage::Guard, 1060);
        recorder.lap(3, Stage::Aspace, 1070);
        recorder.lap(3, Stage::Fpu, 1080);
        recorder.commit(3);
        assert_eq!(sums(&recorder), [10, 10, 10, 0, 0, 30, 10, 10, 0]);
        assert_eq!(recorder.read(syscall::SCHED_STAGES_SWITCHES), Some(1));
    }

    // Defect caught: a register switch closed with no commit before it (a
    // thread that entered schedule() on another CPU and resumed here), or one
    // left open across a thread's first run, which starts outside schedule()
    // and so never closes it, timing the whole next switch as a register switch.
    #[test]
    fn a_register_switch_closes_only_what_the_same_switch_opened()
    {
        let recorder = Recorder::new();
        recorder.arm(0);
        recorder.close_switch(0, 50);
        recorder.start(0, 100);
        recorder.lap(0, Stage::Fpu, 110);
        recorder.commit(0);
        recorder.open_switch(0, 120);
        recorder.start(0, 5000);
        recorder.close_switch(0, 5100);
        assert_eq!(recorder.read(syscall::SCHED_STAGE_SWITCH), Some(0));
        assert_eq!(recorder.read(syscall::SCHED_STAGES_RESUMES), Some(0));
    }

    // Defect caught: a switch of a CPU other than the armed one summed, a sum
    // kept across an arm, or a switch summed before any arm.
    #[test]
    fn only_the_armed_cpu_is_summed_and_an_arm_zeroes_the_sums()
    {
        let recorder = Recorder::new();
        switch(&recorder, 0, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(recorder.read(syscall::SCHED_STAGES_SWITCHES), Some(0));
        recorder.arm(1);
        switch(&recorder, 1, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        switch(&recorder, 2, [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50]);
        assert_eq!(sums(&recorder), [1; 9]);
        recorder.arm(2);
        assert_eq!(sums(&recorder), [0; 9]);
        assert_eq!(recorder.read(syscall::SCHED_STAGES_SWITCHES), Some(0));
        assert_eq!(recorder.read(syscall::SCHED_STAGES_RESUMES), Some(0));
    }

    // Defect caught: an index past the sums or the counts read as a word.
    #[test]
    fn a_word_past_the_counts_is_refused()
    {
        let recorder = Recorder::new();
        assert_eq!(recorder.read(syscall::SCHED_STAGES_ARM), None);
        assert_eq!(recorder.read(u64::MAX), None);
    }
}
