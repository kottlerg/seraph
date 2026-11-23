// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/fuzz.rs

//! The fuzzing run of the child process, the replay of one input, and corpus
//! minimization.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::args::{Budget, Options};
use crate::cmp::{self, Operands};
use crate::corpus::{self, Coverage, Feature};
use crate::cov::Counters;
use crate::exec::{self, Executor, Outcome, PanicRecord};
use crate::minimize::minimize;
use crate::mutate::Mutator;
use crate::report::{self, Crash};
use crate::rng::Rng;
use crate::{EXIT_ERROR, EXIT_FAILED, EXIT_REPORTED, Target};

/// The file, under the working directory, each execution writes its input to
/// for the supervisor.
pub const CURRENT_INPUT: &str = ".current-input";

/// The most candidates the minimization of a panic tries.
const MINIMIZE_BUDGET: usize = 20_000;

/// The compare pairs of its parent each mutation's replacement edits draw
/// from.
const OPERANDS_PER_MUTATION: usize = 4;

/// The message of a target built without the instrumentation.
const NOT_INSTRUMENTED: &str = "no coverage counters are registered: build and run fuzz targets \
                                with `cargo xtask fuzz`, which instruments them";

/// How an input joins the queue.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Source
{
    /// A checked-in seed or regression input: always queued.
    CheckedIn,
    /// An input of the working corpus: queued when novel.
    Corpus,
    /// A mutant: queued and saved to the working corpus when novel.
    Mutant,
}

/// A queued input and the compare pairs its execution recorded, which the
/// replacement edits of its mutants draw from.
struct Entry
{
    data: Vec<u8>,
    operands: Vec<Operands>,
}

/// A failing input the run found.
struct Found
{
    input: Vec<u8>,
    record: PanicRecord,
    execution: u64,
}

/// The state of a fuzzing run.
struct Run<'a>
{
    target: &'a Target,
    options: &'a Options,
    executor: Executor,
    coverage: Coverage,
    queue: Vec<Entry>,
    mutator: Mutator,
    rng: Rng,
    started: Instant,
    next_status: u64,
}

/// The files of `dir`, by name, with their contents; none for a missing
/// directory.
fn read_inputs(dir: &Path) -> Vec<(PathBuf, Vec<u8>)>
{
    let Ok(entries) = fs::read_dir(dir)
    else
    {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    paths.sort();
    paths
        .into_iter()
        .filter_map(|path| fs::read(&path).ok().map(|data| (path, data)))
        .collect()
}

/// The checked-in inputs of `target`: its `seeds/` and its `regressions/`.
fn checked_in(target: &Target, options: &Options) -> Vec<(PathBuf, Vec<u8>)>
{
    let Some(dir) = target.inputs
    else
    {
        return Vec::new();
    };
    let dir = options.root.join(dir);
    let mut inputs = read_inputs(&dir.join("seeds"));
    inputs.extend(read_inputs(&dir.join("regressions")));
    inputs
}

impl Run<'_>
{
    /// Execute `data` and queue it as its `source` says; a panic is the run's
    /// finding.
    fn try_input(&mut self, data: Vec<u8>, source: Source) -> Result<(), Box<Found>>
    {
        cmp::clear();
        if let Outcome::Panicked(record) = self.executor.run(&data)
        {
            return Err(Box::new(Found {
                input: data,
                record,
                execution: self.executor.executions(),
            }));
        }
        let novel = self.observe();
        if !novel && source != Source::CheckedIn
        {
            return Ok(());
        }
        let operands = cmp::recorded();
        if novel
        {
            self.mutator.learn(&operands);
            if source == Source::Mutant
            {
                let name = format!("{:016x}", report::fnv1a(&data));
                let _ = fs::write(self.options.work.join("corpus").join(name), &data);
            }
        }
        self.queue.push(Entry { data, operands });
        Ok(())
    }

    /// Fold the last execution's counters into the run's coverage, and whether
    /// it reached a new feature.
    fn observe(&mut self) -> bool
    {
        let mut novel = false;
        let coverage = &mut self.coverage;
        self.executor.counters().for_each_hit(|index, hits| {
            if coverage.is_new(index, hits)
            {
                coverage.add(index, hits);
                novel = true;
            }
        });
        novel
    }

    /// Execute the checked-in inputs and the working corpus, then mutate until
    /// `budget` is spent.
    fn fuzz(&mut self, budget: Budget) -> Result<(), Box<Found>>
    {
        for (_, data) in checked_in(self.target, self.options)
        {
            self.try_input(data, Source::CheckedIn)?;
        }
        for (_, data) in read_inputs(&self.options.work.join("corpus"))
        {
            self.try_input(data, Source::Corpus)?;
        }
        if self.queue.is_empty()
        {
            self.try_input(Vec::new(), Source::CheckedIn)?;
        }
        while !self.spent(budget)
        {
            let data = self.mutant();
            self.try_input(data, Source::Mutant)?;
            self.status(Last::No);
        }
        self.status(Last::Yes);
        Ok(())
    }

    /// Whether `budget` is spent.
    fn spent(&self, budget: Budget) -> bool
    {
        match budget
        {
            Budget::Runs(runs) => self.executor.executions() >= runs,
            Budget::Time(time) => self.started.elapsed() >= time,
        }
    }

    /// The next input: a queued input, the newer ones likelier, mutated.
    fn mutant(&mut self) -> Vec<u8>
    {
        let len = self.queue.len();
        let parent = self.rng.index(len).max(self.rng.index(len));
        let Some(entry) = self.queue.get(parent)
        else
        {
            return Vec::new();
        };
        let mut data = entry.data.clone();
        let other = if len > 1 && self.rng.one_in(8)
        {
            self.queue
                .get(self.rng.index(len))
                .map(|other| other.data.as_slice())
        }
        else
        {
            None
        };
        let operands: Vec<Operands> = (0..OPERANDS_PER_MUTATION)
            .filter_map(|_| {
                entry
                    .operands
                    .get(self.rng.index(entry.operands.len()))
                    .copied()
            })
            .collect();
        self.mutator
            .mutate(&mut self.rng, &mut data, other, &operands);
        data
    }

    /// Print the run's progress at each power-of-two execution from 4096, and
    /// at its end.
    fn status(&mut self, last: Last)
    {
        let executions = self.executor.executions();
        if executions < self.next_status && last == Last::No
        {
            return;
        }
        self.next_status = executions.saturating_mul(2).max(4096);
        let millis = self.started.elapsed().as_millis().max(1);
        let rate = u128::from(executions)
            .saturating_mul(1000)
            .checked_div(millis)
            .unwrap_or(0);
        eprintln!(
            "fuzz: {}: #{executions} edges {}/{} corpus {} dictionary {} {rate} exec/s",
            self.target.name,
            self.coverage.edges(),
            Counters::edges(),
            self.queue.len(),
            self.mutator.dictionary_len(),
        );
    }

    /// Minimize the input of `found` while it panics at the same location,
    /// write the crash's files, and print its report.
    fn report(&mut self, found: Found) -> i32
    {
        let location = found.record.location.clone();
        let executor = &mut self.executor;
        let mut input = minimize(
            &found.input,
            MINIMIZE_BUDGET,
            |candidate| matches!(executor.run(candidate), Outcome::Panicked(r) if r.location == location),
        );
        let record = match self.executor.run(&input)
        {
            Outcome::Panicked(record) => record,
            Outcome::Passed =>
            {
                input.clone_from(&found.input);
                found.record
            }
        };
        let crash = Crash {
            what: record.message,
            location: Some(record.location),
            execution: found.execution,
            seed: self.options.seed,
            found_len: found.input.len(),
            input,
            details: format!("backtrace:\n{}", record.backtrace),
        };
        write_crash(self.target, self.options, &crash)
    }
}

/// Whether [`Run::status`] prints the run's last line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Last
{
    No,
    Yes,
}

/// Write `crash`'s files and print its report; [`EXIT_REPORTED`], or
/// [`EXIT_ERROR`] when the files could not be written.
#[must_use]
pub fn write_crash(target: &Target, options: &Options, crash: &Crash) -> i32
{
    match report::write(&options.work, target.name, crash)
    {
        Ok(input) =>
        {
            eprintln!("fuzz: {}: crash found\n", target.name);
            eprintln!("{}", report::render(target.name, crash, &input));
            eprintln!("fuzz: report: {}", input.with_extension("txt").display());
            EXIT_REPORTED
        }
        Err(err) =>
        {
            eprintln!("fuzz: {}: writing the crash's files: {err}", target.name);
            EXIT_ERROR
        }
    }
}

/// The registered counters, or `None` after printing why a run cannot start.
fn instrumented() -> Option<Counters>
{
    // SAFETY: the target's code, the only instrumented code, runs on the
    // thread that runs the executions, between the calls of the counters'
    // methods; the engine's other thread, the watchdog, is not instrumented.
    let counters = unsafe { Counters::registered() };
    if counters.is_empty()
    {
        eprintln!("fuzz: {NOT_INSTRUMENTED}");
        return None;
    }
    Some(counters)
}

/// Fuzz `target` for `budget`: the child process's run. Returns
/// [`EXIT_REPORTED`] when it found and reported a crash, 0 when the budget
/// was spent without one, and [`EXIT_ERROR`] when it could not run.
#[must_use]
pub fn fuzz(target: &Target, options: &Options, budget: Budget) -> i32
{
    let Some(counters) = instrumented()
    else
    {
        return EXIT_ERROR;
    };
    let current = fs::create_dir_all(options.work.join("corpus"))
        .and_then(|()| File::create(options.work.join(CURRENT_INPUT)));
    let current = match current
    {
        Ok(file) => file,
        Err(err) =>
        {
            eprintln!("fuzz: {}: {}: {err}", target.name, options.work.display());
            return EXIT_ERROR;
        }
    };
    exec::catch_panics();
    exec::start_watchdog();
    let mut run = Run {
        target,
        options,
        coverage: Coverage::new(counters.len()),
        executor: Executor::new(target.property, counters, Some(current)),
        queue: Vec::new(),
        mutator: Mutator::new(target.max_len),
        rng: Rng::new(options.seed),
        started: Instant::now(),
        next_status: 4096,
    };
    match run.fuzz(budget)
    {
        Ok(()) => 0,
        Err(found) => run.report(*found),
    }
}

/// Run `target` once on the contents of `file`, with the default panic hook,
/// so a failure prints as it would anywhere: 0 when the property holds; a
/// panic ends the process with Rust's panic status.
#[must_use]
pub fn replay(target: &Target, file: &Path) -> i32
{
    let data = match fs::read(file)
    {
        Ok(data) => data,
        Err(err) =>
        {
            eprintln!("fuzz: {}: {}: {err}", target.name, file.display());
            return EXIT_ERROR;
        }
    };
    exec::start_watchdog();
    exec::timed(|| (target.property)(&data));
    eprintln!("fuzz: {}: {} holds", target.name, file.display());
    0
}

/// Minimize the working corpus by coverage ([`corpus::cover`]), the checked-in
/// inputs counted first and kept: remove each corpus file whose features the
/// kept inputs reach.
#[must_use]
pub fn minimize_corpus(target: &Target, options: &Options) -> i32
{
    let Some(counters) = instrumented()
    else
    {
        return EXIT_ERROR;
    };
    exec::catch_panics();
    exec::start_watchdog();
    let mut executor = Executor::new(target.property, counters, None);
    let fixed = checked_in(target, options);
    let corpus = read_inputs(&options.work.join("corpus"));
    let mut inputs: Vec<(usize, Vec<Feature>)> = Vec::new();
    for (path, data) in fixed.iter().chain(&corpus)
    {
        if let Outcome::Panicked(record) = executor.run(data)
        {
            eprintln!(
                "fuzz: {}: {} fails ({} at {}); replay it with --replay",
                target.name,
                path.display(),
                record.message,
                record.location
            );
            return EXIT_FAILED;
        }
        let mut features = Vec::new();
        executor
            .counters()
            .for_each_hit(|index, hits| features.push(corpus::feature(index, hits)));
        inputs.push((data.len(), features));
    }
    let chosen = corpus::cover(&inputs, fixed.len());
    let mut removed = 0usize;
    for (index, (path, _)) in corpus.iter().enumerate()
    {
        if !chosen.contains(&index.saturating_add(fixed.len())) && fs::remove_file(path).is_ok()
        {
            removed = removed.saturating_add(1);
        }
    }
    eprintln!(
        "fuzz: {}: corpus minimized from {} to {} inputs",
        target.name,
        corpus.len(),
        corpus.len().saturating_sub(removed)
    );
    0
}
