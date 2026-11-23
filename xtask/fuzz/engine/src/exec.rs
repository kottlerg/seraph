// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/fuzz/engine/src/exec.rs

//! One execution of the target: the input saved for the supervisor, the edge
//! counters cleared, the property run under the engine's panic catch and the
//! per-input time limit.

use std::backtrace::Backtrace;
use std::fs::File;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use crate::EXIT_ERROR;
use crate::cov::Counters;

/// The exit status of a process an input held past [`TIME_LIMIT`].
pub const EXIT_TIMEOUT: i32 = 71;

/// The per-input time limit.
pub const TIME_LIMIT: Duration = Duration::from_secs(10);

/// How often the watchdog looks at the execution in progress.
const WATCH_INTERVAL: Duration = Duration::from_millis(250);

/// A panic the property raised.
pub struct PanicRecord
{
    /// The panic's message.
    pub message: String,
    /// Where it was raised, `file:line:column`: the crash's deduplication key.
    pub location: String,
    /// The backtrace at the panic.
    pub backtrace: Backtrace,
}

/// The last panic the hook of [`catch_panics`] recorded.
static LAST_PANIC: Mutex<Option<PanicRecord>> = Mutex::new(None);

/// When the execution in progress started, in milliseconds since [`EPOCH`]
/// plus one; 0 while none runs.
static STARTED: AtomicU64 = AtomicU64::new(0);

/// The instant the watchdog's clock counts from.
static EPOCH: OnceLock<Instant> = OnceLock::new();

/// Milliseconds since [`EPOCH`], plus one so the value is never 0.
fn now() -> u64
{
    let elapsed = EPOCH.get_or_init(Instant::now).elapsed().as_millis();
    u64::try_from(elapsed).unwrap_or(u64::MAX).saturating_add(1)
}

/// Replace the panic hook with one that records each panic, silently, for the
/// engine to read: a fuzzing run reports its own crash.
pub fn catch_panics()
{
    std::panic::set_hook(Box::new(|info| {
        let message = info
            .payload_as_str()
            .unwrap_or("(a payload that is not a string)")
            .to_owned();
        let location = info.location().map_or_else(
            || "unknown".to_owned(),
            |at| format!("{}:{}:{}", at.file(), at.line(), at.column()),
        );
        let record = PanicRecord {
            message,
            location,
            backtrace: Backtrace::force_capture(),
        };
        *LAST_PANIC.lock().unwrap_or_else(PoisonError::into_inner) = Some(record);
    }));
}

/// Start the watchdog thread, which ends the process with [`EXIT_TIMEOUT`]
/// when an execution runs past [`TIME_LIMIT`].
pub fn start_watchdog()
{
    let _ = now();
    thread::spawn(|| {
        watch();
    });
}

/// The watchdog's loop.
fn watch() -> !
{
    let limit = u64::try_from(TIME_LIMIT.as_millis()).unwrap_or(u64::MAX);
    loop
    {
        thread::sleep(WATCH_INTERVAL);
        let started = STARTED.load(Ordering::Relaxed);
        if started != 0 && now().saturating_sub(started) > limit
        {
            eprintln!(
                "fuzz: an input ran past the time limit of {} s",
                TIME_LIMIT.as_secs()
            );
            std::process::exit(EXIT_TIMEOUT);
        }
    }
}

/// Run `work` with the watchdog armed.
pub fn timed<T>(work: impl FnOnce() -> T) -> T
{
    STARTED.store(now(), Ordering::Relaxed);
    let result = work();
    STARTED.store(0, Ordering::Relaxed);
    result
}

/// How an execution ended.
pub enum Outcome
{
    /// The property held.
    Passed,
    /// The property panicked.
    Panicked(PanicRecord),
}

/// The executor of a run.
pub struct Executor
{
    property: fn(&[u8]),
    counters: Counters,
    current: Option<File>,
    buffer: Vec<u8>,
    executions: u64,
}

impl Executor
{
    /// An executor of `property` over `counters`. When `current` is given,
    /// each execution first writes its number and its input there, for the
    /// supervisor to read if the process ends.
    #[must_use]
    pub fn new(property: fn(&[u8]), counters: Counters, current: Option<File>) -> Self
    {
        Self {
            property,
            counters,
            current,
            buffer: Vec::new(),
            executions: 0,
        }
    }

    /// The edge counters the executions update.
    #[must_use]
    pub fn counters(&self) -> &Counters
    {
        &self.counters
    }

    /// The number of executions so far.
    #[must_use]
    pub fn executions(&self) -> u64
    {
        self.executions
    }

    /// Execute the property on `data`.
    pub fn run(&mut self, data: &[u8]) -> Outcome
    {
        self.executions = self.executions.saturating_add(1);
        self.save_current(data);
        self.counters.clear();
        LAST_PANIC
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let property = self.property;
        let result = timed(|| catch_unwind(AssertUnwindSafe(|| property(data))));
        if result.is_ok()
        {
            return Outcome::Passed;
        }
        let record = LAST_PANIC
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        Outcome::Panicked(record.unwrap_or_else(|| PanicRecord {
            message: "a panic the hook did not record".to_owned(),
            location: "unknown".to_owned(),
            backtrace: Backtrace::disabled(),
        }))
    }

    /// Write the execution's number, as 8 little-endian bytes, and `data` to
    /// the supervisor's file. A failed write ends the process: the supervisor
    /// could otherwise report the wrong input.
    fn save_current(&mut self, data: &[u8])
    {
        let Some(file) = self.current.as_mut()
        else
        {
            return;
        };
        self.buffer.clear();
        self.buffer
            .extend_from_slice(&self.executions.to_le_bytes());
        self.buffer.extend_from_slice(data);
        let len = u64::try_from(self.buffer.len()).unwrap_or(u64::MAX);
        let written = file
            .seek(SeekFrom::Start(0))
            .and_then(|_| file.write_all(&self.buffer))
            .and_then(|()| file.set_len(len));
        if let Err(err) = written
        {
            eprintln!("fuzz: saving the current input: {err}");
            std::process::exit(EXIT_ERROR);
        }
    }
}

/// The execution number and the input of a file [`Executor`] wrote, or
/// `None` for a file shorter than the number.
#[must_use]
pub fn read_current(bytes: &[u8]) -> Option<(u64, &[u8])>
{
    let (number, input) = bytes.split_first_chunk::<8>()?;
    Some((u64::from_le_bytes(*number), input))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn fails_on_a(data: &[u8])
    {
        assert!(data.first() != Some(&b'A'), "input starts with A");
    }

    // Defect caught: a panic that escapes the catch, is reported with
    // another location, or leaves the supervisor's file naming the wrong
    // input.
    #[test]
    fn a_panic_is_caught_with_its_location_and_the_input_is_saved_first()
    {
        catch_panics();
        let path = std::env::temp_dir().join(format!("fuzz-engine-exec-{}", std::process::id()));
        let file = File::create(&path).unwrap();
        let mut executor = Executor::new(fails_on_a, Counters::registered(), Some(file));
        assert!(matches!(executor.run(b"BBBB"), Outcome::Passed));
        let Outcome::Panicked(record) = executor.run(b"AB")
        else
        {
            panic!("the property's panic was not caught");
        };
        let _ = std::panic::take_hook();
        assert_eq!(record.message, "input starts with A");
        assert!(record.location.contains("exec.rs"), "{}", record.location);
        let saved = std::fs::read(&path).unwrap();
        assert_eq!(read_current(&saved), Some((2, &b"AB"[..])));
        assert_eq!(executor.executions(), 2);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(read_current(&[1, 2, 3]), None);
    }
}
