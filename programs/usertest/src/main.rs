// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// programs/usertest/src/main.rs

//! Programs-surface test orchestrator.
//!
//! Compares the testers under `/tests/programs/` with those its recipe names,
//! spawns each named one present as a child process under the recipe's
//! bound, and reports a pass/fail verdict from the child's exit status. Each
//! child (per-program tester) drives its target `/programs/<name>` through
//! that program's real I/O surface; see
//! [docs/testing.md](../../../docs/testing.md) for the protocol.

#![expect(
    clippy::expect_used,
    reason = "usertest is a test harness: a broken invariant panics, and the run ends without its \
              pass marker, which fails it as a failed host test does; the build lints the harness \
              without the test configuration's relaxation of this lint, and the rule holds for \
              the whole harness, so the suppression is crate-wide"
)]

use std::os::seraph::process::CommandExt;
use std::os::seraph::startup_info;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use usertest::{
    Mismatch, OWN_SLOT, RunEnd, SeedPlan, Supervised, TESTER_BOUND_MS, TESTER_SEEDS, TESTERS,
    TesterList, parse_bound, supervise,
};

const TESTERS_DIR: &str = "/tests/programs";

/// The recipe seed slots usertest takes: its own `pwrmgr.shutdown` at
/// [`OWN_SLOT`] and the authorities its testers are declared to take. A seed
/// past them is released at bootstrap, and a declaration naming one is
/// refused.
const SEED_SLOTS: usize = 8;

/// How often a running tester's exit and the close of its output are
/// checked.
const POLL: Duration = Duration::from_millis(20);

/// How long, after a tester's bound, its kill is given to end it and close
/// its output before the run goes on without them.
const DRAIN: Duration = Duration::from_secs(5);

/// The recipe's declarations: which seeds each tester takes, which testers
/// the image holds, and the bound of each tester's run.
struct Declarations
{
    plan: SeedPlan,
    testers: TesterList,
    bound: Duration,
}

fn main()
{
    std::os::seraph::log::register_name(b"usertest");

    let seeds = bootstrap_seeds();
    let pwrmgr_auth = seeds[OWN_SLOT];

    std::os::seraph::log!("starting");

    let decl = match declarations()
    {
        Ok(decl) => decl,
        Err(refusal) =>
        {
            std::os::seraph::log!("{refusal}");
            std::os::seraph::log!("SOME TESTS FAILED");
            shutdown(pwrmgr_auth);
            return;
        }
    };

    let reconciled = decl.testers.reconcile(&discover_testers());
    let mut failed = 0usize;
    for mismatch in &reconciled.mismatches
    {
        match mismatch
        {
            Mismatch::Missing(name) =>
            {
                std::os::seraph::log!(
                    "  {name}: FAIL (named in {TESTERS}, absent from {TESTERS_DIR})"
                );
            }
            Mismatch::Unnamed(name) =>
            {
                std::os::seraph::log!("  {name}: FAIL (in {TESTERS_DIR}, not named in {TESTERS})");
            }
        }
        failed = failed.saturating_add(1);
    }

    let mut passed = 0usize;
    for name in &reconciled.run
    {
        std::os::seraph::log!("running {TESTERS_DIR}/{name}");
        match run_one(name, &seeds, &decl)
        {
            Ok(()) =>
            {
                std::os::seraph::log!("  {name}: PASS");
                passed = passed.saturating_add(1);
            }
            Err(reason) =>
            {
                std::os::seraph::log!("  {name}: FAIL ({reason})");
                failed = failed.saturating_add(1);
            }
        }
    }

    std::os::seraph::log!("passed={passed} failed={failed}");
    if failed == 0
    {
        std::os::seraph::log!("ALL TESTS PASSED");
    }
    else
    {
        std::os::seraph::log!("SOME TESTS FAILED");
    }

    shutdown(pwrmgr_auth);
}

/// Read the recipe's declarations from the env. A refusal, the log line
/// that says why, fails the run before any tester starts.
fn declarations() -> Result<Declarations, String>
{
    let seeds = std::env::var(TESTER_SEEDS).unwrap_or_default();
    let plan = SeedPlan::parse(&seeds, SEED_SLOTS)
        .map_err(|e| format!("{TESTER_SEEDS} refused: {e:?}"))?;
    let testers = TesterList::parse(&std::env::var(TESTERS).unwrap_or_default())
        .map_err(|e| format!("{TESTERS} refused: {e:?}"))?;
    if let Some(tester) = testers.unlisted_seed_entry(&plan)
    {
        return Err(format!(
            "{TESTER_SEEDS} refused: {tester} is not named in {TESTERS}"
        ));
    }
    let bound_ms = std::env::var(TESTER_BOUND_MS).unwrap_or_default();
    let bound =
        parse_bound(&bound_ms).ok_or_else(|| format!("{TESTER_BOUND_MS} refused: {bound_ms:?}"))?;
    Ok(Declarations {
        plan,
        testers,
        bound,
    })
}

/// The names of the files under `/tests/programs/`, sorted for the same
/// order on every boot. A directory that cannot be read is logged and holds
/// none, so every tester the recipe names is reported missing and the run
/// fails; a name that is not UTF-8 is taken lossily, and fails the run as
/// one the recipe does not name.
fn discover_testers() -> Vec<String>
{
    let entries = match std::fs::read_dir(TESTERS_DIR)
    {
        Ok(it) => it,
        Err(e) =>
        {
            std::os::seraph::log!("cannot read {TESTERS_DIR}: {e}");
            return Vec::new();
        }
    };
    let mut out: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|e| e.path().is_file())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// Spawn the tester `name` with a copy of each seed `decl` declares for it
/// as its bootstrap caps, forward its stdout and stderr to the boot log
/// under a per-tester prefix, each on a thread of its own, and turn its exit
/// status into a pass/fail. A tester with no declared seeds gets no creator
/// endpoint. A run that outlives `decl`'s bound fails, its tester killed.
fn run_one(name: &str, seeds: &[u64; SEED_SLOTS], decl: &Declarations) -> Result<(), String>
{
    let caps = copy_seeds(decl.plan.slots_for(name), seeds)?;
    let mut command = Command::new(format!("{TESTERS_DIR}/{name}"));
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if !caps.is_empty()
    {
        command.bootstrap_caps(&caps);
    }
    let start = Instant::now();
    let mut child = command.spawn().map_err(|e| format!("spawn: {e}"))?;

    // Each stream is drained on its own thread, so a tester blocked on a
    // full pipe ring of one stream never stops the other from closing, and
    // this thread is free to bound the run. A reader that failed to spawn
    // dropped the stream's read end, so the tester's writes to it fail
    // instead of blocking.
    let mut spawn_errors = Vec::new();
    let mut readers = Vec::new();
    let streams = [
        ("out", child.stdout.take().map(reader_input)),
        ("err", child.stderr.take().map(reader_input)),
    ];
    for (stream, input) in streams
    {
        let Some(input) = input
        else
        {
            continue;
        };
        let tester = name.to_string();
        match std::thread::Builder::new()
            .name(format!("{name}-std{stream}"))
            .spawn(move || forward_lines(&tester, stream, input))
        {
            Ok(handle) => readers.push(handle),
            Err(e) => spawn_errors.push(format!("std{stream} reader spawn: {e}")),
        }
    }

    let mut run = TesterRun {
        child,
        readers,
        start,
    };
    let end = supervise(&mut run, decl.bound, DRAIN)?;
    // Readers still running hold a stream a process the tester started keeps
    // open; they are left to end with it.
    if run.streams_closed()
    {
        for reader in run.readers
        {
            reader
                .join()
                .map_err(|_| "output reader panicked".to_string())?;
        }
    }
    let status = match end
    {
        RunEnd::Finished(status) => status,
        RunEnd::Overran(overrun) => return Err(overrun.reason(decl.bound)),
    };
    if let Some(e) = spawn_errors.into_iter().next()
    {
        return Err(e);
    }
    if status.success()
    {
        Ok(())
    }
    else
    {
        Err(match status.code()
        {
            Some(c) => format!("exit={c}"),
            None => "killed by notification".to_string(),
        })
    }
}

/// A tester's output stream as its reader thread takes it.
fn reader_input(stream: impl std::io::Read + Send + 'static) -> Box<dyn std::io::Read + Send>
{
    Box::new(stream)
}

/// A copy of each seed of `slots` for one tester. A copy that fails
/// releases the copies made before it. `SeedPlan::parse` kept every
/// declared slot below `SEED_SLOTS`.
fn copy_seeds(slots: &[usize], seeds: &[u64; SEED_SLOTS]) -> Result<Vec<u64>, String>
{
    let mut caps = Vec::new();
    for &slot in slots
    {
        match copy_seed(seeds.get(slot).copied().unwrap_or(0))
        {
            Ok(cap) => caps.push(cap),
            Err(e) =>
            {
                for &cap in caps.iter().filter(|&&cap| cap != 0)
                {
                    let _ = syscall::cap_delete(cap);
                }
                return Err(e);
            }
        }
    }
    Ok(caps)
}

/// One tester's run as `supervise` drives it: the child, the threads that
/// read its output, and its start.
struct TesterRun
{
    child: Child,
    readers: Vec<JoinHandle<()>>,
    start: Instant,
}

impl Supervised for TesterRun
{
    type Status = ExitStatus;

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, String>
    {
        self.child.try_wait().map_err(|e| e.to_string())
    }

    fn streams_closed(&self) -> bool
    {
        self.readers.iter().all(JoinHandle::is_finished)
    }

    fn kill(&mut self) -> Result<(), String>
    {
        self.child.kill().map_err(|e| e.to_string())
    }

    fn elapsed(&self) -> Duration
    {
        self.start.elapsed()
    }

    fn pause(&mut self)
    {
        std::thread::sleep(POLL);
    }
}

/// Drain a child stream and emit each line through the log under
/// `[<tester>:<stream>]`. Truncates lines at the log buffer; binary
/// output is silently dropped past the first NUL.
fn forward_lines<R: std::io::Read>(tester: &str, stream: &str, mut r: R)
{
    // A read chunk, not a line limit: the loop reads until EOF and `line`
    // grows to hold a line of any length.
    let mut buf = [0u8; 512];
    let mut line: Vec<u8> = Vec::with_capacity(512);
    loop
    {
        match r.read(&mut buf)
        {
            Ok(0) | Err(_) => break,
            Ok(n) =>
            {
                // `Read::read` reports at most the buffer's length.
                let chunk = buf
                    .get(..n)
                    .expect("read reported more bytes than its buffer");
                for &b in chunk
                {
                    if b == b'\n'
                    {
                        let s = String::from_utf8_lossy(&line);
                        std::os::seraph::log!("  [{tester}:{stream}] {s}");
                        line.clear();
                    }
                    else
                    {
                        line.push(b);
                    }
                }
            }
        }
    }
    if !line.is_empty()
    {
        let s = String::from_utf8_lossy(&line);
        std::os::seraph::log!("  [{tester}:{stream}] {s}");
    }
}

/// A copy of `seed` with its own rights, for one tester to take; `0` for an
/// absent seed, which the tester's slot then shows absent.
fn copy_seed(seed: u64) -> Result<u64, String>
{
    if seed == 0
    {
        return Ok(0);
    }
    let tag_rights = syscall::cap_info(seed, syscall_abi::CAP_INFO_TAG_RIGHTS)
        .map_err(|e| format!("seed rights: {e}"))?;
    // CAP_INFO_TAG_RIGHTS packs the tag above bit 32 and the rights below it.
    let rights = tag_rights & 0xFFFF_FFFF;
    syscall::cap_copy(seed, startup_info().self_cspace, rights)
        .map_err(|e| format!("seed copy: {e}"))
}

/// Bootstrap the recipe's seeds from the creator-endpoint rounds: pwrmgr's
/// SHUTDOWN-badged SEND at [`OWN_SLOT`], which the recipe seeds first, then
/// the authorities the testers are declared to take. Absent caps come back as
/// zero; without the shutdown authority the shutdown step logs a skip instead
/// of powering off (boot stays up for inspection).
fn bootstrap_seeds() -> [u64; SEED_SLOTS]
{
    let info = startup_info();
    if info.creator_endpoint == 0
    {
        return [0; SEED_SLOTS];
    }
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    // SAFETY: IPC buffer is registered by `_start` and page-aligned by the
    // boot protocol.
    // Only the present caps ride, named by each round's presence word; an
    // absent slot decodes as `0`. Seeds past `SEED_SLOTS` are released.
    unsafe { ipc::bootstrap::request_slots::<SEED_SLOTS>(info.creator_endpoint, ipc_buf) }
        .unwrap_or([0; SEED_SLOTS])
}

/// Terminal — pwrmgr powers off and QEMU exits. A reply arrives only on
/// failure (cap missing the authority badge or pwrmgr cannot power off);
/// in that case the log records the symptom and the process falls through
/// to its normal exit, leaving the system idle.
fn shutdown(pwrmgr_auth: u64)
{
    if pwrmgr_auth == 0
    {
        std::os::seraph::log!("pwrmgr shutdown skipped: no authority cap");
        return;
    }
    let info = startup_info();
    #[expect(
        clippy::cast_ptr_alignment,
        reason = "the IPC buffer page is 4 KiB-aligned, stricter than u64"
    )]
    let ipc_buf = info.ipc_buffer.cast::<u64>();
    let msg = ipc::IpcMessage::new(ipc::pwrmgr_labels::SHUTDOWN);
    // SAFETY: ipc_buf is the registered IPC buffer.
    let reply = unsafe { ipc::ipc_call(pwrmgr_auth, &msg, ipc_buf) };
    match reply
    {
        Ok(r) => std::os::seraph::log!(
            "pwrmgr SHUTDOWN returned unexpectedly (label={:#x})",
            r.label
        ),
        Err(_) => std::os::seraph::log!("pwrmgr SHUTDOWN ipc_call failed"),
    }
}
