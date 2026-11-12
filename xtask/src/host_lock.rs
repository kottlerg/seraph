// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/host_lock.rs

//! The shared host's launch rules, enforced by the commands that load it.
//!
//! The worktrees of one checkout share one host. Before a boot starts a QEMU,
//! and before a build compiles, the command takes the host lock, reads the
//! host's state (the live holders, the QEMUs running, the exclusive grant,
//! the 1-minute load average), and decides with [`decide`] whether the rules
//! admit it. An admitted boot registers a holder record that stays locked
//! for as long as the command, and every QEMU it starts, runs.
//!
//! The lock directory is `seraph-host/` in the checkout's git common
//! directory, so every worktree of the checkout reads the same holders
//! ([`lock_dir`]). In it:
//!
//! - `admission.lock`: held exclusively for the length of one admission, so
//!   two commands started at the same moment decide one after the other and
//!   the second sees the first's record.
//! - `holders/<pid>-<nanos>.json`: one record per admitted boot, held under an
//!   exclusive file lock by the command and, through an inherited descriptor,
//!   by its QEMUs. A record whose lock can be taken belongs to no live
//!   process; an admission removes it.
//! - `grant.json`: the exclusive grant, written by `cargo xtask orch grant
//!   set` and removed by `orch grant clear` and `orch end`.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail};
use serde_json::{Value, json};

use crate::cli::{BootHostArgs, HostArgs};
use crate::context::Context;
use crate::util::step;

/// The 1-minute load average a build starts under.
pub const BUILD_LOAD_MAX: f64 = 32.0;

/// The 1-minute load average a small boot starts under.
pub const SMALL_BOOT_LOAD_MAX: f64 = 16.0;

/// The 1-minute load average a large boot, or a timing-sensitive
/// measurement, starts under.
pub const LARGE_BOOT_LOAD_MAX: f64 = 10.0;

/// The most vCPUs a QEMU of a small boot has.
pub const SMALL_BOOT_VCPUS_MAX: u32 = 4;

/// The most QEMUs of small boots that run side by side.
pub const SMALL_BOOTS_MAX: u32 = 2;

/// How often a command started with `--wait-host` asks again.
const WAIT_POLL: Duration = Duration::from_secs(10);

/// The lock directory's name under the git common directory.
const LOCK_DIR_NAME: &str = "seraph-host";
const ADMISSION_LOCK: &str = "admission.lock";
const HOLDERS_DIR: &str = "holders";
const GRANT_FILE: &str = "grant.json";

/// The longest command line a holder record keeps.
const COMMAND_MAX: usize = 200;

// ── The rules ─────────────────────────────────────────────────────────────────

/// How a boot shares the host, beyond what its size decides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootMode
{
    /// The size decides: a small boot shares the host with one other.
    Shared,
    /// A run docs/testing.md § Coverage tiers owes: no other QEMU beside it.
    Alone,
    /// A timing-sensitive measurement: no other QEMU, the large-boot load
    /// limit, and no build while it runs.
    Timing,
}

/// What a command asks the host for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request
{
    /// A build: compiles, starts no QEMU.
    Build,
    /// A boot of `qemus` QEMUs side by side, each with `vcpus` vCPUs, under
    /// the grant of `grant` when it names one.
    Boot
    {
        vcpus: u32,
        qemus: u32,
        mode: BootMode,
        grant: Option<String>,
    },
}

/// A live holder of the host, as its record states it.
#[derive(Clone, Debug, PartialEq)]
pub struct Holder
{
    pub pid: u32,
    pub command: String,
    pub checkout: String,
    pub vcpus: u32,
    pub qemus: u32,
    /// Admitted on the condition that nothing runs beside it.
    pub exclusive: bool,
    /// A timing-sensitive measurement.
    pub timing: bool,
}

/// What the host's probes read at one moment.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Probe
{
    /// The 1-minute load average, when the host reports one.
    pub load: Option<f64>,
    /// The vCPU count of each `qemu-system-*` process running.
    pub qemus: Vec<u32>,
}

/// Whether one boot of `vcpus` vCPUs and `qemus` QEMUs in `mode` needs the
/// host to itself: more than [`SMALL_BOOT_VCPUS_MAX`] vCPUs, more QEMUs than
/// [`SMALL_BOOTS_MAX`] (which the two-boot rule admits beside nothing), or a
/// mode that runs alone.
fn needs_host_alone(vcpus: u32, qemus: u32, mode: BootMode) -> bool
{
    vcpus > SMALL_BOOT_VCPUS_MAX || qemus > SMALL_BOOTS_MAX || mode != BootMode::Shared
}

/// The load a boot starts under, with the constant's name and what it limits,
/// for the refusal.
fn boot_load_max(vcpus: u32, qemus: u32, mode: BootMode) -> (f64, &'static str, &'static str)
{
    if vcpus > SMALL_BOOT_VCPUS_MAX || qemus > SMALL_BOOTS_MAX || mode == BootMode::Timing
    {
        (
            LARGE_BOOT_LOAD_MAX,
            "LARGE_BOOT_LOAD_MAX",
            "a boot of more than 4 vCPUs or more than 2 QEMUs, or a timing measurement",
        )
    }
    else
    {
        (
            SMALL_BOOT_LOAD_MAX,
            "SMALL_BOOT_LOAD_MAX",
            "a boot of 4 vCPUs or fewer",
        )
    }
}

/// Refuse when `load` is not under `max`.
fn check_load(load: Option<f64>, max: f64, name: &str, what: &str) -> Result<(), String>
{
    match load
    {
        Some(load) if load >= max => Err(format!(
            "the 1-minute load average is {load:.2}, not under {max} ({name}), the limit for {what}"
        )),
        _ => Ok(()),
    }
}

/// One line naming a holder.
fn describe(holder: &Holder) -> String
{
    format!(
        "pid {} ({} QEMU x {} vCPUs{}{}) in {}: {}",
        holder.pid,
        holder.qemus,
        holder.vcpus,
        if holder.exclusive { ", alone" } else { "" },
        if holder.timing { ", timing" } else { "" },
        holder.checkout,
        holder.command
    )
}

/// Decide whether the rules admit `request`, given the live `holders`, the
/// `probe`'s reading, and the holder of the exclusive grant, if any. The
/// refusal names what is in the way: the holder, the count, or the load read
/// and its limit.
pub fn decide(
    request: &Request,
    holders: &[Holder],
    probe: &Probe,
    grant: Option<&str>,
) -> Result<(), String>
{
    match request
    {
        Request::Build =>
        {
            if let Some(timing) = holders.iter().find(|h| h.timing)
            {
                return Err(format!(
                    "a timing-sensitive measurement holds the host: {}",
                    describe(timing)
                ));
            }
            check_load(probe.load, BUILD_LOAD_MAX, "BUILD_LOAD_MAX", "a build")
        }
        Request::Boot {
            vcpus,
            qemus,
            mode,
            grant: ours,
        } => decide_boot(
            *vcpus,
            *qemus,
            *mode,
            ours.as_deref(),
            holders,
            probe,
            grant,
        ),
    }
}

fn decide_boot(
    vcpus: u32,
    qemus: u32,
    mode: BootMode,
    ours: Option<&str>,
    holders: &[Holder],
    probe: &Probe,
    grant: Option<&str>,
) -> Result<(), String>
{
    if let Some(holder) = grant.filter(|holder| ours != Some(*holder))
    {
        return Err(format!(
            "the exclusive grant is held by {holder}; a boot under it passes --grant {holder}"
        ));
    }
    if let Some(alone) = holders.iter().find(|h| h.exclusive)
    {
        return Err(format!(
            "a boot that runs alone holds the host: {}",
            describe(alone)
        ));
    }
    if let Some(large) = probe.qemus.iter().find(|&&v| v > SMALL_BOOT_VCPUS_MAX)
    {
        return Err(format!(
            "a QEMU of {large} vCPUs is running, and nothing boots beside a boot of more than \
             {SMALL_BOOT_VCPUS_MAX}"
        ));
    }
    let registered: u32 = holders.iter().map(|h| h.qemus).sum();
    let observed = u32::try_from(probe.qemus.len()).unwrap_or(u32::MAX);
    let running = registered.max(observed);
    if needs_host_alone(vcpus, qemus, mode)
    {
        if running > 0
        {
            return Err(format!(
                "{running} QEMU(s) running; this boot ({qemus} QEMU x {vcpus} vCPUs, {mode:?}) \
                 needs the host to itself"
            ));
        }
    }
    else if running + qemus > SMALL_BOOTS_MAX
    {
        return Err(format!(
            "{running} QEMU(s) running; {qemus} more would pass the {SMALL_BOOTS_MAX} small \
             boots (SMALL_BOOTS_MAX) that run side by side"
        ));
    }
    let (max, name, what) = boot_load_max(vcpus, qemus, mode);
    check_load(probe.load, max, name, what)
}

// ── Probes ────────────────────────────────────────────────────────────────────

/// The vCPU count a QEMU command line asks for: the leading number of its
/// `-smp` value, or its `cpus=` key, and 1 (QEMU's default) without one.
pub fn qemu_vcpus(argv: &[String]) -> u32
{
    let Some(value) = argv
        .iter()
        .position(|a| a == "-smp")
        .and_then(|i| argv.get(i + 1))
    else
    {
        return 1;
    };
    let count = value
        .split(',')
        .find_map(|part| part.strip_prefix("cpus="))
        .unwrap_or_else(|| value.split(',').next().unwrap_or(""));
    count.parse().unwrap_or(1)
}

/// Whether `argv` is a QEMU system emulator's, by its program's file name
/// (read whole, so a name longer than the 15 characters of a process's
/// `comm` still matches).
pub fn is_qemu(argv: &[String]) -> bool
{
    argv.first()
        .and_then(|program| Path::new(program).file_name())
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("qemu-system-"))
}

/// The vCPU count of each QEMU system emulator running on the host, read
/// from `/proc`. Empty where the host has no `/proc`.
fn running_qemus() -> Vec<u32>
{
    let Ok(entries) = fs::read_dir("/proc")
    else
    {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_str()
                .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter_map(|e| fs::read(e.path().join("cmdline")).ok())
        .map(|raw| {
            raw.split(|&b| b == 0)
                .filter(|part| !part.is_empty())
                .map(|part| String::from_utf8_lossy(part).into_owned())
                .collect::<Vec<_>>()
        })
        .filter(|argv| is_qemu(argv))
        .map(|argv| qemu_vcpus(&argv))
        .collect()
}

/// The host's 1-minute load average, where the host reports one.
#[cfg(unix)]
fn load_average() -> Option<f64>
{
    let mut loads = [0.0f64; 3];
    // SAFETY: `getloadavg` writes at most `nelem` (here 1) doubles into the
    // buffer it is given, which holds 3, and keeps no pointer to it.
    let read = unsafe { libc::getloadavg(loads.as_mut_ptr(), 1) };
    (read >= 1).then_some(loads[0])
}

/// A host without `getloadavg` reports no load, and the check is skipped.
#[cfg(not(unix))]
fn load_average() -> Option<f64>
{
    None
}

/// Read the host's state now.
pub fn probe_host() -> Probe
{
    Probe {
        load: load_average(),
        qemus: running_qemus(),
    }
}

// ── The lock directory ────────────────────────────────────────────────────────

/// The lock directory of the checkout `ctx` belongs to: `seraph-host/` in
/// its git common directory, which every worktree of the checkout shares, or
/// `target/xtask/host/` outside a git checkout.
pub fn lock_dir(ctx: &Context) -> PathBuf
{
    match git_common_dir(&ctx.root)
    {
        Some(common) => common.join(LOCK_DIR_NAME),
        None => ctx.target_dir.join("xtask").join("host"),
    }
}

/// The absolute git common directory of the checkout at `root`, which every
/// worktree of that checkout shares, or `None` outside a git checkout.
pub fn git_common_dir(root: &Path) -> Option<PathBuf>
{
    Command::new("git")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
}

/// The holder of the exclusive grant recorded in `dir`, if any.
pub fn read_grant(dir: &Path) -> Result<Option<String>>
{
    let path = dir.join(GRANT_FILE);
    let raw = match fs::read_to_string(&path)
    {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    let value: Value =
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
    let holder = value
        .get("holder")
        .and_then(Value::as_str)
        .filter(|h| !h.is_empty())
        .with_context(|| format!("{} names no holder", path.display()))?;
    Ok(Some(holder.to_owned()))
}

/// Record the exclusive grant to `holder` for `commands` in `dir`.
pub fn write_grant(dir: &Path, holder: &str, commands: &str) -> Result<()>
{
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(GRANT_FILE);
    let temporary = dir.join(format!("{GRANT_FILE}.tmp"));
    let body = json!({ "holder": holder, "commands": commands, "set": unix_secs() });
    fs::write(&temporary, format!("{body}\n"))
        .with_context(|| format!("writing {}", temporary.display()))?;
    fs::rename(&temporary, &path).with_context(|| format!("replacing {}", path.display()))
}

/// Remove the exclusive grant from `dir`; no grant to remove is no error.
pub fn clear_grant(dir: &Path) -> Result<()>
{
    let path = dir.join(GRANT_FILE);
    match fs::remove_file(&path)
    {
        Err(err) if err.kind() != std::io::ErrorKind::NotFound =>
        {
            Err(err).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

fn unix_secs() -> u64
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A holder record's contents, from its JSON; `None` when it does not parse
/// (a record being written, seen by a reader outside the admission lock).
fn parse_holder(raw: &str) -> Option<Holder>
{
    let value: Value = serde_json::from_str(raw).ok()?;
    let number = |key: &str| {
        value
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
    };
    let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    let flag = |key: &str| value.get(key).and_then(Value::as_bool);
    Some(Holder {
        pid: number("pid")?,
        command: text("command")?,
        checkout: text("checkout")?,
        vcpus: number("vcpus")?,
        qemus: number("qemus")?,
        exclusive: flag("exclusive")?,
        timing: flag("timing")?,
    })
}

/// Whether a record is held by a live process.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordState
{
    /// Its lock is held.
    Live,
    /// A reader can take its lock, so no live process holds it.
    Dead,
    /// It no longer exists (removed since the directory was read).
    Gone,
}

fn record_state(path: &Path) -> RecordState
{
    let Ok(file) = File::open(path)
    else
    {
        return RecordState::Gone;
    };
    if file.try_lock_shared().is_ok()
    {
        RecordState::Dead
    }
    else
    {
        RecordState::Live
    }
}

/// What to do with a record no live process holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DeadRecords
{
    /// Remove it: only under the admission lock, where no record is between
    /// its creation and its lock.
    Remove,
    /// Leave it: a reader outside the admission lock.
    Keep,
}

/// The live holders recorded in `dir`. A live record that does not parse is
/// counted as a boot that runs alone, so it can only refuse.
fn live_holders(dir: &Path, dead: DeadRecords) -> Vec<Holder>
{
    let Ok(entries) = fs::read_dir(dir.join(HOLDERS_DIR))
    else
    {
        return Vec::new();
    };
    let mut holders = Vec::new();
    for path in entries.flatten().map(|e| e.path())
    {
        match record_state(&path)
        {
            RecordState::Live =>
            {}
            RecordState::Dead =>
            {
                if dead == DeadRecords::Remove
                {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }
            RecordState::Gone => continue,
        }
        let raw = fs::read_to_string(&path).unwrap_or_default();
        holders.push(parse_holder(&raw).unwrap_or_else(|| Holder {
            pid: 0,
            command: format!("unreadable record {}", path.display()),
            checkout: String::new(),
            vcpus: 0,
            qemus: 0,
            exclusive: true,
            timing: false,
        }));
    }
    holders
}

// ── Admission ─────────────────────────────────────────────────────────────────

/// What the caller of an admission states beyond its request.
#[derive(Clone, Debug)]
pub struct Claim
{
    /// The command line, for the holder record.
    pub command: String,
    /// The checkout the command runs in, for the holder record.
    pub checkout: String,
    /// Admit even when the rules refuse (`--host-override`).
    pub overridden: Override,
}

/// Whether the rules' refusal stands (`--host-override`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Override
{
    No,
    Yes,
}

/// An admitted command's hold on the host. A boot's holds its record's
/// locked file; the lock ends when the file's last descriptor closes, which
/// for a boot that shared it with its QEMUs ([`Admission::share_with_children`])
/// is when the last of them exits.
#[derive(Debug)]
pub struct Admission
{
    record: Option<(PathBuf, File)>,
}

impl Admission
{
    /// An admission that holds nothing: a build, or a host check skipped.
    fn none() -> Self
    {
        Self { record: None }
    }

    /// The record's path, for a boot's admission.
    #[cfg(test)]
    pub fn record_path(&self) -> Option<&Path>
    {
        self.record.as_ref().map(|(path, _)| path.as_path())
    }

    /// Let the processes this command starts from now on inherit the
    /// record's descriptor, so a QEMU that outlives the command (the command
    /// killed mid-run) keeps its record live.
    #[cfg(unix)]
    pub fn share_with_children(&self) -> Result<()>
    {
        use std::os::fd::AsRawFd as _;
        let Some((path, file)) = &self.record
        else
        {
            return Ok(());
        };
        let fd = file.as_raw_fd();
        // SAFETY: `fd` is the open descriptor `file` owns for the duration of
        // this call; F_GETFD and F_SETFD read and write only its
        // close-on-exec flag, and touch no memory.
        let cleared = unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            flags >= 0 && libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) >= 0
        };
        if !cleared
        {
            bail!(
                "clearing close-on-exec on {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }
        Ok(())
    }

    /// A host without inheritable descriptors holds the record for the
    /// command's lifetime only.
    #[cfg(not(unix))]
    pub fn share_with_children(&self) -> Result<()>
    {
        Ok(())
    }
}

/// The refusal of one admission attempt, or an error that ends the command.
#[derive(Debug)]
pub enum Attempt
{
    Refused(String),
    Failed(anyhow::Error),
}

impl From<anyhow::Error> for Attempt
{
    fn from(err: anyhow::Error) -> Self
    {
        Attempt::Failed(err)
    }
}

/// Write `request`'s holder record into `dir` and lock it: called under the
/// admission lock, so no reader that removes dead records sees it unlocked.
fn register(dir: &Path, request: &Request, claim: &Claim) -> Result<Admission>
{
    let Request::Boot {
        vcpus, qemus, mode, ..
    } = request
    else
    {
        return Ok(Admission::none());
    };
    let holders = dir.join(HOLDERS_DIR);
    fs::create_dir_all(&holders).with_context(|| format!("creating {}", holders.display()))?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = holders.join(format!("{}-{nanos}.json", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.lock()
        .with_context(|| format!("locking {}", path.display()))?;
    let command: String = claim.command.chars().take(COMMAND_MAX).collect();
    let body = json!({
        "pid": std::process::id(),
        "command": command,
        "checkout": claim.checkout,
        "vcpus": vcpus,
        "qemus": qemus,
        "exclusive": needs_host_alone(*vcpus, *qemus, *mode),
        "timing": *mode == BootMode::Timing,
        "override": claim.overridden == Override::Yes,
        "started": unix_secs(),
    });
    writeln!(file, "{body}").with_context(|| format!("writing {}", path.display()))?;
    Ok(Admission {
        record: Some((path, file)),
    })
}

/// One admission attempt in `dir`: under the admission lock, read the live
/// holders and the grant, take `probe`'s reading, decide, and register when
/// admitted (or when the claim overrides the refusal, which is printed).
pub fn try_admit(
    dir: &Path,
    request: &Request,
    claim: &Claim,
    probe: &dyn Fn() -> Probe,
) -> Result<Admission, Attempt>
{
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let gate_path = dir.join(ADMISSION_LOCK);
    let gate = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&gate_path)
        .with_context(|| format!("opening {}", gate_path.display()))?;
    gate.lock()
        .with_context(|| format!("locking {}", gate_path.display()))?;
    let holders = live_holders(dir, DeadRecords::Remove);
    let grant = read_grant(dir)?;
    match decide(request, &holders, &probe(), grant.as_deref())
    {
        Ok(()) => Ok(register(dir, request, claim)?),
        Err(refusal) if claim.overridden == Override::Yes =>
        {
            step(&format!(
                "host check overridden (--host-override): {refusal}"
            ));
            Ok(register(dir, request, claim)?)
        }
        Err(refusal) => Err(Attempt::Refused(refusal)),
    }
    // `gate` drops here, after the record is locked.
}

/// Admit `request` in `dir`, asking again every `poll` until admitted or
/// until `wait` has passed (no wait refuses at once). A refusal at the bound
/// is the command's error, naming the last reason.
pub fn admit(
    dir: &Path,
    request: &Request,
    claim: &Claim,
    wait: Option<Duration>,
    poll: Duration,
    probe: &dyn Fn() -> Probe,
) -> Result<Admission>
{
    let started = Instant::now();
    let mut last_printed: Option<String> = None;
    loop
    {
        let refusal = match try_admit(dir, request, claim, probe)
        {
            Ok(admission) => return Ok(admission),
            Err(Attempt::Failed(err)) => return Err(err),
            Err(Attempt::Refused(refusal)) => refusal,
        };
        let waited = started.elapsed();
        match wait
        {
            Some(bound) if waited < bound =>
            {
                if last_printed.as_deref() != Some(refusal.as_str())
                {
                    step(&format!(
                        "waiting for the host (up to {}s): {refusal}",
                        bound.as_secs()
                    ));
                    last_printed = Some(refusal);
                }
                std::thread::sleep(poll.min(bound.saturating_sub(waited)));
            }
            Some(bound) => bail!(
                "the host did not admit this command within --wait-host {}: {refusal}",
                bound.as_secs()
            ),
            None => bail!(
                "the host refuses this command: {refusal} (wait with --wait-host <SECS>, or \
                 override with --host-override; `cargo xtask host status` shows the host)"
            ),
        }
    }
}

// ── Entry points for the commands ─────────────────────────────────────────────

/// Whether the command runs on a CI runner, where each job is its own host
/// and the shared host's rules do not apply.
fn on_ci_runner() -> bool
{
    std::env::var("GITHUB_ACTIONS").is_ok_and(|v| v == "true")
}

fn claim(ctx: &Context, host: &HostArgs) -> Claim
{
    let command = std::env::args().collect::<Vec<_>>().join(" ");
    Claim {
        command,
        checkout: ctx.root.display().to_string(),
        overridden: if host.host_override
        {
            Override::Yes
        }
        else
        {
            Override::No
        },
    }
}

fn admit_command(ctx: &Context, host: &HostArgs, request: &Request) -> Result<Admission>
{
    if on_ci_runner()
    {
        step("host checks skipped: a CI runner is its own host");
        return Ok(Admission::none());
    }
    let wait = host.wait_host.map(Duration::from_secs);
    admit(
        &lock_dir(ctx),
        request,
        &claim(ctx, host),
        wait,
        WAIT_POLL,
        &probe_host,
    )
}

/// Admit a build (`build`, `clean`) on the host's load and its timing
/// holders. Holds nothing once admitted.
pub fn admit_build(ctx: &Context, host: &HostArgs) -> Result<()>
{
    admit_command(ctx, host, &Request::Build).map(drop)
}

/// Admit a boot of `qemus` QEMUs side by side, each of `vcpus` vCPUs, and
/// share its record with the QEMUs it starts. The returned admission is held
/// until the command's last QEMU has exited.
pub fn admit_boot(ctx: &Context, host: &BootHostArgs, vcpus: u32, qemus: u32) -> Result<Admission>
{
    let mode = match (host.alone, host.timing)
    {
        (_, true) => BootMode::Timing,
        (true, false) => BootMode::Alone,
        (false, false) => BootMode::Shared,
    };
    let request = Request::Boot {
        vcpus,
        qemus,
        mode,
        grant: host.grant.clone(),
    };
    let admission = admit_command(ctx, &host.common, &request)?;
    admission.share_with_children()?;
    Ok(admission)
}

/// Print the host's state: the load and its limits, the grant, the live
/// holders, and the QEMUs running (`cargo xtask host status`).
pub fn print_status(ctx: &Context) -> Result<()>
{
    let dir = lock_dir(ctx);
    let probe = probe_host();
    println!("lock directory: {}", dir.display());
    match probe.load
    {
        Some(load) => println!(
            "load (1 min): {load:.2}; limits: build {BUILD_LOAD_MAX}, boot of {SMALL_BOOT_VCPUS_MAX} \
             vCPUs or fewer {SMALL_BOOT_LOAD_MAX}, larger boot or timing {LARGE_BOOT_LOAD_MAX}"
        ),
        None => println!("load: not reported by this host"),
    }
    match read_grant(&dir)?
    {
        Some(holder) => println!("exclusive grant: {holder}"),
        None => println!("exclusive grant: none"),
    }
    let holders = live_holders(&dir, DeadRecords::Keep);
    println!("holders: {}", holders.len());
    for holder in &holders
    {
        println!("  {}", describe(holder));
    }
    println!(
        "QEMUs running: {} (vCPUs: {:?})",
        probe.qemus.len(),
        probe.qemus
    );
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests
{
    use super::*;
    use std::sync::{Arc, Barrier};

    fn boot(vcpus: u32, qemus: u32, mode: BootMode) -> Request
    {
        Request::Boot {
            vcpus,
            qemus,
            mode,
            grant: None,
        }
    }

    fn holder(vcpus: u32, qemus: u32, mode: BootMode) -> Holder
    {
        Holder {
            pid: 7,
            command: "cargo xtask run-parallel".into(),
            checkout: "/w".into(),
            vcpus,
            qemus,
            exclusive: needs_host_alone(vcpus, qemus, mode),
            timing: mode == BootMode::Timing,
        }
    }

    fn quiet() -> Probe
    {
        Probe {
            load: Some(1.0),
            qemus: Vec::new(),
        }
    }

    fn loaded(load: f64) -> Probe
    {
        Probe {
            load: Some(load),
            qemus: Vec::new(),
        }
    }

    fn scratch(tag: &str) -> PathBuf
    {
        let dir =
            std::env::temp_dir().join(format!("seraph-host-lock-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Admit `request` once a released lock has ended. A process another
    /// test forks shares this process's descriptors until it execs, so a
    /// lock can outlive its drop by that window; the bounded wait covers it.
    fn admit_after_release(dir: &Path, request: &Request) -> Result<Admission>
    {
        admit(
            dir,
            request,
            &claim(),
            Some(Duration::from_secs(5)),
            Duration::from_millis(20),
            &|| quiet(),
        )
    }

    fn claim() -> Claim
    {
        Claim {
            command: "test".into(),
            checkout: "/w".into(),
            overridden: Override::No,
        }
    }

    #[test]
    fn two_small_boots_run_side_by_side_and_a_third_is_refused()
    {
        let small = boot(4, 1, BootMode::Shared);
        assert!(decide(&small, &[], &quiet(), None).is_ok());
        let one = [holder(4, 1, BootMode::Shared)];
        assert!(decide(&small, &one, &quiet(), None).is_ok());
        let two = [
            holder(4, 1, BootMode::Shared),
            holder(2, 1, BootMode::Shared),
        ];
        let refusal = decide(&small, &two, &quiet(), None).unwrap_err();
        assert!(refusal.contains("SMALL_BOOTS_MAX"), "{refusal}");
        // A run-parallel wave of two takes both places.
        let pair = boot(4, 2, BootMode::Shared);
        assert!(decide(&pair, &[], &quiet(), None).is_ok());
        assert!(decide(&pair, &one, &quiet(), None).is_err());
    }

    #[test]
    fn a_large_boot_is_refused_beside_any_qemu_and_refuses_every_boot()
    {
        let large = boot(8, 1, BootMode::Shared);
        assert!(decide(&large, &[], &quiet(), None).is_ok());
        let small = [holder(1, 1, BootMode::Shared)];
        assert!(decide(&large, &small, &quiet(), None).is_err());
        // A QEMU no record names (started by hand, or by an older xtask).
        let unregistered = Probe {
            load: Some(1.0),
            qemus: vec![2],
        };
        assert!(decide(&large, &[], &unregistered, None).is_err());

        let held = [holder(8, 1, BootMode::Shared)];
        for request in [boot(1, 1, BootMode::Shared), boot(16, 1, BootMode::Shared)]
        {
            assert!(decide(&request, &held, &quiet(), None).is_err());
        }
        let observed_large = Probe {
            load: Some(1.0),
            qemus: vec![16],
        };
        assert!(decide(&boot(1, 1, BootMode::Shared), &[], &observed_large, None).is_err());
    }

    #[test]
    fn more_qemus_than_the_two_boot_rule_admits_need_the_host_alone()
    {
        let wave = boot(4, 4, BootMode::Shared);
        assert!(decide(&wave, &[], &quiet(), None).is_ok());
        assert!(decide(&wave, &[holder(1, 1, BootMode::Shared)], &quiet(), None).is_err());
        let refusal = decide(&wave, &[], &loaded(12.0), None).unwrap_err();
        assert!(refusal.contains("LARGE_BOOT_LOAD_MAX"), "{refusal}");
    }

    #[test]
    fn an_alone_or_timing_boot_runs_beside_nothing()
    {
        for mode in [BootMode::Alone, BootMode::Timing]
        {
            let request = boot(4, 1, mode);
            assert!(decide(&request, &[], &quiet(), None).is_ok());
            assert!(decide(&request, &[holder(4, 1, BootMode::Shared)], &quiet(), None).is_err());
            let held = [holder(4, 1, mode)];
            assert!(decide(&boot(1, 1, BootMode::Shared), &held, &quiet(), None).is_err());
        }
        // An alone run of a small boot keeps the small boot's load limit; a
        // timing run takes the large one.
        assert!(decide(&boot(4, 1, BootMode::Alone), &[], &loaded(12.0), None).is_ok());
        assert!(decide(&boot(4, 1, BootMode::Timing), &[], &loaded(12.0), None).is_err());
    }

    #[test]
    fn the_load_refusal_names_the_value_read_and_the_limit()
    {
        let refusal = decide(&boot(4, 1, BootMode::Shared), &[], &loaded(16.0), None).unwrap_err();
        assert!(refusal.contains("16.00"), "{refusal}");
        assert!(
            refusal.contains("not under 16 (SMALL_BOOT_LOAD_MAX)"),
            "{refusal}"
        );
        assert!(decide(&boot(4, 1, BootMode::Shared), &[], &loaded(15.9), None).is_ok());

        let refusal = decide(&boot(8, 1, BootMode::Shared), &[], &loaded(10.0), None).unwrap_err();
        assert!(
            refusal.contains("not under 10 (LARGE_BOOT_LOAD_MAX)"),
            "{refusal}"
        );

        let refusal = decide(&Request::Build, &[], &loaded(32.5), None).unwrap_err();
        assert!(refusal.contains("32.50"), "{refusal}");
        assert!(
            refusal.contains("not under 32 (BUILD_LOAD_MAX)"),
            "{refusal}"
        );
        assert!(decide(&Request::Build, &[], &loaded(31.0), None).is_ok());

        // A host that reports no load is not refused on it.
        let unknown = Probe::default();
        assert!(decide(&boot(8, 1, BootMode::Shared), &[], &unknown, None).is_ok());
    }

    #[test]
    fn a_build_is_refused_only_beside_a_timing_measurement()
    {
        let shared = [
            holder(4, 1, BootMode::Shared),
            holder(16, 1, BootMode::Shared),
        ];
        assert!(decide(&Request::Build, &shared, &quiet(), None).is_ok());
        assert!(decide(&Request::Build, &[], &quiet(), Some("W3")).is_ok());
        let timing = [holder(4, 1, BootMode::Timing)];
        assert!(decide(&Request::Build, &timing, &quiet(), None).is_err());
    }

    #[test]
    fn under_a_grant_only_its_holders_boots_are_admitted()
    {
        let mut ours = boot(8, 1, BootMode::Shared);
        let refusal = decide(&ours, &[], &quiet(), Some("W3")).unwrap_err();
        assert!(refusal.contains("--grant W3"), "{refusal}");
        if let Request::Boot { grant, .. } = &mut ours
        {
            *grant = Some("W3".into());
        }
        assert!(decide(&ours, &[], &quiet(), Some("W3")).is_ok());
        // The holder's boots still meet the rules.
        assert!(
            decide(
                &ours,
                &[holder(1, 1, BootMode::Shared)],
                &quiet(),
                Some("W3")
            )
            .is_err()
        );
        // A grant passed when none is outstanding is no refusal.
        assert!(decide(&ours, &[], &quiet(), None).is_ok());
    }

    #[test]
    fn the_vcpu_count_is_read_from_every_smp_form()
    {
        let argv = |smp: &[&str]| -> Vec<String> {
            ["qemu-system-x86_64", "-m", "512M"]
                .iter()
                .chain(smp)
                .map(|s| (*s).to_owned())
                .collect()
        };
        assert_eq!(qemu_vcpus(&argv(&["-smp", "8"])), 8);
        assert_eq!(qemu_vcpus(&argv(&["-smp", "cpus=16,sockets=1"])), 16);
        assert_eq!(qemu_vcpus(&argv(&["-smp", "4,sockets=2"])), 4);
        assert_eq!(qemu_vcpus(&argv(&[])), 1);
    }

    #[test]
    fn a_qemu_is_known_by_its_whole_program_name()
    {
        let argv = |program: &str| vec![program.to_owned(), "-smp".to_owned()];
        // Longer than the 15 characters of `comm`, which `pgrep` matched.
        assert!(is_qemu(&argv("/usr/bin/qemu-system-riscv64")));
        assert!(is_qemu(&argv("qemu-system-x86_64")));
        assert!(!is_qemu(&argv("/usr/bin/qemu-img")));
        assert!(!is_qemu(&argv("cargo")));
        assert!(!is_qemu(&[]));
    }

    #[test]
    fn of_commands_started_at_once_only_the_one_the_rules_admit_gets_in()
    {
        let dir = scratch("race");
        let threads = 8;
        let barrier = Arc::new(Barrier::new(threads));
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                let dir = dir.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    try_admit(&dir, &boot(8, 1, BootMode::Shared), &claim(), &|| quiet())
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let admitted = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(admitted, 1);
        assert!(
            results
                .iter()
                .all(|r| matches!(r, Ok(_) | Err(Attempt::Refused(_))))
        );

        // While the admitted one holds its record, a small boot is refused;
        // once its lock ends, its record is removed and the next boot gets in.
        assert!(matches!(
            try_admit(&dir, &boot(1, 1, BootMode::Shared), &claim(), &|| quiet()),
            Err(Attempt::Refused(_))
        ));
        let record = results
            .iter()
            .find_map(|r| r.as_ref().ok())
            .and_then(Admission::record_path)
            .unwrap()
            .to_owned();
        drop(results);
        let next = admit_after_release(&dir, &boot(1, 1, BootMode::Shared));
        assert!(next.is_ok());
        assert!(!record.exists());
        drop(next);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn two_small_boots_hold_the_host_until_one_ends()
    {
        let dir = scratch("small");
        let small = boot(4, 1, BootMode::Shared);
        let first = try_admit(&dir, &small, &claim(), &|| quiet()).unwrap();
        let second = try_admit(&dir, &small, &claim(), &|| quiet()).unwrap();
        assert!(matches!(
            try_admit(&dir, &small, &claim(), &|| quiet()),
            Err(Attempt::Refused(_))
        ));
        drop(first);
        let third = admit_after_release(&dir, &small).unwrap();
        drop((second, third));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_override_admits_a_refused_boot_and_registers_it()
    {
        let dir = scratch("override");
        let held = try_admit(&dir, &boot(8, 1, BootMode::Shared), &claim(), &|| quiet()).unwrap();
        let overriding = Claim {
            overridden: Override::Yes,
            ..claim()
        };
        let admitted = try_admit(&dir, &boot(4, 1, BootMode::Shared), &overriding, &|| {
            quiet()
        })
        .unwrap();
        let holders = live_holders(&dir, DeadRecords::Keep);
        assert_eq!(holders.len(), 2);
        drop((held, admitted));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_wait_ends_at_its_bound_with_the_refusal_and_admits_once_free()
    {
        let dir = scratch("wait");
        let large = boot(8, 1, BootMode::Shared);
        let held = try_admit(&dir, &large, &claim(), &|| quiet()).unwrap();
        let started = Instant::now();
        let err = admit(
            &dir,
            &large,
            &claim(),
            Some(Duration::from_millis(300)),
            Duration::from_millis(50),
            &|| quiet(),
        )
        .unwrap_err();
        assert!(started.elapsed() >= Duration::from_millis(300));
        let text = format!("{err:#}");
        assert!(text.contains("did not admit"), "{text}");
        assert!(text.contains("runs alone"), "{text}");

        let unwaited = admit(&dir, &large, &claim(), None, Duration::ZERO, &|| quiet());
        assert!(unwaited.is_err());

        // Released mid-wait, the waiting command gets in.
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(held);
        });
        let admitted = admit(
            &dir,
            &large,
            &claim(),
            Some(Duration::from_secs(10)),
            Duration::from_millis(50),
            &|| quiet(),
        );
        releaser.join().unwrap();
        assert!(admitted.is_ok());
        drop(admitted);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_grant_file_round_trips_and_clears()
    {
        let dir = scratch("grant");
        assert_eq!(read_grant(&dir).unwrap(), None);
        write_grant(&dir, "W3", "run-parallel --cpus 16").unwrap();
        assert_eq!(read_grant(&dir).unwrap().as_deref(), Some("W3"));
        clear_grant(&dir).unwrap();
        assert_eq!(read_grant(&dir).unwrap(), None);
        clear_grant(&dir).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_round_trips_through_its_json()
    {
        let dir = scratch("record");
        let admitted =
            try_admit(&dir, &boot(16, 1, BootMode::Timing), &claim(), &|| quiet()).unwrap();
        let holders = live_holders(&dir, DeadRecords::Keep);
        assert_eq!(holders.len(), 1);
        assert_eq!(holders[0].pid, std::process::id());
        assert_eq!((holders[0].vcpus, holders[0].qemus), (16, 1));
        assert!(holders[0].exclusive && holders[0].timing);
        drop(admitted);
        fs::remove_dir_all(&dir).unwrap();
    }
}
