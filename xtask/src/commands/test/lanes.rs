// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/test/lanes.rs

//! The lanes of a cell (`cargo xtask test --cell T --lanes N`): the cell's
//! cases split over up to N lanes that run side by side, each on a private
//! copy of the checkout, so no case reads or writes the state another lane's
//! case changes.
//!
//! A lane's copy holds the source tree (the files `git ls-files` lists,
//! untracked ones not ignored included), which the `signing` and
//! `rollback` cases build their bootloaders from, and [`LANE_STATE`], the
//! state the cases read and write. Each case of a lane runs as its own
//! `xtask test <case> --lane-root <copy>` process, which resolves every path
//! from the copy. The weights of the registry only balance the lanes:
//! every case of the cell runs exactly once whatever they are
//! ([`check_cover`]), and the cell's report names each. Around the lanes
//! the cell records [`LANE_STATE`] of the checkout itself and fails when a
//! lane changed it ([`changed`]): a case that wrote outside its copy fails
//! the cell rather than racing another lane unseen.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Instant, SystemTime};

use crate::error::{Context as _, Result, bail, ensure};

use crate::arch::Arch;
use crate::argparse::ValueEnum as _;
use crate::cli::{TestArgs, TestCase, Tester};
use crate::context::Context;
use crate::util::step;

use super::cases::{CaseOption, case};

/// The most lanes a cell runs: the small boots the host launch rules admit
/// side by side (xtask/README.md § Host launch rules), so a lane boot on a
/// shared host is a small boot, and one fewer than the CI runners' 4 vCPUs,
/// since each boot keeps about one CPU busy.
pub const LANES_MAX: u32 = crate::host_lock::SMALL_BOOTS_MAX;

/// The weight of a case whose registry entry states none.
pub const DEFAULT_WEIGHT: u32 = 60;

/// The state, relative to the checkout's root, that a lane copies besides
/// the source tree, each with the cases that change it: the sysroot (every
/// case repacks it; `signing`, `rollback`, `enrolment` and `secureboot`
/// stage substitutes and requests on its ESP), the images every pack writes
/// (`disk.img`, `disk-data.img`), the symbols store crash reports are read
/// against, the trust store every pack signs under
/// (`target/xtask/signing`), and the UEFI targets' build output with the
/// host's build-script units, which the `signing` and `rollback` cases
/// rebuild their bootloaders from and into. A path absent from the checkout
/// is not copied.
pub const LANE_STATE: &[&str] = &[
    "sysroot",
    "symbols",
    "disk.img",
    "disk-data.img",
    "target/xtask/signing",
    "target/x86_64-unknown-uefi",
    "target/riscv64imac-seraph-uefi",
    "target/debug/build",
    "target/release/build",
];

/// The state of the checkout that no lane may change: [`LANE_STATE`] but
/// the build output, which a lane never reaches since its builds run in its
/// copy.
const GUARDED_STATE: &[&str] = &[
    "sysroot",
    "symbols",
    "disk.img",
    "disk-data.img",
    "target/xtask/signing",
];

/// The line a lane's case process prints last: its CPU seconds and its
/// children's.
pub const CPU_MARK: &str = "lane case cpu: ";

/// The start of the line a failing case process prints with its error.
const ERROR_MARK: &str = "error: ";

/// Split `cases`, each with its weight, over at most `lanes` lanes: the
/// heaviest first, each to the lane with the least weight so far (the first
/// such lane on a tie). A lane keeps the order `cases` gives; no lane is
/// empty.
#[must_use]
pub fn assign(cases: &[(TestCase, u32)], lanes: usize) -> Vec<Vec<TestCase>>
{
    let lanes = lanes.clamp(1, cases.len().max(1));
    let mut order: Vec<(usize, TestCase, u32)> = cases
        .iter()
        .enumerate()
        .map(|(i, &(name, weight))| (i, name, weight))
        .collect();
    order.sort_by_key(|&(_, _, weight)| std::cmp::Reverse(weight));
    // Each lane's weight so far and its cases, with their places in `cases`.
    let mut split: Vec<(u64, Vec<(usize, TestCase)>)> = vec![(0, Vec::new()); lanes];
    for (i, name, weight) in order
    {
        // `min_by_key` takes the first of equally light lanes.
        if let Some((load, members)) = split.iter_mut().min_by_key(|(load, _)| *load)
        {
            *load = load.saturating_add(u64::from(weight));
            members.push((i, name));
        }
    }
    split
        .into_iter()
        .filter(|(_, members)| !members.is_empty())
        .map(|(_, mut members)| {
            members.sort_unstable_by_key(|&(i, _)| i);
            members.into_iter().map(|(_, name)| name).collect()
        })
        .collect()
}

/// Fail unless `lanes` hold every case of `cases` exactly once, and
/// nothing else.
pub fn check_cover(cases: &[TestCase], lanes: &[Vec<TestCase>]) -> Result<()>
{
    let mut ran: Vec<TestCase> = lanes.iter().flatten().copied().collect();
    for name in cases
    {
        let count = ran.iter().filter(|r| *r == name).count();
        ensure!(
            count == 1,
            "the lanes run the {} case {count} times, not once",
            name.name()
        );
        ran.retain(|r| r != name);
    }
    if let Some(extra) = ran.first()
    {
        bail!(
            "the lanes run the {} case, which the cell does not",
            extra.name()
        );
    }
    Ok(())
}

/// Each regular file and symbolic link under `paths` of `root` (a path a
/// file itself, or absent), with its length and modification time.
fn snapshot(root: &Path, paths: &[&str]) -> Result<BTreeMap<PathBuf, (u64, Option<SystemTime>)>>
{
    fn walk(path: &Path, out: &mut BTreeMap<PathBuf, (u64, Option<SystemTime>)>) -> Result<()>
    {
        let meta = match fs::symlink_metadata(path)
        {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        if meta.is_dir()
        {
            for entry in
                fs::read_dir(path).with_context(|| format!("reading {}", path.display()))?
            {
                walk(&entry.context("reading a directory entry")?.path(), out)?;
            }
        }
        else
        {
            out.insert(path.to_path_buf(), (meta.len(), meta.modified().ok()));
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    for path in paths
    {
        walk(&root.join(path), &mut out)?;
    }
    Ok(out)
}

/// The paths whose entry differs between `before` and `after`: changed,
/// added or removed.
fn changed(
    before: &BTreeMap<PathBuf, (u64, Option<SystemTime>)>,
    after: &BTreeMap<PathBuf, (u64, Option<SystemTime>)>,
) -> Vec<PathBuf>
{
    let mut out: Vec<PathBuf> = before
        .iter()
        .filter(|(path, entry)| after.get(*path) != Some(entry))
        .map(|(path, _)| path.clone())
        .collect();
    out.extend(
        after
            .keys()
            .filter(|path| !before.contains_key(*path))
            .cloned(),
    );
    out.sort();
    out
}

/// Copy `from` to `to`: a directory with what it holds, a file with its
/// modification time, so Cargo finds a copied build output fresh, and a
/// symbolic link as a link to the same target.
fn copy_tree(from: &Path, to: &Path) -> Result<()>
{
    let meta = fs::symlink_metadata(from).with_context(|| format!("reading {}", from.display()))?;
    if meta.file_type().is_symlink()
    {
        let target =
            fs::read_link(from).with_context(|| format!("reading the link {}", from.display()))?;
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, to)
            .with_context(|| format!("linking {}", to.display()))?;
        #[cfg(not(unix))]
        fs::copy(from, to).with_context(|| format!("copying {}", from.display()))?;
    }
    else if meta.is_dir()
    {
        fs::create_dir_all(to).with_context(|| format!("creating {}", to.display()))?;
        for entry in fs::read_dir(from).with_context(|| format!("reading {}", from.display()))?
        {
            let entry = entry.context("reading a directory entry")?;
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        }
    }
    else
    {
        if let Some(parent) = to.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::copy(from, to)
            .with_context(|| format!("copying {} to {}", from.display(), to.display()))?;
        let copied = fs::File::options()
            .write(true)
            .open(to)
            .with_context(|| format!("opening {}", to.display()))?;
        copied
            .set_modified(
                meta.modified()
                    .with_context(|| format!("reading {}", from.display()))?,
            )
            .with_context(|| format!("setting the time of {}", to.display()))?;
    }
    Ok(())
}

/// The source tree of the checkout at `root`: every file `git ls-files`
/// lists, tracked or untracked and not ignored, relative to `root`.
fn source_files(root: &Path) -> Result<Vec<PathBuf>>
{
    let out = Command::new("git")
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ])
        .current_dir(root)
        .output()
        .context("running git ls-files")?;
    ensure!(
        out.status.success(),
        "git ls-files failed in {}: the lanes copy the checkout's source tree, so they need a git \
         checkout",
        root.display()
    );
    Ok(out
        .stdout
        .split(|&b| b == 0)
        .filter(|name| !name.is_empty())
        .map(|name| PathBuf::from(String::from_utf8_lossy(name).into_owned()))
        .collect())
}

/// Make `lane` a private copy of the checkout at `root`: its source tree
/// and [`LANE_STATE`].
fn populate(root: &Path, lane: &Path, sources: &[PathBuf]) -> Result<()>
{
    for name in sources
    {
        let from = root.join(name);
        // A tracked file deleted in the working tree is not part of it.
        if fs::symlink_metadata(&from).is_err()
        {
            continue;
        }
        let to = lane.join(name);
        if let Some(parent) = to.parent()
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        copy_tree(&from, &to)?;
    }
    for path in LANE_STATE
    {
        let from = root.join(path);
        if fs::symlink_metadata(&from).is_ok()
        {
            copy_tree(&from, &lane.join(path))?;
        }
    }
    Ok(())
}

/// The outcome of one case of a lane.
struct Ran
{
    name: TestCase,
    passed: bool,
    wall: f64,
    cpu: Option<f64>,
    /// The case's last [`ERROR_MARK`] line, without the mark.
    error: Option<String>,
}

/// The output a run of a case's process leaves the cell.
struct Echoed
{
    passed: bool,
    /// The CPU seconds its last [`CPU_MARK`] line states.
    cpu: Option<f64>,
    /// Its last [`ERROR_MARK`] line, without the mark.
    error: Option<String>,
}

/// The command line of `name`'s process in the lane copy `lane`: the case
/// form of `test` with the cell's options it takes.
fn case_command(exe: &Path, name: TestCase, arch: Arch, args: &TestArgs, lane: &Path) -> Command
{
    let mut cmd = Command::new(exe);
    cmd.args(["test", &name.name(), "--arch", &arch.to_string()]);
    if args.release && case(name).options.contains(&CaseOption::Release)
    {
        cmd.arg("--release");
    }
    if let Some(cpus) = args.cpus
    {
        cmd.args(["--cpus", &cpus.to_string()]);
    }
    if let Some(mem) = args.mem
    {
        cmd.args(["--mem", &mem.to_string()]);
    }
    if let Some(secs) = args.host.common.wait_host
    {
        cmd.args(["--wait-host", &secs.to_string()]);
    }
    if args.host.common.host_override
    {
        cmd.arg("--host-override");
    }
    if let Some(holder) = &args.host.common.grant
    {
        cmd.args(["--grant", holder]);
    }
    cmd.arg("--lane-root").arg(lane);
    cmd
}

/// Run `cmd`, echoing each line of its output prefixed with `tag` and
/// appending it to `log`; whether it succeeded, the CPU seconds its last
/// [`CPU_MARK`] line states, and its last [`ERROR_MARK`] line.
fn run_echoed(mut cmd: Command, tag: &str, log: &Mutex<fs::File>) -> Result<Echoed>
{
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("starting a lane's case")?;
    let stdout = child.stdout.take().context("the case's stdout")?;
    let stderr = child.stderr.take().context("the case's stderr")?;
    let cpu = Mutex::new(None);
    let error = Mutex::new(None);
    std::thread::scope(|scope| {
        for stream in [
            Box::new(stdout) as Box<dyn std::io::Read + Send>,
            Box::new(stderr),
        ]
        {
            let (cpu, error) = (&cpu, &error);
            scope.spawn(move || {
                for line in BufReader::new(stream)
                    .lines()
                    .map_while(std::io::Result::ok)
                {
                    if let Some(secs) = line.split(CPU_MARK).nth(1)
                    {
                        *cpu.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            secs.trim_end_matches(" s").parse::<f64>().ok();
                    }
                    if let Some(text) = line.strip_prefix(ERROR_MARK)
                    {
                        *error
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) =
                            Some(text.to_owned());
                    }
                    println!("{tag} {line}");
                    let _ = writeln!(
                        log.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner),
                        "{line}"
                    );
                }
            });
        }
    });
    let status = child.wait().context("waiting for a lane's case")?;
    Ok(Echoed {
        passed: status.success(),
        cpu: cpu
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        error: error
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    })
}

/// The CPU seconds this process and its waited-for children have used, from
/// `/proc/self/stat`; `None` where there is none.
#[must_use]
pub fn cpu_seconds() -> Option<f64>
{
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    // The fields after the parenthesized command name, which may hold
    // spaces: utime, stime, cutime and cstime are the 14th to 17th of the
    // line, the 12th to 15th after it, in clock ticks of 1/100 s.
    let rest = stat.rsplit_once(')')?.1;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ticks: u64 = fields
        .get(11..15)?
        .iter()
        .map(|f| f.parse::<u64>().ok())
        .sum::<Option<u64>>()?;
    #[expect(clippy::cast_precision_loss, reason = "CPU ticks stay far below 2^52")]
    Some(ticks as f64 / 100.0)
}

/// Where a cell's lanes run: the copies of the checkout, under the host's
/// temporary directory, removed when the cell ends, and the directory in
/// the checkout that keeps each lane's logs.
struct LaneDirs
{
    base: PathBuf,
    logs: PathBuf,
}

impl LaneDirs
{
    /// The copy of lane `n` (from 1).
    fn root(&self, n: usize) -> PathBuf
    {
        self.base.join(n.to_string())
    }

    /// The log directory of lane `n` (from 1): `target/xtask/lanes/<n>/`.
    fn logs(&self, n: usize) -> PathBuf
    {
        self.logs.join(n.to_string())
    }
}

impl Drop for LaneDirs
{
    fn drop(&mut self)
    {
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// Run lane `n`'s cases one after another in its copy, each as its own
/// process; their outcomes, and the lane's wall time in seconds. The cases'
/// logs are copied to the lane's log directory afterwards.
fn run_lane(
    n: usize,
    lane: &[TestCase],
    dirs: &LaneDirs,
    lock: &Path,
    arch: Arch,
    args: &TestArgs,
) -> Result<(Vec<Ran>, f64)>
{
    let exe = std::env::current_exe().context("locating the xtask binary")?;
    let root = dirs.root(n);
    let dir = dirs.logs(n);
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let log = Mutex::new(fs::File::create(dir.join("lane.log")).context("creating the lane log")?);
    let started = Instant::now();
    let mut ran = Vec::new();
    for &name in lane
    {
        let mut cmd = case_command(&exe, name, arch, args, &root);
        cmd.env(crate::host_lock::LANE_LOCK_DIR_ENV, lock);
        let case_start = Instant::now();
        let echoed = run_echoed(cmd, &format!("[lane {n}]"), &log)?;
        ran.push(Ran {
            name,
            passed: echoed.passed,
            wall: case_start.elapsed().as_secs_f64(),
            cpu: echoed.cpu,
            error: echoed.error,
        });
    }
    for sub in ["test", "run"]
    {
        let from = root.join("target").join("xtask").join(sub);
        if from.exists()
        {
            copy_tree(&from, &dir.join(sub))?;
        }
    }
    Ok((ran, started.elapsed().as_secs_f64()))
}

/// The cell's report line of the case `r` of lane `n`: its outcome, wall and
/// CPU time, and for a failed case its last error line, so the failure reads
/// from the report, away from the lanes' interleaved output.
fn case_report(tester: Tester, n: usize, r: &Ran) -> String
{
    let cause = match (&r.error, r.passed)
    {
        (Some(error), false) => format!(": {error}"),
        _ => String::new(),
    };
    format!(
        "{} cell: lane {}: {} case: {} in {:.0} s wall{}{cause}",
        tester.name(),
        n,
        r.name.name(),
        if r.passed { "PASS" } else { "FAIL" },
        r.wall,
        cpu_note(r.cpu)
    )
}

/// ` and its CPU seconds`, or nothing when they are unknown.
fn cpu_note(cpu: Option<f64>) -> String
{
    cpu.map_or(String::new(), |c| format!(", {c:.0} s CPU"))
}

/// Run `names`, the cases of `tester`'s cell on `arch`, in up to `lanes`
/// lanes; the names of the cases that failed. Each case's outcome, wall and
/// CPU time are reported, then each lane's.
pub fn run(
    ctx: &Context,
    tester: Tester,
    arch: Arch,
    names: &[TestCase],
    args: &TestArgs,
    lanes: u32,
) -> Result<Vec<String>>
{
    let weighted: Vec<(TestCase, u32)> = names
        .iter()
        .map(|&name| (name, case(name).weight.unwrap_or(DEFAULT_WEIGHT)))
        .collect();
    let split = assign(&weighted, usize::try_from(lanes).unwrap_or(1));
    check_cover(names, &split)?;
    let lock = crate::host_lock::lock_dir(ctx);
    let sources = source_files(&ctx.root)?;
    let dirs = LaneDirs {
        base: std::env::temp_dir().join(format!("seraph-lanes-{}", std::process::id())),
        logs: ctx.target_dir.join("xtask").join("lanes"),
    };
    for dir in [&dirs.base, &dirs.logs]
    {
        if dir.exists()
        {
            fs::remove_dir_all(dir).with_context(|| format!("removing {}", dir.display()))?;
        }
    }
    let guarded = snapshot(&ctx.root, GUARDED_STATE)?;
    for (lane, n) in split.iter().zip(1usize..)
    {
        let list: Vec<String> = lane.iter().map(|name| name.name()).collect();
        step(&format!(
            "{} cell: lane {} of {}: {}",
            tester.name(),
            n,
            split.len(),
            list.join(", ")
        ));
        populate(&ctx.root, &dirs.root(n), &sources)?;
    }
    let results: Vec<Result<(Vec<Ran>, f64)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = split
            .iter()
            .zip(1usize..)
            .map(|(lane, n)| {
                let (dirs, lock) = (&dirs, lock.as_path());
                scope.spawn(move || run_lane(n, lane, dirs, lock, arch, args))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| bail!("a lane's thread panicked"))
            })
            .collect()
    });
    let mut failed = Vec::new();
    let mut ran_names = Vec::new();
    for (result, n) in results.into_iter().zip(1usize..)
    {
        let (ran, wall) = result.with_context(|| format!("lane {n}"))?;
        for r in &ran
        {
            step(&case_report(tester, n, r));
            if !r.passed
            {
                failed.push(r.name.name());
            }
        }
        step(&format!(
            "{} cell: lane {}: {:.0} s wall{}",
            tester.name(),
            n,
            wall,
            cpu_note(ran.iter().map(|r| r.cpu).sum())
        ));
        ran_names.push(ran.into_iter().map(|r| r.name).collect::<Vec<_>>());
    }
    check_cover(names, &ran_names).context("the lanes did not run the cell's cases")?;
    let moved = changed(&guarded, &snapshot(&ctx.root, GUARDED_STATE)?);
    if !moved.is_empty()
    {
        let list: Vec<String> = moved.iter().map(|p| p.display().to_string()).collect();
        bail!(
            "a lane changed the checkout's own state, outside its copy: {}",
            list.join(", ")
        );
    }
    Ok(failed)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use TestCase::*;

    // Defect caught: a lane assignment that drops or repeats a case, or
    // lets one lane carry the heavy cases while another idles.
    #[test]
    fn the_heaviest_cases_go_first_to_the_lightest_lane()
    {
        let cases = [
            (Terminal, 18),
            (Signing, 95),
            (DmaConfinement, 28),
            (Rollback, 30),
            (Enrolment, 112),
            (Secureboot, 38),
            (Wedge, 50),
            (Shutdown, 135),
        ];
        let lanes = assign(&cases, 3);
        assert_eq!(
            lanes,
            [
                vec![Rollback, Shutdown],
                vec![Terminal, Enrolment, Secureboot],
                vec![Signing, DmaConfinement, Wedge]
            ]
        );
        let names: Vec<TestCase> = cases.iter().map(|c| c.0).collect();
        check_cover(&names, &lanes).unwrap();
    }

    // Defect caught: an empty lane started, or more lanes than cases.
    #[test]
    fn no_lane_is_empty()
    {
        assert_eq!(assign(&[(Kaslr, 60)], 3), [vec![Kaslr]]);
        assert_eq!(assign(&[], 3), Vec::<Vec<TestCase>>::new());
        assert_eq!(
            assign(&[(Wedge, 1), (Terminal, 1)], 1),
            [vec![Wedge, Terminal]]
        );
    }

    // Defect caught: a weight that changes which cases run. Equal, zero or
    // extreme weights move cases between lanes and nothing else.
    #[test]
    fn a_weight_never_changes_which_cases_run()
    {
        let names = [Terminal, Signing, Wedge, Shutdown, Enrolment];
        for weights in [[0, 0, 0, 0, 0], [u32::MAX, 0, 1, 7, u32::MAX], [60; 5]]
        {
            let cases: Vec<(TestCase, u32)> = names.iter().copied().zip(weights).collect();
            for lanes in 1..=4
            {
                check_cover(&names, &assign(&cases, lanes)).unwrap();
            }
        }
    }

    // Defect caught: a lane that silently ran fewer cases, or a case twice,
    // reported as a passing cell.
    #[test]
    fn the_cover_check_refuses_a_missing_repeated_or_foreign_case()
    {
        let names = [Terminal, Wedge];
        check_cover(&names, &[vec![Terminal]]).unwrap_err();
        check_cover(&names, &[vec![Terminal, Wedge], vec![Wedge]]).unwrap_err();
        check_cover(&names, &[vec![Terminal, Wedge, Kaslr]]).unwrap_err();
        check_cover(&names, &[vec![Wedge], vec![Terminal]]).unwrap();
    }

    fn scratch(name: &str) -> PathBuf
    {
        let dir = std::env::temp_dir().join(format!("xtask-lanes-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // Defect caught: a write to the checkout's own sysroot or images from a
    // lane passing unseen.
    #[test]
    fn a_change_to_the_guarded_state_is_found()
    {
        let root = scratch("guard");
        fs::create_dir_all(root.join("sysroot/esp")).unwrap();
        fs::write(root.join("sysroot/esp/a"), b"a").unwrap();
        fs::write(root.join("disk.img"), b"img").unwrap();
        let before = snapshot(&root, GUARDED_STATE).unwrap();
        assert_eq!(
            changed(&before, &snapshot(&root, GUARDED_STATE).unwrap()),
            Vec::<PathBuf>::new()
        );
        fs::write(root.join("disk.img"), b"image").unwrap();
        fs::write(root.join("sysroot/esp/b"), b"b").unwrap();
        fs::remove_file(root.join("sysroot/esp/a")).unwrap();
        let moved = changed(&before, &snapshot(&root, GUARDED_STATE).unwrap());
        assert_eq!(
            moved,
            [
                root.join("disk.img"),
                root.join("sysroot/esp/a"),
                root.join("sysroot/esp/b")
            ]
        );
        fs::remove_dir_all(&root).unwrap();
    }

    // Defect caught: a copy that changes the modification times, so Cargo
    // rebuilds every copied output, or that follows a link.
    #[test]
    fn a_copy_keeps_times_and_links()
    {
        let root = scratch("copy");
        fs::create_dir_all(root.join("from/d")).unwrap();
        fs::write(root.join("from/d/f"), b"x").unwrap();
        let old = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        fs::File::options()
            .write(true)
            .open(root.join("from/d/f"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("d/f", root.join("from/l")).unwrap();
        copy_tree(&root.join("from"), &root.join("to")).unwrap();
        assert_eq!(fs::read(root.join("to/d/f")).unwrap(), b"x");
        assert_eq!(
            fs::metadata(root.join("to/d/f"))
                .unwrap()
                .modified()
                .unwrap(),
            old
        );
        #[cfg(unix)]
        assert_eq!(fs::read_link(root.join("to/l")).unwrap(), Path::new("d/f"));
        fs::remove_dir_all(&root).unwrap();
    }

    // Defect caught: a failing case whose error line is only in the lanes'
    // interleaved output, minutes before the cell's report, so the report
    // names the failure without its cause.
    #[test]
    fn a_failed_case_reports_its_last_error_line()
    {
        let root = scratch("echo");
        let log = Mutex::new(fs::File::create(root.join("lane.log")).unwrap());
        let mut cmd = Command::new("sh");
        cmd.args([
            "-c",
            "echo 'boot: error: not the mark'; echo 'error: first' >&2; \
             echo 'error: quit source: QMP write: Broken pipe' >&2; echo 'lane case cpu: 9.5 s'; \
             exit 1",
        ]);
        let echoed = run_echoed(cmd, "[lane 1]", &log).unwrap();
        assert!(!echoed.passed);
        assert_eq!(echoed.cpu, Some(9.5));
        let error = echoed.error.as_deref();
        assert_eq!(error, Some("quit source: QMP write: Broken pipe"));
        let mut ran = Ran {
            name: Vmgenid,
            passed: false,
            wall: 8.0,
            cpu: echoed.cpu,
            error: echoed.error,
        };
        assert_eq!(
            case_report(Tester::Usertest, 1, &ran),
            "usertest cell: lane 1: vmgenid case: FAIL in 8 s wall, 10 s CPU: quit source: QMP \
             write: Broken pipe"
        );
        // A passing case's report carries no error line, even one it printed.
        ran.passed = true;
        assert_eq!(
            case_report(Tester::Usertest, 1, &ran),
            "usertest cell: lane 1: vmgenid case: PASS in 8 s wall, 10 s CPU"
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_cpu_seconds_are_read_on_linux()
    {
        if cfg!(target_os = "linux")
        {
            assert!(cpu_seconds().is_some());
        }
    }
}
