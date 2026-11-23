// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/path_account.rs

//! path-account command: trace one iteration of each kernel benchmark under
//! QEMU's gdbstub and account for its instructions, or write the account
//! document from the traced configurations.
//!
//! The logic is in `crate::path_account`; this module boots the guest, drives
//! the gdbstub, and reads and writes the files. xtask/README.md
//! (`cargo xtask path-account`) states the method and its checks.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::path::{Path as FsPath, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SectionKind, SymbolKind};

use crate::arch::Arch;
use crate::benchmark::{BenchMode, Key, gather};
use crate::breakpoint_kill::resolve;
use crate::bundle::Harness;
use crate::cli::{PathAccountArgs, PathAccountCommand, PathAccountTraceArgs, PathAccountWriteArgs};
use crate::commands::bench_check::{read_runs, write_file};
use crate::commands::ktest_timing::first_line;
use crate::context::Context;
use crate::error::{Context as _, Result, bail, ensure};
use crate::guest::Guest;
use crate::path_account::{
    Configuration, CounterDest, Image, Path, Place, Step, Tally, attributed, counter_read,
    render_block, replace_block, window,
};
use crate::qemu::{
    Execution, Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr,
    X86Paging, X86ShadowStack, build_qemu_argv_for, validate_sysroot_for_launch,
};
use crate::qemu_gdb::{Stub, field_hex, function_path};
use crate::socket_dir::SocketDir;
use crate::symbolize::store::Store;
use crate::symbolize::{Resolution, Symbolizer, text_span};
use crate::util::{require_tool, step};

/// The kernel's line that gives its KASLR slide.
const KASLR_MARKER: &str = "kaslr: slide=";

/// The kernel's line that gives ktest's load bias.
const BIAS_MARKER: &str = "init: PIE bias=";

/// ktest's summary lines, one of which ends its run.
const END_MARKERS: [&str; 2] = ["[ktest] ALL TESTS PASSED", "[ktest] SOME TESTS FAILED"];

/// The kernel function whose first call, ktest's first syscall, comes after
/// the kernel has logged ktest's bias and before any benchmark runs.
const FIRST_SYSCALL: &str = "kernel::syscall::dispatch";

/// ktest's sample buffer, which every benchmark records into from index 0.
const SAMPLES_SYMBOL: &str = "ktest::bench::SAMPLES";

/// The function whose writes to the sample buffer are a benchmark's
/// recordings; the summary's in-place sort writes it too.
const RECORD_FUNCTION: &str = "<bench::stats::Samples>::record";

/// How many consecutive iterations of each benchmark are stepped, from
/// `--iteration`: the account takes the first whose window is the boot's p50.
const CANDIDATES: u32 = 8;

/// The wait for each gdbstub reply but a resume's.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(30);

/// The wait, after a stop, for a result line the guest logged before it.
const LINE_WAIT: Duration = Duration::from_secs(5);

/// Most instructions one traced iteration may step before the trace is
/// abandoned: well above the longest benchmark iteration (thread lifecycle,
/// about 10^5).
const MAX_STEPS: usize = 2_000_000;

/// Entry point for `cargo xtask path-account`.
pub fn run(ctx: &Context, args: &PathAccountArgs) -> Result<()>
{
    match &args.command
    {
        PathAccountCommand::Trace(trace_args) => trace(ctx, trace_args),
        PathAccountCommand::Write(write_args) => write_doc(ctx, write_args),
    }
}

/// The directory of every configuration's result and traces.
fn results_root(ctx: &Context) -> PathBuf
{
    ctx.root.join("target/xtask/path-account")
}

/// `path-account write`: the generated block from every result file.
fn write_doc(ctx: &Context, args: &PathAccountWriteArgs) -> Result<()>
{
    let mut configs = Vec::new();
    for (arch, profile) in [
        ("x86_64", "dev"),
        ("x86_64", "release"),
        ("riscv64", "dev"),
        ("riscv64", "release"),
    ]
    {
        let file = results_root(ctx).join(format!("{arch}-{profile}.tsv"));
        if !file.exists()
        {
            step(&format!(
                "no result for {arch} {profile} ({})",
                file.display()
            ));
            continue;
        }
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        configs.push(Configuration::parse(&text).with_context(|| format!("{}", file.display()))?);
    }
    ensure!(!configs.is_empty(), "no configuration has been traced");
    let doc = ctx.root.join(&args.doc);
    let text =
        std::fs::read_to_string(&doc).with_context(|| format!("reading {}", doc.display()))?;
    let updated = replace_block(&text, &render_block(&configs))
        .with_context(|| format!("{}", doc.display()))?;
    write_file(&doc, &updated)?;
    step(&format!(
        "wrote {} configuration(s) into {}",
        configs.len(),
        doc.display()
    ));
    Ok(())
}

/// The kernel's and ktest's images, symbols and spans.
struct Images
{
    kernel: Vec<u8>,
    ktest: Vec<u8>,
}

/// What the trace resolves addresses against: the two images' symbolizers,
/// their spans and their runtime offsets.
struct Resolver<'a>
{
    kernel: Symbolizer<'a>,
    ktest: Symbolizer<'a>,
    kernel_span: (u64, u64),
    ktest_span: (u64, u64),
    /// Each image's text symbols by address, for code no DWARF covers
    /// (assembly entry stubs).
    kernel_symbols: Vec<(u64, String)>,
    ktest_symbols: Vec<(u64, String)>,
    slide: u64,
    bias: u64,
    cache: HashMap<u64, (Place, Vec<String>)>,
}

impl Resolver<'_>
{
    /// The place of the instruction at runtime address `pc`, and its frames
    /// from the innermost out.
    fn resolve(&mut self, pc: u64) -> Result<(Place, Vec<String>)>
    {
        if let Some(hit) = self.cache.get(&pc)
        {
            return Ok(hit.clone());
        }
        let kernel_vaddr = pc.wrapping_sub(self.slide);
        let ktest_vaddr = pc.wrapping_sub(self.bias);
        let (image, resolution, symbols, vaddr) = if (self.kernel_span.0..self.kernel_span.1)
            .contains(&kernel_vaddr)
        {
            (
                Image::Kernel,
                Some(self.kernel.resolve(kernel_vaddr)?),
                &self.kernel_symbols,
                kernel_vaddr,
            )
        }
        else if (self.ktest_span.0..self.ktest_span.1).contains(&ktest_vaddr)
        {
            (
                Image::Ktest,
                Some(self.ktest.resolve(ktest_vaddr)?),
                &self.ktest_symbols,
                ktest_vaddr,
            )
        }
        else
        {
            (Image::Other, None, &self.kernel_symbols, pc)
        };
        let frames: Vec<String> = match resolution
        {
            Some(Resolution::DebugInfo(frames)) => frames
                .iter()
                .map(|f| {
                    f.function
                        .as_deref()
                        .map_or_else(|| "<unnamed>".to_owned(), |n| function_path(n).to_owned())
                })
                .collect(),
            Some(Resolution::SymbolTable { name, .. }) => vec![function_path(&name).to_owned()],
            Some(Resolution::Unresolved) => vec![nearest_symbol(symbols, vaddr)],
            None => vec![format!("<page {:#x}>", pc & !0xfff)],
        };
        let function = attributed(&frames).to_owned();
        let hit = (Place { image, function }, frames);
        self.cache.insert(pc, hit.clone());
        Ok(hit)
    }
}

/// The text symbols of `data`, demangled to their paths, by address.
fn text_symbols(data: &[u8]) -> Result<Vec<(u64, String)>>
{
    let file = object::File::parse(data).context("parsing the ELF")?;
    let mut symbols: Vec<(u64, String)> = file
        .symbols()
        .filter(|sym| {
            // Assembly labels carry no symbol type: take every symbol defined
            // in executable code.
            sym.is_definition()
                && !matches!(sym.kind(), SymbolKind::Section | SymbolKind::File)
                && sym
                    .section_index()
                    .and_then(|index| file.section_by_index(index).ok())
                    .is_some_and(|section| section.kind() == SectionKind::Text)
        })
        .filter_map(|sym| {
            let name = sym.name().ok()?;
            Some((
                sym.address(),
                function_path(&crate::symbolize::demangle(name)).to_owned(),
            ))
        })
        .collect();
    symbols.sort_unstable();
    Ok(symbols)
}

/// The name of the text symbol at or before `vaddr`, with its offset.
fn nearest_symbol(symbols: &[(u64, String)], vaddr: u64) -> String
{
    let after = symbols.partition_point(|(address, _)| *address <= vaddr);
    after
        .checked_sub(1)
        .and_then(|i| symbols.get(i))
        .map_or_else(|| "<unresolved>".to_owned(), |(_, name)| name.clone())
}

/// One stepped iteration: every instruction stepped, and the measured window
/// among them.
struct Candidate
{
    steps: Vec<Step>,
    window: std::ops::Range<usize>,
}

/// A benchmark's consecutive stepped iterations, before the result line that
/// names it.
struct Traced
{
    candidates: Vec<Candidate>,
}

impl Candidate
{
    /// The instructions of the measured window.
    fn window(&self) -> &[Step]
    {
        self.steps.get(self.window.clone()).unwrap_or(&[])
    }
}

/// `path-account trace`.
fn trace(ctx: &Context, args: &PathAccountTraceArgs) -> Result<()>
{
    let arch = args.arch;
    validate_sysroot_for_launch(ctx, arch)?;
    let harness = crate::sysroot::recorded_harness(ctx)?;
    ensure!(
        harness == Harness::Ktest,
        "the disk image boots the {harness:?} harness; run `cargo xtask mkdisk --harness ktest`"
    );
    ensure!(args.iteration >= 1, "--iteration must be at least 1");
    let profile = if args.release { "release" } else { "dev" };
    let images = read_images(ctx)?;
    let (references, reference_name) = references(args, arch)?;

    let samples = data_symbol(&images.ktest, SAMPLES_SYMBOL)?;
    let first_syscall = resolve(&images.kernel, FIRST_SYSCALL)?.address;
    let mut resolver = Resolver {
        kernel: Symbolizer::new(&images.kernel)?,
        ktest: Symbolizer::new(&images.ktest)?,
        kernel_span: text_span(&images.kernel).context("the kernel has no text")?,
        ktest_span: text_span(&images.ktest).context("ktest has no text")?,
        kernel_symbols: text_symbols(&images.kernel)?,
        ktest_symbols: text_symbols(&images.ktest)?,
        slide: 0,
        bias: 0,
        cache: HashMap::new(),
    };
    ensure!(
        resolver.kernel.has_debug_info() && resolver.ktest.has_debug_info(),
        "the kernel or ktest carries no DWARF: build with `--limited-debug kernel,ktest`"
    );

    let _host = crate::host_lock::admit_boot(ctx, &args.host, 1, 1)?;
    let out_dir = results_root(ctx).join(format!("{arch}-{profile}"));
    std::fs::create_dir_all(&out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let mut boot = Boot::launch(ctx, arch, &out_dir)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(args.timeout))
        .context("--timeout is too large")?;
    let traced = boot.trace_all(
        &mut resolver,
        samples,
        first_syscall,
        args.iteration,
        deadline,
    );
    boot.save_log()?;
    let traced = traced?;

    let mut config = Configuration {
        arch: arch.to_string(),
        profile: profile.to_owned(),
        head: head(ctx),
        date: today(),
        qemu: first_line(arch.qemu_binary(), &["--version"]),
        reference: reference_name,
        paths: Vec::new(),
    };
    let (paths, failures) = account(traced, &references, &mut resolver, &out_dir, args.iteration)?;
    config.paths = paths;
    ensure!(
        failures.is_empty(),
        "the account does not match the counts:\n  {}",
        failures.join("\n  ")
    );
    let result = results_root(ctx).join(format!("{arch}-{profile}.tsv"));
    write_file(&result, &config.render())?;
    step(&format!(
        "{} paths accounted; result {}, traces under {}",
        config.paths.len(),
        result.display(),
        out_dir.display()
    ));
    Ok(())
}

/// Check each traced window against its boot's p50 and its reference count,
/// write its trace, and tally it by function: the paths, and each check that
/// failed.
fn account(
    traced: Vec<(Key, u64, Traced)>,
    references: &BTreeMap<Key, u64>,
    resolver: &mut Resolver<'_>,
    out_dir: &FsPath,
    iteration: u32,
) -> Result<(Vec<Path>, Vec<String>)>
{
    let mut paths = Vec::new();
    let mut failures = Vec::new();
    for (key, p50, trace) in traced
    {
        // The first iteration that ran the boot's p50: one the free-running
        // samples call typical. Failing that, the first, which the check
        // below rejects.
        let lengths: Vec<usize> = trace.candidates.iter().map(|c| c.window().len()).collect();
        let chosen = lengths
            .iter()
            .position(|&n| u64::try_from(n).is_ok_and(|n| n == p50))
            .unwrap_or(0);
        let window = trace
            .candidates
            .get(chosen)
            .map_or(&[][..], Candidate::window);
        let measured = u64::try_from(window.len())?;
        let iteration = iteration.saturating_add(u32::try_from(chosen)?);
        let reference = references.get(&key).copied();
        write_trace(out_dir, &key, window, resolver)?;
        match reference
        {
            Some(reference) if reference == p50 =>
            {}
            Some(reference) => failures.push(format!(
                "{key}: the boot's p50 {p50}, the reference {reference}"
            )),
            None => failures.push(format!("{key}: traced {measured}, no reference count")),
        }
        if p50 != measured
        {
            failures.push(format!(
                "{key}: no stepped iteration ran the p50 {p50}: {lengths:?}"
            ));
        }
        let mut tally_err = None;
        let tally = Tally::of(window.iter().map(|s| s.pc), |pc| {
            match resolver.resolve(pc)
            {
                Ok((place, _)) => place,
                Err(e) =>
                {
                    tally_err.get_or_insert(e);
                    Place {
                        image: Image::Other,
                        function: "<error>".to_owned(),
                    }
                }
            }
        });
        if let Some(e) = tally_err
        {
            return Err(e.context(format!("attributing {key}")));
        }
        step(&format!(
            "{key}: {measured} instructions ({} ktest, {} kernel)",
            tally.of_image(Image::Ktest),
            tally.of_image(Image::Kernel)
        ));
        paths.push(Path {
            key: key.to_string(),
            p50,
            reference: reference.unwrap_or(0),
            iteration,
            tally,
        });
    }
    for key in references
        .keys()
        .filter(|k| !paths.iter().any(|p: &Path| p.key == k.to_string()))
    {
        failures.push(format!("{key}: has a reference count and was not traced"));
    }
    Ok((paths, failures))
}

/// The kernel image, as installed with its symbols, and ktest's symbols
/// store file.
fn read_images(ctx: &Context) -> Result<Images>
{
    let kernel_path = ctx.sysroot_efi_seraph().join("kernel");
    let kernel = std::fs::read(&kernel_path)
        .with_context(|| format!("reading {}", kernel_path.display()))?;
    let ktest_path = Store::at(ctx.symbols_dir()).symbols_path(&ctx.sysroot.join("tests/ktest"))?;
    let ktest =
        std::fs::read(&ktest_path).with_context(|| format!("reading {}", ktest_path.display()))?;
    Ok(Images { kernel, ktest })
}

/// The reference count of each one-CPU measurement: the lowest p50 of the
/// `--reference` logs, and what they are.
fn references(args: &PathAccountTraceArgs, arch: Arch) -> Result<(BTreeMap<Key, u64>, String)>
{
    let runs = read_runs(&args.reference)?;
    let set = gather(BenchMode::Icount, &runs)?;
    ensure!(
        set.arch == arch.to_string(),
        "the reference logs are of {}, not {arch}",
        set.arch
    );
    let counts = set
        .measured
        .iter()
        .filter(|(key, _)| key.cpus == 1)
        .map(|(key, m)| (key.clone(), m.lowest))
        .collect();
    Ok((
        counts,
        format!(
            "{} icount boot(s) of the image without debuginfo",
            runs.len()
        ),
    ))
}

/// The link address of the data symbol whose demangled path is `path`.
fn data_symbol(data: &[u8], path: &str) -> Result<u64>
{
    let file = object::File::parse(data).context("parsing the ELF")?;
    file.symbols()
        .filter(|sym| sym.kind() == SymbolKind::Data && sym.is_definition())
        .find(|sym| {
            sym.name()
                .is_ok_and(|raw| function_path(&crate::symbolize::demangle(raw)) == path)
        })
        .map(|sym| sym.address())
        .with_context(|| format!("no data symbol {path}"))
}

/// The commit of the tree, `-dirty` appended when it differs from it.
fn head(ctx: &Context) -> String
{
    let git = |args: &[&str]| {
        Command::new("git")
            .current_dir(&ctx.root)
            .args(args)
            .stderr(Stdio::null())
            .output()
            .ok()
            .map_or_else(String::new, |o| {
                String::from_utf8_lossy(&o.stdout).trim().to_owned()
            })
    };
    let sha = git(&["rev-parse", "--short=12", "HEAD"]);
    let dirty = !git(&["status", "--porcelain", "--untracked-files=no"]).is_empty();
    if dirty { format!("{sha}-dirty") } else { sha }
}

/// Today's UTC date.
fn today() -> String
{
    first_line("date", &["-u", "+%Y-%m-%d"])
}

/// Write the window of `key` as one line per instruction: its address, its
/// image, and its frames from the outermost in.
fn write_trace(dir: &FsPath, key: &Key, window: &[Step], resolver: &mut Resolver<'_>)
-> Result<()>
{
    let mut out = String::new();
    for s in window
    {
        let (place, frames) = resolver.resolve(s.pc)?;
        let chain: Vec<&str> = frames.iter().rev().map(String::as_str).collect();
        let _ = writeln!(
            out,
            "{:#018x} {} {}",
            s.pc,
            place.image.name(),
            chain.join(" > ")
        );
    }
    let name = key.to_string().replace([' ', '='], "_");
    write_file(&dir.join(format!("{name}.trace")), &out)
}

/// A booted guest and its gdbstub.
struct Boot
{
    arch: Arch,
    guest: Guest,
    stub: Option<Stub>,
    sock: PathBuf,
    /// Declared after `guest`: the socket is removed after QEMU is reaped.
    _sockets: SocketDir,
    /// Every serial line read, in order.
    lines: Vec<String>,
    /// How many of `lines` the trace has looked at for result lines.
    seen: usize,
    log: PathBuf,
    /// The first bytes of the instruction at each address stepped.
    code: HashMap<u64, Option<CounterDest>>,
}

impl Boot
{
    fn launch(ctx: &Context, arch: Arch, out_dir: &FsPath) -> Result<Self>
    {
        let firmware = Firmware::prepare(ctx, arch)?;
        let vars = firmware.launch_vars()?;
        let disk_path = ctx.disk_image();
        let sockets = SocketDir::create()?;
        let sock = sockets.socket("path-account.gdb")?;
        let spec = QemuLaunchSpec {
            arch,
            disk_path: &disk_path,
            disk_block_size: crate::disk::logical_block_size(&disk_path)?,
            second_disk: None,
            firmware_code_path: &firmware.code,
            firmware_vars_path: vars.path(),
            smm: firmware.smm,
            cpus: 1,
            threads_per_core: 1,
            mem_mib: 512,
            display: QemuDisplay::Headless,
            gdb: GdbMode::Unix(&sock),
            qmp_socket: None,
            vmgenid_guid: Some("auto"),
            incoming: None,
            riscv_mmu: RiscvMmu::Sv48,
            riscv_zkr: RiscvZkr::On,
            x86_paging: X86Paging::Four,
            x86_shadow_stack: X86ShadowStack::Off,
            iommu: Iommu::Attached,
            debug_port: None,
            test_devices: false,
            hotplug_port: None,
        };
        let qemu_args = build_qemu_argv_for(&spec, Execution::Icount)?;
        let qemu = require_tool(arch.qemu_binary())?;
        step(&format!(
            "Launching QEMU for the path account ({arch}, 1 CPU, icount, gdbstub on {})",
            sock.display()
        ));
        let child = Command::new(&qemu)
            .args(&qemu_args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning {}", arch.qemu_binary()))?;
        let guest = Guest::from_child(child)?.holding(vars);
        Ok(Self {
            arch,
            guest,
            stub: None,
            sock,
            _sockets: sockets,
            lines: Vec::new(),
            seen: 0,
            log: out_dir.join("boot.log"),
            code: HashMap::new(),
        })
    }

    fn stub(&mut self) -> Result<&mut Stub>
    {
        self.stub.as_mut().context("the gdbstub is not connected")
    }

    /// Read serial lines until one holds `marker`, waiting at most `timeout`;
    /// that line.
    fn line_with(&mut self, marker: &str, timeout: Duration) -> Result<String>
    {
        if let Some(line) = self.lines.iter().find(|l| l.contains(marker))
        {
            return Ok(line.clone());
        }
        let read = self.guest.collect_until(marker, timeout)?;
        self.lines.extend(read);
        self.lines.last().cloned().context("no line read")
    }

    /// Trace every benchmark: returns each traced measurement with the p50
    /// its result line gave and its trace.
    fn trace_all(
        &mut self,
        resolver: &mut Resolver<'_>,
        samples: u64,
        first_syscall: u64,
        iteration: u32,
        deadline: Instant,
    ) -> Result<Vec<(Key, u64, Traced)>>
    {
        let slide_line = self.line_with(KASLR_MARKER, remaining(deadline))?;
        resolver.slide = field_hex(&slide_line, "slide=").context("no slide in the KASLR line")?;
        let mut stub = Stub::connect(&self.sock, ANSWER_TIMEOUT)?;
        stub.request(b"?")?;
        // Steps run with interrupts and timers masked, so no interrupt enters
        // a stepped window.
        stub.expect_ok(b"Qqemu.sstep=0x7")?;
        self.stub = Some(stub);
        let pc_reg = gdb_arch(self.arch).pc_regnum();

        let bp = first_syscall.wrapping_add(resolver.slide);
        let kind = break_kind(self.arch);
        self.stub()?
            .expect_ok(format!("Z1,{bp:x},{kind}").as_bytes())?;
        let stop = self.resume_until_stop(deadline)?;
        ensure!(
            stop.is_some(),
            "the guest ended before ktest's first syscall"
        );
        self.stub()?
            .expect_ok(format!("z1,{bp:x},{kind}").as_bytes())?;
        let bias_line = self.line_with(BIAS_MARKER, LINE_WAIT)?;
        resolver.bias = field_hex(&bias_line, "bias=").context("no bias in ktest's bias line")?;

        let base = samples.wrapping_add(resolver.bias);
        let element = |i: u32| base.wrapping_add(u64::from(i).wrapping_mul(8));
        let before = element(iteration.saturating_sub(1));
        ensure!(
            self.stub()?.read_u64(before)? == 0,
            "ktest recorded a sample before the trace began"
        );
        self.stub()?
            .expect_ok(format!("Z2,{before:x},8").as_bytes())?;

        let mut traced: Vec<(Key, u64, Traced)> = Vec::new();
        let mut pending: Option<Traced> = None;
        while let Some(reply) = self.resume_until_stop(deadline)?
        {
            // QEMU's stop reply does not always name the watchpoint (x86
            // reports a bare `T05`); the watchpoint is the only stop set, and
            // the frames of the stop say whose write it was.
            let pc = self.stub()?.read_register(pc_reg)?;
            let (_, frames) = resolver.resolve(pc)?;
            ensure!(
                is_trap(&reply),
                "unexpected stop {:?} at {pc:#x} ({})",
                String::from_utf8_lossy(&reply),
                frames.join(" < ")
            );
            if !frames.iter().any(|f| f == RECORD_FUNCTION)
            {
                // The summary's sort, or a benchmark that writes the buffer
                // itself.
                continue;
            }
            if let Some(done) = pending.take()
            {
                let (key, p50) = self.next_result(LINE_WAIT)?;
                traced.push((key, p50, done));
            }
            // The stop follows the store of sample k-1: stepping from it to
            // the same address again runs exactly one iteration, whose last
            // instruction is the store of sample k. CANDIDATES iterations are
            // stepped in turn; the account takes the first whose window is
            // the boot's p50, which the result line gives only after them.
            ensure!(
                self.stub()?.read_u64(before)? != 0,
                "the watchpoint stopped before ktest's store at {pc:#x}"
            );
            self.stub()?
                .expect_ok(format!("z2,{before:x},8").as_bytes())?;
            let mut candidates = Vec::new();
            for j in 0..CANDIDATES
            {
                let at = element(iteration.saturating_add(j));
                let steps = self.step_until(pc, pc_reg)?;
                let sample = self.stub()?.read_u64(at)?;
                ensure!(
                    sample != 0,
                    "the stepped iteration recorded no sample at {at:#x}"
                );
                let window = window(&steps, sample)
                    .with_context(|| format!("the benchmark after {} traced", traced.len()))?;
                candidates.push(Candidate { steps, window });
            }
            self.stub()?
                .expect_ok(format!("Z2,{before:x},8").as_bytes())?;
            pending = Some(Traced { candidates });
        }
        if let Some(done) = pending.take()
        {
            let (key, p50) = self.next_result(LINE_WAIT)?;
            traced.push((key, p50, done));
        }
        ensure!(
            self.lines
                .iter()
                .any(|l| END_MARKERS.iter().any(|m| l.contains(m))),
            "ktest did not reach its summary"
        );
        Ok(traced)
    }

    /// Resume the guest and wait for its next stop; `None` when ktest's
    /// summary line came first, or the guest exited.
    fn resume_until_stop(&mut self, deadline: Instant) -> Result<Option<Vec<u8>>>
    {
        let resumed = self.stub()?.resume(b"c");
        if resumed.is_err() && self.ended()
        {
            return Ok(None);
        }
        resumed?;
        loop
        {
            ensure!(Instant::now() < deadline, "the boot outlived --timeout");
            let reply = self.stub()?.wait_stop(Duration::from_millis(500));
            if reply.is_err() && self.ended()
            {
                // QEMU closed the socket as the guest shut down.
                return Ok(None);
            }
            if let Some(reply) = reply?
            {
                self.lines.extend(self.guest.take_lines());
                if reply.first().is_some_and(|b| matches!(b, b'W' | b'X'))
                {
                    return Ok(None);
                }
                return Ok(Some(reply));
            }
            if self.ended()
            {
                return Ok(None);
            }
        }
    }

    /// Whether ktest has logged its summary, the serial lines read so far
    /// taken in.
    fn ended(&mut self) -> bool
    {
        self.lines.extend(self.guest.take_lines());
        self.lines
            .iter()
            .any(|l| END_MARKERS.iter().any(|m| l.contains(m)))
    }

    /// Single-step from `start` until the guest is back at `start`, recording
    /// each instruction and the counter each counter read returned.
    fn step_until(&mut self, start: u64, pc_reg: usize) -> Result<Vec<Step>>
    {
        let arch = self.arch;
        let mut steps = Vec::new();
        let mut pc = start;
        loop
        {
            ensure!(
                steps.len() < MAX_STEPS,
                "{MAX_STEPS} instructions stepped and ktest recorded no sample"
            );
            let cached = self.code.get(&pc).copied();
            let dest = if let Some(dest) = cached
            {
                dest
            }
            else
            {
                let bytes = self.stub()?.read_memory(pc, 4)?;
                let dest = counter_read(arch, &bytes);
                self.code.insert(pc, dest);
                dest
            };
            let reply = self.stub()?.request(b"s")?;
            let counter = match dest
            {
                Some(dest) => Some(self.read_counter(dest)?),
                None => None,
            };
            steps.push(Step { pc, counter });
            ensure!(
                is_trap(&reply),
                "stepping at {pc:#x} answered {:?}",
                String::from_utf8_lossy(&reply)
            );
            pc = self.stub()?.read_register(pc_reg)?;
            if pc == start
            {
                return Ok(steps);
            }
        }
    }

    /// The counter a counter read just left in `dest`.
    fn read_counter(&mut self, dest: CounterDest) -> Result<u64>
    {
        let stub = self.stub()?;
        match dest
        {
            CounterDest::EdxEax =>
            {
                let low = stub.read_register(X86_RAX)? & 0xffff_ffff;
                let high = stub.read_register(X86_RDX)? & 0xffff_ffff;
                Ok((high << 32) | low)
            }
            CounterDest::Register(rd) => stub.read_register(usize::from(rd)),
        }
    }

    /// The next benchmark result line the guest logged: its one-CPU
    /// measurement and p50.
    fn next_result(&mut self, timeout: Duration) -> Result<(Key, u64)>
    {
        let start = Instant::now();
        loop
        {
            while let Some(line) = self.lines.get(self.seen).cloned()
            {
                self.seen = self.seen.saturating_add(1);
                if let Some(found) = result_of(&line)?
                {
                    return Ok(found);
                }
                ensure!(
                    !(line.contains("ktest: bench ") && line.contains(" FAIL (")),
                    "a traced benchmark failed: {line}"
                );
            }
            ensure!(
                start.elapsed() < timeout,
                "no result line followed a traced iteration"
            );
            std::thread::sleep(Duration::from_millis(50));
            self.lines.extend(self.guest.take_lines());
        }
    }

    /// Save every serial line read as `boot.log`.
    fn save_log(&mut self) -> Result<()>
    {
        self.lines.extend(self.guest.take_lines());
        write_file(&self.log, &(self.lines.join("\n") + "\n"))
    }
}

/// The measurement and p50 of a benchmark result line, if `line` is one.
fn result_of(line: &str) -> Result<Option<(Key, u64)>>
{
    let parsed = match bench::parse_line(line)
    {
        Ok(Some(parsed)) => parsed,
        Ok(None) => return Ok(None),
        Err(e) => bail!("result line {line:?}: {e}"),
    };
    let key = Key {
        bench: format!("{}.{}", parsed.suite, parsed.name),
        variant: parsed
            .variant()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" "),
        cpus: parsed.cpus,
    };
    Ok(Some((key, parsed.summary.p50)))
}

/// Whether a stop reply is a trap: a step's end, or a watchpoint's hit.
fn is_trap(reply: &[u8]) -> bool
{
    reply.starts_with(b"T05") || reply.starts_with(b"S05")
}

/// GDB's x86-64 register numbers of RAX and RDX.
const X86_RAX: usize = 0;
const X86_RDX: usize = 3;

fn gdb_arch(arch: Arch) -> gdb_rsp::target::Arch
{
    match arch
    {
        Arch::X86_64 => gdb_rsp::target::Arch::X86_64,
        Arch::Riscv64 => gdb_rsp::target::Arch::Riscv64,
    }
}

/// The `kind` GDB sends with a breakpoint: the instruction's length, which
/// QEMU does not read.
const fn break_kind(arch: Arch) -> u32
{
    match arch
    {
        Arch::X86_64 => 1,
        Arch::Riscv64 => 4,
    }
}

/// The time left before `deadline`.
fn remaining(deadline: Instant) -> Duration
{
    deadline.saturating_duration_since(Instant::now())
}
