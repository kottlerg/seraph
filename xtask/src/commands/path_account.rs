// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/commands/path_account.rs

//! path-account command: boot a benchmark image under QEMU with the
//! path-account plugin, account for the instructions of each gated
//! measurement's windows, or write the account documents from the traced
//! configurations.
//!
//! The logic is in `crate::path_account` and `crate::path_record`; this
//! module builds the plugin, boots the guest, and reads and writes the files.
//! xtask/README.md (`cargo xtask path-account`) states the method and its
//! checks.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::ops::Range;
use std::path::{Path as FsPath, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use bench::Summary;
use object::{Object as _, ObjectSection as _, ObjectSymbol as _, SectionKind, SymbolKind};

use crate::arch::Arch;
use crate::benchmark::{BenchMode, Key, band, gates, gather};
use crate::bundle::Harness;
use crate::cli::{PathAccountArgs, PathAccountCommand, PathAccountTraceArgs};
use crate::commands::bench_check::{read_runs, write_file};
use crate::commands::ktest_timing::first_line;
use crate::context::Context;
use crate::error::{Context as _, Result, bail, ensure};
use crate::guest::Guest;
use crate::path_account::{
    Configuration, KERNEL, OTHER, Path, Place, Placement, Tally, attributed, placements,
    render_block, replace_block,
};
use crate::path_record::{Record, Row, Window, rows, windows};
use crate::qemu::{
    Execution, Firmware, GdbMode, Iommu, QemuDisplay, QemuLaunchSpec, RiscvMmu, RiscvZkr,
    X86Paging, X86ShadowStack, build_qemu_argv_for, validate_sysroot_for_launch,
};
use crate::qemu_gdb::function_path;
use crate::symbolize::store::Store;
use crate::symbolize::{Resolution, Symbolizer, text_span};
use crate::util::{CI_CARGO_ENV, require_tool, run_cmd, step};

/// The plugin's package, and the shared object a release build of it leaves
/// under the target directory.
const PLUGIN_PACKAGE: &str = "seraph-path-account-plugin";
const PLUGIN_OBJECT: &str = "release/libseraph_path_account_plugin.so";

/// What each harness's boot is accounted as: its benchmark programs' result
/// files and document, the name of its init image, the display the
/// benchmark cell boots it with, and the lines that end its run.
struct Account
{
    harness: Harness,
    /// The result files' prefix.
    name: &'static str,
    /// The document whose generated block the result files make.
    doc: &'static str,
    /// The init image's name: what the kernel's `init: PIE bias=` places.
    init: &'static str,
    display: QemuDisplay,
    ends: [&'static str; 2],
}

const ACCOUNTS: [Account; 2] = [
    Account {
        harness: Harness::Ktest,
        name: "ktest",
        doc: "core/kernel/docs/hot-path-account.md",
        init: "ktest",
        display: QemuDisplay::Headless,
        ends: ["[ktest] ALL TESTS PASSED", "[ktest] SOME TESTS FAILED"],
    },
    Account {
        harness: Harness::Init,
        name: "userspace",
        doc: "core/kernel/docs/hot-path-account-userspace.md",
        init: "init",
        display: QemuDisplay::Framebuffer,
        ends: ["[ubench] ALL TESTS PASSED", "[ubench] SOME TESTS FAILED"],
    },
];

/// The svcmgr recipe that runs ubench, which the userspace account's image
/// boots staged among the services (programs/ubench/README.md).
const UBENCH_RECIPE: &str = "config/svcmgr/services/ubench.svc";

/// Entry point for `cargo xtask path-account`.
pub fn run(ctx: &Context, args: &PathAccountArgs) -> Result<()>
{
    match &args.command
    {
        PathAccountCommand::Trace(trace_args) => trace(ctx, trace_args),
        PathAccountCommand::Write => write_docs(ctx),
    }
}

/// The directory of every configuration's result and traces.
fn results_root(ctx: &Context) -> PathBuf
{
    ctx.root.join("target/xtask/path-account")
}

/// `path-account write`: each document's generated block from its result
/// files.
fn write_docs(ctx: &Context) -> Result<()>
{
    let mut written = 0usize;
    for account in &ACCOUNTS
    {
        let mut configs = Vec::new();
        for (arch, profile) in [
            ("x86_64", "dev"),
            ("x86_64", "release"),
            ("riscv64", "dev"),
            ("riscv64", "release"),
        ]
        {
            let file = results_root(ctx).join(format!("{}-{arch}-{profile}.tsv", account.name));
            if !file.exists()
            {
                continue;
            }
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            configs
                .push(Configuration::parse(&text).with_context(|| format!("{}", file.display()))?);
        }
        if configs.is_empty()
        {
            step(&format!("no {} configuration traced", account.name));
            continue;
        }
        let doc = ctx.root.join(account.doc);
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
        written = written.saturating_add(1);
    }
    ensure!(written > 0, "no configuration has been traced");
    Ok(())
}

/// One ELF a boot placed: its symbolizer, its text span at link addresses,
/// and its text symbols by address, for code no DWARF covers (assembly entry
/// stubs).
struct Elf<'a>
{
    path: PathBuf,
    symbolizer: Symbolizer<'a>,
    span: (u64, u64),
    symbols: Vec<(u64, String)>,
}

/// One placed image: its name, its offset, and its ELF.
struct Mapped
{
    name: String,
    bias: u64,
    /// Its text at runtime addresses.
    text: Range<u64>,
    elf: usize,
}

/// What the account resolves addresses against: every image the boot placed.
/// No two images' texts overlap at runtime (`Resolver::new` checks), so an
/// address names its image without its address space.
struct Resolver<'a>
{
    elves: Vec<Elf<'a>>,
    mapped: Vec<Mapped>,
    cache: HashMap<u64, (Place, Vec<String>)>,
}

impl<'a> Resolver<'a>
{
    /// `placed` with the index of its ELF among `files` (path and data).
    fn new(files: &'a [(PathBuf, Vec<u8>)], placed: &[(Placement, usize)]) -> Result<Self>
    {
        let mut elves = Vec::with_capacity(files.len());
        for (path, data) in files
        {
            elves.push(Elf {
                path: path.clone(),
                symbolizer: Symbolizer::new(data)
                    .with_context(|| format!("reading the DWARF of {}", path.display()))?,
                span: text_span(data).with_context(|| format!("{} has no text", path.display()))?,
                symbols: text_symbols(data).with_context(|| format!("{}", path.display()))?,
            });
        }
        let mut mapped = Vec::with_capacity(placed.len());
        for (placement, elf) in placed
        {
            let (start, end) = elves.get(*elf).context("an image's ELF is missing")?.span;
            let text = start
                .checked_add(placement.bias)
                .zip(end.checked_add(placement.bias))
                .map(|(s, e)| s..e)
                .with_context(|| format!("{} placed past the address space", placement.name))?;
            mapped.push(Mapped {
                name: placement.name.clone(),
                bias: placement.bias,
                text,
                elf: *elf,
            });
        }
        let mut by_start: Vec<&Mapped> = mapped.iter().collect();
        by_start.sort_by_key(|m| m.text.start);
        for pair in by_start.windows(2)
        {
            if let [a, b] = pair
            {
                ensure!(
                    a.text.end <= b.text.start,
                    "{} ({:#x}..{:#x}) and {} ({:#x}..{:#x}) overlap at runtime: an address \
                     would not name its image; boot again, at other load addresses",
                    a.name,
                    a.text.start,
                    a.text.end,
                    b.name,
                    b.text.start,
                    b.text.end
                );
            }
        }
        Ok(Self {
            elves,
            mapped,
            cache: HashMap::new(),
        })
    }

    /// The runtime text of the image named `name`, placed once.
    fn text_of(&self, name: &str) -> Result<Range<u64>>
    {
        let mut found = self.mapped.iter().filter(|m| m.name == name);
        let (Some(one), None) = (found.next(), found.next())
        else
        {
            bail!("the boot placed no image, or several, named {name}");
        };
        Ok(one.text.clone())
    }

    /// The place of the instruction at runtime address `pc`, and its frames
    /// from the innermost out.
    fn resolve(&mut self, pc: u64) -> Result<(Place, Vec<String>)>
    {
        if let Some(hit) = self.cache.get(&pc)
        {
            return Ok(hit.clone());
        }
        let Some(mapped) = self.mapped.iter().find(|m| m.text.contains(&pc))
        else
        {
            let page = format!("<page {:#x}>", pc & !0xfff);
            let hit = (
                Place {
                    image: OTHER.to_owned(),
                    function: page.clone(),
                },
                vec![page],
            );
            self.cache.insert(pc, hit.clone());
            return Ok(hit);
        };
        let elf = self
            .elves
            .get(mapped.elf)
            .context("an image's ELF is missing")?;
        ensure!(
            elf.symbolizer.has_debug_info(),
            "{} carries no DWARF: build with `--limited-debug all`",
            elf.path.display()
        );
        let vaddr = pc.wrapping_sub(mapped.bias);
        let frames: Vec<String> = match elf.symbolizer.resolve(vaddr)?
        {
            Resolution::DebugInfo(frames) => frames
                .iter()
                .map(|f| {
                    f.function
                        .as_deref()
                        .map_or_else(|| "<unnamed>".to_owned(), |n| function_path(n).to_owned())
                })
                .collect(),
            Resolution::SymbolTable { name, .. } => vec![function_path(&name).to_owned()],
            Resolution::Unresolved => vec![nearest_symbol(&elf.symbols, vaddr)],
        };
        let hit = (
            Place {
                image: mapped.name.clone(),
                function: attributed(&frames).to_owned(),
            },
            frames,
        );
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

/// The file in the sysroot of the image a boot placed as `name`: the
/// kernel's installed image, which keeps its symbols; a process's by the path
/// procmgr was given (`/services/drivers/virtio-blk`), the filesystem
/// service for a `fatfs:<mount>` instance, or else the file of that name
/// under `services/`, `tests/` or `programs/`.
fn image_file(ctx: &Context, name: &str) -> Result<PathBuf>
{
    if name == KERNEL
    {
        return Ok(ctx.sysroot_efi_seraph().join("kernel"));
    }
    if let Some(path) = name.strip_prefix('/')
    {
        return Ok(ctx.sysroot.join(path));
    }
    if name.starts_with("fatfs:")
    {
        return Ok(ctx.sysroot.join("services/fs/fatfs"));
    }
    let mut dirs: Vec<PathBuf> = ["services", "tests", "programs"]
        .iter()
        .map(|d| ctx.sysroot.join(d))
        .collect();
    while let Some(dir) = dirs.pop()
    {
        let Ok(entries) = std::fs::read_dir(&dir)
        else
        {
            continue;
        };
        for entry in entries.flatten()
        {
            let path = entry.path();
            if path.is_dir()
            {
                dirs.push(path);
            }
            else if entry.file_name() == name
            {
                return Ok(path);
            }
        }
    }
    bail!("no image named {name} in {}", ctx.sysroot.display())
}

/// The ELF of each image a boot placed, each file read once (the kernel's as
/// installed, a process's from the symbols store), and each placement with
/// the index of its file.
struct Images
{
    files: Vec<(PathBuf, Vec<u8>)>,
    placed: Vec<(Placement, usize)>,
}

impl Images
{
    fn read(ctx: &Context, placed: &[Placement]) -> Result<Self>
    {
        let store = Store::at(ctx.symbols_dir());
        let mut files: Vec<(PathBuf, Vec<u8>)> = Vec::new();
        let mut indexed = Vec::with_capacity(placed.len());
        for placement in placed
        {
            let image = image_file(ctx, &placement.name)?;
            let path = if placement.name == KERNEL
            {
                image
            }
            else
            {
                store.symbols_path(&image)?
            };
            let index = if let Some(at) = files.iter().position(|(p, _)| *p == path)
            {
                at
            }
            else
            {
                let data =
                    std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
                files.push((path, data));
                files.len().saturating_sub(1)
            };
            indexed.push((placement.clone(), index));
        }
        Ok(Self {
            files,
            placed: indexed,
        })
    }
}

/// `path-account trace`.
fn trace(ctx: &Context, args: &PathAccountTraceArgs) -> Result<()>
{
    let arch = args.arch;
    let harness = crate::sysroot::recorded_harness(ctx)?;
    let account = ACCOUNTS
        .iter()
        .find(|a| a.harness == harness)
        .context("no account of the disk image's harness")?;
    let profile = if args.release { "release" } else { "dev" };
    let references = references(args, arch)?;
    let out_dir = results_root(ctx).join(format!("{}-{arch}-{profile}", account.name));
    let record_path = out_dir.join("record.txt");
    let log_path = out_dir.join("boot.log");
    if !args.reuse
    {
        validate_sysroot_for_launch(ctx, arch)?;
        if harness == Harness::Init
        {
            ensure!(
                ctx.sysroot.join(UBENCH_RECIPE).is_file(),
                "the init image runs no benchmark: stage ubench (`cp \
                 sysroot/config/svcmgr/tests/ubench.svc sysroot/{UBENCH_RECIPE}`, then \
                 `cargo xtask mkdisk --repack-only`)"
            );
        }
        let plugin = build_plugin(ctx)?;
        let _host = crate::host_lock::admit_boot(ctx, &args.host, 1, 1)?;
        std::fs::create_dir_all(&out_dir)
            .with_context(|| format!("creating {}", out_dir.display()))?;
        if record_path.exists()
        {
            std::fs::remove_file(&record_path)
                .with_context(|| format!("removing {}", record_path.display()))?;
        }
        boot(
            ctx,
            arch,
            account,
            &plugin,
            &record_path,
            &log_path,
            args.timeout,
        )?;
    }
    let lines: Vec<String> = std::fs::read_to_string(&log_path)
        .with_context(|| format!("reading {}", log_path.display()))?
        .lines()
        .map(str::to_owned)
        .collect();
    let text = std::fs::read_to_string(&record_path)
        .with_context(|| format!("reading {}", record_path.display()))?;
    let record = Record::parse(&text).with_context(|| format!("{}", record_path.display()))?;
    ensure!(
        record.arch.name() == arch.to_string(),
        "the record is of {}, not {arch}",
        record.arch.name()
    );
    let images = Images::read(ctx, &placements(&lines, account.init))?;
    let mut resolver = Resolver::new(&images.files, &images.placed)?;
    let paths = account_boot(&record, &lines, &references.0, &mut resolver, &out_dir)?;
    let config = Configuration {
        arch: arch.to_string(),
        profile: profile.to_owned(),
        head: head(ctx),
        date: today(),
        qemu: first_line(arch.qemu_binary(), &["--version"]),
        reference: references.1,
        paths,
    };
    let result = results_root(ctx).join(format!("{}-{arch}-{profile}.tsv", account.name));
    write_file(&result, &config.render())?;
    step(&format!(
        "{} paths accounted; result {}, traces under {}",
        config.paths.len(),
        result.display(),
        out_dir.display()
    ));
    Ok(())
}

/// Account a traced boot: each program's windows divided among its result
/// lines, and each gated line's path, checked against the counts.
///
/// # Errors
/// A program's reads that do not pair into its result lines' samples, or a
/// check of a gated line that failed (every failure is listed).
fn account_boot(
    record: &Record,
    lines: &[String],
    references: &BTreeMap<Key, u64>,
    resolver: &mut Resolver<'_>,
    out_dir: &FsPath,
) -> Result<Vec<Path>>
{
    let results = result_lines(lines)?;
    let mut paths = Vec::new();
    let mut failures = Vec::new();
    let mut programs: Vec<&str> = Vec::new();
    for (key, _) in &results
    {
        let suite = suite_of(key);
        if !programs.contains(&suite)
        {
            programs.push(suite);
        }
    }
    for program in programs
    {
        let text = resolver.text_of(program)?;
        let ws = windows(record, |pc| text.contains(&pc))?;
        let lines_of: Vec<(Key, Summary)> = results
            .iter()
            .filter(|(key, _)| suite_of(key) == program)
            .cloned()
            .collect();
        let rows = rows(&lines_of, &ws).with_context(|| format!("{program}'s windows"))?;
        for row in rows.iter().filter(|r| gates(BenchMode::Icount, &r.key))
        {
            let reference = references.get(&row.key).copied();
            let taken = ws.get(row.windows.clone()).context("a row's windows")?;
            let path = account_row(
                record,
                taken,
                row,
                reference,
                resolver,
                out_dir,
                &mut failures,
            )?;
            paths.push(path);
        }
    }
    for key in references
        .keys()
        .filter(|k| !paths.iter().any(|p: &Path| p.key == k.to_string()))
    {
        failures.push(format!("{key}: has a reference count and was not traced"));
    }
    ensure!(
        failures.is_empty(),
        "the account does not match the counts:\n  {}",
        failures.join("\n  ")
    );
    Ok(paths)
}

/// `<suite>` of a measurement's `<suite>.<name>`: the program that logged it.
fn suite_of(key: &Key) -> &str
{
    key.bench
        .split_once('.')
        .map_or(key.bench.as_str(), |(suite, _)| suite)
}

/// Check one gated row's windows against their samples, its p50 and its
/// reference count, and tally the window that ran the p50 by function: its
/// path. Each check that fails is added to `failures`.
fn account_row(
    record: &Record,
    taken: &[Window],
    row: &Row,
    reference: Option<u64>,
    resolver: &mut Resolver<'_>,
    out_dir: &FsPath,
    failures: &mut Vec<String>,
) -> Result<Path>
{
    let key = &row.key;
    let p50 = row.summary.p50;
    let mut chosen: Option<(usize, BTreeMap<u64, u64>)> = None;
    let mut unequal: Vec<String> = Vec::new();
    for (i, w) in taken.iter().enumerate()
    {
        let retired = record
            .retired(w.open, w.close)
            .with_context(|| format!("{key}: window {i}"))?;
        let total = retired.values().copied().fold(0, u64::saturating_add);
        if total != w.sample
        {
            unequal.push(format!("window {i}: sample {}, retired {total}", w.sample));
        }
        else if chosen.is_none() && w.sample == p50
        {
            chosen = Some((i, retired));
        }
    }
    if let Some(first) = unequal.first()
    {
        failures.push(format!(
            "{key}: {} of {} windows retired other than their sample ({first})",
            unequal.len(),
            taken.len()
        ));
    }
    match reference
    {
        Some(r) if p50.abs_diff(r) <= band(BenchMode::Icount, r, None).unwrap_or(0) =>
        {}
        Some(r) => failures.push(format!(
            "{key}: the traced p50 {p50} is outside the gate's band of the reference {r}"
        )),
        None => failures.push(format!("{key}: traced {p50}, no reference count")),
    }
    let (iteration, retired) = chosen.unwrap_or_else(|| {
        failures.push(format!(
            "{key}: no window that retired its sample ran the p50 {p50}"
        ));
        (0, BTreeMap::new())
    });
    write_trace(out_dir, key, &retired, resolver)?;
    let mut tally_err = None;
    let tally = Tally::of(retired, |pc| match resolver.resolve(pc)
    {
        Ok((place, _)) => place,
        Err(e) =>
        {
            tally_err.get_or_insert(e);
            Place {
                image: OTHER.to_owned(),
                function: "<error>".to_owned(),
            }
        }
    });
    if let Some(e) = tally_err
    {
        return Err(e.context(format!("attributing {key}")));
    }
    step(&format!(
        "{key}: {} instructions ({} kernel)",
        tally.total,
        tally.of_image(KERNEL)
    ));
    Ok(Path {
        key: key.to_string(),
        p50,
        reference: reference.unwrap_or(0),
        iteration: u32::try_from(iteration)?,
        tally,
    })
}

/// The reference count of each gated measurement: the lowest p50 of the
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
        .filter(|(key, _)| gates(BenchMode::Icount, key))
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

/// Build the plugin for the host; the path of its shared object.
fn build_plugin(ctx: &Context) -> Result<PathBuf>
{
    step("Building the path-account plugin");
    run_cmd(
        Command::new("cargo")
            .current_dir(&ctx.root)
            .envs(CI_CARGO_ENV)
            .args(["build", "--release", "--lib", "-p", PLUGIN_PACKAGE]),
    )?;
    let object = ctx.target_dir.join(PLUGIN_OBJECT);
    ensure!(
        object.is_file(),
        "the plugin build left no {}",
        object.display()
    );
    Ok(object)
}

/// A booted guest with the plugin recording, and the serial lines it logged.
struct Boot
{
    guest: Guest,
    /// Every serial line read, in order.
    lines: Vec<String>,
}

impl Boot
{
    /// Boot the sysroot's image at one CPU under icount, as the benchmark
    /// cell boots it, with the plugin recording into `record`.
    fn launch(
        ctx: &Context,
        arch: Arch,
        account: &Account,
        plugin: &FsPath,
        record: &FsPath,
    ) -> Result<Self>
    {
        let firmware = Firmware::prepare(ctx, arch)?;
        let vars = firmware.launch_vars()?;
        let disk_path = ctx.disk_image();
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
            display: account.display,
            gdb: GdbMode::Off,
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
        let mut qemu_args = build_qemu_argv_for(&spec, Execution::Icount)?;
        qemu_args.push("-plugin".to_owned());
        qemu_args.push(format!("{},out={}", plugin.display(), record.display()));
        let qemu = require_tool(arch.qemu_binary())?;
        step(&format!(
            "Launching QEMU for the path account ({arch}, {}, 1 CPU, icount, record {})",
            account.name,
            record.display()
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
            guest,
            lines: Vec::new(),
        })
    }

    /// Read serial lines until one holds a marker of `ends`, waiting at most
    /// `timeout` seconds in all.
    fn run_until(&mut self, ends: &[&str], timeout: u64) -> Result<()>
    {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(timeout))
            .context("--timeout is too large")?;
        loop
        {
            let left = deadline.saturating_duration_since(Instant::now());
            let Some(line) = self.guest.line_within(left)?
            else
            {
                bail!("the boot outlived --timeout");
            };
            let end = ends.iter().any(|m| line.contains(m));
            self.lines.push(line);
            if end
            {
                return Ok(());
            }
        }
    }
}

/// Boot the sysroot's image with the plugin recording into `record` until
/// a line of `account.ends`, and save every serial line read as `log`,
/// whatever the boot's outcome.
fn boot(
    ctx: &Context,
    arch: Arch,
    account: &Account,
    plugin: &FsPath,
    record: &FsPath,
    log: &FsPath,
    timeout: u64,
) -> Result<()>
{
    let mut boot = Boot::launch(ctx, arch, account, plugin, record)?;
    let outcome = boot.run_until(&account.ends, timeout);
    let Boot { guest, lines } = boot;
    guest.shutdown();
    write_file(log, &(lines.join("\n") + "\n"))?;
    outcome
}

/// Every benchmark result line of a boot, as its measurement and summary.
///
/// # Errors
/// A malformed result line, or a benchmark that failed.
fn result_lines(lines: &[String]) -> Result<Vec<(Key, Summary)>>
{
    let mut out = Vec::new();
    for line in lines
    {
        ensure!(
            !(line.contains(" bench ") && line.contains(" FAIL (")),
            "a traced benchmark failed: {line}"
        );
        if let Some(found) = result_of(line)?
        {
            out.push(found);
        }
    }
    Ok(out)
}

/// The measurement and summary of a benchmark result line, if `line` is one.
fn result_of(line: &str) -> Result<Option<(Key, Summary)>>
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
    Ok(Some((key, parsed.summary)))
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

/// Write the window of `key` as one line per address: the address, the
/// instructions retired there, its image, and its frames from the outermost
/// in.
fn write_trace(
    dir: &FsPath,
    key: &Key,
    retired: &BTreeMap<u64, u64>,
    resolver: &mut Resolver<'_>,
) -> Result<()>
{
    let mut out = String::new();
    for (&pc, &count) in retired
    {
        let (place, frames) = resolver.resolve(pc)?;
        let chain: Vec<&str> = frames.iter().rev().map(String::as_str).collect();
        let _ = writeln!(
            out,
            "{pc:#018x} {count} {} {}",
            place.image,
            chain.join(" > ")
        );
    }
    let name = key.to_string().replace([' ', '='], "_");
    write_file(&dir.join(format!("{name}.trace")), &out)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_result_line_names_its_measurement_and_summary()
    {
        let line = "[0.316180] bench ktest.aspace_harvest_all_accessed pages=32 arch=x86_64 cpus=1 \
                    unit=cycles n=4096 min=4786 p50=4790 p90=4790 p99=4790 max=5672";
        let (key, summary) = result_of(line).unwrap().unwrap();
        assert_eq!(
            key.to_string(),
            "ktest.aspace_harvest_all_accessed pages=32 cpus=1"
        );
        assert_eq!(suite_of(&key), "ktest");
        assert_eq!(summary.p50, 4790);
        assert_eq!(summary.n, 4096);
        assert!(
            result_of("[0.416305] [ktest] ALL TESTS PASSED")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_failed_benchmark_fails_the_trace()
    {
        let lines = ["[2.0] [ubench] bench fault_fill FAIL (path=grant: map: error -3)".to_owned()];
        result_lines(&lines).unwrap_err();
    }

    #[test]
    fn the_nearest_symbol_is_at_or_before_the_address()
    {
        let symbols = vec![(0x100, "a".to_owned()), (0x200, "b".to_owned())];
        assert_eq!(nearest_symbol(&symbols, 0x100), "a");
        assert_eq!(nearest_symbol(&symbols, 0x1ff), "a");
        assert_eq!(nearest_symbol(&symbols, 0x250), "b");
        assert_eq!(nearest_symbol(&symbols, 0x50), "<unresolved>");
    }
}
