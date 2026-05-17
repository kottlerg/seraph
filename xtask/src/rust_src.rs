// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! rust_src.rs
//!
//! Assembles an in-project sysroot under `target/seraph-toolchain/` so
//! `-Z build-std` can compile `std` with our `std::sys::seraph` overlay,
//! without touching the real rustup toolchain or rustup metadata.
//!
//! # Mechanism
//!
//! Cargo has no public way to redirect `-Z build-std` at an alternate
//! rust-src path. But `rustc --sysroot=<path>` does override the whole
//! sysroot, and build-std reads `<sysroot>/lib/rustlib/src/rust/library/`.
//! We therefore:
//!
//!   1. Materialise a mirror of the real toolchain at
//!      `target/seraph-toolchain/`, using symlinks for everything except
//!      the subtree we need to mutate (`lib/rustlib/src/rust/library/std/
//!      src/sys/`), which is a physical copy.
//!   2. Apply the seraph overlay to the physical-copy subtree — no
//!      upstream rust-src is touched.
//!   3. Install the `seraph-wrapper-shim` native binary at
//!      `target/seraph-toolchain/bin/rustc` (and the same binary again
//!      as `bin/ws-clippy`). The shim dispatches on argv[0] basename,
//!      reads its config from `SERAPH_SHIM_*` env vars set by the
//!      caller, and execs the real rustc / clippy-driver with the
//!      right flags so every rustc invocation (including `rustc
//!      --print sysroot` which cargo uses internally) reports and
//!      uses our sysroot. The shim replaces the previous `#!/bin/sh`
//!      wrappers — a native binary works on every host without
//!      shebang interpretation, POSIX shell, or chmod.
//!   4. Callers route `cargo build` / `cargo clippy` through the
//!      mirror by calling `SeraphToolchain::apply_env(&mut cmd)`,
//!      which sets `RUSTC`, `RUSTC_WORKSPACE_WRAPPER`, the three
//!      `SERAPH_SHIM_*` config vars, and `RUSTC_BOOTSTRAP=1` in one
//!      go. No rustup-level state is modified;
//!      `target/seraph-toolchain/` is a pure build artifact under
//!      `target/`.
//!
//! # Invariants
//!
//!   * Idempotent — re-running a build is a no-op once the mirror exists
//!     and overlays are applied. Toolchain-version drift invalidates the
//!     mirror (a stamp file records the rustc version).
//!   * Self-contained — everything lives under `target/`. `cargo xtask
//!     clean` keeps the mirror; `cargo xtask clean --all` wipes it along
//!     with the rest of `target/` (acceptable — next build rebuilds it).
//!   * Minimum-surface overlay — anchor-match small inserts; each site
//!     carries a `// seraph-overlay:` marker for idempotency.
//!
//! # Why hard-link-mirror the library/ tree
//!
//! Cargo canonicalises source paths before invoking rustc (deterministic
//! caching). If `library/core/src/lib.rs` in the mirror is a symlink to
//! the real toolchain file, cargo resolves it back to the real path and
//! passes that to rustc — our overlay is bypassed. Hard links have the
//! same inode but distinct path entries: `realpath(3)` stops at the
//! mirror path. Both filesystems must be identical (verified at mirror
//! assembly time); our overlays apply to files by unlink-then-write so
//! the shared inode with the real toolchain is never mutated.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::context::Context as BuildContext;
use crate::fs_compat::link_or_copy;
use crate::util::{run_cmd, step};

/// Substring placed in every patched source file for idempotency
/// detection. Single marker per file suffices; atomic-per-file edits.
const MARKER: &str = "// seraph-overlay:";

/// Name of the toolchain mirror directory under `target/`.
const MIRROR_DIR: &str = "seraph-toolchain";

/// Rustc-version stamp: invalidates the mirror if the underlying
/// toolchain changes (`rustc --version --verbose` output).
const VERSION_STAMP: &str = ".seraph-toolchain-stamp";

// ── Public entry point ────────────────────────────────────────────────────────

/// Paths and shim config callers route their cargo invocations
/// through for StdUser builds.
///
/// `rustc` and `ws_clippy` point at the installed shim under
/// `target/seraph-toolchain/bin/` (the same binary, installed under
/// two names, dispatched by argv[0] basename). `real_rustc`,
/// `real_clippy`, and `mirror_sysroot` are the absolute paths the
/// shim needs to do its job — exposed here so `apply_env` can wire
/// them into cargo's environment.
pub struct SeraphToolchain
{
    pub rustc: PathBuf,
    pub ws_clippy: PathBuf,
    real_rustc: PathBuf,
    real_clippy: PathBuf,
    mirror_sysroot: PathBuf,
}

impl SeraphToolchain
{
    /// Set every env var the shim and cargo need to route a StdUser
    /// build through the seraph toolchain mirror: `RUSTC` and
    /// `RUSTC_WORKSPACE_WRAPPER` (mirror entry points), the three
    /// `SERAPH_SHIM_*` config vars (so the shim knows what to exec),
    /// and `RUSTC_BOOTSTRAP=1` (so the StdUser builds can use
    /// `restricted_std` and `rustc_private`).
    pub fn apply_env(&self, cmd: &mut Command)
    {
        cmd.env("RUSTC", &self.rustc);
        cmd.env("RUSTC_WORKSPACE_WRAPPER", &self.ws_clippy);
        cmd.env("SERAPH_SHIM_REAL_RUSTC", &self.real_rustc);
        cmd.env("SERAPH_SHIM_REAL_CLIPPY", &self.real_clippy);
        cmd.env("SERAPH_SHIM_MIRROR_SYSROOT", &self.mirror_sysroot);
        cmd.env("RUSTC_BOOTSTRAP", "1");
    }
}

/// Ensure the seraph sysroot mirror exists under `target/` with
/// overlays applied and the wrapper shim installed, and return the
/// `SeraphToolchain` callers route their cargo invocations through.
pub fn ensure_seraph_toolchain(ctx: &BuildContext) -> Result<SeraphToolchain>
{
    let real = probe_real_sysroot().context("locating real rustc sysroot")?;
    let rust_src = real.join("lib/rustlib/src/rust");
    if !rust_src.exists()
    {
        bail!(
            "rust-src component not installed at {}; add \"rust-src\" to \
             components in rust-toolchain.toml or run \
             `rustup component add rust-src`",
            rust_src.display()
        );
    }

    let overlay_root = ctx.root.join("runtime").join("ruststd").join("src");
    if !overlay_root.exists()
    {
        bail!(
            "ruststd overlay directory not found at {}",
            overlay_root.display()
        );
    }

    let mirror = ctx.target_dir.join(MIRROR_DIR);
    ensure_mirror(&real, &mirror, &overlay_root, &ctx.root)
        .context("assembling seraph-toolchain mirror")?;
    apply_all_overlays(&mirror, &overlay_root).context("applying seraph overlays")?;
    let real_clippy = real.join("bin/clippy-driver");
    if !real_clippy.exists()
    {
        bail!(
            "clippy-driver not found at {}; add \"clippy\" to components \
             in rust-toolchain.toml or run `rustup component add clippy`",
            real_clippy.display()
        );
    }
    install_wrappers(ctx, &real, &mirror).context("installing wrapper shim")?;

    let real_rustc = real
        .join("bin/rustc")
        .canonicalize()
        .context("canonicalising real rustc")?;
    let real_clippy = real_clippy
        .canonicalize()
        .context("canonicalising real clippy-driver")?;
    let mirror_sysroot = mirror
        .canonicalize()
        .context("canonicalising seraph mirror")?;

    Ok(SeraphToolchain {
        rustc: mirror.join("bin/rustc"),
        ws_clippy: mirror.join("bin/ws-clippy"),
        real_rustc,
        real_clippy,
        mirror_sysroot,
    })
}

// ── Mirror assembly ───────────────────────────────────────────────────────────

/// Materialise `mirror` as a selective copy of `real`: everything is a
/// symlink to `real` except the subtree `lib/rustlib/src/rust/library/
/// std/src/sys/` which is a physical copy so it can carry overlays.
///
/// Idempotent — a version-stamp file records the underlying rustc
/// identity plus the overlay content footprint; if it matches, the
/// mirror is left alone.
fn ensure_mirror(real: &Path, mirror: &Path, overlay_root: &Path, project_root: &Path)
-> Result<()>
{
    let want_stamp = compute_stamp(real, overlay_root, project_root)?;
    let stamp_path = mirror.join(VERSION_STAMP);
    if mirror.exists()
    {
        if let Ok(existing) = fs::read_to_string(&stamp_path)
            && existing.trim() == want_stamp
        {
            return Ok(()); // mirror up to date
        }
        // Stale mirror — scrap and rebuild. Safer than trying to patch.
        fs::remove_dir_all(mirror)
            .with_context(|| format!("removing stale mirror {}", mirror.display()))?;
    }

    step(&format!(
        "seraph-toolchain: assembling mirror at {}",
        mirror.display()
    ));
    fs::create_dir_all(mirror).with_context(|| format!("creating {}", mirror.display()))?;

    // Top-level + descent: symlink every sibling at each level, except
    // the path we're descending. We shadow down to
    // `lib/rustlib/src/rust/library/`.
    symlink_siblings_except(real, mirror, "lib")?;
    let lib_real = real.join("lib");
    let lib_mirror = mirror.join("lib");
    fs::create_dir_all(&lib_mirror)
        .with_context(|| format!("creating {}", lib_mirror.display()))?;
    symlink_siblings_except(&lib_real, &lib_mirror, "rustlib")?;

    let rustlib_real = lib_real.join("rustlib");
    let rustlib_mirror = lib_mirror.join("rustlib");
    fs::create_dir_all(&rustlib_mirror)
        .with_context(|| format!("creating {}", rustlib_mirror.display()))?;
    symlink_siblings_except(&rustlib_real, &rustlib_mirror, "src")?;

    let src_real = rustlib_real.join("src");
    let src_mirror = rustlib_mirror.join("src");
    fs::create_dir_all(&src_mirror)
        .with_context(|| format!("creating {}", src_mirror.display()))?;
    symlink_siblings_except(&src_real, &src_mirror, "rust")?;

    let rust_real = src_real.join("rust");
    let rust_mirror = src_mirror.join("rust");
    fs::create_dir_all(&rust_mirror)
        .with_context(|| format!("creating {}", rust_mirror.display()))?;
    symlink_siblings_except(&rust_real, &rust_mirror, "library")?;

    // Hard-link-mirror the library/ tree. Cargo canonicalises source
    // paths, so a symlinked `library/core/src/lib.rs` resolves back to
    // the real toolchain and bypasses the overlay. Hard links share the
    // inode but keep the mirror path as realpath's fixed point.
    let library_real = rust_real.join("library");
    let library_mirror = rust_mirror.join("library");
    hard_link_tree(&library_real, &library_mirror).context("hard-linking library/ subtree")?;

    fs::write(&stamp_path, format!("{want_stamp}\n"))
        .with_context(|| format!("writing {}", stamp_path.display()))?;
    Ok(())
}

/// For every direct-child entry in `real` whose name differs from
/// `skip`, materialise it in `mirror` via the cheapest mechanism the
/// host supports (symlink on Unix/macOS, falls back to hard-link or
/// copy on Windows via `fs_compat::link_or_copy`). Idempotent:
/// entries already present are left alone.
fn symlink_siblings_except(real: &Path, mirror: &Path, skip: &str) -> Result<()>
{
    for entry in fs::read_dir(real).with_context(|| format!("reading {}", real.display()))?
    {
        let entry = entry?;
        let entry_name = entry.file_name();
        if entry_name == skip
        {
            continue;
        }
        let dst = mirror.join(&entry_name);
        if dst.symlink_metadata().is_ok()
        {
            continue;
        }
        link_or_copy(&entry.path(), &dst).with_context(|| {
            format!(
                "materialising {} -> {}",
                dst.display(),
                entry.path().display()
            )
        })?;
    }
    Ok(())
}

/// Recursively mirror `src` -> `dst` using mkdir for directories and
/// hard links for regular files. Symlinks encountered within `src` are
/// re-created as symlinks in the mirror with the same target.
fn hard_link_tree(src: &Path, dst: &Path) -> Result<()>
{
    fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("reading {}", src.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let dst_path = dst.join(&name);
        let ft = entry.file_type()?;
        if ft.is_dir()
        {
            hard_link_tree(&path, &dst_path)?;
        }
        else if ft.is_symlink()
        {
            // Symlinks inside library/ are vanishingly rare in the
            // shipped rust-src; if one appears, materialise it via
            // `link_or_copy` (symlink on Unix, copy on Windows). The
            // important invariant is that the file resolves to the
            // same bytes — relative-target preservation isn't
            // necessary for cargo's purposes.
            if dst_path.symlink_metadata().is_err()
            {
                link_or_copy(&path, &dst_path).with_context(|| {
                    format!(
                        "materialising library/ symlink {} -> {}",
                        dst_path.display(),
                        path.display(),
                    )
                })?;
            }
        }
        else
        {
            // Hard link the file. If a destination already exists,
            // see whether we can detect (on Unix) that it already
            // shares our inode; otherwise replace to refresh. Cargo
            // canonicalises source paths and bypasses overlays
            // through symlinks, so files inside library/ MUST be
            // hard-linked or physically copied — never symlinked.
            if let Ok(_dst_meta) = dst_path.symlink_metadata()
            {
                if same_inode(&path, &dst_path)
                {
                    continue;
                }
                fs::remove_file(&dst_path)
                    .with_context(|| format!("removing stale {}", dst_path.display()))?;
            }
            // Hard link first (cheap, no copy). On Windows we may
            // fall back to a physical copy via `link_or_copy` if the
            // file systems don't support hard links across the
            // mirror tree — semantically equivalent for cargo.
            if fs::hard_link(&path, &dst_path).is_err()
            {
                fs::copy(&path, &dst_path).with_context(|| {
                    format!("copying {} -> {}", path.display(), dst_path.display())
                })?;
            }
        }
    }
    Ok(())
}

/// Returns true when `a` and `b` are known to share a hard-link inode
/// (only computable on Unix; conservatively returns false elsewhere
/// so the caller does a refresh).
#[cfg(unix)]
fn same_inode(a: &Path, b: &Path) -> bool
{
    use std::os::unix::fs::MetadataExt;
    match (a.symlink_metadata(), b.symlink_metadata())
    {
        (Ok(ma), Ok(mb)) => ma.ino() == mb.ino() && ma.dev() == mb.dev(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_inode(_a: &Path, _b: &Path) -> bool
{
    false
}

/// Identity string for the mirror. Combines the underlying rustc version
/// with a content fingerprint for the overlay sources (`runtime/ruststd/`) and
/// the patch logic (`xtask/src/rust_src.rs`). Any change to those
/// invalidates the mirror, triggering a clean rebuild.
fn compute_stamp(real: &Path, overlay_root: &Path, project_root: &Path) -> Result<String>
{
    let rustc = real.join("bin/rustc");
    let out = Command::new(&rustc)
        .args(["--version", "--verbose"])
        .output()
        .with_context(|| format!("invoking {}", rustc.display()))?;
    if !out.status.success()
    {
        bail!(
            "rustc --version --verbose failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let rustc_ident = String::from_utf8(out.stdout)
        .context("rustc version output not UTF-8")?
        .trim()
        .to_owned();

    let overlay_hash = hash_dir_content(overlay_root)?;
    let patch_logic_path = project_root.join("xtask/src/rust_src.rs");
    let patch_logic_hash = hash_file(&patch_logic_path)?;

    Ok(format!(
        "{rustc_ident}\noverlay: {overlay_hash:016x}\npatch-logic: {patch_logic_hash:016x}"
    ))
}

/// 64-bit FNV-1a over every regular file under `root`, in a deterministic
/// lexicographic order. Used as a cheap content fingerprint.
fn hash_dir_content(root: &Path) -> Result<u64>
{
    let mut state = FNV_OFFSET;
    hash_dir_into(root, &mut state)?;
    Ok(state)
}

fn hash_dir_into(dir: &Path, state: &mut u64) -> Result<()>
{
    let mut entries: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("reading {}", dir.display()))?
        .collect::<std::io::Result<_>>()
        .with_context(|| format!("reading entries of {}", dir.display()))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries
    {
        let path = entry.path();
        let ft = entry.file_type()?;
        // Include the name so deletions/renames register.
        for b in entry.file_name().as_encoded_bytes()
        {
            fnv_mix(state, *b);
        }
        fnv_mix(state, 0x1e); // record separator

        if ft.is_dir()
        {
            hash_dir_into(&path, state)?;
        }
        else if ft.is_file()
        {
            let bytes = fs::read(&path).with_context(|| format!("hashing {}", path.display()))?;
            for b in &bytes
            {
                fnv_mix(state, *b);
            }
        }
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<u64>
{
    let bytes = fs::read(path).with_context(|| format!("hashing {}", path.display()))?;
    let mut state = FNV_OFFSET;
    for b in &bytes
    {
        fnv_mix(&mut state, *b);
    }
    Ok(state)
}

// FNV-1a 64-bit constants.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

#[inline]
fn fnv_mix(state: &mut u64, byte: u8)
{
    *state ^= u64::from(byte);
    *state = state.wrapping_mul(FNV_PRIME);
}

// ── Wrapper-shim installation ────────────────────────────────────────────────

/// Name of the shim crate inside the workspace. Built once per
/// `ensure_seraph_toolchain` call; cargo will no-op when nothing
/// changed.
const SHIM_PACKAGE: &str = "seraph-wrapper-shim";

/// Wrapper-binary names installed in `mirror/bin/`. The shim
/// dispatches by argv[0] basename, so both names point at the same
/// physical binary.
const WRAPPER_NAMES: &[&str] = &["rustc", "ws-clippy"];

/// Build the `seraph-wrapper-shim` crate once for the host triple
/// (no-op when nothing changed), then install its binary into
/// `mirror/bin/` under both wrapper names.
///
/// The previous implementation wrote `#!/bin/sh` heredoc scripts and
/// `chmod +x`'d them — both Unix-only mechanisms. The shim binary
/// works on every host with a native executable format. Wrapper
/// behavior is parameterised via the `SERAPH_SHIM_*` env vars that
/// `SeraphToolchain::apply_env` sets before invoking cargo.
fn install_wrappers(ctx: &BuildContext, real: &Path, mirror: &Path) -> Result<()>
{
    let bin_dir = mirror.join("bin");
    materialise_bin_dir(real, &bin_dir).context("materialising mirror bin/")?;

    let shim_binary = build_shim_binary(ctx)?;
    for &name in WRAPPER_NAMES
    {
        let dst = bin_dir.join(install_name_for(name));
        if dst.symlink_metadata().is_ok()
        {
            fs::remove_file(&dst).with_context(|| format!("removing {}", dst.display()))?;
        }
        // Copy outright — hard-linking would let the shim binary's
        // mode bits / atime tracking diverge across the two install
        // names, and dir-symlinking is not what we want here.
        fs::copy(&shim_binary, &dst).with_context(|| {
            format!(
                "installing wrapper shim {} -> {}",
                shim_binary.display(),
                dst.display()
            )
        })?;
    }
    step(&format!(
        "seraph-toolchain: installed wrapper shim into {}",
        bin_dir.display()
    ));
    Ok(())
}

/// Cargo builds shims into `target/release/<name><EXE>`. Encode the
/// per-host exe suffix here so the path lookup is portable.
fn install_name_for(name: &str) -> String
{
    if std::env::consts::EXE_SUFFIX.is_empty()
    {
        name.to_owned()
    }
    else
    {
        format!("{name}{}", std::env::consts::EXE_SUFFIX)
    }
}

/// `cargo build --release -p seraph-wrapper-shim`. Returns the path
/// to the produced binary. cargo is a no-op when nothing changed.
fn build_shim_binary(ctx: &BuildContext) -> Result<PathBuf>
{
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ctx.root)
        .arg("build")
        .arg("--release")
        .arg("-p")
        .arg(SHIM_PACKAGE);
    run_cmd(&mut cmd).context("building seraph-wrapper-shim")?;

    let mut binary = ctx.target_dir.join("release");
    binary.push(format!(
        "{SHIM_PACKAGE}{suffix}",
        suffix = std::env::consts::EXE_SUFFIX,
    ));
    if !binary.is_file()
    {
        bail!(
            "expected seraph-wrapper-shim binary at {} after build",
            binary.display()
        );
    }
    Ok(binary)
}

/// If `bin_dir` is currently a symlink to `real/bin/`, replace it
/// with a real directory and populate it with mirror entries for
/// every binary in `real/bin/` (so cargo's `rustc --print sysroot`
/// path-resolution still finds the rest of the toolchain). If
/// already a real directory, leave it alone.
fn materialise_bin_dir(real: &Path, bin_dir: &Path) -> Result<()>
{
    let is_symlink = bin_dir
        .symlink_metadata()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if !is_symlink
    {
        return Ok(());
    }

    let real_bin = bin_dir
        .canonicalize()
        .with_context(|| format!("canonicalising {}", bin_dir.display()))?;
    fs::remove_file(bin_dir).with_context(|| format!("removing {}", bin_dir.display()))?;
    fs::create_dir_all(bin_dir).with_context(|| format!("creating {}", bin_dir.display()))?;
    for entry in
        fs::read_dir(&real_bin).with_context(|| format!("reading {}", real_bin.display()))?
    {
        let entry = entry?;
        let dst = bin_dir.join(entry.file_name());
        if dst.symlink_metadata().is_ok()
        {
            continue;
        }
        link_or_copy(&entry.path(), &dst).with_context(|| {
            format!(
                "materialising {} -> {}",
                dst.display(),
                entry.path().display()
            )
        })?;
    }
    // The real_bin path is needed only for the canonicalise+read_dir
    // walk; nothing else references it after this function returns.
    let _ = real;
    Ok(())
}

// ── Overlays ──────────────────────────────────────────────────────────────────

fn apply_all_overlays(mirror: &Path, overlay_root: &Path) -> Result<()>
{
    let rust_src = mirror.join("lib/rustlib/src/rust");
    // overlay_root = <project_root>/runtime/ruststd/src — walk up 3 levels.
    let project_root = overlay_root
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .context("deriving project root from overlay_root")?;
    apply_sys_visibility_overlay(&rust_src).context("sys visibility overlay")?;
    apply_std_cargo_deps_overlay(&rust_src, project_root).context("std Cargo.toml deps overlay")?;
    apply_alloc_overlay(&rust_src, overlay_root).context("alloc overlay")?;
    apply_reserve_overlay(&rust_src, overlay_root).context("reserve overlay")?;
    apply_io_error_overlay(&rust_src).context("io/error overlay")?;
    apply_random_overlay(&rust_src).context("random overlay")?;
    apply_thread_local_overlay(&rust_src).context("thread_local overlay")?;
    apply_stdio_overlay(&rust_src, overlay_root).context("stdio overlay")?;
    apply_exit_overlay(&rust_src).context("exit overlay")?;
    apply_os_overlay(&rust_src, overlay_root).context("os overlay")?;
    apply_thread_overlay(&rust_src, overlay_root).context("thread overlay")?;
    apply_sync_mutex_overlay(&rust_src, overlay_root).context("sync/mutex overlay")?;
    apply_sync_rwlock_overlay(&rust_src, overlay_root).context("sync/rwlock overlay")?;
    apply_sync_once_overlay(&rust_src, overlay_root).context("sync/once overlay")?;
    apply_sync_condvar_overlay(&rust_src, overlay_root).context("sync/condvar overlay")?;
    apply_sync_thread_parking_overlay(&rust_src, overlay_root)
        .context("sync/thread_parking overlay")?;
    apply_time_overlay(&rust_src, overlay_root).context("time overlay")?;
    apply_args_overlay(&rust_src, overlay_root).context("args overlay")?;
    apply_env_overlay(&rust_src, overlay_root).context("env overlay")?;
    apply_env_dispatch_overlay(&rust_src).context("env dispatch overlay")?;
    apply_process_overlay(&rust_src, overlay_root).context("process overlay")?;
    apply_pipe_overlay(&rust_src, overlay_root).context("pipe overlay")?;
    apply_fs_overlay(&rust_src, overlay_root).context("fs overlay")?;
    Ok(())
}

/// Add target-conditional path dependencies on the workspace's `syscall-abi`
/// and `syscall` crates to `library/std/Cargo.toml` when building for
/// seraph. Mirrors the hermit-abi / fortanix-sgx-abi pattern — std calls
/// into the ABI crate directly, eliminating duplicated `asm!` syscall
/// wrappers inside the overlay.
fn apply_std_cargo_deps_overlay(rust_src: &Path, project_root: &Path) -> Result<()>
{
    let cargo_toml = rust_src.join("library/std/Cargo.toml");
    let syscall_abi_path = project_root
        .join("abi/syscall")
        .canonicalize()
        .context("canonicalising abi/syscall")?;
    let syscall_path = project_root
        .join("shared/syscall")
        .canonicalize()
        .context("canonicalising shared/syscall")?;
    let ipc_path = project_root
        .join("shared/ipc")
        .canonicalize()
        .context("canonicalising shared/ipc")?;
    let log_path = project_root
        .join("shared/log")
        .canonicalize()
        .context("canonicalising shared/log")?;
    let process_abi_path = project_root
        .join("abi/process-abi")
        .canonicalize()
        .context("canonicalising abi/process-abi")?;
    let shmem_path = project_root
        .join("shared/shmem")
        .canonicalize()
        .context("canonicalising shared/shmem")?;
    let namespace_protocol_path = project_root
        .join("shared/namespace-protocol")
        .canonicalize()
        .context("canonicalising shared/namespace-protocol")?;
    let registry_client_path = project_root
        .join("shared/registry-client")
        .canonicalize()
        .context("canonicalising shared/registry-client")?;
    let block = format!(
        "\n\
         # seraph-overlay: workspace ABI crates as std deps.\n\
         # Mirrors hermit-abi / fortanix-sgx-abi pattern. Absolute paths are\n\
         # baked here because the mirror lives under target/ and this file\n\
         # is hard-linked on assembly — relative paths would point the wrong\n\
         # way. Regenerated whenever the mirror's content stamp changes.\n\
         [target.'cfg(target_os = \"seraph\")'.dependencies]\n\
         syscall-abi = {{ path = \"{abi}\", features = [\"rustc-dep-of-std\"] }}\n\
         syscall = {{ path = \"{sys}\", features = [\"rustc-dep-of-std\"] }}\n\
         ipc = {{ path = \"{ipc}\", features = [\"rustc-dep-of-std\"] }}\n\
         log = {{ path = \"{log}\", features = [\"rustc-dep-of-std\"] }}\n\
         process-abi = {{ path = \"{proc}\", features = [\"rustc-dep-of-std\"] }}\n\
         shmem = {{ path = \"{shmem}\", features = [\"rustc-dep-of-std\"] }}\n\
         namespace-protocol = {{ path = \"{ns}\", features = [\"rustc-dep-of-std\"] }}\n\
         registry-client = {{ path = \"{regcli}\", features = [\"rustc-dep-of-std\"] }}\n",
        abi = syscall_abi_path.display(),
        sys = syscall_path.display(),
        ipc = ipc_path.display(),
        log = log_path.display(),
        proc = process_abi_path.display(),
        shmem = shmem_path.display(),
        ns = namespace_protocol_path.display(),
        regcli = registry_client_path.display(),
    );

    let text = fs::read_to_string(&cargo_toml)
        .with_context(|| format!("reading {}", cargo_toml.display()))?;
    // Cargo.toml uses `#` comments, not `//`; MARKER was tuned for Rust
    // sources. Match the comment-stripped marker body instead. If the
    // marker is present but a known dep line is missing (added in a
    // later overlay revision), strip the old block and re-apply.
    let marker = "seraph-overlay: workspace ABI crates";
    let has_log_dep = text.contains("log = { path");
    let has_shmem_dep = text.contains("shmem = { path");
    let has_namespace_protocol_dep = text.contains("namespace-protocol = { path");
    let has_registry_client_dep = text.contains("registry-client = { path");
    if text.contains(marker)
        && has_log_dep
        && has_shmem_dep
        && has_namespace_protocol_dep
        && has_registry_client_dep
    {
        return Ok(());
    }
    let patched = if let Some(start) = text.find(marker)
    {
        // Old block present but stale — locate the start of the comment
        // line that contains the marker (one '\n' before the marker, or
        // the file head) and truncate from there. The block extends to
        // EOF in our format.
        let block_start = text[..start].rfind('\n').map_or(0, |p| p + 1);
        let mut head = String::with_capacity(block_start + block.len());
        head.push_str(&text[..block_start]);
        head.push_str(&block);
        head
    }
    else
    {
        text + &block
    };
    write_new_file(&cargo_toml, &patched)?;
    step(&format!(
        "seraph-toolchain: patched {}",
        cargo_toml.display()
    ));
    Ok(())
}

/// Widen `mod alloc;` in `sys/mod.rs` to `pub(crate) mod alloc;` so
/// `std::os::seraph` can reach the seraph PAL's public helpers, and
/// declare the seraph-only `pub(crate) mod reserve;` (the page-
/// reservation allocator). Both overlays touch the same file, so they
/// share one idempotent surgery pass.
fn apply_sys_visibility_overlay(rust_src: &Path) -> Result<()>
{
    let mod_rs = rust_src.join("library/std/src/sys/mod.rs");
    let original = "mod alloc;\n";
    let stale_visibility_only = "// seraph-overlay: expose sys::alloc to the crate for os::seraph\n\
         pub(crate) mod alloc;\n";
    let final_block = "// seraph-overlay: expose sys::alloc to the crate for os::seraph\n\
         pub(crate) mod alloc;\n\
         // seraph-overlay: page-reservation allocator (seraph-only)\n\
         #[cfg(target_os = \"seraph\")]\n\
         pub(crate) mod reserve;\n";

    let text =
        fs::read_to_string(&mod_rs).with_context(|| format!("reading {}", mod_rs.display()))?;
    if text.contains(final_block)
    {
        return Ok(());
    }
    let patched = if text.contains(stale_visibility_only)
    {
        text.replace(stale_visibility_only, final_block)
    }
    else if text.contains(original)
    {
        text.replace(original, final_block)
    }
    else
    {
        bail!(
            "sys/mod.rs has an unexpected shape — neither the upstream `mod alloc;` \
             nor the prior overlay block was found at {}",
            mod_rs.display()
        );
    };
    write_new_file(&mod_rs, &patched)?;
    step(&format!("seraph-toolchain: patched {}", mod_rs.display()));
    Ok(())
}

fn apply_alloc_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let alloc_dir = rust_src.join("library/std/src/sys/alloc");
    let mod_rs = alloc_dir.join("mod.rs");
    let seraph_rs_dst = alloc_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/alloc/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "alloc/seraph.rs")?;

    patch_file(
        &mod_rs,
        "alloc/mod.rs",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n    }\n",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n    }\n    \
         // seraph-overlay: seraph alloc (pub(crate) so os::seraph can reach it)\n    \
         target_os = \"seraph\" => {\n        pub(crate) mod seraph;\n    }\n",
    )
}

/// Install the seraph-only page-reservation allocator at
/// `library/std/src/sys/reserve.rs`. The module declaration lives in
/// `sys/mod.rs` (added by `apply_sys_visibility_overlay`); this overlay
/// supplies the implementation. The overlay source is kept under the
/// conventional `sys/reserve/seraph.rs` name in the project tree even
/// though the toolchain destination is a single `reserve.rs` file —
/// `reserve` exists only on seraph, so a per-target `seraph.rs` would
/// be redundant.
fn apply_reserve_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let dst = rust_src.join("library/std/src/sys/reserve.rs");
    let src = overlay_root.join("sys/reserve/seraph.rs");
    write_if_changed(&src, &dst, "sys/reserve.rs")
}

fn apply_io_error_overlay(rust_src: &Path) -> Result<()>
{
    let mod_rs = rust_src.join("library/std/src/sys/io/error/mod.rs");
    patch_file(
        &mod_rs,
        "io/error/mod.rs",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::*;\n    }\n",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::*;\n    }\n    \
         // seraph-overlay: seraph io errors via generic\n    \
         target_os = \"seraph\" => {\n        mod generic;\n        \
         pub use generic::*;\n    }\n",
    )
}

fn apply_random_overlay(rust_src: &Path) -> Result<()>
{
    let mod_rs = rust_src.join("library/std/src/sys/random/mod.rs");
    let orig =
        fs::read_to_string(&mod_rs).with_context(|| format!("reading {}", mod_rs.display()))?;
    if orig.contains(MARKER)
    {
        return Ok(());
    }

    let a1 = "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::fill_bytes;\n    }\n";
    let a1r = "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::fill_bytes;\n    }\n    \
               // seraph-overlay: seraph random via unsupported\n    \
               target_os = \"seraph\" => {\n        mod unsupported;\n        \
               pub use unsupported::{fill_bytes, hashmap_random_keys};\n    }\n";

    let a2 = "    target_os = \"vexos\",\n)))]\npub fn hashmap_random_keys()";
    let a2r = "    target_os = \"vexos\",\n    target_os = \"seraph\",\n)))]\npub fn hashmap_random_keys()";

    if !orig.contains(a1) || !orig.contains(a2)
    {
        bail!(
            "random/mod.rs anchors not found — upstream layout changed at {}",
            mod_rs.display()
        );
    }
    let patched = orig.replace(a1, a1r).replace(a2, a2r);
    write_new_file(&mod_rs, &patched)?;
    step(&format!("seraph-toolchain: patched {}", mod_rs.display()));
    Ok(())
}

/// Route `std::sys::args` through a seraph module that reads argv from
/// the read-only ProcessInfo page. See
/// `runtime/ruststd/src/sys/args/seraph.rs` for the backing.
fn apply_args_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let args_dir = rust_src.join("library/std/src/sys/args");
    let mod_rs = args_dir.join("mod.rs");
    let seraph_rs_dst = args_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/args/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sys/args/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sys/args/mod.rs",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::*;\n    }\n",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::*;\n    }\n    \
         // seraph-overlay: argv via ProcessInfo page (populated by procmgr at spawn)\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::*;\n    }\n",
    )
}

/// Route `std::sys::process` through a seraph module that implements
/// `Command::spawn` via procmgr `CREATE_FROM_FILE` plus death notifications
/// bound to the child's main thread. See `runtime/ruststd/src/sys/process/seraph.rs`.
fn apply_process_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let process_dir = rust_src.join("library/std/src/sys/process");
    let mod_rs = process_dir.join("mod.rs");
    let seraph_rs_dst = process_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/process/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sys/process/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sys/process/mod.rs",
        "    target_os = \"motor\" => {\n        mod motor;\n        use motor as imp;\n    }\n",
        "    target_os = \"motor\" => {\n        mod motor;\n        use motor as imp;\n    }\n    \
         // seraph-overlay: std::process::Command via procmgr CREATE_FROM_FILE + EventQueue\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         use seraph as imp;\n    }\n",
    )
}

/// Route `std::sys::env` through a seraph module that owns a process-global
/// `Mutex<BTreeMap<OsString, OsString>>`. See `runtime/ruststd/src/sys/env/seraph.rs`.
fn apply_env_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let env_dir = rust_src.join("library/std/src/sys/env");
    let mod_rs = env_dir.join("mod.rs");
    let seraph_rs_dst = env_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/env/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sys/env/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sys/env/mod.rs",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::*;\n    }\n",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::*;\n    }\n    \
         // seraph-overlay: env via process-global Mutex<BTreeMap>\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::*;\n    }\n",
    )
}

/// Route `std::env::current_dir` / `std::env::set_current_dir` through
/// the seraph env-imp module on seraph. Upstream dispatches both to
/// `os_imp::*` (= `sys::pal::*::os`), but seraph has no PAL under
/// `sys/pal/seraph/` — `os_imp` resolves to `sys::pal::unsupported::os`,
/// which returns `Unsupported`. The two functions delegate to
/// `crate::sys::env::seraph::{getcwd, chdir}` instead, which bridge to
/// the cap-native cwd surface in `crate::os::seraph`.
fn apply_env_dispatch_overlay(rust_src: &Path) -> Result<()>
{
    let env_rs = rust_src.join("library/std/src/env.rs");
    let orig =
        fs::read_to_string(&env_rs).with_context(|| format!("reading {}", env_rs.display()))?;
    if orig.contains(MARKER)
    {
        return Ok(());
    }

    let a1 = "pub fn current_dir() -> io::Result<PathBuf> {\n    os_imp::getcwd()\n}";
    let a1r = "pub fn current_dir() -> io::Result<PathBuf> {\n    \
               // seraph-overlay: dispatch through sys::env for cwd-cap bridge\n    \
               #[cfg(target_os = \"seraph\")]\n    \
               { env_imp::getcwd() }\n    \
               #[cfg(not(target_os = \"seraph\"))]\n    \
               { os_imp::getcwd() }\n}";

    let a2 = "pub fn set_current_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {\n    \
              os_imp::chdir(path.as_ref())\n}";
    let a2r = "pub fn set_current_dir<P: AsRef<Path>>(path: P) -> io::Result<()> {\n    \
               // seraph-overlay: dispatch through sys::env for cwd-cap bridge\n    \
               #[cfg(target_os = \"seraph\")]\n    \
               { env_imp::chdir(path.as_ref()) }\n    \
               #[cfg(not(target_os = \"seraph\"))]\n    \
               { os_imp::chdir(path.as_ref()) }\n}";

    if !orig.contains(a1) || !orig.contains(a2)
    {
        bail!(
            "env.rs anchors not found — upstream layout likely changed at {}",
            env_rs.display()
        );
    }
    let patched = orig.replace(a1, a1r).replace(a2, a2r);
    write_new_file(&env_rs, &patched)?;
    step(&format!("seraph-toolchain: patched {}", env_rs.display()));
    Ok(())
}

fn apply_stdio_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let stdio_dir = rust_src.join("library/std/src/sys/stdio");
    let mod_rs = stdio_dir.join("mod.rs");
    let seraph_rs_dst = stdio_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/stdio/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "stdio/seraph.rs")?;

    patch_file(
        &mod_rs,
        "stdio/mod.rs",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::*;\n    }\n",
        "    target_os = \"zkvm\" => {\n        mod zkvm;\n        pub use zkvm::*;\n    }\n    \
         // seraph-overlay: seraph stdio via log endpoint (pub(crate) so os::seraph can reach log_init)\n    \
         target_os = \"seraph\" => {\n        pub(crate) mod seraph;\n        \
         pub use seraph::*;\n    }\n",
    )
}

/// Patch `library/std/src/sys/exit.rs` to route `exit(code)` through
/// `syscall::thread_exit()` on seraph, so `std::process::exit` exits the
/// calling thread cleanly instead of trapping via `intrinsics::abort()` (the
/// unsupported-fallback behaviour). Closes stdio pipes first so any
/// parent blocked on a `read_to_end` / `write` observes EOF /
/// `BrokenPipe` instead of hanging.
fn apply_exit_overlay(rust_src: &Path) -> Result<()>
{
    let exit_rs = rust_src.join("library/std/src/sys/exit.rs");
    patch_file(
        &exit_rs,
        "sys/exit.rs",
        "        target_os = \"xous\" => {\n            crate::os::xous::ffi::exit(code as u32)\n        }\n",
        "        target_os = \"xous\" => {\n            crate::os::xous::ffi::exit(code as u32)\n        }\n        \
         // seraph-overlay: exit via SYS_THREAD_EXIT for clean shutdown\n        \
         target_os = \"seraph\" => {\n            let _ = code;\n            \
         crate::sys::stdio::seraph::close_all();\n            \
         syscall::thread_exit()\n        }\n",
    )
}

fn apply_os_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let os_dir = rust_src.join("library/std/src/os");
    let mod_rs = os_dir.join("mod.rs");
    let seraph_rs_dst = os_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("os/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "os/seraph.rs")?;

    patch_file(
        &mod_rs,
        "os/mod.rs",
        "#[cfg(target_os = \"xous\")]\npub mod xous;\n",
        "#[cfg(target_os = \"xous\")]\npub mod xous;\n\
         // seraph-overlay: std::os::seraph module\n\
         #[cfg(target_os = \"seraph\")]\npub mod seraph;\n",
    )
}

fn apply_thread_local_overlay(rust_src: &Path) -> Result<()>
{
    // Target JSON sets `has-thread-local: true`, so std picks up the
    // `target_thread_local` branch and uses the `native` backend —
    // rustc emits real `#[thread_local]` accesses (`%fs:TPOFF` on x86-64
    // / `tp-relative` on RISC-V) against the per-thread block allocated
    // by procmgr (main thread) or `alloc_thread_tls` (spawned threads).
    //
    // Only the `guard::enable` helper needs a seraph arm: seraph has no
    // concept of "thread exit" visible to std (the kernel unwinds on
    // `SYS_THREAD_EXIT`), so treat it as a no-op — matches hermit/xous.
    let mod_rs = rust_src.join("library/std/src/sys/thread_local/mod.rs");
    let orig =
        fs::read_to_string(&mod_rs).with_context(|| format!("reading {}", mod_rs.display()))?;
    if orig.contains(MARKER)
    {
        return Ok(());
    }

    let a2 = "            target_os = \"vexos\",\n        ) => {\n            \
              pub(crate) fn enable() {";
    let a2r = "            target_os = \"vexos\",\n            \
               // seraph-overlay: guard::enable is a no-op on seraph\n            \
               target_os = \"seraph\",\n        ) => {\n            \
               pub(crate) fn enable() {";

    if !orig.contains(a2)
    {
        bail!(
            "thread_local/mod.rs anchors not found — upstream layout changed at {}",
            mod_rs.display()
        );
    }
    let patched = orig.replace(a2, a2r);
    write_new_file(&mod_rs, &patched)?;
    step(&format!("seraph-toolchain: patched {}", mod_rs.display()));
    Ok(())
}

fn apply_thread_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let thread_dir = rust_src.join("library/std/src/sys/thread");
    let mod_rs = thread_dir.join("mod.rs");
    let seraph_rs_dst = thread_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/thread/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "thread/seraph.rs")?;

    patch_file(
        &mod_rs,
        "thread/mod.rs",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::{Thread, available_parallelism, sleep, yield_now, DEFAULT_MIN_STACK_SIZE};\n\n        #[expect(dead_code)]\n        mod unsupported;\n        pub use unsupported::{current_os_id, set_name};\n    }\n",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::{Thread, available_parallelism, sleep, yield_now, DEFAULT_MIN_STACK_SIZE};\n\n        #[expect(dead_code)]\n        mod unsupported;\n        pub use unsupported::{current_os_id, set_name};\n    }\n    \
         // seraph-overlay: seraph thread via Signal caps\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::{Thread, available_parallelism, current_os_id, set_name, sleep, yield_now, DEFAULT_MIN_STACK_SIZE};\n    }\n",
    )?;

    // Ensure the sleep_until fallback cfg list also excludes seraph, so we
    // pick up the generic sleep-loop impl rather than tripping a duplicate.
    let cfg_anchor = "    target_os = \"vexos\"\n)))]\npub fn sleep_until";
    let cfg_replacement = "    target_os = \"vexos\"\n)))]\n// seraph-overlay: keep seraph on the generic sleep_until fallback\npub fn sleep_until";
    let text =
        fs::read_to_string(&mod_rs).with_context(|| format!("reading {}", mod_rs.display()))?;
    if !text.contains("// seraph-overlay: keep seraph on the generic sleep_until fallback")
        && text.contains(cfg_anchor)
    {
        let patched = text.replace(cfg_anchor, cfg_replacement);
        write_new_file(&mod_rs, &patched)?;
    }
    Ok(())
}

fn apply_sync_mutex_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let dir = rust_src.join("library/std/src/sys/sync/mutex");
    let mod_rs = dir.join("mod.rs");
    let seraph_rs_dst = dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/sync/mutex/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sync/mutex/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sync/mutex/mod.rs",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::Mutex;\n    }\n",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::Mutex;\n    }\n    \
         // seraph-overlay: seraph mutex via Signal caps\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::Mutex;\n    }\n",
    )
}

fn apply_sync_rwlock_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let dir = rust_src.join("library/std/src/sys/sync/rwlock");
    let mod_rs = dir.join("mod.rs");
    let seraph_rs_dst = dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/sync/rwlock/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sync/rwlock/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sync/rwlock/mod.rs",
        "    target_os = \"solid_asp3\" => {\n        mod solid;\n        pub use solid::RwLock;\n    }\n",
        "    target_os = \"solid_asp3\" => {\n        mod solid;\n        pub use solid::RwLock;\n    }\n    \
         // seraph-overlay: seraph rwlock via Signal caps\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::RwLock;\n    }\n",
    )
}

fn apply_sync_once_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let dir = rust_src.join("library/std/src/sys/sync/once");
    let mod_rs = dir.join("mod.rs");
    let seraph_rs_dst = dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/sync/once/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sync/once/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sync/once/mod.rs",
        "    any(\n        windows,\n        target_family = \"unix\",\n        all(target_vendor = \"fortanix\", target_env = \"sgx\"),\n        target_os = \"solid_asp3\",\n        target_os = \"xous\",\n    ) => {\n        mod queue;\n        pub use queue::{Once, OnceState};\n    }\n",
        "    any(\n        windows,\n        target_family = \"unix\",\n        all(target_vendor = \"fortanix\", target_env = \"sgx\"),\n        target_os = \"solid_asp3\",\n        target_os = \"xous\",\n    ) => {\n        mod queue;\n        pub use queue::{Once, OnceState};\n    }\n    \
         // seraph-overlay: seraph once via Signal caps\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::{Once, OnceState};\n    }\n",
    )
}

fn apply_sync_condvar_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let dir = rust_src.join("library/std/src/sys/sync/condvar");
    let mod_rs = dir.join("mod.rs");
    let seraph_rs_dst = dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/sync/condvar/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sync/condvar/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sync/condvar/mod.rs",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::Condvar;\n    }\n",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::Condvar;\n    }\n    \
         // seraph-overlay: seraph condvar via Signal caps\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::Condvar;\n    }\n",
    )
}

fn apply_time_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let dir = rust_src.join("library/std/src/sys/time");
    let mod_rs = dir.join("mod.rs");
    let seraph_rs_dst = dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/time/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "time/seraph.rs")?;

    patch_file(
        &mod_rs,
        "sys/time/mod.rs",
        "    target_os = \"xous\" => {\n        mod xous;\n        use xous as imp;\n    }\n",
        "    target_os = \"xous\" => {\n        mod xous;\n        use xous as imp;\n    }\n    \
         // seraph-overlay: Instant via SYS_SYSTEM_INFO ElapsedUs\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         use seraph as imp;\n    }\n",
    )
}

fn apply_pipe_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let pipe_dir = rust_src.join("library/std/src/sys/pipe");
    let mod_rs = pipe_dir.join("mod.rs");
    let seraph_rs_dst = pipe_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/pipe/seraph.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "pipe/seraph.rs")?;

    patch_file(
        &mod_rs,
        "pipe/mod.rs",
        "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::{Pipe, pipe};\n    }\n",
        "    target_os = \"motor\" => {\n        mod motor;\n        pub use motor::{Pipe, pipe};\n    }\n    \
         // seraph-overlay: shmem-backed Stdio::piped via SPSC ring + signal caps\n    \
         target_os = \"seraph\" => {\n        pub mod seraph;\n        \
         pub use seraph::{Pipe, pipe};\n    }\n",
    )
}

/// Route `std::sys::fs` through a seraph module that implements
/// `std::fs::File` against vfsd / fs-driver IPC. Two source files: the
/// public `seraph.rs` and an inner `release_handler.rs` (declared from
/// `seraph.rs::mod release_handler;`). See
/// `runtime/ruststd/src/sys/fs/seraph.rs`.
fn apply_fs_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let fs_dir = rust_src.join("library/std/src/sys/fs");
    let mod_rs = fs_dir.join("mod.rs");
    let seraph_rs_dst = fs_dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/fs/seraph.rs");
    let release_handler_rs_dst = fs_dir.join("release_handler.rs");
    let release_handler_rs_src = overlay_root.join("sys/fs/release_handler.rs");

    write_if_changed(&seraph_rs_src, &seraph_rs_dst, "sys/fs/seraph.rs")?;
    write_if_changed(
        &release_handler_rs_src,
        &release_handler_rs_dst,
        "sys/fs/release_handler.rs",
    )?;

    patch_file(
        &mod_rs,
        "sys/fs/mod.rs",
        "    target_os = \"motor\" => {\n        mod motor;\n        use motor as imp;\n    }\n",
        "    target_os = \"motor\" => {\n        mod motor;\n        use motor as imp;\n    }\n    \
         // seraph-overlay: std::fs::File via vfsd OPEN + fs-driver FS_READ/FS_READ_FRAME\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         use seraph as imp;\n        \
         pub(crate) use seraph::{walk_path_to_file, walk_path_to_dir, WalkedFile, WalkedDir};\n    }\n",
    )
}

fn apply_sync_thread_parking_overlay(rust_src: &Path, overlay_root: &Path) -> Result<()>
{
    let dir = rust_src.join("library/std/src/sys/sync/thread_parking");
    let mod_rs = dir.join("mod.rs");
    let seraph_rs_dst = dir.join("seraph.rs");
    let seraph_rs_src = overlay_root.join("sys/sync/thread_parking/seraph.rs");

    write_if_changed(
        &seraph_rs_src,
        &seraph_rs_dst,
        "sync/thread_parking/seraph.rs",
    )?;

    patch_file(
        &mod_rs,
        "sync/thread_parking/mod.rs",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::Parker;\n    }\n",
        "    target_os = \"xous\" => {\n        mod xous;\n        pub use xous::Parker;\n    }\n    \
         // seraph-overlay: seraph parker via Signal caps\n    \
         target_os = \"seraph\" => {\n        mod seraph;\n        \
         pub use seraph::Parker;\n    }\n",
    )
}

// ── shared helpers ────────────────────────────────────────────────────────────

fn patch_file(path: &Path, short: &str, anchor: &str, replacement: &str) -> Result<()>
{
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    if text.contains(MARKER)
    {
        return Ok(());
    }
    if !text.contains(anchor)
    {
        bail!(
            "{short} anchor not found — upstream layout likely changed at {}",
            path.display()
        );
    }
    if !replacement.contains(MARKER)
    {
        bail!("overlay replacement for {short} is missing the idempotency marker");
    }
    let patched = text.replace(anchor, replacement);
    // The mirror hard-links from the toolchain rust-src. Writing to a
    // hard link would corrupt the shared inode; unlink first so the
    // subsequent write creates a new file reachable only via the mirror.
    write_new_file(path, &patched)?;
    step(&format!("seraph-toolchain: patched {}", path.display()));
    Ok(())
}

/// Remove `path` if it exists (breaking any hard link) then write
/// `content`. Used by overlays so toolchain rust-src files that are
/// hard-linked into the mirror are never mutated.
fn write_new_file(path: &Path, content: &str) -> Result<()>
{
    if path.symlink_metadata().is_ok()
    {
        fs::remove_file(path).with_context(|| format!("removing {}", path.display()))?;
    }
    fs::write(path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_if_changed(src: &Path, dst: &Path, short: &str) -> Result<()>
{
    if !src.exists()
    {
        bail!("overlay source not found at {}", src.display());
    }
    let desired = fs::read_to_string(src).with_context(|| format!("reading {}", src.display()))?;
    let needs_copy = match fs::read_to_string(dst)
    {
        Ok(current) => current != desired,
        Err(_) => true,
    };
    if needs_copy
    {
        write_new_file(dst, &desired)?;
        step(&format!(
            "seraph-toolchain: wrote {} ({})",
            dst.display(),
            short
        ));
    }
    Ok(())
}

fn probe_real_sysroot() -> Result<PathBuf>
{
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .context("invoking rustc --print sysroot")?;
    if !out.status.success()
    {
        bail!(
            "rustc --print sysroot failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let path = String::from_utf8(out.stdout)
        .context("rustc sysroot output not UTF-8")?
        .trim()
        .to_owned();
    Ok(PathBuf::from(path))
}
