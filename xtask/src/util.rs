// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/util.rs

//! Shared utilities: step printing, command execution, and tool
//! discovery. (The terminal-state RAII guard moved to `term::guard`.)

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Context, Result, bail};

// ── Step printing ─────────────────────────────────────────────────────────────

/// Print a `==> msg` step header to stdout and flush immediately.
pub fn step(msg: &str)
{
    println!("==> {msg}");
    let _ = std::io::stdout().flush();
}

// ── Command execution ─────────────────────────────────────────────────────────

/// Spawn `cmd` (inheriting stdout/stderr), wait for it, and return an error if
/// it exits non-zero.
pub fn run_cmd(cmd: &mut Command) -> Result<()>
{
    let status = cmd
        .status()
        .with_context(|| format!("failed to launch {}", cmd.get_program().display()))?;
    if !status.success()
    {
        bail!("{} exited with {}", cmd.get_program().display(), status);
    }
    Ok(())
}

/// Spawn `cmd`, capture its stdout, and return it as a String.
///
/// Returns an error if the process exits non-zero.
pub fn run_cmd_capture(cmd: &mut Command) -> Result<String>
{
    let output = cmd
        .output()
        .with_context(|| format!("failed to launch {}", cmd.get_program().display()))?;
    if !output.status.success()
    {
        bail!(
            "{} exited with {}",
            cmd.get_program().display(),
            output.status
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ── Formatting ────────────────────────────────────────────────────────────────

/// Check that the Rust source of the cargo workspace at `root` is formatted as
/// `cargo fmt` formats it under the workspace's `rustfmt.toml`, rewriting
/// nothing (`docs/coding-standards.md` § Formatters). `selection` is the
/// package selection `cargo fmt` takes: `--all` for every workspace member, or
/// `-p <crate>` pairs.
///
/// On unformatted source the error carries rustfmt's diff, each hunk headed
/// by `Diff in <file>:<line>:`, and the command that formats the tree; any
/// other failure (rustfmt missing, a file it cannot parse) carries cargo's
/// error output.
pub fn check_formatting(root: &Path, selection: &[&str]) -> Result<()>
{
    let output = Command::new("cargo")
        .current_dir(root)
        .arg("fmt")
        .args(selection)
        .arg("--check")
        .output()
        .context("failed to launch cargo fmt")?;
    if output.status.success()
    {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.contains("Diff in ")
    {
        bail!(
            "Rust source is not formatted (docs/coding-standards.md § Formatters); run \
             `cargo fmt --all` and commit the result:\n{stdout}{stderr}"
        );
    }
    bail!("cargo fmt --check exited with {}:\n{stderr}", output.status);
}

// ── Cargo environment ─────────────────────────────────────────────────────────

/// The environment every cargo command of the build runs with, so a local
/// build compiles what CI's jobs compile: the Rust cache action of
/// `.github/workflows/build-test.yml` writes `CARGO_INCREMENTAL=0` to the job
/// environment, and an incremental `dev` build partitions codegen units, and
/// so orders a binary's statics, differently from a non-incremental one
/// (`docs/build-system.md` § Build Profiles). It is set over any value the
/// caller's environment holds, so a local build never departs from CI's on
/// it.
pub const CI_CARGO_ENV: [(&str, &str); 1] = [("CARGO_INCREMENTAL", "0")];

// ── Tool discovery ────────────────────────────────────────────────────────────

/// Resolve `name` on `PATH`, then, on a Unix host, in `SBIN_DIRS`,
/// returning a clear error with per-tool install hints if missing. Use this
/// for tools that aren't part of xtask's own dependency chain (qemu,
/// llvm-objcopy from rustup, etc.) and spawn the returned path, not `name`:
/// `Command::new(name)` searches `PATH` alone, so a tool found only in an
/// sbin directory would fail to spawn with the OS's opaque "No such file or
/// directory", which this function exists to replace with an actionable
/// message.
pub fn require_tool(name: &str) -> Result<PathBuf>
{
    let path = tool_search_path(std::env::var_os("PATH").as_deref());
    find_executable(
        Path::new(name),
        path.as_deref(),
        std::env::consts::EXE_EXTENSION,
    )
    .ok_or_else(|| {
        let also = if cfg!(unix)
        {
            " or in /usr/local/sbin, /usr/sbin or /sbin"
        }
        else
        {
            ""
        };
        crate::error::err!(
            "{name} not found on PATH{also}\n{hint}",
            hint = install_hint_for(name),
        )
    })
}

/// The system-administration directories a Unix distribution installs some
/// tools in (dosfstools' `fsck.fat` among them) and may leave off an
/// unprivileged user's `PATH`, as Debian's default does; [`require_tool`]
/// searches them after `PATH`.
const SBIN_DIRS: [&str; 3] = ["/usr/local/sbin", "/usr/sbin", "/sbin"];

/// The directories [`require_tool`] searches: those of `path` (a `PATH`
/// value) in order, then, on Unix, each of [`SBIN_DIRS`] that `path` does not
/// already name.
fn tool_search_path(path: Option<&OsStr>) -> Option<OsString>
{
    let mut dirs: Vec<PathBuf> = path.map_or_default(|path| std::env::split_paths(path).collect());
    if cfg!(unix)
    {
        for dir in SBIN_DIRS.map(PathBuf::from)
        {
            if !dirs.contains(&dir)
            {
                dirs.push(dir);
            }
        }
    }
    std::env::join_paths(dirs).ok()
}

/// The executable file `name` names, found as the host's process launcher
/// finds it, or `None` when there is none.
///
/// A name with a directory part (`./gdb`, `/usr/bin/gdb`) names that file,
/// returned absolute so a command run from another directory still finds it.
/// A bare name is looked up in each directory of `path` (a `PATH` value) in
/// order; an empty entry is skipped, not read as the current directory.
/// `extension` is the host's executable extension
/// (`std::env::consts::EXE_EXTENSION`: `exe` on Windows, empty elsewhere),
/// which a name without it takes, as `Command` gives it. A match is a regular
/// file (after symlinks) that, on Unix, has an execute permission bit set.
fn find_executable(name: &Path, path: Option<&OsStr>, extension: &str) -> Option<PathBuf>
{
    let file = with_extension(name, extension);
    if name.components().count() > 1
    {
        return is_executable(&file)
            .then(|| std::path::absolute(&file).ok())
            .flatten();
    }
    std::env::split_paths(path?)
        .filter(|dir| !dir.as_os_str().is_empty())
        .map(|dir| dir.join(&file))
        .find(|candidate| is_executable(candidate))
}

/// `name` with `.extension` appended, unless `extension` is empty or `name`
/// already ends in it (compared ASCII-case-insensitively, as Windows names
/// compare).
fn with_extension(name: &Path, extension: &str) -> PathBuf
{
    let has_it = name
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension));
    if extension.is_empty() || has_it
    {
        return name.to_path_buf();
    }
    let mut file = name.as_os_str().to_owned();
    file.push(".");
    file.push(extension);
    PathBuf::from(file)
}

/// Whether `path` is a regular file with an execute permission bit set.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool
{
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

/// Whether `path` is a regular file: a host without Unix permission bits
/// marks an executable by its extension, which the lookup appends.
#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool
{
    std::fs::metadata(path).is_ok_and(|meta| meta.is_file())
}

fn install_hint_for(name: &str) -> String
{
    match name
    {
        "qemu-system-x86_64" => "Install with:\n  \
            Fedora:           dnf install qemu-system-x86\n  \
            Debian / Ubuntu:  apt install qemu-system-x86\n  \
            Arch:             pacman -S qemu-system-x86\n  \
            macOS (Homebrew): brew install qemu\n  \
            FreeBSD:          pkg install qemu"
            .into(),
        "qemu-system-riscv64" => "Install with:\n  \
            Fedora:           dnf install qemu-system-riscv\n  \
            Debian / Ubuntu:  apt install qemu-system-riscv (older releases: qemu-system-misc)\n  \
            Arch:             pacman -S qemu-system-riscv\n  \
            macOS (Homebrew): brew install qemu\n  \
            FreeBSD:          pkg install qemu"
            .into(),
        "qemu-riscv64" | "riscv64-linux-gnu-gcc" => "`cargo xtask test` runs the riscv64 \
            host tests under QEMU user-mode emulation, linked by the riscv64 Linux cross \
            compiler against its C library. Install with:\n  \
            Debian / Ubuntu:  apt install qemu-user gcc-riscv64-linux-gnu libc6-dev-riscv64-cross\n  \
            Arch:             pacman -S qemu-user riscv64-linux-gnu-gcc riscv64-linux-gnu-glibc"
            .into(),
        "fsck.fat" => "Every pack of the disk images (`cargo xtask build`, `cargo xtask mkdisk` and \
            the tests that repack) checks their FAT volumes with dosfstools' fsck.fat. \
            Install with:\n  \
            Fedora:           dnf install dosfstools\n  \
            Debian / Ubuntu:  apt install dosfstools\n  \
            Arch:             pacman -S dosfstools\n  \
            macOS (Homebrew): brew install dosfstools\n  \
            FreeBSD:          pkg install dosfstools"
            .into(),
        "swtpm" => "`cargo xtask test-tpm` backs QEMU's TPM device with the swtpm \
            TPM 2.0 emulator. Install with:\n  \
            Fedora:           dnf install swtpm swtpm-tools\n  \
            Debian / Ubuntu:  apt install swtpm swtpm-tools\n  \
            Arch:             pacman -S swtpm"
            .into(),
        "cargo" | "rustc" => "Install rustup (https://rustup.rs/); xtask requires the toolchain \
             pinned in rust-toolchain.toml. This usually means xtask itself was invoked \
             outside a rustup-managed environment."
            .into(),
        _ => format!("Install {name} via your distribution's package manager."),
    }
}

/// Locate `llvm-objcopy` from the active Rust toolchain's `llvm-tools` component.
///
/// Resolves to: `$(rustc --print sysroot)/lib/rustlib/<host-triple>/bin/llvm-objcopy`
///
/// Returns an error with install instructions if not found.
pub fn find_llvm_objcopy() -> Result<PathBuf>
{
    let rustc = require_tool("rustc")?;
    let sysroot_out = run_cmd_capture(Command::new(&rustc).args(["--print", "sysroot"]))?;
    let sysroot = sysroot_out.trim();

    let version_out = run_cmd_capture(Command::new(&rustc).args(["-vV"]))?;
    let host_triple = version_out
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("could not parse host triple from `rustc -vV` output")?
        .trim()
        .to_owned();

    let objcopy = PathBuf::from(sysroot)
        .join("lib")
        .join("rustlib")
        .join(&host_triple)
        .join("bin")
        .join("llvm-objcopy");

    if objcopy.is_file()
    {
        Ok(objcopy)
    }
    else
    {
        bail!(
            "llvm-objcopy not found at {}\nInstall with: rustup component add llvm-tools",
            objcopy.display()
        )
    }
}

// ── Host ports ────────────────────────────────────────────────────────────────

/// The host TCP port a debug-port boot serves on: `requested` when the
/// command was given one, and otherwise a port free on `127.0.0.1` now.
///
/// The free port is the one the kernel assigns a listener bound to port 0,
/// which is closed again before the port is returned. A port another boot's
/// QEMU serves on is never picked, so boots from several worktrees do not
/// meet on one fixed port. A process that binds the port between its close
/// and QEMU's own bind takes it, and QEMU then fails to start.
pub fn debug_port_or_free(requested: Option<u16>) -> Result<u16>
{
    if let Some(port) = requested
    {
        return Ok(port);
    }
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .context("binding a listener on 127.0.0.1 to pick a free port")?;
    let port = listener
        .local_addr()
        .context("reading the free port's address")?
        .port();
    Ok(port)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_sbin_directories_are_searched_after_path_once()
    {
        let path = tool_search_path(Some(OsStr::new("/usr/bin:/usr/sbin"))).unwrap();
        let dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
        assert_eq!(
            dirs,
            ["/usr/bin", "/usr/sbin", "/usr/local/sbin", "/sbin"].map(PathBuf::from)
        );
        let none = tool_search_path(None).unwrap();
        let dirs: Vec<PathBuf> = std::env::split_paths(&none).collect();
        assert_eq!(dirs, SBIN_DIRS.map(PathBuf::from));
    }

    #[test]
    fn a_requested_port_is_kept()
    {
        assert_eq!(debug_port_or_free(Some(4560)).unwrap(), 4560);
    }

    #[test]
    fn a_picked_port_is_never_a_held_one()
    {
        // Held here for the whole test, as a running boot's QEMU holds its
        // port. The test binds it itself, so no other process on the host
        // can take it, and the test asserts nothing about a port it does
        // not hold: the picked port can be taken by anyone once the picker
        // closes its listener, the race `debug_port_or_free` states.
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("binding port 0");
        let held_port = held.local_addr().expect("the held port's address").port();
        for _ in 0..32
        {
            let picked = debug_port_or_free(None).unwrap();
            assert_ne!(picked, 0);
            assert_ne!(picked, held_port);
        }
        drop(held);
    }

    /// A fresh directory under the host's temporary directory, unique to
    /// this process and call.
    fn scratch_dir(tag: &str) -> PathBuf
    {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seraph-xtask-util-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Write a file at `path` with Unix permission bits `mode`.
    #[cfg(unix)]
    fn file_with_mode(path: &Path, mode: u32)
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn path_of(dirs: &[&Path]) -> std::ffi::OsString
    {
        std::env::join_paths(dirs).unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn a_bare_name_is_the_first_executable_file_on_path()
    {
        let root = scratch_dir("first");
        let (plain, subdir, exec, later) = (
            root.join("a"),
            root.join("b"),
            root.join("c"),
            root.join("d"),
        );
        for dir in [&plain, &subdir, &exec, &later]
        {
            std::fs::create_dir(dir).unwrap();
        }
        // Skipped: a file without an execute bit, and a directory.
        file_with_mode(&plain.join("tool"), 0o644);
        std::fs::create_dir(subdir.join("tool")).unwrap();
        // Found: the first executable file, not a later one.
        file_with_mode(&exec.join("tool"), 0o755);
        file_with_mode(&later.join("tool"), 0o755);
        let path = path_of(&[&plain, &subdir, &exec, &later]);
        assert_eq!(
            find_executable(Path::new("tool"), Some(&path), ""),
            Some(exec.join("tool"))
        );
        // An execute bit for others alone is still an execute bit.
        file_with_mode(&plain.join("tool"), 0o601);
        assert_eq!(
            find_executable(Path::new("tool"), Some(&path), ""),
            Some(plain.join("tool"))
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn an_empty_path_entry_is_skipped()
    {
        let root = scratch_dir("empty");
        file_with_mode(&root.join("tool"), 0o755);
        let mut path = std::ffi::OsString::from(":");
        path.push(root.as_os_str());
        assert_eq!(
            find_executable(Path::new("tool"), Some(&path), ""),
            Some(root.join("tool"))
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_tool_or_path_finds_nothing()
    {
        let root = scratch_dir("missing");
        let path = path_of(&[&root]);
        assert_eq!(find_executable(Path::new("tool"), Some(&path), ""), None);
        assert_eq!(find_executable(Path::new("tool"), None, ""), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_name_with_a_directory_part_is_that_file_made_absolute()
    {
        let root = scratch_dir("dirpart");
        file_with_mode(&root.join("tool"), 0o755);
        file_with_mode(&root.join("data"), 0o644);
        // PATH is not searched for such a name.
        let empty = scratch_dir("dirpart-path");
        let path = path_of(&[&empty]);
        let absolute = root.join("tool");
        assert_eq!(
            find_executable(&absolute, Some(&path), ""),
            Some(absolute.clone())
        );
        assert_eq!(find_executable(&root.join("data"), Some(&path), ""), None);
        // A relative one resolves against the current directory.
        let relative = Path::new(".").join("seraph-xtask-util-no-such-tool");
        assert_eq!(find_executable(&relative, Some(&path), ""), None);
        std::fs::remove_dir_all(&root).unwrap();
        std::fs::remove_dir_all(&empty).unwrap();
    }

    #[test]
    fn the_host_extension_is_appended_unless_present()
    {
        assert_eq!(
            with_extension(Path::new("qemu-system-x86_64"), ""),
            Path::new("qemu-system-x86_64")
        );
        assert_eq!(
            with_extension(Path::new("qemu-system-x86_64"), "exe"),
            Path::new("qemu-system-x86_64.exe")
        );
        assert_eq!(
            with_extension(Path::new("gdb.EXE"), "exe"),
            Path::new("gdb.EXE")
        );
        assert_eq!(
            with_extension(Path::new("gdb.bat"), "exe"),
            Path::new("gdb.bat.exe")
        );
    }

    // Defect guarded: unformatted Rust that no check reads, as a build that
    // formatted in place let a pushed head's unformatted lines pass CI.
    #[test]
    fn unformatted_source_fails_the_check_naming_its_file_and_line()
    {
        let root = scratch_dir("fmt");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"fmt-probe\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\n\
             [workspace]\n",
        )
        .unwrap();
        // The tree's own formatter configuration and toolchain, so the probe
        // is held to the rules the workspace is.
        let tree = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for config in ["rustfmt.toml", "rust-toolchain.toml"]
        {
            std::fs::copy(tree.join(config), root.join(config)).unwrap();
        }
        std::fs::create_dir(root.join("src")).unwrap();
        std::fs::write(
            root.join("src").join("lib.rs"),
            "pub fn probe( ) -> u32 { 1 }\n",
        )
        .unwrap();

        let text = format!("{:#}", check_formatting(&root, &["--all"]).unwrap_err());
        assert!(text.contains("lib.rs:1:"), "{text}");
        assert!(text.contains("cargo fmt --all"), "{text}");
        let lib = std::fs::read_to_string(root.join("src").join("lib.rs")).unwrap();
        assert_eq!(
            lib, "pub fn probe( ) -> u32 { 1 }\n",
            "the check rewrote the file"
        );

        run_cmd(
            Command::new("cargo")
                .current_dir(&root)
                .args(["fmt", "--all"]),
        )
        .unwrap();
        check_formatting(&root, &["--all"]).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_missing_tool_is_named_with_its_install_hint()
    {
        let err = require_tool("seraph-xtask-no-such-tool").unwrap_err();
        let text = format!("{err:#}");
        assert!(
            text.contains("seraph-xtask-no-such-tool not found on PATH"),
            "{text}"
        );
        assert!(text.contains("Install seraph-xtask-no-such-tool"), "{text}");
    }
}
