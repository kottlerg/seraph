// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/wrapper-shim/src/main.rs

//! Tiny native binary installed into the seraph toolchain mirror as
//! both `rustc` and `ws-clippy`, and for the fuzz build as
//! `sancov-rustc`. Replaces the previous `#!/bin/sh`
//! wrapper scripts so the toolchain mirror works on every host with a
//! native executable format — no shebang interpretation, no POSIX
//! shell, no Unix permission bits beyond what the file system already
//! gives a compiled binary.
//!
//! Dispatches on argv[0] basename:
//!
//! - **`rustc`**: exec the real rustc with `--sysroot=<mirror>`
//!   prepended, unless the caller already supplied `--sysroot`. This
//!   makes cargo's internal invocations (which never supply
//!   `--sysroot`) pick up the overlaid mirror, while letting an
//!   explicit `rustc --sysroot=…` caller bypass.
//!
//! - **`ws-clippy`**: cargo invokes `RUSTC_WORKSPACE_WRAPPER` as
//!   `<wrapper> <rustc_path> <args...>`. Drop the cargo-prepended
//!   `rustc_path`, set `SYSROOT=<mirror>` in the env, and re-drive
//!   `clippy-driver` with both `<mirror>/bin/rustc` and an explicit
//!   `--sysroot=<mirror>` arg. clippy-driver bakes its rustup env
//!   vars at compile time, so both the env var and the flag are
//!   required to override its baked-in sysroot view.
//!
//! - **`sancov-rustc`**: the `RUSTC_WORKSPACE_WRAPPER` of `cargo xtask
//!   fuzz`, whose `RUSTFLAGS` carry the `SanitizerCoverage` flags for every
//!   unit. Drop the cargo-prepended `rustc_path` and exec it, without
//!   those flags for a crate `SERAPH_SHIM_UNINSTRUMENTED` names (the
//!   fuzzing engine, whose callbacks the instrumentation calls).
//!
//! The first two modes read their configuration from three env vars set
//! by xtask before it invokes cargo. xtask is always the root of the process tree, so
//! the vars propagate naturally to every child cargo and rustc
//! spawn:
//!
//! - `SERAPH_SHIM_REAL_RUSTC` — absolute path to the real rustup
//!   rustc binary.
//! - `SERAPH_SHIM_REAL_CLIPPY` — absolute path to the real rustup
//!   clippy-driver binary.
//! - `SERAPH_SHIM_MIRROR_SYSROOT` — absolute path to the seraph
//!   toolchain mirror's root.

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, exit};

/// Env var: absolute path to the real rustup rustc binary.
const ENV_REAL_RUSTC: &str = "SERAPH_SHIM_REAL_RUSTC";

/// Env var: absolute path to the real rustup clippy-driver binary.
const ENV_REAL_CLIPPY: &str = "SERAPH_SHIM_REAL_CLIPPY";

/// Env var: absolute path to the seraph toolchain mirror root.
const ENV_MIRROR_SYSROOT: &str = "SERAPH_SHIM_MIRROR_SYSROOT";

/// Env var: comma-separated crate names `sancov-rustc` compiles without
/// `SanitizerCoverage`.
const ENV_UNINSTRUMENTED: &str = "SERAPH_SHIM_UNINSTRUMENTED";

fn main() -> !
{
    let mut argv = env::args_os();
    let Some(argv0) = argv.next()
    else
    {
        die("argv[0] missing (impossible per POSIX/Windows)")
    };
    let argv_rest: Vec<OsString> = argv.collect();

    let basename = Path::new(&argv0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();

    match basename
    {
        "rustc" => exec_rustc(argv_rest),
        "ws-clippy" => exec_ws_clippy(argv_rest),
        "sancov-rustc" => exec_sancov_rustc(argv_rest),
        other => die(&format!(
            "seraph-wrapper-shim: unknown install name {other:?} \
             (expected 'rustc', 'ws-clippy' or 'sancov-rustc')"
        )),
    }
}

/// Exec the real rustc with `--sysroot=<mirror>` prepended unless the
/// caller already supplied `--sysroot`. Never returns on success.
fn exec_rustc(args: Vec<OsString>) -> !
{
    let real = required_env_path(ENV_REAL_RUSTC);
    let mirror = required_env_path(ENV_MIRROR_SYSROOT);

    let has_sysroot = args.iter().any(|a| {
        let bytes = a.as_encoded_bytes();
        bytes == b"--sysroot" || bytes.starts_with(b"--sysroot=")
    });

    let mut cmd = Command::new(&real);
    if !has_sysroot
    {
        cmd.arg("--sysroot").arg(&mirror);
    }
    cmd.args(args);
    run_or_exec(cmd, "rustc")
}

/// Drop cargo's prepended `rustc_path` arg and re-drive clippy-driver
/// with both `SYSROOT` env and `--sysroot=` flag pointing at the
/// seraph mirror. Never returns on success.
fn exec_ws_clippy(mut args: Vec<OsString>) -> !
{
    let real_clippy = required_env_path(ENV_REAL_CLIPPY);
    let mirror = required_env_path(ENV_MIRROR_SYSROOT);

    if args.is_empty()
    {
        die(
            "ws-clippy: expected at least one arg (rustc_path injected by cargo's \
             RUSTC_WORKSPACE_WRAPPER)",
        );
    }
    args.remove(0);

    let mirror_rustc = mirror.join("bin").join("rustc");
    let sysroot_arg = format!("--sysroot={}", mirror.display());

    let mut cmd = Command::new(&real_clippy);
    cmd.env("SYSROOT", &mirror);
    cmd.arg(&mirror_rustc);
    cmd.arg(&sysroot_arg);
    cmd.args(args);
    run_or_exec(cmd, "clippy-driver")
}

/// Drop cargo's prepended `rustc_path` arg and exec it, without the
/// `SanitizerCoverage` flags when the unit's crate is one
/// `SERAPH_SHIM_UNINSTRUMENTED` names. Never returns on success.
fn exec_sancov_rustc(mut args: Vec<OsString>) -> !
{
    if args.is_empty()
    {
        die(
            "sancov-rustc: expected at least one arg (rustc_path injected by cargo's \
             RUSTC_WORKSPACE_WRAPPER)",
        );
    }
    let rustc = args.remove(0);
    let uninstrumented = env::var(ENV_UNINSTRUMENTED).unwrap_or_default();
    let mut cmd = Command::new(&rustc);
    cmd.args(unit_args(args, &uninstrumented));
    run_or_exec(cmd, "rustc")
}

/// The rustc arguments of a unit: `args` unchanged, or without the
/// `SanitizerCoverage` flags when `--crate-name` names a crate of the
/// comma-separated list `uninstrumented`.
fn unit_args(args: Vec<OsString>, uninstrumented: &str) -> Vec<OsString>
{
    let mut rest = args.iter();
    let crate_name = rest
        .by_ref()
        .find(|arg| *arg == "--crate-name")
        .and_then(|_| rest.next())
        .and_then(|name| name.to_str());
    let skip = crate_name.is_some_and(|name| uninstrumented.split(',').any(|s| s == name));
    if !skip
    {
        return args;
    }
    args.into_iter()
        .filter(|arg| {
            let bytes = arg.as_encoded_bytes();
            bytes != b"-Cpasses=sancov-module"
                && !bytes.starts_with(b"-Cllvm-args=-sanitizer-coverage-")
        })
        .collect()
}

/// Read a required env var and return it as a `PathBuf`. Dies with
/// a clear message naming the missing var if unset.
fn required_env_path(name: &str) -> PathBuf
{
    match env::var_os(name)
    {
        Some(v) if !v.is_empty() => PathBuf::from(v),
        _ => die(&format!(
            "seraph-wrapper-shim: required env var {name} is not set \
             (xtask should set this before invoking cargo)"
        )),
    }
}

/// Replace the current process with `cmd` on Unix (`exec(3)`) or
/// spawn-and-mirror-exit-code on Windows.
#[cfg(unix)]
fn run_or_exec(mut cmd: Command, label: &str) -> !
{
    use std::os::unix::process::CommandExt;
    let err = cmd.exec();
    die(&format!("seraph-wrapper-shim: exec {label} failed: {err}"));
}

#[cfg(not(unix))]
fn run_or_exec(mut cmd: Command, label: &str) -> !
{
    match cmd.status()
    {
        Ok(s) => exit(s.code().unwrap_or(2)),
        Err(e) => die(&format!("seraph-wrapper-shim: spawn {label} failed: {e}")),
    }
}

fn die(msg: &str) -> !
{
    eprintln!("{msg}");
    exit(2);
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn words(args: &[&str]) -> Vec<OsString>
    {
        args.iter().map(OsString::from).collect()
    }

    // Defect caught: the engine compiled with SanitizerCoverage, whose
    // callbacks would then call themselves, or a crate under test compiled
    // without it.
    #[test]
    fn only_a_listed_crate_loses_the_coverage_flags()
    {
        let unit = |name| {
            words(&[
                "--crate-name",
                name,
                "-Cpasses=sancov-module",
                "-Cllvm-args=-sanitizer-coverage-level=3",
                "-Cllvm-args=-other",
                "src/lib.rs",
            ])
        };
        let list = "fuzz_engine,___";
        assert_eq!(
            unit_args(unit("fuzz_engine"), list),
            words(&[
                "--crate-name",
                "fuzz_engine",
                "-Cllvm-args=-other",
                "src/lib.rs"
            ])
        );
        assert_eq!(unit_args(unit("vfsd_gpt"), list), unit("vfsd_gpt"));
        assert_eq!(unit_args(unit("fuzz"), list), unit("fuzz"));
        assert_eq!(unit_args(words(&["-vV"]), list), words(&["-vV"]));
    }
}
