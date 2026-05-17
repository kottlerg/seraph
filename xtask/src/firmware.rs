// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! firmware.rs
//!
//! Host-side discovery of QEMU pflash firmware images.
//!
//! Two firmware surfaces are needed by the launch flow:
//!
//! - **OVMF (x86-64)** — a single readonly code image. x86 launches with
//!   volatile NVRAM and don't ship a writable vars file.
//! - **EDK2 RISC-V (riscv64)** — a paired (code, vars) source. The
//!   readonly code image plus a vars template that is copied per-launch
//!   into a writable pflash file.
//!
//! Discovery is env-var-first, then per-`cfg(target_os)` default path
//! tables, then a structured error that enumerates the tried paths and
//! the install commands for every supported host. The env vars
//! (`SERAPH_OVMF_CODE`, `SERAPH_RISCV_CODE`, `SERAPH_RISCV_VARS`)
//! exist for hosts that don't follow FHS conventions (NixOS, macOS,
//! Windows, custom builds) and override the default search entirely
//! when set.
//!
//! Padding and per-launch caching of the discovered images stays in
//! `qemu.rs::prepare_riscv_firmware` — this module is pure discovery.

use std::path::PathBuf;

use anyhow::{Result, anyhow};

// ── Default search tables ────────────────────────────────────────────────────

/// OVMF code-image search paths (x86-64). First existing path wins.
#[cfg(target_os = "linux")]
const OVMF_CODE_DEFAULTS: &[&str] = &[
    "/usr/share/edk2/ovmf/OVMF_CODE.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
];

#[cfg(target_os = "macos")]
const OVMF_CODE_DEFAULTS: &[&str] = &[
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
    "/usr/local/share/qemu/edk2-x86_64-code.fd",
];

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const OVMF_CODE_DEFAULTS: &[&str] = &[
    "/usr/local/share/qemu/edk2-x86_64-code.fd",
    "/usr/local/share/uefi-firmware/edk2-x86_64-code.fd",
];

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
)))]
const OVMF_CODE_DEFAULTS: &[&str] = &[];

/// EDK2 RISC-V firmware directories (riscv64). The first directory
/// containing `RISCV_VIRT_CODE.fd` is used as the source of both the
/// code image and the vars template, unless `SERAPH_RISCV_CODE` /
/// `SERAPH_RISCV_VARS` override per-file.
#[cfg(target_os = "linux")]
const RISCV_FIRMWARE_DIRS: &[&str] = &[
    "/usr/share/edk2/riscv",
    "/usr/share/edk2-riscv",
    "/usr/share/qemu-efi-riscv64",
];

#[cfg(target_os = "macos")]
const RISCV_FIRMWARE_DIRS: &[&str] = &["/opt/homebrew/share/qemu", "/usr/local/share/qemu"];

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const RISCV_FIRMWARE_DIRS: &[&str] = &["/usr/local/share/qemu", "/usr/local/share/uefi-firmware"];

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
)))]
const RISCV_FIRMWARE_DIRS: &[&str] = &[];

// ── Public discovery API ─────────────────────────────────────────────────────

/// Env var that, when set, overrides the OVMF code-image search with a
/// direct path.
pub const ENV_OVMF_CODE: &str = "SERAPH_OVMF_CODE";

/// Env var that, when set, overrides the RISC-V code-image search with
/// a direct path.
pub const ENV_RISCV_CODE: &str = "SERAPH_RISCV_CODE";

/// Env var that, when set, overrides the RISC-V vars-template search
/// with a direct path.
pub const ENV_RISCV_VARS: &str = "SERAPH_RISCV_VARS";

/// Locate the OVMF code image.
///
/// Resolution order: `$SERAPH_OVMF_CODE`, then `OVMF_CODE_DEFAULTS`
/// for the current `target_os`. On miss, returns a structured error
/// enumerating the tried paths and install commands for every
/// supported host.
pub fn find_ovmf_code() -> Result<PathBuf>
{
    find_path(
        ENV_OVMF_CODE,
        OVMF_CODE_DEFAULTS,
        "OVMF code firmware (x86-64)",
        OVMF_INSTALL_HINTS,
    )
}

/// Locate the RISC-V EDK2 source images, returning `(code, vars)`.
///
/// Per-file env vars `SERAPH_RISCV_CODE` and `SERAPH_RISCV_VARS`
/// override the directory search; when both are set, no directory
/// search runs. When neither is set, the first directory containing
/// `RISCV_VIRT_CODE.fd` and `RISCV_VIRT_VARS.fd` is used as the
/// source of both. When exactly one is set, the directory search
/// resolves the unset one.
pub fn find_riscv_firmware() -> Result<(PathBuf, PathBuf)>
{
    let env_code = std::env::var_os(ENV_RISCV_CODE).map(PathBuf::from);
    let env_vars = std::env::var_os(ENV_RISCV_VARS).map(PathBuf::from);

    if let (Some(code), Some(vars)) = (env_code.as_ref(), env_vars.as_ref())
    {
        return Ok((code.clone(), vars.clone()));
    }

    let dir = find_riscv_firmware_dir()?;
    let code = env_code.unwrap_or_else(|| dir.join("RISCV_VIRT_CODE.fd"));
    let vars = env_vars.unwrap_or_else(|| dir.join("RISCV_VIRT_VARS.fd"));

    if !code.is_file()
    {
        return Err(missing_file_error("RISC-V code firmware", &code));
    }
    if !vars.is_file()
    {
        return Err(missing_file_error("RISC-V vars template", &vars));
    }
    Ok((code, vars))
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Resolve a single firmware file path: env var first, then default
/// list, then structured error.
fn find_path(env_var: &str, defaults: &[&str], label: &str, hints: &str) -> Result<PathBuf>
{
    if let Some(value) = std::env::var_os(env_var)
    {
        let path = PathBuf::from(value);
        if path.is_file()
        {
            return Ok(path);
        }
        return Err(anyhow!(
            "{label} not found: ${env_var}={path} does not exist",
            path = path.display(),
        ));
    }

    for candidate in defaults
    {
        let path = PathBuf::from(candidate);
        if path.is_file()
        {
            return Ok(path);
        }
    }

    Err(not_found_error(label, env_var, defaults, hints))
}

/// Locate the RISC-V firmware *directory* (containing
/// `RISCV_VIRT_CODE.fd`). Used by `find_riscv_firmware` only when at
/// least one of the per-file env vars is unset.
fn find_riscv_firmware_dir() -> Result<PathBuf>
{
    for dir in RISCV_FIRMWARE_DIRS
    {
        let candidate = PathBuf::from(dir);
        if candidate.join("RISCV_VIRT_CODE.fd").is_file()
        {
            return Ok(candidate);
        }
    }
    Err(not_found_error(
        "RISC-V EDK2 firmware directory",
        ENV_RISCV_CODE,
        RISCV_FIRMWARE_DIRS,
        RISCV_INSTALL_HINTS,
    ))
}

/// Build the standard "not found" error: label, env-var instruction,
/// tried-paths list, per-platform install hints.
fn not_found_error(label: &str, env_var: &str, tried: &[&str], hints: &str) -> anyhow::Error
{
    let mut msg = format!("{label} not found");
    msg.push_str("\n\nTried (none existed):\n");
    if tried.is_empty()
    {
        msg.push_str("  (no default paths registered for this host OS)\n");
    }
    else
    {
        for p in tried
        {
            msg.push_str("  ");
            msg.push_str(p);
            msg.push('\n');
        }
    }
    msg.push_str(&format!(
        "\nSet ${env_var} to a direct path, or install the firmware:\n",
    ));
    msg.push_str(hints);
    anyhow!(msg)
}

/// Build the "env var set but file missing" error.
fn missing_file_error(label: &str, path: &std::path::Path) -> anyhow::Error
{
    anyhow!("{label} not found at resolved path: {}", path.display(),)
}

/// Per-platform install hints for OVMF.
const OVMF_INSTALL_HINTS: &str = "  Fedora:           dnf install edk2-ovmf\n  \
                                  Debian / Ubuntu:  apt install ovmf\n  \
                                  Arch:             pacman -S edk2-ovmf\n  \
                                  macOS (Homebrew): brew install qemu\n  \
                                  FreeBSD:          pkg install edk2-qemu-x64\n  \
                                  Windows:          set SERAPH_OVMF_CODE to a direct path\n";

/// Per-platform install hints for the EDK2 RISC-V firmware.
const RISCV_INSTALL_HINTS: &str = "  Fedora:           dnf install edk2-riscv64\n  \
                                   Debian / Ubuntu:  apt install qemu-efi-riscv64\n  \
                                   Arch:             extract the Fedora edk2-riscv64 RPM\n  \
                                                     (RISCV_VIRT_CODE.fd + RISCV_VIRT_VARS.fd)\n  \
                                                     into /usr/share/edk2/riscv/\n  \
                                   macOS (Homebrew): brew install qemu\n  \
                                   FreeBSD:          pkg install edk2-qemu-riscv64\n  \
                                   Windows:          set SERAPH_RISCV_CODE and SERAPH_RISCV_VARS\n";

#[cfg(test)]
mod tests
{
    use super::*;

    /// Helper: run `f` with an env var set, then restore. Avoids
    /// cross-test pollution because each test owns one env var
    /// exclusively for the duration of the call.
    fn with_env_var<F: FnOnce()>(key: &str, value: &str, f: F)
    {
        let prev = std::env::var_os(key);
        // SAFETY: cargo runs tests serialized per process by default
        // only for `--test-threads=1`; multi-threaded tests sharing
        // env vars is racy. The two env-var tests here use distinct
        // keys to minimize interaction, but a reader of these tests
        // should know that the underlying env mutation is
        // process-global. Acceptable for xtask's small test surface.
        unsafe {
            std::env::set_var(key, value);
        }
        f();
        unsafe {
            match prev
            {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }

    #[test]
    fn env_var_override_pointing_at_missing_file_returns_error()
    {
        with_env_var(ENV_OVMF_CODE, "/nonexistent/firmware/path.fd", || {
            let err = find_ovmf_code().unwrap_err();
            let msg = format!("{err:#}");
            assert!(
                msg.contains("SERAPH_OVMF_CODE"),
                "error should name the env var: {msg}",
            );
            assert!(
                msg.contains("/nonexistent/firmware/path.fd"),
                "error should include the bad path: {msg}",
            );
        });
    }

    #[test]
    fn env_var_override_pointing_at_existing_file_succeeds()
    {
        // Cargo.toml is a known-existing file in the workspace.
        let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("Cargo.toml");
        let workspace_str = workspace.to_str().unwrap();
        with_env_var(ENV_OVMF_CODE, workspace_str, || {
            let resolved = find_ovmf_code().unwrap();
            assert_eq!(resolved, workspace);
        });
    }

    #[test]
    fn riscv_firmware_with_both_env_vars_skips_directory_search()
    {
        let workspace_cargo = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("Cargo.toml");
        let path = workspace_cargo.to_str().unwrap();
        with_env_var(ENV_RISCV_CODE, path, || {
            with_env_var(ENV_RISCV_VARS, path, || {
                let (code, vars) = find_riscv_firmware().unwrap();
                assert_eq!(code, workspace_cargo);
                assert_eq!(vars, workspace_cargo);
            });
        });
    }
}
