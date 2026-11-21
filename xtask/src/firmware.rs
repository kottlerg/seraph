// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/firmware.rs

//! Host-side discovery of QEMU pflash firmware images.
//!
//! Each architecture's firmware is a pair of images from one EDK2 build: the
//! read-only code image and the template of its variable store, which every
//! launch copies into a writable pflash file of its own
//! (`qemu::Firmware::launch_vars`):
//!
//! - **OVMF (x86-64)**: `OVMF_CODE` and `OVMF_VARS` in the distribution's
//!   naming.
//! - **EDK2 RISC-V (riscv64)**: `RISCV_VIRT_CODE.fd` and
//!   `RISCV_VIRT_VARS.fd`.
//!
//! The Secure Boot boots (`cargo xtask test secureboot`) take a pair of their
//! own ([`find_secure_boot_firmware`]): a build that enforces Secure Boot,
//! which neither architecture's default pair is on every host (x86-64's
//! default OVMF is built without Secure Boot, and only some RISC-V EDK2
//! builds have it; docs/build-system.md § QEMU and Firmware).
//!
//! Discovery is env-var-first, then per-`cfg(target_os)` default path
//! tables, then a structured error that enumerates the tried paths and
//! the install commands for every supported host. The env vars
//! (`SERAPH_OVMF_CODE` with `SERAPH_OVMF_VARS`, `SERAPH_RISCV_CODE` with
//! `SERAPH_RISCV_VARS`) exist for hosts that don't follow FHS conventions
//! (NixOS, macOS, Windows, custom builds) and, set together, override the
//! default search entirely.
//!
//! Padding, caching and the per-launch copies of the discovered images stay
//! in `qemu.rs::prepare_firmware` — this module is pure discovery.

use std::ffi::OsStr;
use std::fmt::Write;
use std::path::PathBuf;

use crate::error::{Result, err};

// ── Default search tables ────────────────────────────────────────────────────

/// OVMF images (x86-64): each entry the code image and the variable-store
/// template of one firmware build, which QEMU takes as a pair. The first
/// entry whose two files exist wins.
#[cfg(target_os = "linux")]
const OVMF_DEFAULTS: &[(&str, &str)] = &[
    // Debian and Ubuntu.
    (
        "/usr/share/OVMF/OVMF_CODE_4M.fd",
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
    ),
    // Fedora.
    (
        "/usr/share/edk2/ovmf/OVMF_CODE.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    ),
    // Arch.
    (
        "/usr/share/edk2/x64/OVMF_CODE.4m.fd",
        "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
    ),
    // Older Arch.
    (
        "/usr/share/edk2-ovmf/x64/OVMF_CODE.fd",
        "/usr/share/edk2-ovmf/x64/OVMF_VARS.fd",
    ),
    // Older Debian and Ubuntu.
    (
        "/usr/share/OVMF/OVMF_CODE.fd",
        "/usr/share/OVMF/OVMF_VARS.fd",
    ),
];

#[cfg(target_os = "macos")]
const OVMF_DEFAULTS: &[(&str, &str)] = &[
    (
        "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
        "/opt/homebrew/share/qemu/edk2-i386-vars.fd",
    ),
    (
        "/usr/local/share/qemu/edk2-x86_64-code.fd",
        "/usr/local/share/qemu/edk2-i386-vars.fd",
    ),
];

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const OVMF_DEFAULTS: &[(&str, &str)] = &[(
    "/usr/local/share/qemu/edk2-x86_64-code.fd",
    "/usr/local/share/qemu/edk2-i386-vars.fd",
)];

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
)))]
const OVMF_DEFAULTS: &[(&str, &str)] = &[];

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

/// OVMF images with Secure Boot (x86-64): the SMM build each distribution
/// ships beside the default one, which QEMU runs with SMM, and the default
/// variable-store template. The first entry whose two files exist wins.
#[cfg(target_os = "linux")]
const OVMF_SECURE_DEFAULTS: &[(&str, &str)] = &[
    // Debian and Ubuntu.
    (
        "/usr/share/OVMF/OVMF_CODE_4M.secboot.fd",
        "/usr/share/OVMF/OVMF_VARS_4M.fd",
    ),
    // Fedora.
    (
        "/usr/share/edk2/ovmf/OVMF_CODE.secboot.fd",
        "/usr/share/edk2/ovmf/OVMF_VARS.fd",
    ),
    // Arch.
    (
        "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd",
        "/usr/share/edk2/x64/OVMF_VARS.4m.fd",
    ),
];

#[cfg(target_os = "macos")]
const OVMF_SECURE_DEFAULTS: &[(&str, &str)] = &[
    (
        "/opt/homebrew/share/qemu/edk2-x86_64-secure-code.fd",
        "/opt/homebrew/share/qemu/edk2-i386-vars.fd",
    ),
    (
        "/usr/local/share/qemu/edk2-x86_64-secure-code.fd",
        "/usr/local/share/qemu/edk2-i386-vars.fd",
    ),
];

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
))]
const OVMF_SECURE_DEFAULTS: &[(&str, &str)] = &[(
    "/usr/local/share/qemu/edk2-x86_64-secure-code.fd",
    "/usr/local/share/qemu/edk2-i386-vars.fd",
)];

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
)))]
const OVMF_SECURE_DEFAULTS: &[(&str, &str)] = &[];

/// RISC-V EDK2 images with Secure Boot (riscv64): the builds known to enforce
/// it. Arch's `edk2-riscv64` does; Debian's and Ubuntu's
/// `qemu-efi-riscv64` and Fedora's `edk2-riscv64` are built without it.
#[cfg(target_os = "linux")]
const RISCV_SECURE_DEFAULTS: &[(&str, &str)] = &[(
    "/usr/share/edk2/riscv64/RISCV_VIRT_CODE.fd",
    "/usr/share/edk2/riscv64/RISCV_VIRT_VARS.fd",
)];

#[cfg(not(target_os = "linux"))]
const RISCV_SECURE_DEFAULTS: &[(&str, &str)] = &[];

// ── Public discovery API ─────────────────────────────────────────────────────

/// Env var that, set together with [`ENV_OVMF_VARS`], names the OVMF code
/// image in place of the search.
pub const ENV_OVMF_CODE: &str = "SERAPH_OVMF_CODE";

/// Env var that, set together with [`ENV_OVMF_CODE`], names the OVMF
/// variable-store template in place of the search.
pub const ENV_OVMF_VARS: &str = "SERAPH_OVMF_VARS";

/// Env var that, set together with [`ENV_RISCV_VARS`], names the RISC-V code
/// image in place of the search.
pub const ENV_RISCV_CODE: &str = "SERAPH_RISCV_CODE";

/// Env var that, set together with [`ENV_RISCV_CODE`], names the RISC-V
/// variable-store template in place of the search.
pub const ENV_RISCV_VARS: &str = "SERAPH_RISCV_VARS";

/// Env var that, set together with [`ENV_OVMF_SECURE_VARS`], names the OVMF
/// Secure Boot code image in place of the search.
pub const ENV_OVMF_SECURE_CODE: &str = "SERAPH_OVMF_SECURE_CODE";

/// Env var that, set together with [`ENV_OVMF_SECURE_CODE`], names its
/// variable-store template.
pub const ENV_OVMF_SECURE_VARS: &str = "SERAPH_OVMF_SECURE_VARS";

/// Env var that, set together with [`ENV_RISCV_SECURE_VARS`], names a RISC-V
/// code image built with Secure Boot in place of the search.
pub const ENV_RISCV_SECURE_CODE: &str = "SERAPH_RISCV_SECURE_CODE";

/// Env var that, set together with [`ENV_RISCV_SECURE_CODE`], names its
/// variable-store template.
pub const ENV_RISCV_SECURE_VARS: &str = "SERAPH_RISCV_SECURE_VARS";

/// Locate `arch`'s Secure Boot firmware, returning `(code, vars)`: on x86-64
/// an OVMF build that requires SMM, which QEMU must run with SMM
/// (`QemuLaunchSpec::smm`), and on riscv64 an EDK2 build with Secure Boot.
///
/// The env pair (`SERAPH_OVMF_SECURE_CODE` with `SERAPH_OVMF_SECURE_VARS`,
/// `SERAPH_RISCV_SECURE_CODE` with `SERAPH_RISCV_SECURE_VARS`) is
/// all-or-nothing, as the default pairs' are; when neither is set, the first
/// default entry whose two files exist is used. Whether the pair found
/// enforces Secure Boot is the caller's to test: a firmware built without it
/// boots any image.
pub fn find_secure_boot_firmware(arch: crate::arch::Arch) -> Result<(PathBuf, PathBuf)>
{
    use crate::arch::Arch;
    let (code_var, vars_var) = match arch
    {
        Arch::X86_64 => (ENV_OVMF_SECURE_CODE, ENV_OVMF_SECURE_VARS),
        Arch::Riscv64 => (ENV_RISCV_SECURE_CODE, ENV_RISCV_SECURE_VARS),
    };
    find_secure_boot_firmware_impl(
        arch,
        std::env::var_os(code_var).as_deref(),
        std::env::var_os(vars_var).as_deref(),
    )
}

/// Implementation core of [`find_secure_boot_firmware`], parameterized on the
/// env values as the others are.
fn find_secure_boot_firmware_impl(
    arch: crate::arch::Arch,
    env_code: Option<&OsStr>,
    env_vars: Option<&OsStr>,
) -> Result<(PathBuf, PathBuf)>
{
    use crate::arch::Arch;
    let (label, code_var, vars_var, defaults, hints) = match arch
    {
        Arch::X86_64 => (
            "OVMF firmware with Secure Boot (x86-64)",
            ENV_OVMF_SECURE_CODE,
            ENV_OVMF_SECURE_VARS,
            OVMF_SECURE_DEFAULTS,
            OVMF_SECURE_INSTALL_HINTS,
        ),
        Arch::Riscv64 => (
            "RISC-V EDK2 firmware with Secure Boot (riscv64)",
            ENV_RISCV_SECURE_CODE,
            ENV_RISCV_SECURE_VARS,
            RISCV_SECURE_DEFAULTS,
            RISCV_SECURE_INSTALL_HINTS,
        ),
    };
    if let Some(pair) = env_pair(env_code, env_vars, code_var, vars_var)?
    {
        return Ok(pair);
    }
    for (code, vars) in defaults
    {
        let (code, vars) = (PathBuf::from(code), PathBuf::from(vars));
        if code.is_file() && vars.is_file()
        {
            return Ok((code, vars));
        }
    }
    let tried: Vec<String> = defaults
        .iter()
        .map(|(code, vars)| format!("{code} with {vars}"))
        .collect();
    let tried: Vec<&str> = tried.iter().map(String::as_str).collect();
    Err(not_found_error(label, code_var, vars_var, &tried, hints))
}

/// Locate the OVMF images, returning `(code, vars)`.
///
/// `SERAPH_OVMF_CODE` and `SERAPH_OVMF_VARS` are all-or-nothing, as the
/// RISC-V pair is ([`find_riscv_firmware`]). When neither is set, the first
/// entry of `OVMF_DEFAULTS` for the current `target_os` whose two files
/// exist is used; on a miss, a structured error enumerates the tried paths
/// and the install commands for every supported host.
pub fn find_ovmf_firmware() -> Result<(PathBuf, PathBuf)>
{
    find_ovmf_firmware_impl(
        std::env::var_os(ENV_OVMF_CODE).as_deref(),
        std::env::var_os(ENV_OVMF_VARS).as_deref(),
    )
}

/// Locate the RISC-V EDK2 source images, returning `(code, vars)`.
///
/// Per-file env vars `SERAPH_RISCV_CODE` and `SERAPH_RISCV_VARS` are
/// all-or-nothing: setting only one is an error, because the code
/// image and vars template must come from the same firmware build —
/// pairing a custom code image with the system vars template (or
/// vice versa) silently corrupts NVRAM state. When both are set,
/// no directory search runs; when neither is set, the first
/// directory containing both files is used.
pub fn find_riscv_firmware() -> Result<(PathBuf, PathBuf)>
{
    find_riscv_firmware_impl(
        std::env::var_os(ENV_RISCV_CODE).as_deref(),
        std::env::var_os(ENV_RISCV_VARS).as_deref(),
    )
}

/// Implementation core of `find_ovmf_firmware`, parameterized on the env
/// values so tests can exercise the env-override paths without mutating
/// process-global env state.
fn find_ovmf_firmware_impl(
    env_code: Option<&OsStr>,
    env_vars: Option<&OsStr>,
) -> Result<(PathBuf, PathBuf)>
{
    if let Some(pair) = env_pair(env_code, env_vars, ENV_OVMF_CODE, ENV_OVMF_VARS)?
    {
        return Ok(pair);
    }
    for (code, vars) in OVMF_DEFAULTS
    {
        let (code, vars) = (PathBuf::from(code), PathBuf::from(vars));
        if code.is_file() && vars.is_file()
        {
            return Ok((code, vars));
        }
    }
    let tried: Vec<String> = OVMF_DEFAULTS
        .iter()
        .map(|(code, vars)| format!("{code} with {vars}"))
        .collect();
    let tried: Vec<&str> = tried.iter().map(String::as_str).collect();
    Err(not_found_error(
        "OVMF firmware (x86-64)",
        ENV_OVMF_CODE,
        ENV_OVMF_VARS,
        &tried,
        OVMF_INSTALL_HINTS,
    ))
}

/// Implementation core of `find_riscv_firmware`, parameterized on
/// the env values so tests can exercise the env-override paths
/// without mutating process-global env state.
fn find_riscv_firmware_impl(
    env_code: Option<&OsStr>,
    env_vars: Option<&OsStr>,
) -> Result<(PathBuf, PathBuf)>
{
    if let Some(pair) = env_pair(env_code, env_vars, ENV_RISCV_CODE, ENV_RISCV_VARS)?
    {
        return Ok(pair);
    }
    let dir = find_riscv_firmware_dir()?;
    let code = dir.join("RISCV_VIRT_CODE.fd");
    let vars = dir.join("RISCV_VIRT_VARS.fd");
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

/// The `(code, vars)` pair the two env values name, `None` when neither is
/// set.
///
/// # Errors
/// When only one is set, since a code image and a vars template from two
/// firmware builds silently corrupt the variable store, or when either
/// names no file.
fn env_pair(
    env_code: Option<&OsStr>,
    env_vars: Option<&OsStr>,
    code_var: &str,
    vars_var: &str,
) -> Result<Option<(PathBuf, PathBuf)>>
{
    match (env_code.map(PathBuf::from), env_vars.map(PathBuf::from))
    {
        (Some(code), Some(vars)) =>
        {
            if !code.is_file()
            {
                return Err(missing_env_path_error(code_var, &code));
            }
            if !vars.is_file()
            {
                return Err(missing_env_path_error(vars_var, &vars));
            }
            Ok(Some((code, vars)))
        }
        (Some(_), None) | (None, Some(_)) => Err(err!(
            "${code_var} and ${vars_var} must be set together (or both left unset). Pairing a \
             custom code image with a system vars template (or vice versa) silently corrupts \
             NVRAM state."
        )),
        (None, None) => Ok(None),
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

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
        ENV_RISCV_VARS,
        RISCV_FIRMWARE_DIRS,
        RISCV_INSTALL_HINTS,
    ))
}

/// Build the standard "not found" error: label, env-var instruction,
/// tried-paths list, per-platform install hints.
fn not_found_error(
    label: &str,
    code_var: &str,
    vars_var: &str,
    tried: &[&str],
    hints: &str,
) -> crate::error::Error
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
    let _ = write!(
        msg,
        "\nSet ${code_var} and ${vars_var} to direct paths, or install the firmware:\n"
    );
    msg.push_str(hints);
    err!(msg)
}

/// Build the "discovered file missing" error.
fn missing_file_error(label: &str, path: &std::path::Path) -> crate::error::Error
{
    err!("{label} not found at resolved path: {}", path.display())
}

/// Build the "env var set to a path that doesn't exist" error.
/// Names the env var so the user can fix or unset it.
fn missing_env_path_error(env_var: &str, path: &std::path::Path) -> crate::error::Error
{
    err!(
        "${env_var}={} does not exist; unset {env_var} to fall back to default search",
        path.display(),
    )
}

/// Per-platform install hints for OVMF.
const OVMF_INSTALL_HINTS: &str = "  Fedora:           dnf install edk2-ovmf\n  \
                                  Debian / Ubuntu:  apt install ovmf\n  \
                                  Arch:             pacman -S edk2-ovmf\n  \
                                  macOS (Homebrew): brew install qemu\n  \
                                  FreeBSD:          pkg install edk2-qemu-x64\n  \
                                  Windows:          set SERAPH_OVMF_CODE and SERAPH_OVMF_VARS\n";

/// Per-platform install hints for the OVMF Secure Boot build.
const OVMF_SECURE_INSTALL_HINTS: &str = "  The SMM Secure Boot build ships with the default one:\n  \
                                         Fedora:           dnf install edk2-ovmf\n  \
                                         Debian / Ubuntu:  apt install ovmf\n  \
                                         Arch:             pacman -S edk2-ovmf\n  \
                                         macOS (Homebrew): brew install qemu\n";

/// Per-platform install hints for a RISC-V EDK2 build with Secure Boot.
const RISCV_SECURE_INSTALL_HINTS: &str = "  Only some builds have Secure Boot (docs/build-system.md § QEMU and \
                                          Firmware):\n  \
                                          Arch:      pacman -S edk2-riscv64 (built with it)\n  \
                                          Any host:  set SERAPH_RISCV_SECURE_CODE and \
                                          SERAPH_RISCV_SECURE_VARS to the two images of Arch's \
                                          edk2-riscv64, or of an EDK2 RiscVVirtQemu build with \
                                          SECURE_BOOT_ENABLE\n  \
                                          Not these: Debian and Ubuntu qemu-efi-riscv64, Fedora \
                                          edk2-riscv64 (built without it)\n";

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

    /// A known-existing file inside the workspace, used as a stand-in
    /// for a real firmware image in env-override tests.
    fn existing_workspace_file() -> PathBuf
    {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("Cargo.toml")
    }

    #[test]
    fn env_var_override_pointing_at_missing_file_returns_error()
    {
        let bogus = OsStr::new("/nonexistent/firmware/path.fd");
        let workspace = existing_workspace_file();
        let err = find_ovmf_firmware_impl(Some(bogus), Some(workspace.as_os_str())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("SERAPH_OVMF_CODE"),
            "error should name the env var: {msg}",
        );
        assert!(
            msg.contains("/nonexistent/firmware/path.fd"),
            "error should include the bad path: {msg}",
        );
        let err = find_ovmf_firmware_impl(Some(workspace.as_os_str()), Some(bogus)).unwrap_err();
        assert!(
            format!("{err:#}").contains("SERAPH_OVMF_VARS"),
            "error should name the vars env var: {err:#}",
        );
    }

    #[test]
    fn env_var_override_pointing_at_existing_files_succeeds()
    {
        let workspace = existing_workspace_file();
        let os = workspace.as_os_str();
        let (code, vars) = find_ovmf_firmware_impl(Some(os), Some(os)).unwrap();
        assert_eq!(code, workspace);
        assert_eq!(vars, workspace);
    }

    // Defect caught: an OVMF code image paired with the system's vars template
    // from another build, which silently corrupts the variable store the
    // security floor lives in.
    #[test]
    fn ovmf_firmware_with_one_env_var_set_is_rejected()
    {
        let workspace = existing_workspace_file();
        let os = workspace.as_os_str();
        for (code, vars) in [(Some(os), None), (None, Some(os))]
        {
            let msg = format!("{:#}", find_ovmf_firmware_impl(code, vars).unwrap_err());
            assert!(
                msg.contains("must be set together"),
                "expected pairing-error, got: {msg}",
            );
        }
    }

    // Defect caught: a Secure Boot pair taken from one env var and a default
    // path, or the default (non-enforcing) pair returned in its place, so the
    // Secure Boot boots run on a firmware that verifies nothing.
    #[test]
    fn secure_boot_firmware_takes_its_own_env_pair()
    {
        use crate::arch::Arch;
        let workspace = existing_workspace_file();
        let os = workspace.as_os_str();
        for arch in [Arch::X86_64, Arch::Riscv64]
        {
            let (code, vars) = find_secure_boot_firmware_impl(arch, Some(os), Some(os)).unwrap();
            assert_eq!((code, vars), (workspace.clone(), workspace.clone()));
            for (code, vars) in [(Some(os), None), (None, Some(os))]
            {
                let msg = format!(
                    "{:#}",
                    find_secure_boot_firmware_impl(arch, code, vars).unwrap_err()
                );
                assert!(msg.contains("must be set together"), "{msg}");
            }
        }
        for (code, _) in OVMF_SECURE_DEFAULTS.iter().chain(RISCV_SECURE_DEFAULTS)
        {
            assert!(
                !OVMF_DEFAULTS.iter().any(|(default, _)| default == code),
                "{code} is a default (non-enforcing) image"
            );
        }
    }

    #[test]
    fn riscv_firmware_with_both_env_vars_skips_directory_search()
    {
        let workspace = existing_workspace_file();
        let os = workspace.as_os_str();
        let (code, vars) = find_riscv_firmware_impl(Some(os), Some(os)).unwrap();
        assert_eq!(code, workspace);
        assert_eq!(vars, workspace);
    }

    #[test]
    fn riscv_firmware_with_only_code_env_var_set_is_rejected()
    {
        // Setting only SERAPH_RISCV_CODE (without the matching VARS)
        // would silently pair a custom code image against the system
        // vars template — a real footgun. Require both or neither.
        let workspace = existing_workspace_file();
        let err = find_riscv_firmware_impl(Some(workspace.as_os_str()), None).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("must be set together"),
            "expected pairing-error, got: {msg}",
        );
    }

    #[test]
    fn riscv_firmware_with_only_vars_env_var_set_is_rejected()
    {
        let workspace = existing_workspace_file();
        let err = find_riscv_firmware_impl(None, Some(workspace.as_os_str())).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("must be set together"),
            "expected pairing-error, got: {msg}",
        );
    }
}
