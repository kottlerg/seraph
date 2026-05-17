// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! accel.rs
//!
//! Per-host QEMU acceleration-backend selection.
//!
//! `Accel` enumerates the same-architecture accelerators QEMU supports:
//! KVM (Linux), HVF (macOS), WHPX (Windows), NVMM (NetBSD), and the
//! always-available TCG software emulator. Selection is env-var-first
//! (`SERAPH_ACCEL`), then per-`cfg(target_os)` detection, then a TCG
//! fallback for hosts without a registered native accelerator.
//!
//! Scope: cross-architecture emulation (e.g. riscv64 guest on x86_64
//! host) only ever has TCG available; this module's detection routines
//! report the *host's* native accelerator, and a guest of a different
//! arch is resolved to `Tcg` via `detect_for_arch`. The current Seraph
//! launch flow uses native acceleration only for x86_64 guests on
//! x86_64 hosts; everything else (riscv64 guest on any host, x86_64
//! guest on a non-x86_64 host) uses TCG.
//!
//! Env var:
//!
//! - `SERAPH_ACCEL = auto | tcg | kvm | hvf | whpx | nvmm` — override
//!   automatic detection. Unknown values fall through to detection,
//!   silently. `auto` is the documented "do detection" sentinel.

use crate::arch::Arch;

/// Acceleration backend for one QEMU launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accel
{
    /// Linux KVM (`/dev/kvm`). Same-arch only.
    Kvm,
    /// macOS Hypervisor.framework. Same-arch only.
    Hvf,
    /// Windows Hyper-V Platform. Same-arch only.
    Whpx,
    /// NetBSD Native VM Monitor (`/dev/nvmm`). Same-arch only.
    Nvmm,
    /// QEMU TCG software emulation. Universal; only choice for
    /// cross-architecture guests.
    Tcg,
}

/// Env var name that overrides automatic detection.
pub const ENV_ACCEL: &str = "SERAPH_ACCEL";

/// Select an acceleration backend for a guest of the given
/// architecture. Cross-arch guests resolve to `Tcg`; same-arch
/// guests honor `SERAPH_ACCEL` and per-`cfg(target_os)` detection.
pub fn detect_for_arch(arch: Arch) -> Accel
{
    if !is_same_arch(arch)
    {
        return Accel::Tcg;
    }

    if let Some(value) = std::env::var_os(ENV_ACCEL)
    {
        let s = value.to_string_lossy();
        if let Some(parsed) = parse_explicit(&s)
        {
            return parsed;
        }
    }

    detect_default()
}

/// Returns true when the guest architecture matches the host
/// architecture, i.e. when native acceleration could in principle
/// apply.
fn is_same_arch(arch: Arch) -> bool
{
    match arch
    {
        Arch::X86_64 => cfg!(target_arch = "x86_64"),
        Arch::Riscv64 => cfg!(target_arch = "riscv64"),
    }
}

/// Parse a user-provided env-var value into an `Accel`. Returns
/// `None` for the documented `auto` sentinel and for unknown values
/// (both trigger detection).
fn parse_explicit(s: &str) -> Option<Accel>
{
    match s.trim().to_ascii_lowercase().as_str()
    {
        "auto" => None,
        "kvm" => Some(Accel::Kvm),
        "hvf" => Some(Accel::Hvf),
        "whpx" => Some(Accel::Whpx),
        "nvmm" => Some(Accel::Nvmm),
        "tcg" => Some(Accel::Tcg),
        _ => None,
    }
}

// ── Per-host detection ───────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn detect_default() -> Accel
{
    // /dev/kvm existence is not sufficient — runner users on CI may
    // not be in the kvm group, so `open(O_RDWR)` returns EACCES and
    // QEMU exits. Probe the same way QEMU itself does.
    let usable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok();
    if usable { Accel::Kvm } else { Accel::Tcg }
}

#[cfg(target_os = "macos")]
fn detect_default() -> Accel
{
    // HVF is part of macOS 10.10+. There's no cheap probe from Rust;
    // QEMU itself errors clearly if launch fails. Set
    // SERAPH_ACCEL=tcg to opt out.
    Accel::Hvf
}

#[cfg(target_os = "windows")]
fn detect_default() -> Accel
{
    // WHPX requires Windows 10+ with the Hyper-V Platform feature
    // enabled. Same as macOS: no cheap probe; QEMU itself errors
    // clearly on launch failure. Set SERAPH_ACCEL=tcg to opt out.
    Accel::Whpx
}

#[cfg(target_os = "netbsd")]
fn detect_default() -> Accel
{
    let usable = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/nvmm")
        .is_ok();
    if usable { Accel::Nvmm } else { Accel::Tcg }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "netbsd",
)))]
fn detect_default() -> Accel
{
    // FreeBSD, OpenBSD, DragonFly, Solaris, illumos, etc. — none
    // have a standard QEMU accel beyond TCG.
    Accel::Tcg
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn with_env<F: FnOnce()>(key: &str, value: Option<&str>, f: F)
    {
        let prev = std::env::var_os(key);
        // SAFETY: env vars are process-global; tests touching the
        // same var must not run concurrently. xtask's test surface is
        // small enough that single-var ownership per test suffices.
        unsafe {
            match value
            {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
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
    fn cross_arch_guest_always_resolves_to_tcg()
    {
        let cross = if cfg!(target_arch = "x86_64")
        {
            Arch::Riscv64
        }
        else
        {
            Arch::X86_64
        };
        with_env(ENV_ACCEL, Some("kvm"), || {
            assert_eq!(detect_for_arch(cross), Accel::Tcg);
        });
    }

    #[test]
    fn explicit_env_var_tcg_forces_tcg()
    {
        let native = if cfg!(target_arch = "x86_64")
        {
            Arch::X86_64
        }
        else
        {
            Arch::Riscv64
        };
        with_env(ENV_ACCEL, Some("tcg"), || {
            assert_eq!(detect_for_arch(native), Accel::Tcg);
        });
    }

    #[test]
    fn explicit_env_var_auto_falls_through_to_detection()
    {
        // We can't fully test detection (depends on /dev/kvm), but
        // we can confirm "auto" does not pin to any specific backend
        // and is not rejected as invalid: the result must be the same
        // as no env var set at all.
        let native = if cfg!(target_arch = "x86_64")
        {
            Arch::X86_64
        }
        else
        {
            Arch::Riscv64
        };
        with_env(ENV_ACCEL, None, || {
            let baseline = detect_for_arch(native);
            with_env(ENV_ACCEL, Some("auto"), || {
                assert_eq!(detect_for_arch(native), baseline);
            });
        });
    }

    #[test]
    fn unknown_env_value_falls_through_to_detection()
    {
        let native = if cfg!(target_arch = "x86_64")
        {
            Arch::X86_64
        }
        else
        {
            Arch::Riscv64
        };
        with_env(ENV_ACCEL, None, || {
            let baseline = detect_for_arch(native);
            with_env(ENV_ACCEL, Some("notarealbackend"), || {
                assert_eq!(detect_for_arch(native), baseline);
            });
        });
    }

    #[test]
    fn parse_explicit_recognizes_all_documented_names()
    {
        assert_eq!(parse_explicit("kvm"), Some(Accel::Kvm));
        assert_eq!(parse_explicit("hvf"), Some(Accel::Hvf));
        assert_eq!(parse_explicit("whpx"), Some(Accel::Whpx));
        assert_eq!(parse_explicit("nvmm"), Some(Accel::Nvmm));
        assert_eq!(parse_explicit("tcg"), Some(Accel::Tcg));
        assert_eq!(parse_explicit("auto"), None);
        assert_eq!(parse_explicit("garbage"), None);
    }

    #[test]
    fn parse_explicit_ignores_case_and_surrounding_whitespace()
    {
        assert_eq!(parse_explicit("  KVM  "), Some(Accel::Kvm));
        assert_eq!(parse_explicit("Tcg"), Some(Accel::Tcg));
    }
}
