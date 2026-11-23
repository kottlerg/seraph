// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/context.rs

//! Resolved workspace and build output paths, shared by all commands.

use std::path::PathBuf;

use crate::error::{Context as _, Result};

crate::argparse::value_enum! {
    /// A Cargo build profile: the debug build or the `--release` build.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Profile
    {
        /// The unoptimised build (Cargo's `dev` profile).
        #[value(name = "debug")]
        Debug,
        /// The `--release` build.
        #[value(name = "release")]
        Release,
    }
}

impl Profile
{
    /// Name of Cargo's output directory for the profile (`debug`/`release`).
    pub fn dir_name(self) -> &'static str
    {
        match self
        {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    /// Cargo profile *selector* name (`dev`/`release`) for `--config` keys.
    ///
    /// Distinct from [`Profile::dir_name`], which returns the output-directory
    /// name (`debug`/`release`). The cargo profile is literally named `dev`; no
    /// profile is named `debug`, so a per-package `--config` key MUST use this
    /// name — `profile.debug.package.*` would be a silent no-op. Do not fold
    /// this into [`Profile::dir_name`].
    pub fn cargo_profile(self) -> &'static str
    {
        match self
        {
            Self::Debug => "dev",
            Self::Release => "release",
        }
    }
}

/// Resolved project paths used by every command.
pub struct Context
{
    /// Absolute path to the workspace root (parent of xtask/).
    pub root: PathBuf,

    /// Sysroot staging area: contents are packaged into `disk.img` (GPT
    /// image) by `cargo xtask build` and cleared by `cargo xtask clean`.
    pub sysroot: PathBuf,

    /// Cargo's `target/` directory, shared by all workspace members.
    pub target_dir: PathBuf,
}

impl Context
{
    /// Construct a Context from the compiled-in xtask manifest directory.
    ///
    /// `CARGO_MANIFEST_DIR` is set by Cargo to the xtask crate root at compile
    /// time; its parent is the workspace root.
    pub fn from_manifest_dir() -> Result<Self>
    {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir
            .parent()
            .context("xtask manifest dir has no parent — check workspace layout")?
            .to_path_buf();
        Ok(Self::at(root))
    }

    /// A Context for the checkout at `root`: a cell's lane runs its cases in
    /// a private copy of the checkout this way.
    #[must_use]
    pub fn at(root: PathBuf) -> Self
    {
        let sysroot = root.join("sysroot");
        let target_dir = root.join("target");
        Context {
            root,
            sysroot,
            target_dir,
        }
    }

    /// Path to `sysroot/esp/` — ESP partition staging area.
    pub fn sysroot_esp(&self) -> PathBuf
    {
        self.sysroot.join("esp")
    }

    /// Path to `sysroot/esp/EFI/BOOT/` — UEFI fallback bootloader on the ESP.
    pub fn sysroot_efi_boot(&self) -> PathBuf
    {
        self.sysroot.join("esp").join("EFI").join("BOOT")
    }

    /// Path to `sysroot/esp/EFI/seraph/` — Seraph vendor directory on the ESP.
    pub fn sysroot_efi_seraph(&self) -> PathBuf
    {
        self.sysroot.join("esp").join("EFI").join("seraph")
    }

    /// Path to `sysroot/boot/`: the installed kernel and bootloader, whose
    /// ESP copies every pack writes (docs/boot-media.md § Installed Copies).
    pub fn sysroot_boot(&self) -> PathBuf
    {
        self.sysroot.join("boot")
    }

    /// Path to the installed kernel, `/boot/kernel`, signed there.
    pub fn installed_kernel(&self) -> PathBuf
    {
        self.sysroot_boot().join("kernel")
    }

    /// Path to the installed bootloader, `/boot/boot.efi`, whose embedded
    /// trust store every pack signs under.
    pub fn installed_bootloader(&self) -> PathBuf
    {
        self.sysroot_boot().join("boot.efi")
    }

    /// Path to `symbols/`, the symbols store: the unstripped link output of
    /// every image the build installs, by build id, and its manifest
    /// (docs/build-system.md § Symbols Store). Beside the sysroot, so no
    /// pack copies it to a disk image; cleared by `cargo xtask clean`.
    pub fn symbols_dir(&self) -> PathBuf
    {
        self.root.join("symbols")
    }

    /// Path to the GPT disk image (built from sysroot contents).
    pub fn disk_image(&self) -> PathBuf
    {
        self.root.join("disk.img")
    }

    /// Path to the second disk image that carries the data partition alone,
    /// authored by `cargo xtask mkdisk --split-data`.
    pub fn data_disk_image(&self) -> PathBuf
    {
        self.root.join("disk-data.img")
    }

    /// Cargo output directory for a given target triple and build profile.
    ///
    /// Cargo outputs the `dev` profile to `debug/`; all other profiles use the
    /// profile name as the directory name.
    pub fn cargo_output_dir(&self, triple: &str, profile: Profile) -> PathBuf
    {
        self.target_dir.join(triple).join(profile.dir_name())
    }
}
