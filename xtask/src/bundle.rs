// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! bundle.rs
//!
//! Compose the bootloader bundle (`sysroot/esp/EFI/seraph/bootstrap.bundle`)
//! from canonical userspace binaries staged in the sysroot. The format is
//! defined by [`boot_protocol::bundle`] and shared with the bootloader
//! consumer side; this module is the only producer in the tree.
//!
//! Two flavours of bundle are produced, selected by [`Harness`]:
//!
//! - [`Harness::Init`] — default. Pulls `init`, `procmgr`, `memmgr`,
//!   `devmgr`, `vfsd`, `virtio-blk`, `serial`, `framebuffer`, `fatfs`
//!   into the bundle. `init` is named `"init"`; modules carry their
//!   service name. Sources span
//!   `sysroot/services/`, `sysroot/services/drivers/`, and
//!   `sysroot/services/fs/` per each component's install destination.
//! - [`Harness::Ktest`] — pulls `ktest` only, named `"init"`, from
//!   `sysroot/tests/ktest`. Zero module entries. The bootloader's
//!   `step4_parse_bundle` treats this as a monolithic ktest boot per
//!   `boot_protocol::bundle::INIT_ENTRY_NAME` semantics.

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use boot_protocol::bundle as fmt;

use crate::context::Context as BuildContext;
use crate::util::step;

/// Which harness binary to bundle as the `"init"` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Harness
{
    /// Regular userspace init at `sysroot/services/init`. Bundle includes
    /// every service module the system needs to bootstrap userspace.
    #[value(name = "init")]
    Init,
    /// `sysroot/tests/ktest` as the `"init"` entry. Bundle is a single
    /// entry; ktest is monolithic and does not spawn userspace modules.
    #[value(name = "ktest")]
    Ktest,
}

impl Harness
{
    /// Sysroot-relative source path of the harness binary that backs the
    /// bundle's `"init"` entry. The bundle entry itself is always named
    /// `"init"` regardless of source.
    fn init_source(self) -> &'static str
    {
        match self
        {
            Harness::Init => "services/init",
            Harness::Ktest => "tests/ktest",
        }
    }
}

/// Modules that ship in a default-init bundle. init looks them up by
/// the name strings here (via `InitInfo::module_names`, populated by
/// the kernel), so the order is free for the producer's convenience.
/// Each entry is `(bundle_entry_name, sysroot_relative_source_path)`;
/// the bundle-entry name is what init matches against, while the source
/// path follows each binary's `InstallDest` (drivers under
/// `services/drivers/`, fs drivers under `services/fs/`). Kept in the
/// historic ordinal order to keep the disk image byte-stable across
/// builds.
const MODULES: &[(&str, &str)] = &[
    ("procmgr", "services/procmgr"),
    ("devmgr", "services/devmgr"),
    ("vfsd", "services/vfsd"),
    ("virtio-blk", "services/drivers/virtio-blk"),
    ("serial", "services/drivers/serial"),
    ("framebuffer", "services/drivers/framebuffer"),
    ("fatfs", "services/fs/fatfs"),
    ("memmgr", "services/memmgr"),
];

/// Compose a bundle for the chosen harness and write it to
/// `sysroot/esp/EFI/seraph/bootstrap.bundle`, overwriting any existing
/// file. Source binaries are read from per-component sysroot paths
/// driven by each component's [`crate::commands::build::InstallDest`].
///
/// `Harness::Init` bundles `init` plus every entry in [`MODULES`].
/// `Harness::Ktest` bundles only `ktest` as the `init` entry.
pub fn compose(ctx: &BuildContext, harness: Harness) -> Result<()>
{
    let out_path = ctx.sysroot_efi_seraph().join("bootstrap.bundle");

    let init_src = ctx.sysroot.join(harness.init_source());
    if !init_src.exists()
    {
        anyhow::bail!(
            "compose-bundle: harness binary missing at {} (run `cargo xtask build` first)",
            init_src.display()
        );
    }

    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    // Bundle entry named "init" sources from the chosen harness binary.
    entries.push(("init".to_owned(), init_src));
    if harness == Harness::Init
    {
        for (name, source) in MODULES
        {
            let p = ctx.sysroot.join(source);
            if !p.exists()
            {
                anyhow::bail!(
                    "compose-bundle: module binary missing at {} (run `cargo xtask build` first)",
                    p.display()
                );
            }
            entries.push(((*name).to_owned(), p));
        }
    }

    let parent = out_path
        .parent()
        .context("compose-bundle: bundle path has no parent")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("compose-bundle: create {}", parent.display()))?;

    let entry_count =
        u32::try_from(entries.len()).context("compose-bundle: too many entries for u32")?;
    write_bundle(&out_path, entry_count, &entries)?;

    step(&format!(
        "Bundle: {} ({} entries, harness={:?})",
        out_path.display(),
        entries.len(),
        harness
    ));
    Ok(())
}

/// Write the bundle file: header, per-entry headers, then bodies aligned
/// to [`fmt::BODY_ALIGNMENT`].
fn write_bundle(out: &Path, entry_count: u32, entries: &[(String, PathBuf)]) -> Result<()>
{
    let mut out_file = fs::File::create(out)
        .with_context(|| format!("compose-bundle: create {}", out.display()))?;

    out_file
        .write_all(&fmt::MAGIC)
        .context("compose-bundle: write magic")?;
    out_file
        .write_all(&fmt::VERSION.to_le_bytes())
        .context("compose-bundle: write version")?;
    out_file
        .write_all(&entry_count.to_le_bytes())
        .context("compose-bundle: write entry_count")?;

    // Compute body offsets up front so the entry header table can be
    // written before the bodies themselves.
    let header_table_len = (entries.len() * fmt::ENTRY_HEADER_SIZE) as u64;
    let mut offsets: Vec<u64> = Vec::with_capacity(entries.len());
    let mut cursor = fmt::HEADER_SIZE as u64 + header_table_len;
    let mut sizes: Vec<u64> = Vec::with_capacity(entries.len());
    for (_, path) in entries
    {
        let size = fs::metadata(path)
            .with_context(|| format!("compose-bundle: stat {}", path.display()))?
            .len();
        cursor = align_up(cursor, fmt::BODY_ALIGNMENT);
        offsets.push(cursor);
        sizes.push(size);
        cursor += size;
    }

    // Entry header table.
    for ((name, _), (&offset, &size)) in entries.iter().zip(offsets.iter().zip(sizes.iter()))
    {
        let mut name_buf = [0u8; fmt::ENTRY_NAME_LEN];
        let nb = name.as_bytes();
        if nb.len() > fmt::ENTRY_NAME_LEN
        {
            anyhow::bail!(
                "compose-bundle: entry name `{name}` exceeds {} bytes",
                fmt::ENTRY_NAME_LEN
            );
        }
        name_buf[..nb.len()].copy_from_slice(nb);
        out_file
            .write_all(&name_buf)
            .context("compose-bundle: write entry name")?;
        out_file
            .write_all(&offset.to_le_bytes())
            .context("compose-bundle: write entry offset")?;
        out_file
            .write_all(&size.to_le_bytes())
            .context("compose-bundle: write entry size")?;
    }

    // Bodies (aligned).
    for ((_, path), &offset) in entries.iter().zip(offsets.iter())
    {
        out_file
            .seek(SeekFrom::Start(offset))
            .context("compose-bundle: seek to body offset")?;
        let bytes =
            fs::read(path).with_context(|| format!("compose-bundle: read {}", path.display()))?;
        out_file
            .write_all(&bytes)
            .with_context(|| format!("compose-bundle: write body for {}", path.display()))?;
    }

    out_file
        .sync_all()
        .context("compose-bundle: sync bundle file")?;
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> u64
{
    debug_assert!(alignment.is_power_of_two());
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use boot_protocol::bundle as fmt;
    use std::io::Read;

    /// Two-file round trip: write a bundle from two tiny "binary" files,
    /// parse it back via the shared format reader, and verify each
    /// entry's name, offset alignment, and body bytes.
    #[test]
    fn write_bundle_round_trip()
    {
        let tmp = std::env::temp_dir().join(format!(
            "seraph-bundle-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&tmp).unwrap();

        let a_path = tmp.join("a");
        let b_path = tmp.join("b");
        fs::write(&a_path, b"alpha").unwrap();
        fs::write(&b_path, b"beta--").unwrap();

        let out = tmp.join("bundle.bin");
        let entries = vec![("init".to_owned(), a_path), ("svc".to_owned(), b_path)];
        write_bundle(&out, 2, &entries).expect("write_bundle");

        // Read back and parse.
        let mut buf = Vec::new();
        fs::File::open(&out).unwrap().read_to_end(&mut buf).unwrap();
        let hdr = fmt::parse_header(&buf).expect("parse_header");
        assert_eq!(hdr.magic, fmt::MAGIC);
        assert_eq!(hdr.version, fmt::VERSION);
        assert_eq!(hdr.entry_count, 2);

        let e0 = fmt::entry_at(&buf, 0);
        assert_eq!(fmt::name_str(&e0.name), b"init");
        assert_eq!(e0.size, 5);
        assert!(e0.offset.is_multiple_of(fmt::BODY_ALIGNMENT));
        let body0 = &buf[e0.offset as usize..(e0.offset + e0.size) as usize];
        assert_eq!(body0, b"alpha");

        let e1 = fmt::entry_at(&buf, 1);
        assert_eq!(fmt::name_str(&e1.name), b"svc");
        assert_eq!(e1.size, 6);
        assert!(e1.offset.is_multiple_of(fmt::BODY_ALIGNMENT));
        let body1 = &buf[e1.offset as usize..(e1.offset + e1.size) as usize];
        assert_eq!(body1, b"beta--");

        let _ = fs::remove_dir_all(&tmp);
    }
}
