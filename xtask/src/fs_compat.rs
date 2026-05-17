// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! fs_compat.rs
//!
//! Portable file-materialisation helpers.
//!
//! `link_or_copy` makes `dst` refer to the same content as `src` using
//! the cheapest mechanism the host supports: symlink first, then hard
//! link, then physical copy. The chosen mechanism is reported back so
//! callers can log it; semantics are identical from a reader's
//! perspective (cargo and rustc resolve all three to the same bytes).
//!
//! This replaces the previous Unix-only `std::os::unix::fs::symlink`
//! call sites in `rust_src.rs`, which were the last hard blocker to
//! the toolchain-mirror assembly running on Windows. On Unix and
//! macOS, behavior is unchanged (symlink path always succeeds). On
//! Windows the symlink attempt requires developer mode or admin
//! privileges; the function silently falls through to hard-link
//! (files) or recursive copy (dirs).
//!
//! Directory handling: dir symlinks need a distinct API on Windows
//! (`symlink_dir` vs `symlink_file`), and there is no portable
//! directory hard-link. `link_or_copy` dispatches on `src`'s metadata
//! and falls back to recursive copy for directories when symlink
//! fails.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result};

/// Materialise `dst` to reference the same content as `src`. Tries
/// symlink, then hard link (for files), then physical copy.
///
/// `src` must exist; `dst` must not. The caller is responsible for
/// removing any prior `dst`. Failure of one fallback is silent; the
/// only error surfaced is the final-fallback (`fs::copy` for files,
/// recursive copy for dirs) failure, with the source path in
/// context.
pub fn link_or_copy(src: &Path, dst: &Path) -> Result<()>
{
    let meta = fs::symlink_metadata(src).with_context(|| format!("stat {}", src.display()))?;
    if meta.file_type().is_dir()
    {
        link_or_copy_dir(src, dst)
    }
    else
    {
        link_or_copy_file(src, dst)
    }
}

/// File-level materialise: symlink → hard link → copy.
fn link_or_copy_file(src: &Path, dst: &Path) -> Result<()>
{
    if try_symlink_file(src, dst).is_ok()
    {
        return Ok(());
    }
    if fs::hard_link(src, dst).is_ok()
    {
        return Ok(());
    }
    fs::copy(src, dst)
        .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
    Ok(())
}

/// Directory-level materialise: dir-symlink → recursive copy. There
/// is no portable directory hard-link.
fn link_or_copy_dir(src: &Path, dst: &Path) -> Result<()>
{
    if try_symlink_dir(src, dst).is_ok()
    {
        return Ok(());
    }
    copy_dir_recursive(src, dst)?;
    Ok(())
}

/// Recursive directory copy. Used as the last-resort fallback for
/// `link_or_copy_dir` on hosts where directory symlinks aren't
/// available (Windows without developer mode).
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()>
{
    fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
    for entry in fs::read_dir(src).with_context(|| format!("reading {}", src.display()))?
    {
        let entry = entry?;
        let entry_path = entry.path();
        let entry_dst = dst.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir()
        {
            copy_dir_recursive(&entry_path, &entry_dst)?;
        }
        else if ft.is_symlink()
        {
            // Resolve and copy the symlink's content rather than
            // attempting to recreate the symlink — symlink recreation
            // is itself non-portable, and a copy gives the reader the
            // same bytes.
            fs::copy(&entry_path, &entry_dst).with_context(|| {
                format!(
                    "copying (via resolved symlink) {} -> {}",
                    entry_path.display(),
                    entry_dst.display()
                )
            })?;
        }
        else
        {
            fs::copy(&entry_path, &entry_dst).with_context(|| {
                format!(
                    "copying {} -> {}",
                    entry_path.display(),
                    entry_dst.display()
                )
            })?;
        }
    }
    Ok(())
}

// ── Per-platform symlink primitives ──────────────────────────────────────────

#[cfg(unix)]
fn try_symlink_file(src: &Path, dst: &Path) -> io::Result<()>
{
    std::os::unix::fs::symlink(src, dst)
}

#[cfg(unix)]
fn try_symlink_dir(src: &Path, dst: &Path) -> io::Result<()>
{
    std::os::unix::fs::symlink(src, dst)
}

#[cfg(windows)]
fn try_symlink_file(src: &Path, dst: &Path) -> io::Result<()>
{
    std::os::windows::fs::symlink_file(src, dst)
}

#[cfg(windows)]
fn try_symlink_dir(src: &Path, dst: &Path) -> io::Result<()>
{
    std::os::windows::fs::symlink_dir(src, dst)
}

#[cfg(not(any(unix, windows)))]
fn try_symlink_file(_src: &Path, _dst: &Path) -> io::Result<()>
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlinks not supported on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn try_symlink_dir(_src: &Path, _dst: &Path) -> io::Result<()>
{
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "symlinks not supported on this platform",
    ))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn tmpdir() -> std::path::PathBuf
    {
        let dir = std::env::temp_dir().join(format!(
            "seraph-xtask-fs_compat-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn link_or_copy_file_makes_dst_readable_with_same_bytes()
    {
        let dir = tmpdir();
        let src = dir.join("src.txt");
        let dst = dir.join("dst.txt");
        fs::write(&src, b"hello world").unwrap();
        link_or_copy(&src, &dst).unwrap();
        let bytes = fs::read(&dst).unwrap();
        assert_eq!(bytes, b"hello world");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn link_or_copy_dir_replicates_directory_contents()
    {
        let dir = tmpdir();
        let src = dir.join("src");
        let dst = dir.join("dst");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"one").unwrap();
        fs::create_dir(src.join("sub")).unwrap();
        fs::write(src.join("sub/b.txt"), b"two").unwrap();
        link_or_copy(&src, &dst).unwrap();
        assert_eq!(fs::read(dst.join("a.txt")).unwrap(), b"one");
        assert_eq!(fs::read(dst.join("sub/b.txt")).unwrap(), b"two");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn link_or_copy_missing_source_errors()
    {
        let dir = tmpdir();
        let src = dir.join("nope.txt");
        let dst = dir.join("out.txt");
        let err = link_or_copy(&src, &dst).unwrap_err();
        assert!(format!("{err:#}").contains("stat"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_dir_recursive_handles_nested_files_and_dirs()
    {
        let dir = tmpdir();
        let src = dir.join("src");
        let dst = dir.join("dst");
        fs::create_dir(&src).unwrap();
        fs::create_dir(src.join("a")).unwrap();
        fs::create_dir(src.join("a/b")).unwrap();
        fs::write(src.join("a/b/leaf.txt"), b"deep").unwrap();
        copy_dir_recursive(&src, &dst).unwrap();
        assert_eq!(fs::read(dst.join("a/b/leaf.txt")).unwrap(), b"deep");
        let _ = fs::remove_dir_all(&dir);
    }
}
