// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/socket_dir.rs

//! A private directory for the unix sockets a harness has QEMU or `swtpm`
//! serve, under the host's temporary directory, so a socket's path fits the
//! host's `sun_path` whatever the checkout's path.
//!
//! A socket under the target directory carries the checkout's path, and a
//! long checkout passes the limit (108 bytes on Linux, 104 on macOS): QEMU
//! then refuses the socket and exits before it boots. [`SocketDir::socket`]
//! refuses a path the host cannot bind, naming it, before anything is
//! launched on it, so a temporary directory too long for the limit is
//! reported, not worked around.

use std::os::unix::fs::DirBuilderExt as _;
use std::os::unix::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use crate::error::{Context as _, Result, err};

/// Tells apart the directories one process creates.
static NEXT: AtomicU32 = AtomicU32::new(0);

/// A directory only the current user can enter, holding the sockets of one
/// harness. Dropping it removes it and every socket in it, so a harness
/// declares it before the QEMU that serves them and never removes a socket
/// itself. A process killed before the drop leaves the directory and its
/// socket files in the temporary directory, holding nothing else.
pub struct SocketDir
{
    dir: PathBuf,
}

impl SocketDir
{
    /// Create a directory, `seraph-sock-<pid>-<n>`, under the host's
    /// temporary directory (`TMPDIR`, else `/tmp`).
    ///
    /// # Errors
    ///
    /// Fails when the directory cannot be created.
    pub fn create() -> Result<Self>
    {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self::fresh(std::env::temp_dir().join(format!("seraph-sock-{}-{n}", std::process::id())))
    }

    /// Create `dir`, mode 0700, first removing what a process of the same
    /// pid that was killed before its drop left at that path.
    fn fresh(dir: PathBuf) -> Result<Self>
    {
        if let Ok(meta) = dir.symlink_metadata()
        {
            // A symlink is removed, not followed.
            let removed = if meta.is_dir()
            {
                std::fs::remove_dir_all(&dir)
            }
            else
            {
                std::fs::remove_file(&dir)
            };
            removed.with_context(|| format!("removing the stale {}", dir.display()))?;
        }
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// The path of the socket `name` in this directory.
    ///
    /// # Errors
    ///
    /// Fails when the host cannot bind a socket at that path ([`fits`]).
    pub fn socket(&self, name: &str) -> Result<PathBuf>
    {
        let path = self.dir.join(name);
        fits(&path)?;
        Ok(path)
    }
}

impl Drop for SocketDir
{
    fn drop(&mut self)
    {
        // Best-effort: a drop has no caller to report to, and what is left is
        // inert files under the temporary directory.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Whether the host can bind a unix socket at `path`, by its own `sun_path`
/// limit.
///
/// # Errors
///
/// Fails naming the path and its length when it is past the limit.
fn fits(path: &Path) -> Result<()>
{
    SocketAddr::from_pathname(path).map(drop).map_err(|e| {
        err!(
            "the unix socket path {} ({} bytes) is past the host's sun_path limit ({e}); \
             point TMPDIR at a shorter directory",
            path.display(),
            path.as_os_str().len()
        )
    })
}

#[cfg(test)]
mod tests
{
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::net::UnixListener;

    use super::*;

    // Defect caught: a socket path the host cannot bind given to QEMU, which
    // exits before it boots; here the path the defect was seen at, a 99-byte
    // `target/xtask` and the debug-port case's socket name.
    #[test]
    fn a_socket_path_past_sun_path_is_refused_by_name()
    {
        let long = format!("/{}", "d".repeat(98));
        let dir = SocketDir {
            dir: PathBuf::from(&long),
        };
        let err = dir.socket("debug-port-4194304.gdb").unwrap_err();
        let report = format!("{err:#}");
        assert!(report.contains(&long), "{report}");
        assert!(report.contains("sun_path"), "{report}");
    }

    // Defect caught: a directory whose socket paths the host cannot bind, or
    // one other users can enter.
    #[test]
    fn a_socket_in_a_created_directory_binds()
    {
        let dir = SocketDir::create().unwrap();
        let mode = std::fs::metadata(&dir.dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let path = dir
            .socket("a-long-socket-name-of-a-case-4194304.qmp")
            .unwrap();
        UnixListener::bind(&path).unwrap();
    }

    // Defect caught: sockets left behind by a harness that returned.
    #[test]
    fn dropping_the_directory_removes_it_and_its_sockets()
    {
        let dir = SocketDir::create().unwrap();
        let path = dir.socket("s.sock").unwrap();
        let _listener = UnixListener::bind(&path).unwrap();
        let held = dir.dir.clone();
        drop(dir);
        assert!(!held.exists());
    }

    // Defect caught: a directory left at the path by a killed process of the
    // same pid blocking every later harness of that pid.
    #[test]
    fn a_stale_directory_at_the_path_is_replaced()
    {
        let path = std::env::temp_dir().join(format!("seraph-sock-stale-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("old.sock"), b"").unwrap();
        let dir = SocketDir::fresh(path.clone()).unwrap();
        assert!(path.is_dir());
        assert!(!path.join("old.sock").exists());
        drop(dir);
    }
}
