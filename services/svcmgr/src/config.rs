// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/src/config.rs

//! Configuration read through its directory's signed index
//! (docs/signing.md § Configuration): svcmgr reads a configuration
//! directory's `index` and each file the index names through procmgr's
//! verified read in the configuration role (`std::os::seraph::read_verified`),
//! parses only the bodies procmgr returns, and reports, without reading it, a
//! file of the directory the index does not name. A file the index names but
//! the directory lacks, or that procmgr refuses, is reported by the caller,
//! which passes it over.

use std::fs;
use std::io;
use std::os::seraph::fs::DirEntryExt;
use std::os::seraph::{VerifiedData, VerifiedRole, log, namespace_lookup_file, read_verified};

use objsig::{INDEX_NAME, Index};

/// A configuration directory whose index procmgr verified.
pub struct IndexedDir
{
    /// The directory's install path.
    dir: &'static str,
    /// The index's verified body, which [`Index::parse`] accepted.
    index: VerifiedData,
}

impl IndexedDir
{
    /// Read the index of `dir` through procmgr's verified read under
    /// `<dir>/index`, in the configuration role, and check that it parses.
    ///
    /// # Errors
    /// `NotFound` when the directory holds no index; `InvalidData` when
    /// procmgr refuses it or it does not parse as an index; `OutOfMemory`
    /// when its path or its copy cannot be had; the errors of the lookup and
    /// of `read_verified` otherwise.
    pub fn open(dir: &'static str) -> io::Result<Self>
    {
        let invalid = || io::Error::from(io::ErrorKind::InvalidData);
        let index_name = std::str::from_utf8(INDEX_NAME).map_err(|_| invalid())?;
        let index = read(dir, index_name)?;
        Index::parse(index.bytes()).map_err(|_| invalid())?;
        Ok(Self { dir, index })
    }

    /// The directory's install path.
    pub const fn dir(&self) -> &'static str
    {
        self.dir
    }

    /// The names the index holds, in its order (byte order).
    pub fn names(&self) -> impl Iterator<Item = &str>
    {
        // Parsed in `open`, so this parse succeeds and every name, a
        // canonical component, is UTF-8.
        Index::parse(self.index.bytes())
            .into_iter()
            .flat_map(Index::names)
            .filter_map(|name| std::str::from_utf8(name).ok())
    }

    /// Read the file `name` of the directory through procmgr's verified
    /// read, in the configuration role, under its install path.
    ///
    /// # Errors
    /// As [`Self::open`]'s read of the index: `NotFound` for a file the
    /// directory lacks, `InvalidData` for one procmgr refuses.
    pub fn read(&self, name: &str) -> io::Result<VerifiedData>
    {
        read(self.dir, name)
    }

    /// Log each file of the directory that is neither the index nor named by
    /// it: it is not read. A directory that cannot be listed is logged once.
    pub fn report_unnamed(&self)
    {
        let entries = match fs::read_dir(self.dir)
        {
            Ok(entries) => entries,
            Err(e) =>
            {
                log!(warn: "{}: cannot list it ({:?}); files its index does not name not reported", self.dir, e.kind());
                return;
            }
        };
        let Ok(index) = Index::parse(self.index.bytes())
        else
        {
            return;
        };
        for entry in entries.flatten()
        {
            let name = entry.file_name_ref().as_encoded_bytes();
            if name == INDEX_NAME || name == b"." || name == b".." || index.contains(name)
            {
                continue;
            }
            log!(
                warn: "{}/{}: not named by the directory's index; not read",
                self.dir,
                String::from_utf8_lossy(name)
            );
        }
    }
}

/// `<dir>/<name>`, read through procmgr's verified read in the
/// configuration role under that install path.
fn read(dir: &str, name: &str) -> io::Result<VerifiedData>
{
    let mut path = String::new();
    path.try_reserve_exact(dir.len().saturating_add(1).saturating_add(name.len()))
        .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
    path.push_str(dir);
    path.push('/');
    path.push_str(name);
    let (cap, size) = namespace_lookup_file(std::os::seraph::root_dir_cap(), &path)?;
    read_verified(cap, size, &path, VerifiedRole::Configuration)
}
