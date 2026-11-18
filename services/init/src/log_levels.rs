// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/src/log_levels.rs

//! The log levels of the services init spawns: read from the
//! `/config/init/log-levels.conf` boot module ([`read`]) and handed to each
//! service as the `SERAPH_LOG` entry of its environment, procmgr's in the
//! argv/env region init maps for it (`bootstrap::bootstrap_procmgr`),
//! devmgr's, vfsd's and svcmgr's in their create requests ([`SpawnEnv`]),
//! beside each one's name as its argv.
//! `services/init/docs/bootstrap.md` § Log levels specifies the configuration
//! and its delivery.
use init_log_levels::{Levels, Service};
use init_protocol::InitInfo;

use crate::logging::{log, log_parts};
use crate::{MemoryAlloc, TEMP_MAP_BASE};

/// Name of the boot module that holds the configuration: the install path
/// its signature names.
pub(crate) const MODULE_NAME: &[u8] = b"/config/init/log-levels.conf";

/// Read the levels the [`MODULE_NAME`] boot module sets: the configuration its
/// body holds, after the trailer the bootloader verified
/// (`init_log_levels::parse_module`). A missing or unreadable module, or one
/// whose trailer does not parse, sets none, so every service logs at its
/// default; a line that is not a setting is logged and ignored.
///
/// # Safety
/// The scratch span at `TEMP_MAP_BASE` must be unmapped, with no Rust object
/// in it: the module is mapped there for the parse and unmapped again.
pub(crate) unsafe fn read(info: &InitInfo) -> Levels
{
    let Some(slot) = crate::find_module_by_name(info, MODULE_NAME)
    else
    {
        return Levels::default();
    };
    let Some(size) = crate::bootstrap::descriptor_for(info, slot).map(|d| d.aux1)
    else
    {
        log("init: log-levels module has no descriptor; no level set");
        return Levels::default();
    };
    if size == 0
    {
        return Levels::default();
    }
    let Some(pages) = crate::bootstrap::module_scratch_pages(size)
    else
    {
        log("init: log-levels module too large for the scratch region; no level set");
        return Levels::default();
    };
    let Ok(module_ro) = syscall::cap_derive(slot, syscall::RIGHTS_MEM_MAP)
    else
    {
        log("init: log-levels module cap derive failed; no level set");
        return Levels::default();
    };
    // SAFETY: the caller's contract: the span at TEMP_MAP_BASE is unmapped
    // and holds no Rust object; `module_scratch_pages` keeps the mapping
    // within init's scratch region.
    if unsafe {
        syscall::mem_map(
            module_ro,
            info.aspace_cap,
            TEMP_MAP_BASE,
            0,
            pages,
            syscall::MAP_FROM_CAP,
        )
    }
    .is_err()
    {
        log("init: log-levels module map failed; no level set");
        let _ = syscall::cap_delete(module_ro);
        return Levels::default();
    }
    // SAFETY: the module is mapped read-only at TEMP_MAP_BASE, `size` bytes
    // within its `pages` pages.
    let module = unsafe { core::slice::from_raw_parts(TEMP_MAP_BASE as *const u8, size as usize) };
    let levels = init_log_levels::parse_module(module, |line, e| {
        log_parts(&[
            b"init: log-levels: line ignored (",
            e.describe().as_bytes(),
            b"): ",
            line,
        ]);
    })
    .unwrap_or_else(|_| {
        log("init: log-levels module's signature trailer does not parse; no level set");
        Levels::default()
    });
    // SAFETY: the module's scratch mapping; `module` is not used past the parse.
    let _ = unsafe { syscall::mem_unmap(info.aspace_cap, TEMP_MAP_BASE, pages) };
    let _ = syscall::cap_delete(module_ro);
    levels
}

/// The argv and env of one create request (`procmgr_labels::CREATE_ARGV_ENV`):
/// the map-only cap on the page that holds them, and their header's data
/// words.
pub(crate) struct ArgvEnv
{
    /// Map-only derivation of [`SpawnEnv`]'s page; the request transfers it,
    /// and init deletes its handle after the call ([`Self::release`]).
    pub(crate) cap: u64,
    /// The `ipc::procmgr_labels::ArgvEnvHeader`, in wire order.
    pub(crate) header: [u64; ipc::procmgr_labels::ARGV_ENV_HEADER_WORDS],
}

impl ArgvEnv
{
    /// Delete init's handle on the transferred derivation once the create
    /// call has returned. A call that moved the cap left a stale handle,
    /// whose delete the kernel refuses; one that did not leaves the
    /// derivation to delete.
    pub(crate) fn release(self)
    {
        let _ = syscall::cap_delete(self.cap);
    }
}

/// The page that carries a spawned service's argv, its name, and its
/// `SERAPH_LOG` entry, when the configuration sets its level, into its create
/// request. Allocated before `finalize_memmgr`; written before each of
/// devmgr's, vfsd's and svcmgr's creates and lent to procmgr through a
/// map-only derivation, which procmgr copies into the child's argv/env region
/// and deletes before it replies. The name is the one procmgr lists the
/// process under (`procmgr_labels::LIST_PROCESSES`), by which a debugger
/// finds it. The page is init's alone, so it reaches memmgr's pool through the
/// reap donation ([`Self::page`]).
pub(crate) struct SpawnEnv
{
    levels: Levels,
    /// The page's Memory cap; zero when the page could not be allocated.
    page: u64,
}

impl SpawnEnv
{
    /// The argv and env of the services init spawns under `levels`,
    /// allocating their page from `alloc`.
    pub(crate) fn new(levels: Levels, alloc: &mut MemoryAlloc) -> Self
    {
        let page = alloc.alloc_page().unwrap_or_else(|| {
            log("init: spawn argv page alloc failed; spawned services unnamed, logging at info");
            0
        });
        Self { levels, page }
    }

    /// The page's Memory cap, for the reap donation; `None` when there is
    /// none.
    pub(crate) fn page(&self) -> Option<u64>
    {
        (self.page != 0).then_some(self.page)
    }

    /// The argv/env of `service`'s create request: its name as its one argv
    /// string and, when its level is set, its `SERAPH_LOG` entry, written
    /// into the page. `None`, after a log line, when the page is absent or
    /// cannot be written or lent; the service is then spawned without argv or
    /// env, unnamed, and logs at info.
    ///
    /// # Safety
    /// `aspace` must be init's own address space, and the page at
    /// `TEMP_MAP_BASE` must be unmapped, with no Rust object in it: the page
    /// is mapped there for the write and unmapped again.
    pub(crate) unsafe fn argv_env(&self, service: Service, aspace: u64) -> Option<ArgvEnv>
    {
        if self.page == 0
        {
            return None;
        }
        // SAFETY: the caller's contract covers TEMP_MAP_BASE in `aspace`.
        if unsafe {
            syscall::mem_map(
                self.page,
                aspace,
                TEMP_MAP_BASE,
                0,
                1,
                syscall::MAP_WRITABLE,
            )
        }
        .is_err()
        {
            log("init: spawn argv page map failed; service spawned without argv or env");
            return None;
        }
        let name = service.name();
        // The longest name is a few bytes, so neither sum can overflow.
        let args_bytes = name.len().saturating_add(1);
        // SAFETY: TEMP_MAP_BASE is mapped writable, one page, which holds the
        // longest name, its NUL and `LEVEL_ENTRY_MAX` bytes; nothing else
        // refers to it.
        let out = unsafe {
            core::slice::from_raw_parts_mut(
                TEMP_MAP_BASE as *mut u8,
                args_bytes.saturating_add(log::LEVEL_ENTRY_MAX),
            )
        };
        let (argv, env) = out.split_at_mut(args_bytes);
        // `argv` is the name and its NUL, `args_bytes` long.
        let (text, nul) = argv.split_at_mut(name.len());
        text.copy_from_slice(name);
        nul.fill(0);
        let env_bytes = match self.levels.get(service)
        {
            Some(level) => log::level_entry(level, env).unwrap_or_else(|| {
                log("init: log-levels: level has no entry; service logs at info");
                0
            }),
            None => 0,
        };
        // SAFETY: the page's scratch mapping; `out` is not used past here.
        let _ = unsafe { syscall::mem_unmap(aspace, TEMP_MAP_BASE, 1) };
        let Ok(cap) = syscall::cap_derive(self.page, syscall::RIGHTS_MEM_MAP)
        else
        {
            log("init: spawn argv cap derive failed; service spawned without argv or env");
            return None;
        };
        let header = ipc::procmgr_labels::ArgvEnvHeader {
            args_bytes: args_bytes as u64,
            args_count: 1,
            env_bytes: env_bytes as u64,
            env_count: u64::from(env_bytes != 0),
        };
        Some(ArgvEnv {
            cap,
            header: header.to_words(),
        })
    }
}
