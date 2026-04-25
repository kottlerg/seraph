// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/bootstrap.rs

//! Procmgr bootstrap — raw ELF loading and process creation.
//!
//! Creates procmgr directly via kernel syscalls (no IPC) since procmgr is the
//! first process and no process manager exists yet. Installs procmgr's
//! `creator_endpoint_cap` to point at init's bootstrap endpoint (tokened
//! per-child) so procmgr receives its memory-pool bounds via the bootstrap
//! protocol at startup.
//!
//! All subsequent services are created through procmgr IPC.

use crate::logging::log;
use crate::{FrameAlloc, PAGE_SIZE, TEMP_MAP_BASE, arch};
use init_protocol::InitInfo;
use process_abi::{
    PROCESS_ABI_VERSION, PROCESS_INFO_VADDR, PROCESS_STACK_PAGES, PROCESS_STACK_TOP,
};

// ── Constants ────────────────────────────────────────────────────────────────

use va_layout::{INIT_ELF_PAGE_TEMP_VA as ELF_PAGE_TEMP_VA, PROCMGR_IPC_BUF_VA};

// ── ELF loading ──────────────────────────────────────────────────────────────

/// Derive a frame cap with the given protection rights for mapping.
fn derive_frame_for_prot(frame_cap: u32, prot: u64) -> Option<u32>
{
    if prot == syscall::MAP_READONLY
    {
        syscall::cap_derive(frame_cap, syscall::RIGHTS_MAP_READ).ok()
    }
    else if prot == syscall::MAP_EXECUTABLE
    {
        syscall::cap_derive(frame_cap, syscall::RIGHTS_MAP_RX).ok()
    }
    else
    {
        syscall::cap_derive(frame_cap, syscall::RIGHTS_MAP_RW).ok()
    }
}

/// Copy one ELF segment page from `file_data` into a freshly allocated frame,
/// then map it into the target address space.
fn load_elf_page(
    page_vaddr: u64,
    seg_vaddr: u64,
    file_data: &[u8],
    prot: u64,
    alloc: &mut FrameAlloc,
    init_aspace: u32,
    target_aspace: u32,
) -> Option<()>
{
    let Some(frame_cap) = alloc.alloc_page()
    else
    {
        log("ELF load: frame alloc failed");
        return None;
    };

    if syscall::mem_map(
        frame_cap,
        init_aspace,
        ELF_PAGE_TEMP_VA,
        0,
        1,
        syscall::MAP_WRITABLE,
    )
    .is_err()
    {
        log("ELF load: temp map failed");
        return None;
    }

    // SAFETY: ELF_PAGE_TEMP_VA is mapped writable, covers one page.
    unsafe { core::ptr::write_bytes(ELF_PAGE_TEMP_VA as *mut u8, 0, PAGE_SIZE as usize) };

    let dest_offset = if page_vaddr < seg_vaddr
    {
        (seg_vaddr - page_vaddr) as usize
    }
    else
    {
        0
    };
    let seg_offset = page_vaddr.saturating_sub(seg_vaddr) as usize;
    let avail_in_page = PAGE_SIZE as usize - dest_offset;
    let copy_len = avail_in_page.min(file_data.len().saturating_sub(seg_offset));
    if copy_len > 0
    {
        let src = &file_data[seg_offset..seg_offset + copy_len];
        // SAFETY: temp_va is mapped and writable; copy within one page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                (ELF_PAGE_TEMP_VA as *mut u8).add(dest_offset),
                src.len(),
            );
        }
    }

    let _ = syscall::mem_unmap(init_aspace, ELF_PAGE_TEMP_VA, 1);

    let derived_cap = derive_frame_for_prot(frame_cap, prot)?;
    syscall::mem_map(derived_cap, target_aspace, page_vaddr, 0, 1, 0).ok()?;

    Some(())
}

/// Load an ELF image into a target address space.
///
/// Returns the entry point virtual address.
fn load_elf(
    module_bytes: &[u8],
    target_aspace: u32,
    alloc: &mut FrameAlloc,
    init_aspace: u32,
) -> Option<u64>
{
    let ehdr = elf::validate(module_bytes, arch::current::EXPECTED_ELF_MACHINE).ok()?;
    let entry = elf::entry_point(ehdr);

    for seg_result in elf::load_segments(ehdr, module_bytes)
    {
        let seg = seg_result.ok()?;
        if seg.memsz == 0
        {
            continue;
        }

        let prot = if seg.executable
        {
            syscall::MAP_EXECUTABLE
        }
        else if seg.writable
        {
            syscall::MAP_WRITABLE
        }
        else
        {
            syscall::MAP_READONLY
        };

        let first_page = seg.vaddr & !0xFFF;
        let last_page_end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
        let num_pages = ((last_page_end - first_page) / PAGE_SIZE) as usize;

        let file_data = &module_bytes[seg.offset as usize..(seg.offset + seg.filesz) as usize];

        for page_idx in 0..num_pages
        {
            let page_vaddr = first_page + (page_idx as u64) * PAGE_SIZE;
            load_elf_page(
                page_vaddr,
                seg.vaddr,
                file_data,
                prot,
                alloc,
                init_aspace,
                target_aspace,
            )?;
        }
    }

    Some(entry)
}

// ── Procmgr bootstrap ───────────────────────────────────────────────────────

/// Procmgr kernel object caps needed to populate `ProcessInfo`.
struct ProcmgrCaps
{
    aspace: u32,
    cspace: u32,
    thread: u32,
    creator_endpoint_slot: u32,
}

/// Populate procmgr's `ProcessInfo` page and map it read-only into procmgr.
///
/// procmgr is `no_std` and doesn't drive `std::io::stdio`, so the three
/// stdio cap slots are left zero. The log endpoint procmgr needs (as the
/// dispensing source for `MINT_LOG_CAP`) arrives via its bootstrap round,
/// not via `ProcessInfo`.
#[allow(clippy::similar_names)]
fn populate_procmgr_info(
    alloc: &mut FrameAlloc,
    init_aspace: u32,
    caps: &ProcmgrCaps,
) -> Option<u32>
{
    let pi_frame = alloc.alloc_zero_page(init_aspace, TEMP_MAP_BASE)?;

    // SAFETY: TEMP_MAP_BASE is mapped writable and zeroed, one page.
    let pi = unsafe { process_abi::process_info_mut(TEMP_MAP_BASE) };

    let pm_thread_in_pm =
        syscall::cap_copy(caps.thread, caps.cspace, syscall::RIGHTS_THREAD).ok()?;
    let pm_aspace_in_pm = syscall::cap_copy(caps.aspace, caps.cspace, syscall::RIGHTS_ALL).ok()?;
    let pm_cspace_in_pm =
        syscall::cap_copy(caps.cspace, caps.cspace, syscall::RIGHTS_CSPACE).ok()?;

    pi.version = PROCESS_ABI_VERSION;
    pi.self_thread_cap = pm_thread_in_pm;
    pi.self_aspace_cap = pm_aspace_in_pm;
    pi.self_cspace_cap = pm_cspace_in_pm;
    pi.ipc_buffer_vaddr = PROCMGR_IPC_BUF_VA;
    pi.creator_endpoint_cap = caps.creator_endpoint_slot;
    // procmgr has no procmgr above it; leave zero.
    pi.procmgr_endpoint_cap = 0;
    pi.stdin_cap = 0;
    pi.stdout_cap = 0;
    pi.stderr_cap = 0;
    // Procmgr is the source of the log discovery cap (it holds the un-
    // tokened SEND on the log endpoint, used as the dispensing source
    // for `MINT_LOG_CAP` and now also as the source procmgr `cap_copy`s
    // into every child it creates). Procmgr itself does not consume
    // `seraph::log!`, so its own slot stays zero.
    pi.log_discovery_cap = 0;

    let _ = syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, 1);

    let pi_ro_cap = syscall::cap_derive(pi_frame, syscall::RIGHTS_MAP_READ).ok()?;
    syscall::mem_map(pi_ro_cap, caps.aspace, PROCESS_INFO_VADDR, 0, 1, 0).ok()?;

    Some(pi_frame)
}

/// Map stack and IPC buffer pages into the target address space.
fn map_stack_and_ipc(alloc: &mut FrameAlloc, target_aspace: u32, ipc_buf_va: u64) -> Option<()>
{
    let stack_base = PROCESS_STACK_TOP - (PROCESS_STACK_PAGES as u64) * PAGE_SIZE;
    for i in 0..PROCESS_STACK_PAGES
    {
        let frame = alloc.alloc_page()?;
        let rw_cap = syscall::cap_derive(frame, syscall::RIGHTS_MAP_RW).ok()?;
        syscall::mem_map(
            rw_cap,
            target_aspace,
            stack_base + (i as u64) * PAGE_SIZE,
            0,
            1,
            0,
        )
        .ok()?;
    }

    let ipc_frame = alloc.alloc_page()?;
    let ipc_rw_cap = syscall::cap_derive(ipc_frame, syscall::RIGHTS_MAP_RW).ok()?;
    syscall::mem_map(ipc_rw_cap, target_aspace, ipc_buf_va, 0, 1, 0).ok()?;

    Some(())
}

/// Result of bootstrapping procmgr.
pub struct ProcmgrBootstrap
{
    /// Send cap to procmgr's service endpoint (init uses for `CREATE_PROCESS`).
    pub service_ep: u32,
    /// Procmgr's bootstrap token on init's bootstrap endpoint.
    pub bootstrap_token: u64,
    /// Memory pool base slot in procmgr's `CSpace`.
    pub memory_frame_base: u32,
    /// Memory pool count.
    pub memory_frame_count: u32,
    /// Slot in procmgr's `CSpace` holding an un-tokened SEND cap on the
    /// system log endpoint. Procmgr uses this exclusively as the dispensing
    /// source for `MINT_LOG_CAP` requests — it does not consult it during
    /// `CREATE_PROCESS`. Zero when no log endpoint is available (very early
    /// boot); `MINT_LOG_CAP` refuses requests in that window.
    pub log_endpoint_slot: u32,
}

/// Monotonic counter for init-side bootstrap tokens.
pub static NEXT_BOOTSTRAP_TOKEN: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// Create and start procmgr from its boot module ELF image.
///
/// `init_bootstrap_ep` is init's bootstrap endpoint; a tokened send cap is
/// derived from it and installed as procmgr's `creator_endpoint_cap`.
///
/// `pm_service_ep` is procmgr's own service endpoint (created by init, copied
/// into procmgr's `CSpace` so procmgr can `ipc_recv` on it).
///
/// `log_ep` is the system log endpoint; a SEND cap is copied into procmgr's
/// `CSpace` and recorded in `ProcessInfo.log_endpoint_cap` so procmgr (and
/// every child it populates `ProcessInfo` for) has an ambient log sink.
///
/// Returns the [`ProcmgrBootstrap`] record so the caller can issue bootstrap
/// rounds and subsequent `CREATE_PROCESS` calls.
#[allow(clippy::similar_names)]
pub fn bootstrap_procmgr(
    info: &InitInfo,
    alloc: &mut FrameAlloc,
    init_bootstrap_ep: u32,
    pm_service_ep: u32,
    log_ep: u32,
) -> Option<ProcmgrBootstrap>
{
    let init_aspace = info.aspace_cap;

    let module_frame_cap = info.module_frame_base; // Module 0 = procmgr
    let module_size = crate::descriptors(info)
        .iter()
        .find(|d| d.slot == module_frame_cap)
        .map(|d| d.aux1)?;

    let module_pages = (module_size + 0xFFF) / PAGE_SIZE;

    syscall::mem_map(
        module_frame_cap,
        init_aspace,
        TEMP_MAP_BASE,
        0,
        module_pages,
        syscall::MAP_READONLY,
    )
    .ok()?;

    // SAFETY: module frame is now mapped read-only at TEMP_MAP_BASE.
    let module_bytes =
        unsafe { core::slice::from_raw_parts(TEMP_MAP_BASE as *const u8, module_size as usize) };

    let pm_aspace = syscall::cap_create_aspace().ok()?;
    let pm_cspace = syscall::cap_create_cspace(8192).ok()?;
    let pm_thread = syscall::cap_create_thread(pm_aspace, pm_cspace).ok()?;

    log("created procmgr kernel objects");
    log("loading procmgr ELF segments");

    let entry = load_elf(module_bytes, pm_aspace, alloc, init_aspace)?;
    let _ = syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, module_pages);

    log("loaded procmgr ELF");

    // Derive tokened creator endpoint for procmgr.
    let procmgr_token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let tokened_creator =
        syscall::cap_derive_token(init_bootstrap_ep, syscall::RIGHTS_SEND, procmgr_token).ok()?;
    let pm_creator_slot =
        syscall::cap_copy(tokened_creator, pm_cspace, syscall::RIGHTS_SEND).ok()?;

    // Delegate all remaining memory frame caps to procmgr.
    let pm_frame_base = pm_creator_slot + 1;
    let mut pm_frame_count: u32 = 0;
    let frames_to_give = info.memory_frame_count.saturating_sub(alloc.next_idx);
    for i in 0..frames_to_give
    {
        let src_slot = info.memory_frame_base + alloc.next_idx + i;
        if let Ok(intermediary) = syscall::cap_derive(src_slot, syscall::RIGHTS_ALL)
            && syscall::cap_copy(intermediary, pm_cspace, syscall::RIGHTS_ALL).is_ok()
        {
            pm_frame_count += 1;
        }
    }
    alloc.next_idx += frames_to_give;

    // Derive an un-tokened SEND cap on the log endpoint for procmgr's
    // dispensing role (source for `MINT_LOG_CAP`). Kept in init's CSpace
    // and sent to procmgr via the bootstrap round (ipc transfer moves it
    // into procmgr's CSpace at a fresh slot). Procmgr never uses this cap
    // during `CREATE_PROCESS` — only when servicing `MINT_LOG_CAP`.
    let pm_log_send = if log_ep == 0
    {
        0
    }
    else
    {
        syscall::cap_derive(log_ep, syscall::RIGHTS_SEND).ok()?
    };

    let pm_caps = ProcmgrCaps {
        aspace: pm_aspace,
        cspace: pm_cspace,
        thread: pm_thread,
        creator_endpoint_slot: pm_creator_slot,
    };
    populate_procmgr_info(alloc, init_aspace, &pm_caps)?;

    map_stack_and_ipc(alloc, pm_aspace, PROCMGR_IPC_BUF_VA)?;

    syscall::thread_configure(pm_thread, entry, PROCESS_STACK_TOP, PROCESS_INFO_VADDR).ok()?;
    syscall::thread_start(pm_thread).ok()?;

    log("procmgr started");

    // Derive a send cap to procmgr's service endpoint for init's own use.
    let service_ep_for_init =
        syscall::cap_derive(pm_service_ep, syscall::RIGHTS_SEND_GRANT).ok()?;

    Some(ProcmgrBootstrap {
        service_ep: service_ep_for_init,
        bootstrap_token: procmgr_token,
        memory_frame_base: pm_frame_base,
        memory_frame_count: pm_frame_count,
        log_endpoint_slot: pm_log_send,
    })
}
