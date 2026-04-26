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
use init_protocol::{CapDescriptor, InitInfo};
use process_abi::{
    PROCESS_ABI_VERSION, PROCESS_INFO_VADDR, PROCESS_STACK_PAGES, PROCESS_STACK_TOP,
};

// ── Constants ────────────────────────────────────────────────────────────────
//
// Both VAs are private to init's no_std bootstrap path. ELF_PAGE_TEMP_VA
// sits inside init's TEMP_MAP_BASE scratch region (offset 256 MiB).
// PROCMGR_IPC_BUF_VA is the IPC-buffer VA init writes into procmgr's
// `ProcessInfo.ipc_buffer_vaddr` slot; procmgr reads it back at boot.

/// Per-page ELF write scratch during init's procmgr/memmgr bootstrap.
const ELF_PAGE_TEMP_VA: u64 = TEMP_MAP_BASE + 0x1000_0000;

/// procmgr's IPC buffer VA as seen from init while bootstrapping procmgr.
const PROCMGR_IPC_BUF_VA: u64 = 0x0000_7FFF_FFFE_0000;

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

/// Allocate one frame for the main thread's TLS block, populate it from
/// the in-memory `.tdata` template, install the TCB self-pointer, and
/// map it read-write into `target_aspace` at `PROCESS_MAIN_TLS_VADDR`.
///
/// Returns `(tls_base_va, tls_template_metadata)` where the metadata is
/// what gets written into the child's `ProcessInfo.tls_template_*`
/// fields. When the binary has no `PT_TLS` segment, returns
/// `(0, ChildTlsMeta::default())` and the caller passes
/// `tls_base_va = 0` to `thread_configure_with_tls`.
#[derive(Clone, Copy, Default)]
pub struct ChildTlsMeta
{
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[allow(clippy::similar_names)]
fn prepare_main_tls(
    module_bytes: &[u8],
    target_aspace: u32,
    alloc: &mut FrameAlloc,
    init_aspace: u32,
) -> Option<(u64, ChildTlsMeta)>
{
    let ehdr = elf::validate(module_bytes, arch::current::EXPECTED_ELF_MACHINE).ok()?;
    let tls_seg = elf::tls_segment(ehdr, module_bytes).ok()?;
    let Some(seg) = tls_seg
    else
    {
        return Some((0, ChildTlsMeta::default()));
    };
    if seg.memsz == 0
    {
        return Some((0, ChildTlsMeta::default()));
    }
    let meta = ChildTlsMeta {
        vaddr: seg.vaddr,
        filesz: seg.filesz,
        memsz: seg.memsz,
        align: seg.align,
    };

    let (block_size, block_align, tls_base_offset) =
        process_abi::tls_block_layout(seg.memsz, seg.align);
    if block_size == 0
        || block_size > PAGE_SIZE
        || block_size > PAGE_SIZE * process_abi::PROCESS_MAIN_TLS_MAX_PAGES
        || block_align > PAGE_SIZE
    {
        return None;
    }

    let tls_frame = alloc.alloc_zero_page(init_aspace, crate::TEMP_MAP_BASE)?;

    // SAFETY: TEMP_MAP_BASE mapped writable, one page, zeroed.
    let tdata_start = seg.offset as usize;
    let tdata_end = tdata_start + seg.filesz as usize;
    if tdata_end > module_bytes.len()
    {
        let _ = syscall::mem_unmap(init_aspace, crate::TEMP_MAP_BASE, 1);
        return None;
    }
    // SAFETY: TEMP_MAP_BASE mapped writable, length bounded by tls_block_layout.
    unsafe {
        core::ptr::copy_nonoverlapping(
            module_bytes[tdata_start..tdata_end].as_ptr(),
            crate::TEMP_MAP_BASE as *mut u8,
            seg.filesz as usize,
        );
    }

    let tls_base_va = process_abi::PROCESS_MAIN_TLS_VADDR + tls_base_offset;
    // SAFETY: TEMP_MAP_BASE mapped writable; the block fits.
    unsafe {
        process_abi::tls_install_tcb(
            crate::TEMP_MAP_BASE as *mut u8,
            tls_base_offset,
            tls_base_va,
        );
    }

    let _ = syscall::mem_unmap(init_aspace, crate::TEMP_MAP_BASE, 1);

    let tls_rw = syscall::cap_derive(tls_frame, syscall::RIGHTS_MAP_RW).ok()?;
    syscall::mem_map(
        tls_rw,
        target_aspace,
        process_abi::PROCESS_MAIN_TLS_VADDR,
        0,
        1,
        0,
    )
    .ok()?;

    Some((tls_base_va, meta))
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

// ── Memmgr bootstrap ────────────────────────────────────────────────────────

/// Result of bootstrapping memmgr's setup (kernel objects + ELF load +
/// PI / stack / IPC mappings + creator endpoint). Frame-pool delegation
/// and `thread_start` happen later via [`finalize_memmgr`] so that
/// procmgr's setup pages can also draw from init's pool before all
/// remaining frames are handed over to memmgr.
pub struct MemmgrBootstrap
{
    /// Init-side bootstrap token for memmgr's `request_round` reply.
    pub bootstrap_token: u64,
    /// Token init used when minting the procmgr-side tokened SEND on
    /// memmgr's endpoint. Memmgr stores this and uses it to gate the
    /// procmgr-only labels (`REGISTER_PROCESS`, `PROCESS_DIED`).
    pub procmgr_token: u64,
    /// Slot in init's `CSpace` of the tokened SEND cap on memmgr's
    /// endpoint that init will install in procmgr's `ProcessInfo`.
    pub procmgr_send_cap: u32,
    /// Memmgr's `CSpace` cap (in init's `CSpace`). Init copies RAM
    /// Frame caps into here at [`finalize_memmgr`] time.
    pub mm_cspace: u32,
    /// Memmgr's main `Thread` cap (in init's `CSpace`). Init invokes
    /// `thread_configure` + `thread_start` at [`finalize_memmgr`] time.
    pub mm_thread: u32,
    /// Memmgr's ELF entry point.
    pub entry: u64,
}

/// Result of [`finalize_memmgr`] — bootstrap-IPC payload init sends
/// to memmgr in its first `request_round` reply.
///
/// Page counts are packed two per `u64` (low 32 bits = even index,
/// high 32 bits = odd index) so the 64-word IPC data field can carry
/// up to 122 entries after the 3-word prefix.
pub struct MemmgrFinalize
{
    /// First slot of the RAM Frame caps init copied into memmgr's
    /// `CSpace` during finalization.
    pub mm_frame_base: u32,
    /// Number of RAM frames delegated to memmgr.
    pub mm_frame_count: u32,
    /// Page count for each delegated frame, in slot order.
    pub page_counts: [u32; 122],
}

/// Maximum number of frames init can delegate to memmgr in one
/// bootstrap-IPC round. Bounded by the IPC data-word count
/// (`MSG_DATA_WORDS_MAX = 64`) minus the 3-word prefix
/// (`frame_base`, `frame_count`, `procmgr_token`), times 2 for the
/// 2-page-counts-per-word packing.
pub const MEMMGR_BOOTSTRAP_MAX_FRAMES: u32 = 122;

/// Memmgr kernel object caps needed to populate `ProcessInfo`.
struct MemmgrCaps
{
    aspace: u32,
    cspace: u32,
    thread: u32,
    creator_endpoint_slot: u32,
}

/// Populate memmgr's `ProcessInfo` page and map it read-only into memmgr.
#[allow(clippy::similar_names)]
fn populate_memmgr_info(alloc: &mut FrameAlloc, init_aspace: u32, caps: &MemmgrCaps)
-> Option<u32>
{
    let pi_frame = alloc.alloc_zero_page(init_aspace, TEMP_MAP_BASE)?;
    // SAFETY: TEMP_MAP_BASE is mapped writable and zeroed, one page.
    let pi = unsafe { process_abi::process_info_mut(TEMP_MAP_BASE) };

    let mm_thread_in_mm =
        syscall::cap_copy(caps.thread, caps.cspace, syscall::RIGHTS_THREAD).ok()?;
    let mm_aspace_in_mm = syscall::cap_copy(caps.aspace, caps.cspace, syscall::RIGHTS_ALL).ok()?;
    let mm_cspace_in_mm =
        syscall::cap_copy(caps.cspace, caps.cspace, syscall::RIGHTS_CSPACE).ok()?;

    pi.version = PROCESS_ABI_VERSION;
    pi.self_thread_cap = mm_thread_in_mm;
    pi.self_aspace_cap = mm_aspace_in_mm;
    pi.self_cspace_cap = mm_cspace_in_mm;
    pi.ipc_buffer_vaddr = PROCMGR_IPC_BUF_VA;
    pi.creator_endpoint_cap = caps.creator_endpoint_slot;
    pi.procmgr_endpoint_cap = 0;
    pi.memmgr_endpoint_cap = 0;
    pi.stdin_frame_cap = 0;
    pi.stdout_frame_cap = 0;
    pi.stderr_frame_cap = 0;
    pi.log_discovery_cap = 0;
    pi.stdin_data_signal_cap = 0;
    pi.stdin_space_signal_cap = 0;
    pi.stdout_data_signal_cap = 0;
    pi.stdout_space_signal_cap = 0;
    pi.stderr_data_signal_cap = 0;
    pi.stderr_space_signal_cap = 0;

    let _ = syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, 1);

    let pi_ro_cap = syscall::cap_derive(pi_frame, syscall::RIGHTS_MAP_READ).ok()?;
    syscall::mem_map(pi_ro_cap, caps.aspace, PROCESS_INFO_VADDR, 0, 1, 0).ok()?;

    Some(pi_frame)
}

/// Locate a `CapDescriptor` by slot index.
fn descriptor_for(info: &InitInfo, slot: u32) -> Option<&CapDescriptor>
{
    crate::descriptors(info).iter().find(|d| d.slot == slot)
}

/// Set up memmgr's kernel objects, load its ELF, populate `ProcessInfo`,
/// map stack and IPC buffer, and mint the creator + procmgr SEND caps.
/// **Does not delegate frames or start memmgr's thread** — those happen
/// later in [`finalize_memmgr`] so procmgr's setup can still draw from
/// init's frame pool before all remaining frames go to memmgr.
///
/// `init_bootstrap_ep` is init's bootstrap endpoint; init derives a
/// tokened SEND from it and installs it as memmgr's
/// `creator_endpoint_cap`.
///
/// `memmgr_module_idx` is the index of memmgr's ELF in
/// `InitInfo.module_frame_*`. Init uses it to find memmgr's image.
///
/// `mm_service_ep` is the full-rights cap on memmgr's service endpoint
/// (created in init's `CSpace`); init keeps a copy and minted SENDs from it
/// go in each spawned process's `ProcessInfo.memmgr_endpoint_cap`.
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub fn bootstrap_memmgr(
    info: &InitInfo,
    alloc: &mut FrameAlloc,
    init_bootstrap_ep: u32,
    memmgr_module_idx: u32,
    mm_service_ep: u32,
) -> Option<MemmgrBootstrap>
{
    let init_aspace = info.aspace_cap;
    let module_frame_cap = info.module_frame_base + memmgr_module_idx;
    let module_size = descriptor_for(info, module_frame_cap).map(|d| d.aux1)?;
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
    // SAFETY: module frame mapped read-only at TEMP_MAP_BASE.
    let module_bytes =
        unsafe { core::slice::from_raw_parts(TEMP_MAP_BASE as *const u8, module_size as usize) };

    let mm_aspace = syscall::cap_create_aspace().ok()?;
    let mm_cspace = syscall::cap_create_cspace(8192).ok()?;
    let mm_thread = syscall::cap_create_thread(mm_aspace, mm_cspace).ok()?;

    log("created memmgr kernel objects");
    log("loading memmgr ELF segments");

    let entry = load_elf(module_bytes, mm_aspace, alloc, init_aspace)?;
    let _ = syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, module_pages);
    log("loaded memmgr ELF");

    // Tokened creator endpoint for memmgr (init serves the bootstrap round
    // for memmgr, so memmgr's `request_round` lands on init's bootstrap ep
    // tagged with this token).
    let memmgr_token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let tokened_creator =
        syscall::cap_derive_token(init_bootstrap_ep, syscall::RIGHTS_SEND, memmgr_token).ok()?;
    let mm_creator_slot =
        syscall::cap_copy(tokened_creator, mm_cspace, syscall::RIGHTS_SEND).ok()?;

    let mm_caps = MemmgrCaps {
        aspace: mm_aspace,
        cspace: mm_cspace,
        thread: mm_thread,
        creator_endpoint_slot: mm_creator_slot,
    };
    populate_memmgr_info(alloc, init_aspace, &mm_caps)?;
    map_stack_and_ipc(alloc, mm_aspace, PROCMGR_IPC_BUF_VA)?;

    // Mint procmgr's tokened SEND cap on memmgr's endpoint. Memmgr will
    // recognise calls bearing this token as authorised for the
    // procmgr-only labels.
    let procmgr_token_on_mm =
        NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let procmgr_send_cap = syscall::cap_derive_token(
        mm_service_ep,
        syscall::RIGHTS_SEND_GRANT,
        procmgr_token_on_mm,
    )
    .ok()?;

    Some(MemmgrBootstrap {
        bootstrap_token: memmgr_token,
        procmgr_token: procmgr_token_on_mm,
        procmgr_send_cap,
        mm_cspace,
        mm_thread,
        entry,
    })
}

/// Delegate every remaining RAM Frame cap from init's pool into memmgr's
/// `CSpace`, then `thread_configure` + `thread_start` memmgr.
///
/// Call after every `alloc.alloc_page()` consumer (memmgr's own setup,
/// procmgr's setup) has run — at that point everything left in init's
/// frame pool is RAM that memmgr should own. After this call, init has
/// no more frames; subsequent allocations route through memmgr like any
/// other process.
#[allow(clippy::similar_names)]
pub fn finalize_memmgr(
    info: &InitInfo,
    alloc: &mut FrameAlloc,
    mm: &MemmgrBootstrap,
) -> Option<MemmgrFinalize>
{
    // The bootstrap-IPC payload to memmgr packs 2 page_counts per word
    // after a 3-word prefix; up to `MEMMGR_BOOTSTRAP_MAX_FRAMES` entries
    // fit. With memmgr owning all of system RAM, this should comfortably
    // cover any plausible init frame count; raise the bound (or move to
    // multi-round bootstrap) if a target ever exceeds it.
    let mut page_counts = [0u32; MEMMGR_BOOTSTRAP_MAX_FRAMES as usize];
    let mut mm_frame_base: u32 = 0;
    let mut mm_frame_count: u32 = 0;
    let total_remaining = info.memory_frame_count.saturating_sub(alloc.next_idx);
    for i in 0..total_remaining
    {
        if mm_frame_count >= MEMMGR_BOOTSTRAP_MAX_FRAMES
        {
            break;
        }
        let src_slot = info.memory_frame_base + alloc.next_idx + i;
        let bytes = match descriptor_for(info, src_slot)
        {
            Some(d) => d.aux1,
            None => continue,
        };
        let Ok(intermediary) = syscall::cap_derive(src_slot, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        let Ok(dst_slot) = syscall::cap_copy(intermediary, mm.mm_cspace, syscall::RIGHTS_ALL)
        else
        {
            continue;
        };
        if mm_frame_count == 0
        {
            mm_frame_base = dst_slot;
        }
        page_counts[mm_frame_count as usize] = (bytes / PAGE_SIZE) as u32;
        mm_frame_count += 1;
    }
    alloc.next_idx += total_remaining;

    syscall::thread_configure(
        mm.mm_thread,
        mm.entry,
        PROCESS_STACK_TOP,
        PROCESS_INFO_VADDR,
    )
    .ok()?;
    syscall::thread_start(mm.mm_thread).ok()?;
    log("memmgr started");

    Some(MemmgrFinalize {
        mm_frame_base,
        mm_frame_count,
        page_counts,
    })
}

// ── Procmgr bootstrap ───────────────────────────────────────────────────────

/// Procmgr kernel object caps needed to populate `ProcessInfo`.
struct ProcmgrCaps
{
    aspace: u32,
    cspace: u32,
    thread: u32,
    creator_endpoint_slot: u32,
    /// Slot index in procmgr's `CSpace` of the tokened SEND cap on memmgr's
    /// endpoint. Zero when memmgr is not yet wired (early-boot regression
    /// path; never expected after P5).
    memmgr_endpoint_slot: u32,
    /// Slot in procmgr's `CSpace` holding an un-tokened SEND on the system
    /// log endpoint (the "discovery" cap). Std reads it from
    /// `pi.log_discovery_cap` at `_start` and uses it to lazy-acquire a
    /// tokened SEND on first `seraph::log!` call. Zero when no log is
    /// available.
    log_discovery_slot: u32,
    /// `PT_TLS` template metadata, propagated into procmgr's `ProcessInfo`
    /// so spawned-thread allocations (via std) can populate matching
    /// blocks. Zero `memsz` means "no TLS".
    tls: ChildTlsMeta,
}

/// Populate procmgr's `ProcessInfo` page and map it read-only into procmgr.
///
/// procmgr is `no_std` and doesn't drive `std::io::stdio`, so the three
/// stdio cap slots are left zero. The log endpoint procmgr needs (as the
/// source `cap_copy`'d into every child's `ProcessInfo.log_discovery_cap`)
/// arrives via its bootstrap round, not via `ProcessInfo`.
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
    pi.memmgr_endpoint_cap = caps.memmgr_endpoint_slot;
    pi.stdin_frame_cap = 0;
    pi.stdout_frame_cap = 0;
    pi.stderr_frame_cap = 0;
    // Procmgr holds the un-tokened SEND on the log endpoint and
    // `cap_copy`s it into every child's `ProcessInfo.log_discovery_cap`
    // at `CREATE_PROCESS` time. Post-P7 procmgr is std-using and has its
    // own `seraph::log!` surface, so init also installs a discovery
    // SEND here.
    pi.log_discovery_cap = caps.log_discovery_slot;
    pi.stdin_data_signal_cap = 0;
    pi.stdin_space_signal_cap = 0;
    pi.stdout_data_signal_cap = 0;
    pi.stdout_space_signal_cap = 0;
    pi.stderr_data_signal_cap = 0;
    pi.stderr_space_signal_cap = 0;
    pi.tls_template_vaddr = caps.tls.vaddr;
    pi.tls_template_filesz = caps.tls.filesz;
    pi.tls_template_memsz = caps.tls.memsz;
    pi.tls_template_align = caps.tls.align;

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

/// Result of bootstrapping procmgr's setup. Procmgr's thread is
/// configured but **not yet started** — caller invokes [`start_procmgr`]
/// after [`finalize_memmgr`] so memmgr is alive when procmgr's
/// heap-bootstrap fires.
pub struct ProcmgrBootstrap
{
    /// Send cap to procmgr's service endpoint (init uses for `CREATE_PROCESS`).
    pub service_ep: u32,
    /// Procmgr's bootstrap token on init's bootstrap endpoint.
    pub bootstrap_token: u64,
    /// Slot in procmgr's `CSpace` holding an un-tokened SEND cap on the
    /// system log endpoint. Procmgr `cap_copy`s this into every child's
    /// `ProcessInfo.log_discovery_cap` at `CREATE_PROCESS` time. Zero
    /// when no log endpoint is available (very early boot); children
    /// born in that window receive zero and silent-drop `seraph::log!`.
    pub log_endpoint_slot: u32,
    /// Procmgr's main thread cap (in init's `CSpace`). Used by
    /// [`start_procmgr`] to launch procmgr after memmgr is live.
    pub thread: u32,
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
    memmgr_send_cap: u32,
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

    // Allocate, populate, and map the main thread's TLS block while the
    // module is still mapped — `prepare_main_tls` re-validates the ELF
    // headers to locate the `PT_TLS` segment. Procmgr is std-using so the
    // std runtime's `_start` accesses thread-local statics (e.g.
    // `IPC_BUF_TLS`) before user `main` runs; without a configured TLS
    // block, the first such access page-faults at NULL.
    let (pm_tls_base_va, pm_tls_meta) =
        prepare_main_tls(module_bytes, pm_aspace, alloc, init_aspace)?;

    let _ = syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, module_pages);

    log("loaded procmgr ELF");

    // Derive tokened creator endpoint for procmgr.
    let procmgr_token = NEXT_BOOTSTRAP_TOKEN.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let tokened_creator =
        syscall::cap_derive_token(init_bootstrap_ep, syscall::RIGHTS_SEND, procmgr_token).ok()?;
    let pm_creator_slot =
        syscall::cap_copy(tokened_creator, pm_cspace, syscall::RIGHTS_SEND).ok()?;

    // Procmgr no longer maintains its own frame pool (P7 routes every
    // per-child allocation through memmgr). All remaining RAM frames
    // get delegated to memmgr in `finalize_memmgr` after every setup
    // path has finished consuming init's pool.
    let _ = pm_creator_slot;

    // Derive an un-tokened SEND cap on the log endpoint for procmgr.
    // Kept in init's CSpace and sent to procmgr via the bootstrap round
    // (ipc transfer moves it into procmgr's CSpace at a fresh slot).
    // Procmgr `cap_copy`s this into every child's
    // `ProcessInfo.log_discovery_cap` at `CREATE_PROCESS` time.
    let pm_log_send = if log_ep == 0
    {
        0
    }
    else
    {
        syscall::cap_derive(log_ep, syscall::RIGHTS_SEND).ok()?
    };

    // Copy the tokened memmgr SEND cap into procmgr's CSpace. The slot it
    // lands at gets installed in procmgr's `ProcessInfo.memmgr_endpoint_cap`.
    let memmgr_endpoint_slot = if memmgr_send_cap == 0
    {
        0
    }
    else
    {
        syscall::cap_copy(memmgr_send_cap, pm_cspace, syscall::RIGHTS_SEND_GRANT).ok()?
    };

    // Copy a discovery SEND on the log endpoint into procmgr's CSpace so
    // procmgr's own `seraph::log!` calls can `GET_LOG_CAP` on first use.
    // Procmgr is std-using post-P7 and its diagnostics ride the same log
    // surface as every other service; the discovery cap by itself grants
    // no log identity — that comes from the tokened cap returned by
    // `GET_LOG_CAP`.
    let log_discovery_slot = if log_ep == 0
    {
        0
    }
    else
    {
        syscall::cap_copy(log_ep, pm_cspace, syscall::RIGHTS_SEND).ok()?
    };

    let pm_caps = ProcmgrCaps {
        aspace: pm_aspace,
        cspace: pm_cspace,
        thread: pm_thread,
        creator_endpoint_slot: pm_creator_slot,
        memmgr_endpoint_slot,
        log_discovery_slot,
        tls: pm_tls_meta,
    };
    populate_procmgr_info(alloc, init_aspace, &pm_caps)?;

    map_stack_and_ipc(alloc, pm_aspace, PROCMGR_IPC_BUF_VA)?;

    syscall::thread_configure_with_tls(
        pm_thread,
        entry,
        PROCESS_STACK_TOP,
        PROCESS_INFO_VADDR,
        pm_tls_base_va,
    )
    .ok()?;
    // **Don't** thread_start here — procmgr's `_start` calls
    // `heap_bootstrap` which calls memmgr's `REQUEST_FRAMES`, so memmgr
    // must already be ingested + serving before procmgr starts. Caller
    // runs `finalize_memmgr` first, then `start_procmgr`.

    // Derive a send cap to procmgr's service endpoint for init's own use.
    let service_ep_for_init =
        syscall::cap_derive(pm_service_ep, syscall::RIGHTS_SEND_GRANT).ok()?;

    Some(ProcmgrBootstrap {
        service_ep: service_ep_for_init,
        bootstrap_token: procmgr_token,
        log_endpoint_slot: pm_log_send,
        thread: pm_thread,
    })
}

/// Start procmgr's thread. Call after [`finalize_memmgr`] has ingested
/// memmgr's pool and entered the dispatch loop, since procmgr's
/// `_start` calls `heap_bootstrap` which depends on memmgr being live.
pub fn start_procmgr(pm: &ProcmgrBootstrap)
{
    let _ = syscall::thread_start(pm.thread);
    log("procmgr started");
}
