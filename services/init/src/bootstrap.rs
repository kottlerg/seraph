// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// init/src/bootstrap.rs

//! Procmgr bootstrap — raw ELF loading and process creation.
//!
//! Creates procmgr directly via kernel syscalls (no IPC) since procmgr is the
//! first process and no process manager exists yet. Installs procmgr's
//! `creator_endpoint_cap` to point at init's bootstrap endpoint (badged
//! per-child) so procmgr receives its memory-pool bounds via the bootstrap
//! protocol at startup.
//!
//! All subsequent services are created through procmgr IPC.

use crate::logging::log;
use crate::{FrameAlloc, PAGE_SIZE, TEMP_MAP_BASE, arch};
use init_protocol::{CapDescriptor, InitInfo};
use process_abi::{
    DEFAULT_PROCESS_STACK_PAGES, MAX_PROCESS_STACK_PAGES, PROCESS_ABI_VERSION, PROCESS_INFO_VADDR,
    PROCESS_STACK_TOP,
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

// ── Bootstrap arena ────────────────────────────────────────────────────────────
//
// Each tier-1 service (memmgr, procmgr) is backed by one contiguous arena
// Frame cap carved from init's pool. Its front `[0, RETYPE_RESERVE_PAGES)`
// is consumed by the service's `AddressSpace` / `CSpace` / `Thread` retypes
// (a monotonic page-aligned front bump in the cap's `RetypeAllocator`); the
// remainder is offset-mapped page-by-page as the service's loaded backing
// (ELF segments, TLS, `ProcessInfo`, stack, IPC buffer). The retypes each
// hold an ancestor reference on the arena's `FrameObject` for the immortal
// service's life, so init's eventual cap-drop at reap never brings the
// refcount to zero: the offset-mapped backing never dangles and the arena
// never frees into the post-handoff buddy.

/// Front region of a tier-1 service arena reserved for the three kernel-object
/// retypes. `AddressSpace` and `CSpace` each consume `*_RETYPE_PAGES - 1` pages
/// (the value passed as their growth budget); `Thread` consumes
/// `THREAD_RETYPE_PAGES`. The retype bump is page-aligned and monotonic, so
/// backing offsets at or above this bound never collide with a retype slab.
const RETYPE_RESERVE_PAGES: u64 = (crate::ASPACE_RETYPE_PAGES - 1)
    + (crate::CSPACE_RETYPE_PAGES - 1)
    + crate::THREAD_RETYPE_PAGES;

/// Front region of init's own arena reserved for its kernel-object retypes.
///
/// Unlike a tier-1 service, init retypes only endpoints (byte-granular) and
/// one log thread from this arena; it reuses the kernel-supplied
/// `AddressSpace`/`CSpace` rather than creating its own. The reserve is:
///
/// * 1 page for endpoints created before the log-thread retype (the retype
///   allocator packs ~32 endpoints per page; init creates well under that),
/// * `THREAD_RETYPE_PAGES` (6) for the log thread, which page-aligns the bump
///   upward — splitting endpoint packing across a page boundary, and
/// * 1 page for endpoints created after the log-thread retype, so they never
///   bump into the offset-mapped backing region even without relying on the
///   allocator reusing the first page's recovered slack.
///
/// Sound for up to ~32 endpoints on each side of the log-thread retype; init
/// creates roughly a dozen total. [`finalize_memmgr`] asserts the front bump
/// never crossed this bound before forwarding the arena.
pub(crate) const INIT_RETYPE_RESERVE_PAGES: u64 = 1 + crate::THREAD_RETYPE_PAGES + 1;

/// A service's contiguous backing arena: one Frame cap plus a page cursor
/// into its offset-mapped backing region.
pub(crate) struct BootArena
{
    /// Arena Frame cap in init's `CSpace`. Full rights (R+W+X+RETYPE):
    /// retyped from its front, offset-mapped past the retype bump.
    pub(crate) cap: u32,
    /// `AddressSpace` cap the transient per-page scratch maps land in at
    /// [`ELF_PAGE_TEMP_VA`] — always init's own `AddressSpace`.
    init_aspace: u32,
    /// Next free backing-page offset, in pages. Starts at the front reserve;
    /// advances one page per [`Self::place_page`].
    cursor: u64,
}

impl BootArena
{
    /// Carve a `RETYPE_RESERVE_PAGES + backing_pages` contiguous arena off
    /// `alloc` with the cursor positioned past the retype reserve. The
    /// caller performs the three retypes against [`Self::cap`] before
    /// placing any backing page.
    fn carve(alloc: &mut FrameAlloc, init_aspace: u32, backing_pages: u64) -> Option<Self>
    {
        Self::carve_reserve(alloc, init_aspace, RETYPE_RESERVE_PAGES, backing_pages)
    }

    /// Carve a `reserve_pages + backing_pages` contiguous arena off `alloc`
    /// with the cursor positioned past `reserve_pages`. The caller performs
    /// every retype against [`Self::cap`] within the `reserve_pages` front
    /// bound before placing backing pages at or above it.
    pub(crate) fn carve_reserve(
        alloc: &mut FrameAlloc,
        init_aspace: u32,
        reserve_pages: u64,
        backing_pages: u64,
    ) -> Option<Self>
    {
        let cap = alloc.alloc_pages(reserve_pages + backing_pages)?;
        Some(Self {
            cap,
            init_aspace,
            cursor: reserve_pages,
        })
    }

    /// Map the arena's current backing page writable into init at
    /// [`ELF_PAGE_TEMP_VA`], zero it, run `populate` to fill it, unmap it
    /// from init, then map it into `target_aspace` at `target_va` with
    /// `prot`. Advances the cursor. `prot` is an explicit mapping mode
    /// (`MAP_READ` / `MAP_WRITABLE` / `MAP_EXECUTABLE`) applied directly to
    /// the full-rights arena cap — no per-page derived child, so no live
    /// derivation blocks a later `frame_split` of the arena.
    pub(crate) fn place_page(
        &mut self,
        target_aspace: u32,
        target_va: u64,
        prot: u64,
        populate: impl FnOnce(u64),
    ) -> Option<()>
    {
        let offset = self.cursor;
        syscall::mem_map(
            self.cap,
            self.init_aspace,
            ELF_PAGE_TEMP_VA,
            offset,
            1,
            syscall::MAP_WRITABLE,
        )
        .ok()?;
        // SAFETY: ELF_PAGE_TEMP_VA is mapped writable, one page.
        unsafe { core::ptr::write_bytes(ELF_PAGE_TEMP_VA as *mut u8, 0, PAGE_SIZE as usize) };
        populate(ELF_PAGE_TEMP_VA);
        let _ = syscall::mem_unmap(self.init_aspace, ELF_PAGE_TEMP_VA, 1);
        syscall::mem_map(self.cap, target_aspace, target_va, offset, 1, prot).ok()?;
        self.cursor += 1;
        Some(())
    }
}

/// Sum of `PT_LOAD` page spans for `ehdr` — the backing pages an arena must
/// reserve for ELF segments. Mirrors the per-segment page math in
/// [`load_elf_into_arena`]; the two MUST agree or the arena is mis-sized.
fn elf_backing_pages(ehdr: &elf::Elf64Ehdr, module_bytes: &[u8]) -> Option<u64>
{
    let mut total = 0u64;
    for seg_result in elf::load_segments(ehdr, module_bytes)
    {
        let seg = seg_result.ok()?;
        if seg.memsz == 0
        {
            continue;
        }
        let first_page = seg.vaddr & !0xFFF;
        let last_page_end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
        total += (last_page_end - first_page) / PAGE_SIZE;
    }
    Some(total)
}

/// One backing page for the main TLS block when `ehdr` declares a non-empty
/// `PT_TLS`, else zero. Mirrors the presence check in [`place_main_tls`].
fn tls_backing_pages(ehdr: &elf::Elf64Ehdr, module_bytes: &[u8]) -> u64
{
    match elf::tls_segment(ehdr, module_bytes)
    {
        Ok(Some(seg)) if seg.memsz > 0 => 1,
        _ => 0,
    }
}

/// Copy one ELF segment page's file data into the page mapped at
/// `scratch_va` (already zeroed). Handles the partial first/last page via
/// `seg_vaddr` alignment so the loaded image matches the segment's byte
/// layout; the bytes beyond `filesz` stay zero (BSS).
fn copy_segment_into(scratch_va: u64, page_vaddr: u64, seg_vaddr: u64, file_data: &[u8])
{
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
        // SAFETY: scratch_va is mapped writable; the copy stays within one page.
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr(),
                (scratch_va as *mut u8).add(dest_offset),
                src.len(),
            );
        }
    }
}

/// `PT_TLS` template metadata, written into the child's
/// `ProcessInfo.tls_template_*` fields. When the binary has no `PT_TLS`
/// segment, [`place_main_tls`] returns `(0, ChildTlsMeta::default())` and
/// the caller passes `tls_base_va = 0` to `thread_configure_with_tls`.
#[derive(Clone, Copy, Default)]
pub struct ChildTlsMeta
{
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

/// Place the main thread's TLS block in `arena`: populate it from the
/// in-memory `.tdata` template, install the TCB self-pointer, and map it
/// read-write into `target_aspace` at `PROCESS_MAIN_TLS_VADDR`.
///
/// Returns `(tls_base_va, metadata)`. When the binary has no `PT_TLS`
/// segment (or it is empty), returns `(0, ChildTlsMeta::default())` without
/// consuming a backing page — matching [`tls_backing_pages`].
#[allow(clippy::similar_names)]
fn place_main_tls(
    arena: &mut BootArena,
    ehdr: &elf::Elf64Ehdr,
    module_bytes: &[u8],
    target_aspace: u32,
) -> Option<(u64, ChildTlsMeta)>
{
    let Some(seg) = elf::tls_segment(ehdr, module_bytes).ok()?
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

    let tdata_start = seg.offset as usize;
    let tdata_end = tdata_start + seg.filesz as usize;
    if tdata_end > module_bytes.len()
    {
        return None;
    }

    let tls_base_va = process_abi::PROCESS_MAIN_TLS_VADDR + tls_base_offset;
    arena.place_page(
        target_aspace,
        process_abi::PROCESS_MAIN_TLS_VADDR,
        syscall::MAP_WRITABLE,
        |scratch_va| {
            // SAFETY: scratch_va is mapped writable and zeroed; the copy
            // length is bounded by the tls_block_layout fit check above.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    module_bytes[tdata_start..tdata_end].as_ptr(),
                    scratch_va as *mut u8,
                    seg.filesz as usize,
                );
            }
            // SAFETY: scratch_va is mapped writable; the block fits one page.
            unsafe {
                process_abi::tls_install_tcb(scratch_va as *mut u8, tls_base_offset, tls_base_va);
            }
        },
    )?;

    Some((tls_base_va, meta))
}

/// Load an ELF image's `PT_LOAD` segments into `arena`, offset-mapped into
/// `target_aspace` at each segment's virtual address with explicit W^X
/// protection (executable → RX, writable → RW, else RO). Consumes exactly
/// [`elf_backing_pages`] backing pages.
fn load_elf_into_arena(
    arena: &mut BootArena,
    ehdr: &elf::Elf64Ehdr,
    module_bytes: &[u8],
    target_aspace: u32,
) -> Option<()>
{
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
            syscall::MAP_READ
        };

        let first_page = seg.vaddr & !0xFFF;
        let last_page_end = (seg.vaddr + seg.memsz + 0xFFF) & !0xFFF;
        let num_pages = (last_page_end - first_page) / PAGE_SIZE;

        let file_data = &module_bytes[seg.offset as usize..(seg.offset + seg.filesz) as usize];

        for page_idx in 0..num_pages
        {
            let page_vaddr = first_page + page_idx * PAGE_SIZE;
            arena.place_page(target_aspace, page_vaddr, prot, |scratch_va| {
                copy_segment_into(scratch_va, page_vaddr, seg.vaddr, file_data);
            })?;
        }
    }

    Some(())
}

// ── Memmgr bootstrap ────────────────────────────────────────────────────────

/// Result of bootstrapping memmgr's setup (kernel objects + ELF load +
/// PI / stack / IPC mappings + creator endpoint). Frame-pool delegation
/// and `thread_start` happen later via [`finalize_memmgr`] so that
/// procmgr's setup pages can also draw from init's pool before all
/// remaining frames are handed over to memmgr.
pub struct MemmgrBootstrap
{
    /// Init-side bootstrap badge for memmgr's `request_round` reply.
    pub bootstrap_badge: u64,
    /// Badge init used when minting the procmgr-side badged SEND on
    /// memmgr's endpoint. Memmgr stores this and uses it to gate the
    /// procmgr-only labels (`REGISTER_PROCESS`, `PROCESS_DIED`).
    pub procmgr_badge: u64,
    /// Slot in init's `CSpace` of the badged SEND cap on memmgr's
    /// endpoint that init will install in procmgr's `ProcessInfo`.
    pub procmgr_send_cap: u32,
    /// Memmgr's `CSpace` cap (in init's `CSpace`). Init copies RAM
    /// Frame caps into here at [`finalize_memmgr`] time.
    pub mm_cspace: u32,
    /// Memmgr's main `Thread` cap (in init's `CSpace`). Init invokes
    /// `thread_configure` + `thread_start` at [`finalize_memmgr`] time.
    pub mm_thread: u32,
    /// Memmgr's contiguous backing arena Frame cap (in init's `CSpace`).
    /// [`finalize_memmgr`] copies it into memmgr's `CSpace` and forwards it
    /// as an in-use arena so its pages are accounted in memmgr's pool.
    pub arena_cap: u32,
    /// Memmgr's ELF entry point.
    pub entry: u64,
}

/// One in-use bootstrap arena forwarded to memmgr for accounting. Its whole
/// Frame cap is copied into memmgr's `CSpace`; memmgr records it as an
/// `OwnedFrame` against the owning service's record so the arena's pages count
/// toward `pool_total` without ever becoming allocatable. The arena is
/// retype-pinned and offset-mapped for the immortal service's life, so this is
/// pure accounting — memmgr never frees it.
#[derive(Clone, Copy, Default)]
pub struct InUseArena
{
    /// Slot in memmgr's `CSpace` of the copied arena cap.
    pub cap_slot: u32,
    /// Arena size in pages (`RETYPE_RESERVE_PAGES` + backing).
    pub page_count: u32,
    /// Arena physical base.
    pub phys_base: u64,
    /// Owner kind (`ipc::memmgr_bootstrap::IN_USE_KIND_*`).
    pub kind: u64,
}

/// Result of [`finalize_memmgr`] — bootstrap-IPC payload init sends
/// to memmgr in its first `request_round` reply.
///
/// Page counts are packed two per `u64` (low 32 bits = even index,
/// high 32 bits = odd index) so the 64-word IPC data field can carry
/// up to `ipc::memmgr_bootstrap::MAX_FRAMES` entries after the 3-word
/// prefix. Physical bases travel out-of-band via a read-only Frame cap
/// (`caps[1]` in the bootstrap reply); init writes `phys_bases` into the
/// page before deriving the RO cap. Memmgr maps the page, copies the
/// values into its `FreeRun` records, and drops the cap.
pub struct MemmgrFinalize
{
    /// First slot of the RAM Frame caps init copied into memmgr's
    /// `CSpace` during finalization.
    pub mm_frame_base: u32,
    /// Number of RAM frames delegated to memmgr.
    pub mm_frame_count: u32,
    /// Page count for each delegated frame, in slot order.
    pub page_counts: [u32; ipc::memmgr_bootstrap::MAX_FRAMES],
    /// Physical base address for each delegated frame, in slot order.
    /// Sourced from `CapDescriptor.aux0` of the underlying RAM Frame
    /// caps minted by the kernel at boot.
    pub phys_bases: [u64; ipc::memmgr_bootstrap::MAX_FRAMES],
    /// In-use bootstrap arenas (memmgr's, procmgr's, and init's own
    /// backing) copied into memmgr's `CSpace`. Init writes these into the
    /// phys-table page's in-use section; memmgr records them against
    /// per-owner process records.
    pub in_use: [InUseArena; ipc::memmgr_bootstrap::MAX_IN_USE],
    /// Number of valid entries in `in_use`.
    pub in_use_count: usize,
}

/// Memmgr kernel object caps needed to populate `ProcessInfo`.
struct MemmgrCaps
{
    aspace: u32,
    cspace: u32,
    thread: u32,
    creator_endpoint_slot: u32,
}

/// Populate memmgr's `ProcessInfo` page from `arena` and map it read-only
/// into `target_aspace`.
#[allow(clippy::similar_names)]
fn populate_memmgr_info(
    arena: &mut BootArena,
    target_aspace: u32,
    caps: &MemmgrCaps,
    stack_pages: u32,
) -> Option<()>
{
    let mm_thread_in_mm =
        syscall::cap_copy(caps.thread, caps.cspace, syscall::RIGHTS_THREAD).ok()?;
    let mm_aspace_in_mm = syscall::cap_copy(caps.aspace, caps.cspace, syscall::RIGHTS_ALL).ok()?;
    let mm_cspace_in_mm =
        syscall::cap_copy(caps.cspace, caps.cspace, syscall::RIGHTS_CSPACE).ok()?;

    arena.place_page(
        target_aspace,
        PROCESS_INFO_VADDR,
        syscall::MAP_READ,
        |scratch_va| {
            // SAFETY: scratch_va is mapped writable and zeroed, one page.
            let pi = unsafe { process_abi::process_info_mut(scratch_va) };
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
            pi.log_send_cap = 0;
            pi.stdin_data_notification_cap = 0;
            pi.stdin_space_notification_cap = 0;
            pi.stdout_data_notification_cap = 0;
            pi.stdout_space_notification_cap = 0;
            pi.stderr_data_notification_cap = 0;
            pi.stderr_space_notification_cap = 0;
            pi.stack_top_vaddr = PROCESS_STACK_TOP;
            pi.stack_pages = stack_pages;
        },
    )?;

    Some(())
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
/// badged SEND from it and installs it as memmgr's
/// `creator_endpoint_cap`.
///
/// The memmgr boot module is located in [`InitInfo`] by name via
/// [`crate::find_module_by_name`] (init-protocol v7+).
///
/// `mm_service_ep` is the full-rights cap on memmgr's service endpoint
/// (created in init's `CSpace`); init keeps a copy and minted SENDs from it
/// go in each spawned process's `ProcessInfo.memmgr_endpoint_cap`.
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub fn bootstrap_memmgr(
    info: &InitInfo,
    alloc: &mut FrameAlloc,
    init_bootstrap_ep: u32,
    mm_service_ep: u32,
) -> Option<MemmgrBootstrap>
{
    let init_aspace = info.aspace_cap;
    let module_frame_cap = crate::find_module_by_name(info, b"memmgr")?;
    let module_size = descriptor_for(info, module_frame_cap).map(|d| d.aux1)?;
    let module_pages = (module_size + 0xFFF) / PAGE_SIZE;

    // The module Frame cap carries full rights (R+W+X+RETYPE): init retains
    // it as the module-source owner and donates it to memmgr's pool at reap,
    // where RETYPE lets memmgr re-derive. Derive a read-only child cap for the
    // load-time mapping so `mem_map`'s derive-from-cap path produces a strictly
    // read-only page (otherwise W+X cap rights trip W^X).
    let module_ro = syscall::cap_derive(module_frame_cap, syscall::RIGHTS_MAP_READ).ok()?;
    syscall::mem_map(
        module_ro,
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

    let ehdr = elf::validate(module_bytes, arch::current::EXPECTED_ELF_MACHINE).ok()?;
    let entry = elf::entry_point(ehdr);
    let stack_pages = elf::parse_stack_note(ehdr, module_bytes)
        .unwrap_or(DEFAULT_PROCESS_STACK_PAGES)
        .clamp(1, MAX_PROCESS_STACK_PAGES);

    // memmgr's bespoke `_start` configures no TLS, so its arena reserves
    // only ELF segments + `ProcessInfo` + stack + IPC buffer.
    let backing_pages = elf_backing_pages(ehdr, module_bytes)? + 1 + u64::from(stack_pages) + 1;
    let mut arena = BootArena::carve(alloc, init_aspace, backing_pages)?;

    let mm_aspace =
        syscall::cap_create_aspace(arena.cap, 0, crate::ASPACE_RETYPE_PAGES - 1).ok()?;
    let mm_cspace =
        syscall::cap_create_cspace(arena.cap, 0, crate::CSPACE_RETYPE_PAGES - 1, 8192).ok()?;
    let mm_thread = syscall::cap_create_thread(arena.cap, mm_aspace, mm_cspace).ok()?;

    log("created memmgr kernel objects");
    log("loading memmgr ELF segments");

    load_elf_into_arena(&mut arena, ehdr, module_bytes, mm_aspace)?;
    let _ = syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, module_pages);
    let _ = syscall::cap_delete(module_ro);
    log("loaded memmgr ELF");

    // Badged creator endpoint for memmgr (init serves the bootstrap round
    // for memmgr, so memmgr's `request_round` lands on init's bootstrap ep
    // tagged with this badge).
    let memmgr_badge = NEXT_BOOTSTRAP_BADGE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let badged_creator =
        syscall::cap_derive_badge(init_bootstrap_ep, syscall::RIGHTS_SEND, memmgr_badge).ok()?;
    let mm_creator_slot =
        syscall::cap_copy(badged_creator, mm_cspace, syscall::RIGHTS_SEND).ok()?;

    let mm_caps = MemmgrCaps {
        aspace: mm_aspace,
        cspace: mm_cspace,
        thread: mm_thread,
        creator_endpoint_slot: mm_creator_slot,
    };
    populate_memmgr_info(&mut arena, mm_aspace, &mm_caps, stack_pages)?;
    place_stack_and_ipc(&mut arena, mm_aspace, PROCMGR_IPC_BUF_VA, stack_pages)?;

    // Mint procmgr's badged SEND cap on memmgr's endpoint. Memmgr will
    // recognise calls bearing this badge as authorised for the
    // procmgr-only labels.
    let procmgr_badge_on_mm =
        NEXT_BOOTSTRAP_BADGE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let procmgr_send_cap = syscall::cap_derive_badge(
        mm_service_ep,
        syscall::RIGHTS_SEND_GRANT,
        procmgr_badge_on_mm,
    )
    .ok()?;

    Some(MemmgrBootstrap {
        bootstrap_badge: memmgr_badge,
        procmgr_badge: procmgr_badge_on_mm,
        procmgr_send_cap,
        mm_cspace,
        mm_thread,
        arena_cap: arena.cap,
        entry,
    })
}

/// Copy one in-use bootstrap arena cap into memmgr's `CSpace` and build its
/// [`InUseArena`] descriptor. Mirrors the free-run forward: derive a
/// full-rights intermediary, copy it into `mm_cspace`, and read the arena's
/// physical base + size from the cap. The arena is exact-sized (no free
/// tail), so it is never `frame_split`; the copy gives memmgr the accounting
/// anchor while the original cap and the retypes keep the `FrameObject`
/// pinned for the immortal service's life.
fn forward_arena(arena_cap: u32, mm_cspace: u32, kind: u64) -> Option<InUseArena>
{
    let phys_base = syscall::cap_info(arena_cap, syscall::CAP_INFO_FRAME_PHYS_BASE).ok()?;
    let size_bytes = syscall::cap_info(arena_cap, syscall::CAP_INFO_FRAME_SIZE).ok()?;
    let intermediary = syscall::cap_derive(arena_cap, syscall::RIGHTS_ALL).ok()?;
    let cap_slot = syscall::cap_copy(intermediary, mm_cspace, syscall::RIGHTS_ALL).ok()?;
    Some(InUseArena {
        cap_slot,
        page_count: (size_bytes / PAGE_SIZE) as u32,
        phys_base,
        kind,
    })
}

/// Forward a single Frame cap covering `pages` free pages into memmgr's
/// `CSpace` as a free run: derive a full-rights intermediary, copy it into
/// `mm_cspace`, and append the run to the parallel `page_counts`/`phys_bases`
/// tables (advancing `count`, recording `base` on the first run). Used for the
/// `FrameAlloc` tail and the transient phys-table page — both `frame_split`
/// products with no `InitInfo` descriptor that would otherwise free into the
/// sealed post-handoff buddy.
#[allow(clippy::too_many_arguments)]
fn push_free_run(
    src_cap: u32,
    pages: u32,
    mm_cspace: u32,
    page_counts: &mut [u32],
    phys_bases: &mut [u64],
    base: &mut u32,
    count: &mut u32,
)
{
    if pages == 0 || (*count as usize) >= page_counts.len()
    {
        return;
    }
    if let Ok(phys_base) = syscall::cap_info(src_cap, syscall::CAP_INFO_FRAME_PHYS_BASE)
        && let Ok(intermediary) = syscall::cap_derive(src_cap, syscall::RIGHTS_ALL)
        && let Ok(dst_slot) = syscall::cap_copy(intermediary, mm_cspace, syscall::RIGHTS_ALL)
    {
        if *count == 0
        {
            *base = dst_slot;
        }
        page_counts[*count as usize] = pages;
        phys_bases[*count as usize] = phys_base;
        *count += 1;
    }
}

/// Assert init's arena retype front never crossed its reserve into the
/// offset-mapped backing region. init's endpoint and log-thread retypes bump a
/// monotonic cursor through the front; the backing was offset-mapped at
/// `INIT_RETYPE_RESERVE_PAGES`. `available` is the arena's un-retyped byte
/// count, so a front bump past the reserve shows up as a consumed span larger
/// than the reserve. Endpoints created after `finalize_memmgr` (devmgr/vfsd
/// registries, phase 3) stay within the reserve's documented headroom.
fn assert_init_arena_front_bounded(init_arena_cap: u32)
{
    if let (Ok(size), Ok(available)) = (
        syscall::cap_info(init_arena_cap, syscall::CAP_INFO_FRAME_SIZE),
        syscall::cap_info(init_arena_cap, syscall::CAP_INFO_FRAME_AVAILABLE),
    )
    {
        let front_bump = size.saturating_sub(available);
        assert!(
            front_bump <= INIT_RETYPE_RESERVE_PAGES * PAGE_SIZE,
            "init: arena retype front overran its reserve into backing",
        );
    }
}

/// Delegate every remaining RAM Frame cap from init's pool into memmgr's
/// `CSpace`, forward the in-use bootstrap arenas (memmgr's, procmgr's, and
/// init's own backing), then `thread_configure` + `thread_start` memmgr.
///
/// Call after every `alloc.alloc_page()` consumer (memmgr's own setup,
/// procmgr's setup) has run — at that point everything left in init's
/// frame pool is RAM that memmgr should own. After this call, init has
/// no more frames; subsequent allocations route through memmgr like any
/// other process.
///
/// `pm_arena_cap` is procmgr's backing arena and `init_arena_cap` is init's own
/// (from [`ProcmgrBootstrap`] and [`crate::run`]); both are forwarded alongside
/// memmgr's own arena (`mm.arena_cap`) so memmgr's `pool_total` spans every page
/// of bootstrap-consumed RAM, not only the free runs.
///
/// `phys_table_frame` is the auxiliary phys-table page (written after this
/// call). It is a transient bootstrap artifact, so it is forwarded as a free
/// run — its keep-alive moves to memmgr's pool copy, and after memmgr reads it
/// through the read-only `caps[1]` derivation the page becomes allocatable like
/// any other.
#[allow(clippy::similar_names, clippy::too_many_lines)]
pub fn finalize_memmgr(
    info: &InitInfo,
    alloc: &mut FrameAlloc,
    mm: &MemmgrBootstrap,
    pm_arena_cap: u32,
    init_arena_cap: u32,
    phys_table_frame: u32,
) -> Option<MemmgrFinalize>
{
    // The bootstrap-IPC payload to memmgr packs 2 page_counts per word after
    // a 3-word prefix; `ipc::memmgr_bootstrap::MAX_FRAMES` entries fit, of
    // which the loop below claims at most `MAX_FRAMES - 2` for regular memory
    // frames and leaves two for the FrameAlloc tail and the phys-table page.
    // That is enough to seed memmgr's pool for procmgr's first allocations;
    // any regular frames beyond the cap (the buddy can drain into more blocks
    // than fit when the memory map is fragmented) are delivered later via the
    // reap-donation route (`handoff_to_procmgr_reap` → procmgr →
    // `DONATE_FRAMES`), which streams without a per-round cap. So this bound is
    // a round-size limit, not a ceiling on total RAM forwarded — the reap floor
    // below picks up the rest. (The tail and phys-table page have no InitInfo
    // descriptor, so the reap walk cannot reach them; they must ride here.)
    let mut page_counts = [0u32; ipc::memmgr_bootstrap::MAX_FRAMES];
    let mut phys_bases = [0u64; ipc::memmgr_bootstrap::MAX_FRAMES];
    let mut mm_frame_base: u32 = 0;
    let mut mm_frame_count: u32 = 0;
    let total_remaining = info.memory_frame_count.saturating_sub(alloc.next_idx);
    for i in 0..total_remaining
    {
        // Reserve two payload slots for the FrameAlloc tail and the phys-table
        // page forwarded below. Both are `frame_split` products with no
        // InitInfo descriptor, so the reap walk cannot reach them — they MUST
        // ride this bootstrap round. Regular frames that no longer fit are
        // delivered to memmgr's pool via reap instead.
        if mm_frame_count as usize >= ipc::memmgr_bootstrap::MAX_FRAMES - 2
        {
            break;
        }
        let src_slot = info.memory_frame_base + alloc.next_idx + i;
        let Some(desc) = descriptor_for(info, src_slot)
        else
        {
            // Keep the forwarded set a contiguous prefix: stop here and let
            // the reap route donate this frame and everything after it.
            break;
        };
        let bytes = desc.aux1;
        let phys_base = desc.aux0;
        // Every RAM Frame cap init forwards to memmgr MUST carry
        // `Rights::RETYPE`. The kernel stamps RETYPE on usable RAM at
        // Phase-7 mint (`core/kernel/src/cap/mod.rs`); init holds these
        // caps unchanged. If this assertion ever fires, memmgr will be
        // unable to retype frames into kernel objects and the typed-memory
        // contract is broken. `cap_info` on a non-null slot never fails for
        // the universal `TAG_RIGHTS` field; an Err here means the cap-
        // routing graph is broken and the bootstrap invariant fails.
        let Ok(packed) = syscall::cap_info(src_slot, syscall::CAP_INFO_TAG_RIGHTS)
        else
        {
            panic!("init: cap_info failed on RAM Frame cap before memmgr forward");
        };
        // Packed value is `(tag << 32) | rights`; `RIGHTS_RETYPE` is a
        // low-bit-position right so the u64 mask is exact.
        assert!(
            packed & syscall::RIGHTS_RETYPE != 0,
            "init: RAM Frame cap missing RIGHTS_RETYPE before memmgr forward",
        );
        let Ok(intermediary) = syscall::cap_derive(src_slot, syscall::RIGHTS_ALL)
        else
        {
            break;
        };
        let Ok(dst_slot) = syscall::cap_copy(intermediary, mm.mm_cspace, syscall::RIGHTS_ALL)
        else
        {
            break;
        };
        if mm_frame_count == 0
        {
            mm_frame_base = dst_slot;
        }
        page_counts[mm_frame_count as usize] = (bytes / PAGE_SIZE) as u32;
        phys_bases[mm_frame_count as usize] = phys_base;
        mm_frame_count += 1;
    }
    // Advance only past the frames actually forwarded this round (a
    // contiguous prefix — the loop breaks on the first frame it cannot
    // forward). `memory_frame_base + alloc.next_idx` is now the reap floor:
    // every memory-frame cap at or above it is still solely init's, never
    // handed out by `FrameAlloc` nor forwarded here, and is donated to
    // memmgr's pool via the reap route, which has no per-round frame cap.
    alloc.next_idx += mm_frame_count;

    // Forward the partial tail left in `alloc.current`: the unallocated
    // remainder of the last frame `FrameAlloc` split from. It is a
    // `frame_split` product, so it carries no named `InitInfo` descriptor and
    // is excluded from the reap donation walk; without this it would free into
    // the post-handoff buddy (which nothing allocates from) and be lost. It is
    // free RAM, so it joins memmgr's pool as a run like any forwarded frame.
    if alloc.remaining >= PAGE_SIZE
    {
        let tail_pages = (alloc.remaining / PAGE_SIZE) as u32;
        push_free_run(
            alloc.current,
            tail_pages,
            mm.mm_cspace,
            &mut page_counts,
            &mut phys_bases,
            &mut mm_frame_base,
            &mut mm_frame_count,
        );
        alloc.remaining = 0;
    }

    // Forward the transient phys-table page as a free run too (same rationale
    // as the tail: a descriptor-less `frame_split` product). Its content is
    // written after this call and read once by memmgr through the read-only
    // `caps[1]` derivation; the free-run copy is the page's keep-alive, and
    // after the read the page is allocatable like any other.
    push_free_run(
        phys_table_frame,
        1,
        mm.mm_cspace,
        &mut page_counts,
        &mut phys_bases,
        &mut mm_frame_base,
        &mut mm_frame_count,
    );

    // Forward the in-use bootstrap arenas. These are the RAM init carved to
    // back memmgr, procmgr, and itself (retype slabs + offset-mapped
    // ELF/stack/IPC/PI); they are retype-pinned and never freed, but their
    // pages belong in memmgr's `pool_total` so the all-RAM-accounted identity
    // closes. memmgr records each against the owning service's process record.
    // init's arena is forwarded here even though init exits at reap: memmgr's
    // copy becomes the arena's permanent keep-alive and the pages stay parked
    // and accounted.
    let mut in_use = [InUseArena::default(); ipc::memmgr_bootstrap::MAX_IN_USE];
    let mut in_use_count = 0usize;
    for (cap, kind) in [
        (mm.arena_cap, ipc::memmgr_bootstrap::IN_USE_KIND_MEMMGR),
        (pm_arena_cap, ipc::memmgr_bootstrap::IN_USE_KIND_PROCMGR),
        (init_arena_cap, ipc::memmgr_bootstrap::IN_USE_KIND_INIT),
    ]
    {
        if let Some(arena) = forward_arena(cap, mm.mm_cspace, kind)
        {
            in_use[in_use_count] = arena;
            in_use_count += 1;
        }
    }

    assert_init_arena_front_bounded(init_arena_cap);

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
        phys_bases,
        in_use,
        in_use_count,
    })
}

/// Write memmgr's bootstrap aux (phys-table) page from `mm_final`: the
/// per-free-run physical bases, the kernel's immutable RAM-accounting facts
/// (from `info`), and the in-use bootstrap arena descriptors. The layout is
/// defined in `ipc::memmgr_bootstrap`; memmgr's `bootstrap_from_init` reads it
/// back through the read-only cap init derives from the same page.
///
/// # Safety
/// `phys_dst` must point at init's writable mapping of the one-page phys-table
/// frame (at least 4 KiB, `u64`-aligned).
pub unsafe fn write_memmgr_aux_frame(phys_dst: *mut u64, info: &InitInfo, mm_final: &MemmgrFinalize)
{
    use ipc::memmgr_bootstrap as mb;

    for i in 0..(mm_final.mm_frame_count as usize)
    {
        // SAFETY: i < mm_frame_count <= MAX_FRAMES; within the mapped page.
        unsafe { core::ptr::write_volatile(phys_dst.add(i), mm_final.phys_bases[i]) };
    }
    // SAFETY: the facts and in-use-count indices lie within the mapped page.
    unsafe {
        core::ptr::write_volatile(
            phys_dst.add(mb::FACTS_SYSTEM_RAM_IDX),
            info.system_ram_bytes,
        );
        core::ptr::write_volatile(
            phys_dst.add(mb::FACTS_KERNEL_RESERVED_IDX),
            info.kernel_reserved_bytes,
        );
        core::ptr::write_volatile(
            phys_dst.add(mb::IN_USE_COUNT_IDX),
            mm_final.in_use_count as u64,
        );
    }
    for i in 0..mm_final.in_use_count
    {
        let arena = mm_final.in_use[i];
        let base = mb::IN_USE_BASE_IDX + i * mb::IN_USE_WORDS;
        // SAFETY: base + 2 < IN_USE_BASE_IDX + MAX_IN_USE * IN_USE_WORDS, within the page.
        unsafe {
            core::ptr::write_volatile(
                phys_dst.add(base),
                u64::from(arena.cap_slot) | (u64::from(arena.page_count) << 32),
            );
            core::ptr::write_volatile(phys_dst.add(base + 1), arena.phys_base);
            core::ptr::write_volatile(phys_dst.add(base + 2), arena.kind);
        }
    }
}

// ── Procmgr bootstrap ───────────────────────────────────────────────────────

/// Procmgr kernel object caps needed to populate `ProcessInfo`.
struct ProcmgrCaps
{
    aspace: u32,
    cspace: u32,
    thread: u32,
    creator_endpoint_slot: u32,
    /// Slot index in procmgr's `CSpace` of the badged SEND cap on memmgr's
    /// endpoint. Zero when memmgr is not yet wired — an early-boot-only
    /// condition.
    memmgr_endpoint_slot: u32,
    /// Slot in procmgr's `CSpace` holding a badged SEND on the
    /// system log endpoint with badge `LOG_BADGE_PROCMGR`. Std reads
    /// it from `pi.log_send_cap` at `_start` and installs it via
    /// `::log::install_badged_cap` for procmgr's own `seraph::log!`
    /// writes. Zero when no log endpoint is available.
    log_send_slot: u32,
    /// `PT_TLS` template metadata, propagated into procmgr's `ProcessInfo`
    /// so spawned-thread allocations (via std) can populate matching
    /// blocks. Zero `memsz` means "no TLS".
    tls: ChildTlsMeta,
}

/// Populate procmgr's `ProcessInfo` page and map it read-only into procmgr.
///
/// procmgr's stdio cap slots are left zero (procmgr is std-built but
/// does not drive interactive stdio). The un-badged SEND on
/// the log endpoint procmgr uses as the *source* for deriving badged
/// SEND caps per child arrives via procmgr's bootstrap round, not via
/// `ProcessInfo`. The pre-installed badged SEND cap procmgr uses for
/// its OWN `seraph::log!` writes lives in `pi.log_send_cap`.
#[allow(clippy::similar_names)]
fn populate_procmgr_info(
    arena: &mut BootArena,
    target_aspace: u32,
    caps: &ProcmgrCaps,
    stack_pages: u32,
) -> Option<()>
{
    let pm_thread_in_pm =
        syscall::cap_copy(caps.thread, caps.cspace, syscall::RIGHTS_THREAD).ok()?;
    let pm_aspace_in_pm = syscall::cap_copy(caps.aspace, caps.cspace, syscall::RIGHTS_ALL).ok()?;
    let pm_cspace_in_pm =
        syscall::cap_copy(caps.cspace, caps.cspace, syscall::RIGHTS_CSPACE).ok()?;

    arena.place_page(
        target_aspace,
        PROCESS_INFO_VADDR,
        syscall::MAP_READ,
        |scratch_va| {
            // SAFETY: scratch_va is mapped writable and zeroed, one page.
            let pi = unsafe { process_abi::process_info_mut(scratch_va) };
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
            // Procmgr's own `seraph::log!` surface. The slot holds a badged
            // SEND cap on the log endpoint with badge `LOG_BADGE_PROCMGR`,
            // derived by init via `cap_derive_badge`. Procmgr's std `_start`
            // installs it via `::log::install_badged_cap`. The un-badged
            // SEND procmgr uses to derive per-child badged caps is separate
            // (delivered via procmgr's bootstrap round).
            pi.log_send_cap = caps.log_send_slot;
            pi.stdin_data_notification_cap = 0;
            pi.stdin_space_notification_cap = 0;
            pi.stdout_data_notification_cap = 0;
            pi.stdout_space_notification_cap = 0;
            pi.stderr_data_notification_cap = 0;
            pi.stderr_space_notification_cap = 0;
            pi.tls_template_vaddr = caps.tls.vaddr;
            pi.tls_template_filesz = caps.tls.filesz;
            pi.tls_template_memsz = caps.tls.memsz;
            pi.tls_template_align = caps.tls.align;
            pi.stack_top_vaddr = PROCESS_STACK_TOP;
            pi.stack_pages = stack_pages;
        },
    )?;

    Some(())
}

/// Place the stack and IPC buffer pages in `arena`, zeroed and mapped
/// read-write into `target_aspace`. Consumes `stack_pages + 1` backing
/// pages.
fn place_stack_and_ipc(
    arena: &mut BootArena,
    target_aspace: u32,
    ipc_buf_va: u64,
    stack_pages: u32,
) -> Option<()>
{
    let stack_base = PROCESS_STACK_TOP - u64::from(stack_pages) * PAGE_SIZE;
    for i in 0..stack_pages
    {
        arena.place_page(
            target_aspace,
            stack_base + u64::from(i) * PAGE_SIZE,
            syscall::MAP_WRITABLE,
            |_| {},
        )?;
    }
    arena.place_page(target_aspace, ipc_buf_va, syscall::MAP_WRITABLE, |_| {})?;
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
    /// Procmgr's bootstrap badge on init's bootstrap endpoint.
    pub bootstrap_badge: u64,
    /// Slot in procmgr's `CSpace` holding an un-badged SEND cap on
    /// the system log endpoint, used by procmgr as the *source* for
    /// `cap_derive_badge` to mint a badged SEND cap per child (badge =
    /// the child's process badge). The minted cap is placed in the
    /// child's `ProcessInfo.log_send_cap`. Zero when no log endpoint
    /// is available (very early boot); children born in that window
    /// receive zero and silent-drop `seraph::log!`.
    pub log_endpoint_slot: u32,
    /// Slot in procmgr's `CSpace` holding an un-badged SEND cap on
    /// svcmgr's service endpoint (the global service registry).
    /// Procmgr uses it as the *source* for `cap_derive_badge` to mint
    /// a badged SEND cap per child (badge = the child's process
    /// badge, no `PUBLISH_AUTHORITY` bit), which is placed in the
    /// child's `ProcessInfo.service_registry_cap`. The child can
    /// `QUERY_ENDPOINT` but not `PUBLISH_ENDPOINT` — publish-authority
    /// caps are minted separately and handed only to init / devmgr /
    /// svcmgr.
    pub registry_endpoint_slot: u32,
    /// Procmgr's main thread cap (in init's `CSpace`). Used by
    /// [`start_procmgr`] to launch procmgr after memmgr is live.
    pub thread: u32,
    /// Procmgr's contiguous backing arena Frame cap (in init's `CSpace`).
    /// [`finalize_memmgr`] copies it into memmgr's `CSpace` and forwards it
    /// as an in-use arena so its pages are accounted in memmgr's pool.
    pub arena_cap: u32,
}

/// Monotonic counter for init-side bootstrap badges.
pub static NEXT_BOOTSTRAP_BADGE: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(1);

/// Create and start procmgr from its boot module ELF image.
///
/// `init_bootstrap_ep` is init's bootstrap endpoint; a badged send cap is
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
// too_many_lines: linear bootstrap workflow (CSpace setup, ELF load, TLS
// prep, per-purpose cap derivation for log + registry + memmgr) reads
// straight-through; extracting helpers would just shuffle state through
// extra parameters.
#[allow(
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]
pub fn bootstrap_procmgr(
    info: &InitInfo,
    alloc: &mut FrameAlloc,
    init_bootstrap_ep: u32,
    pm_service_ep: u32,
    log_ep: u32,
    svcmgr_service_ep: u32,
    memmgr_send_cap: u32,
) -> Option<ProcmgrBootstrap>
{
    let init_aspace = info.aspace_cap;

    let module_frame_cap = crate::find_module_by_name(info, b"procmgr")?;
    let module_size = crate::descriptors(info)
        .iter()
        .find(|d| d.slot == module_frame_cap)
        .map(|d| d.aux1)?;

    let module_pages = (module_size + 0xFFF) / PAGE_SIZE;

    // Derive a read-only child cap (see `bootstrap_memmgr` for rationale).
    let module_ro = syscall::cap_derive(module_frame_cap, syscall::RIGHTS_MAP_READ).ok()?;
    syscall::mem_map(
        module_ro,
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

    let ehdr = elf::validate(module_bytes, arch::current::EXPECTED_ELF_MACHINE).ok()?;
    let entry = elf::entry_point(ehdr);
    let stack_pages = elf::parse_stack_note(ehdr, module_bytes)
        .unwrap_or(DEFAULT_PROCESS_STACK_PAGES)
        .clamp(1, MAX_PROCESS_STACK_PAGES);

    // procmgr is std-using: its arena reserves ELF segments + the main TLS
    // block + `ProcessInfo` + stack + IPC buffer.
    let backing_pages = elf_backing_pages(ehdr, module_bytes)?
        + tls_backing_pages(ehdr, module_bytes)
        + 1
        + u64::from(stack_pages)
        + 1;
    let mut arena = BootArena::carve(alloc, init_aspace, backing_pages)?;

    let pm_aspace =
        syscall::cap_create_aspace(arena.cap, 0, crate::ASPACE_RETYPE_PAGES - 1).ok()?;
    let pm_cspace =
        syscall::cap_create_cspace(arena.cap, 0, crate::CSPACE_RETYPE_PAGES - 1, 8192).ok()?;
    let pm_thread = syscall::cap_create_thread(arena.cap, pm_aspace, pm_cspace).ok()?;

    log("created procmgr kernel objects");
    log("loading procmgr ELF segments");

    load_elf_into_arena(&mut arena, ehdr, module_bytes, pm_aspace)?;

    // Place the main thread's TLS block while the module is still mapped —
    // `place_main_tls` reads the `PT_TLS` template from it. Procmgr is
    // std-using so the std runtime's `_start` accesses thread-local statics
    // (e.g. `IPC_BUF_TLS`) before user `main` runs; without a configured TLS
    // block, the first such access page-faults at NULL.
    let (pm_tls_base_va, pm_tls_meta) = place_main_tls(&mut arena, ehdr, module_bytes, pm_aspace)?;

    let _ = syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, module_pages);
    let _ = syscall::cap_delete(module_ro);

    log("loaded procmgr ELF");

    // Derive badged creator endpoint for procmgr.
    let procmgr_badge = NEXT_BOOTSTRAP_BADGE.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let badged_creator =
        syscall::cap_derive_badge(init_bootstrap_ep, syscall::RIGHTS_SEND, procmgr_badge).ok()?;
    let pm_creator_slot =
        syscall::cap_copy(badged_creator, pm_cspace, syscall::RIGHTS_SEND).ok()?;

    // Procmgr maintains no frame pool of its own; every per-child
    // allocation routes through memmgr. All remaining RAM frames get
    // delegated to memmgr in `finalize_memmgr` after every setup path
    // has finished consuming init's pool.
    let _ = pm_creator_slot;

    // Derive an un-badged SEND cap on the log endpoint for procmgr.
    // Kept in init's CSpace and sent to procmgr via the bootstrap round
    // (ipc transfer moves it into procmgr's CSpace at a fresh slot).
    // Procmgr uses it as the *source* for `cap_derive_badge` to mint a
    // badged SEND cap per child it spawns.
    let pm_log_send = if log_ep == 0
    {
        0
    }
    else
    {
        syscall::cap_derive(log_ep, syscall::RIGHTS_SEND).ok()?
    };

    // Derive an un-badged SEND cap on svcmgr's service endpoint for
    // procmgr. Kept in init's CSpace and sent to procmgr via the
    // bootstrap round; procmgr uses it as the *source* for
    // `cap_derive_badge` to mint a badged SEND cap per child it
    // spawns, which becomes that child's
    // `ProcessInfo.service_registry_cap`. Per-child badges omit the
    // `PUBLISH_AUTHORITY` bit so children can `QUERY_ENDPOINT` but
    // not `PUBLISH_ENDPOINT`.
    let pm_registry_send = if svcmgr_service_ep == 0
    {
        0
    }
    else
    {
        syscall::cap_derive(svcmgr_service_ep, syscall::RIGHTS_SEND).ok()?
    };

    // Copy the badged memmgr SEND cap into procmgr's CSpace. The slot it
    // lands at gets installed in procmgr's `ProcessInfo.memmgr_endpoint_cap`.
    let memmgr_endpoint_slot = if memmgr_send_cap == 0
    {
        0
    }
    else
    {
        syscall::cap_copy(memmgr_send_cap, pm_cspace, syscall::RIGHTS_SEND_GRANT).ok()?
    };

    // Derive procmgr's pre-installed badged SEND cap on the log
    // endpoint. Badge = `LOG_BADGE_PROCMGR` (reserved). Procmgr's
    // `seraph::log!` writes ride this cap; logd attributes them by the
    // kernel-delivered badge. Init derives in its own CSpace then
    // copies into procmgr's, mirroring the rights of every other
    // procmgr-CSpace seed.
    let log_send_slot = if log_ep == 0
    {
        0
    }
    else
    {
        let init_side = syscall::cap_derive_badge(
            log_ep,
            syscall::RIGHTS_SEND,
            ipc::log_badges::LOG_BADGE_PROCMGR,
        )
        .ok()?;
        let pm_side = syscall::cap_copy(init_side, pm_cspace, syscall::RIGHTS_SEND).ok()?;
        let _ = syscall::cap_delete(init_side);
        pm_side
    };

    let pm_caps = ProcmgrCaps {
        aspace: pm_aspace,
        cspace: pm_cspace,
        thread: pm_thread,
        creator_endpoint_slot: pm_creator_slot,
        memmgr_endpoint_slot,
        log_send_slot,
        tls: pm_tls_meta,
    };
    populate_procmgr_info(&mut arena, pm_aspace, &pm_caps, stack_pages)?;

    place_stack_and_ipc(&mut arena, pm_aspace, PROCMGR_IPC_BUF_VA, stack_pages)?;

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
        bootstrap_badge: procmgr_badge,
        log_endpoint_slot: pm_log_send,
        registry_endpoint_slot: pm_registry_send,
        thread: pm_thread,
        arena_cap: arena.cap,
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
