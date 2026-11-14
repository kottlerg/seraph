// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/src/bootstrap.rs

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
use crate::{MemoryAlloc, PAGE_SIZE, TEMP_MAP_BASE, arch};
use init_protocol::{CapDescriptor, InitInfo};
use process_abi::PROCESS_ABI_VERSION;
use process_layout::{ProcessLayout, choose_process_layout};

// ── Constants ────────────────────────────────────────────────────────────────
//
// ELF_PAGE_TEMP_VA is private to init's no_std bootstrap path and sits inside
// init's TEMP_MAP_BASE scratch region (offset 256 MiB). The per-child bootstrap
// VAs (`ProcessInfo` page, stack top, TLS block, IPC buffer) are drawn per
// process via `process-layout` (ASLR, #39) rather than pinned here, mirroring
// procmgr.

/// Per-page ELF write scratch during init's procmgr/memmgr bootstrap.
///
/// Only [`BootArena::place_page`] and [`BootArena::place_segment`] map this
/// span, and each unmaps it before returning; a module's read-only mapping at
/// `TEMP_MAP_BASE` stops below it ([`MODULE_SCRATCH_MAX_PAGES`]), and nothing
/// else of init lies there, so no Rust object outlives a scratch mapping.
const ELF_PAGE_TEMP_VA: u64 = TEMP_MAP_BASE + 0x1000_0000;

/// Most pages a boot module's read-only mapping at `TEMP_MAP_BASE` may span:
/// a longer one would reach [`ELF_PAGE_TEMP_VA`], where the per-page scratch
/// maps would replace module bytes `populate` is still reading.
const MODULE_SCRATCH_MAX_PAGES: u64 = (ELF_PAGE_TEMP_VA - TEMP_MAP_BASE) / PAGE_SIZE;

/// Pages a boot module of `module_size` bytes spans at `TEMP_MAP_BASE`, or
/// `None` when it would reach the ELF scratch span
/// ([`MODULE_SCRATCH_MAX_PAGES`]).
fn module_scratch_pages(module_size: u64) -> Option<u64>
{
    let pages = module_size.div_ceil(PAGE_SIZE);
    (pages <= MODULE_SCRATCH_MAX_PAGES).then_some(pages)
}

/// Draw the entropy one bootstrap-layout choice consumes (ASLR, #39).
///
/// `None` means the draw failed — a kernel-contract violation once the pool
/// is seeded, which it is before init runs.
fn draw_layout_entropy() -> Option<[u8; process_layout::LAYOUT_ENTROPY_BYTES]>
{
    let mut entropy = [0u8; process_layout::LAYOUT_ENTROPY_BYTES];
    let n = syscall::getrandom(&mut entropy).ok()?;
    (n == entropy.len() as u64).then_some(entropy)
}

/// Choose a child's bootstrap layout from fresh entropy, degrading to the
/// deterministic default layout (with a log line) if the draw fails.
fn choose_child_layout() -> ProcessLayout
{
    let entropy = draw_layout_entropy();
    if entropy.is_none()
    {
        log("init: layout entropy draw failed; using default layout");
    }
    choose_process_layout(entropy.as_ref())
}

/// Draw an `ET_DYN` image load bias (ASLR, #39), degrading to the window
/// base (never bias 0 — the image still relocates through the single PIE
/// path) with a log line if the entropy draw fails.
fn choose_image_bias_or_default() -> u64
{
    if let Ok(r) = syscall::random_u64()
    {
        return process_layout::choose_image_bias(r);
    }
    log("init: image-bias entropy draw failed; using window base");
    process_layout::IMAGE_WINDOW.base
}

/// Log `prefix` followed by a lowercase hex value (init's `log` takes only
/// plain `&str`; no `core::fmt` in the `no_std` bootstrap path). The 96-byte
/// buffer is a diagnostic output cap: a longer prefix truncates and nothing
/// else is bounded.
pub(crate) fn log_hex(prefix: &str, value: u64)
{
    let mut buf = [0u8; 96];
    // The buffer is 96 bytes, so the prefix cap is positive.
    let prefix_len = prefix.len().min(buf.len().saturating_sub(18));
    let mut pos = 0usize;
    let mut push = |b: u8| {
        if let Some(slot) = buf.get_mut(pos)
        {
            *slot = b;
            // `pos` indexed a slot, so it is below the buffer length.
            pos = pos.saturating_add(1);
        }
    };
    for &b in prefix.as_bytes().iter().take(prefix_len)
    {
        push(b);
    }
    push(b'0');
    push(b'x');
    let mut started = false;
    for nibble in (0..16u32).rev()
    {
        // `nibble` is below 16, so the shift is below 64 and `checked_shr` never refuses.
        let digit = ((value.checked_shr(nibble.saturating_mul(4)).unwrap_or(0)) & 0xF) as u8;
        if digit != 0 || started || nibble == 0
        {
            push(
                if digit < 10
                {
                    b'0'.saturating_add(digit)
                }
                else
                {
                    // `digit` is at most 15.
                    b'a'.saturating_add(digit.saturating_sub(10))
                },
            );
            started = true;
        }
    }
    if let Ok(s) = core::str::from_utf8(buf.get(..pos).unwrap_or_default())
    {
        log(s);
    }
}

// ── Bootstrap arena ────────────────────────────────────────────────────────────
//
// Each tier-1 service (memmgr, procmgr) is backed by one contiguous arena
// Memory cap carved from init's pool. Its front `[0, retype_reserve_pages())`
// is consumed by the service's `AddressSpace` / `CSpace` / `Thread` retypes
// (a monotonic page-aligned front bump in the cap's `RetypeAllocator`); the
// remainder is offset-mapped page-by-page as the service's loaded backing
// (ELF segments, TLS, `ProcessInfo`, stack, IPC buffer). The retypes each
// hold an ancestor reference on the arena's `MemoryObject` for the immortal
// service's life, so init's eventual cap-drop at reap never brings the
// refcount to zero: the offset-mapped backing never dangles and the arena
// never frees into the post-handoff buddy.

/// Front region of a tier-1 service arena reserved for the three kernel-object
/// retypes, each of which consumes its pages (`*_RETYPE_PAGES`,
/// [`crate::thread_retype_pages`]). The retype bump is page-aligned and
/// monotonic, so backing offsets at or above this bound never collide with a
/// retype slab.
fn retype_reserve_pages() -> u64
{
    // Three small page-count constants, far below `u64::MAX`.
    crate::ASPACE_RETYPE_PAGES
        .saturating_add(crate::CSPACE_RETYPE_PAGES)
        .saturating_add(crate::thread_retype_pages())
}

/// Bodies init's own `CSpace` arena backs after [`fund_own_cspace`] besides
/// one per MMIO aperture: the split tails of the three `MemoryAlloc` carves
/// that follow init's own arena's (memmgr's and procmgr's arenas and the
/// phys-table page), the two children of the `SchedControl` split, and the
/// derivations of the root `Interrupt` cap and, on x86-64, of the root
/// `IoPort` cap that init serves devmgr. Fixed by init's own code; the
/// aperture derivations scale with the hardware and are counted from
/// `InitInfo` ([`init_cspace_fund_pages`]).
const INIT_FIXED_BODIES: u64 = 3 + 2 + 2;

/// Pool pages init donates to its own `CSpace` before it makes any body or
/// binds any port (core/kernel/docs/capability-internals.md § Body Arena):
///
/// * one arena page per [`syscall_abi::CSPACE_BODIES_PER_PAGE`] bodies: one
///   per `Mmio` descriptor, each derived for devmgr, plus
///   [`INIT_FIXED_BODIES`];
/// * when the kernel minted an `IoPort` cap (x86-64), the port-binding tables
///   of init's main thread (its serial output) and of init-logd,
///   [`syscall_abi::IOPORT_BINDING_TABLE_PAGES`] each;
/// * one page for a directory page the `CSpace`'s slot growth may spend, as
///   `syscall_abi::cspace_topup_pages` counts one.
///
/// The kernel seeds the root `CSpace` with the slots init uses and only the
/// one arena page its arena carve's split spends before this donation
/// (`ROOT_CSPACE_BODY_PAGES`, core/kernel/src/cap/mod.rs), so these counts
/// come from this boot's `InitInfo`, not from a fixed seed.
pub(crate) fn init_cspace_fund_pages(info: &InitInfo) -> u64
{
    let apertures = crate::descriptors(info)
        .iter()
        .filter(|d| d.cap_type == init_protocol::CapType::Mmio)
        .count() as u64;
    // `apertures` is a descriptor count from `InitInfo`, bounded by its page.
    let body_pages = apertures
        .saturating_add(INIT_FIXED_BODIES)
        .div_ceil(syscall_abi::CSPACE_BODIES_PER_PAGE);
    let binding_pages = if crate::find_cap_by_type(info, init_protocol::CapType::IoPort).is_some()
    {
        2 * syscall_abi::IOPORT_BINDING_TABLE_PAGES
    }
    else
    {
        0
    };
    // Page counts bounded by the descriptor count and small constants.
    body_pages.saturating_add(binding_pages).saturating_add(1)
}

/// Donate [`init_cspace_fund_pages`] pages of `arena_cap`'s front to init's
/// own `CSpace` (augment-mode `cap_create_cspace`). The pages come out of the
/// arena's front reserve ([`init_retype_reserve_pages`]), so they are
/// accounted with the arena that `finalize_memmgr` forwards to memmgr as an
/// in-use run and stay parked there after init's reap returns them, as no
/// other donation source would be: a split-off run donated here would reach
/// memmgr's pool through the reap donation while its pages were still retyped
/// into this `CSpace`.
///
/// # Errors
/// The kernel's refusal of the augment, as `cap_create_cspace` returns it:
/// `OutOfMemory` when the arena's front cannot back the pages (a reserve too
/// small for them), or the error of a bad cap or `CSpace` handle.
pub(crate) fn fund_own_cspace(info: &InitInfo, arena_cap: u64) -> Result<(), i64>
{
    syscall::cap_create_cspace(arena_cap, info.cspace_cap, init_cspace_fund_pages(info)).map(|_| ())
}

/// Front region of init's own arena reserved for its kernel-object retypes.
///
/// Unlike a tier-1 service, init retypes only endpoints (byte-granular) and
/// one log thread from this arena, besides its own `CSpace`'s fund; it reuses
/// the kernel-supplied `AddressSpace`/`CSpace` rather than creating its own.
/// The reserve is:
///
/// * [`init_cspace_fund_pages`] for the donation [`fund_own_cspace`] makes
///   first, page-granular,
/// * 1 page for endpoints created before the log-thread retype (the retype
///   allocator packs ~32 endpoints per page; init creates well under that),
/// * [`crate::thread_retype_pages`] (seven or more) for the log thread, which
///   page-aligns the bump upward — splitting endpoint packing across a page
///   boundary, and
/// * 1 page for endpoints created after the log-thread retype, so they never
///   bump into the offset-mapped backing region even without relying on the
///   allocator reusing the first page's recovered slack.
///
/// Sound for up to ~32 endpoints on each side of the log-thread retype; init
/// creates roughly a dozen total. [`finalize_memmgr`] asserts the front bump
/// never crossed this bound before forwarding the arena.
pub(crate) fn init_retype_reserve_pages(info: &InitInfo) -> u64
{
    // Small page-count constants, far below `u64::MAX`.
    init_cspace_fund_pages(info)
        .saturating_add(1)
        .saturating_add(crate::thread_retype_pages())
        .saturating_add(1)
}

/// A service's contiguous backing arena: one Memory cap plus a page cursor
/// into its offset-mapped backing region.
pub(crate) struct BootArena
{
    /// Arena Memory cap in init's `CSpace`. Full rights (R+W+X+RETYPE):
    /// retyped from its front, offset-mapped past the retype bump.
    pub(crate) cap: u64,
    /// `AddressSpace` cap the transient per-page scratch maps land in at
    /// [`ELF_PAGE_TEMP_VA`] — always init's own `AddressSpace`.
    init_aspace: u64,
    /// Next free backing-page offset, in pages. Starts at the front reserve;
    /// advances one page per [`Self::place_page`].
    cursor: u64,
}

impl BootArena
{
    /// Carve a `retype_reserve_pages() + backing_pages` contiguous arena off
    /// `alloc` with the cursor positioned past the retype reserve. The
    /// caller performs the three retypes against [`Self::cap`] before
    /// placing any backing page.
    fn carve(alloc: &mut MemoryAlloc, init_aspace: u64, backing_pages: u64) -> Option<Self>
    {
        Self::carve_reserve(alloc, init_aspace, retype_reserve_pages(), backing_pages)
    }

    /// Carve a `reserve_pages + backing_pages` contiguous arena off `alloc`
    /// with the cursor positioned past `reserve_pages`. The caller performs
    /// every retype against [`Self::cap`] within the `reserve_pages` front
    /// bound before placing backing pages at or above it.
    pub(crate) fn carve_reserve(
        alloc: &mut MemoryAlloc,
        init_aspace: u64,
        reserve_pages: u64,
        backing_pages: u64,
    ) -> Option<Self>
    {
        let cap = alloc.alloc_pages(reserve_pages.checked_add(backing_pages)?)?;
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
    /// derivation blocks a later `memory_split` of the arena.
    ///
    /// # Safety
    /// When `target_aspace` is init's own address space, the page at
    /// `target_va` must hold no live Rust object or registered IPC page (the
    /// contract of `syscall::mem_map`).
    pub(crate) unsafe fn place_page(
        &mut self,
        target_aspace: u64,
        target_va: u64,
        prot: u64,
        populate: impl FnOnce(u64),
    ) -> Option<()>
    {
        let offset = self.cursor;
        // SAFETY: ELF_PAGE_TEMP_VA is init's private scratch span, unmapped
        // between placements, with no Rust object in it (its rustdoc).
        unsafe {
            syscall::mem_map(
                self.cap,
                self.init_aspace,
                ELF_PAGE_TEMP_VA,
                offset,
                1,
                syscall::MAP_WRITABLE,
            )
        }
        .ok()?;
        // SAFETY: ELF_PAGE_TEMP_VA is mapped writable, one page.
        unsafe { core::ptr::write_bytes(ELF_PAGE_TEMP_VA as *mut u8, 0, PAGE_SIZE as usize) };
        populate(ELF_PAGE_TEMP_VA);
        // SAFETY: the scratch page, which `populate` reached only through the
        // raw address it was handed; it has returned, so nothing uses it.
        let _ = unsafe { syscall::mem_unmap(self.init_aspace, ELF_PAGE_TEMP_VA, 1) };
        // SAFETY: the caller's contract covers `target_va` in `target_aspace`.
        unsafe { syscall::mem_map(self.cap, target_aspace, target_va, offset, 1, prot) }.ok()?;
        // `cursor` indexed a backing page of the arena, so it is far below `u64::MAX`.
        self.cursor = self.cursor.saturating_add(1);
        Some(())
    }

    /// Map the arena's next `num_pages` backing pages writable into init at
    /// [`ELF_PAGE_TEMP_VA`], zero the span, run `populate` over the whole
    /// span, unmap it from init, then map the same offset run into
    /// `target_aspace` at `target_va` with `prot`. Advances the cursor by
    /// `num_pages`.
    ///
    /// Segment granularity (rather than [`Self::place_page`]) lets
    /// `populate` write values that straddle a page boundary — an 8-byte
    /// `RELATIVE` relocation target may span two pages. The arena is one
    /// contiguous Memory cap, so the segment's backing pages form one
    /// contiguous offset run.
    ///
    /// `ro_head_pages` maps that many leading pages read-only instead of
    /// `prot` (`PT_GNU_RELRO` enforcement: the read-only-after-relocation
    /// region is a prefix of the writable image region by link order).
    ///
    /// # Safety
    /// When `target_aspace` is init's own address space, the `num_pages`
    /// pages at `target_va` must hold no live Rust object or registered IPC
    /// page (the contract of `syscall::mem_map`).
    pub(crate) unsafe fn place_segment(
        &mut self,
        target_aspace: u64,
        target_va: u64,
        num_pages: u64,
        prot: u64,
        ro_head_pages: u64,
        populate: impl FnOnce(&mut [u8]),
    ) -> Option<()>
    {
        if num_pages == 0
        {
            return Some(());
        }
        let offset = self.cursor;
        // SAFETY: ELF_PAGE_TEMP_VA is init's private scratch span, unmapped
        // between placements, with no Rust object in it (its rustdoc).
        unsafe {
            syscall::mem_map(
                self.cap,
                self.init_aspace,
                ELF_PAGE_TEMP_VA,
                offset,
                num_pages,
                syscall::MAP_WRITABLE,
            )
        }
        .ok()?;
        let len = num_pages.checked_mul(PAGE_SIZE)? as usize;
        // SAFETY: the span at ELF_PAGE_TEMP_VA was just mapped writable for
        // `num_pages` pages.
        let span = unsafe { core::slice::from_raw_parts_mut(ELF_PAGE_TEMP_VA as *mut u8, len) };
        span.fill(0);
        populate(span);
        // SAFETY: the scratch span; `span`, the only reference into it, is not
        // used past `populate`.
        let _ = unsafe { syscall::mem_unmap(self.init_aspace, ELF_PAGE_TEMP_VA, num_pages) };
        let ro = ro_head_pages.min(num_pages);
        if ro > 0
        {
            // SAFETY: the caller's contract covers the target span.
            unsafe {
                syscall::mem_map(
                    self.cap,
                    target_aspace,
                    target_va,
                    offset,
                    ro,
                    syscall::MAP_READ,
                )
            }
            .ok()?;
        }
        if ro < num_pages
        {
            // SAFETY: the caller's contract covers the target span.
            unsafe {
                syscall::mem_map(
                    self.cap,
                    target_aspace,
                    // `ro` is below `num_pages` here, and the span `[target_va,
                    // target_va + num_pages * PAGE_SIZE)` is the caller's mapped span.
                    target_va.saturating_add(ro.saturating_mul(PAGE_SIZE)),
                    offset.saturating_add(ro),
                    num_pages.saturating_sub(ro),
                    prot,
                )
            }
            .ok()?;
        }
        // `cursor` plus the run just mapped stays within the arena, far below `u64::MAX`.
        self.cursor = self.cursor.saturating_add(num_pages);
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
        let last_page_end = seg.vaddr.checked_add(seg.memsz)?.checked_add(0xFFF)? & !0xFFF;
        total = total.checked_add(last_page_end.checked_sub(first_page)? / PAGE_SIZE)?;
    }
    Some(total)
}

/// The pages the main TLS block spans (`process_abi::tls_block_layout`) when
/// `ehdr` declares a non-empty `PT_TLS`, else zero. Mirrors the presence check
/// and the block size in [`place_main_tls`].
fn tls_backing_pages(ehdr: &elf::Elf64Ehdr, module_bytes: &[u8]) -> u64
{
    match elf::tls_segment(ehdr, module_bytes)
    {
        Ok(Some(seg)) if seg.memsz > 0 => process_abi::tls_block_layout(seg.memsz, seg.align)
            .0
            .div_ceil(PAGE_SIZE),
        _ => 0,
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

/// The `RELATIVE` relocation table's bytes within `module_bytes`, or `None`
/// when `table` does not lie inside the image.
fn rela_table_bytes<'a>(module_bytes: &'a [u8], table: &elf::RelaTable) -> Option<&'a [u8]>
{
    let end = table.file_offset.checked_add(table.size)?;
    module_bytes.get(table.file_offset as usize..end as usize)
}

/// Place the main thread's TLS block in `arena`: populate it from the
/// in-memory `.tdata` template, re-apply the template's `RELATIVE`
/// relocations to this independent copy (the image copy is relocated —
/// and counted — during segment loading), install the TCB self-pointer,
/// and map it read-write into `target_aspace` at the chosen `tls_base`.
///
/// Returns `(tls_base_va, metadata)` with the template `vaddr` biased —
/// `ProcessInfo.tls_template_vaddr` must point at the loaded (runtime)
/// template. When the binary has no `PT_TLS` segment (or it is empty),
/// returns `(0, ChildTlsMeta::default())` without consuming a backing
/// page — matching [`tls_backing_pages`].
///
/// # Safety
/// `target_aspace` must name a child's address space, never init's own: the
/// function places pages into it at VAs the child's layout chooses, without
/// checking what init holds there.
unsafe fn place_main_tls(
    arena: &mut BootArena,
    ehdr: &elf::Elf64Ehdr,
    module_bytes: &[u8],
    target_aspace: u64,
    tls_base: u64,
    bias: u64,
    rela: Option<elf::RelaTable>,
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
        vaddr: seg.vaddr.checked_add(bias)?,
        filesz: seg.filesz,
        memsz: seg.memsz,
        align: seg.align,
    };

    // The block spans the pages its memsz needs (`tls_backing_pages` reserved
    // them in the arena), up to the region the layout leaves after the TLS
    // draw.
    let (block_size, block_align, tls_base_offset) =
        process_abi::tls_block_layout(seg.memsz, seg.align);
    let pages = block_size.div_ceil(PAGE_SIZE);
    if block_size == 0 || pages > process_abi::PROCESS_MAIN_TLS_MAX_PAGES || block_align > PAGE_SIZE
    {
        return None;
    }

    let tdata_start = seg.offset as usize;
    let tdata_end = tdata_start.checked_add(seg.filesz as usize)?;
    if tdata_end > module_bytes.len()
    {
        return None;
    }

    let tls_base_va = tls_base.checked_add(tls_base_offset)?;
    // Validated here so the populate closure below has no failure path.
    let tdata = module_bytes.get(tdata_start..tdata_end)?;
    let table = match rela
    {
        Some(t) => Some(rela_table_bytes(module_bytes, &t)?),
        None => None,
    };
    let populate = |span: &mut [u8]| {
        // `filesz <= memsz` (`elf::tls_segment` refuses a template past its
        // `p_memsz`) `<= block_size <= span.len()`: the template fits.
        let Some(template) = span.get_mut(..seg.filesz as usize)
        else
        {
            return;
        };
        template.copy_from_slice(tdata);
        if let Some(table) = table
        {
            let _ = elf::apply_relative_relocs(
                table,
                arch::current::EXPECTED_ELF_MACHINE,
                bias,
                seg.vaddr,
                template,
            );
        }
        // SAFETY: `span` is the zeroed, writable block of `block_size` or
        // more bytes, which holds the TCB at `tls_base_offset`.
        unsafe {
            process_abi::tls_install_tcb(span.as_mut_ptr(), tls_base_offset, tls_base_va);
        }
    };
    // SAFETY: the caller's contract: `target_aspace` is a child's address space,
    // never init's own.
    unsafe {
        arena.place_segment(
            target_aspace,
            tls_base,
            pages,
            syscall::MAP_WRITABLE,
            0,
            populate,
        )
    }?;

    Some((tls_base_va, meta))
}

/// Load an ELF image's `PT_LOAD` segments into `arena` at `bias`-shifted
/// VAs, offset-mapped into `target_aspace` with explicit W^X protection
/// (executable → RX, writable → RW, else RO). `rela` is the image's
/// `RELATIVE` relocation table (`ET_DYN`; `None` for `ET_EXEC`): each segment's
/// in-span records are applied after the file bytes are copied in.
///
/// Consumes exactly [`elf_backing_pages`] backing pages (the bias is
/// page-aligned, so the page counts are bias-invariant). Returns the number
/// of relocations applied; the caller checks it equals the validated table
/// count.
///
/// # Safety
/// `target_aspace` must name a child's address space, never init's own: the
/// function places pages into it at VAs the child's layout chooses, without
/// checking what init holds there.
unsafe fn load_elf_into_arena(
    arena: &mut BootArena,
    ehdr: &elf::Elf64Ehdr,
    module_bytes: &[u8],
    target_aspace: u64,
    bias: u64,
    rela: Option<elf::RelaTable>,
) -> Option<u64>
{
    let machine = arch::current::EXPECTED_ELF_MACHINE;
    // PT_GNU_RELRO (biased, page-rounded): fully-covered pages of writable
    // segments are mapped read-only after relocation.
    let ro_range = elf::relro_span(ehdr, module_bytes)
        .ok()?
        .and_then(|(va, sz)| {
            let start = va.checked_add(bias)?;
            let end = start.checked_add(sz)?.checked_add(0xFFF)?;
            Some((start & !0xFFF, end & !0xFFF))
        });
    let table = match rela
    {
        Some(t) => Some(rela_table_bytes(module_bytes, &t)?),
        None => None,
    };
    let mut applied = 0u64;
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

        let seg_vaddr = seg.vaddr.checked_add(bias)?;
        let first_page = seg_vaddr & !0xFFF;
        let last_page_end = seg_vaddr.checked_add(seg.memsz)?.checked_add(0xFFF)? & !0xFFF;
        let num_pages = last_page_end.checked_sub(first_page)? / PAGE_SIZE;
        let file_end = seg.offset.checked_add(seg.filesz)?;
        let file_data = module_bytes.get(seg.offset as usize..file_end as usize)?;
        // `first_page` is `seg_vaddr` rounded down, so it is not above it.
        let dest_offset = seg_vaddr.saturating_sub(first_page) as usize;

        // RELRO is a prefix of the writable region by link order; pages of
        // this segment fully inside the range map read-only.
        let ro_head_pages = match ro_range
        {
            Some((ro_start, ro_end))
                if seg.writable && ro_start <= first_page && ro_end > first_page =>
            {
                // `last_page_end` and `ro_end` both exceed `first_page` here.
                ro_end.min(last_page_end).saturating_sub(first_page) / PAGE_SIZE
            }
            _ => 0,
        };

        // SAFETY: the caller's contract: `target_aspace` is a child's address space,
        // never init's own.
        unsafe {
            arena.place_segment(
                target_aspace,
                first_page,
                num_pages,
                prot,
                ro_head_pages,
                |span| {
                    let copy_len = file_data.len().min(seg.memsz as usize);
                    // The span is `num_pages` pages from `first_page`, which holds
                    // `dest_offset + memsz` bytes, so both slices exist.
                    if let Some(dst) = span
                        .get_mut(dest_offset..)
                        .and_then(|rest| rest.get_mut(..copy_len))
                        && let Some(src) = file_data.get(..copy_len)
                    {
                        dst.copy_from_slice(src);
                    }
                    // Writable segments only, matching the kernel's init applier: a
                    // target in text/rodata goes unapplied and the caller's
                    // applied-count check rejects the image.
                    if seg.writable
                        && let Some(table) = table
                        && let Some(seg_span) = span
                            .get_mut(dest_offset..)
                            .and_then(|rest| rest.get_mut(..seg.memsz as usize))
                    {
                        // The count of applied relocations is bounded by the table size.
                        applied = applied.saturating_add(elf::apply_relative_relocs(
                            table, machine, bias, seg.vaddr, seg_span,
                        ));
                    }
                },
            )
        }?;
    }

    Some(applied)
}

// ── Memmgr bootstrap ────────────────────────────────────────────────────────

/// Result of bootstrapping memmgr's setup (kernel objects + ELF load +
/// PI / stack / IPC mappings + creator endpoint). Memory-cap-pool delegation
/// and `thread_start` happen later via [`finalize_memmgr`] so that
/// procmgr's setup pages can also draw from init's pool before all
/// remaining memory caps are handed over to memmgr.
pub struct MemmgrBootstrap
{
    /// Init-side bootstrap badge for memmgr's `request_round` reply.
    pub bootstrap_badge: u64,
    /// Badge init used when minting the procmgr-side badged SEND on
    /// memmgr's endpoint. Memmgr stores this and uses it to gate the
    /// procmgr-only labels (`REGISTER_PROCESS`, `PROCESS_DIED`,
    /// `DONATE_MEMORY_CAPS`, `DELEGATE_ASPACE`).
    pub procmgr_badge: u64,
    /// Slot in init's `CSpace` of the badged SEND cap on memmgr's
    /// endpoint that init will install in procmgr's `ProcessInfo`.
    pub procmgr_send_cap: u64,
    /// Memmgr's `CSpace` cap (in init's `CSpace`). Init moves RAM
    /// Memory caps into here at [`finalize_memmgr`] time.
    pub mm_cspace: u64,
    /// Memmgr's main `Thread` cap (in init's `CSpace`). Init invokes
    /// `thread_configure` + `thread_start` at [`finalize_memmgr`] time.
    pub mm_thread: u64,
    /// Memmgr's contiguous backing arena Memory cap (in init's `CSpace`).
    /// [`finalize_memmgr`] copies it into memmgr's `CSpace` and forwards it
    /// as an in-use arena so its pages are accounted in memmgr's pool.
    pub arena_cap: u64,
    /// Memmgr's ELF entry point.
    pub entry: u64,
    /// Stack top init chose and mapped for memmgr; passed as the initial SP to
    /// `thread_configure` in [`finalize_memmgr`].
    pub stack_top_vaddr: u64,
    /// VA of the `ProcessInfo` page init mapped for memmgr; delivered to memmgr
    /// in its entry register by [`finalize_memmgr`].
    pub process_info_va: u64,
}

/// One in-use bootstrap arena forwarded to memmgr for accounting. Its whole
/// Memory cap is copied into memmgr's `CSpace`; memmgr records it as a backing
/// frame against the owning service's record so the arena's pages count
/// toward `pool_total` without ever becoming allocatable. The arena is
/// retype-pinned and offset-mapped for the immortal service's life, so this is
/// pure accounting — memmgr never frees it.
#[derive(Clone, Copy, Default)]
pub struct InUseArena
{
    /// Slot in memmgr's `CSpace` of the copied arena cap.
    pub cap_slot: u64,
    /// Arena size in pages (`retype_reserve_pages()` + backing).
    pub page_count: u32,
    /// Arena physical base.
    pub phys_base: u64,
    /// Owner kind (`ipc::memmgr_bootstrap::IN_USE_KIND_*`).
    pub kind: u64,
}

/// Result of [`finalize_memmgr`] — bootstrap-IPC payload init sends
/// to memmgr in its first `request_round` reply.
///
/// The round names the delegated RAM caps by slot range only; memmgr reads
/// each cap's size and physical base from the kernel (`cap_info`), so no
/// per-cap table travels and the round bounds no cap count. The in-use
/// arenas travel out-of-band in the read-only phys-table page (`caps[1]` in
/// the bootstrap reply).
pub struct MemmgrFinalize
{
    /// First slot of the RAM Memory caps init moved into memmgr's
    /// `CSpace` during finalization.
    pub mm_memory_base: u64,
    /// Number of RAM memory caps delegated to memmgr.
    pub mm_memory_count: u64,
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
    aspace: u64,
    cspace: u64,
    thread: u64,
    creator_endpoint_slot: u64,
    /// Baseline `SchedControl` cap (in init's `CSpace`) copied into memmgr.
    sched_baseline: u64,
}

/// Populate memmgr's `ProcessInfo` page from `arena` and map it read-only
/// into `target_aspace`.
///
/// # Safety
/// `target_aspace` must name a child's address space, never init's own: the
/// function places pages into it at VAs the child's layout chooses, without
/// checking what init holds there.
#[expect(
    clippy::similar_names,
    reason = "memmgr's copies of its own objects are named by object and holder \
              (`mm_aspace_in_mm`, `mm_cspace_in_mm`); the names differ only in the object kind, \
              which is the distinction that matters"
)]
unsafe fn populate_memmgr_info(
    arena: &mut BootArena,
    target_aspace: u64,
    caps: &MemmgrCaps,
    stack_pages: u32,
    layout: &ProcessLayout,
) -> Option<()>
{
    let mm_thread_in_mm =
        syscall::cap_copy(caps.thread, caps.cspace, syscall::RIGHTS_THREAD).ok()?;
    let mm_aspace_in_mm = syscall::cap_copy(caps.aspace, caps.cspace, syscall::RIGHTS_ALL).ok()?;
    let mm_cspace_in_mm =
        syscall::cap_copy(caps.cspace, caps.cspace, syscall::RIGHTS_CS_ALL).ok()?;
    // Baseline SchedControl so memmgr can set its own threads' priorities.
    let mm_sched_in_mm =
        syscall::cap_copy(caps.sched_baseline, caps.cspace, syscall::RIGHTS_ALL).ok()?;

    let populate = |scratch_va: u64| {
        // SAFETY: scratch_va is mapped writable and zeroed, one page.
        let pi = unsafe { process_abi::process_info_mut(scratch_va) };
        pi.version = PROCESS_ABI_VERSION;
        pi.self_thread_cap = mm_thread_in_mm;
        pi.self_aspace_cap = mm_aspace_in_mm;
        pi.self_cspace_cap = mm_cspace_in_mm;
        pi.sched_control_cap = mm_sched_in_mm;
        pi.initial_priority = ipc::sched_policy::MEMMGR_PRIORITY;
        pi.ipc_buffer_vaddr = layout.ipc_buffer_va;
        pi.creator_endpoint_cap = caps.creator_endpoint_slot;
        pi.procmgr_endpoint_cap = 0;
        pi.memmgr_endpoint_cap = 0;
        pi.stdin_memory_cap = 0;
        pi.stdout_memory_cap = 0;
        pi.stderr_memory_cap = 0;
        pi.log_send_cap = 0;
        pi.stdin_data_notification_cap = 0;
        pi.stdin_space_notification_cap = 0;
        pi.stdout_data_notification_cap = 0;
        pi.stdout_space_notification_cap = 0;
        pi.stderr_data_notification_cap = 0;
        pi.stderr_space_notification_cap = 0;
        pi.stack_top_vaddr = layout.stack_top;
        pi.stack_pages = stack_pages;
        // memmgr's bespoke `_start` configures no TLS.
        pi.main_tls_vaddr = 0;
        // Infrastructure is never demand-paged (would recurse on its own
        // faults); leave the pager unbound.
        pi.pager_endpoint_cap = 0;
        pi.pager_badge = 0;
    };
    // SAFETY: the caller's contract: `target_aspace` is a child's address space,
    // never init's own.
    unsafe {
        arena.place_page(
            target_aspace,
            layout.process_info_va,
            syscall::MAP_READ,
            populate,
        )
    }?;

    Some(())
}

/// Locate a `CapDescriptor` by slot index.
fn descriptor_for(info: &InitInfo, slot: u64) -> Option<&CapDescriptor>
{
    crate::descriptors(info).iter().find(|d| d.slot == slot)
}

/// Set up memmgr's kernel objects, load its ELF, populate `ProcessInfo`,
/// map stack and IPC buffer, and mint the creator + procmgr SEND caps.
/// **Does not delegate memory caps or start memmgr's thread** — those happen
/// later in [`finalize_memmgr`] so procmgr's setup can still draw from
/// init's memory-cap pool before all remaining memory caps go to memmgr.
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
#[expect(
    clippy::similar_names,
    reason = "memmgr's kernel objects are named by kind (`mm_aspace`, `mm_cspace`)"
)]
#[expect(
    clippy::too_many_lines,
    reason = "memmgr's raw bring-up is one ordered sequence (load the image, create its objects, \
              mint its creator cap, populate its `ProcessInfo`, place its stack and IPC buffer) \
              whose steps share the caps it creates"
)]
pub fn bootstrap_memmgr(
    info: &InitInfo,
    alloc: &mut MemoryAlloc,
    init_bootstrap_ep: u64,
    mm_service_ep: u64,
    baseline_sched: u64,
) -> Option<MemmgrBootstrap>
{
    let init_aspace = info.aspace_cap;
    let module_memory_cap = crate::find_module_by_name(info, b"memmgr")?;
    let module_size = descriptor_for(info, module_memory_cap).map(|d| d.aux1)?;
    let Some(module_pages) = module_scratch_pages(module_size)
    else
    {
        log("init: FATAL: memmgr module too large for the scratch region");
        return None;
    };

    // The module Memory cap carries full rights (R+W+X+RETYPE): init retains
    // it as the module-source owner and donates it to memmgr's pool at reap,
    // where RETYPE lets memmgr re-derive. Derive a read-only child cap for the
    // load-time mapping so `mem_map`'s derive-from-cap path produces a strictly
    // read-only page (otherwise W+X cap rights trip W^X).
    let module_ro = syscall::cap_derive(module_memory_cap, syscall::RIGHTS_MEM_MAP).ok()?;
    // SAFETY: TEMP_MAP_BASE starts init's scratch region, unmapped between
    // bootstrap steps; `module_scratch_pages` keeps the span below
    // ELF_PAGE_TEMP_VA, and no Rust object of init lies in it.
    unsafe {
        syscall::mem_map(
            module_ro,
            init_aspace,
            TEMP_MAP_BASE,
            0,
            module_pages,
            syscall::MAP_FROM_CAP,
        )
    }
    .ok()?;
    // SAFETY: module memory cap mapped read-only at TEMP_MAP_BASE.
    let module_bytes =
        unsafe { core::slice::from_raw_parts(TEMP_MAP_BASE as *const u8, module_size as usize) };

    let machine = arch::current::EXPECTED_ELF_MACHINE;
    let (ehdr, kind) = elf::validate_executable(module_bytes, machine).ok()?;
    // `validate_executable` returns the header decoded; the parsers borrow it.
    let ehdr = &ehdr;
    let bias = match kind
    {
        elf::ElfKind::Exec => 0,
        elf::ElfKind::Dyn => choose_image_bias_or_default(),
    };
    let (span_min, span_end) = elf::load_span(ehdr, module_bytes).ok()?;
    if kind == elf::ElfKind::Dyn
    {
        if !process_layout::validate_image_placement(bias, span_min, span_end)
        {
            return None;
        }
        // Load-bias observability: debugging correlates through this line.
        log_hex("init: memmgr image bias=", bias);
    }
    let entry = elf::entry_point(ehdr).checked_add(bias)?;
    let rela = if kind == elf::ElfKind::Dyn
    {
        elf::rela_table(ehdr, module_bytes).ok()?
    }
    else
    {
        None
    };
    let total_relocs = match rela
    {
        Some(t) =>
        {
            let table = rela_table_bytes(module_bytes, &t)?;
            elf::validate_relative_relocs(table, machine, span_min, span_end).ok()?
        }
        None => 0,
    };
    // A note outside `1..=MAX_PROCESS_STACK_PAGES` refuses the binary.
    let stack_pages = process_abi::resolve_stack_pages(elf::parse_stack_note(ehdr, module_bytes))?;
    let layout = choose_child_layout();

    // memmgr's bespoke `_start` configures no TLS, so its arena reserves
    // only ELF segments + `ProcessInfo` + stack + IPC buffer.
    let backing_pages = elf_backing_pages(ehdr, module_bytes)?
        .checked_add(1)?
        .checked_add(u64::from(stack_pages))?
        .checked_add(1)?;
    let mut arena = BootArena::carve(alloc, init_aspace, backing_pages)?;

    let mm_aspace = syscall::cap_create_aspace(arena.cap, 0, crate::ASPACE_RETYPE_PAGES).ok()?;
    let mm_cspace = syscall::cap_create_cspace(arena.cap, 0, crate::CSPACE_RETYPE_PAGES).ok()?;
    // memmgr is the system pager: create its thread at the top of the
    // baseline band so nothing it serves can preempt it.
    let mm_thread = syscall::cap_create_thread(
        arena.cap,
        mm_aspace,
        mm_cspace,
        baseline_sched,
        ipc::sched_policy::MEMMGR_PRIORITY,
    )
    .ok()?;

    log("created memmgr kernel objects");
    log("loading memmgr ELF segments");

    // SAFETY: the target is the child address space `cap_create_aspace` retyped
    // above for this service, never init's own.
    let applied_relocs =
        unsafe { load_elf_into_arena(&mut arena, ehdr, module_bytes, mm_aspace, bias, rela) }?;
    if applied_relocs != total_relocs
    {
        log("init: memmgr reloc application mismatch");
        return None;
    }
    // SAFETY: the module's scratch mapping; `module_bytes` and the header
    // borrowed from it are not used past this point.
    let _ = unsafe { syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, module_pages) };
    let _ = syscall::cap_delete(module_ro);
    log("loaded memmgr ELF");

    // Badged creator endpoint for memmgr (init serves the bootstrap round
    // for memmgr, so memmgr's `request_round` lands on init's bootstrap ep
    // tagged with this badge).
    let memmgr_badge = mint_bootstrap_badge()?;
    let badged_creator =
        syscall::cap_derive_badge(init_bootstrap_ep, syscall::RIGHTS_EP_SEND, memmgr_badge).ok()?;
    let mm_creator_slot =
        syscall::cap_copy(badged_creator, mm_cspace, syscall::RIGHTS_EP_SEND).ok()?;

    let mm_caps = MemmgrCaps {
        aspace: mm_aspace,
        cspace: mm_cspace,
        thread: mm_thread,
        creator_endpoint_slot: mm_creator_slot,
        sched_baseline: baseline_sched,
    };
    // SAFETY: the target is the child address space `cap_create_aspace` retyped
    // above for this service, never init's own.
    unsafe { populate_memmgr_info(&mut arena, mm_aspace, &mm_caps, stack_pages, &layout) }?;
    // SAFETY: the target is the child address space `cap_create_aspace` retyped
    // above for this service, never init's own.
    unsafe {
        place_stack_and_ipc(
            &mut arena,
            mm_aspace,
            layout.ipc_buffer_va,
            layout.stack_top,
            stack_pages,
        )
    }?;

    // Mint procmgr's badged SEND cap on memmgr's endpoint. Memmgr will
    // recognise calls bearing this badge as authorised for the
    // procmgr-only labels. The badge is in memmgr's process-badge space, whose
    // phys-class bit procmgr must not carry (memmgr refuses the bootstrap
    // otherwise), and stays nonzero with it cleared.
    let procmgr_badge_on_mm = loop
    {
        let b = mint_bootstrap_badge()? & !ipc::memmgr_labels::PHYS_CLASS_BADGE_BIT;
        if b != 0
        {
            break b;
        }
    };
    let procmgr_send_cap = syscall::cap_derive_badge(
        mm_service_ep,
        syscall::RIGHTS_EP_SEND_GRANT,
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
        stack_top_vaddr: layout.stack_top,
        process_info_va: layout.process_info_va,
    })
}

/// Copy one in-use bootstrap arena cap into memmgr's `CSpace` and build its
/// [`InUseArena`] descriptor: derive a full-rights intermediary, copy it into
/// `mm_cspace`, and read the arena's physical base + size from the cap. Unlike
/// a free run the arena is copied, not moved, since init's own cap carries
/// the arena's retypes. The arena is exact-sized (no free tail), so it is
/// never `memory_split`; the copy gives memmgr the accounting anchor while the
/// original cap and the retypes keep the `MemoryObject` pinned for the
/// immortal service's life.
fn forward_arena(arena_cap: u64, mm_cspace: u64, kind: u64) -> Option<InUseArena>
{
    let phys_base = syscall::cap_info(arena_cap, syscall::CAP_INFO_MEMORY_PHYS_BASE).ok()?;
    let size_bytes = syscall::cap_info(arena_cap, syscall::CAP_INFO_MEMORY_SIZE).ok()?;
    let intermediary = syscall::cap_derive(arena_cap, syscall::RIGHTS_ALL).ok()?;
    let cap_slot = syscall::cap_copy(intermediary, mm_cspace, syscall::RIGHTS_ALL).ok()?;
    Some(InUseArena {
        cap_slot,
        page_count: (size_bytes / PAGE_SIZE) as u32,
        phys_base,
        kind,
    })
}

/// Forward a single Memory cap into memmgr's `CSpace` as a free run: move it
/// into `mm_cspace`, so that once any derivation init took from it is gone
/// memmgr's slot is the only one naming the run and memmgr can split and
/// merge it. Count the run in `count`, recording `base` on the first. Used
/// for the `MemoryAlloc` tail and the transient phys-table page — both
/// `memory_split` products with no `InitInfo` descriptor, which the reap
/// donation walk does not reach, so unforwarded they would stay in init's
/// `CSpace` until the reap frees it and then free into the sealed post-handoff
/// buddy, tripping the kernel's post-seal `debug_assert` in a debug build.
fn push_free_run(src_cap: u64, mm_cspace: u64, base: &mut u64, count: &mut u64)
{
    if let Ok(dst_slot) = syscall::cap_move(src_cap, mm_cspace, 0)
    {
        if *count == 0
        {
            *base = dst_slot;
        }
        // `count` tallies forwarded caps, far below `u64::MAX`.
        *count = count.saturating_add(1);
    }
}

/// General slots of memmgr's `CSpace` the bootstrap forwarding leaves free:
/// room for the `MemoryAlloc` tail, the phys-table page, and the in-use arenas
/// (which must ride the round), and for the splits memmgr makes while it
/// ingests the pool, before its first receive tops its `CSpace` up from its
/// own pool. A few dozen slots cover those; the margin is deliberate.
const MEMMGR_FORWARD_HEADROOM: u64 = 512;

/// Free slots of `cspace` a general allocation may take: capacity less
/// populated slots less the IPC receive reserve. Zero when the queries fail.
fn cspace_general_headroom(cspace: u64) -> u64
{
    let capacity = syscall::cap_info(cspace, syscall_abi::CAP_INFO_CSPACE_CAPACITY).unwrap_or(0);
    let used = syscall::cap_info(cspace, syscall_abi::CAP_INFO_CSPACE_USED).unwrap_or(capacity);
    capacity
        .saturating_sub(used)
        .saturating_sub(syscall_abi::CSPACE_IPC_RECV_RESERVE)
}

/// Assert init's arena retype front never crossed its reserve into the
/// offset-mapped backing region. init's endpoint and log-thread retypes bump a
/// monotonic cursor through the front; the backing was offset-mapped at
/// `init_retype_reserve_pages(info)`. `available` is the arena's un-retyped
/// byte count, so a front bump past the reserve shows up as a consumed span
/// larger than the reserve. Endpoints created after `finalize_memmgr`
/// (devmgr/vfsd registries, phase 3) stay within the reserve's documented
/// headroom.
fn assert_init_arena_front_bounded(info: &InitInfo, init_arena_cap: u64)
{
    if let (Ok(size), Ok(available)) = (
        syscall::cap_info(init_arena_cap, syscall::CAP_INFO_MEMORY_SIZE),
        syscall::cap_info(init_arena_cap, syscall::CAP_INFO_MEMORY_AVAILABLE),
    )
    {
        let front_bump = size.saturating_sub(available);
        assert!(
            front_bump <= init_retype_reserve_pages(info).saturating_mul(PAGE_SIZE),
            "init: arena retype front overran its reserve into backing",
        );
    }
}

/// Delegate the remaining RAM Memory caps from init's pool into memmgr's
/// `CSpace` up to the forwarding stop (the first cap that has no `InitInfo`
/// descriptor, that comes once memmgr's `CSpace` headroom is already below its
/// limit, or whose move is refused), forward the in-use
/// bootstrap arenas (memmgr's, procmgr's, and init's own backing), then
/// `thread_configure` + `thread_start` memmgr. The descriptor-bearing caps from
/// the stop on reach memmgr's pool through the reap donation
/// (`finish_init_reap_handoff`); a cap with no descriptor is not donated.
///
/// Call after every `alloc.alloc_page()` consumer (memmgr's own setup,
/// procmgr's setup) has run — at that point everything left in init's
/// memory-cap pool is RAM that memmgr should own. After this call, init
/// allocates nothing more from its pool; subsequent allocations route through
/// memmgr like any other process.
///
/// Every free run is moved, not copied, so memmgr's slot is the only one that
/// names it: the kernel splits and merges a Memory object only through its
/// sole slot (core/kernel/docs/syscalls.md § `SYS_MEMORY_SPLIT`). A moved
/// cap leaves no slot in init's `CSpace`, so the forward needs no headroom
/// there.
///
/// `pm_arena_cap` is procmgr's backing arena and `init_arena_cap` is init's own
/// (from [`ProcmgrBootstrap`] and [`crate::run`]); both are forwarded alongside
/// memmgr's own arena (`mm.arena_cap`) so memmgr's `pool_total` spans every page
/// of bootstrap-consumed RAM, not only the free runs.
///
/// `phys_table_memory` is the auxiliary phys-table page (written after this
/// call, through the mapping init made before it). It is a transient
/// bootstrap artifact, so it is forwarded as a free run, and the read-only
/// `caps[1]` derivation the caller took from it before this call stays in
/// init's `CSpace` for the bootstrap round. Once memmgr has read the page and
/// deleted `caps[1]`, its run is named by memmgr's slot alone and allocatable
/// like any other.
///
/// Returns `None`, which the caller treats as a fatal bootstrap failure, when
/// the rights of a RAM cap to forward cannot be read or lack
/// `RIGHTS_MEM_RETYPE`, or when memmgr's thread cannot be configured or
/// started.
pub fn finalize_memmgr(
    info: &InitInfo,
    alloc: &mut MemoryAlloc,
    mm: &MemmgrBootstrap,
    pm_arena_cap: u64,
    init_arena_cap: u64,
    phys_table_memory: u64,
) -> Option<MemmgrFinalize>
{
    // The bootstrap round names the forwarded RAM caps by slot range only
    // (memmgr reads each cap's size and physical base from the kernel), so it
    // carries every remaining RAM cap while memmgr's `CSpace` keeps
    // [`MEMMGR_FORWARD_HEADROOM`] general slots. The first cap that has no
    // `InitInfo` descriptor, that comes once that headroom is already below
    // its limit, or whose move is refused ends the forwarded prefix; the
    // descriptor-bearing caps from there on reach memmgr's pool through the
    // reap donation (`finish_init_reap_handoff` → procmgr →
    // `DONATE_MEMORY_CAPS`) instead.
    // (The MemoryAlloc tail and the phys-table page have no InitInfo
    // descriptor, so the reap walk cannot reach them; they must ride here, in
    // the headroom the loop leaves.)
    let mut mm_memory_base: u64 = 0;
    let mut mm_memory_count: u64 = 0;
    let total_remaining = info.memory_count.saturating_sub(alloc.next_idx);
    for i in 0..total_remaining
    {
        // Slot indices lie within the root `CSpace`, far below `u64::MAX`.
        let src_slot = info
            .memory_base
            .saturating_add(alloc.next_idx)
            .saturating_add(i);
        // Keep the forwarded set a contiguous prefix: stop here and let the
        // reap route donate this memory cap and everything after it that has
        // an `InitInfo` descriptor (a cap with none is not donated).
        if descriptor_for(info, src_slot).is_none()
            || cspace_general_headroom(mm.mm_cspace) < MEMMGR_FORWARD_HEADROOM
        {
            break;
        }
        // Every RAM Memory cap init forwards to memmgr MUST carry
        // `MemRights::RETYPE`. The kernel stamps RETYPE on usable RAM at
        // Phase-7 mint (`core/kernel/src/cap/mod.rs`); init holds these
        // caps unchanged. Without it memmgr could not retype memory caps
        // into kernel objects and the typed-memory contract is broken.
        // `cap_info` on a non-null slot never fails for the universal
        // `TAG_RIGHTS` field; an Err here means the cap-routing graph is
        // broken. Either failure fails the memmgr bootstrap, which the
        // caller reports as fatal.
        let Ok(packed) = syscall::cap_info(src_slot, syscall::CAP_INFO_TAG_RIGHTS)
        else
        {
            log("init: cap_info failed on RAM Memory cap before memmgr forward");
            return None;
        };
        // Packed value is `(tag << 32) | rights`; `RIGHTS_MEM_RETYPE` is a
        // low-bit-position right so the u64 mask is exact.
        if packed & syscall::RIGHTS_MEM_RETYPE == 0
        {
            log("init: RAM Memory cap missing RIGHTS_MEM_RETYPE before memmgr forward");
            return None;
        }
        let Ok(dst_slot) = syscall::cap_move(src_slot, mm.mm_cspace, 0)
        else
        {
            break;
        };
        if mm_memory_count == 0
        {
            mm_memory_base = dst_slot;
        }
        // `mm_memory_count` is below `total_remaining`, so it cannot overflow.
        mm_memory_count = mm_memory_count.saturating_add(1);
    }
    // Advance only past the memory caps actually forwarded this round (a
    // contiguous prefix — the loop breaks on the first memory cap it cannot
    // forward). `memory_base + alloc.next_idx` is now the reap floor:
    // every memory cap at or above it is still solely init's, never
    // handed out by `MemoryAlloc` nor forwarded here, and every
    // descriptor-bearing one is donated to memmgr's pool via the reap route,
    // which has no per-round cap.
    // `mm_memory_count` is at most `total_remaining`, the slots left past `next_idx`.
    alloc.next_idx = alloc.next_idx.saturating_add(mm_memory_count);

    // Forward the partial tail left in `alloc.current`: the unallocated
    // remainder of the last memory cap `MemoryAlloc` split from. It is a
    // `memory_split` product, so it carries no named `InitInfo` descriptor and
    // is excluded from the reap donation walk; without this the reap's teardown
    // of init's CSpace would free it into the sealed post-handoff buddy (which
    // nothing allocates from), tripping the kernel's post-seal `debug_assert`
    // in a debug build, and its pages would be lost. It is
    // free RAM, so it joins memmgr's pool as a run like any forwarded memory cap.
    if alloc.remaining >= PAGE_SIZE
    {
        push_free_run(
            alloc.current,
            mm.mm_cspace,
            &mut mm_memory_base,
            &mut mm_memory_count,
        );
        alloc.remaining = 0;
    }

    // Forward the transient phys-table page as a free run too (same rationale
    // as the tail: a descriptor-less `memory_split` product). Its content is
    // written after this call and read once by memmgr through the read-only
    // `caps[1]` derivation; memmgr's moved slot is the page's keep-alive, and
    // after the read the page is allocatable like any other.
    push_free_run(
        phys_table_memory,
        mm.mm_cspace,
        &mut mm_memory_base,
        &mut mm_memory_count,
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
            && let Some(slot) = in_use.get_mut(in_use_count)
        {
            *slot = arena;
            // `in_use_count` indexed a slot, so it is below `MAX_IN_USE`.
            in_use_count = in_use_count.saturating_add(1);
        }
    }

    assert_init_arena_front_bounded(info, init_arena_cap);

    // SAFETY: the thread is bound to the service's own address space, never
    // init's, so its entry state touches nothing init runs on.
    unsafe {
        syscall::thread_configure(
            mm.mm_thread,
            mm.entry,
            mm.stack_top_vaddr,
            mm.process_info_va,
        )
    }
    .ok()?;
    crate::start_thread(mm.mm_thread).ok()?;
    log("memmgr started");

    Some(MemmgrFinalize {
        mm_memory_base,
        mm_memory_count,
        in_use,
        in_use_count,
    })
}

/// Write memmgr's bootstrap aux (phys-table) page from `mm_final`: the
/// kernel's immutable RAM-accounting facts (from `info`) and the in-use
/// bootstrap arena descriptors. The layout is
/// defined in `ipc::memmgr_bootstrap`; memmgr's `bootstrap_from_init` reads it
/// back through the read-only cap init derives from the same page.
///
/// # Safety
/// `phys_dst` must point at init's writable mapping of the one-page phys-table
/// memory cap (at least 4 KiB, `u64`-aligned).
pub unsafe fn write_memmgr_aux_memory(
    phys_dst: *mut u64,
    info: &InitInfo,
    mm_final: &MemmgrFinalize,
)
{
    use ipc::memmgr_bootstrap as mb;

    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "every write is to a word of the phys-table page at a constant index, which \
                  the caller's contract maps writable"
    )]
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
    // `in_use_count` only advances past a slot of `in_use`, so it is within the array.
    let in_use = mm_final
        .in_use
        .get(..mm_final.in_use_count)
        .unwrap_or_default();
    for (i, arena) in in_use.iter().enumerate()
    {
        // `i` is below `MAX_IN_USE`, so the word index stays within the page.
        let base = i
            .saturating_mul(mb::IN_USE_WORDS)
            .saturating_add(mb::IN_USE_BASE_IDX);
        // Each offset below is at most base + 3 < IN_USE_BASE_IDX + MAX_IN_USE *
        // IN_USE_WORDS, within the page; each write is to that word of the
        // caller's writable mapping of the page.
        // SAFETY: the offset `base` lies within the page (above).
        let cap_slot = unsafe { phys_dst.add(base) };
        // SAFETY: `cap_slot` is a word of the caller's writable page mapping.
        unsafe { core::ptr::write_volatile(cap_slot, arena.cap_slot) };
        // SAFETY: the offset `base + 1` lies within the page (above).
        let page_count = unsafe { phys_dst.add(base.saturating_add(1)) };
        // SAFETY: `page_count` is a word of the caller's writable page mapping.
        unsafe { core::ptr::write_volatile(page_count, u64::from(arena.page_count)) };
        // SAFETY: the offset `base + 2` lies within the page (above).
        let phys_base = unsafe { phys_dst.add(base.saturating_add(2)) };
        // SAFETY: `phys_base` is a word of the caller's writable page mapping.
        unsafe { core::ptr::write_volatile(phys_base, arena.phys_base) };
        // SAFETY: the offset `base + 3` lies within the page (above).
        let kind = unsafe { phys_dst.add(base.saturating_add(3)) };
        // SAFETY: `kind` is a word of the caller's writable page mapping.
        unsafe { core::ptr::write_volatile(kind, arena.kind) };
    }
}

// ── Procmgr bootstrap ───────────────────────────────────────────────────────

/// Procmgr kernel object caps needed to populate `ProcessInfo`.
struct ProcmgrCaps
{
    aspace: u64,
    cspace: u64,
    thread: u64,
    creator_endpoint_slot: u64,
    /// Slot index in procmgr's `CSpace` of the badged SEND cap on memmgr's
    /// endpoint. Zero when memmgr is not yet wired — an early-boot-only
    /// condition.
    memmgr_endpoint_slot: u64,
    /// Slot in procmgr's `CSpace` holding a badged SEND on the
    /// system log endpoint with badge `LOG_BADGE_PROCMGR`. Std reads
    /// it from `pi.log_send_cap` at `_start` and installs it via
    /// `::log::install_badged_cap` for procmgr's own `seraph::log!`
    /// writes. Zero when no log endpoint is available.
    log_send_slot: u64,
    /// `PT_TLS` template metadata, propagated into procmgr's `ProcessInfo`
    /// so spawned-thread allocations (via std) can populate matching
    /// blocks. Zero `memsz` means "no TLS".
    tls: ChildTlsMeta,
    /// Baseline `SchedControl` cap (in init's `CSpace`). Copied into procmgr for
    /// its own use and as the fan-out source for every process procmgr creates.
    sched_baseline: u64,
}

/// Populate procmgr's `ProcessInfo` page and map it read-only into procmgr.
///
/// procmgr's stdio cap slots are left zero (procmgr is std-built but
/// does not drive interactive stdio). The un-badged SEND on
/// the log endpoint procmgr uses as the *source* for deriving badged
/// SEND caps per child arrives via procmgr's bootstrap round, not via
/// `ProcessInfo`. The pre-installed badged SEND cap procmgr uses for
/// its OWN `seraph::log!` writes lives in `pi.log_send_cap`.
///
/// # Safety
/// `target_aspace` must name a child's address space, never init's own: the
/// function places pages into it at VAs the child's layout chooses, without
/// checking what init holds there.
#[expect(
    clippy::similar_names,
    reason = "procmgr's copies of its own objects are named by object and holder \
              (`pm_aspace_in_pm`, `pm_cspace_in_pm`); the names differ only in the object kind, \
              which is the distinction that matters"
)]
unsafe fn populate_procmgr_info(
    arena: &mut BootArena,
    target_aspace: u64,
    caps: &ProcmgrCaps,
    stack_pages: u32,
    layout: &ProcessLayout,
) -> Option<()>
{
    let pm_thread_in_pm =
        syscall::cap_copy(caps.thread, caps.cspace, syscall::RIGHTS_THREAD).ok()?;
    // procmgr's own address space without `RIGHTS_AS_READ`: init retyped it
    // from a `PHYS` arena, so it was minted with READ, which would let procmgr
    // translate every page it maps (its children's frames included) with
    // `SYS_ASPACE_QUERY`. procmgr never queries a mapping.
    let pm_aspace_in_pm = syscall::cap_copy(
        caps.aspace,
        caps.cspace,
        syscall::RIGHTS_ALL & !syscall::RIGHTS_AS_READ,
    )
    .ok()?;
    let pm_cspace_in_pm =
        syscall::cap_copy(caps.cspace, caps.cspace, syscall::RIGHTS_CS_ALL).ok()?;
    // Baseline SchedControl: procmgr's own scheduling authority and the
    // fan-out source it cap_copies into every process it creates.
    let pm_sched_in_pm =
        syscall::cap_copy(caps.sched_baseline, caps.cspace, syscall::RIGHTS_ALL).ok()?;

    let populate = |scratch_va: u64| {
        // SAFETY: scratch_va is mapped writable and zeroed, one page.
        let pi = unsafe { process_abi::process_info_mut(scratch_va) };
        pi.version = PROCESS_ABI_VERSION;
        pi.self_thread_cap = pm_thread_in_pm;
        pi.self_aspace_cap = pm_aspace_in_pm;
        pi.self_cspace_cap = pm_cspace_in_pm;
        pi.sched_control_cap = pm_sched_in_pm;
        pi.initial_priority = ipc::sched_policy::PROCMGR_PRIORITY;
        pi.ipc_buffer_vaddr = layout.ipc_buffer_va;
        pi.creator_endpoint_cap = caps.creator_endpoint_slot;
        // procmgr has no procmgr above it; leave zero.
        pi.procmgr_endpoint_cap = 0;
        pi.memmgr_endpoint_cap = caps.memmgr_endpoint_slot;
        pi.stdin_memory_cap = 0;
        pi.stdout_memory_cap = 0;
        pi.stderr_memory_cap = 0;
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
        pi.stack_top_vaddr = layout.stack_top;
        pi.stack_pages = stack_pages;
        // TLS block base, or zero when procmgr's image carries no PT_TLS.
        pi.main_tls_vaddr = if caps.tls.memsz != 0
        {
            layout.tls_base
        }
        else
        {
            0
        };
        // Infrastructure is never demand-paged (would recurse on its own
        // faults); leave the pager unbound.
        pi.pager_endpoint_cap = 0;
        pi.pager_badge = 0;
    };
    // SAFETY: the caller's contract: `target_aspace` is a child's address space,
    // never init's own.
    unsafe {
        arena.place_page(
            target_aspace,
            layout.process_info_va,
            syscall::MAP_READ,
            populate,
        )
    }?;

    Some(())
}

/// Place the stack and IPC buffer pages in `arena`, zeroed and mapped
/// read-write into `target_aspace`. Consumes `stack_pages + 1` backing
/// pages.
///
/// # Safety
/// `target_aspace` must name a child's address space, never init's own: the
/// function places pages into it at VAs the child's layout chooses, without
/// checking what init holds there.
unsafe fn place_stack_and_ipc(
    arena: &mut BootArena,
    target_aspace: u64,
    ipc_buf_va: u64,
    stack_top: u64,
    stack_pages: u32,
) -> Option<()>
{
    let stack_base = stack_top.checked_sub(u64::from(stack_pages).checked_mul(PAGE_SIZE)?)?;
    for i in 0..stack_pages
    {
        let page_va = stack_base.checked_add(u64::from(i).checked_mul(PAGE_SIZE)?)?;
        // SAFETY: the caller's contract: `target_aspace` is a child's address space,
        // never init's own.
        unsafe { arena.place_page(target_aspace, page_va, syscall::MAP_WRITABLE, |_| {}) }?;
    }
    // SAFETY: the caller's contract: `target_aspace` is a child's address space,
    // never init's own.
    unsafe { arena.place_page(target_aspace, ipc_buf_va, syscall::MAP_WRITABLE, |_| {}) }?;
    Some(())
}

/// Result of bootstrapping procmgr's setup. Procmgr's thread is
/// configured but **not yet started** — caller invokes [`start_procmgr`]
/// after [`finalize_memmgr`] so memmgr is alive when procmgr's
/// heap-bootstrap fires.
pub struct ProcmgrBootstrap
{
    /// Send cap to procmgr's service endpoint (init uses for `CREATE_PROCESS`).
    pub service_ep: u64,
    /// Procmgr's bootstrap badge on init's bootstrap endpoint.
    pub bootstrap_badge: u64,
    /// Slot in procmgr's `CSpace` holding an un-badged SEND cap on
    /// the system log endpoint, used by procmgr as the *source* for
    /// `cap_derive_badge` to mint a badged SEND cap per child (badge =
    /// the child's process badge). The minted cap is placed in the
    /// child's `ProcessInfo.log_send_cap`. Zero when no log endpoint
    /// is available (very early boot); children born in that window
    /// receive zero and silent-drop `seraph::log!`.
    pub log_endpoint_slot: u64,
    /// Slot in procmgr's `CSpace` holding an un-badged SEND cap on
    /// svcmgr's service endpoint (the global service registry).
    /// Procmgr uses it as the *source* for `cap_derive_badge` to mint
    /// a badged SEND cap per child (badge = the child's process
    /// badge, no `PUBLISH_AUTHORITY` bit), which is placed in the
    /// child's `ProcessInfo.service_registry_cap`. The child can
    /// `QUERY_ENDPOINT` but not `PUBLISH_ENDPOINT` — publish-authority
    /// caps are minted separately and handed only to init / devmgr /
    /// svcmgr.
    pub registry_endpoint_slot: u64,
    /// Procmgr's main thread cap (in init's `CSpace`). Used by
    /// [`start_procmgr`] to launch procmgr after memmgr is live.
    pub thread: u64,
    /// Procmgr's contiguous backing arena Memory cap (in init's `CSpace`).
    /// [`finalize_memmgr`] copies it into memmgr's `CSpace` and forwards it
    /// as an in-use arena so its pages are accounted in memmgr's pool.
    pub arena_cap: u64,
}

/// Mint a fresh init-side bootstrap badge: a random `u64` from the kernel
/// entropy pool, redrawn off the reserved `0` value (an unbadged SEND carries
/// badge 0). Random rather than monotonic so the service-bringup count it would
/// otherwise leak stays unguessable; each child matches its bootstrap round by
/// badge value, not index. Returns `None` if the entropy draw fails (a
/// kernel-contract violation), aborting the affected bringup step.
pub fn mint_bootstrap_badge() -> Option<u64>
{
    loop
    {
        let b = syscall::random_u64().ok()?;
        if b != 0
        {
            return Some(b);
        }
    }
}

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
#[expect(
    clippy::similar_names,
    reason = "procmgr's kernel objects are named by kind (`pm_aspace`, `pm_cspace`)"
)]
#[expect(
    clippy::too_many_lines,
    reason = "linear bootstrap workflow (CSpace setup, ELF load, TLS prep, per-purpose cap \
              derivation for log + registry + memmgr) reads straight-through; extracting helpers \
              would just shuffle state through extra parameters"
)]
#[expect(
    clippy::too_many_arguments,
    reason = "each endpoint and cap procmgr is bootstrapped with is a distinct input from a \
              different bootstrap stage"
)]
#[expect(
    clippy::large_stack_frames,
    reason = "no single large local: the estimate sums the many small locals of the ELF load \
              (`ehdr`, `layout`, `arena`, `pm_caps`, cap slots) and the `Option` temporaries of \
              its steps, and the compiled frame is under 2 KiB; on init's 16 KiB stack"
)]
pub fn bootstrap_procmgr(
    info: &InitInfo,
    alloc: &mut MemoryAlloc,
    init_bootstrap_ep: u64,
    pm_service_ep: u64,
    log_ep: u64,
    svcmgr_service_ep: u64,
    memmgr_send_cap: u64,
    baseline_sched: u64,
) -> Option<ProcmgrBootstrap>
{
    let init_aspace = info.aspace_cap;

    let module_memory_cap = crate::find_module_by_name(info, b"procmgr")?;
    let module_size = crate::descriptors(info)
        .iter()
        .find(|d| d.slot == module_memory_cap)
        .map(|d| d.aux1)?;

    let Some(module_pages) = module_scratch_pages(module_size)
    else
    {
        log("init: FATAL: procmgr module too large for the scratch region");
        return None;
    };

    // Derive a read-only child cap (see `bootstrap_memmgr` for rationale).
    let module_ro = syscall::cap_derive(module_memory_cap, syscall::RIGHTS_MEM_MAP).ok()?;
    // SAFETY: TEMP_MAP_BASE starts init's scratch region, unmapped between
    // bootstrap steps; `module_scratch_pages` keeps the span below
    // ELF_PAGE_TEMP_VA, and no Rust object of init lies in it.
    unsafe {
        syscall::mem_map(
            module_ro,
            init_aspace,
            TEMP_MAP_BASE,
            0,
            module_pages,
            syscall::MAP_FROM_CAP,
        )
    }
    .ok()?;

    // SAFETY: module memory cap is now mapped read-only at TEMP_MAP_BASE.
    let module_bytes =
        unsafe { core::slice::from_raw_parts(TEMP_MAP_BASE as *const u8, module_size as usize) };

    let machine = arch::current::EXPECTED_ELF_MACHINE;
    let (ehdr, kind) = elf::validate_executable(module_bytes, machine).ok()?;
    // `validate_executable` returns the header decoded; the parsers borrow it.
    let ehdr = &ehdr;
    let bias = match kind
    {
        elf::ElfKind::Exec => 0,
        elf::ElfKind::Dyn => choose_image_bias_or_default(),
    };
    let (span_min, span_end) = elf::load_span(ehdr, module_bytes).ok()?;
    if kind == elf::ElfKind::Dyn
    {
        if !process_layout::validate_image_placement(bias, span_min, span_end)
        {
            return None;
        }
        // Load-bias observability: debugging correlates through this line.
        log_hex("init: procmgr image bias=", bias);
    }
    let entry = elf::entry_point(ehdr).checked_add(bias)?;
    let rela = if kind == elf::ElfKind::Dyn
    {
        elf::rela_table(ehdr, module_bytes).ok()?
    }
    else
    {
        None
    };
    let total_relocs = match rela
    {
        Some(t) =>
        {
            let table = rela_table_bytes(module_bytes, &t)?;
            elf::validate_relative_relocs(table, machine, span_min, span_end).ok()?
        }
        None => 0,
    };
    // A note outside `1..=MAX_PROCESS_STACK_PAGES` refuses the binary.
    let stack_pages = process_abi::resolve_stack_pages(elf::parse_stack_note(ehdr, module_bytes))?;
    let layout = choose_child_layout();

    // procmgr is std-using: its arena reserves ELF segments + the main TLS
    // block + `ProcessInfo` + stack + IPC buffer.
    let backing_pages = elf_backing_pages(ehdr, module_bytes)?
        .checked_add(tls_backing_pages(ehdr, module_bytes))?
        .checked_add(1)?
        .checked_add(u64::from(stack_pages))?
        .checked_add(1)?;
    let mut arena = BootArena::carve(alloc, init_aspace, backing_pages)?;

    let pm_aspace = syscall::cap_create_aspace(arena.cap, 0, crate::ASPACE_RETYPE_PAGES).ok()?;
    let pm_cspace = syscall::cap_create_cspace(arena.cap, 0, crate::CSPACE_RETYPE_PAGES).ok()?;
    // procmgr sits directly below memmgr: above every process it manages,
    // preemptible only by its own pager.
    let pm_thread = syscall::cap_create_thread(
        arena.cap,
        pm_aspace,
        pm_cspace,
        baseline_sched,
        ipc::sched_policy::PROCMGR_PRIORITY,
    )
    .ok()?;

    log("created procmgr kernel objects");
    log("loading procmgr ELF segments");

    // SAFETY: the target is the child address space `cap_create_aspace` retyped
    // above for this service, never init's own.
    let applied_relocs =
        unsafe { load_elf_into_arena(&mut arena, ehdr, module_bytes, pm_aspace, bias, rela) }?;
    if applied_relocs != total_relocs
    {
        log("init: procmgr reloc application mismatch");
        return None;
    }

    // Place the main thread's TLS block while the module is still mapped —
    // `place_main_tls` reads the `PT_TLS` template from it. Procmgr is
    // std-using so the std runtime's `_start` accesses thread-local statics
    // (e.g. `IPC_BUF_TLS`) before user `main` runs; without a configured TLS
    // block, the first such access page-faults at NULL.
    // SAFETY: the target is the child address space `cap_create_aspace` retyped
    // above for this service, never init's own.
    let (pm_tls_base_va, pm_tls_meta) = unsafe {
        place_main_tls(
            &mut arena,
            ehdr,
            module_bytes,
            pm_aspace,
            layout.tls_base,
            bias,
            rela,
        )
    }?;

    // SAFETY: the module's scratch mapping; `module_bytes` and the header
    // borrowed from it are not used past this point.
    let _ = unsafe { syscall::mem_unmap(init_aspace, TEMP_MAP_BASE, module_pages) };
    let _ = syscall::cap_delete(module_ro);

    log("loaded procmgr ELF");

    // Derive badged creator endpoint for procmgr.
    let procmgr_badge = mint_bootstrap_badge()?;
    let badged_creator =
        syscall::cap_derive_badge(init_bootstrap_ep, syscall::RIGHTS_EP_SEND, procmgr_badge)
            .ok()?;
    let pm_creator_slot =
        syscall::cap_copy(badged_creator, pm_cspace, syscall::RIGHTS_EP_SEND).ok()?;

    // Procmgr maintains no memory-cap pool of its own; every per-child
    // allocation routes through memmgr. All remaining RAM memory caps get
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
        syscall::cap_derive(log_ep, syscall::RIGHTS_EP_SEND).ok()?
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
        syscall::cap_derive(svcmgr_service_ep, syscall::RIGHTS_EP_SEND).ok()?
    };

    // Copy the badged memmgr SEND cap into procmgr's CSpace. The slot it
    // lands at gets installed in procmgr's `ProcessInfo.memmgr_endpoint_cap`.
    let memmgr_endpoint_slot = if memmgr_send_cap == 0
    {
        0
    }
    else
    {
        syscall::cap_copy(memmgr_send_cap, pm_cspace, syscall::RIGHTS_EP_SEND_GRANT).ok()?
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
            syscall::RIGHTS_EP_SEND,
            ipc::log_badges::LOG_BADGE_PROCMGR,
        )
        .ok()?;
        let pm_side = syscall::cap_copy(init_side, pm_cspace, syscall::RIGHTS_EP_SEND).ok()?;
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
        sched_baseline: baseline_sched,
    };
    // SAFETY: the target is the child address space `cap_create_aspace` retyped
    // above for this service, never init's own.
    unsafe { populate_procmgr_info(&mut arena, pm_aspace, &pm_caps, stack_pages, &layout) }?;

    // SAFETY: the target is the child address space `cap_create_aspace` retyped
    // above for this service, never init's own.
    unsafe {
        place_stack_and_ipc(
            &mut arena,
            pm_aspace,
            layout.ipc_buffer_va,
            layout.stack_top,
            stack_pages,
        )
    }?;

    // SAFETY: the thread is bound to the service's own address space, never
    // init's, so its entry state touches nothing init runs on.
    unsafe {
        syscall::thread_configure_with_tls(
            pm_thread,
            entry,
            layout.stack_top,
            layout.process_info_va,
            pm_tls_base_va,
        )
    }
    .ok()?;
    // **Don't** thread_start here — procmgr's `_start` calls
    // `heap_bootstrap` which calls memmgr's `REQUEST_MEMORY_CAPS`, so memmgr
    // must already be ingested + serving before procmgr starts. Caller
    // runs `finalize_memmgr` first, then `start_procmgr`.

    // Derive a send cap to procmgr's service endpoint for init's own use.
    let service_ep_for_init =
        syscall::cap_derive(pm_service_ep, syscall::RIGHTS_EP_SEND_GRANT).ok()?;

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
/// Like the other bootstrap entry points, it reports failure to
/// [`crate::run`], which decides that init cannot continue.
///
/// # Errors
/// Returns the error [`crate::start_thread`] reports: the first
/// `syscall::thread_start` failure other than `Interrupted`, which
/// `start_thread` retries.
pub fn start_procmgr(pm: &ProcmgrBootstrap) -> Result<(), i64>
{
    crate::start_thread(pm.thread)
}
