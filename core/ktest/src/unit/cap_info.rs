// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/ktest/src/unit/cap_info.rs

//! Tier 1 tests for `SYS_CAP_INFO`.
//!
//! Covers the read-only inspection syscall that returns a discriminated
//! union of cap state via the [`syscall::cap_info`] field-selector wrapper.
//! Each call returns a single `u64`; userspace assembles a full picture by
//! issuing repeated calls. The shape mirrors `SYS_SYSTEM_INFO`.
//!
//! Field coverage:
//! - `CAP_INFO_TAG_RIGHTS` against several cap tags (`Memory`, `AddressSpace`,
//!   `Notification`, `CSpace`).
//! - Creation-mint masks of every userspace-creatable type against the ABI's
//!   per-type rights constants (`creation_masks_match_abi`).
//! - `CAP_INFO_MEMORY_*` against a Memory cap, including `CAP_INFO_MEMORY_MAPPINGS`
//!   following a frame's mappings into two address spaces and out again.
//! - `CAP_INFO_SOLE_REFERENCE` following a Memory cap's references through a
//!   derivation and a retyped object (`sole_reference`).
//! - `CAP_INFO_CSPACE_*` against a `CSpace` cap.
//! - The `InitInfo` RAM Memory descriptors against their caps
//!   (`ram_descriptors_match_caps`).
//! - The `RIGHTS_MEM_PHYS` gate on `CAP_INFO_MEMORY_PHYS_BASE` and on the
//!   `RIGHTS_AS_READ` an address-space retype mints (`phys_base_needs_the_right`).
//! - Negative paths: null slot index (`InvalidCapability`) and tag-mismatched
//!   selector (`InvalidArgument`).

use syscall::{
    MAP_WRITABLE, RIGHTS_ALL, cap_create_aspace, cap_create_cspace, cap_create_endpoint,
    cap_create_notification, cap_delete, cap_derive, cap_info, cap_info_memory_mappings,
    cap_info_phys_base, mem_map, mem_unmap,
};
use syscall_abi::{
    CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_CAPACITY, CAP_INFO_CSPACE_USED,
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_HAS_RETYPE, CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES,
    CAP_INFO_MEMORY_PHYS_BASE, CAP_INFO_MEMORY_SIZE, CAP_INFO_SOLE_REFERENCE, CAP_INFO_TAG_RIGHTS,
    CSPACE_SLOTS_PER_PAGE, SyscallError,
};

use crate::{TestContext, TestResult};

// CapTag discriminants (core/kernel/src/cap/slot.rs `CapTag`). Keep in sync with the
// `#[repr(u8)]` enum.
const TAG_MEMORY: u8 = 1;
const TAG_ADDRESS_SPACE: u8 = 2;
const TAG_SIGNAL: u8 = 4;
const TAG_CSPACE: u8 = 9;

// Memory RETYPE bit, cast to the 32-bit rights half of the packed
// CAP_INFO_TAG_RIGHTS value. The ABI guarantees every rights bit fits u32.
#[allow(clippy::cast_possible_truncation)]
const RIGHTS_RETYPE_BIT: u32 = syscall_abi::RIGHTS_MEM_RETYPE as u32;

/// Decode a `CAP_INFO_TAG_RIGHTS` packed return: `(tag << 32) | rights`.
fn unpack_tag_rights(value: u64) -> (u8, u32)
{
    // The kernel guarantees the high 32 bits hold an 8-bit tag (zero-extended)
    // and the low 32 bits hold the rights bitmask. The casts are exact and
    // truncating only the deliberately-zero upper bits.
    #[allow(clippy::cast_possible_truncation)]
    let tag = (value >> 32) as u8;
    // The low 32 bits are the rights bitmask; the cast drops only the tag half.
    #[allow(clippy::cast_possible_truncation)]
    let rights = value as u32;
    (tag, rights)
}

// ── CAP_INFO_TAG_RIGHTS ───────────────────────────────────────────────────────

/// `cap_info(aspace_cap, CAP_INFO_TAG_RIGHTS)` reports `AddressSpace` tag.
///
/// The cap is allocated by the kernel at boot; its tag is `AddressSpace`
/// (= 2) and its rights include at least `MAP | READ`.
pub fn tag_rights_aspace(ctx: &TestContext) -> TestResult
{
    let value = cap_info(ctx.aspace_cap, CAP_INFO_TAG_RIGHTS)
        .map_err(|_| "cap_info(aspace_cap, TAG_RIGHTS) failed")?;
    let (tag, rights) = unpack_tag_rights(value);
    if tag != TAG_ADDRESS_SPACE
    {
        return Err("cap_info on aspace cap returned unexpected tag");
    }
    if rights == 0
    {
        return Err("cap_info on aspace cap reported empty rights bitmask");
    }
    Ok(())
}

/// `cap_info(<memory cap>, CAP_INFO_TAG_RIGHTS)` reports `Memory` tag.
///
/// Uses the TEXT segment Memory cap (`aspace_cap + 1`), present as a `Memory`
/// cap with at least `MAP | EXECUTE` rights.
pub fn tag_rights_memory(ctx: &TestContext) -> TestResult
{
    let memory_cap = ctx.aspace_cap + 1;
    let value = cap_info(memory_cap, CAP_INFO_TAG_RIGHTS)
        .map_err(|_| "cap_info(memory_cap, TAG_RIGHTS) failed")?;
    let (tag, rights) = unpack_tag_rights(value);
    if tag != TAG_MEMORY
    {
        return Err("cap_info on TEXT segment cap returned unexpected tag");
    }
    if rights == 0
    {
        return Err("cap_info on TEXT segment cap reported empty rights bitmask");
    }
    Ok(())
}

/// `cap_info(<notification cap>, CAP_INFO_TAG_RIGHTS)` reports `Notification` tag.
///
/// Allocates a fresh notification cap to verify the universal field works for
/// non-memory tags as well.
pub fn tag_rights_notification(ctx: &TestContext) -> TestResult
{
    let sig =
        cap_create_notification(ctx.memory_base).map_err(|_| "cap_create_notification failed")?;
    let value = cap_info(sig, CAP_INFO_TAG_RIGHTS)
        .map_err(|_| "cap_info(notification, TAG_RIGHTS) failed")?;
    let (tag, rights) = unpack_tag_rights(value);
    cap_delete(sig).map_err(|_| "cap_delete(notification) failed")?;
    if tag != TAG_SIGNAL
    {
        return Err("cap_info on notification cap returned unexpected tag");
    }
    if rights == 0
    {
        return Err("cap_info on notification cap reported empty rights bitmask");
    }
    Ok(())
}

// ── Memory-specific fields ───────────────────────────────────────────────────

/// Scratch VA (crate docs § Scratch VAs) for the mappings-count probe, in
/// ktest's own address space and in the second one it creates.
const MAPPINGS_VA: u64 = 0x1_5D00_0000;

/// `CAP_INFO_MEMORY_MAPPINGS` counts the live user leaves naming a frame:
/// none before a map, one per address space that maps it, one fewer after an
/// unmap, and none once the last mapping's address space is destroyed. On a
/// region larger than `CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES` pages, a full-length
/// window past the first `MAX_PAGES` answers, and a window that is too long,
/// empty, or runs past the region is refused.
pub fn memory_mappings(ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("cap_info::memory_mappings: frame pool exhausted")?;
    let result = mappings_probe(ctx, memory_cap);
    // A failed cleanup can leave the frame mapped; it then stays out of the
    // pool rather than break `free`'s precondition.
    if cap_info_memory_mappings(memory_cap, 0, 1) == Ok(0)
    {
        // SAFETY: the kernel reports no address space maps the frame, so every
        // mapping the probe made of it is gone.
        unsafe { crate::frame_pool::free(memory_cap) };
    }
    result?;

    mappings_windows(ctx)
}

/// The windowed query on `memory_base`, a region larger than one window:
/// windows inside it answer wherever they start, and the refused shapes are
/// refused.
fn mappings_windows(ctx: &TestContext) -> TestResult
{
    let size = cap_info(ctx.memory_base, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "cap_info::memory_mappings: cap_info(memory_base, SIZE) failed")?;
    let pages = size / syscall_abi::PAGE_SIZE;
    let max = CAP_INFO_MEMORY_MAPPINGS_MAX_PAGES;
    if pages < 2 * max + 1
    {
        return Err("cap_info::memory_mappings: memory_base is too small to test the window");
    }
    if cap_info_memory_mappings(ctx.memory_base, max, max).is_err()
        || cap_info_memory_mappings(ctx.memory_base, pages - 1, 1).is_err()
    {
        return Err("cap_info::memory_mappings: a window inside a large region was refused");
    }
    let refused = |first, len| {
        cap_info_memory_mappings(ctx.memory_base, first, len)
            == Err(SyscallError::InvalidArgument as i64)
    };
    if !refused(0, max + 1)
        || !refused(0, 0)
        || !refused(pages - max + 1, max)
        || !refused(pages, 1)
    {
        return Err("cap_info::memory_mappings: a malformed window was not refused");
    }
    Ok(())
}

/// Map `memory_cap` into ktest's address space and a fresh one, checking the
/// count after each step. Unmaps it from both on every path that can.
fn mappings_probe(ctx: &TestContext, memory_cap: u64) -> TestResult
{
    let count = || {
        cap_info_memory_mappings(memory_cap, 0, 1)
            .map_err(|_| "cap_info::memory_mappings: cap_info(MAPPINGS) failed")
    };
    if count()? != 0
    {
        return Err("cap_info::memory_mappings: an unmapped frame reported mappings");
    }
    let other = cap_create_aspace(ctx.memory_base, 0, 8)
        .map_err(|_| "cap_info::memory_mappings: cap_create_aspace failed")?;
    // SAFETY: `MAPPINGS_VA` is a scratch VA (crate docs § Scratch VAs) of
    // ktest's address space.
    let own = unsafe { mem_map(memory_cap, ctx.aspace_cap, MAPPINGS_VA, 0, 1, MAP_WRITABLE) };
    // SAFETY: `other` is an address space this test created, which runs
    // nothing of ktest's.
    let theirs = unsafe { mem_map(memory_cap, other, MAPPINGS_VA, 0, 1, MAP_WRITABLE) };
    let mapped = own.and(theirs);
    let both = count();
    // SAFETY: as for the map above.
    let unmapped = unsafe { mem_unmap(ctx.aspace_cap, MAPPINGS_VA, 1) };
    let one = count();
    cap_delete(other).map_err(|_| "cap_info::memory_mappings: cap_delete(aspace) failed")?;
    let none = count();
    mapped.map_err(|_| "cap_info::memory_mappings: mem_map failed")?;
    unmapped.map_err(|_| "cap_info::memory_mappings: mem_unmap failed")?;
    if both? != 2 || one? != 1 || none? != 0
    {
        return Err("cap_info::memory_mappings: the count did not follow the mappings (2, 1, 0)");
    }
    Ok(())
}

/// `CAP_INFO_SOLE_REFERENCE` reports whether the queried slot is the only
/// reference to its object: a fresh frame's cap is sole; a derivation of it
/// shares its Memory object, so neither is sole while both live; an object
/// retyped from it holds a lease on that object, so the cap is not sole while
/// the object lives, and the object's own cap is sole; each answer returns to
/// sole once the other reference is deleted.
pub fn sole_reference(_ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("cap_info::sole_reference: frame pool exhausted")?;
    let result = sole_probe(memory_cap);
    // A failed cleanup can leave a derivation or a retyped object; the frame
    // then stays out of the pool rather than break `free`'s precondition.
    if cap_info(memory_cap, CAP_INFO_SOLE_REFERENCE) == Ok(1)
    {
        // SAFETY: the kernel reports no other reference to the frame's object,
        // so the probe's derivation and endpoint are gone, and it never mapped
        // the frame.
        unsafe { crate::frame_pool::free(memory_cap) };
    }
    result
}

/// The sole-reference answers on `memory_cap` through a derivation and a
/// retyped endpoint, in order: alone, derived (both sides), derivation
/// deleted, endpoint live (Memory cap and endpoint), endpoint deleted.
fn sole_probe(memory_cap: u64) -> TestResult
{
    let sole = |cap| {
        cap_info(cap, CAP_INFO_SOLE_REFERENCE)
            .map_err(|_| "cap_info::sole_reference: cap_info(SOLE_REFERENCE) failed")
    };
    let alone = sole(memory_cap)?;
    let copy = cap_derive(memory_cap, RIGHTS_ALL)
        .map_err(|_| "cap_info::sole_reference: cap_derive failed")?;
    let derived = (sole(memory_cap), sole(copy));
    cap_delete(copy).map_err(|_| "cap_info::sole_reference: cap_delete(copy) failed")?;
    let underived = sole(memory_cap)?;
    let ep = cap_create_endpoint(memory_cap)
        .map_err(|_| "cap_info::sole_reference: cap_create_endpoint failed")?;
    let leased = (sole(memory_cap), sole(ep));
    cap_delete(ep).map_err(|_| "cap_info::sole_reference: cap_delete(endpoint) failed")?;
    let released = sole(memory_cap)?;
    if alone != 1 || underived != 1 || released != 1
    {
        return Err("cap_info::sole_reference: a cap with no other reference was not sole");
    }
    if derived.0? != 0 || derived.1? != 0
    {
        return Err("cap_info::sole_reference: a derived Memory cap or its source reported sole");
    }
    if leased.0? != 0 || leased.1? != 1
    {
        return Err(
            "cap_info::sole_reference: a retype lease was not counted, or the object's cap",
        );
    }
    Ok(())
}

/// Memory fields are consistent: `size > 0`, `available <= size`, `has_retype`
/// is `0` or `1`.
///
/// Uses a frame from the pool — these are buddy-backed RAM frames carrying
/// the `RETYPE` right at boot.
pub fn memory_fields(_ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("cap_info::memory_fields: frame pool exhausted")?;

    // Every read of the cap happens before it goes back to the pool.
    let reads = read_memory_fields(memory_cap);

    // SAFETY: alloc() returned the cap and it was never mapped; the reads above
    // are its last use. The pool is single-threaded for tests.
    unsafe { crate::frame_pool::free(memory_cap) };

    let (size, available, has_retype, tag_rights) = reads?;
    if size == 0
    {
        return Err("cap_info(memory_cap, MEMORY_SIZE) returned 0");
    }
    if available > size
    {
        return Err("cap_info(memory_cap, MEMORY_AVAILABLE) > MEMORY_SIZE");
    }
    if has_retype > 1
    {
        return Err("cap_info(memory_cap, MEMORY_HAS_RETYPE) returned non-boolean value");
    }

    // Cross-check the boolean against the rights bitmask via TAG_RIGHTS.
    let (_tag, rights) = unpack_tag_rights(tag_rights);
    let expected = u64::from((rights & RIGHTS_RETYPE_BIT) != 0);
    if has_retype != expected
    {
        return Err("MEMORY_HAS_RETYPE disagrees with TAG_RIGHTS bitmask");
    }
    Ok(())
}

/// Read `memory_cap`'s size, available bytes, has-retype flag, and packed
/// tag-and-rights word, in that order.
fn read_memory_fields(memory_cap: u64) -> Result<(u64, u64, u64, u64), &'static str>
{
    let size = cap_info(memory_cap, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "cap_info(memory_cap, MEMORY_SIZE) failed")?;
    let available = cap_info(memory_cap, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "cap_info(memory_cap, MEMORY_AVAILABLE) failed")?;
    let has_retype = cap_info(memory_cap, CAP_INFO_MEMORY_HAS_RETYPE)
        .map_err(|_| "cap_info(memory_cap, MEMORY_HAS_RETYPE) failed")?;
    let tag_rights = cap_info(memory_cap, CAP_INFO_TAG_RIGHTS)
        .map_err(|_| "cap_info(memory_cap, TAG_RIGHTS) failed")?;
    Ok((size, available, has_retype, tag_rights))
}

/// RAM Memory caps minted by the kernel at boot carry the `RETYPE` right.
///
/// Every usable-RAM Memory cap minted by the kernel at Phase 7
/// (`core/kernel/src/cap/mod.rs`) carries `MemRights::RETYPE`. The bit must
/// propagate through the cap-routing graph (kernel → init → memmgr →
/// child via `REQUEST_MEMORY_CAPS`) so memmgr's consumers can retype frames
/// into kernel objects (see docs/capability-model.md § Typed Memory).
///
/// ktest is loaded as init and so receives the RAM Memory caps directly
/// at slots `info.memory_base..+memory_count`. This test reads the cap at
/// `ctx.memory_base`: the head of the first RAM cap, which
/// `frame_pool::init` leaves in place after carving the pool's single-page
/// frames off its tail.
pub fn memory_caps_carry_retype_right(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;
    if memory == 0
    {
        return Err("memory_caps_carry_retype_right: ctx.memory_base is zero");
    }

    // Path 1: read the rights bitmask via TAG_RIGHTS.
    let value =
        cap_info(memory, CAP_INFO_TAG_RIGHTS).map_err(|_| "cap_info(memory, TAG_RIGHTS) failed")?;
    let (tag, rights) = unpack_tag_rights(value);

    // Path 2: read the RETYPE-only boolean via the dedicated selector.
    let has_retype = cap_info(memory, CAP_INFO_MEMORY_HAS_RETYPE)
        .map_err(|_| "cap_info(memory, MEMORY_HAS_RETYPE) failed")?;

    if tag != TAG_MEMORY
    {
        return Err("memory_caps_carry_retype_right: cap reported non-Memory tag");
    }
    if rights & RIGHTS_RETYPE_BIT == 0
    {
        return Err("memory_caps_carry_retype_right: TAG_RIGHTS missing RETYPE bit");
    }
    if has_retype != 1
    {
        return Err("memory_caps_carry_retype_right: MEMORY_HAS_RETYPE != 1");
    }
    Ok(())
}

/// Every RAM Memory descriptor `InitInfo` carries describes the cap in its
/// slot: the `memory_count` descriptors for slots `memory_base..`, in slot
/// order, each a `Memory` descriptor whose base is its cap's
/// `CAP_INFO_MEMORY_PHYS_BASE` and whose size is at least its cap's
/// `CAP_INFO_MEMORY_SIZE` (ktest's own start-up splits tails off some of
/// them). The kernel writes these descriptors over the drained RAM extents
/// they describe, in the `InitInfo` block itself
/// (core/kernel/docs/initialization.md § Phase 7), so a write that overtook
/// an extent not yet read would show here as a base or size of another
/// extent.
pub fn ram_descriptors_match_caps(ctx: &TestContext) -> TestResult
{
    use init_protocol::{CapType, InitInfo};
    // SAFETY: the kernel maps the read-only InitInfo page at init_info_va for
    // ktest's lifetime.
    let info = unsafe { &*(ctx.init_info_va as *const InitInfo) };
    let ram = || {
        crate::init_info::descriptors(info).iter().filter(|d| {
            d.cap_type == CapType::Memory
                && (info.memory_base..info.memory_base + info.memory_count).contains(&d.slot)
        })
    };
    if u64::try_from(ram().count()) != Ok(info.memory_count) || info.memory_count == 0
    {
        return Err("ram_descriptors_match_caps: not one descriptor per RAM Memory cap");
    }
    for (d, slot) in ram().zip(info.memory_base..)
    {
        if d.slot != slot
        {
            return Err("ram_descriptors_match_caps: RAM descriptors out of slot order");
        }
        let base = cap_info(d.slot, CAP_INFO_MEMORY_PHYS_BASE)
            .map_err(|_| "ram_descriptors_match_caps: cap_info(PHYS_BASE) failed")?;
        let size = cap_info(d.slot, CAP_INFO_MEMORY_SIZE)
            .map_err(|_| "ram_descriptors_match_caps: cap_info(SIZE) failed")?;
        if base != d.aux0
        {
            return Err("ram_descriptors_match_caps: a descriptor's base is not its cap's");
        }
        if size > d.aux1 || size == 0
        {
            return Err("ram_descriptors_match_caps: a cap is larger than its descriptor");
        }
    }
    Ok(())
}

/// Kernel creation-mint masks match the ABI's per-type rights numbering.
///
/// Creates one object of each userspace-creatable type, reads
/// `CAP_INFO_TAG_RIGHTS`, and asserts the rights half equals the mask the
/// kernel mints for that type, built from the named ABI constants. Rights are
/// scoped per capability type, so a renumbering drift between the kernel's
/// typed constants and the ABI on any one type fails here behaviourally
/// rather than surfacing as a misgated syscall elsewhere.
pub fn creation_masks_match_abi(ctx: &TestContext) -> TestResult
{
    let ep = syscall::cap_create_endpoint(ctx.memory_base)
        .map_err(|_| "creation_masks: cap_create_endpoint failed")?;
    let r = check_mask(
        ep,
        syscall_abi::RIGHTS_EP_SEND | syscall_abi::RIGHTS_EP_RECEIVE | syscall_abi::RIGHTS_EP_GRANT,
        "creation_masks: endpoint mint mask mismatch",
    );
    cap_delete(ep).map_err(|_| "creation_masks: cap_delete(endpoint) failed")?;
    r?;

    let sig = cap_create_notification(ctx.memory_base)
        .map_err(|_| "creation_masks: cap_create_notification failed")?;
    let r = check_mask(
        sig,
        syscall_abi::RIGHTS_NTF_NOTIFY | syscall_abi::RIGHTS_NTF_WAIT,
        "creation_masks: notification mint mask mismatch",
    );
    cap_delete(sig).map_err(|_| "creation_masks: cap_delete(notification) failed")?;
    r?;

    let eq = syscall::event_queue_create(ctx.memory_base, 4)
        .map_err(|_| "creation_masks: event_queue_create failed")?;
    let r = check_mask(
        eq,
        syscall_abi::RIGHTS_EQ_POST | syscall_abi::RIGHTS_EQ_RECV,
        "creation_masks: event queue mint mask mismatch",
    );
    cap_delete(eq).map_err(|_| "creation_masks: cap_delete(event queue) failed")?;
    r?;

    let ws = syscall::wait_set_create(ctx.memory_base, crate::WS_CAPACITY)
        .map_err(|_| "creation_masks: wait_set_create failed")?;
    let r = check_mask(
        ws,
        syscall_abi::RIGHTS_WS_MODIFY | syscall_abi::RIGHTS_WS_WAIT,
        "creation_masks: wait set mint mask mismatch",
    );
    cap_delete(ws).map_err(|_| "creation_masks: cap_delete(wait set) failed")?;
    r?;

    bound_creation_masks(ctx)
}

/// Rights word of `cap` (via `CAP_INFO_TAG_RIGHTS`) equals `expected` exactly.
fn check_mask(cap: u64, expected: u64, what: &'static str) -> TestResult
{
    // The ABI constants are u64 with all bits in the low 32 (asserted by the
    // abi host tests); the rights half of the packed value is u32.
    #[allow(clippy::cast_possible_truncation)]
    let expected32 = expected as u32;
    let value = cap_info(cap, CAP_INFO_TAG_RIGHTS).map_err(|_| what)?;
    let (_tag, rights) = unpack_tag_rights(value);
    if rights != expected32
    {
        return Err(what);
    }
    Ok(())
}

/// `CAP_INFO_MEMORY_PHYS_BASE` answers only a holder of `RIGHTS_MEM_PHYS`
/// (core/kernel/docs/syscalls.md § `SYS_CAP_INFO`): a boot RAM cap, which
/// carries the right, answers; a derivation without it is refused
/// `InsufficientRights`, alone and with itself as the credential, answers
/// with the RAM cap as its credential, and a credential that is not a Memory
/// cap is refused `InvalidCapability`. An `AddressSpace` retyped through the
/// derivation is minted without `RIGHTS_AS_READ`, so `SYS_ASPACE_QUERY`
/// cannot translate its pages; one retyped from the RAM cap carries it
/// (`creation_masks_match_abi`).
pub fn phys_base_needs_the_right(ctx: &TestContext) -> TestResult
{
    let memory = ctx.memory_base;
    let base = cap_info(memory, CAP_INFO_MEMORY_PHYS_BASE)
        .map_err(|_| "phys_base_needs_the_right: a RAM cap's physical base was refused")?;
    let child = cap_derive(memory, RIGHTS_ALL & !syscall_abi::RIGHTS_MEM_PHYS)
        .map_err(|_| "phys_base_needs_the_right: cap_derive without PHYS failed")?;
    let r = phys_gate_on(child, memory, base, ctx.aspace_cap)
        .and_then(|()| aspace_read_follows_phys(child));
    cap_delete(child).map_err(|_| "phys_base_needs_the_right: cap_delete of the derivation")?;
    r
}

/// [`phys_base_needs_the_right`]'s selector checks on `child`, a derivation
/// of `memory` without `RIGHTS_MEM_PHYS` whose base is `base`; `other` is a
/// cap of another type.
fn phys_gate_on(child: u64, memory: u64, base: u64, other: u64) -> TestResult
{
    let refused = Err(SyscallError::InsufficientRights as i64);
    if cap_info(child, CAP_INFO_MEMORY_PHYS_BASE) != refused
    {
        return Err("phys_base_needs_the_right: a cap without PHYS was not refused");
    }
    if cap_info_phys_base(child, child) != refused
    {
        return Err("phys_base_needs_the_right: a credential without PHYS was accepted");
    }
    if cap_info_phys_base(child, memory) != Ok(base)
    {
        return Err("phys_base_needs_the_right: a PHYS credential did not answer the base");
    }
    if cap_info_phys_base(child, other) != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("phys_base_needs_the_right: a non-Memory credential was not refused");
    }
    Ok(())
}

/// [`phys_base_needs_the_right`]'s address-space check: a retype through
/// `child`, which lacks `RIGHTS_MEM_PHYS`, mints no `RIGHTS_AS_READ`.
fn aspace_read_follows_phys(child: u64) -> TestResult
{
    let aspace = cap_create_aspace(child, 0, 4)
        .map_err(|_| "phys_base_needs_the_right: cap_create_aspace through the derivation")?;
    let rights = cap_info(aspace, CAP_INFO_TAG_RIGHTS).map(|v| unpack_tag_rights(v).1);
    cap_delete(aspace).map_err(|_| "phys_base_needs_the_right: cap_delete of the aspace")?;
    let rights = rights.map_err(|_| "phys_base_needs_the_right: TAG_RIGHTS of the aspace")?;
    if u64::from(rights) & syscall_abi::RIGHTS_AS_READ != 0
    {
        return Err("phys_base_needs_the_right: an aspace retyped without PHYS carries READ");
    }
    if u64::from(rights) & syscall_abi::RIGHTS_AS_MAP == 0
    {
        return Err("phys_base_needs_the_right: an aspace retyped without PHYS lacks MAP");
    }
    Ok(())
}

/// `creation_masks_match_abi` tail: the aspace/cspace/thread arms.
///
/// The aspace and cspace must outlive the thread bound to them, so their
/// checks defer teardown to the shared delete sequence at the end
/// (best-effort on the failure paths, mirroring the per-object arms in
/// `creation_masks_match_abi`).
fn bound_creation_masks(ctx: &TestContext) -> TestResult
{
    let aspace = syscall::cap_create_aspace(ctx.memory_base, 0, 4)
        .map_err(|_| "creation_masks: cap_create_aspace failed")?;
    let r = check_mask(
        aspace,
        syscall_abi::RIGHTS_AS_MAP | syscall_abi::RIGHTS_AS_READ | syscall_abi::RIGHTS_AS_CONTROL,
        "creation_masks: address space mint mask mismatch",
    );
    if r.is_err()
    {
        cap_delete(aspace).ok();
        return r;
    }

    let Ok(cs) = cap_create_cspace(ctx.memory_base, 0, 4)
    else
    {
        cap_delete(aspace).ok();
        return Err("creation_masks: cap_create_cspace failed");
    };
    let r = check_mask(
        cs,
        syscall_abi::RIGHTS_CS_INSERT
            | syscall_abi::RIGHTS_CS_DELETE
            | syscall_abi::RIGHTS_CS_DERIVE,
        "creation_masks: cspace mint mask mismatch",
    );
    if r.is_err()
    {
        cap_delete(cs).ok();
        cap_delete(aspace).ok();
        return r;
    }

    // Thread bound to the aspace/cspace above; sched cap 0 + priority 0
    // creates at the band floor with no SchedControl. Never started —
    // deleted right after the mask read.
    let Ok(thread) = syscall::cap_create_thread(ctx.memory_base, aspace, cs, 0, 0)
    else
    {
        cap_delete(cs).ok();
        cap_delete(aspace).ok();
        return Err("creation_masks: cap_create_thread failed");
    };
    let r = check_mask(
        thread,
        syscall_abi::RIGHTS_THREAD,
        "creation_masks: thread mint mask mismatch",
    );
    cap_delete(thread).map_err(|_| "creation_masks: cap_delete(thread) failed")?;
    cap_delete(cs).map_err(|_| "creation_masks: cap_delete(cspace) failed")?;
    cap_delete(aspace).map_err(|_| "creation_masks: cap_delete(aspace) failed")?;
    r
}

// ── CSpace-specific fields ───────────────────────────────────────────────────

/// `CSpace` fields report the currently-backed capacity, and the cap's tag
/// is `CSpace`.
///
/// With `S` the slots per leaf page (`CSPACE_SLOTS_PER_PAGE`, the kernel's
/// `L2_SIZE`), a fresh `init_pages = 4` cspace (3 pool pages, none consumed)
/// reports `capacity == 3 × S`, `used == 0`, and `budget == 3` pages.
/// Inserting one cap draws the first slot page from the pool, so capacity
/// settles at `3 × S − 1` (slot 0 reserved) with `used == 1`. An
/// augment-mode donation of 2 pages raises capacity by `2 × S`. The page
/// and slot arithmetic follows core/kernel/docs/capability-internals.md
/// § Page Pools, § Representation, and § Storage: Hybrid Radix Directory.
pub fn cspace_fields(ctx: &TestContext) -> TestResult
{
    // Slots per leaf page: the kernel's `L2_SIZE`, published in the ABI.
    const L2_SIZE: u64 = CSPACE_SLOTS_PER_PAGE;
    let cs = cap_create_cspace(ctx.memory_base, 0, 4).map_err(|_| "cap_create_cspace failed")?;

    let fresh_capacity = cap_info(cs, CAP_INFO_CSPACE_CAPACITY)
        .map_err(|_| "cap_info(cspace, CSPACE_CAPACITY) failed")?;
    let fresh_used =
        cap_info(cs, CAP_INFO_CSPACE_USED).map_err(|_| "cap_info(cspace, CSPACE_USED) failed")?;
    let fresh_budget = cap_info(cs, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "cap_info(cspace, CSPACE_BUDGET) failed")?;
    let (tag, _) = unpack_tag_rights(
        cap_info(cs, CAP_INFO_TAG_RIGHTS).map_err(|_| "cap_info(cspace, TAG_RIGHTS) failed")?,
    );
    if tag != TAG_CSPACE
    {
        cap_delete(cs).ok();
        return Err("cap_info(cspace, TAG_RIGHTS) did not report the CSpace tag");
    }

    // Populate one slot so the first slot page is drawn from the pool.
    let probe =
        cap_create_notification(ctx.memory_base).map_err(|_| "cap_create_notification failed")?;
    if syscall::cap_copy(probe, cs, 1).is_err()
    {
        cap_delete(probe).ok();
        cap_delete(cs).ok();
        return Err("cap_copy into fresh cspace failed");
    }
    let after_capacity = cap_info(cs, CAP_INFO_CSPACE_CAPACITY)
        .map_err(|_| "cap_info(CSPACE_CAPACITY) after insert failed")?;
    let after_used = cap_info(cs, CAP_INFO_CSPACE_USED)
        .map_err(|_| "cap_info(CSPACE_USED) after insert failed")?;

    // Augment-mode donation must raise the backed capacity.
    let augment_ok = cap_create_cspace(ctx.memory_base, cs, 2).is_ok();
    let aug_capacity = cap_info(cs, CAP_INFO_CSPACE_CAPACITY)
        .map_err(|_| "cap_info(CSPACE_CAPACITY) after augment failed")?;

    cap_delete(probe).ok();
    cap_delete(cs).map_err(|_| "cap_delete(cspace) failed")?;

    if fresh_capacity != 3 * L2_SIZE
    {
        return Err("fresh cspace capacity != 3 pool pages of CSPACE_SLOTS_PER_PAGE slots");
    }
    if fresh_used != 0
    {
        return Err("freshly-created cspace reported non-zero CSPACE_USED");
    }
    if fresh_budget != 3 * syscall_abi::PAGE_SIZE
    {
        return Err("fresh cspace budget != 3 pool pages");
    }
    if after_capacity != 3 * L2_SIZE - 1
    {
        return Err("capacity after first insert != 3 pages of slots less slot 0");
    }
    if after_used != 1
    {
        return Err("CSPACE_USED != 1 after one insert");
    }
    if !augment_ok
    {
        return Err("augment-mode cap_create_cspace failed");
    }
    if aug_capacity != after_capacity + 2 * L2_SIZE
    {
        return Err("capacity did not grow by 2 pages of slots after a 2-page augment");
    }
    Ok(())
}

// ── Negative paths ───────────────────────────────────────────────────────────

/// `cap_info(0, _)` returns `InvalidCapability` — slot 0 is permanently null
/// (docs/capability-model.md § Capability Spaces).
pub fn null_slot_invalid(_ctx: &TestContext) -> TestResult
{
    let err = cap_info(0, CAP_INFO_TAG_RIGHTS);
    if err != Err(SyscallError::InvalidCapability as i64)
    {
        return Err("cap_info(0, TAG_RIGHTS) did not return InvalidCapability");
    }
    Ok(())
}

/// Tag-specific selector on a non-matching cap returns `InvalidArgument`.
///
/// We use a freshly created `Notification` cap and ask for `MEMORY_SIZE`.
pub fn tag_mismatch_invalid_arg(ctx: &TestContext) -> TestResult
{
    let sig =
        cap_create_notification(ctx.memory_base).map_err(|_| "cap_create_notification failed")?;
    let err = cap_info(sig, CAP_INFO_MEMORY_SIZE);
    cap_delete(sig).map_err(|_| "cap_delete(notification) failed")?;
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("cap_info(notification, MEMORY_SIZE) did not return InvalidArgument");
    }
    Ok(())
}

/// `SYS_CAP_CREATE_CSPACE` rejects a non-zero arg3 with `InvalidArgument`.
///
/// arg3 carried the removed `max_slots` quota; it is reserved and must be
/// zero in both create and augment modes. The 3-arg `cap_create_cspace`
/// wrapper always passes 0, so the probe issues the raw entry point.
pub fn cspace_create_rejects_nonzero_arg3(ctx: &TestContext) -> TestResult
{
    // Create-mode with arg3 = 1.
    let ret = syscall::raw_cap_create_cspace(ctx.memory_base, 0, 4, 1);
    if ret != SyscallError::InvalidArgument as i64
    {
        return Err("create-mode arg3 != 0 was not rejected with InvalidArgument");
    }

    // Augment-mode with arg3 = 1 against a valid target.
    let cs = cap_create_cspace(ctx.memory_base, 0, 2)
        .map_err(|_| "cap_create_cspace for augment-arg3 probe failed")?;
    let ret = syscall::raw_cap_create_cspace(ctx.memory_base, cs, 2, 1);
    cap_delete(cs).map_err(|_| "cap_delete(cspace) failed")?;
    if ret != SyscallError::InvalidArgument as i64
    {
        return Err("augment-mode arg3 != 0 was not rejected with InvalidArgument");
    }
    Ok(())
}

/// Unknown selector returns `InvalidArgument`.
pub fn unknown_field_invalid_arg(ctx: &TestContext) -> TestResult
{
    // Pick a value far outside the assigned selector range.
    let err = cap_info(ctx.aspace_cap, 0xFFFF_FFFF);
    if err != Err(SyscallError::InvalidArgument as i64)
    {
        return Err("cap_info(aspace, 0xFFFFFFFF) did not return InvalidArgument");
    }
    Ok(())
}
