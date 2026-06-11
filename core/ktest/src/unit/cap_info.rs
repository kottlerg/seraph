// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/unit/cap_info.rs

//! Tier 1 tests for `SYS_CAP_INFO`.
//!
//! Covers the read-only inspection syscall that returns a discriminated
//! union of cap state via the [`syscall::cap_info`] field-selector wrapper.
//! Each call returns a single `u64`; userspace assembles a full picture by
//! issuing repeated calls. The shape mirrors `SYS_SYSTEM_INFO`.
//!
//! Field coverage:
//! - `CAP_INFO_TAG_RIGHTS` against several cap tags (`Memory`, `AddressSpace`,
//!   `Notification`).
//! - `CAP_INFO_MEMORY_*` against a Memory cap.
//! - `CAP_INFO_CSPACE_*` against a `CSpace` cap.
//! - Negative paths: null slot index (`InvalidCapability`) and tag-mismatched
//!   selector (`InvalidArgument`).

use syscall::{cap_create_cspace, cap_create_notification, cap_delete, cap_info};
use syscall_abi::{
    CAP_INFO_CSPACE_BUDGET, CAP_INFO_CSPACE_CAPACITY, CAP_INFO_CSPACE_USED,
    CAP_INFO_MEMORY_AVAILABLE, CAP_INFO_MEMORY_HAS_RETYPE, CAP_INFO_MEMORY_SIZE,
    CAP_INFO_TAG_RIGHTS, SyscallError,
};

use crate::{TestContext, TestResult};

// CapTag discriminants (kernel/src/cap/slot.rs). Keep in sync with the
// `#[repr(u8)]` enum.
const TAG_MEMORY: u8 = 1;
const TAG_ADDRESS_SPACE: u8 = 2;
const TAG_SIGNAL: u8 = 4;
const TAG_CSPACE: u8 = 9;

// Rights bits (kernel/src/cap/slot.rs).
const RIGHTS_RETYPE_BIT: u32 = 1 << 21;

/// Decode a `CAP_INFO_TAG_RIGHTS` packed return: `(tag << 32) | rights`.
fn unpack_tag_rights(value: u64) -> (u8, u32)
{
    // The kernel guarantees the high 32 bits hold an 8-bit tag (zero-extended)
    // and the low 32 bits hold the rights bitmask. The casts are exact and
    // truncating only the deliberately-zero upper bits.
    #[allow(clippy::cast_possible_truncation)]
    let tag = (value >> 32) as u8;
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

/// Memory fields are consistent: `size > 0`, `available <= size`, `has_retype`
/// is `0` or `1`.
///
/// Uses a frame from the pool — these are buddy-backed RAM frames carrying
/// the `RETYPE` right at boot.
pub fn memory_fields(_ctx: &TestContext) -> TestResult
{
    let memory_cap =
        crate::frame_pool::alloc().ok_or("cap_info::memory_fields: frame pool exhausted")?;

    let size = cap_info(memory_cap, CAP_INFO_MEMORY_SIZE)
        .map_err(|_| "cap_info(memory_cap, MEMORY_SIZE) failed")?;
    let available = cap_info(memory_cap, CAP_INFO_MEMORY_AVAILABLE)
        .map_err(|_| "cap_info(memory_cap, MEMORY_AVAILABLE) failed")?;
    let has_retype = cap_info(memory_cap, CAP_INFO_MEMORY_HAS_RETYPE)
        .map_err(|_| "cap_info(memory_cap, MEMORY_HAS_RETYPE) failed")?;

    // SAFETY: alloc() returned the cap; pool is single-threaded for tests.
    unsafe { crate::frame_pool::free(memory_cap) };

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
    let value = cap_info(memory_cap, CAP_INFO_TAG_RIGHTS)
        .map_err(|_| "cap_info(memory_cap, TAG_RIGHTS) failed")?;
    let (_tag, rights) = unpack_tag_rights(value);
    let expected = u64::from((rights & RIGHTS_RETYPE_BIT) != 0);
    if has_retype != expected
    {
        return Err("MEMORY_HAS_RETYPE disagrees with TAG_RIGHTS bitmask");
    }
    Ok(())
}

/// RAM Memory caps minted by the kernel at boot carry the `RETYPE` right.
///
/// Every usable-RAM Memory cap minted by the kernel at Phase 7
/// (`core/kernel/src/cap/mod.rs`) carries `Rights::RETYPE`. The bit must
/// propagate through the cap-routing graph (kernel → init → memmgr →
/// child via `REQUEST_FRAMES`) so memmgr's consumers can retype frames
/// into kernel objects under the typed-memory contract.
///
/// ktest is loaded as init and so receives the RAM Memory caps directly
/// at slots `info.memory_base..+memory_count`. These are the
/// caps the kernel actually stamps with RETYPE; segment-derived Memory
/// caps (the BSS-derived `frame_pool` slots used elsewhere in this file)
/// are intentionally minted *without* RETYPE since they back ELF pages,
/// not retypable RAM.
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

// ── CSpace-specific fields ───────────────────────────────────────────────────

/// `CSpace` fields are consistent on a freshly created cspace.
///
/// `capacity == max_slots requested`; `used == 0` for a brand-new empty
/// cspace; `budget` reads cleanly without erroring.
pub fn cspace_fields(ctx: &TestContext) -> TestResult
{
    const REQUESTED: u64 = 64;
    let cs = cap_create_cspace(ctx.memory_base, 0, 4, REQUESTED)
        .map_err(|_| "cap_create_cspace failed")?;

    let capacity = cap_info(cs, CAP_INFO_CSPACE_CAPACITY)
        .map_err(|_| "cap_info(cspace, CSPACE_CAPACITY) failed")?;
    let used =
        cap_info(cs, CAP_INFO_CSPACE_USED).map_err(|_| "cap_info(cspace, CSPACE_USED) failed")?;
    let _budget = cap_info(cs, CAP_INFO_CSPACE_BUDGET)
        .map_err(|_| "cap_info(cspace, CSPACE_BUDGET) failed")?;

    cap_delete(cs).map_err(|_| "cap_delete(cspace) failed")?;

    if capacity != REQUESTED
    {
        return Err("cap_info(cspace, CSPACE_CAPACITY) did not match requested max_slots");
    }
    if used != 0
    {
        return Err("freshly-created cspace reported non-zero CSPACE_USED");
    }
    Ok(())
}

// ── Negative paths ───────────────────────────────────────────────────────────

/// `cap_info(0, _)` returns `InvalidCapability` — slot 0 is permanently null.
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

/// `max_slots = 0` on create-mode `cap_create_cspace` defaults the quota
/// to what the seeded pool backs — `(init_pages - 1) * 56 - 1` usable
/// slots — never an unbacked 14336 ceiling (#366).
pub fn cspace_default_max_slots_is_pool_backed(ctx: &TestContext) -> TestResult
{
    let cs = cap_create_cspace(ctx.memory_base, 0, 4, 0)
        .map_err(|_| "cap_create_cspace(init_pages=4, max_slots=0) failed")?;
    let capacity = cap_info(cs, CAP_INFO_CSPACE_CAPACITY);
    cap_delete(cs).map_err(|_| "cap_delete(cspace) failed")?;
    let capacity = capacity.map_err(|_| "cap_info(CSPACE_CAPACITY) failed")?;
    if capacity != 3 * 56 - 1
    {
        return Err("default max_slots != pool-backed capacity (3 pool pages)");
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

// CapTag values are kept aligned with the kernel; if the enum gains a new
// variant the constants above need updating in lockstep.
const _: () = {
    // Static cross-checks (shake out typos at compile time).
    assert!(TAG_MEMORY == 1);
    assert!(TAG_ADDRESS_SPACE == 2);
    assert!(TAG_SIGNAL == 4);
    assert!(TAG_CSPACE == 9);
};

// Keep the unused constant from being optimised out when the test list does
// not currently exercise an explicit CSpace tag check via TAG_RIGHTS.
const _: u8 = TAG_CSPACE;
