// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/headroom.rs

//! devmgr's own `CSpace` held above a low-water mark of general slots
//! (`services/devmgr/docs/responsibilities.md` § `CSpace` headroom), through
//! `std::os::seraph::CSpaceHeadroom`.

use std::os::seraph::{CSpaceHeadroom, startup_info};

/// Capabilities one bound driver's resource takes in devmgr's `CSpace` while
/// it is bound: devmgr's own cap, carved for the record, and the driver's
/// copy, derived at the spawn. Each is also a body of the `CSpace`'s arena
/// (an `Mmio`, `IoPort`, or `Interrupt` split or copy).
const CAPS_PER_RESOURCE: u64 = 2;

/// Slots a spawn holds beyond its resources' copies: the end round's
/// endpoints (`driver_binding::resources::END_SLOTS`), the badged creator,
/// the argv and env, the three caps of procmgr's create reply, and the
/// death-observer `POST` copy.
const SPAWN_SLOTS: u64 = driver_binding::resources::END_SLOTS as u64 + 6;

/// Slots the registry's workers and the DMA thread take while one thread
/// tops up: a few each, for four workers and the DMA thread.
const CONCURRENT_SLOTS: u64 = 16;

/// The bodies one record's bind takes at most: a body for each of its
/// resources' caps, at most `spawn::MAX_BOUND_RESOURCES`.
const RECORD_BODIES: u64 = CAPS_PER_RESOURCE * crate::spawn::MAX_BOUND_RESOURCES as u64;

/// General-allocation headroom of devmgr's `CSpace` below which it tops the
/// pool up: the most one record's bind takes, its carves and its driver's
/// spawn, at the declaration bound of resources, with the requests the other
/// threads serve meanwhile. The body arena draws whole pages from the growth
/// budget the slots grow from, each page lowering the capacity by a page's
/// slots, so the record's bodies count as the slots of the pages they take.
/// `CSpaceHeadroom` holds a page beyond the mark for the first of those
/// pages (`syscall_abi::cspace_topup_pages`). About 450 slots.
const CSPACE_LOW_WATER: u64 = CAPS_PER_RESOURCE * crate::spawn::MAX_BOUND_RESOURCES as u64
    + SPAWN_SLOTS
    + RECORD_BODIES.div_ceil(syscall_abi::CSPACE_BODIES_PER_PAGE)
        * syscall_abi::CSPACE_SLOTS_PER_PAGE
    + CONCURRENT_SLOTS;

/// Headroom a top-up funds: twice the mark, about 16 slot pages, so a top-up
/// comes only after several dozen more bound drivers of a few resources each.
const CSPACE_TOPUP_SLOTS: u64 = 2 * CSPACE_LOW_WATER;

/// devmgr's `CSpace` headroom, shared by every devmgr thread.
static HEADROOM: CSpaceHeadroom = CSpaceHeadroom::new(CSPACE_LOW_WATER, CSPACE_TOPUP_SLOTS);

/// Hold devmgr's `CSpace` above [`CSPACE_LOW_WATER`] before an operation
/// that allocates slots, on any devmgr thread: each control-loop turn, each
/// record's bind before its carves, each driver spawn, each registry request,
/// and each DMA request. Logs nothing, so a registry
/// worker or the DMA thread may call it while logd, or a driver logd writes
/// through, waits on its reply; the control thread reports a failed top-up
/// ([`hold_and_report`]).
pub fn hold()
{
    HEADROOM.hold(startup_info().self_cspace);
}

/// [`hold`], then log a run of failed top-ups, whichever thread's top-up
/// failed, once per run: the control thread's hold, which may log.
pub fn hold_and_report()
{
    hold();
    if HEADROOM.failure_to_report()
    {
        std::os::seraph::log!(warn: "CSpace headroom top-up failed; retrying before each operation");
    }
}
