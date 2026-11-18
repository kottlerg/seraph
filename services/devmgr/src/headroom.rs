// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/headroom.rs

//! devmgr's own `CSpace` held above a low-water mark of general slots
//! (`services/devmgr/docs/responsibilities.md` § `CSpace` headroom), through
//! `std::os::seraph::CSpaceHeadroom`.

use std::os::seraph::{CSpaceHeadroom, startup_info};

/// General-allocation headroom of devmgr's `CSpace` below which it tops the
/// pool up. A driver spawn holds the most slots at once: a copy of each of
/// its resources and of its end round's endpoints
/// (`spawn::MAX_BOUND_RESOURCES` plus `driver_binding::resources::END_SLOTS`,
/// 75 at most), its badged creator, its argv and env, and the three caps of
/// procmgr's create reply, about 80; each registry worker's request and the
/// DMA thread's take a few more while one thread tops up. The mark covers all
/// of them with margin.
const CSPACE_LOW_WATER: u64 = 128;

/// Headroom a top-up funds: about 10 slot pages, so the next top-up comes
/// only after a few dozen more bound drivers.
const CSPACE_TOPUP_SLOTS: u64 = 512;

/// devmgr's `CSpace` headroom, shared by every devmgr thread.
static HEADROOM: CSpaceHeadroom = CSpaceHeadroom::new(CSPACE_LOW_WATER, CSPACE_TOPUP_SLOTS);

/// Hold devmgr's `CSpace` above [`CSPACE_LOW_WATER`] before an operation
/// that allocates slots, on any devmgr thread. Logs nothing, so a registry
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
