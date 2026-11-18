// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/memmgr_grant.rs

//! The reply-shape decoder of memmgr's grant replies (`memmgr_labels`), re-exported
//! at the crate root.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use crate::{IpcMessage, memmgr_errors};

/// Split a `memmgr_labels::REQUEST_MEMORY_CAPS` success reply into its page
/// counts and region ids, one of each per transferred cap: `data[1 + i]` and
/// `data[1 + count + i]` for `i` below the declared `count` in `data[0]`
/// (services/memmgr/docs/ipc-interface.md § Label 1). A region id is the
/// opaque name `memmgr_labels::RELEASE_MEMORY_CAPS` takes for its cap's run.
///
/// The reply is wire input, so nothing is indexed until it passes these
/// checks. Returns `None` for an error label, a reply with no data words, a
/// declared count of zero or other than the number of caps transferred, or
/// data words too few to cover the declared count; the id words of such a
/// reply sit at an offset its count does not establish, so no id is read.
#[must_use]
pub fn memmgr_grant_layout(reply: &IpcMessage) -> Option<(&[u64], &[u64])>
{
    let words = reply.words();
    let count = reply.caps().len();
    let (&declared, rest) = words.split_first()?;
    if reply.label != memmgr_errors::SUCCESS || count == 0 || declared != count as u64
    {
        return None;
    }
    let (counts, rest) = rest.split_at_checked(count)?;
    Some((counts, rest.get(..count)?))
}
