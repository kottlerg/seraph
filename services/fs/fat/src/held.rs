// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/fs/fat/src/held.rs

//! The dispatch loop's line for a request it held too long.
//!
//! The loop takes a [`HeldRequest`] when it receives a request and drops it
//! when its turn ends, after the reply. A request held [`SLOW_REQUEST`] or
//! longer is logged with its label, its time, and how much of that time its
//! block calls took and how many it made ([`cache::block_call_totals`]), so
//! the line tells a stall in the block path from one in fatfs or in another
//! service it calls (README § Slow requests). A request held less costs two
//! clock reads and two counter reads.

use std::time::{Duration, Instant};

use ipc::{fs_labels, ns_labels};

use crate::cache;

/// A request held this long or longer, from its receipt to the end of its
/// dispatch, is logged.
///
/// vfsd's `FS_UNMOUNT_TIMEOUT_MS` (5 s, `services/vfsd/src/main.rs`), the
/// tightest bound a client puts on a call to a filesystem driver: a request
/// held this long has outlasted the bound of any such call queued behind it,
/// since one thread serves them all. The other bounds on such a call, procmgr's
/// `FILE_CAP_CALL_TIMEOUT_MS` and vfsd's `FALLTHROUGH_TIMEOUT_MS` and
/// `PROBE_TIMEOUT_MS`, are 10 s. The constants are private to their crates,
/// so vfsd's names this one as depending on it. A request that removes a large
/// file can take seconds; one that reaches the bound makes an unmount queued
/// behind it time out, so vfsd tears the mount down without the driver's
/// cooperation, and its line names the request. A diagnostic bound that bounds
/// no capacity: it decides only which requests are logged.
pub const SLOW_REQUEST: Duration = Duration::from_secs(5);

/// One request's receipt: its opcode, the time, and the block-call totals.
pub struct HeldRequest
{
    opcode: u64,
    received: Instant,
    block_time: Duration,
    block_calls: u64,
}

impl HeldRequest
{
    /// Start timing the request with opcode `opcode` (the label's low 16 bits).
    pub fn start(opcode: u64) -> Self
    {
        let (block_time, block_calls) = cache::block_call_totals();
        Self {
            opcode,
            received: Instant::now(),
            block_time,
            block_calls,
        }
    }
}

impl Drop for HeldRequest
{
    /// Log the request when it was held [`SLOW_REQUEST`] or longer.
    fn drop(&mut self)
    {
        let held = self.received.elapsed();
        if held < SLOW_REQUEST
        {
            return;
        }
        let (block_time, block_calls) = cache::block_call_totals();
        std::os::seraph::log!(
            warn: "slow request: {} (label {}) held {} ms, {} ms of it in {} block calls",
            label_name(self.opcode),
            self.opcode,
            held.as_millis(),
            block_time.saturating_sub(self.block_time).as_millis(),
            block_calls.wrapping_sub(self.block_calls)
        );
    }
}

/// The name of the label with opcode `opcode` that fatfs serves.
fn label_name(opcode: u64) -> &'static str
{
    match opcode
    {
        fs_labels::FS_READ => "FS_READ",
        fs_labels::FS_CLOSE => "FS_CLOSE",
        fs_labels::FS_WRITE => "FS_WRITE",
        fs_labels::FS_READ_MEMORY => "FS_READ_MEMORY",
        fs_labels::FS_RELEASE_MEMORY => "FS_RELEASE_MEMORY",
        fs_labels::FS_MOUNT => "FS_MOUNT",
        fs_labels::FS_WRITE_MEMORY => "FS_WRITE_MEMORY",
        fs_labels::FS_CREATE => "FS_CREATE",
        fs_labels::FS_REMOVE => "FS_REMOVE",
        fs_labels::FS_MKDIR => "FS_MKDIR",
        fs_labels::FS_RENAME => "FS_RENAME",
        fs_labels::FS_TRUNCATE => "FS_TRUNCATE",
        fs_labels::FS_OPEN => "FS_OPEN",
        fs_labels::FS_UNMOUNT => "FS_UNMOUNT",
        ns_labels::NS_LOOKUP => "NS_LOOKUP",
        ns_labels::NS_STAT => "NS_STAT",
        ns_labels::NS_READDIR => "NS_READDIR",
        _ => "an unknown label",
    }
}
