// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/vmgenid.rs

//! VM Generation ID (VMGENID) snapshot-resume detector.
//!
//! The hypervisor rewrites a 16-byte GUID in guest RAM whenever the VM's
//! execution history forks (snapshot resume, restore, clone) — with the
//! vCPUs paused, before any of them runs again. A resumed snapshot replays
//! the entropy pool and every per-CPU generator, so two clones would emit
//! identical streams until a reseed; the GUID is the detection channel that
//! forces that reseed before any post-resume output.
//!
//! Detection is per-draw and per-CPU: each generator compares the live GUID
//! against the one it last reseeded under ([`read_guid`] is a 16-byte
//! volatile read through the direct map) and treats a mismatch as a
//! mandatory reseed. No cross-CPU state exists — the GUID in guest RAM *is*
//! the shared authority. The BSP timer tick additionally polls the GUID
//! purely for observability ([`poll_log`]); it shares nothing with the draw
//! path and takes no locks.
//!
//! The GUID's physical address is discovered by the bootloader (QEMU VMGENID
//! SSDT scan; see `boot-protocol` v13) and is zero when absent — riscv64
//! today, or non-QEMU hosts. Absence degrades to the time-budget reseed
//! bound in [`super::reseed_policy`].

use core::sync::atomic::{AtomicU64, Ordering};

use super::pool;

/// Kernel VA of the live GUID (via the direct map). Zero until [`init`]
/// arms detection; zero forever when the platform has no VMGENID.
static GUID_VA: AtomicU64 = AtomicU64::new(0);

/// BSP poll cache for [`poll_log`], as two little-endian words. BSP-private
/// (written at Phase 5 single-threaded boot and from the BSP tick only), so
/// `Relaxed` suffices.
static LAST_SEEN: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// Arm snapshot detection. Phase 5, BSP, after paging (direct map live) and
/// pool install; `paddr` was ceiling-checked against the physical memory
/// span at `BootInfo` capture. Zero = no VMGENID; detection stays disarmed.
///
/// Absorbs the initial GUID into the pool: with QEMU `guid=auto` this is a
/// free 128-bit host-random boot source.
pub fn init(paddr: u64)
{
    if paddr == 0
    {
        return;
    }
    let va = crate::mm::paging::phys_to_virt(paddr);
    let guid = read_at(va);
    pool::absorb(&guid);
    let (lo, hi) = split(&guid);
    LAST_SEEN[0].store(lo, Ordering::Relaxed);
    LAST_SEEN[1].store(hi, Ordering::Relaxed);
    GUID_VA.store(va, Ordering::Release);
    crate::kprintln!("entropy: vmgenid armed @ {paddr:#x}");
}

/// The live GUID, or `None` when detection is disarmed.
#[inline]
pub fn read_guid() -> Option<[u8; 16]>
{
    let va = GUID_VA.load(Ordering::Acquire);
    if va == 0
    {
        return None;
    }
    Some(read_at(va))
}

/// Volatile 16-byte read of the GUID at kernel VA `va`.
///
/// The hypervisor rewrites the GUID only while the vCPUs are paused, so a
/// torn read cannot occur in practice; if one ever did, the per-draw compare
/// self-heals — the next draw still mismatches and reseeds again.
#[inline]
fn read_at(va: u64) -> [u8; 16]
{
    // SAFETY: `va` was derived by `init` from a BootInfo physical address
    // validated against the physical memory span; the direct map covers it
    // for the kernel's lifetime.
    unsafe { core::ptr::read_volatile(va as *const [u8; 16]) }
}

fn split(guid: &[u8; 16]) -> (u64, u64)
{
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&guid[..8]);
    hi.copy_from_slice(&guid[8..]);
    (u64::from_le_bytes(lo), u64::from_le_bytes(hi))
}

/// BSP timer-tick observability hook: log once per generation change.
///
/// Interrupt context — lock-free except the console lock inside `kprintln`
/// on the (once-per-resume) change path, matching the tick-path watchdog
/// precedent. The reseed guarantee never depends on this poll; the draw
/// path performs its own compare.
pub fn poll_log()
{
    let va = GUID_VA.load(Ordering::Acquire);
    if va == 0
    {
        return;
    }
    let (lo, hi) = split(&read_at(va));
    if LAST_SEEN[0].load(Ordering::Relaxed) != lo || LAST_SEEN[1].load(Ordering::Relaxed) != hi
    {
        LAST_SEEN[0].store(lo, Ordering::Relaxed);
        LAST_SEEN[1].store(hi, Ordering::Relaxed);
        crate::kprintln!("entropy: VM generation change detected");
    }
}
