// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/topology.rs

//! SMT sibling topology: which logical CPUs share one core.
//!
//! Each CPU records its core key (`arch::current::cpu::core_key`) in its slot
//! of a per-CPU slab at its bring-up: the boot CPU in Phase 8 before it starts
//! the APs, each AP in `kernel_entry_ap` before it reports itself online. Once
//! every AP is online the boot CPU links the CPUs of each core into a ring, a
//! second per-CPU slab holding each CPU's next sibling in ascending index order,
//! wrapping, and publishes it. The ring is read-only from then on. A reader
//! before the publication sees no siblings, which costs placement its
//! tie-break and nothing else. The scheduler's placement reads it
//! (core/kernel/docs/scheduler.md § SMT Awareness), and `SYS_SYSTEM_INFO`
//! reports it (`SystemInfoType::SmtSibling`).
//!
//! A ring rather than a CPU set per core keeps the storage at one entry per CPU
//! (docs/coding-standards.md § CPU-Count Width): a set per core costs a
//! CPU-count-wide mask per core, and every reader walks only the few CPUs of
//! one core.

use core::sync::atomic::{AtomicPtr, Ordering};

#[cfg(not(test))]
use crate::mm::BuddyAllocator;
use crate::sched::PerCpuSlab;

/// One CPU's entry in the core-key slab: its core key and its index. The
/// derived order is by key, then by index, so a sort groups each core's CPUs
/// in ascending index order. A zero-filled entry is a valid value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct CoreSlot
{
    /// The CPU's core key (`arch::current::cpu::core_key`).
    key: u32,
    /// The CPU's logical index.
    cpu: u32,
}

/// The core-key slab: one [`CoreSlot`] per CPU, written by that CPU.
const CORE_SLOTS_SLAB: PerCpuSlab = PerCpuSlab::of::<CoreSlot>("CORE_SLOTS");
const _: () = assert!(
    CORE_SLOTS_SLAB.sized_at_every_width(),
    "CORE_SLOTS slab overflows"
);

/// The sibling-ring slab: per CPU, the index of the next CPU of its core.
const SIBLING_RING_SLAB: PerCpuSlab = PerCpuSlab::of::<u32>("SIBLING_RING");
const _: () = assert!(
    SIBLING_RING_SLAB.sized_at_every_width(),
    "SIBLING_RING slab overflows"
);

/// The ring entry no CPU has been linked to yet. No CPU index reaches it,
/// since every index is below `MAX_CPUS`.
const UNLINKED: u32 = u32::MAX;

/// The core-key slab, published (Release) at Phase 4 by [`init_storage`].
static CORE_SLOTS_PTR: AtomicPtr<CoreSlot> = AtomicPtr::new(core::ptr::null_mut());

/// The sibling-ring slab as allocated, before its links are written; read only
/// by the boot CPU's [`build_sibling_rings`].
static SIBLING_RING_STORAGE: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());

/// The linked sibling ring, `CPU_COUNT` entries, published (Release) by
/// [`build_sibling_rings`] once every link is written; null before.
static SIBLING_RING_PTR: AtomicPtr<u32> = AtomicPtr::new(core::ptr::null_mut());

/// What the linked rings hold, for the boot log.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RingSummary
{
    /// The number of cores, one ring each.
    pub cores: usize,
    /// The most CPUs one core holds.
    pub max_threads: usize,
}

/// Allocate the core-key and sibling-ring slabs, each sized to `cpu_count`
/// (Phase 4, while the buddy still holds large blocks).
///
/// # Panics
/// Halts via `crate::fatal` on buddy exhaustion (`alloc_per_cpu_slab`).
#[cfg(not(test))]
pub fn init_storage(cpu_count: u32, allocator: &mut BuddyAllocator)
{
    let n = cpu_count as usize;
    let slots = crate::sched::alloc_per_cpu_slab::<CoreSlot>(CORE_SLOTS_SLAB, n, allocator);
    CORE_SLOTS_PTR.store(slots, Ordering::Release);
    let ring = crate::sched::alloc_per_cpu_slab::<u32>(SIBLING_RING_SLAB, n, allocator);
    SIBLING_RING_STORAGE.store(ring, Ordering::Relaxed);
}

/// Record the core key of the calling CPU, logical CPU `cpu`, in its slot.
///
/// # Safety
/// Runs on CPU `cpu`, which is below `CPU_COUNT`, once, after
/// [`init_storage`] and before the boot CPU's [`build_sibling_rings`]: on an
/// AP, before its `APS_READY` increment, whose Release the boot CPU's Acquire
/// wait pairs with.
#[cfg(not(test))]
pub unsafe fn record_this_cpu(cpu: u32)
{
    let base = CORE_SLOTS_PTR.load(Ordering::Acquire);
    debug_assert!(
        !base.is_null(),
        "record_this_cpu: CORE_SLOTS slab not allocated"
    );
    let slot = CoreSlot {
        key: crate::arch::current::cpu::core_key(cpu),
        cpu,
    };
    // SAFETY: cpu < CPU_COUNT and the slab holds CPU_COUNT entries (caller
    // contract), so the offset stays inside it.
    let entry = unsafe { base.add(cpu as usize) };
    // SAFETY: `entry` is this CPU's own slot, written only here, and the boot
    // CPU reads it only after the ordering the contract names.
    unsafe { entry.write(slot) };
}

/// Link each core's CPUs into a ring from every CPU's recorded key and publish
/// it, returning what it holds. Halts by name when a CPU's slot is missing or
/// recorded twice.
///
/// # Safety
/// The boot CPU, once, with `cpu_count` equal to `CPU_COUNT`, after every
/// CPU's [`record_this_cpu`] is ordered before this call (its own by program
/// order, each AP's through the Acquire wait on `APS_READY`), and with no
/// CPU recording after it.
#[cfg(not(test))]
pub unsafe fn build_sibling_rings(cpu_count: usize) -> RingSummary
{
    let slots_base = CORE_SLOTS_PTR.load(Ordering::Acquire);
    let ring_base = SIBLING_RING_STORAGE.load(Ordering::Relaxed);
    if slots_base.is_null() || ring_base.is_null()
    {
        crate::fatal("topology: core-key or sibling-ring slab not allocated");
    }
    // SAFETY: the slab holds cpu_count entries (caller contract), every write
    // to it is ordered before this call and none follows, so this is the only
    // reference.
    let slots = unsafe { core::slice::from_raw_parts_mut(slots_base, cpu_count) };
    // SAFETY: the slab holds cpu_count entries and is reached only here until
    // it is published below.
    let ring = unsafe { core::slice::from_raw_parts_mut(ring_base, cpu_count) };
    let Some(summary) = link_sibling_rings(slots, ring)
    else
    {
        crate::fatal("topology: a CPU's core key is missing or recorded twice");
    };
    SIBLING_RING_PTR.store(ring_base, Ordering::Release);
    summary
}

/// The published sibling ring, or an empty slice before [`build_sibling_rings`]
/// publishes it.
fn ring() -> &'static [u32]
{
    let base = SIBLING_RING_PTR.load(Ordering::Acquire);
    if base.is_null()
    {
        return &[];
    }
    let len = crate::sched::CPU_COUNT.load(Ordering::Relaxed) as usize;
    // SAFETY: the published slab holds CPU_COUNT entries, every one written
    // before the Release that published it, and nothing writes it after.
    unsafe { core::slice::from_raw_parts(base, len) }
}

/// The CPU after `cpu` in its core's ring (ascending index order, wrapping):
/// `cpu` itself when its core has no other CPU, when `cpu` is out of range,
/// or before the ring is published.
pub fn sibling_after(cpu: usize) -> usize
{
    ring().get(cpu).map_or(cpu, |&next| next as usize)
}

/// The number of `cpu`'s siblings, the other CPUs of its core, for which
/// `busy` holds: 0 when it has none or before the ring is published.
pub fn busy_siblings(cpu: usize, busy: impl Fn(usize) -> bool) -> u32
{
    siblings_where(ring(), cpu, busy)
}

/// Sort `slots` and link each core's CPUs, in ascending index order, into a
/// ring in `ring` (each CPU's entry the index of the next, the last's the
/// first's). `None` when the two lengths differ, or when a slot names a CPU
/// out of range or one already linked: with as many slots as entries, that
/// covers a slot left unrecorded, whose zero fill repeats CPU 0.
fn link_sibling_rings(slots: &mut [CoreSlot], ring: &mut [u32]) -> Option<RingSummary>
{
    if slots.len() != ring.len()
    {
        return None;
    }
    ring.fill(UNLINKED);
    slots.sort_unstable();
    let mut summary = RingSummary {
        cores: 0,
        max_threads: 0,
    };
    for core in slots.chunk_by(|a, b| a.key == b.key)
    {
        let first = core.first()?;
        let nexts = core.iter().skip(1).chain(core::iter::once(first));
        for (slot, next) in core.iter().zip(nexts)
        {
            let link = ring.get_mut(slot.cpu as usize)?;
            if *link != UNLINKED
            {
                return None;
            }
            *link = next.cpu;
        }
        summary.cores = summary.cores.saturating_add(1);
        summary.max_threads = summary.max_threads.max(core.len());
    }
    Some(summary)
}

/// The number of CPUs after `cpu` in its ring in `ring`, up to `cpu` again,
/// for which `pred` holds. The walk takes at most `ring.len()` steps and
/// stops before an index out of range, so a malformed ring can neither loop it
/// nor hand `pred` a CPU past the ring.
fn siblings_where(ring: &[u32], cpu: usize, pred: impl Fn(usize) -> bool) -> u32
{
    let mut count = 0u32;
    let mut at = cpu;
    for _ in 0..ring.len()
    {
        let Some(&next) = ring.get(at)
        else
        {
            break;
        };
        let next = next as usize;
        if next == cpu || next >= ring.len()
        {
            break;
        }
        if pred(next)
        {
            count = count.saturating_add(1);
        }
        at = next;
    }
    count
}

#[cfg(test)]
mod tests
{
    use super::{CoreSlot, RingSummary, UNLINKED, link_sibling_rings, siblings_where};

    fn slots(keys: &[u32]) -> Vec<CoreSlot>
    {
        (0u32..)
            .zip(keys)
            .map(|(cpu, &key)| CoreSlot { key, cpu })
            .collect()
    }

    // Defect guarded: siblings left out of each other's ring, or CPUs of two
    // cores linked into one, so the placement tie-break counts the wrong CPUs.
    #[test]
    fn each_core_is_one_ascending_ring()
    {
        // CPUs 0 and 4 share core 7, 1 and 2 share core 3, 3 is alone; the
        // keys arrive in CPU order, unsorted.
        let mut s = slots(&[7, 3, 3, 9, 7]);
        let mut ring = [0u32; 5];
        let summary = link_sibling_rings(&mut s, &mut ring);
        assert_eq!(
            summary,
            Some(RingSummary {
                cores: 3,
                max_threads: 2
            })
        );
        assert_eq!(ring, [4, 2, 1, 3, 0]);
    }

    // Defect guarded: a core of more than two threads linked out of index
    // order or not closed back to its first CPU.
    #[test]
    fn a_four_thread_core_wraps_to_its_lowest_cpu()
    {
        let mut s = slots(&[1, 1, 1, 1]);
        let mut ring = [0u32; 4];
        assert!(link_sibling_rings(&mut s, &mut ring).is_some());
        assert_eq!(ring, [1, 2, 3, 0]);
    }

    // Defect guarded: a CPU that never recorded its key (its zero-filled slot
    // repeats CPU 0), or one recorded twice, linked silently into a ring.
    #[test]
    fn a_missing_or_repeated_cpu_is_refused()
    {
        let mut ring = [0u32; 3];
        let mut unrecorded = vec![
            CoreSlot { key: 5, cpu: 0 },
            CoreSlot { key: 0, cpu: 0 },
            CoreSlot { key: 6, cpu: 2 },
        ];
        assert_eq!(link_sibling_rings(&mut unrecorded, &mut ring), None);
        let mut out_of_range = slots(&[1, 1]);
        out_of_range.push(CoreSlot { key: 2, cpu: 3 });
        assert_eq!(link_sibling_rings(&mut out_of_range, &mut ring), None);
        let mut short = slots(&[1, 1]);
        assert_eq!(link_sibling_rings(&mut short, &mut ring), None);
    }

    // Defect guarded: a CPU counted as its own sibling, or a walk that does
    // not stop on a malformed ring.
    #[test]
    fn siblings_where_counts_the_others_only()
    {
        let ring = [4, 2, 1, 3, 0];
        assert_eq!(siblings_where(&ring, 0, |_| true), 1);
        assert_eq!(siblings_where(&ring, 3, |_| true), 0);
        assert_eq!(siblings_where(&ring, 1, |cpu| cpu == 2), 1);
        assert_eq!(siblings_where(&ring, 1, |cpu| cpu != 2), 0);
        // A ring that never returns to CPU 0 (1 -> 2 -> 1) ends after the
        // walk's bound instead of looping, and one past the end stops.
        let open = [1, 2, 1];
        assert!(siblings_where(&open, 0, |_| true) <= 3);
        assert_eq!(siblings_where(&[UNLINKED], 0, |_| true), 0);
        assert_eq!(siblings_where(&[], 0, |_| true), 0);
    }
}
