// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/firmware/src/property/cpus.rs

//! The CPU-ID placement's contract: the BSP first, every other distinct ID
//! once in list order, and truncation exactly when the distinct IDs outnumber
//! the slots.

use boot_protocol::MAX_CPUS;

use crate::cpus::{cpu_id_capacity, place_cpu_ids, record_cpu_id};

/// Slots the check gives the placement at most.
const MAX_SLOTS: usize = 8;

/// Check the placement on `input`, read as a slot count (its first byte,
/// modulo 9), the BSP's ID and the listed IDs (little-endian `u16`s).
///
/// # Panics
///
/// When the placement breaks its contract.
pub(crate) fn cpus_holds(input: &[u8])
{
    let Some((&slots, rest)) = input.split_first()
    else
    {
        return;
    };
    let ids = rest.as_chunks::<2>().0;
    let Some((bsp, list)) = ids.split_first()
    else
    {
        return;
    };
    let bsp = u32::from(u16::from_le_bytes(*bsp));
    let list = list.iter().map(|c| u32::from(u16::from_le_bytes(*c)));
    let slots = usize::from(slots) % (MAX_SLOTS + 1);
    let mut out = [0u32; MAX_SLOTS];
    place_holds(bsp, &list, out.get_mut(..slots).unwrap_or_default());
    // The records the placement makes, one by one.
    let mut ids = [0u32; MAX_SLOTS];
    let ids = ids.get_mut(..slots).unwrap_or_default();
    let mut count = 0;
    for id in core::iter::once(bsp).chain(list)
    {
        count = record_holds(id, ids, count);
    }
    capacity_holds(rest.len());
}

/// Check one record of `id` into `ids[..count]`, `ids` of at most
/// [`MAX_SLOTS`] slots.
///
/// # Panics
///
/// When the record breaks its contract.
pub(crate) fn record_holds(id: u32, ids: &mut [u32], count: usize) -> usize
{
    assert!(ids.len() <= MAX_SLOTS, "the check's own bound");
    let before_ids = {
        let mut copy = [0u32; MAX_SLOTS];
        for (c, i) in copy.iter_mut().zip(ids.iter())
        {
            *c = *i;
        }
        copy
    };
    let mut after = count;
    let mut truncated = false;
    record_cpu_id(id, ids, &mut after, &mut truncated);
    // An ID is already placed when one of the first `count` slots holds it; a
    // count past the slots places none.
    let placed = count <= ids.len() && (0..count).any(|i| before_ids.get(i) == Some(&id));
    if placed
    {
        assert_eq!((after, truncated), (count, false));
    }
    else if count < ids.len()
    {
        assert_eq!((after, truncated), (count.saturating_add(1), false));
        assert_eq!(ids.get(count), Some(&id));
    }
    else
    {
        assert_eq!(after, count);
        assert!(truncated);
    }
    // No slot but the one written changes.
    for (i, (now, was)) in ids.iter().zip(before_ids.iter()).enumerate()
    {
        assert!(now == was || i == count);
    }
    after
}

/// Check the placement of `bsp` and `list` into `out`.
///
/// # Panics
///
/// When the placement breaks its contract.
pub(crate) fn place_holds(bsp: u32, list: &(impl Iterator<Item = u32> + Clone), out: &mut [u32])
{
    let (count, truncated) = place_cpu_ids(bsp, list.clone(), out);
    let count = count as usize;
    assert!(count <= out.len());
    let placed = out.get(..count).unwrap_or_default();
    if let Some(&first) = placed.first()
    {
        assert_eq!(first, bsp);
    }
    // Each placed ID is distinct, and placed in order of first appearance.
    for (i, a) in placed.iter().enumerate()
    {
        assert!(!placed.iter().skip(i.saturating_add(1)).any(|b| b == a));
    }
    let mut distinct = 0usize;
    for (i, id) in core::iter::once(bsp).chain(list.clone()).enumerate()
    {
        let first = !core::iter::once(bsp)
            .chain(list.clone())
            .take(i)
            .any(|x| x == id);
        if first
        {
            match placed.get(distinct)
            {
                Some(&p) => assert_eq!(p, id),
                None => assert!(truncated),
            }
            distinct = distinct.saturating_add(1);
        }
    }
    assert_eq!(truncated, distinct > out.len());
    assert_eq!(count, distinct.min(out.len()));
}

/// Check the slots a table of `entries` CPUs is given.
///
/// # Panics
///
/// When the capacity breaks its contract.
pub(crate) fn capacity_holds(entries: usize)
{
    let cap = cpu_id_capacity(entries);
    assert!((1..=MAX_CPUS).contains(&cap));
    assert_eq!(
        cap,
        if entries >= MAX_CPUS
        {
            MAX_CPUS
        }
        else
        {
            entries.saturating_add(1)
        }
    );
}
