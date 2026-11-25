// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/property.rs

//! The contract of the decoders of what a `VirtIO` device writes for its
//! driver to read, as one property over any input, [`virtio_core_holds`],
//! which the fuzz target `virtio-core` (`xtask/fuzz/targets`) drives and the
//! replay test of the checked-in inputs under `fuzz/virtio-core/` runs on
//! every `cargo xtask test`; the `proofs` modules of `virtqueue.rs` and
//! `pci.rs` prove its checks of each step on every input up to their bounds
//! (docs/testing.md § Fuzzing, § Bounded verification).
//!
//! The input is read two ways. As the script of a split virtqueue's life
//! ([`queue_script`]), run on a [`SplitVirtqueue`] over host memory that
//! stands in for its rings, in which the driver submits chains and polls and
//! the device writes whatever the script says into the used ring, its index,
//! the descriptor table and the available index. Each poll is judged against
//! a model of the outstanding chains kept apart from the queue's bookkeeping
//! and read from `VirtIO` 1.2 § 2.7: the chains the descriptor table holds
//! as the driver wrote them, and the used ring as the device wrote it. And as
//! the operands of a configuration read ([`config_holds`]): a register
//! window, a device configuration region and a word offset in it, and the
//! successive reads of a 64-bit field with the generation around each.

use alloc::vec;
use alloc::vec::Vec;

use crate::pci::{self, CONFIG_READ_ATTEMPTS, ConfigError};
use crate::virtqueue::{
    self, Chains, MAX_QUEUE_SIZE, Reserved, SplitVirtqueue, VRING_DESC_F_NEXT, VRING_DESC_F_WRITE,
    VirtqAvail, VirtqDesc, VirtqUsed, VirtqUsedElem, VirtqueueError,
};

/// Check the contract of every decoder of device-written memory on `input`.
///
/// # Panics
///
/// When a decoder breaks its contract on `input`: a defect of the decoder.
pub fn virtio_core_holds(input: &[u8])
{
    let _ = queue_script(input);
    config_holds(input);
}

// ── Readings ────────────────────────────────────────────────────────────────

/// The `N` bytes of `bytes` at `at`, when they lie wholly inside it.
fn bytes_at<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]>
{
    let end = at.checked_add(N)?;
    bytes.get(at..end)?.try_into().ok()
}

/// The little-endian `u16` of `bytes` at `at`.
fn le16(bytes: &[u8], at: usize) -> Option<u16>
{
    bytes_at(bytes, at).map(u16::from_le_bytes)
}

/// The little-endian `u32` of `bytes` at `at`.
fn le32(bytes: &[u8], at: usize) -> Option<u32>
{
    bytes_at(bytes, at).map(u32::from_le_bytes)
}

/// The little-endian `u64` of `bytes` at `at`.
fn le64(bytes: &[u8], at: usize) -> Option<u64>
{
    bytes_at(bytes, at).map(u64::from_le_bytes)
}

// ── The bookkeeping ─────────────────────────────────────────────────────────

/// Which descriptors the free list of `chains` holds, indexed by
/// descriptor: `num_free` of them from `free_head` along the links, each
/// below the queue size and none twice. `None` when the list is not of that
/// form.
fn free_set(chains: &Chains) -> Option<Vec<bool>>
{
    let mut free = vec![false; usize::from(chains.queue_size)];
    let mut idx = chains.free_head;
    for step in 0..chains.num_free
    {
        let seen = free.get_mut(usize::from(idx))?;
        if *seen
        {
            return None;
        }
        *seen = true;
        if step.saturating_add(1) < chains.num_free
        {
            idx = *chains.links.get(usize::from(idx))?;
        }
    }
    Some(free)
}

/// Mark in `seen` the descriptors of the chain at `head`, `len` of them
/// along the links of `chains`: whether each is below the queue size and
/// none was marked before.
fn mark_chain(chains: &Chains, head: u16, len: u16, seen: &mut [bool]) -> bool
{
    let mut idx = head;
    for step in 0..len
    {
        match seen.get_mut(usize::from(idx))
        {
            Some(slot) if !*slot => *slot = true,
            _ => return false,
        }
        if step.saturating_add(1) < len
        {
            let Some(&next) = chains.links.get(usize::from(idx))
            else
            {
                return false;
            };
            idx = next;
        }
    }
    true
}

/// Whether `chains` holds the invariant [`Chains`] states: a queue size that
/// is a power of two of at most [`MAX_QUEUE_SIZE`], with its mask and a
/// table entry of each kind per descriptor; a free list and outstanding
/// chains that visit every descriptor exactly once between them; as many
/// chains as `outstanding` counts; and `writable` 0 at every index that
/// heads none.
pub(crate) fn invariant(chains: &Chains) -> bool
{
    let size = usize::from(chains.queue_size);
    if !chains.queue_size.is_power_of_two()
        || chains.queue_size > MAX_QUEUE_SIZE
        || chains.ring_mask != chains.queue_size.wrapping_sub(1)
        || chains.links.len() != size
        || chains.chain_len.len() != size
        || chains.writable.len() != size
    {
        return false;
    }
    let Some(mut seen) = free_set(chains)
    else
    {
        return false;
    };
    let mut count = 0u16;
    for (head, (&len, &writable)) in
        (0..chains.queue_size).zip(chains.chain_len.iter().zip(&chains.writable))
    {
        if len == 0
        {
            if writable != 0
            {
                return false;
            }
            continue;
        }
        count = count.saturating_add(1);
        if !mark_chain(chains, head, len, &mut seen)
        {
            return false;
        }
    }
    seen.iter().all(|&s| s) && count == chains.outstanding
}

/// Whether `a` and `b` hold the same bookkeeping, field by field (the
/// tables compared entry by entry).
fn same(a: &Chains, b: &Chains) -> bool
{
    a.queue_size == b.queue_size
        && a.ring_mask == b.ring_mask
        && a.free_head == b.free_head
        && a.num_free == b.num_free
        && a.outstanding == b.outstanding
        && a.avail_idx == b.avail_idx
        && a.last_used_idx == b.last_used_idx
        && a.links.iter().eq(&b.links)
        && a.chain_len.iter().eq(&b.chain_len)
        && a.writable.iter().eq(&b.writable)
}

/// The recorded length of the chain at `head` in `chains`: 0 when it heads
/// none.
fn len_at(chains: &Chains, head: u16) -> u16
{
    chains
        .chain_len
        .get(usize::from(head))
        .copied()
        .unwrap_or(0)
}

/// [`Chains::new`] gives the bookkeeping of a queue of any size that is a
/// power of two of at most [`MAX_QUEUE_SIZE`], every descriptor free, no
/// chain outstanding and both indices at 0, and refuses every other size.
pub(crate) fn new_holds(queue_size: u16)
{
    let chains = Chains::new(queue_size);
    let valid = queue_size.is_power_of_two() && queue_size <= MAX_QUEUE_SIZE;
    assert_eq!(chains.is_some(), valid, "a queue size judged otherwise");
    if let Some(chains) = chains
    {
        assert!(
            invariant(&chains)
                && chains.num_free == queue_size
                && chains.outstanding == 0
                && chains.avail_idx == 0
                && chains.last_used_idx == 0,
            "new bookkeeping not empty"
        );
    }
}

/// [`Chains::reserve`] on `chains`, which holds the invariant, refuses
/// `bufs` when it is empty or longer than the free descriptors, changing
/// nothing; and otherwise records one chain of free descriptors, one per
/// buffer, as outstanding with the saturating sum of its device-writable
/// buffers' lengths, publishes it at the next available slot and index, and
/// leaves every other chain and the used index as they were, keeping the
/// invariant. Returns what it reserved.
pub(crate) fn reserve_holds(chains: &mut Chains, bufs: &[(u64, u32, bool)]) -> Option<Reserved>
{
    let before = chains.clone();
    let reserved = chains.reserve(bufs);
    if bufs.is_empty() || usize::from(before.num_free) < bufs.len()
    {
        assert!(
            reserved.is_none() && same(chains, &before),
            "a chain past the free descriptors taken"
        );
        return None;
    }
    assert!(
        reserved.is_some(),
        "a chain the free descriptors hold refused"
    );
    let reserved = reserved?;
    let len = u16::try_from(bufs.len()).unwrap_or(0);
    let writable = bufs
        .iter()
        .filter(|&&(_, _, device_writable)| device_writable)
        .fold(0u32, |sum, &(_, len, _)| sum.saturating_add(len));
    // The chain's descriptors, marked over the free list as it was: each one
    // free before, and none twice.
    let mut free = free_set(&before).unwrap_or_default();
    let mut taken = 0usize;
    for idx in chains.chain(reserved.head)
    {
        let was_free = free
            .get_mut(usize::from(idx))
            .is_some_and(|f| core::mem::replace(f, false));
        assert!(was_free, "a chain not of distinct free descriptors");
        taken = taken.saturating_add(1);
    }
    assert!(
        taken == bufs.len()
            && reserved.slot == before.avail_idx & before.ring_mask
            && reserved.avail_idx == before.avail_idx.wrapping_add(1)
            && chains.avail_idx == reserved.avail_idx
            && len_at(chains, reserved.head) == len
            && chains.writable.get(usize::from(reserved.head)) == Some(&writable)
            && chains.outstanding == before.outstanding.saturating_add(1)
            && chains.num_free == before.num_free.saturating_sub(len)
            && chains.last_used_idx == before.last_used_idx,
        "a chain recorded otherwise"
    );
    others_kept(&before, chains, reserved.head);
    assert!(invariant(chains), "the invariant broken by a reserve");
    Some(reserved)
}

/// Every outstanding chain of `before` but the one at `except` is in
/// `after` as it was: its length, its descriptors and its recorded bytes.
fn others_kept(before: &Chains, after: &Chains, except: u16)
{
    for head in 0..before.queue_size
    {
        let len = len_at(before, head);
        if len == 0 || head == except
        {
            continue;
        }
        assert!(
            len_at(after, head) == len
                && after.writable.get(usize::from(head)) == before.writable.get(usize::from(head))
                && before.chain(head).eq(after.chain(head)),
            "another chain changed"
        );
    }
}

/// What [`Chains::take_used`] makes of a used ring whose index is `used_idx`
/// and whose element at the slot after the last consumed is `elem`, read
/// from `VirtIO` 1.2 § 2.7.8 against the chains `before` holds outstanding
/// (by the invariant, the indices with a non-zero chain length, as many as
/// `outstanding` counts): nothing new when the index is the last consumed;
/// a refusal when it publishes more elements, modulo 2^16, than chains are
/// outstanding; and otherwise the element judged: its `id` the head of an
/// outstanding chain, and its `len` given, clamped to the bytes of that
/// chain's device-writable buffers. The script's model
/// ([`queue_script`]) reads the same outcomes from the chains the
/// descriptor table holds, apart from this bookkeeping.
fn used_reading(
    before: &Chains,
    used_idx: u16,
    elem: VirtqUsedElem,
) -> Result<Option<(u16, u32)>, VirtqueueError>
{
    let pending = used_idx.wrapping_sub(before.last_used_idx);
    if pending == 0
    {
        return Ok(None);
    }
    if pending > before.outstanding
    {
        return Err(VirtqueueError::IndexPastOutstanding { used_idx });
    }
    let Some(head) =
        (0..before.queue_size).find(|&h| u32::from(h) == elem.id && len_at(before, h) != 0)
    else
    {
        return Err(VirtqueueError::UnknownHead { id: elem.id });
    };
    let writable = before.writable.get(usize::from(head)).copied().unwrap_or(0);
    Ok(Some((head, elem.len.min(writable))))
}

/// [`Chains::take_used`] on `chains`, which holds the invariant, with the
/// used index `used_idx` and the element `elem` at the next slot: gives
/// what its reading ([`used_reading`]) gives; reads the element once, at the
/// slot after the last consumed, exactly when it consumes one; moves the
/// last consumed index past what it consumed; frees the descriptors of a
/// completed chain and nothing else, and on any other outcome changes
/// nothing but that index; and keeps the invariant. Returns the outcome.
#[expect(
    clippy::panic_in_result_fn,
    reason = "a check panics on a defect of the decoder by design; its Result is the outcome it \
              judged, which the script hands on"
)]
pub(crate) fn used_holds(
    chains: &mut Chains,
    used_idx: u16,
    elem: VirtqUsedElem,
) -> Result<Option<(u16, u32)>, VirtqueueError>
{
    let before = chains.clone();
    let expected = used_reading(&before, used_idx, elem);
    let mut read_at = None;
    let mut reads = 0u32;
    let taken = chains.take_used(used_idx, |slot| {
        reads = reads.saturating_add(1);
        read_at = Some(slot);
        elem
    });
    assert_eq!(taken, expected, "a used element judged otherwise");
    let consumed_one = matches!(
        expected,
        Ok(Some(_)) | Err(VirtqueueError::UnknownHead { .. })
    );
    let next_slot = before.last_used_idx & before.ring_mask;
    assert!(
        reads <= 1 && (read_at == Some(next_slot)) == consumed_one,
        "the used element read otherwise"
    );
    let last = match expected
    {
        Ok(None) => before.last_used_idx,
        Err(VirtqueueError::IndexPastOutstanding { .. }) => used_idx,
        Ok(Some(_)) | Err(VirtqueueError::UnknownHead { .. }) =>
        {
            before.last_used_idx.wrapping_add(1)
        }
    };
    assert_eq!(
        chains.last_used_idx, last,
        "the used index consumed otherwise"
    );
    if let Ok(Some((head, _))) = expected
    {
        let len = len_at(&before, head);
        let free = free_set(chains).unwrap_or_default();
        assert!(
            len_at(chains, head) == 0
                && chains.outstanding == before.outstanding.saturating_sub(1)
                && chains.num_free == before.num_free.saturating_add(len)
                && before
                    .chain(head)
                    .all(|idx| free.get(usize::from(idx)) == Some(&true))
                && chains.avail_idx == before.avail_idx,
            "a completed chain freed otherwise"
        );
        others_kept(&before, chains, head);
    }
    else
    {
        let mut unchanged = before;
        unchanged.last_used_idx = last;
        assert!(
            same(chains, &unchanged),
            "a refusal changed the bookkeeping"
        );
    }
    assert!(invariant(chains), "the invariant broken by a poll");
    taken
}

// ── The script ──────────────────────────────────────────────────────────────

/// The outcomes a script reached, for the replay test's check that the seeds
/// reach each one.
#[derive(Clone, Copy, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "a tally of outcomes each reached or not, independent of the others; no state \
              machine hides in them"
)]
pub(crate) struct Outcomes
{
    /// A completion taken.
    pub(crate) completed: bool,
    /// A completion taken at index 65535, the last before the wrap.
    pub(crate) wrapped: bool,
    /// A completion whose `len` was past its chain's writable bytes, taken
    /// clamped.
    pub(crate) clamped: bool,
    /// Each refusal of a poll.
    pub(crate) index_past: bool,
    pub(crate) unknown_head: bool,
    /// A chain refused for want of free descriptors (not for being empty).
    pub(crate) add_refused: bool,
}

/// Host memory standing in for a queue's rings: the descriptor table, the
/// available ring (flags, index, entries), and the used ring as 32-bit words
/// (flags and index in the first, then each element's `id` and `len`).
struct Rings
{
    desc: Vec<VirtqDesc>,
    avail: Vec<u16>,
    used: Vec<u32>,
}

impl Rings
{
    fn new(queue_size: u16) -> Self
    {
        Self {
            desc: vec![VirtqDesc::default(); usize::from(queue_size)],
            avail: vec![0; virtqueue::avail_ring_size(queue_size).div_ceil(2)],
            used: vec![0; virtqueue::used_ring_size(queue_size).div_ceil(4)],
        }
    }

    /// The available ring's `idx` field.
    fn avail_idx(&self) -> u16
    {
        self.avail.get(1).copied().unwrap_or(0)
    }

    /// The available ring's entry at `slot`.
    fn avail_entry(&self, slot: u16) -> u16
    {
        self.avail
            .get(usize::from(slot).saturating_add(2))
            .copied()
            .unwrap_or(0)
    }

    /// The device writing the available ring's `idx` field.
    fn set_avail_idx(&mut self, idx: u16)
    {
        if let Some(word) = self.avail.get_mut(1)
        {
            *word = idx;
        }
    }

    /// The device writing the used ring's `idx` field, the second half of
    /// its first word.
    fn set_used_idx(&mut self, idx: u16)
    {
        if let Some(word) = self.used.first_mut()
        {
            let [flags_0, flags_1, _, _] = word.to_ne_bytes();
            let [idx_0, idx_1] = idx.to_ne_bytes();
            *word = u32::from_ne_bytes([flags_0, flags_1, idx_0, idx_1]);
        }
    }

    /// The device writing `elem` at used-ring slot `slot`.
    fn set_used_elem(&mut self, slot: u16, elem: VirtqUsedElem)
    {
        let at = usize::from(slot).saturating_mul(2).saturating_add(1);
        if let Some(words) = self.used.get_mut(at..at.saturating_add(2))
        {
            words.copy_from_slice(&[elem.id, elem.len]);
        }
    }

    /// The used-ring element at `slot`, as the device last wrote it.
    fn used_elem(&self, slot: u16) -> VirtqUsedElem
    {
        let at = usize::from(slot).saturating_mul(2).saturating_add(1);
        VirtqUsedElem {
            id: self.used.get(at).copied().unwrap_or(0),
            len: self.used.get(at.saturating_add(1)).copied().unwrap_or(0),
        }
    }

    /// The chain the descriptor table holds from `head`, `len` descriptors
    /// along each one's `next` while it carries `VRING_DESC_F_NEXT`, as the
    /// device reads it: each descriptor's index and contents. `None` when it
    /// leaves the table or ends early.
    fn table_chain(&self, head: u16, len: usize) -> Option<Vec<(u16, VirtqDesc)>>
    {
        let mut chain = Vec::new();
        let mut idx = head;
        for step in 0..len
        {
            let desc = *self.desc.get(usize::from(idx))?;
            chain.push((idx, desc));
            let last = step.saturating_add(1) == len;
            if (desc.flags & VRING_DESC_F_NEXT != 0) == last
            {
                return None;
            }
            idx = desc.next;
        }
        Some(chain)
    }
}

/// The device's side of a script: what it last wrote as the used index, and
/// what the model holds outstanding (each chain's head, descriptors and
/// device-writable bytes, unsaturated).
struct Model
{
    used_idx: u16,
    consumed: u16,
    avail_idx: u16,
    chains: Vec<(u16, Vec<u16>, u64)>,
}

/// Run the script `input` holds on a [`SplitVirtqueue`] over host rings,
/// judging each operation as the module documentation says, and return the
/// outcomes it reached.
///
/// The script: byte 0 sets the queue size to 2 to the power of its value
/// modulo 8; bytes 1 and 2, little-endian, the index both rings start at;
/// then each operation, a byte whose value modulo 5 names it, and its
/// operands: 0, the driver submits a chain of as many buffers as the next
/// byte's value modulo 9, each a byte whose bit 0 makes it device-writable
/// and a little-endian `u32` length; 1, the device publishes an element, a
/// little-endian `u32` `id` and `len`, at its next used slot and moves the
/// used index past it; 2, the device writes the used index, a little-endian
/// `u16`; 3, the device writes a little-endian `u16` over the `next` and
/// `flags` of the descriptor it names modulo the queue size, and over the
/// available index; 4, the driver polls. The script ends where an
/// operation's bytes do.
///
/// # Panics
///
/// When the queue breaks its contract: a defect of the queue.
pub(crate) fn queue_script(input: &[u8]) -> Outcomes
{
    let mut outcomes = Outcomes::default();
    let (Some(&size_byte), Some(start)) = (input.first(), le16(input, 1))
    else
    {
        return outcomes;
    };
    let queue_size = 1u16.checked_shl(u32::from(size_byte % 8)).unwrap_or(1);
    new_holds(queue_size);
    let mut rings = Rings::new(queue_size);
    // SAFETY: the three buffers are zeroed, aligned to their element types
    // (16-byte descriptors in a `Vec<VirtqDesc>`, the available ring's u16
    // words, the used ring's u32 words), non-overlapping, sized by the
    // `VirtIO` 1.2 ring sizes, and outlive the queue, which this function
    // drops before them.
    let queue = unsafe {
        SplitVirtqueue::new(
            rings.desc.as_mut_ptr(),
            rings.avail.as_mut_ptr().cast::<VirtqAvail>(),
            rings.used.as_mut_ptr().cast::<VirtqUsed>(),
            queue_size,
        )
    };
    assert!(queue.is_some(), "a queue of a power-of-two size refused");
    let Some(mut queue) = queue
    else
    {
        return outcomes;
    };
    queue.chains.avail_idx = start;
    queue.chains.last_used_idx = start;
    rings.set_avail_idx(start);
    rings.set_used_idx(start);
    let mut model = Model {
        used_idx: start,
        consumed: start,
        avail_idx: start,
        chains: Vec::new(),
    };

    let mut at = 3usize;
    while let Some(&op) = input.get(at)
    {
        at = at.saturating_add(1);
        let Some(next) = (match op % 5
        {
            0 => add(input, at, &mut queue, &mut rings, &mut model, &mut outcomes),
            1 => publish(input, at, queue_size, &mut rings, &mut model),
            2 => le16(input, at).map(|idx| {
                rings.set_used_idx(idx);
                model.used_idx = idx;
                at.saturating_add(2)
            }),
            3 => le16(input, at).map(|value| {
                let slot = usize::from(value & queue_size.wrapping_sub(1));
                if let Some(desc) = rings.desc.get_mut(slot)
                {
                    desc.next = value;
                    desc.flags = value;
                }
                rings.set_avail_idx(value);
                at.saturating_add(2)
            }),
            _ =>
            {
                poll(&mut queue, &rings, &mut model, &mut outcomes);
                Some(at)
            }
        })
        else
        {
            break;
        };
        at = next;
        assert!(invariant(&queue.chains), "the invariant broken");
    }
    outcomes
}

/// The device's `publish` operation at `at`: returns where the next
/// operation starts.
fn publish(
    input: &[u8],
    at: usize,
    queue_size: u16,
    rings: &mut Rings,
    model: &mut Model,
) -> Option<usize>
{
    let elem = VirtqUsedElem {
        id: le32(input, at)?,
        len: le32(input, at.saturating_add(4))?,
    };
    rings.set_used_elem(model.used_idx & queue_size.wrapping_sub(1), elem);
    model.used_idx = model.used_idx.wrapping_add(1);
    rings.set_used_idx(model.used_idx);
    Some(at.saturating_add(8))
}

/// The driver's `add` operation at `at`: the chain its operands describe,
/// submitted, judged against the model and the step check; returns where the
/// next operation starts.
fn add(
    input: &[u8],
    at: usize,
    queue: &mut SplitVirtqueue,
    rings: &mut Rings,
    model: &mut Model,
    outcomes: &mut Outcomes,
) -> Option<usize>
{
    let count = usize::from(*input.get(at)? % 9);
    let mut bufs = Vec::new();
    let mut next = at.saturating_add(1);
    for n in 0..count
    {
        let flags = *input.get(next)?;
        let len = le32(input, next.saturating_add(1))?;
        // Each buffer at a device address of its own.
        let addr = u64::try_from(n)
            .unwrap_or(0)
            .saturating_add(1)
            .saturating_mul(0x1000);
        bufs.push((addr, len, flags & 1 != 0));
        next = next.saturating_add(5);
    }
    let in_chains: usize = model.chains.iter().map(|(_, descs, _)| descs.len()).sum();
    let free = usize::from(queue.queue_size()).saturating_sub(in_chains);
    let avail_before = rings.avail_idx();
    let mut step = queue.chains.clone();
    let reserved = reserve_holds(&mut step, &bufs);
    let head = queue.add_chain(&bufs);
    assert!(
        head == reserved.map(|r| r.head) && same(&queue.chains, &step),
        "add_chain decided otherwise than its bookkeeping"
    );
    let Some(head) = head
    else
    {
        assert!(
            (bufs.is_empty() || bufs.len() > free) && rings.avail_idx() == avail_before,
            "a chain refused with descriptors free, or published"
        );
        outcomes.add_refused |= !bufs.is_empty();
        return Some(next);
    };
    assert!(
        !bufs.is_empty() && bufs.len() <= free,
        "a chain past the free descriptors taken"
    );
    // The chain as the device reads it from the table: the buffers in order,
    // on descriptors no outstanding chain holds.
    let chain = rings.table_chain(head, bufs.len());
    assert!(chain.is_some(), "a published chain the table does not hold");
    let chain = chain?;
    for ((idx, desc), &(addr, len, writable)) in chain.iter().zip(&bufs)
    {
        let flags = if writable { VRING_DESC_F_WRITE } else { 0 };
        assert!(
            desc.addr == addr
                && desc.len == len
                && desc.flags & VRING_DESC_F_WRITE == flags
                && !model.chains.iter().any(|(_, descs, _)| descs.contains(idx)),
            "a chain written otherwise"
        );
    }
    let slot = model.avail_idx & queue.queue_size().wrapping_sub(1);
    model.avail_idx = model.avail_idx.wrapping_add(1);
    assert!(
        rings.avail_entry(slot) == head && rings.avail_idx() == model.avail_idx,
        "a chain published otherwise"
    );
    let writable = bufs
        .iter()
        .filter(|&&(_, _, w)| w)
        .map(|&(_, len, _)| u64::from(len))
        .sum();
    model
        .chains
        .push((head, chain.iter().map(|&(idx, _)| idx).collect(), writable));
    Some(next)
}

/// The driver's poll: judged against the model and the step check.
fn poll(queue: &mut SplitVirtqueue, rings: &Rings, model: &mut Model, outcomes: &mut Outcomes)
{
    let mask = queue.queue_size().wrapping_sub(1);
    let pending = model.used_idx.wrapping_sub(model.consumed);
    let elem = rings.used_elem(model.consumed & mask);
    let expected = if pending == 0
    {
        Ok(None)
    }
    else if usize::from(pending) > model.chains.len()
    {
        model.consumed = model.used_idx;
        Err(VirtqueueError::IndexPastOutstanding {
            used_idx: model.used_idx,
        })
    }
    else
    {
        let at_wrap = model.consumed == u16::MAX;
        model.consumed = model.consumed.wrapping_add(1);
        let found = model
            .chains
            .iter()
            .position(|(head, _, _)| u32::from(*head) == elem.id);
        match found.and_then(|n| Some((n, model.chains.get(n)?.0, model.chains.get(n)?.2)))
        {
            None => Err(VirtqueueError::UnknownHead { id: elem.id }),
            Some((n, head, writable)) =>
            {
                model.chains.swap_remove(n);
                outcomes.wrapped |= at_wrap;
                outcomes.clamped |= u64::from(elem.len) > writable;
                // At most elem.len, so it fits.
                let len = u32::try_from(writable.min(u64::from(elem.len))).unwrap_or(elem.len);
                Ok(Some((head, len)))
            }
        }
    };
    let mut step = queue.chains.clone();
    let decoded = used_holds(&mut step, model.used_idx, elem);
    let polled = queue.poll_used();
    assert!(
        polled == decoded && same(&queue.chains, &step),
        "poll_used decided otherwise than its bookkeeping"
    );
    assert_eq!(polled, expected, "a poll judged against the model");
    match polled
    {
        Ok(Some(_)) => outcomes.completed = true,
        Ok(None) =>
        {}
        Err(VirtqueueError::IndexPastOutstanding { .. }) => outcomes.index_past = true,
        Err(VirtqueueError::UnknownHead { .. }) => outcomes.unknown_head = true,
    }
}

// ── Configuration reads ─────────────────────────────────────────────────────

/// The configuration reads of `input`: a register window's address (bytes 0
/// to 7), the device region's window offset (8 to 15) and length (16 to 23)
/// and a word offset in it (24 to 27), each little-endian; then
/// [`CONFIG_READ_ATTEMPTS`] and one more reads of a 64-bit field from byte
/// 28, each a generation byte, the little-endian low and high words, and a
/// generation byte. A field past the input reads as 0.
pub(crate) fn config_holds(input: &[u8])
{
    config_word_holds(
        le64(input, 0).unwrap_or(0),
        le64(input, 8).unwrap_or(0),
        le64(input, 16).unwrap_or(0),
        le32(input, 24).unwrap_or(0),
    );
    settle_holds(&config_reads(input));
}

/// The reads of a 64-bit configuration field `input` holds from byte 28,
/// as [`config_holds`] reads them.
pub(crate) fn config_reads(input: &[u8])
-> [(u8, u32, u32, u8); CONFIG_READ_ATTEMPTS as usize + 1]
{
    let mut reads = [(0u8, 0u32, 0u32, 0u8); CONFIG_READ_ATTEMPTS as usize + 1];
    for (n, read) in reads.iter_mut().enumerate()
    {
        let at = n.saturating_mul(10).saturating_add(28);
        *read = (
            input.get(at).copied().unwrap_or(0),
            le32(input, at.saturating_add(1)).unwrap_or(0),
            le32(input, at.saturating_add(5)).unwrap_or(0),
            input.get(at.saturating_add(9)).copied().unwrap_or(0),
        );
    }
    reads
}

/// [`pci::config_word_addr`] gives the window address of the word at
/// `offset` exactly when its four bytes lie inside the region's
/// `device_len` at a multiple of 4 from its start and the address, the
/// window's plus the region's offset plus `offset` modulo 2^64, is a
/// multiple of 4.
pub(crate) fn config_word_holds(window_va: u64, device_off: u64, device_len: u64, offset: u32)
{
    let inside = offset % 4 == 0 && u64::from(offset).saturating_add(4) <= device_len;
    let addr = window_va
        .wrapping_add(device_off)
        .wrapping_add(u64::from(offset));
    assert_eq!(
        pci::config_word_addr(window_va, device_off, device_len, offset),
        (inside && addr % 4 == 0).then_some(addr),
        "a configuration word placed otherwise"
    );
}

/// [`pci::settle`] over `reads` (the reads a device answers in turn, the
/// last repeated past the end) takes the words of the first of the first
/// [`CONFIG_READ_ATTEMPTS`] whose generation bytes are equal, low word
/// first, after exactly the reads up to it; and with none, refuses as
/// unsettled after exactly [`CONFIG_READ_ATTEMPTS`] reads. Each read is
/// judged alone by [`pci::config_u64`] the same way.
pub(crate) fn settle_holds(reads: &[(u8, u32, u32, u8)])
{
    for &(before, lo, hi, after) in reads
    {
        assert_eq!(
            pci::config_u64(before, lo, hi, after),
            (before == after).then_some(u64::from(lo) | (u64::from(hi) << 32)),
            "a 64-bit field judged otherwise"
        );
    }
    let attempts = usize::try_from(CONFIG_READ_ATTEMPTS).unwrap_or(0);
    let first = reads
        .iter()
        .take(attempts)
        .position(|&(before, _, _, after)| before == after);
    let mut calls = 0usize;
    let settled = pci::settle(CONFIG_READ_ATTEMPTS, || {
        let read = reads
            .get(calls)
            .or_else(|| reads.last())
            .copied()
            .unwrap_or((0, 0, 0, 1));
        calls = calls.saturating_add(1);
        read
    });
    let expected = first
        .and_then(|n| reads.get(n))
        .map(|&(_, lo, hi, _)| u64::from(lo) | (u64::from(hi) << 32))
        .ok_or(ConfigError::Unsettled);
    assert_eq!(settled, expected, "a settled read judged otherwise");
    assert_eq!(
        calls,
        first.map_or(attempts, |n| n.saturating_add(1)),
        "a settled read made another number of reads"
    );
}
