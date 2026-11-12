// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/bootstrap.rs

//! Bootstrap IPC protocol — child-side and creator-side primitives.
//!
//! A child reaches its creator through `creator_endpoint_cap` (in
//! `process_abi::ProcessInfo`, beside the other caps the handover page
//! carries). The child calls [`request_round`] in a loop on that cap; the
//! creator serves each request with [`reply_round`] or [`reply_error`],
//! transferring up to `MSG_CAP_SLOTS_MAX` caps plus payload words per round.
//! When the creator sets the `done` flag, the child stops.
//!
//! Per-(creator, child-type) payload formats are defined in each child's
//! crate. Beside the generic protocol, this module owns one shared payload
//! codec, for caps that fill positional slots that may be absent:
//! [`pack_slots`] / [`unpack_slots`] for one round, and [`slot_rounds`] /
//! [`SlotAccumulator`] / [`request_slots`] for a slot list split over as
//! many rounds as it needs (the rounds svcmgr serves the children it
//! launches, and init's `CAPS` endowment of svcmgr).

// When this crate is compiled as a std dep via rustc-dep-of-std, the
// crate root is `no_core` and the usual prelude is not auto-imported.
// The crate-root `use core::prelude::rust_2024::*;` only covers the
// root module; submodules need their own import. Harmless no-op
// otherwise.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use crate::{IpcMessage, bootstrap_errors};
use syscall_abi::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

// ── Protocol labels ─────────────────────────────────────────────────────────

/// Child → creator: request the next batch of startup caps.
pub const REQUEST: u64 = 1;

/// Creator → child: caps delivered; more rounds pending.
pub const MORE: u64 = 0;

/// Creator → child: caps delivered; bootstrap complete.
pub const DONE: u64 = 1;

// ── Round data ──────────────────────────────────────────────────────────────

/// One round's worth of data delivered to a child.
///
/// Owns its payload: `data[..data_words]` is a stack-owned snapshot of the
/// data words delivered in this round. Subsequent IPC cannot clobber it.
pub struct BootstrapRound
{
    /// Capability handles of the received caps in the child's `CSpace`. Only
    /// the first `cap_count` entries are valid.
    pub caps: [u64; MSG_CAP_SLOTS_MAX],
    /// Number of valid handles in `caps`.
    pub cap_count: usize,
    /// Owned data words delivered with this round. Only the first
    /// `data_words` entries are valid.
    pub data: [u64; MSG_DATA_WORDS_MAX],
    /// Number of valid data words in `data`.
    pub data_words: usize,
    /// `true` when this is the final round.
    pub done: bool,
}

// ── Label packing ───────────────────────────────────────────────────────────

/// Pack a successful reply label: base (`MORE`/`DONE`) + cap count + data count.
/// Each field is 8 bits, which holds the base labels, `MSG_CAP_SLOTS_MAX`
/// and `MSG_DATA_WORDS_MAX`, so the widths bound no round.
#[must_use]
pub const fn pack_reply_label(done: bool, cap_count: usize, data_words: usize) -> u64
{
    let base = if done { DONE } else { MORE };
    base | ((cap_count as u64) << 8) | ((data_words as u64) << 16)
}

/// Extract the base label (`MORE`/`DONE` or error code) from a packed label.
#[must_use]
pub const fn unpack_base(label: u64) -> u64
{
    label & 0xFF
}

/// Extract cap count from a packed success label.
#[must_use]
pub const fn unpack_cap_count(label: u64) -> usize
{
    ((label >> 8) & 0xFF) as usize
}

/// Extract data word count from a packed success label.
#[must_use]
pub const fn unpack_data_words(label: u64) -> usize
{
    ((label >> 16) & 0xFF) as usize
}

// ── Positional slots ────────────────────────────────────────────────────────

/// A round's positional cap slots packed for the wire: the present caps in
/// slot order and the presence word naming the slot each fills.
///
/// The kernel refuses a message carrying a null cap slot, so a round whose
/// consumer reads its caps by position cannot carry an absent cap as `0`.
/// Such a round transfers [`PackedSlots::caps`] and carries
/// [`PackedSlots::presence`] in `data[0]`: bit `i` is set when slot `i`
/// holds a cap. The child spreads the caps back over their slots with
/// [`unpack_slots`].
pub struct PackedSlots
{
    caps: [u64; MSG_CAP_SLOTS_MAX],
    cap_count: usize,
    /// A `u64` mask covers every slot of a round, which carries at most
    /// `MSG_CAP_SLOTS_MAX` caps.
    presence: u64,
}

impl PackedSlots
{
    /// The caps the round transfers, in slot order, none of them `0`.
    #[must_use]
    pub fn caps(&self) -> &[u64]
    {
        // `pack_slots` keeps `cap_count <= MSG_CAP_SLOTS_MAX`, so `get` always
        // finds the range.
        self.caps.get(..self.cap_count).unwrap_or_default()
    }

    /// The presence word, carried in the round's `data[0]`.
    #[must_use]
    pub fn presence(&self) -> u64
    {
        self.presence
    }
}

/// Pack positional `slots`, where `0` marks an absent cap, into the caps a
/// round transfers and its presence word. Slots past `MSG_CAP_SLOTS_MAX`
/// are not packed; a longer slot list is split over rounds by
/// [`slot_rounds`].
#[must_use]
pub fn pack_slots(slots: &[u64]) -> PackedSlots
{
    let mut packed = PackedSlots {
        caps: [0; MSG_CAP_SLOTS_MAX],
        cap_count: 0,
        presence: 0,
    };
    let mut out = packed.caps.iter_mut();
    for (i, &cap) in slots.iter().take(MSG_CAP_SLOTS_MAX).enumerate()
    {
        // At most `MSG_CAP_SLOTS_MAX` slots are read, so `out` holds one
        // place for each present cap.
        if cap != 0
            && let Some(place) = out.next()
        {
            *place = cap;
            packed.cap_count = packed.cap_count.saturating_add(1);
            packed.presence |= 1 << i;
        }
    }
    packed
}

/// Spread a received round's caps over its positional slots by the presence
/// word in `data[0]`: slot `i` takes the next delivered cap when bit `i` is
/// set and is `0` otherwise.
///
/// # Errors
/// [`bootstrap_errors::INVALID`] when the round carries no presence word,
/// the word sets a bit at or above `MSG_CAP_SLOTS_MAX`, or it names a
/// different number of caps than the round delivered, or the round's
/// `cap_count` or `data_words` is past its array.
pub fn unpack_slots(round: &BootstrapRound) -> Result<[u64; MSG_CAP_SLOTS_MAX], u64>
{
    let (caps, presence) = round_slots(round).ok_or(bootstrap_errors::INVALID)?;
    spread_slots(caps, presence)
}

/// A round's delivered caps and the presence word in its `data[0]`; `None`
/// when it carries no data word, or its `cap_count` or `data_words` is past
/// its array.
fn round_slots(round: &BootstrapRound) -> Option<(&[u64], u64)>
{
    let caps = round.caps.get(..round.cap_count)?;
    let presence = *round.data.get(..round.data_words)?.first()?;
    Some((caps, presence))
}

/// Spread one round's delivered `caps` over its `MSG_CAP_SLOTS_MAX`
/// positional slots by `presence`: slot `i` takes the next cap when bit `i`
/// is set and is `0` otherwise. [`unpack_slots`] reads `presence` from
/// `data[0]`; a protocol that carries it in another word calls this
/// directly.
///
/// # Errors
/// [`bootstrap_errors::INVALID`] when `presence` sets a bit at or above
/// `MSG_CAP_SLOTS_MAX` or names a different number of caps than `caps`
/// holds.
pub fn spread_slots(caps: &[u64], presence: u64) -> Result<[u64; MSG_CAP_SLOTS_MAX], u64>
{
    if presence >> MSG_CAP_SLOTS_MAX != 0 || presence.count_ones() as usize != caps.len()
    {
        return Err(bootstrap_errors::INVALID);
    }
    let mut slots = [0u64; MSG_CAP_SLOTS_MAX];
    let mut next = caps.iter();
    for (i, slot) in slots.iter_mut().enumerate()
    {
        if presence & (1 << i) != 0
        {
            *slot = next.next().copied().ok_or(bootstrap_errors::INVALID)?;
        }
    }
    Ok(slots)
}

/// The number of rounds that carry `slot_count` positional slots: one per
/// `MSG_CAP_SLOTS_MAX`-slot window, and one empty round for no slots.
#[must_use]
pub const fn slot_round_count(slot_count: usize) -> usize
{
    if slot_count == 0
    {
        1
    }
    else
    {
        slot_count.div_ceil(MSG_CAP_SLOTS_MAX)
    }
}

/// Split positional `slots` (`0` marks an absent cap) over consecutive
/// rounds: round `k` packs the window `slots[k * MSG_CAP_SLOTS_MAX..]` of at
/// most `MSG_CAP_SLOTS_MAX` slots with [`pack_slots`], so its presence word
/// is relative to that window. Yields [`slot_round_count`] rounds; no slots
/// still yield one empty round. A child concatenates the rounds with
/// [`SlotAccumulator`].
pub fn slot_rounds(slots: &[u64]) -> impl Iterator<Item = PackedSlots> + '_
{
    let empty = slots.is_empty().then(|| pack_slots(&[]));
    empty
        .into_iter()
        .chain(slots.chunks(MSG_CAP_SLOTS_MAX).map(pack_slots))
}

/// Concatenates the windows of consecutive slot rounds (see
/// [`slot_rounds`]) into `N` positional slots: the `k`-th pushed round fills
/// slots `k * MSG_CAP_SLOTS_MAX` onwards. A slot no round filled is `0`.
pub struct SlotAccumulator<const N: usize>
{
    slots: [u64; N],
    rounds: usize,
}

impl<const N: usize> Default for SlotAccumulator<N>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<const N: usize> SlotAccumulator<N>
{
    /// An accumulator with no round pushed and every slot `0`.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            slots: [0; N],
            rounds: 0,
        }
    }

    /// Add the next round's window from its delivered `caps` and its
    /// `presence` word. A present cap whose slot lies at or past `N` is
    /// handed to `overflow`, so the caller can release a cap it has no slot
    /// for instead of leaking it.
    ///
    /// # Errors
    /// [`bootstrap_errors::INVALID`] when the window does not decode (see
    /// [`spread_slots`]); nothing is recorded and no cap reaches
    /// `overflow`, so every cap of that round is still the caller's.
    pub fn push(
        &mut self,
        caps: &[u64],
        presence: u64,
        mut overflow: impl FnMut(u64),
    ) -> Result<(), u64>
    {
        let window = spread_slots(caps, presence)?;
        let base = self.rounds.saturating_mul(MSG_CAP_SLOTS_MAX);
        for (i, &cap) in window.iter().enumerate()
        {
            if cap == 0
            {
                continue;
            }
            match self.slots.get_mut(base.saturating_add(i))
            {
                Some(slot) => *slot = cap,
                None => overflow(cap),
            }
        }
        // A saturated count puts every later cap past `N`, to `overflow`.
        self.rounds = self.rounds.saturating_add(1);
        Ok(())
    }

    /// The slots filled so far.
    #[must_use]
    pub fn slots(&self) -> &[u64; N]
    {
        &self.slots
    }
}

// ── Child side ──────────────────────────────────────────────────────────────

/// Request the next bootstrap round from the creator.
///
/// Blocks until the creator replies. On a `MORE`/`DONE` reply, returns a
/// [`BootstrapRound`] whose `caps` and `data` fields are stack-owned copies
/// of the received payload — the per-thread IPC buffer is scratch after
/// return and nested IPC cannot clobber the round.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// * `Err(code)` with the low byte of any reply label other than
///   [`MORE`] / [`DONE`]: the creator's [`bootstrap_errors::NO_CHILD`],
///   [`bootstrap_errors::EXHAUSTED`], or [`bootstrap_errors::INVALID`], or
///   `0xFF` when the kernel's reply-cap transfer failed
///   (`IPC_REPLY_TRANSFER_FAILED`). Any caps such a reply delivered are
///   deleted.
/// * `Err(bootstrap_errors::INVALID)` if the underlying IPC fails, or if
///   the reply's label disagrees with its payload: the delivered cap count
///   differs from the count the label declares, or the label declares more
///   data words than a message carries. The caps such a reply delivered
///   are deleted.
pub unsafe fn request_round(creator_ep: u64, ipc_buf: *mut u64) -> Result<BootstrapRound, u64>
{
    let request = IpcMessage::new(REQUEST);
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { crate::ipc_call(creator_ep, &request, ipc_buf) }
        .map_err(|_| bootstrap_errors::INVALID)?;

    let base = unpack_base(reply.label);
    match base
    {
        MORE | DONE =>
        {
            let reply_caps = reply.caps();
            let declared_cap_count = unpack_cap_count(reply.label);
            let data_words = unpack_data_words(reply.label);
            // The label is the creator's word; a mismatch with what the
            // kernel delivered is refused in every build, and the caps the
            // kernel did deliver are released rather than leaked.
            if reply_caps.len() != declared_cap_count || data_words > MSG_DATA_WORDS_MAX
            {
                delete_slots(reply_caps);
                return Err(bootstrap_errors::INVALID);
            }
            // `IpcMessage` holds at most `MSG_CAP_SLOTS_MAX` caps and
            // `MSG_DATA_WORDS_MAX` words, so each copy covers its source.
            let mut caps = [0u64; MSG_CAP_SLOTS_MAX];
            for (dst, &src) in caps.iter_mut().zip(reply_caps)
            {
                *dst = src;
            }
            let mut data = [0u64; MSG_DATA_WORDS_MAX];
            let words = reply.words();
            for (dst, &src) in data.iter_mut().zip(words)
            {
                *dst = src;
            }
            Ok(BootstrapRound {
                caps,
                cap_count: reply_caps.len(),
                data,
                data_words: data_words.min(words.len()),
                done: base == DONE,
            })
        }
        err =>
        {
            // A refused reply's caps reach no caller; release them.
            delete_slots(reply.caps());
            Err(err)
        }
    }
}

/// Drain a creator's slot rounds (see [`slot_rounds`]) into `N` positional
/// slots: request rounds until one is marked [`DONE`], spreading each over
/// the next `MSG_CAP_SLOTS_MAX` slots by the presence word in its `data[0]`.
/// A slot no round filled is `0`; a delivered cap past slot `N` is deleted.
///
/// The round loop has no count bound: the creator serving it created this
/// process and already holds full authority over it, so an endless stream of
/// rounds grants it nothing it lacks.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// The [`request_round`] error of a failed round, or
/// [`bootstrap_errors::INVALID`] for a round with no presence word or one
/// that does not decode. On an error every cap received so far is deleted.
pub unsafe fn request_slots<const N: usize>(
    creator_ep: u64,
    ipc_buf: *mut u64,
) -> Result<[u64; N], u64>
{
    let mut acc = SlotAccumulator::<N>::new();
    loop
    {
        // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
        let round = match unsafe { request_round(creator_ep, ipc_buf) }
        {
            Ok(round) => round,
            Err(code) =>
            {
                delete_slots(acc.slots());
                return Err(code);
            }
        };
        // `request_round` keeps `cap_count <= MSG_CAP_SLOTS_MAX`.
        let delivered = round.caps.get(..round.cap_count).unwrap_or_default();
        let pushed = match round_slots(&round)
        {
            Some((caps, presence)) => acc.push(caps, presence, |cap| {
                let _ = syscall::cap_delete(cap);
            }),
            None => Err(bootstrap_errors::INVALID),
        };
        if let Err(code) = pushed
        {
            delete_slots(delivered);
            delete_slots(acc.slots());
            return Err(code);
        }
        if round.done
        {
            return Ok(acc.slots);
        }
    }
}

/// Delete every non-zero cap in `caps`.
fn delete_slots(caps: &[u64])
{
    for &cap in caps
    {
        if cap != 0
        {
            let _ = syscall::cap_delete(cap);
        }
    }
}

// ── Creator side ────────────────────────────────────────────────────────────

/// Reply to a pending [`REQUEST`] with the next round. Caps past
/// `MSG_CAP_SLOTS_MAX` are silently dropped.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// Returns a negative kernel error code from the underlying IPC.
///
/// # Panics
/// Panics when `data` is longer than `MSG_DATA_WORDS_MAX` words.
pub unsafe fn reply_round(
    done: bool,
    cap_slots: &[u64],
    data: &[u64],
    ipc_buf: *mut u64,
) -> Result<(), i64>
{
    let cap_count = cap_slots.len().min(MSG_CAP_SLOTS_MAX);
    let label = pack_reply_label(done, cap_count, data.len());
    let mut builder = IpcMessage::builder(label);
    if !data.is_empty()
    {
        builder = builder.words(0, data);
    }
    for &slot in cap_slots.iter().take(cap_count)
    {
        builder = builder.cap(slot);
    }
    let msg = builder.build();
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { crate::ipc_reply(&msg, ipc_buf) }
}

/// Reply to a pending [`REQUEST`] with an error code.
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// Returns a negative kernel error code from the underlying IPC.
pub unsafe fn reply_error(code: u64, ipc_buf: *mut u64) -> Result<(), i64>
{
    let msg = IpcMessage::new(code);
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { crate::ipc_reply(&msg, ipc_buf) }
}

/// Receive one bootstrap request, verify the sender's badge, and reply
/// with the given round.
///
/// Blocks until a [`REQUEST`] arrives on `bootstrap_ep`. If the badge
/// embedded in the received cap does not match `expected_badge`, replies with
/// [`bootstrap_errors::NO_CHILD`] and returns `Err`. If the label is not
/// [`REQUEST`], replies with [`bootstrap_errors::INVALID`] and returns `Err`.
/// Otherwise, replies with the round (caps + data + done flag).
///
/// # Safety
/// `ipc_buf` must point to the caller thread's registered IPC buffer page.
///
/// # Errors
/// * `Err(bootstrap_errors::NO_CHILD)` — unexpected badge.
/// * `Err(bootstrap_errors::INVALID)` — protocol error.
pub unsafe fn serve_round(
    bootstrap_ep: u64,
    expected_badge: u64,
    ipc_buf: *mut u64,
    done: bool,
    caps: &[u64],
    data: &[u64],
) -> Result<(), u64>
{
    // SAFETY: caller guarantees `ipc_buf` is the registered IPC buffer.
    let request =
        unsafe { crate::ipc_recv(bootstrap_ep, ipc_buf) }.map_err(|_| bootstrap_errors::INVALID)?;

    if request.badge != expected_badge
    {
        // SAFETY: same invariant.
        let _ = unsafe { reply_error(bootstrap_errors::NO_CHILD, ipc_buf) };
        return Err(bootstrap_errors::NO_CHILD);
    }

    if (request.label & 0xFFFF) != REQUEST
    {
        // SAFETY: same invariant.
        let _ = unsafe { reply_error(bootstrap_errors::INVALID, ipc_buf) };
        return Err(bootstrap_errors::INVALID);
    }

    // SAFETY: same invariant.
    unsafe { reply_round(done, caps, data, ipc_buf) }.map_err(|_| bootstrap_errors::INVALID)
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// The round a child receives for `packed`, as `request_round` builds it.
    fn received(packed: &PackedSlots) -> BootstrapRound
    {
        let mut round = BootstrapRound {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: packed.caps().len(),
            data: [0; MSG_DATA_WORDS_MAX],
            data_words: 1,
            done: true,
        };
        round.caps[..packed.caps().len()].copy_from_slice(packed.caps());
        round.data[0] = packed.presence();
        round
    }

    #[test]
    fn slots_round_trip_with_every_slot_present_or_absent()
    {
        for mask in 0u32..(1 << MSG_CAP_SLOTS_MAX)
        {
            let mut slots = [0u64; MSG_CAP_SLOTS_MAX];
            for (i, slot) in slots.iter_mut().enumerate()
            {
                if mask & (1 << i) != 0
                {
                    *slot = 0x40 + i as u64;
                }
            }
            let packed = pack_slots(&slots);
            assert_eq!(unpack_slots(&received(&packed)), Ok(slots));
        }
    }

    // The kernel refuses a message carrying a null cap slot, so an absent
    // slot must leave the cap list rather than ride in it as `0`.
    #[test]
    fn an_absent_slot_is_left_off_the_cap_list()
    {
        let packed = pack_slots(&[0x41, 0, 0x43]);
        assert_eq!(packed.caps(), &[0x41, 0x43]);
        assert_eq!(packed.presence(), 0b101);
    }

    #[test]
    fn a_round_without_its_presence_word_is_invalid()
    {
        let mut round = received(&pack_slots(&[0x41]));
        round.data_words = 0;
        assert_eq!(unpack_slots(&round), Err(bootstrap_errors::INVALID));
    }

    // The defect caught: a round whose public counts are past their arrays,
    // which panicked on the slice instead of reading as malformed.
    #[test]
    fn a_round_with_a_count_past_its_array_is_invalid()
    {
        let mut caps_past = received(&pack_slots(&[0x41]));
        caps_past.cap_count = MSG_CAP_SLOTS_MAX + 1;
        assert_eq!(unpack_slots(&caps_past), Err(bootstrap_errors::INVALID));

        let mut words_past = received(&pack_slots(&[0x41]));
        words_past.data_words = MSG_DATA_WORDS_MAX + 1;
        assert_eq!(unpack_slots(&words_past), Err(bootstrap_errors::INVALID));
    }

    #[test]
    fn a_presence_word_disagreeing_with_the_delivered_caps_is_invalid()
    {
        let mut more_bits = received(&pack_slots(&[0x41]));
        more_bits.data[0] = 0b11;
        assert_eq!(unpack_slots(&more_bits), Err(bootstrap_errors::INVALID));

        let mut fewer_bits = received(&pack_slots(&[0x41, 0x42]));
        fewer_bits.data[0] = 0b01;
        assert_eq!(unpack_slots(&fewer_bits), Err(bootstrap_errors::INVALID));
    }

    /// The slots a child holds after pushing every round of `slot_rounds`,
    /// and the caps handed to `overflow` (the crate is `no_std`, so a fixed
    /// buffer and its fill count).
    fn concatenated<const N: usize>(slots: &[u64]) -> ([u64; N], [u64; 8], usize)
    {
        let mut acc = SlotAccumulator::<N>::new();
        let mut dropped = [0u64; 8];
        let mut dropped_count = 0;
        for round in slot_rounds(slots)
        {
            acc.push(round.caps(), round.presence(), |cap| {
                dropped[dropped_count] = cap;
                dropped_count += 1;
            })
            .unwrap();
        }
        (*acc.slots(), dropped, dropped_count)
    }

    #[test]
    fn slots_past_one_round_split_into_windows_and_concatenate_back()
    {
        // Six slots, absent ones in both windows: two rounds, the second's
        // presence word relative to its own window.
        let slots = [0x41, 0, 0x43, 0x44, 0, 0x46];
        assert_eq!(slot_rounds(&slots).count(), 2);
        let second = slot_rounds(&slots).nth(1).unwrap();
        assert_eq!(second.caps(), &[0x46]);
        assert_eq!(second.presence(), 0b10);
        let (received, _, dropped) = concatenated::<6>(&slots);
        assert_eq!(received, slots);
        assert_eq!(dropped, 0);
    }

    #[test]
    fn no_slots_still_yield_one_empty_round()
    {
        assert_eq!(slot_rounds(&[]).count(), 1);
        let only = slot_rounds(&[]).next().unwrap();
        assert!(only.caps().is_empty());
        assert_eq!(only.presence(), 0);
    }

    // A child that expects fewer slots than the creator sent must be handed
    // the extra caps to release, not lose them.
    #[test]
    fn caps_past_the_childs_slots_go_to_overflow()
    {
        let (slots, dropped, count) = concatenated::<2>(&[0x41, 0x42, 0x43, 0, 0x45]);
        assert_eq!(slots, [0x41, 0x42]);
        assert_eq!(&dropped[..count], &[0x43, 0x45]);
    }

    #[test]
    fn a_malformed_later_round_is_refused_and_records_nothing()
    {
        let mut acc = SlotAccumulator::<8>::new();
        acc.push(&[0x41], 0b1, |_| panic!("no overflow")).unwrap();
        assert_eq!(
            acc.push(&[0x45], 0b11, |_| panic!("no overflow")),
            Err(bootstrap_errors::INVALID)
        );
        assert_eq!(acc.slots(), &[0x41, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_presence_bit_with_no_slot_is_invalid()
    {
        let mut round = received(&pack_slots(&[0x41]));
        round.cap_count = 2;
        round.caps[1] = 0x42;
        round.data[0] = 0b1 | (1 << MSG_CAP_SLOTS_MAX);
        assert_eq!(unpack_slots(&round), Err(bootstrap_errors::INVALID));
    }
}
