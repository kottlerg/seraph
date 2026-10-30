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
//! codec: [`pack_slots`] / [`unpack_slots`], for a round whose caps fill
//! positional slots that may be absent (the rounds svcmgr serves the
//! children it launches).

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
    pub caps: [u32; MSG_CAP_SLOTS_MAX],
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
    caps: [u32; MSG_CAP_SLOTS_MAX],
    cap_count: usize,
    presence: u64,
}

impl PackedSlots
{
    /// The caps the round transfers, in slot order, none of them `0`.
    #[must_use]
    pub fn caps(&self) -> &[u32]
    {
        &self.caps[..self.cap_count]
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
/// are not packed; the caller bounds its slot list to the round.
#[must_use]
pub fn pack_slots(slots: &[u32]) -> PackedSlots
{
    let mut packed = PackedSlots {
        caps: [0; MSG_CAP_SLOTS_MAX],
        cap_count: 0,
        presence: 0,
    };
    for (i, &cap) in slots.iter().take(MSG_CAP_SLOTS_MAX).enumerate()
    {
        if cap != 0
        {
            packed.caps[packed.cap_count] = cap;
            packed.cap_count += 1;
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
/// different number of caps than the round delivered.
pub fn unpack_slots(round: &BootstrapRound) -> Result<[u32; MSG_CAP_SLOTS_MAX], u64>
{
    if round.data_words == 0
    {
        return Err(bootstrap_errors::INVALID);
    }
    let presence = round.data[0];
    if presence >> MSG_CAP_SLOTS_MAX != 0 || presence.count_ones() as usize != round.cap_count
    {
        return Err(bootstrap_errors::INVALID);
    }
    let mut slots = [0u32; MSG_CAP_SLOTS_MAX];
    let mut next = round.caps[..round.cap_count].iter();
    for (i, slot) in slots.iter_mut().enumerate()
    {
        if presence & (1 << i) != 0
        {
            *slot = next.next().copied().ok_or(bootstrap_errors::INVALID)?;
        }
    }
    Ok(slots)
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
///   (`IPC_REPLY_TRANSFER_FAILED`).
/// * `Err(bootstrap_errors::INVALID)` if the underlying IPC fails, or if
///   the reply's label disagrees with its payload: the delivered cap count
///   differs from the count the label declares, or the label declares more
///   data words than a message carries.
pub unsafe fn request_round(creator_ep: u32, ipc_buf: *mut u64) -> Result<BootstrapRound, u64>
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
            // kernel delivered is refused in every build.
            if reply_caps.len() != declared_cap_count || data_words > MSG_DATA_WORDS_MAX
            {
                return Err(bootstrap_errors::INVALID);
            }
            let mut caps = [0u32; MSG_CAP_SLOTS_MAX];
            caps[..reply_caps.len()].copy_from_slice(reply_caps);
            let mut data = [0u64; MSG_DATA_WORDS_MAX];
            let words = reply.words();
            data[..words.len()].copy_from_slice(words);
            Ok(BootstrapRound {
                caps,
                cap_count: reply_caps.len(),
                data,
                data_words: data_words.min(words.len()),
                done: base == DONE,
            })
        }
        err => Err(err),
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
    cap_slots: &[u32],
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
    bootstrap_ep: u32,
    expected_badge: u64,
    ipc_buf: *mut u64,
    done: bool,
    caps: &[u32],
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
            let mut slots = [0u32; MSG_CAP_SLOTS_MAX];
            for (i, slot) in slots.iter_mut().enumerate()
            {
                if mask & (1 << i) != 0
                {
                    *slot = 0x40 + i as u32;
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
