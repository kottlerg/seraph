// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/endowment/src/lib.rs

//! Wire codec for init's handover endowment of svcmgr.
//!
//! init serves the endowment over the bootstrap-round protocol and svcmgr
//! drains it; this crate owns the round kinds and the encoding of the rounds
//! that carry optional source caps (`CAPS` and `LOGD_SOURCES`). The kernel
//! refuses a message carrying a null cap slot, so an absent source cannot
//! ride as a zero slot: each of these rounds lists only the caps present,
//! and a presence bitmap in a data word names which slot each listed cap
//! fills. The `CAPS` slots are a positional list of any length, split over
//! as many `CAPS` rounds as it needs with `ipc::bootstrap`'s slot-round
//! windows. The encoding is specified in
//! [services/svcmgr/docs/ipc-interface.md](../../docs/ipc-interface.md#handover-endowment-bootstrap-rounds)
//! (see also the crate [README](../README.md)).
//! The crate performs no IPC and issues no syscalls, so both sides of the
//! codec are host-tested (see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

use ipc::bootstrap::{PackedSlots, SlotAccumulator, slot_round_count, slot_rounds};
use syscall_abi::MSG_CAP_SLOTS_MAX;

/// Round kinds, tagged in `data[0]` of every endowment round.
pub mod kind
{
    /// svcmgr's own endpoints plus the publish-role source caps, over one or
    /// more consecutive rounds.
    pub const CAPS: u64 = 1;
    /// One substrate `(name, thread_cap)` registration.
    pub const SUBSTRATE: u64 = 2;
    /// Terminal round: the reserved log-sink sources svcmgr mints real-logd's
    /// bootstrap caps from on every (re)launch.
    pub const LOGD_SOURCES: u64 = 3;
}

/// Positions in the `CAPS` slot list. Round `k` of the `CAPS` rounds
/// carries slots `k * MSG_CAP_SLOTS_MAX` onwards, and its presence word
/// (`data[2]`) is relative to that window.
pub mod caps_slot
{
    /// svcmgr's service endpoint (RECV). Required.
    pub const SERVICE: usize = 0;
    /// svcmgr's own bootstrap endpoint (RECV). Required.
    pub const BOOTSTRAP: usize = 1;
    /// The SEND on the root filesystem's namespace endpoint (`rootfs.root`).
    pub const ROOTFS_ROOT: usize = 2;
    /// The badge-0 `SEND|GRANT` source on devmgr's registry endpoint.
    pub const DEVMGR_REGISTRY: usize = 3;
    /// The `vfsd_labels::MOUNT_AUTHORITY`-badged SEND on vfsd's service
    /// endpoint (`vfsd.mount`).
    pub const VFSD_MOUNT: usize = 4;
    /// The `vfsd_labels::DENY_BADGE`-badged SEND on vfsd's service endpoint
    /// (`vfsd.deny`).
    pub const VFSD_DENY: usize = 5;
}

/// Number of slots in the `CAPS` slot list.
pub const CAPS_SLOTS: usize = 6;

/// Number of `CAPS` rounds the slot list takes.
pub const CAPS_ROUNDS: usize = slot_round_count(CAPS_SLOTS);

/// Presence bits of the `LOGD_SOURCES` round's slots, in `data[1]`.
pub mod logd_present
{
    /// The reserved master-log endpoint source.
    pub const MASTER_LOG: u64 = 1 << 0;
    /// The badge-0 `SEND|GRANT` source on procmgr's service endpoint.
    pub const PROCMGR_DEATH_AUTH: u64 = 1 << 1;
}

/// Data words an encoded round carries at most (`CAPS`: kind, version,
/// presence, rounds left).
const ROUND_DATA_WORDS: usize = 4;

/// The caps of the `CAPS` rounds, by role. `0` marks an absent source cap.
/// The two endpoints are required; in a decoded round set they are never
/// `0`, since [`CapsDecoder`] refuses a set that lacks either.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapsRound
{
    /// svcmgr's service endpoint (RECV).
    pub service_ep: u32,
    /// svcmgr's own bootstrap endpoint (RECV).
    pub bootstrap_ep: u32,
    /// SEND on the root filesystem's namespace endpoint, or `0`.
    pub rootfs_root: u32,
    /// Badge-0 `SEND|GRANT` source on devmgr's registry endpoint, or `0`.
    pub devmgr_registry: u32,
    /// `MOUNT_AUTHORITY`-badged SEND on vfsd's service endpoint, or `0`.
    pub vfsd_mount: u32,
    /// `DENY_BADGE`-badged SEND on vfsd's service endpoint, or `0`.
    pub vfsd_deny: u32,
}

impl CapsRound
{
    /// The positional slot list, indexed by [`caps_slot`].
    fn slots(&self) -> [u32; CAPS_SLOTS]
    {
        let mut slots = [0; CAPS_SLOTS];
        slots[caps_slot::SERVICE] = self.service_ep;
        slots[caps_slot::BOOTSTRAP] = self.bootstrap_ep;
        slots[caps_slot::ROOTFS_ROOT] = self.rootfs_root;
        slots[caps_slot::DEVMGR_REGISTRY] = self.devmgr_registry;
        slots[caps_slot::VFSD_MOUNT] = self.vfsd_mount;
        slots[caps_slot::VFSD_DENY] = self.vfsd_deny;
        slots
    }

    fn from_slots(slots: &[u32; CAPS_SLOTS]) -> Self
    {
        CapsRound {
            service_ep: slots[caps_slot::SERVICE],
            bootstrap_ep: slots[caps_slot::BOOTSTRAP],
            rootfs_root: slots[caps_slot::ROOTFS_ROOT],
            devmgr_registry: slots[caps_slot::DEVMGR_REGISTRY],
            vfsd_mount: slots[caps_slot::VFSD_MOUNT],
            vfsd_deny: slots[caps_slot::VFSD_DENY],
        }
    }
}

/// The caps of the `LOGD_SOURCES` round, by role. `0` marks an absent source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LogdSources
{
    /// Reserved master-log endpoint source, or `0`.
    pub master_log_source: u32,
    /// Badge-0 `SEND|GRANT` source on procmgr's service endpoint, or `0`.
    pub procmgr_death_auth_source: u32,
}

/// One encoded round: the caps to transfer, none of them `0`, and the data
/// words, `data[0]` being the round kind.
pub struct Round
{
    caps: [u32; MSG_CAP_SLOTS_MAX],
    cap_count: usize,
    data: [u64; ROUND_DATA_WORDS],
    data_words: usize,
}

impl Round
{
    /// The caps the round transfers, in wire order.
    #[must_use]
    pub fn caps(&self) -> &[u32]
    {
        &self.caps[..self.cap_count]
    }

    /// The round's data words.
    #[must_use]
    pub fn data(&self) -> &[u64]
    {
        &self.data[..self.data_words]
    }

    fn new(data: &[u64]) -> Self
    {
        let mut round = Round {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: 0,
            data: [0; ROUND_DATA_WORDS],
            data_words: data.len(),
        };
        round.data[..data.len()].copy_from_slice(data);
        round
    }

    /// A round carrying `packed`'s caps.
    fn with_caps(data: &[u64], packed: &PackedSlots) -> Self
    {
        let mut round = Round::new(data);
        round.caps[..packed.caps().len()].copy_from_slice(packed.caps());
        round.cap_count = packed.caps().len();
        round
    }

    /// Append `cap` when it is present, and return `bit` for the presence
    /// bitmap, or `0` when it is absent.
    fn push_optional(&mut self, cap: u32, bit: u64) -> u64
    {
        if cap == 0
        {
            return 0;
        }
        self.caps[self.cap_count] = cap;
        self.cap_count += 1;
        bit
    }
}

/// Why a received round does not decode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError
{
    /// A `CAPS` round's handshake word is missing or is not this build's
    /// `SVCMGR_LABELS_VERSION`.
    VersionMismatch,
    /// The round's kind, data words, or caps disagree with its encoding:
    /// a required cap, the presence word, or the rounds-left word is
    /// missing, the bitmap sets a bit with no slot, the bitmap names a
    /// different number of caps than the round delivered, or a `CAPS` round
    /// arrives past the rounds the slot list takes or with a rounds-left
    /// word that disagrees with them.
    Malformed,
}

/// Encode the `CAPS` rounds, [`CAPS_ROUNDS`] of them in serving order.
/// `service_ep` and `bootstrap_ep` MUST be non-zero (init derives both
/// before it starts svcmgr); an optional source of `0` is left off its
/// round's cap list and its presence bit clear. Round `k` carries
/// `data = [CAPS, SVCMGR_LABELS_VERSION, presence, rounds_left]`, where
/// `rounds_left` counts the `CAPS` rounds after it.
#[must_use]
pub fn encode_caps(caps: &CapsRound) -> [Round; CAPS_ROUNDS]
{
    let slots = caps.slots();
    let mut windows = slot_rounds(&slots);
    core::array::from_fn(|k| {
        let packed = windows
            .next()
            .unwrap_or_else(|| ipc::bootstrap::pack_slots(&[]));
        Round::with_caps(
            &[
                kind::CAPS,
                u64::from(ipc::SVCMGR_LABELS_VERSION),
                packed.presence(),
                (CAPS_ROUNDS - 1 - k) as u64,
            ],
            &packed,
        )
    })
}

/// Encode the `LOGD_SOURCES` round. A source of `0` is left off the cap
/// list and its presence bit clear, so both sources absent encode the empty
/// terminal round init serves after a failed `CAPS` round.
#[must_use]
pub fn encode_logd_sources(sources: &LogdSources) -> Round
{
    let mut round = Round::new(&[kind::LOGD_SOURCES, 0]);
    let presence = round.push_optional(sources.master_log_source, logd_present::MASTER_LOG)
        | round.push_optional(
            sources.procmgr_death_auth_source,
            logd_present::PROCMGR_DEATH_AUTH,
        );
    round.data[1] = presence;
    round
}

/// Concatenates the rounds of an `N`-slot list split over
/// [`slot_round_count`]`(N)` rounds, each with a rounds-left count.
struct SlotListDecoder<const N: usize>
{
    slots: SlotAccumulator<N>,
    received: usize,
}

impl<const N: usize> SlotListDecoder<N>
{
    const ROUNDS: usize = slot_round_count(N);

    const fn new() -> Self
    {
        SlotListDecoder {
            slots: SlotAccumulator::new(),
            received: 0,
        }
    }

    /// Add the next round. Returns the slots once the last round (rounds
    /// left `0`) arrives, `None` while more are owed. Refuses a round past
    /// the list's round count, a rounds-left count that disagrees with the
    /// rounds still owed, and a round that does not decode or carries a cap
    /// past slot `N`.
    fn push(
        &mut self,
        caps: &[u32],
        presence: u64,
        rounds_left: u64,
    ) -> Result<Option<[u32; N]>, DecodeError>
    {
        let owed_after = Self::ROUNDS
            .checked_sub(self.received + 1)
            .ok_or(DecodeError::Malformed)?;
        if rounds_left != owed_after as u64
        {
            return Err(DecodeError::Malformed);
        }
        // A cap past the list would come from an encoder with a longer list,
        // which the rounds-left check above rules out; refuse it regardless.
        let mut overflowed = false;
        self.slots
            .push(caps, presence, |_| overflowed = true)
            .map_err(|_| DecodeError::Malformed)?;
        if overflowed
        {
            return Err(DecodeError::Malformed);
        }
        self.received += 1;
        Ok((owed_after == 0).then(|| *self.slots.slots()))
    }
}

/// Concatenates received `CAPS` rounds into the [`CapsRound`] they encode.
pub struct CapsDecoder
{
    list: SlotListDecoder<CAPS_SLOTS>,
}

impl Default for CapsDecoder
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl CapsDecoder
{
    /// A decoder that has received no `CAPS` round.
    #[must_use]
    pub const fn new() -> Self
    {
        CapsDecoder {
            list: SlotListDecoder::new(),
        }
    }

    /// Add one received `CAPS` round from its delivered `caps` and its
    /// `data` words. Returns the decoded [`CapsRound`] once the round whose
    /// rounds-left word is `0` arrives, and `None` while more are owed.
    ///
    /// # Errors
    /// [`DecodeError::VersionMismatch`] when `data[1]` is missing or differs
    /// from this build's `SVCMGR_LABELS_VERSION`; [`DecodeError::Malformed`]
    /// when the kind is not `CAPS`, the presence or rounds-left word is
    /// missing, the presence bitmap disagrees with the delivered caps, the
    /// round is past the [`CAPS_ROUNDS`] the list takes or its rounds-left
    /// word disagrees with the rounds still owed, or the last round leaves a
    /// required endpoint absent. On an error the round's caps are still the
    /// caller's to release.
    pub fn push(&mut self, caps: &[u32], data: &[u64]) -> Result<Option<CapsRound>, DecodeError>
    {
        if data.first() != Some(&kind::CAPS)
        {
            return Err(DecodeError::Malformed);
        }
        if data.get(1) != Some(&u64::from(ipc::SVCMGR_LABELS_VERSION))
        {
            return Err(DecodeError::VersionMismatch);
        }
        let (Some(&presence), Some(&rounds_left)) = (data.get(2), data.get(3))
        else
        {
            return Err(DecodeError::Malformed);
        };
        let Some(slots) = self.list.push(caps, presence, rounds_left)?
        else
        {
            return Ok(None);
        };
        let decoded = CapsRound::from_slots(&slots);
        if decoded.service_ep == 0 || decoded.bootstrap_ep == 0
        {
            return Err(DecodeError::Malformed);
        }
        Ok(Some(decoded))
    }
}

/// Decode a received `LOGD_SOURCES` round from its delivered `caps` and its
/// `data` words.
///
/// # Errors
/// [`DecodeError::Malformed`] when the kind is not `LOGD_SOURCES`, the
/// presence word is missing, or the presence bitmap disagrees with the
/// delivered caps.
pub fn decode_logd_sources(caps: &[u32], data: &[u64]) -> Result<LogdSources, DecodeError>
{
    if data.first() != Some(&kind::LOGD_SOURCES)
    {
        return Err(DecodeError::Malformed);
    }
    let Some(&presence) = data.get(1)
    else
    {
        return Err(DecodeError::Malformed);
    };
    let slots = ipc::bootstrap::spread_slots(caps, presence).map_err(|_| DecodeError::Malformed)?;
    if presence >> 2 != 0
    {
        return Err(DecodeError::Malformed);
    }
    Ok(LogdSources {
        master_log_source: slots[0],
        procmgr_death_auth_source: slots[1],
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    const SERVICE: u32 = 0x11;
    const BOOTSTRAP: u32 = 0x12;
    const VERSION: u64 = ipc::SVCMGR_LABELS_VERSION as u64;

    fn caps_round(rootfs_root: u32, devmgr_registry: u32) -> CapsRound
    {
        CapsRound {
            service_ep: SERVICE,
            bootstrap_ep: BOOTSTRAP,
            rootfs_root,
            devmgr_registry,
            vfsd_mount: 0,
            vfsd_deny: 0,
        }
    }

    /// Feed every encoded `CAPS` round to a fresh decoder.
    fn decode_all(rounds: &[Round]) -> Result<Option<CapsRound>, DecodeError>
    {
        let mut decoder = CapsDecoder::new();
        let mut last = Ok(None);
        for round in rounds
        {
            last = decoder.push(round.caps(), round.data());
            if last.is_err()
            {
                break;
            }
        }
        last
    }

    // The six slots take two rounds; each optional source, in either
    // window, round-trips present or absent.
    #[test]
    fn caps_round_trips_with_every_source_present_or_absent()
    {
        for mask in 0u32..16
        {
            let pick = |bit: u32, cap: u32| if mask & bit != 0 { cap } else { 0 };
            let sent = CapsRound {
                vfsd_mount: pick(4, 0x23),
                vfsd_deny: pick(8, 0x24),
                ..caps_round(pick(1, 0x21), pick(2, 0x22))
            };
            assert_eq!(decode_all(&encode_caps(&sent)), Ok(Some(sent)));
        }
    }

    #[test]
    fn logd_sources_round_trip_with_every_source_present_or_absent()
    {
        for (master, death) in [(0, 0), (0x31, 0), (0, 0x32), (0x31, 0x32)]
        {
            let sent = LogdSources {
                master_log_source: master,
                procmgr_death_auth_source: death,
            };
            let round = encode_logd_sources(&sent);
            assert_eq!(decode_logd_sources(round.caps(), round.data()), Ok(sent));
        }
    }

    // The kernel refuses a message carrying a null cap slot, so an absent
    // source must leave the cap list rather than ride in it as `0`.
    #[test]
    fn an_absent_source_is_left_off_the_cap_list()
    {
        let caps = encode_caps(&caps_round(0, 0x22));
        assert_eq!(caps[0].caps(), &[SERVICE, BOOTSTRAP, 0x22]);
        assert_eq!(caps[0].data()[2], 0b1011);

        let logd = encode_logd_sources(&LogdSources {
            master_log_source: 0x31,
            procmgr_death_auth_source: 0,
        });
        assert_eq!(logd.caps(), &[0x31]);
        assert_eq!(logd.data()[1], logd_present::MASTER_LOG);
    }

    // A decoder that stopped at the first round would lose every slot a later
    // round carries.
    #[test]
    fn a_slot_list_past_one_round_is_concatenated_until_the_last()
    {
        let mut list = SlotListDecoder::<6>::new();
        assert_eq!(list.push(&[0x41, 0x42, 0x44], 0b1011, 1), Ok(None));
        assert_eq!(
            list.push(&[0x46], 0b10, 0),
            Ok(Some([0x41, 0x42, 0, 0x44, 0, 0x46]))
        );
    }

    #[test]
    fn a_round_past_the_list_or_a_wrong_rounds_left_is_malformed()
    {
        // `rounds_left` must count the rounds still owed.
        let mut list = SlotListDecoder::<6>::new();
        assert_eq!(list.push(&[0x41], 0b1, 0), Err(DecodeError::Malformed));

        // An empty CAPS round after the rounds the list takes.
        let mut decoder = CapsDecoder::new();
        let rounds = encode_caps(&caps_round(0, 0));
        assert_eq!(decode_all(&rounds).map(|set| set.is_some()), Ok(true));
        for round in &rounds
        {
            assert!(decoder.push(round.caps(), round.data()).is_ok());
        }
        assert_eq!(
            decoder.push(&[], &[kind::CAPS, VERSION, 0, 0]),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn a_round_carrying_a_slot_past_the_list_is_malformed()
    {
        let mut list = SlotListDecoder::<6>::new();
        assert_eq!(list.push(&[0x41], 0b1, 1), Ok(None));
        // Window slot 2 of round 2 is list slot 6, past the list.
        assert_eq!(list.push(&[0x47], 0b100, 0), Err(DecodeError::Malformed));
    }

    #[test]
    fn caps_round_with_a_wrong_or_missing_version_is_refused()
    {
        let rounds = encode_caps(&caps_round(0x21, 0x22));
        let mut data = [0u64; ROUND_DATA_WORDS];
        data.copy_from_slice(rounds[0].data());
        data[1] = VERSION + 1;
        assert_eq!(
            CapsDecoder::new().push(rounds[0].caps(), &data),
            Err(DecodeError::VersionMismatch)
        );
        assert_eq!(
            CapsDecoder::new().push(rounds[0].caps(), &data[..1]),
            Err(DecodeError::VersionMismatch)
        );
    }

    #[test]
    fn caps_round_missing_a_word_or_an_endpoint_is_malformed()
    {
        let rounds = encode_caps(&caps_round(0, 0));
        for words in [2, 3]
        {
            assert_eq!(
                CapsDecoder::new().push(rounds[0].caps(), &rounds[0].data()[..words]),
                Err(DecodeError::Malformed)
            );
        }
        // Only the bootstrap endpoint present: the service slot is absent.
        let mut decoder = CapsDecoder::new();
        assert_eq!(
            decoder.push(&[BOOTSTRAP], &[kind::CAPS, VERSION, 0b0010, 1]),
            Ok(None)
        );
        assert_eq!(
            decoder.push(&[], &[kind::CAPS, VERSION, 0, 0]),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn a_bitmap_naming_a_different_cap_count_is_malformed()
    {
        let both = encode_caps(&caps_round(0x21, 0x22));
        let one = encode_caps(&caps_round(0x21, 0));
        // Bitmap names two optional caps, one delivered; and the reverse.
        assert_eq!(
            CapsDecoder::new().push(one[0].caps(), both[0].data()),
            Err(DecodeError::Malformed)
        );
        assert_eq!(
            CapsDecoder::new().push(both[0].caps(), one[0].data()),
            Err(DecodeError::Malformed)
        );

        let none = encode_logd_sources(&LogdSources {
            master_log_source: 0,
            procmgr_death_auth_source: 0,
        });
        assert_eq!(
            decode_logd_sources(&[0x31], none.data()),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn a_presence_bit_with_no_slot_is_malformed()
    {
        let data = [kind::LOGD_SOURCES, logd_present::MASTER_LOG | (1 << 2)];
        assert_eq!(
            decode_logd_sources(&[0x31, 0x32], &data),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn a_round_of_another_kind_or_without_presence_word_is_malformed()
    {
        let caps = encode_caps(&caps_round(0, 0));
        assert_eq!(
            decode_logd_sources(caps[0].caps(), caps[0].data()),
            Err(DecodeError::Malformed)
        );
        assert_eq!(
            decode_logd_sources(&[], &[kind::LOGD_SOURCES]),
            Err(DecodeError::Malformed)
        );
        let logd = encode_logd_sources(&LogdSources {
            master_log_source: 0,
            procmgr_death_auth_source: 0,
        });
        assert_eq!(
            CapsDecoder::new().push(logd.caps(), logd.data()),
            Err(DecodeError::Malformed)
        );
    }
}
