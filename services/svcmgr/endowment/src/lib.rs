// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/endowment/src/lib.rs

//! Wire codec for init's handover endowment of svcmgr.
//!
//! init serves the endowment over the bootstrap-round protocol and svcmgr
//! drains it; this crate owns the round kinds and the encoding of every round:
//! `CAPS` and `LOGD_SOURCES`, which carry optional source caps, and
//! `SUBSTRATE`, which carries one substrate service's registration. The kernel
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
    /// One substrate service's registration: its name, its main thread cap,
    /// and the cap svcmgr observes the faults of its other threads through.
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
    /// The SEND on vfsd's synthetic root, derived from init's system-root
    /// cap (`rootfs.root`).
    pub const ROOTFS_ROOT: usize = 2;
    /// The badge-0 `SEND|GRANT` source on devmgr's registry endpoint.
    pub const DEVMGR_REGISTRY: usize = 3;
    /// The `vfsd_labels::MOUNT_AUTHORITY`-badged SEND on vfsd's service
    /// endpoint (`vfsd.mount`).
    pub const VFSD_MOUNT: usize = 4;
    /// The `vfsd_labels::DENY_BADGE`-badged SEND on vfsd's service endpoint
    /// (`vfsd.deny`).
    pub const VFSD_DENY: usize = 5;
    /// The `vfsd_labels::SWAP_AUTHORITY`-badged SEND on vfsd's service
    /// endpoint (`vfsd.swap`).
    pub const VFSD_SWAP: usize = 6;
    /// The `EntropyControl` source carrying `Contribute`, derived from the
    /// root capability the kernel mints into init. Never published: svcmgr
    /// derives the `entropy_authority = yes` service's copy from it.
    pub const ENTROPY_SOURCE: usize = 7;
    /// The `memmgr_labels::SWAP_AUTHORITY`-badged `SEND|GRANT` on memmgr's
    /// endpoint (`memmgr.swap`).
    pub const MEMMGR_SWAP: usize = 8;
    /// The `PmuControl` source carrying `Configure`, derived from the root
    /// capability the kernel mints into init. Never published: svcmgr derives
    /// the `pmu_authority = yes` service's copy from it, and deletes it once
    /// the recipes are read when no recipe holds the key.
    pub const PMU_SOURCE: usize = 9;
}

/// Number of slots in the `CAPS` slot list: one per role in [`caps_slot`],
/// whose roles are fixed, so the list cannot overflow.
pub const CAPS_SLOTS: usize = 10;

/// Number of `CAPS` rounds the slot list takes.
pub const CAPS_ROUNDS: usize = slot_round_count(CAPS_SLOTS);

/// Presence bits of the `LOGD_SOURCES` round's slots, in `data[1]`.
pub mod logd_present
{
    /// The reserved master-log endpoint source.
    pub const MASTER_LOG: u64 = 1 << 0;
    /// The badge-0 `SEND|GRANT` source on procmgr's service endpoint.
    pub const PROCMGR_DEATH_AUTH: u64 = 1 << 1;
    /// The `KernelLog` source carrying `Read`.
    pub const KERNEL_LOG: u64 = 1 << 2;
}

/// Values of a `SUBSTRATE` round's observer word (`data[2]`): which cap,
/// if any, follows the thread cap, through which svcmgr binds a death
/// observer on the service's address space.
pub mod observer_kind
{
    /// No observer cap: the round carries the thread cap alone.
    pub const NONE: u64 = 0;
    /// A `Control`-only cap on the service's address space, which svcmgr
    /// binds with `SYS_ASPACE_BIND_NOTIFICATION` (a service init created by
    /// raw syscalls: memmgr, procmgr).
    pub const ADDRESS_SPACE: u64 = 1;
    /// The service's procmgr process handle, on which svcmgr sends
    /// `procmgr_labels::BIND_DEATH_OBSERVER` (a service init created through
    /// procmgr: devmgr, vfsd).
    pub const PROCESS_HANDLE: u64 = 2;
}

/// Data words of a `SUBSTRATE` round ahead of the name words: kind, name
/// length, observer kind.
const SUBSTRATE_HEADER_WORDS: usize = 3;

/// Data words an encoded round carries at most: a `SUBSTRATE` round's
/// header and the longest name (`CAPS` rounds carry four).
const ROUND_DATA_WORDS: usize = SUBSTRATE_HEADER_WORDS + ipc::svcmgr_labels::NAME_WORDS;

/// The caps of the `CAPS` rounds, by role. `0` marks an absent source cap.
/// The two endpoints are required; in a decoded round set they are never
/// `0`, since [`CapsDecoder`] refuses a set that lacks either.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapsRound
{
    /// svcmgr's service endpoint (RECV).
    pub service_ep: u64,
    /// svcmgr's own bootstrap endpoint (RECV).
    pub bootstrap_ep: u64,
    /// SEND on vfsd's synthetic root (`rootfs.root`), or `0`.
    pub rootfs_root: u64,
    /// Badge-0 `SEND|GRANT` source on devmgr's registry endpoint, or `0`.
    pub devmgr_registry: u64,
    /// `MOUNT_AUTHORITY`-badged SEND on vfsd's service endpoint, or `0`.
    pub vfsd_mount: u64,
    /// `DENY_BADGE`-badged SEND on vfsd's service endpoint, or `0`.
    pub vfsd_deny: u64,
    /// `SWAP_AUTHORITY`-badged SEND on vfsd's service endpoint, or `0`.
    pub vfsd_swap: u64,
    /// `EntropyControl` source carrying `Contribute`, or `0`.
    pub entropy_source: u64,
    /// `SWAP_AUTHORITY`-badged `SEND|GRANT` on memmgr's endpoint, or `0`.
    pub memmgr_swap: u64,
    /// `PmuControl` source carrying `Configure`, or `0`.
    pub pmu_source: u64,
}

impl CapsRound
{
    /// The positional slot list, indexed by [`caps_slot`].
    fn slots(&self) -> [u64; CAPS_SLOTS]
    {
        let mut slots = [0; CAPS_SLOTS];
        slots[caps_slot::SERVICE] = self.service_ep;
        slots[caps_slot::BOOTSTRAP] = self.bootstrap_ep;
        slots[caps_slot::ROOTFS_ROOT] = self.rootfs_root;
        slots[caps_slot::DEVMGR_REGISTRY] = self.devmgr_registry;
        slots[caps_slot::VFSD_MOUNT] = self.vfsd_mount;
        slots[caps_slot::VFSD_DENY] = self.vfsd_deny;
        slots[caps_slot::VFSD_SWAP] = self.vfsd_swap;
        slots[caps_slot::ENTROPY_SOURCE] = self.entropy_source;
        slots[caps_slot::MEMMGR_SWAP] = self.memmgr_swap;
        slots[caps_slot::PMU_SOURCE] = self.pmu_source;
        slots
    }

    fn from_slots(slots: &[u64; CAPS_SLOTS]) -> Self
    {
        CapsRound {
            service_ep: slots[caps_slot::SERVICE],
            bootstrap_ep: slots[caps_slot::BOOTSTRAP],
            rootfs_root: slots[caps_slot::ROOTFS_ROOT],
            devmgr_registry: slots[caps_slot::DEVMGR_REGISTRY],
            vfsd_mount: slots[caps_slot::VFSD_MOUNT],
            vfsd_deny: slots[caps_slot::VFSD_DENY],
            vfsd_swap: slots[caps_slot::VFSD_SWAP],
            entropy_source: slots[caps_slot::ENTROPY_SOURCE],
            memmgr_swap: slots[caps_slot::MEMMGR_SWAP],
            pmu_source: slots[caps_slot::PMU_SOURCE],
        }
    }
}

/// The caps of the `LOGD_SOURCES` round, by role. `0` marks an absent source.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LogdSources
{
    /// Reserved master-log endpoint source, or `0`.
    pub master_log_source: u64,
    /// Badge-0 `SEND|GRANT` source on procmgr's service endpoint, or `0`.
    pub procmgr_death_auth_source: u64,
    /// `KernelLog` source carrying `Read`, derived from the root
    /// capability the kernel mints into init, or `0`.
    pub kernel_log_source: u64,
}

/// One encoded round: the caps to transfer, none of them `0`, and the data
/// words, `data[0]` being the round kind.
pub struct Round
{
    caps: [u64; MSG_CAP_SLOTS_MAX],
    cap_count: usize,
    data: [u64; ROUND_DATA_WORDS],
    data_words: usize,
}

impl Round
{
    /// The caps the round transfers, in wire order.
    #[must_use]
    pub fn caps(&self) -> &[u64]
    {
        self.caps.get(..self.cap_count).unwrap_or_default()
    }

    /// The round's data words.
    #[must_use]
    pub fn data(&self) -> &[u64]
    {
        self.data.get(..self.data_words).unwrap_or_default()
    }

    fn new(data: &[u64]) -> Self
    {
        let mut round = Round {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: 0,
            data: [0; ROUND_DATA_WORDS],
            data_words: data.len().min(ROUND_DATA_WORDS),
        };
        for (slot, word) in round.data.iter_mut().zip(data)
        {
            *slot = *word;
        }
        round
    }

    /// A round carrying `packed`'s caps.
    fn with_caps(data: &[u64], packed: &PackedSlots) -> Self
    {
        let mut round = Round::new(data);
        for (slot, cap) in round.caps.iter_mut().zip(packed.caps())
        {
            *slot = *cap;
        }
        round.cap_count = packed.caps().len().min(MSG_CAP_SLOTS_MAX);
        round
    }

    /// Append `cap` when it is present, and return `bit` for the presence
    /// bitmap, or `0` when it is absent.
    fn push_optional(&mut self, cap: u64, bit: u64) -> u64
    {
        if cap == 0
        {
            return 0;
        }
        let Some(slot) = self.caps.get_mut(self.cap_count)
        else
        {
            return 0;
        };
        *slot = cap;
        // `cap_count` indexed a slot, so it is below `MSG_CAP_SLOTS_MAX`.
        self.cap_count = self.cap_count.saturating_add(1);
        bit
    }
}

/// The cap a `SUBSTRATE` round carries after the service's thread cap, by
/// its [`observer_kind`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SubstrateObserver
{
    /// No observer cap.
    None,
    /// A `Control`-only cap on the service's address space.
    AddressSpace(u64),
    /// The service's procmgr process handle.
    ProcessHandle(u64),
}

impl SubstrateObserver
{
    /// The [`observer_kind`] word and the cap, `None` for no cap.
    fn kind_and_cap(self) -> (u64, Option<u64>)
    {
        match self
        {
            SubstrateObserver::None => (observer_kind::NONE, None),
            SubstrateObserver::AddressSpace(cap) => (observer_kind::ADDRESS_SPACE, Some(cap)),
            SubstrateObserver::ProcessHandle(cap) => (observer_kind::PROCESS_HANDLE, Some(cap)),
        }
    }
}

/// A decoded `SUBSTRATE` round.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Substrate
{
    name: [u8; ipc::svcmgr_labels::NAME_MAX],
    name_len: usize,
    /// The service's main thread cap.
    pub thread: u64,
    /// The cap svcmgr observes the service's address space through.
    pub observer: SubstrateObserver,
}

impl Substrate
{
    /// The service's name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8]
    {
        self.name.get(..self.name_len).unwrap_or_default()
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
                // `k` is below `CAPS_ROUNDS`, so neither step saturates.
                CAPS_ROUNDS.saturating_sub(1).saturating_sub(k) as u64,
            ],
            &packed,
        )
    })
}

/// Encode the `SUBSTRATE` round of the service `name`, whose main thread cap
/// is `thread` and whose address space svcmgr observes through `observer`:
/// `caps = [thread, observer cap?]`, `data = [SUBSTRATE, name_len, observer
/// kind, name words...]`. `None` when `thread` or the observer cap is `0`
/// (the kernel refuses a null cap slot), or `name` is empty or longer than
/// `svcmgr_labels::NAME_MAX`.
#[must_use]
pub fn encode_substrate(name: &[u8], thread: u64, observer: SubstrateObserver) -> Option<Round>
{
    if thread == 0 || name.is_empty()
    {
        return None;
    }
    let (observer_word, observer_cap) = observer.kind_and_cap();
    let mut name_words = [0u64; ipc::svcmgr_labels::NAME_WORDS];
    let words = ipc::svcmgr_labels::pack_name(name, &mut name_words)?;
    let mut data = [0u64; ROUND_DATA_WORDS];
    data[0] = kind::SUBSTRATE;
    data[1] = name.len() as u64;
    data[2] = observer_word;
    for (dst, src) in data
        .iter_mut()
        .skip(SUBSTRATE_HEADER_WORDS)
        .zip(name_words.get(..words)?)
    {
        *dst = *src;
    }
    // `words` is at most `NAME_WORDS`, so the sum is at most the array length.
    let mut round = Round::new(data.get(..SUBSTRATE_HEADER_WORDS.saturating_add(words))?);
    round.caps[0] = thread;
    round.cap_count = 1;
    if let Some(cap) = observer_cap
    {
        if cap == 0
        {
            return None;
        }
        round.caps[1] = cap;
        round.cap_count = 2;
    }
    Some(round)
}

/// Decode a received `SUBSTRATE` round from its delivered `caps` and its
/// `data` words.
///
/// # Errors
/// [`DecodeError::Malformed`] when the kind is not `SUBSTRATE`, a header
/// word is missing, the observer word is not an [`observer_kind`], the round
/// delivered other than the thread cap and the cap its observer word names,
/// or the name is empty, longer than `svcmgr_labels::NAME_MAX`, or carried in
/// fewer words than its length needs. On an error the round's caps are still
/// the caller's to release.
pub fn decode_substrate(caps: &[u64], data: &[u64]) -> Result<Substrate, DecodeError>
{
    let (Some(&kind::SUBSTRATE), Some(&name_len), Some(&observer_word)) =
        (data.first(), data.get(1), data.get(2))
    else
    {
        return Err(DecodeError::Malformed);
    };
    let observer = match (observer_word, caps)
    {
        (observer_kind::NONE, &[_]) => SubstrateObserver::None,
        (observer_kind::ADDRESS_SPACE, &[_, cap]) => SubstrateObserver::AddressSpace(cap),
        (observer_kind::PROCESS_HANDLE, &[_, cap]) => SubstrateObserver::ProcessHandle(cap),
        _ => return Err(DecodeError::Malformed),
    };
    let thread = caps.first().copied().unwrap_or(0);
    let name_len = usize::try_from(name_len).map_err(|_| DecodeError::Malformed)?;
    let name = ipc::svcmgr_labels::unpack_name(
        data.get(SUBSTRATE_HEADER_WORDS..).unwrap_or_default(),
        name_len,
    )
    .ok_or(DecodeError::Malformed)?;
    if thread == 0
        || matches!(
            observer,
            SubstrateObserver::AddressSpace(0) | SubstrateObserver::ProcessHandle(0)
        )
    {
        return Err(DecodeError::Malformed);
    }
    Ok(Substrate {
        name,
        name_len,
        thread,
        observer,
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
        )
        | round.push_optional(sources.kernel_log_source, logd_present::KERNEL_LOG);
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
        caps: &[u64],
        presence: u64,
        rounds_left: u64,
    ) -> Result<Option<[u64; N]>, DecodeError>
    {
        let owed_after = Self::ROUNDS
            .checked_sub(self.received.saturating_add(1))
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
        // `received` is below `ROUNDS`, since `owed_after` was computed from it.
        self.received = self.received.saturating_add(1);
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
    pub fn push(&mut self, caps: &[u64], data: &[u64]) -> Result<Option<CapsRound>, DecodeError>
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
pub fn decode_logd_sources(caps: &[u64], data: &[u64]) -> Result<LogdSources, DecodeError>
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
    if presence >> 3 != 0
    {
        return Err(DecodeError::Malformed);
    }
    Ok(LogdSources {
        master_log_source: slots[0],
        procmgr_death_auth_source: slots[1],
        kernel_log_source: slots[2],
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    const SERVICE: u64 = 0x11;
    const BOOTSTRAP: u64 = 0x12;
    const VERSION: u64 = ipc::SVCMGR_LABELS_VERSION as u64;

    fn caps_round(rootfs_root: u64, devmgr_registry: u64) -> CapsRound
    {
        CapsRound {
            service_ep: SERVICE,
            bootstrap_ep: BOOTSTRAP,
            rootfs_root,
            devmgr_registry,
            vfsd_mount: 0,
            vfsd_deny: 0,
            vfsd_swap: 0,
            entropy_source: 0,
            memmgr_swap: 0,
            pmu_source: 0,
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

    // The ten slots take three rounds; each optional source, in any window,
    // round-trips present or absent.
    #[test]
    fn caps_round_trips_with_every_source_present_or_absent()
    {
        assert_eq!(CAPS_ROUNDS, 3);
        for mask in 0u32..256
        {
            let pick = |bit: u32, cap: u64| if mask & bit != 0 { cap } else { 0 };
            let sent = CapsRound {
                vfsd_mount: pick(4, 0x23),
                vfsd_deny: pick(8, 0x24),
                vfsd_swap: pick(16, 0x25),
                entropy_source: pick(32, 0x26),
                memmgr_swap: pick(64, 0x27),
                pmu_source: pick(128, 0x28),
                ..caps_round(pick(1, 0x21), pick(2, 0x22))
            };
            assert_eq!(decode_all(&encode_caps(&sent)), Ok(Some(sent)));
        }
    }

    #[test]
    fn logd_sources_round_trip_with_every_source_present_or_absent()
    {
        for mask in 0u64..8
        {
            let pick = |bit: u64, cap: u64| if mask & bit != 0 { cap } else { 0 };
            let sent = LogdSources {
                master_log_source: pick(1, 0x31),
                procmgr_death_auth_source: pick(2, 0x32),
                kernel_log_source: pick(4, 0x33),
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
            kernel_log_source: 0,
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
            decoder.push(round.caps(), round.data()).unwrap();
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
        let mut data = [0u64; 4];
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
        let last = CAPS_ROUNDS as u64 - 1;
        assert_eq!(
            decoder.push(&[BOOTSTRAP], &[kind::CAPS, VERSION, 0b0010, last]),
            Ok(None)
        );
        for left in (1..last).rev()
        {
            assert_eq!(decoder.push(&[], &[kind::CAPS, VERSION, 0, left]), Ok(None));
        }
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
            kernel_log_source: 0,
        });
        assert_eq!(
            decode_logd_sources(&[0x31], none.data()),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn a_presence_bit_with_no_slot_is_malformed()
    {
        let data = [kind::LOGD_SOURCES, logd_present::MASTER_LOG | (1 << 3)];
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
            kernel_log_source: 0,
        });
        assert_eq!(
            CapsDecoder::new().push(logd.caps(), logd.data()),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn a_round_given_more_words_than_it_holds_keeps_only_the_words_it_holds()
    {
        let words = [7u64; ROUND_DATA_WORDS + 3];
        let round = Round::new(&words);
        assert_eq!(round.data(), &words[..ROUND_DATA_WORDS]);
    }

    #[test]
    fn substrate_round_trips_with_each_observer()
    {
        for observer in [
            SubstrateObserver::None,
            SubstrateObserver::AddressSpace(0x52),
            SubstrateObserver::ProcessHandle(0x53),
        ]
        {
            let round = encode_substrate(b"procmgr", 0x51, observer).expect("encodes");
            let decoded = decode_substrate(round.caps(), round.data()).expect("decodes");
            assert_eq!(decoded.name(), b"procmgr");
            assert_eq!(decoded.thread, 0x51);
            assert_eq!(decoded.observer, observer);
        }
        let long = [b'n'; ipc::svcmgr_labels::NAME_MAX];
        let round = encode_substrate(&long, 0x51, SubstrateObserver::None).expect("encodes");
        assert_eq!(
            decode_substrate(round.caps(), round.data()).map(|s| s.name().len()),
            Ok(long.len())
        );
    }

    #[test]
    fn substrate_with_a_null_cap_or_a_bad_name_does_not_encode()
    {
        assert!(encode_substrate(b"vfsd", 0, SubstrateObserver::None).is_none());
        assert!(encode_substrate(b"vfsd", 1, SubstrateObserver::ProcessHandle(0)).is_none());
        assert!(encode_substrate(b"", 1, SubstrateObserver::None).is_none());
        let long = [b'n'; ipc::svcmgr_labels::NAME_MAX + 1];
        assert!(encode_substrate(&long, 1, SubstrateObserver::None).is_none());
    }

    // The observer word names how many caps the round carries; a disagreement
    // would bind an observer through a cap of the wrong kind, or none.
    #[test]
    fn substrate_whose_caps_disagree_with_its_observer_word_is_malformed()
    {
        let aspace = encode_substrate(b"memmgr", 0x51, SubstrateObserver::AddressSpace(0x52))
            .expect("encodes");
        let bare = encode_substrate(b"memmgr", 0x51, SubstrateObserver::None).expect("encodes");
        assert_eq!(
            decode_substrate(bare.caps(), aspace.data()),
            Err(DecodeError::Malformed)
        );
        assert_eq!(
            decode_substrate(aspace.caps(), bare.data()),
            Err(DecodeError::Malformed)
        );
        let mut data = [0u64; ROUND_DATA_WORDS];
        data[..aspace.data().len()].copy_from_slice(aspace.data());
        data[2] = 3;
        assert_eq!(
            decode_substrate(aspace.caps(), &data[..aspace.data().len()]),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn substrate_of_another_kind_or_short_of_words_is_malformed()
    {
        let round = encode_substrate(b"devmgr", 0x51, SubstrateObserver::None).expect("encodes");
        for words in 0..round.data().len()
        {
            assert_eq!(
                decode_substrate(round.caps(), &round.data()[..words]),
                Err(DecodeError::Malformed)
            );
        }
        let logd = encode_logd_sources(&LogdSources {
            master_log_source: 0x31,
            procmgr_death_auth_source: 0,
            kernel_log_source: 0,
        });
        assert_eq!(
            decode_substrate(logd.caps(), logd.data()),
            Err(DecodeError::Malformed)
        );
    }

    #[test]
    fn an_optional_cap_past_the_last_cap_slot_is_left_off_with_its_bit_clear()
    {
        let mut round = Round::new(&[kind::LOGD_SOURCES, 0]);
        for _ in 0..MSG_CAP_SLOTS_MAX
        {
            assert_eq!(round.push_optional(5, 1), 1);
        }
        assert_eq!(round.push_optional(6, 1), 0);
        assert_eq!(round.caps().len(), MSG_CAP_SLOTS_MAX);
    }
}
