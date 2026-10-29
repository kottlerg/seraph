// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/endowment/src/lib.rs

//! Wire codec for init's handover endowment of svcmgr.
//!
//! init serves the endowment over the bootstrap-round protocol and svcmgr
//! drains it; this crate owns the round kinds and the encoding of the two
//! rounds that carry optional source caps (`CAPS` and `LOGD_SOURCES`). The
//! kernel refuses a message carrying a null cap slot, so an absent source
//! cannot ride as a zero slot: each of these rounds lists only the caps
//! present, and a presence bitmap in a data word names which optional slot
//! each listed cap fills. The encoding is specified in
//! [services/svcmgr/docs/ipc-interface.md](../../docs/ipc-interface.md#handover-endowment-bootstrap-rounds).
//! The crate performs no IPC and issues no syscalls, so both sides of the
//! codec are host-tested (see
//! [coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

use syscall_abi::MSG_CAP_SLOTS_MAX;

/// Round kinds, tagged in `data[0]` of every endowment round.
pub mod kind
{
    /// svcmgr's own endpoints plus the publish-role source caps.
    pub const CAPS: u64 = 1;
    /// One substrate `(name, thread_cap)` registration.
    pub const SUBSTRATE: u64 = 2;
    /// Terminal round: the reserved log-sink sources svcmgr mints real-logd's
    /// bootstrap caps from on every (re)launch.
    pub const LOGD_SOURCES: u64 = 3;
}

/// Presence bits of the `CAPS` round's optional slots, in `data[2]`.
pub mod caps_present
{
    /// The SEND on the root filesystem's namespace endpoint (`rootfs.root`).
    pub const ROOTFS_ROOT: u64 = 1 << 0;
    /// The badge-0 `SEND|GRANT` source on devmgr's registry endpoint.
    pub const DEVMGR_REGISTRY: u64 = 1 << 1;
}

/// Presence bits of the `LOGD_SOURCES` round's slots, in `data[1]`.
pub mod logd_present
{
    /// The reserved master-log endpoint source.
    pub const MASTER_LOG: u64 = 1 << 0;
    /// The badge-0 `SEND|GRANT` source on procmgr's service endpoint.
    pub const PROCMGR_DEATH_AUTH: u64 = 1 << 1;
}

/// Data words an encoded round carries at most (`CAPS`: kind, version,
/// presence).
const ROUND_DATA_WORDS: usize = 3;

/// The caps of the `CAPS` round, by role. `0` marks an absent source cap;
/// the two endpoints are required and never `0` in a decoded round.
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

    /// Append `cap` to the cap list, unconditionally.
    fn push(&mut self, cap: u32)
    {
        self.caps[self.cap_count] = cap;
        self.cap_count += 1;
    }

    /// Append `cap` when it is present, and return `bit` for the presence
    /// bitmap, or `0` when it is absent.
    fn push_optional(&mut self, cap: u32, bit: u64) -> u64
    {
        if cap == 0
        {
            return 0;
        }
        self.push(cap);
        bit
    }
}

/// Why a received round does not decode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DecodeError
{
    /// The `CAPS` round's handshake word is missing or is not this build's
    /// `SVCMGR_LABELS_VERSION`.
    VersionMismatch,
    /// The round's kind, data words, or caps disagree with its encoding:
    /// a required cap or the presence word is missing, the bitmap sets a bit
    /// with no slot, or the bitmap names a different number of caps than
    /// the round delivered.
    Malformed,
}

/// Encode the `CAPS` round. `service_ep` and `bootstrap_ep` MUST be
/// non-zero (init derives both before it starts svcmgr); an optional source
/// of `0` is left off the cap list and its presence bit clear.
#[must_use]
pub fn encode_caps(caps: &CapsRound) -> Round
{
    let mut round = Round::new(&[kind::CAPS, u64::from(ipc::SVCMGR_LABELS_VERSION), 0]);
    round.push(caps.service_ep);
    round.push(caps.bootstrap_ep);
    let presence = round.push_optional(caps.rootfs_root, caps_present::ROOTFS_ROOT)
        | round.push_optional(caps.devmgr_registry, caps_present::DEVMGR_REGISTRY);
    round.data[2] = presence;
    round
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

/// Decode a received `CAPS` round from its delivered `caps` and its `data`
/// words.
///
/// # Errors
/// [`DecodeError::VersionMismatch`] when `data[1]` is missing or differs from
/// this build's `SVCMGR_LABELS_VERSION`; [`DecodeError::Malformed`] when the
/// kind is not `CAPS`, the presence word or a required endpoint is missing,
/// or the presence bitmap disagrees with the delivered caps.
pub fn decode_caps(caps: &[u32], data: &[u64]) -> Result<CapsRound, DecodeError>
{
    if data.first() != Some(&kind::CAPS)
    {
        return Err(DecodeError::Malformed);
    }
    if data.get(1) != Some(&u64::from(ipc::SVCMGR_LABELS_VERSION))
    {
        return Err(DecodeError::VersionMismatch);
    }
    let (Some(&presence), Some((required, optional))) = (data.get(2), caps.split_at_checked(2))
    else
    {
        return Err(DecodeError::Malformed);
    };
    let [rootfs_root, devmgr_registry] = take_optional::<2>(presence, optional)?;
    Ok(CapsRound {
        service_ep: required[0],
        bootstrap_ep: required[1],
        rootfs_root,
        devmgr_registry,
    })
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
    let [master_log_source, procmgr_death_auth_source] = take_optional::<2>(presence, caps)?;
    Ok(LogdSources {
        master_log_source,
        procmgr_death_auth_source,
    })
}

/// Spread the delivered optional `caps` over `N` slots by `presence`: slot
/// `i` takes the next cap when bit `i` is set and is `0` otherwise. Refuses
/// a bit at or above `N` and a bitmap naming a different number of caps
/// than were delivered.
fn take_optional<const N: usize>(presence: u64, caps: &[u32]) -> Result<[u32; N], DecodeError>
{
    if presence >> N != 0 || presence.count_ones() as usize != caps.len()
    {
        return Err(DecodeError::Malformed);
    }
    let mut slots = [0u32; N];
    let mut next = caps.iter();
    for (i, slot) in slots.iter_mut().enumerate()
    {
        if presence & (1 << i) != 0
        {
            *slot = next.next().copied().ok_or(DecodeError::Malformed)?;
        }
    }
    Ok(slots)
}

#[cfg(test)]
mod tests
{
    use super::*;

    const SERVICE: u32 = 0x11;
    const BOOTSTRAP: u32 = 0x12;

    fn caps_round(rootfs_root: u32, devmgr_registry: u32) -> CapsRound
    {
        CapsRound {
            service_ep: SERVICE,
            bootstrap_ep: BOOTSTRAP,
            rootfs_root,
            devmgr_registry,
        }
    }

    #[test]
    fn caps_round_trips_with_every_source_present_or_absent()
    {
        for (rootfs, devmgr) in [(0, 0), (0x21, 0), (0, 0x22), (0x21, 0x22)]
        {
            let sent = caps_round(rootfs, devmgr);
            let round = encode_caps(&sent);
            assert_eq!(decode_caps(round.caps(), round.data()), Ok(sent));
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
        assert_eq!(caps.caps(), &[SERVICE, BOOTSTRAP, 0x22]);
        assert_eq!(caps.data()[2], caps_present::DEVMGR_REGISTRY);

        let logd = encode_logd_sources(&LogdSources {
            master_log_source: 0x31,
            procmgr_death_auth_source: 0,
        });
        assert_eq!(logd.caps(), &[0x31]);
        assert_eq!(logd.data()[1], logd_present::MASTER_LOG);
    }

    #[test]
    fn caps_round_with_a_wrong_or_missing_version_is_refused()
    {
        let round = encode_caps(&caps_round(0x21, 0x22));
        let mut data = [0u64; ROUND_DATA_WORDS];
        data.copy_from_slice(round.data());
        data[1] = u64::from(ipc::SVCMGR_LABELS_VERSION) + 1;
        assert_eq!(decode_caps(round.caps(), &data), Err(DecodeError::VersionMismatch));
        assert_eq!(decode_caps(round.caps(), &data[..1]), Err(DecodeError::VersionMismatch));
    }

    #[test]
    fn caps_round_missing_its_presence_word_or_an_endpoint_is_malformed()
    {
        let round = encode_caps(&caps_round(0, 0));
        assert_eq!(decode_caps(round.caps(), &round.data()[..2]), Err(DecodeError::Malformed));
        assert_eq!(decode_caps(&round.caps()[..1], round.data()), Err(DecodeError::Malformed));
    }

    #[test]
    fn a_bitmap_naming_a_different_cap_count_is_malformed()
    {
        let both = encode_caps(&caps_round(0x21, 0x22));
        let one = encode_caps(&caps_round(0x21, 0));
        // Bitmap names two optional caps, one delivered; and the reverse.
        assert_eq!(decode_caps(one.caps(), both.data()), Err(DecodeError::Malformed));
        assert_eq!(decode_caps(both.caps(), one.data()), Err(DecodeError::Malformed));

        let none = encode_logd_sources(&LogdSources {
            master_log_source: 0,
            procmgr_death_auth_source: 0,
        });
        assert_eq!(decode_logd_sources(&[0x31], none.data()), Err(DecodeError::Malformed));
    }

    #[test]
    fn a_presence_bit_with_no_slot_is_malformed()
    {
        let data = [kind::LOGD_SOURCES, logd_present::MASTER_LOG | (1 << 2)];
        assert_eq!(decode_logd_sources(&[0x31, 0x32], &data), Err(DecodeError::Malformed));
    }

    #[test]
    fn a_round_of_another_kind_or_without_presence_word_is_malformed()
    {
        let caps = encode_caps(&caps_round(0, 0));
        assert_eq!(decode_logd_sources(caps.caps(), caps.data()), Err(DecodeError::Malformed));
        assert_eq!(decode_logd_sources(&[], &[kind::LOGD_SOURCES]), Err(DecodeError::Malformed));
        let logd = encode_logd_sources(&LogdSources {
            master_log_source: 0,
            procmgr_death_auth_source: 0,
        });
        assert_eq!(decode_caps(logd.caps(), logd.data()), Err(DecodeError::Malformed));
    }
}
