// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/svcmgr_labels.rs

//! IPC labels for the service manager (`svcmgr`).

// Under `rustc-dep-of-std` the crate is `no_core`, so this module, which
// defines functions, imports the prelude the crate root imports.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

/// The one name limit of the svcmgr protocol, in bytes: a service name
/// (a `.svc` file's stem and a `SUBSTRATE` round's name), a published
/// registry name, and a `PUBLISH_ENDPOINT` / `QUERY_ENDPOINT` name. Set
/// by the encoding, not by a pool: [`NAME_WORDS`] words beside the label
/// and the round header fit one message with room to spare, and every
/// holder stores a name at its own length or in one per-entry buffer.
/// The longest name in use is 15 bytes.
pub const NAME_MAX: usize = 64;

/// Data words a [`NAME_MAX`]-byte name occupies, packed by
/// [`pack_name`].
pub const NAME_WORDS: usize = NAME_MAX.div_ceil(8);

const _: () = core::assert!(NAME_WORDS + 2 <= super::MSG_DATA_WORDS_MAX);

/// Pack `name` into data words (byte `i` occupies bits `(i%8)*8..` of
/// word `i/8`), overwriting all of `out`, the encoding every svcmgr name
/// rides in. Returns the number of words used, or `None` (leaving `out`
/// zeroed) when `name` is longer than [`NAME_MAX`]; [`unpack_name`] is
/// its inverse.
#[must_use]
pub fn pack_name(name: &[u8], out: &mut [u64; NAME_WORDS]) -> Option<usize>
{
    *out = [0; NAME_WORDS];
    if name.len() > NAME_MAX
    {
        return None;
    }
    for (word, chunk) in out.iter_mut().zip(name.chunks(8))
    {
        *word = u64::from_le_bytes(crate::padded_word(chunk));
    }
    Some(name.len().div_ceil(8))
}

/// Unpack a `len`-byte name from `words` as [`pack_name`] packed it,
/// returning the name zero-padded to [`NAME_MAX`]. `None` when `len` is 0
/// or over [`NAME_MAX`], or `words` holds fewer than its words; the name
/// is wire input, so nothing is read past either bound.
#[must_use]
pub fn unpack_name(words: &[u64], len: usize) -> Option<[u8; NAME_MAX]>
{
    if len == 0 || len > NAME_MAX || words.len() < len.div_ceil(8)
    {
        return None;
    }
    let mut out = [0u8; NAME_MAX];
    for (chunk, word) in out.get_mut(..len)?.chunks_mut(8).zip(words)
    {
        for (byte, src) in chunk.iter_mut().zip(word.to_le_bytes())
        {
            *byte = src;
        }
    }
    Some(out)
}

// The services init started before svcmgr existed (memmgr, procmgr,
// devmgr, vfsd) are handed to svcmgr over init's bootstrap-round
// endowment, not a dedicated label (svcmgr launches logd itself, from
// its recipe). The `CAPS` rounds carry svcmgr's own endpoints plus the source
// caps it needs for its publish role (`rootfs.root` SEND,
// devmgr-registry `SEND|GRANT` source, `vfsd.mount`, `vfsd.deny`, and
// `vfsd.swap` SENDs), the `EntropyControl` source it gives the
// `entropy_authority` service a copy of, and `SVCMGR_LABELS_VERSION` in
// `data[1]`; each `SUBSTRATE` round carries one `(name, thread_cap, observer)`
// triple svcmgr parks in its pending-registration table; a final
// `LOGD_SOURCES` round carries the master-log and procmgr death-auth
// sources svcmgr launches logd with. On `HANDOVER_COMPLETE` svcmgr
// reconciles every parked name against `/config/svcmgr/services/`:
// a parked name with a definition is bound and supervised using the
// on-disk recipe; a defined name not parked is launched by svcmgr
// itself; a parked name with no definition is a hard error (svcmgr
// has no recipe to restart it). The round kinds and the encoding of
// the endowment are the `svcmgr-endowment` crate
// (`services/svcmgr/endowment`); see
// `services/svcmgr/docs/ipc-interface.md` and
// `services/svcmgr/docs/service-definitions.md` for the spec. The
// bootstrap rounds svcmgr serves each child it launches (the `seed` and
// `log_sink` rounds) split its positional slots into windows of
// `MSG_CAP_SLOTS_MAX`, one round each, carrying only the present caps
// and a presence word in `data[0]` (`bootstrap::slot_rounds` /
// `bootstrap::request_slots`); the endowment's `CAPS` slot list spans
// rounds the same way. That layout is part of this version.

/// Internal namespace-policy descriptor stored on `ServiceEntry`
/// (one of the values below). Parsed by svcmgr from each
/// service's `namespace = ...` line in `/config/svcmgr/services/<name>.svc`.
///
/// Namespace-policy descriptor: hand the child a `cap_copy` of
/// svcmgr's own root cap at full rights. Reserved for the services
/// that need genuine root authority; today the `terminal`, `svctest`,
/// and `usertest` recipes select it.
pub const NS_POLICY_UNIVERSAL: u8 = 0;
/// Namespace-policy descriptor: do not deliver any namespace
/// cap. The child's `ProcessInfo.system_root_cap` stays zero
/// (`Unsupported` on absolute-path fs ops in std). Default for
/// services that own only hardware / IPC authority and never
/// touch the filesystem.
pub const NS_POLICY_NONE: u8 = 1;
/// Namespace-policy descriptor: walk svcmgr's root for a
/// per-service path with a per-service rights mask, and hand
/// the resulting directory cap as the child's namespace root.
/// Path and rights come from the `namespace = subtree:<path>:<rights>`
/// line in `/config/svcmgr/services/<name>.svc` so attenuation survives a
/// crash-restart cycle.
pub const NS_POLICY_SUBTREE: u8 = 2;
/// Notification that init handover is complete. Honoured once, and
/// only from a caller whose badge carries [`HANDOVER_AUTHORITY`];
/// svcmgr replies [`svcmgr_errors::UNAUTHORIZED`] to any other caller
/// and to a repeat.
pub const HANDOVER_COMPLETE: u64 = 2;
/// Verb-bit authorising [`HANDOVER_COMPLETE`]. init alone mints it, on
/// a SEND it derives for the handover call and deletes after. Only
/// svcmgr and its trusted minters hold an unbadged SEND on svcmgr's
/// endpoint (init, and procmgr's per-child source), which is what keeps
/// the bit theirs: every other SEND on the endpoint is already badged (a
/// badge is set once) without it — devmgr's with [`PUBLISH_AUTHORITY`],
/// each stop-authority holder's with
/// [`crate::stop_labels::STOP_AUTHORITY`], the published
/// `svcmgr` name's with [`PUBLISHED_SEND_BADGE`], and each per-process
/// `service_registry_cap` with a process badge, which
/// [`VERB_BIT_MASK`](crate::VERB_BIT_MASK) keeps clear of verb bits.
pub const HANDOVER_AUTHORITY: u64 = 1u64 << 62;
/// Badge on the SEND svcmgr publishes on its own endpoint under the
/// `svcmgr` name: a fixed value with no verb bit, so a consumer can
/// `QUERY_ENDPOINT` through it but cannot re-badge it to mint
/// [`HANDOVER_AUTHORITY`], [`PUBLISH_AUTHORITY`] or
/// [`crate::stop_labels::STOP_AUTHORITY`].
pub const PUBLISHED_SEND_BADGE: u64 = 1;
const _: () = core::assert!(PUBLISHED_SEND_BADGE & crate::VERB_BIT_MASK == 0);
/// Publish a named endpoint into the discovery registry.
///
/// Label bits 16..31 carry `name_len`; data words from 0 carry the name
/// bytes packed little-endian. `caps[0]` is the endpoint the name
/// resolves to. The 16-bit field exceeds [`NAME_MAX`], so that
/// constant, not the field width, bounds a name.
pub const PUBLISH_ENDPOINT: u64 = 3;
/// Look up a named public endpoint; on success the reply carries a
/// freshly derived SEND cap.
///
/// Label bits 16..31 carry `name_len`; data words from 0 carry the name
/// bytes packed little-endian, as for [`PUBLISH_ENDPOINT`] ([`pack_name`]
/// is the reference encoder). Reply attaches a freshly derived SEND cap
/// on success. On failure it carries no cap and returns
/// `svcmgr_errors::INVALID_NAME` if `name_len` is 0 or exceeds
/// [`NAME_MAX`], or the message carries fewer data words than `name_len`
/// needs; `svcmgr_errors::UNKNOWN_NAME` on miss and for a seed-only name
/// (one whose cap carries authority, or
/// [`crate::published_names::VFSD_DENY`], svctest's test twin, which
/// carries none; a seed-only name reaches only the recipes seeding it;
/// see [`crate::published_names`]);
/// or `svcmgr_errors::INSUFFICIENT_CAPS` if svcmgr cannot derive a SEND
/// from the published endpoint, in which case it drops the entry, so a
/// later query of the name gets `UNKNOWN_NAME`.
pub const QUERY_ENDPOINT: u64 = 4;

/// Verb-bit carried by the caller's badge to authorise
/// [`PUBLISH_ENDPOINT`] by an *external* publisher (no per-publisher
/// identity in the low bits today — server-side auth is binary: have
/// the bit, or don't). svcmgr publishes the well-known names it owns
/// (those listed in `services/svcmgr/docs/ipc-interface.md` § Handover
/// endowment, each device class's `devmgr.class.<stem>` name, and each
/// provider's `provides` names) directly into its own registry, so those
/// need no badge. The gate exists for a future external publisher — devmgr
/// holds a `PUBLISH_AUTHORITY`-badged SEND from its bootstrap bundle,
/// reserved for driver registrations.
///
/// The SEND distributed to every process via
/// `ProcessInfo.service_registry_cap` carries the child's
/// per-process badge (no `PUBLISH_AUTHORITY` bit), so it is
/// accepted for `QUERY_ENDPOINT` only; svcmgr rejects publish
/// attempts whose badge lacks the bit with
/// [`svcmgr_errors::UNAUTHORIZED`]. See
/// `docs/capability-model.md` "verb-bit authority pattern" for
/// the rationale and parallel use in
/// `pwrmgr_labels::SHUTDOWN_AUTHORITY`.
///
/// Per-publisher attenuation (e.g. name-prefix restrictions in
/// the low badge bits, so a session daemon can publish only
/// `user.*`) is the future-work shape and the badge namespace
/// reserves it — see GitHub issue #76.
pub const PUBLISH_AUTHORITY: u64 = 1u64 << 63;

/// List the stop sources: the running services whose recipes set
/// `stop_source`, each with its class and a SEND on its service endpoint
/// badged with [`crate::stop_labels::STOP_AUTHORITY`], through which the
/// holder lists and stops that source's candidates. Served only on a badge
/// carrying that bit (`svcmgr_errors::UNAUTHORIZED` otherwise).
///
/// `data[0]` is the cursor: 0 starts the walk, and each reply's `data[1]`
/// is the cursor that resumes it. The reply carries the page's count in
/// `data[0]`, the next cursor in `data[1]`, then per entry
/// [`STOP_SOURCE_WORDS`] words: the class
/// ([`crate::stop_labels::CLASS_PROGRAM`]), the service name's length,
/// and the name's bytes ([`pack_stop_source`]); `caps[i]` is entry
/// `i`'s SEND. At most [`LIST_STOP_SOURCES_PAGE`] entries, and a page
/// shorter than that ends the walk. Specified in
/// `services/svcmgr/docs/ipc-interface.md` § Label 7: `LIST_STOP_SOURCES`.
pub const LIST_STOP_SOURCES: u64 = 7;

/// Data words one [`LIST_STOP_SOURCES`] entry takes: the class, the
/// name's length, and the name in [`NAME_MAX`] bytes.
pub const STOP_SOURCE_WORDS: usize = 2 + NAME_WORDS;

/// Data words of a [`LIST_STOP_SOURCES`] reply before its first entry:
/// the count and the next cursor.
pub const STOP_SOURCES_HEADER_WORDS: usize = 2;

/// Entries one [`LIST_STOP_SOURCES`] reply carries at most: one per cap
/// a message carries.
pub const LIST_STOP_SOURCES_PAGE: usize = super::MSG_CAP_SLOTS_MAX;

const _: () = core::assert!(
    STOP_SOURCES_HEADER_WORDS + LIST_STOP_SOURCES_PAGE * STOP_SOURCE_WORDS
        <= super::MSG_DATA_WORDS_MAX
);

/// Write entry `index` of a [`LIST_STOP_SOURCES`] reply into `words` (the
/// reply's data words, whose header the caller sets): the class, the
/// name's length, and the name's bytes as [`pack_name`] packs them,
/// zero-padded. Returns `false`, writing nothing, when `name` is empty or
/// longer than [`NAME_MAX`], or the entry does not fit `words`.
pub fn pack_stop_source(words: &mut [u64], index: usize, class: u64, name: &[u8]) -> bool
{
    let mut packed = [0; NAME_WORDS];
    if name.is_empty() || pack_name(name, &mut packed).is_none()
    {
        return false;
    }
    let Some([class_word, len_word, name_words @ ..]) = stop_source_base(index)
        .and_then(|base| words.get_mut(base..)?.get_mut(..STOP_SOURCE_WORDS))
    else
    {
        return false;
    };
    *class_word = class;
    *len_word = name.len() as u64;
    name_words.copy_from_slice(&packed);
    true
}

/// Read entry `index` of a [`LIST_STOP_SOURCES`] reply's data words
/// `words`: the class, and the name, zero-padded to [`NAME_MAX`], with its
/// length. `None` when `index` is past the reply's count or its words, or
/// the entry's length is 0 or past [`NAME_MAX`]; the reply is wire input,
/// so nothing is read past either bound.
#[must_use]
pub fn unpack_stop_source(words: &[u64], index: usize) -> Option<(u64, [u8; NAME_MAX], usize)>
{
    let count = usize::try_from(*words.first()?).ok()?;
    if index >= count
    {
        return None;
    }
    let [class, len_word, name_words @ ..] = words
        .get(stop_source_base(index)?..)?
        .get(..STOP_SOURCE_WORDS)?
    else
    {
        return None;
    };
    let len = usize::try_from(*len_word).ok()?;
    let name = unpack_name(name_words, len)?;
    Some((*class, name, len))
}

/// The first data word of entry `index` of a [`LIST_STOP_SOURCES`]
/// reply, past the header; `None` when it does not fit a `usize`.
fn stop_source_base(index: usize) -> Option<usize>
{
    index
        .checked_mul(STOP_SOURCE_WORDS)?
        .checked_add(STOP_SOURCES_HEADER_WORDS)
}

const _: () = core::assert!(
    crate::stop_labels::STOP_AUTHORITY != PUBLISH_AUTHORITY
        && crate::stop_labels::STOP_AUTHORITY != HANDOVER_AUTHORITY
);

#[cfg(test)]
mod tests
{
    use crate::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX, svcmgr_labels};

    #[test]
    fn a_stop_source_page_round_trips_and_holds_one_entry_per_cap()
    {
        use svcmgr_labels::{
            LIST_STOP_SOURCES_PAGE, NAME_MAX, STOP_SOURCE_WORDS, pack_stop_source,
            unpack_stop_source,
        };
        assert_eq!(LIST_STOP_SOURCES_PAGE, MSG_CAP_SLOTS_MAX);
        let long = [b'y'; NAME_MAX];
        let names: [&[u8]; 2] = [b"sessiond", &long];
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        for (i, name) in names.iter().enumerate()
        {
            assert!(pack_stop_source(&mut words, i, 1 + i as u64, name));
        }
        words[0] = names.len() as u64;
        for (i, name) in names.iter().enumerate()
        {
            let (class, out, len) = unpack_stop_source(&words, i).unwrap();
            assert_eq!((class, &out[..len]), (1 + i as u64, *name));
        }
        assert!(unpack_stop_source(&words, names.len()).is_none());
        assert!(!pack_stop_source(&mut words, 0, 1, b""));
        assert!(pack_stop_source(
            &mut words,
            LIST_STOP_SOURCES_PAGE - 1,
            1,
            b"a"
        ));
        // A claimed length past NAME_MAX is refused, and an index whose
        // offset overflows writes and reads nothing.
        words[0] = 1;
        words[3] = NAME_MAX as u64 + 1;
        assert!(unpack_stop_source(&words, 0).is_none());
        let index = usize::MAX / STOP_SOURCE_WORDS + 1;
        let mut empty = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_stop_source(&mut empty, index, 1, b"a"));
        assert_eq!(empty, [0; MSG_DATA_WORDS_MAX]);
        empty[0] = u64::MAX;
        assert!(unpack_stop_source(&empty, index).is_none());
    }

    #[test]
    fn svcmgr_name_round_trips_at_every_length_to_name_max()
    {
        use svcmgr_labels::{NAME_MAX, NAME_WORDS, pack_name, unpack_name};
        let source: [u8; NAME_MAX] = core::array::from_fn(|i| b'a' + (i % 26) as u8);
        for len in 1..=NAME_MAX
        {
            let mut words = [u64::MAX; NAME_WORDS];
            assert_eq!(pack_name(&source[..len], &mut words), Some(len.div_ceil(8)));
            let back = unpack_name(&words, len).expect("packed name unpacks");
            assert_eq!(&back[..len], &source[..len]);
            assert!(back[len..].iter().all(|&b| b == 0));
        }
    }

    #[test]
    fn svcmgr_name_codec_refuses_lengths_outside_one_to_name_max()
    {
        use svcmgr_labels::{NAME_MAX, NAME_WORDS, pack_name, unpack_name};
        let mut words = [u64::MAX; NAME_WORDS];
        assert_eq!(pack_name(&[b'a'; NAME_MAX + 1], &mut words), None);
        assert_eq!(words, [0; NAME_WORDS]);
        assert_eq!(unpack_name(&words, 0), None);
        assert_eq!(unpack_name(&words, NAME_MAX + 1), None);
        // A length whose words the message does not carry.
        assert_eq!(unpack_name(&words[..1], 9), None);
    }
}
