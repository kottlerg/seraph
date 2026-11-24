// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/store.rs

//! The trust store: the roots a system trusts, the key ids it refuses, and
//! the lowest security version it runs
//! ([docs/signing.md](../../../docs/signing.md) § Trust Store).
//!
//! [`TrustStore::parse`] checks the whole blob once and keeps borrowed
//! slices of it; a lookup decodes only the anchor it finds.

use crate::composite::PUBLIC_KEY_LEN;
use crate::wire::{Reader, Writer, concat};
use crate::{EncodeError, KEY_ID_LEN, KeyId, PublicKey, StoreError, Usage, key_id};

/// The magic the store begins with.
pub const MAGIC: [u8; 8] = *b"SRPHTRST";

/// The store format's version.
pub const VERSION: u16 = 2;

/// The length of the store's header.
pub const HEADER_LEN: usize = 18;

/// The length of an anchor's label field.
pub const LABEL_LEN: usize = 32;

/// The length of an anchor: its key, usage, flags and label, 2,024 bytes.
pub const ANCHOR_LEN: usize = PUBLIC_KEY_LEN + 4 + 4 + LABEL_LEN;

/// The anchor flag that marks a root generated on the build machine.
pub const FLAG_LOCAL: u32 = 1;

/// A trusted root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor<'a>
{
    /// The root's composite public key, borrowed from the store.
    pub key: &'a PublicKey,
    /// The key id of [`Self::key`], computed.
    pub key_id: KeyId,
    /// The roles the root may sign directly, and whether it may certify.
    pub usage: Usage,
    /// Whether the root was generated on the build machine (`LOCAL`).
    pub local: bool,
    /// The root's name.
    pub label: &'a str,
}

/// An anchor to encode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorSpec<'a>
{
    /// The root's composite public key.
    pub key: &'a PublicKey,
    /// The root's usage.
    pub usage: Usage,
    /// Whether the root was generated on the build machine.
    pub local: bool,
    /// The root's name: 1 to [`LABEL_LEN`] bytes of UTF-8, no NUL.
    pub label: &'a str,
}

/// A parsed trust store, borrowing the blob it was parsed from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustStore<'a>
{
    anchors: &'a [[u8; ANCHOR_LEN]],
    revoked: &'a [KeyId],
    security_floor: u32,
}

impl<'a> TrustStore<'a>
{
    /// Parse and check a whole trust store.
    ///
    /// # Errors
    ///
    /// The [`StoreError`] of the first rule `bytes` breaks, in the order
    /// the header, the length, each anchor, the anchors' order, the revoked
    /// key ids' order.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, StoreError>
    {
        let store = store_layout(bytes)?;
        let mut previous: Option<KeyId> = None;
        for raw in store.anchors
        {
            let (_, usage, flags, label) = anchor_parts(raw).ok_or(StoreError::Length)?;
            anchor_checks(usage, flags, label)?;
            previous = Some(in_order(previous, raw_key_id(raw))?);
        }
        if !ascending(store.revoked)
        {
            return Err(StoreError::RevokedOrder);
        }
        Ok(store)
    }

    /// The anchors, in key-id order.
    pub fn anchors(&self) -> impl Iterator<Item = Anchor<'a>> + use<'a>
    {
        let anchors: &'a [[u8; ANCHOR_LEN]] = self.anchors;
        anchors.iter().filter_map(|raw| decode_anchor(raw).ok())
    }

    /// The anchor whose key id is `id`.
    #[must_use]
    pub fn anchor(&self, id: &KeyId) -> Option<Anchor<'a>>
    {
        let index = self
            .anchors
            .binary_search_by(|raw| {
                anchor_key(raw).map_or(core::cmp::Ordering::Less, |key| key_id(key).cmp(id))
            })
            .ok()?;
        decode_anchor(self.anchors.get(index)?).ok()
    }

    /// Whether `id` is revoked.
    #[must_use]
    pub fn is_revoked(&self, id: &KeyId) -> bool
    {
        self.revoked.binary_search(id).is_ok()
    }

    /// The anchors' encodings, in key-id order.
    pub(crate) const fn raw_anchors(&self) -> &'a [[u8; ANCHOR_LEN]]
    {
        self.anchors
    }

    /// The revoked key ids, ascending.
    #[must_use]
    pub const fn revoked(&self) -> &'a [KeyId]
    {
        self.revoked
    }

    /// The lowest security version the system runs.
    #[must_use]
    pub const fn security_floor(&self) -> u32
    {
        self.security_floor
    }

    /// The length of a store of `anchors` anchors and `revoked` revoked key
    /// ids.
    ///
    /// # Errors
    ///
    /// `TooLong` when a count does not fit its `u16` field.
    pub fn encoded_len(anchors: usize, revoked: usize) -> Result<usize, EncodeError>
    {
        if u16::try_from(anchors).is_err() || u16::try_from(revoked).is_err()
        {
            return Err(EncodeError::TooLong);
        }
        anchors
            .checked_mul(ANCHOR_LEN)
            .and_then(|len| len.checked_add(HEADER_LEN))
            .and_then(|len| len.checked_add(revoked.checked_mul(KEY_ID_LEN)?))
            .ok_or(EncodeError::TooLong)
    }

    /// Encode a store at the start of `out`; returns its length.
    ///
    /// # Errors
    ///
    /// `Store` when there is no anchor, a label breaks the rule of
    /// [`AnchorSpec::label`], or the anchors or the revoked key ids are not
    /// sorted strictly ascending by key id; the errors of
    /// [`Self::encoded_len`]; `BufferTooSmall` when `out` is shorter than
    /// the encoding.
    pub fn encode(
        security_floor: u32,
        anchors: &[AnchorSpec<'_>],
        revoked: &[KeyId],
        out: &mut [u8],
    ) -> Result<usize, EncodeError>
    {
        let len = Self::encoded_len(anchors.len(), revoked.len())?;
        let anchor_count = u16::try_from(anchors.len()).map_err(|_| EncodeError::TooLong)?;
        let revoked_count = u16::try_from(revoked.len()).map_err(|_| EncodeError::TooLong)?;
        if anchor_count == 0
            || anchors.iter().any(|anchor| !label_is_valid(anchor.label))
            || anchors
                .windows(2)
                .any(|pair| matches!(pair, [a, b] if key_id(a.key) >= key_id(b.key)))
            || revoked
                .windows(2)
                .any(|pair| matches!(pair, [a, b] if a >= b))
        {
            return Err(EncodeError::Store);
        }
        let mut writer = Writer::new(out);
        writer.put(&MAGIC)?;
        writer.put(&VERSION.to_le_bytes())?;
        writer.put(&anchor_count.to_le_bytes())?;
        writer.put(&revoked_count.to_le_bytes())?;
        writer.put(&security_floor.to_le_bytes())?;
        for anchor in anchors
        {
            put_anchor(&mut writer, anchor)?;
        }
        for id in revoked
        {
            writer.put(id)?;
        }
        debug_assert_eq!(writer.len(), len, "the parts add up to encoded_len");
        Ok(len)
    }
}

/// Read a trust store's header and cut the blob into its anchors and its
/// revoked key ids: the store as its header lays it out, the anchors and the
/// revoked key ids not yet checked.
///
/// # Errors
///
/// `Length`, `Magic`, `Version` or `NoAnchor`, as [`TrustStore::parse`]
/// orders them.
pub(crate) fn store_layout(bytes: &[u8]) -> Result<TrustStore<'_>, StoreError>
{
    let mut reader = Reader::new(bytes);
    let magic = reader.array::<8>().ok_or(StoreError::Length)?;
    let version = reader.u16().ok_or(StoreError::Length)?;
    let anchor_count = reader.u16().ok_or(StoreError::Length)?;
    let revoked_count = reader.u16().ok_or(StoreError::Length)?;
    let security_floor = reader.u32().ok_or(StoreError::Length)?;
    if magic != MAGIC
    {
        return Err(StoreError::Magic);
    }
    if version != VERSION
    {
        return Err(StoreError::Version);
    }
    if anchor_count == 0
    {
        return Err(StoreError::NoAnchor);
    }
    let anchors_len = usize::from(anchor_count)
        .checked_mul(ANCHOR_LEN)
        .ok_or(StoreError::Length)?;
    let anchors = reader.take(anchors_len).ok_or(StoreError::Length)?;
    let revoked = reader.rest();
    if Some(revoked.len()) != usize::from(revoked_count).checked_mul(KEY_ID_LEN)
    {
        return Err(StoreError::Length);
    }
    let (anchors, _) = anchors.as_chunks::<ANCHOR_LEN>();
    let (revoked, _) = revoked.as_chunks::<KEY_ID_LEN>();
    Ok(TrustStore {
        anchors,
        revoked,
        security_floor,
    })
}

/// `id`, when it follows `previous`, the key id of the anchor before it, in
/// strictly ascending order.
///
/// # Errors
///
/// `AnchorOrder`.
pub(crate) fn in_order(previous: Option<KeyId>, id: KeyId) -> Result<KeyId, StoreError>
{
    if previous.is_some_and(|before| before >= id)
    {
        return Err(StoreError::AnchorOrder);
    }
    Ok(id)
}

/// Whether `ids` are sorted strictly ascending.
pub(crate) fn ascending(ids: &[KeyId]) -> bool
{
    !ids.windows(2).any(|pair| matches!(pair, [a, b] if a >= b))
}

/// The key id of an anchor's encoding.
pub(crate) fn raw_key_id(raw: &[u8; ANCHOR_LEN]) -> KeyId
{
    anchor_key(raw).map_or([0; KEY_ID_LEN], key_id)
}

/// Write the 2,024-byte encoding of `anchor`.
pub(crate) fn put_anchor(
    writer: &mut Writer<'_>,
    anchor: &AnchorSpec<'_>,
) -> Result<(), EncodeError>
{
    let flags = if anchor.local { FLAG_LOCAL } else { 0 };
    let label: [u8; LABEL_LEN] = concat(&[anchor.label.as_bytes()]);
    writer.put(anchor.key)?;
    writer.put(&anchor.usage.to_bits().to_le_bytes())?;
    writer.put(&flags.to_le_bytes())?;
    writer.put(&label)
}

/// Whether `label` is 1 to [`LABEL_LEN`] bytes with no NUL.
pub(crate) fn label_is_valid(label: &str) -> bool
{
    !label.is_empty() && label.len() <= LABEL_LEN && !label.as_bytes().contains(&0)
}

/// The key of an anchor's encoding: its first [`PUBLIC_KEY_LEN`] bytes,
/// which [`ANCHOR_LEN`] always holds.
pub(crate) fn anchor_key(raw: &[u8; ANCHOR_LEN]) -> Option<&PublicKey>
{
    raw.first_chunk::<PUBLIC_KEY_LEN>()
}

/// Decode and check one anchor: its fields cut ([`anchor_parts`]) and
/// checked ([`anchor_checks`]), and its key id.
pub(crate) fn decode_anchor(raw: &[u8; ANCHOR_LEN]) -> Result<Anchor<'_>, StoreError>
{
    let (key, usage, flags, label) = anchor_parts(raw).ok_or(StoreError::Length)?;
    let (usage, local, label) = anchor_checks(usage, flags, label)?;
    Ok(Anchor {
        key,
        key_id: key_id(key),
        usage,
        local,
        label,
    })
}

/// The fields of an anchor's encoding, cut where they lie: its key, its
/// usage and flags words, and its label field.
pub(crate) type AnchorParts<'a> = (&'a PublicKey, u32, u32, &'a [u8; LABEL_LEN]);

/// Cut an anchor's encoding into its fields. The reads cannot run short:
/// their lengths add up to [`ANCHOR_LEN`], so this is never `None`.
pub(crate) fn anchor_parts(raw: &[u8; ANCHOR_LEN]) -> Option<AnchorParts<'_>>
{
    let mut reader = Reader::new(raw);
    let key = reader.array_ref::<PUBLIC_KEY_LEN>()?;
    let usage = reader.u32()?;
    let flags = reader.u32()?;
    let label = reader.array_ref::<LABEL_LEN>()?;
    Some((key, usage, flags, label))
}

/// Check an anchor's usage and flags words and its label field
/// ([`LABEL_LEN`] bytes in an anchor; the check holds for a field of any
/// length); returns its usage, `LOCAL` flag and label: the text before the
/// field's NUL padding, of at least one byte, in UTF-8.
///
/// # Errors
///
/// `AnchorUsage`, `AnchorFlags`, then `Label`.
pub(crate) fn anchor_checks(
    usage: u32,
    flags: u32,
    label: &[u8],
) -> Result<(Usage, bool, &str), StoreError>
{
    let usage = Usage::from_bits(usage).ok_or(StoreError::AnchorUsage)?;
    if flags & !FLAG_LOCAL != 0
    {
        return Err(StoreError::AnchorFlags);
    }
    let end = label
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(label.len());
    let (text, padding) = label.split_at_checked(end).ok_or(StoreError::Label)?;
    if text.is_empty() || padding.iter().any(|&byte| byte != 0)
    {
        return Err(StoreError::Label);
    }
    let label = core::str::from_utf8(text).map_err(|_| StoreError::Label)?;
    Ok((usage, flags & FLAG_LOCAL != 0, label))
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::sync::OnceLock;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::{Role, RoleSet};

    const ROOT: Usage = Usage {
        roles: RoleSet::ALL,
        certify: true,
    };

    /// Three keys, sorted by key id.
    fn keys() -> &'static [PublicKey; 3]
    {
        static KEYS: OnceLock<[PublicKey; 3]> = OnceLock::new();
        KEYS.get_or_init(|| {
            let mut keys = [
                [1u8; PUBLIC_KEY_LEN],
                [2u8; PUBLIC_KEY_LEN],
                [3u8; PUBLIC_KEY_LEN],
            ];
            keys.sort_by_key(key_id);
            keys
        })
    }

    fn specs() -> Vec<AnchorSpec<'static>>
    {
        let [a, b, c] = keys();
        vec![
            AnchorSpec {
                key: a,
                usage: ROOT,
                local: true,
                label: "local root",
            },
            AnchorSpec {
                key: b,
                usage: Usage {
                    roles: RoleSet::of(&[Role::Program]),
                    certify: false,
                },
                local: false,
                label: "deployer programs ünï",
            },
            AnchorSpec {
                key: c,
                usage: ROOT,
                local: false,
                label: "abcdefghijklmnopqrstuvwxyz012345",
            },
        ]
    }

    fn revoked() -> Vec<KeyId>
    {
        let mut ids = vec![[9u8; 16], [7u8; 16]];
        ids.sort_unstable();
        ids
    }

    fn encode(floor: u32, anchors: &[AnchorSpec<'_>], revoked: &[KeyId]) -> Vec<u8>
    {
        let len = TrustStore::encoded_len(anchors.len(), revoked.len()).unwrap();
        let mut out = vec![0u8; len];
        assert_eq!(
            TrustStore::encode(floor, anchors, revoked, &mut out),
            Ok(len)
        );
        out
    }

    #[test]
    fn layout_matches_the_specification()
    {
        assert_eq!(ANCHOR_LEN, 2024);
        let specs = specs();
        let bytes = encode(0x0a0b_0c0d, &specs[..1], &revoked());
        assert_eq!(bytes.len(), 18 + 2024 + 2 * 16);
        assert_eq!(&bytes[0..8], b"SRPHTRST");
        assert_eq!(&bytes[8..10], &2u16.to_le_bytes());
        assert_eq!(&bytes[10..12], &1u16.to_le_bytes());
        assert_eq!(&bytes[12..14], &2u16.to_le_bytes());
        assert_eq!(&bytes[14..18], &0x0a0b_0c0du32.to_le_bytes());
        assert_eq!(&bytes[18..2002], &specs[0].key[..]);
        assert_eq!(&bytes[2002..2006], &(0x3feu32 | (1 << 31)).to_le_bytes());
        assert_eq!(&bytes[2006..2010], &1u32.to_le_bytes());
        assert_eq!(&bytes[2010..2020], b"local root");
        assert_eq!(&bytes[2020..2042], &[0u8; 22]);
        assert_eq!(&bytes[2042..2058], &revoked()[0]);
        assert_eq!(&bytes[2058..2074], &revoked()[1]);
    }

    #[test]
    fn round_trips_and_finds_by_key_id()
    {
        let specs = specs();
        let bytes = encode(5, &specs, &revoked());
        let store = TrustStore::parse(&bytes).unwrap();
        assert_eq!(store.security_floor(), 5);
        assert_eq!(store.revoked(), revoked().as_slice());
        let anchors: Vec<_> = store.anchors().collect();
        assert_eq!(anchors.len(), specs.len());
        for (anchor, spec) in anchors.iter().zip(&specs)
        {
            assert_eq!(anchor.key, spec.key);
            assert_eq!(anchor.key_id, key_id(spec.key));
            assert_eq!(anchor.usage, spec.usage);
            assert_eq!(anchor.local, spec.local);
            assert_eq!(anchor.label, spec.label);
            assert_eq!(store.anchor(&anchor.key_id), Some(*anchor));
        }
        assert_eq!(store.anchor(&[0u8; 16]), None);
        assert_eq!(store.anchor(&[0xffu8; 16]), None);
        for id in revoked()
        {
            assert!(store.is_revoked(&id));
        }
        assert!(!store.is_revoked(&anchors[0].key_id));

        let lone = encode(0, &specs[1..2], &[]);
        let store = TrustStore::parse(&lone).unwrap();
        assert_eq!(store.revoked(), &[] as &[KeyId]);
        assert_eq!(store.anchors().count(), 1);
    }

    #[test]
    fn refuses_each_malformed_field()
    {
        let good = encode(5, &specs(), &revoked());
        let refuse = |edit: &dyn Fn(&mut Vec<u8>), error| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            assert_eq!(TrustStore::parse(&bytes), Err(error));
        };
        let anchor = |index: usize, offset: usize| 18 + ANCHOR_LEN * index + offset;
        let usage = PUBLIC_KEY_LEN;
        let flags = usage + 4;
        let label = flags + 4;
        refuse(&|b| b.truncate(17), StoreError::Length);
        refuse(&|b| b.truncate(18), StoreError::Length);
        refuse(
            &|b| {
                b.pop();
            },
            StoreError::Length,
        );
        refuse(&|b| b.push(0), StoreError::Length);
        refuse(&|b| b[12] = 3, StoreError::Length);
        refuse(&|b| b[10] = 4, StoreError::Length);
        refuse(&|b| b[0] = b's', StoreError::Magic);
        // Version 1, the retired Ed25519 format, and a version not defined.
        refuse(&|b| b[8] = 1, StoreError::Version);
        refuse(&|b| b[8] = 3, StoreError::Version);
        refuse(&|b| b[10] = 0, StoreError::NoAnchor);
        refuse(&|b| b[anchor(1, usage)] |= 1, StoreError::AnchorUsage);
        // Bit 10, which no role has yet.
        refuse(&|b| b[anchor(1, usage + 1)] |= 4, StoreError::AnchorUsage);
        refuse(
            &|b| b[anchor(1, usage + 3)] |= 0x40,
            StoreError::AnchorUsage,
        );
        refuse(&|b| b[anchor(1, flags)] |= 2, StoreError::AnchorFlags);
        refuse(
            &|b| b[anchor(1, flags + 3)] |= 0x80,
            StoreError::AnchorFlags,
        );
        refuse(&|b| b[anchor(0, label)] = 0, StoreError::Label);
        refuse(&|b| b[anchor(0, ANCHOR_LEN - 1)] = b'x', StoreError::Label);
        refuse(&|b| b[anchor(0, label)] = 0xff, StoreError::Label);
        refuse(
            &|b| {
                let first = b[anchor(0, 0)..anchor(1, 0)].to_vec();
                b[anchor(1, 0)..anchor(2, 0)].copy_from_slice(&first);
            },
            StoreError::AnchorOrder,
        );
        refuse(
            &|b| {
                let first = b[anchor(0, 0)..anchor(1, 0)].to_vec();
                let second = b[anchor(1, 0)..anchor(2, 0)].to_vec();
                b[anchor(0, 0)..anchor(1, 0)].copy_from_slice(&second);
                b[anchor(1, 0)..anchor(2, 0)].copy_from_slice(&first);
            },
            StoreError::AnchorOrder,
        );
        let revoked_at = anchor(3, 0);
        refuse(
            &|b| {
                let first = b[revoked_at..revoked_at + 16].to_vec();
                b[revoked_at + 16..].copy_from_slice(&first);
            },
            StoreError::RevokedOrder,
        );
        refuse(
            &|b| {
                b[revoked_at..].rotate_left(16);
            },
            StoreError::RevokedOrder,
        );
    }

    #[test]
    fn encoder_refuses_what_the_parser_refuses()
    {
        let specs = specs();
        let refuse = |anchors: &[AnchorSpec<'_>], revoked: &[KeyId], error| {
            let mut out = vec![0u8; 18 + ANCHOR_LEN * 4 + 16 * 4];
            assert_eq!(
                TrustStore::encode(0, anchors, revoked, &mut out),
                Err(error)
            );
        };
        refuse(&[], &[], EncodeError::Store);
        for label in ["", "abcdefghijklmnopqrstuvwxyz0123456", "a\0b"]
        {
            refuse(&[AnchorSpec { label, ..specs[0] }], &[], EncodeError::Store);
        }
        refuse(&[specs[1], specs[0]], &[], EncodeError::Store);
        refuse(&[specs[0], specs[0]], &[], EncodeError::Store);
        let mut descending = revoked();
        descending.reverse();
        refuse(&specs, &descending, EncodeError::Store);
        refuse(&specs, &[[1; 16], [1; 16]], EncodeError::Store);
        let mut out = vec![0u8; 18 + ANCHOR_LEN * 3];
        assert_eq!(
            TrustStore::encode(0, &specs, &[], &mut out[..18 + ANCHOR_LEN * 3 - 1]),
            Err(EncodeError::BufferTooSmall)
        );
        assert_eq!(
            TrustStore::encoded_len(65_536, 0),
            Err(EncodeError::TooLong)
        );
        assert_eq!(
            TrustStore::encoded_len(1, 65_536),
            Err(EncodeError::TooLong)
        );
        assert_eq!(
            TrustStore::encoded_len(65_535, 65_535),
            Ok(18 + 2024 * 65_535 + 16 * 65_535)
        );
    }
}

/// Bounded proofs of the trust store's parse (docs/testing.md § Bounded
/// verification, Parser proofs), each on every input up to the bounds its
/// comment states.
///
/// How they compose into the property's check of [`TrustStore::parse`]
/// (`property::trust_store_holds`). The walk of the anchors is a loop whose
/// step is three functions in turn, its state the key id of the anchor
/// before: [`anchor_parts`] cuts an anchor into its fields, [`anchor_checks`]
/// checks them, and [`in_order`] takes its key id after the one before. It
/// is proven by induction: the layout proof shows that the walk starts on
/// the anchors and the revoked key ids the header gives, cut where they lie;
/// the cut, checks and order proofs run each part of the step on any input,
/// so whatever state a step hands the next, the next judges its anchor as
/// the reading does; and the ascending proof checks the revoked key ids the
/// walk ends on. What lies outside the proofs is `parse`, the loop that
/// drives the step and the check after it, and the key id each step is
/// given, the SHA-512 of the anchor's key ([`raw_key_id`]), which no proof
/// may stub (docs/coding-standards.md § Proof Harnesses); the fuzz target
/// `objsig`, the replay of the checked-in inputs and the unit tests check
/// them.
#[cfg(kani)]
mod proofs
{
    use super::ANCHOR_LEN;
    use crate::{KeyId, property};

    /// Every store of at most 2,059 bytes holds the layout's contract: 2,059
    /// bytes hold the header (18 bytes), an anchor (2,024), a revoked key id
    /// (16) and one byte more, so each refusal of the header, a length short
    /// of and past what the counts give, and a store laid out are reached.
    /// No loop: the lists are cut by length.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_store_lays_out_as_its_header_says()
    {
        let bytes: [u8; 2059] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::store_layout_holds(&bytes[..len]);
    }

    /// Every anchor is cut into its fields where they lie. No loop.
    #[kani::proof]
    fn every_anchor_is_cut_into_its_fields()
    {
        let raw: [u8; ANCHOR_LEN] = kani::any();
        let _ = property::anchor_parts_holds(&raw);
    }

    /// Every usage and flags word, and every label field of up to 8 bytes of
    /// any value, hold the checks' contract: each refusal, the empty label, a
    /// label filling its field and one before NUL padding, a NUL inside the
    /// text or the padding, and every UTF-8 sequence (at most 4 bytes) whole,
    /// cut by the field's end or broken, are reached. The checks read a
    /// field of any length alike, and an anchor's field of 32 bytes adds no
    /// case: each byte is judged alone or within its one sequence. The
    /// validation of UTF-8 over 32 bytes of any value is past what a proof
    /// finishes. The loops are the label's: its bytes are walked from the
    /// end, searched for a NUL and checked as UTF-8, each at most 8 steps.
    #[kani::proof]
    #[kani::unwind(10)]
    fn every_anchors_fields_are_checked_as_read()
    {
        let field: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= field.len());
        let _ = property::anchor_checks_holds(kani::any(), kani::any(), &field[..len]);
    }

    /// Every key id after any key id, or none, is judged in order as the
    /// reading does. No loop.
    #[kani::proof]
    fn every_key_id_is_judged_in_order()
    {
        let previous: Option<KeyId> = kani::any();
        let _ = property::in_order_holds(previous, kani::any());
    }

    /// Every list of up to 3 key ids is judged ascending as the reading
    /// does: 3 ids hold two neighbouring pairs, so an order broken at either
    /// pair, and by an equal pair, is reached.
    #[kani::proof]
    #[kani::unwind(17)]
    fn every_list_of_key_ids_is_judged_ascending()
    {
        let ids: [KeyId; 3] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= ids.len());
        let _ = property::ascending_holds(&ids[..len]);
    }
}
