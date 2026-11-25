// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/enrol.rs

//! The trust store enrolled in firmware storage, the change request that
//! alters it, and the effective store the two give with the store built into
//! the bootloader ([docs/signing.md](../../../docs/signing.md) § Trust Store).
//!
//! The bootloader keeps an [`EnrolledStore`] in a UEFI variable and changes it
//! only by applying a [`TrustRequest`] read from the ESP ([`apply`]). It verifies
//! the boot with, and hands procmgr, the built-in store merged with the
//! enrolled one ([`merge`]): the anchors united, the revoked key ids united, and
//! the built-in store's floor. A revoked key id beats an anchor from either
//! store, since the verifier refuses a record whose anchor or signing key is
//! revoked.
//!
//! Both formats are a header, anchors in the trust store's 2,024-byte layout
//! sorted strictly ascending by key id, and revoked key ids sorted the same
//! way, with no anchor's key id among the revoked ones.

use core::cmp::Ordering;

use crate::store::{
    ANCHOR_LEN, Anchor, AnchorSpec, TrustStore, anchor_checks, anchor_parts, ascending, decoded,
    in_order, label_is_valid, put_anchor, raw_key_id,
};
use crate::wire::{Reader, Writer};
use crate::{EncodeError, KEY_ID_LEN, KeyId, StoreError, key_id};

/// The magic an enrolled store begins with.
pub const STORE_MAGIC: [u8; 8] = *b"SRPHENRL";

/// The magic a change request begins with.
pub const REQUEST_MAGIC: [u8; 8] = *b"SRPHTREQ";

/// The version of both formats. A later layout, the enrolled store spread
/// over several variables among them, takes another.
pub const VERSION: u16 = 1;

/// The length of either format's header: magic, version, anchor count and
/// revoked count.
pub const HEADER_LEN: usize = 14;

/// The most anchors an enrolled store holds.
pub const MAX_ANCHORS: usize = 3;

/// The most revoked key ids an enrolled store holds.
pub const MAX_REVOKED: usize = 120;

/// The longest enrolled store, 8,006 bytes: under the 8,110 bytes of data
/// that the smallest firmware variable limit met so far (8,132 bytes of name
/// and data, the riscv64 EDK2's) leaves beside the variable's 22-byte name
/// (docs/signing.md § Trust Store).
pub const MAX_STORE_LEN: usize = HEADER_LEN + MAX_ANCHORS * ANCHOR_LEN + MAX_REVOKED * KEY_ID_LEN;

/// The name a change request is signed under, in the enrolment role: a
/// slot name, as the kernel's and init's are.
pub const REQUEST_NAME: &[u8] = b"trust-request";

/// Why an enrolled store or a change request does not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrolError
{
    /// The blob is shorter than its header, or not exactly as long as its
    /// header, anchors and revoked key ids.
    Length,
    /// The magic is not the format's.
    Magic,
    /// The version is not 1.
    Version,
    /// An anchor breaks a rule of the trust store's anchor
    /// (`AnchorUsage`, `AnchorFlags` or `Label`).
    Anchor(StoreError),
    /// The anchors are not sorted strictly ascending by key id.
    AnchorOrder,
    /// The revoked key ids are not sorted strictly ascending.
    RevokedOrder,
    /// An anchor's key id is also a revoked key id.
    RevokedAnchor,
    /// An enrolled store holds more than [`MAX_ANCHORS`] anchors or more than
    /// [`MAX_REVOKED`] revoked key ids.
    Bound,
}

/// The anchors and revoked key ids of a parsed blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Lists<'a>
{
    pub(crate) anchors: &'a [[u8; ANCHOR_LEN]],
    pub(crate) revoked: &'a [KeyId],
}

impl<'a> Lists<'a>
{
    /// Parse and check a blob of either format, begun by `magic`.
    fn parse(bytes: &'a [u8], magic: [u8; 8]) -> Result<Self, EnrolError>
    {
        let lists = lists_layout(bytes, magic)?;
        let mut previous: Option<KeyId> = None;
        for raw in lists.anchors
        {
            let (_, usage, flags, label) = anchor_parts(raw)
                .ok_or(StoreError::Length)
                .map_err(anchor_error)?;
            anchor_checks(usage, flags, label).map_err(anchor_error)?;
            previous = Some(in_order(previous, raw_key_id(raw)).map_err(anchor_error)?);
        }
        if !ascending(lists.revoked)
        {
            return Err(EnrolError::RevokedOrder);
        }
        if keyed(lists.anchors).any(|(id, _)| lists.is_revoked(&id))
        {
            return Err(EnrolError::RevokedAnchor);
        }
        Ok(lists)
    }

    fn anchors(&self) -> impl Iterator<Item = Anchor<'a>> + use<'a>
    {
        decoded(self.anchors)
    }

    fn anchor(&self, id: &KeyId) -> Option<Anchor<'a>>
    {
        self.anchors().find(|anchor| anchor.key_id == *id)
    }

    pub(crate) fn is_revoked(&self, id: &KeyId) -> bool
    {
        self.revoked.binary_search(id).is_ok()
    }
}

/// Read the header of a blob of either format, begun by `magic`, and cut
/// it into its anchors and its revoked key ids.
///
/// # Errors
///
/// `Length`, `Magic` or `Version`, as [`EnrolledStore::parse`] orders
/// them.
pub(crate) fn lists_layout(bytes: &[u8], magic: [u8; 8]) -> Result<Lists<'_>, EnrolError>
{
    let mut reader = Reader::new(bytes);
    let found = reader.array::<8>().ok_or(EnrolError::Length)?;
    let version = reader.u16().ok_or(EnrolError::Length)?;
    let anchor_count = reader.u16().ok_or(EnrolError::Length)?;
    let revoked_count = reader.u16().ok_or(EnrolError::Length)?;
    if found != magic
    {
        return Err(EnrolError::Magic);
    }
    if version != VERSION
    {
        return Err(EnrolError::Version);
    }
    let anchors_len = usize::from(anchor_count)
        .checked_mul(ANCHOR_LEN)
        .ok_or(EnrolError::Length)?;
    let anchors = reader.take(anchors_len).ok_or(EnrolError::Length)?;
    let revoked = reader.rest();
    if Some(revoked.len()) != usize::from(revoked_count).checked_mul(KEY_ID_LEN)
    {
        return Err(EnrolError::Length);
    }
    let (anchors, _) = anchors.as_chunks::<ANCHOR_LEN>();
    let (revoked, _) = revoked.as_chunks::<KEY_ID_LEN>();
    Ok(Lists { anchors, revoked })
}

/// The error of a blob of either format for the trust store's error of one
/// of its anchors ([`anchor_parts`], [`anchor_checks`], [`in_order`]).
pub(crate) fn anchor_error(error: StoreError) -> EnrolError
{
    if error == StoreError::AnchorOrder
    {
        EnrolError::AnchorOrder
    }
    else
    {
        EnrolError::Anchor(error)
    }
}

/// Whether an enrolled store of these lists holds at most [`MAX_ANCHORS`]
/// anchors and [`MAX_REVOKED`] revoked key ids.
pub(crate) const fn within_bound(lists: &Lists<'_>) -> bool
{
    lists.anchors.len() <= MAX_ANCHORS && lists.revoked.len() <= MAX_REVOKED
}

/// The anchors of `raw` with their key ids.
fn keyed(raw: &[[u8; ANCHOR_LEN]]) -> impl Iterator<Item = (KeyId, &[u8; ANCHOR_LEN])>
{
    raw.iter().map(|anchor| (raw_key_id(anchor), anchor))
}

/// Revoked key ids, each keyed by itself.
fn keyed_ids(ids: &[KeyId]) -> impl Iterator<Item = (KeyId, &KeyId)>
{
    ids.iter().map(|id| (*id, id))
}

/// The length of a blob of either format holding `anchors` anchors and
/// `revoked` revoked key ids.
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

/// Write a header of magic, version and the two counts: either format's
/// whole, the trust store's but for its floor.
fn put_header(
    writer: &mut Writer<'_>,
    (magic, version): ([u8; 8], u16),
    anchors: usize,
    revoked: usize,
) -> Result<(), EncodeError>
{
    let anchors = u16::try_from(anchors).map_err(|_| EncodeError::TooLong)?;
    let revoked = u16::try_from(revoked).map_err(|_| EncodeError::TooLong)?;
    writer.put(&magic)?;
    writer.put(&version.to_le_bytes())?;
    writer.put(&anchors.to_le_bytes())?;
    writer.put(&revoked.to_le_bytes())
}

/// Write a blob of either format; returns its length.
fn encode_lists(
    magic: [u8; 8],
    anchors: &[AnchorSpec<'_>],
    revoked: &[KeyId],
    out: &mut [u8],
) -> Result<usize, EncodeError>
{
    let len = encoded_len(anchors.len(), revoked.len())?;
    if anchors.iter().any(|anchor| !label_is_valid(anchor.label))
        || anchors
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if key_id(a.key) >= key_id(b.key)))
        || revoked
            .windows(2)
            .any(|pair| matches!(pair, [a, b] if a >= b))
        || anchors
            .iter()
            .any(|anchor| revoked.binary_search(&key_id(anchor.key)).is_ok())
    {
        return Err(EncodeError::Store);
    }
    let mut writer = Writer::new(out);
    put_header(&mut writer, (magic, VERSION), anchors.len(), revoked.len())?;
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

/// The trust store enrolled in firmware storage: the anchors and revoked key
/// ids requests have added, at most [`MAX_ANCHORS`] and [`MAX_REVOKED`]. It
/// carries no floor, and may hold no anchor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrolledStore<'a>
{
    lists: Lists<'a>,
}

impl<'a> EnrolledStore<'a>
{
    /// The store of a machine where nothing is enrolled.
    pub const EMPTY: EnrolledStore<'static> = EnrolledStore {
        lists: Lists {
            anchors: &[],
            revoked: &[],
        },
    };

    /// Parse and check a whole enrolled store.
    ///
    /// # Errors
    ///
    /// The [`EnrolError`] of the first rule `bytes` breaks, in the order the
    /// header, the length, each anchor, the anchors' order, the revoked key
    /// ids' order, an anchor revoked, the bound.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EnrolError>
    {
        let lists = Lists::parse(bytes, STORE_MAGIC)?;
        if !within_bound(&lists)
        {
            return Err(EnrolError::Bound);
        }
        Ok(Self { lists })
    }

    /// The anchors, in key-id order.
    pub fn anchors(&self) -> impl Iterator<Item = Anchor<'a>> + use<'a>
    {
        self.lists.anchors()
    }

    /// The anchor whose key id is `id`.
    #[must_use]
    pub fn anchor(&self, id: &KeyId) -> Option<Anchor<'a>>
    {
        self.lists.anchor(id)
    }

    /// Whether `id` is revoked.
    #[must_use]
    pub fn is_revoked(&self, id: &KeyId) -> bool
    {
        self.lists.is_revoked(id)
    }

    /// The revoked key ids, ascending.
    #[must_use]
    pub const fn revoked(&self) -> &'a [KeyId]
    {
        self.lists.revoked
    }

    /// Encode an enrolled store at the start of `out`; returns its length.
    ///
    /// # Errors
    ///
    /// `Store` when a count passes its bound, a label breaks the rule of
    /// [`AnchorSpec::label`], the anchors or the revoked key ids are not
    /// sorted strictly ascending by key id, or an anchor's key id is revoked;
    /// `BufferTooSmall` when `out` is shorter than the encoding.
    pub fn encode(
        anchors: &[AnchorSpec<'_>],
        revoked: &[KeyId],
        out: &mut [u8],
    ) -> Result<usize, EncodeError>
    {
        if anchors.len() > MAX_ANCHORS || revoked.len() > MAX_REVOKED
        {
            return Err(EncodeError::Store);
        }
        encode_lists(STORE_MAGIC, anchors, revoked, out)
    }
}

/// A change request: anchors to add and key ids to revoke. Removing a root
/// is revoking it. Signed in the enrolment role under [`REQUEST_NAME`], it is
/// applied with no one present; unsigned, only on a confirmation at the
/// console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustRequest<'a>
{
    lists: Lists<'a>,
}

impl<'a> TrustRequest<'a>
{
    /// Parse and check a whole change request: the body of a signed one, or
    /// the whole file of an unsigned one.
    ///
    /// # Errors
    ///
    /// The [`EnrolError`] of the first rule `bytes` breaks, in the order of
    /// [`EnrolledStore::parse`]; a request has no bound of its own.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EnrolError>
    {
        Ok(Self {
            lists: Lists::parse(bytes, REQUEST_MAGIC)?,
        })
    }

    /// The anchors to add, in key-id order.
    pub fn additions(&self) -> impl Iterator<Item = Anchor<'a>> + use<'a>
    {
        self.lists.anchors()
    }

    /// The key ids to revoke, ascending.
    #[must_use]
    pub const fn revocations(&self) -> &'a [KeyId]
    {
        self.lists.revoked
    }

    /// Encode a change request at the start of `out`; returns its length.
    ///
    /// # Errors
    ///
    /// As [`EnrolledStore::encode`], with no bound.
    pub fn encode(
        anchors: &[AnchorSpec<'_>],
        revoked: &[KeyId],
        out: &mut [u8],
    ) -> Result<usize, EncodeError>
    {
        encode_lists(REQUEST_MAGIC, anchors, revoked, out)
    }
}

/// Hand `sink` the union of two sequences sorted strictly ascending by key,
/// in key order, the item of `first` where both hold a key; returns the
/// number of items.
fn union<'x, const N: usize>(
    first: impl Iterator<Item = (KeyId, &'x [u8; N])>,
    second: impl Iterator<Item = (KeyId, &'x [u8; N])>,
    mut sink: impl FnMut(&[u8; N]) -> Result<(), EncodeError>,
) -> Result<usize, EncodeError>
{
    let mut first = first.peekable();
    let mut second = second.peekable();
    let mut count = 0usize;
    loop
    {
        let order = match (first.peek(), second.peek())
        {
            (None, None) => break,
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (Some((a, _)), Some((b, _))) => a.cmp(b),
        };
        let next = match order
        {
            Ordering::Less => first.next(),
            Ordering::Greater => second.next(),
            Ordering::Equal =>
            {
                second.next();
                first.next()
            }
        };
        if let Some((_, item)) = next
        {
            sink(item)?;
            count = count.saturating_add(1);
        }
    }
    Ok(count)
}

/// The number of anchors and of revoked key ids [`merge`] writes.
fn merged_counts(builtin: &TrustStore<'_>, enrolled: &EnrolledStore<'_>) -> (usize, usize)
{
    // A sink that only counts cannot fail.
    let anchors = union(
        keyed(builtin.raw_anchors()),
        keyed(enrolled.lists.anchors),
        |_| Ok(()),
    )
    .unwrap_or(0);
    let revoked = union(
        keyed_ids(builtin.revoked()),
        keyed_ids(enrolled.revoked()),
        |_| Ok(()),
    )
    .unwrap_or(0);
    (anchors, revoked)
}

/// The length of the trust store [`merge`] writes.
///
/// # Errors
///
/// The errors of [`TrustStore::encoded_len`].
pub fn merged_len(
    builtin: &TrustStore<'_>,
    enrolled: &EnrolledStore<'_>,
) -> Result<usize, EncodeError>
{
    let (anchors, revoked) = merged_counts(builtin, enrolled);
    TrustStore::encoded_len(anchors, revoked)
}

/// Merge the built-in store with the enrolled one into a trust store at the
/// start of `out`; returns its length. Its anchors are both stores' (the
/// built-in anchor kept where both hold a key id), its revoked key ids both
/// stores', and its floor the built-in store's. It is the store the
/// bootloader verifies with and hands procmgr.
///
/// # Errors
///
/// The errors of [`TrustStore::encoded_len`]; `BufferTooSmall` when `out` is
/// shorter than [`merged_len`].
pub fn merge(
    builtin: &TrustStore<'_>,
    enrolled: &EnrolledStore<'_>,
    out: &mut [u8],
) -> Result<usize, EncodeError>
{
    let (anchors, revoked) = merged_counts(builtin, enrolled);
    let len = TrustStore::encoded_len(anchors, revoked)?;
    let mut writer = Writer::new(out);
    put_header(
        &mut writer,
        (crate::store::MAGIC, crate::store::VERSION),
        anchors,
        revoked,
    )?;
    // The trust store's header holds the floor after the counts.
    writer.put(&builtin.security_floor().to_le_bytes())?;
    union(
        keyed(builtin.raw_anchors()),
        keyed(enrolled.lists.anchors),
        |anchor| writer.put(anchor),
    )?;
    union(
        keyed_ids(builtin.revoked()),
        keyed_ids(enrolled.revoked()),
        |id| writer.put(id),
    )?;
    debug_assert_eq!(writer.len(), len, "the parts add up to merged_len");
    Ok(len)
}

/// What [`apply`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Applied
{
    /// The request would change nothing: every anchor it adds is already
    /// an anchor or revoked, and every key id it revokes already revoked by
    /// the enrolled store. A replayed request is one. Nothing was written.
    Unchanged,
    /// The new enrolled store was written.
    Changed
    {
        /// Its length.
        len: usize,
        /// The anchors added.
        added: usize,
        /// The enrolled anchors removed, each revoked.
        removed: usize,
        /// The key ids newly revoked.
        revoked: usize,
    },
}

/// Why [`apply`] refused a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyError
{
    /// The enrolled store would hold more than [`MAX_ANCHORS`] anchors or more
    /// than [`MAX_REVOKED`] revoked key ids; the counts it would hold.
    Bound
    {
        /// The anchors it would hold.
        anchors: usize,
        /// The revoked key ids it would hold.
        revoked: usize,
    },
    /// `out` is shorter than the new store.
    Encode(EncodeError),
}

/// Apply `request` to `enrolled`, writing the new enrolled store at the
/// start of `out` ([`MAX_STORE_LEN`] bytes always suffice).
///
/// An anchor is added unless the built-in or the enrolled store already
/// holds its key id as an anchor, or either has revoked it: a revoked key id
/// is never enrolled again, so a replayed request changes nothing. A key id
/// the enrolled store has not revoked is revoked, and an enrolled anchor with
/// that id leaves the store, its id staying revoked. Authorizing the request
/// and the commit rule are the caller's.
///
/// # Errors
///
/// `Bound` when the new store would pass the bound, so the request is refused
/// whole; `Encode` when `out` is too short.
pub fn apply(
    builtin: &TrustStore<'_>,
    enrolled: &EnrolledStore<'_>,
    request: &TrustRequest<'_>,
    out: &mut [u8],
) -> Result<Applied, ApplyError>
{
    let kept = || keyed(enrolled.lists.anchors).filter(|(id, _)| !request.lists.is_revoked(id));
    let added = || {
        keyed(request.lists.anchors).filter(|(id, _)| {
            builtin.anchor(id).is_none()
                && enrolled.anchor(id).is_none()
                && !builtin.is_revoked(id)
                && !enrolled.is_revoked(id)
        })
    };
    let newly_revoked =
        || keyed_ids(request.lists.revoked).filter(|(id, _)| !enrolled.is_revoked(id));

    let kept_count = kept().count();
    let added_count = added().count();
    let revoked_count = newly_revoked().count();
    let removed_count = enrolled.lists.anchors.len().saturating_sub(kept_count);
    if added_count == 0 && removed_count == 0 && revoked_count == 0
    {
        return Ok(Applied::Unchanged);
    }
    let anchors = kept_count.saturating_add(added_count);
    let revoked = enrolled.lists.revoked.len().saturating_add(revoked_count);
    if anchors > MAX_ANCHORS || revoked > MAX_REVOKED
    {
        return Err(ApplyError::Bound { anchors, revoked });
    }
    let len = encoded_len(anchors, revoked).map_err(ApplyError::Encode)?;
    let mut writer = Writer::new(out);
    let mut write = || -> Result<(), EncodeError> {
        put_header(&mut writer, (STORE_MAGIC, VERSION), anchors, revoked)?;
        union(kept(), added(), |anchor| writer.put(anchor))?;
        union(keyed_ids(enrolled.lists.revoked), newly_revoked(), |id| {
            writer.put(id)
        })?;
        Ok(())
    };
    write().map_err(ApplyError::Encode)?;
    debug_assert_eq!(writer.len(), len, "the parts add up to encoded_len");
    Ok(Applied::Changed {
        len,
        added: added_count,
        removed: removed_count,
        revoked: revoked_count,
    })
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::composite::PUBLIC_KEY_LEN;
    use crate::testutil::{Key, ROOT, attrs, keys, object, record, store};
    use crate::verify::{Expectation, RecordFailure, Refusal, verify};
    use crate::{Arch, PublicKey, Role, RoleSet, Usage};

    /// Five keys that need not be valid, sorted by key id.
    fn fake_keys() -> &'static [PublicKey; 5]
    {
        static KEYS: std::sync::OnceLock<[PublicKey; 5]> = std::sync::OnceLock::new();
        KEYS.get_or_init(|| {
            let mut keys = [1u8, 2, 3, 4, 5].map(|byte| [byte; PUBLIC_KEY_LEN]);
            keys.sort_by_key(key_id);
            keys
        })
    }

    fn spec(key: &PublicKey) -> AnchorSpec<'_>
    {
        AnchorSpec {
            key,
            usage: ROOT,
            local: false,
            label: "enrolled root",
        }
    }

    fn sorted(mut ids: Vec<KeyId>) -> Vec<KeyId>
    {
        ids.sort_unstable();
        ids
    }

    fn enrolled_bytes(anchors: &[AnchorSpec<'_>], revoked: &[KeyId]) -> Vec<u8>
    {
        let mut out = vec![0u8; encoded_len(anchors.len(), revoked.len()).unwrap()];
        let len = EnrolledStore::encode(anchors, revoked, &mut out).unwrap();
        assert_eq!(len, out.len());
        out
    }

    fn request_bytes(anchors: &[AnchorSpec<'_>], revoked: &[KeyId]) -> Vec<u8>
    {
        let mut out = vec![0u8; encoded_len(anchors.len(), revoked.len()).unwrap()];
        let len = TrustRequest::encode(anchors, revoked, &mut out).unwrap();
        assert_eq!(len, out.len());
        out
    }

    fn ids(count: u16, fill: u8) -> Vec<KeyId>
    {
        (0..count)
            .map(|n| {
                let mut id = [fill; 16];
                id[..2].copy_from_slice(&n.to_be_bytes());
                id
            })
            .collect()
    }

    #[test]
    fn layout_matches_the_specification()
    {
        assert_eq!(MAX_STORE_LEN, 8006);
        let [a, ..] = fake_keys();
        let revoked = sorted(vec![[9; 16], [7; 16]]);
        for (magic, bytes) in [
            (b"SRPHENRL", enrolled_bytes(&[spec(a)], &revoked)),
            (b"SRPHTREQ", request_bytes(&[spec(a)], &revoked)),
        ]
        {
            assert_eq!(bytes.len(), 14 + 2024 + 2 * 16);
            assert_eq!(&bytes[0..8], magic);
            assert_eq!(&bytes[8..10], &1u16.to_le_bytes());
            assert_eq!(&bytes[10..12], &1u16.to_le_bytes());
            assert_eq!(&bytes[12..14], &2u16.to_le_bytes());
            assert_eq!(&bytes[14..1998], &a[..]);
            assert_eq!(&bytes[1998..2002], &(0x3feu32 | (1 << 31)).to_le_bytes());
            assert_eq!(&bytes[2002..2006], &0u32.to_le_bytes());
            assert_eq!(&bytes[2006..2019], b"enrolled root");
            assert_eq!(&bytes[2038..2054], &revoked[0]);
            assert_eq!(&bytes[2054..2070], &revoked[1]);
        }
    }

    #[test]
    fn round_trips_and_allows_no_anchor()
    {
        let [a, b, ..] = fake_keys();
        let revoked = sorted(vec![[9; 16], [7; 16]]);
        let bytes = enrolled_bytes(&[spec(a), spec(b)], &revoked);
        let store = EnrolledStore::parse(&bytes).unwrap();
        let anchors: Vec<_> = store.anchors().collect();
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].key, a);
        assert_eq!(anchors[1].key, b);
        assert_eq!(store.anchor(&key_id(b)), Some(anchors[1]));
        assert_eq!(store.anchor(&[9; 16]), None);
        assert_eq!(store.revoked(), revoked.as_slice());
        assert!(store.is_revoked(&[7; 16]));
        assert!(!store.is_revoked(&key_id(a)));

        let empty = enrolled_bytes(&[], &[]);
        assert_eq!(empty.len(), HEADER_LEN);
        assert_eq!(EnrolledStore::parse(&empty), Ok(EnrolledStore::EMPTY));

        let bytes = request_bytes(&[spec(b)], &revoked);
        let request = TrustRequest::parse(&bytes).unwrap();
        assert_eq!(request.additions().map(|a| a.key).collect::<Vec<_>>(), [b]);
        assert_eq!(request.revocations(), revoked.as_slice());
    }

    #[test]
    fn refuses_each_malformed_field()
    {
        let [a, b, ..] = fake_keys();
        let revoked = sorted(vec![[9; 16], [7; 16]]);
        let good = enrolled_bytes(&[spec(a), spec(b)], &revoked);
        let refuse = |edit: &dyn Fn(&mut Vec<u8>), error| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            assert_eq!(EnrolledStore::parse(&bytes), Err(error));
            bytes[..8].copy_from_slice(&REQUEST_MAGIC);
            assert_eq!(TrustRequest::parse(&bytes).map(|_| ()), Err(error));
        };
        let anchor = |index: usize, offset: usize| 14 + ANCHOR_LEN * index + offset;
        let usage = PUBLIC_KEY_LEN;
        refuse(&|b| b.truncate(13), EnrolError::Length);
        refuse(
            &|b| {
                b.pop();
            },
            EnrolError::Length,
        );
        refuse(&|b| b.push(0), EnrolError::Length);
        refuse(&|b| b[10] = 3, EnrolError::Length);
        refuse(&|b| b[8] = 2, EnrolError::Version);
        refuse(&|b| b[8] = 0, EnrolError::Version);
        // Bit 10, which no role has.
        refuse(
            &|b| b[anchor(1, usage + 1)] |= 4,
            EnrolError::Anchor(StoreError::AnchorUsage),
        );
        refuse(
            &|b| b[anchor(0, usage + 4)] |= 2,
            EnrolError::Anchor(StoreError::AnchorFlags),
        );
        refuse(
            &|b| b[anchor(0, usage + 8)] = 0,
            EnrolError::Anchor(StoreError::Label),
        );
        refuse(
            &|b| {
                let first = b[anchor(0, 0)..anchor(1, 0)].to_vec();
                b[anchor(1, 0)..anchor(2, 0)].copy_from_slice(&first);
            },
            EnrolError::AnchorOrder,
        );
        let revoked_at = anchor(2, 0);
        refuse(
            &|b| b[revoked_at..].rotate_left(16),
            EnrolError::RevokedOrder,
        );
        // An anchor's own key id among the revoked ones.
        refuse(
            &|b| {
                let both = sorted(vec![key_id(a), revoked[1]]);
                b[revoked_at..revoked_at + 16].copy_from_slice(&both[0]);
                b[revoked_at + 16..].copy_from_slice(&both[1]);
            },
            EnrolError::RevokedAnchor,
        );

        // Each magic is the other format's refusal, and the trust store's
        // is neither.
        let mut request = good.clone();
        request[..8].copy_from_slice(&REQUEST_MAGIC);
        assert_eq!(EnrolledStore::parse(&request), Err(EnrolError::Magic));
        assert_eq!(
            TrustRequest::parse(&good).map(|_| ()),
            Err(EnrolError::Magic)
        );
        let mut trust_store = good.clone();
        trust_store[..8].copy_from_slice(b"SRPHTRST");
        assert_eq!(EnrolledStore::parse(&trust_store), Err(EnrolError::Magic));
    }

    #[test]
    fn an_enrolled_store_past_the_bound_is_refused_and_a_request_is_not()
    {
        let four: Vec<_> = fake_keys()[..4].iter().map(spec).collect();
        EnrolledStore::parse(&enrolled_bytes(&four[..3], &[])).unwrap();
        let many = ids(121, 0);
        let mut out = vec![0u8; encoded_len(4, 121).unwrap()];
        assert_eq!(
            EnrolledStore::encode(&four, &[], &mut out),
            Err(EncodeError::Store)
        );
        assert_eq!(
            EnrolledStore::encode(&[], &many, &mut out),
            Err(EncodeError::Store)
        );
        EnrolledStore::encode(&[], &many[..120], &mut out).unwrap();

        let over_anchors = request_bytes(&four, &[]);
        let over_revoked = request_bytes(&[], &many);
        TrustRequest::parse(&over_anchors).unwrap();
        TrustRequest::parse(&over_revoked).unwrap();
        for mut bytes in [over_anchors, over_revoked]
        {
            bytes[..8].copy_from_slice(&STORE_MAGIC);
            assert_eq!(EnrolledStore::parse(&bytes), Err(EnrolError::Bound));
        }
    }

    #[test]
    fn encoder_refuses_what_the_parser_refuses()
    {
        let [a, b, ..] = fake_keys();
        let refuse = |anchors: &[AnchorSpec<'_>], revoked: &[KeyId]| {
            let mut out = vec![0u8; encoded_len(3, 3).unwrap()];
            assert_eq!(
                EnrolledStore::encode(anchors, revoked, &mut out),
                Err(EncodeError::Store)
            );
            assert_eq!(
                TrustRequest::encode(anchors, revoked, &mut out),
                Err(EncodeError::Store)
            );
        };
        for label in ["", "abcdefghijklmnopqrstuvwxyz0123456", "a\0b"]
        {
            refuse(&[AnchorSpec { label, ..spec(a) }], &[]);
        }
        refuse(&[spec(b), spec(a)], &[]);
        refuse(&[spec(a), spec(a)], &[]);
        refuse(&[], &[[2; 16], [1; 16]]);
        refuse(&[], &[[1; 16], [1; 16]]);
        refuse(&[spec(a)], &[key_id(a)]);
        let mut out = vec![0u8; HEADER_LEN + ANCHOR_LEN - 1];
        assert_eq!(
            TrustRequest::encode(&[spec(a)], &[], &mut out),
            Err(EncodeError::BufferTooSmall)
        );
        assert_eq!(encoded_len(65_536, 0), Err(EncodeError::TooLong));
        assert_eq!(encoded_len(0, 65_536), Err(EncodeError::TooLong));
    }

    /// A kernel image signed by `key`.
    fn kernel(key: &Key) -> Vec<u8>
    {
        let body = b"kernel image";
        object(
            body,
            &[record(
                key,
                None,
                attrs(body, &[Role::Kernel], b"kernel", 3),
            )],
        )
    }

    const KERNEL: Expectation<'static> = Expectation {
        roles: RoleSet::of(&[Role::Kernel]),
        name: b"kernel",
        arch: Arch::X86_64,
    };

    fn merged(builtin: &TrustStore<'_>, enrolled: &[u8]) -> Vec<u8>
    {
        let enrolled = EnrolledStore::parse(enrolled).unwrap();
        let mut out = vec![0u8; merged_len(builtin, &enrolled).unwrap()];
        assert_eq!(merge(builtin, &enrolled, &mut out), Ok(out.len()));
        out
    }

    // Defect guarded: an enrolled anchor that does not verify the boot, a
    // revocation from the enrolled store that the built-in anchor survives,
    // or a merged floor other than the built-in one.
    #[test]
    fn the_merged_store_unites_both_and_a_revocation_beats_an_anchor()
    {
        let k = keys();
        let builtin_bytes = store(3, &[(&k.root, ROOT)], &[[7; 16]]);
        let builtin = TrustStore::parse(&builtin_bytes).unwrap();

        let bytes = merged(
            &builtin,
            &enrolled_bytes(&[spec(&k.second_root.public)], &[[5; 16]]),
        );
        let store = TrustStore::parse(&bytes).unwrap();
        assert_eq!(store.security_floor(), 3);
        assert_eq!(store.anchors().count(), 2);
        assert!(store.anchor(&k.root.id()).is_some());
        assert!(store.anchor(&k.second_root.id()).is_some());
        assert_eq!(store.revoked(), &[[5; 16], [7; 16]]);
        verify(&kernel(&k.root), &store, &KERNEL).unwrap();
        verify(&kernel(&k.second_root), &store, &KERNEL).unwrap();
        assert_eq!(
            verify(&kernel(&k.stranger), &store, &KERNEL).map(|_| ()),
            Err(Refusal::Untrusted)
        );

        // The enrolled store revokes the built-in root: its kernel is
        // refused, the enrolled root's still verifies.
        let bytes = merged(
            &builtin,
            &enrolled_bytes(&[spec(&k.second_root.public)], &[k.root.id()]),
        );
        let store = TrustStore::parse(&bytes).unwrap();
        assert_eq!(
            verify(&kernel(&k.root), &store, &KERNEL).map(|_| ()),
            Err(Refusal::Failed(RecordFailure::Revoked))
        );
        verify(&kernel(&k.second_root), &store, &KERNEL).unwrap();

        // A key id both hold: one anchor, the built-in one.
        let narrow = AnchorSpec {
            usage: Usage {
                roles: RoleSet::of(&[Role::Data]),
                certify: false,
            },
            ..spec(&k.root.public)
        };
        let bytes = merged(&builtin, &enrolled_bytes(&[narrow], &[[7; 16]]));
        let store = TrustStore::parse(&bytes).unwrap();
        assert_eq!(store.anchors().count(), 1);
        assert_eq!(store.anchor(&k.root.id()).map(|a| a.usage), Some(ROOT));
        assert_eq!(store.revoked(), &[[7; 16]]);

        // Nothing enrolled: the built-in store, byte for byte.
        let mut out = merged(&builtin, &enrolled_bytes(&[], &[]));
        assert_eq!(out, builtin_bytes);
        assert_eq!(
            merge(&builtin, &EnrolledStore::EMPTY, &mut out[..17]),
            Err(EncodeError::BufferTooSmall)
        );
    }

    fn applied(
        builtin: &TrustStore<'_>,
        enrolled: &[u8],
        request: &[u8],
    ) -> (Result<Applied, ApplyError>, Vec<u8>)
    {
        let enrolled = EnrolledStore::parse(enrolled).unwrap();
        let request = TrustRequest::parse(request).unwrap();
        let mut out = vec![0u8; MAX_STORE_LEN];
        let result = apply(builtin, &enrolled, &request, &mut out);
        if let Ok(Applied::Changed { len, .. }) = result
        {
            out.truncate(len);
            EnrolledStore::parse(&out).unwrap();
        }
        else
        {
            out.clear();
        }
        (result, out)
    }

    // Defect guarded: a replayed request that changes the store, a revoked
    // key id enrolled again, a revoked enrolled anchor left in the anchor
    // area, or a request past the bound applied in part.
    #[test]
    fn a_request_adds_revokes_and_never_enrols_a_revoked_id()
    {
        let [k1, k2, k3, k4, k5] = fake_keys();
        let root = keys().root.id();
        let builtin_bytes = store(0, &[(&keys().root, ROOT)], &[key_id(k5)]);
        let builtin = TrustStore::parse(&builtin_bytes).unwrap();
        let empty = enrolled_bytes(&[], &[]);

        // Adding a root.
        let add_a = request_bytes(&[spec(k1)], &[]);
        let (result, one) = applied(&builtin, &empty, &add_a);
        assert_eq!(
            result,
            Ok(Applied::Changed {
                len: HEADER_LEN + ANCHOR_LEN,
                added: 1,
                removed: 0,
                revoked: 0
            })
        );
        assert_eq!(one, enrolled_bytes(&[spec(k1)], &[]));
        // The same request again changes nothing, nor does adding the
        // built-in root, a key id the built-in store revokes, or nothing.
        for request in [
            add_a.clone(),
            request_bytes(&[spec(&keys().root.public)], &[]),
            request_bytes(&[spec(k5)], &[]),
            request_bytes(&[], &[]),
        ]
        {
            assert_eq!(applied(&builtin, &one, &request).0, Ok(Applied::Unchanged));
        }

        // Revoking the enrolled root removes it and keeps its id revoked.
        let revoke_a = request_bytes(&[], &[key_id(k1)]);
        let (result, none) = applied(&builtin, &one, &revoke_a);
        assert_eq!(
            result,
            Ok(Applied::Changed {
                len: HEADER_LEN + 16,
                added: 0,
                removed: 1,
                revoked: 1
            })
        );
        assert_eq!(none, enrolled_bytes(&[], &[key_id(k1)]));
        assert_eq!(
            applied(&builtin, &none, &revoke_a).0,
            Ok(Applied::Unchanged)
        );
        // It is never enrolled again.
        assert_eq!(applied(&builtin, &none, &add_a).0, Ok(Applied::Unchanged));

        // A rotation: a new root added and the built-in one revoked, beside
        // a revocation already in place.
        let rotate = request_bytes(&[spec(k2)], &sorted(vec![root, key_id(k1)]));
        let (result, rotated) = applied(&builtin, &none, &rotate);
        assert_eq!(
            result,
            Ok(Applied::Changed {
                len: HEADER_LEN + ANCHOR_LEN + 2 * 16,
                added: 1,
                removed: 0,
                revoked: 1
            })
        );
        let rotated = EnrolledStore::parse(&rotated).unwrap();
        assert!(rotated.is_revoked(&root));
        assert!(rotated.is_revoked(&key_id(k1)));
        assert!(rotated.anchor(&key_id(k2)).is_some());

        // The bound: a fourth anchor is refused whole.
        let three = enrolled_bytes(&[spec(k1), spec(k2), spec(k3)], &[]);
        let fourth = request_bytes(&[spec(k4)], &[[1; 16]]);
        assert_eq!(
            applied(&builtin, &three, &fourth).0,
            Err(ApplyError::Bound {
                anchors: 4,
                revoked: 1
            })
        );
        // Revoking one of the three makes room for it.
        let swap = request_bytes(&[spec(k4)], &[key_id(k3)]);
        let (result, swapped) = applied(&builtin, &three, &swap);
        assert!(matches!(
            result,
            Ok(Applied::Changed {
                added: 1,
                removed: 1,
                revoked: 1,
                ..
            })
        ));
        let swapped = EnrolledStore::parse(&swapped).unwrap();
        assert_eq!(swapped.anchors().count(), 3);
        assert!(swapped.anchor(&key_id(k3)).is_none());
        assert!(swapped.anchor(&key_id(k4)).is_some());
        // 121 revoked key ids are refused whole; 120 are applied.
        let many = ids(121, 0xee);
        assert_eq!(
            applied(&builtin, &empty, &request_bytes(&[], &many)).0,
            Err(ApplyError::Bound {
                anchors: 0,
                revoked: 121
            })
        );
        assert!(matches!(
            applied(&builtin, &empty, &request_bytes(&[], &many[..120])).0,
            Ok(Applied::Changed { revoked: 120, .. })
        ));

        // A buffer short of the new store.
        let request = TrustRequest::parse(&add_a).unwrap();
        let mut short = [0u8; HEADER_LEN];
        assert_eq!(
            apply(&builtin, &EnrolledStore::EMPTY, &request, &mut short),
            Err(ApplyError::Encode(EncodeError::BufferTooSmall))
        );
    }

    #[test]
    fn a_request_is_signed_in_the_enrolment_role_alone_under_a_slot_name()
    {
        assert!(RoleSet::of(&[Role::Enrolment]).is_signable());
        assert!(!RoleSet::of(&[Role::Enrolment, Role::Data]).is_signable());
        assert!(crate::name_is_canonical(REQUEST_NAME));
        assert!(!crate::name_is_install_path(REQUEST_NAME));
    }
}

/// Bounded proofs of the enrolled store's and the trust request's parse
/// (docs/testing.md § Bounded verification, Parser proofs), each on every
/// input up to the bounds its comment states.
///
/// How they compose into the property's checks of [`EnrolledStore::parse`]
/// and [`TrustRequest::parse`] (`property::enrolled_store_holds`,
/// `property::trust_request_holds`). Both parse with `Lists::parse`, whose
/// walk of the anchors takes the trust store's step ([`anchor_parts`],
/// [`anchor_checks`], [`in_order`]), proven by induction in `store.rs`
/// with the order of the revoked key ids; here
/// the layout proof shows that the walk starts on the lists the header
/// gives, the error proof that a step's refusal becomes the blob's, and the
/// lookup and bound proofs check the revoked lookup the last check makes and
/// the enrolled store's bound. What lies outside the proofs is
/// `Lists::parse` and the two `parse` functions, which drive these checks
/// in their order, the lookups' loop over the anchors (`decoded` in
/// `store.rs`), and the SHA-512 key id each anchor is walked and looked up
/// by, which no proof may stub (docs/coding-standards.md § Proof
/// Harnesses); the fuzz target `objsig`, the replay of the checked-in
/// inputs and the unit tests check them.
#[cfg(kani)]
mod proofs
{
    use super::{ANCHOR_LEN, Lists, MAX_ANCHORS, MAX_REVOKED, REQUEST_MAGIC, STORE_MAGIC};
    use crate::{KeyId, StoreError, property};

    /// Every blob of at most 2,055 bytes, begun by either format's magic or
    /// another, holds the layout's contract: 2,055 bytes hold the header (14
    /// bytes), an anchor (2,024), a revoked key id (16) and one byte more,
    /// so each refusal of the header, a length short of and past what the
    /// counts give, and a blob laid out are reached. No loop: the lists are
    /// cut by length.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_blob_lays_out_as_its_header_says()
    {
        let bytes: [u8; 2055] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let magic = if kani::any()
        {
            STORE_MAGIC
        }
        else
        {
            REQUEST_MAGIC
        };
        let _ = property::lists_layout_holds(&bytes[..len], magic);
    }

    /// Every error of an anchor's step maps to the error of a blob as the
    /// reading does: `AnchorOrder` to the blob's own, any other within
    /// `Anchor`.
    #[kani::proof]
    fn every_anchor_error_maps_to_the_blobs()
    {
        let errors = [
            StoreError::Length,
            StoreError::Magic,
            StoreError::Version,
            StoreError::NoAnchor,
            StoreError::AnchorUsage,
            StoreError::AnchorFlags,
            StoreError::Label,
            StoreError::AnchorOrder,
            StoreError::RevokedOrder,
        ];
        let index: usize = kani::any();
        kani::assume(index < errors.len());
        let _ = property::anchor_error_holds(errors[index]);
    }

    /// Every key id is found among up to 3 ascending revoked key ids exactly
    /// when it is one of them: 3 ids are two halvings of the binary search,
    /// and the ids before, between and after each are reached.
    #[kani::proof]
    #[kani::unwind(17)]
    fn every_key_id_is_found_revoked_exactly_when_listed()
    {
        let ids: [KeyId; 3] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= ids.len());
        let revoked = &ids[..len];
        kani::assume(revoked.windows(2).all(|pair| pair[0] < pair[1]));
        let lists = Lists {
            anchors: &[],
            revoked,
        };
        let _ = property::revoked_holds(&lists, &kani::any());
    }

    /// Lists of every count of anchors and revoked key ids up to one past the
    /// bound are judged within it as the reading does. The counts alone are
    /// read, so lists of zero bytes stand for any.
    #[kani::proof]
    fn every_count_is_judged_against_the_bound()
    {
        static ANCHORS: [[u8; ANCHOR_LEN]; MAX_ANCHORS + 1] = [[0; ANCHOR_LEN]; MAX_ANCHORS + 1];
        static REVOKED: [KeyId; MAX_REVOKED + 1] = [[0; 16]; MAX_REVOKED + 1];
        let anchors: usize = kani::any();
        let revoked: usize = kani::any();
        kani::assume(anchors <= ANCHORS.len() && revoked <= REVOKED.len());
        let lists = Lists {
            anchors: &ANCHORS[..anchors],
            revoked: &REVOKED[..revoked],
        };
        let _ = property::bound_holds(&lists);
    }
}
