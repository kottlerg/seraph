// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/signing/store.rs

//! The trust store a build embeds in the bootloader: the identity's anchors,
//! merged with or replaced by a deployer's store (docs/signing.md § Trust
//! Store and § Signing).

use std::collections::BTreeMap;

use objsig::{AnchorSpec, KeyId, TrustStore};

use crate::error::{Result, bail, err};

/// How a deployer's store combines with the identity's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreMode
{
    /// The union of both stores: every anchor and revoked key id of either,
    /// and the higher security floor.
    Merge,
    /// The deployer's store alone.
    Replace,
}

impl StoreMode
{
    /// The mode a `SERAPH_TRUST_STORE_MODE` value names: `merge` or
    /// `replace`.
    pub fn parse(value: &str) -> Option<Self>
    {
        match value
        {
            "merge" => Some(Self::Merge),
            "replace" => Some(Self::Replace),
            _ => None,
        }
    }
}

/// The store of `identity` (an encoded store), combined with `deployer`'s
/// as its mode says. The floor is at least `floor`, the tree's security
/// version.
///
/// # Errors
///
/// When a store does not parse; when the stores hold one key as anchors
/// that differ in usage, flag or label; when the result does not encode.
pub fn build(
    identity: &[u8],
    deployer: Option<(&[u8], StoreMode)>,
    floor: u32,
) -> Result<Vec<u8>>
{
    let parse = |bytes, whose| {
        TrustStore::parse(bytes).map_err(|e| err!("the {whose} trust store does not parse ({e:?})"))
    };
    let own = parse(identity, "signing identity's")?;
    let stores = match deployer
    {
        None => vec![own],
        Some((bytes, StoreMode::Merge)) => vec![own, parse(bytes, "deployer's")?],
        Some((bytes, StoreMode::Replace)) => vec![parse(bytes, "deployer's")?],
    };
    let mut anchors: BTreeMap<KeyId, AnchorSpec<'_>> = BTreeMap::new();
    let mut revoked: Vec<KeyId> = Vec::new();
    let mut security_floor = floor;
    for store in &stores
    {
        for anchor in store.anchors()
        {
            let spec = AnchorSpec {
                key: anchor.key,
                usage: anchor.usage,
                local: anchor.local,
                label: anchor.label,
            };
            match anchors.get(&anchor.key_id)
            {
                Some(held) if *held != spec =>
                {
                    bail!(
                        "the trust stores hold the anchor {} with different usage, flags or labels",
                        hex(&anchor.key_id)
                    );
                }
                _ =>
                {
                    anchors.insert(anchor.key_id, spec);
                }
            }
        }
        revoked.extend_from_slice(store.revoked());
        security_floor = security_floor.max(store.security_floor());
    }
    revoked.sort_unstable();
    revoked.dedup();
    // A BTreeMap iterates by key id, the order the store requires.
    let anchors: Vec<AnchorSpec<'_>> = anchors.into_values().collect();
    encode(security_floor, &anchors, &revoked)
}

/// Encode a store of `anchors`, which are sorted by key id, and `revoked`.
///
/// # Errors
///
/// When `TrustStore::encode` refuses them.
pub fn encode(security_floor: u32, anchors: &[AnchorSpec<'_>], revoked: &[KeyId]) -> Result<Vec<u8>>
{
    let refused = |e| err!("encoding the trust store ({e:?})");
    let mut out = vec![0u8; TrustStore::encoded_len(anchors.len(), revoked.len()).map_err(refused)?];
    TrustStore::encode(security_floor, anchors, revoked, &mut out).map_err(refused)?;
    Ok(out)
}

/// A key id in lower-case hex.
pub fn hex(id: &KeyId) -> String
{
    id.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}
