// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/signing/store.rs

//! The trust store a build embeds in the bootloader: the identity's anchors,
//! merged with or replaced by a deployer's store (docs/signing.md § Trust
//! Store and § Signing).

use std::collections::BTreeMap;

use objsig::{AnchorSpec, KeyId, RoleSet, TrustStore, Usage};

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
pub fn build(identity: &[u8], deployer: Option<(&[u8], StoreMode)>, floor: u32) -> Result<Vec<u8>>
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

/// `store` with `id` among its revoked key ids, its anchors and floor
/// unchanged.
///
/// # Errors
///
/// When `store` does not parse.
pub fn with_revoked(store: &[u8], id: KeyId) -> Result<Vec<u8>>
{
    let parsed =
        TrustStore::parse(store).map_err(|e| err!("the trust store does not parse ({e:?})"))?;
    // The parsed anchors come in key-id order, the order encode requires.
    let anchors: Vec<AnchorSpec<'_>> = parsed
        .anchors()
        .map(|anchor| AnchorSpec {
            key: anchor.key,
            usage: anchor.usage,
            local: anchor.local,
            label: anchor.label,
        })
        .collect();
    let mut revoked = parsed.revoked().to_vec();
    revoked.push(id);
    revoked.sort_unstable();
    revoked.dedup();
    encode(parsed.security_floor(), &anchors, &revoked)
}

/// `store` with the anchors of each store of `scoped` added, each anchor
/// usable for the roles of its own usage that the paired set holds alone, and
/// may certify as it could; its floor and revoked key ids unchanged. A store
/// that trusts another key for some roles only, as a deployer's may.
///
/// # Errors
///
/// When a store does not parse; when `store` holds an anchor of one of the
/// keys added; when the result does not encode.
pub fn with_scoped_anchors(store: &[u8], scoped: &[(&[u8], RoleSet)]) -> Result<Vec<u8>>
{
    let parse =
        |bytes| TrustStore::parse(bytes).map_err(|e| err!("a trust store does not parse ({e:?})"));
    let base = parse(store)?;
    let mut anchors: BTreeMap<KeyId, AnchorSpec<'_>> = base
        .anchors()
        .map(|anchor| {
            (
                anchor.key_id,
                AnchorSpec {
                    key: anchor.key,
                    usage: anchor.usage,
                    local: anchor.local,
                    label: anchor.label,
                },
            )
        })
        .collect();
    let others = scoped
        .iter()
        .map(|(bytes, roles)| parse(bytes).map(|parsed| (parsed, *roles)))
        .collect::<Result<Vec<_>>>()?;
    for (other, roles) in &others
    {
        for anchor in other.anchors()
        {
            let spec = AnchorSpec {
                key: anchor.key,
                usage: Usage {
                    roles: anchor.usage.roles.intersection(*roles),
                    certify: anchor.usage.certify,
                },
                local: anchor.local,
                label: anchor.label,
            };
            if anchors.insert(anchor.key_id, spec).is_some()
            {
                bail!(
                    "the trust store already holds the anchor {}",
                    hex(&anchor.key_id)
                );
            }
        }
    }
    let anchors: Vec<AnchorSpec<'_>> = anchors.into_values().collect();
    encode(base.security_floor(), &anchors, base.revoked())
}

/// Encode a store of `anchors`, which are sorted by key id, and `revoked`.
///
/// # Errors
///
/// When `TrustStore::encode` refuses them.
pub fn encode(security_floor: u32, anchors: &[AnchorSpec<'_>], revoked: &[KeyId])
-> Result<Vec<u8>>
{
    let refused = |e| err!("encoding the trust store ({e:?})");
    let mut out =
        vec![0u8; TrustStore::encoded_len(anchors.len(), revoked.len()).map_err(refused)?];
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

#[cfg(test)]
mod tests
{
    use objsig::{PublicKey, Role, key_id};

    use super::*;

    /// The test key whose every byte is `byte`, leaked.
    fn key(byte: u8) -> &'static PublicKey
    {
        Box::leak(Box::new([byte; objsig::composite::PUBLIC_KEY_LEN]))
    }

    /// An anchor of `key` that may certify every kind.
    fn anchor<'a>(key: &'a PublicKey, label: &'a str) -> AnchorSpec<'a>
    {
        AnchorSpec {
            key,
            usage: Usage {
                roles: RoleSet::ALL,
                certify: true,
            },
            local: false,
            label,
        }
    }

    /// A store of `anchors`, sorted here, and `revoked`.
    fn store_of(floor: u32, mut anchors: Vec<AnchorSpec<'_>>, mut revoked: Vec<KeyId>) -> Vec<u8>
    {
        anchors.sort_by_key(|spec| key_id(spec.key));
        revoked.sort_unstable();
        encode(floor, &anchors, &revoked).unwrap()
    }

    /// The key ids of the anchors of the encoded `store`, its revoked ids
    /// and its floor.
    fn contents(store: &[u8]) -> (Vec<KeyId>, Vec<KeyId>, u32)
    {
        let store = TrustStore::parse(store).unwrap();
        let anchors = store.anchors().map(|anchor| anchor.key_id).collect();
        (anchors, store.revoked().to_vec(), store.security_floor())
    }

    /// `ids`, sorted.
    fn sorted(mut ids: Vec<KeyId>) -> Vec<KeyId>
    {
        ids.sort_unstable();
        ids
    }

    // Defect caught: a merge that drops an anchor or a revocation of either
    // store, lowers a floor, or emits anchors out of key-id order, which the
    // store's parser refuses.
    #[test]
    fn merging_unites_the_anchors_and_revocations_under_the_highest_floor()
    {
        let own = store_of(1, vec![anchor(key(1), "own")], vec![[9; 16]]);
        let shared = anchor(key(2), "shared");
        let deployer = store_of(
            5,
            vec![shared, anchor(key(3), "deployer")],
            vec![[8; 16], [9; 16]],
        );
        let merged = build(&own, Some((&deployer, StoreMode::Merge)), 1).unwrap();
        let ids = sorted(vec![key_id(key(1)), key_id(key(2)), key_id(key(3))]);
        assert_eq!(contents(&merged), (ids, vec![[8; 16], [9; 16]], 5));

        // The tree's version raises a lower floor, and an anchor both stores
        // hold alike is kept once.
        let again = store_of(0, vec![shared], Vec::new());
        let merged = build(&deployer, Some((&again, StoreMode::Merge)), 7).unwrap();
        let ids = sorted(vec![key_id(key(2)), key_id(key(3))]);
        assert_eq!(contents(&merged), (ids, vec![[8; 16], [9; 16]], 7));
    }

    // Defect caught: a replacing store that keeps the builder's own root,
    // which the deployer asked to stop trusting.
    #[test]
    fn replacing_keeps_the_deployers_store_alone()
    {
        let own = store_of(1, vec![anchor(key(1), "own")], Vec::new());
        let deployer = store_of(0, vec![anchor(key(3), "deployer")], vec![[8; 16]]);
        let replaced = build(&own, Some((&deployer, StoreMode::Replace)), 1).unwrap();
        assert_eq!(
            contents(&replaced),
            (vec![key_id(key(3))], vec![[8; 16]], 1)
        );
    }

    // Defect caught: one of two conflicting anchors of a key kept silently,
    // granting the key a usage one of the stores withheld.
    #[test]
    fn one_key_anchored_differently_by_two_stores_is_refused()
    {
        let own = store_of(1, vec![anchor(key(1), "own")], Vec::new());
        let mut narrow = anchor(key(1), "own");
        narrow.usage.certify = false;
        let deployer = store_of(1, vec![narrow], Vec::new());
        build(&own, Some((&deployer, StoreMode::Merge)), 1).unwrap_err();
    }

    // Defect caught: an added anchor kept with its own usage, so a key the
    // test means to trust for some roles verifies in every one; or an anchor
    // of the base store replaced by an added one.
    #[test]
    fn scoped_anchors_are_added_for_their_roles_alone()
    {
        let base = store_of(3, vec![anchor(key(1), "own")], vec![[9; 16]]);
        let other = store_of(1, vec![anchor(key(2), "other")], Vec::new());
        let config = RoleSet::of(&[Role::Configuration]);
        let scoped = with_scoped_anchors(&base, &[(&other, config)]).unwrap();
        let parsed = TrustStore::parse(&scoped).unwrap();
        assert_eq!(
            (parsed.security_floor(), parsed.revoked()),
            (3, &[[9; 16]][..])
        );
        let added = parsed.anchor(&key_id(key(2))).unwrap();
        assert_eq!(added.usage.roles, config);
        assert!(added.usage.certify);
        assert_eq!(
            parsed.anchor(&key_id(key(1))).unwrap().usage.roles,
            RoleSet::ALL
        );
        with_scoped_anchors(&base, &[(&base, config)]).unwrap_err();
    }

    // Defect caught: a deployer's file that is not a store ignored, so the
    // build embeds a store the deployer did not ask for.
    #[test]
    fn a_deployer_store_that_does_not_parse_is_refused()
    {
        let own = store_of(1, vec![anchor(key(1), "own")], Vec::new());
        build(&own, Some((b"not a store", StoreMode::Merge)), 1).unwrap_err();
        build(&own, Some((b"not a store", StoreMode::Replace)), 1).unwrap_err();
    }
}
