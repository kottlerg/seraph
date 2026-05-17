// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/gate.rs

//! Per-label rights gate for tokened namespace endpoints.
//!
//! [`gate`] is the only public path from a `(label, token)` pair to a
//! [`NodeId`] outside this crate. Servers call it before dispatching
//! any tokened message; it looks up the operation's rights requirement
//! in [`RIGHTS_TABLE`], unpacks the token, and returns
//! `Ok((node_id, rights))` only when the token's rights mask satisfies
//! the requirement.
//!
//! Adding a new tokened label requires one row in [`RIGHTS_TABLE`]
//! next to the wire-protocol definition; an unmatched opcode replies
//! [`GateError::UnknownLabel`] (mapped to the wire's `UNKNOWN_OPCODE`).

#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

use core::num::NonZeroU32;

use crate::rights::{self, NamespaceRights};
use crate::token::{NodeId, unpack};

/// Failure modes for [`gate`]. Callers map to their wire layer's
/// `UNKNOWN_OPCODE` / `PERMISSION_DENIED` codes.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum GateError
{
    /// Opcode is not registered in [`RIGHTS_TABLE`].
    UnknownLabel,
    /// Token's rights mask is missing a required bit (or is empty for
    /// [`RightsRequirement::AnyNonEmpty`] operations).
    PermissionDenied,
}

/// Decode a tokened request and enforce its rights requirement.
///
/// `label` is the full IPC label; the opcode is `label & 0xFFFF` so
/// callers may pass labels carrying payload length in high bits
/// (e.g. `NS_LOOKUP`'s name length in bits 16..32).
///
/// # Errors
///
/// [`GateError::UnknownLabel`] when the opcode is absent from
/// [`RIGHTS_TABLE`]; [`GateError::PermissionDenied`] when the token's
/// rights mask does not satisfy the entry.
pub fn gate(label: u64, token: u64) -> Result<(NodeId, NamespaceRights), GateError>
{
    let opcode = label & 0xFFFF;
    let req = required_rights_for(opcode).ok_or(GateError::UnknownLabel)?;
    let (node, rights) = unpack(token);
    let ok = match req
    {
        RightsRequirement::Bits(bits) => rights.contains(bits.get()),
        RightsRequirement::AnyNonEmpty => !rights.is_empty(),
    };
    if ok
    {
        Ok((node, rights))
    }
    else
    {
        Err(GateError::PermissionDenied)
    }
}

/// Compute the `caller_requested` word for an `NS_LOOKUP` that one
/// namespace server is about to forward to another (e.g. vfsd's
/// fall-through delegation to a mounted filesystem driver).
///
/// Decodes the caller's parent rights from `recv_token`, decodes
/// `recv_word0` (treating the wire's `0xFFFF` "everything I'm allowed"
/// sentinel as [`NamespaceRights::ALL`]), and returns the raw mask of
/// their intersection. The forwarder writes this mask into the
/// outbound message's `word(0)` before sending.
///
/// # Why
///
/// The receiving server composes its returned rights as
/// `parent_rights ∩ entry.max_rights ∩ caller_requested`, where
/// `parent_rights` is unpacked from the **destination cap's** token —
/// i.e. the forwarding intermediary's authority on the receiver, not
/// the original caller's authority on the intermediary. Forwarding
/// the caller's `word(0)` verbatim therefore launders authority: a
/// caller holding an attenuated cap on the intermediary can obtain a
/// child cap whose rights exceed its parent's, violating the
/// monotonic-attenuation invariant in `docs/namespace-model.md`
/// § "Walking". Pre-intersecting the request body restores the
/// invariant; the receiver still applies its own
/// `entry.max_rights` ceiling on top.
///
/// # Wire impact
///
/// The `0xFFFF` sentinel is replaced by an explicit 24-bit mask on
/// the forwarded message. Semantically identical — every receiver
/// already decodes raw rights bits the same way — and no protocol
/// version change is required.
#[must_use]
pub fn compose_forward_lookup_rights(recv_token: u64, recv_word0: u64) -> u32
{
    let (_, parent_rights) = unpack(recv_token);
    let caller_requested = crate::decode_caller_requested(recv_word0);
    (parent_rights & caller_requested).raw()
}

#[derive(Copy, Clone)]
enum RightsRequirement
{
    /// Token must contain every bit in this mask. The [`NonZeroU32`]
    /// makes the empty mask unrepresentable.
    Bits(NonZeroU32),
    /// Token's rights mask must be non-empty. For bookkeeping
    /// operations on already-issued resources where authority lives at
    /// issuance.
    AnyNonEmpty,
}

const fn nz(bit: u32) -> NonZeroU32
{
    match NonZeroU32::new(bit)
    {
        Some(n) => n,
        None => panic!("rights bit must be non-zero"),
    }
}

/// Per-tokened-label rights requirements. Untokened service-level
/// labels (e.g. `FS_MOUNT`) are dispatched separately and do not
/// appear here.
const RIGHTS_TABLE: &[(u64, RightsRequirement)] = &[
    (
        ipc::ns_labels::NS_LOOKUP,
        RightsRequirement::Bits(nz(rights::LOOKUP)),
    ),
    (
        ipc::ns_labels::NS_STAT,
        RightsRequirement::Bits(nz(rights::STAT)),
    ),
    (
        ipc::ns_labels::NS_READDIR,
        RightsRequirement::Bits(nz(rights::READDIR)),
    ),
    (
        ipc::fs_labels::FS_READ,
        RightsRequirement::Bits(nz(rights::READ)),
    ),
    (
        ipc::fs_labels::FS_READ_FRAME,
        RightsRequirement::Bits(nz(rights::READ)),
    ),
    (
        ipc::fs_labels::FS_RELEASE_FRAME,
        RightsRequirement::AnyNonEmpty,
    ),
    (ipc::fs_labels::FS_CLOSE, RightsRequirement::AnyNonEmpty),
    (
        ipc::fs_labels::FS_WRITE,
        RightsRequirement::Bits(nz(rights::WRITE)),
    ),
    (
        ipc::fs_labels::FS_WRITE_FRAME,
        RightsRequirement::Bits(nz(rights::WRITE)),
    ),
    (
        ipc::fs_labels::FS_CREATE,
        RightsRequirement::Bits(nz(rights::MUTATE_DIR)),
    ),
    (
        ipc::fs_labels::FS_REMOVE,
        RightsRequirement::Bits(nz(rights::MUTATE_DIR)),
    ),
    (
        ipc::fs_labels::FS_MKDIR,
        RightsRequirement::Bits(nz(rights::MUTATE_DIR)),
    ),
    (
        ipc::fs_labels::FS_RENAME,
        RightsRequirement::Bits(nz(rights::MUTATE_DIR)),
    ),
];

fn required_rights_for(opcode: u64) -> Option<RightsRequirement>
{
    let mut i = 0;
    while i < RIGHTS_TABLE.len()
    {
        let (op, req) = RIGHTS_TABLE[i];
        if op == opcode
        {
            return Some(req);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::token::pack;

    fn token_with(rights_bits: u32) -> u64
    {
        pack(
            NodeId::new(0x42).unwrap(),
            NamespaceRights::from_raw(rights_bits),
        )
    }

    #[test]
    fn unknown_opcode_returns_unknown_label()
    {
        assert_eq!(
            gate(0x9999, token_with(0xFFFF)),
            Err(GateError::UnknownLabel)
        );
    }

    #[test]
    fn ns_lookup_accepts_token_with_lookup_bit()
    {
        let (node, _) = gate(ipc::ns_labels::NS_LOOKUP, token_with(rights::LOOKUP)).unwrap();
        assert_eq!(node.raw(), 0x42);
    }

    #[test]
    fn ns_lookup_rejects_token_without_lookup_bit()
    {
        assert_eq!(
            gate(ipc::ns_labels::NS_LOOKUP, token_with(rights::STAT)),
            Err(GateError::PermissionDenied)
        );
    }

    #[test]
    fn ns_stat_gates_on_stat_bit()
    {
        assert!(gate(ipc::ns_labels::NS_STAT, token_with(rights::STAT)).is_ok());
        assert_eq!(
            gate(ipc::ns_labels::NS_STAT, token_with(rights::READ)),
            Err(GateError::PermissionDenied)
        );
    }

    #[test]
    fn ns_readdir_gates_on_readdir_bit()
    {
        assert!(gate(ipc::ns_labels::NS_READDIR, token_with(rights::READDIR)).is_ok());
        assert_eq!(
            gate(ipc::ns_labels::NS_READDIR, token_with(rights::LOOKUP)),
            Err(GateError::PermissionDenied)
        );
    }

    #[test]
    fn fs_read_and_fs_read_frame_share_the_read_bit()
    {
        assert!(gate(ipc::fs_labels::FS_READ, token_with(rights::READ)).is_ok());
        assert!(gate(ipc::fs_labels::FS_READ_FRAME, token_with(rights::READ)).is_ok());
        assert_eq!(
            gate(ipc::fs_labels::FS_READ, token_with(rights::STAT)),
            Err(GateError::PermissionDenied)
        );
        assert_eq!(
            gate(ipc::fs_labels::FS_READ_FRAME, token_with(rights::STAT)),
            Err(GateError::PermissionDenied)
        );
    }

    #[test]
    fn fs_release_frame_accepts_any_single_bit()
    {
        assert!(gate(ipc::fs_labels::FS_RELEASE_FRAME, token_with(rights::READ)).is_ok());
        assert!(gate(ipc::fs_labels::FS_RELEASE_FRAME, token_with(rights::STAT)).is_ok());
        assert!(gate(ipc::fs_labels::FS_RELEASE_FRAME, token_with(rights::ADMIN)).is_ok());
    }

    #[test]
    fn fs_release_frame_rejects_empty_rights_mask()
    {
        assert_eq!(
            gate(ipc::fs_labels::FS_RELEASE_FRAME, token_with(0)),
            Err(GateError::PermissionDenied)
        );
    }

    #[test]
    fn fs_close_rejects_empty_rights_mask()
    {
        assert_eq!(
            gate(ipc::fs_labels::FS_CLOSE, token_with(0)),
            Err(GateError::PermissionDenied)
        );
    }

    #[test]
    fn fs_write_and_fs_write_frame_share_the_write_bit()
    {
        assert!(gate(ipc::fs_labels::FS_WRITE, token_with(rights::WRITE)).is_ok());
        assert!(gate(ipc::fs_labels::FS_WRITE_FRAME, token_with(rights::WRITE)).is_ok());
        assert_eq!(
            gate(ipc::fs_labels::FS_WRITE, token_with(rights::READ)),
            Err(GateError::PermissionDenied)
        );
        assert_eq!(
            gate(ipc::fs_labels::FS_WRITE_FRAME, token_with(rights::READ)),
            Err(GateError::PermissionDenied)
        );
    }

    #[test]
    fn fs_mutate_dir_labels_gate_on_mutate_dir_bit()
    {
        for label in [
            ipc::fs_labels::FS_CREATE,
            ipc::fs_labels::FS_REMOVE,
            ipc::fs_labels::FS_MKDIR,
            ipc::fs_labels::FS_RENAME,
        ]
        {
            assert!(
                gate(label, token_with(rights::MUTATE_DIR)).is_ok(),
                "label {label:#x} should accept MUTATE_DIR"
            );
            assert_eq!(
                gate(label, token_with(rights::LOOKUP | rights::READDIR)),
                Err(GateError::PermissionDenied),
                "label {label:#x} should reject without MUTATE_DIR"
            );
        }
    }

    #[test]
    fn high_label_bits_are_ignored_on_opcode_lookup()
    {
        // NS_LOOKUP encodes name length in bits 16..32.
        let label = ipc::ns_labels::NS_LOOKUP | (5u64 << 16);
        assert!(gate(label, token_with(rights::LOOKUP)).is_ok());
    }

    #[test]
    fn returned_rights_match_token_rights()
    {
        let bits = rights::LOOKUP | rights::READ | rights::STAT;
        let (_, r) = gate(ipc::ns_labels::NS_LOOKUP, token_with(bits)).unwrap();
        assert_eq!(r.raw(), bits);
    }

    #[test]
    fn compose_forward_lookup_rights_intersects_parent_with_request()
    {
        let parent = rights::LOOKUP | rights::READ | rights::STAT;
        let token = token_with(parent);
        // Caller asks for exactly READ — receiver should see READ.
        assert_eq!(
            compose_forward_lookup_rights(token, u64::from(rights::READ)),
            rights::READ
        );
        // Caller asks for STAT|READ — receiver should see STAT|READ.
        assert_eq!(
            compose_forward_lookup_rights(token, u64::from(rights::READ | rights::STAT)),
            rights::READ | rights::STAT,
        );
    }

    #[test]
    fn compose_forward_lookup_rights_resolves_sentinel_against_parent()
    {
        let parent = rights::LOOKUP | rights::STAT;
        let token = token_with(parent);
        // 0xFFFF means "everything I'm allowed"; intersected with parent
        // it must collapse to exactly the parent rights.
        assert_eq!(compose_forward_lookup_rights(token, 0xFFFF), parent);
    }

    #[test]
    fn compose_forward_lookup_rights_drops_bits_caller_does_not_hold()
    {
        // Parent only has LOOKUP|STAT; caller's request body asks for READ.
        // Forwarded mask must not include READ.
        let token = token_with(rights::LOOKUP | rights::STAT);
        assert_eq!(
            compose_forward_lookup_rights(token, u64::from(rights::READ)),
            0
        );
    }

    #[test]
    fn compose_forward_lookup_rights_strips_bits_above_field_width()
    {
        // Reserved high bits in word(0) (above RIGHTS_MASK) must not
        // bleed into the forwarded mask.
        let token = token_with(rights::LOOKUP);
        let raw = u64::from(rights::LOOKUP) | (1u64 << 31);
        assert_eq!(compose_forward_lookup_rights(token, raw), rights::LOOKUP,);
    }
}
