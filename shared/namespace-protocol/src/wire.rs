// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/wire.rs

//! Wire-format definitions for the namespace protocol.
//!
//! This module exposes the protocol's error-code namespace
//! ([`NsError`]) used as reply-label values. Per-opcode encode / decode
//! lives inline in `dispatch_request` (see crate root); the wire
//! shape is documented in `shared/namespace-protocol/README.md`.
//! Numeric label values live in [`ipc::ns_labels`].

// Under `rustc-dep-of-std` the crate root is `no_core` and the usual
// prelude is not auto-imported into submodules. Mirrors the
// `shared/ipc/src/bootstrap.rs` shape; no-op on regular no_std builds.
#[cfg(feature = "rustc-dep-of-std")]
#[allow(unused_imports)]
use core::prelude::rust_2024::*;

/// Reply-label values used by the namespace protocol on error.
///
/// Each variant maps to a distinct numeric label transmitted as the
/// reply's label field. A successful reply uses label `0` (no
/// dedicated `NsError::Success` variant — success is the absence of
/// error).
///
/// Numeric values are stable wire codes and MUST NOT be reordered
/// without a coordinated migration.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u64)]
pub enum NsError
{
    /// Requested name does not exist, or is hidden by per-entry
    /// visibility filtering. Hidden and absent are indistinguishable to
    /// the caller by design.
    NotFound = 1,
    /// Caller holds the cap but lacks the namespace right required for
    /// this operation. "No cap at all" fails earlier at the kernel
    /// layer and never reaches the server.
    PermissionDenied = 2,
    /// Operation requires a directory cap but the addressed node is a
    /// file (e.g., a non-final walk component is a file).
    NotADirectory = 3,
    /// Operation requires a file cap but the addressed node is a
    /// directory (e.g., the final walk component is a directory and
    /// the caller asked to open a file).
    IsADirectory = 4,
    /// Name failed validation (see [`crate::name::validate_name`]).
    InvalidName = 5,
    /// Read offset is out of range for the addressed file.
    InvalidOffset = 6,
    /// `NS_READ_FRAME` reply target frame cap is missing required
    /// rights or has the wrong shape. Preserved from the existing
    /// fs-frame protocol.
    InvalidFrameCap = 7,
    /// `NS_READ_FRAME` cookie is invalid (e.g., zero, or duplicates an
    /// outstanding cookie). Preserved from the existing fs-frame
    /// protocol.
    InvalidCookie = 8,
    /// Frame referenced by a held cookie has been evicted; the client
    /// MUST drop the stale frame cap and reissue. Preserved from the
    /// existing fs-frame protocol.
    Evicted = 9,
    /// Backend storage failed (disk read error, filesystem
    /// inconsistency, …).
    IoError = 10,
    /// Operation is recognised but not implemented on this server (or
    /// not yet implemented in this version of the protocol).
    NotSupported = 11,
    /// Server cannot satisfy the request due to resource exhaustion
    /// (table full, allocator failure, …).
    OutOfResources = 12,
}

impl NsError
{
    /// The numeric reply-label value for this error.
    #[must_use]
    pub const fn as_label(self) -> u64
    {
        self as u64
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn error_codes_match_protocol_specification()
    {
        // Stable wire codes per docs/namespace-model.md and the
        // error table in shared/namespace-protocol/README.md.
        // Reordering or renumbering breaks the wire contract; this
        // test is a guard against accidental edits.
        assert_eq!(NsError::NotFound.as_label(), 1);
        assert_eq!(NsError::PermissionDenied.as_label(), 2);
        assert_eq!(NsError::NotADirectory.as_label(), 3);
        assert_eq!(NsError::IsADirectory.as_label(), 4);
        assert_eq!(NsError::InvalidName.as_label(), 5);
        assert_eq!(NsError::InvalidOffset.as_label(), 6);
        assert_eq!(NsError::InvalidFrameCap.as_label(), 7);
        assert_eq!(NsError::InvalidCookie.as_label(), 8);
        assert_eq!(NsError::Evicted.as_label(), 9);
        assert_eq!(NsError::IoError.as_label(), 10);
        assert_eq!(NsError::NotSupported.as_label(), 11);
        assert_eq!(NsError::OutOfResources.as_label(), 12);
    }

    #[test]
    fn error_label_zero_is_reserved_for_success()
    {
        // No variant should map to label 0; that label is reserved for
        // success replies.
        for err in [
            NsError::NotFound,
            NsError::PermissionDenied,
            NsError::NotADirectory,
            NsError::IsADirectory,
            NsError::InvalidName,
            NsError::InvalidOffset,
            NsError::InvalidFrameCap,
            NsError::InvalidCookie,
            NsError::Evicted,
            NsError::IoError,
            NsError::NotSupported,
            NsError::OutOfResources,
        ]
        {
            assert_ne!(err.as_label(), 0);
        }
    }
}
