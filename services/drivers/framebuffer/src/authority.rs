// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/framebuffer/src/authority.rs

//! Verb-bit gate of the framebuffer driver's service endpoint.
//!
//! [`fb_labels::FB_WRITE_BYTES`] and [`fb_labels::FB_SET_ATTRS`] are gated
//! on [`fb_labels::WRITE_AUTHORITY`] in the caller's badge (see
//! `docs/capability-model.md` on verb bits). Unknown opcodes carry no gate,
//! so the driver answers them `UNKNOWN_OPCODE`, not `UNAUTHORIZED`.

use ipc::fb_labels;

/// Whether a request with label `label` from a caller badged `badge` may be
/// served.
///
/// Returns `false` when the label's opcode (bits 0-15) is
/// [`fb_labels::FB_WRITE_BYTES`] or [`fb_labels::FB_SET_ATTRS`] and `badge`
/// lacks [`fb_labels::WRITE_AUTHORITY`]; the driver then replies
/// `fb_errors::UNAUTHORIZED`. Returns `true` for every other request.
#[must_use]
pub fn authorized(label: u64, badge: u64) -> bool
{
    let op = label & 0xFFFF;
    if op == fb_labels::FB_WRITE_BYTES || op == fb_labels::FB_SET_ATTRS
    {
        badge & fb_labels::WRITE_AUTHORITY != 0
    }
    else
    {
        true
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn write_and_set_attrs_are_refused_without_write_authority()
    {
        // A byte-length field in bits 16-31 must not hide the opcode, and a
        // badge carrying some other bit is no substitute for the verb bit.
        let write = fb_labels::FB_WRITE_BYTES | (5 << 16);
        let attrs = fb_labels::FB_SET_ATTRS | (6 << 16);
        for label in [write, attrs]
        {
            assert!(!authorized(label, 0));
            assert!(!authorized(label, 1u64 << 62));
            assert!(authorized(label, fb_labels::WRITE_AUTHORITY));
        }
    }

    #[test]
    fn unknown_opcode_is_not_gated()
    {
        assert!(authorized(0xFFFF, 0));
    }
}
