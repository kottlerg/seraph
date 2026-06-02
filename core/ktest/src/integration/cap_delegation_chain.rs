// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// ktest/src/integration/cap_delegation_chain.rs

//! Integration: multi-level capability attenuation and cascaded revocation.
//!
//! Verifies two properties that single-level unit tests (`derive_attenuation`,
//! `revoke_invalidates`) do not cover:
//!
//! 1. **Multi-level attenuation**: a cap derived from a restricted cap cannot
//!    exceed the rights of its parent, even if a wider rights mask is requested.
//!    Root → level1 (NOTIFY only) → level2 (NOTIFY only, clamped from level1).
//!
//! 2. **Cascaded revocation**: revoking the root cap invalidates level1 AND
//!    level2, not just level1.
//!
//! ## Rights used
//!
//! - NOTIFY (bit 7): allows `notification_send`
//! - WAIT   (bit 8): allows `notification_wait` (held only by root)
//!
//! level1 and level2 each have NOTIFY only. Any `notification_wait` on level1 or
//! level2 must fail with `InsufficientRights`.

use syscall::{
    cap_create_notification, cap_delete, cap_derive, cap_revoke, notification_send,
    notification_wait,
};
use syscall_abi::SyscallError;

use crate::{TestContext, TestResult};

// NOTIFY right only (bit 7) — can send, cannot wait.
const RIGHTS_NOTIFY: u64 = 1 << 7;
// NOTIFY + WAIT rights (bits 7 and 8) — full notification capability.
const RIGHTS_NOTIFY_WAIT: u64 = (1 << 7) | (1 << 8);

pub fn run(ctx: &TestContext) -> TestResult
{
    crate::log("cap_delegation_chain: starting");

    // Root cap: full NOTIFY+WAIT rights.
    let root = cap_create_notification(ctx.memory_base)
        .map_err(|_| "cap_delegation_chain: cap_create_notification failed")?;

    // ── Level 1: derive from root with NOTIFY only ────────────────────────────
    let level1 = cap_derive(root, RIGHTS_NOTIFY)
        .map_err(|_| "cap_delegation_chain: cap_derive level1 failed")?;

    // ── Level 2: derive from level1, requesting NOTIFY+WAIT ──────────────────
    // The kernel must clamp to level1's rights (NOTIFY only); WAIT must be
    // stripped because level1 does not carry it.
    let level2 = cap_derive(level1, RIGHTS_NOTIFY_WAIT)
        .map_err(|_| "cap_delegation_chain: cap_derive level2 failed")?;

    // ── Verify attenuation: level1 can send, cannot wait ─────────────────────
    crate::log("cap_delegation_chain: verifying level1 rights");
    notification_send(level1, 0x1)
        .map_err(|_| "cap_delegation_chain: level1 notification_send should succeed")?;
    // Drain the bit via root so subsequent waits don't see stale state.
    notification_wait(root)
        .map_err(|_| "cap_delegation_chain: root drain after level1 send failed")?;

    let err1 = notification_wait(level1);
    if err1 != Err(SyscallError::InsufficientRights as i64)
    {
        return Err(
            "cap_delegation_chain: level1 notification_wait should fail with InsufficientRights",
        );
    }

    // ── Verify attenuation: level2 can send, cannot wait ─────────────────────
    crate::log("cap_delegation_chain: verifying level2 rights");
    notification_send(level2, 0x2)
        .map_err(|_| "cap_delegation_chain: level2 notification_send should succeed")?;
    notification_wait(root)
        .map_err(|_| "cap_delegation_chain: root drain after level2 send failed")?;

    let err2 = notification_wait(level2);
    if err2 != Err(SyscallError::InsufficientRights as i64)
    {
        return Err(
            "cap_delegation_chain: level2 notification_wait should fail with InsufficientRights",
        );
    }

    // ── Cascaded revocation: revoke root → level1 and level2 both invalid ────
    //
    // cap_revoke invalidates all *descendants* of the revoked cap. The revoked
    // cap itself (root) remains valid — revocation is an operation on children,
    // not self-destruction. Delete root explicitly after verifying the cascade.
    crate::log("cap_delegation_chain: revoking root");
    cap_revoke(root).map_err(|_| "cap_delegation_chain: cap_revoke root failed")?;

    // Both derived caps must now be unusable.
    let post_revoke_l1 = notification_send(level1, 0x1);
    if post_revoke_l1.is_ok()
    {
        return Err(
            "cap_delegation_chain: level1 still usable after root revocation (cascade failed)",
        );
    }

    let post_revoke_l2 = notification_send(level2, 0x1);
    if post_revoke_l2.is_ok()
    {
        return Err(
            "cap_delegation_chain: level2 still usable after root revocation (cascade failed)",
        );
    }

    // Cleanup: level1/level2 slots are invalid after revoke (.ok() ignores errors).
    // root is still valid and must be explicitly deleted.
    cap_delete(level2).ok();
    cap_delete(level1).ok();
    cap_delete(root).ok();

    crate::log("cap_delegation_chain: PASS");
    Ok(())
}
