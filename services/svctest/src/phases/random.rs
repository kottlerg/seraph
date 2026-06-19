// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Userspace randomness surface (#246).
//!
//! Exercises `SYS_GETRANDOM` directly and the std `RandomState`/`HashMap`
//! seeding it backs (`hashmap_random_keys`). The gating property is
//! cross-process divergence: a respawned child's per-process hash seed must
//! differ from the parent's, proving the seed is drawn per process rather than
//! being a constant. (The former `unsupported` stub derived keys from stack and
//! heap addresses, identical across two runs of the same binary under seraph's
//! deterministic VA layout — so it would collide here, where the real
//! per-process kernel draw diverges.)

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// argv role: the child draws its own per-process hash seed and exits `0` iff
/// it differs from the parent fingerprint passed as `argv[2]`.
const ROLE_DIVERGE: &str = "random-diverge-child";

/// Fixed hasher input; the resulting hash depends only on the sampling thread's
/// `RandomState` `SipHash` keys (drawn via `hashmap_random_keys` → `SYS_GETRANDOM`).
const FINGERPRINT_INPUT: u64 = 0x5365_7261_7068_2121; // "Seraph!!"

pub fn phases() -> &'static [Phase]
{
    &[Phase {
        name: "random",
        run: random_phase,
    }]
}

/// Draw 8 random bytes from `SYS_GETRANDOM` as a `u64`.
fn draw_u64() -> u64
{
    let mut buf = [0u8; 8];
    let n = syscall::getrandom(buf.as_mut_ptr(), buf.len()).expect("SYS_GETRANDOM failed");
    assert_eq!(n, buf.len() as u64, "SYS_GETRANDOM short draw");
    u64::from_ne_bytes(buf)
}

/// Hash of a fixed value under a freshly-seeded `RandomState`, sampled in a new
/// thread so its thread-local `SipHash` keys come straight from this process's
/// `hashmap_random_keys()` at increment 0 — not from `RandomState`'s per-call
/// key bump. Sampling in a fresh thread on both sides keeps the parent and the
/// freshly-spawned child at the same increment, so the comparison reflects the
/// per-process kernel seed itself: a constant or non-per-process seed collides;
/// a real draw diverges.
fn base_fingerprint() -> u64
{
    std::thread::spawn(|| RandomState::new().hash_one(FINGERPRINT_INPUT))
        .join()
        .expect("fingerprint thread panicked")
}

/// Child-mode dispatch (see `reentry::dispatch`).
pub fn reentry_main(role: &str)
{
    if role == ROLE_DIVERGE
    {
        let parent = std::env::args()
            .nth(2)
            .and_then(|s| u64::from_str_radix(&s, 16).ok())
            .expect("random-diverge-child: missing/invalid parent fingerprint");
        // exit 0 = diverged (expected); 1 = collision (seed not per-process).
        std::process::exit(i32::from(base_fingerprint() == parent));
    }
}

pub fn random_phase(_: &Caps)
{
    // Direct SYS_GETRANDOM: successive draws differ and are not all-zero.
    let a = draw_u64();
    let b = draw_u64();
    assert_ne!(a, b, "two SYS_GETRANDOM draws returned identical bytes");
    assert!(a != 0 && b != 0, "SYS_GETRANDOM returned all-zero bytes");

    // HashMap seeding is live and random: two independently-seeded RandomState
    // keys (each sampled at increment 0) differ. A constant seed would collide.
    let p1 = base_fingerprint();
    let p2 = base_fingerprint();
    assert_ne!(
        p1, p2,
        "RandomState seeds collided in-process (HashMap seed not random)"
    );

    // Gating property: a respawned child's per-process seed must differ from ours.
    let mine = base_fingerprint();
    let status = std::process::Command::new("/tests/svctest")
        .arg(ROLE_DIVERGE)
        .arg(format!("{mine:x}"))
        .status()
        .expect("spawn /tests/svctest random-diverge-child failed");
    assert!(
        status.success(),
        "child hash seed matched parent — per-process seed not divergent: {status}"
    );

    std::os::seraph::log!("random phase passed");
}
