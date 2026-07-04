// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

//! Userspace randomness surface (#246) and ASLR layout divergence (#39).
//!
//! Exercises `SYS_GETRANDOM` directly and the std `RandomState`/`HashMap`
//! seeding it backs (`hashmap_random_keys`). The gating property is
//! cross-process divergence, checked twice: a respawned child's per-process
//! hash seed must differ from the parent's (proving the seed is a real
//! per-process kernel draw, not a constant), and the child's bootstrap
//! layout tuple must differ from the parent's (proving the creator draws
//! each process's layout independently).

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::os::seraph::startup_info;

use crate::bootstrap::Caps;
use crate::runner::Phase;

/// argv role: the child draws its own per-process hash seed and exits `0` iff
/// it differs from the parent fingerprint passed as `argv[2]`.
const ROLE_DIVERGE: &str = "random-diverge-child";

/// argv role: the child compares its bootstrap-layout tuple against the
/// parent tuple passed as `argv[2]` and exits `0` iff they differ.
const ROLE_LAYOUT_DIVERGE: &str = "aslr-layout-diverge-child";

/// Fixed hasher input; the resulting hash depends only on the sampling thread's
/// `RandomState` `SipHash` keys (drawn via `hashmap_random_keys` → `SYS_GETRANDOM`).
const FINGERPRINT_INPUT: u64 = 0x5365_7261_7068_2121; // "Seraph!!"

pub fn phases() -> &'static [Phase]
{
    &[
        Phase {
            name: "random",
            run: random_phase,
        },
        Phase {
            name: "aslr-layout",
            run: aslr_layout_phase,
        },
    ]
}

/// The parent-visible bootstrap-layout tuple: stack top, main-TLS base, IPC
/// buffer. Every component is an independent per-process window draw.
fn layout_fingerprint() -> String
{
    let info = startup_info();
    format!(
        "{:x}-{:x}-{:x}",
        info.stack_top_vaddr, info.main_tls_vaddr, info.ipc_buffer as u64
    )
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
    if role == ROLE_LAYOUT_DIVERGE
    {
        let parent = std::env::args()
            .nth(2)
            .expect("aslr-layout-diverge-child: missing parent layout tuple");
        // exit 0 = diverged (expected); 1 = collision (layout not per-process).
        std::process::exit(i32::from(layout_fingerprint() == parent));
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

pub fn aslr_layout_phase(_: &Caps)
{
    // Cross-process ASLR divergence (#39): a respawned child's bootstrap
    // layout tuple must differ from the parent's. Each component carries
    // 23 bits of independent entropy, so a false failure (all three draws
    // colliding at once) is ~2⁻⁶⁹ per run — negligible even under burn-in.
    let mine = layout_fingerprint();
    let status = std::process::Command::new("/tests/svctest")
        .arg(ROLE_LAYOUT_DIVERGE)
        .arg(&mine)
        .status()
        .expect("spawn /tests/svctest aslr-layout-diverge-child failed");
    assert!(
        status.success(),
        "child bootstrap layout matched parent — ASLR not divergent: {status}"
    );

    std::os::seraph::log!("aslr layout divergence phase passed");
}
