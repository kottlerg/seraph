// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/kernel/src/entropy/health.rs

//! Continuous health tests for the hardware RNG (NIST SP 800-90B §4.4):
//! the Repetition Count Test (§4.4.1), the Adaptive Proportion Test
//! (§4.4.2), and the §4.3 startup gate, applied byte-wise. Cutoffs, startup
//! length, and the failure policy: [entropy.md](../../docs/entropy.md)
//! § Health tests (hardware RNG gating).

/// Conservative assessed min-entropy per byte from the hardware source.
const ASSESSED_H: u32 = 1;

/// RCT cutoff: `1 + ceil(30 / H)` (α = 2⁻³⁰).
const RCT_CUTOFF: u32 = 1 + 30u32.div_ceil(ASSESSED_H);

/// APT window length (samples): the §4.4.2 window for non-binary samples.
const APT_WINDOW: u32 = 512;

/// APT cutoff: reject when the window's first value recurs past ¾ of the window.
const APT_CUTOFF: u32 = APT_WINDOW * 3 / 4;

/// Bytes that must pass both tests before the source is trusted (§4.3).
const STARTUP_BYTES: u32 = 1024;

/// Continuous-health-test state for one hardware source.
pub struct Health
{
    rct_last: u8,
    rct_run: u32,
    apt_first: u8,
    apt_count: u32,
    apt_pos: u32,
    startup_remaining: u32,
    failed: bool,
}

impl Health
{
    /// Fresh state: nothing seen, startup pending.
    pub const fn new() -> Self
    {
        Self {
            rct_last: 0,
            rct_run: 0,
            apt_first: 0,
            apt_count: 0,
            apt_pos: APT_WINDOW, // force a new window on the first byte
            startup_remaining: STARTUP_BYTES,
            failed: false,
        }
    }

    /// Feed one byte through RCT and APT, updating startup progress.
    pub fn push(&mut self, byte: u8)
    {
        // RCT (§4.4.1): consecutive identical values.
        if self.rct_run != 0 && byte == self.rct_last
        {
            self.rct_run = self.rct_run.saturating_add(1);
            if self.rct_run >= RCT_CUTOFF
            {
                self.failed = true;
            }
        }
        else
        {
            self.rct_last = byte;
            self.rct_run = 1;
        }

        // APT (§4.4.2): proportion of the window's first sample.
        if self.apt_pos >= APT_WINDOW
        {
            self.apt_first = byte;
            self.apt_count = 1;
            self.apt_pos = 1;
        }
        else
        {
            if byte == self.apt_first
            {
                self.apt_count = self.apt_count.saturating_add(1);
                if self.apt_count > APT_CUTOFF
                {
                    self.failed = true;
                }
            }
            self.apt_pos = self.apt_pos.saturating_add(1);
        }

        self.startup_remaining = self.startup_remaining.saturating_sub(1);
    }

    /// Feed all 8 bytes of a 64-bit sample.
    pub fn push_word(&mut self, word: u64)
    {
        for b in word.to_le_bytes()
        {
            self.push(b);
        }
    }

    /// Whether the source has failed a health test (permanently distrusted).
    pub fn failed(&self) -> bool
    {
        self.failed
    }

    /// Whether the source has passed startup and is currently trusted.
    pub fn trusted(&self) -> bool
    {
        !self.failed && self.startup_remaining == 0
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn cutoffs()
    {
        // H = 1 → RCT cutoff = 1 + 30 = 31; APT cutoff = 3/4 of 512.
        assert_eq!(RCT_CUTOFF, 31);
        assert_eq!(APT_CUTOFF, 384);
    }

    #[test]
    fn varied_source_passes_startup()
    {
        let mut h = Health::new();
        // A non-repeating, well-spread stream over > STARTUP_BYTES bytes.
        let mut x = 0x1234_5678_9abc_def0u64;
        for _ in 0..(STARTUP_BYTES / 8 + 4)
        {
            x = x
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            h.push_word(x);
        }
        assert!(!h.failed(), "varied source must not trip a health test");
        assert!(h.trusted(), "varied source must pass startup");
    }

    #[test]
    fn stuck_source_trips_rct()
    {
        let mut h = Health::new();
        for _ in 0..RCT_CUTOFF
        {
            h.push(0xAA);
        }
        assert!(h.failed(), "stuck-at value must trip the RCT");
        assert!(!h.trusted());
    }

    #[test]
    fn biased_source_trips_apt()
    {
        let mut h = Health::new();
        // Mostly 0x00 (the window's first value) with a 0x01 marker every
        // RCT_CUTOFF samples, so the longest 0x00 run is RCT_CUTOFF-1 (RCT never
        // trips) yet 0x00 recurs far past the APT cutoff within one window.
        for i in 0..APT_WINDOW
        {
            let byte = u8::from(i % RCT_CUTOFF == RCT_CUTOFF - 1);
            h.push(byte);
        }
        assert!(h.failed(), "dominant value must trip the APT");
    }
}

/// Bounded proofs of the health tests (docs/testing.md § Bounded
/// verification), by induction over the bytes a source produces: `new`
/// starts in the invariant `holds` states, and one `push` of any byte
/// from any state in it keeps it, counts what NIST SP 800-90B §4.4 defines,
/// and fails only when a cutoff is passed. Every field of the state and the
/// byte are symbolic, so the two harnesses cover byte sequences of every
/// length with no loop to unwind (`push` has none; `push_word` is its eight
/// calls).
///
/// By induction: `rct_run` is the length of the current run of equal bytes,
/// saturated, so a run of `RCT_CUTOFF` equal bytes fails the source;
/// `apt_count` counts the window's first byte among the window's
/// `apt_pos` bytes, so a window holding it more than `APT_CUTOFF` times
/// fails it; failure is permanent; and the source is trusted exactly when
/// `STARTUP_BYTES` bytes have passed with no failure.
#[cfg(kani)]
mod proofs
{
    use super::{APT_CUTOFF, APT_WINDOW, Health, RCT_CUTOFF, STARTUP_BYTES};

    /// The invariant every reachable state keeps.
    fn holds(h: &Health) -> bool
    {
        (1..=APT_WINDOW).contains(&h.apt_pos)
            && h.apt_count <= h.apt_pos
            && h.startup_remaining <= STARTUP_BYTES
            && (h.rct_run < RCT_CUTOFF || h.failed)
            && (h.apt_count <= APT_CUTOFF || h.failed)
    }

    /// A fresh state is in the invariant, failed on nothing and not yet
    /// trusted.
    #[kani::proof]
    fn a_fresh_source_starts_in_the_invariant_untrusted()
    {
        let h = Health::new();
        assert!(holds(&h));
        assert!(!h.failed() && !h.trusted());
    }

    /// One byte from any state in the invariant keeps it; extends the run
    /// of equal bytes or starts a new one of length 1; counts the byte in
    /// the APT window or, past the window's end, opens a new window with it;
    /// counts startup down by one; and sets failure, which it never clears,
    /// only when `rct_run` reaches `RCT_CUTOFF` or `apt_count` passes
    /// `APT_CUTOFF`.
    #[kani::proof]
    fn each_byte_keeps_the_invariant_and_fails_only_past_a_cutoff()
    {
        let mut h = Health {
            rct_last: kani::any(),
            rct_run: kani::any(),
            apt_first: kani::any(),
            apt_count: kani::any(),
            apt_pos: kani::any(),
            startup_remaining: kani::any(),
            failed: kani::any(),
        };
        kani::assume(holds(&h));
        let before = Health { ..h };
        let byte: u8 = kani::any();
        h.push(byte);

        assert!(holds(&h));
        if before.rct_run != 0 && byte == before.rct_last
        {
            assert_eq!(h.rct_run, before.rct_run.saturating_add(1));
        }
        else
        {
            assert!(h.rct_run == 1 && h.rct_last == byte);
        }
        if before.apt_pos == APT_WINDOW
        {
            assert!(h.apt_first == byte && h.apt_count == 1 && h.apt_pos == 1);
        }
        else
        {
            assert!(h.apt_first == before.apt_first && h.apt_pos == before.apt_pos + 1);
            assert_eq!(
                h.apt_count,
                before.apt_count + u32::from(byte == before.apt_first)
            );
        }
        assert_eq!(
            h.startup_remaining,
            before.startup_remaining.saturating_sub(1)
        );
        assert!(h.failed || !before.failed);
        if h.failed && !before.failed
        {
            assert!(h.rct_run >= RCT_CUTOFF || h.apt_count > APT_CUTOFF);
        }
        assert_eq!(h.trusted(), !h.failed && h.startup_remaining == 0);
    }
}
