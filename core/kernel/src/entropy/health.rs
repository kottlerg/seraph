// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// kernel/src/entropy/health.rs

//! Continuous health tests for the hardware RNG (NIST SP 800-90B §4.4).
//!
//! Samples are processed byte-wise through the Repetition Count Test (RCT,
//! §4.4.1) and the Adaptive Proportion Test (APT, §4.4.2) to catch a noise
//! source that goes stuck or grossly biased. Per §4.3, the source is not
//! trusted until [`STARTUP_BYTES`] bytes have passed both tests. On any
//! failure the source is permanently distrusted and the subsystem falls back
//! to jitter — the hardware RNG is never the sole input regardless.
//!
//! Cutoffs assume a conservative assessed min-entropy of [`ASSESSED_H`]
//! bits/byte. RCT uses the spec formula `C = 1 + ceil(-log2(α)/H)` with
//! α = 2⁻³⁰. APT uses the spec's windowed mechanism with a conservative cutoff
//! (a single value dominating ¾ of the window): trivially tripped by a stuck or
//! near-stuck source, with negligible false-positive on a uniform source
//! (expected count W·2⁻ᴴ, many σ below the cutoff).

/// Conservative assessed min-entropy per byte from the hardware source.
const ASSESSED_H: u32 = 1;

/// RCT cutoff: `1 + ceil(30 / H)` (α = 2⁻³⁰).
const RCT_CUTOFF: u32 = 1 + 30_u32.div_ceil(ASSESSED_H);

/// APT window length (samples).
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
            self.rct_run += 1;
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
                self.apt_count += 1;
                if self.apt_count > APT_CUTOFF
                {
                    self.failed = true;
                }
            }
            self.apt_pos += 1;
        }

        if self.startup_remaining > 0
        {
            self.startup_remaining -= 1;
        }
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
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
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
            let byte = if i % RCT_CUTOFF == RCT_CUTOFF - 1
            {
                0x01
            }
            else
            {
                0x00
            };
            h.push(byte);
        }
        assert!(h.failed(), "dominant value must trip the APT");
    }
}
