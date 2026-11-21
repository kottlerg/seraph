// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/src/kat_hex.rs

//! Hex decoding of known-answer vectors at compile time, shared by the
//! known-answer tests of every primitive.

/// `text`, `2 * N` lower-case hex digits, as `N` bytes. Called only in the
/// initialisers of known-answer constants, so a malformed vector fails the
/// build.
#[expect(
    clippy::panic,
    reason = "evaluated only in constant initialisers, where a panic is a build error naming \
              the malformed vector, never a runtime panic"
)]
pub(crate) const fn hex<const N: usize>(text: &str) -> [u8; N]
{
    let mut out = [0u8; N];
    let mut digits = text.as_bytes();
    let mut slots = out.as_mut_slice();
    while let Some((slot, more)) = slots.split_first_mut()
    {
        let [high, low, rest @ ..] = digits
        else
        {
            panic!("hex vector shorter than its array");
        };
        *slot = (nibble(*high) << 4) | nibble(*low);
        digits = rest;
        slots = more;
    }
    assert!(digits.is_empty(), "hex vector longer than its array");
    out
}

/// The value of one lower-case hex digit.
#[expect(
    clippy::panic,
    reason = "evaluated only in constant initialisers through `hex`, where a panic is a build \
              error naming the malformed vector, never a runtime panic"
)]
const fn nibble(digit: u8) -> u8
{
    match digit
    {
        b'0'..=b'9' => digit.wrapping_sub(b'0'),
        b'a'..=b'f' => digit.wrapping_sub(b'a').wrapping_add(10),
        _ => panic!("not a lower-case hex digit"),
    }
}
