// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/keysym.rs

//! Keysym numbering, modifier mask bits, and the
//! [`input_labels::INPUT_READ_EVENTS`](crate::input_labels::INPUT_READ_EVENTS) event wire encoding — the
//! transport-agnostic contract shared by every keyboard driver and every
//! input consumer.
//!
//! Keysyms follow X11 numbering: a printable Latin-1 keysym *is* its Unicode
//! codepoint (`a` = 0x61, `A` = 0x41, `1` = 0x31), and named keys use the
//! `0xFF00`+ function range. The driver resolves Shift/Caps into the keysym
//! (`A` vs `a`) and reports the full modifier mask so consumers can form
//! Ctrl/Alt combinations without the driver encoding terminal policy. The mask
//! reflects state *after* the event is applied, so a modifier key's own press
//! event carries its bit (a Shift press reports `MOD_SHIFT` next to keysym
//! `SHIFT_L`); its release clears it.

// Named keys (X11 function-key range). Printable keys are not enumerated;
// their keysym equals their Unicode codepoint.
/// Keysym of the Backspace key.
pub const BACKSPACE: u32 = 0xFF08;
/// Keysym of the Tab key.
pub const TAB: u32 = 0xFF09;
/// Keysym of the Return key.
pub const RETURN: u32 = 0xFF0D;
/// Keysym of the Escape key.
pub const ESCAPE: u32 = 0xFF1B;
/// Keysym of the Home key.
pub const HOME: u32 = 0xFF50;
/// Keysym of the Left arrow key.
pub const LEFT: u32 = 0xFF51;
/// Keysym of the Up arrow key.
pub const UP: u32 = 0xFF52;
/// Keysym of the Right arrow key.
pub const RIGHT: u32 = 0xFF53;
/// Keysym of the Down arrow key.
pub const DOWN: u32 = 0xFF54;
/// Keysym of the End key.
pub const END: u32 = 0xFF57;
/// Keysym of the Delete key.
pub const DELETE: u32 = 0xFFFF;

// Modifier keys are delivered as their own press/release events too, so
// consumers can observe modifier state changes directly.
/// Keysym of the Left Shift key.
pub const SHIFT_L: u32 = 0xFFE1;
/// Keysym of the Right Shift key.
pub const SHIFT_R: u32 = 0xFFE2;
/// Keysym of the Left Control key.
pub const CONTROL_L: u32 = 0xFFE3;
/// Keysym of the Right Control key.
pub const CONTROL_R: u32 = 0xFFE4;
/// Keysym of the Caps Lock key.
pub const CAPS_LOCK: u32 = 0xFFE5;
/// Keysym of the Left Alt key.
pub const ALT_L: u32 = 0xFFE9;
/// Keysym of the Right Alt key.
pub const ALT_R: u32 = 0xFFEA;

// Modifier mask bits (X11 state-mask values: Shift=1, Lock=2, Control=4,
// Mod1=8). Reported in bits 32-62 of a packed event.
/// Modifier-mask bit: Shift held.
pub const MOD_SHIFT: u32 = 1 << 0;
/// Modifier-mask bit: Caps Lock active.
pub const MOD_CAPS: u32 = 1 << 1;
/// Modifier-mask bit: Control held.
pub const MOD_CTRL: u32 = 1 << 2;
/// Modifier-mask bit: Alt held.
pub const MOD_ALT: u32 = 1 << 3;

/// Maximum events returned by one
/// [`super::input_labels::INPUT_READ_EVENTS`] reply. Bounded so `word[0]`
/// (count) plus `n` event words fit the 64-word IPC data area with
/// headroom. Events past it stay in the device ring for the next read,
/// so the bound only adds reads.
pub const INPUT_MAX_EVENTS_PER_READ: usize = 32;

/// Pack a key event into one IPC data word: keysym in bits 0-31, the
/// modifier mask in bits 32-62, and `pressed` (true = down) in bit 63.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`pressed` is the key state, encoded in bit 63 of the event word"
)]
pub const fn pack_event(keysym: u32, modifiers: u32, pressed: bool) -> u64
{
    // `as` (not `u64::from`) because `From` is not const-callable; the
    // crate-level allow covers the (non-)truncating int casts.
    (keysym as u64) | (((modifiers & 0x7FFF_FFFF) as u64) << 32) | ((pressed as u64) << 63)
}

/// Inverse of [`pack_event`]: returns `(keysym, modifiers, pressed)`.
#[must_use]
pub const fn unpack_event(word: u64) -> (u32, u32, bool)
{
    let keysym = (word & 0xFFFF_FFFF) as u32;
    let modifiers = ((word >> 32) & 0x7FFF_FFFF) as u32;
    let pressed = (word >> 63) & 1 != 0;
    (keysym, modifiers, pressed)
}
