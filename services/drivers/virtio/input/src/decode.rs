// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/input/src/decode.rs

//! Keycode decoding and modifier-state tracking.
//!
//! Translates virtio-input `EV_KEY` events (carrying Linux input-event
//! keycodes) into the shared keysym ABI ([`ipc::keysym`]). Tracks Shift,
//! Ctrl, Alt, and Caps Lock state; Shift/Caps are resolved into the emitted
//! keysym (`A` vs `a`), and the full modifier mask is reported so consumers
//! can form Ctrl/Alt combinations without the driver encoding terminal
//! policy. US layout only — layout switching is out of scope.
//!
//! The raw-keycode → keysym table is transport-specific (virtio-input uses
//! Linux keycodes); a future USB-HID or PS-2 keyboard driver carries its own
//! table targeting the same keysym output. The [`ModifierState`] FSM is
//! transport-agnostic and a natural shared-crate extraction once a second
//! keyboard backend lands.

use ipc::keysym;

use crate::input::{EV_KEY, VirtioInputEvent};

// Linux input-event-codes (subset the driver maps). Source:
// `include/uapi/linux/input-event-codes.h`.
const KEY_ESC: u16 = 1;
const KEY_BACKSPACE: u16 = 14;
const KEY_TAB: u16 = 15;
const KEY_ENTER: u16 = 28;
const KEY_LEFTCTRL: u16 = 29;
const KEY_LEFTSHIFT: u16 = 42;
const KEY_RIGHTSHIFT: u16 = 54;
const KEY_LEFTALT: u16 = 56;
const KEY_CAPSLOCK: u16 = 58;
const KEY_RIGHTCTRL: u16 = 97;
const KEY_RIGHTALT: u16 = 100;
const KEY_HOME: u16 = 102;
const KEY_UP: u16 = 103;
const KEY_LEFT: u16 = 105;
const KEY_RIGHT: u16 = 106;
const KEY_END: u16 = 107;
const KEY_DOWN: u16 = 108;
const KEY_DELETE: u16 = 111;

/// One decoded key event: a resolved keysym, the modifier mask in effect, and
/// whether the key went down (`true`) or up (`false`).
pub struct DecodedKey
{
    pub keysym: u32,
    pub modifiers: u32,
    pub pressed: bool,
}

// Held-modifier-key bits. Left and right are tracked separately so releasing
// one side does not clear a modifier the other side still holds.
const HELD_SHIFT_L: u8 = 1 << 0;
const HELD_SHIFT_R: u8 = 1 << 1;
const HELD_CTRL_L: u8 = 1 << 2;
const HELD_CTRL_R: u8 = 1 << 3;
const HELD_ALT_L: u8 = 1 << 4;
const HELD_ALT_R: u8 = 1 << 5;

const HELD_SHIFT: u8 = HELD_SHIFT_L | HELD_SHIFT_R;
const HELD_CTRL: u8 = HELD_CTRL_L | HELD_CTRL_R;
const HELD_ALT: u8 = HELD_ALT_L | HELD_ALT_R;

/// Tracked modifier state across events. `held` is the set of currently-held
/// modifier keys; Caps Lock is a separate toggle (flips on each press).
pub struct ModifierState
{
    held: u8,
    caps: bool,
}

impl ModifierState
{
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            held: 0,
            caps: false,
        }
    }

    fn set_held(&mut self, bit: u8, pressed: bool)
    {
        if pressed
        {
            self.held |= bit;
        }
        else
        {
            self.held &= !bit;
        }
    }

    fn mask(&self) -> u32
    {
        let mut m = 0;
        if self.held & HELD_SHIFT != 0
        {
            m |= keysym::MOD_SHIFT;
        }
        if self.caps
        {
            m |= keysym::MOD_CAPS;
        }
        if self.held & HELD_CTRL != 0
        {
            m |= keysym::MOD_CTRL;
        }
        if self.held & HELD_ALT != 0
        {
            m |= keysym::MOD_ALT;
        }
        m
    }

    /// Decode one virtio-input event, updating modifier state. Returns the
    /// resolved key event, or `None` for events that carry no keysym (non-key
    /// types, autorepeat, and unmapped keycodes).
    pub fn decode(&mut self, ev: VirtioInputEvent) -> Option<DecodedKey>
    {
        if ev.event_type != EV_KEY
        {
            return None;
        }
        // virtio-input EV_KEY value: 1 = press, 0 = release, 2 = autorepeat.
        // Key-repeat is out of scope, so autorepeat is dropped.
        let pressed = match ev.value
        {
            1 => true,
            0 => false,
            _ => return None,
        };

        let code = ev.code;
        match code
        {
            KEY_LEFTSHIFT => self.set_held(HELD_SHIFT_L, pressed),
            KEY_RIGHTSHIFT => self.set_held(HELD_SHIFT_R, pressed),
            KEY_LEFTCTRL => self.set_held(HELD_CTRL_L, pressed),
            KEY_RIGHTCTRL => self.set_held(HELD_CTRL_R, pressed),
            KEY_LEFTALT => self.set_held(HELD_ALT_L, pressed),
            KEY_RIGHTALT => self.set_held(HELD_ALT_R, pressed),
            // Caps Lock toggles on the press edge only.
            KEY_CAPSLOCK if pressed => self.caps = !self.caps,
            _ =>
            {}
        }

        let modifiers = self.mask();
        let shift = self.held & HELD_SHIFT != 0;
        let sym = keysym_for(code, shift, self.caps)?;
        Some(DecodedKey {
            keysym: sym,
            modifiers,
            pressed,
        })
    }
}

/// Resolve a keycode to a keysym given the current Shift and Caps state.
fn keysym_for(code: u16, shift: bool, caps: bool) -> Option<u32>
{
    // Modifier keys are reported as their own keysym events.
    let modifier = match code
    {
        KEY_LEFTSHIFT => Some(keysym::SHIFT_L),
        KEY_RIGHTSHIFT => Some(keysym::SHIFT_R),
        KEY_LEFTCTRL => Some(keysym::CONTROL_L),
        KEY_RIGHTCTRL => Some(keysym::CONTROL_R),
        KEY_LEFTALT => Some(keysym::ALT_L),
        KEY_RIGHTALT => Some(keysym::ALT_R),
        KEY_CAPSLOCK => Some(keysym::CAPS_LOCK),
        _ => None,
    };
    if modifier.is_some()
    {
        return modifier;
    }

    if let Some(named) = named_keysym(code)
    {
        return Some(named);
    }

    let (base, shifted, caps_affects) = printable(code)?;
    // Caps Lock affects only letters; for digits/punctuation only Shift does.
    let upper = if caps_affects { shift ^ caps } else { shift };
    Some(if upper { shifted } else { base })
}

/// Named (non-printable) keys whose keysym is modifier-independent.
fn named_keysym(code: u16) -> Option<u32>
{
    let k = match code
    {
        KEY_ENTER => keysym::RETURN,
        KEY_BACKSPACE => keysym::BACKSPACE,
        KEY_TAB => keysym::TAB,
        KEY_ESC => keysym::ESCAPE,
        KEY_UP => keysym::UP,
        KEY_DOWN => keysym::DOWN,
        KEY_LEFT => keysym::LEFT,
        KEY_RIGHT => keysym::RIGHT,
        KEY_HOME => keysym::HOME,
        KEY_END => keysym::END,
        KEY_DELETE => keysym::DELETE,
        _ => return None,
    };
    Some(k)
}

/// Printable keys, returning `(base, shifted, caps_affects)`: the unshifted
/// keysym, the shifted keysym, and whether Caps Lock participates in the
/// Shift decision (`true` for letters only). Keysyms equal their Unicode
/// codepoint (US layout).
fn printable(code: u16) -> Option<(u32, u32, bool)>
{
    // Letters: base = lowercase, shifted = uppercase, Caps Lock applies.
    let letter = |lower: char, upper: char| Some((u32::from(lower), u32::from(upper), true));
    // Symbols and digits: Caps Lock does not apply.
    let sym = |base: char, shifted: char| Some((u32::from(base), u32::from(shifted), false));

    match code
    {
        16 => letter('q', 'Q'),
        17 => letter('w', 'W'),
        18 => letter('e', 'E'),
        19 => letter('r', 'R'),
        20 => letter('t', 'T'),
        21 => letter('y', 'Y'),
        22 => letter('u', 'U'),
        23 => letter('i', 'I'),
        24 => letter('o', 'O'),
        25 => letter('p', 'P'),
        30 => letter('a', 'A'),
        31 => letter('s', 'S'),
        32 => letter('d', 'D'),
        33 => letter('f', 'F'),
        34 => letter('g', 'G'),
        35 => letter('h', 'H'),
        36 => letter('j', 'J'),
        37 => letter('k', 'K'),
        38 => letter('l', 'L'),
        44 => letter('z', 'Z'),
        45 => letter('x', 'X'),
        46 => letter('c', 'C'),
        47 => letter('v', 'V'),
        48 => letter('b', 'B'),
        49 => letter('n', 'N'),
        50 => letter('m', 'M'),
        2 => sym('1', '!'),
        3 => sym('2', '@'),
        4 => sym('3', '#'),
        5 => sym('4', '$'),
        6 => sym('5', '%'),
        7 => sym('6', '^'),
        8 => sym('7', '&'),
        9 => sym('8', '*'),
        10 => sym('9', '('),
        11 => sym('0', ')'),
        12 => sym('-', '_'),
        13 => sym('=', '+'),
        26 => sym('[', '{'),
        27 => sym(']', '}'),
        39 => sym(';', ':'),
        40 => sym('\'', '"'),
        41 => sym('`', '~'),
        43 => sym('\\', '|'),
        51 => sym(',', '<'),
        52 => sym('.', '>'),
        53 => sym('/', '?'),
        57 => sym(' ', ' '),
        _ => None,
    }
}
