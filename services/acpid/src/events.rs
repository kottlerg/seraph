// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/events.rs

//! acpid's ACPI events (ACPI 6.5 § 4.8.1 and § 5.6): the fixed power button
//! of the `PM1a` event block and the general-purpose events of the `GPE0`
//! block, which raise the SCI.
//!
//! Each event has a status bit, which the hardware sets and a write of 1
//! clears, and an enable bit; the SCI is asserted while any event has both.
//! The event thread runs [`scan`] on each SCI: it clears the enable bit of
//! every event that fired, so the SCI deasserts, and leaves its status set.
//! The evaluation thread then handles the event and enables it again: a
//! GPE's `\_GPE._Lxx` or `_Exx` method between [`gpe_begin`] and
//! [`gpe_end`], the power button once its `WAIT_EVENT` reply is delivered
//! ([`rearm_power_button`]). Because a status bit is cleared only once
//! its event is handled, an event that a dead acpid had not handled is
//! still set when the restarted acpid runs [`arm`], which dispatches it.
//! A sleep ([`quiesce`]) and an acpid that cannot take the SCI ([`clear`])
//! are the exceptions: they clear every status, so an event taken but not
//! yet handled before either is handled only by the acpid that took it.
//!
//! The registers are reached through [`Registers`], which the binary
//! implements with port I/O and the tests with a simulated register file.

use aml::Namespace;
use aml::encoding::Seg;
use aml::namespace::{NodeId, Object};

/// `PM1_STS` and `PM1_EN` bit 8: `PWRBTN_STS` and `PWRBTN_EN`, the fixed
/// power button.
pub const PWRBTN: u16 = 1 << 8;

/// The `PM1_STS` bits of the fixed events: `TMR_STS` (0), `BM_STS` (4),
/// `GBL_STS` (5), `PWRBTN_STS` (8), `SLPBTN_STS` (9), `RTC_STS` (10) and
/// `WAK_STS` (15). A write of these bits clears them.
pub const FIXED_STATUS: u16 = 1 | (1 << 4) | (1 << 5) | PWRBTN | (1 << 9) | (1 << 10) | (1 << 15);

/// The `PM1_EN` bits of the fixed events: `TMR_EN` (0), `GBL_EN` (5),
/// `PWRBTN_EN` (8), `SLPBTN_EN` (9) and `RTC_EN` (10). Every other bit is
/// kept as it reads.
pub const FIXED_ENABLE: u16 = 1 | (1 << 5) | PWRBTN | (1 << 9) | (1 << 10);

/// FADT `Flags` (offset 112) bit 4, `PWR_BUTTON`: set when the power
/// button is a control-method device, clear when it is the fixed one.
const FADT_PWR_BUTTON: u32 = 1 << 4;

/// FADT `Flags` offset.
const FADT_OFF_FLAGS: usize = 112;

/// Bytes of an ACPI table header, which holds its length at offset 4.
const SDT_HDR_LEN: usize = 36;

/// Port access to the event blocks.
pub trait Registers
{
    /// Read the byte at `port`.
    fn read8(&mut self, port: u16) -> u8;
    /// Write `value` to `port`.
    fn write8(&mut self, port: u16, value: u8);
    /// Read the word at `port`.
    fn read16(&mut self, port: u16) -> u16;
    /// Write `value` to `port`.
    fn write16(&mut self, port: u16, value: u16);
}

/// Where the event registers lie: the `PM1a` event block and the `GPE0`
/// block, each a status half and an enable half (ACPI 6.5 § 4.8.3.1 and
/// § 4.8.4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout
{
    /// `PM1a_EVT_BLK`, `PM1a_STS` at its start.
    pm1: u16,
    /// `PM1_EVT_LEN`, of which `PM1a_EN` is the second half.
    pm1_len: u16,
    /// `GPE0_BLK` and `GPE0_BLK_LEN`, when the platform has the block.
    gpe0: Option<(u16, u16)>,
}

impl Layout
{
    /// The layout of the `PM1a` event block of `pm1_len` ports at `pm1`
    /// and the `GPE0` block `gpe0`, its first port and port count; `None`
    /// when the `PM1a` block is shorter than its two 16-bit registers or not
    /// an even length, or a `GPE0` block is empty or not an even length, or
    /// a block runs past the last port.
    #[must_use]
    pub fn new(pm1: u16, pm1_len: u64, gpe0: Option<(u16, u64)>) -> Option<Self>
    {
        let block = |port: u16, len: u64| {
            let len = u16::try_from(len).ok().filter(|l| *l > 0 && l % 2 == 0)?;
            port.checked_add(len.saturating_sub(1))?;
            Some(len)
        };
        let pm1_len = block(pm1, pm1_len).filter(|&l| l >= 4)?;
        let gpe0 = match gpe0
        {
            Some((port, len)) => Some((port, block(port, len)?)),
            None => None,
        };
        Some(Self { pm1, pm1_len, gpe0 })
    }

    /// The number of GPEs of the `GPE0` block: 8 for each byte of its
    /// status half.
    #[must_use]
    pub fn gpe_count(&self) -> u16
    {
        self.gpe0.map_or(0, |(_, len)| (len / 2).saturating_mul(8))
    }

    const fn pm1_status(&self) -> u16
    {
        self.pm1
    }

    /// `PM1a_EN`, which [`Layout::new`] checked lies inside the port space.
    const fn pm1_enable(&self) -> u16
    {
        self.pm1.saturating_add(self.pm1_len / 2)
    }

    /// The status and enable ports of `GPE0` register `index`, the byte of
    /// GPEs `8 * index` to `8 * index + 7`.
    fn gpe_ports(&self, index: u16) -> Option<(u16, u16)>
    {
        let (port, len) = self.gpe0?;
        let half = len / 2;
        // In the block, which [`Layout::new`] checked lies inside the port
        // space.
        (index < half).then(|| {
            (
                port.saturating_add(index),
                port.saturating_add(half).saturating_add(index),
            )
        })
    }

    /// Whether `port` is a port of one of the blocks.
    #[must_use]
    pub fn holds(&self, port: u16) -> bool
    {
        let within = |base: u16, len: u16| port.checked_sub(base).is_some_and(|off| off < len);
        within(self.pm1, self.pm1_len) || self.gpe0.is_some_and(|(b, l)| within(b, l))
    }
}

/// How a GPE's method is triggered: `_Lxx` for a level-triggered GPE, whose
/// status is cleared after the method, `_Exx` for an edge-triggered one,
/// whose status is cleared before it (ACPI 6.5 § 5.6.4.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger
{
    /// `_Lxx`.
    Level,
    /// `_Exx`.
    Edge,
}

/// A GPE acpid handles: its number, trigger and `\_GPE` method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handler
{
    /// The GPE's number in the `GPE0` block.
    pub gpe: u16,
    /// Its trigger.
    pub trigger: Trigger,
    /// The method to run.
    pub method: NodeId,
}

/// The GPEs acpid handles: each `\_GPE._Lxx` and `_Exx` control method of
/// a GPE below `count`, in GPE order; and the names of the `\_GPE` methods
/// of that form left out, a GPE at or past `count` or one a method of the
/// other trigger names already.
#[must_use]
pub fn handlers(ns: &Namespace, count: u16) -> (Vec<Handler>, Vec<Seg>)
{
    let mut handled: Vec<Handler> = Vec::new();
    let mut ignored = Vec::new();
    let Some(gpe_scope) = ns.find("\\_GPE")
    else
    {
        return (handled, ignored);
    };
    for node in ns.children(gpe_scope)
    {
        let Some(name) = ns.name(node)
        else
        {
            continue;
        };
        let Some((trigger, gpe)) = gpe_method_name(name)
        else
        {
            continue;
        };
        let Some(Object::Method(_)) = ns.object(node)
        else
        {
            continue;
        };
        if gpe >= count || handled.iter().any(|h| h.gpe == gpe)
        {
            ignored.push(name);
            continue;
        }
        handled.push(Handler {
            gpe,
            trigger,
            method: node,
        });
    }
    handled.sort_by_key(|h| h.gpe);
    (handled, ignored)
}

/// The trigger and GPE number a `\_GPE` method name gives: `_Lxx` or
/// `_Exx` with `xx` two upper-case hexadecimal digits.
fn gpe_method_name(name: Seg) -> Option<(Trigger, u16)>
{
    let trigger = match name
    {
        [b'_', b'L', ..] => Trigger::Level,
        [b'_', b'E', ..] => Trigger::Edge,
        _ => return None,
    };
    let digit = |c: u8| {
        char::from(c)
            .to_digit(16)
            .filter(|_| !c.is_ascii_lowercase())
    };
    let [_, _, high, low] = name;
    let gpe = (digit(high)? << 4) | digit(low)?;
    Some((trigger, u16::try_from(gpe).ok()?))
}

/// Whether the FADT `fadt` declares the fixed power button: its `Flags`'
/// `PWR_BUTTON` bit clear. `None` when the table is not a FADT or does not
/// reach `Flags`.
#[must_use]
pub fn fixed_power_button(fadt: &[u8]) -> Option<bool>
{
    if fadt.get(..4)? != b"FACP"
    {
        return None;
    }
    let len = u32::from_le_bytes(fadt.get(4..8)?.try_into().ok()?);
    let len = usize::try_from(len).ok()?.min(fadt.len());
    if len < SDT_HDR_LEN
    {
        return None;
    }
    let flags = u32::from_le_bytes(
        fadt.get(..len)?
            .get(FADT_OFF_FLAGS..FADT_OFF_FLAGS + 4)?
            .try_into()
            .ok()?,
    );
    Some(flags & FADT_PWR_BUTTON == 0)
}

/// The events of a [`scan`] or of [`arm`]: their status set and their
/// enable cleared, each to be handled and then enabled again.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fired
{
    /// The power button was pressed.
    pub power_button: bool,
    /// The GPEs, in number order.
    pub gpes: Vec<u16>,
}

/// The events acpid handles.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Handled
{
    /// The fixed power button ([`fixed_power_button`]).
    pub power_button: bool,
    /// The GPEs of the `GPE0` block that have a method ([`handlers`]).
    pub gpes: Vec<u16>,
}

/// Which start of acpid in the boot this is: on the first, acquisition
/// [`clear`]s the events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start
{
    /// The first: no acpid ran in this boot before.
    First,
    /// A restart, after an acpid of this boot died.
    Restart,
}

/// The first start of the boot, before anything else touches the events:
/// disable every fixed event and GPE and clear every status, the
/// power-button press that turned the machine on among them. An event
/// latched after it is a real one, which [`arm`] keeps.
pub fn clear(regs: &mut impl Registers, layout: &Layout)
{
    disable_and_clear(regs, layout, 0);
}

/// Before the `PM1a_CNT` writes that enter a sleep state (ACPI 6.5
/// § 16.1.6): disable every GPE and every fixed event but the power button,
/// S5's wake event, whose enable is left as it reads, then clear every
/// status, `WAK_STS` among them, so that no event acpid armed stays a wake
/// source. acpid enables no GPE for wake: it evaluates no `_PRW`. The
/// status of an event acpid took and has not yet handled (a press not yet
/// delivered, a GPE whose method has not run) is cleared too: the
/// specification leaves no status set on entry, and the event stays queued
/// in acpid, though a restart no longer finds it latched. [`resume`]
/// enables the GPEs again when the platform keeps running.
pub fn quiesce(regs: &mut impl Registers, layout: &Layout)
{
    disable_and_clear(regs, layout, PWRBTN);
}

/// Disable every fixed event but those of `keep`, a mask of
/// [`FIXED_ENABLE`] bits left as they read, and every GPE; then clear
/// every status.
fn disable_and_clear(regs: &mut impl Registers, layout: &Layout, keep: u16)
{
    let enable = regs.read16(layout.pm1_enable());
    regs.write16(layout.pm1_enable(), enable & !(FIXED_ENABLE & !keep));
    let status = regs.read16(layout.pm1_status()) & FIXED_STATUS;
    if status != 0
    {
        regs.write16(layout.pm1_status(), status);
    }
    for index in 0..layout.gpe_count() / 8
    {
        let Some((sts, en)) = layout.gpe_ports(index)
        else
        {
            break;
        };
        regs.write8(en, 0);
        let status = regs.read8(sts);
        if status != 0
        {
            regs.write8(sts, status);
        }
    }
}

/// Set up the events on acpid's start: disable every fixed event and GPE
/// acpid does not handle and clear its status; enable each event of
/// `handled`, except those whose status is already set, which are
/// returned to be dispatched, still disabled. Such an event latched after
/// the first start's [`clear`], or was left by an acpid of this boot that
/// died before it handled it.
pub fn arm(regs: &mut impl Registers, layout: &Layout, handled: &Handled) -> Fired
{
    let mut fired = Fired::default();
    let status = clear_fixed_status(regs, layout, handled);
    let mut enable = regs.read16(layout.pm1_enable()) & !FIXED_ENABLE;
    if handled.power_button
    {
        if status & PWRBTN != 0
        {
            fired.power_button = true;
        }
        else
        {
            enable |= PWRBTN;
        }
    }
    regs.write16(layout.pm1_enable(), enable);
    fired.gpes = arm_gpes(regs, layout, &handled.gpes);
    fired
}

/// After a sleep whose `PM1a_CNT` writes returned, the platform still
/// running: enable again each GPE of `handled` that [`quiesce`] disabled,
/// except those whose status latched since, which are returned to be
/// dispatched, still disabled; clear the status of every other fixed event
/// and GPE. The power button is left as [`quiesce`] left it: a press taken
/// before or during the sleep is handled, and the button enabled again, by
/// the path that took it, so it is never returned here.
pub fn resume(regs: &mut impl Registers, layout: &Layout, handled: &Handled) -> Fired
{
    clear_fixed_status(regs, layout, handled);
    Fired {
        power_button: false,
        gpes: arm_gpes(regs, layout, &handled.gpes),
    }
}

/// Clear the status of every fixed event but the power button when
/// `handled` holds it; the `PM1_STS` value read before.
fn clear_fixed_status(regs: &mut impl Registers, layout: &Layout, handled: &Handled) -> u16
{
    let clear = if handled.power_button
    {
        FIXED_STATUS & !PWRBTN
    }
    else
    {
        FIXED_STATUS
    };
    let status = regs.read16(layout.pm1_status());
    if status & clear != 0
    {
        regs.write16(layout.pm1_status(), status & clear);
    }
    status
}

/// Enable each GPE of `gpes` whose status is clear and clear the status of
/// every other GPE; the GPEs of `gpes` whose status is set, left disabled.
fn arm_gpes(regs: &mut impl Registers, layout: &Layout, gpes: &[u16]) -> Vec<u16>
{
    let mut pending_gpes = Vec::new();
    for index in 0..layout.gpe_count() / 8
    {
        let Some((sts, en)) = layout.gpe_ports(index)
        else
        {
            break;
        };
        let mask = gpe_mask(gpes, index);
        regs.write8(en, 0);
        let status = regs.read8(sts);
        let clear = status & !mask;
        if clear != 0
        {
            regs.write8(sts, clear);
        }
        let pending = status & !clear;
        pending_gpes.extend(bits(pending, index));
        regs.write8(en, mask & !pending);
    }
    pending_gpes
}

/// On an SCI: every event whose status and enable are both set, its enable
/// cleared and its status kept.
pub fn scan(regs: &mut impl Registers, layout: &Layout) -> Fired
{
    let mut fired = Fired::default();
    let enable = regs.read16(layout.pm1_enable());
    if regs.read16(layout.pm1_status()) & enable & PWRBTN != 0
    {
        regs.write16(layout.pm1_enable(), enable & !PWRBTN);
        fired.power_button = true;
    }
    for index in 0..layout.gpe_count() / 8
    {
        let Some((sts, en)) = layout.gpe_ports(index)
        else
        {
            break;
        };
        let enable = regs.read8(en);
        let active = regs.read8(sts) & enable;
        if active != 0
        {
            regs.write8(en, enable & !active);
            fired.gpes.extend(bits(active, index));
        }
    }
    fired
}

/// Before GPE `gpe`'s method runs: clear the status of an edge-triggered
/// GPE, so an edge during the method sets it again.
pub fn gpe_begin(regs: &mut impl Registers, layout: &Layout, gpe: u16, trigger: Trigger)
{
    if trigger == Trigger::Edge
    {
        clear_gpe(regs, layout, gpe);
    }
}

/// After GPE `gpe`'s method ran: clear the status of a level-triggered GPE,
/// whose method has quieted its source, and enable the GPE again.
pub fn gpe_end(regs: &mut impl Registers, layout: &Layout, gpe: u16, trigger: Trigger)
{
    if trigger == Trigger::Level
    {
        clear_gpe(regs, layout, gpe);
    }
    if let Some((_, en)) = layout.gpe_ports(gpe / 8)
    {
        let bit = 1u8 << (gpe % 8);
        let enable = regs.read8(en);
        regs.write8(en, enable | bit);
    }
}

/// After a press was delivered: clear `PWRBTN_STS` and enable the power
/// button again.
pub fn rearm_power_button(regs: &mut impl Registers, layout: &Layout)
{
    regs.write16(layout.pm1_status(), PWRBTN);
    let enable = regs.read16(layout.pm1_enable());
    regs.write16(layout.pm1_enable(), enable | PWRBTN);
}

fn clear_gpe(regs: &mut impl Registers, layout: &Layout, gpe: u16)
{
    if let Some((sts, _)) = layout.gpe_ports(gpe / 8)
    {
        regs.write8(sts, 1 << (gpe % 8));
    }
}

/// The bits of GPE register `index` that `gpes` names.
fn gpe_mask(gpes: &[u16], index: u16) -> u8
{
    gpes.iter()
        .filter(|&&g| g / 8 == index)
        .fold(0, |m, &g| m | (1 << (g % 8)))
}

/// The GPE numbers of the bits set in `byte` of GPE register `index`.
fn bits(byte: u8, index: u16) -> impl Iterator<Item = u16>
{
    (0..8u16)
        .filter(move |b| byte & (1 << b) != 0)
        .map(move |b| index.saturating_mul(8).saturating_add(b))
}

#[cfg(test)]
mod tests
{
    use std::collections::BTreeMap;

    use super::*;
    use crate::sim;

    /// QEMU q35's event blocks: `PM1a` events at 0x600 (4 ports), `GPE0`
    /// at 0x620 (16 ports, 64 GPEs).
    fn q35() -> Layout
    {
        Layout::new(0x600, 4, Some((0x620, 16))).unwrap()
    }

    /// A register file: the status registers clear the bits written as 1,
    /// every other port keeps what is written; ports read 0 at first.
    #[derive(Default)]
    struct Regs
    {
        bytes: BTreeMap<u16, u8>,
    }

    impl Regs
    {
        fn w1c(port: u16) -> bool
        {
            (0x600..0x602).contains(&port) || (0x620..0x628).contains(&port)
        }

        fn get(&self, port: u16) -> u8
        {
            self.bytes.get(&port).copied().unwrap_or(0)
        }

        fn put(&mut self, port: u16, value: u8)
        {
            let value = if Self::w1c(port)
            {
                self.get(port) & !value
            }
            else
            {
                value
            };
            self.bytes.insert(port, value);
        }

        /// The hardware raising `bits` at `port`.
        fn raise(&mut self, port: u16, bits: u8)
        {
            let v = self.get(port) | bits;
            self.bytes.insert(port, v);
        }

        fn word(&self, port: u16) -> u16
        {
            u16::from_le_bytes([self.get(port), self.get(port + 1)])
        }
    }

    impl Registers for Regs
    {
        fn read8(&mut self, port: u16) -> u8
        {
            self.get(port)
        }

        fn write8(&mut self, port: u16, value: u8)
        {
            self.put(port, value);
        }

        fn read16(&mut self, port: u16) -> u16
        {
            self.word(port)
        }

        fn write16(&mut self, port: u16, value: u16)
        {
            let [lo, hi] = value.to_le_bytes();
            self.put(port, lo);
            self.put(port + 1, hi);
        }
    }

    /// `PWRBTN`'s bit in the high byte of a `PM1` register.
    const PWRBTN_HI: u8 = 1;

    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "power_button is data: the value of `Handled::power_button`"
    )]
    fn handled(power_button: bool, gpes: &[u16]) -> Handled
    {
        Handled {
            power_button,
            gpes: gpes.to_vec(),
        }
    }

    #[test]
    fn layout_takes_the_halves_and_refuses_short_odd_or_overflowing_blocks()
    {
        let l = q35();
        assert_eq!(l.gpe_count(), 64);
        assert_eq!(l.pm1_enable(), 0x602);
        assert_eq!(l.gpe_ports(0), Some((0x620, 0x628)));
        assert_eq!(l.gpe_ports(7), Some((0x627, 0x62F)));
        assert_eq!(l.gpe_ports(8), None);
        assert!(l.holds(0x603) && l.holds(0x62F));
        assert!(!l.holds(0x604) && !l.holds(0x630) && !l.holds(0x5FF));
        assert_eq!(Layout::new(0x600, 2, None), None);
        assert_eq!(Layout::new(0x600, 5, None), None);
        assert_eq!(Layout::new(0xFFFE, 4, None), None);
        assert_eq!(Layout::new(0x600, 4, Some((0x620, 0))), None);
        assert_eq!(Layout::new(0x600, 4, Some((0x620, 3))), None);
        assert_eq!(Layout::new(0x600, 4, None).unwrap().gpe_count(), 0);
    }

    #[test]
    fn first_start_clears_every_status_then_enables_only_what_acpid_handles()
    {
        let l = q35();
        let mut r = Regs::default();
        // The press that powered the machine on, a stale RTC alarm, the
        // firmware's own enables, and latched GPEs 1 and 9.
        r.raise(0x601, PWRBTN_HI | 0x04);
        r.bytes.insert(0x602, 0x21);
        r.bytes.insert(0x603, 0x44);
        r.raise(0x620, 0b10);
        r.raise(0x621, 0b10);
        r.bytes.insert(0x621 + 8, 0xFF);
        clear(&mut r, &l);
        assert_eq!(r.word(0x602), 0x4000);
        assert_eq!(r.get(0x629), 0);
        let fired = arm(&mut r, &l, &handled(true, &[1, 2]));
        assert_eq!(fired, Fired::default());
        assert_eq!(r.word(0x600), 0);
        // PWRBTN_EN alone of the fixed enables, bit 14 kept.
        assert_eq!(r.word(0x602), 0x4000 | PWRBTN);
        assert_eq!(r.get(0x620), 0);
        assert_eq!(r.get(0x621), 0);
        assert_eq!(r.get(0x628), 0b110);
        assert_eq!(r.get(0x629), 0);
    }

    #[test]
    fn quiesce_leaves_only_the_power_button_enabled_and_no_status_and_resume_restores()
    {
        let l = q35();
        let mut r = Regs::default();
        clear(&mut r, &l);
        let armed = handled(true, &[1, 2, 9]);
        arm(&mut r, &l, &armed);
        // A non-event enable bit (14), and what latched since: a press,
        // WAK_STS, an RTC alarm, the handled GPEs 1 and 9, unhandled GPE 23.
        r.bytes.insert(0x603, r.get(0x603) | 0x40);
        r.raise(0x601, PWRBTN_HI | 0x80 | 0x04);
        r.raise(0x620, 0b10);
        r.raise(0x621, 0b10);
        r.raise(0x622, 0x80);
        let before = (r.word(0x602), r.get(0x628), r.get(0x629));
        assert_eq!(before, (0x4000 | PWRBTN, 0b110, 0b10));

        quiesce(&mut r, &l);
        // No GPE is enabled when the sleep's writes are reached, and of the
        // fixed events the power button alone; every status is clear.
        for port in 0x628..0x630
        {
            assert_eq!(r.get(port), 0, "GPE enable {port:#x}");
        }
        for port in 0x620..0x628
        {
            assert_eq!(r.get(port), 0, "GPE status {port:#x}");
        }
        assert_eq!(r.word(0x602), 0x4000 | PWRBTN);
        assert_eq!(r.word(0x600), 0);

        // The platform keeps running: resuming restores the enables.
        assert_eq!(resume(&mut r, &l, &armed), Fired::default());
        assert_eq!((r.word(0x602), r.get(0x628), r.get(0x629)), before);
    }

    #[test]
    fn resume_reports_no_press_again_and_dispatches_the_gpes_latched_in_the_grace()
    {
        let l = q35();
        let mut r = Regs::default();
        let armed = handled(true, &[1, 2]);
        arm(&mut r, &l, &armed);
        quiesce(&mut r, &l);
        // A press during the grace: the scan takes it, and its delivery's
        // re-enable waits behind the sleep. GPE 1 latches too.
        r.raise(0x601, PWRBTN_HI);
        r.raise(0x620, 0b10);
        assert_eq!(
            scan(&mut r, &l),
            Fired {
                power_button: true,
                gpes: Vec::new(),
            }
        );
        let fired = resume(&mut r, &l, &armed);
        assert_eq!(
            fired,
            Fired {
                power_button: false,
                gpes: vec![1],
            }
        );
        // The button stays as the scan left it, its press latched for its
        // re-enable; GPE 1 waits for its method, GPE 2 is enabled.
        assert_eq!(r.word(0x602) & PWRBTN, 0);
        assert_eq!(r.word(0x600), PWRBTN);
        assert_eq!(r.get(0x628), 0b100);
        rearm_power_button(&mut r, &l);
        assert_eq!(r.word(0x600), 0);
        assert_eq!(r.word(0x602) & PWRBTN, PWRBTN);
    }

    #[test]
    fn quiesce_keeps_a_press_pending_delivery_disabled()
    {
        let l = q35();
        let mut r = Regs::default();
        arm(&mut r, &l, &handled(true, &[]));
        r.raise(0x601, PWRBTN_HI);
        assert!(scan(&mut r, &l).power_button);
        quiesce(&mut r, &l);
        assert_eq!(r.word(0x602), 0);
        assert_eq!(r.word(0x600), 0);
    }

    #[test]
    fn restart_returns_the_press_and_the_gpes_the_dead_acpid_left_and_keeps_them_disabled()
    {
        let l = q35();
        let mut r = Regs::default();
        r.raise(0x601, PWRBTN_HI);
        r.raise(0x600, 0x01);
        r.raise(0x620, 0b110);
        r.raise(0x622, 0x80);
        let fired = arm(&mut r, &l, &handled(true, &[1, 2]));
        assert_eq!(
            fired,
            Fired {
                power_button: true,
                gpes: vec![1, 2],
            }
        );
        // The press stays latched until it is delivered; the timer status
        // is cleared; the button and the pending GPEs stay disabled.
        assert_eq!(r.word(0x600), PWRBTN);
        assert_eq!(r.word(0x602) & PWRBTN, 0);
        assert_eq!(r.get(0x620), 0b110);
        assert_eq!(r.get(0x628), 0);
        // GPE 23, unhandled, is cleared and stays disabled.
        assert_eq!(r.get(0x622), 0);
        assert_eq!(r.get(0x62A), 0);

        rearm_power_button(&mut r, &l);
        assert_eq!(r.word(0x600), 0);
        assert_eq!(r.word(0x602) & PWRBTN, PWRBTN);
    }

    #[test]
    fn without_a_fixed_button_its_status_is_cleared_and_it_stays_disabled()
    {
        let l = q35();
        let mut r = Regs::default();
        r.raise(0x601, PWRBTN_HI);
        let fired = arm(&mut r, &l, &handled(false, &[]));
        assert_eq!(fired, Fired::default());
        assert_eq!(r.word(0x600), 0);
        assert_eq!(r.word(0x602), 0);
    }

    #[test]
    fn scan_disables_what_fired_and_leaves_its_status_for_the_handler()
    {
        let l = q35();
        let mut r = Regs::default();
        clear(&mut r, &l);
        arm(&mut r, &l, &handled(true, &[1, 9]));
        // A press, GPE 1, and GPE 3, which is disabled.
        r.raise(0x601, PWRBTN_HI);
        r.raise(0x620, 0b1010);
        let fired = scan(&mut r, &l);
        assert_eq!(
            fired,
            Fired {
                power_button: true,
                gpes: vec![1],
            }
        );
        assert_eq!(r.word(0x602) & PWRBTN, 0);
        assert_eq!(r.get(0x628), 0);
        assert_eq!(r.get(0x629), 0b10);
        assert_eq!(r.word(0x600), PWRBTN);
        assert_eq!(r.get(0x620), 0b1010);
        // Nothing enabled is set: a scan finds nothing more.
        assert_eq!(scan(&mut r, &l), Fired::default());
    }

    #[test]
    fn an_edge_gpe_is_cleared_before_its_method_and_a_level_one_after()
    {
        let l = q35();
        let mut r = Regs::default();
        r.raise(0x620, 0b10);
        r.raise(0x621, 0b10);
        gpe_begin(&mut r, &l, 1, Trigger::Edge);
        assert_eq!(r.get(0x620), 0);
        gpe_begin(&mut r, &l, 9, Trigger::Level);
        assert_eq!(r.get(0x621), 0b10);
        gpe_end(&mut r, &l, 9, Trigger::Level);
        assert_eq!(r.get(0x621), 0);
        assert_eq!(r.get(0x629), 0b10);
        // An edge during the method stays set, and is found by the next
        // scan once the GPE is enabled.
        r.raise(0x620, 0b10);
        gpe_end(&mut r, &l, 1, Trigger::Edge);
        assert_eq!(r.get(0x620), 0b10);
        assert_eq!(r.get(0x628), 0b10);
        assert_eq!(scan(&mut r, &l).gpes, vec![1]);
    }

    #[test]
    fn gpe_method_names_give_the_trigger_and_number()
    {
        assert_eq!(gpe_method_name(*b"_E01"), Some((Trigger::Edge, 1)));
        assert_eq!(gpe_method_name(*b"_L1F"), Some((Trigger::Level, 0x1F)));
        assert_eq!(gpe_method_name(*b"_EVT"), None);
        assert_eq!(gpe_method_name(*b"_e01"), None);
        assert_eq!(gpe_method_name(*b"_L1f"), None);
        assert_eq!(gpe_method_name(*b"_HID"), None);
    }

    #[test]
    fn q35_handles_the_gpe_methods_of_its_tables()
    {
        // `_E01` is ACPI PCI hotplug's (absent under native control),
        // `_E02` CPU hotplug's and `_E05` the VMGENID's, in SSDT1.
        for (config, expected) in [
            ("x86-default", &[1u16, 2, 5][..]),
            ("x86-rootport", &[1, 2, 5][..]),
            ("x86-rootport-native", &[2, 5][..]),
        ]
        {
            let ns = sim::fixture(config);
            let (handled, ignored) = handlers(&ns, 64);
            let gpes: Vec<u16> = handled.iter().map(|h| h.gpe).collect();
            assert_eq!(gpes, expected, "{config}");
            assert!(
                handled.iter().all(|h| h.trigger == Trigger::Edge),
                "{config}"
            );
            assert!(ignored.is_empty(), "{config}");
        }
        let ns = sim::fixture("riscv64-rootport");
        assert_eq!(handlers(&ns, 64), (Vec::new(), Vec::new()));
    }

    #[test]
    fn handlers_leave_out_a_gpe_past_the_block_and_a_second_method_of_one()
    {
        // \_GPE with _E01, _L01 and _L40, each Method (name, 0) { }.
        let method = |name: &[u8; 4]| [&[0x14, 0x06][..], name, &[0x00]].concat();
        let body = [
            &[0x10][..],
            &sim::pkg(
                &[
                    &b"\\_GPE"[..],
                    &method(b"_E01"),
                    &method(b"_L01"),
                    &method(b"_L40"),
                ]
                .concat(),
            ),
        ]
        .concat();
        let ns = sim::namespace(&[sim::table(&body)]);
        let (handled, mut ignored) = handlers(&ns, 64);
        assert_eq!(handled.len(), 1);
        assert_eq!(handled[0].gpe, 1);
        let other = match handled[0].trigger
        {
            Trigger::Edge => *b"_L01",
            Trigger::Level => *b"_E01",
        };
        ignored.sort_unstable();
        let mut expected = vec![other, *b"_L40"];
        expected.sort_unstable();
        assert_eq!(ignored, expected);
        assert_eq!(handlers(&ns, 0).0, Vec::new());
    }

    #[test]
    fn the_fadt_flags_say_whether_the_power_button_is_fixed()
    {
        let mut fadt = vec![0u8; 276];
        fadt[..4].copy_from_slice(b"FACP");
        fadt[4..8].copy_from_slice(&276u32.to_le_bytes());
        // QEMU q35: WBINVD, PROC_C1, SLP_BUTTON, RTC_S4 and more; not
        // PWR_BUTTON.
        fadt[112..116].copy_from_slice(&0x0000_84A5u32.to_le_bytes());
        assert_eq!(fixed_power_button(&fadt), Some(true));
        fadt[112] |= 0x10;
        assert_eq!(fixed_power_button(&fadt), Some(false));
        fadt[4..8].copy_from_slice(&100u32.to_le_bytes());
        assert_eq!(fixed_power_button(&fadt), None);
        fadt[..4].copy_from_slice(b"APIC");
        assert_eq!(fixed_power_button(&fadt), None);
    }
}
