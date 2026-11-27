// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/console.rs

//! The console format: an entry as one line of the fields its sink's
//! settings name, in their order, one space between two fields
//! ([sinks.md](../../docs/sinks.md) § The console format).

use crate::level::TAG_WIDTH;
use crate::prefix::{NAME_FIELD_MAX, STAMP_MAX, pad_tag, write_name, write_stamp, write_tag};
use crate::settings::{Field, Fields, HOSTNAME_MAX};

/// Bytes of the longest `procid` field: a `u64` badge in hex.
pub(crate) const PROCID_MAX: usize = 16;

/// The bytes the console format writes around the message, at most: every
/// field but `msg` at its longest and a space after each.
pub const FRAME_MAX: usize = STAMP_MAX + HOSTNAME_MAX + TAG_WIDTH + NAME_FIELD_MAX + PROCID_MAX + 5;

/// What the fields of a line show of its entry.
#[derive(Clone, Copy)]
pub struct Entry<'a>
{
    /// When the entry was retained, microseconds since boot.
    pub us: u64,
    /// Its level, an `ipc::stream_labels::LEVEL_*` code.
    pub level: u64,
    /// The sender's badge.
    pub badge: u64,
    /// The sender's name, empty for one that registered none.
    pub name: &'a [u8],
    /// The host name, `None` while none is set.
    pub host: Option<&'a [u8]>,
}

/// A writer that counts the bytes it passes on.
struct Counter<'o, F: FnMut(u8)>
{
    out: &'o mut F,
    n: usize,
}

impl<F: FnMut(u8)> Counter<'_, F>
{
    fn put(&mut self, b: u8)
    {
        (self.out)(b);
        self.n = self.n.saturating_add(1);
    }
}

/// Write `entry`'s line in `fields` through `out`, its message written by
/// `msg`, without the line's end. The level tag is padded to [`TAG_WIDTH`]
/// columns when another field follows it, so the fields after it line up.
/// Returns where the tag is among the bytes written, its start and end
/// offsets, `None` when the fields show no level: what a sink colours.
pub fn write(
    fields: &Fields,
    entry: &Entry<'_>,
    out: &mut impl FnMut(u8),
    msg: impl FnOnce(&mut dyn FnMut(u8)),
) -> Option<(usize, usize)>
{
    let mut c = Counter { out, n: 0 };
    let mut tag = None;
    let mut msg = Some(msg);
    let list = fields.as_slice();
    for (i, field) in list.iter().enumerate()
    {
        if i > 0
        {
            c.put(b' ');
        }
        match field
        {
            Field::Time => write_stamp(entry.us, &mut |b| c.put(b)),
            Field::Host => match entry.host
            {
                Some(host) => host.iter().for_each(|&b| c.put(b)),
                None => c.put(b'-'),
            },
            Field::Level =>
            {
                let start = c.n;
                write_tag(entry.level, &mut |b| c.put(b));
                tag = Some((start, c.n));
                if i.saturating_add(1) < list.len()
                {
                    pad_tag(entry.level, &mut |b| c.put(b));
                }
            }
            Field::Name => write_name(entry.name, &mut |b| c.put(b)),
            Field::Procid => write_hex(entry.badge, &mut |b| c.put(b)),
            Field::Msg =>
            {
                if let Some(msg) = msg.take()
                {
                    msg(&mut |b| c.put(b));
                }
            }
        }
    }
    tag
}

/// Write `value` in lower-case hex, with no leading zeros.
pub(crate) fn write_hex(value: u64, out: &mut impl FnMut(u8))
{
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digits = (64u32.saturating_sub(value.leading_zeros()))
        .div_ceil(4)
        .max(1);
    for i in (0..digits).rev()
    {
        let nibble = value.checked_shr(i.saturating_mul(4)).unwrap_or(0) & 0xF;
        out(HEX
            .get(usize::try_from(nibble).unwrap_or(0))
            .copied()
            .unwrap_or(b'0'));
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::settings::SinkKind;
    use ipc::stream_labels::{LEVEL_CRITICAL, LEVEL_INFO, LEVEL_NOTICE};

    fn fields(list: &str) -> Fields
    {
        let text = format!("fields={list}");
        SinkKind::Serial
            .defaults()
            .parse_over(SinkKind::Serial, &text)
            .unwrap()
            .fields
    }

    fn line(fields: &Fields, entry: &Entry<'_>, text: &str) -> (String, Option<(usize, usize)>)
    {
        let mut bytes = Vec::new();
        let tag = write(fields, entry, &mut |b| bytes.push(b), |out| {
            text.bytes().for_each(out);
        });
        (String::from_utf8(bytes).unwrap(), tag)
    }

    const ENTRY: Entry<'static> = Entry {
        us: 6_308_457,
        level: LEVEL_NOTICE,
        badge: 0x2a,
        name: b"svcmgr",
        host: None,
    };

    // Defect caught: the default line differing from the prefix init-logd
    // writes, so the console changes character at the handover, or the tag's
    // span off the tag, so the framebuffer colours the wrong bytes.
    #[test]
    fn the_default_fields_write_the_shared_prefix_and_locate_the_tag()
    {
        let defaults = SinkKind::Serial.defaults();
        let (text, tag) = line(&defaults.fields, &ENTRY, "restarted");
        let mut prefix = Vec::new();
        crate::prefix::write(ENTRY.us, ENTRY.level, ENTRY.name, |b| prefix.push(b));
        assert_eq!(
            text,
            format!("{}restarted", String::from_utf8(prefix).unwrap())
        );
        assert_eq!(text, "[    6.308457] NOTICE [svcmgr] restarted");
        assert_eq!(tag, Some((15, 21)));
        assert_eq!(text.get(15..21), Some("NOTICE"));
        let info = Entry {
            level: LEVEL_INFO,
            ..ENTRY
        };
        let (text, tag) = line(&defaults.fields, &info, "up");
        assert_eq!(text, "[    6.308457] INFO   [svcmgr] up");
        assert_eq!(tag, Some((15, 19)));
    }

    // Defect caught: a field list written out of its order, a field written
    // twice or left out, or the tag padded at the end of a line.
    #[test]
    fn a_field_list_writes_its_fields_in_order_and_pads_the_tag_only_before_another()
    {
        let (text, tag) = line(&fields("msg:level"), &ENTRY, "m");
        assert_eq!(text, "m NOTICE");
        assert_eq!(tag, Some((2, 8)));
        let crit = Entry {
            level: LEVEL_CRITICAL,
            ..ENTRY
        };
        assert_eq!(line(&fields("msg:level"), &crit, "m").0, "m CRIT");
        assert_eq!(line(&fields("level:msg"), &crit, "m").0, "CRIT   m");
        assert_eq!(line(&fields("msg"), &ENTRY, "m"), ("m".into(), None));
        assert_eq!(
            line(&fields("procid:host:name:msg"), &ENTRY, "m").0,
            "2a - [svcmgr] m"
        );
        let named = Entry {
            host: Some(b"node-1"),
            badge: 0,
            name: b"",
            ..ENTRY
        };
        assert_eq!(
            line(&fields("host:procid:name:msg"), &named, "m").0,
            "node-1 0 [?] m"
        );
    }

    // Defect caught: a badge written with leading zeros, upper case, or cut,
    // so a procid does not match the badge a query reports.
    #[test]
    fn a_procid_is_the_badge_in_lower_case_hex()
    {
        let hex = |v| {
            let mut out = Vec::new();
            write_hex(v, &mut |b| out.push(b));
            String::from_utf8(out).unwrap()
        };
        assert_eq!(hex(0), "0");
        assert_eq!(hex(0xF), "f");
        assert_eq!(hex(0x10), "10");
        assert_eq!(hex(u64::MAX), "ffffffffffffffff");
        assert_eq!(hex(u64::MAX).len(), PROCID_MAX);
    }
}
