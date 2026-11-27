// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/logd/codec/src/settings.rs

//! A device sink's settings and the parser of the recipe syntax that sets
//! them ([sinks.md](../../docs/sinks.md) § Settings).
//!
//! logd keeps one [`SinkSettings`] per device sink, under its state lock, and
//! renders and paces the sink from it. At start it parses the sink's
//! `LOGD_SINK_<NAME>` entry of its recipe over the sink's defaults
//! ([`SinkKind::defaults`], [`SinkSettings::parse_over`]); an entry that does
//! not parse leaves the defaults whole. A runtime change of a sink's settings
//! parses its string the same way over the settings the sink has, so the
//! recipe and a runtime change share one syntax and one representation.

use core::fmt;

use ipc::stream_labels::{LEVEL_CRITICAL, LEVEL_DEBUG, LEVEL_INFO, level_or_info};

/// The largest `backlog` a sink takes.
pub const BACKLOG_MAX: u16 = 256;

/// The framebuffer's default `backlog`: the entries a screen shows when it
/// attaches, and the most its emergency walk writes before an emergency
/// entry.
pub const FRAMEBUFFER_BACKLOG: u16 = 64;

/// The largest rfc5424 `facility` (RFC 5424 §6.2.1: 0 to 23).
pub const FACILITY_MAX: u8 = 23;

/// The default rfc5424 `facility`: 3, system daemons.
pub const FACILITY_DAEMON: u8 = 3;

/// The most fields a console field list names: each of the six at most once.
pub const FIELDS_MAX: usize = 6;

/// The longest host name `LOGD_HOSTNAME` sets, in bytes (RFC 5424 §6.2.4).
pub const HOSTNAME_MAX: usize = 255;

/// The recipe's `env` key of the host name the console `host` field and the
/// rfc5424 HOSTNAME show.
pub const HOSTNAME_ENV: &str = "LOGD_HOSTNAME";

/// One of logd's device sinks, for the settings it takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SinkKind
{
    /// The serial console.
    Serial,
    /// The framebuffer.
    Framebuffer,
}

impl SinkKind
{
    /// The recipe's `env` key of the sink's settings.
    #[must_use]
    pub const fn env_key(self) -> &'static str
    {
        match self
        {
            Self::Serial => "LOGD_SINK_SERIAL",
            Self::Framebuffer => "LOGD_SINK_FRAMEBUFFER",
        }
    }

    /// The sink's settings when its recipe sets none: serial at info,
    /// `console`, `hold`, no backlog, `relayed` entries passed, no colour;
    /// the framebuffer at critical, `console`, `skip`, a backlog of
    /// [`FRAMEBUFFER_BACKLOG`], `relayed` entries shown, the level tag
    /// coloured.
    #[must_use]
    pub const fn defaults(self) -> SinkSettings
    {
        match self
        {
            Self::Serial => SinkSettings {
                level: Some(LEVEL_INFO),
                format: Format::Console,
                fields: Fields::DEFAULT,
                pace: Pace::Hold,
                backlog: 0,
                relayed: Relayed::Pass,
                colour: Colour::Off,
                facility: FACILITY_DAEMON,
            },
            Self::Framebuffer => SinkSettings {
                level: Some(LEVEL_CRITICAL),
                format: Format::Console,
                fields: Fields::DEFAULT,
                pace: Pace::Skip,
                backlog: FRAMEBUFFER_BACKLOG,
                relayed: Relayed::Show,
                colour: Colour::On,
                facility: FACILITY_DAEMON,
            },
        }
    }

    /// Whether the sink's driver can colour the level tag: the framebuffer's.
    const fn takes_colour(self) -> bool
    {
        matches!(self, Self::Framebuffer)
    }
}

/// A sink's output format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format
{
    /// The console format, with its field list ([`Fields`]).
    Console,
    /// One RFC 5424 message per entry.
    Rfc5424,
}

/// How a sink's progress holds senders back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pace
{
    /// While it is served and not stalled, its progress holds senders back,
    /// as do a flush and the kernel reader's acknowledgement, and the entries
    /// it shows and has not written are kept from eviction while another is
    /// left to evict.
    Hold,
    /// It holds nobody, and loses the entries the history evicts before it
    /// reaches them.
    Skip,
}

/// What a sink does with a `relayed` entry, one init-logd wrote to the
/// console before the handover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relayed
{
    /// Shows it.
    Show,
    /// Passes it, as one it does not show.
    Pass,
}

/// Whether a sink colours the level tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Colour
{
    /// The tag is drawn in its level's colour.
    On,
    /// No colour.
    Off,
}

/// One field of the console format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field
{
    /// The stamp: `[sec.usfrac]`, the seconds since boot.
    Time,
    /// The host name, `-` when none is set.
    Host,
    /// The level tag, padded to six columns when a field follows it.
    Level,
    /// `[name]`, `[?]` for a sender with no name.
    Name,
    /// The sender's badge in lower-case hex.
    Procid,
    /// The line's text, or a record's rendering.
    Msg,
}

impl Field
{
    /// Every field, in the order of the six keys.
    const ALL: [Self; FIELDS_MAX] = [
        Self::Time,
        Self::Host,
        Self::Level,
        Self::Name,
        Self::Procid,
        Self::Msg,
    ];

    /// The field's key in a field list.
    #[must_use]
    pub const fn key(self) -> &'static str
    {
        match self
        {
            Self::Time => "time",
            Self::Host => "host",
            Self::Level => "level",
            Self::Name => "name",
            Self::Procid => "procid",
            Self::Msg => "msg",
        }
    }

    /// The field a key names.
    fn of_key(key: &str) -> Option<Self>
    {
        Self::ALL.into_iter().find(|field| field.key() == key)
    }
}

/// The console format's fields, in the order a line shows them: each at
/// most once, `msg` always among them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields
{
    /// The fields, the first [`Self::len`] in use; the rest are `Msg`, so
    /// two lists of the same fields compare equal.
    list: [Field; FIELDS_MAX],
    /// The number of fields in use.
    len: usize,
}

impl Fields
{
    /// `time:level:name:msg`: `[sec.usfrac] LEVEL  [name] msg`.
    pub const DEFAULT: Self = Self {
        list: [
            Field::Time,
            Field::Level,
            Field::Name,
            Field::Msg,
            Field::Msg,
            Field::Msg,
        ],
        len: 4,
    };

    /// The fields in order.
    #[must_use]
    pub fn as_slice(&self) -> &[Field]
    {
        self.list.get(..self.len).unwrap_or_default()
    }

    /// The list a `fields` value names: `:`-separated keys, each at most
    /// once, `msg` among them; `None` for any other value.
    fn parse(value: &str) -> Option<Self>
    {
        let mut fields = Self {
            list: [Field::Msg; FIELDS_MAX],
            len: 0,
        };
        for key in value.split(':')
        {
            let field = Field::of_key(key)?;
            if fields.as_slice().contains(&field)
            {
                return None;
            }
            *fields.list.get_mut(fields.len)? = field;
            fields.len = fields.len.saturating_add(1);
        }
        fields.as_slice().contains(&Field::Msg).then_some(fields)
    }
}

/// One device sink's settings ([sinks.md](../../docs/sinks.md) § Settings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SinkSettings
{
    /// The least severe level the sink shows, an
    /// `ipc::stream_labels::LEVEL_*` code; `None` (`off`) while it shows
    /// none.
    pub level: Option<u64>,
    /// The output format.
    pub format: Format,
    /// The console format's fields.
    pub fields: Fields,
    /// How the sink's progress holds senders back.
    pub pace: Pace,
    /// For a `skip` sink, how many entries before the newest its cursor
    /// starts at when it attaches further behind; for every sink, the most
    /// entries the emergency walk writes before an emergency entry.
    pub backlog: u16,
    /// What the sink does with `relayed` entries.
    pub relayed: Relayed,
    /// Whether the level tag is coloured.
    pub colour: Colour,
    /// The rfc5424 format's facility for every entry but the kernel's.
    pub facility: u8,
}

impl SinkSettings
{
    /// Whether the sink shows an entry at `level`, of a `relayed` origin
    /// or not: at or above its level, and for a `relayed` entry, only when
    /// the sink shows those.
    #[must_use]
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "relayed is data: the entry's origin"
    )]
    pub fn shows(&self, level: u64, relayed: bool) -> bool
    {
        self.shows_level(level) && (!relayed || self.relayed == Relayed::Show)
    }

    /// Whether the sink's level admits an entry at `level`; a code past the
    /// eight reads as info.
    #[must_use]
    pub fn shows_level(&self, level: u64) -> bool
    {
        self.level
            .is_some_and(|least| level_or_info(level) <= least)
    }

    /// These settings with each `key=value` of `text` applied, items
    /// separated by `,`; the error names the first item that does not
    /// apply, and then nothing of `text` is applied. Each key is given at
    /// most once. `colour=yes` is refused for a sink whose driver draws no
    /// colour.
    ///
    /// # Errors
    ///
    /// [`SettingsError`] for an item with no `=`, an unknown or repeated key,
    /// or a value its key does not take.
    pub fn parse_over(self, kind: SinkKind, text: &str) -> Result<Self, SettingsError<'_>>
    {
        let mut out = self;
        let mut seen: u16 = 0;
        for item in text.split(',')
        {
            let Some((key, value)) = item.split_once('=')
            else
            {
                return Err(SettingsError::Malformed(item));
            };
            let setting = Key::of(key).ok_or(SettingsError::UnknownKey(key))?;
            if seen & setting.bit() != 0
            {
                return Err(SettingsError::Repeated(key));
            }
            seen |= setting.bit();
            if !out.apply(kind, setting, value)
            {
                return Err(SettingsError::BadValue { key, value });
            }
        }
        Ok(out)
    }

    /// Set `key` to `value`; `false` for a value the key does not take.
    fn apply(&mut self, kind: SinkKind, key: Key, value: &str) -> bool
    {
        match key
        {
            Key::Level =>
            {
                self.level = match value
                {
                    "off" => None,
                    _ => match log::parse_level(value.as_bytes())
                    {
                        Some(level) if level <= LEVEL_DEBUG => Some(level),
                        _ => return false,
                    },
                };
            }
            Key::Format =>
            {
                self.format = match value
                {
                    "console" => Format::Console,
                    "rfc5424" => Format::Rfc5424,
                    _ => return false,
                };
            }
            Key::Fields =>
            {
                let Some(fields) = Fields::parse(value)
                else
                {
                    return false;
                };
                self.fields = fields;
            }
            Key::Pace =>
            {
                self.pace = match value
                {
                    "hold" => Pace::Hold,
                    "skip" => Pace::Skip,
                    _ => return false,
                };
            }
            Key::Backlog =>
            {
                let Some(backlog) = decimal(value).and_then(|n| u16::try_from(n).ok())
                else
                {
                    return false;
                };
                if backlog > BACKLOG_MAX
                {
                    return false;
                }
                self.backlog = backlog;
            }
            Key::Relayed =>
            {
                self.relayed = match value
                {
                    "yes" => Relayed::Show,
                    "no" => Relayed::Pass,
                    _ => return false,
                };
            }
            Key::Colour =>
            {
                self.colour = match value
                {
                    "yes" if kind.takes_colour() => Colour::On,
                    "no" => Colour::Off,
                    _ => return false,
                };
            }
            Key::Facility =>
            {
                let Some(facility) = decimal(value).and_then(|n| u8::try_from(n).ok())
                else
                {
                    return false;
                };
                if facility > FACILITY_MAX
                {
                    return false;
                }
                self.facility = facility;
            }
        }
        true
    }
}

/// A settings key.
#[derive(Clone, Copy)]
enum Key
{
    Level,
    Format,
    Fields,
    Pace,
    Backlog,
    Relayed,
    Colour,
    Facility,
}

impl Key
{
    /// The key `key` names.
    fn of(key: &str) -> Option<Self>
    {
        Some(match key
        {
            "level" => Self::Level,
            "format" => Self::Format,
            "fields" => Self::Fields,
            "pace" => Self::Pace,
            "backlog" => Self::Backlog,
            "relayed" => Self::Relayed,
            "colour" => Self::Colour,
            "facility" => Self::Facility,
            _ => return None,
        })
    }

    /// The key's bit in the set of keys a string has given.
    const fn bit(self) -> u16
    {
        match self
        {
            Self::Level => 1,
            Self::Format => 1 << 1,
            Self::Fields => 1 << 2,
            Self::Pace => 1 << 3,
            Self::Backlog => 1 << 4,
            Self::Relayed => 1 << 5,
            Self::Colour => 1 << 6,
            Self::Facility => 1 << 7,
        }
    }
}

/// The value of a run of ASCII digits; `None` for any other text, or one
/// past `u64`.
fn decimal(value: &str) -> Option<u64>
{
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    value.parse().ok()
}

/// Why a settings string did not apply, naming the text at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsError<'a>
{
    /// An item with no `=`, an empty one included.
    Malformed(&'a str),
    /// A key no setting has.
    UnknownKey(&'a str),
    /// A key given a second time.
    Repeated(&'a str),
    /// A value the key does not take.
    BadValue
    {
        /// The key.
        key: &'a str,
        /// The value it does not take.
        value: &'a str,
    },
}

impl fmt::Display for SettingsError<'_>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::Malformed(item) => write!(f, "malformed item \"{item}\""),
            Self::UnknownKey(key) => write!(f, "unknown key \"{key}\""),
            Self::Repeated(key) => write!(f, "key \"{key}\" given twice"),
            Self::BadValue { key, value } => write!(f, "bad value \"{value}\" for {key}"),
        }
    }
}

/// The host name the console `host` field and the rfc5424 HOSTNAME show:
/// 1 to [`HOSTNAME_MAX`] printable US-ASCII bytes (33 to 126), as RFC 5424
/// §6.2.4 requires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostName
{
    bytes: [u8; HOSTNAME_MAX],
    len: usize,
}

impl HostName
{
    /// The host name `text` names; `None` for an empty one, a longer one,
    /// or one with a byte outside printable US-ASCII.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self>
    {
        let src = text.as_bytes();
        if src.is_empty() || !src.iter().all(|b| (33..=126).contains(b))
        {
            return None;
        }
        let mut bytes = [0u8; HOSTNAME_MAX];
        bytes.get_mut(..src.len())?.copy_from_slice(src);
        Some(Self {
            bytes,
            len: src.len(),
        })
    }

    /// The name's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use ipc::stream_labels::{LEVEL_EMERGENCY, LEVEL_ERROR, LEVEL_NOTICE, LEVEL_WARN};

    fn serial(text: &str) -> Result<SinkSettings, SettingsError<'_>>
    {
        SinkKind::Serial
            .defaults()
            .parse_over(SinkKind::Serial, text)
    }

    // Defect caught: a key read into another setting, or a value of one key
    // read as another value, so a recipe sets something it does not name.
    #[test]
    fn each_key_sets_its_own_setting_to_the_value_named()
    {
        let s = serial(
            "level=warn,format=rfc5424,fields=msg:name,pace=skip,backlog=256,\
             relayed=yes,colour=no,facility=23",
        )
        .unwrap();
        assert_eq!(s.level, Some(LEVEL_WARN));
        assert_eq!(s.format, Format::Rfc5424);
        assert_eq!(s.fields.as_slice(), [Field::Msg, Field::Name]);
        assert_eq!(s.pace, Pace::Skip);
        assert_eq!(s.backlog, 256);
        assert_eq!(s.relayed, Relayed::Show);
        assert_eq!(s.colour, Colour::Off);
        assert_eq!(s.facility, 23);
    }

    // Defect caught: a key a string does not name moved off its default, or
    // the framebuffer given serial's defaults.
    #[test]
    fn an_absent_key_keeps_the_sinks_default()
    {
        let s = serial("level=debug").unwrap();
        assert_eq!(
            s,
            SinkSettings {
                level: Some(LEVEL_DEBUG),
                ..SinkKind::Serial.defaults()
            }
        );
        let fb = SinkKind::Framebuffer.defaults();
        assert_eq!(fb.level, Some(LEVEL_CRITICAL));
        assert_eq!((fb.pace, fb.backlog), (Pace::Skip, FRAMEBUFFER_BACKLOG));
        assert_eq!((fb.relayed, fb.colour), (Relayed::Show, Colour::On));
        assert_eq!(SinkKind::Serial.defaults().pace, Pace::Hold);
    }

    // Defect caught: an off sink, or a level keyword, read wrong, so a quiet
    // sink shows lines or a verbose one hides them.
    #[test]
    fn a_level_shows_itself_and_the_more_severe_and_off_shows_none()
    {
        let warn = serial("level=warn").unwrap();
        assert!(warn.shows_level(LEVEL_EMERGENCY));
        assert!(warn.shows_level(LEVEL_WARN));
        assert!(!warn.shows_level(LEVEL_NOTICE));
        // A code past the eight reads as info.
        assert!(!warn.shows_level(LEVEL_DEBUG + 1));
        assert!(serial("level=info").unwrap().shows_level(LEVEL_DEBUG + 1));
        let off = serial("level=off").unwrap();
        assert_eq!(off.level, None);
        assert!(!off.shows_level(LEVEL_EMERGENCY));
        assert_eq!(
            serial("level=critical").unwrap().level,
            Some(LEVEL_CRITICAL)
        );
        assert_eq!(serial("level=error").unwrap().level, Some(LEVEL_ERROR));
    }

    // Defect caught: a relayed entry shown by a sink that passes them, or
    // hidden from one that shows them.
    #[test]
    fn a_relayed_entry_is_shown_only_by_a_sink_that_shows_them()
    {
        let serial = SinkKind::Serial.defaults();
        assert!(serial.shows(LEVEL_INFO, false));
        assert!(!serial.shows(LEVEL_INFO, true));
        let fb = SinkKind::Framebuffer.defaults();
        assert!(fb.shows(LEVEL_CRITICAL, true));
        assert!(!fb.shows(LEVEL_ERROR, true));
    }

    // Defect caught: a malformed string half applied, or applied at all, or
    // its error naming the wrong text, so the self-logged line misleads.
    #[test]
    fn a_string_that_does_not_parse_names_its_fault_and_applies_nothing()
    {
        assert_eq!(serial("level"), Err(SettingsError::Malformed("level")));
        assert_eq!(serial(""), Err(SettingsError::Malformed("")));
        assert_eq!(serial("level=warn,"), Err(SettingsError::Malformed("")));
        assert_eq!(serial("loud=yes"), Err(SettingsError::UnknownKey("loud")));
        assert_eq!(
            serial("level=warn,level=info"),
            Err(SettingsError::Repeated("level"))
        );
        for (text, key, value) in [
            ("level=verbose", "level", "verbose"),
            ("format=json", "format", "json"),
            ("pace=wait", "pace", "wait"),
            ("backlog=257", "backlog", "257"),
            ("backlog=70000", "backlog", "70000"),
            ("backlog=-1", "backlog", "-1"),
            ("backlog=", "backlog", ""),
            ("relayed=maybe", "relayed", "maybe"),
            ("facility=24", "facility", "24"),
            ("facility=+3", "facility", "+3"),
        ]
        {
            assert_eq!(serial(text), Err(SettingsError::BadValue { key, value }));
        }
        assert_eq!(
            serial("level=info,colour=yes").unwrap_err().to_string(),
            "bad value \"yes\" for colour"
        );
    }

    // Defect caught: colour accepted for serial, whose output CI matches, or
    // refused for the framebuffer, which draws it.
    #[test]
    fn only_the_framebuffer_takes_colour()
    {
        assert_eq!(
            serial("colour=yes"),
            Err(SettingsError::BadValue {
                key: "colour",
                value: "yes"
            })
        );
        assert_eq!(serial("colour=no").unwrap().colour, Colour::Off);
        let fb = SinkKind::Framebuffer.defaults();
        let set = |text| fb.parse_over(SinkKind::Framebuffer, text).unwrap().colour;
        assert_eq!(set("colour=no"), Colour::Off);
        assert_eq!(set("colour=yes"), Colour::On);
    }

    // Defect caught: a field list that repeats a field, names an unknown one,
    // or shows no message accepted, or a valid one reordered.
    #[test]
    fn a_field_list_names_each_field_once_in_order_with_msg()
    {
        let all = serial("fields=procid:host:time:level:name:msg").unwrap();
        assert_eq!(
            all.fields.as_slice(),
            [
                Field::Procid,
                Field::Host,
                Field::Time,
                Field::Level,
                Field::Name,
                Field::Msg
            ]
        );
        assert_eq!(
            serial("fields=msg").unwrap().fields.as_slice(),
            [Field::Msg]
        );
        for bad in [
            "fields=time:time:msg",
            "fields=time:level",
            "fields=time:pid:msg",
            "fields=",
        ]
        {
            assert!(
                matches!(
                    serial(bad),
                    Err(SettingsError::BadValue { key: "fields", .. })
                ),
                "{bad}"
            );
        }
        assert_eq!(SinkKind::Serial.defaults().fields, Fields::DEFAULT);
        assert_eq!(
            Fields::DEFAULT.as_slice(),
            [Field::Time, Field::Level, Field::Name, Field::Msg]
        );
    }

    // Defect caught: a host name RFC 5424 forbids (empty, too long, a space
    // or a control byte) accepted, or a valid one cut.
    #[test]
    fn a_host_name_is_one_to_255_printable_ascii_bytes()
    {
        assert_eq!(
            HostName::parse("node-1.example").unwrap().as_bytes(),
            b"node-1.example"
        );
        let longest = "h".repeat(HOSTNAME_MAX);
        assert_eq!(
            HostName::parse(&longest).unwrap().as_bytes().len(),
            HOSTNAME_MAX
        );
        for bad in ["", "two words", "tab\t", "é"]
        {
            assert_eq!(HostName::parse(bad), None, "{bad:?}");
        }
        assert_eq!(HostName::parse(&"h".repeat(HOSTNAME_MAX + 1)), None);
    }
}
