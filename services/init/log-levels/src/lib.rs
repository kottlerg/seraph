// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/init/log-levels/src/lib.rs

//! The log-level configuration init reads at boot: the parser of the
//! `log-levels` boot module, which names the level of each service init
//! spawns (`services/init/docs/bootstrap.md` § Log levels).
//!
//! The module is text, one setting per line, `<service> = <level>`: a
//! [`Service`] name and a level `log::parse_level` accepts. A `#` starts a
//! comment that runs to the end of its line; blank lines and the ASCII
//! whitespace around each field are ignored. A line that is not a setting is
//! reported and ignored, and a later setting of a service replaces an earlier
//! one. The crate performs no IPC and issues no syscalls, so it stays
//! host-testable
//! ([coding-standards.md](../../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

/// A service init spawns, whose level the configuration may set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Service
{
    /// procmgr, which init loads itself.
    Procmgr,
    /// devmgr, which init spawns through procmgr.
    Devmgr,
    /// vfsd, which init spawns through procmgr.
    Vfsd,
    /// svcmgr, which init spawns through procmgr from the root filesystem.
    Svcmgr,
}

impl Service
{
    /// Every service, in the order of [`Levels`]' table.
    pub const ALL: [Self; 4] = [Self::Procmgr, Self::Devmgr, Self::Vfsd, Self::Svcmgr];

    /// The name a setting gives the service.
    #[must_use]
    pub fn name(self) -> &'static [u8]
    {
        match self
        {
            Self::Procmgr => b"procmgr",
            Self::Devmgr => b"devmgr",
            Self::Vfsd => b"vfsd",
            Self::Svcmgr => b"svcmgr",
        }
    }

    /// The service a setting's name names, if any.
    fn from_name(name: &[u8]) -> Option<Self>
    {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// The service's index in [`Levels`]' table.
    fn index(self) -> usize
    {
        match self
        {
            Self::Procmgr => 0,
            Self::Devmgr => 1,
            Self::Vfsd => 2,
            Self::Svcmgr => 3,
        }
    }
}

/// The level the configuration sets for each [`Service`]: an
/// `ipc::stream_labels::LEVEL_*` code, or `None` for a service it leaves at
/// the default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Levels
{
    levels: [Option<u64>; Service::ALL.len()],
}

impl Levels
{
    /// The level set for `service`, if any.
    #[must_use]
    pub fn get(&self, service: Service) -> Option<u64>
    {
        self.levels.get(service.index()).copied().flatten()
    }

    /// Set `service`'s level to `level`.
    fn set(&mut self, service: Service, level: u64)
    {
        if let Some(slot) = self.levels.get_mut(service.index())
        {
            *slot = Some(level);
        }
    }
}

/// Why a line of the configuration is not a setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineError
{
    /// The line has no `=`.
    NoSeparator,
    /// The name before the `=` is no [`Service`]'s.
    UnknownService,
    /// The value after the `=` is no level `log::parse_level` accepts.
    UnknownLevel,
}

impl LineError
{
    /// A short description, for init's log line.
    #[must_use]
    pub fn describe(self) -> &'static str
    {
        match self
        {
            Self::NoSeparator => "no '='",
            Self::UnknownService => "unknown service",
            Self::UnknownLevel => "unknown level",
        }
    }
}

/// Parse the configuration `text`, calling `on_error` with each line that is
/// not a setting (comment and surrounding whitespace removed) and the reason.
#[must_use]
pub fn parse(text: &[u8], mut on_error: impl FnMut(&[u8], LineError)) -> Levels
{
    let mut levels = Levels::default();
    for raw in text.split(|&b| b == b'\n')
    {
        let line = raw.split(|&b| b == b'#').next().unwrap_or_default().trim_ascii();
        if line.is_empty()
        {
            continue;
        }
        match parse_setting(line)
        {
            Ok((service, level)) => levels.set(service, level),
            Err(e) => on_error(line, e),
        }
    }
    levels
}

/// The setting `line` (non-empty, comment removed, trimmed) makes.
fn parse_setting(line: &[u8]) -> Result<(Service, u64), LineError>
{
    let mut fields = line.splitn(2, |&b| b == b'=');
    let (Some(name), Some(value)) = (fields.next(), fields.next())
    else
    {
        return Err(LineError::NoSeparator);
    };
    let service = Service::from_name(name.trim_ascii()).ok_or(LineError::UnknownService)?;
    let level = log::parse_level(value.trim_ascii()).ok_or(LineError::UnknownLevel)?;
    Ok((service, level))
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn debug() -> u64
    {
        log::parse_level(b"debug").unwrap()
    }

    fn warn() -> u64
    {
        log::parse_level(b"warn").unwrap()
    }

    fn trace() -> u64
    {
        log::parse_level(b"trace").unwrap()
    }

    fn parse_ok(text: &str) -> Levels
    {
        parse(text.as_bytes(), |line, e| {
            panic!("unexpected error {e:?} on {:?}", String::from_utf8_lossy(line))
        })
    }

    fn errors(text: &str) -> (Levels, Vec<(String, LineError)>)
    {
        let mut errs = Vec::new();
        let levels = parse(text.as_bytes(), |line, e| {
            errs.push((String::from_utf8_lossy(line).into_owned(), e));
        });
        (levels, errs)
    }

    // Defect caught: a default configuration that changes some service's
    // level from info.
    #[test]
    fn an_empty_or_comment_only_file_sets_nothing()
    {
        assert_eq!(parse_ok(""), Levels::default());
        assert_eq!(
            parse_ok("# vfsd = debug\n\n   \n\t# procmgr = trace\n"),
            Levels::default()
        );
        for s in Service::ALL
        {
            assert_eq!(Levels::default().get(s), None);
        }
    }

    // Defect caught: a setting read for the wrong service, or not read.
    #[test]
    fn each_service_s_setting_sets_its_level_alone()
    {
        let levels = parse_ok("vfsd = debug\nprocmgr=warn\n");
        assert_eq!(levels.get(Service::Vfsd), Some(debug()));
        assert_eq!(levels.get(Service::Procmgr), Some(warn()));
        assert_eq!(levels.get(Service::Devmgr), None);
        assert_eq!(levels.get(Service::Svcmgr), None);
        for s in Service::ALL
        {
            let text = format!("{} = trace", String::from_utf8_lossy(s.name()));
            let one = parse_ok(&text);
            for other in Service::ALL
            {
                let want = (other == s).then(trace);
                assert_eq!(one.get(other), want, "{text}");
            }
        }
    }

    // Defect caught: a trailing comment, CRLF line end or padding making a
    // valid setting unreadable.
    #[test]
    fn comments_whitespace_and_crlf_around_a_setting_are_ignored()
    {
        let levels = parse_ok("  devmgr\t=  debug   # the PCI walk\r\nsvcmgr = warn\r\n");
        assert_eq!(levels.get(Service::Devmgr), Some(debug()));
        assert_eq!(levels.get(Service::Svcmgr), Some(warn()));
    }

    // Defect caught: a malformed line aborting the parse or setting a level.
    #[test]
    fn a_line_that_is_not_a_setting_is_reported_and_ignored()
    {
        let (levels, errs) =
            errors("vfsd debug\nfatfs = debug\nvfsd = loud\nDEVMGR = debug\nvfsd = trace\n");
        assert_eq!(levels.get(Service::Vfsd), Some(trace()));
        assert_eq!(levels.get(Service::Devmgr), None);
        assert_eq!(
            errs,
            [
                ("vfsd debug".to_string(), LineError::NoSeparator),
                ("fatfs = debug".to_string(), LineError::UnknownService),
                ("vfsd = loud".to_string(), LineError::UnknownLevel),
                ("DEVMGR = debug".to_string(), LineError::UnknownService),
            ]
        );
    }

    // Defect caught: an empty value or a second `=` read as a level.
    #[test]
    fn an_empty_or_compound_value_is_no_level()
    {
        let (levels, errs) = errors("vfsd =\nvfsd = debug = 1\n= debug\n");
        assert_eq!(levels, Levels::default());
        let kinds: Vec<LineError> = errs.into_iter().map(|(_, e)| e).collect();
        assert_eq!(
            kinds,
            [
                LineError::UnknownLevel,
                LineError::UnknownLevel,
                LineError::UnknownService
            ]
        );
    }

    // Defect caught: the first of two settings of a service winning.
    #[test]
    fn a_later_setting_replaces_an_earlier_one()
    {
        let levels = parse_ok("vfsd = debug\nvfsd = warn\n");
        assert_eq!(levels.get(Service::Vfsd), Some(warn()));
    }

    #[test]
    fn every_error_has_a_description()
    {
        for e in [
            LineError::NoSeparator,
            LineError::UnknownService,
            LineError::UnknownLevel,
        ]
        {
            assert_ne!(e.describe(), "");
        }
    }
}
