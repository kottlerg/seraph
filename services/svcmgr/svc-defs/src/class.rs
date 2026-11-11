// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/svcmgr/svc-defs/src/class.rs

//! Parser for the device class files of `/config/devmgr/classes/`: a
//! class's access policy, which svcmgr turns into one class SEND
//! (`ipc::devmgr_labels::MINT_CLASS_SEND`) and publishes seed-only as
//! `devmgr.class.<class>` (`services/svcmgr/docs/service-definitions.md`
//! § Device class files).
//!
//! The grammar is a `.svc` file's: line-oriented `key = value`, `#` starts a
//! comment, and an unknown or repeated key is an error. The class name is
//! the file name without its `.class` suffix, as a service's is its `.svc`
//! file's.

use crate::parse::{ParseError, owned};

/// A parsed class file.
#[derive(Debug, PartialEq, Eq)]
pub struct ClassDefinition
{
    /// The class name, the file name without `.class`.
    pub name: String,
    /// The verb bits a `QUERY_DEVICE` reply through the class SEND carries,
    /// a non-empty subset of `ipc::VERB_BIT_MASK`.
    pub verbs: u64,
    /// The class's drivers come from the boot bundle only
    /// (`ipc::devmgr_labels::CLASS_BOOT_ONLY`).
    pub boot_only: bool,
}

/// The directory svcmgr reads the class files from.
pub const CLASSES_DIR: &str = "/config/devmgr/classes";

/// Suffix of a class file's name.
pub const CLASS_FILE_SUFFIX: &str = ".class";

/// The discovery-registry name svcmgr publishes class `class`'s SEND
/// under: `ipc::published_names::DEVMGR_CLASS_PREFIX` then the class name.
/// `None` when the heap cannot hold it.
#[must_use]
pub fn class_publication(class: &[u8]) -> Option<Vec<u8>>
{
    let prefix = ipc::published_names::DEVMGR_CLASS_PREFIX;
    let mut name = Vec::new();
    name.try_reserve_exact(prefix.len() + class.len()).ok()?;
    name.extend_from_slice(prefix);
    name.extend_from_slice(class);
    Some(name)
}

/// The lowest bit position of `ipc::VERB_BIT_MASK`.
const VERB_BIT_FIRST: u32 = ipc::VERB_BIT_MASK.trailing_zeros();

/// Parse the contents of one class file; `name` is the file name without
/// its `.class` suffix.
///
/// Keys: `verbs` (required), the bit positions of the verb bits, separated
/// by spaces, each in `ipc::VERB_BIT_MASK` (58 to 63) and none repeated;
/// `boot_only`, `yes` or `no` (default `no`).
///
/// # Errors
/// A [`ParseError`] naming the offending line: a name that is not 1 to
/// `ipc::devmgr_labels::MAX_CLASS_NAME_BYTES` lowercase ASCII letters,
/// digits, `-`, and `_` (line 0), a missing `=`, an unknown or repeated key,
/// a missing or empty `verbs`, a bit position outside the mask or repeated,
/// or a `boot_only` other than `yes` or `no`.
pub fn parse_class(name: &str, contents: &str) -> Result<ClassDefinition, ParseError>
{
    let valid_name = !name.is_empty()
        && name.len() <= ipc::devmgr_labels::MAX_CLASS_NAME_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if !valid_name
    {
        return Err(ParseError::InvalidValue(
            0,
            "class name is not a valid class name",
        ));
    }
    let mut verbs: Option<u64> = None;
    let mut boot_only: Option<bool> = None;
    for entry in svc_grammar::entries(contents)
    {
        let svc_grammar::Entry {
            line: lineno,
            key,
            value,
        } = entry.map_err(|svc_grammar::MissingEquals(l)| ParseError::MissingEquals(l))?;
        match (key, value)
        {
            ("verbs", value) =>
            {
                if verbs.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "verbs"));
                }
                verbs = Some(parse_verbs(lineno, value)?);
            }
            ("boot_only", value) =>
            {
                if boot_only.is_some()
                {
                    return Err(ParseError::DuplicateKey(lineno, "boot_only"));
                }
                boot_only = Some(match value
                {
                    "yes" => true,
                    "no" => false,
                    _ =>
                    {
                        return Err(ParseError::InvalidValue(
                            lineno,
                            "boot_only must be yes or no",
                        ));
                    }
                });
            }
            (other, _) => return Err(ParseError::UnknownKey(lineno, owned(other)?)),
        }
    }
    Ok(ClassDefinition {
        name: owned(name)?,
        verbs: verbs.ok_or(ParseError::MissingKey("verbs"))?,
        boot_only: boot_only.unwrap_or(false),
    })
}

/// The verb mask `value` names: space-separated bit positions of
/// `ipc::VERB_BIT_MASK`, at least one, none repeated.
fn parse_verbs(lineno: usize, value: &str) -> Result<u64, ParseError>
{
    let mut mask = 0u64;
    for token in value.split_whitespace()
    {
        let bit: u32 = token
            .parse()
            .map_err(|_| ParseError::InvalidValue(lineno, "verbs takes bit positions"))?;
        let one = 1u64
            .checked_shl(bit)
            .filter(|&b| bit >= VERB_BIT_FIRST && b & ipc::VERB_BIT_MASK != 0)
            .ok_or(ParseError::InvalidValue(
                lineno,
                "a verb bit outside VERB_BIT_MASK",
            ))?;
        if mask & one != 0
        {
            return Err(ParseError::InvalidValue(lineno, "a verb bit repeated"));
        }
        mask |= one;
    }
    if mask == 0
    {
        return Err(ParseError::InvalidValue(lineno, "verbs names no bit"));
    }
    Ok(mask)
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_class_publishes_under_the_prefix_within_the_name_bound()
    {
        assert_eq!(
            class_publication(b"serial").unwrap(),
            b"devmgr.class.serial".to_vec()
        );
        let longest = [b'a'; ipc::devmgr_labels::MAX_CLASS_NAME_BYTES];
        let name = class_publication(&longest).unwrap();
        assert!(name.len() <= ipc::svcmgr_labels::NAME_MAX);
    }

    #[test]
    fn a_class_file_parses_with_its_defaults()
    {
        let def = parse_class("serial", "# the console UART\nverbs = 63 62\n").unwrap();
        assert_eq!(
            def,
            ClassDefinition {
                name: String::from("serial"),
                verbs: (1 << 63) | (1 << 62),
                boot_only: false,
            }
        );
        let block = parse_class("block", "verbs=63\nboot_only = yes").unwrap();
        assert!(block.boot_only);
        assert_eq!(block.verbs, 1 << 63);
        assert_eq!(
            parse_class("debug-port", "verbs = 58").unwrap().verbs,
            1 << 58
        );
    }

    #[test]
    fn verbs_are_required_and_bounded()
    {
        assert!(matches!(
            parse_class("rtc", "boot_only = no"),
            Err(ParseError::MissingKey("verbs"))
        ));
        for bad in [
            "verbs =",
            "verbs = 57",
            "verbs = 64",
            "verbs = 99999999999",
            "verbs = x",
            "verbs = 63 63",
        ]
        {
            assert!(
                matches!(parse_class("rtc", bad), Err(ParseError::InvalidValue(1, _))),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_malformed_line_or_key_is_refused()
    {
        assert!(matches!(
            parse_class("rtc", "verbs = 63\nverbs = 62"),
            Err(ParseError::DuplicateKey(2, "verbs"))
        ));
        assert!(matches!(
            parse_class("rtc", "verbs = 63\nboot_only = yes\nboot_only = no"),
            Err(ParseError::DuplicateKey(3, "boot_only"))
        ));
        assert!(matches!(
            parse_class("rtc", "verbs = 63\nboot_only = maybe"),
            Err(ParseError::InvalidValue(2, _))
        ));
        assert!(matches!(
            parse_class("rtc", "verbs = 63\nmode = fast"),
            Err(ParseError::UnknownKey(2, _))
        ));
        assert!(matches!(
            parse_class("rtc", "verbs 63"),
            Err(ParseError::MissingEquals(1))
        ));
    }

    #[test]
    fn the_class_name_is_bounded_and_checked()
    {
        let longest = "a".repeat(ipc::devmgr_labels::MAX_CLASS_NAME_BYTES);
        assert!(parse_class(&longest, "verbs = 63").is_ok());
        let too_long = "a".repeat(ipc::devmgr_labels::MAX_CLASS_NAME_BYTES + 1);
        for name in ["", "Block", "with space", "dot.ted", too_long.as_str()]
        {
            assert!(
                matches!(
                    parse_class(name, "verbs = 63"),
                    Err(ParseError::InvalidValue(0, _))
                ),
                "{name:?}"
            );
        }
    }
}
