// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/boot-policy/src/lib.rs

//! The boot-time policy: the parser of the `/config/boot/policy.conf` bundle
//! entry (`boot_protocol::bundle::POLICY_ENTRY_NAME`), which holds the
//! settings by which a system's signed configuration makes hardware a boot
//! requirement (docs/signing.md § Configuration).
//!
//! The policy is text in the `key = value` line grammar of `svc-grammar`:
//! blank lines and lines whose first character is `#` are skipped, and the
//! key and the value are trimmed. Each key appears at most once, and a key
//! the policy does not set takes its default. The keys are [`Policy`]'s
//! fields, and the README lists them with their values.
//!
//! A policy is accepted whole or not at all: a body that is not UTF-8, a line
//! with no `=`, an unknown key, a value its key does not take, and a key set
//! twice each refuse it ([`Error`]). A consumer that is handed no policy, or
//! one that does not parse, applies [`Policy::FAIL_CLOSED`], every
//! requirement on: the bundle container is not signed, so a requirement that
//! held only while its file was present would be turned off by deleting the
//! entry.
//!
//! The policy is a signed object (docs/signing.md): the settings are its
//! body, which [`parse_module`] takes through the parse-only `objsig::split`,
//! since the bootloader verified the module before it exposed it. The crate
//! performs no IPC and issues no syscalls, so it stays host-testable
//! ([coding-standards.md](../../../docs/coding-standards.md#d-testing-invariants)).

#![cfg_attr(not(test), no_std)]

/// Whether every DMA-capable device must be confined by an IOMMU: the
/// `dma-confinement` key (docs/device-management.md § DMA Safety Model).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaConfinement
{
    /// `opportunistic`, the default: the IOMMU confines each device a
    /// remapping unit translates, and every other device runs with its DMA
    /// unconfined.
    Opportunistic,
    /// `required`: devmgr starts no DMA-capable driver for a device no IOMMU
    /// unit confines.
    Required,
}

impl DmaConfinement
{
    /// The key that sets it.
    pub const KEY: &'static str = "dma-confinement";

    /// The value that names it.
    #[must_use]
    pub const fn value(self) -> &'static str
    {
        match self
        {
            Self::Opportunistic => "opportunistic",
            Self::Required => "required",
        }
    }

    /// The setting `value` names, if any.
    fn from_value(value: &str) -> Option<Self>
    {
        [Self::Opportunistic, Self::Required]
            .into_iter()
            .find(|setting| setting.value() == value)
    }
}

/// The boot-time policy: one field per key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy
{
    /// `dma-confinement`.
    pub dma_confinement: DmaConfinement,
}

impl Policy
{
    /// The policy of a file that sets no key: every setting at its default.
    pub const DEFAULT: Self = Self {
        dma_confinement: DmaConfinement::Opportunistic,
    };

    /// The policy a consumer applies when it is handed none, or one that does
    /// not parse: every requirement on.
    pub const FAIL_CLOSED: Self = Self {
        dma_confinement: DmaConfinement::Required,
    };
}

/// Why a policy is refused, with the 1-based number of the line at fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error
{
    /// The body is not UTF-8.
    NotUtf8,
    /// The line is neither blank, a comment, nor `key = value`.
    NoSeparator(usize),
    /// The line's key is no key of the policy.
    UnknownKey(usize),
    /// The line's value is none its key takes.
    UnknownValue(usize),
    /// The line sets a key an earlier line set.
    Repeated(usize),
}

impl core::fmt::Display for Error
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        match *self
        {
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::NoSeparator(line) => write!(f, "line {line}: no '='"),
            Self::UnknownKey(line) => write!(f, "line {line}: unknown key"),
            Self::UnknownValue(line) => write!(f, "line {line}: a value its key does not take"),
            Self::Repeated(line) => write!(f, "line {line}: a key set twice"),
        }
    }
}

/// Parse the policy `text`.
///
/// # Errors
/// The first [`Error`] of `text`, which refuses the whole policy.
pub fn parse(text: &[u8]) -> Result<Policy, Error>
{
    let text = core::str::from_utf8(text).map_err(|_| Error::NotUtf8)?;
    let mut dma_confinement = None;
    for entry in svc_grammar::entries(text)
    {
        let entry = entry.map_err(|svc_grammar::MissingEquals(line)| Error::NoSeparator(line))?;
        if entry.key != DmaConfinement::KEY
        {
            return Err(Error::UnknownKey(entry.line));
        }
        if dma_confinement.is_some()
        {
            return Err(Error::Repeated(entry.line));
        }
        dma_confinement =
            Some(DmaConfinement::from_value(entry.value).ok_or(Error::UnknownValue(entry.line))?);
    }
    Ok(Policy {
        dma_confinement: dma_confinement.unwrap_or(Policy::DEFAULT.dma_confinement),
    })
}

/// Why a policy module is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleError
{
    /// The module's signature trailer does not parse, an unsigned module's
    /// among them; its body is not read.
    Trailer(objsig::ParseError),
    /// The module's body is refused ([`parse`]).
    Policy(Error),
}

/// Parse the `/config/boot/policy.conf` boot module `module`: the policy its
/// body holds, as [`parse`] reads it. The bootloader verified the module in
/// the configuration role, so its trailer is split off with the parse checks
/// alone (docs/signing.md § Verifier Discipline).
///
/// # Errors
/// [`ModuleError::Trailer`] when the trailer does not parse;
/// [`ModuleError::Policy`] when the body is refused.
pub fn parse_module(module: &[u8]) -> Result<Policy, ModuleError>
{
    let signed = objsig::split(module).map_err(ModuleError::Trailer)?;
    parse(signed.body()).map_err(ModuleError::Policy)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn required() -> Policy
    {
        Policy {
            dma_confinement: DmaConfinement::Required,
        }
    }

    /// `body` with a trailer that parses: one record whose signature is not
    /// checked, as the parse-only split does not check it.
    fn signed(body: &[u8]) -> Vec<u8>
    {
        let record = objsig::RecordSpec {
            signer_key_id: [1; objsig::KEY_ID_LEN],
            attrs: objsig::Attributes {
                body_len: u64::try_from(body.len()).unwrap(),
                security_version: 1,
                roles: objsig::RoleSet::of(&[objsig::Role::Configuration]),
                arch: objsig::Arch::X86_64,
                body_hash: [0; 64],
                name: b"/config/boot/policy.conf",
            },
            certificate: None,
            signature: &[0; objsig::composite::SIGNATURE_LEN],
        };
        let mut trailer = vec![0u8; objsig::trailer_len(&[record]).unwrap()];
        objsig::encode_trailer(body, &[record], &mut trailer).unwrap();
        [body, trailer.as_slice()].concat()
    }

    // Defect caught: a committed policy that moves a setting off its
    // default, which would change every system's boot, or one the consumers
    // refuse, which would put every requirement on at every boot.
    #[test]
    fn the_committed_policy_states_the_defaults()
    {
        let committed = include_str!("../../../rootfs/config/boot/policy.conf");
        assert_eq!(parse(committed.as_bytes()), Ok(Policy::DEFAULT));
    }

    // Defect caught: a setting read from the wrong side of its line, a
    // comment or blank line taken for a setting, or a policy that sets no key
    // read as anything but the defaults.
    #[test]
    fn each_value_sets_its_key_and_an_unset_key_takes_its_default()
    {
        assert_eq!(parse(b""), Ok(Policy::DEFAULT));
        assert_eq!(
            parse(b"# dma-confinement = required\n\n  \n"),
            Ok(Policy::DEFAULT)
        );
        assert_eq!(parse(b"  dma-confinement\t=  required  \n"), Ok(required()));
        assert_eq!(
            parse(b"# the default, written out\ndma-confinement = opportunistic"),
            Ok(Policy::DEFAULT)
        );
    }

    // Defect caught: a policy that is malformed in part applied in part, so
    // a requirement its signer meant to set is read as unset, or an error
    // reported against the wrong line.
    #[test]
    fn any_line_at_fault_refuses_the_whole_policy()
    {
        let cases: [(&[u8], Error); 8] = [
            (b"dma-confinement = required\n\xff\n", Error::NotUtf8),
            (
                b"dma-confinement = required\nrequired\n",
                Error::NoSeparator(2),
            ),
            (
                b"dma-confinement = required\ntpm = required\n",
                Error::UnknownKey(2),
            ),
            (b"DMA-confinement = required\n", Error::UnknownKey(1)),
            (b"# c\ndma-confinement = Required\n", Error::UnknownValue(2)),
            (b"dma-confinement = required # on\n", Error::UnknownValue(1)),
            (b"dma-confinement =\n", Error::UnknownValue(1)),
            (
                b"dma-confinement = required\ndma-confinement = opportunistic\n",
                Error::Repeated(2),
            ),
        ];
        for (text, error) in cases
        {
            assert_eq!(
                parse(text),
                Err(error),
                "{:?}",
                String::from_utf8_lossy(text)
            );
        }
        assert_eq!(Error::UnknownKey(2).to_string(), "line 2: unknown key");
    }

    // Defect caught: a module whose trailer is read as policy lines, or an
    // unsigned or malformed module read as a policy.
    #[test]
    fn a_module_s_body_is_its_policy()
    {
        let module = signed(b"dma-confinement = required\n");
        assert_eq!(parse_module(&module), Ok(required()));
        assert_eq!(
            parse_module(b"dma-confinement = opportunistic\n"),
            Err(ModuleError::Trailer(objsig::ParseError::Magic))
        );
        let mut broken = module.clone();
        let last = broken.len() - 1;
        broken[last] ^= 1;
        assert!(matches!(
            parse_module(&broken),
            Err(ModuleError::Trailer(_))
        ));
        assert_eq!(
            parse_module(&signed(b"dma-confinement = on\n")),
            Err(ModuleError::Policy(Error::UnknownValue(1)))
        );
    }
}
