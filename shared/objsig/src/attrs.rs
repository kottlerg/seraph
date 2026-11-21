// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/attrs.rs

//! The signed attributes: the bytes a record's signature covers, which bind
//! the signature to its body, role set, name, architecture and security version
//! ([docs/signing.md](../../../docs/signing.md) § Signed Attributes).

use crate::wire::{Reader, Writer};
use crate::{Arch, EncodeError, ParseError, RoleSet};

/// The domain tag the attributes begin with: `seraph/obj/v3`, padded with
/// NUL bytes to 16. Attributes of another version carry another tag and do
/// not parse.
pub const DOMAIN: [u8; 16] = *b"seraph/obj/v3\0\0\0";

/// The length of the attributes' fixed part, before the name.
pub const FIXED_LEN: usize = 99;

/// The longest attributes a record holds: its `attrs_len` is a `u16`.
pub const MAX_LEN: usize = u16::MAX as usize;

/// The length of a body hash, a SHA-512 digest.
pub const HASH_LEN: usize = 64;

/// Decoded signed attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes<'a>
{
    /// The body's length in bytes.
    pub body_len: u64,
    /// The object's security version.
    pub security_version: u32,
    /// The roles the object may be loaded in.
    pub roles: RoleSet,
    /// The architecture the object is built for.
    pub arch: Arch,
    /// The SHA-512 of the body.
    pub body_hash: [u8; HASH_LEN],
    /// The slot name (`kernel`, `init`) or install path, compared byte for
    /// byte.
    pub name: &'a [u8],
}

impl<'a> Attributes<'a>
{
    /// Decode the attributes that fill `bytes` exactly.
    ///
    /// # Errors
    ///
    /// The [`ParseError`] of the first rule `bytes` breaks:
    /// `AttributesLength`, `AttributesDomain`, `Roles`, `Arch` or
    /// `EmptyName`.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError>
    {
        if bytes.len() < FIXED_LEN || bytes.len() > MAX_LEN
        {
            return Err(ParseError::AttributesLength);
        }
        let mut reader = Reader::new(bytes);
        let short = ParseError::AttributesLength;
        let domain = reader.array::<16>().ok_or(short)?;
        let body_len = reader.u64().ok_or(short)?;
        let security_version = reader.u32().ok_or(short)?;
        let roles = reader.u32().ok_or(short)?;
        let body_hash = reader.array::<HASH_LEN>().ok_or(short)?;
        let name_len = reader.u16().ok_or(short)?;
        let arch = reader.u8().ok_or(short)?;
        if domain != DOMAIN
        {
            return Err(ParseError::AttributesDomain);
        }
        let roles = RoleSet::from_signed(roles).ok_or(ParseError::Roles)?;
        let arch = Arch::from_u8(arch).ok_or(ParseError::Arch)?;
        if name_len == 0
        {
            return Err(ParseError::EmptyName);
        }
        let name = reader.rest();
        if name.len() != usize::from(name_len)
        {
            return Err(ParseError::AttributesLength);
        }
        Ok(Self {
            body_len,
            security_version,
            roles,
            arch,
            body_hash,
            name,
        })
    }

    /// The length of the encoded attributes, 99 + the name's length.
    ///
    /// # Errors
    ///
    /// `EmptyName` for an empty name; `Roles` for a role set
    /// [`RoleSet::is_signable`] refuses; `TooLong` when the encoding would be
    /// longer than [`MAX_LEN`].
    pub fn encoded_len(&self) -> Result<usize, EncodeError>
    {
        if self.name.is_empty()
        {
            return Err(EncodeError::EmptyName);
        }
        if !self.roles.is_signable()
        {
            return Err(EncodeError::Roles);
        }
        FIXED_LEN
            .checked_add(self.name.len())
            .filter(|len| *len <= MAX_LEN)
            .ok_or(EncodeError::TooLong)
    }

    /// Encode the attributes at the start of `out`; returns their length.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::encoded_len`], and `BufferTooSmall` when
    /// `out` is shorter than the encoding.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, EncodeError>
    {
        let mut writer = Writer::new(out);
        self.write(&mut writer)
    }

    /// Append the encoded attributes; returns their length.
    pub(crate) fn write(&self, writer: &mut Writer<'_>) -> Result<usize, EncodeError>
    {
        let len = self.encoded_len()?;
        let name_len = u16::try_from(self.name.len()).map_err(|_| EncodeError::TooLong)?;
        writer.put(&DOMAIN)?;
        writer.put(&self.body_len.to_le_bytes())?;
        writer.put(&self.security_version.to_le_bytes())?;
        writer.put(&self.roles.bits().to_le_bytes())?;
        writer.put(&self.body_hash)?;
        writer.put(&name_len.to_le_bytes())?;
        writer.put(&[self.arch as u8])?;
        writer.put(self.name)?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::*;
    use crate::Role;

    fn sample(name: &[u8]) -> Attributes<'_>
    {
        Attributes {
            body_len: 0x0102_0304_0506_0708,
            security_version: 0x1122_3344,
            roles: RoleSet::of(&[Role::Service, Role::BootModule]),
            arch: Arch::Riscv64,
            body_hash: [0xa5; HASH_LEN],
            name,
        }
    }

    fn encoded(attrs: &Attributes<'_>) -> Vec<u8>
    {
        let mut out = vec![0u8; attrs.encoded_len().unwrap()];
        assert_eq!(attrs.encode(&mut out), Ok(out.len()));
        out
    }

    #[test]
    fn layout_matches_the_specification()
    {
        let bytes = encoded(&sample(b"/services/svcmgr"));
        assert_eq!(bytes.len(), 99 + 16);
        assert_eq!(&bytes[0..16], b"seraph/obj/v3\0\0\0");
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&bytes[24..28], &0x1122_3344u32.to_le_bytes());
        assert_eq!(
            &bytes[28..32],
            &0b0001_1000u32.to_le_bytes(),
            "roles boot module and service"
        );
        assert_eq!(&bytes[32..96], &[0xa5; 64]);
        assert_eq!(&bytes[96..98], &16u16.to_le_bytes());
        assert_eq!(bytes[98], 2, "arch riscv64");
        assert_eq!(&bytes[99..], b"/services/svcmgr");
    }

    #[test]
    fn round_trips()
    {
        for bits in 0..=u32::from(u8::MAX)
        {
            let Some(roles) = RoleSet::from_signed(bits)
            else
            {
                continue;
            };
            for arch in [Arch::X86_64, Arch::Riscv64]
            {
                let attrs = Attributes {
                    roles,
                    arch,
                    ..sample(b"init")
                };
                assert_eq!(Attributes::parse(&encoded(&attrs)), Ok(attrs));
            }
        }
        let long = vec![b'n'; MAX_LEN - FIXED_LEN];
        let attrs = sample(&long);
        assert_eq!(Attributes::parse(&encoded(&attrs)), Ok(attrs));
    }

    #[test]
    fn refuses_each_malformed_field()
    {
        let good = encoded(&sample(b"kernel"));
        let refuse = |edit: &dyn Fn(&mut Vec<u8>), error| {
            let mut bytes = good.clone();
            edit(&mut bytes);
            assert_eq!(Attributes::parse(&bytes), Err(error), "{bytes:?}");
        };
        refuse(&|b| b.truncate(FIXED_LEN - 1), ParseError::AttributesLength);
        refuse(&|b| b.truncate(FIXED_LEN), ParseError::AttributesLength);
        refuse(&|b| b.push(0), ParseError::AttributesLength);
        refuse(
            &|b| {
                b.pop();
            },
            ParseError::AttributesLength,
        );
        refuse(&|b| b.resize(MAX_LEN + 1, 0), ParseError::AttributesLength);
        refuse(&|b| b[0] = b'S', ParseError::AttributesDomain);
        refuse(&|b| b[15] = 1, ParseError::AttributesDomain);
        refuse(&|b| b[28] = 0, ParseError::Roles);
        refuse(&|b| b[28] = 0b0001_1001, ParseError::Roles);
        refuse(&|b| b[28] = 0b0000_0110, ParseError::Roles);
        refuse(&|b| b[28] = 0b0001_0010, ParseError::Roles);
        refuse(&|b| b[28] = 0b1000_0100, ParseError::Roles);
        // Bit 8, which no role has yet, and bit 31, CERTIFY in a usage mask.
        refuse(&|b| b[29] = 1, ParseError::Roles);
        refuse(&|b| b[31] = 0x80, ParseError::Roles);
        refuse(&|b| b[30] = 1, ParseError::Roles);
        refuse(&|b| b[98] = 0, ParseError::Arch);
        refuse(&|b| b[98] = 3, ParseError::Arch);
        refuse(
            &|b| {
                b.truncate(FIXED_LEN);
                b[96] = 0;
            },
            ParseError::EmptyName,
        );
    }

    /// The attributes of an earlier version, version 1's single kind or
    /// version 2's one-byte role set at byte 28: their domain tag is not this
    /// version's, so they do not parse, whatever the bytes after it hold.
    #[test]
    fn refuses_an_earlier_version()
    {
        for tag in [b"seraph/obj/v1\0\0\0", b"seraph/obj/v2\0\0\0"]
        {
            let mut old = encoded(&sample(b"/services/svcmgr"));
            old[..16].copy_from_slice(tag);
            for kind in 1..=7
            {
                old[28] = kind;
                assert_eq!(Attributes::parse(&old), Err(ParseError::AttributesDomain));
            }
        }
    }

    /// The parser's rule for the role field: every set of roles is accepted
    /// but an empty one, one with bit 0 or a bit no role has, and one holding
    /// kernel or init beside another role.
    #[test]
    fn accepts_exactly_the_signable_role_sets()
    {
        let accepted = (0..=0x3ffu32)
            .filter(|bits| RoleSet::from_signed(*bits).is_some())
            .count();
        // The 31 nonempty sets of the five roles past init, and kernel and
        // init alone.
        assert_eq!(accepted, 31 + 2);
        for bit in 8..32
        {
            let service = RoleSet::of(&[Role::Service]).bits();
            assert_eq!(
                RoleSet::from_signed(service | (1 << bit)),
                None,
                "bit {bit}"
            );
        }
        for role in Role::ALL
        {
            assert!(RoleSet::from_signed(RoleSet::of(&[role]).bits()).is_some());
        }
        let all_runtime = RoleSet::of(&[
            Role::BootModule,
            Role::Service,
            Role::Driver,
            Role::Program,
            Role::Data,
        ]);
        assert_eq!(RoleSet::from_signed(all_runtime.bits()), Some(all_runtime));
        assert_eq!(RoleSet::from_signed(RoleSet::ALL.bits()), None);
    }

    #[test]
    fn encoder_refuses_what_the_parser_refuses()
    {
        assert_eq!(sample(b"").encoded_len(), Err(EncodeError::EmptyName));
        for roles in [
            RoleSet::EMPTY,
            RoleSet::of(&[Role::Init, Role::BootModule]),
            RoleSet::of(&[Role::Kernel, Role::Init]),
        ]
        {
            let attrs = Attributes {
                roles,
                ..sample(b"init")
            };
            assert_eq!(attrs.encoded_len(), Err(EncodeError::Roles));
        }
        let long = vec![b'n'; MAX_LEN - FIXED_LEN + 1];
        assert_eq!(sample(&long).encoded_len(), Err(EncodeError::TooLong));
        let mut short = [0u8; FIXED_LEN];
        assert_eq!(
            sample(b"x").encode(&mut short),
            Err(EncodeError::BufferTooSmall)
        );
    }
}
