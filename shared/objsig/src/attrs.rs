// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/attrs.rs

//! The signed attributes: the bytes a record's signature covers, which bind
//! the signature to its body, kind, name, architecture and security version
//! ([docs/signing.md](../../../docs/signing.md) § Signed Attributes).

use crate::wire::{Reader, Writer};
use crate::{Arch, EncodeError, Kind, ParseError};

/// The domain tag the attributes begin with: `seraph/obj/v1`, padded with
/// NUL bytes to 16.
pub const DOMAIN: [u8; 16] = *b"seraph/obj/v1\0\0\0";

/// The length of the attributes' fixed part, before the name.
pub const FIXED_LEN: usize = 96;

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
    /// The role the object is loaded in.
    pub kind: Kind,
    /// The architecture the object is built for.
    pub arch: Arch,
    /// The SHA-512 of the body.
    pub body_hash: [u8; HASH_LEN],
    /// The bundle entry name or install path, compared byte for byte.
    pub name: &'a [u8],
}

impl<'a> Attributes<'a>
{
    /// Decode the attributes that fill `bytes` exactly.
    ///
    /// # Errors
    ///
    /// The [`ParseError`] of the first rule `bytes` breaks:
    /// `AttributesLength`, `AttributesDomain`, `Kind`, `Arch` or
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
        let kind = reader.u8().ok_or(short)?;
        let arch = reader.u8().ok_or(short)?;
        let name_len = reader.u16().ok_or(short)?;
        let body_hash = reader.array::<HASH_LEN>().ok_or(short)?;
        if domain != DOMAIN
        {
            return Err(ParseError::AttributesDomain);
        }
        let kind = Kind::from_u8(kind).ok_or(ParseError::Kind)?;
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
            kind,
            arch,
            body_hash,
            name,
        })
    }

    /// The length of the encoded attributes, 96 + the name's length.
    ///
    /// # Errors
    ///
    /// `EmptyName` for an empty name; `TooLong` when the encoding would be
    /// longer than [`MAX_LEN`].
    pub fn encoded_len(&self) -> Result<usize, EncodeError>
    {
        if self.name.is_empty()
        {
            return Err(EncodeError::EmptyName);
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
        writer.put(&[self.kind as u8, self.arch as u8])?;
        writer.put(&name_len.to_le_bytes())?;
        writer.put(&self.body_hash)?;
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

    fn sample(name: &[u8]) -> Attributes<'_>
    {
        Attributes {
            body_len: 0x0102_0304_0506_0708,
            security_version: 0x1122_3344,
            kind: Kind::Service,
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
        assert_eq!(bytes.len(), 96 + 16);
        assert_eq!(&bytes[0..16], b"seraph/obj/v1\0\0\0");
        assert_eq!(&bytes[16..24], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&bytes[24..28], &0x1122_3344u32.to_le_bytes());
        assert_eq!(bytes[28], 4, "kind service");
        assert_eq!(bytes[29], 2, "arch riscv64");
        assert_eq!(&bytes[30..32], &16u16.to_le_bytes());
        assert_eq!(&bytes[32..96], &[0xa5; 64]);
        assert_eq!(&bytes[96..], b"/services/svcmgr");
    }

    #[test]
    fn round_trips()
    {
        for kind in Kind::ALL
        {
            for arch in [Arch::X86_64, Arch::Riscv64]
            {
                let attrs = Attributes {
                    kind,
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
        refuse(&|b| b[28] = 0, ParseError::Kind);
        refuse(&|b| b[28] = 8, ParseError::Kind);
        refuse(&|b| b[29] = 0, ParseError::Arch);
        refuse(&|b| b[29] = 3, ParseError::Arch);
        refuse(
            &|b| {
                b.truncate(FIXED_LEN);
                b[30] = 0;
            },
            ParseError::EmptyName,
        );
    }

    #[test]
    fn encoder_refuses_what_the_parser_refuses()
    {
        assert_eq!(sample(b"").encoded_len(), Err(EncodeError::EmptyName));
        let long = vec![b'n'; MAX_LEN - FIXED_LEN + 1];
        assert_eq!(sample(&long).encoded_len(), Err(EncodeError::TooLong));
        let mut short = [0u8; FIXED_LEN];
        assert_eq!(
            sample(b"x").encode(&mut short),
            Err(EncodeError::BufferTooSmall)
        );
    }
}
