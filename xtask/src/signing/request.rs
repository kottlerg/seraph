// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/signing/request.rs

//! Trust requests: the file on the ESP, `\EFI\seraph\trust-request`, that
//! asks the bootloader to enrol roots and revoke key ids in the trust store it
//! keeps in firmware storage (docs/signing.md § Trust Store).
//!
//! [`build`] encodes a request from the anchors of trust store files and the
//! key ids to revoke, unsigned or signed by a signing identity in the
//! enrolment role under `objsig::enrol::REQUEST_NAME`. [`stage`] puts one in the
//! sysroot's ESP, where the next pack's image carries it, and [`clear`] removes
//! it; [`is_request`] is what the ESP check accepts there.

use std::fs;
use std::path::PathBuf;

use objsig::enrol::{TrustRequest, encoded_len};
use objsig::{AnchorSpec, KeyId, ParseError, Role, RoleSet, TrustStore};

use super::Signer;
use crate::context::Context as BuildContext;
use crate::error::{Context, Result, bail, ensure, err};

/// The request's file name in the ESP's `\EFI\seraph\`, which the bootloader
/// reads (`core/boot/src/main.rs`).
pub const FILE_NAME: &str = "trust-request";

/// The path of the request staged in the sysroot's ESP.
#[must_use]
pub fn staged_path(ctx: &BuildContext) -> PathBuf
{
    ctx.sysroot_efi_seraph().join(FILE_NAME)
}

/// A request adding every anchor of each trust store of `stores` and revoking
/// `revoke`, signed by `signer` in the enrolment role, or unsigned when it is
/// `None`. An anchor two stores hold is added once, and a key id named twice
/// revoked once.
///
/// # Errors
/// When a store does not parse, the request is empty, or the signature
/// cannot be made (an identity whose certificate lacks the enrolment role).
pub fn build(stores: &[Vec<u8>], revoke: &[KeyId], signer: Option<&Signer>) -> Result<Vec<u8>>
{
    let mut anchors: Vec<AnchorSpec<'_>> = Vec::new();
    for (index, bytes) in stores.iter().enumerate()
    {
        let store = TrustStore::parse(bytes).map_err(|e| {
            err!(
                "trust store {} does not parse ({e:?})",
                index.saturating_add(1)
            )
        })?;
        for anchor in store.anchors()
        {
            anchors.push(AnchorSpec {
                key: anchor.key,
                usage: anchor.usage,
                local: anchor.local,
                label: anchor.label,
            });
        }
    }
    anchors.sort_by_key(|anchor| objsig::key_id(anchor.key));
    anchors.dedup_by_key(|anchor| objsig::key_id(anchor.key));
    let mut revoked = revoke.to_vec();
    revoked.sort_unstable();
    revoked.dedup();
    ensure!(
        !anchors.is_empty() || !revoked.is_empty(),
        "a trust request adds an anchor or revokes a key id"
    );
    let len = encoded_len(anchors.len(), revoked.len())
        .map_err(|e| err!("the request is too long to encode ({e:?})"))?;
    let mut body = vec![0u8; len];
    TrustRequest::encode(&anchors, &revoked, &mut body)
        .map_err(|e| err!("encoding the request ({e:?})"))?;
    match signer
    {
        Some(signer) => signer
            .sign(
                &body,
                RoleSet::of(&[Role::Enrolment]),
                std::str::from_utf8(objsig::enrol::REQUEST_NAME)
                    .context("the request name is not UTF-8")?,
            )
            .context("signing the request in the enrolment role"),
        None => Ok(body),
    }
}

/// Whether `bytes` is a trust request: a request body, with or without a
/// signature trailer. Whether it is signed by a key the store trusts is the
/// bootloader's to decide.
#[must_use]
pub fn is_request(bytes: &[u8]) -> bool
{
    let body = match objsig::split(bytes)
    {
        Ok(object) => object.body(),
        Err(ParseError::Magic | ParseError::TooShort) => bytes,
        Err(_) => return false,
    };
    TrustRequest::parse(body).is_ok()
}

/// The key id `hex` names: `objsig::KEY_ID_LEN` bytes as lowercase or uppercase
/// hex digits, as the bootloader logs them.
///
/// # Errors
/// When `hex` is not that many hex digit pairs.
pub fn parse_key_id(hex: &str) -> Result<KeyId>
{
    let mut id = [0u8; objsig::KEY_ID_LEN];
    let digits = objsig::KEY_ID_LEN.saturating_mul(2);
    ensure!(
        hex.len() == digits && hex.is_ascii(),
        "the key id {hex:?} is not {digits} hex digits"
    );
    for (byte, pair) in id.iter_mut().zip(hex.as_bytes().chunks(2))
    {
        let pair = std::str::from_utf8(pair).context("a key id that is not ASCII")?;
        *byte = u8::from_str_radix(pair, 16)
            .map_err(|_| err!("the key id {hex:?} holds a character that is no hex digit"))?;
    }
    Ok(id)
}

/// Stage `request` in the sysroot's ESP, so the next pack's image carries it.
///
/// # Errors
/// When `request` is no trust request, or the file cannot be written.
pub fn stage(ctx: &BuildContext, request: &[u8]) -> Result<PathBuf>
{
    if !is_request(request)
    {
        bail!("the bytes to stage are no trust request");
    }
    let path = staged_path(ctx);
    let dir = ctx.sysroot_efi_seraph();
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::write(&path, request).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Remove the request staged in the sysroot's ESP, so the next pack's image
/// lacks it. An absent request is left absent.
///
/// # Errors
/// On an I/O failure other than the file's absence.
pub fn clear(ctx: &BuildContext) -> Result<()>
{
    let path = staged_path(ctx);
    match fs::remove_file(&path)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::signing::testing::{scratch, signer};

    // Defect caught: a request the bootloader cannot read (unsorted or
    // duplicated lists), or a signature in another role or under another
    // name, so the bootloader asks the console for a request the identity
    // signed.
    #[test]
    fn a_built_request_parses_and_verifies_in_the_enrolment_role()
    {
        let dir = scratch("request-build");
        let signer = signer(&dir, crate::arch::Arch::X86_64);
        let store = signer.store().to_vec();
        let revoked = [
            [3u8; objsig::KEY_ID_LEN],
            [1u8; objsig::KEY_ID_LEN],
            [3u8; objsig::KEY_ID_LEN],
        ];
        let bare = build(&[store.clone(), store.clone()], &revoked, None).unwrap();
        let request = TrustRequest::parse(&bare).unwrap();
        assert_eq!(request.additions().count(), 1);
        assert_eq!(
            request.revocations(),
            &[[1u8; objsig::KEY_ID_LEN], [3u8; objsig::KEY_ID_LEN]]
        );
        assert!(is_request(&bare));

        let sealed = build(std::slice::from_ref(&store), &[], Some(&signer)).unwrap();
        assert!(is_request(&sealed));
        let trusted = TrustStore::parse(&store).unwrap();
        let expect = objsig::Expectation {
            roles: RoleSet::of(&[Role::Enrolment]),
            name: objsig::enrol::REQUEST_NAME,
            arch: objsig::Arch::X86_64,
        };
        objsig::verify(&sealed, &trusted, &expect).unwrap();
        build(&[], &[], None).unwrap_err();
        assert!(!is_request(b"not a request"));
        assert!(!is_request(&store));
    }

    // Defect caught: a key id read from the bootloader's log taken with a
    // digit lost, so the request revokes another key.
    #[test]
    fn a_key_id_is_its_hex_digits()
    {
        let id = parse_key_id("000102030405060708090a0b0c0d0eFF").unwrap();
        assert_eq!(id[..3], [0, 1, 2]);
        assert_eq!(id[15], 0xff);
        parse_key_id("0001").unwrap_err();
        parse_key_id("000102030405060708090a0b0c0d0eZZ").unwrap_err();
    }
}
