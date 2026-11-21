// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// core/boot/src/signing.rs

//! Signature verification of the kernel and the bundle entries against the
//! trust store built into the bootloader
//! ([docs/signing.md](../../../docs/signing.md) § Trust Store and § Verifier
//! Discipline).
//!
//! The store is embedded at build time from the file xtask names in
//! `SERAPH_BOOT_TRUST_STORE` (xtask/README.md § Signing), in the layout of
//! `objsig::embed`, through which a pack reads it back out of the installed
//! image. Every object is verified through [`Verifier::object`], which returns
//! the body the caller then parses and loads, or the one [`BootError`] that
//! halts the boot.

use objsig::{Arch, CertificateCache, Expectation, Role, RoleSet, TrustStore, verify_cached};

use crate::bprintln;
use crate::error::{BootError, ObjectName};

/// The architecture every object this bootloader loads is signed for.
#[cfg(target_arch = "riscv64")]
const ARCH: Arch = Arch::Riscv64;
/// The architecture every object this bootloader loads is signed for.
#[cfg(not(target_arch = "riscv64"))]
const ARCH: Arch = Arch::X86_64;

/// The trust store's bytes, from the file the build names.
#[cfg(not(test))]
const STORE: &[u8] = include_bytes!(env!(
    "SERAPH_BOOT_TRUST_STORE",
    "the bootloader embeds the trust store xtask names in SERAPH_BOOT_TRUST_STORE: build it \
     with `cargo xtask build`"
));

/// The trust store in its embedded layout, which a pack locates in the image.
#[cfg(not(test))]
static EMBEDDED: objsig::embed::Embedded<{ STORE.len() }> = objsig::embed::Embedded::new(STORE);

/// The embedded trust store's bytes.
#[cfg(not(test))]
pub fn embedded_store() -> &'static [u8]
{
    EMBEDDED.store()
}

/// The embedded trust store's bytes: the host tests build no store, and
/// verify against stores of their own.
#[cfg(test)]
pub fn embedded_store() -> &'static [u8]
{
    &[]
}

/// Parse the trust store `bytes` holds, and log each anchor's label and key
/// id, marking one generated on the build machine (`LOCAL`) as locally
/// generated.
///
/// # Errors
/// [`BootError::TrustStore`] when the store does not parse.
pub fn parse_store(bytes: &[u8]) -> Result<TrustStore<'_>, BootError>
{
    let store = TrustStore::parse(bytes).map_err(BootError::TrustStore)?;
    for anchor in store.anchors()
    {
        let origin = if anchor.local
        {
            " (locally generated)"
        }
        else
        {
            ""
        };
        bprintln!(
            "[--------] boot: trust anchor \"{}\" key id {}{}",
            anchor.label,
            KeyIdHex(&anchor.key_id),
            origin
        );
    }
    bprintln!(
        "[--------] boot: trust store: security floor {}",
        store.security_floor()
    );
    Ok(store)
}

/// The bootloader's verifier: the trust store, and the certificates whose
/// signature has verified during this boot (`objsig::CertificateCache`), so the
/// certificate every object of one signer carries is verified once.
pub struct Verifier<'s>
{
    store: TrustStore<'s>,
    certificates: CertificateCache,
}

impl<'s> Verifier<'s>
{
    /// A verifier for `store` that has verified no certificate yet.
    pub const fn new(store: TrustStore<'s>) -> Self
    {
        Self {
            store,
            certificates: CertificateCache::new(),
        }
    }

    /// Verify `object` in `role` under `name` for this architecture: its
    /// signed role set holds `role`. Return its body, the only bytes the
    /// caller may parse or load.
    ///
    /// # Errors
    /// [`BootError::SignatureRefused`], naming the object and the verifier's
    /// refusal.
    pub fn object<'a>(
        &mut self,
        object: &'a [u8],
        role: Role,
        name: &[u8],
    ) -> Result<&'a [u8], BootError>
    {
        let expect = Expectation {
            roles: RoleSet::of(&[role]),
            name,
            arch: ARCH,
        };
        match verify_cached(object, &self.store, &expect, &mut self.certificates)
        {
            Ok(verified) => Ok(verified.body),
            Err(refusal) => Err(BootError::SignatureRefused {
                object: ObjectName::new(name),
                refusal,
            }),
        }
    }
}

/// A key id written as lowercase hex.
struct KeyIdHex<'a>(&'a objsig::KeyId);

impl core::fmt::Display for KeyIdHex<'_>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    {
        for byte in self.0
        {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Fixtures of the host tests here and in `main.rs`: stores and signed
/// objects of fixed test keys.
#[cfg(test)]
pub(crate) mod testing
{
    use objsig::composite::{self, SEED_LEN};
    use objsig::{
        AnchorSpec, Attributes, RecordSpec, Role, RoleSet, TrustStore, Usage, encode_trailer,
        key_id, trailer_len,
    };

    use super::ARCH;

    /// The composite secret of the root the test stores trust.
    pub(crate) const ROOT_SEED: [u8; SEED_LEN] = [7; SEED_LEN];
    /// The composite secret of a key no test store trusts.
    pub(crate) const STRANGER_SEED: [u8; SEED_LEN] = [9; SEED_LEN];

    /// A store of one anchor, the key of `seed`, which may sign every role.
    pub(crate) fn store_of(seed: &[u8; SEED_LEN]) -> Vec<u8>
    {
        let key = composite::public_key(seed);
        let spec = AnchorSpec {
            key: &key,
            usage: Usage {
                roles: RoleSet::ALL,
                certify: true,
            },
            local: true,
            label: "test root",
        };
        let mut out = vec![0u8; TrustStore::encoded_len(1, 0).unwrap()];
        TrustStore::encode(1, &[spec], &[], &mut out).unwrap();
        out
    }

    /// `body` signed by the key of `seed` with the set of `roles`, named
    /// `name`.
    pub(crate) fn signed(seed: &[u8; SEED_LEN], body: &[u8], roles: &[Role], name: &[u8])
    -> Vec<u8>
    {
        let attrs = Attributes {
            body_len: u64::try_from(body.len()).unwrap(),
            security_version: 1,
            roles: RoleSet::of(roles),
            arch: ARCH,
            body_hash: crypto::sha512(body),
            name,
        };
        let mut message = vec![0u8; attrs.encoded_len().unwrap()];
        attrs.encode(&mut message).unwrap();
        let signature = Box::new(composite::sign(seed, &message).unwrap());
        let record = RecordSpec {
            signer_key_id: key_id(&composite::public_key(seed)),
            attrs,
            certificate: None,
            signature: &signature,
        };
        let mut trailer = vec![0u8; trailer_len(&[record]).unwrap()];
        encode_trailer(body, &[record], &mut trailer).unwrap();
        [body, trailer.as_slice()].concat()
    }
}

#[cfg(test)]
mod tests
{
    use objsig::{RecordFailure, Refusal};

    use super::testing::{ROOT_SEED, STRANGER_SEED, signed, store_of};
    use super::*;

    // Defect caught: a bootloader that loads anything but the verified body
    // of an object the store accepts.
    #[test]
    fn an_accepted_object_yields_its_body()
    {
        let bytes = store_of(&ROOT_SEED);
        let mut verifier = Verifier::new(parse_store(&bytes).unwrap());
        let object = signed(&ROOT_SEED, b"\x7fELF kernel", &[Role::Kernel], b"kernel");
        assert_eq!(
            verifier.object(&object, Role::Kernel, b"kernel").unwrap(),
            b"\x7fELF kernel"
        );
        // An installed service the bootstrap needs, loaded as a bundle entry.
        let devmgr = signed(
            &ROOT_SEED,
            b"devmgr image",
            &[Role::Service, Role::BootModule],
            DEVMGR,
        );
        assert_eq!(
            verifier.object(&devmgr, Role::BootModule, DEVMGR).unwrap(),
            b"devmgr image"
        );
    }

    /// The install path of the module the refusal tests load.
    const DEVMGR: &[u8] = b"/services/devmgr";

    // Defect caught: a tampered, renamed, misused or unsigned object, or one
    // signed by a key the store does not trust, loaded rather than refused,
    // or refused without its name.
    #[test]
    fn every_refusal_names_the_object()
    {
        let bytes = store_of(&ROOT_SEED);
        let mut verifier = Verifier::new(parse_store(&bytes).unwrap());
        let object = signed(
            &ROOT_SEED,
            b"devmgr image",
            &[Role::Service, Role::BootModule],
            DEVMGR,
        );
        let mut tampered = object.clone();
        tampered[0] ^= 1;
        let mut refused = |object: &[u8], role: Role, name: &[u8]| match verifier
            .object(object, role, name)
        {
            Err(BootError::SignatureRefused { object, refusal }) =>
            {
                assert_eq!(object.as_bytes(), name);
                refusal
            }
            other => panic!("expected a refusal, got {other:?}"),
        };
        assert_eq!(
            refused(&tampered, Role::BootModule, DEVMGR),
            Refusal::Failed(RecordFailure::BodyHash)
        );
        assert_eq!(
            refused(&object, Role::BootModule, b"/services/vfsd"),
            Refusal::Failed(RecordFailure::Name)
        );
        assert_eq!(
            refused(&object, Role::Init, DEVMGR),
            Refusal::Failed(RecordFailure::Role)
        );
        // An installed service the bundle list may not name.
        let service = signed(&ROOT_SEED, b"devmgr image", &[Role::Service], DEVMGR);
        assert_eq!(
            refused(&service, Role::BootModule, DEVMGR),
            Refusal::Failed(RecordFailure::Role)
        );
        assert!(matches!(
            refused(b"devmgr image", Role::BootModule, DEVMGR),
            Refusal::Parse(_)
        ));
        let stranger = signed(
            &STRANGER_SEED,
            b"devmgr image",
            &[Role::Service, Role::BootModule],
            DEVMGR,
        );
        assert_eq!(
            refused(&stranger, Role::BootModule, DEVMGR),
            Refusal::Untrusted
        );
        let message = format!(
            "{}",
            Verifier::new(parse_store(&bytes).unwrap())
                .object(&tampered, Role::BootModule, DEVMGR)
                .unwrap_err()
        );
        assert!(
            message.contains("/services/devmgr") && message.contains("BodyHash"),
            "{message}"
        );
    }

    // Defect caught: a store that does not parse taken as an empty store, or
    // halting without saying why.
    #[test]
    fn a_store_that_does_not_parse_is_a_boot_error()
    {
        let mut bytes = store_of(&ROOT_SEED);
        bytes[0] ^= 1;
        assert!(matches!(
            parse_store(&bytes),
            Err(BootError::TrustStore(objsig::StoreError::Magic))
        ));
        assert!(matches!(
            parse_store(embedded_store()),
            Err(BootError::TrustStore(_))
        ));
    }

    // Defect caught: a key id logged in another form than xtask prints.
    #[test]
    fn a_key_id_is_written_as_lowercase_hex()
    {
        let mut id = [0u8; objsig::KEY_ID_LEN];
        id[0] = 0xab;
        id[15] = 0x01;
        assert_eq!(
            format!("{}", KeyIdHex(&id)),
            "ab000000000000000000000000000001"
        );
    }
}
