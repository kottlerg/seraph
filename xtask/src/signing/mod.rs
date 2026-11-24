// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/signing/mod.rs

//! Signing of the objects a build packs, and the trust store the bootloader
//! is built with (docs/signing.md § Signing).
//!
//! Every object is signed once, in the sysroot, under its install path and the
//! roles it may be loaded in ([`sign_sysroot`]): the kernel, every ELF image
//! under `services/`, `programs/` and `tests/`, the data files, the
//! configuration files with the index of each of their directories, and every
//! other file a bundle list names. [`crate::disk::create_disk_image`] signs the sysroot as
//! it packs ([`sign_for_harness`]), before [`crate::esp`] composes the ESP,
//! which copies installed files and signs nothing. A signed object is its body and a trailer of one record
//! ([`Signer::sign`]), which [`objsig::verify`] accepts under the build's
//! trust store before it is written, with each of its roles, its name and the
//! architecture the bootloader and procmgr expect of it.
//!
//! - [`identity`]: the signing key, its certificate and the anchors it
//!   contributes, in a directory outside the work tree, generated on first
//!   use; an external signer in place of the key.
//! - [`store`]: the trust store, from the identity's anchors and a deployer's
//!   store.

mod identity;
pub mod request;
mod store;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use objsig::attrs::Attributes;
use objsig::{Expectation, KeyId, ParseError, RecordSpec, Role, RoleSet, TrustStore};

use crate::arch::Arch;
use crate::bundle::Harness;
use crate::context::Context as BuildContext;
use crate::error::{Context, Result, bail, ensure, err};

pub use identity::{Identity, os_random};
pub use store::StoreMode;

/// The security version every record of a build of this tree carries, and the
/// lowest floor of the trust store it builds (docs/signing.md § Signing).
/// Raised by a security fix that MUST make the images of older trees
/// unbootable.
pub const SECURITY_VERSION: u32 = 1;

/// The directory of the signing identity; by default
/// `seraph/signing/ed25519-ml-dsa-65-roles-1-9` in the user's data directory
/// ([`default_dir`]).
pub const ENV_SIGNING_DIR: &str = "SERAPH_SIGNING_DIR";

/// An external signer program, which holds the signing key in place of the
/// identity's seed.
pub const ENV_SIGNER: &str = "SERAPH_SIGNER";

/// A deployer's trust store, combined with the identity's as
/// [`ENV_TRUST_STORE_MODE`] says.
pub const ENV_TRUST_STORE: &str = "SERAPH_TRUST_STORE";

/// How [`ENV_TRUST_STORE`] combines with the identity's store: `merge` (the
/// default) or `replace`.
pub const ENV_TRUST_STORE_MODE: &str = "SERAPH_TRUST_STORE_MODE";

/// The last component of the default identity directory: the signature
/// algorithm of the identity it holds, and the roles its key is certified for
/// (1 to 9, [`Role::ALL`]).
const IDENTITY_DIR: &str = "ed25519-ml-dsa-65-roles-1-9";

/// The first four bytes of an ELF image.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// The sysroot trees whose ELF images [`sign_sysroot`] signs, each installed
/// on the root filesystem at its sysroot path.
const SIGNED_TREES: &[&str] = &["services", "programs", "tests"];

/// The sysroot trees whose every regular file [`sign_sysroot`] signs in the
/// data role, each under its install path: the data files a process reads
/// from the root filesystem as trusted input through procmgr's verified
/// read (docs/signing.md § Which Stage Verifies What): `config/devmgr/platform`
/// the platform description tables devmgr reads, and `data/svctest/signed`
/// svctest's fixture of that read.
const DATA_TREES: &[&str] = &["config/devmgr/platform", "data/svctest/signed"];

/// The sysroot directories of configuration files a service reads through
/// the directory's signed index (docs/signing.md § Configuration), each
/// with the suffix every file in it carries: svcmgr's service recipes and
/// device class files. [`sign_sysroot`] writes each directory's index and
/// signs it and every file in it in the configuration role, under its
/// install path.
const CONFIG_TREES: &[(&str, &str)] = &[
    ("config/svcmgr/services", ".svc"),
    ("config/devmgr/classes", ".class"),
];

/// The configuration files a service reads alone, through procmgr's
/// verified read in the configuration role under the file's install path
/// (docs/signing.md § Configuration), with no index: vfsd's storage
/// statement (`storage_statement::PATH`), whose removal withdraws the roles
/// it gives and grants none. [`sign_sysroot`] signs each the sysroot holds.
const CONFIG_FILES: &[&str] = &[storage_statement::PATH];

/// The index file name, [`objsig::INDEX_NAME`], as text.
const INDEX_FILE: &str = "index";

/// The signing configuration a build reads from its environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config
{
    /// The directory of the signing identity.
    pub dir: PathBuf,
    /// The external signer, when one holds the key.
    pub signer: Option<PathBuf>,
    /// A deployer's store and how it combines with the identity's.
    pub deployer_store: Option<(PathBuf, StoreMode)>,
}

impl Config
{
    /// The configuration [`ENV_SIGNING_DIR`], [`ENV_SIGNER`],
    /// [`ENV_TRUST_STORE`] and [`ENV_TRUST_STORE_MODE`] set in the
    /// environment.
    ///
    /// # Errors
    ///
    /// Those of [`Self::from_vars`].
    pub fn from_env() -> Result<Self>
    {
        Self::from_vars(&|name| std::env::var_os(name))
    }

    /// The configuration of the variables `lookup` returns; an empty
    /// variable is unset.
    ///
    /// # Errors
    ///
    /// When no per-user data directory is known and [`ENV_SIGNING_DIR`] is
    /// unset; when [`ENV_TRUST_STORE_MODE`] names no mode or is set without
    /// [`ENV_TRUST_STORE`].
    pub fn from_vars(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<Self>
    {
        let var = |name: &str| lookup(name).filter(|value| !value.is_empty());
        let dir = match var(ENV_SIGNING_DIR)
        {
            Some(dir) => PathBuf::from(dir),
            None => default_dir(&var)?,
        };
        let mode = match var(ENV_TRUST_STORE_MODE)
        {
            None => None,
            Some(value) => Some(value.to_str().and_then(StoreMode::parse).with_context(|| {
                format!(
                    "{ENV_TRUST_STORE_MODE}={} names no mode: merge or replace",
                    value.to_string_lossy()
                )
            })?),
        };
        let deployer_store = match (var(ENV_TRUST_STORE), mode)
        {
            (Some(path), mode) => Some((PathBuf::from(path), mode.unwrap_or(StoreMode::Merge))),
            (None, Some(_)) => bail!("{ENV_TRUST_STORE_MODE} is set without {ENV_TRUST_STORE}"),
            (None, None) => None,
        };
        Ok(Self {
            dir,
            signer: var(ENV_SIGNER).map(PathBuf::from),
            deployer_store,
        })
    }
}

/// The default directory of the signing identity, from the variables `var`
/// returns: `seraph/signing/` and [`IDENTITY_DIR`] in `XDG_DATA_HOME`, in
/// `.local/share` of `HOME`, or in `LOCALAPPDATA`, the first of them set to
/// an absolute path. The last component names the signature algorithm and the
/// roles a generated key is certified for, so an identity of an earlier
/// algorithm, or one certified before a role existed, in its own directory, is
/// never loaded as this one's (docs/signing.md § Signing).
fn default_dir(var: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf>
{
    let absolute = |name: &str| {
        var(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
    };
    absolute("XDG_DATA_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".local").join("share")))
        .or_else(|| absolute("LOCALAPPDATA"))
        .map(|data| data.join("seraph").join("signing").join(IDENTITY_DIR))
        .with_context(|| format!("no per-user data directory: set {ENV_SIGNING_DIR}"))
}

/// The signing context of one build: its identity, its trust store, and the
/// architecture its objects run on.
pub struct Signer
{
    identity: Identity,
    store: Vec<u8>,
    arch: objsig::Arch,
}

impl Signer
{
    /// The signer of a pack of `arch` in `ctx`: [`Self::for_bootloader`],
    /// refused unless the installed bootloader embeds its trust store
    /// ([`check_installed_store`]), so no pack signs under a store the
    /// bootloader it boots with, a copy of the installed one, does not hold.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::for_bootloader`] and [`check_installed_store`].
    pub fn open(ctx: &BuildContext, arch: Arch) -> Result<Self>
    {
        let signer = Self::for_bootloader(ctx, arch)?;
        check_installed_store(&ctx.installed_bootloader(), signer.store())?;
        Ok(signer)
    }

    /// The signer of a build of `arch` in `ctx`, configured by the
    /// environment ([`Config::from_env`]), generating a local identity on
    /// first use. The bootloader's build takes it unchecked, since it writes
    /// the store the bootloader embeds; every pack takes [`Self::open`].
    ///
    /// # Errors
    ///
    /// The errors of [`Config::from_env`] and [`Self::new`].
    pub fn for_bootloader(ctx: &BuildContext, arch: Arch) -> Result<Self>
    {
        Self::new(&Config::from_env()?, &ctx.root, arch, &mut os_random)
    }

    /// The signer `config` describes, refusing a key inside `work_tree`,
    /// generating a local identity with seeds from `fill` when its directory
    /// holds none.
    ///
    /// # Errors
    ///
    /// The errors of [`Identity::load`] and of building the store; when the
    /// deployer's store cannot be read; when the store trusts the signing key
    /// for some roles but not for every one a build signs in
    /// ([`missing_roles`]).
    pub fn new(
        config: &Config,
        work_tree: &Path,
        arch: Arch,
        fill: &mut dyn FnMut(&mut [u8; 32]),
    ) -> Result<Self>
    {
        let identity = Identity::load(&config.dir, config.signer.as_deref(), work_tree, fill)?;
        let deployer = config
            .deployer_store
            .as_ref()
            .map(|(path, mode)| {
                fs::read(path)
                    .with_context(|| format!("reading the deployer's store {}", path.display()))
                    .map(|bytes| (bytes, *mode))
            })
            .transpose()?;
        let store = store::build(
            identity.store(),
            deployer
                .as_ref()
                .map(|(bytes, mode)| (bytes.as_slice(), *mode)),
            SECURITY_VERSION,
        )?;
        let missing = missing_roles(&store, identity.public_key(), identity.certificate())?;
        if !missing.is_empty()
        {
            bail!(
                "the signing identity in {} may not sign the {missing:?} role under the build's \
                 trust store, and a build signs every role: a key certified before a role existed \
                 lacks it. Use an identity certified for every role: unset {ENV_SIGNING_DIR} to \
                 have one generated in the default directory, or have the identity's root certify \
                 the key again (docs/signing.md § Signing)",
                config.dir.display()
            );
        }
        Ok(Self {
            identity,
            store,
            arch: objsig_arch(arch),
        })
    }

    /// The encoded trust store of the build.
    pub fn store(&self) -> &[u8]
    {
        &self.store
    }

    /// The key id of the signing key, which every record it makes names.
    pub fn key_id(&self) -> KeyId
    {
        objsig::key_id(self.identity.public_key())
    }

    /// The build's trust store with the signing key's id among its revoked
    /// key ids: a store that refuses every record this signer makes
    /// (`RecordFailure::Revoked`), as a deployer's store revoking the key
    /// would.
    ///
    /// # Errors
    ///
    /// When the build's store does not parse.
    pub fn store_revoking_own_key(&self) -> Result<Vec<u8>>
    {
        store::with_revoked(&self.store, self.key_id())
    }

    /// The build's trust store with the anchors of the identity of each signer
    /// of `scoped` added, each trusted for the paired roles alone
    /// (`store::with_scoped_anchors`): a store a test builds a bootloader
    /// under to have it refuse a key outside the roles it is trusted for.
    ///
    /// # Errors
    ///
    /// Those of `store::with_scoped_anchors`.
    pub fn store_trusting(&self, scoped: &[(&Self, RoleSet)]) -> Result<Vec<u8>>
    {
        let pairs: Vec<(&[u8], RoleSet)> = scoped
            .iter()
            .map(|(signer, roles)| (signer.identity.store(), *roles))
            .collect();
        store::with_scoped_anchors(&self.store, &pairs)
    }

    /// The build's trust store with its floor set to `security_floor`: under
    /// a higher floor, a store that refuses every record [`Self::sign`] makes
    /// (`RecordFailure::SecurityFloor`), as a later build's would.
    ///
    /// # Errors
    ///
    /// When the build's store does not parse.
    pub fn store_with_floor(&self, security_floor: u32) -> Result<Vec<u8>>
    {
        store::with_floor(&self.store, security_floor)
    }

    /// `object` signed with the role set `roles` under `name`: its body, the
    /// object less any trailer it carries, followed by a trailer of one
    /// record of the signing key. The result is verified under the build's
    /// store, with each of `roles`, `name` and the build's architecture
    /// expected, before it is returned. Signing is deterministic, so an
    /// object already signed so comes back unchanged.
    ///
    /// # Errors
    ///
    /// When `object` ends in a malformed trailer or its body in the trailer
    /// magic; when `name` is not in the canonical form of docs/signing.md
    /// § Signed Attributes (`objsig::name_is_canonical`), which a loader
    /// checks the name it is given against; when `roles` is not a set a
    /// record may carry (empty, or kernel or init beside another role); when
    /// the signature cannot be made; when the signed object does not verify
    /// (a faulty external signer, or a store that does not trust the key for
    /// one of the roles).
    pub fn sign(&self, object: &[u8], roles: RoleSet, name: &str) -> Result<Vec<u8>>
    {
        self.sign_at(object, roles, name, SECURITY_VERSION)
    }

    /// [`Self::sign`] with the security version `security_version` in
    /// place of the tree's [`SECURITY_VERSION`]: the object a later build,
    /// whose trust store carries a higher floor, makes.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::sign`]; when the signing key's certificate does
    /// not allow `security_version`, or it is below the build's floor.
    pub fn sign_at(
        &self,
        object: &[u8],
        roles: RoleSet,
        name: &str,
        security_version: u32,
    ) -> Result<Vec<u8>>
    {
        if !objsig::name_is_canonical(name.as_bytes())
        {
            bail!(
                "signing {name}: the name is not in the canonical form of docs/signing.md § Signed Attributes"
            );
        }
        let body = body_of(object)?;
        let refused = |e| err!("signing {name}: {e:?}");
        let attrs = Attributes {
            body_len: u64::try_from(body.len()).context("an object longer than u64")?,
            security_version,
            roles,
            arch: self.arch,
            body_hash: crypto::sha512(body),
            name: name.as_bytes(),
        };
        let mut signed = vec![0u8; attrs.encoded_len().map_err(refused)?];
        attrs.encode(&mut signed).map_err(refused)?;
        let signature = self.identity.sign(&signed)?;
        let record = RecordSpec {
            signer_key_id: self.key_id(),
            attrs,
            certificate: self.identity.certificate(),
            signature: &signature,
        };
        let trailer = objsig::trailer_len(&[record]).map_err(refused)?;
        let mut out = body.to_vec();
        out.resize(
            body.len()
                .checked_add(trailer)
                .context("a signed object longer than usize")?,
            0,
        );
        let (_, tail) = out.split_at_mut(body.len());
        objsig::encode_trailer(body, &[record], tail).map_err(refused)?;
        self.check(&out, roles, name)?;
        Ok(out)
    }

    /// Verify the signed `object` as the loader of each of `roles` will,
    /// under the name `name`.
    fn check(&self, object: &[u8], roles: RoleSet, name: &str) -> Result<()>
    {
        let store = TrustStore::parse(&self.store)
            .map_err(|e| err!("the build's trust store does not parse ({e:?})"))?;
        for role in Role::ALL.into_iter().filter(|&role| roles.contains(role))
        {
            let expect = Expectation {
                roles: RoleSet::of(&[role]),
                name: name.as_bytes(),
                arch: self.arch,
            };
            objsig::verify(object, &store, &expect).map_err(|refusal| {
                err!(
                    "{name}, signed with the {role:?} role, does not verify under the build's \
                     trust store ({refusal:?})"
                )
            })?;
        }
        Ok(())
    }

    /// Sign the file at `path` in place with `roles` under `name`; returns
    /// whether its bytes changed.
    ///
    /// # Errors
    ///
    /// On an I/O failure and the errors of [`Self::sign`].
    pub fn sign_file(&self, path: &Path, roles: RoleSet, name: &str) -> Result<bool>
    {
        let object = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let signed = self
            .sign(&object, roles, name)
            .with_context(|| format!("signing {}", path.display()))?;
        if signed == object
        {
            return Ok(false);
        }
        fs::write(path, &signed).with_context(|| format!("writing {}", path.display()))?;
        Ok(true)
    }
}

/// The roles of [`Role::ALL`] the store `store` does not trust the key `key`
/// to sign in, the key certified by `certificate` when it has one: those the
/// usage of the anchor (the issuer's, or the key's own when it is a root) or
/// of the certificate leaves out, as `objsig::verify` refuses them
/// (`Failed(KeyUsage)`). None when the store holds no anchor for the key or
/// its issuer, or the issuer's anchor may not certify: the signing check of
/// every object reports that store as not trusting the key at all.
///
/// # Errors
///
/// When the store or the certificate does not parse.
fn missing_roles(
    store: &[u8],
    key: &objsig::PublicKey,
    certificate: Option<&[u8; objsig::cert::LEN]>,
) -> Result<Vec<Role>>
{
    let store = TrustStore::parse(store)
        .map_err(|e| err!("the build's trust store does not parse ({e:?})"))?;
    let roles = match certificate
    {
        Some(bytes) =>
        {
            let cert = objsig::Certificate::parse(bytes)
                .map_err(|e| err!("the signing key's certificate does not parse ({e:?})"))?;
            match store.anchor(&cert.body.issuer_key_id)
            {
                Some(anchor) if anchor.usage.certify =>
                {
                    anchor.usage.roles.intersection(cert.body.usage.roles)
                }
                _ => return Ok(Vec::new()),
            }
        }
        None => match store.anchor(&objsig::key_id(key))
        {
            Some(anchor) => anchor.usage.roles,
            None => return Ok(Vec::new()),
        },
    };
    Ok(Role::ALL
        .into_iter()
        .filter(|&role| !roles.contains(role))
        .collect())
}

/// The body of `object`: the object less its trailer when it ends in one,
/// the whole object otherwise.
///
/// # Errors
///
/// When `object` ends in the trailer magic but does not parse; a trailer of
/// another format version is refused naming the version as the reason, since
/// a sysroot an earlier tree signed holds such objects until a build installs
/// them again or a clean removes them.
pub fn body_of(object: &[u8]) -> Result<&[u8]>
{
    match objsig::split(object)
    {
        Ok(signed) => Ok(signed.body()),
        Err(ParseError::TooShort | ParseError::Magic) => Ok(object),
        Err(ParseError::Version) => bail!(
            "the object ends in a signature trailer of a format version this tree does not \
             read, as an object an earlier tree signed does: run `cargo xtask build` to \
             install it again, or `cargo xtask clean` when no build of this tree installs it \
             (docs/signing.md § Composite Signature)"
        ),
        Err(e) => bail!("the object ends in a malformed signature trailer ({e:?})"),
    }
}

/// The signed object of `object`'s body whose trailer holds the records of
/// `first` and then those of `object`: a verifier checks `first`'s records
/// before `object`'s.
///
/// # Errors
///
/// When either is not a signed object, when their bodies differ, or when the
/// records do not fit one trailer.
pub fn prepend_records(object: &[u8], first: &[u8]) -> Result<Vec<u8>>
{
    let split = |bytes, which: &str| {
        objsig::split(bytes).map_err(|e| err!("the {which} object does not parse ({e:?})"))
    };
    let own = split(object, "second")?;
    let other = split(first, "first")?;
    let body = own.body();
    ensure!(
        other.body() == body,
        "the two objects are signed over different bodies"
    );
    let records: Vec<RecordSpec<'_>> = other
        .records()
        .chain(own.records())
        .map(|record| record.spec())
        .collect();
    let refused = |e| err!("encoding the trailer of {} records ({e:?})", records.len());
    let trailer = objsig::trailer_len(&records).map_err(refused)?;
    let mut out = body.to_vec();
    out.resize(
        body.len()
            .checked_add(trailer)
            .context("a signed object longer than usize")?,
        0,
    );
    let (_, tail) = out.split_at_mut(body.len());
    objsig::encode_trailer(body, &records, tail).map_err(refused)?;
    Ok(out)
}

/// The trailer format's architecture of `arch`.
pub fn objsig_arch(arch: Arch) -> objsig::Arch
{
    match arch
    {
        Arch::X86_64 => objsig::Arch::X86_64,
        Arch::Riscv64 => objsig::Arch::Riscv64,
    }
}

/// The role of the image installed at `path`, relative to the root of the
/// root filesystem: a driver under a `drivers/` directory, a program under a
/// `programs/` directory, and a service otherwise (docs/signing.md
/// § Signing).
fn location_role(path: &Path) -> Role
{
    let names: Vec<&std::ffi::OsStr> = path
        .parent()
        .into_iter()
        .flat_map(Path::components)
        .map(std::path::Component::as_os_str)
        .collect();
    if names.iter().any(|name| *name == "drivers")
    {
        Role::Driver
    }
    else if names.iter().any(|name| *name == "programs")
    {
        Role::Program
    }
    else
    {
        Role::Service
    }
}

/// The name of the bundle's `init` slot, which the object in it is signed
/// under (`boot_protocol::bundle::INIT_ENTRY_NAME`).
pub const INIT_SLOT: &str = "init";

/// The name and the role set the ELF image installed at `install` is signed
/// with, where `slots` holds the objects signed into the `init` slot and
/// `boot_modules` the entries the bundle lists name: an object of `slots`,
/// `init` with the init role alone; every other image, its install path with
/// its [`location_role`], and the role the bootloader verifies its bundle
/// entry in (`crate::bundle::entry_role`) when a list names it
/// (docs/signing.md § Signing).
fn image_signature(
    install: &str,
    relative: &Path,
    slots: &[String],
    boot_modules: &[String],
) -> (String, RoleSet)
{
    if slots.iter().any(|slot| slot == install)
    {
        return (INIT_SLOT.to_owned(), RoleSet::of(&[Role::Init]));
    }
    let role = location_role(relative);
    let roles = if boot_modules.iter().any(|module| module == install)
    {
        RoleSet::of(&[role, crate::bundle::entry_role(install)])
    }
    else
    {
        RoleSet::of(&[role])
    };
    (install.to_owned(), roles)
}

/// The install path of `path`, relative to the root of the root filesystem:
/// `/` and its components joined by `/`.
fn install_name(path: &Path) -> Result<String>
{
    let mut name = String::new();
    for component in path.components()
    {
        let part = component
            .as_os_str()
            .to_str()
            .with_context(|| format!("{} is not UTF-8", path.display()))?;
        name.push('/');
        name.push_str(part);
    }
    Ok(name)
}

/// Sign every object of the sysroot for a pack of `arch` that composes the
/// bundle of `harness`, as the installed bundle lists of `arch` say
/// (`crate::bundle::read_list`): the installed kernel, `kernel` with the
/// kernel role alone; every ELF image under [`SIGNED_TREES`] as
/// [`image_signature`] says; every regular file under [`DATA_TREES`] under
/// its install path in the data role, and beside it, when a list names it,
/// the role the bootloader verifies its bundle entry in
/// (`crate::bundle::entry_role`); every regular file of each directory of
/// [`CONFIG_TREES`] under its install path in the configuration role, the
/// role of its bundle entry too, with the directory's index written from the
/// files it holds ([`write_index`]) and signed in the configuration role
/// under `<directory>/index`; each of [`CONFIG_FILES`] the sysroot holds
/// under its install path in the configuration role; and every other
/// installed file a list names,
/// `init` with the init role alone when it is the object of a signed `init`
/// slot, under its install path with its bundle entry's role alone otherwise. The `init` slot objects signed are the init harness's, always,
/// and `harness`'s. A file a list names that the sysroot does not install is
/// left to the compose of a bundle that names it, which refuses it. Returns how
/// many objects were signed and how many of them changed.
///
/// # Errors
///
/// On an I/O failure; the errors of `crate::bundle::read_list`,
/// [`Signer::sign_file`] and [`config_files`]; when an object a list puts in
/// the `init` slot is an entry of a list too, since an object is signed under
/// one name.
pub fn sign_sysroot(
    ctx: &BuildContext,
    signer: &Signer,
    arch: Arch,
    harness: Harness,
) -> Result<(usize, usize)>
{
    let boot_modules = crate::bundle::boot_modules(ctx, arch)?;
    let mut slots = vec![crate::bundle::read_list(ctx, arch, Harness::Init)?.init];
    let packed = crate::bundle::read_list(ctx, arch, harness)?.init;
    if !slots.contains(&packed)
    {
        slots.push(packed);
    }
    if let Some(both) = slots.iter().find(|slot| boot_modules.contains(slot))
    {
        bail!(
            "{both} is the object of an `init` slot and an entry of a bundle list: an object \
             is signed under one name"
        );
    }
    let mut total = 0usize;
    let mut changed = 0usize;
    let mut count = |was_changed: bool| {
        total = total.saturating_add(1);
        changed = changed.saturating_add(usize::from(was_changed));
    };
    let kernel = ctx.installed_kernel();
    if kernel.is_file()
    {
        count(signer.sign_file(&kernel, RoleSet::of(&[Role::Kernel]), "kernel")?);
    }
    let mut done = std::collections::HashSet::new();
    for tree in SIGNED_TREES
    {
        for relative in tree_files(&ctx.sysroot, Path::new(tree), Files::Elf)?
        {
            let install = install_name(&relative)?;
            let (name, roles) = image_signature(&install, &relative, &slots, &boot_modules);
            count(signer.sign_file(&ctx.sysroot.join(&relative), roles, &name)?);
            done.insert(install);
        }
    }
    for tree in DATA_TREES
    {
        for relative in tree_files(&ctx.sysroot, Path::new(tree), Files::All)?
        {
            let install = install_name(&relative)?;
            let roles = if boot_modules.contains(&install)
            {
                RoleSet::of(&[Role::Data, crate::bundle::entry_role(&install)])
            }
            else
            {
                RoleSet::of(&[Role::Data])
            };
            count(signer.sign_file(&ctx.sysroot.join(&relative), roles, &install)?);
            done.insert(install);
        }
    }
    sign_config_trees(ctx, signer, &mut done, &mut count)?;
    for install in CONFIG_FILES
    {
        let path = ctx.sysroot.join(install.trim_start_matches('/'));
        if !path.is_file()
        {
            continue;
        }
        let roles = if boot_modules.iter().any(|module| module == install)
        {
            RoleSet::of(&[Role::Configuration, crate::bundle::entry_role(install)])
        }
        else
        {
            RoleSet::of(&[Role::Configuration])
        };
        count(signer.sign_file(&path, roles, install)?);
        done.insert((*install).to_owned());
    }
    for install in slots.iter().chain(&boot_modules)
    {
        let path = ctx.sysroot.join(install.trim_start_matches('/'));
        if done.contains(install) || !path.is_file()
        {
            continue;
        }
        let (name, role) = if slots.contains(install)
        {
            (INIT_SLOT, Role::Init)
        }
        else
        {
            (install.as_str(), crate::bundle::entry_role(install))
        };
        count(signer.sign_file(&path, RoleSet::of(&[role]), name)?);
    }
    Ok((total, changed))
}

/// Sign every file of each directory of [`CONFIG_TREES`] in `ctx`'s sysroot
/// in the configuration role under its install path, which is also the role
/// the bootloader verifies it in when a bundle list names it
/// (`crate::bundle::entry_role`), and write the directory's index of their
/// names and body digests ([`write_index`]); each install path signed goes
/// into `done`, and each object signed to `count`, with whether it changed.
///
/// # Errors
///
/// Those of [`config_files`], [`Signer::sign_file`] and [`write_index`].
fn sign_config_trees(
    ctx: &BuildContext,
    signer: &Signer,
    done: &mut std::collections::HashSet<String>,
    count: &mut dyn FnMut(bool),
) -> Result<()>
{
    for (tree, suffix) in CONFIG_TREES
    {
        let Some(names) = config_files(&ctx.sysroot.join(tree), suffix)?
        else
        {
            continue;
        };
        for name in &names
        {
            let relative = Path::new(tree).join(name);
            let install = install_name(&relative)?;
            let roles = RoleSet::of(&[Role::Configuration]);
            count(signer.sign_file(&ctx.sysroot.join(&relative), roles, &install)?);
            done.insert(install);
        }
        let entries = index_entries(&ctx.sysroot.join(tree), &names)?;
        let relative = Path::new(tree).join(INDEX_FILE);
        let install = install_name(&relative)?;
        count(write_index(
            signer,
            &ctx.sysroot.join(&relative),
            &install,
            &entries,
        )?);
        done.insert(install);
    }
    Ok(())
}

/// The names of the files of the configuration directory `dir`, sorted byte
/// for byte, the order its index holds them in; the index itself, which the
/// pack writes, is not one. `None` when `dir` is absent.
///
/// # Errors
///
/// On an I/O failure; when `dir` holds a subdirectory or a link, or a file
/// whose name does not end in `suffix` or is not a canonical path component
/// (`objsig::name_is_component`): a consumer reads only the files the index
/// names, so a file it would pass over is refused here, where it was put.
pub fn config_files(dir: &Path, suffix: &str) -> Result<Option<Vec<String>>>
{
    let entries = match fs::read_dir(dir)
    {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut names = Vec::new();
    for entry in entries
    {
        let entry = entry.with_context(|| format!("reading {}", dir.display()))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .with_context(|| format!("reading {}", path.display()))?;
        ensure!(
            kind.is_file(),
            "{}: a configuration directory holds regular files alone, each named by the \
             directory's signed index (docs/signing.md § Configuration)",
            path.display()
        );
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| err!("{}: the name is not UTF-8", path.display()))?;
        if name == INDEX_FILE
        {
            continue;
        }
        ensure!(
            name.ends_with(suffix) && objsig::name_is_component(name.as_bytes()),
            "{}: every file of {} is a `{suffix}` file, the only kind its consumer reads \
             (docs/signing.md § Configuration)",
            path.display(),
            dir.display()
        );
        names.push(name);
    }
    // Byte order: `str`'s order is its bytes'.
    names.sort_unstable();
    Ok(Some(names))
}

/// One line of a directory index: a file's name and the SHA-512 of its body.
pub type IndexEntry = (String, objsig::index::Digest);

/// The index entries of the files `names` of the configuration directory
/// `dir`, in the order of `names`: each name with the digest of the file's
/// body, the file less its signature trailer ([`body_of`]), so signing a
/// file again leaves its entry unchanged.
///
/// # Errors
///
/// On an I/O failure, and those of [`body_of`].
pub fn index_entries(dir: &Path, names: &[String]) -> Result<Vec<IndexEntry>>
{
    names
        .iter()
        .map(|name| {
            let path = dir.join(name);
            let object = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            let body = body_of(&object).with_context(|| format!("reading {}", path.display()))?;
            Ok((name.clone(), objsig::index::body_digest(body)))
        })
        .collect()
}

/// The body of the index of `entries`, which are sorted by name
/// ([`config_files`]).
///
/// # Errors
///
/// When `objsig::index::encode` refuses them.
pub fn index_body(entries: &[IndexEntry]) -> Result<Vec<u8>>
{
    let entries: Vec<objsig::index::Entry<'_>> = entries
        .iter()
        .map(|(name, digest)| objsig::index::Entry {
            name: name.as_bytes(),
            digest: *digest,
        })
        .collect();
    let refused = |e| err!("encoding a directory index ({e:?})");
    let mut body =
        vec![0u8; objsig::index::encoded_len(&entries).context("an index longer than usize")?];
    objsig::index::encode(&entries, &mut body).map_err(refused)?;
    Ok(body)
}

/// Write at `path` the index of `entries` ([`index_body`]) signed in the
/// configuration role under `install`, unless the file already holds it;
/// returns whether its bytes changed.
///
/// # Errors
///
/// On an I/O failure and the errors of [`index_body`] and [`Signer::sign`].
fn write_index(signer: &Signer, path: &Path, install: &str, entries: &[IndexEntry])
-> Result<bool>
{
    let object = signer
        .sign(
            &index_body(entries)?,
            RoleSet::of(&[Role::Configuration]),
            install,
        )
        .with_context(|| format!("signing {}", path.display()))?;
    if fs::read(path).is_ok_and(|held| held == object)
    {
        return Ok(false);
    }
    fs::write(path, &object).with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// The sysroot paths of the index of each directory of [`CONFIG_TREES`],
/// which every pack writes: the rootfs mirror's prune keeps them.
pub fn config_indexes(sysroot: &Path) -> Vec<PathBuf>
{
    CONFIG_TREES
        .iter()
        .map(|(tree, _)| sysroot.join(tree).join(INDEX_FILE))
        .collect()
}

/// Sign the sysroot for a pack of `arch` that composes the bundle of
/// `harness` ([`sign_sysroot`]), with the signer of a pack
/// ([`Signer::open`]): what a pack does before it composes the ESP, since
/// the ESP copies the installed files as they are.
///
/// # Errors
///
/// Those of [`Signer::open`] and [`sign_sysroot`].
pub fn sign_for_harness(ctx: &BuildContext, arch: Arch, harness: Harness) -> Result<()>
{
    let signer = Signer::open(ctx, arch)?;
    let (images, changed) = sign_sysroot(ctx, &signer, arch, harness)?;
    crate::util::step(&format!("Signed {images} objects ({changed} changed)"));
    Ok(())
}

/// Which regular files of a tree [`tree_files`] lists.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Files
{
    /// Those whose bytes begin with the ELF magic.
    Elf,
    /// Every one.
    All,
}

/// The regular files under `root/dir` that `which` selects, as paths
/// relative to `root`, sorted; none when `dir` is absent. A symbolic link
/// is not followed.
fn tree_files(root: &Path, dir: &Path, which: Files) -> Result<Vec<PathBuf>>
{
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(relative) = pending.pop()
    {
        let full = root.join(&relative);
        let entries = match fs::read_dir(&full)
        {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", full.display())),
        };
        for entry in entries
        {
            let entry = entry.with_context(|| format!("reading {}", full.display()))?;
            let kind = entry
                .file_type()
                .with_context(|| format!("reading {}", entry.path().display()))?;
            let path = relative.join(entry.file_name());
            if kind.is_dir()
            {
                pending.push(path);
            }
            else if kind.is_file()
                && (which == Files::All || starts_with_elf_magic(&entry.path())?)
            {
                found.push(path);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Whether the file at `path` begins with [`ELF_MAGIC`].
fn starts_with_elf_magic(path: &Path) -> Result<bool>
{
    use std::io::Read as _;
    let mut magic = [0u8; 4];
    let mut file = fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    match file.read_exact(&mut magic)
    {
        Ok(()) => Ok(&magic == ELF_MAGIC),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write the build's trust store to `target/xtask/signing/trust-store`,
/// the store the bootloader is to embed, leaving the file untouched when it
/// already holds it, so a build that tracks the file will rebuild only when
/// the store changes; returns its path.
///
/// # Errors
///
/// On an I/O failure.
pub fn write_boot_store(ctx: &BuildContext, signer: &Signer) -> Result<PathBuf>
{
    let dir = ctx.target_dir.join("xtask").join("signing");
    let path = dir.join("trust-store");
    if fs::read(&path).is_ok_and(|held| held == signer.store())
    {
        return Ok(path);
    }
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::write(&path, signer.store()).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// The trust store the installed bootloader (`/boot/boot.efi`) embeds: the
/// one a boot of a pack verifies under, since the ESP's bootloader images are
/// its copies.
///
/// # Errors
///
/// When the image cannot be read or embeds no store or more than one.
pub fn installed_store(ctx: &BuildContext) -> Result<Vec<u8>>
{
    let image = ctx.installed_bootloader();
    let bytes = fs::read(&image).with_context(|| {
        format!(
            "reading the installed bootloader {} (run `cargo xtask build`)",
            image.display()
        )
    })?;
    let store = objsig::embed::find(&bytes).map_err(|e| {
        err!(
            "the installed bootloader {} holds no trust store ({e:?}): run `cargo xtask build`",
            image.display()
        )
    })?;
    Ok(store.to_vec())
}

/// Refuse unless `image` embeds `store`: the trust store read out of the
/// image ([`objsig::embed::find`]) is the one the pack signs under.
///
/// # Errors
///
/// Naming the image and the rebuild that fixes it: when the image cannot be
/// read, embeds no store or more than one, embeds one that does not parse, or
/// embeds another store.
pub fn check_installed_store(image: &Path, store: &[u8]) -> Result<()>
{
    const FIX: &str = "rebuild the bootloader with `cargo xtask build`";
    let bytes = fs::read(image).with_context(|| {
        format!(
            "reading the installed bootloader {}, whose trust store a pack signs under ({FIX})",
            image.display()
        )
    })?;
    let embedded = objsig::embed::find(&bytes).map_err(|e| {
        err!(
            "the installed bootloader {} holds no trust store a pack can read ({e:?}): {FIX}",
            image.display()
        )
    })?;
    if embedded != store
    {
        bail!(
            "the installed bootloader {} embeds another trust store than this build signs under, \
             so it would refuse what the pack signs: {FIX}",
            image.display()
        );
    }
    Ok(())
}

/// Fixtures of the signing tests, here and in [`crate::bundle`].
#[cfg(test)]
pub mod testing
{
    use std::path::{Path, PathBuf};

    use super::{Config, Signer};
    use crate::arch::Arch;
    use crate::context::Context as BuildContext;

    /// Install the repository's bundle lists (`rootfs/config/bundle/`) in the
    /// sysroot of `ctx`, as the rootfs mirror does.
    pub fn install_lists(ctx: &BuildContext)
    {
        let from = work_tree().join("rootfs").join(crate::bundle::LIST_DIR);
        let to = ctx.sysroot.join(crate::bundle::LIST_DIR);
        std::fs::create_dir_all(&to).unwrap();
        for entry in std::fs::read_dir(from).unwrap()
        {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }

    /// Install the repository's boot-time policy in `ctx`'s sysroot, unsigned,
    /// over any file there: the body a pack accepts.
    pub fn install_policy(ctx: &BuildContext)
    {
        let name = String::from_utf8_lossy(boot_protocol::bundle::POLICY_ENTRY_NAME);
        let to = ctx.sysroot.join(&name[1..]);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        std::fs::copy(work_tree().join("rootfs").join(&name[1..]), to).unwrap();
    }

    /// The work tree the tests' identities lie outside of: the repository.
    pub fn work_tree() -> PathBuf
    {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    }

    /// A new, empty directory outside the work tree, unique to this process
    /// and call. The tests run in parallel threads of one process, so the
    /// name carries a per-process sequence number rather than a clock
    /// reading two calls can share; a directory an earlier process of the
    /// same id left behind is removed first.
    pub fn scratch(tag: &str) -> PathBuf
    {
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "seraph-signing-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A seed source that fills each seed with one byte value, `first` and
    /// then each next one, so a test's keys are fixed.
    pub fn counter(first: u8) -> impl FnMut(&mut [u8; 32])
    {
        let mut next = first;
        move |seed| {
            seed.fill(next);
            next = next.wrapping_add(1);
        }
    }

    /// The configuration of an identity in `dir`, with no external signer
    /// and no deployer's store.
    pub fn config(dir: &Path) -> Config
    {
        Config {
            dir: dir.to_path_buf(),
            signer: None,
            deployer_store: None,
        }
    }

    /// A signer for `arch` whose local identity is generated in `dir`.
    pub fn signer(dir: &Path, arch: Arch) -> Signer
    {
        Signer::new(&config(dir), &work_tree(), arch, &mut counter(1)).unwrap()
    }
}

#[cfg(test)]
mod tests
{
    use std::collections::BTreeMap;

    use objsig::Arch as SigArch;

    use super::testing::{config, counter, scratch, signer, work_tree};
    use super::*;

    /// Two calls of `testing::scratch` with one tag, which a clock reading of
    /// the same value used to give one directory, give two distinct
    /// directories, each present.
    #[test]
    fn scratch_gives_each_call_its_own_directory()
    {
        let (first, second) = (scratch("scratch-twice"), scratch("scratch-twice"));
        assert_ne!(first, second);
        assert!(first.is_dir() && second.is_dir());
        std::fs::remove_dir_all(first).unwrap();
        std::fs::remove_dir_all(second).unwrap();
    }

    /// `object` verified under `signer`'s store for a loader of `role`
    /// named `name` on riscv64.
    fn verifies(signer: &Signer, object: &[u8], role: Role, name: &str) -> bool
    {
        let store = TrustStore::parse(signer.store()).unwrap();
        let expect = Expectation {
            roles: RoleSet::of(&[role]),
            name: name.as_bytes(),
            arch: SigArch::Riscv64,
        };
        objsig::verify(object, &store, &expect).is_ok()
    }

    /// The set of `roles`.
    fn set(roles: &[Role]) -> RoleSet
    {
        RoleSet::of(roles)
    }

    // Defect caught: a record whose attributes or signature the loader of one
    // of its roles would refuse (a wrong body hash, role set, name or
    // architecture), a role the set does not hold accepted, or a signed object
    // whose body is not the image it was given.
    #[test]
    fn a_signed_object_verifies_in_each_of_its_roles_with_the_image_as_its_body()
    {
        let root = scratch("roles");
        let signer = signer(&root.join("keys"), Arch::Riscv64);
        for role in Role::ALL
        {
            let name = if matches!(role, Role::Kernel | Role::Init)
            {
                "init"
            }
            else
            {
                "/services/x"
            };
            let object = signer.sign(b"\x7fELF image", set(&[role]), name).unwrap();
            assert!(verifies(&signer, &object, role, name), "{role:?}");
            assert_eq!(objsig::split(&object).unwrap().body(), b"\x7fELF image");
        }
        let both = signer
            .sign(
                b"\x7fELF image",
                set(&[Role::Driver, Role::BootModule]),
                "/services/drivers/x",
            )
            .unwrap();
        for role in Role::ALL
        {
            assert_eq!(
                verifies(&signer, &both, role, "/services/drivers/x"),
                matches!(role, Role::Driver | Role::BootModule),
                "{role:?}"
            );
        }
        // No record carries kernel or init beside another role.
        signer
            .sign(
                b"\x7fELF image",
                set(&[Role::Init, Role::BootModule]),
                "init",
            )
            .unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a second pack stacking a trailer on the first, which the
    // verifier refuses as a nested trailer, or re-signing an unchanged image
    // to new bytes.
    #[test]
    fn signing_a_signed_object_again_signs_its_body()
    {
        let root = scratch("again");
        let signer = signer(&root.join("keys"), Arch::Riscv64);
        let once = signer
            .sign(b"\x7fELF image", set(&[Role::Service]), "/services/x")
            .unwrap();
        assert_eq!(
            signer
                .sign(&once, set(&[Role::Service]), "/services/x")
                .unwrap(),
            once
        );
        let renamed = signer
            .sign(&once, set(&[Role::BootModule]), "/services/y")
            .unwrap();
        assert_eq!(objsig::split(&renamed).unwrap().body(), b"\x7fELF image");
        assert!(verifies(&signer, &renamed, Role::BootModule, "/services/y"));
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: an object signed under a name no loader can be given,
    // since a loader refuses a non-canonical name before it verifies, or a
    // name that names its file one of several ways.
    #[test]
    fn a_name_not_in_the_canonical_form_is_refused()
    {
        let root = scratch("names");
        let signer = signer(&root.join("keys"), Arch::Riscv64);
        for name in [
            "",
            "/services//x",
            "/services/x/",
            "services/x",
            "/services/./x",
            "x\0",
        ]
        {
            signer
                .sign(b"\x7fELF image", set(&[Role::Service]), name)
                .expect_err(name);
        }
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: an image ending in a damaged trailer signed whole, so
    // the damaged trailer becomes part of the signed body; an object an
    // earlier tree signed, whose footer carries another format version,
    // refused without naming the build that installs it again or the clean
    // that removes one no build installs.
    #[test]
    fn an_object_ending_in_a_malformed_trailer_is_refused()
    {
        let root = scratch("malformed");
        let signer = signer(&root.join("keys"), Arch::Riscv64);
        let good = signer
            .sign(b"\x7fELF image", set(&[Role::Service]), "/services/x")
            .unwrap();
        // The footer's version field: 8 bytes of magic end the footer, after
        // the 2-byte version; its record count lies before the version.
        let version = good.len() - 10;
        for earlier in [1, 3]
        {
            let mut object = good.clone();
            object[version] = earlier;
            let error = signer
                .sign(&object, set(&[Role::Service]), "/services/x")
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains("cargo xtask build"), "{error}");
            assert!(error.contains("cargo xtask clean"), "{error}");
        }
        let mut object = good;
        object[version - 2] = 0;
        let error = signer
            .sign(&object, set(&[Role::Service]), "/services/x")
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("malformed signature trailer"),
            "{error:#}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: an image written although its record does not verify
    // under the store the build embeds, so the image would not boot.
    #[test]
    fn a_signature_the_trust_store_does_not_accept_is_refused()
    {
        let root = scratch("untrusted");
        let other = root.join("other");
        identity::generate(&other, &mut counter(40)).unwrap();
        let mut replaced = config(&root.join("keys"));
        replaced.deployer_store = Some((other.join("trust.store"), StoreMode::Replace));
        let signer = Signer::new(&replaced, &work_tree(), Arch::Riscv64, &mut counter(1)).unwrap();
        signer
            .sign(b"\x7fELF image", set(&[Role::Service]), "/services/x")
            .unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a revoking store that does not revoke the signing key, or
    // that drops an anchor or lowers the floor, so the signing case's
    // revoked-signer boot would refuse nothing or refuse for another reason.
    #[test]
    fn the_store_revoking_the_signing_key_refuses_its_records_and_keeps_the_rest()
    {
        let root = scratch("revoking");
        let signer = signer(&root.join("keys"), Arch::Riscv64);
        let object = signer
            .sign(b"\x7fELF image", set(&[Role::Kernel]), "kernel")
            .unwrap();
        let revoking = signer.store_revoking_own_key().unwrap();
        let store = TrustStore::parse(&revoking).unwrap();
        let built = TrustStore::parse(signer.store()).unwrap();
        assert_eq!(store.revoked(), [signer.key_id()]);
        assert!(store.anchors().eq(built.anchors()));
        assert_eq!(store.security_floor(), built.security_floor());
        let expect = Expectation {
            roles: set(&[Role::Kernel]),
            name: b"kernel",
            arch: SigArch::Riscv64,
        };
        assert_eq!(
            objsig::verify(&object, &store, &expect).map(|_| ()),
            Err(objsig::Refusal::Failed(objsig::RecordFailure::Revoked))
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: an object whose combined trailer loses a record or
    // reorders them, or two objects of different bodies combined, so a record
    // signs bytes the object does not carry.
    #[test]
    fn prepended_records_come_first_over_the_shared_body()
    {
        let root = scratch("prepend");
        let ours = signer(&root.join("keys"), Arch::Riscv64);
        let theirs = Signer::new(
            &config(&root.join("other-keys")),
            &work_tree(),
            Arch::Riscv64,
            &mut counter(50),
        )
        .unwrap();
        let trusted = ours
            .sign(b"\x7fELF image", set(&[Role::Service]), "/services/x")
            .unwrap();
        let untrusted = theirs
            .sign(&trusted, set(&[Role::Service]), "/services/x")
            .unwrap();
        let both = prepend_records(&trusted, &untrusted).unwrap();
        let signed = objsig::split(&both).unwrap();
        assert_eq!(signed.body(), b"\x7fELF image");
        let signers: Vec<KeyId> = signed
            .records()
            .map(|record| record.signer_key_id)
            .collect();
        assert_eq!(signers, [theirs.key_id(), ours.key_id()]);
        assert!(verifies(&ours, &both, Role::Service, "/services/x"));
        let other = theirs
            .sign(b"\x7fELF other", set(&[Role::Service]), "/services/x")
            .unwrap();
        prepend_records(&trusted, &other).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    /// A sysroot in a fresh scratch directory holding `files`.
    fn sysroot_of(tag: &str, files: &[(&str, &[u8])]) -> (PathBuf, BuildContext)
    {
        let root = scratch(tag);
        let ctx = BuildContext {
            root: root.clone(),
            sysroot: root.join("sysroot"),
            target_dir: root.join("target"),
        };
        for (path, bytes) in files
        {
            let full = ctx.sysroot.join(path);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(&full, bytes).unwrap();
        }
        (root, ctx)
    }

    /// Each ELF image of the test sysroot of riscv64 under the init harness:
    /// its sysroot-relative path, its role set and its name.
    const SIGNED_IMAGES: [(&str, &[Role], &str); 9] = [
        ("boot/kernel", &[Role::Kernel], "kernel"),
        ("services/init", &[Role::Init], "init"),
        (
            "services/devmgr",
            &[Role::Service, Role::BootModule],
            "/services/devmgr",
        ),
        ("services/svcmgr", &[Role::Service], "/services/svcmgr"),
        (
            "services/fs/fatfs",
            &[Role::Service, Role::BootModule],
            "/services/fs/fatfs",
        ),
        (
            "services/drivers/virtio-blk",
            &[Role::Driver, Role::BootModule],
            "/services/drivers/virtio-blk",
        ),
        (
            "services/drivers/iommu-riscv",
            &[Role::Driver, Role::BootModule],
            "/services/drivers/iommu-riscv",
        ),
        ("programs/hello", &[Role::Program], "/programs/hello"),
        (
            "tests/programs/fixture",
            &[Role::Program],
            "/tests/programs/fixture",
        ),
    ];

    // Defect caught: an object left unsigned, signed under a name or a role
    // set its loader does not expect (a bundle entry without the boot-module
    // role, an object no list names with it, init under its path, ktest as
    // init in an image that does not boot it), a data file a list names left
    // unsigned, a file outside the signed trees given a trailer (the
    // installed bootloader among them), or an object signed both into an
    // `init` slot and as an entry, or a platform description table, which no
    // list names, signed in another role than the data role.
    #[test]
    fn the_sysroot_objects_are_signed_under_their_names_and_roles()
    {
        let arch = Arch::Riscv64;
        let images = SIGNED_IMAGES;
        let table = "/config/devmgr/platform/qemu-virt.platform";
        let listed = "/config/init/log-levels.conf";
        let data: Vec<&str> = [table, listed].into();
        // ELF files outside the signed trees, and a text file inside one.
        let outside = ["config/x", "boot/boot.efi", "esp/EFI/seraph/kernel"];
        let text = "services/init.conf";
        let mut files: Vec<(&str, &[u8])> = images
            .iter()
            .map(|(path, _, _)| (*path, b"\x7fELF image".as_slice()))
            .collect();
        files.push(("tests/ktest", b"\x7fELF ktest"));
        files.extend(
            outside
                .iter()
                .map(|path| (*path, b"\x7fELF outside".as_slice())),
        );
        files.push((text, b"vfsd = debug\n"));
        files.extend(
            data.iter()
                .map(|path| (&path[1..], b"data = 1\n".as_slice())),
        );
        let (root, ctx) = sysroot_of("sysroot", &files);
        testing::install_lists(&ctx);
        let signer = signer(&root.join("keys"), arch);

        let objects = images.len() + 1 + data.len();
        assert_eq!(
            sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap(),
            (objects, objects)
        );
        for (path, roles, name) in images
        {
            let object = fs::read(ctx.sysroot.join(path)).unwrap();
            let attrs = objsig::split(&object)
                .unwrap()
                .records()
                .next()
                .unwrap()
                .attrs;
            assert_eq!(attrs.roles, RoleSet::of(roles), "{path}");
            assert_eq!(attrs.name, name.as_bytes(), "{path}");
            for &role in roles
            {
                assert!(verifies(&signer, &object, role, name), "{path}");
            }
        }
        let ktest = fs::read(ctx.sysroot.join("tests/ktest")).unwrap();
        assert!(verifies(&signer, &ktest, Role::Service, "/tests/ktest"));
        assert!(!verifies(&signer, &ktest, Role::Init, "init"));
        for (install, role) in [(table, Role::Data), (listed, Role::Configuration)]
        {
            let object = fs::read(ctx.sysroot.join(&install[1..])).unwrap();
            let attrs = objsig::split(&object)
                .unwrap()
                .records()
                .next()
                .unwrap()
                .attrs;
            assert_eq!(attrs.roles, RoleSet::of(&[role]), "{install}");
            assert!(verifies(&signer, &object, role, install));
        }
        assert_eq!(fs::read(ctx.sysroot.join(text)).unwrap(), b"vfsd = debug\n");
        for path in outside
        {
            assert_eq!(
                fs::read(ctx.sysroot.join(path)).unwrap(),
                b"\x7fELF outside"
            );
        }
        // A second pack of an unchanged sysroot changes no file.
        assert_eq!(
            sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap(),
            (objects, 0)
        );
        // Under the ktest harness, ktest is signed init and nothing else
        // changes.
        assert_eq!(
            sign_sysroot(&ctx, &signer, arch, Harness::Ktest).unwrap(),
            (objects, 1)
        );
        let ktest = fs::read(ctx.sysroot.join("tests/ktest")).unwrap();
        assert!(verifies(&signer, &ktest, Role::Init, "init"));
        assert_eq!(objsig::split(&ktest).unwrap().body(), b"\x7fELF ktest");
        // A file a list names that the sysroot does not install is not
        // signed; the compose of a bundle that names it refuses it.
        fs::remove_file(ctx.sysroot.join(&listed[1..])).unwrap();
        assert_eq!(
            sign_sysroot(&ctx, &signer, arch, Harness::Ktest).unwrap(),
            (objects - 1, 0)
        );
        // An object both in an `init` slot and an entry of a list is refused.
        fs::write(
            ctx.sysroot.join("config/bundle/ktest.list"),
            "init /tests/ktest\n/services/init\n",
        )
        .unwrap();
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: the storage statement left unsigned, or signed in another
    // role or under another name than its install path, so vfsd's verified
    // read refuses it and the roles it names on a second disk are given to
    // none; or a statement the sysroot does not hold counted as signed.
    #[test]
    fn the_storage_statement_is_signed_in_the_configuration_role_under_its_path()
    {
        let arch = Arch::Riscv64;
        let install = storage_statement::PATH;
        let body = b"swap 5a9f0e11-2345-6789-abcd-ef0123456789\n".as_slice();
        let (root, ctx) = sysroot_of("statement", &[(&install[1..], body)]);
        testing::install_lists(&ctx);
        let signer = signer(&root.join("keys"), arch);

        assert_eq!(
            sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap(),
            (1, 1)
        );
        let object = fs::read(ctx.sysroot.join(&install[1..])).unwrap();
        let split = objsig::split(&object).unwrap();
        assert_eq!(split.body(), body);
        let attrs = split.records().next().unwrap().attrs;
        assert_eq!(attrs.roles, RoleSet::of(&[Role::Configuration]));
        assert!(verifies(&signer, &object, Role::Configuration, install));
        assert!(!verifies(&signer, &object, Role::Data, install));
        // With no statement, nothing is signed in its place.
        fs::remove_file(ctx.sysroot.join(&install[1..])).unwrap();
        assert_eq!(
            sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap(),
            (0, 0)
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a file under a data tree left unsigned, signed in an
    // image role, or under a name other than its install path, so procmgr's
    // verified read refuses the file it is meant to hand its reader; or a
    // file outside every data tree given a trailer.
    #[test]
    fn a_file_under_a_data_tree_is_signed_in_the_data_role_under_its_install_path()
    {
        let arch = Arch::Riscv64;
        let fixture = "data/svctest/signed/verified.dat";
        let nested = "data/svctest/signed/sub/nested.dat";
        let plain = "data/svctest/large.bin";
        let (root, ctx) = sysroot_of(
            "data-trees",
            &[
                (fixture, b"body\n".as_slice()),
                (nested, b"\x7fELF-looking data".as_slice()),
                (plain, b"plain".as_slice()),
            ],
        );
        testing::install_lists(&ctx);
        let signer = signer(&root.join("keys"), arch);
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        for path in [fixture, nested]
        {
            let name = format!("/{path}");
            let object = fs::read(ctx.sysroot.join(path)).unwrap();
            let attrs = objsig::split(&object)
                .unwrap()
                .records()
                .next()
                .unwrap()
                .attrs;
            assert_eq!(attrs.roles, RoleSet::of(&[Role::Data]), "{path}");
            assert!(verifies(&signer, &object, Role::Data, &name), "{path}");
        }
        assert_eq!(fs::read(ctx.sysroot.join(plain)).unwrap(), b"plain");
        let _ = fs::remove_dir_all(&root);
    }

    /// The index body of `files`, each a name and its body, in order.
    fn index_of(files: &[(&str, &[u8])]) -> Vec<u8>
    {
        files
            .iter()
            .flat_map(|(name, body)| {
                let line = objsig::index::body_digest(body).iter().fold(
                    format!("{name} "),
                    |mut line, byte| {
                        use std::fmt::Write as _;
                        let _ = write!(line, "{byte:02x}");
                        line
                    },
                );
                format!("{line}\n").into_bytes()
            })
            .collect()
    }

    // Defect caught: a configuration file left unsigned or signed outside the
    // configuration role, under a name other than its install path; an index
    // missing, unsigned, naming a file the directory lacks or omitting one it
    // holds, holding a digest other than its file's body's (the signed file's,
    // or a stale one after an edit), or rewritten by a pack of an unchanged
    // directory.
    #[test]
    fn a_configuration_directory_is_signed_with_an_index_of_its_files()
    {
        let arch = Arch::Riscv64;
        let services = "config/svcmgr/services";
        let classes = "config/devmgr/classes";
        let (root, ctx) = sysroot_of(
            "config-trees",
            &[
                (
                    "config/svcmgr/services/timed.svc",
                    b"binary = x\n".as_slice(),
                ),
                (
                    "config/svcmgr/services/crashd.svc",
                    b"binary = y\n".as_slice(),
                ),
                (
                    "config/devmgr/classes/rtc.class",
                    b"class = rtc\n".as_slice(),
                ),
                // A stale index of an earlier pack, which the pack replaces.
                ("config/svcmgr/services/index", b"gone.svc\n".as_slice()),
            ],
        );
        testing::install_lists(&ctx);
        let signer = signer(&root.join("keys"), arch);
        let (total, _) = sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        let config = RoleSet::of(&[Role::Configuration]);
        let read = |relative: String| {
            let object = fs::read(ctx.sysroot.join(&relative)).unwrap();
            let attrs = objsig::split(&object)
                .unwrap()
                .records()
                .next()
                .unwrap()
                .attrs;
            assert_eq!(attrs.roles, config, "{relative}");
            assert!(
                verifies(
                    &signer,
                    &object,
                    Role::Configuration,
                    &format!("/{relative}")
                ),
                "{relative}"
            );
            assert!(!verifies(
                &signer,
                &object,
                Role::Data,
                &format!("/{relative}")
            ));
            objsig::split(&object).unwrap().body().to_vec()
        };
        for file in ["timed.svc", "crashd.svc"]
        {
            read(format!("{services}/{file}"));
        }
        read(format!("{classes}/rtc.class"));
        assert_eq!(
            read(format!("{services}/index")),
            index_of(&[
                ("crashd.svc", b"binary = y\n"),
                ("timed.svc", b"binary = x\n")
            ])
        );
        assert_eq!(
            read(format!("{classes}/index")),
            index_of(&[("rtc.class", b"class = rtc\n")])
        );
        // A second pack of an unchanged sysroot changes no file.
        assert_eq!(
            sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap(),
            (total, 0)
        );
        // A file added, one removed, and one edited are in the next pack's
        // index.
        fs::write(ctx.sysroot.join(services).join("oomd.svc"), b"binary = z\n").unwrap();
        fs::remove_file(ctx.sysroot.join(services).join("timed.svc")).unwrap();
        fs::write(
            ctx.sysroot.join(services).join("crashd.svc"),
            b"binary = w\n",
        )
        .unwrap();
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        assert_eq!(
            read(format!("{services}/index")),
            index_of(&[
                ("crashd.svc", b"binary = w\n"),
                ("oomd.svc", b"binary = z\n")
            ])
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a file a consumer would pass over (another suffix, a
    // subdirectory) packed silently into a configuration directory.
    #[test]
    fn a_configuration_directory_holding_another_kind_of_entry_is_refused()
    {
        let arch = Arch::Riscv64;
        let (root, ctx) = sysroot_of(
            "config-strays",
            &[
                (
                    "config/svcmgr/services/timed.svc",
                    b"binary = x\n".as_slice(),
                ),
                (
                    "config/devmgr/classes/rtc.class",
                    b"class = rtc\n".as_slice(),
                ),
            ],
        );
        testing::install_lists(&ctx);
        let signer = signer(&root.join("keys"), arch);
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap();
        let services = ctx.sysroot.join("config/svcmgr/services");
        fs::write(services.join("notes.txt"), b"x").unwrap();
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap_err();
        fs::remove_file(services.join("notes.txt")).unwrap();
        fs::create_dir(ctx.sysroot.join("config/devmgr/classes/sub.class")).unwrap();
        sign_sysroot(&ctx, &signer, arch, Harness::Init).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a signer whose store trusts its key for some roles
    // accepted, so the first configuration file of a pack fails deep in the
    // signing, or a key refused for a store that does not trust it at all,
    // which the signing check names.
    #[test]
    fn a_key_the_store_trusts_for_some_roles_alone_is_refused()
    {
        let arch = Arch::Riscv64;
        let dir = scratch("missing-roles");
        let full = signer(&dir.join("full"), arch);
        let key = full.identity.public_key();
        let cert = full.identity.certificate();
        assert_eq!(missing_roles(full.store(), key, cert).unwrap(), Vec::new());
        // Seeds other than `signer`'s, so another root and key.
        let other = Signer::new(
            &config(&dir.join("other")),
            &work_tree(),
            arch,
            &mut counter(9),
        )
        .unwrap();
        let all_but: Vec<Role> = Role::ALL
            .into_iter()
            .filter(|&role| role != Role::Configuration)
            .collect();
        let narrowed = other
            .store_trusting(&[(&full, RoleSet::of(&all_but))])
            .unwrap();
        assert_eq!(
            missing_roles(&narrowed, key, cert).unwrap(),
            vec![Role::Configuration]
        );
        // A store with no anchor of the key's issuer leaves it to the check.
        assert_eq!(missing_roles(other.store(), key, cert).unwrap(), Vec::new());
        // Signer::new refuses the narrowed store as a deployer's replacing one.
        let store = dir.join("narrowed.store");
        fs::write(&store, &narrowed).unwrap();
        let mut config = config(&dir.join("full"));
        config.deployer_store = Some((store, StoreMode::Replace));
        let refused = Signer::new(&config, &work_tree(), arch, &mut counter(1));
        assert!(
            refused.is_err_and(|e| format!("{e:#}").contains("Configuration")),
            "a narrowed store refused naming the role"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The configuration of the variables `vars` sets.
    fn config_of(vars: &[(&str, &str)]) -> Result<Config>
    {
        let vars: BTreeMap<String, OsString> = vars
            .iter()
            .map(|(name, value)| ((*name).to_owned(), OsString::from(value)))
            .collect();
        Config::from_vars(&|name| vars.get(name).cloned())
    }

    // Defect caught: an identity looked for anywhere but the user's data
    // directory when no directory is named, or a deployer's store that
    // replaces the builder's root when no mode asked for it.
    #[test]
    fn the_configuration_defaults_to_the_user_data_directory_and_a_merged_store()
    {
        let home = config_of(&[("HOME", "/home/u"), ("SERAPH_TRUST_STORE", "/s")]).unwrap();
        assert_eq!(
            home.dir,
            Path::new("/home/u/.local/share/seraph/signing/ed25519-ml-dsa-65-roles-1-9")
        );
        assert_eq!(
            home.deployer_store,
            Some((PathBuf::from("/s"), StoreMode::Merge))
        );
        let xdg = config_of(&[("HOME", "/home/u"), ("XDG_DATA_HOME", "/x")]).unwrap();
        assert_eq!(
            xdg.dir,
            Path::new("/x/seraph/signing/ed25519-ml-dsa-65-roles-1-9")
        );
        let named = config_of(&[("HOME", "/home/u"), ("SERAPH_SIGNING_DIR", "/k")]).unwrap();
        assert_eq!(named.dir, Path::new("/k"));
        assert_eq!(named.deployer_store, None);
        config_of(&[("HOME", "relative")]).unwrap_err();
    }

    // Defect caught: a mistyped or orphaned store mode ignored, so the image
    // trusts other roots than the deployer asked for.
    #[test]
    fn a_store_mode_naming_no_mode_or_without_a_store_is_refused()
    {
        let replace = [
            ("SERAPH_SIGNING_DIR", "/k"),
            ("SERAPH_TRUST_STORE", "/s"),
            ("SERAPH_TRUST_STORE_MODE", "replace"),
        ];
        assert_eq!(
            config_of(&replace).unwrap().deployer_store,
            Some((PathBuf::from("/s"), StoreMode::Replace))
        );
        config_of(&[
            ("SERAPH_SIGNING_DIR", "/k"),
            ("SERAPH_TRUST_STORE", "/s"),
            ("SERAPH_TRUST_STORE_MODE", "Replace"),
        ])
        .unwrap_err();
        config_of(&[
            ("SERAPH_SIGNING_DIR", "/k"),
            ("SERAPH_TRUST_STORE_MODE", "merge"),
        ])
        .unwrap_err();
    }

    /// An image of `store` embedded between other bytes, as the bootloader
    /// build lays it out.
    fn bootloader_image(store: &[u8]) -> Vec<u8>
    {
        let mut image = b"MZ code".to_vec();
        image.extend_from_slice(&objsig::embed::MARKER);
        image.extend_from_slice(&u32::try_from(store.len()).unwrap().to_le_bytes());
        image.extend_from_slice(store);
        image.extend_from_slice(b"more code");
        image
    }

    // Defect caught: a pack that signs under a store the installed bootloader
    // does not hold (a store changed since the bootloader was built, a missing
    // bootloader, or one built without a store), so the boot of its ESP copies
    // refuses every object; or a compose that verifies under another store
    // than the installed bootloader's.
    #[test]
    fn a_pack_signs_only_under_the_store_the_installed_bootloader_embeds()
    {
        let root = scratch("installed-store");
        let ctx = BuildContext {
            root: root.clone(),
            sysroot: root.join("sysroot"),
            target_dir: root.join("target"),
        };
        let ours = signer(&root.join("keys"), Arch::Riscv64);
        let theirs = Signer::new(
            &config(&root.join("other-keys")),
            &work_tree(),
            Arch::Riscv64,
            &mut counter(50),
        )
        .unwrap();
        assert_ne!(ours.store(), theirs.store());
        let image = ctx.installed_bootloader();
        fs::create_dir_all(image.parent().unwrap()).unwrap();

        fs::write(&image, bootloader_image(ours.store())).unwrap();
        check_installed_store(&image, ours.store()).unwrap();
        assert_eq!(installed_store(&ctx).unwrap(), ours.store());

        fs::write(&image, bootloader_image(theirs.store())).unwrap();
        let refusal = format!(
            "{:#}",
            check_installed_store(&image, ours.store()).unwrap_err()
        );
        assert!(refusal.contains("boot.efi"), "{refusal}");
        assert!(refusal.contains("another trust store"), "{refusal}");
        assert_eq!(installed_store(&ctx).unwrap(), theirs.store());

        fs::write(&image, b"an image without a store").unwrap();
        let refusal = format!(
            "{:#}",
            check_installed_store(&image, ours.store()).unwrap_err()
        );
        assert!(refusal.contains("NoMarker"), "{refusal}");
        installed_store(&ctx).unwrap_err();

        fs::remove_file(&image).unwrap();
        let refusal = format!(
            "{:#}",
            check_installed_store(&image, ours.store()).unwrap_err()
        );
        assert!(refusal.contains("cargo xtask build"), "{refusal}");
        installed_store(&ctx).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: an unchanged store rewritten on every build, which makes
    // a build that tracks the file rebuild the bootloader each time.
    #[test]
    fn writing_an_unchanged_boot_store_leaves_the_file_untouched()
    {
        let root = scratch("boot-store");
        let ctx = BuildContext {
            root: root.clone(),
            sysroot: root.join("sysroot"),
            target_dir: root.join("target"),
        };
        let signer = signer(&root.join("keys"), Arch::Riscv64);
        let path = write_boot_store(&ctx, &signer).unwrap();
        assert_eq!(fs::read(&path).unwrap(), signer.store());
        let old = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        write_boot_store(&ctx, &signer).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), old);
        let _ = fs::remove_dir_all(&root);
    }
}
