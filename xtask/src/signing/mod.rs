// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/signing/mod.rs

//! Signing of the objects a build packs, and the trust store the bootloader
//! is built with (docs/signing.md § Signing).
//!
//! Every image is signed as it is packed: [`crate::disk::create_disk_image`]
//! signs the kernel and every ELF image under `services/`, `programs/` and
//! `tests/` in the sysroot ([`sign_sysroot`]), and [`crate::bundle`] signs
//! each ELF entry of the bundle it composes. A signed object is its body and a
//! trailer of one record ([`Signer::sign`]), which [`objsig::verify`] accepts
//! under the build's trust store before it is written, with the kind, name and
//! architecture the bootloader and procmgr expect of it.
//!
//! - [`identity`]: the signing key, its certificate and the anchors it
//!   contributes, in a directory outside the work tree, generated on first
//!   use; an external signer in place of the key.
//! - [`store`]: the trust store, from the identity's anchors and a deployer's
//!   store.

mod identity;
mod store;

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use objsig::attrs::Attributes;
use objsig::{Expectation, Kind, KindSet, ParseError, RecordSpec, TrustStore};

use crate::arch::Arch;
use crate::context::Context as BuildContext;
use crate::error::{Context, Result, bail, err};

pub use identity::{Identity, os_random};
pub use store::StoreMode;

/// The security version every record of a build of this tree carries, and the
/// lowest floor of the trust store it builds (docs/signing.md § Signing).
/// Raised by a security fix that MUST make the images of older trees
/// unbootable.
pub const SECURITY_VERSION: u32 = 1;

/// The directory of the signing identity; by default `seraph/signing` in the
/// user's data directory ([`default_dir`]).
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

/// The first four bytes of an ELF image.
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";

/// The sysroot trees whose ELF images [`sign_sysroot`] signs, each installed
/// on the root filesystem at its sysroot path.
const SIGNED_TREES: &[&str] = &["services", "programs", "tests"];

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
            Some(value) => Some(
                value
                    .to_str()
                    .and_then(StoreMode::parse)
                    .with_context(|| {
                        format!(
                            "{ENV_TRUST_STORE_MODE}={} names no mode: merge or replace",
                            value.to_string_lossy()
                        )
                    })?,
            ),
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
/// returns: `seraph/signing` in `XDG_DATA_HOME`, in `.local/share` of
/// `HOME`, or in `LOCALAPPDATA`, the first of them set to an absolute path.
fn default_dir(var: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf>
{
    let absolute = |name: &str| var(name).map(PathBuf::from).filter(|path| path.is_absolute());
    absolute("XDG_DATA_HOME")
        .or_else(|| absolute("HOME").map(|home| home.join(".local").join("share")))
        .or_else(|| absolute("LOCALAPPDATA"))
        .map(|data| data.join("seraph").join("signing"))
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
    /// The signer of a build of `arch` in `ctx`, configured by the
    /// environment ([`Config::from_env`]), generating a local identity on
    /// first use.
    ///
    /// # Errors
    ///
    /// The errors of [`Config::from_env`] and [`Self::new`].
    pub fn open(ctx: &BuildContext, arch: Arch) -> Result<Self>
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
    /// deployer's store cannot be read.
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
            deployer.as_ref().map(|(bytes, mode)| (bytes.as_slice(), *mode)),
            SECURITY_VERSION,
        )?;
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

    /// `object` signed as `kind` under `name`: its body, the object less
    /// any trailer it carries, followed by a trailer of one record of the
    /// signing key. The result is verified under the build's store, with
    /// `kind`, `name` and the build's architecture expected, before it is
    /// returned. Signing is deterministic, so an object already signed so
    /// comes back unchanged.
    ///
    /// # Errors
    ///
    /// When `object` ends in a malformed trailer or its body in the trailer
    /// magic; when `name` is empty or too long for the attributes; when the
    /// signature cannot be made; when the signed object does not verify
    /// (a faulty external signer, or a store that does not trust the key).
    pub fn sign(&self, object: &[u8], kind: Kind, name: &str) -> Result<Vec<u8>>
    {
        let body = body_of(object)?;
        let refused = |e| err!("signing {name}: {e:?}");
        let attrs = Attributes {
            body_len: u64::try_from(body.len()).context("an object longer than u64")?,
            security_version: SECURITY_VERSION,
            kind,
            arch: self.arch,
            body_hash: crypto::sha512(body),
            name: name.as_bytes(),
        };
        let mut signed = vec![0u8; attrs.encoded_len().map_err(refused)?];
        attrs.encode(&mut signed).map_err(refused)?;
        let record = RecordSpec {
            signer_key_id: objsig::key_id(self.identity.public_key()),
            attrs,
            certificate: self.identity.certificate(),
            signature: self.identity.sign(&signed)?,
        };
        let trailer = objsig::trailer_len(&[record]).map_err(refused)?;
        let mut out = body.to_vec();
        out.resize(
            body.len().checked_add(trailer).context("a signed object longer than usize")?,
            0,
        );
        let (_, tail) = out.split_at_mut(body.len());
        objsig::encode_trailer(body, &[record], tail).map_err(refused)?;
        self.check(&out, kind, name)?;
        Ok(out)
    }

    /// Verify the signed `object` as the loader of a `kind` named `name`
    /// will.
    fn check(&self, object: &[u8], kind: Kind, name: &str) -> Result<()>
    {
        let store = TrustStore::parse(&self.store)
            .map_err(|e| err!("the build's trust store does not parse ({e:?})"))?;
        let expect = Expectation {
            kinds: KindSet::of(&[kind]),
            name: name.as_bytes(),
            arch: self.arch,
        };
        objsig::verify(object, &store, &expect)
            .map(|_| ())
            .map_err(|refusal| {
                err!(
                    "{name}, signed as {kind:?}, does not verify under the build's trust store \
                     ({refusal:?})"
                )
            })
    }

    /// Sign the file at `path` in place as `kind` under `name`; returns
    /// whether its bytes changed.
    ///
    /// # Errors
    ///
    /// On an I/O failure and the errors of [`Self::sign`].
    pub fn sign_file(&self, path: &Path, kind: Kind, name: &str) -> Result<bool>
    {
        let object = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let signed = self
            .sign(&object, kind, name)
            .with_context(|| format!("signing {}", path.display()))?;
        if signed == object
        {
            return Ok(false);
        }
        fs::write(path, &signed).with_context(|| format!("writing {}", path.display()))?;
        Ok(true)
    }
}

/// The body of `object`: the object less its trailer when it ends in one,
/// the whole object otherwise.
///
/// # Errors
///
/// When `object` ends in the trailer magic but does not parse.
pub fn body_of(object: &[u8]) -> Result<&[u8]>
{
    match objsig::split(object)
    {
        Ok(signed) => Ok(signed.body()),
        Err(ParseError::TooShort | ParseError::Magic) => Ok(object),
        Err(e) => bail!("the object ends in a malformed signature trailer ({e:?})"),
    }
}

/// The trailer format's architecture of `arch`.
fn objsig_arch(arch: Arch) -> objsig::Arch
{
    match arch
    {
        Arch::X86_64 => objsig::Arch::X86_64,
        Arch::Riscv64 => objsig::Arch::Riscv64,
    }
}

/// The kind of the image installed at `path`, relative to the root of the
/// root filesystem: a driver under a `drivers/` directory, a program under a
/// `programs/` directory, and a service otherwise (docs/signing.md
/// § Signing).
fn image_kind(path: &Path) -> Kind
{
    let mut directories = path.parent().into_iter().flat_map(Path::components);
    let names: Vec<_> = directories.by_ref().map(|c| c.as_os_str()).collect();
    if names.iter().any(|name| *name == "drivers")
    {
        Kind::Driver
    }
    else if names.iter().any(|name| *name == "programs")
    {
        Kind::Program
    }
    else
    {
        Kind::Service
    }
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

/// Sign the kernel, as kernel `kernel`, and every ELF image under
/// [`SIGNED_TREES`] of the sysroot, under its install path and its
/// [`image_kind`]; returns how many objects were signed and how many of
/// them changed.
///
/// # Errors
///
/// On an I/O failure and the errors of [`Signer::sign_file`].
pub fn sign_sysroot(ctx: &BuildContext, signer: &Signer) -> Result<(usize, usize)>
{
    let mut signed = 0usize;
    let mut changed = 0usize;
    let mut count = |was_changed: bool| {
        signed = signed.saturating_add(1);
        changed = changed.saturating_add(usize::from(was_changed));
    };
    let kernel = ctx.sysroot_efi_seraph().join("kernel");
    if kernel.is_file()
    {
        count(signer.sign_file(&kernel, Kind::Kernel, "kernel")?);
    }
    for tree in SIGNED_TREES
    {
        for relative in elf_images(&ctx.sysroot, Path::new(tree))?
        {
            let name = install_name(&relative)?;
            count(signer.sign_file(&ctx.sysroot.join(&relative), image_kind(&relative), &name)?);
        }
    }
    Ok((signed, changed))
}

/// The regular files under `root/dir` whose bytes begin with the ELF
/// magic, as paths relative to `root`, sorted; none when `dir` is absent.
/// A symbolic link is not followed.
fn elf_images(root: &Path, dir: &Path) -> Result<Vec<PathBuf>>
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
            else if kind.is_file() && starts_with_elf_magic(&entry.path())?
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
/// leaving the file untouched when it already holds it, so the bootloader's
/// build, which tracks the file, rebuilds only when the store changes;
/// returns its path.
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
