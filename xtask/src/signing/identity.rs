// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/signing/identity.rs

//! The signing identity: the key that signs a build's objects, its
//! certificate, and the anchors it contributes to the trust store, held in a
//! directory outside the work tree (docs/signing.md § Signing).
//!
//! The directory holds:
//!
//! - `signer.seed`: the signing key's 64-byte secret, the Ed25519 seed and the
//!   ML-DSA-65 seed of its composite key, absent when an external signer holds
//!   the key;
//! - `signer.cert`: the signing key's 5,409-byte certificate, or, for a signing
//!   key that is itself a root, `signer.pub`, its 1,984-byte composite public
//!   key;
//! - `trust.store`: a trust store of the anchors the identity contributes.
//!
//! An absent or empty directory gets a local identity on first use
//! ([`generate`]): a root generated on the build machine, whose seed certifies
//! the signing key and is then discarded, and a store listing that root with
//! `LOCAL`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use objsig::composite::{self, PUBLIC_KEY_LEN, SEED_LEN, SIGNATURE_LEN};
use objsig::store::LABEL_LEN;
use objsig::{
    AnchorSpec, Certificate, CertificateBody, PublicKey, RoleSet, Signature, TrustStore, Usage,
    cert, key_id,
};

use crate::error::{Context, Result, bail, ensure, err};

/// The secret seed of the signing key.
pub const SEED_FILE: &str = "signer.seed";

/// The signing key's certificate.
pub const CERT_FILE: &str = "signer.cert";

/// The public key of a signing key that is a root and carries no certificate.
pub const PUB_FILE: &str = "signer.pub";

/// The trust store of the anchors the identity contributes.
pub const STORE_FILE: &str = "trust.store";

/// The label of a generated local root's anchor.
const LOCAL_LABEL: &str = "local build root";

const _: () = assert!(
    LOCAL_LABEL.len() <= LABEL_LEN,
    "an anchor label fits its field"
);

/// The secret of a composite key: the Ed25519 seed, then the ML-DSA-65
/// seed, 32 bytes each; overwritten when dropped.
pub struct Seed([u8; SEED_LEN]);

impl Seed
{
    /// A secret of two seeds `fill` draws, the Ed25519 seed first, each
    /// drawn on its own so neither half's key is derived from the other's.
    pub fn drawn(fill: &mut dyn FnMut(&mut [u8; 32])) -> Self
    {
        let mut seed = Self([0; SEED_LEN]);
        for half in seed.0.as_chunks_mut::<32>().0
        {
            fill(half);
        }
        seed
    }

    /// The secret's composite public key.
    fn public_key(&self) -> PublicKey
    {
        composite::public_key(&self.0)
    }

    /// The composite signature of `message`.
    fn sign(&self, message: &[u8]) -> Result<Signature>
    {
        composite::sign(&self.0, message).map_err(|e| err!("signing ({e:?})"))
    }
}

impl Drop for Seed
{
    fn drop(&mut self)
    {
        self.0.fill(0);
        // Keeps the overwrite of memory about to be freed from being elided.
        core::hint::black_box(&self.0);
    }
}

/// Fill `seed` from the host operating system's random source.
pub fn os_random(seed: &mut [u8; 32])
{
    use std::random::Rng as _;
    std::random::SystemRng.fill_bytes(seed);
}

/// What makes a signing key's signatures.
enum KeySource
{
    /// The seed, signed with in this process.
    Seed(Seed),
    /// A program that reads the signed bytes on its standard input and
    /// writes the composite signature to its standard output.
    External(PathBuf),
}

/// A loaded signing identity.
pub struct Identity
{
    key: KeySource,
    public: Box<PublicKey>,
    certificate: Option<Box<[u8; cert::LEN]>>,
    store: Vec<u8>,
}

impl std::fmt::Debug for Identity
{
    /// The signing key's public key and where its signatures come from; never
    /// the seed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        let source = match &self.key
        {
            KeySource::Seed(_) => "seed".to_owned(),
            KeySource::External(program) => program.display().to_string(),
        };
        f.debug_struct("Identity")
            .field("key_id", &super::store::hex(&objsig::key_id(&self.public)))
            .field("signer", &source)
            .finish_non_exhaustive()
    }
}

impl Identity
{
    /// Load the identity in `dir`, generating a local one with seeds from
    /// `fill` when `dir` is absent or empty and no external signer is named.
    /// With `signer`, the key is the program it names and no seed is read.
    ///
    /// # Errors
    ///
    /// When `dir` or the seed file lies inside `work_tree`; when `signer`
    /// is named and `dir` holds no identity; when a file is missing, has the
    /// wrong length, or does not parse; when the seed's public key is not the
    /// certificate's subject or `signer.pub`; on an I/O failure.
    pub fn load(
        dir: &Path,
        signer: Option<&Path>,
        work_tree: &Path,
        fill: &mut dyn FnMut(&mut [u8; 32]),
    ) -> Result<Self>
    {
        refuse_inside(dir, work_tree)?;
        if is_absent_or_empty(dir)?
        {
            if let Some(program) = signer
            {
                bail!(
                    "{} holds no signing identity, and the external signer {} needs one: its \
                     {CERT_FILE} (or {PUB_FILE}) and {STORE_FILE}",
                    dir.display(),
                    program.display()
                );
            }
            generate(dir, fill)?;
        }
        let certificate = read_optional(&dir.join(CERT_FILE))?
            .map(|bytes| parse_certificate(&bytes))
            .transpose()
            .with_context(|| format!("reading {}", dir.join(CERT_FILE).display()))
            .with_context(|| format_hint(dir))?;
        let public = match &certificate
        {
            Some(bytes) => Box::new(
                *Certificate::parse(bytes)
                    .map_err(|e| err!("not a certificate ({e:?})"))?
                    .body
                    .subject_key,
            ),
            None => read_exact::<PUBLIC_KEY_LEN>(&dir.join(PUB_FILE))
                .with_context(|| {
                    format!("{} has neither {CERT_FILE} nor {PUB_FILE}", dir.display())
                })
                .with_context(|| format_hint(dir))?,
        };
        let store = fs::read(dir.join(STORE_FILE))
            .with_context(|| format!("reading {}", dir.join(STORE_FILE).display()))?;
        TrustStore::parse(&store)
            .map_err(|e| {
                err!(
                    "{}: not a trust store ({e:?})",
                    dir.join(STORE_FILE).display()
                )
            })
            .with_context(|| format_hint(dir))?;
        let key = match signer
        {
            Some(program) => KeySource::External(program.to_path_buf()),
            None => KeySource::Seed(load_seed(dir, work_tree, &public)?),
        };
        Ok(Self {
            key,
            public,
            certificate,
            store,
        })
    }

    /// The signing key's public key.
    pub fn public_key(&self) -> &PublicKey
    {
        &self.public
    }

    /// The signing key's encoded certificate; `None` when the key is a root.
    pub fn certificate(&self) -> Option<&[u8; cert::LEN]>
    {
        self.certificate.as_deref()
    }

    /// The encoded trust store of the anchors the identity contributes.
    pub fn store(&self) -> &[u8]
    {
        &self.store
    }

    /// The signing key's signature of `message`. The caller verifies it.
    ///
    /// # Errors
    ///
    /// When the external signer cannot be run, exits unsuccessfully, or
    /// writes anything but a composite signature's length.
    pub fn sign(&self, message: &[u8]) -> Result<Box<Signature>>
    {
        match &self.key
        {
            KeySource::Seed(seed) => seed.sign(message).map(Box::new),
            KeySource::External(program) => sign_external(program, message),
        }
    }
}

/// What a failure to read the identity in `dir` adds: an identity of an
/// earlier signature format does not load.
fn format_hint(dir: &Path) -> String
{
    format!(
        "{} does not hold a signing identity of the composite signature format \
         (Ed25519 and ML-DSA-65, docs/signing.md § Signing); an identity of an earlier \
         format does not load: remove the directory to have a local one generated, or provide \
         one of this format",
        dir.display()
    )
}

/// The seed in `dir`, which is the secret key of `public`.
///
/// # Errors
///
/// When the seed file lies inside `work_tree`, cannot be read, does not hold
/// 64 bytes, or is not the secret key of `public`.
fn load_seed(dir: &Path, work_tree: &Path, public: &PublicKey) -> Result<Seed>
{
    let path = dir.join(SEED_FILE);
    refuse_inside(&path, work_tree)?;
    let seed = Seed(*read_exact::<SEED_LEN>(&path).with_context(|| format_hint(dir))?);
    ensure!(
        seed.public_key() == *public,
        "{} is not the secret key of the signing key {CERT_FILE} or {PUB_FILE} names",
        path.display()
    );
    Ok(seed)
}

/// Run the external signer `program` on `message`.
fn sign_external(program: &Path, message: &[u8]) -> Result<Box<Signature>>
{
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("running the external signer {}", program.display()))?;
    // The signer reads the whole message (the signed attributes, at most
    // 64 KiB) before it writes the signature, so writing all of one before
    // reading the other cannot fill both pipes.
    let mut stdin = child
        .stdin
        .take()
        .context("the external signer's standard input")?;
    let written = stdin.write_all(message);
    drop(stdin);
    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for the external signer {}", program.display()))?;
    written.with_context(|| format!("writing to the external signer {}", program.display()))?;
    ensure!(
        output.status.success(),
        "the external signer {} failed ({})",
        program.display(),
        output.status
    );
    Box::<Signature>::try_from(output.stdout.into_boxed_slice()).map_err(|bytes| {
        err!(
            "the external signer {} wrote {} bytes, not a {SIGNATURE_LEN}-byte composite signature",
            program.display(),
            bytes.len()
        )
    })
}

/// Fail when the canonical form of `path` lies inside the canonical
/// `work_tree`: no key file enters the tree, `target/` included.
///
/// # Errors
///
/// When it does, or when `work_tree` cannot be resolved.
pub fn refuse_inside(path: &Path, work_tree: &Path) -> Result<()>
{
    let tree = fs::canonicalize(work_tree)
        .with_context(|| format!("resolving the work tree {}", work_tree.display()))?;
    let resolved = canonical_prefix(path)?;
    ensure!(
        !resolved.starts_with(&tree),
        "{} lies inside the work tree {}: no signing key enters it (docs/signing.md \
         § Signing); set SERAPH_SIGNING_DIR to a directory outside it",
        resolved.display(),
        tree.display()
    );
    Ok(())
}

/// `path` made absolute, with its longest existing prefix canonicalized and
/// the rest appended, so a path not yet created resolves through the
/// symbolic links of the directories above it.
fn canonical_prefix(path: &Path) -> Result<PathBuf>
{
    let absolute =
        std::path::absolute(path).with_context(|| format!("resolving {}", path.display()))?;
    let mut rest = Vec::new();
    let mut existing = absolute.as_path();
    loop
    {
        if let Ok(canonical) = fs::canonicalize(existing)
        {
            return Ok(rest
                .iter()
                .rev()
                .fold(canonical, |dir, part| dir.join(part)));
        }
        let (Some(parent), Some(name)) = (existing.parent(), existing.file_name())
        else
        {
            return Ok(absolute);
        };
        rest.push(name.to_os_string());
        existing = parent;
    }
}

/// Whether `dir` does not exist or holds no entry.
fn is_absent_or_empty(dir: &Path) -> Result<bool>
{
    match fs::read_dir(dir)
    {
        Ok(mut entries) => Ok(entries.next().is_none()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e).with_context(|| format!("reading {}", dir.display())),
    }
}

/// Generate a local identity in `dir`, which is absent or empty, with seeds
/// from `fill`.
///
/// The files are written in a new directory beside `dir` and moved into
/// place by one rename, so several builds that start at once end with one
/// identity: a build whose rename finds `dir` filled by another discards
/// its own.
///
/// # Errors
///
/// On an I/O failure other than losing that race.
pub fn generate(dir: &Path, fill: &mut dyn FnMut(&mut [u8; 32])) -> Result<()>
{
    let files = local_identity(fill)?;
    let parent = dir
        .parent()
        .with_context(|| format!("{} has no parent directory", dir.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let name = dir
        .file_name()
        .with_context(|| format!("{} names no directory", dir.display()))?;
    let staging = parent.join(format!(
        ".{}.new-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos())
    ));
    let written = write_identity(&staging, &files).and_then(|()| place(&staging, dir));
    if staging.exists()
    {
        let _ = fs::remove_dir_all(&staging);
    }
    written
}

/// The files of a local identity: the seed, the certificate and the store.
struct LocalFiles
{
    seed: Seed,
    certificate: Box<[u8; cert::LEN]>,
    store: Vec<u8>,
}

/// A local root and a signing key it certifies, from two seeds of `fill`.
fn local_identity(fill: &mut dyn FnMut(&mut [u8; 32])) -> Result<LocalFiles>
{
    let root = Seed::drawn(fill);
    let seed = Seed::drawn(fill);
    let root_key = root.public_key();
    let subject_key = seed.public_key();
    let body = CertificateBody {
        subject_key: &subject_key,
        issuer_key_id: key_id(&root_key),
        serial: 1,
        usage: Usage {
            roles: RoleSet::ALL,
            certify: false,
        },
        min_security_version: 0,
        max_security_version: u32::MAX,
    };
    let encoding = |e| err!("encoding the signing key's certificate ({e:?})");
    let mut signed = Box::new([0u8; cert::SIGNED_LEN]);
    body.encode_signed(&mut signed).map_err(encoding)?;
    let mut certificate = Box::new([0u8; cert::LEN]);
    body.encode(&root.sign(&signed[..])?, &mut certificate)
        .map_err(encoding)?;
    let anchor = AnchorSpec {
        key: &root_key,
        usage: Usage {
            roles: RoleSet::ALL,
            certify: true,
        },
        local: true,
        label: LOCAL_LABEL,
    };
    let store = super::store::encode(super::SECURITY_VERSION, &[anchor], &[])?;
    Ok(LocalFiles {
        seed,
        certificate,
        store,
    })
}

/// Write `files` into the new directory `staging`.
fn write_identity(staging: &Path, files: &LocalFiles) -> Result<()>
{
    create_private_dir(staging)?;
    write_new(&staging.join(SEED_FILE), &files.seed.0)?;
    write_new(&staging.join(CERT_FILE), &files.certificate[..])?;
    write_new(&staging.join(STORE_FILE), &files.store)
}

/// Move `staging` to `dir`, which is absent or empty; leave `dir` as it
/// is when another build filled it first.
fn place(staging: &Path, dir: &Path) -> Result<()>
{
    // A rename does not replace a directory on every host; an empty one is
    // removed first, and a failure to remove it is the race below.
    if dir.exists()
    {
        let _ = fs::remove_dir(dir);
    }
    match fs::rename(staging, dir)
    {
        Ok(()) => Ok(()),
        Err(_) if !is_absent_or_empty(dir)? => Ok(()),
        Err(e) => Err(e).with_context(|| format!("moving the new identity to {}", dir.display())),
    }
}

/// Create `dir`, readable by its owner alone where the host has modes.
fn create_private_dir(dir: &Path) -> Result<()>
{
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Write `bytes` to the new file `path`, readable by its owner alone where
/// the host has modes.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()>
{
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("writing {}", path.display()))
}

/// The bytes of `path`, `None` when it does not exist.
fn read_optional(path: &Path) -> Result<Option<Vec<u8>>>
{
    match fs::read(path)
    {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// The `N` bytes of `path`, which holds exactly `N`.
fn read_exact<const N: usize>(path: &Path) -> Result<Box<[u8; N]>>
{
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Box::<[u8; N]>::try_from(bytes.into_boxed_slice())
        .map_err(|bytes| err!("{} holds {} bytes, not {N}", path.display(), bytes.len()))
}

/// A certificate file's bytes, checked to be exactly one certificate.
fn parse_certificate(bytes: &[u8]) -> Result<Box<[u8; cert::LEN]>>
{
    let raw = <&[u8; cert::LEN]>::try_from(bytes).map_err(|_| {
        err!(
            "{} bytes, not a {}-byte certificate",
            bytes.len(),
            cert::LEN
        )
    })?;
    Certificate::parse(raw).map_err(|e| err!("not a certificate ({e:?})"))?;
    Ok(Box::new(*raw))
}

#[cfg(test)]
mod tests
{
    use super::*;
    use crate::signing::testing::{counter, scratch, work_tree};

    /// A seed source an existing identity never calls.
    fn no_draw(_: &mut [u8; 32])
    {
        panic!("an existing identity draws no seed");
    }

    /// The names of the entries of `dir`, sorted.
    fn names(dir: &Path) -> Vec<String>
    {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    // Defect caught: a signing key no anchor of the store certifies, a root
    // not marked local, a root seed written to disk, or an identity
    // regenerated on every build, which changes the store each time.
    #[test]
    fn a_generated_identity_is_certified_by_a_local_root_and_reloads_unchanged()
    {
        let root = scratch("generate");
        let dir = root.join("keys");
        let first = Identity::load(&dir, None, &work_tree(), &mut counter(1)).unwrap();
        assert_eq!(names(&dir), [CERT_FILE, SEED_FILE, STORE_FILE]);

        let cert = Certificate::parse(first.certificate().unwrap()).unwrap();
        assert_eq!(cert.body.subject_key, first.public_key());
        let store = TrustStore::parse(first.store()).unwrap();
        let anchors: Vec<_> = store.anchors().collect();
        assert_eq!(anchors.len(), 1);
        let anchor = anchors[0];
        assert!(anchor.local && anchor.usage.certify);
        assert_eq!(anchor.key_id, cert.body.issuer_key_id);
        composite::verify(anchor.key, cert.signed(), cert.signature).unwrap();
        let signature = first.sign(b"message").unwrap();
        composite::verify(first.public_key(), b"message", &signature).unwrap();
        // The seed is the signing key's two seeds, each drawn on its own:
        // the root took the first two draws.
        let mut drawn = [3u8; SEED_LEN];
        drawn[32..].fill(4);
        assert_eq!(fs::read(dir.join(SEED_FILE)).unwrap(), drawn);

        let again = Identity::load(&dir, None, &work_tree(), &mut no_draw).unwrap();
        assert_eq!(again.public_key(), first.public_key());
        assert_eq!(again.store(), first.store());
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a secret seed, or its directory, readable by other users
    // of the build machine.
    #[cfg(unix)]
    #[test]
    fn a_generated_seed_is_readable_by_its_owner_alone()
    {
        use std::os::unix::fs::PermissionsExt as _;
        let root = scratch("modes");
        let dir = root.join("keys");
        generate(&dir, &mut counter(1)).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join(SEED_FILE)), 0o600);
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: two builds that start at once each writing an identity,
    // so one build's images are signed by a key the other's store lacks, or
    // a losing build leaving its files behind.
    #[test]
    fn a_generation_that_finds_the_directory_filled_keeps_the_identity_there()
    {
        let root = scratch("race");
        let dir = root.join("keys");
        generate(&dir, &mut counter(1)).unwrap();
        let first = Identity::load(&dir, None, &work_tree(), &mut no_draw).unwrap();
        generate(&dir, &mut counter(50)).unwrap();
        let kept = Identity::load(&dir, None, &work_tree(), &mut no_draw).unwrap();
        assert_eq!(kept.public_key(), first.public_key());
        assert_eq!(names(&root), ["keys"]);
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a key written into, or read from, the work tree, where a
    // commit or an archive of the tree would carry it.
    #[test]
    fn a_key_inside_the_work_tree_is_refused()
    {
        let root = scratch("inside");
        let tree = root.join("tree");
        fs::create_dir_all(tree.join("target")).unwrap();
        let inside = tree.join("target").join("keys");
        Identity::load(&inside, None, &tree, &mut no_draw).unwrap_err();
        assert!(!inside.exists());

        #[cfg(unix)]
        {
            // A directory reached through a link into the tree, and a seed
            // file that is a link into it.
            std::os::unix::fs::symlink(&tree, root.join("link")).unwrap();
            let linked = root.join("link").join("keys");
            Identity::load(&linked, None, &tree, &mut no_draw).unwrap_err();
            assert!(!tree.join("keys").exists());

            let dir = root.join("keys");
            generate(&dir, &mut counter(1)).unwrap();
            fs::rename(dir.join(SEED_FILE), tree.join("seed")).unwrap();
            std::os::unix::fs::symlink(tree.join("seed"), dir.join(SEED_FILE)).unwrap();
            Identity::load(&dir, None, &tree, &mut no_draw).unwrap_err();
        }
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a build signing with a key the certificate does not
    // name, whose images no store accepts, or one that proceeds on a partial
    // identity.
    #[test]
    fn a_mismatched_or_incomplete_identity_is_refused()
    {
        let root = scratch("mismatch");
        let (one, two) = (root.join("one"), root.join("two"));
        generate(&one, &mut counter(1)).unwrap();
        generate(&two, &mut counter(10)).unwrap();
        fs::copy(two.join(SEED_FILE), one.join(SEED_FILE)).unwrap();
        Identity::load(&one, None, &work_tree(), &mut no_draw).unwrap_err();

        fs::remove_file(two.join(CERT_FILE)).unwrap();
        Identity::load(&two, None, &work_tree(), &mut no_draw).unwrap_err();
        fs::write(two.join(CERT_FILE), [0u8; 12]).unwrap();
        Identity::load(&two, None, &work_tree(), &mut no_draw).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: an external signer whose input is not the message, or
    // whose output is taken for a signature when it is not one.
    #[cfg(unix)]
    #[test]
    fn an_external_signer_signs_its_standard_input_and_its_failures_are_refused()
    {
        let root = scratch("external");
        let dir = root.join("keys");
        generate(&dir, &mut counter(1)).unwrap();
        // The external signer holds the key: no seed is read.
        fs::remove_file(dir.join(SEED_FILE)).unwrap();
        // `cat` writes back what it reads: a message of a composite
        // signature's length comes back as its signature.
        let cat = Identity::load(&dir, Some(Path::new("cat")), &work_tree(), &mut no_draw).unwrap();
        let message = [7u8; SIGNATURE_LEN];
        assert_eq!(*cat.sign(&message).unwrap(), message);
        cat.sign(&[7u8; 64]).unwrap_err();
        cat.sign(b"short").unwrap_err();

        let fails =
            Identity::load(&dir, Some(Path::new("false")), &work_tree(), &mut no_draw).unwrap();
        fails.sign(&message).unwrap_err();
        let absent = Identity::load(
            &dir,
            Some(&root.join("no-such-signer")),
            &work_tree(),
            &mut no_draw,
        )
        .unwrap();
        absent.sign(&message).unwrap_err();
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: an identity of the retired Ed25519 format (a 32-byte
    // seed, a 148-byte certificate) loaded, or refused without saying that
    // its format is the reason.
    #[test]
    fn an_identity_of_an_earlier_format_is_refused()
    {
        let root = scratch("earlier");
        let dir = root.join("keys");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(SEED_FILE), [1u8; 32]).unwrap();
        fs::write(dir.join(CERT_FILE), [2u8; 148]).unwrap();
        fs::write(dir.join(STORE_FILE), [3u8; 90]).unwrap();
        let error = Identity::load(&dir, None, &work_tree(), &mut no_draw).unwrap_err();
        assert!(
            format!("{error:#}").contains("composite signature format"),
            "{error:#}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // Defect caught: a local identity generated beside an external signer,
    // whose seed would then sign in its place.
    #[test]
    fn an_external_signer_without_an_identity_is_refused()
    {
        let root = scratch("external-empty");
        let dir = root.join("keys");
        Identity::load(&dir, Some(Path::new("cat")), &work_tree(), &mut no_draw).unwrap_err();
        assert!(!dir.exists());
        let _ = fs::remove_dir_all(&root);
    }
}
