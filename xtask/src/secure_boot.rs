// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/secure_boot.rs

//! UEFI Secure Boot on the host (docs/signing.md § Secure Boot): the
//! Authenticode signature of the installed bootloader, development keys, and
//! the enrolment of keys in a firmware variable store.
//!
//! - [`DbKey`]: the configured key the build signs `/boot/boot.efi` with,
//!   from [`ENV_SECURE_BOOT_KEY`] and [`ENV_SECURE_BOOT_CERT`]; with none
//!   configured the bootloader is not signed, and Secure Boot stays optional.
//! - [`sign`]: `sbsign`, then `sbverify` against the key's certificate.
//! - [`DevKeys`]: a development platform key, key exchange key and db key,
//!   made with `openssl`.
//! - [`enroll`] and [`edit_store`]: `virt-fw-vars` on a variable store
//!   (`crate::qemu::LaunchVars`), the enrolment of PK, KEK and db, or any
//!   other edit a caller passes.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Context as _, Result, bail};
use crate::util::require_tool;

/// The PEM private key of the db key the build signs the bootloader with;
/// set together with [`ENV_SECURE_BOOT_CERT`].
pub const ENV_SECURE_BOOT_KEY: &str = "SERAPH_SECURE_BOOT_KEY";

/// The PEM X.509 certificate of the key [`ENV_SECURE_BOOT_KEY`] names, the
/// certificate a machine enrols in its db.
pub const ENV_SECURE_BOOT_CERT: &str = "SERAPH_SECURE_BOOT_CERT";

/// The owner GUID every certificate [`enroll`] writes carries: the Seraph
/// vendor GUID (`SERAPH_VENDOR_GUID` in `core/boot/src/uefi.rs`).
pub const OWNER_GUID: &str = "a53c3964-9d31-4f44-843a-526baa1271b8";

/// A signing key and its certificate, each a PEM file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DbKey
{
    /// The private key.
    pub key: PathBuf,
    /// The X.509 certificate of its public key.
    pub cert: PathBuf,
}

impl DbKey
{
    /// The key the environment configures, `None` when it configures none.
    ///
    /// # Errors
    ///
    /// Those of [`Self::from_vars`].
    pub fn from_env() -> Result<Option<Self>>
    {
        Self::from_vars(&|name| std::env::var_os(name))
    }

    /// The key the variables `lookup` returns configure; an empty variable
    /// is unset.
    ///
    /// # Errors
    ///
    /// When only one of [`ENV_SECURE_BOOT_KEY`] and [`ENV_SECURE_BOOT_CERT`]
    /// is set, or either names no file.
    pub fn from_vars(lookup: &dyn Fn(&str) -> Option<OsString>) -> Result<Option<Self>>
    {
        let var = |name: &str| lookup(name).filter(|value| !value.is_empty());
        match (var(ENV_SECURE_BOOT_KEY), var(ENV_SECURE_BOOT_CERT))
        {
            (None, None) => Ok(None),
            (Some(key), Some(cert)) =>
            {
                let key = DbKey {
                    key: PathBuf::from(key),
                    cert: PathBuf::from(cert),
                };
                for (var, path) in [
                    (ENV_SECURE_BOOT_KEY, &key.key),
                    (ENV_SECURE_BOOT_CERT, &key.cert),
                ]
                {
                    if !path.is_file()
                    {
                        bail!("${var}={} names no file", path.display());
                    }
                }
                Ok(Some(key))
            }
            _ => bail!(
                "${ENV_SECURE_BOOT_KEY} and ${ENV_SECURE_BOOT_CERT} must be set together (or both \
                 left unset): the bootloader is signed with the key and checked against the \
                 certificate"
            ),
        }
    }
}

/// Authenticode-sign the PE image `image` with `key` into `out` (which may
/// be `image`), with `sbsign`, and check the result against the key's
/// certificate with `sbverify`.
///
/// # Errors
///
/// When `sbsign` or `sbverify` is missing, or either fails: a key that does
/// not match its certificate fails the check.
pub fn sign(image: &Path, out: &Path, key: &DbKey) -> Result<()>
{
    let sbsign = require_tool("sbsign")?;
    let sbverify = require_tool("sbverify")?;
    // sbsign reads its input whole before it writes its output, so `out`
    // may name the input; a temporary keeps a failed signing from leaving a
    // partial file at `out`.
    let signed = with_suffix(out, ".signing");
    run(Command::new(&sbsign)
        .arg("--key")
        .arg(&key.key)
        .arg("--cert")
        .arg(&key.cert)
        .arg("--output")
        .arg(&signed)
        .arg(image))
    .with_context(|| format!("signing {}", image.display()))?;
    let checked = run(Command::new(&sbverify)
        .arg("--cert")
        .arg(&key.cert)
        .arg(&signed))
    .with_context(|| {
        format!(
            "the signature of {} does not verify under {}",
            image.display(),
            key.cert.display()
        )
    });
    if let Err(e) = checked
    {
        let _ = fs::remove_file(&signed);
        return Err(e);
    }
    fs::rename(&signed, out)
        .with_context(|| format!("renaming {} to {}", signed.display(), out.display()))
}

/// `path` with `suffix` appended to its file name.
fn with_suffix(path: &Path, suffix: &str) -> PathBuf
{
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A development key hierarchy: the platform key, the key exchange key and
/// the db key, each self-signed RSA-2048 with SHA-256, the shape every UEFI
/// implementation takes.
#[derive(Clone, Debug)]
pub struct DevKeys
{
    pub pk: DbKey,
    pub kek: DbKey,
    pub db: DbKey,
}

impl DevKeys
{
    /// Generate the three keys into `dir` (`PK.key`, `PK.crt`, and the same
    /// for `KEK` and `db`), with `openssl`.
    ///
    /// # Errors
    ///
    /// When `openssl` is missing or fails, or `dir` cannot be created.
    pub fn generate(dir: &Path) -> Result<Self>
    {
        let openssl = require_tool("openssl")?;
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let make = |name: &str| -> Result<DbKey> {
            let key = DbKey {
                key: dir.join(format!("{name}.key")),
                cert: dir.join(format!("{name}.crt")),
            };
            run(Command::new(&openssl)
                .args([
                    "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "3650",
                ])
                .args(["-nodes", "-subj"])
                .arg(format!("/CN=Seraph development {name}/"))
                .arg("-keyout")
                .arg(&key.key)
                .arg("-out")
                .arg(&key.cert))
            .with_context(|| format!("generating the development {name}"))?;
            Ok(key)
        };
        Ok(Self {
            pk: make("PK")?,
            kek: make("KEK")?,
            db: make("db")?,
        })
    }
}

/// Enrol `pk` as the platform key, `kek` in KEK and `db` in db of the
/// firmware variable store `store`, in place, and turn Secure Boot on: the
/// firmware booted on it verifies every image it runs against db.
///
/// # Errors
///
/// Those of [`edit_store`].
pub fn enroll(store: &Path, pk: &Path, kek: &Path, db: &Path) -> Result<()>
{
    let guid = OsStr::new(OWNER_GUID);
    edit_store(
        store,
        &[
            OsStr::new("--set-pk"),
            guid,
            pk.as_os_str(),
            OsStr::new("--add-kek"),
            guid,
            kek.as_os_str(),
            OsStr::new("--add-db"),
            guid,
            db.as_os_str(),
            OsStr::new("--sb"),
        ],
    )
    .context("enrolling the Secure Boot keys")
}

/// Edit the EDK2 variable store `store` in place with `virt-fw-vars` and
/// the arguments `edit` (its variable and Secure Boot options).
///
/// # Errors
///
/// When `virt-fw-vars` is missing or fails.
pub fn edit_store(store: &Path, edit: &[&OsStr]) -> Result<()>
{
    let tool = require_tool("virt-fw-vars")?;
    run(Command::new(&tool).arg("--inplace").arg(store).args(edit))
        .with_context(|| format!("editing the variable store {}", store.display()))
}

/// Run `cmd` with its output captured, and fail with that output when it
/// exits non-zero.
fn run(cmd: &mut Command) -> Result<()>
{
    let output = cmd
        .output()
        .with_context(|| format!("failed to launch {}", cmd.get_program().display()))?;
    if !output.status.success()
    {
        bail!(
            "{} exited with {}:\n{}{}",
            cmd.get_program().display(),
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn lookup(pairs: &[(&'static str, OsString)]) -> impl Fn(&str) -> Option<OsString>
    {
        let pairs = pairs.to_vec();
        move |name| {
            pairs
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, value)| value.clone())
        }
    }

    fn existing_file() -> OsString
    {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("Cargo.toml")
            .into_os_string()
    }

    // Defect caught: a build that signs with a key and checks against
    // another's certificate, or signs nothing while the user set one of the
    // two, so a bootloader the machine's db refuses is installed silently.
    #[test]
    fn the_key_and_certificate_are_configured_together()
    {
        assert_eq!(DbKey::from_vars(&lookup(&[])).unwrap(), None);
        assert_eq!(
            DbKey::from_vars(&lookup(&[(ENV_SECURE_BOOT_KEY, OsString::new())])).unwrap(),
            None
        );
        for only in [ENV_SECURE_BOOT_KEY, ENV_SECURE_BOOT_CERT]
        {
            let msg = format!(
                "{:#}",
                DbKey::from_vars(&lookup(&[(only, existing_file())])).unwrap_err()
            );
            assert!(msg.contains("must be set together"), "{msg}");
        }
        let both = DbKey::from_vars(&lookup(&[
            (ENV_SECURE_BOOT_KEY, existing_file()),
            (ENV_SECURE_BOOT_CERT, existing_file()),
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(both.key, PathBuf::from(existing_file()));
        let msg = format!(
            "{:#}",
            DbKey::from_vars(&lookup(&[
                (ENV_SECURE_BOOT_KEY, existing_file()),
                (ENV_SECURE_BOOT_CERT, OsString::from("/nonexistent/db.crt")),
            ]))
            .unwrap_err()
        );
        assert!(
            msg.contains("SERAPH_SECURE_BOOT_CERT=/nonexistent/db.crt"),
            "{msg}"
        );
    }

    // Defect caught: a temporary that replaces the input's name, so signing
    // in place reads the file it is writing.
    #[test]
    fn the_signing_temporary_is_beside_the_output()
    {
        assert_eq!(
            with_suffix(Path::new("/s/boot/boot.efi"), ".signing"),
            PathBuf::from("/s/boot/boot.efi.signing")
        );
    }
}
