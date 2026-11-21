// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/generate/openssl.rs

//! The reference: the `openssl` command, which signs, verifies and hashes
//! for the generator.
//!
//! Keys pass as DER files (RFC 8410 for Ed25519, the IETF LAMPS encodings of
//! OID 2.16.840.1.101.3.4.3.18 for ML-DSA-65), and a
//! signature and a signed message as files (a one-shot signature operation
//! reads no stream), in a working directory the generator owns; a hashed
//! message passes on standard input.

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use super::Error;

/// The DER prefix of an Ed25519 PKCS #8 private key, followed by its 32 raw
/// bytes.
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The DER prefix of an Ed25519 `SubjectPublicKeyInfo`, followed by its 32
/// raw bytes.
const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// The DER prefix of an ML-DSA-65 PKCS #8 private key in its seed-only form
/// (`[0] IMPLICIT OCTET STRING`), followed by the 32-byte seed.
const ML_DSA_65_PKCS8_PREFIX: [u8; 22] = [
    0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x03, 0x12, 0x04, 0x22, 0x80, 0x20,
];

/// The DER prefix of an ML-DSA-65 `SubjectPublicKeyInfo`, followed by the
/// 1952-byte raw public key.
const ML_DSA_65_SPKI_PREFIX: [u8; 22] = [
    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03,
    0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
];

/// The `openssl` command, with its working directory.
pub struct OpenSsl
{
    dir: PathBuf,
}

impl OpenSsl
{
    /// The command, writing its files under `dir`, a directory the generator
    /// created for the run alone.
    pub const fn new(dir: PathBuf) -> Self
    {
        Self { dir }
    }

    fn file(&self, name: &str, data: &[u8]) -> Result<PathBuf, Error>
    {
        let path = self.dir.join(name);
        fs::write(&path, data).map_err(|e| Error(format!("writing {}: {e}", path.display())))?;
        Ok(path)
    }

    /// Run `openssl args` with `input` on its standard input.
    fn run(args: &[&str], input: &[u8]) -> Result<Output, Error>
    {
        let what = || format!("openssl {}", args.join(" "));
        let mut child = Command::new("openssl")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error(format!("{}: {e}", what())))?;
        if let Some(mut stdin) = child.stdin.take()
        {
            stdin
                .write_all(input)
                .map_err(|e| Error(format!("{}: {e}", what())))?;
        }
        child
            .wait_with_output()
            .map_err(|e| Error(format!("{}: {e}", what())))
    }

    /// Run `openssl args` and return its standard output; an error when it
    /// fails.
    fn output(args: &[&str], input: &[u8]) -> Result<Vec<u8>, Error>
    {
        let out = Self::run(args, input)?;
        if !out.status.success()
        {
            return Err(Error(format!(
                "openssl {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(out.stdout)
    }

    /// The tool's version line.
    pub fn version() -> Result<String, Error>
    {
        let out = Self::output(&["version"], &[])?;
        Ok(String::from_utf8_lossy(&out).trim().to_owned())
    }

    /// The SHA-512 digest of `data`.
    pub fn sha512(data: &[u8]) -> Result<[u8; 64], Error>
    {
        let out = Self::output(&["dgst", "-sha512", "-binary"], data)?;
        out.try_into()
            .map_err(|_| Error("openssl dgst: not a 64-byte digest".into()))
    }

    /// The public key of the private key `secret`, and its signature over
    /// `message` (RFC 8032 § 5.1.6).
    pub fn sign(&self, secret: &[u8; 32], message: &[u8]) -> Result<([u8; 32], [u8; 64]), Error>
    {
        let mut der = PKCS8_PREFIX.to_vec();
        der.extend_from_slice(secret);
        let key = self.file("private.der", &der)?;
        let key = key.to_string_lossy();
        let data = self.file("message", message)?;
        let signature = Self::output(
            &[
                "pkeyutl",
                "-sign",
                "-rawin",
                "-keyform",
                "DER",
                "-inkey",
                &key,
                "-in",
                &data.to_string_lossy(),
            ],
            &[],
        )?;
        let public = Self::output(
            &[
                "pkey", "-inform", "DER", "-in", &key, "-pubout", "-outform", "DER",
            ],
            &[],
        )?;
        let public = public
            .strip_prefix(&SPKI_PREFIX)
            .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
            .ok_or_else(|| Error("openssl pkey: not an Ed25519 public key".into()))?;
        let signature = <[u8; 64]>::try_from(signature)
            .map_err(|_| Error("openssl pkeyutl -sign: not a 64-byte signature".into()))?;
        Ok((public, signature))
    }

    /// Whether OpenSSL's verification accepts `signature` over `message`
    /// under `public_key`; an error when the command fails otherwise than by
    /// refusing the signature.
    pub fn verifies(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<bool, Error>
    {
        let mut der = SPKI_PREFIX.to_vec();
        der.extend_from_slice(public_key);
        let key = self.file("public.der", &der)?;
        let sig = self.file("signature", signature)?;
        let data = self.file("message", message)?;
        let args = [
            "pkeyutl",
            "-verify",
            "-pubin",
            "-rawin",
            "-keyform",
            "DER",
            "-inkey",
            &key.to_string_lossy(),
            "-sigfile",
            &sig.to_string_lossy(),
            "-in",
            &data.to_string_lossy(),
        ];
        Self::verdict(&args)
    }

    /// Run the `openssl pkeyutl -verify` of `args`: whether it accepts the
    /// signature, or an error when it fails otherwise than by refusing it.
    fn verdict(args: &[&str]) -> Result<bool, Error>
    {
        let out = Self::run(args, &[])?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success() && stdout.contains("Signature Verified Successfully")
        {
            return Ok(true);
        }
        if stdout.contains("Signature Verification Failure")
        {
            return Ok(false);
        }
        Err(Error(format!(
            "openssl pkeyutl -verify failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )))
    }

    /// The first `len` bytes of SHAKE128 or SHAKE256 (`function`, the
    /// command's digest name) of `data`; `len` is at least one.
    pub fn shake(function: &str, data: &[u8], len: usize) -> Result<Vec<u8>, Error>
    {
        let out = Self::output(
            &[
                "dgst",
                &format!("-{function}"),
                "-xoflen",
                &len.to_string(),
                "-binary",
            ],
            data,
        )?;
        if out.len() == len
        {
            Ok(out)
        }
        else
        {
            Err(Error(format!("openssl dgst -{function}: not {len} bytes")))
        }
    }

    /// The `pkeyutl` options that pass the ML-DSA context string `context`,
    /// none for an empty one.
    fn context_options(context: &[u8]) -> Vec<String>
    {
        if context.is_empty()
        {
            return Vec::new();
        }
        vec![
            "-pkeyopt".to_owned(),
            format!("hexcontext-string:{}", crate::hex::encode(context)),
        ]
    }

    /// The ML-DSA-65 public key of the key-generation seed `seed`, and its
    /// deterministic signature over `message` with context string `context`
    /// (FIPS 204 Algorithms 1 and 2).
    pub fn ml_dsa_sign(
        &self,
        seed: &[u8; 32],
        message: &[u8],
        context: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error>
    {
        let mut der = ML_DSA_65_PKCS8_PREFIX.to_vec();
        der.extend_from_slice(seed);
        let key = self.file("ml-dsa-private.der", &der)?;
        let key = key.to_string_lossy();
        let data = self.file("message", message)?;
        let data = data.to_string_lossy();
        let mut args = vec![
            "pkeyutl",
            "-sign",
            "-rawin",
            "-keyform",
            "DER",
            "-inkey",
            &key,
            "-in",
            &data,
            "-pkeyopt",
            "deterministic:1",
        ];
        let context = Self::context_options(context);
        args.extend(context.iter().map(String::as_str));
        let signature = Self::output(&args, &[])?;
        let public = Self::output(
            &[
                "pkey", "-inform", "DER", "-in", &key, "-pubout", "-outform", "DER",
            ],
            &[],
        )?;
        let public = public
            .strip_prefix(&ML_DSA_65_SPKI_PREFIX)
            .filter(|raw| raw.len() == crate::ml_dsa::PUBLIC_KEY_LEN)
            .ok_or_else(|| Error("openssl pkey: not an ML-DSA-65 public key".into()))?;
        if signature.len() != crate::ml_dsa::SIGNATURE_LEN
        {
            return Err(Error(
                "openssl pkeyutl -sign: not an ML-DSA-65 signature".into(),
            ));
        }
        Ok((public.to_vec(), signature))
    }

    /// Whether OpenSSL's ML-DSA-65 verification accepts `signature` over
    /// `message` with context string `context` under `public_key`; an error
    /// when the command fails otherwise than by refusing the signature.
    pub fn ml_dsa_verifies(
        &self,
        public_key: &[u8],
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error>
    {
        let mut der = ML_DSA_65_SPKI_PREFIX.to_vec();
        der.extend_from_slice(public_key);
        let key = self.file("ml-dsa-public.der", &der)?;
        let key = key.to_string_lossy();
        let sig = self.file("signature", signature)?;
        let sig = sig.to_string_lossy();
        let data = self.file("message", message)?;
        let data = data.to_string_lossy();
        let mut args = vec![
            "pkeyutl", "-verify", "-pubin", "-rawin", "-keyform", "DER", "-inkey", &key,
            "-sigfile", &sig, "-in", &data,
        ];
        let context = Self::context_options(context);
        args.extend(context.iter().map(String::as_str));
        Self::verdict(&args)
    }
}
