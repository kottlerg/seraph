// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/generate/mod.rs

//! The generator of the reference vectors, `vectors/reference/ed25519.json`
//! and `sha512.json`: it builds every input and writes it with the outcome
//! OpenSSL gives it.
//!
//! OpenSSL is the reference (the [`openssl`] module runs the command). The
//! generated inputs come from [`Rng`] under fixed seeds, so the files are the
//! same on every run, and the Ed25519 edge cases are built with the curve
//! arithmetic of [`edwards`], which is independent of `shared/crypto`.
//!
//! An Ed25519 verdict names the first RFC 8032 check that fails, in order: S
//! at or above the group order L, a public key that is not the canonical
//! encoding of a point, then OpenSSL's cofactorless verification. OpenSSL
//! decodes a non-canonical key leniently, so the generator checks the
//! encoding itself with [`edwards::decode`]; it fails when OpenSSL accepts an
//! S at or above L, which OpenSSL refuses by its own check, when a crafted
//! case does not reach the outcome it is built for, and when the public key
//! OpenSSL derives differs from the one [`edwards`] derives.

pub mod edwards;
pub mod nat;
mod openssl;

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use json::{Value, json};

use self::edwards::{L, Point, decode, scalars, torsion};
use self::nat::U256;
use self::openssl::OpenSsl;
use crate::ed25519::{self, Verdict};
use crate::hex;
use crate::rng::Rng;
use crate::sha512;
use crate::wycheproof::{self, Case as _, Expected, eddsa};

/// The seed of the generated Ed25519 inputs.
pub const ED25519_SEED: u64 = 0x5e4a_ed25;
/// The number of generated Ed25519 rounds.
pub const ED25519_ROUNDS: usize = 128;
/// The seed of the generated SHA-512 messages.
pub const SHA512_SEED: u64 = 0x5e4a_9512;
/// The number of long SHA-512 messages, beside every length from 0 to 300.
pub const SHA512_LONG: usize = 64;

/// Why the generator stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(pub String);

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(&self.0)
    }
}

/// The generated files: each name under `vectors/reference/` and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Files
{
    /// Every file, by name.
    pub files: Vec<(&'static str, String)>,
}

/// Generate both vector files with OpenSSL, the command's files kept in a
/// private working directory under the system's temporary directory (see
/// [`private_dir`]) and removed after.
///
/// # Errors
///
/// An [`Error`] when the `openssl` command fails or is missing, a file
/// cannot be written, or a check of the module description fails.
pub fn generate() -> Result<Files, Error>
{
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let dir = private_dir(
        &std::env::temp_dir(),
        &format!("crypto-reference-vectors-{}-{nonce}", std::process::id()),
    )?;
    let ed25519 = Ed25519 {
        openssl: OpenSsl::new(dir.clone()),
    };
    let result = ed25519.file().and_then(|ed| Ok((ed, sha512_file()?)));
    // A leftover working directory holds nothing secret; a failure to remove
    // it does not fail the run.
    let _ = fs::remove_dir_all(&dir);
    let (ed, sha) = result?;
    Ok(Files {
        files: vec![(ed25519::FILE, ed), (sha512::FILE, sha)],
    })
}

/// Create the directory `name` under `base` for this run alone: it must not
/// exist yet, so a directory another user prepared (holding a symlink a file
/// write would follow) fails the run instead of receiving its files, and on
/// Unix only the owner can enter it.
///
/// # Errors
///
/// An [`Error`] when the directory exists or cannot be created.
fn private_dir(base: &Path, name: &str) -> Result<PathBuf, Error>
{
    let dir = base.join(name);
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
        .create(&dir)
        .map_err(|e| Error(format!("creating {}: {e}", dir.display())))?;
    Ok(dir)
}

/// The version line of the `openssl` command, the reference.
///
/// # Errors
///
/// An [`Error`] when the command fails or is missing.
pub fn reference_version() -> Result<String, Error>
{
    OpenSsl::version()
}

/// A vector file: the header's members, then each section as an array of
/// one case per line.
fn vector_file(header: &[(&str, Value)], sections: &[(&str, Vec<Value>)]) -> String
{
    let mut members: Vec<String> = header
        .iter()
        .map(|(key, value)| format!("  {}: {value}", Value::from(*key)))
        .collect();
    for (key, cases) in sections
    {
        let body: Vec<String> = cases.iter().map(|case| format!("    {case}")).collect();
        members.push(format!(
            "  {}: [\n{}\n  ]",
            Value::from(*key),
            body.join(",\n")
        ));
    }
    format!("{{\n{}\n}}\n", members.join(",\n"))
}

/// `data` with bit `bit` flipped, bit 0 the low bit of the first byte.
fn flip(data: &[u8], bit: usize) -> Vec<u8>
{
    let mut out = data.to_vec();
    if let Some(byte) = out.get_mut(bit / 8)
    {
        *byte ^= 1 << (bit % 8);
    }
    out
}

/// A 32-byte array of `data`, which the caller sized.
fn array<const N: usize>(data: &[u8]) -> [u8; N]
{
    let mut out = [0u8; N];
    out.copy_from_slice(data);
    out
}

/// `k = SHA-512(R ‖ A ‖ M) mod L`.
fn challenge(r: &[u8; 32], a: &[u8; 32], message: &[u8]) -> Result<U256, Error>
{
    let mut data = r.to_vec();
    data.extend_from_slice(a);
    data.extend_from_slice(message);
    Ok(scalars().reduce_le_bytes(&OpenSsl::sha512(&data)?))
}

/// The clamped scalar of the private key `secret` (RFC 8032 § 5.1.5),
/// modulo L.
fn secret_scalar(secret: &[u8; 32]) -> Result<U256, Error>
{
    let hash = OpenSsl::sha512(secret)?;
    let mut low: [u8; 32] = array(&hash[..32]);
    low[0] &= 0xf8;
    low[31] &= 0x7f;
    low[31] |= 0x40;
    Ok(scalars().reduce(U256::from_le_bytes(&low)))
}

/// Every encoding whose y field (the low 255 bits) is at or above p, with
/// and without the sign bit: no such encoding is canonical.
fn y_at_or_above_p() -> Vec<[u8; 32]>
{
    let mut out = Vec::new();
    for low in 0xedu8..=0xff
    {
        for top in [0x7fu8, 0xff]
        {
            let mut encoding = [0xff; 32];
            encoding[0] = low;
            encoding[31] = top;
            out.push(encoding);
        }
    }
    out
}

/// The two points with x = 0 (y = 1 and y = -1), encoded with the sign bit
/// set: neither encoding is canonical.
fn x_zero_with_sign() -> Vec<[u8; 32]>
{
    let mut one = [0u8; 32];
    one[0] = 1;
    one[31] = 0x80;
    let mut minus_one = [0xff; 32];
    minus_one[0] = 0xec;
    vec![one, minus_one]
}

/// Whether a crafted signature is to satisfy the cofactorless equation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Equation
{
    Holds,
    Fails,
}

impl Equation
{
    /// The verdict a cofactorless verifier gives the crafted signature.
    const fn verdict(self) -> Verdict
    {
        match self
        {
            Self::Holds => Verdict::Accept,
            Self::Fails => Verdict::Mismatch,
        }
    }
}

/// The first message `stem ‖ n` (n a little-endian u32 counting up from 0)
/// whose challenge under `nonce_point` and `key` makes `[k]point` the
/// identity exactly when the equation is to hold: the term that decides the
/// cofactorless equation for the crafted signatures.
fn message_where(
    stem: &[u8],
    nonce_point: &[u8; 32],
    key: &[u8; 32],
    point: &Point,
    equation: Equation,
) -> Result<Vec<u8>, Error>
{
    for n in 0..=u32::MAX
    {
        let mut message = stem.to_vec();
        message.extend_from_slice(&n.to_le_bytes());
        let k = challenge(nonce_point, key, &message)?;
        let killed = point.mul(k) == Point::identity();
        if killed == (equation == Equation::Holds)
        {
            return Ok(message);
        }
    }
    Err(Error(format!("no message makes the equation {equation:?}")))
}

/// `R = O, S = 0`: valid under the identity key for every message.
fn identity_signature() -> [u8; 64]
{
    array(&[Point::identity().encode(), [0; 32]].concat())
}

/// The valid signature the edge cases corrupt.
struct Base<'a>
{
    secret: [u8; 32],
    message: &'a [u8],
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl Base<'_>
{
    /// The base input with S replaced by `s`.
    fn with_s(&self, builder: &Ed25519, label: &str, s: &[u8; 32]) -> Result<Value, Error>
    {
        let signature = array(&[&self.signature[..32], s.as_slice()].concat());
        builder.case(label, &self.public_key, self.message, &signature)
    }

    /// The base input with R replaced by `r`.
    fn with_r(&self, builder: &Ed25519, label: &str, r: &[u8; 32]) -> Result<Value, Error>
    {
        let signature = array(&[r.as_slice(), &self.signature[32..]].concat());
        builder.case(label, &self.public_key, self.message, &signature)
    }
}

/// The Ed25519 vectors' builder, with the reference.
struct Ed25519
{
    openssl: OpenSsl,
}

impl Ed25519
{
    /// The reference verdict: the first RFC 8032 check that fails.
    fn verdict(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<Verdict, Error>
    {
        let accepts = self.openssl.verifies(public_key, message, signature)?;
        let s = U256::from_le_bytes(&array(&signature[32..]));
        if s >= U256::from_le_bytes(&L)
        {
            if accepts
            {
                return Err(Error(format!(
                    "OpenSSL accepted S at or above L: {}",
                    hex::encode(signature)
                )));
            }
            return Ok(Verdict::NonCanonicalS);
        }
        if decode(public_key).is_none()
        {
            return Ok(Verdict::BadPublicKey);
        }
        Ok(
            if accepts
            {
                Verdict::Accept
            }
            else
            {
                Verdict::Mismatch
            },
        )
    }

    /// One case, with its reference verdict.
    fn case(
        &self,
        label: &str,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Result<Value, Error>
    {
        let verdict = self.verdict(public_key, message, signature)?;
        Ok(json!({
            "label": label,
            "publicKey": hex::encode(public_key),
            "message": hex::encode(message),
            "signature": hex::encode(signature),
            "verdict": verdict.name(),
        }))
    }

    /// A crafted case, which must reach the verdict it is built for.
    fn crafted(
        &self,
        label: &str,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
        want: Verdict,
    ) -> Result<Value, Error>
    {
        let case = self.case(label, public_key, message, signature)?;
        if case["verdict"] != want.name()
        {
            return Err(Error(format!("{label}: OpenSSL does not give {want:?}")));
        }
        Ok(case)
    }

    /// The public key of `secret` and its signature over `message`, by
    /// OpenSSL; an error when [`edwards`] derives another key.
    fn sign(&self, secret: &[u8; 32], message: &[u8]) -> Result<([u8; 32], [u8; 64]), Error>
    {
        let (public_key, signature) = self.openssl.sign(secret, message)?;
        if Point::base().mul(secret_scalar(secret)?).encode() != public_key
        {
            return Err(Error(format!(
                "OpenSSL's public key of {} differs from [a]B",
                hex::encode(secret)
            )));
        }
        Ok((public_key, signature))
    }

    /// The file: its header and its three sections.
    fn file(&self) -> Result<String, Error>
    {
        let generated = self.generated()?;
        let edge_cases = self.edge_cases()?;
        let acceptable = self.wycheproof_acceptable()?;
        let count = generated.len() + edge_cases.len() + acceptable.len();
        Ok(vector_file(
            &[
                ("schema", json!(ed25519::SCHEMA)),
                ("seed", json!(ED25519_SEED)),
                ("rounds", json!(ED25519_ROUNDS)),
                ("numberOfTests", json!(count)),
            ],
            &[
                ("generated", generated),
                ("edgeCases", edge_cases),
                ("wycheproofAcceptable", acceptable),
            ],
        ))
    }

    /// The generated rounds. Each signs a random message (empty, short, or
    /// up to a few blocks of the hash) under a random key and yields the
    /// valid signature, one-bit flips of the signature, the message and the
    /// key, the signature under a random 32-byte key, and a random 64-byte
    /// signature.
    fn generated(&self) -> Result<Vec<Value>, Error>
    {
        let mut rng = Rng::new(ED25519_SEED);
        let mut out = Vec::new();
        for round in 0..ED25519_ROUNDS
        {
            self.round(&mut rng, round, &mut out)?;
        }
        Ok(out)
    }

    /// One generated round, its inputs appended to ¤out¤.
    fn round(&self, rng: &mut Rng, round: usize, out: &mut Vec<Value>) -> Result<(), Error>
    {
        let secret: [u8; 32] = rng.array();
        let len = match rng.below(4)
        {
            0 => 0,
            1 => rng.below(4096),
            _ => rng.below(300),
        };
        let message = rng.bytes(len);
        let (pk, sig) = self.sign(&secret, &message)?;
        let label = |what: &str| format!("round {round} {what}");
        out.push(self.case(&label("valid"), &pk, &message, &sig)?);
        let flipped = array(&flip(&sig, rng.below(512)));
        out.push(self.case(&label("signature bit"), &pk, &message, &flipped)?);
        if !message.is_empty()
        {
            let flipped = flip(&message, rng.below(len * 8));
            out.push(self.case(&label("message bit"), &pk, &flipped, &sig)?);
        }
        let flipped = array(&flip(&pk, rng.below(256)));
        out.push(self.case(&label("key bit"), &flipped, &message, &sig)?);
        let key = rng.array();
        out.push(self.case(&label("random key"), &key, &message, &sig)?);
        let random = rng.array();
        out.push(self.case(&label("random signature"), &pk, &message, &random)?);
        Ok(())
    }

    /// The edge-case corpus: signature malleability and the S range check,
    /// non-canonical and small-order R, and degenerate public keys (the
    /// torsion points, every non-canonical encoding, a y with no x, and
    /// mixed-order keys with signatures crafted to satisfy, or fail, the
    /// cofactorless equation).
    fn edge_cases(&self) -> Result<Vec<Value>, Error>
    {
        let secret = [0x5e; 32];
        let message = b"seraph ed25519 edge case".as_slice();
        let (public_key, signature) = self.sign(&secret, message)?;
        let base = Base {
            secret,
            message,
            public_key,
            signature,
        };
        let mut out = vec![self.case("base", &public_key, message, &signature)?];
        self.s_cases(&base, &mut out)?;
        self.r_cases(&base, &mut out)?;
        self.non_canonical_key_cases(&base, &mut out)?;
        self.small_order_key_cases(&base, &mut out)?;
        self.mixed_order_key_cases(&base, &mut out)?;
        out.push(self.case("all zero", &[0; 32], message, &[0; 64])?);
        Ok(out)
    }

    /// S: S + kL for every k that keeps it below 2^256, the range boundary,
    /// and canonical but wrong values.
    fn s_cases(&self, base: &Base<'_>, out: &mut Vec<Value>) -> Result<(), Error>
    {
        let s = U256::from_le_bytes(&array(&base.signature[32..]));
        let l = U256::from_le_bytes(&L);
        let mut k = 1;
        let mut shifted = s.checked_add(l);
        while let Some(value) = shifted
        {
            out.push(base.with_s(self, &format!("S + {k}L"), &value.to_le_bytes())?);
            k += 1;
            shifted = value.checked_add(l);
        }
        let mut two_252 = [0u8; 32];
        two_252[31] = 0x10;
        let mut high_bit = s.to_le_bytes();
        high_bit[31] |= 0x80;
        for (label, value) in [
            ("S = L", L),
            ("S = L - 1", l.wrapping_sub(U256::ONE).to_le_bytes()),
            ("S = L + 1", l.overflowing_add(U256::ONE).0.to_le_bytes()),
            ("S = 2^252", two_252),
            ("S = 2^256 - 1", [0xff; 32]),
            ("S = 0", [0; 32]),
            ("S with bit 255 set", high_bit),
        ]
        {
            out.push(base.with_s(self, label, &value)?);
        }
        Ok(())
    }

    /// R: every non-canonical encoding, the torsion points, and R with its
    /// sign bit flipped.
    fn r_cases(&self, base: &Base<'_>, out: &mut Vec<Value>) -> Result<(), Error>
    {
        for encoding in y_at_or_above_p().into_iter().chain(x_zero_with_sign())
        {
            out.push(base.with_r(self, "R not canonical", &encoding)?);
        }
        for (i, point) in torsion().iter().enumerate()
        {
            out.push(base.with_r(self, &format!("R = torsion {i}"), &point.encode())?);
        }
        let flipped = array(&flip(&base.signature, 255));
        out.push(self.case(
            "R sign bit flipped",
            &base.public_key,
            base.message,
            &flipped,
        )?);
        Ok(())
    }

    /// A: every non-canonical encoding and a y with no x, each with the base
    /// signature and with R = O, S = 0, which a lenient decoder accepts under
    /// a key it decodes to the identity.
    fn non_canonical_key_cases(&self, base: &Base<'_>, out: &mut Vec<Value>) -> Result<(), Error>
    {
        let mut no_x = [0u8; 32];
        no_x[0] = 2;
        for encoding in y_at_or_above_p()
            .into_iter()
            .chain(x_zero_with_sign())
            .chain([no_x])
        {
            out.push(self.case("A not canonical", &encoding, base.message, &base.signature)?);
            out.push(self.case(
                "A not canonical, R = O, S = 0",
                &encoding,
                base.message,
                &identity_signature(),
            )?);
        }
        Ok(())
    }

    /// A in the torsion subgroup: the base signature, and R = O, S = 0 under
    /// a message whose challenge kills A (the cofactorless equation holds)
    /// and one whose challenge does not.
    fn small_order_key_cases(&self, base: &Base<'_>, out: &mut Vec<Value>) -> Result<(), Error>
    {
        let identity = Point::identity().encode();
        for (i, point) in torsion().iter().enumerate()
        {
            let key = point.encode();
            out.push(self.case(
                &format!("A = torsion {i}"),
                &key,
                base.message,
                &base.signature,
            )?);
            for equation in [Equation::Holds, Equation::Fails]
            {
                if i == 0 && equation == Equation::Fails
                {
                    // [k]O is the identity for every k.
                    continue;
                }
                let crafted = message_where(b"small order A", &identity, &key, point, equation)?;
                out.push(self.crafted(
                    &format!("A = torsion {i}, R = O, S = 0, equation {equation:?}"),
                    &key,
                    &crafted,
                    &identity_signature(),
                    equation.verdict(),
                )?);
            }
        }
        Ok(())
    }

    /// A of mixed order (A + T for each torsion point T): signatures made
    /// with A's private scalar, under a message whose challenge kills T (the
    /// cofactorless equation holds) and one whose challenge does not (only
    /// the cofactored equation holds).
    fn mixed_order_key_cases(&self, base: &Base<'_>, out: &mut Vec<Value>) -> Result<(), Error>
    {
        let order = scalars();
        let scalar = secret_scalar(&base.secret)?;
        let point = Point::base().mul(scalar);
        let nonce = order.reduce_le_bytes(&[0x3c; 64]);
        let nonce_point = Point::base().mul(nonce).encode();
        for (i, torsion_point) in torsion().iter().enumerate().skip(1)
        {
            let key = point.add(torsion_point).encode();
            for equation in [Equation::Holds, Equation::Fails]
            {
                let crafted = message_where(
                    b"mixed order A",
                    &nonce_point,
                    &key,
                    torsion_point,
                    equation,
                )?;
                let k = challenge(&nonce_point, &key, &crafted)?;
                let s = order.add(nonce, order.mul(k, scalar));
                let signature = array(&[nonce_point, s.to_le_bytes()].concat());
                out.push(self.crafted(
                    &format!("A + torsion {i}, equation {equation:?}"),
                    &key,
                    &crafted,
                    &signature,
                    equation.verdict(),
                )?);
            }
        }
        Ok(())
    }

    /// Every acceptable case of the vendored Wycheproof Ed25519 file (a
    /// small- or mixed-order key), which the standard lets a verifier take
    /// either way: the verdict states how a cofactorless verifier takes it.
    fn wycheproof_acceptable(&self) -> Result<Vec<Value>, Error>
    {
        let file = wycheproof::load::<eddsa::Group>(&wycheproof::ED25519)
            .map_err(|e| Error(format!("{}: {e}", wycheproof::ED25519.file)))?;
        let mut out = Vec::new();
        for group in &file.groups
        {
            for case in group
                .tests
                .iter()
                .filter(|c| c.expected() == Expected::Acceptable)
            {
                let label = format!("wycheproof tcId {}", case.id());
                let (Ok(pk), Ok(sig)) = (
                    <[u8; 32]>::try_from(group.public_key.pk.as_slice()),
                    <[u8; 64]>::try_from(case.sig.as_slice()),
                )
                else
                {
                    return Err(Error(format!(
                        "{label}: a key or signature of another size"
                    )));
                };
                out.push(self.case(&label, &pk, &case.msg, &sig)?);
            }
        }
        Ok(out)
    }
}

/// The SHA-512 file: every length from 0 to 300 bytes (the 111/112-byte
/// padding boundary and the 128- and 256-byte block boundaries among them)
/// and long messages of up to 8191 bytes, each split at random offsets, one
/// of them on the first block boundary when the message reaches it, with
/// OpenSSL's digest.
fn sha512_file() -> Result<String, Error>
{
    let mut rng = Rng::new(SHA512_SEED);
    let mut lengths: Vec<usize> = (0..=300).collect();
    lengths.extend((0..SHA512_LONG).map(|_| rng.below(8192)));
    let mut cases = Vec::new();
    for len in lengths
    {
        let data = rng.bytes(len);
        let mut cuts: Vec<usize> = (0..rng.below(4)).map(|_| rng.below(len + 1)).collect();
        if len >= 128
        {
            cuts.push(128);
        }
        cuts.sort_unstable();
        cases.push(json!({
            "message": hex::encode(&data),
            "cuts": cuts,
            "digest": hex::encode(&OpenSsl::sha512(&data)?),
        }));
    }
    Ok(vector_file(
        &[
            ("schema", json!(sha512::SCHEMA)),
            ("seed", json!(SHA512_SEED)),
            ("long", json!(SHA512_LONG)),
            ("numberOfTests", json!(cases.len())),
        ],
        &[("generated", cases)],
    ))
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_vector_file_reads_back_as_its_header_and_sections()
    {
        let text = vector_file(
            &[("schema", json!("s")), ("seed", json!(7u64))],
            &[
                ("cases", vec![json!({"a": 1u64}), json!({"a": 2u64})]),
                ("none", vec![]),
            ],
        );
        let value = json::parse(&text).unwrap();
        assert_eq!(value["schema"], "s");
        assert_eq!(value["seed"], 7u64);
        assert_eq!(value["cases"][1]["a"], 2u64);
        assert_eq!(value["none"].as_array().map(Vec::len), Some(0));
        assert_eq!(text.lines().filter(|l| l.contains("\"a\"")).count(), 2);
    }

    #[test]
    fn the_working_directory_is_new_and_private()
    {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let base = private_dir(
            &std::env::temp_dir(),
            &format!("crypto-testkit-test-{}-{nanos}", std::process::id()),
        )
        .unwrap();
        let dir = private_dir(&base, "work").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(&dir).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
        assert!(
            private_dir(&base, "work").is_err(),
            "an existing directory is refused"
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn the_non_canonical_encodings_all_fail_to_decode()
    {
        for encoding in y_at_or_above_p().into_iter().chain(x_zero_with_sign())
        {
            assert_eq!(decode(&encoding), None, "{}", hex::encode(&encoding));
        }
        assert_eq!(y_at_or_above_p().len(), 38);
    }
}
