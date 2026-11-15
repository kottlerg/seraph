// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/ed25519.rs

//! The Ed25519 reference vectors: generated signatures with their one-bit
//! corruptions, a corpus of edge cases, and the acceptable Wycheproof cases,
//! each input with the reference's verdict.
//!
//! The vectors are `vectors/reference/ed25519.json`, which the
//! [`generate`](crate::generate) module writes with OpenSSL as the
//! reference. A verdict names which check fails, in RFC 8032 order, so a
//! differential run checks the reason for a rejection as well as the
//! rejection:
//!
//! 1. S at or above the group order L (§ 5.1.7): [`Verdict::NonCanonicalS`].
//! 2. A public key that is not the canonical encoding of a point (§ 5.1.3: a
//!    y at or above p, a y with no x, or x = 0 with the sign bit set):
//!    [`Verdict::BadPublicKey`].
//! 3. The cofactorless equation `[S]B = R + [k]A`, R compared as the
//!    encoding the signature carries, as OpenSSL checks it:
//!    [`Verdict::Mismatch`].
//!
//! The cofactorless equation is the one RFC 8032 § 5.1.7 permits beside the
//! cofactored one; it accepts a subset of what the cofactored equation
//! accepts, and is the equation `shared/crypto` checks.

use std::fmt;

use json::Value;

use crate::hex;
use crate::vectors::{self, LoadError};

/// The file's name under `vectors/reference/`.
pub const FILE: &str = "ed25519.json";

/// The schema the file declares, which [`load`] checks.
pub const SCHEMA: &str = "seraph_ed25519_reference_v1";

/// The file's text.
const TEXT: &str = include_str!("../vectors/reference/ed25519.json");

/// The outcome of verifying one input: acceptance, or the first check that
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict
{
    /// The signature is valid.
    Accept,
    /// S is not below the group order L.
    NonCanonicalS,
    /// The public key is not the canonical encoding of a point.
    BadPublicKey,
    /// The verification equation does not hold.
    Mismatch,
}

impl Verdict
{
    const ALL: [Self; 4] = [
        Self::Accept,
        Self::NonCanonicalS,
        Self::BadPublicKey,
        Self::Mismatch,
    ];

    /// The verdict's name in the vector file.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::Accept => "accept",
            Self::NonCanonicalS => "nonCanonicalS",
            Self::BadPublicKey => "badPublicKey",
            Self::Mismatch => "mismatch",
        }
    }

    /// The verdict a vector file names `name`.
    fn from_name(name: &str) -> Option<Self>
    {
        Self::ALL.into_iter().find(|v| v.name() == name)
    }
}

/// One verification input, with its reference verdict.
#[derive(Clone, PartialEq, Eq)]
pub struct Input
{
    /// What the input exercises.
    pub label: String,
    /// The 32-byte public key A.
    pub public_key: [u8; 32],
    /// The message.
    pub message: Vec<u8>,
    /// The 64-byte signature R ‖ S.
    pub signature: [u8; 64],
    /// The reference's verdict.
    pub reference: Verdict,
}

impl fmt::Debug for Input
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "{}: pk {} msg {} sig {}",
            self.label,
            hex::encode(&self.public_key),
            hex::encode(&self.message),
            hex::encode(&self.signature)
        )
    }
}

impl Input
{
    fn from_json(value: &Value) -> Result<Self, LoadError>
    {
        let verdict = vectors::string(value, "verdict")?;
        Ok(Self {
            label: vectors::string(value, "label")?.to_owned(),
            public_key: vectors::fixed(value, "publicKey")?,
            message: vectors::bytes(value, "message")?,
            signature: vectors::fixed(value, "signature")?,
            reference: Verdict::from_name(verdict)
                .ok_or_else(|| LoadError::Parse(format!("unknown verdict {verdict:?}")))?,
        })
    }
}

/// The reference vectors.
#[derive(Debug, Clone)]
pub struct Vectors
{
    /// Generated rounds: each a valid signature over a random message under
    /// a random key, one-bit flips of the signature, the message and the
    /// key, the signature under a random 32-byte key, and a random 64-byte
    /// signature.
    pub generated: Vec<Input>,
    /// S + kL and the S range boundary, non-canonical and small-order R,
    /// every non-canonical public-key encoding, the torsion points as keys,
    /// and mixed-order keys with signatures crafted to satisfy or fail the
    /// cofactorless equation.
    pub edge_cases: Vec<Input>,
    /// Every case the vendored Wycheproof file marks acceptable (a small- or
    /// mixed-order key), labelled with its `tcId`.
    pub wycheproof_acceptable: Vec<Input>,
}

impl Vectors
{
    /// The reference verdict of the input `public_key`, `message`,
    /// `signature`; `None` when the vectors do not hold it.
    #[must_use]
    pub fn verdict(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> Option<Verdict>
    {
        self.generated
            .iter()
            .chain(&self.edge_cases)
            .chain(&self.wycheproof_acceptable)
            .find(|i| {
                i.public_key == *public_key && i.message == message && i.signature == *signature
            })
            .map(|i| i.reference)
    }
}

/// Load the reference vectors.
///
/// # Errors
///
/// A [`LoadError`] when the file does not parse or a case is malformed,
/// declares another schema, or holds another number of cases than it
/// declares.
pub fn load() -> Result<Vectors, LoadError>
{
    parse(TEXT)
}

fn parse(text: &str) -> Result<Vectors, LoadError>
{
    let document = vectors::document(text)?;
    let section = |key: &str| -> Result<Vec<Input>, LoadError> {
        vectors::array(&document, key)?
            .iter()
            .map(Input::from_json)
            .collect()
    };
    let loaded = Vectors {
        generated: section("generated")?,
        edge_cases: section("edgeCases")?,
        wycheproof_acceptable: section("wycheproofAcceptable")?,
    };
    let found =
        loaded.generated.len() + loaded.edge_cases.len() + loaded.wycheproof_acceptable.len();
    vectors::check_header(&document, SCHEMA, found)?;
    Ok(loaded)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn case(verdict: &str, signature: &str) -> String
    {
        format!(
            r#"{{"label": "x", "publicKey": "{}", "message": "ab", "signature": "{signature}", "verdict": "{verdict}"}}"#,
            "11".repeat(32)
        )
    }

    fn file(declared: usize, generated: &[String]) -> String
    {
        format!(
            r#"{{"schema": "{SCHEMA}", "numberOfTests": {declared}, "generated": [{}],
            "edgeCases": [], "wycheproofAcceptable": []}}"#,
            generated.join(",")
        )
    }

    #[test]
    fn parse_reads_each_case_and_finds_its_verdict()
    {
        let sig = "22".repeat(64);
        let loaded = parse(&file(
            2,
            &[case("accept", &sig), case("badPublicKey", &"33".repeat(64))],
        ))
        .unwrap();
        assert_eq!(loaded.generated[1].reference, Verdict::BadPublicKey);
        assert_eq!(
            loaded.verdict(&[0x11; 32], &[0xab], &[0x22; 64]),
            Some(Verdict::Accept)
        );
        assert_eq!(loaded.verdict(&[0x11; 32], &[0xac], &[0x22; 64]), None);
    }

    #[test]
    fn parse_refuses_a_wrong_count_an_unknown_verdict_or_a_short_signature()
    {
        let sig = "22".repeat(64);
        assert!(matches!(
            parse(&file(2, &[case("accept", &sig)])),
            Err(LoadError::Count {
                declared: 2,
                found: 1
            })
        ));
        assert!(matches!(
            parse(&file(1, &[case("maybe", &sig)])),
            Err(LoadError::Parse(_))
        ));
        assert!(matches!(
            parse(&file(1, &[case("accept", "22")])),
            Err(LoadError::Parse(_))
        ));
    }

    #[test]
    fn the_checked_in_vectors_load_and_hold_every_verdict()
    {
        let loaded = load().unwrap();
        let all: Vec<&Input> = loaded
            .generated
            .iter()
            .chain(&loaded.edge_cases)
            .chain(&loaded.wycheproof_acceptable)
            .collect();
        for verdict in Verdict::ALL
        {
            assert!(
                all.iter().any(|i| i.reference == verdict),
                "no {verdict:?} case"
            );
        }
    }
}
