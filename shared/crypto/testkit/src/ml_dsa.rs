// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/ml_dsa.rs

//! The ML-DSA-65 reference vectors: signing inputs, each a seed, a message
//! and a context string with the public key and the deterministic signature
//! the reference derives; and verification inputs, each a signing input with
//! one edit (a one-bit flip, or bytes crafted to break one check) and the
//! reference's verdict.
//!
//! The vectors are `vectors/reference/ml_dsa_65.json`, which the
//! [`generate`](crate::generate) module writes with OpenSSL as the
//! reference. A verdict names which check fails, in FIPS 204 Algorithm 8
//! order, so a differential run checks the reason for a rejection as well as
//! the rejection:
//!
//! 1. A hint section that is not the canonical encoding of a hint vector
//!    (`HintBitUnpack`, Algorithm 21): [`Verdict::MalformedHint`].
//! 2. A coefficient of z at or beyond GAMMA1 - BETA in magnitude:
//!    [`Verdict::ZOutOfRange`].
//! 3. The recomputed commitment hash differing from the signature's:
//!    [`Verdict::Mismatch`].

use std::fmt;

use json::Value;

use crate::vectors::{self, LoadError};

/// The file's name under `vectors/reference/`.
pub const FILE: &str = "ml_dsa_65.json";

/// The schema the file declares, which [`load`] checks.
pub const SCHEMA: &str = "seraph_ml_dsa_65_reference_v1";

/// The file's text.
const TEXT: &str = include_str!("../vectors/reference/ml_dsa_65.json");

/// The length of an ML-DSA-65 public key (FIPS 204 Table 2).
pub const PUBLIC_KEY_LEN: usize = 1952;

/// The length of an ML-DSA-65 signature (FIPS 204 Table 2).
pub const SIGNATURE_LEN: usize = 3309;

/// The longest context string (FIPS 204 Algorithm 2).
pub const MAX_CONTEXT_LEN: usize = 255;

/// The outcome of verifying one input: acceptance, or the first check that
/// failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict
{
    /// The signature is valid.
    Accept,
    /// The hint section is not canonical.
    MalformedHint,
    /// z exceeds its norm bound.
    ZOutOfRange,
    /// The commitment hash does not match.
    Mismatch,
}

impl Verdict
{
    const ALL: [Self; 4] = [
        Self::Accept,
        Self::MalformedHint,
        Self::ZOutOfRange,
        Self::Mismatch,
    ];

    /// The verdict's name in the vector file.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::Accept => "accept",
            Self::MalformedHint => "malformedHint",
            Self::ZOutOfRange => "zOutOfRange",
            Self::Mismatch => "mismatch",
        }
    }

    fn from_json(value: &Value) -> Result<Self, LoadError>
    {
        let name = vectors::string(value, "verdict")?;
        Self::ALL
            .into_iter()
            .find(|v| v.name() == name)
            .ok_or_else(|| LoadError::Parse(format!("unknown verdict {name:?}")))
    }
}

/// The input an edit changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field
{
    /// The public key.
    PublicKey,
    /// The message.
    Message,
    /// The context string.
    Context,
    /// The signature.
    Signature,
}

impl Field
{
    const ALL: [Self; 4] = [
        Self::PublicKey,
        Self::Message,
        Self::Context,
        Self::Signature,
    ];

    /// The field's name in the vector file.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::PublicKey => "publicKey",
            Self::Message => "message",
            Self::Context => "context",
            Self::Signature => "signature",
        }
    }
}

/// A seed, a message and a context string, with the reference's public key
/// and deterministic signature.
#[derive(Clone, PartialEq, Eq)]
pub struct SignInput
{
    /// The 32-byte key-generation seed (FIPS 204 Algorithm 1's xi).
    pub seed: [u8; 32],
    /// The message.
    pub message: Vec<u8>,
    /// The context string, at most [`MAX_CONTEXT_LEN`] bytes.
    pub context: Vec<u8>,
    /// The public key the reference derives from the seed,
    /// [`PUBLIC_KEY_LEN`] bytes.
    pub public_key: Vec<u8>,
    /// The reference's deterministic signature, [`SIGNATURE_LEN`] bytes.
    pub signature: Vec<u8>,
}

impl fmt::Debug for SignInput
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "seed {}, {}-byte message, {}-byte context",
            crate::hex::encode(&self.seed),
            self.message.len(),
            self.context.len()
        )
    }
}

impl SignInput
{
    fn from_json(value: &Value) -> Result<Self, LoadError>
    {
        let input = Self {
            seed: vectors::fixed(value, "seed")?,
            message: vectors::bytes(value, "message")?,
            context: vectors::bytes(value, "context")?,
            public_key: vectors::bytes(value, "publicKey")?,
            signature: vectors::bytes(value, "signature")?,
        };
        if input.public_key.len() != PUBLIC_KEY_LEN
            || input.signature.len() != SIGNATURE_LEN
            || input.context.len() > MAX_CONTEXT_LEN
        {
            return Err(LoadError::Parse(format!(
                "a {}-byte public key, {}-byte signature or {}-byte context",
                input.public_key.len(),
                input.signature.len(),
                input.context.len()
            )));
        }
        Ok(input)
    }

    /// The input's `field`.
    #[must_use]
    pub fn field(&self, field: Field) -> &[u8]
    {
        match field
        {
            Field::PublicKey => &self.public_key,
            Field::Message => &self.message,
            Field::Context => &self.context,
            Field::Signature => &self.signature,
        }
    }

    fn field_mut(&mut self, field: Field) -> &mut Vec<u8>
    {
        match field
        {
            Field::PublicKey => &mut self.public_key,
            Field::Message => &mut self.message,
            Field::Context => &mut self.context,
            Field::Signature => &mut self.signature,
        }
    }
}

/// A verification input: a signing input's public key, message, context
/// and signature with at most one edit, and the reference's verdict.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyInput
{
    /// What the edit is.
    pub comment: String,
    /// The index of the signing input the case edits.
    pub signing: usize,
    /// The edited input.
    pub input: SignInput,
    /// The reference's verdict.
    pub verdict: Verdict,
}

impl fmt::Debug for VerifyInput
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "signing input {}, {} ({})",
            self.signing,
            self.comment,
            self.verdict.name()
        )
    }
}

/// An edit: `bytes` written over `field` from `offset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit
{
    /// The input it changes.
    pub field: Field,
    /// The first byte it overwrites.
    pub offset: usize,
    /// The bytes written there.
    pub bytes: Vec<u8>,
}

impl Edit
{
    fn from_json(value: &Value) -> Result<Self, LoadError>
    {
        let name = vectors::string(value, "field")?;
        Ok(Self {
            field: Field::ALL
                .into_iter()
                .find(|f| f.name() == name)
                .ok_or_else(|| LoadError::Parse(format!("unknown field {name:?}")))?,
            offset: vectors::count(value, "offset")?,
            bytes: vectors::bytes(value, "bytes")?,
        })
    }

    /// `input` with the edit applied.
    ///
    /// # Errors
    ///
    /// [`LoadError::Parse`] when the edit is empty or reaches past its
    /// field.
    pub fn apply(&self, input: &SignInput) -> Result<SignInput, LoadError>
    {
        let mut edited = input.clone();
        let target = edited
            .field_mut(self.field)
            .get_mut(self.offset..)
            .and_then(|tail| tail.get_mut(..self.bytes.len()))
            .filter(|target| !target.is_empty())
            .ok_or_else(|| LoadError::Parse(format!("edit {self:?} is empty or past its field")))?;
        target.copy_from_slice(&self.bytes);
        Ok(edited)
    }
}

/// The loaded vectors.
#[derive(Debug, Clone)]
pub struct Vectors
{
    /// The signing inputs.
    pub signing: Vec<SignInput>,
    /// The verification inputs.
    pub verification: Vec<VerifyInput>,
}

/// Load the reference vectors: signing inputs from fixed seeds over messages
/// and context strings of random lengths (empty and the longest context
/// among them); and for each, its valid signature, one-bit flips of the
/// signature, the public key, the message and the context, a coefficient of
/// z at and inside its norm bound, and hint sections broken in each way
/// `HintBitUnpack` refuses.
///
/// # Errors
///
/// A [`LoadError`] when the file does not parse or a case is malformed (a
/// key or signature of another length, a context over
/// [`MAX_CONTEXT_LEN`] bytes, an edit past its field or of a signing input
/// the file lacks among them), declares another schema, or holds another
/// number of cases than it declares.
pub fn load() -> Result<Vectors, LoadError>
{
    parse(TEXT)
}

fn parse(text: &str) -> Result<Vectors, LoadError>
{
    let document = vectors::document(text)?;
    let signing = vectors::array(&document, "signing")?
        .iter()
        .map(SignInput::from_json)
        .collect::<Result<Vec<_>, _>>()?;
    let verification = vectors::array(&document, "verification")?
        .iter()
        .map(|case| {
            let index = vectors::count(case, "signing")?;
            let base = signing
                .get(index)
                .ok_or_else(|| LoadError::Parse(format!("no signing input {index}")))?;
            let input = match case.get("edit")
            {
                Some(edit) => Edit::from_json(edit)?.apply(base)?,
                None => base.clone(),
            };
            Ok(VerifyInput {
                comment: vectors::string(case, "comment")?.to_owned(),
                signing: index,
                input,
                verdict: Verdict::from_json(case)?,
            })
        })
        .collect::<Result<Vec<_>, LoadError>>()?;
    vectors::check_header(&document, SCHEMA, signing.len() + verification.len())?;
    Ok(Vectors {
        signing,
        verification,
    })
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn file(signing_index: usize, edit: &str, context: &str) -> String
    {
        format!(
            r#"{{"schema": "{SCHEMA}", "numberOfTests": 2,
            "signing": [{{"seed": "{}", "message": "6162", "context": "{context}",
              "publicKey": "{}", "signature": "{}"}}],
            "verification": [{{"signing": {signing_index}, "comment": "c",
              {edit} "verdict": "mismatch"}}]}}"#,
            "00".repeat(32),
            "00".repeat(PUBLIC_KEY_LEN),
            "00".repeat(SIGNATURE_LEN)
        )
    }

    #[test]
    fn parse_applies_each_edit_to_its_signing_input()
    {
        let loaded = parse(&file(
            0,
            r#""edit": {"field": "message", "offset": 1, "bytes": "ff"},"#,
            "",
        ))
        .unwrap();
        let case = &loaded.verification[0];
        assert_eq!(case.input.message, [0x61, 0xff]);
        assert_eq!(case.input.signature, loaded.signing[0].signature);
        assert_eq!(case.verdict, Verdict::Mismatch);
        let unedited = parse(&file(0, "", "")).unwrap();
        assert_eq!(unedited.verification[0].input, unedited.signing[0]);
    }

    #[test]
    fn parse_refuses_an_edit_past_its_field_a_missing_input_or_a_long_context()
    {
        for text in [
            file(
                0,
                r#""edit": {"field": "message", "offset": 1, "bytes": "ffff"},"#,
                "",
            ),
            file(
                0,
                r#""edit": {"field": "context", "offset": 0, "bytes": "ff"},"#,
                "",
            ),
            file(
                0,
                r#""edit": {"field": "message", "offset": 0, "bytes": ""},"#,
                "",
            ),
            file(
                0,
                r#""edit": {"field": "seed", "offset": 0, "bytes": "ff"},"#,
                "",
            ),
            file(1, "", ""),
            file(0, "", &"00".repeat(MAX_CONTEXT_LEN + 1)),
        ]
        {
            assert!(matches!(parse(&text), Err(LoadError::Parse(_))));
        }
    }
}
