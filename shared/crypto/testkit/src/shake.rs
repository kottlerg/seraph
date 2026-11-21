// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/shake.rs

//! The SHAKE128 and SHAKE256 reference vectors: messages of every length
//! around the rate (the padding and block boundaries), and longer generated
//! messages, each with the points at which an incremental absorber is fed,
//! an output length, the points at which an incremental reader splits the
//! output, and the reference output.
//!
//! The vectors are `vectors/reference/shake.json`, which the
//! [`generate`](crate::generate) module writes with OpenSSL as the
//! reference.

use std::fmt;

use json::Value;

use crate::hex;
use crate::vectors::{self, LoadError};

/// The file's name under `vectors/reference/`.
pub const FILE: &str = "shake.json";

/// The schema the file declares, which [`load`] checks.
pub const SCHEMA: &str = "seraph_shake_reference_v1";

/// The file's text.
const TEXT: &str = include_str!("../vectors/reference/shake.json");

/// The extendable-output function of a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Function
{
    /// SHAKE128 (FIPS 202), rate 168 bytes.
    Shake128,
    /// SHAKE256 (FIPS 202), rate 136 bytes.
    Shake256,
}

impl Function
{
    /// Both functions.
    pub const ALL: [Self; 2] = [Self::Shake128, Self::Shake256];

    /// The function's name in the vector file.
    #[must_use]
    pub const fn name(self) -> &'static str
    {
        match self
        {
            Self::Shake128 => "SHAKE128",
            Self::Shake256 => "SHAKE256",
        }
    }

    /// The rate in bytes: the block size the sponge absorbs and squeezes.
    #[must_use]
    pub const fn rate(self) -> usize
    {
        match self
        {
            Self::Shake128 => 168,
            Self::Shake256 => 136,
        }
    }

    fn from_json(value: &Value) -> Result<Self, LoadError>
    {
        let name = vectors::string(value, "function")?;
        Self::ALL
            .into_iter()
            .find(|f| f.name() == name)
            .ok_or_else(|| LoadError::Parse(format!("unknown function {name:?}")))
    }
}

/// One message and output length, the split points of an incremental absorb
/// and read, and the reference output.
#[derive(Clone, PartialEq, Eq)]
pub struct Input
{
    /// The function.
    pub function: Function,
    /// The message.
    pub data: Vec<u8>,
    /// The offsets at which the message is split into `update` calls,
    /// ascending, each at most `data.len()`.
    pub cuts: Vec<usize>,
    /// The offsets at which the output is split into reads, ascending, each
    /// at most `output.len()`.
    pub output_cuts: Vec<usize>,
    /// The reference output, of the case's output length (at least one
    /// byte).
    pub output: Vec<u8>,
}

impl fmt::Debug for Input
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "{} of {} bytes to {} bytes, cuts {:?}, output cuts {:?}: {}",
            self.function.name(),
            self.data.len(),
            self.output.len(),
            self.cuts,
            self.output_cuts,
            hex::encode(&self.data)
        )
    }
}

impl Input
{
    fn from_json(value: &Value) -> Result<Self, LoadError>
    {
        let data = vectors::bytes(value, "message")?;
        let output = vectors::bytes(value, "output")?;
        if output.is_empty()
        {
            return Err(LoadError::Parse("an empty output".into()));
        }
        Ok(Self {
            function: Function::from_json(value)?,
            cuts: vectors::offsets(value, "cuts", data.len())?,
            output_cuts: vectors::offsets(value, "outputCuts", output.len())?,
            data,
            output,
        })
    }

    /// The message split at `cuts`: the pieces an incremental absorber is
    /// fed, empty pieces included.
    #[must_use]
    pub fn pieces(&self) -> Vec<&[u8]>
    {
        vectors::pieces(&self.data, &self.cuts)
    }

    /// The lengths of the successive reads that produce the output, split
    /// at `output_cuts`, empty reads included.
    #[must_use]
    pub fn read_lengths(&self) -> Vec<usize>
    {
        vectors::pieces(&self.output, &self.output_cuts)
            .iter()
            .map(|piece| piece.len())
            .collect()
    }
}

/// Load the reference vectors: for each function, every message length from
/// 0 to one byte past the rate, then longer messages of several blocks; each
/// with a random output length of up to two blocks and more, and its message
/// and output split at random offsets, one of them on the first block
/// boundary when the message or the output reaches it.
///
/// # Errors
///
/// A [`LoadError`] when the file does not parse or a case is malformed (an
/// unknown function, an empty output, or cuts out of order or past their
/// data among them), declares another schema, or holds another number of
/// cases than it declares.
pub fn load() -> Result<Vec<Input>, LoadError>
{
    parse(TEXT)
}

fn parse(text: &str) -> Result<Vec<Input>, LoadError>
{
    let document = vectors::document(text)?;
    let cases = vectors::array(&document, "generated")?
        .iter()
        .map(Input::from_json)
        .collect::<Result<Vec<_>, _>>()?;
    vectors::check_header(&document, SCHEMA, cases.len())?;
    Ok(cases)
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn file(function: &str, output: &str, output_cuts: &str) -> String
    {
        format!(
            r#"{{"schema": "{SCHEMA}", "numberOfTests": 1, "generated": [
            {{"function": "{function}", "message": "616263", "cuts": [1],
              "outputCuts": {output_cuts}, "output": "{output}"}}]}}"#
        )
    }

    #[test]
    fn parse_reads_a_case_and_its_read_lengths()
    {
        let loaded = parse(&file("SHAKE256", "000102", "[0, 2]")).unwrap();
        let input = &loaded[0];
        assert_eq!(input.function, Function::Shake256);
        assert_eq!(input.pieces(), [&b"a"[..], b"bc"]);
        assert_eq!(input.read_lengths(), [0, 2, 1]);
    }

    #[test]
    fn parse_refuses_an_unknown_function_an_empty_output_or_bad_output_cuts()
    {
        for text in [
            file("SHAKE512", "00", "[]"),
            file("SHAKE128", "", "[]"),
            file("SHAKE128", "0001", "[3]"),
            file("SHAKE128", "0001", "[1, 0]"),
        ]
        {
            assert!(matches!(parse(&text), Err(LoadError::Parse(_))), "{text}");
        }
    }
}
