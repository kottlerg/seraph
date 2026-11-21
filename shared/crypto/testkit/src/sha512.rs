// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/sha512.rs

//! The SHA-512 reference vectors: messages of every length around the
//! padding and block boundaries, and longer generated messages, each with
//! the points at which an incremental hasher is fed and the reference
//! digest.
//!
//! The vectors are `vectors/reference/sha512.json`, which the
//! [`generate`](crate::generate) module writes with OpenSSL as the
//! reference.

use std::fmt;

use json::Value;

use crate::hex;
use crate::vectors::{self, LoadError};

/// The file's name under `vectors/reference/`.
pub const FILE: &str = "sha512.json";

/// The schema the file declares, which [`load`] checks.
pub const SCHEMA: &str = "seraph_sha512_reference_v1";

/// The file's text.
const TEXT: &str = include_str!("../vectors/reference/sha512.json");

/// One message, the ascending offsets at which an incremental hasher splits
/// it into `update` calls, and its reference digest.
#[derive(Clone, PartialEq, Eq)]
pub struct Input
{
    /// The message.
    pub data: Vec<u8>,
    /// The split offsets, ascending, each at most `data.len()`.
    pub cuts: Vec<usize>,
    /// The reference SHA-512 digest of the message.
    pub digest: [u8; 64],
}

impl fmt::Debug for Input
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        write!(
            f,
            "{} bytes, cuts {:?}: {}",
            self.data.len(),
            self.cuts,
            hex::encode(&self.data)
        )
    }
}

impl Input
{
    fn from_json(value: &Value) -> Result<Self, LoadError>
    {
        let data = vectors::bytes(value, "message")?;
        let cuts = vectors::offsets(value, "cuts", data.len())?;
        Ok(Self {
            data,
            cuts,
            digest: vectors::fixed(value, "digest")?,
        })
    }

    /// The message split at `cuts`: the pieces an incremental hasher is fed,
    /// empty pieces included.
    #[must_use]
    pub fn pieces(&self) -> Vec<&[u8]>
    {
        vectors::pieces(&self.data, &self.cuts)
    }
}

/// Load the reference vectors: every length from 0 to 300 bytes (the
/// 111/112-byte padding boundary and the 128- and 256-byte block boundaries
/// among them), then longer messages of several blocks; each split at random
/// offsets, one of them on the first block boundary when the message reaches
/// it.
///
/// # Errors
///
/// A [`LoadError`] when the file does not parse or a case is malformed (cuts
/// out of order or past the message among them), declares another schema,
/// or holds another number of cases than it declares.
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

    #[test]
    fn pieces_cover_the_message_in_order_with_empty_pieces_kept()
    {
        let input = Input {
            data: b"abcdef".to_vec(),
            cuts: vec![0, 2, 2, 6],
            digest: [0; 64],
        };
        let pieces: Vec<&[u8]> = input.pieces();
        assert_eq!(pieces, [&b""[..], b"ab", b"", b"cdef", b""]);
    }

    fn file(cuts: &str) -> String
    {
        format!(
            r#"{{"schema": "{SCHEMA}", "numberOfTests": 1, "generated": [
            {{"message": "616263", "cuts": {cuts}, "digest": "{}"}}]}}"#,
            "00".repeat(64)
        )
    }

    #[test]
    fn parse_reads_a_case_and_refuses_cuts_out_of_order_or_past_the_message()
    {
        let loaded = parse(&file("[1, 3]")).unwrap();
        assert_eq!(
            (loaded[0].data.as_slice(), loaded[0].cuts.as_slice()),
            (&b"abc"[..], &[1, 3][..])
        );
        for bad in ["[2, 1]", "[4]", "[-1]"]
        {
            assert!(
                matches!(parse(&file(bad)), Err(LoadError::Parse(_))),
                "{bad}"
            );
        }
    }
}
