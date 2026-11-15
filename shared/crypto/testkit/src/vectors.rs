// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/crypto/testkit/src/vectors.rs

//! Reading the JSON vector files: the load error, and the field readers the
//! Wycheproof loader and the reference vector loaders share.
//!
//! A file is parsed by the in-tree strict JSON reader (`shared/json`), and
//! every field a loader needs is read through a reader here, which names the
//! field in the error when it is missing or of another type.

use std::fmt;

use json::Value;

use crate::hex;

/// Why a vector file did not load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError
{
    /// The file is not well-formed for its schema (malformed JSON, a missing
    /// field, a field of another type, an unknown result, bad hex).
    Parse(String),
    /// The file declares another schema than its loader reads.
    Schema(String),
    /// A group is of another type than the schema's.
    GroupType(String),
    /// The file holds another number of cases than it declares.
    Count
    {
        /// The declared `numberOfTests`.
        declared: usize,
        /// The cases present.
        found: usize,
    },
    /// Two cases share this `tcId`.
    DuplicateId(u64),
}

impl fmt::Display for LoadError
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        match self
        {
            Self::Parse(why) => write!(f, "malformed test file: {why}"),
            Self::Schema(found) => write!(f, "unexpected schema {found}"),
            Self::GroupType(found) => write!(f, "unexpected group type {found}"),
            Self::Count { declared, found } =>
            {
                write!(f, "file declares {declared} cases and holds {found}")
            }
            Self::DuplicateId(id) => write!(f, "tcId {id} occurs twice"),
        }
    }
}

/// The JSON value of a file's text.
pub(crate) fn document(text: &str) -> Result<Value, LoadError>
{
    json::parse(text).map_err(|e| LoadError::Parse(e.to_string()))
}

/// The error for a field `key` that is missing or not `what`.
fn bad(key: &str, what: &str) -> LoadError
{
    LoadError::Parse(format!("field {key:?} is missing or not {what}"))
}

/// The member `key` of `value`.
pub(crate) fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, LoadError>
{
    value.get(key).ok_or_else(|| bad(key, "present"))
}

/// The string member `key`.
pub(crate) fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, LoadError>
{
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| bad(key, "a string"))
}

/// The non-negative integer member `key`.
pub(crate) fn integer(value: &Value, key: &str) -> Result<u64, LoadError>
{
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| bad(key, "a non-negative integer"))
}

/// The non-negative integer member `key`, as a count or an index.
pub(crate) fn count(value: &Value, key: &str) -> Result<usize, LoadError>
{
    usize::try_from(integer(value, key)?).map_err(|_| bad(key, "an integer that fits a usize"))
}

/// The array member `key`.
pub(crate) fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], LoadError>
{
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| bad(key, "an array"))
}

/// The array-of-strings member `key`.
pub(crate) fn strings(value: &Value, key: &str) -> Result<Vec<String>, LoadError>
{
    array(value, key)?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| bad(key, "an array of strings"))
        })
        .collect()
}

/// The hex string member `key`, decoded.
pub(crate) fn bytes(value: &Value, key: &str) -> Result<Vec<u8>, LoadError>
{
    let text = string(value, key)?;
    hex::decode(text).map_err(|e| LoadError::Parse(format!("field {key:?}: {e:?} in {text:?}")))
}

/// The hex string member `key`, decoded, of exactly `N` bytes.
pub(crate) fn fixed<const N: usize>(value: &Value, key: &str) -> Result<[u8; N], LoadError>
{
    <[u8; N]>::try_from(bytes(value, key)?).map_err(|_| bad(key, &format!("{N} bytes of hex")))
}

/// Check that a file declares `schema` and holds as many cases as its
/// `numberOfTests`.
pub(crate) fn check_header(document: &Value, schema: &str, found: usize) -> Result<(), LoadError>
{
    let declared_schema = string(document, "schema")?;
    if declared_schema != schema
    {
        return Err(LoadError::Schema(declared_schema.to_owned()));
    }
    let declared = count(document, "numberOfTests")?;
    if declared != found
    {
        return Err(LoadError::Count { declared, found });
    }
    Ok(())
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_field_reader_names_a_missing_or_mistyped_field()
    {
        let value = document(r#"{"s": "ab", "n": 3, "a": ["x"], "neg": -1}"#).unwrap();
        assert_eq!(string(&value, "s"), Ok("ab"));
        assert_eq!(count(&value, "n"), Ok(3));
        assert_eq!(strings(&value, "a"), Ok(vec!["x".to_owned()]));
        assert_eq!(fixed::<1>(&value, "s"), Ok([0xab]));
        for error in [
            string(&value, "n").map(|_| ()),
            count(&value, "neg").map(|_| ()),
            array(&value, "missing").map(|_| ()),
            fixed::<2>(&value, "s").map(|_| ()),
        ]
        {
            assert!(matches!(error, Err(LoadError::Parse(_))), "{error:?}");
        }
        let LoadError::Parse(why) = string(&value, "n").unwrap_err()
        else
        {
            unreachable!()
        };
        assert!(why.contains("\"n\""), "{why}");
    }

    #[test]
    fn the_header_check_refuses_another_schema_or_count()
    {
        let value = document(r#"{"schema": "s", "numberOfTests": 2}"#).unwrap();
        assert_eq!(check_header(&value, "s", 2), Ok(()));
        assert_eq!(
            check_header(&value, "t", 2),
            Err(LoadError::Schema("s".into()))
        );
        assert_eq!(
            check_header(&value, "s", 1),
            Err(LoadError::Count {
                declared: 2,
                found: 1
            })
        );
        assert!(matches!(document("{"), Err(LoadError::Parse(_))));
    }
}
