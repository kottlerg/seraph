// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/json/src/lib.rs

//! A strict JSON value (RFC 8259): the parser of untrusted text, the value it
//! yields, and the compact and indented printers.
//!
//! [`parse`] reads exactly the grammar of RFC 8259 and refuses everything else,
//! within [`MAX_DEPTH`] and [`MAX_LEN`], and refuses an object that names a key
//! twice. A [`Value`] prints compactly through `Display` and indented through
//! [`Value::to_string_pretty`]; [`json!`] builds one from Rust expressions.
//!
//! `no_std` with `alloc`, no dependency. In-tree code replaces a registry crate
//! here (`docs/coding-standards.md` § Dependencies).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod parse;
mod print;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::{Index, IndexMut};

pub use parse::{Error, ErrorKind, MAX_DEPTH, MAX_LEN, parse};

/// The members of an object, by name, in name order.
pub type Map = BTreeMap<String, Value>;

/// A JSON value.
#[derive(Clone, Debug, PartialEq)]
pub enum Value
{
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A number.
    Number(Number),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<Value>),
    /// An object.
    Object(Map),
}

/// A JSON number, held as the first of an unsigned 64-bit integer, a negative
/// 64-bit integer, and a finite 64-bit float that holds it: an integer the
/// two integer forms cannot hold, and every number written with a fraction or
/// an exponent, is a float.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Number(Repr);

#[derive(Clone, Copy, Debug, PartialEq)]
enum Repr
{
    /// Zero or above.
    Unsigned(u64),
    /// Below zero.
    Negative(i64),
    /// Finite.
    Float(f64),
}

impl Number
{
    /// The number `value`; `None` when it is not finite, which JSON cannot
    /// write.
    #[must_use]
    pub fn from_f64(value: f64) -> Option<Self>
    {
        value.is_finite().then_some(Self(Repr::Float(value)))
    }

    /// The number as a `u64`, when it is an integer that fits one.
    #[must_use]
    pub const fn as_u64(self) -> Option<u64>
    {
        match self.0
        {
            Repr::Unsigned(n) => Some(n),
            Repr::Negative(_) | Repr::Float(_) => None,
        }
    }

    /// The number as an `i64`, when it is an integer that fits one.
    #[must_use]
    pub fn as_i64(self) -> Option<i64>
    {
        match self.0
        {
            Repr::Unsigned(n) => i64::try_from(n).ok(),
            Repr::Negative(n) => Some(n),
            Repr::Float(_) => None,
        }
    }

    /// The number as an `f64`, rounded to the nearest one for an integer
    /// above 2^53 in magnitude.
    #[must_use]
    #[expect(
        clippy::cast_precision_loss,
        reason = "an f64 reading of an integer rounds it, as JSON readers do"
    )]
    pub const fn as_f64(self) -> f64
    {
        match self.0
        {
            Repr::Unsigned(n) => n as f64,
            Repr::Negative(n) => n as f64,
            Repr::Float(f) => f,
        }
    }
}

impl From<u64> for Number
{
    fn from(n: u64) -> Self
    {
        Self(Repr::Unsigned(n))
    }
}

impl From<i64> for Number
{
    fn from(n: i64) -> Self
    {
        if n < 0
        {
            Self(Repr::Negative(n))
        }
        else
        {
            Self(Repr::Unsigned(n.unsigned_abs()))
        }
    }
}

/// What [`Index`] yields for a member or an element the value does not hold.
static NULL: Value = Value::Null;

impl Value
{
    /// The member `key` of an object; `None` when the value is not an object
    /// or has no such member.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self>
    {
        self.as_object()?.get(key)
    }

    /// The member `key` of an object, mutably; `None` as for [`Value::get`].
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Self>
    {
        self.as_object_mut()?.get_mut(key)
    }

    /// The value an RFC 6901 JSON pointer names: `""` is the whole value, and
    /// each `/token` names an object's member, or an array's element by its
    /// decimal index (`0` or a digit string with no leading zero). `~1` in a
    /// token stands for `/` and `~0` for `~`. `None` when the pointer is
    /// malformed or names nothing.
    #[must_use]
    pub fn pointer(&self, pointer: &str) -> Option<&Self>
    {
        if pointer.is_empty()
        {
            return Some(self);
        }
        let mut at = self;
        for token in pointer.strip_prefix('/')?.split('/')
        {
            let token = token.replace("~1", "/").replace("~0", "~");
            at = match at
            {
                Self::Object(members) => members.get(&token)?,
                Self::Array(items) => items.get(array_index(&token)?)?,
                Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) => return None,
            };
        }
        Some(at)
    }

    /// The value, leaving `null` in its place.
    #[must_use]
    pub const fn take(&mut self) -> Self
    {
        core::mem::replace(self, Self::Null)
    }

    /// The string, when the value is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str>
    {
        match self
        {
            Self::String(text) => Some(text),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    /// The boolean, when the value is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool>
    {
        match self
        {
            Self::Bool(b) => Some(*b),
            Self::Null | Self::Number(_) | Self::String(_) | Self::Array(_) | Self::Object(_) =>
            {
                None
            }
        }
    }

    /// The number, when the value is one.
    #[must_use]
    pub const fn as_number(&self) -> Option<Number>
    {
        match self
        {
            Self::Number(n) => Some(*n),
            Self::Null | Self::Bool(_) | Self::String(_) | Self::Array(_) | Self::Object(_) => None,
        }
    }

    /// The number as a `u64`, as [`Number::as_u64`] reads it.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64>
    {
        self.as_number()?.as_u64()
    }

    /// The number as an `i64`, as [`Number::as_i64`] reads it.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64>
    {
        self.as_number()?.as_i64()
    }

    /// The number as an `f64`, as [`Number::as_f64`] reads it.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64>
    {
        Some(self.as_number()?.as_f64())
    }

    /// The elements, when the value is an array.
    #[must_use]
    pub const fn as_array(&self) -> Option<&Vec<Self>>
    {
        match self
        {
            Self::Array(items) => Some(items),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Object(_) =>
            {
                None
            }
        }
    }

    /// The elements, mutably, when the value is an array.
    pub const fn as_array_mut(&mut self) -> Option<&mut Vec<Self>>
    {
        match self
        {
            Self::Array(items) => Some(items),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Object(_) =>
            {
                None
            }
        }
    }

    /// The members, when the value is an object.
    #[must_use]
    pub const fn as_object(&self) -> Option<&Map>
    {
        match self
        {
            Self::Object(members) => Some(members),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }

    /// The members, mutably, when the value is an object.
    pub const fn as_object_mut(&mut self) -> Option<&mut Map>
    {
        match self
        {
            Self::Object(members) => Some(members),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => None,
        }
    }

    /// Whether the value is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool
    {
        matches!(self, Self::Null)
    }

    /// Whether the value is `true` or `false`.
    #[must_use]
    pub const fn is_boolean(&self) -> bool
    {
        matches!(self, Self::Bool(_))
    }

    /// Whether the value is a number.
    #[must_use]
    pub const fn is_number(&self) -> bool
    {
        matches!(self, Self::Number(_))
    }

    /// Whether the value is a string.
    #[must_use]
    pub const fn is_string(&self) -> bool
    {
        matches!(self, Self::String(_))
    }

    /// Whether the value is an array.
    #[must_use]
    pub const fn is_array(&self) -> bool
    {
        matches!(self, Self::Array(_))
    }

    /// Whether the value is an object.
    #[must_use]
    pub const fn is_object(&self) -> bool
    {
        matches!(self, Self::Object(_))
    }
}

/// The array index a pointer token writes: `0`, or decimal digits with no
/// leading zero.
fn array_index(token: &str) -> Option<usize>
{
    let digits = token.bytes().all(|b| b.is_ascii_digit());
    let leading_zero = token.len() > 1 && token.starts_with('0');
    if !digits || leading_zero
    {
        return None;
    }
    token.parse().ok()
}

impl Index<&str> for Value
{
    type Output = Self;

    /// The member `index`, or `null` when the value is not an object or has
    /// no such member.
    fn index(&self, index: &str) -> &Self
    {
        self.get(index).unwrap_or(&NULL)
    }
}

impl IndexMut<&str> for Value
{
    /// The member `index`, mutably, inserted as `null` when the object has no
    /// such member; a value that is not an object is first replaced by an
    /// empty one, so an assignment through an index always lands.
    fn index_mut(&mut self, index: &str) -> &mut Self
    {
        if !self.is_object()
        {
            *self = Self::Object(Map::new());
        }
        match self
        {
            Self::Object(members) => members.entry(index.into()).or_insert(Self::Null),
            Self::Null | Self::Bool(_) | Self::Number(_) | Self::String(_) | Self::Array(_) => self,
        }
    }
}

impl Index<usize> for Value
{
    type Output = Self;

    /// The element at `index`, or `null` when the value is not an array or
    /// is shorter.
    fn index(&self, index: usize) -> &Self
    {
        self.as_array()
            .and_then(|items| items.get(index))
            .unwrap_or(&NULL)
    }
}

impl PartialEq<str> for Value
{
    fn eq(&self, other: &str) -> bool
    {
        self.as_str() == Some(other)
    }
}

impl PartialEq<&str> for Value
{
    fn eq(&self, other: &&str) -> bool
    {
        self.as_str() == Some(*other)
    }
}

impl PartialEq<String> for Value
{
    fn eq(&self, other: &String) -> bool
    {
        self.as_str() == Some(other.as_str())
    }
}

impl PartialEq<bool> for Value
{
    fn eq(&self, other: &bool) -> bool
    {
        self.as_bool() == Some(*other)
    }
}

/// `PartialEq` with integer types: equal when the value is a number of the
/// same integer value.
macro_rules! integer_eq {
    ($($int:ty),*) => {
        $(
            impl PartialEq<$int> for Value
            {
                fn eq(&self, other: &$int) -> bool
                {
                    self.as_number().is_some_and(|n| {
                        let same = |n: i128| i128::try_from(*other).ok() == Some(n);
                        match n.0
                        {
                            Repr::Unsigned(n) => same(i128::from(n)),
                            Repr::Negative(n) => same(i128::from(n)),
                            Repr::Float(_) => false,
                        }
                    })
                }
            }
        )*
    };
}

integer_eq!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

impl From<&str> for Value
{
    fn from(text: &str) -> Self
    {
        Self::String(text.into())
    }
}

impl From<String> for Value
{
    fn from(text: String) -> Self
    {
        Self::String(text)
    }
}

impl From<Vec<Self>> for Value
{
    fn from(items: Vec<Self>) -> Self
    {
        Self::Array(items)
    }
}

impl From<Map> for Value
{
    fn from(members: Map) -> Self
    {
        Self::Object(members)
    }
}

/// A Rust value's JSON form, read through a reference so that [`json!`] leaves
/// what it is given to its owner.
pub trait ToJson
{
    /// The value's JSON form.
    fn to_json(&self) -> Value;
}

impl ToJson for Value
{
    fn to_json(&self) -> Value
    {
        self.clone()
    }
}

impl ToJson for str
{
    fn to_json(&self) -> Value
    {
        Value::String(self.into())
    }
}

impl ToJson for String
{
    fn to_json(&self) -> Value
    {
        Value::String(self.clone())
    }
}

impl ToJson for bool
{
    fn to_json(&self) -> Value
    {
        Value::Bool(*self)
    }
}

impl ToJson for f64
{
    /// The number; `null` for a value that is not finite, which JSON cannot
    /// write.
    fn to_json(&self) -> Value
    {
        Number::from_f64(*self).map_or(Value::Null, Value::Number)
    }
}

/// [`ToJson`] for integer types that convert to `u64` or `i64` without loss.
macro_rules! integer_to_json {
    ($wide:ty: $($narrow:ty),*) => {
        $(
            impl ToJson for $narrow
            {
                fn to_json(&self) -> Value
                {
                    Value::Number(Number::from(<$wide>::from(*self)))
                }
            }
        )*
    };
}

integer_to_json!(u64: u8, u16, u32, u64);
integer_to_json!(i64: i8, i16, i32, i64);

impl ToJson for usize
{
    /// The number; every host xtask and its tests run on has a `usize` of at
    /// most 64 bits, and a wider one saturates.
    fn to_json(&self) -> Value
    {
        Value::Number(Number::from(u64::try_from(*self).unwrap_or(u64::MAX)))
    }
}

impl<T: ToJson + ?Sized> ToJson for &T
{
    fn to_json(&self) -> Value
    {
        (**self).to_json()
    }
}

impl<T: ToJson> ToJson for Option<T>
{
    /// The value, or `null` for `None`.
    fn to_json(&self) -> Value
    {
        self.as_ref().map_or(Value::Null, ToJson::to_json)
    }
}

impl<T: ToJson> ToJson for [T]
{
    fn to_json(&self) -> Value
    {
        Value::Array(self.iter().map(ToJson::to_json).collect())
    }
}

impl<T: ToJson, const N: usize> ToJson for [T; N]
{
    fn to_json(&self) -> Value
    {
        self.as_slice().to_json()
    }
}

impl<T: ToJson> ToJson for Vec<T>
{
    fn to_json(&self) -> Value
    {
        self.as_slice().to_json()
    }
}

impl<T: ToJson> ToJson for BTreeMap<String, T>
{
    fn to_json(&self) -> Value
    {
        Value::Object(
            self.iter()
                .map(|(key, value)| (key.clone(), value.to_json()))
                .collect(),
        )
    }
}

/// What [`json!`] expands to, which the calling crate may not name itself.
#[doc(hidden)]
pub mod __private
{
    pub use alloc::string::String;
    pub use alloc::vec;
    pub use alloc::vec::Vec;
}

/// A [`Value`] written as JSON text with Rust expressions in it.
///
/// `null`, an array `[...]` and an object `{ "key": value, ... }` are written
/// as in JSON, with string literal keys and an optional trailing comma. Any
/// other value is a Rust expression, converted by [`ToJson`] through a
/// reference, so the expression keeps its value. A key written twice keeps
/// its last value.
#[macro_export]
macro_rules! json {
    // ── Whole values ─────────────────────────────────────────────────────────
    (null) => {
        $crate::Value::Null
    };
    ([]) => {
        $crate::Value::Array($crate::__private::Vec::new())
    };
    ([ $($tt:tt)+ ]) => {
        $crate::Value::Array($crate::json!(@array [] $($tt)+))
    };
    ({}) => {
        $crate::Value::Object($crate::Map::new())
    };
    ({ $($tt:tt)+ }) => {{
        let mut object = $crate::Map::new();
        $crate::json!(@object object $($tt)+);
        $crate::Value::Object(object)
    }};

    // ── Array elements, munched into the bracketed list of done ones ────────
    (@array [$($done:expr,)*]) => {
        $crate::__private::vec![$($done,)*]
    };
    (@array [$($done:expr),*]) => {
        $crate::__private::vec![$($done),*]
    };
    (@array [$($done:expr,)*] null $($rest:tt)*) => {
        $crate::json!(@array [$($done,)* $crate::json!(null)] $($rest)*)
    };
    (@array [$($done:expr,)*] [$($array:tt)*] $($rest:tt)*) => {
        $crate::json!(@array [$($done,)* $crate::json!([$($array)*])] $($rest)*)
    };
    (@array [$($done:expr,)*] {$($object:tt)*} $($rest:tt)*) => {
        $crate::json!(@array [$($done,)* $crate::json!({$($object)*})] $($rest)*)
    };
    (@array [$($done:expr,)*] $next:expr, $($rest:tt)*) => {
        $crate::json!(@array [$($done,)* $crate::json!($next),] $($rest)*)
    };
    (@array [$($done:expr,)*] $last:expr) => {
        $crate::json!(@array [$($done,)* $crate::json!($last)])
    };
    (@array [$($done:expr),*] , $($rest:tt)*) => {
        $crate::json!(@array [$($done,)*] $($rest)*)
    };

    // ── Object members, inserted one at a time ──────────────────────────────
    (@object $object:ident) => {};
    (@object $object:ident $key:literal : null $(, $($rest:tt)*)?) => {
        $object.insert($crate::__private::String::from($key), $crate::json!(null));
        $crate::json!(@object $object $($($rest)*)?);
    };
    (@object $object:ident $key:literal : [$($array:tt)*] $(, $($rest:tt)*)?) => {
        $object.insert($crate::__private::String::from($key), $crate::json!([$($array)*]));
        $crate::json!(@object $object $($($rest)*)?);
    };
    (@object $object:ident $key:literal : {$($inner:tt)*} $(, $($rest:tt)*)?) => {
        $object.insert($crate::__private::String::from($key), $crate::json!({$($inner)*}));
        $crate::json!(@object $object $($($rest)*)?);
    };
    (@object $object:ident $key:literal : $value:expr , $($rest:tt)*) => {
        $object.insert($crate::__private::String::from($key), $crate::json!($value));
        $crate::json!(@object $object $($rest)*);
    };
    (@object $object:ident $key:literal : $value:expr) => {
        $object.insert($crate::__private::String::from($key), $crate::json!($value));
    };

    // ── Any other value: a Rust expression ─────────────────────────────────
    ($other:expr) => {
        $crate::ToJson::to_json(&$other)
    };
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn indexing_off_the_value_yields_null()
    {
        let issue = parse(r#"{"labels": [{"name": "bug"}], "milestone": null}"#).unwrap();
        assert_eq!(issue["labels"][0]["name"], "bug");
        assert!(issue["labels"][1].is_null());
        assert!(issue["missing"]["name"].is_null());
        assert!(issue["milestone"]["title"].is_null());
        assert!(issue["labels"]["name"].is_null());
        assert_eq!(issue.get("labels").and_then(|l| l.get("name")), None);
    }

    #[test]
    fn a_pointer_walks_members_and_elements_and_unescapes_its_tokens()
    {
        let value = parse(r#"{"a/b": {"c~d": [10, 20]}, "": 1}"#).unwrap();
        assert_eq!(value.pointer(""), Some(&value));
        assert_eq!(value.pointer("/a~1b/c~0d/1"), Some(&json!(20)));
        assert_eq!(value.pointer("/"), Some(&json!(1)));
        // A missing member, an index past the end, a leading zero, a sign,
        // a step into a number, and a pointer that does not start with "/".
        for missing in [
            "/x",
            "/a~1b/c~0d/2",
            "/a~1b/c~0d/01",
            "/a~1b/c~0d/+1",
            "/a~1b/c~0d/0/0",
            "a~1b",
        ]
        {
            assert_eq!(value.pointer(missing), None, "{missing}");
        }
    }

    #[test]
    fn a_number_reads_as_each_type_that_holds_it()
    {
        let read = |text: &str| parse(text).unwrap().as_number().unwrap();
        let max = read("18446744073709551615");
        assert_eq!((max.as_u64(), max.as_i64()), (Some(u64::MAX), None));
        let min = read("-9223372036854775808");
        assert_eq!((min.as_u64(), min.as_i64()), (None, Some(i64::MIN)));
        // Past both integer ranges, and written with a fraction: floats.
        let past = read("18446744073709551616");
        assert_eq!(
            (past.as_u64(), past.as_f64()),
            (None, 18_446_744_073_709_551_616.0)
        );
        let one = read("1.0");
        assert_eq!(
            (one.as_u64(), one.as_i64(), one.as_f64()),
            (None, None, 1.0)
        );
        assert_eq!(read("-0").as_i64(), None);
    }

    #[test]
    fn the_macro_builds_the_value_its_text_writes()
    {
        let holder = String::from("W1");
        let commands = vec!["build", "boot"];
        let none: Option<u32> = None;
        let built = json!({
            "holder": holder,
            "commands": commands,
            "count": commands.len(),
            "exclusive": 4 > 2,
            "grant": null,
            "queue": [],
            "order": [{ "id": 1 }, [null, -2], "x"],
            "since": none,
            "nested": { "deep": [true, false] },
        });
        let text = r#"{"holder": "W1", "commands": ["build", "boot"], "count": 2,
            "exclusive": true, "grant": null, "queue": [],
            "order": [{"id": 1}, [null, -2], "x"], "since": null,
            "nested": {"deep": [true, false]}}"#;
        assert_eq!(built, parse(text).unwrap());
        // The macro read its operands through references.
        assert_eq!((holder.as_str(), commands.len()), ("W1", 2));
    }

    #[test]
    fn a_float_json_cannot_write_converts_to_null()
    {
        assert_eq!(json!(f64::NAN), Value::Null);
        assert_eq!(json!(f64::INFINITY), Value::Null);
        assert_eq!(json!(0.5f64).as_f64(), Some(0.5));
    }
}
