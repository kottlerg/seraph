// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// xtask/src/error.rs

//! xtask's error type: a message with the chain of context it was raised
//! under, and the `Result`, [`Context`], `err!`, `bail!` and `ensure!`
//! that build it.
//!
//! An [`Error`] holds its messages as text, so it is `Send`, `Sync` and
//! `'static` whatever it was made from. A standard error converted by `?`
//! keeps its own message and those of its
//! [`source`](std::error::Error::source) chain; [`Context`] puts an outer
//! message on the error of a failed `Result`, or makes one from a `None`.
//!
//! `{}` prints the outermost message, `{:#}` the whole chain joined by
//! `": "` (what `main` prints), and `{:?}` the outermost message with a
//! `Caused by:` list of the rest, which a failed test's `unwrap` shows.
//!
//! `Error` does not implement [`std::error::Error`]: the blanket
//! `From<E: std::error::Error>` that lets `?` convert any standard error
//! would otherwise overlap the standard library's `From<T> for T`.

use std::fmt;

/// A `Result` whose error defaults to [`Error`].
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// An error message and the chain of context it was raised under.
pub struct Error
{
    /// The outermost message.
    message: String,
    /// The messages beneath `message`, the outermost first.
    causes: Vec<String>,
}

impl Error
{
    /// An error with `message` alone.
    pub fn msg(message: impl fmt::Display) -> Self
    {
        Self {
            message: message.to_string(),
            causes: Vec::new(),
        }
    }

    /// This error under `context`, which becomes its outermost message.
    #[must_use]
    pub fn context(mut self, context: impl fmt::Display) -> Self
    {
        let inner = std::mem::replace(&mut self.message, context.to_string());
        self.causes.insert(0, inner);
        self
    }
}

impl<E: std::error::Error> From<E> for Error
{
    /// `err`'s message, then those of its `source` chain.
    fn from(err: E) -> Self
    {
        let mut causes = Vec::new();
        let mut source = err.source();
        while let Some(cause) = source
        {
            causes.push(cause.to_string());
            source = cause.source();
        }
        Self {
            message: err.to_string(),
            causes,
        }
    }
}

impl fmt::Display for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(&self.message)?;
        if f.alternate()
        {
            for cause in &self.causes
            {
                write!(f, ": {cause}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Error
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(&self.message)?;
        match self.causes.as_slice()
        {
            [] => Ok(()),
            [cause] => write!(f, "\n\nCaused by:\n    {cause}"),
            causes =>
            {
                f.write_str("\n\nCaused by:")?;
                for (i, cause) in causes.iter().enumerate()
                {
                    write!(f, "\n    {i}: {cause}")?;
                }
                Ok(())
            }
        }
    }
}

/// An outer message for the error of a failed `Result`, or an error made
/// from a `None`.
pub trait Context<T>
{
    /// `self`, its error put under `context`.
    ///
    /// # Errors
    ///
    /// The error of `self`, converted to an [`Error`] with `context` as
    /// its outermost message; for a `None`, an error with `context` alone.
    fn context(self, context: impl fmt::Display) -> Result<T>;

    /// As [`Context::context`], with the message made by `context` only
    /// when `self` failed.
    ///
    /// # Errors
    ///
    /// As [`Context::context`].
    fn with_context<C: fmt::Display>(self, context: impl FnOnce() -> C) -> Result<T>;
}

impl<T, E: Into<Error>> Context<T> for std::result::Result<T, E>
{
    fn context(self, context: impl fmt::Display) -> Result<T>
    {
        self.map_err(|err| err.into().context(context))
    }

    fn with_context<C: fmt::Display>(self, context: impl FnOnce() -> C) -> Result<T>
    {
        self.map_err(|err| err.into().context(context()))
    }
}

impl<T> Context<T> for Option<T>
{
    fn context(self, context: impl fmt::Display) -> Result<T>
    {
        self.ok_or_else(|| Error::msg(context))
    }

    fn with_context<C: fmt::Display>(self, context: impl FnOnce() -> C) -> Result<T>
    {
        self.ok_or_else(|| Error::msg(context()))
    }
}

/// An [`Error`] from a format string and its arguments, as `format!` takes
/// them, or from one value that implements `Display`.
macro_rules! err {
    ($fmt:literal $($arg:tt)*) => {
        $crate::error::Error::msg(::std::format!($fmt $($arg)*))
    };
    ($message:expr $(,)?) => {
        $crate::error::Error::msg($message)
    };
}

/// Return early with `err!` of the arguments as the error.
macro_rules! bail {
    ($($arg:tt)+) => {
        return ::std::result::Result::Err($crate::error::err!($($arg)+))
    };
}

/// Return early with `err!` of the arguments after the condition as the
/// error, unless the condition holds.
macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond
        {
            $crate::error::bail!($($arg)+);
        }
    };
}

pub(crate) use {bail, ensure, err};

#[cfg(test)]
mod tests
{
    use super::*;

    /// A standard error with an optional source, as `io` and parse errors
    /// carry one.
    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl fmt::Display for Layer
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
        {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Layer
    {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)>
        {
            self.1
                .as_deref()
                .map(|l| l as &(dyn std::error::Error + 'static))
        }
    }

    fn layered() -> Layer
    {
        Layer("outer io", Some(Box::new(Layer("os error 2", None))))
    }

    #[test]
    fn display_shows_the_outermost_message_and_alternate_the_whole_chain()
    {
        let err = Error::from(layered())
            .context("reading x")
            .context("loading y");
        assert_eq!(format!("{err}"), "loading y");
        assert_eq!(
            format!("{err:#}"),
            "loading y: reading x: outer io: os error 2"
        );
    }

    #[test]
    fn debug_lists_one_cause_unnumbered_and_several_numbered()
    {
        assert_eq!(format!("{:?}", Error::msg("a")), "a");
        assert_eq!(
            format!("{:?}", Error::msg("b").context("a")),
            "a\n\nCaused by:\n    b"
        );
        assert_eq!(
            format!("{:?}", Error::msg("c").context("b").context("a")),
            "a\n\nCaused by:\n    0: b\n    1: c"
        );
    }

    #[test]
    fn question_mark_converts_a_standard_error_with_its_source_chain()
    {
        fn standard() -> std::result::Result<(), Layer>
        {
            Err(layered())
        }
        fn fails() -> Result<()>
        {
            standard()?;
            Ok(())
        }
        assert_eq!(
            format!("{:#}", fails().unwrap_err()),
            "outer io: os error 2"
        );
    }

    #[test]
    fn context_wraps_a_failed_result_and_leaves_ok_alone()
    {
        let failed: std::result::Result<(), Layer> = Err(Layer("inner", None));
        assert_eq!(
            format!("{:#}", failed.context("outer").unwrap_err()),
            "outer: inner"
        );
        let ours: Result<()> = Err(Error::msg("inner"));
        let err = ours.with_context(|| format!("outer {}", 1)).unwrap_err();
        assert_eq!(format!("{err:#}"), "outer 1: inner");
        let mut called = false;
        let ok: Result<u8> = Ok(7);
        let value = ok
            .with_context(|| {
                called = true;
                "unused"
            })
            .unwrap();
        assert_eq!((value, called), (7, false));
    }

    #[test]
    fn context_on_none_is_the_error_and_on_some_the_value()
    {
        assert_eq!(
            format!("{:#}", None::<u8>.context("missing").unwrap_err()),
            "missing"
        );
        assert_eq!(Some(3).with_context(|| "unused").unwrap(), 3);
    }

    #[test]
    fn err_formats_a_literal_with_arguments_or_takes_a_display_value()
    {
        let n = 4;
        assert_eq!(err!("plain").to_string(), "plain");
        assert_eq!(err!("n is {n}").to_string(), "n is 4");
        assert_eq!(err!("{} and {}", 1, n,).to_string(), "1 and 4");
        let message = String::from("built elsewhere");
        assert_eq!(err!(message).to_string(), "built elsewhere");
    }

    #[test]
    fn bail_and_ensure_return_the_error_and_ensure_passes_a_held_condition()
    {
        fn check(n: u32) -> Result<u32>
        {
            ensure!(n < 10, "{n} is too large");
            if n == 0
            {
                bail!("zero");
            }
            Ok(n)
        }
        assert_eq!(check(3).unwrap(), 3);
        assert_eq!(check(0).unwrap_err().to_string(), "zero");
        assert_eq!(check(12).unwrap_err().to_string(), "12 is too large");
    }
}
