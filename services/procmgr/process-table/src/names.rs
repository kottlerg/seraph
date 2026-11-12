// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/names.rs

//! A process's name, which `LIST_PROCESSES` reports beside its badge: the
//! first string of its argv as its creator passed it, truncated to
//! `svcmgr_labels::NAME_MAX` bytes, or empty when it was created without
//! argv. The creator chooses it, so it is a label for a debugger to find a
//! process by, not an identity; an attach still goes by badge
//! (`services/procmgr/docs/ipc-interface.md` § `LIST_PROCESSES`).

use ipc::svcmgr_labels::NAME_MAX;

/// A process name: at most [`NAME_MAX`] bytes, no NUL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessName
{
    bytes: [u8; NAME_MAX],
    len: usize,
}

impl Default for ProcessName
{
    fn default() -> Self
    {
        Self::EMPTY
    }
}

impl ProcessName
{
    /// The name of a process created without argv.
    pub const EMPTY: Self = Self {
        bytes: [0; NAME_MAX],
        len: 0,
    };

    /// The name's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8]
    {
        self.bytes.get(..self.len).unwrap_or_default()
    }
}

/// Reads a process's name from its argv blob, fed in chunks: the bytes of
/// the first string, up to its NUL, kept up to [`NAME_MAX`].
#[derive(Clone, Copy, Debug, Default)]
pub struct NameCapture
{
    name: ProcessName,
    /// The first string's NUL has been seen.
    done: bool,
}

impl NameCapture
{
    /// Take the next chunk of the argv blob.
    pub fn feed(&mut self, chunk: &[u8])
    {
        if self.done
        {
            return;
        }
        let string = chunk.split(|&b| b == 0).next().unwrap_or_default();
        let free = self.name.bytes.get_mut(self.name.len..).unwrap_or_default();
        let take = string.len().min(free.len());
        for (dst, &src) in free.iter_mut().zip(string)
        {
            *dst = src;
        }
        // `take` is at most the free room, so `len` stays at most `NAME_MAX`.
        self.name.len = self.name.len.saturating_add(take);
        self.done = string.len() < chunk.len();
    }

    /// The name captured.
    #[must_use]
    pub fn name(&self) -> ProcessName
    {
        self.name
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn captured(chunks: &[&[u8]]) -> ProcessName
    {
        let mut c = NameCapture::default();
        for chunk in chunks
        {
            c.feed(chunk);
        }
        c.name()
    }

    #[test]
    fn the_name_is_the_first_string_across_chunk_boundaries()
    {
        assert_eq!(
            captured(&[b"deb", b"ugger\0--gdb", b"-target\0"]).as_bytes(),
            b"debugger"
        );
        assert_eq!(captured(&[b"a\0b\0"]).as_bytes(), b"a");
        assert_eq!(captured(&[b"\0x\0"]).as_bytes(), b"");
    }

    #[test]
    fn a_first_string_past_the_bound_is_truncated()
    {
        let long = [b'n'; NAME_MAX + 10];
        let name = captured(&[&long[..30], &long[30..], b"\0"]);
        assert_eq!(name.as_bytes(), &long[..NAME_MAX]);
    }

    #[test]
    fn no_argv_gives_the_empty_name()
    {
        assert_eq!(captured(&[]), ProcessName::EMPTY);
    }
}
