// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/stop_labels.rs

//! The stop protocol every stop source serves, one module for every source
//! (docs/session-supervision.md § Stop Sources): a paged list of the
//! candidates the source would stop, and the stop of one, named by its key.
//! svcmgr serves it on its own endpoint for the service class; every other
//! source is a service whose recipe sets `stop_source`, which serves it on
//! the endpoint its recipe provides, and svcmgr hands the holder of its stop
//! authority a SEND on that endpoint badged with [`STOP_AUTHORITY`]
//! (`svcmgr_labels::LIST_STOP_SOURCES`).
//!
//! A source serves both labels only on a badge carrying [`STOP_AUTHORITY`],
//! and its own labels avoid [`STOP_CANDIDATE`] and [`LIST_CANDIDATES`]. A
//! key names one candidate and no other while the source runs.

// Under `rustc-dep-of-std` the crate is `no_core`, so this module, which
// defines functions, imports the prelude the crate root imports.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use super::svcmgr_labels::{NAME_MAX, NAME_WORDS, pack_name, unpack_name};

/// Verb bit authorising [`STOP_CANDIDATE`] and [`LIST_CANDIDATES`] on a
/// source's endpoint, and on svcmgr's also `svcmgr_labels::LIST_STOP_SOURCES`.
/// svcmgr alone mints it: on a SEND on its own service endpoint it
/// delivers to a service whose recipe sets `stop_authority = yes`, in the
/// bootstrap slot after the seeds and the debug-authority cap, fresh on
/// every launch and restart; and on each SEND a `LIST_STOP_SOURCES` reply
/// carries, derived from the source's endpoint. A source's recipe provides
/// only badged names, so no holder of a name can mint it. The SEND carries
/// no other verb bit.
pub const STOP_AUTHORITY: u64 = 1u64 << 61;

const _: () = core::assert!(STOP_AUTHORITY & crate::VERB_BIT_MASK != 0);

/// Stop the candidate whose key is `data[0]`, through the authority the
/// source holds over it. The reply is [`SUCCESS`] once it is stopped,
/// [`NO_CANDIDATE`] when the key names no current candidate (it is gone,
/// or never was one), [`UNAVAILABLE`] when the source cannot stop it now,
/// and [`UNAUTHORIZED`] on a badge without [`STOP_AUTHORITY`]. A refusal
/// changes nothing.
pub const STOP_CANDIDATE: u64 = 5;

/// List the candidates the source would stop, one page per call.
/// `data[0]` is the cursor: 0 starts the walk, and each reply's `data[1]`
/// is the cursor that resumes it, greater than the one asked. The reply
/// carries the page's count in `data[0]`, the next cursor in `data[1]`,
/// then per entry [`CANDIDATE_WORDS`] words: the key, the rank, the pages
/// its memory budget subtree holds, its name's length, and the name's
/// bytes ([`pack_candidate`]); at most [`LIST_CANDIDATES_PAGE`] entries,
/// and a page shorter than that ends the walk. [`UNAVAILABLE`] when the
/// source cannot read its candidates now, [`UNAUTHORIZED`] on a badge
/// without [`STOP_AUTHORITY`].
pub const LIST_CANDIDATES: u64 = 6;

/// Data words one [`LIST_CANDIDATES`] entry takes: the key, the rank, the
/// pages, the name's length, and the name in [`NAME_MAX`] bytes.
pub const CANDIDATE_WORDS: usize = 4 + NAME_WORDS;

/// Data words of a [`LIST_CANDIDATES`] reply before its first entry: the
/// count and the next cursor.
pub const HEADER_WORDS: usize = 2;

/// Entries one [`LIST_CANDIDATES`] reply carries at most: as many as fit
/// the data words after the header.
pub const LIST_CANDIDATES_PAGE: usize =
    (super::MSG_DATA_WORDS_MAX - HEADER_WORDS) / CANDIDATE_WORDS;

const _: () = core::assert!(LIST_CANDIDATES_PAGE >= 1);

/// The class code `svcmgr_labels::LIST_STOP_SOURCES` gives a source whose
/// recipe sets `stop_source = program`: the programs of sessions. svcmgr
/// is the service class's one source and is never listed.
pub const CLASS_PROGRAM: u64 = 1;

/// The rank of every candidate of the service class.
pub const RANK_SERVICE: u64 = 0;
/// The program class's rank of a job: a child of a session's leader with
/// every process below it.
pub const RANK_JOB: u64 = 0;
/// The program class's rank of a whole session, stopped after its jobs.
pub const RANK_SESSION: u64 = 1;

/// The reply label of a handled request.
pub const SUCCESS: u64 = 0;
/// The caller's badge lacks [`STOP_AUTHORITY`].
pub const UNAUTHORIZED: u64 = 1;
/// [`STOP_CANDIDATE`]: the key names no current candidate; nothing
/// changed.
pub const NO_CANDIDATE: u64 = 2;
/// The source cannot list or stop now (a service it calls is down, or
/// the stop failed); nothing changed.
pub const UNAVAILABLE: u64 = 3;

/// One entry of a [`LIST_CANDIDATES`] reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate
{
    /// The key [`STOP_CANDIDATE`] names it by.
    pub key: u64,
    /// Its rank within its source's class, the lower stopped first.
    pub rank: u64,
    /// The pages its memory budget subtree holds.
    pub pages: u64,
    /// Its name, zero-padded to [`NAME_MAX`].
    pub name: [u8; NAME_MAX],
    /// The name's length in bytes.
    pub len: usize,
}

/// Write entry `index` of a [`LIST_CANDIDATES`] reply into `words` (the
/// reply's data words, whose header the caller sets). Returns `false`,
/// writing nothing, when `name` is empty or longer than [`NAME_MAX`], or
/// the entry does not fit `words`.
pub fn pack_candidate(
    words: &mut [u64],
    index: usize,
    key: u64,
    rank: u64,
    pages: u64,
    name: &[u8],
) -> bool
{
    let mut packed = [0; NAME_WORDS];
    if name.is_empty() || pack_name(name, &mut packed).is_none()
    {
        return false;
    }
    let Some([key_word, rank_word, pages_word, len_word, name_words @ ..]) =
        entry_base(index).and_then(|base| words.get_mut(base..)?.get_mut(..CANDIDATE_WORDS))
    else
    {
        return false;
    };
    *key_word = key;
    *rank_word = rank;
    *pages_word = pages;
    *len_word = name.len() as u64;
    name_words.copy_from_slice(&packed);
    true
}

/// Read entry `index` of a [`LIST_CANDIDATES`] reply's data words
/// `words`. `None` when `index` is past the reply's count or its words,
/// or the entry's name length is 0 or past [`NAME_MAX`]; the reply is wire
/// input, so nothing is read past either bound.
#[must_use]
pub fn unpack_candidate(words: &[u64], index: usize) -> Option<Candidate>
{
    let count = usize::try_from(*words.first()?).ok()?;
    if index >= count
    {
        return None;
    }
    let [key, rank, pages, len_word, name_words @ ..] =
        words.get(entry_base(index)?..)?.get(..CANDIDATE_WORDS)?
    else
    {
        return None;
    };
    let len = usize::try_from(*len_word).ok()?;
    let name = unpack_name(name_words, len)?;
    Some(Candidate {
        key: *key,
        rank: *rank,
        pages: *pages,
        name,
        len,
    })
}

/// The first data word of entry `index` of a [`LIST_CANDIDATES`] reply,
/// past the header; `None` when it does not fit a `usize`.
fn entry_base(index: usize) -> Option<usize>
{
    index
        .checked_mul(CANDIDATE_WORDS)?
        .checked_add(HEADER_WORDS)
}

#[cfg(test)]
mod tests
{
    use crate::{MSG_DATA_WORDS_MAX, stop_labels, svcmgr_labels};

    #[test]
    fn a_candidate_list_page_round_trips_every_field_and_name_length()
    {
        use stop_labels::{LIST_CANDIDATES_PAGE, pack_candidate, unpack_candidate};
        use svcmgr_labels::NAME_MAX;
        let long = [b'x'; NAME_MAX];
        let names: [&[u8]; 3] = [b"memhog", &long, b"a"];
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        for (i, name) in names.iter().enumerate()
        {
            let i64 = i as u64;
            assert!(pack_candidate(
                &mut words,
                i,
                u64::MAX - i64,
                i64,
                0x100 + i64,
                name
            ));
        }
        words[0] = names.len() as u64;
        for (i, name) in names.iter().enumerate()
        {
            let entry = unpack_candidate(&words, i).unwrap();
            let i64 = i as u64;
            assert_eq!(
                (entry.key, entry.rank, entry.pages, &entry.name[..entry.len]),
                (u64::MAX - i64, i64, 0x100 + i64, *name)
            );
            assert!(entry.name[entry.len..].iter().all(|&b| b == 0));
        }
        assert!(unpack_candidate(&words, names.len()).is_none());
        // A full page fits the message, and the entry past it does not.
        assert!(pack_candidate(
            &mut words,
            LIST_CANDIDATES_PAGE - 1,
            1,
            0,
            1,
            b"a"
        ));
        assert!(!pack_candidate(
            &mut words,
            LIST_CANDIDATES_PAGE,
            1,
            0,
            1,
            b"a"
        ));
    }

    #[test]
    fn a_candidate_entry_refuses_names_outside_one_to_name_max()
    {
        use stop_labels::{HEADER_WORDS, pack_candidate, unpack_candidate};
        use svcmgr_labels::NAME_MAX;
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_candidate(&mut words, 0, 1, 0, 7, b""));
        assert!(!pack_candidate(
            &mut words,
            0,
            1,
            0,
            7,
            &[b'n'; NAME_MAX + 1]
        ));
        assert_eq!(words, [0; MSG_DATA_WORDS_MAX]);
        assert!(pack_candidate(&mut words, 0, 1, 0, 7, b"job"));
        words[0] = 1;
        // A length the reply claims past NAME_MAX, or zero, is wire input
        // refused, not read.
        words[HEADER_WORDS + 3] = NAME_MAX as u64 + 1;
        assert!(unpack_candidate(&words, 0).is_none());
        words[HEADER_WORDS + 3] = 0;
        assert!(unpack_candidate(&words, 0).is_none());
    }

    #[test]
    fn a_candidate_index_whose_offset_overflows_is_refused()
    {
        use stop_labels::{CANDIDATE_WORDS, pack_candidate, unpack_candidate};
        let index = usize::MAX / CANDIDATE_WORDS + 1;
        let mut words = [0u64; MSG_DATA_WORDS_MAX];
        assert!(!pack_candidate(&mut words, index, 1, 0, 7, b"a"));
        assert_eq!(words, [0; MSG_DATA_WORDS_MAX]);
        words[0] = u64::MAX;
        assert!(unpack_candidate(&words, index).is_none());
    }
}
