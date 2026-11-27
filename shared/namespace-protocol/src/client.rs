// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/namespace-protocol/src/client.rs

//! The client side of an `NS_LOOKUP` walk: the components each request
//! carries and where the walk continues after each reply.
//!
//! A client walks a path from a directory cap by sending the components it
//! has left, as many whole ones as one request carries
//! ([`crate::MAX_LOOKUP_PATH_LEN`]), and continuing from the cap the reply
//! returns with the components the reply did not consume
//! (`shared/namespace-protocol/README.md` § `NS_LOOKUP`). [`PathWalk`] holds
//! that state; the client makes the calls and owns the caps.

// Under `rustc-dep-of-std` the crate root is `no_core` and the usual
// prelude is not auto-imported into submodules. Mirrors the
// `shared/ipc/src/bootstrap.rs` shape; no-op on regular no_std builds.
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use crate::{MAX_LOOKUP_PATH_LEN, NodeKind};

/// A path being walked by `NS_LOOKUP` requests: the components not yet
/// consumed by a reply. Empty components (a leading, trailing or doubled
/// `/`) are skipped; the components themselves are not validated here, and a
/// server answers one that fails [`crate::validate_name`] with
/// `InvalidName`.
#[derive(Copy, Clone, Debug)]
pub struct PathWalk<'a>
{
    /// The unconsumed rest of the path, starting at a component.
    rest: &'a [u8],
}

/// One `NS_LOOKUP` request of a [`PathWalk`]: the leading components it has
/// left that fit one request, joined by single `/`.
#[derive(Clone, Debug)]
pub struct LookupRequest
{
    bytes: [u8; MAX_LOOKUP_PATH_LEN],
    len: usize,
    components: u64,
}

impl LookupRequest
{
    /// The request's path bytes, which its data words carry after the rights
    /// word.
    #[must_use]
    pub fn path(&self) -> &[u8]
    {
        // `len <= MAX_LOOKUP_PATH_LEN` by construction (`PathWalk::request`).
        self.bytes.get(..self.len).unwrap_or_default()
    }

    /// The request's label: `NS_LOOKUP` with the path length in bits 16..32.
    #[must_use]
    pub fn label(&self) -> u64
    {
        ipc::ns_labels::NS_LOOKUP | ((self.len as u64) << 16)
    }

    /// The number of components the request carries.
    #[must_use]
    pub fn components(&self) -> u64
    {
        self.components
    }
}

/// Why a reply cannot advance a [`PathWalk`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum StepError
{
    /// The reply's consumed count is zero or more than the request carried:
    /// a malformed reply.
    ConsumedOutOfRange,
    /// The reply reached an entry that is not a directory while components
    /// remain after it.
    NotADirectory,
}

impl<'a> PathWalk<'a>
{
    /// A walk of the `/`-separated components of `path`.
    #[must_use]
    pub fn new(path: &'a [u8]) -> Self
    {
        Self {
            rest: skip_separators(path),
        }
    }

    /// Whether every component has been consumed (or the path held none).
    #[must_use]
    pub fn is_finished(&self) -> bool
    {
        self.rest.is_empty()
    }

    /// The components not yet consumed, in order.
    pub fn components(&self) -> impl Iterator<Item = &'a [u8]> + use<'a>
    {
        self.rest.split(|&b| b == b'/').filter(|c| !c.is_empty())
    }

    /// The `index`-th unconsumed component, which an error reply to the next
    /// request names by that index; `None` past the last.
    #[must_use]
    pub fn component(&self, index: u64) -> Option<&'a [u8]>
    {
        self.components().nth(usize::try_from(index).ok()?)
    }

    /// The next request: as many whole unconsumed components as fit
    /// [`MAX_LOOKUP_PATH_LEN`] bytes joined by `/`. `None` when the walk is
    /// finished, or when its next component alone is longer than a request
    /// carries (longer than any valid name).
    #[must_use]
    pub fn request(&self) -> Option<LookupRequest>
    {
        let mut request = LookupRequest {
            bytes: [0u8; MAX_LOOKUP_PATH_LEN],
            len: 0,
            components: 0,
        };
        for name in self.components()
        {
            let start = if request.components == 0
            {
                0
            }
            else
            {
                // Within the buffer: `len < MAX_LOOKUP_PATH_LEN` was checked
                // when the previous component was added.
                let sep = request.bytes.get_mut(request.len)?;
                *sep = b'/';
                request.len.checked_add(1)?
            };
            let Some(dst) = start
                .checked_add(name.len())
                .and_then(|end| request.bytes.get_mut(start..end))
            else
            {
                break;
            };
            dst.copy_from_slice(name);
            request.len = start.saturating_add(name.len());
            // At most `MAX_LOOKUP_PATH_LEN` components fit.
            request.components = request.components.saturating_add(1);
            if request.len >= MAX_LOOKUP_PATH_LEN
            {
                break;
            }
        }
        (request.components != 0).then_some(request)
    }

    /// Advance past the `consumed` components of the reply to `request`,
    /// which reached an entry of `kind` (the reply's `data[0]`).
    ///
    /// # Errors
    ///
    /// [`StepError::ConsumedOutOfRange`], leaving the walk unchanged, when
    /// `consumed` is zero or more than `request` carried;
    /// [`StepError::NotADirectory`] when components remain and `kind` is not
    /// a directory.
    pub fn advance(
        &mut self,
        request: &LookupRequest,
        consumed: u64,
        kind: u64,
    ) -> Result<(), StepError>
    {
        consumed_in_range(consumed, request.components)?;
        for _ in 0..consumed
        {
            let after = self
                .rest
                .iter()
                .position(|&b| b == b'/')
                .and_then(|end| self.rest.get(end..))
                .unwrap_or_default();
            self.rest = skip_separators(after);
        }
        self.may_stop_at(kind)
    }

    /// Whether the walk, as it stands after a reply, may have reached an entry
    /// of `kind` (the reply's `data[0]`): an entry that is not a directory
    /// only when no component remains.
    ///
    /// # Errors
    ///
    /// [`StepError::NotADirectory`] when components remain and `kind` is not
    /// a directory.
    pub(crate) fn may_stop_at(&self, kind: u64) -> Result<(), StepError>
    {
        if !self.is_finished() && kind != NodeKind::Dir as u64
        {
            return Err(StepError::NotADirectory);
        }
        Ok(())
    }
}

/// Whether a reply's `consumed` count is one a request of `carried`
/// components allows: 1 to `carried`.
///
/// # Errors
///
/// [`StepError::ConsumedOutOfRange`] for zero or a count past `carried`.
pub(crate) fn consumed_in_range(consumed: u64, carried: u64) -> Result<(), StepError>
{
    if consumed == 0 || consumed > carried
    {
        return Err(StepError::ConsumedOutOfRange);
    }
    Ok(())
}

/// `path` without its leading separators.
fn skip_separators(path: &[u8]) -> &[u8]
{
    let start = path.iter().position(|&b| b != b'/').unwrap_or(path.len());
    path.get(start..).unwrap_or_default()
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn a_request_carries_every_component_that_fits_joined_by_one_separator()
    {
        let walk = PathWalk::new(b"//a//bc/d/");
        let request = walk.request().unwrap();
        assert_eq!(request.path(), b"a/bc/d");
        assert_eq!(request.components(), 3);
        assert_eq!(request.label(), ipc::ns_labels::NS_LOOKUP | (6 << 16));
    }

    #[test]
    fn a_path_longer_than_one_request_splits_at_a_component_boundary()
    {
        // Three 200-byte components: two (401 bytes) fit 504, the third
        // goes in the next request.
        let mut path = [b'x'; 3 * 201];
        path[200] = b'/';
        path[401] = b'/';
        path[602] = b'y';
        let mut walk = PathWalk::new(&path[..602]);
        let first = walk.request().unwrap();
        assert_eq!(first.components(), 2);
        assert_eq!(first.path().len(), 401);
        walk.advance(&first, 2, NodeKind::Dir as u64).unwrap();
        let second = walk.request().unwrap();
        assert_eq!(second.components(), 1);
        assert_eq!(second.path(), &[b'x'; 200][..]);
        walk.advance(&second, 1, NodeKind::File as u64).unwrap();
        assert!(walk.is_finished());
    }

    #[test]
    fn a_component_that_fills_a_request_exactly_is_sent_alone()
    {
        let mut path = [b'n'; MAX_LOOKUP_PATH_LEN + 2];
        path[MAX_LOOKUP_PATH_LEN] = b'/';
        let walk = PathWalk::new(&path);
        let request = walk.request().unwrap();
        assert_eq!(request.components(), 1);
        assert_eq!(request.path().len(), MAX_LOOKUP_PATH_LEN);
    }

    #[test]
    fn no_request_is_made_for_an_empty_path_or_an_oversized_component()
    {
        assert!(PathWalk::new(b"///").request().is_none());
        assert!(PathWalk::new(b"///").is_finished());
        let long = [b'n'; MAX_LOOKUP_PATH_LEN + 1];
        assert!(PathWalk::new(&long).request().is_none());
    }

    #[test]
    fn a_partial_reply_continues_with_the_unconsumed_components()
    {
        let mut walk = PathWalk::new(b"a/b/c");
        let request = walk.request().unwrap();
        walk.advance(&request, 1, NodeKind::Dir as u64).unwrap();
        assert_eq!(walk.request().unwrap().path(), b"b/c");
        assert_eq!(walk.component(1), Some(&b"c"[..]));
        assert_eq!(walk.component(2), None);
    }

    #[test]
    fn a_consumed_count_outside_the_request_is_refused_and_changes_nothing()
    {
        let mut walk = PathWalk::new(b"a/b");
        let request = walk.request().unwrap();
        for consumed in [0, 3]
        {
            assert_eq!(
                walk.advance(&request, consumed, NodeKind::Dir as u64),
                Err(StepError::ConsumedOutOfRange)
            );
        }
        assert_eq!(walk.request().unwrap().path(), b"a/b");
    }

    #[test]
    fn a_file_with_components_after_it_is_not_a_directory()
    {
        let mut walk = PathWalk::new(b"a/b");
        let request = walk.request().unwrap();
        assert_eq!(
            walk.advance(&request, 1, NodeKind::File as u64),
            Err(StepError::NotADirectory)
        );
        let mut walk = PathWalk::new(b"a/b");
        walk.advance(&request, 2, NodeKind::File as u64).unwrap();
        assert!(walk.is_finished());
    }
}

/// Proofs of the client's check of a server's `NS_LOOKUP` reply
/// (docs/testing.md § Bounded verification, Parser proofs).
///
/// The reply's words, the consumed count and the kind, are a server's and
/// may be hostile; the path is the client's own. [`PathWalk::advance`] checks
/// the count with `consumed_in_range` before it moves, skips that many
/// components of the client's path, and checks the kind with
/// `PathWalk::may_stop_at`. The count proof proves the count check on every
/// count and every request's component count, and the kind proof the kind
/// check on every kind, with components left and with none. What lies outside
/// the proofs is the skip, `PathWalk::request` and the walk's reading of the
/// path, which read the client's own path and no server's word; the fuzz
/// target `namespace-protocol` and the replay of the checked-in inputs check
/// them, and the whole walk against the replies, on paths of every length.
#[cfg(kani)]
mod proofs
{
    use crate::property;

    /// Every reply's count is taken exactly when it is 1 to the request's
    /// component count, for every count and component count. No loop.
    #[kani::proof]
    fn every_reply_count_is_checked_against_its_request()
    {
        property::consumed_holds(kani::any(), kani::any());
    }

    /// Every reply's kind is checked against whether components remain: the
    /// walks of the paths of up to two bytes, `a` and `/` among them, hold
    /// a component and none. The longest loops are the walks of the two
    /// bytes, so an unwind bound of 4 covers them.
    #[kani::proof]
    #[kani::unwind(4)]
    fn every_reply_kind_is_checked_against_the_rest_of_the_walk()
    {
        let path: [u8; 2] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= path.len());
        property::stop_holds(&crate::client::PathWalk::new(&path[..len]), kani::any());
    }
}
