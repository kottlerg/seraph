// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/objsig/src/embed.rs

//! The trust store as the bootloader image embeds it, and the search a pack
//! makes to read it back out of the installed image
//! ([docs/signing.md](../../../docs/signing.md) § Signing).
//!
//! The embedding is `MARKER || len || store`: the 16-byte [`MARKER`], the
//! store's length as a little-endian `u32`, then the store. [`Embedded`] is
//! that layout as one `#[repr(C)]` value, so a `static` of it puts the three
//! parts next to each other in the image's read-only data whatever the
//! image's format: a PE/COFF image with its section table on x86-64, and on
//! riscv64 a flat binary behind a hand-written header, with no section table
//! and no symbols. [`find`] locates the one copy of the marker in an image
//! and returns the store after it.
//!
//! The marker cannot occur in the image by accident:
//!
//! - It holds the bytes `0xff` and `0xfe`, which no UTF-8 text holds, so no
//!   string of the image or label of the store holds it.
//! - The rest of the store is its header, key ids and keys: a key or key id
//!   holding it takes the marker's 16 bytes at random, a chance of 2^-128 per
//!   position.
//! - The image's code never compares against the marker: [`Embedded::new`]
//!   writes it at compile time and [`Embedded::store`] reads past it.
//!
//! [`find`] refuses an image holding the marker more than once, so a second
//! copy, however it came, stops the pack rather than letting it read the
//! wrong one.

use crate::StoreError;
use crate::store::TrustStore;

/// The 16 bytes that open the embedded store.
pub const MARKER: [u8; 16] = *b"\xffSERAPH-TRUST\x00\xfe\x01";

/// Length of the prefix before the store: the marker and the store's length.
pub const PREFIX_LEN: usize = MARKER.len() + 4;

/// A trust store of `N` bytes in its embedded layout.
#[repr(C)]
pub struct Embedded<const N: usize>
{
    marker: [u8; 16],
    len: [u8; 4],
    store: [u8; N],
}

impl<const N: usize> Embedded<N>
{
    /// The embedding of `store`, which is `N` bytes long.
    ///
    /// # Panics
    /// At compile time, in the `static` it initializes, when `store` is not
    /// `N` bytes long or `N` does not fit a `u32`.
    #[must_use]
    pub const fn new(store: &[u8]) -> Self
    {
        assert!(store.len() == N, "an embedded store is N bytes long");
        let mut bytes = [0u8; N];
        bytes.copy_from_slice(store);
        assert!(
            N <= u32::MAX as usize,
            "an embedded store's length fits a u32"
        );
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the assertion above bounds N by u32::MAX"
        )]
        let len = (N as u32).to_le_bytes();
        Self {
            marker: MARKER,
            len,
            store: bytes,
        }
    }

    /// The embedded store's bytes.
    ///
    /// The value is read through `core::hint::black_box`, so the compiler
    /// keeps all of it in the image, the marker that [`find`] locates
    /// included, rather than only the bytes a caller reads.
    #[must_use]
    pub fn store(&'static self) -> &'static [u8]
    {
        &core::hint::black_box(self).store
    }
}

/// Why [`find`] refused an image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FindError
{
    /// The image holds no [`MARKER`].
    NoMarker,
    /// The image holds [`MARKER`] more than once.
    SeveralMarkers,
    /// The length after the marker runs past the end of the image.
    Length,
    /// The bytes found do not parse as a trust store.
    Store(StoreError),
}

/// The trust store `image` embeds: the bytes after its one [`MARKER`] and the
/// length that follows it, refused unless they parse as a trust store.
///
/// # Errors
/// A [`FindError`]: no marker, more than one, a length past the end of the
/// image, or a store that does not parse.
pub fn find(image: &[u8]) -> Result<&[u8], FindError>
{
    let mut starts = image
        .windows(MARKER.len())
        .enumerate()
        .filter(|(_, window)| *window == MARKER)
        .map(|(start, _)| start);
    let start = starts.next().ok_or(FindError::NoMarker)?;
    if starts.next().is_some()
    {
        return Err(FindError::SeveralMarkers);
    }
    let rest = image
        .get(start.saturating_add(MARKER.len())..)
        .ok_or(FindError::Length)?;
    let (len, rest) = rest.split_first_chunk::<4>().ok_or(FindError::Length)?;
    let len = usize::try_from(u32::from_le_bytes(*len)).map_err(|_| FindError::Length)?;
    let store = rest.get(..len).ok_or(FindError::Length)?;
    TrustStore::parse(store).map_err(FindError::Store)?;
    Ok(store)
}

#[cfg(test)]
mod tests
{
    extern crate std;
    use std::vec::Vec;

    use super::*;
    use crate::testutil::{ROOT, keys, store};

    fn image_of(embedded: &[u8]) -> Vec<u8>
    {
        let mut image = Vec::from(&b"code before the store"[..]);
        image.extend_from_slice(embedded);
        image.extend_from_slice(b"code after the store");
        image
    }

    fn embedding(store: &[u8]) -> Vec<u8>
    {
        let mut out = Vec::from(MARKER);
        out.extend_from_slice(&u32::try_from(store.len()).unwrap().to_le_bytes());
        out.extend_from_slice(store);
        out
    }

    // Defect caught: an `Embedded` whose layout is not marker, length, store
    // as `find` reads it, so a pack reads another store than the bootloader's.
    #[test]
    fn find_reads_back_the_store_an_embedding_holds()
    {
        static STORE: [u8; 4] = *b"abcd";
        static EMBEDDED: Embedded<4> = Embedded::new(&STORE);
        // SAFETY: `Embedded` is `repr(C)` of byte arrays, so its bytes are
        // initialized and as long as its size.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                core::ptr::from_ref(&EMBEDDED).cast::<u8>(),
                size_of::<Embedded<4>>(),
            )
        };
        assert_eq!(bytes, embedding(b"abcd").as_slice());
        assert_eq!(EMBEDDED.store(), b"abcd");

        let trust = store(1, &[(&keys().root, ROOT)], &[]);
        assert_eq!(find(&image_of(&embedding(&trust))), Ok(trust.as_slice()));
    }

    // Defect caught: a pack that signs under no store, or under a store it
    // cannot tell from another, when the image holds no marker or two.
    #[test]
    fn an_image_without_one_marker_is_refused()
    {
        let trust = store(1, &[(&keys().root, ROOT)], &[]);
        assert_eq!(find(b"no store here"), Err(FindError::NoMarker));
        let mut twice = image_of(&embedding(&trust));
        twice.extend_from_slice(&MARKER);
        assert_eq!(find(&twice), Err(FindError::SeveralMarkers));
    }

    // Defect caught: a length past the image read out of bounds, or a store
    // that does not parse taken as the bootloader's.
    #[test]
    fn a_short_image_or_a_store_that_does_not_parse_is_refused()
    {
        let trust = store(1, &[(&keys().root, ROOT)], &[]);
        let whole = embedding(&trust);
        assert_eq!(find(&whole[..MARKER.len() + 2]), Err(FindError::Length));
        assert_eq!(find(&whole[..whole.len() - 1]), Err(FindError::Length));
        let mut bad = whole.clone();
        bad[PREFIX_LEN] ^= 0xff;
        assert_eq!(find(&bad), Err(FindError::Store(StoreError::Magic)));
    }

    // Defect caught: a marker a label could hold, read as the store's start.
    #[test]
    fn the_marker_is_not_utf8()
    {
        core::str::from_utf8(&MARKER).unwrap_err();
    }
}
