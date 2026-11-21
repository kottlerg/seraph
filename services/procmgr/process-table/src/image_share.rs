// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/procmgr/process-table/src/image_share.rs

//! Which pages of an image the instances of one binary share, and the
//! table of the memory objects that hold them.
//!
//! procmgr seals the pages of a binary's `PT_LOAD` segments that are not
//! writable (text and read-only data), which no relocation touches, into one
//! memory object, and attaches it shared to each demand-paged instance
//! (services/procmgr/README.md § Image Sharing). [`share_layout`] says which
//! segments go into the object and where, and [`ImageCache`] keeps one
//! object per binary body for as long as an instance attaches it. Neither
//! touches a capability: the object handle is a slot index procmgr holds.

extern crate alloc;

use alloc::vec::Vec;

/// Bytes in a page.
const PAGE: u64 = 4096;

/// A `PT_LOAD` segment as the share layout reads it: its unbiased address and
/// size in memory, and whether it is writable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentSpan
{
    /// The segment's address in the image (`p_vaddr`), before the load bias.
    pub vaddr: u64,
    /// The segment's size in memory (`p_memsz`).
    pub memsz: u64,
    /// Whether the segment is writable (`PF_W`).
    pub writable: bool,
}

/// Where a shared segment's pages lie in the image object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharedSegment
{
    /// The segment's first page in the image, before the load bias.
    pub first_page: u64,
    /// The segment's pages, from `first_page`.
    pub pages: u64,
    /// The object page that holds `first_page`.
    pub object_page: u64,
}

/// The layout of an image's object: for each segment of the image, in order,
/// where its pages lie in the object, or `None` for a segment that stays
/// private; and the object's pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareLayout
{
    /// One entry per segment given to [`share_layout`], in its order.
    pub segments: Vec<Option<SharedSegment>>,
    /// The object's pages, the sum of the shared segments' pages.
    pub pages: u64,
}

/// The pages of one segment, `[first, end)` in the image, page-rounded;
/// `None` for an empty segment or one whose end overflows.
fn page_span(seg: &SegmentSpan) -> Option<(u64, u64)>
{
    if seg.memsz == 0
    {
        return None;
    }
    let first = seg.vaddr & !(PAGE - 1);
    let end = seg.vaddr.checked_add(seg.memsz)?.checked_add(PAGE - 1)? & !(PAGE - 1);
    Some((first, end))
}

/// The share layout of an image whose `PT_LOAD` segments are `segments`, in
/// program-header order: each segment that is not writable takes the next
/// pages of the object, its page span as the loader maps it, and every other
/// segment, and every empty one, stays private.
///
/// Returns `None`, so the image is loaded private whole, when no segment is
/// shared, when a segment's end overflows, when the object's pages overflow,
/// or when a shared segment's pages meet another segment's: a page that holds
/// bytes of a writable segment is relocated, and two segments loaded on one
/// page are refused by the private loader as by memmgr's attach, which the
/// fallback then reports.
#[must_use]
pub fn share_layout(segments: &[SegmentSpan]) -> Option<ShareLayout>
{
    let mut layout = ShareLayout {
        segments: Vec::with_capacity(segments.len()),
        pages: 0,
    };
    for (i, seg) in segments.iter().enumerate()
    {
        let span = if seg.memsz == 0
        {
            None
        }
        else
        {
            Some(page_span(seg)?)
        };
        let shared = match span
        {
            Some((first, end)) if !seg.writable =>
            {
                let meets = segments.iter().enumerate().any(|(j, other)| {
                    j != i
                        && page_span(other)
                            .is_some_and(|(o_first, o_end)| o_first < end && first < o_end)
                });
                if meets
                {
                    return None;
                }
                let pages = end.saturating_sub(first) / PAGE;
                let shared = SharedSegment {
                    first_page: first,
                    pages,
                    object_page: layout.pages,
                };
                layout.pages = layout.pages.checked_add(pages)?;
                Some(shared)
            }
            _ => None,
        };
        layout.segments.push(shared);
    }
    (layout.pages != 0).then_some(layout)
}

/// What names one binary's object in the cache: the SHA-512 of its signed body
/// and the body's length, both from the signature record that verified it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageKey
{
    /// The body's SHA-512 (`objsig::Attributes::body_hash`).
    pub hash: [u8; 64],
    /// The body's length in bytes.
    pub len: u64,
}

/// One instance's use of a cached object, which [`ImageCache::acquire`] and
/// [`ImageCache::insert`] give and [`ImageCache::release`] takes back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageRef
{
    /// The entry's id, which the instance's process entry keeps; never `0`.
    pub id: u64,
    /// Slot in procmgr's `CSpace` of the object handle.
    pub handle: u64,
    /// The object's pages.
    pub pages: u64,
}

/// What [`ImageCache::insert`] did with a new object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inserted
{
    /// The object is the binary's; the reference is to it.
    New(ImageRef),
    /// Another create sealed the binary's object first: the reference is to
    /// that one, and the caller releases the object it sealed.
    Existing(ImageRef),
}

/// One cached object.
#[derive(Clone, Copy, Debug)]
struct Entry
{
    key: ImageKey,
    id: u64,
    handle: u64,
    pages: u64,
    /// Live instances that attach it, at least 1.
    refs: u64,
}

/// The image objects procmgr holds, one per binary body, each kept while an
/// instance attaches it. The table is procmgr's alone, behind its own lock,
/// which no IPC call is made under.
#[derive(Debug, Default)]
pub struct ImageCache
{
    entries: Vec<Entry>,
    /// The id the next entry takes, after an increment, so no id is `0`.
    last_id: u64,
}

impl ImageCache
{
    /// An empty cache.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            entries: Vec::new(),
            last_id: 0,
        }
    }

    /// A reference to the object of `key`, counted, or `None` when the
    /// cache holds none.
    pub fn acquire(&mut self, key: &ImageKey) -> Option<ImageRef>
    {
        let entry = self.entries.iter_mut().find(|e| e.key == *key)?;
        entry.refs = entry.refs.checked_add(1)?;
        Some(ImageRef {
            id: entry.id,
            handle: entry.handle,
            pages: entry.pages,
        })
    }

    /// Record `handle`, an object of `pages` pages just sealed for `key`,
    /// with one reference, unless the cache gained an object for `key` since
    /// the caller's [`Self::acquire`] missed: that one is referenced instead.
    /// `None` when the table cannot grow; the caller releases its object.
    pub fn insert(&mut self, key: ImageKey, handle: u64, pages: u64) -> Option<Inserted>
    {
        if let Some(existing) = self.acquire(&key)
        {
            return Some(Inserted::Existing(existing));
        }
        self.entries.try_reserve(1).ok()?;
        let id = self.last_id.checked_add(1)?;
        self.last_id = id;
        self.entries.push(Entry {
            key,
            id,
            handle,
            pages,
            refs: 1,
        });
        Some(Inserted::New(ImageRef { id, handle, pages }))
    }

    /// The key and the object handle of the entry `id`, or `None` for an id
    /// the cache does not hold.
    #[must_use]
    pub fn find(&self, id: u64) -> Option<(ImageKey, u64)>
    {
        self.entries
            .iter()
            .find(|e| e.id == id)
            .map(|e| (e.key, e.handle))
    }

    /// Drop one reference to the entry `id`. Returns the object handle when
    /// that was the last, the entry then gone from the cache, so the caller
    /// releases the object (`memmgr_labels::OBJECT_RELEASE`) and deletes the
    /// handle; `None` otherwise, and for an id the cache does not hold.
    pub fn release(&mut self, id: u64) -> Option<u64>
    {
        let at = self.entries.iter().position(|e| e.id == id)?;
        let entry = self.entries.get_mut(at)?;
        entry.refs = entry.refs.saturating_sub(1);
        if entry.refs != 0
        {
            return None;
        }
        Some(self.entries.swap_remove(at).handle)
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    fn ro(vaddr: u64, memsz: u64) -> SegmentSpan
    {
        SegmentSpan {
            vaddr,
            memsz,
            writable: false,
        }
    }

    fn rw(vaddr: u64, memsz: u64) -> SegmentSpan
    {
        SegmentSpan {
            vaddr,
            memsz,
            writable: true,
        }
    }

    fn key(byte: u8) -> ImageKey
    {
        ImageKey {
            hash: [byte; 64],
            len: 100,
        }
    }

    #[test]
    fn read_only_segments_share_in_order_and_writable_ones_stay_private()
    {
        // rodata (with the header), text, relocated data, as lld lays out a
        // position-independent executable.
        let layout = share_layout(&[ro(0, 0x1234), ro(0x2234, 0x3000), rw(0x6000, 0x800)])
            .expect("two read-only segments share");
        assert_eq!(
            layout.segments,
            [
                Some(SharedSegment {
                    first_page: 0,
                    pages: 2,
                    object_page: 0,
                }),
                Some(SharedSegment {
                    first_page: 0x2000,
                    pages: 4,
                    object_page: 2,
                }),
                None,
            ]
        );
        assert_eq!(layout.pages, 6);
    }

    #[test]
    fn empty_segments_stay_private_and_keep_their_place()
    {
        let layout =
            share_layout(&[ro(0x1000, 0), ro(0x1000, 0x10)]).expect("the non-empty segment shares");
        assert_eq!(layout.segments.first(), Some(&None));
        assert_eq!(layout.pages, 1);
    }

    #[test]
    fn an_image_with_no_read_only_segment_shares_nothing()
    {
        assert_eq!(share_layout(&[rw(0, 0x1000)]), None);
        assert_eq!(share_layout(&[]), None);
    }

    #[test]
    fn a_shared_page_that_holds_writable_bytes_refuses_the_layout()
    {
        // Text ends on the page relocated data starts on.
        assert_eq!(share_layout(&[ro(0, 0x1800), rw(0x1800, 0x100)]), None);
    }

    #[test]
    fn two_read_only_segments_on_one_page_refuse_the_layout()
    {
        assert_eq!(share_layout(&[ro(0, 0x800), ro(0x800, 0x800)]), None);
    }

    #[test]
    fn a_segment_whose_end_overflows_refuses_the_layout()
    {
        assert_eq!(share_layout(&[ro(u64::MAX - 0x10, 0x100)]), None);
    }

    #[test]
    fn instances_of_one_binary_share_its_entry_until_the_last_release()
    {
        let mut cache = ImageCache::new();
        assert_eq!(cache.acquire(&key(1)), None);
        let Some(Inserted::New(first)) = cache.insert(key(1), 40, 7)
        else
        {
            panic!("the first object is new");
        };
        let second = cache.acquire(&key(1)).expect("the binary is cached");
        assert_eq!(second, first);
        assert_eq!(cache.release(first.id), None);
        assert_eq!(cache.release(second.id), Some(40));
        assert_eq!(cache.acquire(&key(1)), None);
    }

    #[test]
    fn a_second_seal_of_one_binary_takes_the_first_object()
    {
        let mut cache = ImageCache::new();
        let Some(Inserted::New(first)) = cache.insert(key(1), 40, 7)
        else
        {
            panic!("the first object is new");
        };
        assert_eq!(cache.insert(key(1), 41, 7), Some(Inserted::Existing(first)));
        // Both references count: the first release keeps the object.
        assert_eq!(cache.release(first.id), None);
        assert_eq!(cache.release(first.id), Some(40));
    }

    #[test]
    fn binaries_with_other_bodies_take_other_entries()
    {
        let mut cache = ImageCache::new();
        let Some(Inserted::New(one)) = cache.insert(key(1), 40, 7)
        else
        {
            panic!("new");
        };
        let other = ImageKey {
            hash: [1; 64],
            len: 101,
        };
        let Some(Inserted::New(two)) = cache.insert(other, 41, 7)
        else
        {
            panic!("a body of another length is another binary");
        };
        assert_ne!(one.id, two.id);
        assert_eq!(cache.release(two.id), Some(41));
        assert_eq!(cache.acquire(&key(1)).map(|r| r.handle), Some(40));
    }

    #[test]
    fn a_release_of_an_unknown_id_changes_nothing()
    {
        let mut cache = ImageCache::new();
        let Some(Inserted::New(one)) = cache.insert(key(1), 40, 7)
        else
        {
            panic!("new");
        };
        assert_eq!(cache.release(one.id.wrapping_add(1)), None);
        assert_eq!(cache.release(one.id), Some(40));
    }

    #[test]
    fn a_reference_finds_its_key_and_handle_until_the_entry_goes()
    {
        let mut cache = ImageCache::new();
        let Some(Inserted::New(one)) = cache.insert(key(1), 40, 7)
        else
        {
            panic!("new");
        };
        assert_eq!(cache.find(one.id), Some((key(1), 40)));
        assert_eq!(cache.find(one.id.wrapping_add(1)), None);
        assert_eq!(cache.release(one.id), Some(40));
        assert_eq!(cache.find(one.id), None);
    }
}
