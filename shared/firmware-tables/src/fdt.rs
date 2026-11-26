// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/firmware-tables/src/fdt.rs

//! The flattened device tree (FDT): the blob's header, the structure block's
//! tokens as events, and the strings block, per the Devicetree Specification
//! v0.4 chapter 5 (version 17 layout). What a node or a property means is the
//! consumer's; the format reads only the tree's own structure. Operates on a
//! caller-mapped byte slice of the blob. No alloc.

use crate::bytes::{be_u32, be_u64};

/// The magic number at the start of a blob.
pub const FDT_MAGIC: u32 = 0xd00d_feed;

/// Structure block token: a node opens, its name following.
pub const FDT_BEGIN_NODE: u32 = 0x0000_0001;
/// Structure block token: the open node closes.
pub const FDT_END_NODE: u32 = 0x0000_0002;
/// Structure block token: a property, its length and name offset following.
pub const FDT_PROP: u32 = 0x0000_0003;
/// Structure block token: padding, skipped.
pub const FDT_NOP: u32 = 0x0000_0004;
// FDT_END (0x9) and any unrecognised token fall through the walker's
// wildcard arm and terminate the stream.

// Offsets in the FDT header.
/// Header offset of the magic number.
pub const HDR_MAGIC: usize = 0;
/// Header offset of `totalsize`: the blob's length.
pub const HDR_TOTALSIZE: usize = 4;
/// Header offset of `off_dt_struct`: the structure block's offset.
pub const HDR_OFF_DT_STRUCT: usize = 8;
/// Header offset of `off_dt_strings`: the strings block's offset.
pub const HDR_OFF_DT_STRINGS: usize = 12;
// HDR_OFF_MEM_RSVMAP: usize = 16 (unused here)
// HDR_VERSION: usize = 20 (accepted silently for v17-compatible blobs)
// HDR_LAST_COMP_VERSION: usize = 24 (not checked — QEMU emits v17)
/// Header offset of `size_dt_strings`: the strings block's length.
pub const HDR_SIZE_DT_STRINGS: usize = 32;
/// Header offset of `size_dt_struct`: the structure block's length.
pub const HDR_SIZE_DT_STRUCT: usize = 36;
/// Bytes of the header this decoder reads.
pub const HDR_LEN: usize = 40;

/// A flat device tree view: the blob, with where its structure and strings
/// blocks lie.
#[derive(Clone, Copy, Debug)]
pub struct Fdt<'a>
{
    /// The whole blob.
    blob: &'a [u8],
    /// The structure block's offset.
    struct_off: usize,
    /// The structure block's length.
    struct_len: usize,
    /// The strings block's offset.
    strings_off: usize,
    /// The strings block's length.
    strings_len: usize,
}

impl<'a> Fdt<'a>
{
    /// Validate the blob header and return a view. Returns `None` for a blob
    /// shorter than the 40-byte header, a bad magic, a `totalsize` beyond the
    /// blob, a structure block beyond `totalsize`, or a strings block beyond
    /// `totalsize` (Devicetree Specification v0.4 § 5.2).
    #[must_use]
    pub fn new(blob: &'a [u8]) -> Option<Self>
    {
        if blob.len() < HDR_LEN || be_u32(blob, HDR_MAGIC) != FDT_MAGIC
        {
            return None;
        }
        let totalsize = be_u32(blob, HDR_TOTALSIZE) as usize;
        if totalsize > blob.len()
        {
            return None;
        }
        let struct_off = be_u32(blob, HDR_OFF_DT_STRUCT) as usize;
        let struct_len = be_u32(blob, HDR_SIZE_DT_STRUCT) as usize;
        let strings_off = be_u32(blob, HDR_OFF_DT_STRINGS) as usize;
        let strings_len = be_u32(blob, HDR_SIZE_DT_STRINGS) as usize;
        if struct_off
            .checked_add(struct_len)
            .is_none_or(|end| end > totalsize)
            || strings_off
                .checked_add(strings_len)
                .is_none_or(|end| end > totalsize)
        {
            return None;
        }
        Some(Self {
            blob,
            struct_off,
            struct_len,
            strings_off,
            strings_len,
        })
    }

    /// The whole blob.
    #[must_use]
    pub const fn blob(&self) -> &'a [u8]
    {
        self.blob
    }

    /// The structure block's offset in the blob.
    #[must_use]
    pub const fn struct_off(&self) -> usize
    {
        self.struct_off
    }

    /// The structure block's length.
    #[must_use]
    pub const fn struct_len(&self) -> usize
    {
        self.struct_len
    }

    /// The offset in the blob where the structure block ends.
    #[must_use]
    pub const fn struct_end(&self) -> usize
    {
        self.struct_off.saturating_add(self.struct_len)
    }

    /// The strings block's offset in the blob.
    #[must_use]
    pub const fn strings_off(&self) -> usize
    {
        self.strings_off
    }

    /// The strings block's length.
    #[must_use]
    pub const fn strings_len(&self) -> usize
    {
        self.strings_len
    }

    /// Read a NUL-terminated string from the strings block at `off`: the
    /// bytes from `off` to the first NUL or the block's end. An `off` at or
    /// past the block's end reads as empty, as does a block the blob does not
    /// hold.
    #[must_use]
    pub fn read_string(&self, off: usize) -> &'a [u8]
    {
        let Some(block) = self
            .strings_off
            .checked_add(self.strings_len)
            .and_then(|end| self.blob.get(self.strings_off..end))
        else
        {
            return &[];
        };
        let Some(remain) = block.get(off..)
        else
        {
            return &[];
        };
        // `split` always yields a first piece: the bytes up to the first NUL.
        remain.split(|&b| b == 0).next().unwrap_or(&[])
    }

    /// The events of the structure block, from its start to where
    /// [`next_event`] ends the walk.
    #[must_use]
    pub const fn events(&self) -> Events<'a>
    {
        self.events_at(self.struct_off)
    }

    /// The events of the structure block from the token at `off`, to where
    /// [`next_event`] ends the walk.
    #[must_use]
    pub const fn events_at(&self, off: usize) -> Events<'a>
    {
        Events {
            fdt: *self,
            off,
            end: self.struct_end(),
        }
    }
}

/// Events yielded by [`next_event`]. Node names are not consumed; the walk
/// skips them in-stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdtEvent<'a>
{
    /// A node opens; `start` is its `FDT_BEGIN_NODE` token's offset.
    BeginNode
    {
        /// The token's offset in the blob.
        start: usize,
    },
    /// The open node closes.
    EndNode,
    /// A property of the open node.
    Prop
    {
        /// The property's name, from the strings block.
        name: &'a [u8],
        /// The property's value.
        data: &'a [u8],
        /// The offset in the blob of the property's value.
        at: usize,
    },
}

/// The event of the token at `off` of `fdt`'s structure block, which ends
/// at `end`, past any `FDT_NOP` tokens, and the offset after it; `None` at
/// `FDT_END`, an unknown token, or a token that runs past `end`.
#[must_use]
pub fn next_event<'a>(fdt: &Fdt<'a>, off: usize, end: usize) -> Option<(FdtEvent<'a>, usize)>
{
    let mut tok_off = off;
    loop
    {
        let after_tok = tok_off.checked_add(4).filter(|&e| e <= end)?;
        match be_u32(fdt.blob, tok_off)
        {
            FDT_BEGIN_NODE =>
            {
                // Name is NUL-terminated, padded to 4 bytes. The walk does not
                // use the node name; it just skips it.
                let mut p = after_tok;
                while p < end && fdt.blob.get(p).is_some_and(|&b| b != 0)
                {
                    p = p.saturating_add(1);
                }
                // skip NUL + padding
                let next = p.saturating_add(1).saturating_add(3) & !3;
                return Some((FdtEvent::BeginNode { start: tok_off }, next));
            }
            FDT_END_NODE => return Some((FdtEvent::EndNode, after_tok)),
            FDT_PROP =>
            {
                let hdr_end = after_tok.checked_add(8).filter(|&e| e <= end)?;
                let len = be_u32(fdt.blob, after_tok) as usize;
                let nameoff = be_u32(fdt.blob, after_tok.saturating_add(4)) as usize;
                let data_end = hdr_end.checked_add(len).filter(|&e| e <= end)?;
                let data = fdt.blob.get(hdr_end..data_end)?;
                let next = data_end.saturating_add(3) & !3;
                let name = fdt.read_string(nameoff);
                return Some((
                    FdtEvent::Prop {
                        name,
                        data,
                        at: hdr_end,
                    },
                    next,
                ));
            }
            FDT_NOP => tok_off = after_tok,
            // FDT_END or any unknown token terminates the walk.
            _ => return None,
        }
    }
}

/// The events of a structure block, in order ([`Fdt::events`],
/// [`Fdt::events_at`]): each as [`next_event`] reads it, until it ends the
/// walk.
#[derive(Clone, Debug)]
pub struct Events<'a>
{
    fdt: Fdt<'a>,
    off: usize,
    end: usize,
}

impl<'a> Iterator for Events<'a>
{
    type Item = FdtEvent<'a>;

    fn next(&mut self) -> Option<FdtEvent<'a>>
    {
        let (event, next) = next_event(&self.fdt, self.off, self.end)?;
        self.off = next;
        Some(event)
    }
}

/// Check whether a `compatible` property value (a list of NUL-separated
/// strings) contains `needle`.
#[must_use]
pub fn compatible_contains(data: &[u8], needle: &[u8]) -> bool
{
    let mut rest = data;
    while !rest.is_empty()
    {
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let (entry, tail) = rest.split_at(end);
        if entry == needle
        {
            return true;
        }
        // Skip the entry's NUL terminator.
        rest = tail.get(1..).unwrap_or(&[]);
    }
    false
}

/// Read a 1- or 2-cell big-endian value at `off`; `None` for any other
/// cell count.
#[must_use]
pub fn read_cells(data: &[u8], off: usize, cells: usize) -> Option<u64>
{
    match cells
    {
        1 => Some(u64::from(be_u32(data, off))),
        2 => Some(be_u64(data, off)),
        _ => None,
    }
}

/// A `reg` property's first `(address, size)` pair, in `addr_cells` and
/// `size_cells` cells of 1 or 2; `None` for other cell counts or a property
/// shorter than the pair.
#[must_use]
pub fn reg_pair(data: &[u8], addr_cells: usize, size_cells: usize) -> Option<(u64, u64)>
{
    if addr_cells
        .checked_add(size_cells)
        .and_then(|cells| cells.checked_mul(4))
        .is_none_or(|need| data.len() < need)
    {
        return None;
    }
    let base = read_cells(data, 0, addr_cells)?;
    let size = read_cells(data, addr_cells.saturating_mul(4), size_cells)?;
    Some((base, size))
}

#[cfg(test)]
mod tests
{
    use super::*;

    /// Minimal FDT v17 blob builder: header, structure block, strings block.
    struct Builder
    {
        strct: Vec<u8>,
        strings: Vec<u8>,
    }

    impl Builder
    {
        fn new() -> Self
        {
            Self {
                strct: Vec::new(),
                strings: Vec::new(),
            }
        }

        fn token(mut self, tok: u32) -> Self
        {
            self.strct.extend_from_slice(&tok.to_be_bytes());
            self
        }

        fn begin(mut self, name: &str) -> Self
        {
            self = self.token(FDT_BEGIN_NODE);
            self.strct.extend_from_slice(name.as_bytes());
            self.strct.push(0);
            while self.strct.len() % 4 != 0
            {
                self.strct.push(0);
            }
            self
        }

        fn end(self) -> Self
        {
            self.token(FDT_END_NODE)
        }

        fn prop(mut self, name: &str, data: &[u8]) -> Self
        {
            let nameoff = u32::try_from(self.strings.len()).unwrap();
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            self = self.token(FDT_PROP);
            self.strct
                .extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
            self.strct.extend_from_slice(&nameoff.to_be_bytes());
            self.strct.extend_from_slice(data);
            while self.strct.len() % 4 != 0
            {
                self.strct.push(0);
            }
            self
        }

        fn finish(self) -> Vec<u8>
        {
            let strct = self.token(0x9);
            let off_struct = 40u32;
            let size_struct = u32::try_from(strct.strct.len()).unwrap();
            let off_strings = off_struct + size_struct;
            let total = off_strings + u32::try_from(strct.strings.len()).unwrap();
            let mut blob = Vec::new();
            for word in [
                FDT_MAGIC,
                total,
                off_struct,
                off_strings,
                0,
                17,
                16,
                0,
                u32::try_from(strct.strings.len()).unwrap(),
                size_struct,
            ]
            {
                blob.extend_from_slice(&word.to_be_bytes());
            }
            blob.extend_from_slice(&strct.strct);
            blob.extend_from_slice(&strct.strings);
            blob
        }
    }

    /// A blob of one node holding the property `name` with `data`.
    fn one_property(name: &str, data: &[u8]) -> Vec<u8>
    {
        Builder::new().begin("").prop(name, data).end().finish()
    }

    #[test]
    fn a_property_reads_its_name_value_and_offset()
    {
        let blob = one_property("reg", &[1, 2, 3, 4]);
        let fdt = Fdt::new(&blob).unwrap();
        let events: Vec<_> = fdt.events().collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], FdtEvent::BeginNode { start: HDR_LEN });
        let FdtEvent::Prop { name, data, at } = events[1]
        else
        {
            panic!("not a property: {:?}", events[1]);
        };
        assert_eq!((name, data), (b"reg".as_slice(), [1, 2, 3, 4].as_slice()));
        assert_eq!(&blob[at..at + 4], [1, 2, 3, 4]);
        assert_eq!(events[2], FdtEvent::EndNode);
    }

    #[test]
    fn events_at_starts_from_the_token_given()
    {
        let blob = one_property("reg", &[0; 4]);
        let fdt = Fdt::new(&blob).unwrap();
        let from_prop = fdt.events_at(HDR_LEN + 8).collect::<Vec<_>>();
        assert_eq!(from_prop.len(), 2);
        assert_eq!(fdt.events().count(), 3);
        assert_eq!(fdt.events_at(fdt.struct_end()).count(), 0);
    }

    #[test]
    fn nop_tokens_are_skipped()
    {
        let blob = Builder::new()
            .token(FDT_NOP)
            .begin("")
            .token(FDT_NOP)
            .end()
            .finish();
        let fdt = Fdt::new(&blob).unwrap();
        assert_eq!(
            fdt.events().collect::<Vec<_>>(),
            [
                FdtEvent::BeginNode { start: HDR_LEN + 4 },
                FdtEvent::EndNode
            ]
        );
    }

    #[test]
    fn property_running_past_the_structure_block_ends_the_walk()
    {
        let mut blob = one_property("reg", &[0; 4]);
        // The property's length word follows the BEGIN_NODE token and its
        // name ("") and the FDT_PROP token.
        let len_off = HDR_LEN + 8 + 4;
        blob[len_off..len_off + 4].copy_from_slice(&0x1000u32.to_be_bytes());
        let fdt = Fdt::new(&blob).unwrap();
        assert_eq!(fdt.events().count(), 1);
    }

    #[test]
    fn property_header_running_past_the_structure_block_ends_the_walk()
    {
        // The structure block ends right after an FDT_PROP token, so its
        // 8-byte length / name-offset header lies outside it.
        let mut blob = Builder::new().begin("").token(FDT_PROP).finish();
        let size_struct = 8 + 4;
        blob[HDR_SIZE_DT_STRUCT..HDR_SIZE_DT_STRUCT + 4]
            .copy_from_slice(&u32::try_from(size_struct).unwrap().to_be_bytes());
        let fdt = Fdt::new(&blob).unwrap();
        let mut events = fdt.events();
        assert!(matches!(events.next(), Some(FdtEvent::BeginNode { .. })));
        assert!(events.next().is_none());
    }

    #[test]
    fn header_with_bad_magic_is_rejected()
    {
        let mut blob = one_property("reg", &[0; 4]);
        blob[0] = 0;
        assert!(Fdt::new(&blob).is_none());
    }

    #[test]
    fn header_with_totalsize_beyond_the_blob_is_rejected()
    {
        let blob = one_property("reg", &[0; 4]);
        assert!(Fdt::new(&blob[..blob.len() - 1]).is_none());
    }

    #[test]
    fn header_with_structure_block_beyond_totalsize_is_rejected()
    {
        let mut blob = one_property("reg", &[0; 4]);
        let size_struct = be_u32(&blob, HDR_SIZE_DT_STRUCT) + 0x100;
        blob[HDR_SIZE_DT_STRUCT..HDR_SIZE_DT_STRUCT + 4]
            .copy_from_slice(&size_struct.to_be_bytes());
        assert!(Fdt::new(&blob).is_none());
    }

    #[test]
    fn header_with_strings_block_beyond_totalsize_is_rejected()
    {
        let mut blob = one_property("reg", &[0; 4]);
        let size_strings = be_u32(&blob, HDR_SIZE_DT_STRINGS) + 1;
        blob[HDR_SIZE_DT_STRINGS..HDR_SIZE_DT_STRINGS + 4]
            .copy_from_slice(&size_strings.to_be_bytes());
        assert!(Fdt::new(&blob).is_none());
        let mut blob = one_property("reg", &[0; 4]);
        blob[HDR_SIZE_DT_STRINGS..HDR_SIZE_DT_STRINGS + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(Fdt::new(&blob).is_none());
    }

    #[test]
    fn blob_shorter_than_the_header_is_rejected()
    {
        let blob = one_property("reg", &[0; 4]);
        assert!(Fdt::new(&[]).is_none());
        assert!(Fdt::new(&blob[..HDR_LEN - 1]).is_none());
    }

    #[test]
    fn a_string_is_read_only_inside_the_strings_block()
    {
        let blob = one_property("reg", &[0; 4]);
        let mut fdt = Fdt::new(&blob).unwrap();
        assert_eq!(fdt.strings_len(), 4);
        assert_eq!(fdt.read_string(0), b"reg");
        assert_eq!(fdt.read_string(1), b"eg");
        assert_eq!(fdt.read_string(3), b"");
        assert_eq!(fdt.read_string(4), b"");
        assert_eq!(fdt.read_string(usize::MAX), b"");
        // A block with no NUL ends at its own end, not at the blob's.
        fdt.strings_len = 2;
        assert_eq!(fdt.read_string(0), b"re");
        assert_eq!(fdt.read_string(2), b"");
    }

    #[test]
    fn a_compatible_list_holds_an_entry_only_whole()
    {
        let list = b"abc\0de\0f";
        assert!(compatible_contains(list, b"abc"));
        assert!(compatible_contains(list, b"de"));
        assert!(compatible_contains(list, b"f"));
        assert!(!compatible_contains(list, b"ab"));
        assert!(!compatible_contains(list, b"bc"));
        assert!(!compatible_contains(b"", b"a"));
    }

    #[test]
    fn a_reg_pair_is_read_in_one_or_two_cells()
    {
        let data = [0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4];
        assert_eq!(reg_pair(&data, 2, 1), Some((0x1_0000_0002, 3)));
        assert_eq!(reg_pair(&data, 1, 1), Some((1, 2)));
        assert_eq!(reg_pair(&data, 2, 2), Some((0x1_0000_0002, 0x3_0000_0004)));
        assert_eq!(reg_pair(&data, 3, 1), None);
        assert_eq!(reg_pair(&data, 2, 0), None);
        assert_eq!(reg_pair(&data[..11], 2, 1), None);
        assert_eq!(reg_pair(&data, usize::MAX, 1), None);
    }
}

/// The proofs of the property's checks of the device tree decoders
/// (docs/testing.md § Bounded verification): the header whole, the token at
/// any place, a `reg` property's cells, and the `compatible` match. What lies
/// outside the proofs is the loop that drives the steps: `Events` from one
/// token to the next; the fuzz target `firmware-tables`, the replay of the
/// checked-in inputs and the unit tests check it.
#[cfg(kani)]
mod proofs
{
    use super::Fdt;
    use crate::property::fdt as property;

    /// Every input of at most 44 bytes holds the header's contract: the
    /// header is 40 bytes, so its every field and a blob cut inside it are
    /// reached. No loop.
    #[kani::proof]
    fn every_header_reads_as_its_fields()
    {
        let bytes: [u8; 44] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        let _ = property::header_holds(&bytes[..len]);
    }

    /// Every token at place 4 of a structure block that ends anywhere in a
    /// blob of 24 bytes, with the strings block anywhere, reads as the
    /// block's: 20 bytes hold a property with its 8-byte header and a value,
    /// a node and its name, and runs of `FDT_NOP`, and a block that ends
    /// before a token's end cuts it short. The loops are the NOPs, the node's
    /// name and the property's name.
    #[kani::proof]
    #[kani::unwind(22)]
    fn every_token_reads_as_its_fields()
    {
        let bytes: [u8; 24] = kani::any();
        let end: usize = kani::any();
        kani::assume(end <= bytes.len());
        let fdt = Fdt {
            blob: &bytes,
            struct_off: 0,
            struct_len: end,
            strings_off: kani::any(),
            strings_len: kani::any(),
        };
        let _ = property::token_holds(&fdt, 4, end);
    }

    /// Every property value of at most 16 bytes reads as a `reg` of any cell
    /// counts: 16 bytes hold a pair of two cells each. No loop.
    #[kani::proof]
    fn every_reg_reads_as_its_cells()
    {
        let bytes: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= bytes.len());
        property::reg_holds(&bytes[..len], kani::any(), kani::any());
    }

    /// Every `compatible` value of 7 bytes holds a two-byte entry exactly
    /// when one of its entries is it: 7 bytes hold the entry with a NUL
    /// before and after it, the entry cut short at the end, an entry it
    /// begins, and entries of every other length. The match takes the entry
    /// as a parameter, so its length is the proof's choice; the fuzz target
    /// drives `pci-host-ecam-generic`. The loops are the entries and their
    /// bytes.
    #[kani::proof]
    #[kani::unwind(9)]
    fn every_compatible_list_matches_its_entries()
    {
        let bytes: [u8; 7] = kani::any();
        property::compatible_holds(&bytes, b"ab");
    }
}
