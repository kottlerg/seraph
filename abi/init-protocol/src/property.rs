// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// abi/init-protocol/src/property.rs

//! The contract of this crate's parser of the handover's module-name table as
//! one property over any input, [`init_protocol_holds`], which the fuzz target
//! `init-protocol` (`xtask/fuzz/targets`) drives, the replay test of the
//! checked-in inputs under `fuzz/init-protocol/` runs on every
//! `cargo xtask test`, and the proofs of `lib.rs` check on every input up to
//! their bounds (docs/testing.md § Fuzzing, § Bounded verification). Init runs
//! [`find_module_slot`] over the table the kernel copies from the boot
//! modules' names, which the bundle carries.

use crate::{
    INIT_MODULE_NAME_LEN, InitModuleName, find_module_slot, module_name_str, slot_if_carries,
};

/// The most table entries an input is read as.
const MAX_NAMES: usize = 8;

/// The bytes of one table entry: its slot, then its name.
const ENTRY_LEN: usize = 8 + INIT_MODULE_NAME_LEN;

/// The longest request: one byte past the longest name, which no entry holds.
const MAX_REQUEST: usize = INIT_MODULE_NAME_LEN + 1;

/// The request lengths an input names: 0 to [`MAX_REQUEST`].
const REQUEST_LENGTHS: usize = MAX_REQUEST + 1;

/// Check the parser's contract on `input`, read as a request and a table:
/// the request's length in the first two bytes (little-endian, modulo
/// `MAX_REQUEST + 1`), its bytes after them, then up to [`MAX_NAMES`]
/// entries of a little-endian slot and a name.
///
/// # Panics
///
/// When the parser breaks its contract on `input`: a defect of the parser.
pub fn init_protocol_holds(input: &[u8])
{
    let request_len = input
        .get(..2)
        .and_then(|len| len.try_into().ok())
        .map_or(0, |len| usize::from(u16::from_le_bytes(len)))
        .checked_rem(REQUEST_LENGTHS)
        .unwrap_or(0);
    let request = input
        .get(2..)
        .unwrap_or_default()
        .get(..request_len)
        .unwrap_or_else(|| input.get(2..).unwrap_or_default());
    let table = input
        .get(request.len().saturating_add(2)..)
        .unwrap_or_default();
    let mut names = [InitModuleName {
        slot: 0,
        name: [0; INIT_MODULE_NAME_LEN],
    }; MAX_NAMES];
    let (entries, _) = table.as_chunks::<ENTRY_LEN>();
    let count = entries.len().min(MAX_NAMES);
    for (entry, raw) in names.iter_mut().zip(entries)
    {
        let (slot, name) = raw.split_at(8);
        entry.slot = slot.try_into().map_or(0, u64::from_le_bytes);
        entry.name.copy_from_slice(name);
    }
    for entry in names.get(..count).unwrap_or_default()
    {
        name_holds(&entry.name);
        slot_holds(entry, request);
    }
    lookup_holds(names.get(..count).unwrap_or_default(), request);
}

/// Whether the NUL-padded table name `name` stands for `request`: its bytes
/// before the first NUL, or the whole name when it holds none
/// ([`InitModuleName::name`]), are `request`'s. Each byte is compared at its
/// own index, so the check makes no search or compare of a length the
/// input decides.
fn stands_for(name: &[u8; INIT_MODULE_NAME_LEN], request: &[u8]) -> bool
{
    let mut ended = false;
    let mut same = request.len() <= INIT_MODULE_NAME_LEN;
    for (at, &byte) in name.iter().enumerate()
    {
        ended = ended || byte == 0;
        let asked = request.get(at).copied();
        same = same
            && if ended
            {
                asked.is_none()
            }
            else
            {
                asked == Some(byte)
            };
    }
    same
}

/// [`module_name_str`] of `name` is its bytes before the first NUL, or the
/// whole name when it holds none ([`InitModuleName::name`]): a prefix of the
/// name itself, with no NUL before its end and a NUL, or the name's end, at
/// it. Each byte is checked at its own index.
pub(crate) fn name_holds(name: &[u8; INIT_MODULE_NAME_LEN])
{
    let trimmed = module_name_str(name);
    let end = trimmed.len();
    assert!(
        trimmed.as_ptr() == name.as_ptr() && end <= INIT_MODULE_NAME_LEN,
        "a name was trimmed to other bytes"
    );
    for (at, &byte) in name.iter().enumerate()
    {
        if at < end
        {
            assert_ne!(byte, 0, "a trimmed name holds a NUL");
        }
        else if at == end
        {
            assert_eq!(byte, 0, "a name was trimmed short of its first NUL");
        }
    }
}

/// [`slot_if_carries`], the step [`find_module_slot`] puts to each entry,
/// answers `entry`'s slot exactly when its name stands for `request`, and
/// nothing otherwise.
pub(crate) fn slot_holds(entry: &InitModuleName, request: &[u8])
{
    assert_eq!(
        slot_if_carries(entry, request),
        stands_for(&entry.name, request).then_some(entry.slot),
        "an entry was taken, or passed over, against its name"
    );
}

/// [`find_module_slot`] over `names` keeps its contract (its doc): it finds
/// the slot of the first entry whose name is `request` whole, and nothing
/// when no entry's is.
pub(crate) fn lookup_holds(names: &[InitModuleName], request: &[u8])
{
    let expected = names
        .iter()
        .find(|entry| stands_for(&entry.name, request))
        .map(|entry| entry.slot);
    assert_eq!(
        find_module_slot(names, request),
        expected,
        "the lookup found another entry than the first of the name"
    );
}
