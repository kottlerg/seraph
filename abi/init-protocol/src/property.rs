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

use crate::{INIT_MODULE_NAME_LEN, InitModuleName, find_module_slot, module_name_str};

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
    }
    lookup_holds(names.get(..count).unwrap_or_default(), request);
}

/// The name a NUL-padded table name stands for: its bytes before the first
/// NUL, or the whole name when it holds none ([`InitModuleName::name`]).
fn trimmed(name: &[u8; INIT_MODULE_NAME_LEN]) -> &[u8]
{
    let end = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(INIT_MODULE_NAME_LEN);
    name.get(..end).unwrap_or(name)
}

/// [`module_name_str`] of `name` is the name it stands for.
pub(crate) fn name_holds(name: &[u8; INIT_MODULE_NAME_LEN])
{
    assert_eq!(
        module_name_str(name),
        trimmed(name),
        "a name was trimmed to other bytes"
    );
}

/// [`find_module_slot`] over `names` keeps its contract (its doc): it finds
/// the slot of the first entry whose name is `request` whole, and nothing
/// when no entry's is.
pub(crate) fn lookup_holds(names: &[InitModuleName], request: &[u8])
{
    let expected = names
        .iter()
        .find(|entry| trimmed(&entry.name) == request)
        .map(|entry| entry.slot);
    assert_eq!(
        find_module_slot(names, request),
        expected,
        "the lookup found another entry than the first of the name"
    );
}
