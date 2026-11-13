// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/iommu/core/src/bootstrap.rs

//! The bootstrap rounds devmgr serves an IOMMU driver, and the scopes of the
//! units they deliver.
//!
//! One non-terminal round per unit, in unit-index order, then one terminal
//! round:
//!
//! - **Unit round.** `caps[0]` = the unit's register `Mmio` cap;
//!   `data[0]` = [`ROUND_UNIT`], `data[1]` = the unit's PCI segment,
//!   `data[2]` = flags ([`FLAG_INCLUDE_PCI_ALL`]), `data[3]` = the pages the
//!   register cap spans (1 to [`MAX_REGISTER_PAGES`]), `data[4..]` = the
//!   unit's scope, one [`Scope`] word per function or bus range it names, at
//!   most [`MAX_SCOPES`].
//! - **Endpoint round** (terminal). `caps[0]` = the driver's service
//!   endpoint, `caps[1]` = its devmgr query cap (a SEND on its settle
//!   batch's private endpoint, for `DRIVER_READY`); `data[0]` =
//!   [`ROUND_ENDPOINTS`].
//!
//! devmgr parses the firmware's description of the units (the ACPI DMAR on
//! x86-64, the ACPI RIMT on riscv64) and resolves each scope entry against
//! the PCI topology before it encodes it, so the driver reads no firmware
//! table.

use alloc::vec::Vec;

use ipc::bootstrap::BootstrapRound;
use syscall_abi::MSG_DATA_WORDS_MAX;

/// `data[0]` of a unit round.
pub const ROUND_UNIT: u64 = 1;
/// `data[0]` of the terminal endpoint round.
pub const ROUND_ENDPOINTS: u64 = 2;
/// Unit-round flag: the unit translates every function of its segment that
/// no other unit's scope names.
pub const FLAG_INCLUDE_PCI_ALL: u64 = 1 << 0;
/// Data words of a unit round before its scope words.
const UNIT_HEADER_WORDS: usize = 4;
/// Pages a unit's register cap may span. VT-d sizes a unit's register set
/// as a power of two pages up to 2^15 in its firmware table, and a unit's
/// registers occupy one page in practice; the bound keeps the driver's
/// register window small. A unit whose set is larger is not handed over.
pub const MAX_REGISTER_PAGES: u64 = 16;
/// Scope words one unit round carries: the data words left after its
/// header. A unit whose firmware scope names more is not handed over.
pub const MAX_SCOPES: usize = MSG_DATA_WORDS_MAX - UNIT_HEADER_WORDS;
/// Units one IOMMU driver serves. A platform with more units of one family
/// than this hands over the first ones and refuses the DMA-capable functions
/// of the rest; `docs/limits.md` classifies the bound.
pub const MAX_UNITS: usize = 16;

/// [`Scope`] word: a bus range rather than one function.
const SCOPE_BUSES: u64 = 1 << 32;

/// PCI functions a unit's scope names: one function, by its bus, device, and
/// function (bus in bits 8..16, device in bits 3..8, function in bits
/// 0..3), or every function on a range of buses (a bridge's secondary
/// through subordinate bus).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope
{
    /// One function.
    Function(u16),
    /// Every function on buses `first..=last`.
    Buses
    {
        /// First bus of the range.
        first: u8,
        /// Last bus of the range, inclusive.
        last: u8,
    },
}

impl Scope
{
    /// The word a unit round carries for the scope.
    #[must_use]
    pub const fn encode(self) -> u64
    {
        match self
        {
            Self::Function(bdf) => bdf as u64,
            Self::Buses { first, last } => SCOPE_BUSES | (first as u64) | ((last as u64) << 8),
        }
    }

    /// The scope a unit-round word names; `None` for a word with bits
    /// outside the encoding, or a bus range that ends before it starts.
    #[must_use]
    pub fn decode(word: u64) -> Option<Self>
    {
        if word & SCOPE_BUSES == 0
        {
            return u16::try_from(word).ok().map(Self::Function);
        }
        let rest = word & !SCOPE_BUSES;
        let first = u8::try_from(rest & 0xff).ok()?;
        let last = u8::try_from(rest >> 8).ok()?;
        (first <= last).then_some(Self::Buses { first, last })
    }

    /// Whether the scope names the function `bdf`.
    #[must_use]
    pub fn covers(self, bdf: u16) -> bool
    {
        match self
        {
            Self::Function(f) => f == bdf,
            Self::Buses { first, last } =>
            {
                let bus = bdf.to_be_bytes()[0];
                (first..=last).contains(&bus)
            }
        }
    }
}

/// One unit's PCI segment and the functions it translates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitScope
{
    /// The segment of every function the unit translates.
    pub segment: u16,
    /// Whether the unit translates every function of its segment that no
    /// other unit's scope names.
    pub include_pci_all: bool,
    /// The functions and bus ranges the unit names explicitly.
    pub scopes: Vec<Scope>,
}

/// Every unit the bootstrap delivered, in unit-index order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Units(pub Vec<UnitScope>);

impl Units
{
    /// The index of the unit that translates function `bdf` of `segment`:
    /// the first unit of the segment whose scope names it, else the
    /// segment's first include-all unit. `None` when no unit translates it.
    #[must_use]
    pub fn unit_for(&self, segment: u16, bdf: u16) -> Option<usize>
    {
        let mut catch_all = None;
        for (index, unit) in self.0.iter().enumerate()
        {
            if unit.segment != segment
            {
                continue;
            }
            if unit.scopes.iter().any(|s| s.covers(bdf))
            {
                return Some(index);
            }
            if unit.include_pci_all && catch_all.is_none()
            {
                catch_all = Some(index);
            }
        }
        catch_all
    }
}

/// The data words of a unit round for a unit of `segment` whose register
/// cap spans `register_pages` pages, with `scopes`. `None` when the scopes
/// exceed [`MAX_SCOPES`] or the pages are outside 1 to
/// [`MAX_REGISTER_PAGES`].
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`include_pci_all` is the unit's INCLUDE_PCI_ALL flag, encoded into a round word"
)]
pub fn unit_round_words(
    segment: u16,
    include_pci_all: bool,
    register_pages: u64,
    scopes: &[Scope],
) -> Option<Vec<u64>>
{
    if scopes.len() > MAX_SCOPES || !(1..=MAX_REGISTER_PAGES).contains(&register_pages)
    {
        return None;
    }
    let mut words = Vec::new();
    // At most `MSG_DATA_WORDS_MAX` words: the scopes are checked against
    // `MAX_SCOPES` above.
    words
        .try_reserve(UNIT_HEADER_WORDS.saturating_add(scopes.len()))
        .ok()?;
    let flags = if include_pci_all
    {
        FLAG_INCLUDE_PCI_ALL
    }
    else
    {
        0
    };
    words.extend([ROUND_UNIT, u64::from(segment), flags, register_pages]);
    words.extend(scopes.iter().map(|s| s.encode()));
    Some(words)
}

/// One unit's register `Mmio` cap and the pages it spans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registers
{
    /// The `Mmio` cap.
    pub cap: u64,
    /// Pages the cap spans, 1 to [`MAX_REGISTER_PAGES`].
    pub pages: u64,
}

/// What the bootstrap delivered.
#[derive(Debug, PartialEq, Eq)]
pub struct Bootstrap
{
    /// Each unit's register cap, by unit index.
    pub registers: Vec<Registers>,
    /// Each unit's segment and scope, by unit index.
    pub units: Units,
    /// The driver's service endpoint.
    pub service_ep: u64,
    /// The driver's devmgr query cap, for `DRIVER_READY`.
    pub devmgr_query: u64,
}

/// Why the bootstrap could not be decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError
{
    /// A round could not be received; its bootstrap error code.
    Round(u64),
    /// A round's shape is not a unit or endpoint round, a unit round came
    /// after the endpoint round, more than [`MAX_UNITS`] units came, or no
    /// unit came at all.
    Malformed,
    /// The unit list could not grow.
    OutOfMemory,
}

/// Decode one unit round: the register cap and the unit's scope.
fn parse_unit(round: &BootstrapRound) -> Result<(Registers, UnitScope), BootstrapError>
{
    let words = round.data.get(..round.data_words);
    let Some(&[kind, segment, flags, pages, ref scope_words @ ..]) = words
    else
    {
        return Err(BootstrapError::Malformed);
    };
    if round.cap_count != 1 || kind != ROUND_UNIT
    {
        return Err(BootstrapError::Malformed);
    }
    let segment = u16::try_from(segment).map_err(|_| BootstrapError::Malformed)?;
    if flags & !FLAG_INCLUDE_PCI_ALL != 0 || !(1..=MAX_REGISTER_PAGES).contains(&pages)
    {
        return Err(BootstrapError::Malformed);
    }
    let mut scopes = Vec::new();
    scopes
        .try_reserve(scope_words.len())
        .map_err(|_| BootstrapError::OutOfMemory)?;
    for &w in scope_words
    {
        scopes.push(Scope::decode(w).ok_or(BootstrapError::Malformed)?);
    }
    Ok((
        Registers {
            cap: round.caps[0],
            pages,
        },
        UnitScope {
            segment,
            include_pci_all: flags & FLAG_INCLUDE_PCI_ALL != 0,
            scopes,
        },
    ))
}

/// Decode the rounds of a bootstrap, in the order they arrived; the last
/// must be the terminal endpoint round.
///
/// # Errors
/// [`BootstrapError::Malformed`] or [`BootstrapError::OutOfMemory`].
pub fn parse(rounds: &[BootstrapRound]) -> Result<Bootstrap, BootstrapError>
{
    let (last, unit_rounds) = rounds.split_last().ok_or(BootstrapError::Malformed)?;
    if !last.done
        || last.cap_count != 2
        || last.data_words < 1
        || last.data[0] != ROUND_ENDPOINTS
        || unit_rounds.is_empty()
        || unit_rounds.len() > MAX_UNITS
        || unit_rounds.iter().any(|r| r.done)
    {
        return Err(BootstrapError::Malformed);
    }
    let mut registers = Vec::new();
    let mut units = Vec::new();
    registers
        .try_reserve(unit_rounds.len())
        .map_err(|_| BootstrapError::OutOfMemory)?;
    units
        .try_reserve(unit_rounds.len())
        .map_err(|_| BootstrapError::OutOfMemory)?;
    for round in unit_rounds
    {
        let (register, scope) = parse_unit(round)?;
        registers.push(register);
        units.push(scope);
    }
    Ok(Bootstrap {
        registers,
        units: Units(units),
        service_ep: last.caps[0],
        devmgr_query: last.caps[1],
    })
}

/// Receive every round of the bootstrap from `creator_ep` and decode them.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`BootstrapError::Round`] when a round cannot be received, else as
/// [`parse`].
pub unsafe fn receive(creator_ep: u64, ipc_buf: *mut u64) -> Result<Bootstrap, BootstrapError>
{
    let mut rounds = Vec::new();
    rounds
        .try_reserve(MAX_UNITS + 1)
        .map_err(|_| BootstrapError::OutOfMemory)?;
    while rounds.len() <= MAX_UNITS
    {
        // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
        let round = unsafe { ipc::bootstrap::request_round(creator_ep, ipc_buf) }
            .map_err(BootstrapError::Round)?;
        let done = round.done;
        rounds.push(round);
        if done
        {
            break;
        }
    }
    parse(&rounds)
}

#[cfg(test)]
mod tests
{
    use super::*;
    use syscall_abi::MSG_CAP_SLOTS_MAX;

    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`done` is the round's `done` field, stored in the round it builds"
    )]
    fn round(caps: &[u64], words: &[u64], done: bool) -> BootstrapRound
    {
        let mut r = BootstrapRound {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: caps.len(),
            data: [0; MSG_DATA_WORDS_MAX],
            data_words: words.len(),
            done,
        };
        r.caps[..caps.len()].copy_from_slice(caps);
        r.data[..words.len()].copy_from_slice(words);
        r
    }

    fn endpoints() -> BootstrapRound
    {
        round(&[70, 71], &[ROUND_ENDPOINTS], true)
    }

    #[test]
    fn a_scope_word_round_trips()
    {
        for s in [
            Scope::Function(0x0018),
            Scope::Function(0xffff),
            Scope::Buses { first: 2, last: 9 },
            Scope::Buses {
                first: 0,
                last: 255,
            },
        ]
        {
            assert_eq!(Scope::decode(s.encode()), Some(s));
        }
    }

    #[test]
    fn a_malformed_scope_word_is_refused()
    {
        assert_eq!(Scope::decode(1 << 40), None);
        assert_eq!(Scope::decode(SCOPE_BUSES | 9 | (2 << 8)), None);
    }

    #[test]
    fn a_bus_range_covers_every_function_on_its_buses_only()
    {
        let s = Scope::Buses { first: 2, last: 3 };
        assert!(s.covers(0x0200));
        assert!(s.covers(0x03ff));
        assert!(!s.covers(0x0100));
        assert!(!s.covers(0x0400));
    }

    #[test]
    fn a_function_named_by_a_scope_goes_to_that_unit_before_the_catch_all()
    {
        let units = Units(vec![
            UnitScope {
                segment: 0,
                include_pci_all: true,
                scopes: vec![],
            },
            UnitScope {
                segment: 0,
                include_pci_all: false,
                scopes: vec![Scope::Function(0x0010)],
            },
            UnitScope {
                segment: 1,
                include_pci_all: false,
                scopes: vec![Scope::Function(0x0018)],
            },
        ]);
        assert_eq!(units.unit_for(0, 0x0010), Some(1));
        assert_eq!(units.unit_for(0, 0x0018), Some(0));
        assert_eq!(units.unit_for(1, 0x0018), Some(2));
        assert_eq!(units.unit_for(1, 0x0010), None);
    }

    #[test]
    fn unit_rounds_decode_into_the_units_they_encode()
    {
        let scopes = [Scope::Function(0x0008), Scope::Buses { first: 4, last: 5 }];
        let words = unit_round_words(3, false, 1, &scopes).unwrap();
        let catch_all = unit_round_words(0, true, 2, &[]).unwrap();
        let b = parse(&[
            round(&[50], &words, false),
            round(&[51], &catch_all, false),
            endpoints(),
        ])
        .unwrap();
        assert_eq!(
            b.registers,
            [
                Registers { cap: 50, pages: 1 },
                Registers { cap: 51, pages: 2 }
            ]
        );
        assert_eq!(b.units.0[0].segment, 3);
        assert!(!b.units.0[0].include_pci_all);
        assert_eq!(b.units.0[0].scopes, scopes);
        assert!(b.units.0[1].include_pci_all);
        assert_eq!((b.service_ep, b.devmgr_query), (70, 71));
    }

    #[test]
    fn a_unit_with_more_scopes_than_a_round_holds_is_not_encoded()
    {
        let scopes = vec![Scope::Function(1); MAX_SCOPES + 1];
        assert_eq!(unit_round_words(0, false, 1, &scopes), None);
        assert!(unit_round_words(0, false, 1, &scopes[..MAX_SCOPES]).is_some());
    }

    #[test]
    fn a_register_span_outside_its_bound_is_not_encoded_or_accepted()
    {
        assert_eq!(unit_round_words(0, true, 0, &[]), None);
        assert_eq!(unit_round_words(0, true, MAX_REGISTER_PAGES + 1, &[]), None);
        let zero_pages = round(&[50], &[ROUND_UNIT, 0, FLAG_INCLUDE_PCI_ALL, 0], false);
        assert_eq!(
            parse(&[zero_pages, endpoints()]),
            Err(BootstrapError::Malformed)
        );
    }

    #[test]
    fn a_bootstrap_without_units_or_without_its_endpoint_round_is_refused()
    {
        let unit = round(&[50], &unit_round_words(0, true, 1, &[]).unwrap(), false);
        assert_eq!(parse(&[endpoints()]), Err(BootstrapError::Malformed));
        assert_eq!(parse(&[unit]), Err(BootstrapError::Malformed));
    }

    #[test]
    fn a_unit_round_with_unknown_flags_or_a_bad_segment_is_refused()
    {
        let bad_flags = round(&[50], &[ROUND_UNIT, 0, 2, 1], false);
        let bad_segment = round(&[50], &[ROUND_UNIT, 1 << 16, 0, 1], false);
        assert_eq!(
            parse(&[bad_flags, endpoints()]),
            Err(BootstrapError::Malformed)
        );
        assert_eq!(
            parse(&[bad_segment, endpoints()]),
            Err(BootstrapError::Malformed)
        );
    }

    #[test]
    fn a_unit_round_counting_more_words_than_a_round_holds_is_refused()
    {
        let mut unit = round(&[50], &unit_round_words(0, true, 1, &[]).unwrap(), false);
        unit.data_words = MSG_DATA_WORDS_MAX + 1;
        assert_eq!(parse(&[unit, endpoints()]), Err(BootstrapError::Malformed));
    }

    #[test]
    fn more_units_than_a_driver_serves_are_refused()
    {
        let words = unit_round_words(0, true, 1, &[]).unwrap();
        let mut rounds: Vec<_> = (0..=MAX_UNITS as u64)
            .map(|c| round(&[c], &words, false))
            .collect();
        rounds.push(endpoints());
        assert_eq!(parse(&rounds), Err(BootstrapError::Malformed));
        rounds.remove(0);
        assert_eq!(parse(&rounds).unwrap().registers.len(), MAX_UNITS);
    }
}
