// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/firmware/src/binding.rs

//! The match table: which collected driver declaration binds each device
//! record, within the declaration bounds
//! ([docs/driver-binding.md](../../../../docs/driver-binding.md) § Matching,
//! § Declaration Bounds).
//!
//! A [`MatchTable`] holds the declarations one bind pass considers, each with
//! where it came from ([`Source`]) and how many devices it is bound to. For
//! one unbound record, [`MatchTable::choose`] takes the most specific match
//! over every key the record carries ([`rank`]); two declarations equally
//! specific are a conflict, and a declaration at its instance limit is passed
//! over. devmgr walks its records in record order, so a driver's instance
//! limit counts its devices in that order, and a limited driver's devices are
//! counted over the boot ([`BoundCounts`]), so a later pass binds it only to
//! the devices its limit leaves. [`grants`] applies the source
//! bounds to what a declaration asks for. The table knows no driver: it
//! compares the keys a declaration carries against the keys a record carries.

extern crate alloc;

use alloc::collections::TryReserveError;
use alloc::vec::Vec;

use driver_binding::decl::{DriverDecl, DriverName, MatchKey, Tier};

use crate::classes::Classes;

/// Where a declaration came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source
{
    /// A boot module init forwarded.
    BootModule,
    /// An entry of `/services/drivers/`.
    DriversDir,
}

/// A PCI function's identity keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PciIdentity
{
    pub vendor: u16,
    pub device: u16,
    /// Base class `<< 16 |` subclass `<< 8 |` programming interface.
    pub class_code: u32,
}

/// The identity keys one device record carries (docs/driver-binding.md
/// § Device Records). A record carries the keys of every source merged into
/// it, so it can carry several kinds.
#[derive(Clone, Copy, Debug, Default)]
pub struct RecordKeys<'a>
{
    pub pci: Option<PciIdentity>,
    pub acpi_hid: Option<&'a [u8]>,
    pub acpi_cids: &'a [&'a [u8]],
    pub spcr: Option<u8>,
    pub platform: Option<&'a [u8]>,
    pub iommu_family: Option<&'a [u8]>,
    pub boot_framebuffer: bool,
}

/// How specific a match is: 1 is the most specific, 6 the least
/// (docs/driver-binding.md § Matching).
pub type Rank = u8;

/// The rank at which `key` matches `record`, or `None` when it does not:
/// 1 for an exact PCI vendor and device, an IOMMU family key, or a platform
/// key; 2 for an SPCR interface type; 3 for an ACPI `_HID`; 4 for a PCI
/// class under its mask; 5 for an ACPI `_CID`; 6 for `boot-framebuffer`.
#[must_use]
pub fn rank(key: &MatchKey, record: &RecordKeys<'_>) -> Option<Rank>
{
    match key
    {
        MatchKey::PciId { vendor, device } => record
            .pci
            .is_some_and(|p| p.vendor == *vendor && p.device == *device)
            .then_some(1),
        MatchKey::IommuFamily(family) =>
        {
            (record.iommu_family == Some(family.as_bytes())).then_some(1)
        }
        MatchKey::Platform(platform) => (record.platform == Some(platform.as_bytes())).then_some(1),
        MatchKey::Spcr(interface) => (record.spcr == Some(*interface)).then_some(2),
        MatchKey::AcpiHid(hid) => (record.acpi_hid == Some(hid.as_bytes())).then_some(3),
        MatchKey::PciClass { code, mask } => record
            .pci
            .is_some_and(|p| p.class_code & mask == code & mask)
            .then_some(4),
        MatchKey::AcpiCid(cid) => record
            .acpi_cids
            .iter()
            .any(|c| *c == cid.as_bytes())
            .then_some(5),
        MatchKey::BootFramebuffer => record.boot_framebuffer.then_some(6),
    }
}

/// The most specific rank at which any key of `decl` matches `record`, a
/// declaration from `source` taking only the keys that source may declare:
/// an IOMMU family key is accepted only from a boot module
/// (docs/driver-binding.md § Declaration Bounds).
#[must_use]
pub fn decl_rank(decl: &DriverDecl, source: Source, record: &RecordKeys<'_>) -> Option<Rank>
{
    decl.matches()
        .iter()
        .filter(|key| source == Source::BootModule || !matches!(key, MatchKey::IommuFamily(_)))
        .filter_map(|key| rank(key, record))
        .min()
}

/// Whether `decl`, from `source`, may be considered at all: a declaration of
/// a class a class request marked boot-only is accepted only from a boot
/// module (docs/driver-binding.md § Declaration Bounds), so a
/// drivers-directory binary cannot claim a boot-only class's devices.
#[must_use]
pub fn class_admits<T>(classes: &Classes<T>, decl: &DriverDecl, source: Source) -> bool
{
    source == Source::BootModule
        || decl
            .class
            .is_none_or(|class| !classes.is_boot_only(class.as_str()))
}

/// What a declaration from `source` is given, within the source bounds, and
/// which of the fields it asked for were ignored (each logged by devmgr).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grants
{
    /// The priority tier the driver is created at.
    pub tier: Tier,
    /// Whether the driver is created `CREATE_PHYS_ACCESS`.
    pub phys_access: bool,
    /// The declaration asked for the boot tier from the drivers directory.
    pub tier_ignored: bool,
    /// The declaration asked for physical access where it is not accepted.
    pub phys_access_ignored: bool,
}

/// What `decl`, from `source`, is given for a record that is an IOMMU record
/// (`iommu_record`) or not: the boot tier only from a boot module; physical
/// access only from a boot module and only for an IOMMU record
/// (docs/driver-binding.md § Declaration Bounds). A drivers-directory driver
/// runs at the auxiliary tier.
#[must_use]
#[expect(
    clippy::fn_params_excessive_bools,
    reason = "`iommu_record` is whether the bound record is an IOMMU record, compared to bound the \
              physical-access grant"
)]
pub fn grants(decl: &DriverDecl, source: Source, iommu_record: bool) -> Grants
{
    let boot = source == Source::BootModule;
    let tier_ignored = decl.tier == Tier::Boot && !boot;
    let phys_access = decl.phys_access && boot && iommu_record;
    Grants {
        tier: if tier_ignored
        {
            Tier::Auxiliary
        }
        else
        {
            decl.tier
        },
        phys_access,
        tier_ignored,
        phys_access_ignored: decl.phys_access && !phys_access,
    }
}

/// One declaration in the table.
pub struct Candidate<T>
{
    pub decl: DriverDecl,
    pub source: Source,
    /// Devices a driver of the declaration's name is bound to so far this
    /// boot, by this pass and every earlier one.
    pub bound: u16,
    /// What devmgr starts the driver from (its boot module or its file).
    pub binary: T,
}

impl<T> Candidate<T>
{
    /// Whether the declaration is at its instance limit.
    #[must_use]
    pub fn at_limit(&self) -> bool
    {
        self.decl
            .instance_limit
            .is_some_and(|limit| self.bound >= limit)
    }
}

/// The outcome of [`MatchTable::choose`] for one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice
{
    /// Bind the declaration at this index.
    Bind(usize),
    /// Two declarations, at these indices, match equally specifically: bind
    /// neither.
    Conflict(usize, usize),
    /// No declaration below its instance limit matches.
    Unmatched,
}

/// The declarations one bind pass considers.
pub struct MatchTable<T>
{
    candidates: Vec<Candidate<T>>,
}

impl<T> Default for MatchTable<T>
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl<T> MatchTable<T>
{
    /// A table with no declaration.
    #[must_use]
    pub const fn new() -> Self
    {
        Self {
            candidates: Vec::new(),
        }
    }

    /// Add `decl`, from `source`, started from `binary`, a driver of its
    /// name being bound to `bound` devices by the earlier passes of the boot
    /// ([`BoundCounts::track`]); returns its index.
    ///
    /// # Errors
    /// Returns the allocation error when the table cannot grow.
    pub fn add(
        &mut self,
        decl: DriverDecl,
        source: Source,
        binary: T,
        bound: u16,
    ) -> Result<usize, TryReserveError>
    {
        self.candidates.try_reserve(1)?;
        let index = self.candidates.len();
        self.candidates.push(Candidate {
            decl,
            source,
            bound,
            binary,
        });
        Ok(index)
    }

    /// The declarations, by index.
    #[must_use]
    pub fn candidates(&self) -> &[Candidate<T>]
    {
        &self.candidates
    }

    /// Whether the table holds no declaration.
    #[must_use]
    pub fn is_empty(&self) -> bool
    {
        self.candidates.is_empty()
    }

    /// The declaration that binds `record`: the most specific match among
    /// those below their instance limit, a conflict when two share that rank,
    /// or none.
    #[must_use]
    pub fn choose(&self, record: &RecordKeys<'_>) -> Choice
    {
        let mut best: Option<(Rank, usize)> = None;
        let mut tied: Option<usize> = None;
        for (index, candidate) in self.candidates.iter().enumerate()
        {
            if candidate.at_limit()
            {
                continue;
            }
            let Some(r) = decl_rank(&candidate.decl, candidate.source, record)
            else
            {
                continue;
            };
            match best
            {
                Some((best_rank, _)) if r > best_rank =>
                {}
                Some((best_rank, _)) if r == best_rank =>
                {
                    tied.get_or_insert(index);
                }
                _ =>
                {
                    best = Some((r, index));
                    tied = None;
                }
            }
        }
        match (best, tied)
        {
            (Some((_, first)), Some(second)) => Choice::Conflict(first, second),
            (Some((_, index)), None) => Choice::Bind(index),
            (None, _) => Choice::Unmatched,
        }
    }

    /// Count one more device bound to the declaration at `index`; an index
    /// past the table is ignored.
    pub fn note_bound(&mut self, index: usize)
    {
        if let Some(candidate) = self.candidates.get_mut(index)
        {
            candidate.bound = candidate.bound.saturating_add(1);
        }
    }

    /// Remove every declaration and hand back the binaries, in index order.
    pub fn drain_binaries(&mut self) -> impl Iterator<Item = T> + '_
    {
        self.candidates.drain(..).map(|c| c.binary)
    }
}

/// The devices each driver with an instance limit is bound to over the boot,
/// by driver name, so the limit holds across bind passes: a pass's
/// [`MatchTable`] starts each limited declaration at the count the earlier
/// passes left. A driver with no limit is not tracked, so the table grows
/// only with the limited drivers a boot considers.
#[derive(Default)]
pub struct BoundCounts
{
    counts: Vec<(DriverName, u16)>,
}

impl BoundCounts
{
    /// No driver bound.
    #[must_use]
    pub const fn new() -> Self
    {
        Self { counts: Vec::new() }
    }

    /// The devices a driver named `decl.name` is bound to so far, tracking
    /// the name from here on when `decl` declares an instance limit; 0 for a
    /// declaration with no limit, which [`MatchTable::choose`] does not
    /// count against.
    ///
    /// # Errors
    /// Returns the allocation error when a limited name is not yet tracked
    /// and the table cannot grow.
    pub fn track(&mut self, decl: &DriverDecl) -> Result<u16, TryReserveError>
    {
        if decl.instance_limit.is_none()
        {
            return Ok(0);
        }
        if let Some(&(_, bound)) = self.counts.iter().find(|(n, _)| *n == decl.name)
        {
            return Ok(bound);
        }
        self.counts.try_reserve(1)?;
        self.counts.push((decl.name, 0));
        Ok(0)
    }

    /// Count one more device bound to the driver named `name`; a name not
    /// tracked (one with no instance limit) is ignored.
    pub fn note(&mut self, name: &DriverName)
    {
        if let Some((_, bound)) = self.counts.iter_mut().find(|(n, _)| n == name)
        {
            *bound = bound.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests
{
    use super::*;
    use driver_binding::decl::{Declaration, Interrupt, Match, Reset, decode, encode};

    fn decl(matches: &[Match<'_>], limit: Option<u16>) -> DriverDecl
    {
        decl_with(matches, limit, Tier::Auxiliary, false)
    }

    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`phys` is the declaration's `phys_access` field, stored in the declaration it \
                  builds"
    )]
    fn decl_with(matches: &[Match<'_>], limit: Option<u16>, tier: Tier, phys: bool) -> DriverDecl
    {
        decode(
            encode(&Declaration {
                name: "d",
                class: Some("c"),
                matches,
                instance_limit: limit,
                interrupt: Interrupt::NONE,
                dma: false,
                dma_width: None,
                phys_access: phys,
                reset: Reset::None,
                tier,
            })
            .as_bytes(),
        )
        .unwrap()
    }

    fn pci(vendor: u16, device: u16, class_code: u32) -> RecordKeys<'static>
    {
        RecordKeys {
            pci: Some(PciIdentity {
                vendor,
                device,
                class_code,
            }),
            ..RecordKeys::default()
        }
    }

    #[test]
    fn every_key_kind_matches_at_its_rank()
    {
        let cids: [&[u8]; 2] = [b"PNP0C02", b"PNP0501"];
        let record = RecordKeys {
            pci: Some(PciIdentity {
                vendor: 0x1AF4,
                device: 0x1042,
                class_code: 0x01_0000,
            }),
            acpi_hid: Some(b"QEMU0001"),
            acpi_cids: &cids,
            spcr: Some(3),
            platform: Some(b"virt-rtc"),
            iommu_family: Some(b"dmar"),
            boot_framebuffer: true,
        };
        let ranked = |m: Match<'_>| decl_rank(&decl(&[m], None), Source::BootModule, &record);
        assert_eq!(
            ranked(Match::PciId {
                vendor: 0x1AF4,
                device: 0x1042
            }),
            Some(1)
        );
        assert_eq!(ranked(Match::IommuFamily("dmar")), Some(1));
        assert_eq!(ranked(Match::Platform("virt-rtc")), Some(1));
        assert_eq!(ranked(Match::Spcr(3)), Some(2));
        assert_eq!(ranked(Match::AcpiHid("QEMU0001")), Some(3));
        assert_eq!(
            ranked(Match::PciClass {
                code: 0x01_0000,
                mask: 0xFF_0000
            }),
            Some(4)
        );
        assert_eq!(ranked(Match::AcpiCid("PNP0501")), Some(5));
        assert_eq!(ranked(Match::BootFramebuffer), Some(6));
        assert_eq!(ranked(Match::AcpiHid("PNP0501")), None);
        assert_eq!(ranked(Match::Spcr(0)), None);
        assert_eq!(
            ranked(Match::PciId {
                vendor: 0x1AF4,
                device: 0x1041
            }),
            None
        );
    }

    #[test]
    fn a_pci_class_compares_only_its_masked_bits()
    {
        let record = pci(0x8086, 0x10D3, 0x02_0000);
        let class = |code, mask| decl(&[Match::PciClass { code, mask }], None);
        assert_eq!(
            decl_rank(&class(0x02_00FF, 0xFF_FF00), Source::BootModule, &record),
            Some(4)
        );
        assert_eq!(
            decl_rank(&class(0x02_0100, 0xFF_FF00), Source::BootModule, &record),
            None
        );
    }

    #[test]
    fn a_declaration_ranks_at_its_most_specific_matching_key()
    {
        let record = pci(0x1AF4, 0x1042, 0x01_0000);
        let d = decl(
            &[
                Match::PciClass {
                    code: 0x01_0000,
                    mask: 0xFF_0000,
                },
                Match::PciId {
                    vendor: 0x1AF4,
                    device: 0x1042,
                },
            ],
            None,
        );
        assert_eq!(decl_rank(&d, Source::BootModule, &record), Some(1));
    }

    #[test]
    fn the_most_specific_declaration_binds_whatever_its_order()
    {
        let record = pci(0x1AF4, 0x1042, 0x01_0000);
        let mut table = MatchTable::new();
        table
            .add(
                decl(
                    &[Match::PciClass {
                        code: 0x01_0000,
                        mask: 0xFF_0000,
                    }],
                    None,
                ),
                Source::BootModule,
                "generic",
                0,
            )
            .unwrap();
        let exact = table
            .add(
                decl(
                    &[Match::PciId {
                        vendor: 0x1AF4,
                        device: 0x1042,
                    }],
                    None,
                ),
                Source::BootModule,
                "exact",
                0,
            )
            .unwrap();
        assert_eq!(table.choose(&record), Choice::Bind(exact));
    }

    #[test]
    fn two_equally_specific_declarations_conflict_and_neither_binds()
    {
        let record = pci(0x1AF4, 0x1042, 0x01_0000);
        let id = Match::PciId {
            vendor: 0x1AF4,
            device: 0x1042,
        };
        let mut table = MatchTable::new();
        table
            .add(decl(&[Match::Spcr(1)], None), Source::BootModule, (), 0)
            .unwrap();
        let a = table
            .add(decl(&[id], None), Source::BootModule, (), 0)
            .unwrap();
        let b = table
            .add(decl(&[id], None), Source::DriversDir, (), 0)
            .unwrap();
        // A less specific declaration does not stand in for the conflict.
        table
            .add(
                decl(
                    &[Match::PciClass {
                        code: 0x01_0000,
                        mask: 0xFF_0000,
                    }],
                    None,
                ),
                Source::BootModule,
                (),
                0,
            )
            .unwrap();
        assert_eq!(table.choose(&record), Choice::Conflict(a, b));
    }

    #[test]
    fn a_declaration_at_its_instance_limit_is_passed_over_in_record_order()
    {
        let records = [
            pci(0x1AF4, 0x1043, 0x07_8000),
            pci(0x1AF4, 0x1043, 0x07_8000),
        ];
        let mut table = MatchTable::new();
        let one = table
            .add(
                decl(
                    &[Match::PciId {
                        vendor: 0x1AF4,
                        device: 0x1043,
                    }],
                    Some(1),
                ),
                Source::BootModule,
                (),
                0,
            )
            .unwrap();
        let fallback = table
            .add(
                decl(
                    &[Match::PciClass {
                        code: 0x07_0000,
                        mask: 0xFF_0000,
                    }],
                    None,
                ),
                Source::BootModule,
                (),
                0,
            )
            .unwrap();
        let mut chosen = Vec::new();
        for record in &records
        {
            let choice = table.choose(record);
            if let Choice::Bind(index) = choice
            {
                table.note_bound(index);
            }
            chosen.push(choice);
        }
        assert_eq!(chosen, [Choice::Bind(one), Choice::Bind(fallback)]);
        assert_eq!(table.candidates()[one].bound, 1);
    }

    #[test]
    fn an_instance_limit_counts_the_devices_earlier_passes_bound()
    {
        let limited = decl(
            &[Match::PciId {
                vendor: 1,
                device: 2,
            }],
            Some(1),
        );
        let mut counts = BoundCounts::new();
        // The first pass binds the limited driver to one device.
        let mut first = MatchTable::new();
        let index = first
            .add(
                limited,
                Source::DriversDir,
                (),
                counts.track(&limited).unwrap(),
            )
            .unwrap();
        assert_eq!(first.choose(&pci(1, 2, 0)), Choice::Bind(index));
        first.note_bound(index);
        counts.note(&limited.name);
        // A later pass, from another source too, starts at that count and
        // binds the driver to no second device.
        let mut later = MatchTable::new();
        later
            .add(
                limited,
                Source::BootModule,
                (),
                counts.track(&limited).unwrap(),
            )
            .unwrap();
        assert_eq!(later.choose(&pci(1, 2, 0)), Choice::Unmatched);
    }

    #[test]
    fn an_unlimited_declaration_is_not_tracked()
    {
        let unlimited = decl(
            &[Match::PciId {
                vendor: 1,
                device: 2,
            }],
            None,
        );
        let mut counts = BoundCounts::new();
        assert_eq!(counts.track(&unlimited).unwrap(), 0);
        counts.note(&unlimited.name);
        assert_eq!(counts.track(&unlimited).unwrap(), 0);
        assert_eq!(
            counts.counts,
            [] as [(driver_binding::decl::Text<32>, u16); 0]
        );
    }

    #[test]
    fn a_limited_declaration_with_nothing_else_leaves_the_rest_unmatched()
    {
        let mut table = MatchTable::new();
        let only = table
            .add(
                decl(
                    &[Match::PciId {
                        vendor: 1,
                        device: 2,
                    }],
                    Some(1),
                ),
                Source::DriversDir,
                (),
                0,
            )
            .unwrap();
        table.note_bound(only);
        assert_eq!(table.choose(&pci(1, 2, 0)), Choice::Unmatched);
        assert_eq!(table.choose(&pci(3, 4, 0)), Choice::Unmatched);
    }

    #[test]
    fn an_iommu_family_key_counts_only_from_a_boot_module()
    {
        let record = RecordKeys {
            iommu_family: Some(b"rimt"),
            ..RecordKeys::default()
        };
        let d = decl(&[Match::IommuFamily("rimt")], None);
        assert_eq!(decl_rank(&d, Source::BootModule, &record), Some(1));
        assert_eq!(decl_rank(&d, Source::DriversDir, &record), None);
    }

    #[test]
    fn the_boot_tier_and_physical_access_are_granted_only_within_the_source_bounds()
    {
        let m = [Match::IommuFamily("dmar")];
        let boot_phys = decl_with(&m, None, Tier::Boot, true);
        assert_eq!(
            grants(&boot_phys, Source::BootModule, true),
            Grants {
                tier: Tier::Boot,
                phys_access: true,
                tier_ignored: false,
                phys_access_ignored: false,
            }
        );
        // Physical access only for an IOMMU record.
        assert_eq!(
            grants(&boot_phys, Source::BootModule, false),
            Grants {
                tier: Tier::Boot,
                phys_access: false,
                tier_ignored: false,
                phys_access_ignored: true,
            }
        );
        // Neither from the drivers directory.
        assert_eq!(
            grants(&boot_phys, Source::DriversDir, true),
            Grants {
                tier: Tier::Auxiliary,
                phys_access: false,
                tier_ignored: true,
                phys_access_ignored: true,
            }
        );
        let plain = decl(&m, None);
        assert_eq!(
            grants(&plain, Source::DriversDir, false),
            Grants {
                tier: Tier::Auxiliary,
                phys_access: false,
                tier_ignored: false,
                phys_access_ignored: false,
            }
        );
    }

    #[test]
    fn a_boot_only_class_admits_a_boot_module_declaration_alone()
    {
        let m = [Match::PciId {
            vendor: 1,
            device: 2,
        }];
        // `decl_with` declares class `c`.
        let declared = decl_with(&m, None, Tier::Auxiliary, false);
        let mut classless = declared;
        classless.class = None;
        let mut classes = Classes::<()>::new();
        assert!(class_admits(&classes, &declared, Source::DriversDir));
        let c = driver_binding::decl::ClassName::class(b"c").unwrap();
        classes.configure(&c, false, false).unwrap();
        assert!(class_admits(&classes, &declared, Source::DriversDir));
        classes.configure(&c, true, false).unwrap();
        assert!(!class_admits(&classes, &declared, Source::DriversDir));
        assert!(class_admits(&classes, &declared, Source::BootModule));
        assert!(class_admits(&classes, &classless, Source::DriversDir));
    }
}
