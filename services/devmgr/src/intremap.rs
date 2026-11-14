// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/intremap.rs

//! devmgr's side of VT-d interrupt remapping: turning it on, and writing the
//! remapping entry of each interrupt source before a device can raise it.
//!
//! Once the IOMMU driver reports ready on a platform whose DMAR offers
//! interrupt remapping, [`enable`] has the driver set up the remapping table
//! every unit shares (`iommu_labels::REMAP_SETUP`), sized to the handles the
//! kernel can hand out (`CAP_INFO_IRQ_REMAP_HANDLES`), and switches the
//! kernel to the remappable formats (`SYS_IRQ_REMAP`), before any line is
//! routed or any message target minted. From then on an interrupt message
//! reaches a CPU only through an entry the driver wrote, for the one
//! requester the entry names: devmgr writes each line's entry, for the source
//! ID of the I/O APIC that delivers it, once the line is routed
//! ([`InterruptRemap::line`]), and each message target's, for the requester
//! ID of the function it is given to, before the message is programmed into
//! the function ([`InterruptRemap::message`]); it clears a message target's
//! entry before it frees the target ([`InterruptRemap::clear`]). The kernel
//! reports each source's entry (`CAP_INFO_IRQ_REMAP_ENTRY`).
//!
//! When the DMAR offers no interrupt remapping, a VT-d unit was not handed to
//! the driver, the units translate more than one PCI segment (the shared
//! table's entries name a requester with no segment), an I/O APIC the MADT
//! lists has no source ID in the DMAR, the table cannot be set up, or the
//! kernel refuses the switch, remapping stays off, logged once, and a device's
//! messages reach the local APICs unchecked, as without an IOMMU. The RISC-V
//! IOMMU confines messages by translation instead (`crate::dma`), so riscv64
//! never turns this on. See `docs/device-management.md` § Interrupt Delivery.

use std::sync::Arc;

use firmware::acpi::IoApic;
use ipc::iommu_labels;
use syscall_abi::{
    CAP_INFO_IRQ_REMAP_ENTRY, CAP_INFO_IRQ_REMAP_HANDLES, IRQ_MODE_LEVEL, IRQ_REMAP_ON,
    IRQ_REMAP_ON_EXTENDED, remap_entry_unpack,
};

use crate::iommu::{Iommu, IommuClient};
use crate::tables::{locate_table_by_sig, with_acpi_table};

/// Interrupt remapping, on: the IOMMU driver devmgr has write each entry, and
/// the source ID of every I/O APIC.
pub struct InterruptRemap
{
    client: Arc<IommuClient>,
    /// Each I/O APIC of the MADT and the source ID its interrupt requests
    /// carry (`firmware::dmar::IoApicScope::source_id`).
    io_apics: Vec<(IoApic, u16)>,
}

/// A remapping entry was not written or cleared (logged where it failed).
#[derive(Debug)]
pub struct NotRemapped;

impl InterruptRemap
{
    /// Write the entry of the source `cap` names for requests from `source`,
    /// level-triggered when `level` is set.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`level` is the remapping entry's trigger-mode bit"
    )]
    fn write(&self, cap: u64, level: bool, source: u16) -> Result<(), NotRemapped>
    {
        let entry = syscall::cap_info(cap, CAP_INFO_IRQ_REMAP_ENTRY).map_err(|e| {
            std::os::seraph::log!(warn: "interrupt remapping entry not read ({})", e);
            NotRemapped
        })?;
        let (handle, vector, apic_id) = remap_entry_unpack(entry);
        self.client
            .remap_set(handle, apic_id, vector, level, source)
            .map_err(|code| {
                std::os::seraph::log!(
                    warn: "interrupt remapping entry {} not written ({})",
                    u64::from(handle),
                    code
                );
                NotRemapped
            })
    }

    /// Write the entry of wired line `gsi`, routed in `mode` through `cap`,
    /// for the I/O APIC that delivers it.
    ///
    /// # Errors
    /// No I/O APIC delivers the line, or the entry was not written; logged.
    pub fn line(&self, cap: u64, gsi: u32, mode: u64) -> Result<(), NotRemapped>
    {
        let io_apics = self.io_apics.iter().map(|&(io_apic, _)| io_apic);
        let Some(io_apic) = firmware::acpi::io_apic_for(io_apics, gsi)
        else
        {
            std::os::seraph::log!(warn: "GSI {:#x}: no I/O APIC delivers it", u64::from(gsi));
            return Err(NotRemapped);
        };
        let source = self
            .io_apics
            .iter()
            .find(|(a, _)| *a == io_apic)
            .map(|&(_, source)| source)
            .ok_or(NotRemapped)?;
        self.write(cap, mode & IRQ_MODE_LEVEL != 0, source)
    }

    /// Write the entry of the message target `cap` names for requests from
    /// the function `rid` (`iommu_labels::requester_id`, whose bus, device,
    /// and function are the source ID), edge-triggered.
    ///
    /// # Errors
    /// The entry was not written; logged.
    pub fn message(&self, cap: u64, rid: u64) -> Result<(), NotRemapped>
    {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the source ID is the requester ID's low 16 bits; remapping is on only when \
                      every unit translates one segment (`firmware::dmar::remap_obstacle`), so \
                      the segment dropped names no other requester"
        )]
        let source = rid as u16;
        self.write(cap, false, source)
    }

    /// Clear the entry of the message target `cap` names, so a message
    /// naming it is blocked until a later source's entry is written there.
    ///
    /// # Errors
    /// The entry was not read or cleared; logged.
    pub fn clear(&self, cap: u64) -> Result<(), NotRemapped>
    {
        let entry = syscall::cap_info(cap, CAP_INFO_IRQ_REMAP_ENTRY).map_err(|_| NotRemapped)?;
        let (handle, _, _) = remap_entry_unpack(entry);
        self.client.remap_clear(handle).map_err(|code| {
            std::os::seraph::log!(
                warn: "interrupt remapping entry {} not cleared ({})",
                u64::from(handle),
                code
            );
            NotRemapped
        })
    }
}

/// Turn interrupt remapping on through `authority`, an `Interrupt` cap
/// carrying `RIGHTS_IRQ_MINT`, before any interrupt source exists, when the
/// IOMMU is VT-d and the firmware offers it (module doc). `None`, logged
/// unless the IOMMU is another family's, leaves it off.
pub fn enable(
    iommu: &Iommu,
    firmware: &crate::caps::Firmware,
    authority: u64,
) -> Option<InterruptRemap>
{
    let (flags, sources) = iommu.io_apic_sources()?;
    let off = |why: &str| {
        std::os::seraph::log!(warn: "interrupt remapping off ({}): device messages unchecked", why);
    };
    if !flags.interrupt_remapping
    {
        off("the DMAR offers none");
        return None;
    }
    if let Some(obstacle) = iommu.remap_obstacle()
    {
        off(obstacle.why());
        return None;
    }
    let io_apics = locate_table_by_sig(firmware, *b"APIC").and_then(|madt| {
        with_acpi_table(firmware, madt, |bytes| {
            firmware::acpi::madt_io_apics(bytes).map(Iterator::collect::<Vec<_>>)
        })
    });
    let Some(io_apics) = io_apics.filter(|a| !a.is_empty())
    else
    {
        off("no I/O APIC in the MADT");
        return None;
    };
    let mut paired = Vec::new();
    if paired.try_reserve(io_apics.len()).is_err()
    {
        off("no memory");
        return None;
    }
    for io_apic in io_apics
    {
        let Some(&(_, source)) = sources.iter().find(|(id, _)| *id == io_apic.id)
        else
        {
            off("an I/O APIC has no source ID in the DMAR");
            return None;
        };
        paired.push((io_apic, source));
    }
    let Some(entries) = syscall::cap_info(authority, CAP_INFO_IRQ_REMAP_HANDLES)
        .ok()
        .map(|handles| handles.max(2).next_power_of_two())
        .filter(|&entries| entries <= iommu_labels::MAX_REMAP_ENTRIES)
    else
    {
        off("the kernel reports no handle count");
        return None;
    };
    let client = Arc::clone(iommu.client());
    let extended = match client.remap_setup(entries, !flags.x2apic_opt_out)
    {
        Ok(extended) => extended,
        Err(code) =>
        {
            std::os::seraph::log!(
                warn: "interrupt remapping off (table not set up: {}): device messages unchecked",
                code
            );
            return None;
        }
    };
    let setting = if extended
    {
        IRQ_REMAP_ON_EXTENDED
    }
    else
    {
        IRQ_REMAP_ON
    };
    if let Err(e) = syscall::irq_remap(authority, setting)
    {
        let _ = client.remap_setup(0, false);
        std::os::seraph::log!(
            warn: "interrupt remapping off (kernel refused the switch: {}): device messages unchecked",
            e
        );
        return None;
    }
    std::os::seraph::log!(
        "interrupt remapping on: {} entries, {}-bit destinations",
        entries,
        if extended { 32u64 } else { 8u64 }
    );
    Some(InterruptRemap {
        client,
        io_apics: paired,
    })
}
