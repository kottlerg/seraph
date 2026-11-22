// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/iommu_labels.rs

//! IPC labels for an IOMMU driver's service endpoint, on which devmgr directs
//! the IOMMU of one family (VT-d, the RISC-V IOMMU).
//!
//! devmgr and the driver hold the only caps to the endpoint (devmgr the
//! original, the driver a full-rights copy it receives on), and neither hands
//! one on, so no other process can send on it. devmgr spawns the driver,
//! hands it each unit's register cap, and drives it from its registry, DMA,
//! and fault-log threads, keeping the drivers' `devmgr_dma_labels` contract
//! unchanged whichever IOMMU, or none, sits behind it. devmgr chooses every IOVA; the
//! IOMMU driver installs and withdraws what devmgr asks and reports faults.
//! No reply arrives before the hardware does what it states: a mapping
//! withdrawn, or a device blocked, is unreachable by the device when the reply
//! is sent. Every request carries the caller's compiled
//! [`IOMMU_LABELS_VERSION`](crate::IOMMU_LABELS_VERSION) in `data[0]`; the driver replies
//! [`iommu_errors::LABEL_VERSION_MISMATCH`](crate::iommu_errors::LABEL_VERSION_MISMATCH) when it differs. Specified in
//! `docs/device-management.md` § IOMMU Discovery and Programming.

/// Give a PCI function its own translation domain, in which it reaches
/// nothing until [`MAP`] or [`MAP_RESERVED`] installs a range.
///
/// Request: `data[1]` = the unit index, in the order the driver's
/// bootstrap delivered the units; `data[2]` = the function's requester
/// ID ([`requester_id`]); `data[3]` = the domain handle to give it, or 0
/// for one the driver chooses; `data[4]` = the domain ID to tag its
/// translations with on its unit, or 0 for one the driver chooses. A
/// restarted driver's replay names the handle and domain ID the function
/// held under the instance before it ([`COMMIT`]); devmgr names every
/// handle, each once in the boot, so that a restarted instance gives none
/// a dead one gave. Reply: label `SUCCESS`
/// with `data[0]` = the domain handle every later request for the
/// function names and `data[1]` = its domain ID; or an error code,
/// `INVALID_REQUEST` for a named handle or domain ID another domain holds
/// or the unit does not have. A function attached twice keeps its first
/// domain.
pub const ATTACH: u64 = 1;
/// Make the frames of a Memory cap reachable by a domain's function at an
/// IOVA devmgr chose.
///
/// Request: `data[1]` = domain, `data[2]` = IOVA of the cap's first byte,
/// page-aligned, `data[3]` = access (`devmgr_dma_labels::ACCESS_*`);
/// `caps[0]` = a derivation of the Memory cap devmgr keeps for the
/// mapping, moved to the driver, which keeps it while the range is
/// installed and deletes it at its [`UNMAP`] or the domain's [`BLOCK`].
/// The whole cap is installed. Reply: empty body, label `SUCCESS`, or an
/// error code with the cap deleted.
pub const MAP: u64 = 2;
/// Withdraw the range [`MAP`] installed at an IOVA of a domain.
///
/// Request: `data[1]` = domain, `data[2]` = the IOVA. Reply: empty body,
/// label `SUCCESS` once the range is removed and the invalidation it
/// needs has completed, or an error code; `INVALID_REQUEST` for a range
/// [`MAP_RESERVED`] or [`MAP_MSI`] installed.
pub const UNMAP: u64 = 3;
/// Block a domain's function: it reaches no frame from the reply on.
/// Every range of the domain is withdrawn with it.
///
/// Request: `data[1]` = domain. Reply: empty body, label `SUCCESS` once
/// the block and its invalidation have completed, or an error code.
pub const BLOCK: u64 = 4;
/// Report a unit's translation limits, which devmgr's IOVA allocator
/// keeps within.
///
/// Request: `data[1]` = unit index. Reply: label `SUCCESS` with
/// `data[0]` = the widest IOVA the unit translates, in bits; or an error
/// code.
pub const QUERY_UNIT: u64 = 5;
/// Take the faults the driver has recorded since the last call.
///
/// Request: no further words. Reply: label `SUCCESS` with `data[0]` =
/// the number of faults that follow, at most [`MAX_FAULTS_PER_REPLY`],
/// then two words per fault: the requester ID in the low 32 bits and
/// the unit's fault reason in bits 32..48 (VT-d's 8-bit fault reason,
/// the RISC-V IOMMU's 12-bit `CAUSE`), and the faulting IOVA, or for a
/// VT-d interrupt remapping fault (reason `0x20` and above) the handle
/// the blocked interrupt named. A fault past the bound stays for the
/// next call.
pub const TAKE_FAULTS: u64 = 6;
/// Make a physical range the firmware reserves for a domain's function
/// (a VT-d RMRR) reachable by it at the same address: an identity
/// mapping, read-write, that devmgr installs right after [`ATTACH`] and
/// before the function's DMA grant.
///
/// Request: `data[1]` = domain, `data[2]` = the range's first byte,
/// page-aligned, `data[3]` = its length, a nonzero multiple of the page
/// size; no cap, since no Memory cap covers firmware-reserved memory.
/// The range stays for the domain's life: [`UNMAP`] refuses it, and the
/// domain's [`BLOCK`] withdraws it. Reply: empty body, label `SUCCESS`,
/// or an error code.
pub const MAP_RESERVED: u64 = 7;
/// Make one interrupt file a message-signalled interrupt targets
/// reachable by a domain's function at its own address, so the
/// function's MSI writes to it reach it: on riscv64 the supervisor-level
/// IMSIC file of a hart one of the function's interrupt targets sits on,
/// which the RISC-V IOMMU translates as any other write of the function.
/// A domain reaches only the files installed in it.
///
/// Request: `data[1]` = domain, `data[2]` = the file's physical address,
/// page-aligned; one page, read-write, no cap. The page stands for the
/// domain's life: [`UNMAP`] refuses it, and the domain's [`BLOCK`]
/// withdraws it. Reply: empty body, label `SUCCESS`, or an error code;
/// `INVALID_REQUEST` from an IOMMU family whose MSIs are not reached
/// through its DMA translation (VT-d, whose interrupt remapping governs
/// them).
pub const MAP_MSI: u64 = 8;
/// Turn interrupt remapping on or off for every unit, with one
/// remapping table devmgr allocates and keeps for the boot and every unit
/// shares: with it on, an interrupt message reaches a CPU only through a
/// table entry [`REMAP_SET`] made, and one in the compatibility format is
/// blocked. devmgr sends it once, before any interrupt source exists, and
/// turns remapping off again with it when the kernel does not take the
/// remappable formats. A restarted driver finds remapping on from the
/// table and adopts it as it stands, interrupts still delivered through
/// its entries.
///
/// Request: `data[1]` = the table's entries, a power of two from 2 to
/// [`MAX_REMAP_ENTRIES`], or 0 to turn remapping off; `data[2]` = 1 to
/// ask for 32-bit destinations, 0 for 8-bit ones; `caps[0]` = a Memory
/// cap on the table, physically contiguous, zeroed when devmgr allocated
/// it, and of at least 16 bytes an entry, which the driver keeps; none
/// when turning remapping off. Reply: label `SUCCESS` with `data[0]` = 1
/// when the destinations are 32-bit, 0 when they are 8-bit; or an error
/// code, with remapping off (a restarted driver's left as it stood):
/// `INVALID_REQUEST` for a size outside the bound, a missing or short
/// table cap, a table already set up, units that translate more than
/// one PCI segment (an entry names its requester by a source ID with no
/// segment), an IOMMU family or unit that does not remap interrupts, or
/// a restarted driver whose units do not remap from the table given.
pub const REMAP_SETUP: u64 = 9;
/// Make one entry of the remapping table deliver to a CPU's vector for
/// one requester, replacing what it held; the reply follows the
/// invalidation of every unit's cached copy. An entry that already
/// holds exactly this is left as it is, so devmgr may set a live
/// source's entry again without a gap in its delivery.
///
/// Request: `data[1]` = the entry's handle, below the table's entries;
/// `data[2]` = the destination CPU's interrupt controller ID, within the
/// width [`REMAP_SETUP`] replied; `data[3]` = the vector, 16 to 255;
/// `data[4]` = 1 for level-triggered, 0 for edge; `data[5]` = the
/// source ID (bus, device, function) of the only requester the entry
/// accepts. Reply: empty body, label `SUCCESS`, or an error code;
/// `INVALID_REQUEST` with remapping off or a field outside its bound.
pub const REMAP_SET: u64 = 10;
/// Make one entry of the remapping table not present, so an interrupt
/// naming it is blocked and faulted; the reply follows the invalidation
/// of every unit's cached copy.
///
/// Request: `data[1]` = the entry's handle. Reply: as [`REMAP_SET`].
pub const REMAP_CLEAR: u64 = 11;
/// Make a restarted driver's tables the ones the units translate through.
///
/// A driver devmgr restarts after its predecessor died finds every unit
/// translating from the root page devmgr keeps for it (its anchor,
/// `driver_binding::resources::FLAG_ADOPT`) through the dead instance's
/// tables, and builds devmgr's replayed domains in tables of its own
/// under a staging root. `COMMIT` copies each staged root entry into the
/// anchor, one aligned 64-bit store for an entry whose old and new values
/// differ in one word (every function sees its old or its new context,
/// both holding the same ranges under the same domain ID), then
/// invalidates every unit's translation caches, draining the device
/// accesses in flight, and on VT-d makes not present every remapping
/// entry not set since the restart. From the reply on no unit reaches a
/// page of the dead instance's.
///
/// Request: no further words. Reply: empty body, label `SUCCESS`, or an
/// error code: `INVALID_REQUEST` from a driver not started to adopt or
/// one that has committed already, `HARDWARE_TIMEOUT` when a unit does
/// not complete an invalidation.
pub const COMMIT: u64 = 12;

/// Entries one remapping table holds at most ([`REMAP_SETUP`]): a
/// remappable interrupt message names its entry in 16 bits.
pub const MAX_REMAP_ENTRIES: u64 = 1 << 16;

/// Faults one [`TAKE_FAULTS`] reply carries: two words each after the
/// count, within the message's data words.
pub const MAX_FAULTS_PER_REPLY: usize = (crate::MSG_DATA_WORDS_MAX - 1) / 2;

/// The requester ID of a PCI function: segment in bits 16..32, bus in
/// bits 8..16, device in bits 3..8, function in bits 0..3.
#[must_use]
pub const fn requester_id(segment: u16, bus: u8, device: u8, function: u8) -> u64
{
    ((segment as u64) << 16)
        | ((bus as u64) << 8)
        | (((device & 0x1f) as u64) << 3)
        | ((function & 0x7) as u64)
}

#[cfg(test)]
mod tests
{
    use crate::{MSG_DATA_WORDS_MAX, iommu_labels};

    #[test]
    fn a_requester_id_packs_segment_bus_device_and_function()
    {
        assert_eq!(iommu_labels::requester_id(0, 0, 3, 0), 0x18);
        assert_eq!(iommu_labels::requester_id(1, 2, 0x1f, 7), 0x1_02ff);
        // Out-of-range device and function bits are masked off.
        assert_eq!(iommu_labels::requester_id(0, 0, 0x20, 8), 0);
    }

    #[test]
    fn a_fault_reply_fits_its_count_and_two_words_per_fault()
    {
        const { assert!(2 * iommu_labels::MAX_FAULTS_PER_REPLY < MSG_DATA_WORDS_MAX) };
    }
}
