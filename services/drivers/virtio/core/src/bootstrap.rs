// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/bootstrap.rs

//! The bootstrap rounds devmgr serves a `VirtIO` PCI driver, and their
//! driver-side decoding.
//!
//! Two rounds over `ipc::bootstrap`:
//!
//! - Round 1 (not terminal) carries one `Mmio` cap per distinct BAR the
//!   device's register regions name, in ascending BAR index (the order of
//!   [`RegisterLayout::bars`](crate::RegisterLayout::bars)), and one data
//!   word per cap: `data[i]` is the PCI BAR index of `caps[i]`.
//! - Round 2 (terminal) carries the positional slots [`SLOT_SERVICE`],
//!   [`SLOT_IRQ`], and [`SLOT_DEVMGR_QUERY`], packed with
//!   [`ipc::bootstrap::pack_slots`] and its presence word in `data[0]`
//!   ([`DATA_PRESENCE`]), and the IRQ line's mode in `data[1]`
//!   ([`DATA_IRQ_MODE`]): the trigger and polarity word the driver passes to
//!   `SYS_IRQ_REGISTER` (`IRQ_MODE_*` in `abi/syscall`), which devmgr derives
//!   for the line (services/devmgr/docs/pci-enumeration.md). The IRQ slot is
//!   absent when devmgr could give the device no IRQ cap, and the mode word is
//!   then 0.
//!
//! The protocol carries no version constant; a round of another shape fails
//! the checks here and the driver exits.

use ipc::bootstrap::BootstrapRound;
use syscall_abi::MSG_CAP_SLOTS_MAX;

use crate::MAX_VIRTIO_BARS;

// devmgr delivers every BAR a device names in round 1, one cap each.
const _: () = assert!(MAX_VIRTIO_BARS <= MSG_CAP_SLOTS_MAX);

/// Round-2 slot of the driver's service endpoint.
pub const SLOT_SERVICE: usize = 0;
/// Round-2 slot of the device's single-IRQ `Interrupt` cap.
pub const SLOT_IRQ: usize = 1;
/// Round-2 slot of the per-device badged SEND on the private driver endpoint
/// of the driver's devmgr spawn batch, for `QUERY_DEVICE_INFO` and, once the
/// device is set up, `DRIVER_READY` (`ipc::devmgr_labels`). devmgr serves the
/// driver's service endpoint only after that report, and revokes this cap
/// once its batch has settled.
pub const SLOT_DEVMGR_QUERY: usize = 2;
/// Slots round 2 carries.
pub const ROUND2_SLOTS: usize = 3;
/// Round-2 data word holding the presence word of the slots.
pub const DATA_PRESENCE: usize = 0;
/// Round-2 data word holding the IRQ line's `SYS_IRQ_REGISTER` mode.
pub const DATA_IRQ_MODE: usize = 1;
/// Data words round 2 carries.
pub const ROUND2_DATA_WORDS: usize = 2;

// Round 2 is one positional-slot round.
const _: () = assert!(ROUND2_SLOTS <= MSG_CAP_SLOTS_MAX);

/// The BAR caps a driver received in round 1, each with its PCI BAR index.
pub struct DeliveredBars
{
    caps: [u64; MAX_VIRTIO_BARS],
    bar_indices: [u64; MAX_VIRTIO_BARS],
    count: usize,
}

impl DeliveredBars
{
    /// Decode round 1. Returns `None` when the round is terminal, carries no
    /// cap or more than [`MAX_VIRTIO_BARS`], or does not carry one BAR-index
    /// word per cap.
    #[must_use]
    pub fn from_round(round: &BootstrapRound) -> Option<Self>
    {
        let count = round.cap_count;
        if round.done || count == 0 || count > MAX_VIRTIO_BARS || round.data_words != count
        {
            return None;
        }
        let mut bars = Self {
            caps: [0; MAX_VIRTIO_BARS],
            bar_indices: [0; MAX_VIRTIO_BARS],
            count,
        };
        bars.caps[..count].copy_from_slice(&round.caps[..count]);
        bars.bar_indices[..count].copy_from_slice(&round.data[..count]);
        Some(bars)
    }

    /// The BAR caps, in delivery order.
    #[must_use]
    pub fn caps(&self) -> &[u64]
    {
        &self.caps[..self.count]
    }

    /// The PCI BAR index of each cap, parallel to [`caps`](Self::caps); a
    /// driver checks it with
    /// [`RegisterLayout::matches_delivered`](crate::RegisterLayout::matches_delivered).
    #[must_use]
    pub fn bar_indices(&self) -> &[u64]
    {
        &self.bar_indices[..self.count]
    }
}

/// The caps a driver received in round 2; `0` marks an absent slot.
pub struct DriverEndpoints
{
    /// The driver's service endpoint ([`SLOT_SERVICE`]).
    pub service: u64,
    /// The device's IRQ cap ([`SLOT_IRQ`]), `0` when devmgr delivered none.
    pub irq: u64,
    /// The mode the driver passes to `SYS_IRQ_REGISTER` for [`Self::irq`]
    /// ([`DATA_IRQ_MODE`]).
    pub irq_mode: u64,
    /// devmgr's per-device query and ready-report endpoint
    /// ([`SLOT_DEVMGR_QUERY`]).
    pub devmgr_query: u64,
}

impl DriverEndpoints
{
    /// Decode round 2. Returns `None` when the round is not terminal, it
    /// carries other than [`ROUND2_DATA_WORDS`] data words, its presence word
    /// disagrees with its caps ([`ipc::bootstrap::spread_slots`]), it fills a
    /// slot past [`ROUND2_SLOTS`], or its mode word sets a bit outside
    /// `IRQ_MODE_MASK`.
    #[must_use]
    pub fn from_round(round: &BootstrapRound) -> Option<Self>
    {
        if !round.done || round.data_words != ROUND2_DATA_WORDS
        {
            return None;
        }
        let slots =
            ipc::bootstrap::spread_slots(&round.caps[..round.cap_count], round.data[DATA_PRESENCE])
                .ok()?;
        let irq_mode = round.data[DATA_IRQ_MODE];
        if slots[ROUND2_SLOTS..].iter().any(|&s| s != 0)
            || irq_mode & !syscall_abi::IRQ_MODE_MASK != 0
        {
            return None;
        }
        Some(Self {
            service: slots[SLOT_SERVICE],
            irq: slots[SLOT_IRQ],
            irq_mode,
            devmgr_query: slots[SLOT_DEVMGR_QUERY],
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use syscall_abi::MSG_DATA_WORDS_MAX;

    fn round(done: bool, caps: &[u64], data: &[u64]) -> BootstrapRound
    {
        let mut r = BootstrapRound {
            caps: [0; MSG_CAP_SLOTS_MAX],
            cap_count: caps.len(),
            data: [0; MSG_DATA_WORDS_MAX],
            data_words: data.len(),
            done,
        };
        r.caps[..caps.len()].copy_from_slice(caps);
        r.data[..data.len()].copy_from_slice(data);
        r
    }

    #[test]
    fn round_one_pairs_each_bar_cap_with_its_bar_index()
    {
        let bars = DeliveredBars::from_round(&round(false, &[10, 11], &[2, 4]))
            .expect("well-formed round 1");
        assert_eq!(bars.caps(), &[10, 11]);
        assert_eq!(bars.bar_indices(), &[2, 4]);
    }

    #[test]
    fn round_one_of_another_shape_is_refused()
    {
        // The single-BAR shape this protocol replaced: three caps, no words.
        assert!(DeliveredBars::from_round(&round(false, &[10, 11, 12], &[])).is_none());
        // One index word short.
        assert!(DeliveredBars::from_round(&round(false, &[10, 11], &[2])).is_none());
        // No BAR at all.
        assert!(DeliveredBars::from_round(&round(false, &[], &[])).is_none());
        // Terminal: the driver would never receive round 2.
        assert!(DeliveredBars::from_round(&round(true, &[10], &[0])).is_none());
    }

    #[test]
    fn round_two_spreads_present_caps_over_their_slots()
    {
        // No IRQ: service and devmgr query present (slots 0 and 2).
        let eps = DriverEndpoints::from_round(&round(true, &[20, 22], &[0b101, 0]))
            .expect("well-formed round 2");
        assert_eq!((eps.service, eps.irq, eps.devmgr_query), (20, 0, 22));
    }

    #[test]
    fn round_two_carries_the_irq_lines_mode()
    {
        let mode = syscall_abi::IRQ_MODE_LEVEL | syscall_abi::IRQ_MODE_ACTIVE_LOW;
        let eps = DriverEndpoints::from_round(&round(true, &[20, 21, 22], &[0b111, mode]))
            .expect("well-formed round 2");
        assert_eq!((eps.irq, eps.irq_mode), (21, mode));
    }

    #[test]
    fn round_two_of_another_shape_is_refused()
    {
        // Not terminal.
        assert!(DriverEndpoints::from_round(&round(false, &[20, 21, 22], &[0b111, 0])).is_none());
        // No presence word.
        assert!(DriverEndpoints::from_round(&round(true, &[20], &[])).is_none());
        // No mode word: the shape before the mode word.
        assert!(DriverEndpoints::from_round(&round(true, &[20, 21, 22], &[0b111])).is_none());
        // A slot past the three round 2 defines.
        assert!(
            DriverEndpoints::from_round(&round(true, &[20, 21, 22, 23], &[0b1111, 0])).is_none()
        );
        // A mode bit outside IRQ_MODE_MASK.
        let bad = syscall_abi::IRQ_MODE_MASK + 1;
        assert!(DriverEndpoints::from_round(&round(true, &[20, 21, 22], &[0b111, bad])).is_none());
    }
}
