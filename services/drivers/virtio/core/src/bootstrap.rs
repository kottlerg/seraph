// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/bootstrap.rs

//! A `VirtIO` PCI driver's reading of the resource list devmgr delivers it
//! (`driver_binding::resources`; docs/driver-binding.md § Binding).
//!
//! For a function that presents the `VirtIO` register layout, devmgr delivers
//! the BARs the layout's register regions name, in ascending BAR index (the
//! order of [`RegisterLayout::bars`](crate::RegisterLayout::bars)), each as
//! one `Mmio` resource from its start or, around the pages holding the
//! function's MSI-X table and Pending Bit Array, which no driver is
//! delivered, as several, each naming its PCI BAR and its offset in it; then
//! the device's interrupt when it has one: its wired line with the mode the
//! driver passes to `SYS_IRQ_REGISTER`, or MSI-X vector 0, whose table entry
//! devmgr has programmed; then the end round's service endpoint, devmgr
//! query cap, and DMA capability. [`DeliveredDevice`] reads that list into
//! the shape the transport maps, and refuses any other.

use driver_binding::resources::{self, InterruptKind, Resource, ResourceList};

use crate::{BarRange, MAX_VIRTIO_RANGES};

/// The interrupt devmgr delivered a `VirtIO` driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceInterrupt
{
    /// The device's wired line: its `Interrupt` cap and the mode the driver
    /// passes to `SYS_IRQ_REGISTER`. The device reports each interrupt in its
    /// ISR status, and the binding owes an acknowledgement per delivery.
    Wired
    {
        cap: u64, mode: u64
    },
    /// MSI-X vector 0, the device's only vector: its message target's
    /// `Interrupt` cap, registered with mode 0. The device reports nothing in
    /// its ISR status under MSI-X (`VirtIO` 1.2 § 4.1.4.5), and the target is
    /// never masked and owes no acknowledgement.
    MsiX
    {
        cap: u64
    },
}

impl DeviceInterrupt
{
    /// The `Interrupt` cap.
    #[must_use]
    pub const fn cap(&self) -> u64
    {
        match *self
        {
            Self::Wired { cap, .. } | Self::MsiX { cap } => cap,
        }
    }

    /// The mode the driver passes to `SYS_IRQ_REGISTER` for the cap.
    #[must_use]
    pub const fn mode(&self) -> u64
    {
        match *self
        {
            Self::Wired { mode, .. } => mode,
            Self::MsiX { .. } => 0,
        }
    }

    /// What the driver logs at bind for the interrupt it was given.
    #[must_use]
    pub const fn describe(&self) -> &'static str
    {
        match *self
        {
            Self::Wired { .. } => "wired line",
            Self::MsiX { .. } => "MSI-X, 1 vector",
        }
    }
}

/// What devmgr delivered a `VirtIO` PCI driver: its BAR ranges, its
/// interrupt, and its endpoints; `0` marks an absent endpoint cap.
pub struct DeliveredDevice
{
    ranges: [BarRange; MAX_VIRTIO_RANGES],
    range_count: usize,
    /// The device's interrupt, `None` when devmgr delivered none.
    pub interrupt: Option<DeviceInterrupt>,
    /// The driver's service endpoint.
    pub service: u64,
    /// The per-device badged SEND on the private driver endpoint of the
    /// driver's devmgr spawn batch, for `QUERY_DEVICE_INFO` and, once the
    /// device is set up, `DRIVER_READY` (`ipc::devmgr_labels`). devmgr serves
    /// the driver's service endpoint only after that report, and revokes this
    /// cap once its batch has settled.
    pub devmgr_query: u64,
    /// The device's DMA capability: a SEND on devmgr's DMA endpoint badged
    /// with the device's badge, for `DMA_MAP` and `DMA_UNMAP`
    /// (`ipc::devmgr_dma_labels`). It lives as long as the driver serves the
    /// device; devmgr revokes it when it withdraws the driver.
    pub dma: u64,
}

impl DeliveredDevice
{
    /// Read a complete resource list. Returns `None` when the list has no
    /// end round or no service endpoint, holds an IOMMU unit (an IOMMU
    /// record's list), delivers no BAR range or more than
    /// [`MAX_VIRTIO_RANGES`], an `Mmio` range that is no PCI BAR's, an
    /// `IoPort`, more than one interrupt, or an interrupt other than a wired
    /// line or MSI-X vector 0 (`VirtIO` over PCI signals by no other).
    #[must_use]
    pub fn from_list(list: &ResourceList) -> Option<Self>
    {
        let endpoints = list.endpoints()?;
        if endpoints.service == 0 || list.holds_units()
        {
            return None;
        }
        let mut device = Self {
            ranges: [BarRange::default(); MAX_VIRTIO_RANGES],
            range_count: 0,
            interrupt: None,
            service: endpoints.service,
            devmgr_query: endpoints.devmgr_query,
            dma: endpoints.dma,
        };
        for resource in list.resources()
        {
            let interrupt = match *resource
            {
                Resource::Mmio {
                    cap,
                    bar: Some(bar),
                    bytes,
                    offset,
                    ..
                } =>
                {
                    // A range past the MAX_VIRTIO_RANGES slots refuses the list.
                    *device.ranges.get_mut(device.range_count)? = BarRange {
                        cap,
                        bar,
                        offset,
                        bytes,
                    };
                    // Below MAX_VIRTIO_RANGES before the increment: no saturation.
                    device.range_count = device.range_count.saturating_add(1);
                    continue;
                }
                Resource::Interrupt {
                    cap,
                    kind: InterruptKind::Wired,
                    mode,
                    ..
                } => DeviceInterrupt::Wired { cap, mode },
                Resource::Interrupt {
                    cap,
                    kind: InterruptKind::MsiX,
                    vector: 0,
                    ..
                } => DeviceInterrupt::MsiX { cap },
                Resource::Mmio { bar: None, .. }
                | Resource::IoPort { .. }
                | Resource::Interrupt {
                    kind: InterruptKind::Msi | InterruptKind::MsiX,
                    ..
                } => return None,
            };
            if device.interrupt.replace(interrupt).is_some()
            {
                return None;
            }
        }
        (device.range_count > 0).then_some(device)
    }

    /// Request and read the resource list from `creator`, the driver's
    /// creator endpoint. `None` when a round fails, the list does not decode
    /// ([`resources::receive`]), or it is not a `VirtIO` device's
    /// ([`Self::from_list`]); every cap received is then deleted.
    ///
    /// # Safety
    /// `ipc_buf` must point to the calling thread's registered IPC buffer
    /// page.
    #[must_use]
    pub unsafe fn receive(creator: u64, ipc_buf: *mut u64) -> Option<Self>
    {
        // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
        let list = unsafe { resources::receive(creator, ipc_buf) }.ok()?;
        let device = Self::from_list(&list);
        if device.is_none()
        {
            for cap in list.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
        }
        device
    }

    /// The delivered BAR ranges, in delivery order; a driver places them in
    /// its register window with
    /// [`RegisterLayout::place`](crate::RegisterLayout::place).
    #[must_use]
    pub fn ranges(&self) -> &[BarRange]
    {
        // `range_count` never exceeds the array (`from_list`).
        self.ranges.get(..self.range_count).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use driver_binding::resources::{Endpoints, IommuUnit, Round};
    use ipc::bootstrap::BootstrapRound;
    use syscall_abi::{MSG_CAP_SLOTS_MAX, MSG_DATA_WORDS_MAX};

    fn list(rounds: &[Round]) -> ResourceList
    {
        let mut list = ResourceList::new();
        for r in rounds
        {
            let mut round = BootstrapRound {
                caps: [0; MSG_CAP_SLOTS_MAX],
                cap_count: r.caps().len(),
                data: [0; MSG_DATA_WORDS_MAX],
                data_words: r.data().len(),
                done: r.done(),
            };
            round.caps[..r.caps().len()].copy_from_slice(r.caps());
            round.data[..r.data().len()].copy_from_slice(r.data());
            list.absorb(&round).expect("well-formed round");
        }
        list
    }

    fn end(service: u64) -> Round
    {
        Round::end(&Endpoints {
            service,
            devmgr_query: 21,
            dma: 22,
        })
    }

    fn range(cap: u64, bar: u8, offset: u64, bytes: u64) -> BarRange
    {
        BarRange {
            cap,
            bar,
            offset,
            bytes,
        }
    }

    #[test]
    fn ranges_line_and_endpoints_are_read_in_delivery_order()
    {
        let mode = syscall_abi::IRQ_MODE_LEVEL | syscall_abi::IRQ_MODE_ACTIVE_LOW;
        let device = DeliveredDevice::from_list(&list(&[
            Round::mmio(10, Some(1), 0x1000, 0x1000),
            Round::mmio(11, Some(4), 0x8000, 0x2000),
            Round::mmio_at(12, Some(4), 0xB000, 0x1000, 0x3000),
            Round::interrupts(InterruptKind::Wired, 0, mode, &[13]).expect("one line"),
            end(20),
        ]))
        .expect("a VirtIO device's list");
        assert_eq!(
            device.ranges(),
            &[
                range(10, 1, 0, 0x1000),
                range(11, 4, 0, 0x2000),
                range(12, 4, 0x3000, 0x1000)
            ]
        );
        assert_eq!(
            device.interrupt,
            Some(DeviceInterrupt::Wired { cap: 13, mode })
        );
        assert_eq!(
            device.interrupt.map(|i| (i.cap(), i.mode())),
            Some((13, mode))
        );
        assert_eq!(
            (device.service, device.devmgr_query, device.dma),
            (20, 21, 22)
        );
    }

    #[test]
    fn msix_vector_0_is_read_with_mode_0()
    {
        let vector = Round::interrupts(InterruptKind::MsiX, 0, 0, &[14]).expect("one vector");
        let device = DeliveredDevice::from_list(&list(&[
            Round::mmio(10, Some(4), 0, 0x4000),
            vector,
            end(20),
        ]))
        .expect("a VirtIO device's list");
        assert_eq!(device.interrupt, Some(DeviceInterrupt::MsiX { cap: 14 }));
        assert_eq!(device.interrupt.map(|i| (i.cap(), i.mode())), Some((14, 0)));
    }

    #[test]
    fn a_device_with_no_interrupt_has_none()
    {
        let device =
            DeliveredDevice::from_list(&list(&[Round::mmio(10, Some(0), 0, 0x1000), end(20)]))
                .expect("a VirtIO device's list");
        assert_eq!(device.interrupt, None);
    }

    #[test]
    fn a_list_of_another_shape_is_refused()
    {
        let bar = || Round::mmio(10, Some(0), 0, 0x1000);
        let line = || Round::interrupts(InterruptKind::Wired, 0, 0, &[12]).expect("one line");
        let msix = |vector, caps: &[u64]| {
            Round::interrupts(InterruptKind::MsiX, vector, 0, caps).expect("vectors")
        };
        // Incomplete: no end round.
        assert!(DeliveredDevice::from_list(&list(&[bar()])).is_none());
        // No service endpoint.
        assert!(DeliveredDevice::from_list(&list(&[bar(), end(0)])).is_none());
        // No BAR.
        assert!(DeliveredDevice::from_list(&list(&[line(), end(20)])).is_none());
        // A range of no BAR.
        assert!(
            DeliveredDevice::from_list(&list(&[Round::mmio(10, None, 0, 0x1000), end(20)]))
                .is_none()
        );
        // An I/O port range.
        assert!(
            DeliveredDevice::from_list(&list(&[bar(), Round::io_port(13, 0x60, 1), end(20)]))
                .is_none()
        );
        // Two lines; a line beside a vector.
        assert!(DeliveredDevice::from_list(&list(&[bar(), line(), line(), end(20)])).is_none());
        assert!(
            DeliveredDevice::from_list(&list(&[bar(), line(), msix(0, &[14]), end(20)])).is_none()
        );
        // Two MSI-X vectors, or a vector other than 0.
        assert!(DeliveredDevice::from_list(&list(&[bar(), msix(0, &[14, 15]), end(20)])).is_none());
        assert!(DeliveredDevice::from_list(&list(&[bar(), msix(1, &[14]), end(20)])).is_none());
        // An MSI vector.
        let msi = Round::interrupts(InterruptKind::Msi, 0, 0, &[14]).expect("one vector");
        assert!(DeliveredDevice::from_list(&list(&[bar(), msi, end(20)])).is_none());
        // An IOMMU unit, even before a well-formed device's resources.
        let unit = Round::iommu_unit(&IommuUnit {
            segment: 0,
            include_pci_all: true,
            scopes: Vec::new(),
        })
        .expect("no scopes");
        assert!(DeliveredDevice::from_list(&list(&[unit, bar(), end(20)])).is_none());
        // More ranges than a delivery holds.
        let many: Vec<Round> = (0..=MAX_VIRTIO_RANGES)
            .map(|i| {
                let page = u64::try_from(i).expect("a small index");
                Round::mmio_at(30 + page, Some(0), page * 0x1000, 0x1000, page * 0x1000)
            })
            .chain([end(20)])
            .collect();
        assert!(DeliveredDevice::from_list(&list(&many)).is_none());
    }
}
