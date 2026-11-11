// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/bootstrap.rs

//! A `VirtIO` PCI driver's reading of the resource list devmgr delivers it
//! (`driver_binding::resources`; docs/driver-binding.md § Binding).
//!
//! For a function that presents the `VirtIO` register layout, devmgr delivers
//! one `Mmio` resource per distinct BAR the layout's register regions name,
//! in ascending BAR index (the order of
//! [`RegisterLayout::bars`](crate::RegisterLayout::bars)), each naming its
//! PCI BAR; then the function's wired interrupt line when it has one, with
//! the mode the driver passes to `SYS_IRQ_REGISTER`; then the end round's
//! service endpoint, devmgr query cap, and DMA capability. [`DeliveredDevice`]
//! reads that list into the shape the transport maps, and refuses any other.

use driver_binding::resources::{self, InterruptKind, Resource, ResourceList};

use crate::MAX_VIRTIO_BARS;

/// What devmgr delivered a `VirtIO` PCI driver: its BAR caps, its interrupt
/// line, and its endpoints; `0` marks an absent cap.
pub struct DeliveredDevice
{
    bar_caps: [u64; MAX_VIRTIO_BARS],
    bar_indices: [u64; MAX_VIRTIO_BARS],
    bar_count: usize,
    /// The device's wired-line `Interrupt` cap, `0` when devmgr delivered
    /// none.
    pub irq: u64,
    /// The mode the driver passes to `SYS_IRQ_REGISTER` for [`Self::irq`];
    /// 0 with no line.
    pub irq_mode: u64,
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
    /// end round or no service endpoint, delivers no BAR or more than
    /// [`MAX_VIRTIO_BARS`], an `Mmio` range that is no PCI BAR, an `IoPort`,
    /// more than one interrupt, or an interrupt other than a wired line.
    #[must_use]
    pub fn from_list(list: &ResourceList) -> Option<Self>
    {
        let endpoints = list.endpoints()?;
        if endpoints.service == 0
        {
            return None;
        }
        let mut device = Self {
            bar_caps: [0; MAX_VIRTIO_BARS],
            bar_indices: [0; MAX_VIRTIO_BARS],
            bar_count: 0,
            irq: 0,
            irq_mode: 0,
            service: endpoints.service,
            devmgr_query: endpoints.devmgr_query,
            dma: endpoints.dma,
        };
        for resource in list.resources()
        {
            match *resource
            {
                Resource::Mmio {
                    cap,
                    bar: Some(bar),
                    ..
                } if device.bar_count < MAX_VIRTIO_BARS =>
                {
                    device.bar_caps[device.bar_count] = cap;
                    device.bar_indices[device.bar_count] = u64::from(bar);
                    device.bar_count += 1;
                }
                Resource::Interrupt {
                    cap,
                    kind: InterruptKind::Wired,
                    mode,
                    ..
                } if device.irq == 0 =>
                {
                    device.irq = cap;
                    device.irq_mode = mode;
                }
                _ => return None,
            }
        }
        (device.bar_count > 0).then_some(device)
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

    /// The BAR caps, in delivery order.
    #[must_use]
    pub fn bar_caps(&self) -> &[u64]
    {
        &self.bar_caps[..self.bar_count]
    }

    /// The PCI BAR index of each cap, parallel to
    /// [`bar_caps`](Self::bar_caps); a driver checks it with
    /// [`RegisterLayout::matches_delivered`](crate::RegisterLayout::matches_delivered).
    #[must_use]
    pub fn bar_indices(&self) -> &[u64]
    {
        &self.bar_indices[..self.bar_count]
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use driver_binding::resources::{Endpoints, Round};
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

    #[test]
    fn bars_line_and_endpoints_are_read_in_delivery_order()
    {
        let mode = syscall_abi::IRQ_MODE_LEVEL | syscall_abi::IRQ_MODE_ACTIVE_LOW;
        let device = DeliveredDevice::from_list(&list(&[
            Round::mmio(10, Some(1), 0x1000, 0x1000),
            Round::mmio(11, Some(4), 0x8000, 0x4000),
            Round::interrupts(InterruptKind::Wired, 0, mode, &[12]).expect("one line"),
            end(20),
        ]))
        .expect("a VirtIO device's list");
        assert_eq!(device.bar_caps(), &[10, 11]);
        assert_eq!(device.bar_indices(), &[1, 4]);
        assert_eq!((device.irq, device.irq_mode), (12, mode));
        assert_eq!(
            (device.service, device.devmgr_query, device.dma),
            (20, 21, 22)
        );
    }

    #[test]
    fn a_device_with_no_line_has_no_irq()
    {
        let device =
            DeliveredDevice::from_list(&list(&[Round::mmio(10, Some(0), 0, 0x1000), end(20)]))
                .expect("a VirtIO device's list");
        assert_eq!((device.irq, device.irq_mode), (0, 0));
    }

    #[test]
    fn a_list_of_another_shape_is_refused()
    {
        let bar = || Round::mmio(10, Some(0), 0, 0x1000);
        let line = || Round::interrupts(InterruptKind::Wired, 0, 0, &[12]).expect("one line");
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
        // Two lines.
        assert!(DeliveredDevice::from_list(&list(&[bar(), line(), line(), end(20)])).is_none());
        // A message-signaled vector.
        let msi = Round::interrupts(InterruptKind::Msi, 0, 0, &[14]).expect("one vector");
        assert!(DeliveredDevice::from_list(&list(&[bar(), msi, end(20)])).is_none());
        // More BARs than the layout names.
        let many: Vec<Round> = (0..=MAX_VIRTIO_BARS)
            .map(|i| {
                let bar = u8::try_from(i).expect("a BAR index");
                Round::mmio(30 + u64::from(bar), Some(bar), 0, 0x1000)
            })
            .chain([end(20)])
            .collect();
        assert!(DeliveredDevice::from_list(&list(&many)).is_none());
    }
}
