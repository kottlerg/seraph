// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/core/src/pci.rs

//! `VirtIO` modern PCI transport (`VirtIO` 1.2 §4.1).
//!
//! Provides register-level access to the four `VirtIO` PCI capability regions
//! (common cfg, notification, ISR, device cfg) mapped via MMIO BARs.

use crate::{STATUS_FEATURES_OK, VirtioPciStartupInfo};

/// Modern PCI transport backed by MMIO-mapped BAR regions.
///
/// The four register regions are located within BAR MMIO mappings at offsets
/// provided by devmgr via [`VirtioPciStartupInfo`].
pub struct PciTransport
{
    /// Virtual address of the mapped BAR containing common/notify/ISR/device regions.
    bar_va: u64,
    common_off: u32,
    notify_off: u32,
    isr_off: u32,
    device_off: u32,
    notify_off_multiplier: u32,
}

impl PciTransport
{
    /// Create a new PCI transport from a mapped BAR base address and startup info.
    ///
    /// `bar_va` is the virtual address where the BAR is mapped.
    /// All four capability regions must reside in the same BAR (BAR0).
    #[must_use]
    pub fn new(bar_va: u64, info: &VirtioPciStartupInfo) -> Self
    {
        Self {
            bar_va,
            common_off: info.common_cfg.offset,
            notify_off: info.notify_cfg.offset,
            isr_off: info.isr_cfg.offset,
            device_off: info.device_cfg.offset,
            notify_off_multiplier: info.notify_off_multiplier,
        }
    }

    // ── Common configuration registers (`VirtIO` 1.2 §4.1.4.3) ─────────

    fn common_addr(&self, offset: u32) -> u64
    {
        self.bar_va + u64::from(self.common_off) + u64::from(offset)
    }

    /// Read device feature bits (selected by `device_feature_select`).
    #[must_use]
    pub fn read_device_features(&self, sel: u32) -> u32
    {
        self.write_common_u32(0x00, sel); // device_feature_select
        self.read_common_u32(0x04) // device_feature
    }

    /// Write driver feature bits (selected by `driver_feature_select`).
    pub fn write_driver_features(&self, sel: u32, val: u32)
    {
        self.write_common_u32(0x08, sel); // driver_feature_select
        self.write_common_u32(0x0C, val); // driver_feature
    }

    /// Read device status.
    #[must_use]
    pub fn get_status(&self) -> u8
    {
        // SAFETY: common cfg region is mapped and offset 0x14 is within bounds.
        unsafe { core::ptr::read_volatile(self.common_addr(0x14) as *const u8) }
    }

    /// Write device status.
    pub fn set_status(&self, status: u8)
    {
        // SAFETY: common cfg region is mapped and offset 0x14 is within bounds.
        unsafe { core::ptr::write_volatile(self.common_addr(0x14) as *mut u8, status) }
        mmio::mmio_to_mmio_barrier();
    }

    /// Select a virtqueue for subsequent queue register operations.
    pub fn queue_select(&self, idx: u16)
    {
        self.write_common_u16(0x16, idx);
    }

    /// Read maximum queue size for the selected queue.
    #[must_use]
    pub fn queue_max_size(&self) -> u16
    {
        self.read_common_u16(0x18)
    }

    /// Set queue size for the selected queue.
    pub fn queue_set_size(&self, size: u16)
    {
        self.write_common_u16(0x18, size);
    }

    /// Read the notification offset for the selected queue.
    #[must_use]
    pub fn queue_notify_off(&self) -> u16
    {
        self.read_common_u16(0x1E)
    }

    /// Set descriptor table physical address (low 32 bits).
    pub fn queue_set_desc_lo(&self, addr: u32)
    {
        self.write_common_u32(0x20, addr);
    }

    /// Set descriptor table physical address (high 32 bits).
    pub fn queue_set_desc_hi(&self, addr: u32)
    {
        self.write_common_u32(0x24, addr);
    }

    /// Set available ring physical address (low 32 bits).
    pub fn queue_set_avail_lo(&self, addr: u32)
    {
        self.write_common_u32(0x28, addr);
    }

    /// Set available ring physical address (high 32 bits).
    pub fn queue_set_avail_hi(&self, addr: u32)
    {
        self.write_common_u32(0x2C, addr);
    }

    /// Set used ring physical address (low 32 bits).
    pub fn queue_set_used_lo(&self, addr: u32)
    {
        self.write_common_u32(0x30, addr);
    }

    /// Set used ring physical address (high 32 bits).
    pub fn queue_set_used_hi(&self, addr: u32)
    {
        self.write_common_u32(0x34, addr);
    }

    /// Enable (1) or disable (0) the selected queue.
    pub fn queue_set_ready(&self, ready: u16)
    {
        self.write_common_u16(0x1C, ready);
    }

    // ── Notification (`VirtIO` 1.2 §4.1.4.4) ───────────────────────────

    /// Notify the device that new buffers are available in `queue_idx`.
    ///
    /// Issues a DMA→MMIO ordering barrier before the notify write so that
    /// the device observes prior descriptor/avail-ring/idx updates before
    /// servicing the notification. Without this barrier the device model
    /// may read a stale `avail.idx` and find an empty ring; observed as
    /// intermittent hangs at `cpus>1` on RISC-V, where the required ordering
    /// is not implicit and raw `write_volatile` is the `writel_relaxed`
    /// analogue.
    pub fn notify(&self, queue_idx: u16, queue_notify_off: u16)
    {
        mmio::dma_to_mmio_barrier();

        let offset = u64::from(self.notify_off)
            + u64::from(queue_notify_off) * u64::from(self.notify_off_multiplier);
        let addr = (self.bar_va + offset) as *mut u16;
        // SAFETY: notification region is within the mapped BAR; addr is
        // naturally aligned (notify_off and multiplier are set by the device
        // to maintain u16 alignment per VirtIO 1.2 §4.1.4.4).
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::write_volatile(addr, queue_idx);
        }
        mmio::mmio_to_mmio_barrier();
    }

    // ── ISR status (`VirtIO` 1.2 §4.1.4.5) ─────────────────────────────

    /// Read and clear the ISR status register.
    #[must_use]
    pub fn read_isr(&self) -> u8
    {
        let addr = (self.bar_va + u64::from(self.isr_off)) as *const u8;
        // SAFETY: ISR region is within the mapped BAR.
        unsafe { core::ptr::read_volatile(addr) }
    }

    // ── Device-specific config (`VirtIO` 1.2 §4.1.4.6) ─────────────────

    /// Read a u32 from device-specific configuration space.
    #[must_use]
    pub fn config_read_u32(&self, offset: u32) -> u32
    {
        let addr = self.bar_va + u64::from(self.device_off) + u64::from(offset);
        // SAFETY: device cfg region is within the mapped BAR; offset is
        // caller-provided and must be u32-aligned.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    /// Read a u64 from device-specific configuration space.
    #[must_use]
    pub fn config_read_u64(&self, offset: u32) -> u64
    {
        let lo = self.config_read_u32(offset);
        let hi = self.config_read_u32(offset + 4);
        u64::from(lo) | (u64::from(hi) << 32)
    }

    // ── Device negotiation (`VirtIO` 1.2 §3.1.1) ───────────────────────

    /// Reset the device (write 0 to status).
    pub fn reset(&self)
    {
        self.set_status(0);
        // Wait for reset to complete: status must read 0.
        while self.get_status() != 0
        {
            core::hint::spin_loop();
        }
    }

    /// Run the standard feature negotiation sequence.
    ///
    /// Reads device features, calls `negotiate` to select driver features,
    /// writes them back, and sets `FEATURES_OK`. Returns the negotiated
    /// feature bits, or `None` if the device rejected them.
    pub fn negotiate_features<F>(&self, negotiate: F) -> Option<u64>
    where
        F: FnOnce(u64) -> u64,
    {
        let dev_lo = self.read_device_features(0);
        let dev_hi = self.read_device_features(1);
        let device_features = u64::from(dev_lo) | (u64::from(dev_hi) << 32);

        let driver_features = negotiate(device_features);

        #[allow(clippy::cast_possible_truncation)]
        {
            self.write_driver_features(0, driver_features as u32);
            self.write_driver_features(1, (driver_features >> 32) as u32);
        }

        let status = self.get_status() | STATUS_FEATURES_OK;
        self.set_status(status);

        // Device must accept by keeping FEATURES_OK set.
        if self.get_status() & STATUS_FEATURES_OK == 0
        {
            return None;
        }

        Some(driver_features)
    }

    // ── Internal helpers ────────────────────────────────────────────────

    fn read_common_u16(&self, offset: u32) -> u16
    {
        let addr = self.common_addr(offset);
        // SAFETY: common cfg region is mapped; VirtIO PCI common cfg registers
        // are naturally aligned within the BAR.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::read_volatile(addr as *const u16)
        }
    }

    fn write_common_u16(&self, offset: u32, val: u16)
    {
        let addr = self.common_addr(offset);
        // SAFETY: common cfg region is mapped; VirtIO PCI common cfg registers
        // are naturally aligned within the BAR.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::write_volatile(addr as *mut u16, val);
        }
        mmio::mmio_to_mmio_barrier();
    }

    fn read_common_u32(&self, offset: u32) -> u32
    {
        let addr = self.common_addr(offset);
        // SAFETY: common cfg region is mapped; VirtIO PCI common cfg registers
        // are naturally aligned within the BAR.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    fn write_common_u32(&self, offset: u32, val: u32)
    {
        let addr = self.common_addr(offset);
        // SAFETY: common cfg region is mapped; VirtIO PCI common cfg registers
        // are naturally aligned within the BAR.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, val);
        }
        mmio::mmio_to_mmio_barrier();
    }
}
