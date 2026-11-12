// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/pci.rs

//! `VirtIO` modern PCI transport (`VirtIO` 1.2 §4.1).
//!
//! Provides register-level access to the four `VirtIO` PCI capability regions
//! (common cfg, notification, ISR, device cfg) mapped via MMIO BARs.

use core::time::Duration;

use crate::bootstrap::DeviceInterrupt;
use crate::{COMMON_CFG_LEN, RegisterLayout, STATUS_FEATURES_OK};

/// How long a reset is waited for, on the caller's clock: by
/// [`PciTransport::try_reset`] in a driver, and by devmgr when it resets a
/// withdrawn driver's device (services/devmgr/docs/responsibilities.md),
/// which holds devmgr's thread up to that long per withdrawn device, all of it
/// for a device whose status does not read 0 within the bound.
/// QEMU completes a reset within the status write; the bound only keeps a
/// wedged device from parking the waiter in the poll. A wall-clock bound, so
/// the time it spans does not depend on the platform's MMIO-read cost. A
/// tuning value that bounds no capacity: it decides only when an
/// unacknowledged reset is given up on.
pub const RESET_TIMEOUT: Duration = Duration::from_secs(5);

/// The MSI-X vector value that routes an event to no vector (`VirtIO` 1.2
/// § 4.1.5.1.2).
pub const NO_VECTOR: u16 = 0xFFFF;

/// Offset of `config_msix_vector` in the common configuration region
/// (`VirtIO` 1.2 § 4.1.4.3).
const COMMON_CONFIG_MSIX_VECTOR: u32 = 0x10;
/// Offset of `queue_msix_vector` in the common configuration region.
const COMMON_QUEUE_MSIX_VECTOR: u32 = 0x1A;

/// Poll `done` until it holds or `elapsed` reaches `timeout`, returning
/// whether it held.
///
/// `done` is probed once more after the deadline passes, so a thread
/// descheduled across the whole window still sees a condition that became
/// true meanwhile rather than reporting a timeout it never polled through.
pub fn poll_until(
    timeout: Duration,
    elapsed: impl Fn() -> Duration,
    mut done: impl FnMut() -> bool,
) -> bool
{
    loop
    {
        if done()
        {
            return true;
        }
        if elapsed() >= timeout
        {
            return done();
        }
        core::hint::spin_loop();
    }
}

/// `addr` as the `(low, high)` 32-bit halves a common-configuration register
/// pair takes a 64-bit device address in (`VirtIO` 1.2 §4.1.4.3).
// cast_possible_truncation: keeping the low half is the point, and the shift
// leaves the high half at 32 bits.
#[allow(clippy::cast_possible_truncation)]
#[must_use]
pub fn split_address(addr: u64) -> (u32, u32)
{
    (addr as u32, (addr >> 32) as u32)
}

/// Modern PCI transport backed by MMIO-mapped BAR regions.
///
/// The four register regions are reached through the driver's register
/// window, which maps every BAR they name as a [`RegisterLayout`] lays it
/// out; each region sits at its window offset, inside its own BAR's
/// mapping.
pub struct PciTransport
{
    /// Virtual address of the register window.
    window_va: u64,
    /// Window offsets of the common, notification, ISR, and device regions.
    common_off: u64,
    notify_off: u64,
    isr_off: u64,
    device_off: u64,
    /// Length of the notification region, which bounds every doorbell.
    notify_len: u64,
    /// Length of the device-specific configuration region, which bounds
    /// every read of it.
    device_len: u64,
    notify_off_multiplier: u32,
}

/// Byte offset of a queue's notification register from the start of the
/// notification capability region (`VirtIO` 1.2 §4.1.4.4).
///
/// `queue_notify_off` is the per-queue offset the device reports; scaling it
/// by `notify_off_multiplier` and adding the notification region's own
/// offset `notify_off` yields the doorbell's offset. Operands widen to `u64`
/// before the multiply, matching the address arithmetic in
/// [`PciTransport::notify`]. `None` when the offset does not fit a `u64`.
#[must_use]
pub fn notify_addr_offset(
    notify_off: u64,
    queue_notify_off: u16,
    notify_off_multiplier: u32,
) -> Option<u64>
{
    u64::from(queue_notify_off)
        .checked_mul(u64::from(notify_off_multiplier))
        .and_then(|scaled| notify_off.checked_add(scaled))
}

/// Whether a queue's 16-bit doorbell, `queue_notify_off` scaled by
/// `notify_off_multiplier` into the notification region, lies inside the
/// region's `notify_len` bytes, as `VirtIO` 1.2 §4.1.4.4 requires of the
/// device (`cap.length >= queue_notify_off * notify_off_multiplier + 2`).
/// In the multi-BAR register window a doorbell past the region could
/// otherwise reach another region or another BAR's mapping.
#[must_use]
pub fn doorbell_fits(queue_notify_off: u16, notify_off_multiplier: u32, notify_len: u64) -> bool
{
    u64::from(queue_notify_off)
        .checked_mul(u64::from(notify_off_multiplier))
        .and_then(|scaled| scaled.checked_add(2))
        .is_some_and(|end| end <= notify_len)
}

/// Whether a `width`-byte read at `offset` into the device-specific
/// configuration region lies inside the region's `device_len` bytes and is
/// naturally aligned there. In the multi-BAR register window a read past the
/// region could otherwise reach another region or another BAR's mapping.
#[must_use]
pub fn config_fits(offset: u32, width: u32, device_len: u64) -> bool
{
    offset.is_multiple_of(width)
        && u64::from(offset)
            .checked_add(u64::from(width))
            .is_some_and(|end| end <= device_len)
}

impl PciTransport
{
    /// Create a PCI transport over a register window mapped as `layout`
    /// lays it out.
    ///
    /// `window_va` is the virtual address of the window: the mapping of
    /// `layout`'s first BAR, followed by each later BAR's.
    #[must_use]
    pub fn new(window_va: u64, layout: &RegisterLayout) -> Self
    {
        Self {
            window_va,
            common_off: layout.common,
            notify_off: layout.notify,
            isr_off: layout.isr,
            device_off: layout.device,
            notify_len: layout.notify_len,
            device_len: layout.device_len,
            notify_off_multiplier: layout.notify_off_multiplier,
        }
    }

    // ── Common configuration registers (`VirtIO` 1.2 §4.1.4.3) ─────────

    /// Window address of the common-configuration register at `offset`.
    /// Every caller passes a register that ends within [`COMMON_CFG_LEN`],
    /// which [`RegisterLayout`] guarantees the common region holds.
    fn common_addr(&self, offset: u32) -> u64
    {
        debug_assert!(offset < COMMON_CFG_LEN);
        self.window_addr(self.common_off.wrapping_add(u64::from(offset)))
    }

    /// Virtual address of window offset `offset`. Wrapping: the window is
    /// mapped, so an offset inside it addresses no wrapped address, and a
    /// caller checks an offset that may lie outside before it dereferences
    /// the address.
    fn window_addr(&self, offset: u64) -> u64
    {
        self.window_va.wrapping_add(offset)
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
        // SAFETY: the common region is mapped and holds COMMON_CFG_LEN bytes
        // (RegisterLayout), so `device_status` (0x14) is within it.
        unsafe {
            core::ptr::read_volatile(self.common_addr(crate::COMMON_DEVICE_STATUS) as *const u8)
        }
    }

    /// Write device status.
    pub fn set_status(&self, status: u8)
    {
        // SAFETY: the common region is mapped and holds COMMON_CFG_LEN bytes
        // (RegisterLayout), so `device_status` (0x14) is within it.
        unsafe {
            core::ptr::write_volatile(
                self.common_addr(crate::COMMON_DEVICE_STATUS) as *mut u8,
                status,
            );
        }
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

    /// Whether the doorbell of a queue with `queue_notify_off` lies inside
    /// the notification region ([`doorbell_fits`]). A driver checks it once
    /// at queue setup and refuses the device otherwise; [`notify`](Self::notify)
    /// writes no doorbell that fails it.
    #[must_use]
    pub fn doorbell_in_region(&self, queue_notify_off: u16) -> bool
    {
        doorbell_fits(
            queue_notify_off,
            self.notify_off_multiplier,
            self.notify_len,
        )
    }

    /// Set the selected queue's descriptor table, available ring, and used
    /// ring device addresses, as `DMA_MAP` returned them. Each register pair
    /// takes its address in 32-bit halves ([`split_address`]).
    pub fn queue_set_rings(&self, desc: u64, avail: u64, used: u64)
    {
        for (low_offset, high_offset, addr) in
            [(0x20, 0x24, desc), (0x28, 0x2C, avail), (0x30, 0x34, used)]
        {
            let (low, high) = split_address(addr);
            self.write_common_u32(low_offset, low);
            self.write_common_u32(high_offset, high);
        }
    }

    /// Enable (1) or disable (0) the selected queue.
    pub fn queue_set_ready(&self, ready: u16)
    {
        self.write_common_u16(0x1C, ready);
    }

    // ── MSI-X vectors (`VirtIO` 1.2 § 4.1.5.1.2) ───────────────────────

    /// Route configuration-change events to MSI-X `vector`, or to none with
    /// [`NO_VECTOR`]. Returns whether the device took it: it reads back
    /// [`NO_VECTOR`] for a vector it cannot use (`VirtIO` 1.2 § 4.1.5.1.2).
    /// Meaningful only while MSI-X is enabled for the function.
    #[must_use]
    pub fn set_config_vector(&self, vector: u16) -> bool
    {
        self.write_common_u16(COMMON_CONFIG_MSIX_VECTOR, vector);
        self.read_common_u16(COMMON_CONFIG_MSIX_VECTOR) == vector
    }

    /// Route the selected queue's used-buffer events to MSI-X `vector`, or to
    /// none with [`NO_VECTOR`]; written before the queue is enabled. Returns
    /// whether the device took it, as [`set_config_vector`](Self::set_config_vector)
    /// does.
    #[must_use]
    pub fn queue_set_vector(&self, vector: u16) -> bool
    {
        self.write_common_u16(COMMON_QUEUE_MSIX_VECTOR, vector);
        self.read_common_u16(COMMON_QUEUE_MSIX_VECTOR) == vector
    }

    /// Route configuration-change events for a driver whose interrupt is
    /// `interrupt`: to no vector under MSI-X, since no driver waits on them;
    /// nothing to route for a wired line or none. Returns whether the device
    /// took the routing.
    #[must_use]
    pub fn route_config(&self, interrupt: Option<DeviceInterrupt>) -> bool
    {
        match interrupt
        {
            Some(DeviceInterrupt::MsiX { .. }) => self.set_config_vector(NO_VECTOR),
            Some(DeviceInterrupt::Wired { .. }) | None => true,
        }
    }

    /// Route the selected queue's used-buffer events to `interrupt`: to MSI-X
    /// vector 0, the driver's only vector, under MSI-X; nothing to route for
    /// a wired line or none. Written before the queue is enabled. Returns
    /// whether the device took the routing; while MSI-X is enabled a queue
    /// the device refuses a vector for signals no interrupt at all.
    #[must_use]
    pub fn route_queue(&self, interrupt: Option<DeviceInterrupt>) -> bool
    {
        match interrupt
        {
            Some(DeviceInterrupt::MsiX { .. }) => self.queue_set_vector(0),
            Some(DeviceInterrupt::Wired { .. }) | None => true,
        }
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
    ///
    /// A doorbell outside the notification region
    /// ([`doorbell_in_region`](Self::doorbell_in_region)) is not written.
    pub fn notify(&self, queue_idx: u16, queue_notify_off: u16)
    {
        if !self.doorbell_in_region(queue_notify_off)
        {
            return;
        }
        let Some(offset) = notify_addr_offset(
            self.notify_off,
            queue_notify_off,
            self.notify_off_multiplier,
        )
        else
        {
            return;
        };
        mmio::dma_to_mmio_barrier();

        let addr = self.window_addr(offset) as *mut u16;
        // SAFETY: the doorbell lies inside the notification region (checked
        // above), which is within its BAR's mapping; addr is naturally
        // aligned, since RegisterLayout holds the region's offset and the
        // multiplier 2-aligned (structure_usable) and the window maps the BAR
        // page-aligned.
        // cast_ptr_alignment: the doorbell is u16-aligned, as stated above.
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
        let addr = self.window_addr(self.isr_off) as *const u8;
        // SAFETY: ISR region is within its BAR's mapping.
        unsafe { core::ptr::read_volatile(addr) }
    }

    // ── Device-specific config (`VirtIO` 1.2 §4.1.4.6) ─────────────────

    /// Read a u32 from device-specific configuration space. `None` when the
    /// read does not lie inside the region or is not naturally aligned
    /// ([`config_fits`]), or its address is not 4-byte aligned in the window.
    #[must_use]
    pub fn config_read_u32(&self, offset: u32) -> Option<u32>
    {
        let addr = self.window_addr(self.device_off.wrapping_add(u64::from(offset)));
        if !config_fits(offset, 4, self.device_len) || !addr.is_multiple_of(4)
        {
            return None;
        }
        // cast_ptr_alignment: addr is checked 4-byte aligned above.
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: the four bytes lie inside the device cfg region (checked
        // above), which is within its BAR's mapping, and addr is 4-byte
        // aligned (checked above).
        let value = unsafe { core::ptr::read_volatile(addr as *const u32) };
        Some(value)
    }

    /// Read a u64 from device-specific configuration space, as two u32
    /// reads, low half first. `None` when either read is
    /// ([`config_read_u32`](Self::config_read_u32)).
    #[must_use]
    pub fn config_read_u64(&self, offset: u32) -> Option<u64>
    {
        let lo = self.config_read_u32(offset)?;
        let hi = self.config_read_u32(offset.checked_add(4)?)?;
        Some(u64::from(lo) | (u64::from(hi) << 32))
    }

    // ── Device negotiation (`VirtIO` 1.2 §3.1.1) ───────────────────────

    /// Reset the device (write 0 to status), polling the status register for
    /// at most [`RESET_TIMEOUT`] for the reset to complete. `elapsed` is the
    /// time since the call began, on the caller's monotonic clock (this
    /// crate is `no_std` and has none of its own).
    ///
    /// Returns `true` once the status reads 0. From then on the device sends
    /// no notifications and does not interact with the queues until the
    /// driver re-initialises it (`VirtIO` 1.2 §2.4.1), so a driver can use a
    /// `true` return to quiesce DMA it can no longer track. Returns `false`
    /// when the status never reads 0 within the bound: the device has not
    /// confirmed the reset and may still be accessing driver memory. The
    /// status is device-written, so the wait is bounded rather than trusted
    /// to end.
    #[must_use]
    pub fn try_reset(&self, elapsed: impl Fn() -> Duration) -> bool
    {
        self.set_status(0);
        poll_until(RESET_TIMEOUT, elapsed, || self.get_status() == 0)
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

        // cast_possible_truncation: the two `driver_feature_select` values take
        // the low and the high 32 feature bits, so keeping the low half is the
        // point, and the shift leaves the high half at 32 bits.
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
        // SAFETY: the common region is mapped and holds COMMON_CFG_LEN bytes
        // (RegisterLayout), past every register this file addresses in it;
        // each register sits at a multiple of its width from the region's
        // start, which RegisterLayout holds 4-aligned (structure_usable).
        // cast_ptr_alignment: as the SAFETY comment says, and the window maps
        // the BAR page-aligned.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::read_volatile(addr as *const u16)
        }
    }

    fn write_common_u16(&self, offset: u32, val: u16)
    {
        let addr = self.common_addr(offset);
        // SAFETY: the common region is mapped and holds COMMON_CFG_LEN bytes
        // (RegisterLayout), past every register this file addresses in it;
        // each register sits at a multiple of its width from the region's
        // start, which RegisterLayout holds 4-aligned (structure_usable).
        // cast_ptr_alignment: as the SAFETY comment says, and the window maps
        // the BAR page-aligned.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::write_volatile(addr as *mut u16, val);
        }
        mmio::mmio_to_mmio_barrier();
    }

    fn read_common_u32(&self, offset: u32) -> u32
    {
        let addr = self.common_addr(offset);
        // SAFETY: the common region is mapped and holds COMMON_CFG_LEN bytes
        // (RegisterLayout), past every register this file addresses in it;
        // each register sits at a multiple of its width from the region's
        // start, which RegisterLayout holds 4-aligned (structure_usable).
        // cast_ptr_alignment: as the SAFETY comment says, and the window maps
        // the BAR page-aligned.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::read_volatile(addr as *const u32)
        }
    }

    fn write_common_u32(&self, offset: u32, val: u32)
    {
        let addr = self.common_addr(offset);
        // SAFETY: the common region is mapped and holds COMMON_CFG_LEN bytes
        // (RegisterLayout), past every register this file addresses in it;
        // each register sits at a multiple of its width from the region's
        // start, which RegisterLayout holds 4-aligned (structure_usable).
        // cast_ptr_alignment: as the SAFETY comment says, and the window maps
        // the BAR page-aligned.
        #[allow(clippy::cast_ptr_alignment)]
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, val);
        }
        mmio::mmio_to_mmio_barrier();
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    use core::cell::Cell;

    #[test]
    fn split_address_gives_the_low_then_the_high_half()
    {
        // Distinct halves with their top bits set: a swapped pair, a
        // sign-extending or a dropped half reads back wrong.
        let (low, high) = split_address(0x8765_4321_89AB_CDEF);
        assert_eq!((low, high), (0x89AB_CDEF, 0x8765_4321));
        assert_eq!(
            u64::from(high) << 32 | u64::from(low),
            0x8765_4321_89AB_CDEF
        );
    }

    #[test]
    fn poll_until_gives_up_at_the_deadline_whatever_the_poll_count()
    {
        // A fake clock advancing 1 s per reading: the wait ends on time, not
        // after a fixed number of polls.
        let now = Cell::new(0u64);
        let elapsed = || {
            now.set(now.get() + 1);
            Duration::from_secs(now.get())
        };
        let polls = Cell::new(0u32);
        let held = poll_until(Duration::from_secs(5), elapsed, || {
            polls.set(polls.get() + 1);
            false
        });
        assert!(!held);
        // Five clock readings below the deadline each followed a poll, plus
        // the final probe after it.
        assert_eq!(polls.get(), 6);
    }

    #[test]
    fn poll_until_reports_a_condition_that_held_by_the_final_probe()
    {
        // The clock is past the deadline at its first reading (the thread
        // was descheduled), and the condition became true meanwhile.
        let polls = Cell::new(0u32);
        let held = poll_until(
            Duration::from_secs(5),
            || Duration::from_secs(60),
            || {
                polls.set(polls.get() + 1);
                polls.get() == 2
            },
        );
        assert!(held);
    }

    #[test]
    fn notify_addr_offset_scales_queue_offset_by_multiplier()
    {
        // notify_off + queue_notify_off * notify_off_multiplier, all in u64.
        assert_eq!(notify_addr_offset(0x3000, 2, 4), Some(0x3008));
    }

    #[test]
    fn notify_addr_offset_gates_queue_offset_when_multiplier_zero()
    {
        // A zero multiplier collapses every queue onto notify_off: the queue
        // term must be multiplied, not added.
        assert_eq!(notify_addr_offset(0x3000, 2, 0), Some(0x3000));
    }

    #[test]
    fn notify_addr_offset_past_u64_is_none()
    {
        // A region offset near the top of the window's range: the doorbell
        // offset would wrap to a low address.
        assert_eq!(notify_addr_offset(u64::MAX - 3, 2, 4), None);
        assert_eq!(notify_addr_offset(u64::MAX - 8, 2, 4), Some(u64::MAX));
    }

    #[test]
    fn notify_writes_only_a_doorbell_inside_the_notification_region()
    {
        let cap = |offset, length| crate::VirtioCapLocation {
            bar: 0,
            pad: [0; 3],
            offset,
            length,
        };
        let layout = crate::VirtioPciStartupInfo {
            common_cfg: cap(0, 0x38),
            notify_cfg: cap(0x800, 0x100),
            isr_cfg: cap(0x900, 4),
            device_cfg: cap(0xA00, 8),
            notify_off_multiplier: 4,
            pad: 0,
        }
        .register_layout()
        .expect("every region present");
        assert_eq!(layout.notify_len, 0x100);
        // A host buffer stands in for the one-page register window; the
        // barriers `notify` issues are no-ops on the host.
        let mut window = vec![0u16; 0x800];
        let transport = PciTransport::new(window.as_mut_ptr() as u64, &layout);

        // Queue offset 2: the doorbell is 0x800 + 2 * 4 = 0x808, inside.
        assert!(transport.doorbell_in_region(2));
        transport.notify(7, 2);
        assert_eq!(window[0x808 / 2], 7);

        // Queue offset 0x40: 0x40 * 4 = 0x100 is the region's end, so the
        // doorbell at 0x900 (the ISR region) is not written.
        assert!(!transport.doorbell_in_region(0x40));
        transport.notify(9, 0x40);
        assert_eq!(window[0x900 / 2], 0);
        assert_eq!(window.iter().filter(|&&w| w != 0).count(), 1);
    }

    #[test]
    fn vectors_are_written_to_their_common_registers_and_read_back()
    {
        let cap = |offset, length| crate::VirtioCapLocation {
            bar: 0,
            pad: [0; 3],
            offset,
            length,
        };
        let layout = crate::VirtioPciStartupInfo {
            common_cfg: cap(0x100, 0x38),
            notify_cfg: cap(0x800, 0x100),
            isr_cfg: cap(0x900, 4),
            device_cfg: cap(0xA00, 8),
            notify_off_multiplier: 4,
            pad: 0,
        }
        .register_layout()
        .expect("every region present");
        // A host buffer stands in for the register window: it keeps what is
        // written, as a device that takes the vector does.
        let mut window = vec![0u16; 0x800];
        let transport = PciTransport::new(window.as_mut_ptr() as u64, &layout);
        assert!(transport.set_config_vector(NO_VECTOR));
        assert!(transport.queue_set_vector(0));
        assert_eq!(window[(0x100 + 0x10) / 2], NO_VECTOR);
        assert_eq!(window[(0x100 + 0x1A) / 2], 0);
        assert!(transport.queue_set_vector(3));
        assert_eq!(window[(0x100 + 0x1A) / 2], 3);

        // Routing writes only under MSI-X: vector 0 for the queue, none for
        // configuration changes.
        let wired = Some(DeviceInterrupt::Wired { cap: 1, mode: 0 });
        assert!(transport.route_queue(wired) && transport.route_queue(None));
        assert!(transport.route_config(wired) && transport.route_config(None));
        assert_eq!(window[(0x100 + 0x1A) / 2], 3);
        window[(0x100 + 0x10) / 2] = 0;
        let msix = Some(DeviceInterrupt::MsiX { cap: 2 });
        assert!(transport.route_queue(msix) && transport.route_config(msix));
        assert_eq!(window[(0x100 + 0x1A) / 2], 0);
        assert_eq!(window[(0x100 + 0x10) / 2], NO_VECTOR);
    }

    #[test]
    fn a_config_read_fits_only_aligned_and_inside_the_region()
    {
        // The last u32 of an 8-byte region fits; one past it does not.
        assert!(config_fits(4, 4, 8));
        assert!(!config_fits(8, 4, 8));
        // Unaligned, though inside.
        assert!(!config_fits(2, 4, 8));
        // An offset near u32::MAX does not wrap into the region.
        assert!(!config_fits(u32::MAX - 3, 4, 8));
    }

    #[test]
    fn config_reads_return_nothing_past_the_device_region()
    {
        let cap = |offset, length| crate::VirtioCapLocation {
            bar: 0,
            pad: [0; 3],
            offset,
            length,
        };
        let layout = crate::VirtioPciStartupInfo {
            common_cfg: cap(0, 0x38),
            notify_cfg: cap(0x800, 0x100),
            isr_cfg: cap(0x900, 4),
            device_cfg: cap(0xA00, 12),
            notify_off_multiplier: 4,
            pad: 0,
        }
        .register_layout()
        .expect("every region present");
        // A host buffer stands in for the one-page register window, with
        // the device region's 12 bytes, and the word after them, filled.
        let mut window = vec![0u32; 0x400];
        window[0xA00 / 4..0xA00 / 4 + 4].copy_from_slice(&[1, 2, 3, 0xDEAD]);
        let transport = PciTransport::new(window.as_mut_ptr() as u64, &layout);

        assert_eq!(transport.config_read_u32(8), Some(3));
        assert_eq!(transport.config_read_u32(12), None);
        assert_eq!(transport.config_read_u32(2), None);
        assert_eq!(transport.config_read_u64(0), Some(2 << 32 | 1));
        // The high half would be the word past the region.
        assert_eq!(transport.config_read_u64(8), None);
    }

    #[test]
    fn a_doorbell_fits_only_with_its_two_bytes_inside_the_region()
    {
        // 0x3FF * 4 = 0xFFC: the 16-bit doorbell ends at 0xFFE, inside.
        assert!(doorbell_fits(0x3FF, 4, 0x1000));
        // 0x400 * 4 = 0x1000: the doorbell starts at the region's end.
        assert!(!doorbell_fits(0x400, 4, 0x1000));
        // A zero multiplier puts every doorbell at the region's start.
        assert!(doorbell_fits(0xFFFF, 0, 2));
        assert!(!doorbell_fits(0, 4, 1));
    }
}
