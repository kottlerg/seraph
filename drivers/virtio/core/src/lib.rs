// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// drivers/virtio/core/src/lib.rs

//! `VirtIO` transport and virtqueue primitives shared by all `VirtIO` drivers.
//!
//! Provides the modern PCI transport, virtqueue management, device negotiation,
//! and the startup message format used by devmgr to pass PCI capability info
//! to `VirtIO` drivers.

#![no_std]

pub mod pci;
pub mod virtqueue;

// ── Device status bits (VirtIO 1.2 §2.1) ───────────────────────────────────

pub const STATUS_ACKNOWLEDGE: u8 = 1;
pub const STATUS_DRIVER: u8 = 2;
pub const STATUS_DRIVER_OK: u8 = 4;
pub const STATUS_FEATURES_OK: u8 = 8;
pub const STATUS_DEVICE_NEEDS_RESET: u8 = 64;
pub const STATUS_FAILED: u8 = 128;

// ── PCI capability info (startup message format) ────────────────────────────

/// `VirtIO` PCI capability location within a BAR.
///
/// Serialised into the driver's startup message by devmgr. The driver
/// deserialises it to locate `VirtIO` register regions within mapped BARs.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioCapLocation
{
    /// PCI BAR index (0-5) containing this capability's registers.
    pub bar: u8,
    /// Padding for alignment.
    pub pad: [u8; 3],
    /// Byte offset within the BAR.
    pub offset: u32,
    /// Length in bytes.
    pub length: u32,
}

/// Startup message written by devmgr for `VirtIO` PCI drivers.
///
/// Contains the locations of the four `VirtIO` PCI capability regions
/// and the notification offset multiplier. devmgr discovers these by
/// walking the PCI capability list during enumeration.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioPciStartupInfo
{
    /// Common configuration (type 1).
    pub common_cfg: VirtioCapLocation,
    /// Notification structure (type 2).
    pub notify_cfg: VirtioCapLocation,
    /// ISR status (type 3).
    pub isr_cfg: VirtioCapLocation,
    /// Device-specific configuration (type 4).
    pub device_cfg: VirtioCapLocation,
    /// Multiplier for queue-specific notification offsets.
    pub notify_off_multiplier: u32,
    /// Padding for alignment.
    pub pad: u32,
}

impl VirtioPciStartupInfo
{
    /// Size of the serialised startup message in bytes.
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// Deserialise from a byte slice (startup message).
    ///
    /// Returns `None` if the slice is too short.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self>
    {
        if bytes.len() < Self::SIZE
        {
            return None;
        }
        // SAFETY: VirtioPciStartupInfo is repr(C) with no padding invariants;
        // any bit pattern is valid. Slice length is checked above.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr().cast::<Self>()) })
    }

    /// Serialise to a byte buffer. Returns `None` if the buffer is too small.
    #[must_use]
    pub fn to_bytes(&self, buf: &mut [u8]) -> Option<()>
    {
        if buf.len() < Self::SIZE
        {
            return None;
        }
        // SAFETY: buf has sufficient length; Self is repr(C) POD.
        unsafe {
            core::ptr::copy_nonoverlapping(
                core::ptr::from_ref(self).cast::<u8>(),
                buf.as_mut_ptr(),
                Self::SIZE,
            );
        }
        Some(())
    }

    /// Number of IPC data words needed to hold the serialised form (7 words).
    pub const IPC_WORD_COUNT: usize = 7;

    /// Pack the startup info into 7 `u64` data words for an `IpcMessage`.
    ///
    /// Layout: 2 words per cap location (bar|offset in lo, length in hi),
    /// except the last cap shares its hi word with `notify_off_multiplier`.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_words(&self) -> [u64; Self::IPC_WORD_COUNT]
    {
        let mut out = [0u64; Self::IPC_WORD_COUNT];
        let caps = [
            &self.common_cfg,
            &self.notify_cfg,
            &self.isr_cfg,
            &self.device_cfg,
        ];
        for (i, cap) in caps.iter().enumerate()
        {
            out[i * 2] = u64::from(cap.bar) | (u64::from(cap.offset) << 32);
            if i < 3
            {
                out[i * 2 + 1] = u64::from(cap.length);
            }
        }
        // Word 6: device_cfg.length | (notify_off_multiplier << 32).
        out[6] = u64::from(self.device_cfg.length) | (u64::from(self.notify_off_multiplier) << 32);
        out
    }

    /// Unpack the startup info from 7 `u64` data words delivered over IPC.
    ///
    /// If `words` has fewer than [`Self::IPC_WORD_COUNT`] entries the
    /// remaining fields are read as zero.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_words(words: &[u64]) -> Self
    {
        let mut info = Self::default();
        let read = |i: usize| -> u64 { words.get(i).copied().unwrap_or(0) };

        let caps = [
            &mut info.common_cfg,
            &mut info.notify_cfg,
            &mut info.isr_cfg,
            &mut info.device_cfg,
        ];
        for (i, cap) in caps.into_iter().enumerate()
        {
            let lo = read(i * 2);
            cap.bar = lo as u8;
            cap.offset = (lo >> 32) as u32;
            if i < 3
            {
                let hi = read(i * 2 + 1);
                cap.length = hi as u32;
            }
        }
        // Word 6: device_cfg.length | (notify_off_multiplier << 32).
        let last = read(6);
        info.device_cfg.length = last as u32;
        info.notify_off_multiplier = (last >> 32) as u32;

        info
    }
}

// ── VirtIO PCI capability types (VirtIO 1.2 §4.1.4) ────────────────────────

/// Common configuration capability type.
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Notification capability type.
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// ISR status capability type.
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Device-specific configuration capability type.
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
