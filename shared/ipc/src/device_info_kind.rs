// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/device_info_kind.rs

//! Device-info kind discriminants for [`devmgr_labels::QUERY_DEVICE_INFO`](crate::devmgr_labels::QUERY_DEVICE_INFO)
//! replies. Each driver class owns a fixed value; devmgr stores payload
//! bytes against this discriminant in its `DeviceCatalog` and replies
//! with the discriminant as `word[0]` so callers can verify the type
//! before deserialising.

/// `VirtIO` PCI device startup info
/// (`virtio_core::VirtioPciStartupInfo`).
pub const VIRTIO_PCI: u32 = 1;
/// Linear framebuffer geometry (`boot_protocol::FramebufferInfo`).
pub const FRAMEBUFFER: u32 = 2;
/// The CMOS RAM index of a CMOS RTC's century register, from the FADT's
/// `CENTURY` field: a one-byte payload. Absent when the FADT names none.
pub const RTC_CENTURY: u32 = 3;
/// Schema version of the [`RTC_CENTURY`] payload.
pub const RTC_CENTURY_VERSION: u32 = 1;
