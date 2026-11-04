// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/dma.rs

//! devmgr's DMA endpoint: the DMA capability of each DMA-capable device's
//! driver, and the thread that serves it.
//!
//! [`DmaService::start`] creates the endpoint and the thread that receives
//! on it. For each DMA-capable device devmgr carves, [`DmaService::grant`]
//! registers the device in the shared [`DmaTable`] and derives a SEND on the
//! endpoint badged with the device's badge, which devmgr keeps and from
//! which it derives the driver's copy (`virtio_core::bootstrap::SLOT_DMA`).
//! The thread serves `DMA_MAP` and `DMA_UNMAP` (`ipc::devmgr_dma_labels`) on
//! its own, so a driver's mapping never waits for the registry loop: that
//! loop makes nested calls (a `CREATE_FROM_FILE` reads the driver binary
//! through virtio-blk, which maps the read's buffer) and settles a batch
//! whose drivers map their rings before they report ready.
//!
//! No IOMMU is programmed: every device is unconfined, and the device address
//! a mapping returns is its frames' physical address. The table is shared
//! with the registry loop, which withdraws a device's grant
//! ([`DmaGrant::withdraw`]); either thread holds its lock only around table
//! operations, never across IPC. See `docs/device-management.md`
//! § DMA Authorisation.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use firmware::dma::{DmaTable, MapError, Mapping, UnmapError, check_access};
use ipc::recv_guard::RecvGuard;
use ipc::{IpcMessage, devmgr_dma_errors, devmgr_dma_labels};

/// The shared table, locked. A poisoned lock means the other thread panicked
/// mid-operation; every table operation leaves the table consistent before it
/// can panic, so the table is used as it stands.
fn lock(table: &Mutex<DmaTable>) -> MutexGuard<'_, DmaTable>
{
    table.lock().unwrap_or_else(PoisonError::into_inner)
}

/// devmgr's DMA endpoint, its serving thread, and the table it shares with
/// that thread.
pub struct DmaService
{
    ep: u64,
    table: Arc<Mutex<DmaTable>>,
}

impl DmaService
{
    /// Create the DMA endpoint and start the thread that serves it. Logs
    /// that DMA runs unconfined, since no IOMMU is programmed. `None`, logged,
    /// when the endpoint or the thread cannot be created.
    pub fn start() -> Option<Self>
    {
        let Some(ep) = crate::create_service_endpoint()
        else
        {
            std::os::seraph::log!("DMA endpoint not created");
            return None;
        };
        let table = Arc::new(Mutex::new(DmaTable::new()));
        let served = Arc::clone(&table);
        if std::thread::Builder::new()
            .name("dma".into())
            .spawn(move || serve(ep, &served))
            .is_err()
        {
            std::os::seraph::log!("DMA thread not started");
            let _ = syscall::cap_delete(ep);
            return None;
        }
        std::os::seraph::log!("no IOMMU programmed: DMA-capable devices run unconfined");
        Some(Self { ep, table })
    }

    /// Give the device `device_badge` DMA: register it in the table and
    /// derive its DMA capability, a SEND on the DMA endpoint badged
    /// `device_badge`, which the returned grant keeps. `None`, logged, when
    /// the table cannot grow or the derivation fails; nothing is registered
    /// then.
    pub fn grant(&self, device_badge: u64) -> Option<DmaGrant>
    {
        if lock(&self.table).register(device_badge).is_err()
        {
            std::os::seraph::log!("DMA table full; device {} not given DMA", device_badge);
            return None;
        }
        let Ok(cap) =
            syscall::cap_derive_badge(self.ep, syscall::RIGHTS_EP_SEND_GRANT, device_badge)
        else
        {
            std::os::seraph::log!("DMA capability not derived for device {}", device_badge);
            lock(&self.table).withdraw(device_badge);
            return None;
        };
        Some(DmaGrant {
            cap,
            device_badge,
            table: Arc::clone(&self.table),
        })
    }
}

/// One device's DMA capability, kept by devmgr, and its place in the table.
pub struct DmaGrant
{
    cap: u64,
    device_badge: u64,
    table: Arc<Mutex<DmaTable>>,
}

impl DmaGrant
{
    /// devmgr's copy of the device's DMA capability, from which it derives
    /// the driver's.
    pub fn cap(&self) -> u64
    {
        self.cap
    }

    /// Withdraw the device's DMA: revoke every copy of its DMA capability
    /// derived from devmgr's (the driver's), and remove the device and its
    /// mappings from the table, deleting the Memory cap kept for each, so a
    /// request already queued is refused. A second withdrawal finds nothing.
    /// Returns whether an IOMMU now blocks the device's DMA, which lets its
    /// driver's frames be released without the device confirmed quiet
    /// (`docs/device-management.md` § DMA-Safe Teardown). Always `false`: no
    /// IOMMU is programmed, so a withdrawn device can still reach every
    /// frame it was given.
    pub fn withdraw(&self) -> bool
    {
        let _ = syscall::cap_revoke(self.cap);
        let held = lock(&self.table).withdraw(self.device_badge);
        release_mappings(held.into_iter().flatten());
        false
    }

    /// Withdraw the device's DMA ([`Self::withdraw`]) and delete devmgr's copy
    /// of its capability.
    pub fn release(&self)
    {
        self.withdraw();
        let _ = syscall::cap_delete(self.cap);
    }
}

/// The DMA thread: receive on `ep` for the rest of the boot and serve each
/// request against `table`.
fn serve(ep: u64, table: &Mutex<DmaTable>)
{
    let ipc_buf = std::os::seraph::current_ipc_buf();
    if ipc_buf.is_null()
    {
        std::os::seraph::log!("DMA thread has no IPC buffer; DMA requests go unserved");
        return;
    }
    let mut guard = RecvGuard::new(crate::recv_diag);
    loop
    {
        // SAFETY: ipc_buf is this thread's registered IPC buffer.
        let msg = match unsafe { ipc::ipc_recv(ep, ipc_buf) }
        {
            Ok(msg) => msg,
            Err(e) =>
            {
                guard.on_failure(e);
                continue;
            }
        };
        guard.on_success();
        match msg.label
        {
            devmgr_dma_labels::DMA_MAP => handle_map(&msg, table, ipc_buf),
            devmgr_dma_labels::DMA_UNMAP =>
            {
                release_caps(msg.caps());
                let code = unmap(&msg, table);
                reply(&IpcMessage::new(code), ipc_buf);
            }
            _ =>
            {
                release_caps(msg.caps());
                reply(&IpcMessage::new(devmgr_dma_errors::UNKNOWN_OPCODE), ipc_buf);
            }
        }
    }
}

/// Serve a `DMA_MAP`: record the mapping of the carried Memory cap, which
/// devmgr keeps while the mapping stands, and reply its device address. A
/// refused request deletes the cap; a reply the caller cannot take undoes the
/// mapping and deletes it too.
fn handle_map(msg: &IpcMessage, table: &Mutex<DmaTable>, ipc_buf: *mut u64)
{
    let Some((&cap, extra)) = msg.caps().split_first()
    else
    {
        reply(
            &IpcMessage::new(devmgr_dma_errors::INVALID_REQUEST),
            ipc_buf,
        );
        return;
    };
    release_caps(extra);
    let device_addr = match map(msg, cap, table)
    {
        Ok(device_addr) => device_addr,
        Err(code) =>
        {
            let _ = syscall::cap_delete(cap);
            reply(&IpcMessage::new(code), ipc_buf);
            return;
        }
    };
    let reply_msg = IpcMessage::builder(devmgr_dma_errors::SUCCESS)
        .word(0, device_addr)
        .build();
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply_msg, ipc_buf) }.is_err()
    {
        release_mappings(lock(table).unmap(msg.badge, device_addr).ok());
    }
}

/// Check a `DMA_MAP` of `cap` and record its mapping; the device address of
/// its first byte, or the `devmgr_dma_errors` code to reply.
fn map(msg: &IpcMessage, cap: u64, table: &Mutex<DmaTable>) -> Result<u64, u64>
{
    if msg.word(0) != u64::from(ipc::DEVMGR_DMA_LABELS_VERSION)
    {
        return Err(devmgr_dma_errors::LABEL_VERSION_MISMATCH);
    }
    let invalid = devmgr_dma_errors::INVALID_REQUEST;
    let access = msg.word(1);
    let tag_rights = syscall::cap_info(cap, syscall::CAP_INFO_TAG_RIGHTS).map_err(|_| invalid)?;
    // CAP_INFO_TAG_RIGHTS packs the tag above bit 32 and the rights below it.
    if tag_rights >> 32 != u64::from(syscall::CAP_TAG_MEMORY)
    {
        return Err(invalid);
    }
    check_access(access, tag_rights & 0xFFFF_FFFF).map_err(map_error_code)?;
    let len = syscall::cap_info(cap, syscall::CAP_INFO_MEMORY_SIZE).map_err(|_| invalid)?;
    let phys = syscall::cap_info(cap, syscall::CAP_INFO_MEMORY_PHYS_BASE).map_err(|_| invalid)?;
    // Unconfined: with no IOMMU between the device and memory, the device
    // reaches the frames only at their physical address.
    let device_addr = phys;
    lock(table)
        .map(
            msg.badge,
            Mapping {
                cap,
                device_addr,
                phys,
                len,
                access,
            },
        )
        .map_err(map_error_code)?;
    Ok(device_addr)
}

/// Serve a `DMA_UNMAP`; the `devmgr_dma_errors` code to reply.
fn unmap(msg: &IpcMessage, table: &Mutex<DmaTable>) -> u64
{
    if msg.word(0) != u64::from(ipc::DEVMGR_DMA_LABELS_VERSION)
    {
        return devmgr_dma_errors::LABEL_VERSION_MISMATCH;
    }
    let removed = lock(table).unmap(msg.badge, msg.word(1));
    match removed
    {
        Ok(mapping) =>
        {
            release_mappings(Some(mapping));
            devmgr_dma_errors::SUCCESS
        }
        Err(UnmapError::UnknownDevice) => devmgr_dma_errors::UNAUTHORIZED,
        Err(UnmapError::NoMapping) => devmgr_dma_errors::NO_MAPPING,
    }
}

/// Delete the Memory cap devmgr kept for each removed mapping. Called with
/// the table unlocked.
fn release_mappings(mappings: impl IntoIterator<Item = Mapping>)
{
    for m in mappings
    {
        let _ = syscall::cap_delete(m.cap);
    }
}

/// The `devmgr_dma_errors` code a refused mapping replies.
fn map_error_code(e: MapError) -> u64
{
    match e
    {
        MapError::UnknownDevice => devmgr_dma_errors::UNAUTHORIZED,
        MapError::InvalidRequest | MapError::InsufficientRights =>
        {
            devmgr_dma_errors::INVALID_REQUEST
        }
        MapError::TooMany => devmgr_dma_errors::TOO_MANY_MAPPINGS,
        MapError::AddressInUse => devmgr_dma_errors::ADDRESS_IN_USE,
        MapError::OutOfMemory => devmgr_dma_errors::OUT_OF_RESOURCES,
    }
}

/// Delete caps a request carried that the label does not take.
fn release_caps(caps: &[u64])
{
    for &c in caps
    {
        let _ = syscall::cap_delete(c);
    }
}

/// Reply `msg` on the current request; a reply the caller cannot take needs
/// no further action, since it moves no cap.
fn reply(msg: &IpcMessage, ipc_buf: *mut u64)
{
    // SAFETY: ipc_buf is this thread's registered IPC buffer.
    let _ = unsafe { ipc::ipc_reply(msg, ipc_buf) };
}
