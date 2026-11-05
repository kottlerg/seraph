// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/dma.rs

//! devmgr's DMA endpoint: the DMA capability of each DMA-capable device's
//! driver, and the thread that serves it.
//!
//! [`DmaService::start`] creates the endpoint and the thread that receives
//! on it. For each DMA-capable device devmgr carves, [`DmaService::grant`]
//! registers the device in the shared [`DmaTable`] with its confinement and
//! derives a SEND on the endpoint badged with the device's badge, which
//! devmgr keeps and from which it derives the driver's copy
//! (`virtio_core::bootstrap::SLOT_DMA`). The thread serves `DMA_MAP` and
//! `DMA_UNMAP` (`ipc::devmgr_dma_labels`) on its own, at the boot drivers'
//! level (`BOOT_DRIVER_PRIORITY`, above devmgr's), so a driver's mapping never
//! waits for the registry loop: that loop makes nested calls (a
//! `CREATE_FROM_FILE` reads the driver binary through virtio-blk, which maps
//! the read's buffer) and settles a batch whose drivers map their rings
//! before they report ready.
//!
//! A device the IOMMU confines gets an IOVA from its own IOVA space for each
//! mapping, and the thread has the IOMMU driver install the mapping (`MAP`,
//! with a derivation of the carried Memory cap) before it replies, and
//! withdraw it (`UNMAP`) before it deletes the cap; an unconfined device's
//! device address is its frames' physical address. The table is shared with
//! the registry loop, which withdraws a device's grant
//! ([`DmaGrant::withdraw`], which blocks a confined device in the IOMMU);
//! either thread holds its lock only around table operations, never across
//! IPC, and a mapping is pending in the table while its IOMMU call is in
//! flight, so a withdrawal meanwhile neither races the commit nor deletes the
//! cap the call carries. See `docs/device-management.md` § DMA Authorisation.

use std::os::seraph::thread::BuilderExt;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use firmware::dma::{Confinement, DmaTable, MapError, Mapping, UnmapError, check_access};
use ipc::recv_guard::RecvGuard;
use ipc::{IpcMessage, devmgr_dma_errors, devmgr_dma_labels, iommu_errors};

use crate::iommu::IommuClient;

/// The shared table, locked. A poisoned lock means the other thread panicked
/// mid-operation; every table operation leaves the table consistent before it
/// can panic, so the table is used as it stands.
fn lock(table: &Mutex<DmaTable>) -> MutexGuard<'_, DmaTable>
{
    table.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the DMA thread and the grants share: the table and, once the IOMMU
/// driver reports ready, the client it is called through.
struct Shared
{
    table: Mutex<DmaTable>,
    iommu: OnceLock<Arc<IommuClient>>,
}

/// devmgr's DMA endpoint, its serving thread, and the state it shares with
/// that thread.
pub struct DmaService
{
    ep: u64,
    shared: Arc<Shared>,
}

impl DmaService
{
    /// Create the DMA endpoint and start the thread that serves it. `None`,
    /// logged, when the endpoint or the thread cannot be created.
    pub fn start() -> Option<Self>
    {
        let Some(ep) = crate::create_service_endpoint()
        else
        {
            std::os::seraph::log!("DMA endpoint not created");
            return None;
        };
        let shared = Arc::new(Shared {
            table: Mutex::new(DmaTable::new()),
            iommu: OnceLock::new(),
        });
        let served = Arc::clone(&shared);
        // At the boot drivers' level, above devmgr's own: virtio-blk, the
        // root-disk path, blocks on this thread twice per transfer, so a
        // thread below it would let any runnable thread between the two
        // levels delay that path (`ipc::sched_policy`).
        if std::thread::Builder::new()
            .name("dma".into())
            .spawn_at_priority(ipc::sched_policy::BOOT_DRIVER_PRIORITY, move || {
                serve(ep, &served);
            })
            .is_err()
        {
            std::os::seraph::log!("DMA thread not started");
            let _ = syscall::cap_delete(ep);
            return None;
        }
        Some(Self { ep, shared })
    }

    /// Route every confined device's mappings through the IOMMU driver
    /// `client` from now on. Set once, before the first confined grant.
    pub fn set_iommu(&self, client: Arc<IommuClient>)
    {
        let _ = self.shared.iommu.set(client);
    }

    /// Give the device `device_badge` DMA with `confinement`: register it in
    /// the table and derive its DMA capability, a SEND on the DMA endpoint
    /// badged `device_badge`, which the returned grant keeps. `None`, logged,
    /// when the table cannot grow or the derivation fails; nothing is
    /// registered then.
    pub fn grant(&self, device_badge: u64, confinement: Confinement) -> Option<DmaGrant>
    {
        if lock(&self.shared.table)
            .register(device_badge, confinement)
            .is_err()
        {
            std::os::seraph::log!("DMA table full; device {} not given DMA", device_badge);
            return None;
        }
        let Ok(cap) =
            syscall::cap_derive_badge(self.ep, syscall::RIGHTS_EP_SEND_GRANT, device_badge)
        else
        {
            std::os::seraph::log!("DMA capability not derived for device {}", device_badge);
            lock(&self.shared.table).withdraw(device_badge);
            return None;
        };
        Some(DmaGrant {
            cap,
            device_badge,
            confined: confinement != Confinement::Unconfined,
            shared: Arc::clone(&self.shared),
        })
    }
}

/// One device's DMA capability, kept by devmgr, and its place in the table.
pub struct DmaGrant
{
    cap: u64,
    device_badge: u64,
    confined: bool,
    shared: Arc<Shared>,
}

impl DmaGrant
{
    /// devmgr's copy of the device's DMA capability, from which it derives
    /// the driver's.
    pub fn cap(&self) -> u64
    {
        self.cap
    }

    /// Whether the IOMMU confines the device.
    pub fn confined(&self) -> bool
    {
        self.confined
    }

    /// Withdraw the device's DMA: revoke every copy of its DMA capability
    /// derived from devmgr's (the driver's), remove the device and its
    /// mappings from the table, so a request already queued is refused,
    /// block a confined device in the IOMMU (`BLOCK`), and then delete the
    /// Memory cap kept for each standing mapping. A second withdrawal finds
    /// nothing. Returns whether the IOMMU now blocks the device's DMA, which
    /// lets its driver's frames be released without the device confirmed
    /// quiet (`docs/device-management.md` § DMA-Safe Teardown): `false` for
    /// an unconfined device, one already withdrawn, and one whose block the
    /// IOMMU driver did not complete.
    pub fn withdraw(&self) -> bool
    {
        if syscall::cap_revoke_all(self.cap).is_err()
        {
            std::os::seraph::log!(
                "DMA capability of device {} not fully revoked",
                self.device_badge
            );
        }
        let Some(withdrawn) = lock(&self.shared.table).withdraw(self.device_badge)
        else
        {
            return false;
        };
        let blocked = match (withdrawn.confinement, self.shared.iommu.get())
        {
            (Confinement::Domain { handle, .. }, Some(client)) => client.block(handle),
            _ => false,
        };
        if self.confined && !blocked
        {
            std::os::seraph::log!("device {} not blocked in the IOMMU", self.device_badge);
        }
        release_mappings(withdrawn.mappings);
        blocked
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
/// request against `shared`.
fn serve(ep: u64, shared: &Shared)
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
            devmgr_dma_labels::DMA_MAP => handle_map(&msg, shared, ipc_buf),
            devmgr_dma_labels::DMA_UNMAP =>
            {
                release_caps(msg.caps());
                let code = if msg.word(0) == u64::from(ipc::DEVMGR_DMA_LABELS_VERSION)
                {
                    unmap(shared, msg.badge, msg.word(1))
                }
                else
                {
                    devmgr_dma_errors::LABEL_VERSION_MISMATCH
                };
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

/// Serve a `DMA_MAP`: map the carried Memory cap, which devmgr keeps while
/// the mapping stands, and reply its device address. A refused request
/// deletes the cap; a reply the caller cannot take undoes the mapping and
/// deletes it too.
fn handle_map(msg: &IpcMessage, shared: &Shared, ipc_buf: *mut u64)
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
    let device_addr = match map(msg, cap, shared)
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
        let _ = unmap(shared, msg.badge, device_addr);
    }
}

/// Check a `DMA_MAP` of `cap`, reserve its device address, have the IOMMU
/// driver install it for a confined device, and commit it; the device
/// address of its first byte, or the `devmgr_dma_errors` code to reply.
fn map(msg: &IpcMessage, cap: u64, shared: &Shared) -> Result<u64, u64>
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
    let confinement = lock(&shared.table)
        .confinement(msg.badge)
        .ok_or(devmgr_dma_errors::UNAUTHORIZED)?;
    let handle = match confinement
    {
        Confinement::Domain { handle, .. } => Some(handle),
        Confinement::Unconfined => None,
    };
    // Unconfined: with no IOMMU between the device and memory, the device
    // reaches the frames only at their physical address. A confined device's
    // address is an IOVA, and devmgr reads no physical address for it.
    let phys = if handle.is_none()
    {
        Some(syscall::cap_info(cap, syscall::CAP_INFO_MEMORY_PHYS_BASE).map_err(|_| invalid)?)
    }
    else
    {
        None
    };
    let mapping = lock(&shared.table)
        .reserve(msg.badge, cap, len, access, phys)
        .map_err(map_error_code)?;
    if let Some(handle) = handle
        && let Err(code) = install(shared, handle, &mapping)
    {
        lock(&shared.table).abort(msg.badge, mapping.device_addr);
        return Err(code);
    }
    if !lock(&shared.table).commit(msg.badge, mapping.device_addr)
    {
        // Withdrawn while the IOMMU call was in flight; the withdrawal's
        // BLOCK removed whatever the call installed.
        return Err(devmgr_dma_errors::UNAUTHORIZED);
    }
    Ok(mapping.device_addr)
}

/// Have the IOMMU driver install `mapping` in the domain `handle`, moving it
/// a derivation of the mapping's cap; the `devmgr_dma_errors` code when it
/// does not.
fn install(shared: &Shared, handle: u64, mapping: &Mapping) -> Result<(), u64>
{
    let Some(client) = shared.iommu.get()
    else
    {
        return Err(devmgr_dma_errors::IOMMU_FAILED);
    };
    let Ok(copy) = syscall::cap_derive(mapping.cap, syscall::RIGHTS_ALL)
    else
    {
        return Err(devmgr_dma_errors::OUT_OF_RESOURCES);
    };
    client
        .map(handle, mapping.device_addr, mapping.access, copy)
        .map_err(|code| match code
        {
            iommu_errors::OUT_OF_RESOURCES => devmgr_dma_errors::OUT_OF_RESOURCES,
            _ => devmgr_dma_errors::IOMMU_FAILED,
        })
}

/// Withdraw the device `badge`'s standing mapping at `device_addr`: have the
/// IOMMU driver remove it for a confined device, then delete devmgr's cap;
/// the `devmgr_dma_errors` code to reply. A failed IOMMU `UNMAP` leaves the
/// mapping standing.
fn unmap(shared: &Shared, badge: u64, device_addr: u64) -> u64
{
    let begun = lock(&shared.table).begin_unmap(badge, device_addr);
    let (mapping, confinement) = match begun
    {
        Ok(found) => found,
        Err(UnmapError::UnknownDevice) => return devmgr_dma_errors::UNAUTHORIZED,
        Err(UnmapError::NoMapping) => return devmgr_dma_errors::NO_MAPPING,
    };
    if let Confinement::Domain { handle, .. } = confinement
    {
        let removed = shared
            .iommu
            .get()
            .is_some_and(|c| c.unmap(handle, device_addr).is_ok());
        if !removed
        {
            if !lock(&shared.table).restore(badge, device_addr)
            {
                // Withdrawn meanwhile: its BLOCK withdrew every range, and
                // the cap the table no longer holds is this thread's.
                let _ = syscall::cap_delete(mapping.cap);
            }
            return devmgr_dma_errors::IOMMU_FAILED;
        }
    }
    lock(&shared.table).finish_unmap(badge, device_addr);
    let _ = syscall::cap_delete(mapping.cap);
    devmgr_dma_errors::SUCCESS
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
        MapError::NoAddressSpace | MapError::OutOfMemory => devmgr_dma_errors::OUT_OF_RESOURCES,
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
