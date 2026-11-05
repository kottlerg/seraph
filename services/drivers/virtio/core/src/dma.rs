// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/drivers/virtio/core/src/dma.rs

//! Driver-side mapping of a Memory cap's frames for the driver's device,
//! through the device's DMA capability (`bootstrap::SLOT_DMA`).
//!
//! A driver programs its device only with the device addresses these calls
//! return, never with a physical address: devmgr chooses the address
//! (`docs/device-management.md` § DMA Authorisation).

use ipc::devmgr_dma_labels::{ACCESS_DEVICE_READ, ACCESS_DEVICE_WRITE};

/// The device reads the frames and never writes them.
pub const DEVICE_READS: u64 = ACCESS_DEVICE_READ;
/// The device reads and writes the frames.
pub const DEVICE_READS_WRITES: u64 = ACCESS_DEVICE_READ | ACCESS_DEVICE_WRITE;

/// Map the frames of `memory_cap` for the device whose DMA capability
/// `dma_ep` is, with `access` ([`DEVICE_READS`] or [`DEVICE_READS_WRITES`]),
/// and return the device address of their first byte. The driver keeps
/// `memory_cap`: devmgr is sent a derivation of it carrying only the rights
/// the access needs (`MAP`, and `WRITE` for a device that writes), which it
/// keeps while the mapping stands.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// The `ipc::DmaError` of the call, with `DmaError::Call` also for a
/// derivation that failed before it.
pub unsafe fn map(
    dma_ep: u64,
    memory_cap: u64,
    access: u64,
    ipc_buf: *mut u64,
) -> Result<u64, ipc::DmaError>
{
    let rights = if access & ACCESS_DEVICE_WRITE != 0
    {
        syscall::RIGHTS_MEM_MAP | syscall::RIGHTS_MEM_WRITE
    }
    else
    {
        syscall::RIGHTS_MEM_MAP
    };
    let copy = syscall::cap_derive(memory_cap, rights).map_err(ipc::DmaError::Call)?;
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let mapped = unsafe { ipc::dma_map(dma_ep, copy, access, ipc_buf) };
    if let Err(ipc::DmaError::Call(_)) = mapped
    {
        // The call failed before the copy moved: it is still the driver's.
        let _ = syscall::cap_delete(copy);
    }
    mapped
}

/// Map the frames of `memory_cap` for the device to read and write
/// ([`map`] with [`DEVICE_READS_WRITES`]), as a driver maps its rings and
/// fixed buffers at setup, and return their device address. A device cannot
/// be driven without them, so when devmgr refuses, `on_refusal` is called
/// with the error (to log it) and the calling thread exits.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
pub unsafe fn map_or_exit(
    dma_ep: u64,
    memory_cap: u64,
    ipc_buf: *mut u64,
    on_refusal: impl FnOnce(ipc::DmaError),
) -> u64
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    match unsafe { map(dma_ep, memory_cap, DEVICE_READS_WRITES, ipc_buf) }
    {
        Ok(device_addr) => device_addr,
        Err(e) =>
        {
            on_refusal(e);
            syscall::thread_exit();
        }
    }
}

/// Withdraw the mapping at `device_addr` that [`map`] made for the device
/// whose DMA capability `dma_ep` is.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// The `ipc::DmaError` of the call.
pub unsafe fn unmap(dma_ep: u64, device_addr: u64, ipc_buf: *mut u64) -> Result<(), ipc::DmaError>
{
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    unsafe { ipc::dma_unmap(dma_ep, device_addr, ipc_buf) }
}
