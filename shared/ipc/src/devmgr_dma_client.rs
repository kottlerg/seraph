// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// shared/ipc/src/devmgr_dma_client.rs

//! Driver-side calls of devmgr's DMA endpoint (`devmgr_dma_labels`), re-exported
//! at the crate root.

// Under `rustc-dep-of-std` the crate root is `no_core`, and a submodule needs
// its own prelude import (see `recv_guard.rs`).
#[cfg(feature = "rustc-dep-of-std")]
use core::prelude::rust_2024::*;

use crate::{
    DEVMGR_DMA_LABELS_VERSION, IpcMessage, devmgr_dma_errors, devmgr_dma_labels, ipc_call,
};

/// Why [`dma_map`], [`dma_unmap`] or [`dma_faults`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaError
{
    /// The `ipc_call` itself failed, with this syscall error.
    Call(i64),
    /// devmgr replied this non-`SUCCESS` label ([`devmgr_dma_errors`]).
    Refused(u64),
}

/// Map the frames of `memory_cap` for the device whose DMA capability
/// `dma_ep` is ([`devmgr_dma_labels::DMA_MAP`]) with `access`, and return the
/// device address of their first byte. The call moves `memory_cap` to
/// devmgr, which keeps it while the mapping stands, so a caller passes a
/// derivation of the cap it goes on using.
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`DmaError::Call`] when the call fails, and [`DmaError::Refused`] with
/// devmgr's reply label when devmgr refuses the mapping.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 32 KiB at the smallest (a std driver's main thread)"
)]
pub unsafe fn dma_map(
    dma_ep: u64,
    memory_cap: u64,
    access: u64,
    ipc_buf: *mut u64,
) -> Result<u64, DmaError>
{
    let request = IpcMessage::builder(devmgr_dma_labels::DMA_MAP)
        .word(0, u64::from(DEVMGR_DMA_LABELS_VERSION))
        .word(1, access)
        .cap(memory_cap)
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc_call(dma_ep, &request, ipc_buf) }.map_err(DmaError::Call)?;
    if reply.label == devmgr_dma_errors::SUCCESS
    {
        Ok(reply.word(0))
    }
    else
    {
        Err(DmaError::Refused(reply.label))
    }
}

/// Withdraw the mapping at `device_addr` of the device whose DMA capability
/// `dma_ep` is ([`devmgr_dma_labels::DMA_UNMAP`]).
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`DmaError::Call`] when the call fails, and [`DmaError::Refused`] with
/// devmgr's reply label when devmgr refuses: `NO_MAPPING` when `device_addr`
/// names no mapping of the device, `UNAUTHORIZED` when the device is
/// withdrawn or was never given DMA, `IOMMU_FAILED` when the IOMMU driver did
/// not remove the mapping, which stays standing, or `LABEL_VERSION_MISMATCH`
/// ([`devmgr_dma_labels::DMA_UNMAP`]).
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 32 KiB at the smallest (a std driver's main thread)"
)]
pub unsafe fn dma_unmap(dma_ep: u64, device_addr: u64, ipc_buf: *mut u64) -> Result<(), DmaError>
{
    let request = IpcMessage::builder(devmgr_dma_labels::DMA_UNMAP)
        .word(0, u64::from(DEVMGR_DMA_LABELS_VERSION))
        .word(1, device_addr)
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc_call(dma_ep, &request, ipc_buf) }.map_err(DmaError::Call)?;
    if reply.label == devmgr_dma_errors::SUCCESS
    {
        Ok(())
    }
    else
    {
        Err(DmaError::Refused(reply.label))
    }
}

/// The reply of [`devmgr_dma_labels::DMA_FAULTS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DmaFaults
{
    /// An IOMMU confines the device.
    pub confined: bool,
    /// The faults devmgr has taken for the device since its DMA grant.
    pub count: u64,
    /// The IOVA of the latest, page aligned; 0 with none.
    pub last_iova: u64,
}

/// Ask for the IOMMU faults devmgr has taken for the device whose DMA
/// capability `dma_ep` is ([`devmgr_dma_labels::DMA_FAULTS`]).
///
/// # Safety
/// `ipc_buf` must point to the calling thread's registered IPC buffer page.
///
/// # Errors
/// [`DmaError::Call`] when the call fails, and [`DmaError::Refused`] with
/// devmgr's reply label when devmgr refuses: `UNAUTHORIZED` when the device
/// is withdrawn or was never given DMA, or `LABEL_VERSION_MISMATCH`.
#[expect(
    clippy::large_stack_frames,
    reason = "the request and reply `IpcMessage`s (568 B each) and the builder's copy; on its \
              caller's stack, 32 KiB at the smallest (a std driver's main thread)"
)]
pub unsafe fn dma_faults(dma_ep: u64, ipc_buf: *mut u64) -> Result<DmaFaults, DmaError>
{
    let request = IpcMessage::builder(devmgr_dma_labels::DMA_FAULTS)
        .word(0, u64::from(DEVMGR_DMA_LABELS_VERSION))
        .build();
    // SAFETY: the caller guarantees `ipc_buf` is the registered IPC buffer.
    let reply = unsafe { ipc_call(dma_ep, &request, ipc_buf) }.map_err(DmaError::Call)?;
    if reply.label == devmgr_dma_errors::SUCCESS
    {
        Ok(DmaFaults {
            confined: reply.word(0) == devmgr_dma_labels::DMA_CONFINED,
            count: reply.word(1),
            last_iova: reply.word(2),
        })
    }
    else
    {
        Err(DmaError::Refused(reply.label))
    }
}
