// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/devmgr.rs

//! acpid's calls to devmgr over the `devmgr.acpi` SEND: the tables, the
//! fixed register blocks, the region grants and configuration-space
//! accesses the evaluator asks for, and the pushes of each host bridge's
//! results. Every call carries the compiled `DEVMGR_LABELS_VERSION`.

use ipc::{IpcMessage, devmgr_errors, devmgr_labels};

/// Why a call returned no result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallError
{
    /// The IPC itself failed, with the kernel's error.
    Transport(i64),
    /// devmgr replied this status.
    Status(u64),
    /// A `SUCCESS` reply without the capability or a word its label
    /// promises.
    Malformed,
}

impl CallError
{
    /// Whether devmgr's policy refused the request
    /// (`devmgr_errors::REFUSED`).
    pub const fn refused(self) -> bool
    {
        matches!(self, Self::Status(devmgr_errors::REFUSED))
    }
}

/// A table served by `QUERY_ACPI_TABLE`: a read-only Memory capability over
/// its region and where the table sits in it.
pub struct TableView
{
    /// The Memory capability, acpid's to delete.
    pub memory_cap: u64,
    /// The region's physical base.
    pub region_base: u64,
    /// The region's size.
    pub region_size: u64,
    /// The table's physical address.
    pub table_phys: u64,
}

/// A region granted by `ACPI_REGION_GRANT`.
pub struct Grant
{
    /// An `IoPort` over the ports, or an `Mmio` over the pages.
    pub cap: u64,
    /// The first port, or the first page's address.
    pub base: u64,
    /// The length in ports or bytes.
    pub len: u64,
}

/// acpid's SEND on devmgr's registry endpoint; each thread that calls
/// through it calls from its own IPC buffer.
#[derive(Clone)]
pub struct Devmgr
{
    registry: u64,
}

impl Devmgr
{
    /// Calls through the `devmgr.acpi` SEND `registry`.
    pub const fn new(registry: u64) -> Self
    {
        Self { registry }
    }

    /// Call `label` with the version word, then `words`, from the calling
    /// thread's IPC buffer; the reply when devmgr answers `SUCCESS`.
    pub fn call(&self, label: u64, words: &[u64]) -> Result<IpcMessage, CallError>
    {
        let msg = IpcMessage::builder(label)
            .word(0, u64::from(ipc::DEVMGR_LABELS_VERSION))
            .words(1, words)
            .build();
        let ipc_buf = std::os::seraph::current_ipc_buf();
        // SAFETY: `current_ipc_buf` is the calling thread's registered IPC
        // buffer.
        let reply =
            unsafe { ipc::ipc_call(self.registry, &msg, ipc_buf) }.map_err(CallError::Transport)?;
        if reply.label == devmgr_errors::SUCCESS
        {
            Ok(reply)
        }
        else
        {
            // A refusal carries no capability; delete any a reply carried.
            for &cap in reply.caps()
            {
                let _ = syscall::cap_delete(cap);
            }
            Err(CallError::Status(reply.label))
        }
    }

    /// The table of signature `signature` the XSDT lists at `index`
    /// among those of that signature (`DSDT` names the FADT's DSDT).
    pub fn table(&self, signature: [u8; 4], index: u64) -> Result<TableView, CallError>
    {
        let sig = u64::from(u32::from_le_bytes(signature));
        let reply = self.call(devmgr_labels::QUERY_ACPI_TABLE, &[sig, 0, index])?;
        let memory_cap = *reply.caps().first().ok_or(CallError::Malformed)?;
        Ok(TableView {
            memory_cap,
            region_base: reply.word(0),
            region_size: reply.word(1),
            table_phys: reply.word(2),
        })
    }

    /// A grant of the region `[base, base + len)` of `space`
    /// (`ACPI_SPACE_MEMORY` or `ACPI_SPACE_IO`).
    pub fn grant(&self, space: u64, base: u64, len: u64) -> Result<Grant, CallError>
    {
        let reply = self.call(devmgr_labels::ACPI_REGION_GRANT, &[space, base, len])?;
        let cap = *reply.caps().first().ok_or(CallError::Malformed)?;
        Ok(Grant {
            cap,
            base: reply.word(0),
            len: reply.word(1),
        })
    }

    /// One configuration-space access: `op` (`ACPI_CONFIG_READ` or
    /// `ACPI_CONFIG_WRITE`) of `width` bytes at `offset` of the function
    /// `function` (`devmgr_labels::pci_function`); the value read.
    pub fn config(
        &self,
        op: u64,
        function: u64,
        offset: u64,
        width: u64,
        value: u64,
    ) -> Result<u64, CallError>
    {
        self.call(
            devmgr_labels::ACPI_PCI_CONFIG,
            &[op, function, offset, width, value],
        )
        .map(|reply| reply.word(0))
    }

    /// Ask devmgr to run the hotplug job of the slot below the port
    /// `port` (`devmgr_labels::pci_function`) for `event`
    /// (`devmgr_labels::HOTPLUG_ADDED` or `HOTPLUG_REMOVED`). Returns once
    /// the job ended, with the functions it recorded or removed.
    pub fn acpi_hotplug(&self, event: u64, port: u64) -> Result<u64, CallError>
    {
        self.call(devmgr_labels::ACPI_HOTPLUG, &[event, port])
            .map(|reply| reply.word(0))
    }

    /// Push one bridge's results with `label`: `words` follow its segment
    /// and bus.
    pub fn push(&self, label: u64, segment: u16, bus: u8, words: &[u64]) -> Result<(), CallError>
    {
        let mut all = Vec::with_capacity(words.len().saturating_add(2));
        all.extend([u64::from(segment), u64::from(bus)]);
        all.extend_from_slice(words);
        self.call(label, &all).map(drop)
    }
}
