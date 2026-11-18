// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/acpid/src/platform.rs

//! The [`Host`] acpid gives the evaluator: every hardware access goes
//! through a grant devmgr made.
//!
//! An I/O access asks devmgr for its operation region's whole span, a
//! memory access for the page that holds it (`ACPI_REGION_GRANT`), on first
//! use; acpid binds the `IoPort` to the evaluation thread or maps the
//! `Mmio`, and keeps the grant. A refused span is kept too, so it is asked
//! for once. A configuration-space access is one `ACPI_PCI_CONFIG` call.
//! Each `Notify` of a hotplug event is kept, once per object and event
//! ([`hotplug::keep`]), for the evaluation thread to act on once the
//! evaluation ends ([`Platform::take_hotplug_notes`]). acpid holds no
//! Global Lock, since devmgr refuses the FACS, so the evaluator's
//! acquisition fails.

use std::time::{Duration, Instant};

use aml::encoding::Seg;
use aml::host::{Host, HostError, PciAddress, Span, Width};
use ipc::devmgr_labels;
use std::os::seraph::reserve_pages;

use acpid::hotplug::{self, HotplugNote, Kept};

use crate::arch;
use crate::devmgr::{CallError, Devmgr};

/// The page size of an `Mmio` grant.
const PAGE_SIZE: u64 = 0x1000;

/// A region devmgr granted, held for acpid's lifetime.
struct Held
{
    /// `ACPI_SPACE_IO` or `ACPI_SPACE_MEMORY`.
    space: u64,
    /// The first port, or the first page's physical address.
    base: u64,
    /// The end of the grant (exclusive).
    end: u64,
    /// Where a memory grant is mapped; 0 for ports.
    va: u64,
}

/// The evaluator's host.
pub struct Platform<'a>
{
    devmgr: &'a Devmgr,
    aspace: u64,
    thread: u64,
    held: Vec<Held>,
    refused: Vec<(u64, Span)>,
    start: Instant,
    hotplug_notes: Vec<HotplugNote>,
}

impl<'a> Platform<'a>
{
    /// A host reaching devmgr through `devmgr`, mapping into `aspace` and
    /// binding ports to `thread`, the evaluation thread.
    pub fn new(devmgr: &'a Devmgr, aspace: u64, thread: u64) -> Self
    {
        Self {
            devmgr,
            aspace,
            thread,
            held: Vec::new(),
            refused: Vec::new(),
            start: Instant::now(),
            hotplug_notes: Vec::new(),
        }
    }

    /// The calls to devmgr this host makes its accesses through.
    pub const fn devmgr(&self) -> &'a Devmgr
    {
        self.devmgr
    }

    /// The hotplug `Notify` calls kept since the last take, in their order.
    pub fn take_hotplug_notes(&mut self) -> Vec<HotplugNote>
    {
        core::mem::take(&mut self.hotplug_notes)
    }

    /// The held grant of `space` that covers `[addr, addr + width)`,
    /// asking devmgr first when none does: for `region` of ports, for the
    /// page that holds `addr` of memory, which devmgr grants a page at a
    /// time.
    fn covering(
        &mut self,
        space: u64,
        region: Span,
        addr: u64,
        width: Width,
    ) -> Result<&Held, HostError>
    {
        let end = addr.checked_add(width.bytes()).ok_or(HostError::Failed)?;
        let covers = |h: &Held| h.space == space && h.base <= addr && end <= h.end;
        if !self.held.iter().any(covers)
        {
            let ask = if space == devmgr_labels::ACPI_SPACE_MEMORY
            {
                Span {
                    base: addr & !(PAGE_SIZE - 1),
                    len: PAGE_SIZE,
                }
            }
            else
            {
                region
            };
            self.acquire(space, ask)?;
        }
        self.held
            .iter()
            .find(|h| covers(h))
            .ok_or(HostError::Failed)
    }

    /// Ask devmgr for `region` of `space` and hold the grant: bind ports,
    /// map memory.
    fn acquire(&mut self, space: u64, region: Span) -> Result<(), HostError>
    {
        if self.refused.contains(&(space, region))
        {
            return Err(HostError::Refused);
        }
        let grant = match self.devmgr.grant(space, region.base, region.len)
        {
            Ok(grant) => grant,
            Err(e) if e.refused() =>
            {
                std::os::seraph::log!(
                    warn: "region refused: {} {:#x}+{:#x}",
                    space_name(space),
                    region.base,
                    region.len
                );
                self.refused.push((space, region));
                return Err(HostError::Refused);
            }
            Err(e) =>
            {
                std::os::seraph::log!(
                    warn: "region grant failed: {} {:#x}+{:#x}: {e:?}",
                    space_name(space),
                    region.base,
                    region.len
                );
                return Err(HostError::Failed);
            }
        };
        let end = grant.base.checked_add(grant.len).ok_or(HostError::Failed)?;
        let va = if space == devmgr_labels::ACPI_SPACE_IO
        {
            if !arch::current::bind_ports(self.thread, grant.cap)
            {
                let _ = syscall::cap_delete(grant.cap);
                return Err(HostError::Failed);
            }
            0
        }
        else
        {
            self.map(grant.cap, grant.len)?
        };
        self.held.push(Held {
            space,
            base: grant.base,
            end,
            va,
        });
        Ok(())
    }

    /// Map the `Mmio` capability `cap` of `len` bytes; its address.
    fn map(&self, cap: u64, len: u64) -> Result<u64, HostError>
    {
        let pages = len.div_ceil(PAGE_SIZE);
        let Ok(range) = reserve_pages(pages)
        else
        {
            let _ = syscall::cap_delete(cap);
            return Err(HostError::Failed);
        };
        let va = range.va_start();
        // SAFETY: `range` is a fresh reservation of `pages` pages from the
        // per-process arena: VA no Rust object or IPC page occupies. The
        // grant is held for acpid's lifetime, so the range is never returned
        // and nothing else is placed there.
        if unsafe { std::os::seraph::mmio_map_funded(self.aspace, cap, va, pages) }.is_err()
        {
            // A refused map can leave some pages mapped, so the range stays
            // reserved and the capability is kept with it.
            return Err(HostError::Failed);
        }
        Ok(va)
    }
}

/// The ASL path of the absolute path `path`, root first (`\_SB_.PCI0`).
pub fn path_text(path: &[Seg]) -> String
{
    let segs: Vec<String> = path
        .iter()
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    format!("\\{}", segs.join("."))
}

/// The name of region space `space` in a log line.
const fn space_name(space: u64) -> &'static str
{
    if space == devmgr_labels::ACPI_SPACE_IO
    {
        "SystemIO"
    }
    else
    {
        "SystemMemory"
    }
}

/// The `ACPI_PCI_CONFIG` width of `width`; `None` for a quadword, which
/// configuration space is not accessed with.
const fn config_width(width: Width) -> Option<u64>
{
    match width
    {
        Width::QWord => None,
        Width::Byte | Width::Word | Width::DWord => Some(width.bytes()),
    }
}

/// The host error of a failed devmgr call.
const fn host_error(e: CallError) -> HostError
{
    if e.refused()
    {
        HostError::Refused
    }
    else
    {
        HostError::Failed
    }
}

/// `function` packed as `ACPI_PCI_CONFIG` names it.
const fn function_word(function: PciAddress) -> u64
{
    devmgr_labels::pci_function(
        function.segment,
        function.bus,
        function.device,
        function.function,
    )
}

impl Host for Platform<'_>
{
    fn io_read(&mut self, region: Span, port: u64, width: Width) -> Result<u64, HostError>
    {
        self.covering(devmgr_labels::ACPI_SPACE_IO, region, port, width)?;
        let port = u16::try_from(port).map_err(|_| HostError::Failed)?;
        // SAFETY: the held grant covers `[port, port + width)` and its
        // `IoPort` is bound to this thread, the evaluation thread; the read
        // is the access the firmware's AML asks for.
        unsafe { arch::current::port_read(port, width) }.ok_or(HostError::Failed)
    }

    fn io_write(
        &mut self,
        region: Span,
        port: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        self.covering(devmgr_labels::ACPI_SPACE_IO, region, port, width)?;
        let port = u16::try_from(port).map_err(|_| HostError::Failed)?;
        // SAFETY: as in `io_read`; the write is the firmware's.
        if unsafe { arch::current::port_write(port, width, value) }
        {
            Ok(())
        }
        else
        {
            Err(HostError::Failed)
        }
    }

    fn mem_read(&mut self, region: Span, addr: u64, width: Width) -> Result<u64, HostError>
    {
        let ptr = self.mem_ptr(region, addr, width)?;
        // SAFETY: `mem_ptr` gives an address inside a held `Mmio` mapping,
        // aligned to `width`; a volatile device read touches no Rust object.
        Ok(unsafe { read(ptr, width) })
    }

    fn mem_write(
        &mut self,
        region: Span,
        addr: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        let ptr = self.mem_ptr(region, addr, width)?;
        // SAFETY: as in `mem_read`; the write is the firmware's.
        unsafe { write(ptr, width, value) };
        Ok(())
    }

    fn pci_read(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
    ) -> Result<u64, HostError>
    {
        let width = config_width(width).ok_or(HostError::Failed)?;
        self.devmgr
            .config(
                devmgr_labels::ACPI_CONFIG_READ,
                function_word(function),
                offset,
                width,
                0,
            )
            .map_err(host_error)
    }

    fn pci_write(
        &mut self,
        function: PciAddress,
        offset: u64,
        width: Width,
        value: u64,
    ) -> Result<(), HostError>
    {
        let width = config_width(width).ok_or(HostError::Failed)?;
        self.devmgr
            .config(
                devmgr_labels::ACPI_CONFIG_WRITE,
                function_word(function),
                offset,
                width,
                value,
            )
            .map(drop)
            .map_err(host_error)
    }

    fn notify(&mut self, path: &[Seg], value: u64) -> Result<(), HostError>
    {
        match hotplug::keep(&mut self.hotplug_notes, path, value)
        {
            Kept::Kept | Kept::Repeat =>
            {}
            Kept::NotHotplug => std::os::seraph::log!(
                debug: "Notify({}, {value:#x}) dropped: not a hotplug event",
                path_text(path)
            ),
            Kept::NoMemory => std::os::seraph::log!(
                warn: "Notify({}, {value:#x}) dropped: no memory to keep it",
                path_text(path)
            ),
        }
        Ok(())
    }

    fn sleep(&mut self, ms: u64)
    {
        std::thread::sleep(Duration::from_millis(ms));
    }

    fn stall(&mut self, us: u64)
    {
        let start = Instant::now();
        let wait = Duration::from_micros(us);
        while start.elapsed() < wait
        {
            core::hint::spin_loop();
        }
    }

    fn timer(&mut self) -> u64
    {
        u64::try_from(self.start.elapsed().as_nanos() / 100).unwrap_or(u64::MAX)
    }

    fn acquire_global_lock(&mut self, _timeout_ms: u16) -> Result<bool, HostError>
    {
        Err(HostError::Refused)
    }

    fn release_global_lock(&mut self) -> Result<(), HostError>
    {
        Err(HostError::Refused)
    }

    fn osi(&mut self, _name: &[u8]) -> bool
    {
        false
    }
}

impl Platform<'_>
{
    /// The mapped address of `[addr, addr + width)` of `region`, granted
    /// and aligned to `width`.
    fn mem_ptr(&mut self, region: Span, addr: u64, width: Width) -> Result<u64, HostError>
    {
        if !addr.is_multiple_of(width.bytes())
        {
            return Err(HostError::Failed);
        }
        let held = self.covering(devmgr_labels::ACPI_SPACE_MEMORY, region, addr, width)?;
        addr.checked_sub(held.base)
            .and_then(|offset| held.va.checked_add(offset))
            .ok_or(HostError::Failed)
    }
}

/// Read `width` bytes at `ptr`.
///
/// # Safety
///
/// `ptr` is mapped device memory, aligned to `width`, that no Rust object
/// occupies.
unsafe fn read(ptr: u64, width: Width) -> u64
{
    match width
    {
        Width::Byte =>
        {
            // SAFETY: the caller's contract.
            u64::from(unsafe { core::ptr::read_volatile(ptr as *const u8) })
        }
        Width::Word =>
        {
            // SAFETY: the caller's contract.
            u64::from(unsafe { core::ptr::read_volatile(ptr as *const u16) })
        }
        Width::DWord =>
        {
            // SAFETY: the caller's contract.
            u64::from(unsafe { core::ptr::read_volatile(ptr as *const u32) })
        }
        Width::QWord =>
        {
            // SAFETY: the caller's contract.
            unsafe { core::ptr::read_volatile(ptr as *const u64) }
        }
    }
}

/// Write the low `width` bytes of `value` at `ptr`, ordered before any
/// later device write (`mmio::mmio_to_mmio_barrier`), as the firmware's
/// field writes are a register sequence.
///
/// # Safety
///
/// As [`read`].
#[expect(
    clippy::cast_possible_truncation,
    reason = "the evaluator passes a value no wider than its access, so each cast keeps all of it"
)]
unsafe fn write(ptr: u64, width: Width, value: u64)
{
    match width
    {
        Width::Byte =>
        {
            // SAFETY: the caller's contract.
            unsafe { core::ptr::write_volatile(ptr as *mut u8, value as u8) };
        }
        Width::Word =>
        {
            // SAFETY: the caller's contract.
            unsafe { core::ptr::write_volatile(ptr as *mut u16, value as u16) };
        }
        Width::DWord =>
        {
            // SAFETY: the caller's contract.
            unsafe { core::ptr::write_volatile(ptr as *mut u32, value as u32) };
        }
        Width::QWord =>
        {
            // SAFETY: the caller's contract.
            unsafe { core::ptr::write_volatile(ptr as *mut u64, value) };
        }
    }
    mmio::mmio_to_mmio_barrier();
}
