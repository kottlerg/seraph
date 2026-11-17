// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/hotplug.rs

//! PCI Express native hotplug: the slots devmgr manages under a
//! native-control grant, the poller thread that watches their Slot Status,
//! and the add job the control thread runs for each arrival, as
//! [hotplug.md](../docs/hotplug.md) specifies. The register logic, the BAR
//! assignment and the poller's decisions are the host-tested
//! `firmware::hotplug`; this module maps the configuration pages and runs
//! them.

use std::sync::mpsc;

use firmware::acpid::{Address, Bridges, address};
use firmware::hotplug::{
    self as hp, Action, Admission, LINK_ACTIVE, LINK_STATUS, SLOT_CONTROL, SLOT_STATUS,
    SLOTCTL_EVENT_ENABLES, SLOTSTA_COMMAND_COMPLETED, SLOTSTA_LATCHES, Slot, SlotState,
};
use firmware::pci_records::RecordState;
use firmware::scan::{ConfigSpace, PciDevice};
use std::os::seraph::thread::BuilderExt;

use crate::bind::{self, ConfigRegs};
use crate::{Registry, caps, settle};

/// The step of the poller's waits for a Slot Control command and for a
/// link, in milliseconds.
const WAIT_STEP_MS: u64 = 10;

/// Where a slot's native-control grant stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Grant
{
    /// No grant is known yet: the host bridge's `_OSC` result has not arrived
    /// and the platform table grants nothing.
    Waiting,
    /// devmgr manages the slot: the poller watches it.
    Managed,
    /// The grant was refused, or the slot could not be handed to the
    /// poller; devmgr never touches the slot.
    Unmanaged,
}

/// A hotplug slot the boot scan found and devmgr may manage.
struct Candidate
{
    slot: Slot,
    grant: Grant,
}

/// A managed slot as the poller holds it.
struct Polled
{
    /// The slot's index among the candidates, which its arrivals carry.
    index: usize,
    slot: Slot,
    /// A derivation of the port's configuration page cap.
    page: u64,
    /// Whether a live record lay behind the slot when it was managed.
    recorded: bool,
    state: SlotState,
}

/// devmgr's hotplug slots and the channels between the control thread and
/// the poller.
pub struct Hotplug
{
    candidates: Vec<Candidate>,
    /// The platform description table's `pcie_native_hotplug`.
    platform_grant: bool,
    /// devmgr's own address space, which the poller maps pages in.
    aspace: u64,
    /// The control thread's job notification, which the poller signals
    /// with each arrival it posts.
    job_note: u64,
    /// The poller's channel of slots to manage; `None` until the first slot is
    /// managed and the poller started.
    poller: Option<mpsc::Sender<Polled>>,
    /// The arrivals' channel: the index of each slot the poller brought up.
    posted: mpsc::Sender<usize>,
    arrivals: mpsc::Receiver<usize>,
}

impl Hotplug
{
    /// The hotplug slots of `found` devmgr may manage, none managed yet: a
    /// slot whose subtree holds an IOMMU unit's function (a record the IOMMU
    /// pass bound, which `records` holds bound before any other pass runs) is
    /// not, logged; a window that lies outside every boot aperture
    /// (`apertures`, each `(base, end)`) is closed, logged, since no BAR in it
    /// could be carved. `platform_grant` is the platform description table's
    /// grant.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`platform_grant` is the platform description table's `pcie_native_hotplug` value"
    )]
    pub fn new(
        found: Vec<Slot>,
        records: &bind::Records,
        platform_grant: bool,
        apertures: &[(u64, u64)],
        job_note: u64,
        aspace: u64,
    ) -> Self
    {
        let iommu: Vec<Address> = records
            .pci
            .devices()
            .iter()
            .enumerate()
            .filter(|&(i, _)| records.pci.state(i) == Some(RecordState::Bound))
            .map(|(_, d)| address(d))
            .collect();
        let mut candidates = Vec::new();
        for mut slot in found
        {
            let (s, b, d, f) = slot.port;
            if let Some(&(_, ib, id, ifn)) = iommu.iter().find(|&&a| slot.holds(a))
            {
                std::os::seraph::log!(
                    warn: "hotplug: slot {}:{}:{}.{}: the IOMMU function {}:{}.{} lies behind it; \
                           not managed",
                    s, b, d, f, ib, id, ifn
                );
                continue;
            }
            for (what, window) in [
                ("memory", &mut slot.memory),
                ("prefetchable", &mut slot.prefetchable),
            ]
            {
                if let Some(w) = *window
                    && !w.inside(apertures)
                {
                    std::os::seraph::log!(
                        warn: "hotplug: slot {}:{}:{}.{}: {} window {:#x}..{:#x} outside every \
                               aperture; closed",
                        s, b, d, f, what, w.base, w.end
                    );
                    *window = None;
                }
            }
            if candidates.try_reserve(1).is_err()
            {
                std::os::seraph::log!(warn: "hotplug: no memory to hold slot {}:{}:{}.{}", s, b, d, f);
                continue;
            }
            let (base, end) = slot.memory.map_or((0, 0), |w| (w.base, w.end));
            std::os::seraph::log!(
                "hotplug: slot {}:{}:{}.{} (bus {}, memory {:#x}..{:#x}): found",
                s,
                b,
                d,
                f,
                slot.secondary,
                base,
                end
            );
            candidates.push(Candidate {
                slot,
                grant: Grant::Waiting,
            });
        }
        let (posted, arrivals) = mpsc::channel();
        Self {
            candidates,
            platform_grant,
            aspace,
            job_note,
            poller: None,
            posted,
            arrivals,
        }
    }

    /// Manage each slot whose grant has come: the `_OSC` result of its host
    /// bridge among `bridges` grants native hotplug control, or the platform
    /// table does ([`hp::native_control`]). A slot whose host bridge's `_OSC`
    /// result withholds it, with no platform grant, is never managed,
    /// logged. A slot neither grants nor withholds waits. The record of each
    /// managed slot's port is held in `records` ([`hp::hold_port`]).
    pub fn grant(
        &mut self,
        bridges: &Bridges,
        records: &mut bind::Records,
        caps: &mut caps::DevmgrCaps,
    )
    {
        for index in 0..self.candidates.len()
        {
            let Some(candidate) = self.candidates.get(index)
            else
            {
                continue;
            };
            if candidate.grant != Grant::Waiting
            {
                continue;
            }
            let slot = candidate.slot;
            let (s, b, d, f) = slot.port;
            let osc = hp::host_bridge(bridges, s, b).and_then(|bridge| bridge.osc);
            let grant = if hp::native_control(osc, self.platform_grant)
            {
                let by = if self.platform_grant
                {
                    "the platform table"
                }
                else
                {
                    "_OSC"
                };
                self.manage(index, slot, records, caps, by)
            }
            else if let Some(osc) = osc
            {
                if osc.evaluated
                {
                    std::os::seraph::log!(
                        "hotplug: slot {}:{}:{}.{}: not managed: _OSC control {:#x} withholds \
                         native hotplug",
                        s,
                        b,
                        d,
                        f,
                        osc.control
                    );
                }
                else
                {
                    std::os::seraph::log!(
                        "hotplug: slot {}:{}:{}.{}: not managed: _OSC failed, status {:#x}",
                        s,
                        b,
                        d,
                        f,
                        osc.status
                    );
                }
                Grant::Unmanaged
            }
            else
            {
                continue;
            };
            if let Some(candidate) = self.candidates.get_mut(index)
            {
                candidate.grant = grant;
            }
        }
    }

    /// Hand slot `index` to the poller, starting the poller with the first,
    /// and hold its port's record; `by` names the grant in the log line.
    fn manage(
        &mut self,
        index: usize,
        slot: Slot,
        records: &mut bind::Records,
        caps: &mut caps::DevmgrCaps,
        by: &str,
    ) -> Grant
    {
        let (s, b, d, f) = slot.port;
        let page = bind::config_page(caps, slot.port)
            .and_then(|page| syscall::cap_derive(page, syscall::RIGHTS_ALL).ok());
        let Some(page) = page
        else
        {
            std::os::seraph::log!(
                warn: "hotplug: slot {}:{}:{}.{}: no configuration page for the port; not managed",
                s, b, d, f
            );
            return Grant::Unmanaged;
        };
        if self.poller.is_none()
        {
            self.poller = start_poller(self.posted.clone(), self.job_note, self.aspace);
        }
        let polled = Polled {
            index,
            slot,
            page,
            recorded: records.live_pci().any(|r| slot.holds(address(r))),
            state: SlotState::Empty,
        };
        let sent = self.poller.as_ref().map(|poller| poller.send(polled));
        if !matches!(sent, Some(Ok(())))
        {
            let _ = syscall::cap_delete(page);
            std::os::seraph::log!(
                warn: "hotplug: slot {}:{}:{}.{}: no poller; not managed",
                s, b, d, f
            );
            return Grant::Unmanaged;
        }
        // The poller now writes the port's Slot Control and Slot Status. The
        // control thread, which runs this, also serves acpid's configuration
        // accesses, so none is made between the hand-over and the hold.
        hp::hold_port(&mut records.pci, slot.port);
        std::os::seraph::log!(
            "hotplug: slot {}:{}:{}.{} managed (native control by {})",
            s,
            b,
            d,
            f,
            by
        );
        Grant::Managed
    }

    /// Run the add job of every arrival the poller posted: record the
    /// functions behind the slot ([`add`]), then, once the drivers
    /// directory is installed, bind them in a drivers-directory pass of their
    /// own settle batch, the hotplug batch. Before `SET_DRIVERS_DIR` the
    /// functions are only recorded, and its pass binds them.
    pub fn run(
        &self,
        registry: &Registry,
        records: &mut bind::Records,
        carve: &mut bind::Carve,
        watch: &mut settle::DriverWatch,
        ipc_buf: *mut u64,
    )
    {
        while let Ok(index) = self.arrivals.try_recv()
        {
            let Some(slot) = self.candidates.get(index).map(|c| c.slot)
            else
            {
                continue;
            };
            if add(&slot, records, carve.caps) == 0
            {
                continue;
            }
            let (dir, dir_path) = {
                let state = registry.lock();
                (state.drivers_dir_cap, state.drivers_dir_path)
            };
            if dir == 0
            {
                std::os::seraph::log!(
                    "hotplug: drivers directory not installed; its pass binds the functions added"
                );
                continue;
            }
            crate::spawn_dir_drivers(
                "hotplug batch",
                records,
                carve,
                dir,
                dir_path.as_bytes(),
                watch,
                registry,
                ipc_buf,
            );
        }
    }
}

/// Start the poller thread, which owns the managed slots it is sent; its
/// channel, or `None`, logged, when the thread cannot be started.
fn start_poller(
    posted: mpsc::Sender<usize>,
    job_note: u64,
    aspace: u64,
) -> Option<mpsc::Sender<Polled>>
{
    let (sender, slots) = mpsc::channel::<Polled>();
    let started = std::thread::Builder::new()
        .name("hotplug".into())
        .spawn_at_priority(ipc::sched_policy::DEVMGR_PRIORITY, move || {
            poll_loop(&slots, &posted, job_note, aspace);
        });
    if started.is_err()
    {
        std::os::seraph::log!(warn: "hotplug: poller thread not started; no slot is managed");
        return None;
    }
    Some(sender)
}

/// The poller: take over each slot as it arrives, then every
/// [`hp::HOTPLUG_POLL_MS`] read and act on each managed slot's Slot Status.
fn poll_loop(
    slots: &mpsc::Receiver<Polled>,
    posted: &mpsc::Sender<usize>,
    job_note: u64,
    aspace: u64,
) -> !
{
    let mut managed: Vec<Polled> = Vec::new();
    loop
    {
        while let Ok(mut slot) = slots.try_recv()
        {
            if managed.try_reserve(1).is_err()
            {
                let _ = syscall::cap_delete(slot.page);
                let (s, b, d, f) = slot.slot.port;
                std::os::seraph::log!(
                    warn: "hotplug: no memory to poll slot {}:{}:{}.{}; not watched",
                    s, b, d, f
                );
                continue;
            }
            take_over(&mut slot, aspace);
            managed.push(slot);
        }
        for slot in &mut managed
        {
            poll(slot, aspace, posted, job_note);
        }
        let _ = syscall::thread_sleep(hp::HOTPLUG_POLL_MS);
    }
}

/// Run `access` on the port's configuration registers, mapped for the call;
/// `None`, logged, when the page cannot be mapped.
fn with_port<R>(slot: &Polled, aspace: u64, access: impl FnOnce(&ConfigRegs) -> R) -> Option<R>
{
    crate::with_mmio_mapped(aspace, slot.page, 1, "hotplug slot", |va| {
        // SAFETY: `with_mmio_mapped` maps the whole configuration page at `va` for
        // this closure, which reaches it only through `regs`'s raw volatile
        // accesses.
        let regs = unsafe { ConfigRegs::new(va) };
        access(&regs)
    })
}

/// Take over a slot: turn its event interrupts off (the poller reads the
/// latches instead), clear its latches, and hold it occupied when a card is
/// present and recorded, else empty, so an unrecorded card present at
/// take-over is brought up on the first poll.
fn take_over(slot: &mut Polled, aspace: u64)
{
    let s = slot.slot;
    let state = with_port(slot, aspace, |regs| {
        let control = regs.read16(s.register(SLOT_CONTROL));
        if control != u16::MAX && control & SLOTCTL_EVENT_ENABLES != 0
        {
            write_control(regs, &s, control & !SLOTCTL_EVENT_ENABLES);
        }
        let status = regs.read16(s.register(SLOT_STATUS));
        clear_latches(regs, &s, status);
        hp::initial(status, slot.recorded)
    });
    slot.state = state.unwrap_or(SlotState::Empty);
}

/// Read a managed slot's Slot Status, clear the latches it holds, and act
/// on it ([`hp::next`]).
fn poll(slot: &mut Polled, aspace: u64, posted: &mpsc::Sender<usize>, job_note: u64)
{
    let s = slot.slot;
    let (seg, b, d, f) = s.port;
    let current = slot.state;
    let state = with_port(slot, aspace, |regs| {
        let status = regs.read16(s.register(SLOT_STATUS));
        clear_latches(regs, &s, status);
        let (state, action) = hp::next(current, status);
        match action
        {
            Action::None => state,
            Action::Removal =>
            {
                std::os::seraph::log!(
                    warn: "hotplug: slot {}:{}:{}.{}: card removed or its button pressed; devmgr \
                           does not remove functions, its records stay",
                    seg, b, d, f
                );
                state
            }
            Action::PowerUp if power_up(regs, &s) =>
            {
                std::os::seraph::log!("hotplug: slot {}:{}:{}.{}: card added", seg, b, d, f);
                if posted.send(slot.index).is_ok()
                {
                    let _ = syscall::notification_send(job_note, 1);
                }
                SlotState::Occupied
            }
            Action::PowerUp =>
            {
                std::os::seraph::log!(
                    warn: "hotplug: slot {}:{}:{}.{}: card present but its link did not come up; \
                           slot powered off until the card is removed",
                    seg, b, d, f
                );
                let control = regs.read16(s.register(SLOT_CONTROL));
                let off = hp::power_off(control, s.capabilities);
                if control != u16::MAX && off != control
                {
                    write_control(regs, &s, off);
                }
                SlotState::Failed
            }
        }
    });
    if let Some(state) = state
    {
        slot.state = state;
    }
}

/// Clear the event latches Slot Status `status` holds (RW1C).
fn clear_latches(regs: &ConfigRegs, slot: &Slot, status: u16)
{
    let latched = status & SLOTSTA_LATCHES;
    if status != u16::MAX && latched != 0
    {
        regs.write16(slot.register(SLOT_STATUS), latched);
    }
}

/// Power the slot on and wait for its link: up to [`hp::SLOT_WAIT_MS`] for
/// Data Link Layer Link Active, then [`hp::LINK_SETTLE_MS`], where the port
/// reports it; [`hp::SLOT_WAIT_MS`] where it does not. Returns whether the
/// link came up (always, where it is not reported). The latches the
/// power-up set are cleared.
fn power_up(regs: &ConfigRegs, slot: &Slot) -> bool
{
    let control = regs.read16(slot.register(SLOT_CONTROL));
    let on = hp::power_on(control, slot.capabilities);
    if control != u16::MAX && on != control
    {
        write_control(regs, slot, on);
    }
    let up = if slot.link_reporting
    {
        let link = || {
            let status = regs.read16(slot.register(LINK_STATUS));
            status != u16::MAX && status & LINK_ACTIVE != 0
        };
        let up = wait_for(hp::SLOT_WAIT_MS, link);
        if up
        {
            let _ = syscall::thread_sleep(hp::LINK_SETTLE_MS);
        }
        up
    }
    else
    {
        let _ = syscall::thread_sleep(hp::SLOT_WAIT_MS);
        true
    };
    clear_latches(regs, slot, regs.read16(slot.register(SLOT_STATUS)));
    up
}

/// Write Slot Control and, where the slot reports Command Completed, wait
/// up to [`hp::SLOT_WAIT_MS`] for the command to complete, the latch cleared
/// before the write and after. A command that does not complete in time is
/// logged; the poller goes on.
fn write_control(regs: &ConfigRegs, slot: &Slot, value: u16)
{
    let status = slot.register(SLOT_STATUS);
    if slot.command_completion()
    {
        regs.write16(status, SLOTSTA_COMMAND_COMPLETED);
    }
    regs.write16(slot.register(SLOT_CONTROL), value);
    if !slot.command_completion()
    {
        return;
    }
    let completed = wait_for(hp::SLOT_WAIT_MS, || {
        let s = regs.read16(status);
        s != u16::MAX && s & SLOTSTA_COMMAND_COMPLETED != 0
    });
    regs.write16(status, SLOTSTA_COMMAND_COMPLETED);
    if !completed
    {
        let (seg, b, d, f) = slot.port;
        std::os::seraph::log!(
            warn: "hotplug: slot {}:{}:{}.{}: Slot Control write {:#x} did not complete",
            seg, b, d, f, value
        );
    }
}

/// Whether `done` holds within `ms` milliseconds, checked every
/// [`WAIT_STEP_MS`].
fn wait_for(ms: u64, done: impl Fn() -> bool) -> bool
{
    let mut waited = 0;
    while waited < ms
    {
        if done()
        {
            return true;
        }
        let _ = syscall::thread_sleep(WAIT_STEP_MS);
        waited = waited.saturating_add(WAIT_STEP_MS);
    }
    done()
}

/// One function's configuration page, mapped, as a `ConfigSpace` that holds
/// only that function: every other address reads all ones.
struct FunctionSpace<'a>
{
    regs: &'a ConfigRegs,
    at: (u8, u8, u8),
}

impl FunctionSpace<'_>
{
    fn here(&self, bus: u8, dev: u8, func: u8) -> bool
    {
        (bus, dev, func) == self.at
    }
}

impl ConfigSpace for FunctionSpace<'_>
{
    fn read8(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u8
    {
        if self.here(bus, dev, func)
        {
            self.regs.read8(reg)
        }
        else
        {
            u8::MAX
        }
    }

    fn read16(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u16
    {
        if self.here(bus, dev, func)
        {
            self.regs.read16(reg)
        }
        else
        {
            u16::MAX
        }
    }

    fn read32(&self, bus: u8, dev: u8, func: u8, reg: u16) -> u32
    {
        if self.here(bus, dev, func)
        {
            self.regs.read32(reg)
        }
        else
        {
            u32::MAX
        }
    }

    fn write16(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u16)
    {
        if self.here(bus, dev, func)
        {
            self.regs.write16(reg, val);
        }
    }

    fn write32(&self, bus: u8, dev: u8, func: u8, reg: u16, val: u32)
    {
        if self.here(bus, dev, func)
        {
            self.regs.write32(reg, val);
        }
    }
}

/// The add job of an arrival at `slot`: read each function of device 0 on
/// the slot's secondary bus (a downstream port forwards configuration
/// requests to device 0 only), place its MMIO BARs in the slot's windows
/// clear of the live records' BARs below the slot, program them, and append
/// its record. A type-1 function is logged and not descended into; a
/// function whose BARs do not fit, or do not read back as programmed, is
/// logged and not recorded, so no driver is bound to it; a refused append is
/// logged. Returns the number of records appended.
fn add(slot: &Slot, records: &mut bind::Records, caps: &mut caps::DevmgrCaps) -> usize
{
    let (segment, bus) = (slot.port.0, slot.secondary);
    let mut appended = 0usize;
    let mut functions = 1u8;
    let mut func = 0u8;
    while func < functions
    {
        let taken: Vec<(u64, u64)> = records
            .live_pci()
            .filter(|r| slot.holds(address(r)))
            .flat_map(mmio_ranges)
            .collect();
        let found = with_function(caps, (segment, bus, 0, func), |cfg| {
            let found = hp::place(cfg, slot, (bus, 0, func), &taken);
            // Bit 7 of a present function 0's Header Type marks a
            // multi-function device, whose functions 1 to 7 are read too.
            if func == 0
                && !matches!(found, hp::Found::Absent)
                && cfg.read8(bus, 0, 0, 0x0E) & 0x80 != 0
            {
                functions = 8;
            }
            found
        });
        let at = |d: &PciDevice| (d.vendor_id, d.device_id);
        match found
        {
            None | Some(hp::Found::Absent) =>
            {
                if func == 0
                {
                    std::os::seraph::log!(
                        warn: "hotplug: bus {}:{}: no function answers; nothing added",
                        segment, bus
                    );
                }
            }
            Some(hp::Found::Ready(device)) =>
            {
                let (vendor, id) = at(&device);
                match hp::admit(device, |d| records.pci.append(d))
                {
                    Admission::Appended(index) =>
                    {
                        appended = appended.saturating_add(1);
                        std::os::seraph::log!(
                            "hotplug: {}:{}:0.{} {:04x}:{:04x} recorded as PCI record {}",
                            segment,
                            bus,
                            func,
                            vendor,
                            id,
                            index
                        );
                    }
                    Admission::Bridge => std::os::seraph::log!(
                        warn: "hotplug: {}:{}:0.{} {:04x}:{:04x} is a bridge; not descended into",
                        segment, bus, func, vendor, id
                    ),
                    Admission::Refused(e) => std::os::seraph::log!(
                        warn: "hotplug: {}:{}:0.{} {:04x}:{:04x} not recorded: {}",
                        segment, bus, func, vendor, id, hp::refusal(e)
                    ),
                }
            }
            Some(hp::Found::Unplaced(device, why)) =>
            {
                let (vendor, id) = at(&device);
                let (register, what) = match why
                {
                    hp::Unplaced::BadSize(r) => (r, "its size is no power of two"),
                    hp::Unplaced::NoWindow(r) => (r, "no window of the slot can hold it"),
                    hp::Unplaced::NoRoom(r) => (r, "the slot's windows have no room for it"),
                };
                std::os::seraph::log!(
                    warn: "hotplug: {}:{}:0.{} {:04x}:{:04x}: BAR {} not placed ({}); not \
                           recorded, no driver",
                    segment, bus, func, vendor, id, register, what
                );
            }
            Some(hp::Found::NotProgrammed(device)) =>
            {
                let (vendor, id) = at(&device);
                std::os::seraph::log!(
                    warn: "hotplug: {}:{}:0.{} {:04x}:{:04x}: BARs did not read back as written; \
                           not recorded, no driver",
                    segment, bus, func, vendor, id
                );
            }
        }
        func = func.saturating_add(1);
    }
    appended
}

/// The `(base, end)` of each MMIO BAR of `device` that is assigned.
fn mmio_ranges(device: &PciDevice) -> impl Iterator<Item = (u64, u64)> + '_
{
    device
        .bar_phys
        .iter()
        .zip(&device.bar_size)
        .zip(&device.bar_is_mmio)
        .take(device.bar_count)
        .filter(|&((&phys, _), &mmio)| mmio && phys != 0)
        .map(|((&phys, &size), _)| (phys, phys.saturating_add(size)))
}

/// Run `access` on the function at `at` (segment, bus, device, function),
/// its configuration page carved ([`bind::config_page`]) and mapped for the
/// call; `None`, logged, when the page cannot be carved or mapped.
fn with_function<R>(
    caps: &mut caps::DevmgrCaps,
    at: Address,
    access: impl FnOnce(&FunctionSpace<'_>) -> R,
) -> Option<R>
{
    let (segment, bus, dev, func) = at;
    let Some(page) = bind::config_page(caps, at)
    else
    {
        std::os::seraph::log!(
            warn: "hotplug: {}:{}:{}.{}: no configuration page; not read",
            segment, bus, dev, func
        );
        return None;
    };
    crate::with_mmio_mapped(caps.self_aspace, page, 1, "hotplug function", |va| {
        // SAFETY: `with_mmio_mapped` maps the whole configuration page at `va` for
        // this closure, which reaches it only through `regs`'s raw volatile
        // accesses.
        let regs = unsafe { ConfigRegs::new(va) };
        access(&FunctionSpace {
            regs: &regs,
            at: (bus, dev, func),
        })
    })
}
