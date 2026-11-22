// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/hotplug.rs

//! PCI Express hotplug: the slots devmgr manages under a native-control
//! grant and the poller thread that watches their Slot Status, the slots
//! whose firmware drives hotplug and acpid's events for them, and the add and
//! removal jobs the control thread runs for each arrival and departure, as
//! [hotplug.md](../docs/hotplug.md) specifies. The register logic, the BAR
//! assignment and the poller's decisions are the host-tested
//! `firmware::hotplug`; this module maps the configuration pages and runs
//! them.

use std::sync::mpsc;

use firmware::acpid::{Address, Bridges, Osc, address};
use firmware::hotplug::{
    self as hp, Action, Admission, LINK_ACTIVE, LINK_STATUS, SLOT_CONTROL, SLOT_STATUS,
    SLOTCTL_EVENT_ENABLES, SLOTSTA_COMMAND_COMPLETED, SLOTSTA_LATCHES, Slot, SlotState,
};
use firmware::pci_records::RecordState;
use firmware::resource::SpanTable;
use firmware::resource::SplitError;
use firmware::scan::{ConfigSpace, MAX_BARS, PciDevice};
use std::os::seraph::thread::BuilderExt;
use syscall_abi::PAGE_SIZE;

use crate::acpi::Reply;
use crate::bind::{self, ConfigRegs};
use crate::{Registry, caps, settle};
use ipc::devmgr_errors as errors;
use ipc::devmgr_labels;

/// The step of the poller's waits for a Slot Control command and for a
/// link, in milliseconds.
const WAIT_STEP_MS: u64 = 10;

/// Where a slot's native-control grant stands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Grant
{
    /// No grant is known yet ([`hp::SlotGrant::Wait`]): the host bridge's
    /// `_OSC` result has not arrived, or withholds native control while
    /// devmgr does not know its platform description tables yet. Or a grant
    /// has come while devmgr's `CSpace` headroom is short
    /// ([`hp::held_grant`]), and a later turn settles it.
    Waiting,
    /// devmgr manages the slot: the poller watches it.
    Managed,
    /// The host bridge's `_OSC` withholds native hotplug control, or failed,
    /// and the platform description tables, known, grant none: the firmware
    /// drives the slot, and acpid posts its jobs from the firmware's
    /// `Notify`.
    Firmware,
    /// The slot could not be handed to the poller, or its BAR pages could not
    /// be held; devmgr never touches the slot.
    Unmanaged,
}

/// A hotplug slot the boot scan found and devmgr may manage.
struct Candidate
{
    slot: Slot,
    grant: Grant,
    /// Whether the slot's grant has waited for devmgr's `CSpace` headroom,
    /// which is logged once.
    held_back: bool,
}

/// A job the poller or acpid posts to the control thread, which runs the
/// jobs in the order they were posted, one at a time.
enum Job
{
    /// The card in slot `.0` (its index among the candidates) was powered
    /// up, or the firmware reports it present: record and bind the functions
    /// behind it ([`add`]).
    Added(usize, Owner),
    /// The card in slot `.0` is leaving: withdraw and remove the functions
    /// behind it ([`remove`]), then complete the job as its owner says.
    Removed(usize, Owner),
}

/// A hotplug event acpid posts for a slot the firmware drives.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Event
{
    /// The firmware reports a card in the slot (a device check).
    Added,
    /// The firmware asks for the slot's card to be ejected (an eject
    /// request).
    Removed,
}

/// Who posted a job, which is who drives the slot, and so how the job
/// completes.
enum Owner
{
    /// The poller, for a slot devmgr manages: a removal completes by telling
    /// the poller, which powers the slot off.
    Native,
    /// acpid, for a slot the firmware drives: the job completes with the
    /// reply sent here, after which acpid runs a removal's `_EJ0`.
    Acpi(mpsc::SyncSender<Reply>),
}

impl Owner
{
    /// Complete an acpid job with `reply`; a native job has none.
    fn reply(&self, reply: Reply)
    {
        if let Self::Acpi(to) = self
        {
            // The worker waits for its reply; one that is gone leaves
            // nothing to tell.
            let _ = to.send(reply);
        }
    }
}

/// A managed slot as the poller holds it.
struct Polled
{
    /// The slot's index among the candidates, which its jobs carry.
    index: usize,
    slot: Slot,
    /// A derivation of the port's configuration page cap.
    page: u64,
    /// What lay behind the slot when it was managed ([`behind`]).
    behind: hp::Behind,
    state: SlotState,
}

/// devmgr's hotplug slots and the channels between the control thread and
/// the poller.
pub struct Hotplug
{
    candidates: Vec<Candidate>,
    /// The matching platform description table's `pcie_native_hotplug` once
    /// devmgr knows its tables (`Some(false)` when it knows there is none);
    /// `None` before ([`Hotplug::tables_known`]).
    platform_grant: Option<bool>,
    /// devmgr's own address space, which the poller maps pages in.
    aspace: u64,
    /// The control thread's job notification, which the poller signals
    /// with each job it posts.
    job_note: u64,
    /// The poller's channels, of slots to manage and of the slots whose
    /// removal job completed; `None` until the first slot is managed and the
    /// poller started.
    poller: Option<Poller>,
    /// The jobs' channel, which the poller and [`Hotplug::post_acpi`] post
    /// on.
    posted: mpsc::Sender<Job>,
    jobs: mpsc::Receiver<Job>,
}

/// The control thread's ends of the poller's channels.
struct Poller
{
    /// The slots to manage.
    slots: mpsc::Sender<Polled>,
    /// The index of each slot whose removal job completed, which the poller
    /// then powers off.
    removed: mpsc::Sender<usize>,
}

impl Hotplug
{
    /// The hotplug slots of `found` devmgr may manage, none managed yet: a
    /// slot whose subtree holds an IOMMU unit's function (a record the IOMMU
    /// pass bound, which `records` holds bound before any other pass runs) is
    /// not, logged; a window that lies outside every boot aperture
    /// (`apertures`, each `(base, end)`) is closed, logged, since no BAR in it
    /// could be carved. `platform_grant` is the matching platform description
    /// table's grant when devmgr knows its tables already (a boot module's
    /// table matched), `None` when it does not yet.
    pub fn new(
        found: Vec<Slot>,
        records: &bind::Records,
        platform_grant: Option<bool>,
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
                held_back: false,
            });
        }
        let (posted, jobs) = mpsc::channel();
        Self {
            candidates,
            platform_grant,
            aspace,
            job_note,
            poller: None,
            posted,
            jobs,
        }
    }

    /// Whether devmgr knows its platform description tables: a boot module's
    /// table matched, or [`Self::set_tables`] has recorded the outcome of the
    /// read from the root filesystem.
    pub const fn tables_known(&self) -> bool
    {
        self.platform_grant.is_some()
    }

    /// Record that devmgr knows its platform description tables, `grant`
    /// being the matching table's `pcie_native_hotplug` (`false` when none
    /// matched). A grant once known is kept.
    #[expect(
        clippy::fn_params_excessive_bools,
        reason = "`grant` is the matching platform description table's `pcie_native_hotplug` value"
    )]
    pub fn set_tables(&mut self, grant: bool)
    {
        if self.platform_grant.is_none()
        {
            self.platform_grant = Some(grant);
        }
    }

    /// Settle each slot whose grant has come ([`hp::slot_grant`]). A slot
    /// whose host bridge's `_OSC` result among `bridges` grants native
    /// hotplug control, or whose platform table does, is managed, the record
    /// of its port held in `records` ([`hp::hold_port`]). A slot whose host
    /// bridge's `_OSC` result withholds it, or failed, is left to the
    /// firmware ([`Grant::Firmware`]), logged, once the platform description
    /// tables are known and grant none; until then it waits, as does a slot
    /// with no `_OSC` result. Either keeps capabilities, so a slot whose grant
    /// has come waits while devmgr's `CSpace` headroom is short and its
    /// top-up refused ([`hp::held_grant`]), logged once, and a later turn
    /// settles it.
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
            let (s, b, _, _) = slot.port;
            let osc = hp::host_bridge(bridges, s, b).and_then(|bridge| bridge.osc);
            let decided = hp::slot_grant(osc, self.platform_grant);
            let settled = hp::held_grant(decided, crate::headroom::hold);
            if settled != decided
            {
                if !candidate.held_back
                {
                    let (_, _, d, f) = slot.port;
                    std::os::seraph::log!(
                        warn: "hotplug: slot {}:{}:{}.{}: CSpace short of its headroom; its grant \
                               waits",
                        s, b, d, f
                    );
                }
                if let Some(candidate) = self.candidates.get_mut(index)
                {
                    candidate.held_back = true;
                }
                continue;
            }
            let grant = match (settled, osc)
            {
                (hp::SlotGrant::Manage(by), _) =>
                {
                    let by = match by
                    {
                        hp::GrantBy::PlatformTable => "the platform table",
                        hp::GrantBy::Osc => "_OSC",
                    };
                    self.manage(index, slot, records, caps, by)
                }
                (hp::SlotGrant::Firmware, Some(osc)) => firmware(slot, osc, records, caps),
                (hp::SlotGrant::Firmware | hp::SlotGrant::Wait, _) => continue,
            };
            if let Some(candidate) = self.candidates.get_mut(index)
            {
                candidate.grant = grant;
            }
        }
    }

    /// Post acpid's job of `event` at the slot of the port `port`, whose
    /// reply goes on `reply` when it ends ([`Hotplug::run`]). A port that is
    /// no slot of the boot scan is answered `NO_DEVICE` here, logged.
    pub fn post_acpi(&self, event: Event, port: Address, reply: mpsc::SyncSender<Reply>)
    {
        let Some(index) = self.candidates.iter().position(|c| c.slot.port == port)
        else
        {
            let (s, b, d, f) = port;
            std::os::seraph::log!(
                warn: "hotplug: acpid's event of port {}:{}:{}.{}: no hotplug slot there",
                s, b, d, f
            );
            let _ = reply.send(Reply::status(errors::NO_DEVICE));
            return;
        };
        let owner = Owner::Acpi(reply);
        let job = match event
        {
            Event::Added => Job::Added(index, owner),
            Event::Removed => Job::Removed(index, owner),
        };
        // The control thread runs the jobs next, after this; a send that
        // fails drops the job's reply, which the worker answers.
        let _ = self.posted.send(job);
    }

    /// Hand slot `index` to the poller, starting the poller with the first,
    /// and hold its port's record and the BAR pages of the functions behind
    /// it ([`hold_behind`]); `by` names the grant in the log line.
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
        let Some(held) = hold_behind(&slot, records, caps)
        else
        {
            let _ = syscall::cap_delete(page);
            std::os::seraph::log!(
                warn: "hotplug: slot {}:{}:{}.{}: the BAR pages of the functions behind it could \
                       not be held; not managed",
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
            behind: behind(&slot, records, caps),
            state: SlotState::Empty,
        };
        let sent = self.poller.as_ref().map(|poller| poller.slots.send(polled));
        if !matches!(sent, Some(Ok(())))
        {
            let _ = syscall::cap_delete(page);
            release(caps, &held);
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

    /// Run every job the poller and acpid posted, in the order they were
    /// posted, each to its end before the next: one slot's removal job posted
    /// while its add job waits runs after it, and withdraws what it bound.
    ///
    /// An add job records the functions behind the slot ([`add`]), then,
    /// once the drivers directory is installed, binds them in a
    /// drivers-directory pass of their own settle batch, the hotplug batch.
    /// Before `SET_DRIVERS_DIR` the functions are only recorded, and its pass
    /// binds them. A removal job withdraws and removes them ([`remove`]),
    /// then posts the slot to the poller, which powers it off.
    ///
    /// acpid's job runs only on a slot the firmware drives, and is refused,
    /// logged, on any other. Its add job records nothing while live records
    /// lie behind the slot, as a device check of a card already recorded
    /// does. Each acpid job ends with its reply: the functions recorded or
    /// removed.
    ///
    /// An add job keeps capabilities, so while devmgr's `CSpace` headroom
    /// is short and its top-up refused it is refused, logged, and records
    /// nothing (`firmware::headroom::hotplug_refusal`): acpid's is answered
    /// `OUT_OF_RESOURCES`, and a managed slot's card stays unrecorded until
    /// its removal. A removal job runs whatever the headroom.
    pub fn run(
        &self,
        registry: &Registry,
        records: &mut bind::Records,
        carve: &mut bind::Carve,
        watch: &mut settle::DriverWatch,
        ipc_buf: *mut u64,
    )
    {
        while let Ok(job) = self.jobs.try_recv()
        {
            // A settle of an earlier job's batch can take the IOMMU driver's
            // death; its restart runs before this job binds or withdraws.
            crate::restart_iommu_if_due(registry, carve, watch, ipc_buf);
            let (index, owner, removal) = match job
            {
                Job::Added(index, owner) => (index, owner, false),
                Job::Removed(index, owner) => (index, owner, true),
            };
            let Some(candidate) = self.candidates.get(index)
            else
            {
                owner.reply(Reply::status(errors::NO_DEVICE));
                continue;
            };
            let (slot, grant) = (candidate.slot, candidate.grant);
            let (s, b, d, f) = slot.port;
            if matches!(owner, Owner::Acpi(_)) && grant != Grant::Firmware
            {
                std::os::seraph::log!(
                    warn: "hotplug: slot {}:{}:{}.{}: acpid's {} refused: the firmware does not \
                           drive the slot ({})",
                    s, b, d, f,
                    if removal { "eject request" } else { "device check" },
                    match grant
                    {
                        Grant::Waiting => "no grant yet",
                        Grant::Managed => "devmgr manages it",
                        Grant::Firmware | Grant::Unmanaged => "not managed",
                    }
                );
                owner.reply(Reply::status(errors::REFUSED));
                continue;
            }
            if removal
            {
                if matches!(owner, Owner::Acpi(_))
                {
                    std::os::seraph::log!(
                        "hotplug: slot {}:{}:{}.{}: removing its functions (the firmware's eject \
                         request)",
                        s,
                        b,
                        d,
                        f
                    );
                }
                let removed = remove(&slot, registry, records, carve.caps, ipc_buf);
                match owner
                {
                    Owner::Native =>
                    {
                        // The slot is powered off whatever the job found, so
                        // the poller never holds it removing.
                        let sent = self.poller.as_ref().map(|p| p.removed.send(index));
                        if !matches!(sent, Some(Ok(())))
                        {
                            std::os::seraph::log!(
                                warn: "hotplug: no poller to power off a removed slot"
                            );
                        }
                    }
                    Owner::Acpi(_) =>
                    {
                        owner.reply(Reply::success(
                            &[u64::try_from(removed).unwrap_or(u64::MAX)],
                        ));
                    }
                }
                continue;
            }
            run_add(&slot, &owner, registry, records, carve, watch, ipc_buf);
        }
    }
}

/// Run the add job of `slot`, posted by `owner`, to its reply
/// ([`Hotplug::run`]): an acpid job records nothing while live records lie
/// behind the slot, and any add job is refused, recording nothing, while
/// devmgr's `CSpace` headroom is short and its top-up refused
/// (`firmware::headroom::hotplug_refusal`); else [`add`], then
/// [`bind_added`] when it recorded a function.
fn run_add(
    slot: &Slot,
    owner: &Owner,
    registry: &Registry,
    records: &mut bind::Records,
    carve: &mut bind::Carve,
    watch: &mut settle::DriverWatch,
    ipc_buf: *mut u64,
)
{
    let (s, b, d, f) = slot.port;
    if matches!(owner, Owner::Acpi(_))
    {
        if records.live_pci().any(|r| slot.holds(address(r)))
        {
            std::os::seraph::log!(
                "hotplug: slot {}:{}:{}.{}: the firmware reports a card, whose functions \
                 are recorded; nothing added",
                s,
                b,
                d,
                f
            );
            owner.reply(Reply::success(&[0]));
            return;
        }
        std::os::seraph::log!(
            "hotplug: slot {}:{}:{}.{}: card added (the firmware's device check)",
            s,
            b,
            d,
            f
        );
    }
    if let Some(code) = firmware::headroom::hotplug_refusal(devmgr_labels::HOTPLUG_ADDED)
        && !crate::headroom::hold()
    {
        std::os::seraph::log!(
            warn: "hotplug: slot {}:{}:{}.{}: CSpace short of its headroom; card not \
                   added, nothing recorded",
            s, b, d, f
        );
        owner.reply(Reply::status(code));
        return;
    }
    let added = add(slot, records, carve.caps);
    if added > 0
    {
        bind_added(registry, records, carve, watch, ipc_buf);
    }
    owner.reply(Reply::success(&[u64::try_from(added).unwrap_or(u64::MAX)]));
}

/// Bind the functions an add job recorded, in a drivers-directory pass of
/// their own settle batch, the hotplug batch, once the drivers directory is
/// installed; before `SET_DRIVERS_DIR` its pass binds them.
fn bind_added(
    registry: &Registry,
    records: &mut bind::Records,
    carve: &mut bind::Carve,
    watch: &mut settle::DriverWatch,
    ipc_buf: *mut u64,
)
{
    let (dir, dir_path) = {
        let state = registry.lock();
        (state.drivers_dir_cap, state.drivers_dir_path)
    };
    if dir == 0
    {
        std::os::seraph::log!(
            "hotplug: drivers directory not installed; its pass binds the functions added"
        );
        return;
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

/// Leave `slot` to the firmware, its host bridge's `_OSC` result `osc`
/// withholding native hotplug control or failed: hold the BAR pages of the
/// functions behind it ([`hold_behind`]), as for a managed slot, so no
/// placement of a later add job lands on them, and log the grant.
/// [`Grant::Unmanaged`], logged, when the pages cannot be held. The poller
/// never watches the slot, and devmgr writes none of the port's registers.
fn firmware(slot: Slot, osc: Osc, records: &bind::Records, caps: &mut caps::DevmgrCaps) -> Grant
{
    let (s, b, d, f) = slot.port;
    if hold_behind(&slot, records, caps).is_none()
    {
        std::os::seraph::log!(
            warn: "hotplug: slot {}:{}:{}.{}: the BAR pages of the functions behind it could not \
                   be held; not managed",
            s, b, d, f
        );
        return Grant::Unmanaged;
    }
    if osc.evaluated
    {
        std::os::seraph::log!(
            "hotplug: slot {}:{}:{}.{}: firmware hotplug: _OSC control {:#x} withholds native \
             hotplug; acpid posts its events",
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
            "hotplug: slot {}:{}:{}.{}: firmware hotplug: _OSC failed, status {:#x}; acpid posts \
             its events",
            s,
            b,
            d,
            f,
            osc.status
        );
    }
    Grant::Firmware
}

/// Start the poller thread, which owns the managed slots it is sent; its
/// channels, or `None`, logged, when the thread cannot be started.
fn start_poller(posted: mpsc::Sender<Job>, job_note: u64, aspace: u64) -> Option<Poller>
{
    let (sender, slots) = mpsc::channel::<Polled>();
    let (removed, completions) = mpsc::channel::<usize>();
    let started = std::thread::Builder::new()
        .name("hotplug".into())
        .spawn_at_priority(ipc::sched_policy::DEVMGR_PRIORITY, move || {
            poll_loop(&slots, &completions, &posted, job_note, aspace);
        });
    if started.is_err()
    {
        std::os::seraph::log!(warn: "hotplug: poller thread not started; no slot is managed");
        return None;
    }
    Some(Poller {
        slots: sender,
        removed,
    })
}

/// The poller: take over each slot as it arrives, power off each slot whose
/// removal job completed ([`power_off`]), then every
/// [`hp::HOTPLUG_POLL_MS`] read and act on each managed slot's Slot Status.
fn poll_loop(
    slots: &mpsc::Receiver<Polled>,
    completions: &mpsc::Receiver<usize>,
    posted: &mpsc::Sender<Job>,
    job_note: u64,
    aspace: u64,
) -> !
{
    let mut managed: Vec<Polled> = Vec::new();
    loop
    {
        while let Ok(index) = completions.try_recv()
        {
            if let Some(slot) = managed.iter_mut().find(|s| s.index == index)
            {
                power_off(slot, aspace);
            }
        }
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
/// latches instead), clear its latches, and hold it as what lay behind it
/// when it was managed ([`hp::initial`]): the first poll removes a recorded
/// card that left before take-over, removes and then adds a card that
/// replaced it, and brings up an unrecorded card present.
fn take_over(slot: &mut Polled, aspace: u64)
{
    let s = slot.slot;
    // A port that cannot be mapped is logged by `with_port`; its state is
    // still the records'.
    let _ = with_port(slot, aspace, |regs| {
        let control = regs.read16(s.register(SLOT_CONTROL));
        set_control(regs, &s, control, control & !SLOTCTL_EVENT_ENABLES);
        let status = regs.read16(s.register(SLOT_STATUS));
        clear_latches(regs, &s, status);
    });
    slot.state = hp::initial(slot.behind);
}

/// Read a managed slot's Slot Status, clear the latches it holds, and act
/// on it ([`hp::next`]), reading Link Status as well when Data Link Layer
/// State Changed is latched on a slot that reports its link.
fn poll(slot: &mut Polled, aspace: u64, posted: &mpsc::Sender<Job>, job_note: u64)
{
    let s = slot.slot;
    let (seg, b, d, f) = s.port;
    let current = slot.state;
    let post = |job: Job| {
        if posted.send(job).is_ok()
        {
            let _ = syscall::notification_send(job_note, 1);
        }
    };
    let state = with_port(slot, aspace, |regs| {
        let status = regs.read16(s.register(SLOT_STATUS));
        clear_latches(regs, &s, status);
        let link_down = s.link_reporting && hp::link_changed(status) && {
            let link = regs.read16(s.register(LINK_STATUS));
            link != u16::MAX && link & LINK_ACTIVE == 0
        };
        let (state, action) = hp::next(current, status, link_down);
        let control = || regs.read16(s.register(SLOT_CONTROL));
        match action
        {
            Action::None => state,
            Action::Blink =>
            {
                std::os::seraph::log!(
                    "hotplug: slot {}:{}:{}.{}: attention button pressed; removal in {} ms \
                     unless pressed again",
                    seg,
                    b,
                    d,
                    f,
                    hp::ABORT_POLLS.saturating_mul(hp::HOTPLUG_POLL_MS)
                );
                set_control(regs, &s, control(), hp::blink(control(), s.capabilities));
                state
            }
            Action::Cancel =>
            {
                std::os::seraph::log!(
                    "hotplug: slot {}:{}:{}.{}: attention button pressed again; removal cancelled",
                    seg,
                    b,
                    d,
                    f
                );
                set_control(
                    regs,
                    &s,
                    control(),
                    hp::indicator_on(control(), s.capabilities),
                );
                state
            }
            Action::Remove =>
            {
                std::os::seraph::log!(
                    "hotplug: slot {}:{}:{}.{}: removing its functions ({})",
                    seg,
                    b,
                    d,
                    f,
                    hp::removal_cause(current, status, link_down)
                );
                post(Job::Removed(slot.index, Owner::Native));
                state
            }
            Action::PowerUp if power_up(regs, &s) =>
            {
                std::os::seraph::log!("hotplug: slot {}:{}:{}.{}: card added", seg, b, d, f);
                post(Job::Added(slot.index, Owner::Native));
                SlotState::Occupied
            }
            Action::PowerUp =>
            {
                std::os::seraph::log!(
                    warn: "hotplug: slot {}:{}:{}.{}: card present but its link did not come up; \
                           slot powered off until the card is removed",
                    seg, b, d, f
                );
                let control = control();
                set_control(regs, &s, control, hp::power_off(control, s.capabilities));
                SlotState::Failed
            }
        }
    });
    if let Some(state) = state
    {
        slot.state = state;
    }
}

/// Power off a slot whose removal job completed: the power controller off,
/// then the power indicator off, two Slot Control writes, so a slot that
/// acts on the write leaving both off (QEMU's) does so once the controller
/// is off. The slot is then off while the card the removal removed is
/// present, else empty, a card inserted or asked for meanwhile powered up
/// on the next poll ([`hp::completed`]), its latches cleared.
fn power_off(slot: &mut Polled, aspace: u64)
{
    let s = slot.slot;
    let (seg, b, d, f) = s.port;
    let current = slot.state;
    let state = with_port(slot, aspace, |regs| {
        let control = regs.read16(s.register(SLOT_CONTROL));
        let off = hp::power_controller_off(control, s.capabilities);
        set_control(regs, &s, control, off);
        set_control(regs, &s, off, hp::indicator_off(off, s.capabilities));
        let status = regs.read16(s.register(SLOT_STATUS));
        clear_latches(regs, &s, status);
        (hp::completed(current, status), hp::present(status))
    });
    let (state, present) = state.unwrap_or_else(|| (hp::completed(current, u16::MAX), false));
    std::os::seraph::log!(
        "hotplug: slot {}:{}:{}.{}: powered off ({})",
        seg,
        b,
        d,
        f,
        if state == SlotState::Off
        {
            "card still present"
        }
        else if present
        {
            "a card inserted or asked for meanwhile; powering it up"
        }
        else
        {
            "empty"
        }
    );
    slot.state = state;
}

/// Write Slot Control `value` ([`write_control`]) when it differs from
/// `control`, the value read, and the port answered.
fn set_control(regs: &ConfigRegs, slot: &Slot, control: u16, value: u16)
{
    if control != u16::MAX && value != control
    {
        write_control(regs, slot, value);
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
    set_control(
        regs,
        slot,
        control,
        hp::power_on(control, slot.capabilities),
    );
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
/// requests to device 0 only), place its MMIO BARs in the ranges of the
/// slot's windows the apertures still hold ([`hp::free_ranges`]), program
/// them, and admit it ([`admit`]). A type-1 function is logged and not
/// descended into; a function whose BARs do not fit, or do not read back as
/// programmed, is logged and not recorded, so no driver is bound to it, and
/// the apertures are as they were. Returns the number of records appended.
fn add(slot: &Slot, records: &mut bind::Records, caps: &mut caps::DevmgrCaps) -> usize
{
    let (segment, bus) = (slot.port.0, slot.secondary);
    let mut appended = 0usize;
    let mut functions = 1u8;
    let mut func = 0u8;
    while func < functions
    {
        let mut free = Vec::new();
        if hp::free_ranges(caps.apertures.spans(), slot, &mut free).is_err()
        {
            std::os::seraph::log!(
                warn: "hotplug: bus {}:{}: no memory for the free ranges; nothing more added",
                segment, bus
            );
            break;
        }
        let found = with_function(caps, (segment, bus, 0, func), |cfg| {
            let found = hp::place(cfg, slot, (bus, 0, func), &free);
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
                if admit(device, (segment, bus, 0, func), records, caps)
                {
                    appended = appended.saturating_add(1);
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

/// Admit the function `device` at `at`, its BARs placed and programmed: hold
/// its BAR pages, moving each page span ([`hp::bar_spans`]) out of the
/// apertures into the held BAR pages ([`caps::DevmgrCaps::slot_bars`]),
/// where a bind carves them and no region grant or later placement reaches
/// them, then append its record ([`hp::admit`]). A type-1 function holds
/// nothing and is not recorded. Pages that cannot be held, or whose record
/// is refused, are returned to the apertures, logged, the function not
/// recorded. Returns whether its record was appended.
fn admit(
    device: PciDevice,
    at: Address,
    records: &mut bind::Records,
    caps: &mut caps::DevmgrCaps,
) -> bool
{
    let (segment, bus, _, func) = at;
    let (vendor, id) = (device.vendor_id, device.device_id);
    let mut spans = [(0u64, 0u64); MAX_BARS];
    let mut count = 0usize;
    if device.bridge_buses.is_none()
    {
        for (to, span) in spans.iter_mut().zip(hp::bar_spans(&device))
        {
            *to = span;
            count = count.saturating_add(1);
        }
    }
    let spans = spans.get(..count).unwrap_or(&[]);
    if let Err(e) = caps.apertures.move_all(
        &mut caps.slot_bars,
        spans,
        PAGE_SIZE,
        crate::split_mmio,
        crate::merge_mmio,
    )
    {
        std::os::seraph::log!(
            warn: "hotplug: {}:{}:0.{} {:04x}:{:04x}: BAR pages not held ({:?}); not recorded, no \
                   driver",
            segment, bus, func, vendor, id, e
        );
        return false;
    }
    match hp::admit(device, |d| records.pci.append(d))
    {
        Admission::Appended(index) =>
        {
            std::os::seraph::log!(
                "hotplug: {}:{}:0.{} {:04x}:{:04x} recorded as PCI record {}",
                segment,
                bus,
                func,
                vendor,
                id,
                index
            );
            true
        }
        Admission::Bridge =>
        {
            std::os::seraph::log!(
                warn: "hotplug: {}:{}:0.{} {:04x}:{:04x} is a bridge; not descended into",
                segment, bus, func, vendor, id
            );
            false
        }
        Admission::Refused(e) =>
        {
            release(caps, spans);
            std::os::seraph::log!(
                warn: "hotplug: {}:{}:0.{} {:04x}:{:04x} not recorded: {}",
                segment, bus, func, vendor, id, hp::refusal(e)
            );
            false
        }
    }
}

/// Hold the BAR pages of the functions behind `slot` that the apertures
/// still hold: move the part of the page span ([`hp::bar_spans`]) of each
/// MMIO BAR of each live record behind it that each aperture cap covers out
/// of the apertures into the held BAR pages
/// ([`caps::DevmgrCaps::slot_bars`]), so no placement in the slot's windows,
/// which takes only what the apertures hold, lands on them, and a bind
/// carves them from there. A bound function's BARs were carved at its bind,
/// whole or up to what its driver maps, so only what its bind left is moved.
/// Returns the ranges held, or `None`, none held, when the moves fail.
fn hold_behind(
    slot: &Slot,
    records: &bind::Records,
    caps: &mut caps::DevmgrCaps,
) -> Option<Vec<(u64, u64)>>
{
    let mut held: Vec<(u64, u64)> = Vec::new();
    for device in records.live_pci().filter(|d| slot.holds(address(d)))
    {
        for (base, len) in hp::bar_spans(device)
        {
            let end = base.saturating_add(len);
            for s in caps.apertures.spans()
            {
                let (from, to) = (s.base.max(base), s.end.min(end));
                // BARs that share a page share its span, held once.
                let taken = held
                    .iter()
                    .any(|&(b, l)| b < to && from < b.saturating_add(l));
                if from < to && !taken
                {
                    held.try_reserve(1).ok()?;
                    held.push((from, to.saturating_sub(from)));
                }
            }
        }
    }
    caps.apertures
        .move_all(
            &mut caps.slot_bars,
            &held,
            PAGE_SIZE,
            crate::split_mmio,
            crate::merge_mmio,
        )
        .ok()?;
    Some(held)
}

/// Return the held BAR pages `spans`, each a span [`hold_behind`] or
/// [`add`] moved whole, from [`caps::DevmgrCaps::slot_bars`] to the
/// apertures, each merged there with the spans beside it
/// ([`crate::merge_mmio`]). Moved back whole, a span splits nothing; one the
/// apertures cannot grow to hold stays held, logged, where only a bind
/// reaches it.
fn release(caps: &mut caps::DevmgrCaps, spans: &[(u64, u64)])
{
    let mut kept = 0usize;
    for &(base, size) in spans
    {
        let returned = caps.slot_bars.move_merged(
            &mut caps.apertures,
            base,
            size,
            PAGE_SIZE,
            |_, _| Err(SplitError::Failed),
            crate::merge_mmio,
        );
        if returned.is_err()
        {
            kept = kept.saturating_add(1);
        }
    }
    if kept > 0
    {
        std::os::seraph::log!(
            warn: "hotplug: {} held BAR spans not returned; they stay held",
            kept
        );
    }
}

/// The removal job of `slot` ([`hp::remove`]): withdraw the driver of each
/// live record behind it ([`Registry::withdraw_at`]), its device's BAR caps
/// given back to the held BAR pages; quiesce each function
/// ([`hp::quiesce`]); return the held BAR pages inside their BARs to the
/// apertures, whole, each merged there with the spans beside it
/// ([`crate::merge_mmio`]); mark the records removed; and return each removed
/// record's instance to its driver's instance limit
/// ([`bind::Records::release_removed`]). A driver that does not answer
/// cannot delay it: a withdrawal asks the driver nothing. Returns the number
/// of records removed.
fn remove(
    slot: &Slot,
    registry: &Registry,
    records: &mut bind::Records,
    caps: &mut caps::DevmgrCaps,
    ipc_buf: *mut u64,
) -> usize
{
    let (s, b, d, f) = slot.port;
    let mut held = core::mem::take(&mut caps.slot_bars);
    let mut free = core::mem::take(&mut caps.apertures);
    let mut withdrawn = 0usize;
    let removal = hp::remove(
        slot,
        &mut records.pci,
        &mut held,
        &mut free,
        |at, held: &mut SpanTable<u64>| {
            if registry.withdraw_at(at, held, ipc_buf)
            {
                withdrawn = withdrawn.saturating_add(1);
            }
        },
        |at| {
            let (_, bus, dev, func) = at;
            let _ = with_function(caps, at, |cfg| hp::quiesce(cfg, (bus, dev, func)));
        },
        crate::merge_mmio,
    );
    caps.slot_bars = held;
    caps.apertures = free;
    records.release_removed();
    let returned = match removal.returned
    {
        Ok(returned) => returned,
        Err((returned, error)) =>
        {
            std::os::seraph::log!(
                warn: "hotplug: slot {}:{}:{}.{}: held BAR pages not all returned ({:?}); the \
                       rest stay held",
                s, b, d, f, error
            );
            returned
        }
    };
    std::os::seraph::log!(
        "hotplug: slot {}:{}:{}.{}: functions removed: {}, drivers withdrawn: {}, held BAR spans \
         returned: {}",
        s,
        b,
        d,
        f,
        removal.functions,
        withdrawn,
        returned
    );
    removal.functions
}

/// What lies behind `slot` as it is managed: nothing when no live record
/// does; replaced, logged, when a recorded function no longer reads as its
/// record ([`hp::same_function`]), its card removed or replaced while the
/// slot's grant waited; else recorded. A function whose configuration page
/// cannot be read is taken as recorded.
fn behind(slot: &Slot, records: &bind::Records, caps: &mut caps::DevmgrCaps) -> hp::Behind
{
    let mut behind = hp::Behind::Nothing;
    for record in records.live_pci().filter(|r| slot.holds(address(r)))
    {
        let at = address(record);
        if with_function(caps, at, |cfg| hp::same_function(cfg, record)) == Some(false)
        {
            let (s, b, d, f) = slot.port;
            std::os::seraph::log!(
                "hotplug: slot {}:{}:{}.{}: {}:{}:{}.{} {:04x}:{:04x} no longer reads as \
                 recorded; its card is removed, and a card present then added",
                s,
                b,
                d,
                f,
                at.0,
                at.1,
                at.2,
                at.3,
                record.vendor_id,
                record.device_id
            );
            return hp::Behind::Replaced;
        }
        behind = hp::Behind::Recorded;
    }
    behind
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
