// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 George Kottler <mail@kottlerg.com>

// services/devmgr/src/acpi.rs

//! acpid's requests (services/acpid/README.md § Region grants and § Checks).
//!
//! `QUERY_ACPI_RESOURCES` of a fixed register block is answered on the
//! registry worker that receives it, from the FADT alone. Every other
//! request, the `QUERY_ACPI_RESOURCES` of the SCI, of `RESET_REG` and of
//! the sleep registers among them ([`on_control`]), runs on the control thread,
//! which owns the device records, the apertures, the interrupt lines and
//! the configuration space: the worker posts it as a [`Job`], signals the control thread, and
//! replies with what it hands back, so a region grant, a configuration
//! access or a push is decided against records no bind changes meanwhile,
//! with no lock beyond the ones devmgr already has. A request waits while the
//! control thread runs a pass and its settle.
//!
//! A job runs to its end whatever happens to acpid: a reply that fails
//! deletes only the copy it carried, and a memory grant stays kept for a
//! restarted acpid ([`firmware::acpid::Grants`]).
//!
//! An `ACPI_HOTPLUG` job is the one the control thread does not answer
//! here: it is handed to the hotplug slots ([`crate::hotplug::Hotplug::post_acpi`]),
//! whose add or removal job replies when it ends.

use std::sync::mpsc;

use firmware::acpi::{FixedRegister, ResetRegister, SleepRegister};
use firmware::acpid::{
    Address, ConfigAccess, ConfigError, ConfigOp, Disagreement, Grants, Osc, PrtMode, PrtTable,
    Push, Range, Space, Window,
};
use firmware::resource::CarveError;
use ipc::IpcMessage;
use ipc::devmgr_errors as errors;
use ipc::devmgr_labels as labels;

use crate::caps::{DevmgrCaps, Firmware};
use crate::hotplug::{Event, Hotplug};
use crate::{IrqRangeAllocator, arch, bind, reply_status, tables};

/// The data words of the longest reply, `QUERY_HOST_BRIDGE`'s.
const REPLY_WORDS: usize = 9;

/// One acpid request the control thread runs, decoded.
pub enum Request
{
    /// `ACPI_REGION_GRANT`.
    Region
    {
        space: Space, base: u64, len: u64
    },
    /// `ACPI_PCI_CONFIG`.
    Config
    {
        op: ConfigOp,
        function: Address,
        offset: u64,
        width: u64,
        value: u64,
    },
    /// `OSC_RESULT`.
    Osc
    {
        segment: u16,
        bus: u8,
        osc: Osc,
        asked: u32,
    },
    /// `BRIDGE_WINDOWS`.
    Windows
    {
        segment: u16,
        bus: u8,
        windows: Vec<Window>,
    },
    /// `PRT_TABLE`.
    Prt
    {
        segment: u16,
        bus: u8,
        mode: PrtMode,
        table: Box<PrtTable>,
    },
    /// `QUERY_HOST_BRIDGE`.
    HostBridge
    {
        ordinal: u64
    },
    /// `QUERY_ACPI_RESOURCES` of `ACPI_SCI`.
    Sci,
    /// `QUERY_ACPI_RESOURCES` of `ACPI_SLEEP_CONTROL` or
    /// `ACPI_SLEEP_STATUS`.
    Sleep(SleepRegister),
    /// `QUERY_ACPI_RESOURCES` of `ACPI_RESET`.
    Reset,
    /// `ACPI_HOTPLUG`: `event` at the slot of the port at `port`.
    Hotplug
    {
        event: Event, port: Address
    },
}

/// What the control thread hands back for a worker to reply with.
pub struct Reply
{
    label: u64,
    words: [u64; REPLY_WORDS],
    count: usize,
    cap: Option<u64>,
}

impl Reply
{
    /// A reply of `label` with no data and no cap.
    pub(crate) fn status(label: u64) -> Self
    {
        Self {
            label,
            words: [0; REPLY_WORDS],
            count: 0,
            cap: None,
        }
    }

    /// A `SUCCESS` reply of `words`.
    pub(crate) fn success(words: &[u64]) -> Self
    {
        let mut reply = Self::status(errors::SUCCESS);
        for (slot, &word) in reply.words.iter_mut().zip(words)
        {
            *slot = word;
            reply.count = reply.count.saturating_add(1);
        }
        reply
    }

    /// A `SUCCESS` reply granting `cap` over `range`: its base and length.
    fn granted(range: &Range, cap: u64) -> Self
    {
        let mut reply = Self::success(&[range.base, range.len()]);
        reply.cap = Some(cap);
        reply
    }
}

/// A request posted to the control thread and the channel its reply goes
/// back on.
pub struct Job
{
    request: Request,
    reply: mpsc::SyncSender<Reply>,
}

/// The worker's end of the control thread's job channel.
pub type Jobs = mpsc::Sender<Job>;

/// Decode an acpid request a worker posts to the control thread, its gate
/// and version checked. `Err` with the reply label otherwise:
/// `INVALID_REQUEST` for a malformed request, `UNKNOWN_OPCODE` for a label
/// that is not one.
pub fn decode(msg: &IpcMessage) -> Result<Request, u64>
{
    let invalid = errors::INVALID_REQUEST;
    let bridge = |msg: &IpcMessage| {
        Ok::<_, u64>((
            u16::try_from(msg.word(1)).map_err(|_| invalid)?,
            u8::try_from(msg.word(2)).map_err(|_| invalid)?,
        ))
    };
    let dword = |word: u64| u32::try_from(word).map_err(|_| invalid);
    if firmware::acpid::request_words(msg.label, msg.word(3)).is_some_and(|n| msg.word_count() < n)
    {
        return Err(invalid);
    }
    Ok(match msg.label
    {
        labels::ACPI_REGION_GRANT => Request::Region {
            space: match msg.word(1)
            {
                labels::ACPI_SPACE_MEMORY => Space::Memory,
                labels::ACPI_SPACE_IO => Space::Io,
                _ => return Err(invalid),
            },
            base: msg.word(2),
            len: msg.word(3),
        },
        labels::ACPI_PCI_CONFIG => Request::Config {
            op: match msg.word(1)
            {
                labels::ACPI_CONFIG_READ => ConfigOp::Read,
                labels::ACPI_CONFIG_WRITE => ConfigOp::Write,
                _ => return Err(invalid),
            },
            function: unpack_function(msg.word(2)).ok_or(invalid)?,
            offset: msg.word(3),
            width: msg.word(4),
            value: msg.word(5),
        },
        labels::OSC_RESULT =>
        {
            let (segment, bus) = bridge(msg)?;
            let evaluated = match msg.word(3)
            {
                0 => false,
                1 => true,
                _ => return Err(invalid),
            };
            Request::Osc {
                segment,
                bus,
                osc: Osc {
                    evaluated,
                    status: dword(msg.word(4))?,
                    control: dword(msg.word(5))?,
                },
                asked: dword(msg.word(6))?,
            }
        }
        labels::BRIDGE_WINDOWS =>
        {
            let (segment, bus) = bridge(msg)?;
            let count = usize::try_from(msg.word(3))
                .ok()
                .filter(|&c| c <= labels::MAX_BRIDGE_WINDOWS)
                .ok_or(invalid)?;
            let words: Vec<u64> = (0..count.saturating_mul(3))
                .map(|i| msg.word(i.saturating_add(4)))
                .collect();
            Request::Windows {
                segment,
                bus,
                windows: firmware::acpid::windows_from_words(&words).ok_or(invalid)?,
            }
        }
        labels::PRT_TABLE =>
        {
            let (segment, bus) = bridge(msg)?;
            let mode = match msg.word(3)
            {
                labels::PRT_ROUTES => PrtMode::Routes,
                labels::PRT_PIC_MODE => PrtMode::PicMode,
                _ => return Err(invalid),
            };
            let words: Vec<u64> = (4..labels::PRT_TABLE_WORDS).map(|i| msg.word(i)).collect();
            Request::Prt {
                segment,
                bus,
                mode,
                table: Box::new(firmware::acpid::prt_from_words(&words).ok_or(invalid)?),
            }
        }
        labels::QUERY_HOST_BRIDGE => Request::HostBridge {
            ordinal: msg.word(1),
        },
        labels::QUERY_ACPI_RESOURCES => resources_request(msg.word(1)).ok_or(invalid)?,
        labels::ACPI_HOTPLUG => hotplug_request(msg)?,
        _ => return Err(errors::UNKNOWN_OPCODE),
    })
}

/// The `QUERY_ACPI_RESOURCES` the control thread serves, by its `data[1]`;
/// `None` for one a registry worker answers or none.
fn resources_request(which: u64) -> Option<Request>
{
    match which
    {
        labels::ACPI_SCI => Some(Request::Sci),
        labels::ACPI_RESET => Some(Request::Reset),
        labels::ACPI_SLEEP_CONTROL => Some(Request::Sleep(SleepRegister::Control)),
        labels::ACPI_SLEEP_STATUS => Some(Request::Sleep(SleepRegister::Status)),
        _ => None,
    }
}

/// `ACPI_HOTPLUG`, decoded; `Err(INVALID_REQUEST)` for an unknown event or
/// a malformed address.
fn hotplug_request(msg: &IpcMessage) -> Result<Request, u64>
{
    let event = match msg.word(1)
    {
        labels::HOTPLUG_ADDED => Event::Added,
        labels::HOTPLUG_REMOVED => Event::Removed,
        _ => return Err(errors::INVALID_REQUEST),
    };
    let port = unpack_function(msg.word(2)).ok_or(errors::INVALID_REQUEST)?;
    Ok(Request::Hotplug { event, port })
}

/// The address `labels::pci_function` packed into `word`; `None` when a
/// bit above the segment is set.
fn unpack_function(word: u64) -> Option<Address>
{
    if word >> 32 != 0
    {
        return None;
    }
    let field = |shift: u32, mask: u64| (word >> shift) & mask;
    Some((
        u16::try_from(field(16, 0xFFFF)).ok()?,
        u8::try_from(field(8, 0xFF)).ok()?,
        u8::try_from(field(3, 0x1F)).ok()?,
        u8::try_from(field(0, 0x7)).ok()?,
    ))
}

/// Post `request` to the control thread through `jobs`, wake it with
/// `signal`, wait for its reply, and send that on this worker's IPC buffer
/// `ipc_buf`. A reply that fails deletes the cap it carried, a copy of
/// what devmgr keeps. Replies `INVALID_REQUEST` when the control thread
/// cannot take the job.
pub fn run_on_control(jobs: &Jobs, signal: impl FnOnce(), request: Request, ipc_buf: *mut u64)
{
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if jobs
        .send(Job {
            request,
            reply: reply_tx,
        })
        .is_err()
    {
        reply_status(errors::INVALID_REQUEST, ipc_buf);
        return;
    }
    signal();
    let Ok(reply) = reply_rx.recv()
    else
    {
        reply_status(errors::INVALID_REQUEST, ipc_buf);
        return;
    };
    let mut message = IpcMessage::builder(reply.label);
    for (i, &word) in reply.words.iter().take(reply.count).enumerate()
    {
        message = message.word(i, word);
    }
    if let Some(cap) = reply.cap
    {
        message = message.cap(cap);
    }
    // SAFETY: ipc_buf is this worker's registered IPC buffer.
    if unsafe { ipc::ipc_reply(&message.build(), ipc_buf) }.is_err()
        && let Some(cap) = reply.cap
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// Whether `QUERY_ACPI_RESOURCES` of `block` runs on the control thread: the
/// SCI, whose line the control thread holds, and `RESET_REG` and the sleep
/// registers, whose memory page it keeps beside the region grants
/// (`AcpiService::memory_cap`), since one page can hold them and an
/// operation region. The worker answers every other block
/// ([`query_resources`]).
pub const fn on_control(block: u64) -> bool
{
    matches!(
        block,
        labels::ACPI_SCI
            | labels::ACPI_RESET
            | labels::ACPI_SLEEP_CONTROL
            | labels::ACPI_SLEEP_STATUS
    )
}

/// `QUERY_ACPI_RESOURCES`, past its gate and version check: reply with a
/// narrow `IoPort` over the FADT's fixed register block `msg` names, its
/// first port, its port count, the value the FADT gives with it and its
/// space, the I/O space.
pub fn query_resources(firmware: &Firmware, msg: &IpcMessage, ipc_buf: *mut u64)
{
    use firmware::acpi::FadtBlock;
    let block = match msg.word(1)
    {
        labels::ACPI_PM1A_EVT => FadtBlock::Pm1aEvt,
        labels::ACPI_PM1A_CNT => FadtBlock::Pm1aCnt,
        labels::ACPI_GPE0 => FadtBlock::Gpe0,
        labels::ACPI_SMI_CMD => FadtBlock::SmiCmd,
        _ =>
        {
            reply_status(errors::INVALID_REQUEST, ipc_buf);
            return;
        }
    };
    let Some((cap, io)) = arch::current::acpi_io_block(firmware, block)
    else
    {
        reply_status(errors::NO_DEVICE, ipc_buf);
        return;
    };
    let reply = IpcMessage::builder(errors::SUCCESS)
        .word(0, u64::from(io.port))
        .word(1, u64::from(io.count))
        .word(2, u64::from(io.value))
        .word(3, labels::ACPI_SPACE_IO)
        .cap(cap)
        .build();
    // SAFETY: ipc_buf is this worker's registered IPC buffer.
    if unsafe { ipc::ipc_reply(&reply, ipc_buf) }.is_err()
    {
        let _ = syscall::cap_delete(cap);
    }
}

/// The ranges the kernel owns: the register window of each interrupt
/// controller the MADT describes, rounded out to pages, and the ports of
/// [`arch::current::kernel_ports`].
fn kernel_ranges(firmware: &Firmware) -> Vec<Range>
{
    let windows = tables::locate_table_by_sig(firmware, *b"APIC")
        .and_then(|madt| {
            tables::with_acpi_table(firmware, madt, |bytes| {
                firmware::acpi::madt_interrupt_controllers(bytes).map(Iterator::collect::<Vec<_>>)
            })
        })
        .unwrap_or_default();
    windows
        .into_iter()
        .filter_map(|(base, len)| firmware::acpid::grant_range(Space::Memory, base, len))
        .chain(arch::current::kernel_ports())
        .collect()
}

/// The control thread's side of acpid: the job channel's receiving end and
/// the state its requests are decided against.
pub struct AcpiService
{
    jobs: mpsc::Receiver<Job>,
    grants: Grants<u64>,
    bridges: firmware::acpid::Bridges,
    /// The apertures devmgr was given at boot, `(base, end)`, before any
    /// carve: the memory a bridge's BARs must lie in.
    boot_apertures: Vec<(u64, u64)>,
    /// The interrupt controllers the MADT describes and the ports the kernel
    /// owns, which no grant reaches.
    kernel: Vec<Range>,
    /// The FACS, which no grant reaches.
    facs: Option<Range>,
    /// The FADT's `SCI_INT`, `None` when it names no SCI
    /// (`firmware::acpi::fadt_sci_int`).
    sci_int: Option<u16>,
    /// Whether devmgr has served acpid the SCI in this boot, so a later
    /// request comes from a restarted acpid.
    sci_served: bool,
    /// The FADT's `SLEEP_CONTROL_REG` and `SLEEP_STATUS_REG`, `None` each
    /// when the FADT is not hardware-reduced or names no usable register
    /// (`firmware::acpi::fadt_sleep_register`).
    sleep: [Option<FixedRegister>; 2],
    /// The FADT's `RESET_REG` and `RESET_VALUE`, `None` when it names no
    /// usable one (`firmware::acpi::fadt_reset_register`).
    reset: Option<ResetRegister>,
}

impl AcpiService
{
    /// The service over `jobs`, made before devmgr carves anything from
    /// `caps`, so it records the apertures as init gave them. Logs where the
    /// FADT places the FACS, and whether an ACPI region devmgr holds covers
    /// it.
    pub fn new(caps: &DevmgrCaps, jobs: mpsc::Receiver<Job>) -> Self
    {
        let firmware: &Firmware = &caps.firmware;
        let boot_apertures = caps
            .apertures
            .spans()
            .iter()
            .map(|span| (span.base, span.end))
            .collect();
        let facs_phys = tables::locate_table_by_sig(firmware, *b"FACP").and_then(|fadt| {
            tables::with_acpi_table(firmware, fadt, firmware::acpi::fadt_facs_phys)
        });
        let sci_int = tables::locate_table_by_sig(firmware, *b"FACP")
            .and_then(|fadt| tables::with_acpi_table(firmware, fadt, firmware::acpi::fadt_sci_int));
        let sleep = [SleepRegister::Control, SleepRegister::Status].map(|register| {
            tables::locate_table_by_sig(firmware, *b"FACP").and_then(|fadt| {
                tables::with_acpi_table(firmware, fadt, |bytes| {
                    firmware::acpi::fadt_sleep_register(bytes, register)
                })
            })
        });
        let reset = tables::locate_table_by_sig(firmware, *b"FACP").and_then(|fadt| {
            tables::with_acpi_table(firmware, fadt, firmware::acpi::fadt_reset_register)
        });
        let facs = facs_phys.and_then(|base| {
            firmware::acpid::grant_range(Space::Memory, base, firmware::acpi::FACS_MIN_LEN)
        });
        match facs_phys
        {
            Some(base) => std::os::seraph::log!(
                "FACS at {:#x}: {}",
                base,
                if tables::acpi_region_holds(firmware, base)
                {
                    "in an ACPI region devmgr holds"
                }
                else
                {
                    "outside every ACPI region devmgr holds"
                }
            ),
            None => std::os::seraph::log!("no FACS: the FADT names none"),
        }
        Self {
            jobs,
            grants: Grants::new(),
            bridges: firmware::acpid::Bridges::new(),
            boot_apertures,
            kernel: kernel_ranges(firmware),
            facs,
            sci_int,
            sci_served: false,
            sleep,
            reset,
        }
    }

    /// The host bridges acpid has reported: their bus windows, `_PRT`
    /// entries and `_OSC` results.
    pub const fn bridges(&self) -> &firmware::acpid::Bridges
    {
        &self.bridges
    }

    /// The apertures devmgr was given at boot, each `(base, end)`, before
    /// any carve.
    pub fn boot_apertures(&self) -> &[(u64, u64)]
    {
        &self.boot_apertures
    }

    /// Run every job posted, each to its end, handing its reply back. A
    /// reply the worker can no longer take has its cap deleted. An
    /// `ACPI_HOTPLUG` job is posted to `hotplug` instead, whose job replies
    /// ([`Hotplug::post_acpi`]).
    pub fn run(
        &mut self,
        records: &bind::Records,
        caps: &mut DevmgrCaps,
        irq_range: &mut IrqRangeAllocator,
        hotplug: &Hotplug,
    )
    {
        while let Ok(Job { request, reply }) = self.jobs.try_recv()
        {
            if let Request::Hotplug { event, port } = request
            {
                hotplug.post_acpi(event, port, reply);
                continue;
            }
            let answer = self.answer(request, records, caps, irq_range);
            if let Err(mpsc::SendError(reply)) = reply.send(answer)
                && let Some(cap) = reply.cap
            {
                let _ = syscall::cap_delete(cap);
            }
        }
    }

    fn answer(
        &mut self,
        request: Request,
        records: &bind::Records,
        caps: &mut DevmgrCaps,
        irq_range: &mut IrqRangeAllocator,
    ) -> Reply
    {
        match request
        {
            Request::Region { space, base, len } => self.region(space, base, len, records, caps),
            Request::Config {
                op,
                function,
                offset,
                width,
                value,
            } => config(op, function, offset, width, value, records, caps),
            Request::Osc {
                segment,
                bus,
                osc,
                asked,
            } => self.osc(segment, bus, osc, asked),
            Request::Windows {
                segment,
                bus,
                windows,
            } =>
            {
                let pushed = self.bridges.push_windows(
                    segment,
                    bus,
                    windows,
                    records.live_pci(),
                    &self.boot_apertures,
                );
                let covered = |b: &firmware::acpid::Bridge| b.windows.as_ref().map(|h| h.covered);
                self.pushed("_CRS windows", segment, bus, pushed, covered)
            }
            Request::Prt {
                segment,
                bus,
                mode,
                table,
            } =>
            {
                let Some(rule) = arch::current::prt_rule(mode)
                else
                {
                    return Reply::status(errors::INVALID_REQUEST);
                };
                // Checked against the line a function has from its records
                // alone (its Interrupt Line, or the riscv64 swizzle), never
                // one routed by a table acpid pushed: no bridge's tables.
                let unrouted = firmware::acpid::Bridges::new();
                let pushed = self.bridges.push_prt(
                    segment,
                    bus,
                    mode,
                    &table,
                    rule,
                    records.live_pci(),
                    |f| bind::device_gsi(f, &unrouted),
                );
                let (what, covered): (_, fn(&firmware::acpid::Bridge) -> Option<u64>) = match mode
                {
                    PrtMode::Routes => ("_PRT routes", |b| b.routes.as_ref().map(|h| h.covered)),
                    PrtMode::PicMode => ("PIC-mode _PRT routes", |b| {
                        b.pic.as_ref().map(|h| h.covered)
                    }),
                };
                self.pushed(what, segment, bus, pushed, covered)
            }
            Request::HostBridge { ordinal } => self.host_bridge(ordinal),
            Request::Sci => self.sci(irq_range),
            Request::Sleep(register) => self.sleep_register(register, records, caps),
            Request::Reset => self.reset_register(records, caps),
            // `run` posts it to the hotplug slots.
            Request::Hotplug { .. } => Reply::status(errors::INVALID_REQUEST),
        }
    }

    /// `QUERY_ACPI_RESOURCES` of `ACPI_SCI`: a derivation of the SCI's line,
    /// held for the boot like a PCI device's (`IrqRangeAllocator::line_cap`),
    /// so a restarted acpid gets a new one on the same line; its GSI, its
    /// mode, and whether an earlier acpid of this boot was served it. The
    /// `SCI_INT` maps through the MADT's overrides to its GSI.
    fn sci(&mut self, irq_range: &mut IrqRangeAllocator) -> Reply
    {
        let Some(sci_int) = self.sci_int
        else
        {
            return Reply::status(errors::NO_DEVICE);
        };
        let gsi = firmware::acpi::sci_gsi(irq_range.overrides.iter().copied(), sci_int);
        match irq_range.line_cap(gsi)
        {
            Ok(cap) =>
            {
                let restarted = u64::from(self.sci_served);
                self.sci_served = true;
                let mut reply =
                    Reply::success(&[u64::from(gsi), irq_range.line_mode(gsi), restarted]);
                reply.cap = Some(cap);
                reply
            }
            Err(e) =>
            {
                std::os::seraph::log!(warn: "SCI (SCI_INT {sci_int}, GSI {gsi}) not served: {e:?}");
                Reply::status(errors::NO_DEVICE)
            }
        }
    }

    /// `QUERY_ACPI_RESOURCES` of a sleep register, checked as a region grant
    /// is ([`Self::checked_register`]).
    fn sleep_register(
        &mut self,
        register: SleepRegister,
        records: &bind::Records,
        caps: &mut DevmgrCaps,
    ) -> Reply
    {
        let [control, status] = self.sleep;
        let (fixed, name) = match register
        {
            SleepRegister::Control => (control, "SLEEP_CONTROL_REG"),
            SleepRegister::Status => (status, "SLEEP_STATUS_REG"),
        };
        fixed.map_or_else(
            || Reply::status(errors::NO_DEVICE),
            |fixed| self.checked_register(fixed, 0, name, records, caps),
        )
    }

    /// `QUERY_ACPI_RESOURCES` of `RESET_REG`. A memory register is checked as
    /// a region grant is ([`Self::checked_register`]): its cap reaches the
    /// whole page that holds it. A port is served as the other fixed blocks
    /// are, unchecked: its cap reaches that port alone, and a PC chipset's
    /// `RESET_REG`, port 0xCF9, lies among the configuration-mechanism ports
    /// a region grant is refused. Both replies carry `RESET_VALUE`.
    fn reset_register(&mut self, records: &bind::Records, caps: &mut DevmgrCaps) -> Reply
    {
        let Some(ResetRegister { register, value }) = self.reset
        else
        {
            return Reply::status(errors::NO_DEVICE);
        };
        if register.space == Space::Memory
        {
            return self.checked_register(register, value, "RESET_REG", records, caps);
        }
        let cap = u16::try_from(register.address)
            .ok()
            .and_then(|port| arch::current::carve_io_ports(caps, port, 1));
        match cap
        {
            Some(cap) => register_reply(register, value, cap),
            None =>
            {
                std::os::seraph::log!(
                    warn: "acpid: RESET_REG port {:#x} not served",
                    register.address
                );
                Reply::status(errors::NO_DEVICE)
            }
        }
    }

    /// A byte register of the FADT, `name`, with `value` the FADT gives with
    /// it: its range, the port or the page that holds it, refused, logged, as
    /// a region grant is refused ([`Self::refusal`]); then an `IoPort` over
    /// the port, or the kept grant of the page ([`Self::memory_cap`]), with
    /// the register's address, its byte count, `value`, and its space.
    fn checked_register(
        &mut self,
        register: FixedRegister,
        value: u8,
        name: &str,
        records: &bind::Records,
        caps: &mut DevmgrCaps,
    ) -> Reply
    {
        let FixedRegister { space, address } = register;
        let Some(range) = firmware::acpid::request_range(space, address, 1)
        else
        {
            return Reply::status(errors::NO_DEVICE);
        };
        if self.refusal(&range, records)
        {
            return Reply::status(errors::REFUSED);
        }
        let cap = match space
        {
            Space::Io => u16::try_from(address)
                .ok()
                .and_then(|port| arch::current::carve_io_ports(caps, port, 1))
                .ok_or(errors::NO_DEVICE),
            Space::Memory => self.memory_cap(&range, caps).map(|(_, cap)| cap),
        };
        match cap
        {
            Ok(cap) => register_reply(register, value, cap),
            Err(status) =>
            {
                std::os::seraph::log!(warn: "acpid: {name} {space:?} {address:#x} not served");
                Reply::status(status)
            }
        }
    }

    /// Whether a holder overlaps `range`: a device record's resource, a
    /// range the kernel owns, the configuration-mechanism ports or the FACS
    /// (`firmware::acpid::region_refusal`). A refusal is logged.
    fn refusal(&self, range: &Range, records: &bind::Records) -> bool
    {
        let Some(refusal) = firmware::acpid::region_refusal(
            range,
            records.resource_ranges(),
            &self.kernel,
            self.facs,
        )
        else
        {
            return false;
        };
        std::os::seraph::log!(
            warn: "acpid: region {:?} {:#x}..{:#x} refused: it overlaps {:?} {:#x}..{:#x}",
            range.space,
            range.base,
            range.end,
            refusal.holder,
            refusal.range.base,
            refusal.range.end
        );
        true
    }

    /// `ACPI_REGION_GRANT`: refuse a range a holder overlaps; grant ports
    /// from devmgr's `IoPort`; grant a memory page from the kept grant of
    /// it, else carve it from the apertures and keep it.
    fn region(
        &mut self,
        space: Space,
        base: u64,
        len: u64,
        records: &bind::Records,
        caps: &mut DevmgrCaps,
    ) -> Reply
    {
        let Some(range) = firmware::acpid::request_range(space, base, len)
        else
        {
            return Reply::status(errors::INVALID_REQUEST);
        };
        if self.refusal(&range, records)
        {
            return Reply::status(errors::REFUSED);
        }
        match space
        {
            Space::Io =>
            {
                let cap = u16::try_from(range.base)
                    .ok()
                    .zip(u16::try_from(range.len()).ok())
                    .and_then(|(port, count)| arch::current::carve_io_ports(caps, port, count));
                cap.map_or_else(
                    || Reply::status(errors::INVALID_REQUEST),
                    |cap| Reply::granted(&range, cap),
                )
            }
            Space::Memory => self
                .memory_cap(&range, caps)
                .map_or_else(Reply::status, |(kept, cap)| Reply::granted(&kept, cap)),
        }
    }

    /// A cap over `range`, one page, and the range of the grant it is over:
    /// a derivation of the kept grant of it, or of the cap newly carved and
    /// kept for it. Grants are kept a page at a
    /// time, so a page is either kept whole or not carved at all, and a
    /// region grant and a sleep register in the same page share its keep.
    /// The status to reply otherwise: `REFUSED`, logged, when no aperture
    /// devmgr holds covers the page, else `INVALID_REQUEST`.
    fn memory_cap(&mut self, range: &Range, caps: &mut DevmgrCaps) -> Result<(Range, u64), u64>
    {
        let derive = |kept: Range, cap: u64| {
            syscall::cap_derive(cap, syscall::RIGHTS_ALL)
                .map(|copy| (kept, copy))
                .map_err(|_| errors::INVALID_REQUEST)
        };
        if let Some((kept, cap)) = self.grants.within(range)
        {
            return derive(kept, cap);
        }
        match crate::carve_aperture(caps, range.base, range.len())
        {
            Ok(cap) =>
            {
                if self.grants.keep(*range, cap).is_err()
                {
                    std::os::seraph::log!(
                        warn: "acpid: memory {:#x}..{:#x} granted unkept: no memory to keep it",
                        range.base,
                        range.end
                    );
                    return Ok((*range, cap));
                }
                derive(*range, cap)
            }
            Err(CarveError::NotCovered) =>
            {
                std::os::seraph::log!(
                    warn: "acpid: memory {:#x}..{:#x} refused: no aperture devmgr holds covers it",
                    range.base,
                    range.end
                );
                Err(errors::REFUSED)
            }
            Err(_) => Err(errors::INVALID_REQUEST),
        }
    }

    /// `OSC_RESULT`: keep the bridge's first result, log a differing later
    /// one.
    fn osc(&mut self, segment: u16, bus: u8, osc: Osc, asked: u32) -> Reply
    {
        match self.bridges.push_osc(segment, bus, osc)
        {
            Some(Push::Kept) if osc.evaluated => std::os::seraph::log!(
                "acpid: bridge {}:{} _OSC grants control {:#x} of {:#x} asked (status {:#x})",
                segment,
                bus,
                osc.control,
                asked,
                osc.status
            ),
            Some(Push::Kept) => std::os::seraph::log!(
                "acpid: bridge {}:{} has no _OSC, or it failed: no native control granted",
                segment,
                bus
            ),
            Some(Push::Differs) => std::os::seraph::log!(
                warn: "acpid: bridge {}:{} _OSC result differs from the first; the first is kept",
                segment,
                bus
            ),
            Some(Push::Same | Push::Refused(_)) =>
            {}
            None =>
            {
                std::os::seraph::log!(warn: "acpid: no memory to record bridge {}:{}", segment, bus);
                return Reply::status(errors::INVALID_REQUEST);
            }
        }
        Reply::status(errors::SUCCESS)
    }

    /// The reply to a checked push of `what`, logged: `SUCCESS` when devmgr
    /// holds the bridge's value, `REFUSED` when it failed the check.
    fn pushed(
        &self,
        what: &str,
        segment: u16,
        bus: u8,
        pushed: Option<Push>,
        covered: impl Fn(&firmware::acpid::Bridge) -> Option<u64>,
    ) -> Reply
    {
        match pushed
        {
            Some(Push::Kept) =>
            {
                let checked = self
                    .bridges
                    .find(segment, bus)
                    .and_then(covered)
                    .unwrap_or(0);
                std::os::seraph::log!(
                    "acpid: bridge {}:{} {} agree with {} boot functions; kept",
                    segment,
                    bus,
                    what,
                    checked
                );
                Reply::status(errors::SUCCESS)
            }
            Some(Push::Same) => Reply::status(errors::SUCCESS),
            Some(Push::Differs) =>
            {
                std::os::seraph::log!(
                    warn: "acpid: bridge {}:{} {} differ from the first; the first is kept",
                    segment,
                    bus,
                    what
                );
                Reply::status(errors::SUCCESS)
            }
            Some(Push::Refused(why)) =>
            {
                log_disagreement(what, segment, bus, why);
                Reply::status(errors::REFUSED)
            }
            None =>
            {
                std::os::seraph::log!(warn: "acpid: no memory to record bridge {}:{}", segment, bus);
                Reply::status(errors::INVALID_REQUEST)
            }
        }
    }

    /// `QUERY_HOST_BRIDGE`: what devmgr holds for the bridge at `ordinal`.
    fn host_bridge(&self, ordinal: u64) -> Reply
    {
        let bridge = usize::try_from(ordinal)
            .ok()
            .and_then(|o| self.bridges.get(o));
        let Some(bridge) = bridge
        else
        {
            return Reply::status(errors::NO_DEVICE);
        };
        let osc = bridge.osc.filter(|o| o.evaluated);
        Reply::success(&[
            u64::from(bridge.segment),
            u64::from(bridge.bus),
            u64::from(osc.is_some()),
            osc.map_or(0, |o| u64::from(o.status)),
            osc.map_or(0, |o| u64::from(o.control)),
            u64::from(bridge.routes.is_some()),
            bridge.routes.as_ref().map_or(0, |h| h.covered),
            u64::from(bridge.windows.is_some()),
            bridge.windows.as_ref().map_or(0, |h| h.covered),
        ])
    }
}

/// The `SUCCESS` reply serving byte register `register` through `cap`: its
/// address, its byte count, `value`, and its space.
fn register_reply(register: FixedRegister, value: u8, cap: u64) -> Reply
{
    let space = match register.space
    {
        Space::Io => labels::ACPI_SPACE_IO,
        Space::Memory => labels::ACPI_SPACE_MEMORY,
    };
    let mut reply = Reply::success(&[register.address, 1, u64::from(value), space]);
    reply.cap = Some(cap);
    reply
}

/// `ACPI_PCI_CONFIG`: make the access `firmware::acpid::config_access`
/// allows, refusing, logged, a write it does not.
fn config(
    op: ConfigOp,
    function: Address,
    offset: u64,
    width: u64,
    value: u64,
    records: &bind::Records,
    caps: &mut DevmgrCaps,
) -> Reply
{
    let state = records.pci_state_at(function);
    match firmware::acpid::config_access(op, offset, width, state)
    {
        Err(ConfigError::Invalid) => Reply::status(errors::INVALID_REQUEST),
        Err(ConfigError::Refused) =>
        {
            let (segment, bus, dev, func) = function;
            std::os::seraph::log!(
                warn: "acpid: configuration write at {:#x} of {}:{}:{}.{} refused (record {:?})",
                offset,
                segment,
                bus,
                dev,
                func,
                state
            );
            Reply::status(errors::REFUSED)
        }
        Ok(ConfigAccess::AllOnes) => Reply::success(&[firmware::acpid::all_ones(width)]),
        Ok(ConfigAccess::Access) =>
        {
            let write = (op == ConfigOp::Write).then_some(value);
            let done = u16::try_from(offset)
                .ok()
                .zip(u16::try_from(width).ok())
                .and_then(|(offset, width)| {
                    bind::acpi_config_access(caps, function, offset, width, write)
                });
            done.map_or_else(
                || Reply::status(errors::INVALID_REQUEST),
                |read| Reply::success(&[read]),
            )
        }
    }
}

/// Log why devmgr refused a bridge's push of `what`: the bridge then lacks
/// it for the boot, until a later push passes.
fn log_disagreement(what: &str, segment: u16, bus: u8, why: Disagreement)
{
    std::os::seraph::log!(
        warn: "acpid: bridge {}:{} {} refused, not held: {:?}",
        segment,
        bus,
        what,
        why
    );
}
